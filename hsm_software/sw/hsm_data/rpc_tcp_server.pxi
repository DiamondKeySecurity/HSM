#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
# Implementation of Cryptech RPC protocol multiplexer in Python.
#
# This implementation is by Diamond Key Security, NFP using code from
# CrypTech's cryptech_muxd. It is an implementation of the CrypTech
# multiplexer that accepts incoming TCP connections using the
# Tornado library. It then uses PySerial to communicate directly with
# an Alpha.
#
# This Python script uses code from 'cryptech_muxd.'
# The 'cryptech_muxd' copyright is below.
#
#---------------------------------------------------------------------
# Original cryptech_muxd copyright
#
# Copyright (c) 2016-2017, NORDUnet A/S All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cdef inc_atomic_int.inc_atomic_int rpc_client_next_handle

cdef bytes slip_encode(bytes buffer):
    "Encode a buffer using SLIP encapsulation."
    return SLIP_END + buffer.replace(SLIP_ESC, SLIP_ESC + SLIP_ESC_ESC).replace(SLIP_END, SLIP_ESC + SLIP_ESC_END) + SLIP_END

cdef bytes slip_decode(bytes buffer):
    "Decode a SLIP-encapsulated buffer."
    return buffer.strip(SLIP_END).replace(SLIP_ESC + SLIP_ESC_END, SLIP_END).replace(SLIP_ESC + SLIP_ESC_ESC, SLIP_ESC)

class RPCTCPServer(TCPServer):
    """
    Serve multiplexed Cryptech RPC over a TCP socket.
    """

    def __init__(self, rpc_preprocessor, port, ssl):
        self.rpc_preprocessor = rpc_preprocessor
        super(RPCTCPServer, self).__init__(port, ssl)

    def error_from_request(self, unencoded_request, hal_error):
        unpacker = ContextManagedUnpacker(unencoded_request)
        
        # get the code of the RPC request
        code = unpacker.unpack_uint()

        # get the handle which identifies the TCP connection that the request came from
        client = unpacker.unpack_uint()

        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)
        response.pack_uint(hal_error)

        return response.get_buffer()

    def verify_result(self, result):
        decoded_request = slip_decode(result)

        # handle the message normally
        unpacker = ContextManagedUnpacker(decoded_request)

        # get the code of the RPC request
        code = unpacker.unpack_uint()

        # get the handle which identifies the TCP connection that the request came from
        client = unpacker.unpack_uint()

        # hal error
        hal_error = unpacker.unpack_uint()

        if(hal_error is not 0):
            print 'HALERROR:%X - CODE:%X'%(hal_error, code)



    @tornado.gen.coroutine
    def handle_stream(self, stream, address):
        """Start processing a stream from the ethernet"""

        # is the HSM locked
        if(self.rpc_preprocessor.is_rpc_locked()):
            # get the RPC message so we can reply no
            while True:
                try:
                    decoded_query = None
                    cryptech.muxd.logger.debug("Forbidden RPC socket read, handle 0")
                    query = yield stream.read_until(cryptech.muxd.SLIP_END)
                    if len(query) < 9:
                        continue

                    # get the old handle
                    decoded_query = slip_decode(query)

                    if (not self.rpc_preprocessor.is_mkm_set):
                        reply = self.error_from_request(decoded_query, DKS_HALError.HAL_ERROR_MASTERKEY_NOT_SET)
                    else:
                        reply = self.error_from_request(decoded_query, DKS_HALError.HAL_ERROR_FORBIDDEN)
                except:
                    if (decoded_query is not None):
                        reply = self.error_from_request(decoded_query, DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)
                    else:
                        return

                #encode
                reply_encoded = slip_encode(reply)

                try:
                    yield stream.write(cryptech.muxd.SLIP_END + reply_encoded)
                except:
                    # if something happens, we're closing this connection anyway
                    pass

                # stop and close this connection
                return

        self.__handle_stream(stream, address, from_ethernet = True)

    @tornado.gen.coroutine
    def handle_internal_stream(self, stream, address):
        """Start processing a stream from an intenal PF_UNIX connection"""
        self.__handle_stream(stream, address, from_ethernet = False)

    @tornado.gen.coroutine
    def try_restart_serial(self, rpc, encoded_request, handle, queue, e):
        serial_obj = rpc.serial

        message = 'Restarting serial %s because of %s'%(str(serial_obj.serial_device), e.message)

        cryptech.muxd.logger.debug(message)
        print message

        try:
            # try to reopen the serial device
            serial_obj.serial = serial.Serial(serial_obj.serial_device, 921600, timeout = 0, write_timeout = 0.1)

            yield serial_obj.rpc_input(encoded_request, handle, queue)
        except Exception as e:
            message = 'Unable to restarting serial %s because of %s'%(str(serial_obj.serial_device), e.message)
            rpc.change_state(CrypTechDeviceState.HSMNotReady)

    @tornado.gen.coroutine
    def __handle_stream(self, stream, address, from_ethernet):
        "Handle one network connection."
        cdef int handle = rpc_client_next_handle.inc(1)
        cdef int old_handle
        cdef bytes decoded_query
        cdef bytes query
        cdef bytes request
        cdef bytes encoded_request
        cdef object queue
        cdef safe_queue.SafeQueue[libhal.rpc_packet] rpc_result_queue
        cdef libhal.rpc_packet ipacket

        queue  = tornado.queues.Queue()
        cryptech.muxd.logger.info("RPC connected %r, handle 0x%x", stream, handle)

        self.rpc_preprocessor.create_session(handle, from_ethernet)

        while True:
            try:
                cryptech.muxd.logger.debug("RPC socket read, handle 0x%x", handle)
                query = yield stream.read_until(cryptech.muxd.SLIP_END)
                if len(query) < 9:
                    continue

                if (0 == utils.CreatePacketFromSlipEncodedBuffer(ipacket, query)):
                    continue

                # get the old handle
                decoded_query = slip_decode(query)
                old_handle = cryptech.muxd.client_handle_get(decoded_query)

                # set the handle to be the handle of this stream handler
                request = cryptech.muxd.client_handle_set(decoded_query, handle)

                # the serial we use is decided on by the query(request), send non-slip encoded
                action = self.rpc_preprocessor.process_incoming_rpc(request)

                # the request may have been updated
                request = action.request

                # do we actually have a def
                while ((self.rpc_preprocessor.device_count() > 0) and
                       (action.result is None) and
                       (action.rpc_list is not None)):
                    # slip encode a request to send to the HSM
                    encoded_request = slip_encode(request)

                    # because we may send to multiple alphas, we need to save every reply
                    reply_list = []

                    for rpc in action.rpc_list:
                        serial = rpc.serial
                        # if the load balancer returns a serial to write to, then it wasn't able to handle te request with cached data
                        try:
                            yield serial.rpc_input(encoded_request, handle, queue)
                        except Exception as e:
                            yield self.try_restart_serial(rpc, encoded_request, handle, queue, e)

                        cryptech.muxd.logger.debug("RPC queue wait, handle 0x%x", handle)
                        reply = yield queue.get()
                        if reply is None:
                            raise cryptech.muxd.QueuedStreamClosedError()
                        cryptech.muxd.logger.debug("RPC socket write, handle 0x%x", handle)

                        # TODO: remove - debugging only
                        self.verify_result(reply)

                        # save the replies for the callback
                        reply_list.append(slip_decode(reply))

                    if(action.callback is not None):
                        # use the action callback to respond to data from multiple alphas
                        action = action.callback(reply_list)
                    else:
                        # just use the first response
                        action = RPCAction(reply_list[0], None, None)

                if(action.result is not None):
                    reply = action.result
                else:
                    reply = self.error_from_request(request, DKS_HALError.HAL_ERROR_FORBIDDEN)

                #set old handle in reply
                reply_old_handle_encoded = slip_encode(cryptech.muxd.client_handle_set(reply, old_handle))

                yield stream.write(cryptech.muxd.SLIP_END + reply_old_handle_encoded)

            except tornado.iostream.StreamClosedError:
                cryptech.muxd.logger.info("RPC closing %r, handle 0x%x", stream, handle)
                stream.close()
                self.rpc_preprocessor.delete_session(handle)

                # log out
                query = slip_encode(cryptech.muxd.client_handle_set(cryptech.muxd.logout_msg, handle))

                rpc_serials = self.rpc_preprocessor.make_all_rpc_list()
                for rpc in rpc_serials:
                    serial = rpc.serial
                    yield serial.rpc_input(query, handle)
                    
                return

class SecondaryPFUnixListener(cryptech.muxd.PFUnixServer):
    """ Variant on the PFUnixServer in cryptech_muxd
    This method will listen for connections on a PFUnix socket
    and forward the connection to a RPCTCPServer instance
    """
    def __init__(self, rpc_tcp_server, socket_filename, mode = 0600):
        super(SecondaryPFUnixListener, self).__init__(rpc_tcp_server, socket_filename, mode)
        self.rpc_tcp_server = rpc_tcp_server

    @tornado.gen.coroutine
    def handle_stream(self, stream, address):
        return self.rpc_tcp_server.handle_internal_stream(stream, address)