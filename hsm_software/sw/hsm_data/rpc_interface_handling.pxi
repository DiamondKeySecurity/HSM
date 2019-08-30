#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
from cython.operator cimport dereference as deref
from libcpp.vector cimport vector
from libcpp.string cimport string

cdef class rpc_internal_handling(object):
    cdef rpc_handler.rpc_handler *rpc_preprocessor
    cdef bint hsm_locked
    cdef object tamper_detected
    cdef object settings
    
    """ Python interface to the rpc handler"""
    def __init__(self, rpc_list, settings, netiface):
        self.tamper_detected = ThreadSafeVariable(False)
        self.hsm_locked = False
        self.settings = settings

        cdef vector[string] real_rpc_list
        cdef str rpc

        for rpc in rpc_list:
            real_rpc_list.push_back(rpc)

        self.rpc_preprocessor.create_serial_connections(real_rpc_list)

    def __cinit__(self, rpc_list, settings, netiface):
        self.rpc_preprocessor = new rpc_handler.rpc_handler(netiface.get_ip())

    def __dealloc(self):
        del self.rpc_preprocessor

    @property
    def is_mkm_set(self):
        return self.settings.get_setting(HSMSettings.MASTERKEY_SET) == True

    def unlock_hsm(self):
        self.rpc_preprocessor.unlock_hsm()

    def device_count(self):
        return self.rpc_preprocessor.device_count()

    def get_current_rpc(self):
        return self.rpc_preprocessor.get_current_rpc()

    def set_current_rpc(self, int index):
        self.rpc_preprocessor.set_current_rpc(index)

    def on_tamper_event(self, object tamper_object):
        new_tamper_state = tamper_object.get_tamper_state()
        old_tamper_state = self.tamper_detected.value

        if(new_tamper_state != old_tamper_state):
            self.tamper_detected.value = new_tamper_state

            # if(new_tamper_state is True):
            #     self.hsm_locked = True
            #     for rpc in self.rpc_list:
            #         rpc.change_state(CrypTechDeviceState.TAMPER)
            # else:
            #     self.hsm_locked = True
            #     for rpc in self.rpc_list:
            #         rpc.clear_tamper(CrypTechDeviceState.TAMPER_RESET)
    
    def process_incoming_rpc(self, bytes encoded_request, int client):
        # packet that we received from the user
        cdef libhal.rpc_packet ipacket

        # packet to send back to the user
        cdef libhal.rpc_packet opacket

        # used to convert resulting C packet
        cdef char reply_buffer_encoded[16384]
        cdef int reply_buffer_encoded_len = 0

        # decode slip packet
        if (0 == ipacket.createFromSlipEncoded(encoded_request)):
            return None

        # send to C++ code to process
        with nogil:
            self.rpc_preprocessor.process_incoming_rpc(ipacket, client, opacket)

        # convert result back for Python
        reply_buffer_encoded_len = opacket.encodeToSlip(reply_buffer_encoded, 16384)
        out_reply = reply_buffer_encoded[:reply_buffer_encoded_len]

        return out_reply

    def is_rpc_locked(self):
        return ((self.rpc_preprocessor.is_hsm_locked()) or
                (not self.is_mkm_set))

    def create_session(self, int handle, bint from_ethernet, bint enable_exportable_private_keys):
        self.rpc_preprocessor.create_session(handle, from_ethernet, enable_exportable_private_keys)

    def delete_session(self, int handle):
        self.rpc_preprocessor.delete_session(handle)

cdef _internal_set_cache_variable_rpc_(rpc_internal_handling o, hsm_cache.hsm_cache *c_cache_object):
    o.rpc_preprocessor.set_cache_object(c_cache_object)

cdef _internal_set_keydb_variable_rpc_(rpc_internal_handling o, keydb.keydb *c_keydb_object):
    o.rpc_preprocessor.set_keydb_object(c_keydb_object)

class rpc_interface_handling(object):
    """ Limitted Python interface to the rpc handler"""
    def __init__(self, internal_handler):
        self.internal_handler = internal_handler

    def unlock_hsm(self):
        self.internal_handler.unlock_hsm()

    def device_count(self):
        return self.internal_handler.device_count()

    def get_current_rpc(self):
        cdef int current_rpc
        current_rpc = self.internal_handler.get_current_rpc()
        if(current_rpc < 0):
            return "auto"
        elif (self.device_count() > current_rpc):
            return "RPC%i"%current_rpc
        else:
            return "INVALID RPC"

    def set_current_rpc(self, index):
        if(isinstance(index, (int, )) is False):
            return "Invalid index. The index must be a valid RPC index."
        elif (index > self.device_count()):
            return "Index out of range. The index must be a valid RPC index."
        else:
            self.internal_handler.set_current_rpc(index)
            return "RPC is now: " + self.get_current_rpc()

    def get_names(self):
        cdef int i
        for i in xrange(self.device_count()):
            yield "RPC%i"%i

    def append_futures(self, futures):
        futures.append(self.rpc_output_loop())

    def empty_call(self):
        pass

    @tornado.gen.coroutine
    def rpc_output_loop(self):
        "Keep Tornado alive"
        while(True):
            yield self.empty_call()