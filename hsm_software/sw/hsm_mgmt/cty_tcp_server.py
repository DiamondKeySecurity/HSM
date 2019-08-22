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
import time
import atexit
import logging
import logging.handlers
import threading

import serial

import tornado.iostream
import tornado.gen

# import classes from the original cryptech.muxd
# cryptech_muxd has been renamed to cryptech/muxd.py
import cryptech.muxd

from cryptech.tcpserver import TCPServer

def response_thread(e, cty_mux):
    """Simple thread that gets new responses from CTY"""
    while not e.isSet():
        cty_mux.handle_cty_output()
        time.sleep(0.01)

class CTYTCPServer(TCPServer):
    """
    Serve Cryptech console over a TCP socket.
    """

    def __init__(self, cty_mux, port, ssl):
        self.cty_mux = cty_mux
        super(CTYTCPServer, self).__init__(port, ssl)

    @tornado.gen.coroutine
    def handle_stream(self, stream, address):
        "Handle one network connection."

        e = threading.Event()
        t1 = threading.Thread(name='cty_reponse',
                            target=response_thread,
                            args=(e,self.cty_mux))
        t1.start()

        if self.cty_mux.attached_cty is not None:
            yield stream.write("[Console already in use, sorry]\n")
            stream.close()
            return

        cryptech.muxd.logger.info("CTY connected to %r", stream)

        self.cty_mux.reset()

        try:
            self.cty_mux.attached_cty = stream
            while self.cty_mux.attached_cty is stream:
                yield self.cty_mux.write((yield stream.read_bytes(1024, partial = True)))


        except tornado.iostream.StreamClosedError:
            stream.close()

        finally:
            cryptech.muxd.logger.info("CTY disconnected from %r", stream)
            e.set()
            if self.cty_mux.attached_cty is stream:
                self.cty_mux.attached_cty = None
                self.cty_mux.reset()