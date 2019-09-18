#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# All rights reserved.
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

import xdrlib
from uuid import UUID

import enum

# import classes from the original cryptech.muxd
# cryptech_muxd has been renamed to cryptech/muxd.py
import hsm_tools.cryptech.muxd


class KeyMatchResult:
    def __init__(self):
        self.code = 0
        self.client = 0
        self.result = 0
        self.session = 0
        self.uuid_list = []

    def build_result_packet(self, result_max):
        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(self.code)
        response.pack_uint(self.client)
        response.pack_uint(self.result)
        response.pack_uint(self.session)

        # don't return more than the max
        count = len(self.uuid_list)
        if(count > result_max): count = result_max
    
        response.pack_uint(count)
        for i in xrange(count):
            response.pack_bytes(self.uuid_list[i].bytes)

        return response.get_buffer()


class KeyMatchDetails:
    none_uuid = UUID(int = 0)

    def __init__(self):
        self.result_max = 0
        self.uuid = KeyMatchDetails.none_uuid
        self.result = KeyMatchResult()
        self.rpc_index = 0

    def unpack(self, unpacker):
        # consume pkcs11 session id
        self.session = unpacker.unpack_uint()

        # consume type
        self.type = unpacker.unpack_uint()

        # consume curve
        self.curve = unpacker.unpack_uint()

        # consume mask
        self.mask = unpacker.unpack_uint()

        # consume flags
        self.flags = unpacker.unpack_uint()

        # consume attributes
        self.attr_len = unpacker.unpack_uint()
        self.attr = []
        for i in xrange(self.attr_len):
            self.attr.append((unpacker.unpack_uint(), unpacker.unpack_bytes()))

        # consume status
        self.status = unpacker.unpack_uint()

        # max uuid's requested
        self.result_max = unpacker.unpack_uint()

        #get the new uuid
        self.uuid = UUID(bytes = unpacker.unpack_bytes())

    def repack(self, code, client):
        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)

        # repack altered data
        response.pack_uint(self.session)

        # consume type
        response.pack_uint(self.type)

        # consume curve
        response.pack_uint(self.curve)

        # consume mask
        response.pack_uint(self.mask)

        # consume flags
        response.pack_uint(self.flags)

        # consume attributes
        response.pack_uint(self.attr_len)
        for i in xrange(self.attr_len):
            response.pack_uint(self.attr[i][0])
            response.pack_bytes(self.attr[i][1])

        # consume status
        response.pack_uint(self.status)

        # max uuid's requested
        response.pack_uint(self.result_max)

        #get the new uuid
        response.pack_bytes(self.uuid.bytes)

        # return the buffer
        return response.get_buffer()

class RPCpkey_open:
    @staticmethod
    def create(code, client, session, uuid):
        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)

        # repack altered data
        response.pack_uint(session)

        response.pack_bytes(uuid.bytes)

        # return the buffer
        return response.get_buffer()

class RPCKeygen_result:
    @staticmethod
    def create(code, client, result, handle, uuid):
        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)
        response.pack_uint(result)
        response.pack_uint(handle)
        response.pack_bytes(uuid.bytes)

        # return the buffer
        return response.get_buffer()
