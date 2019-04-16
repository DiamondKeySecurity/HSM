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
