#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
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
    none_uuid = str(UUID(int = 0))

    def __init__(self):
        self.result_max = 0
        self.uuid = KeyMatchDetails.none_uuid
        self.result = KeyMatchResult()
        self.rpc_index = 0

    def unpack(self, unpacker):
        # consume pkcs11 session id
        unpacker.unpack_uint()

        # consume type
        unpacker.unpack_uint()

        # consume curve
        unpacker.unpack_uint()

        # consume mask
        unpacker.unpack_uint()

        # consume flags
        unpacker.unpack_uint()

        # consume attributes
        attr_len = unpacker.unpack_uint()
        for i in xrange(attr_len):
            unpacker.unpack_uint()
            unpacker.unpack_bytes()

        # consume status
        unpacker.unpack_uint()

        # max uuid's requested
        self.result_max = unpacker.unpack_uint()

        #get the new uuid
        u = UUID(bytes = unpacker.unpack_bytes())
        self.uuid = str(u)

