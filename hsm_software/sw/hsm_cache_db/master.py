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

import atexit
import threading
import enum
import os
import uuid

from cache import CacheTable

from hsm_tools.cryptech.muxd import logger

class MasterKeyListRow(object):
    """Represents a row in the cache's master key list"""
    def __init__(self, key_rpc_index, key_uuid, keytype = 0, flags = 0):
        """Initialize the rows data
        key_rpc_index - index of the CrypTech device that the key with the associated key_uuid is on
        key_uuid      - uuid of the key on the CrypTech deviced defined by key_rpc_index
        keytype       - the key's type (eg. HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE)
        flags         - the flags set in the alpha
        """
        self.keytype = keytype
        self.flags = flags
        self.uuid_dict = { key_rpc_index : key_uuid }

    def __str__(self):
        """Provide override of _str__ for testing"""
        uuids = ''
        uuid_count = len(self.uuid_dict)
        i = 0
        for key, val in self.uuid_dict.iteritems():
            uuid = '"%s": "{%s}"'%(key, val)
            if (i < uuid_count-1):
                uuids = '%s%s,'%(uuids, uuid)
            else:
                uuids = '%s%s'%(uuids, uuid)

            i += 1

        try:
            result = '{"keytype":%d, "flags":%d, "uuid_list":{%s}}'%(self.keytype, self.flags, uuids)
        except Exception as e:
            logger.exception("Exception %s", str(e))
            result = '{}'

        return result

class CacheTableMaster(CacheTable):
    """Uses a dictionary to hold table data for keys on the HSM
    key    - the uuid of the key in the alpha
    record - MasterKeyListRow
    """
    def __init__(self, cacheDB):
        self.lock = threading.Lock()
        super(CacheTableMaster, self).__init__(cacheDB)

    def get_table(self):
        return self.cacheDB.get_masterTable()

    def check_record_type(self, record):
        return isinstance(record, MasterKeyListRow)

    def add_row(self, key, record):
        if (key is None):
            key = uuid.uuid4()
        return super(CacheTableMaster, self).add_row(key, record)

    def delete_row(self, key):
        super(CacheTableMaster, self).delete_row(key)

    def save_mapping(self, fname):
        """
        Saves mapping as a JSON dictionary,
        Key   - device uuid
        Value - master uuid

        Values will duplicate. Keys will not.
        """
        rows = self.get_rows()
        num_rows = len(rows)
        row_num = 0

        with open(fname, "w") as fh:
            fh.write('{')
            for key, row in rows.iteritems():
                uuid_count = len(row.uuid_dict)
                uuid_index = 0
                for uuid in row.uuid_dict.itervalues():
                    fh.write('\n  "%s": "%s"'%(uuid, key))

                    # do we need a comma
                    uuid_index += 1
                    if(uuid_index < uuid_count):
                        fh.write(',')

                # do we need a comma
                row_num += 1
                if(row_num < num_rows):
                    fh.write(',')

            fh.write('\n}')
            fh.truncate()