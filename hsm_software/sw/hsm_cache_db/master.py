#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import atexit
import threading
import enum
import os

from cache import CacheTable

class MasterKeyListRow(object):
    """Represents a row in the cache's master key list"""
    def __init__(self, uuid, keytype = 0, flags = 0):
        """Initialize the rows data
        keytype      - the key's type (eg. HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE)
        flags        - the flags set in the alpha
        """
        self.keytype = keytype
        self.flags = flags
        self.attributes_set = False
        self.attributes = { }
        self.uuid_list = [ uuid ]

    def __str__(self):
        """Provide override of _str__ for testing"""
        uuids = ''
        uuid_count = len(self.uuid_list)
        for i in xrange(uuid_count):
            uuid = self.uuid_list[i]
            if (i < uuid_count-1):
                uuids = '%s%s,'%(uuids, uuid)
            else:
                uuids = '%s%s'%(uuids, uuid)

        return '{"keytype":%d, "flags":%d, "uuid_list":[%s]}'%(self.keytype, self.flags, uuids)

class CacheTableMaster(CacheTable):
    __next_index = 0
    lock = threading.Lock()

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
        # get the next index to use
        with CacheTableMaster.lock:
            key = CacheTableMaster.__next_index
            CacheTableMaster.__next_index += 1

        return super(CacheTableMaster, self).add_row(key, record)

    def delete_row(self, key):
        super(CacheTableMaster, self).delete_row(key)

    def save_mapping(self, fname):
        rows = self.get_rows()
        num_rows = len(rows)
        row_num = 0

        with open(fname, "w") as fh:
            fh.write('[')
            for row in rows.itervalues():
                fh.write('\n  [')

                num_uuids = len(row.uuid_list)
                for uuid_index in xrange(num_uuids):
                    fh.write('"%s"'%str(row.uuid_list[uuid_index]))
                    if(uuid_index < num_uuids-1):
                        fh.write(',')

                fh.write(']')
                row_num += 1
                if(row_num < num_rows):
                    fh.write(',')

            fh.write('\n]')
            fh.truncate()