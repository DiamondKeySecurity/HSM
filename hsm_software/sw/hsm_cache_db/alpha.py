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

from cache import CacheTable

class AlphaCacheRow(object):
    """Represents a row in the cache for a specific alpha"""
    def __init__(self, masterListID = 0):
        """Initialize the rows data
        keyID        - the primary key
        uuid         - the uuid of the key in the alpha
        masterListID - foreign key to master key list
        """
        self.masterListID = masterListID


    def __str__(self):
        """Provide override of _str__ for testing"""
        return '{"masterListID":%s}'%str(self.masterListID)

class CacheTableAlpha(CacheTable):
    """Uses a dictionary to hold table data for keys on an alpha
       key    - the uuid of the key in the alpha
       record - AlphaCacheRow
    """
    def __init__(self, cacheDB, alpha_index):
        super(CacheTableAlpha, self).__init__(cacheDB)
        self.alpha_index = alpha_index

    def get_table(self):
        return self.cacheDB.get_alphaTable(self.alpha_index)

    def check_record_type(self, record):
        return isinstance(record, AlphaCacheRow)

    def add_row(self, key, record):
        return super(CacheTableAlpha, self).add_row(key, record)

    def delete_row(self, key):
        super(CacheTableAlpha, self).delete_row(key)

    def get_from_uuid(self, uuid):
        return self.fetch_row(uuid)

    def get_from_masterListID(self, masterListID):
        table = self.get_table()

        with self.lock:
            for key, value in table.iteritems():
                if(value.masterListID == masterListID):
                    return key

        return None