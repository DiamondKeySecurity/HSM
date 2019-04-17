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