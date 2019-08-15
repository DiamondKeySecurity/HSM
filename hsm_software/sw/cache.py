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


import os
import threading

from hsm_tools.cryptech.cryptech.libhal import HALDigestAlgorithm, HALKeyType, HALCurve

from hsm_cache_db.alpha import CacheTableAlpha, AlphaCacheRow
from hsm_cache_db.master import CacheTableMaster, MasterKeyListRow
from hsm_cache_db.cache import CacheDB

class HSMCache(CacheDB):
    """ Root cache object that uses dictionaries to store key information"""
    def __init__(self, rpc_count, cache_folder):
        # set up initialization and file structure
        self.__cache_initialized__ = False
        self.lock = threading.Lock()
        self.cache_folder = cache_folder

        # make sure the path exist
        try:
            os.makedirs(self.cache_folder)
        except OSError:
            pass

        # create cache tables        
        super(HSMCache, self).__init__(rpc_count)

        self.masterTable = CacheTableMaster(self)
        self.alphaTables = []
        for rpc_index in xrange(rpc_count):
            self.alphaTables.append(CacheTableAlpha(self, rpc_index))

    def reset(self):
        with self.lock:
            self.__cache_initialized__ = False
        
        self.clear()

    def initialize_cache(self):
        """Update cache from changes made to a duplicate DB"""
        with self.lock:
            self.__cache_initialized__ = True

    def is_initialized(self):
        with self.lock:
            return self.__cache_initialized__

    def get_alpha_table_object(self, index):
        assert index >= 0 and index < self.rpc_count

        return self.alphaTables[index]

    def get_master_table_object(self):
        return self.masterTable

    def get_master_uuid(self, device_index, device_uuid):
        alphaTable = self.alphaTables[device_index]
        row = alphaTable.fetch_row(device_uuid)
        if (row is not None):
            return row.masterListID
        else:
            return None

    def get_master_uuid_lowest_index(self, master_uuid):
        full_list = self.get_alphas(master_uuid)

        index = None
        for key in full_list.iterkeys():
            if (index is None or index < key):
                index = key

        return index

    def add_key_to_alpha(self, rpc_index, uuid, keytype = 0, flags = 0, param_masterListID = None, auto_backup = True):
        masterTable = self.masterTable
        alphaTable = self.alphaTables[rpc_index]

        masterListID = None

        if(param_masterListID is not None):
            # link new uuid to existing key
            row = masterTable.fetch_row(param_masterListID)
            if(row is not None):
                row.uuid_dict[rpc_index] = uuid

                masterTable.update_row(param_masterListID, row)

                # updates to the mapping must be made right away
                if (auto_backup):
                    self.backup_matching_map()

                masterListID = param_masterListID
        
        if (masterListID is None):
            # add a new entry to the master table
            # if param_masterListID is not None, we must
            # create an entry in the master table, because
            # this is being reloaded from saved data. if
            # param_masterListID is None, add_row will
            # generate a new UUID
            masterListID = masterTable.add_row(param_masterListID, MasterKeyListRow(rpc_index, uuid, keytype, flags))

        alphaTable.add_row(uuid, AlphaCacheRow(masterListID))

        return masterListID

    def remove_key_from_alpha(self, rpc_index, uuid):
        alphaTable = self.alphaTables[rpc_index]

        # find in the master list so we can delete all references
        alpha_row = alphaTable.get_from_uuid(uuid)
        if(alpha_row is None):
            return False

        masterListID = alpha_row.masterListID

        # remove from the alpha
        alphaTable.delete_row(uuid)

        # remove from the master list. later the synchronizer will
        # clean up uuids on alphas that don't have a master list reference
        masterTable = self.masterTable
        masterTable.delete_row(masterListID)

        # updates to the mapping must be made right away
        self.backup_matching_map()

    def get_alpha_lowest_index(self, master_uuid):
        """Returns information on the alpha with the master_uuid as a tuple.
        The first element is the device index and the second is the device
        uuid. If the master_uuid refers to items on multiple devices,
        the device with the smallest index is returned"""
        full_list = self.get_alphas(master_uuid)

        result = None
        for key, val in full_list.iteritems():
            if (result is None or result[0] < key):
                result = (key, val)

        return result

    def get_alphas(self, master_uuid):
        """Returns a list of alphas that the master UUID is on"""
        row = self.masterTable.fetch_row(master_uuid)

        # return a copy of the dictionary to prevent changes
        if (row is not None):
            return row.uuid_dict.copy()
        else:
            return {}

    def clear(self):
        super(HSMCache, self).clear()

        if (self.is_initialized()):
            self.backup()

    def backup_matching_map(self):
        print 'backing up matching uuids'

        self.masterTable.save_mapping('%s/cache_mapping.db'%self.cache_folder)

    def backup_tables(self):
        print 'backing up tables'

        self.masterTable.save_table('%s/cache_master.db'%self.cache_folder)

        alpha_index = 0
        for alpha_table in self.alphaTables:
            alpha_table.save_table('%s/cache_alpha_%d.db'%(self.cache_folder, alpha_index))
            alpha_index += 1

    def backup(self):
        print 'backing up'
        self.backup_matching_map()
        self.backup_tables()

    def getVerboseMapping(self):
        """Return a list of strings with information on the cache and all linked keys"""
        results = []

        master_rows = self.masterTable.get_rows()
        alpha_rows = []

        for alpha_index in xrange(self.rpc_count):
            alpha_rows.append(self.alphaTables[alpha_index].get_rows())

        for master_key, master_row in master_rows.iteritems():
            results.append('-----------------------------------------------------')
            results.append('UUID: %s, Type: %s,  Flags: %s'%(master_key, str(master_row.keytype), str(master_row.flags)))
            for rpc_index, uuid in master_row.uuid_dict.iteritems():
                results.append('-> %s in RPC:%i'%(uuid, rpc_index))

        return results

