#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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

    def add_key_to_alpha(self, rpc_index, uuid, keytype = 0, flags = 0, param_masterListID = None):
        masterTable = self.masterTable
        alphaTable = self.alphaTables[rpc_index]

        masterListID = None

        if(param_masterListID is not None):
            # link new uuid to existing key
            row = masterTable.fetch_row(param_masterListID)
            if(row is not None):
                row.uuid_list.append(uuid)

                masterTable.update_row(param_masterListID, row)

                # updates to the mapping must be made right away
                self.backup_matching_map()

                masterListID = param_masterListID
            else:
                print 'error on %s at %i'%(uuid, param_masterListID)
        
        if (masterListID is None):
            # add a new entry to the master table
            masterListID = masterTable.add_row(None, MasterKeyListRow(uuid, keytype, flags))

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

    def get_alphas(self, uuid):
        """Return a list of alphas that the uuid is on"""
        # master_index = None
        result = {}

        # first match the uuid exactly
        for rpc_index in range(self.rpc_count):
            alpha_table = self.alphaTables[rpc_index]

            row = alpha_table.get_from_uuid(uuid)

            if(row is not None):
                master_index = row.masterListID
                result[rpc_index] = uuid

                break

        # # see if the key has been duplicated on another alpha
        # if(master_index is not None):
        #     for rpc_index in range(self.rpc_count):
        #         alpha_table = CacheTableAlpha(self, rpc_index)

        #         found_uuid = alpha_table.get_from_masterListID(master_index)
        #         if(found_uuid != uuid):
        #             result[rpc_index] = found_uuid

        # result is a key value pair
        # key   - rpc index
        # value - uuid on that rpc
        return result

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
            results.append('Cache Index: %i, Type: %s,  Flags: %s'%(master_key, str(master_row.keytype), str(master_row.flags)))
            for uuid in master_row.uuid_list:
                alpha_index = 'BROKEN'
                for i in xrange(self.rpc_count):
                    if (uuid in alpha_rows[i]):
                        alpha_index = str(i)

                results.append('-> %s in RPC:%s'%(uuid, alpha_index))

        return results

