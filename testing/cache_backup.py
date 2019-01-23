#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

"""
This Python script was developed to build new cache functionality. It is used to 
restore a saved cache object to preserve links to matching keys.
"""

import os
import sys
import uuid

sys.path.insert(0, '../')

from hsm_software.sw.hsm_cache_db.alpha import CacheTableAlpha
from hsm_software.sw.hsm_cache_db.cache import CacheDB, CacheTable
from hsm_software.sw.hsm_cache_db.master import CacheTableMaster
from hsm_software.sw.cache import HSMCache

import json

def byteify(input):
    """Converts unicode(2 byte) values stored in a dictionary or string to utf-8"""
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def findMatchingMasterListID(new_uuid, matching_map, master_rows):
    """Uses the matching map to find the masterListID of a matching key"""
    for match in matching_map:
        if(new_uuid in match):
            # we found the row with the new uuid
            for uuid in match:
                # look through the matches to find in master rows
                if (uuid != new_uuid):
                    print 'looking for %s in master rows to match %s'%(uuid, new_uuid)
                    for key, value in master_rows.iteritems():
                        uuid_list = value.uuid_list
                        if(uuid in uuid_list):
                            print 'found %i'%key
                            return key
                
    return None

def addAlphaData(rpc_index, cache_worker, matching_map, first, cache_folder):
    master = CacheTableMaster(cache_worker)
    master_rows = master.get_rows()

    fname = '%s/cache_alpha_%d.db'%(cache_folder, rpc_index)
    print fname

    try:
        with open(fname, 'r') as fh:
            for line in fh:
                if(len(line) > 10):
                    split = line.split(':')
                    if(len(split) > 1):
                        new_uuid = split[0].strip()

                        if(first or matching_map is None):
                            # add uuid without matching
                            masterListID = None
                        else:
                            masterListID = findMatchingMasterListID(new_uuid, matching_map, master_rows)

                        cache_worker.add_key_to_alpha(rpc_index, new_uuid, 0, 0, param_masterListID = masterListID)

    except Exception as e:
        print 'exception %s'%e.message

def loadSavedCache(num_alphas, cache_folder, worker):
    # get the mapping
    try:
        with open('%s/cache_mapping.db'%cache_folder, 'r') as fh:
            matching_map = byteify(json.load(fh))
    except:
        matching_map = None
    
    first = True
    # load complete saved history
    for rpc_index in xrange(num_alphas):
        addAlphaData(rpc_index, worker, matching_map, first, cache_folder)

        first = False

def createNewUUIDs(num_alphas, worker):
    # load complete saved history
    for alpha_index in xrange(num_alphas):
        # create new 10 uuids on each alpha
        for _ in xrange(10):
            worker.add_key_to_alpha(alpha_index, str(uuid.uuid4()), 0, 0, param_masterListID = None)

def buildUUIDCopyList(worker, src_index, dest_index, max_uuids):
    """get a list of uuids to copy from one alpha to another"""

    # this function has been generalized to work on an HSM with n alphas
    source =  CacheTableAlpha(worker, src_index)
    destination = CacheTableAlpha(worker, dest_index)
    master = CacheTableMaster(worker)

    # get a copy of the data that won't be affected if there are changes on another thread
    source_list = source.get_rows()
    destination_list = destination.get_rows()
    master_rows = master.get_rows()

    # look through all of the uuids in the source and add them to our list if they don't
    # already have a match

    results = []
    count = 0

    for key, row in source_list.iteritems():
        masterListID = row.masterListID
        if(masterListID in master_rows):
            master_row = master_rows[masterListID]
            found = False

            # look at the uuids in the master list and see if
            # they match a key in the destination list
            for uuid in master_row.uuid_list:
                if(uuid != key and uuid in destination_list):
                    found = True
            if (not found):
                # if the uuid doesn't match anything in the destination,
                # add it to our results
                count += 1
                results.append(key)
        if (count == max_uuids):
            break

    return results

def CopyUUIDs(worker, list, src_index, dest_index):
    # get the source alpha
    source =  CacheTableAlpha(worker, src_index)

    # get a copy of the data that won't be affected if there are changes on another thread
    source_list = source.get_rows()

    for key_uuid in list:
        # get the masterlistID
        try:
            masterlistID = source_list[key_uuid].masterListID
        except:
            continue

        # copy the KEY
        copy = str(uuid.uuid4())
        worker.add_key_to_alpha(dest_index, copy, 0, 0, param_masterListID = masterlistID)

        print '%s linked to %s'%(copy, key_uuid)

def synchronize(worker):
    list0_1 = buildUUIDCopyList(worker, 0, 1, 150)
    CopyUUIDs(worker, list0_1, 0, 1)

    list1_0 = buildUUIDCopyList(worker, 1, 0, 150)
    CopyUUIDs(worker, list1_0, 1, 0)

def main():
    num_alphas = 2
    cache_folder = '/home/douglas/Documents/CACHE_TEST'

    cache = HSMCache(num_alphas, cache_folder)
    worker = cache.get_cache_object()

    loadSavedCache(num_alphas, cache_folder, worker)
    createNewUUIDs(num_alphas, worker)

    synchronize(worker)

    cache.backup()

main()