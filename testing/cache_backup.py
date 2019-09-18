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
    if (new_uuid in matching_map):
        return matching_map[new_uuid]
                
    return None

def addAlphaData(rpc_index, cache_worker, matching_map, cache_folder):
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
                        new_uuid = uuid.UUID(new_uuid.strip('"{'))

                        if(matching_map is None):
                            # add uuid without matching
                            masterListID = None
                        else:
                            masterListID = findMatchingMasterListID(new_uuid, matching_map, master_rows)

                        cache_worker.add_key_to_alpha(rpc_index, new_uuid, 0, 0, param_masterListID = masterListID)

    except Exception as e:
        print '[exception %s]'%e.message

def loadSavedCache(num_alphas, cache_folder, worker):
    # get the mapping
    try:
        with open('%s/cache_mapping.db'%cache_folder, 'r') as fh:
            base_matching_map = byteify(json.load(fh))

        # convert to UUIDs
        matching_map = {}

        for key, val in base_matching_map.iteritems():
            matching_map[uuid.UUID(key)] = uuid.UUID(val)
    except:
        matching_map = None

    # load complete saved history
    for rpc_index in xrange(num_alphas):
        addAlphaData(rpc_index, worker, matching_map, cache_folder)

def createNewUUIDs(num_alphas, worker):
    # load complete saved history
    for alpha_index in xrange(num_alphas):
        # create new 10 uuids on each alpha
        for _ in xrange(10):
            worker.add_key_to_alpha(alpha_index, uuid.uuid4(), 0, 0, param_masterListID = None)

def buildUUIDCopyList(worker, src_index, dest_index, max_uuids):
    """get a list of uuids to copy from one alpha to another"""

    # this function has been generalized to work on an HSM with n alphas
    master = CacheTableMaster(worker)

    # get a copy of the data that won't be affected if there are changes on another thread
    master_rows = master.get_rows()

    # look through all of the uuids in the source and add them to our list if they don't
    # already have a match

    results = []
    count = 0

    # look through the master list for uuids that have a src uuid, but not a dest uuid
    for row in master_rows.itervalues():
        if (src_index in row.uuid_dict and
            dest_index not in row.uuid_dict):

            results.append(row.uuid_dict[src_index])
            count += 1

        if (count == max_uuids):
            break

    return results

def CopyUUIDs(worker, list_uuid, src_index, dest_index):
    # get the source alpha
    source = CacheTableAlpha(worker, src_index)

    # get a copy of the data that won't be affected if there are changes on another thread
    source_list = source.get_rows()

    for key_uuid in list_uuid:
        # get the masterlistID
        try:
            masterlistID = source_list[key_uuid].masterListID
        except:
            continue

        # copy the KEY
        copy = uuid.uuid4()
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

    loadSavedCache(num_alphas, cache_folder, cache)
    createNewUUIDs(num_alphas, cache)

    synchronize(cache)

    cache.backup()

main()