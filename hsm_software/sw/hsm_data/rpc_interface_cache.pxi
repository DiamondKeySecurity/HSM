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

from cython.operator cimport dereference as deref
from libcpp.map cimport map as mapcpp
from libcpp.pair cimport pair
from libcpp.vector cimport vector
from libcpp.string cimport string as stringcpp

from c_uuids cimport uuid_t

cdef class rpc_interface_cache:
    cdef hsm_cache.hsm_cache *c_cache_object

    """ Root cache object that uses dictionaries to store key information"""
    cdef void set_internal(self, hsm_cache.hsm_cache *cache_object):
        self.c_cache_object = cache_object

    def initialize_cache(self):
        deref(self.c_cache_object).initialize_cache()

    def is_initialized(self):
        return deref(self.c_cache_object).is_initialized()

    def get_device_count(self):
        return deref(self.c_cache_object).get_device_count()

    def get_key_count(self, int device_index):
        return deref(self.c_cache_object).get_key_count(device_index)

    def get_master_uuid(self, device_index, device_uuid):
        cdef uuid_t result
        cdef char buffer[40]

        cdef uuid_t c_device_uuid
        c_device_uuid.fromBytes(device_uuid.bytes)

        result = deref(self.c_cache_object).get_master_uuid(device_index, c_device_uuid)

        return uuid.UUID(hex = result.to_string(buffer))

    def get_master_uuid_lowest_index(self, master_uuid):
        cdef uuid_t c_master_uuid
        c_master_uuid.fromBytes(master_uuid.bytes)

        return deref(self.c_cache_object).get_master_uuid_lowest_index(c_master_uuid)

    def add_key_to_alpha(self, rpc_index, uuid, keytype = 0, flags = 0, param_masterListID = None, auto_backup = True):
        cdef uuid_t c_uuid
        cdef uuid_t c_param_masterListID
        if (uuid is not None):
            c_uuid.fromBytes(uuid.bytes)
        if (param_masterListID is not None):
            c_param_masterListID.fromBytes(param_masterListID.bytes)

        deref(self.c_cache_object).add_key_to_device(rpc_index, c_uuid, keytype, flags, c_param_masterListID, auto_backup)

    def get_alpha_lowest_index(self, master_uuid):
        cdef uuid_t c_master_uuid
        cdef pair[int, uuid_t] result

        if (master_uuid is not None):
            c_master_uuid.fromBytes(master_uuid.bytes)

        if(deref(self.c_cache_object).get_device_lowest_index(c_master_uuid, result)):
            return result.first

        return -1

    def get_alphas(self, master_uuid):
        cdef uuid_t c_master_uuid
        cdef mapcpp[int, uuid_t] results
        cdef mapcpp[int, uuid_t].iterator it
        cdef char buffer[40]
        cdef int i

        if (master_uuid is not None):
            c_master_uuid.fromBytes(master_uuid.bytes)

        deref(self.c_cache_object).get_devices(c_master_uuid, results)

        rval = {}

        # convert result to python dictionary
        if (results.size() > 0):
            it = results.begin()
            while (it != results.end()):
                rval[deref(it).first] = uuid.UUID(hex = deref(it).second.to_string(buffer))

        return rval


    def clear(self):
        deref(self.c_cache_object).clear()

    def backup_matching_map(self):
        print 'backing up matching uuids'
        deref(self.c_cache_object).backup_matching_map()

    def backup_tables(self):
        print 'backing up tables'
        deref(self.c_cache_object).backup_tables()

    def backup(self):
        print 'backup'
        deref(self.c_cache_object).backup()

    def getVerboseMapping(self):
        cdef vector[stringcpp] result

        deref(self.c_cache_object).getVerboseMapping(result)

        rval = []

        for i in range(result.size()):
            rval.append(result[i].c_str())

        return rval

cdef _internal_set_cache_variable_(rpc_interface_cache o, hsm_cache.hsm_cache *c_cache_object):
    o.c_cache_object = c_cache_object