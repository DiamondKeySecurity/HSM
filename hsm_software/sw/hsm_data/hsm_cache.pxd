#!/usr/bin/env python
# Copyright (c) 2018, 2019  Diamond Key Security, NFP
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
from c_uuids cimport uuid_t
from table_rows cimport alpha_table_row, master_table_row
from libcpp.unordered_map cimport unordered_map
from libcpp.map cimport map
from libcpp.pair cimport pair
from libcpp.vector cimport vector
from libcpp.string cimport string

cdef extern from "c_code/_hsm_cache.h" namespace "advanced_cache":
    cdef cppclass HSMCache:
        HSMCache(int rpc_count, const char *cache_folder)
        void initialize_cache()
        bint is_initialized()
        bint get_device_table_rows(int device_index, unordered_map[uuid_t, alpha_table_row] &rows)
        void get_master_table_rows(unordered_map[uuid_t, master_table_row] &rows)
        uuid_t get_master_uuid(int device_index, uuid_t device_uuid)
        int get_master_uuid_lowest_index(uuid_t master_uuid)
        uuid_t add_key_to_device(int device_index, uuid_t device_uuid, unsigned int keytype, unsigned int flags, uuid_t param_masterListID, bint auto_backup)
        void remove_key_from_device(uuid_t master_uuid, map[int, uuid_t] &device_uuids)
        bint get_device_lowest_index(uuid_t master_uuid, pair[int, uuid_t] &result)
        void get_devices(uuid_t master_uuid, map[int, uuid_t] &results)
        void clear()
        void backup_matching_map()
        void backup_tables()
        void backup()
        void getVerboseMapping(vector[string] &result)
        void printdb()
