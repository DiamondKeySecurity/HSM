#!/usr/bin/env python
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

