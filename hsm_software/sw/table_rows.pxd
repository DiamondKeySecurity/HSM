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
from libcpp.map cimport map
from libcpp.string cimport string

cdef extern from "c_code/_table_rows.h" namespace "advanced_cache":
    cdef cppclass alpha_table_row:
        uuid_t masterListID
        alpha_table_row()
        alpha_table_row(uuid_t masterListID)
        string operator () const

    cdef cppclass master_table_row:
        unsigned int keytype
        unsigned int flags
        map[int, uuid_t] uuid_dict
        master_table_row()
        master_table_row(int key_rpc_index, uuid_t key_uuid, unsigned int keytype, unsigned int flags)
        string operator () const
