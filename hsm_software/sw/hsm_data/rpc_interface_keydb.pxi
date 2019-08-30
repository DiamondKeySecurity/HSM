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
#     key_database.reset(new keydb::keydb("tcp://127.0.0.1:3306", "root", "p@ssw0rd", "rootdomain"));

cdef class rpc_interface_keydb:
    cdef keydb.keydb *c_keydb_object
    cdef str cache_db_path

    """ Root cache object that uses dictionaries to store key information"""
    def __init__(self, cache_db_path):
        self.cache_db_path = cache_db_path

    def connect(self):
        self.c_keydb_object.connect(0,                      # const int keydb_setting_flags
                                    "tcp://127.0.0.1:3306", # const char *dbhostaddr
                                    self.cache_db_path,     # const char *keydb_settings_path
                                    "root",                 # const char *dbuser
                                    "p@ssw0rd"              # const char *dbpw
                                    )

cdef _internal_set_keydb_variable_(rpc_interface_keydb o, keydb.keydb *c_keydb_object):
    o.c_keydb_object = c_keydb_object