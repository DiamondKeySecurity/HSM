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