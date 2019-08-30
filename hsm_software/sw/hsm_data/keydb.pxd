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

cdef extern from "c_code/keydb/keydb.h" namespace "diamond_hsm::keydb":
    cdef cppclass keydb:
        keydb()
        bint connect(const int keydb_setting_flags, const char *dbhostaddr, const char *keydb_settings_path, const char *dbuser, const char *dbpw)