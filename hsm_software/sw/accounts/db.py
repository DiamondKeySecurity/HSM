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

import sqlite3 as sql
import hashlib
import os.path

from migrations.manager import MigrationManager

class domains(object):
    def __init__(self, id = 0, name = "", domain_key = None, owner_id = None):
        self.id = id
        self.name = name
        self.domain_key = domain_key
        self.owner_id = owner_id


class users(object):
    def __init__(self, id = 0, user_name = "", domain_id = 0, created_at = "", mustchangepw = False):
        self.id = id
        self.user_name = user_name
        self.domain_id = domain_id
        self.created_at = created_at
        self.mustchangepw = mustchangepw

class passwords(object):
    def __init__(self, id = 0, hashed_password = "", salt = "", user_id = ""):
        self.id = id
        self.hashed_password = hashed_password
        self.salt = salt
        self.user_id = user_id

class DBContext(object):
    def __init__(self, dbpath):
        self.dbfile = os.path.join(dbpath, "database.db")

        # make sure the path exist
        try:
            os.makedirs(dbpath)
        except OSError:
            pass

        # make sure the database exist
        MigrationManager().update(self.dbfile)

if __name__ == "__main__":
    domain = DBContext("/home/douglas/Documents/domaintest")