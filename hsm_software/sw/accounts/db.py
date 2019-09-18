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

import sqlite3 as sql
import hashlib
import os.path

from threading import Lock

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

        self.conn_lock = Lock()
        self.conn = sql.connect(self.dbfile, check_same_thread=False)

    def __del__(self):
        self.conn.close()

    def authenticate_user(self, username, password, domain):
        # temporary for development
        # TODO: check the database
        with self.conn_lock:
            if (username == 'wheel' and 
                password == 'ilovediamonds' and
                domain == 'ssh'):
                return True
            else:
                return False

if __name__ == "__main__":
    domain = DBContext("/home/douglas/Documents/domaintest")