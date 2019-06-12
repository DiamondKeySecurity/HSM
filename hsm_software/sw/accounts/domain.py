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

class Domain(object):
    def __init__(self, dbpath, name):
        self.dbpath = os.path.join(dbpath, name)

        # make sure the path exist
        try:
            os.makedirs(self.dbpath)
        except OSError:
            pass

        # make sure the database exist
        con = sql.connect(os.path.join(self.dbpath, "database.db"))
        cur = con.cursor()
        cur.execute("create table if not exists users ( id integer primary key autoincrement, \
username text not null, password blob not null, mustchangepassword interger );")
        con.commit()
        con.close()

    def insertUser(self, username, password):
        con = sql.connect("database.db")
        cur = con.cursor()
        cur.execute("INSERT INTO users (username,password) VALUES (?,?)", (username,password))
        con.commit()
        con.close()

if __name__ == "__main__":
    domain = Domain("/home/douglas/Documents/domaintest", "ssh")