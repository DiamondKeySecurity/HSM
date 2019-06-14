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

from migration import Migration

"""
CREATE TABLE domains
(
  id INTEGER PRIMARY KEY,
  name TEXT,
  domain_key TEXT,
  owner_id INTEGER
);

CREATE TABLE users
(
  id INTEGER PRIMARY KEY,
  user_name TEXT,
  domain_id INTEGER,
  created_at TEXT,
  mustchangepw TEXT,
  FOREIGN KEY (domain_id) REFERENCES domains (id) ON UPDATE SET NULL
);

CREATE TABLE passwords
(
  id INTERGER PRIMARY KEY,
  hashed_password TEXT not null,
  salt TEXT not null,
  user_id INT,
  FOREIGN KEY (user_id) REFERENCES users (id) ON UPDATE SET NULL
);
"""

import sqlite3 as sql

class _201906130_InitialMigration(Migration):
    def version(self):
        """Returns integer version of this migration"""
        # 2019-06-13-0
        return 201906130

    def up(self, con):
        """Sqlite3 commands to alter and create tables for this version"""
        cur = con.cursor()

        cur.execute("""CREATE TABLE domains
                       (
                         id INTEGER PRIMARY KEY,
                         name TEXT,
                         domain_key TEXT,
                         owner_id INTEGER
                    );""")

        cur.execute("""CREATE TABLE users
                       (
                         id INTEGER PRIMARY KEY,
                         user_name TEXT,
                         domain_id INTEGER,
                         created_at TEXT,
                         mustchangepw TEXT,
                         FOREIGN KEY (domain_id) REFERENCES domains (id) ON UPDATE SET NULL
                       );""")

        cur.execute("""CREATE TABLE passwords
                       (
                         id INTERGER PRIMARY KEY,
                         hashed_password TEXT not null,
                         salt TEXT not null,
                         user_id INT,
                         FOREIGN KEY (user_id) REFERENCES users (id) ON UPDATE SET NULL
                       );""")

        con.commit()