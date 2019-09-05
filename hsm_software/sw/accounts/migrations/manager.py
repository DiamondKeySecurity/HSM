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

from _201906130_InitialMigration import _201906130_InitialMigration

import sqlite3 as sql

class MigrationManager(object):
    def __init__(self):
        self.migrations = []

        self.migrations.append(_201906130_InitialMigration())

    def update(self, dbpath):
        con = sql.connect(dbpath)

        cur = con.cursor()

        # make sure database version table exist
        cur.execute("create table if not exists db_migration_details( \
            id INTEGER PRIMARY KEY CHECK (id = 0), \
            version INTEGER not null \
            );")

        con.commit()

        # get the current version
        cur.execute("SELECT version from db_migration_details where id = 0;")

        # will return None if DB was just created
        version = cur.fetchone()
        if (version is not None):
            version = version[0]

        # we need to add migrations
        for migration in self.migrations:
            if (version is None or version < migration.version()):
                migration.up(con)

        last_migration = self.migrations[-1]

        if (version is None):
            # add row with version
            cur.execute("INSERT into db_migration_details (id, version) VALUES (?, ?)", (0, last_migration.version()))
        elif (version < last_migration.version()):
            # update the version
            cur.execute("UPDATE db_migration_details SET version = ? WHERE id = 0;", (last_migration.version(),))

        con.commit()
        con.close()