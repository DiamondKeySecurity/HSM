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