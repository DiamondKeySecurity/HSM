// Copyright(c) 2019  Diamond Key Security, NFP
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2
// of the License only.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, If not, see <https://www.gnu.org/licenses/>.

#include <string>
#include <iostream>

#include "migration_manager.h"
#include "_201908270_InitialMigration.h"

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

namespace diamond_hsm
{
namespace keydb
{

MigrationManager::MigrationManager()
{
    migrations.push_back(std::move(std::unique_ptr<Migration>(new _201906130_InitialMigration())));
}

int MigrationManager::update(std::shared_ptr<sql::Connection> con, std::string schema)
{
    std::unique_ptr<sql::Statement> stmt;
    std::unique_ptr<sql::ResultSet> res;
    std::unique_ptr<sql::PreparedStatement> pstmt;

    try
    {
        con->setSchema(schema);

        // make sure database version table exist
        stmt.reset(con->createStatement());

        stmt->execute("create table if not exists db_migration_details( \
                    id INTEGER PRIMARY KEY CHECK (id = 0), \
                    version INTEGER not null \
                    );");

        res.reset(stmt->executeQuery("SELECT version from db_migration_details where id = 0;"));

        // will return None if DB was just created
        int version = 0;
        int last_migration_version = 0;
        while (res->next())
        {
            version = res->getInt(1);
        }

        // we need to add migrations
        for (auto it = migrations.begin(); it < migrations.end(); ++it)
        {
            last_migration_version = (*it)->version();
            if (version < last_migration_version)
                (*it)->up(con);
        }
        

        // free result and statement objects
        res.reset(NULL);
        stmt.reset(NULL);

        if (version == 0)
        {
            std::cout << "Adding to new table" << std::endl;
            pstmt.reset(con->prepareStatement("INSERT into db_migration_details (id, version) VALUES (?, ?)"));
            pstmt->setInt(1, 0);
            pstmt->setInt(2, last_migration_version);
            pstmt->executeUpdate();
        }
        else if (version < last_migration_version)
        {
            std::cout << "Updating old table" << std::endl;
            pstmt.reset(con->prepareStatement("UPDATE db_migration_details SET version = ? WHERE id = 0;"));
            pstmt->setInt(1, last_migration_version);
            pstmt->executeUpdate();
        }
        else
        {
            std::cout << "table not updated" << std::endl;
        }
        
    }
    catch(sql::SQLException &e)
    {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;

        return 1;
    }


    std::cout << "Mirgation Done" << std::endl;
    return 0;
}

}

}