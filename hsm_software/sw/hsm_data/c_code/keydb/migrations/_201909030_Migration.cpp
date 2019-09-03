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

#include "_201909030_Migration.h"
#include <string>

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>


namespace diamond_hsm
{
namespace keydb
{

void _201909030_Migration::up(std::shared_ptr<sql::Connection> con) const
// commands to alter and create tables for this version
{
    std::unique_ptr<sql::Statement> stmt;
    std::unique_ptr<sql::ResultSet> res;

    char sql_table_statement1[] =
"ALTER TABLE domainkeys \
ADD CKA_COPYABLE BOOLEAN NOT NULL DEFAULT FALSE;";

    char sql_table_statement2[] =
"ALTER TABLE domainkeys \
ADD CKA_DESTROYABLE BOOLEAN NOT NULL DEFAULT TRUE;";

    stmt.reset(con->createStatement());
    stmt->execute(sql_table_statement1);
    stmt->execute(sql_table_statement2);
}

}

}