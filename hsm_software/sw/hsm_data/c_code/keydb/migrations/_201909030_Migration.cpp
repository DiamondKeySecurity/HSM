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

    char sql_table_statement[] =
"ALTER TABLE domainkeys \
ADD COLUMN CKA_COPYABLE BOOLEAN NOT NULL DEFAULT FALSE, \
ADD COLUMN CKA_DESTROYABLE BOOLEAN NOT NULL DEFAULT TRUE, \
ADD COLUMN CKA_START_DATE VARCHAR(8) DEFAULT NULL, \
ADD COLUMN CKA_END_DATE VARCHAR(8) DEFAULT NULL, \
ADD COLUMN CKA_KEY_GEN_MECHANISM INT DEFAULT 0, \
ADD COLUMN CKA_LOCAL BOOLEAN DEFAULT FALSE;";

    stmt.reset(con->createStatement());
    stmt->execute(sql_table_statement);
}

}

}