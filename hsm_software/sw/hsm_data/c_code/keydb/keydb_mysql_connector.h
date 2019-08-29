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
#include "keydb_connector.h"

namespace diamond_hsm
{
namespace keydb
{

class keydb_mysql_connector
{
    public:
        keydb_mysql_connector(std::string address, std::string db, std::string user, std::string password);
        ~keydb_mysql_connector();

        // returns 1 if the table exists
        int tableExist(std::string table_name);

        // creates a new table with columns defined in the columns map. A primary key with the name ID should
        // automatically be created in this call without being defined in columns. Text fields default to
        // the std::pair is the SQL type and default value
        int createTable(const std::string table_name, const std::map<std::string, std::pair<std::string, std::string>> &columns);

        // add columns to an existing table
        // the std::pair is the SQL type and default value
        int addTableColumns(const std::string table_name, const std::map<std::string, std::pair<std::string, std::string>> &columns);

        // remove columns from an existing table
        int removeTableColumns(const std::string table_name, const std::vector<std::string> &columns);

        // the std::pair is the SQL type and default value
        int insert_row(const std::map<std::string, std::string> &row);

        // fetch rows from the database
        int fetch_row(const std::vector<std::string> &columns, std::vector<std::string> values);
};

}
}