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

#include <map>
#include <vector>

namespace diamond_hsm
{
namespace keydb
{

class keydb_connector
{
    public:
        virtual ~keydb_connector() {}

        // returns 1 if the table exists
        virtual int tableExist(std::string table_name) = 0;

        // creates a new table with columns defined in the columns map. A primary key with the name ID should
        // automatically be created in this call without being defined in columns. Text fields default to
        // the std::pair is the SQL type and default value
        virtual int createTable(const std::string table_name, const std::map<std::string, std::pair<std::string, std::string>> &columns) = 0;

        // add columns to an existing table
        // the std::pair is the SQL type and default value
        virtual int addTableColumns(const std::string table_name, const std::map<std::string, std::pair<std::string, std::string>> &columns) = 0;

        // remove columns from an existing table
        virtual int removeTableColumns(const std::string table_name, const std::vector<std::string> &columns) = 0;

        // the std::pair is the SQL type and default value
        virtual int insert_row(const std::map<std::string, std::string> &row) = 0;

        // fetch rows from the database
        virtual int fetch_row(const std::vector<std::string> &columns, std::vector<std::string> values) = 0;
};

}
}