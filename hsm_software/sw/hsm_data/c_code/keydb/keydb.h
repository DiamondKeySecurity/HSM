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
#ifndef KEYDB_HEADER
#define KEYDB_HEADER

#include <string>
#include <cppconn/driver.h>

#include "keydb_shared.h"
#include "keydb_con.h"

namespace diamond_hsm
{
namespace keydb
{

class keydb : keydb_shared
{
    public:
        keydb();

        bool connect(const int keydb_setting_flags,
                     const char *dbhostaddr,
                     const char *keydb_settings_path,
                     const char *dbuser,
                     const char *dbpw);

        keydb_con *getDBCon();

    private:
        std::string get_updated_setting(const char *name, const char *updated_value, const char *settings_file);

        std::string schema;
        std::string dbaddress;
        std::string user;
        std::string pw;

};

}

}
#endif