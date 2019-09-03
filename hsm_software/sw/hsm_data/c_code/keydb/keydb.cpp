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
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include "keydb.h"
#include "migrations/migration_manager.h"

namespace diamond_hsm
{
namespace keydb
{

keydb::keydb()
:schema("rootdomain")
{

}

bool keydb::connect(const int keydb_setting_flags,
                    const char *dbhostaddr,
                    const char *keydb_settings_path,
                    const char *dbuser,
                    const char *dbpw)
{
    std::cout << "keydb::connect" << std::endl;

    std::string settings_file_path(keydb_settings_path);
    settings_file_path += "/keydb.cnf";

    user = get_updated_setting("dbuser", dbuser, settings_file_path.c_str());
    if (user.size() == 0) return false;

    pw   = get_updated_setting("dbpw",   dbpw, settings_file_path.c_str());
    if (pw.size() == 0) return false;

    dbaddress = dbhostaddr;

    try
    {
        // connect to the database and perform any needed updates
        sql::Driver *driver = get_driver_instance();

        std::shared_ptr<sql::Connection> con(driver->connect(dbaddress, user, pw));

        MigrationManager migrations;

        migrations.update(con, schema);
    }
    catch(sql::SQLException &e)
    {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;

        return false;
    }

    return true;
}

keydb_con *keydb::getDBCon()
{
    // connect to the database and perform any needed updates
    sql::Driver *driver = get_driver_instance();

    // create a new db connection
    std::shared_ptr<sql::Connection> con(driver->connect(dbaddress, user, pw));
    con->setSchema(schema);

    return new keydb_con(con, this);
}

std::string keydb::get_updated_setting(const char *name, const char *updated_value, const char *settings_file)
{
    if (updated_value != NULL)
    {
        return updated_value;
    }

    FILE *fp = fopen(settings_file, "rt");

    if (fp != NULL)
    {
        char linebuffer[256];

        while (fgets(linebuffer, sizeof(linebuffer), fp))
        {
            if (strncmp(linebuffer, name, strlen(name)) == 0)
            {
                fclose(fp);

                std::string result(&linebuffer[strlen(name)+1]);

                result.pop_back();

                return result;
            }
        }

        fclose(fp);
    }

    return "";
}
 

}

}
