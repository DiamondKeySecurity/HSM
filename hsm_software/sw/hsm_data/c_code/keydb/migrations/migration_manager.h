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

#ifndef KEYDB_MIGRATION_MANAGER_HEADER
#define KEYDB_MIGRATION_MANAGER_HEADER

#include <string>
#include <vector>
#include <memory>

#include "migration.h"

namespace diamond_hsm
{
namespace keydb
{

class MigrationManager
{
    public:
        MigrationManager();

        int update(std::shared_ptr<sql::Connection> con, std::string schema);

    private:
        std::vector<std::unique_ptr<Migration>> migrations;

};

}

}

#endif