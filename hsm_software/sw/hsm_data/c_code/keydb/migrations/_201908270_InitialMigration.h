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

#ifndef _201908270_InitialMigration_H
#define _201908270_InitialMigration_H

#include "migration.h"

#include <memory>
#include <cppconn/driver.h>

namespace diamond_hsm
{
namespace keydb
{

class _201908270_InitialMigration: public Migration
{
    public:
        int version() const
        // Returns integer version of this migration
        {
          // 2019-06-13-0
          return 201908270;
        }

        virtual void up(std::shared_ptr<sql::Connection> con) const;
        // commands to alter and create tables for this version
};

}

}

#endif