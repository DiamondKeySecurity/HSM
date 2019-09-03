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
#ifndef KEYDB_CON_HEADER
#define KEYDB_CON_HEADER

#include <string>
#include <memory>

#include <cppconn/driver.h>

#include "../libhal/hal.h"
#include "../libhal/rpc_packet.h"
#include "../_uuid.hpp"

namespace diamond_hsm
{
namespace keydb
{

class keydb_shared;

class keydb_con
{
    public:
        keydb_con(std::shared_ptr<::sql::Connection> con, const keydb_shared *shared_data);

        hal_error_t add_key(const uuids::uuid_t master_uuid, const uint32_t key_type, const uint32_t key_flags, const uint32_t curve);

        hal_error_t get_key_id(const uuids::uuid_t master_uuid, uint32_t &id);

        hal_error_t parse_set_keyattribute_packet(const uuids::uuid_t master_uuid, const libhal::rpc_packet &ipacket);

    private:
        std::shared_ptr<::sql::Connection> con;

        const keydb_shared *shared_data;
};

}

}
#endif