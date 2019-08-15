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

#include "_rpc_handler.h"

namespace diamond_hsm
{

rpc_handler::rpc_handler()
{
}

void rpc_handler::unlock_hsm()
{
}

int rpc_handler::device_count()
{
    return 5;
}

int rpc_handler::get_current_rpc()
{
    return 1;
}

void rpc_handler::set_current_rpc(int index)
{
}

}