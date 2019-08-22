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

#ifndef _RPC_ACTION_H
#define _RPC_ACTION_H

#include <memory>
#include <vector>
#include "libhal/rpc_packet.h"

namespace diamond_hsm
{

class rpc_action;
class rpc_handler;

typedef rpc_action *(rpc_handler::*rpc_action_callback)(std::vector<libhal::rpc_packet> &reply_list);

class rpc_action
{
    public:
        // After an RPC has been preprocessed by the load balancer, this class is the
        // result of that operation and tells RPCTCPServer what action to perform
        rpc_action(libhal::rpc_packet *result,
                   std::vector<int> *rpc_list,
                   rpc_action_callback callback,
                   libhal::rpc_packet *request = NULL)
        {
            if (result != NULL)
                result_packet.reset(new libhal::rpc_packet(*result));

            if (rpc_list != NULL)
                this->rpc_list = *rpc_list;

            this->callback = callback;

            if (request != NULL)
                request_packet.reset(new libhal::rpc_packet(*request));
        }

        // result - buffer to immediately send back to the caller
        std::unique_ptr<libhal::rpc_packet> result_packet;

        // rpc_list - if result is None, this is the list of alpha's to send the message to
        std::vector<int> rpc_list;

        // callback - after the rpcs have been sent, this is the callback so the loadbalancer can see the result
        rpc_action_callback callback;

        // packet to send to devices
        std::unique_ptr<libhal::rpc_packet> request_packet;
};

}
#endif