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

#ifndef _RPC_HANDLER_H
#define _RPC_HANDLER_H

#include <unordered_map>
#include "_uuid.hpp"
#include "libhal/rpc_packet.h"

namespace diamond_hsm
{

class KeyOperationData
{
    public:
        KeyOperationData(int rpc_index, uint32_t handle, uuids::uuid_t uuid)
        {
            this->rpc_index = rpc_index;
            this->handle = handle;
            this->device_uuid = uuid;
        }

        int rpc_index;
        uint32_t handle;
        uuids::uuid_t device_uuid;
};

class KeyHandleDetails
{
    public:
        // Information on the key that a handle points to
        KeyHandleDetails(int rpc_index, uuids::uuid_t uuid)
        {
            this->rpc_index = rpc_index;
            this->uuid = uuid;
        }

        int rpc_index;

        uuids::uuid_t uuid;
};

class MuxSession
{
    public:
        // Simple class for defining the state of a
        // connection to the load balancer
        MuxSession(int rpc_index, /*cache, settings,*/ bool from_ethernet)
        :from_ethernet(from_ethernet),
         cache_generated_keys(true),
         incoming_uuids_are_device_uuids(false),
         current_request(NULL),
         rpc_index(rpc_index),
         cur_hashing_index(0),
         key_op_data(-1, 0, uuids::uuid_none)
        {
            //s = settings.get_setting(HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS)
            this->enable_exportable_private_keys = false;
        }

        // if true, this session was started by a connection from
        // outside the HSM and is not trusted
        bool from_ethernet;

        // should new keys be added to the cache? The synchronizer
        // manually adds keys
        bool cache_generated_keys;

        // if true, all incoming uuids should be treated as device uuids
        bool incoming_uuids_are_device_uuids;

        // complete unencoded request that we're working on
        void *current_request;

        // the current rpc_index to use for this session
        int rpc_index;

        // the index of the rpc that is being used for the
        // initializing hash op
        int cur_hashing_index;

        // dictionary mapping of hash rpc indexes by the hash handle
        std::unordered_map<uint32_t, uint32_t> hash_rpcs;
        
        // dictionary mapping of key rpc indexes by the key handle
        std::unordered_map<uint32_t, KeyHandleDetails> key_rpcs;

        // parameters for the current key operation
        KeyOperationData key_op_data;

        // should exportable private keys be used for this session?
        bool enable_exportable_private_keys;
};

class rpc_handler
{
    public:
        rpc_handler();

        void unlock_hsm();

        int device_count();

        int get_current_rpc();

        void set_current_rpc(int index);

        void process_incoming_rpc(libhal::rpc_packet &ipacket, int client, libhal::rpc_packet &opacket);
};

}

#endif