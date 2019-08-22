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

#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include "_uuid.hpp"
#include "libhal/rpc_packet.h"
#include "libhal/rpc_stream.h"
#include "_hsm_cache.h"

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
        MuxSession(int _rpc_index, /*cache*/ bool _from_ethernet, bool _enable_exportable_private_keys)
        :from_ethernet(_from_ethernet),
         cache_generated_keys(true),
         incoming_uuids_are_device_uuids(false),
         current_request(NULL),
         rpc_index(_rpc_index),
         cur_hashing_index(0),
         key_op_data(-1, 0, uuids::uuid_none),
         enable_exportable_private_keys(_enable_exportable_private_keys),
         myqueue(new SafeQueue<libhal::rpc_packet>())
        {
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

        // queue to retrieve packet from stream
        std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue;
};

class rpc_handler
{
    public:
        rpc_handler();

        // uses list of serial device addresses to create serial connections
        void create_serial_connections(std::vector<std::string> &rpc_list);

        // unlocks the hsm
        void unlock_hsm();

        // returns the number of connected devices
        int device_count();

        // returns the currently set rpc index
        int get_current_rpc();

        // sets the current rpc
        void set_current_rpc(int index);

        // sets the cache object
        void set_cache_object(hsm_cache *c_cache_object);

        // processes an incoming packet
        void process_incoming_rpc(libhal::rpc_packet &ipacket, int client, libhal::rpc_packet &opacket);

        // creates a session for an incoming connection
        void create_session(uint32_t handle, bool from_ethernet, bool enable_exportable_private_keys);

        // deletes a session
        void delete_session(uint32_t handle);

        // is the HSM locked
        bool is_hsm_locked() const;

    private:
        // processes an incoming packet
        hal_error_t sendto_cryptech_device(const libhal::rpc_packet &ipacket,
                                           libhal::rpc_packet &opacket, 
                                           const int device_index,
                                           const int session_client_handle,
                                           const uint32_t code,
                                           std::shared_ptr<SafeQueue<libhal::rpc_packet>> queue);

        int choose_rpc();

        std::vector<libhal::rpc_serial_stream> rpc_list;
        std::unordered_map<uint32_t, std::shared_ptr<MuxSession>> sessions;

        std::mutex session_mutex;

        std::atomic_bool hsm_locked;

        // An external program (Python) controls the life of this object
        hsm_cache *c_cache_object;
};

}

#endif