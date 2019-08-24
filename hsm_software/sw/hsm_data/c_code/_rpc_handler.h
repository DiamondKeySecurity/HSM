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
#include <limits>
#include "_uuid.hpp"
#include "libhal/rpc_packet.h"
#include "libhal/rpc_stream.h"
#include "_hsm_cache.h"
#include "_device_state.h"

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

        KeyHandleDetails(const KeyHandleDetails &other)
        {
            rpc_index = other.rpc_index;
            uuid = other.uuid;
        }

        KeyHandleDetails()
        :rpc_index(-1)
        {
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

class rpc_handler;

typedef void (rpc_handler:: *rpc_handler_func)(const uint32_t code,
                                               const uint32_t session_client_handle,
                                               const libhal::rpc_packet &ipacket,
                                               std::shared_ptr<MuxSession> session,
                                               libhal::rpc_packet &opacket);

class rpc_handler
{
    public:
        rpc_handler(const char *ip_address);
        ~rpc_handler();

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
        void process_incoming_rpc(const libhal::rpc_packet &ipacket, const int client, libhal::rpc_packet &opacket);

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

        int get_cryptech_device_weight(int device_index)
        {
            int weight = -1;
            if (device_index > 0 && device_index < device_count())
            {
                weight = rpc_device_states[device_index].get_busy_factor();
            }

            if (weight < 0) return large_weight;
            else return weight;
        }

        // list of the connected RPC devices
        std::vector<libhal::rpc_serial_stream> rpc_list;

        // parallel array with information on the RPC device states
        std::vector<device_state> rpc_device_states;

        std::unordered_map<uint32_t, std::shared_ptr<MuxSession>> sessions;

        std::mutex session_mutex;

        std::atomic_bool hsm_locked;

        // An external program (Python) controls the life of this object
        hsm_cache *c_cache_object;

        // used when selecting any rpc, attempts to evenly
        // distribute keys across all devices, even when
        // only one thread is being used
        int next_any_device;
        int next_any_device_uses;
        std::mutex choose_any_thread_lock;

        const int large_weight = std::numeric_limits<int>::max();
        const int pkey_op_weight = 1;
        const int pkey_gen_weight = 100;

        // function table for quick calls to rpc handlers
        rpc_handler_func *function_table;

        // handlers and call backs
        void handle_set_rpc(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                            std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_enable_cache_keygen(const uint32_t code, const uint32_t session_client_handle,
                                        const libhal::rpc_packet &ipacket, std::shared_ptr<MuxSession> session,
                                        libhal::rpc_packet &opacket);
        void handle_disable_cache_keygen(const uint32_t code, const uint32_t session_client_handle,
                                         const libhal::rpc_packet &ipacket, std::shared_ptr<MuxSession> session,
                                         libhal::rpc_packet &opacket);
        void handle_use_incoming_device_uuids(const uint32_t code, const uint32_t session_client_handle,
                                              const libhal::rpc_packet &ipacket, std::shared_ptr<MuxSession> session,
                                              libhal::rpc_packet &opacket);
        void handle_use_incoming_master_uuids(const uint32_t code, const uint32_t session_client_handle,
                                              const libhal::rpc_packet &ipacket, std::shared_ptr<MuxSession> session,
                                              libhal::rpc_packet &opacket);
        void handle_rpc_any(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                            std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_all(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                            std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_starthash(const uint32_t code, const uint32_t session_client_handle,
                                  const libhal::rpc_packet &ipacket, std::shared_ptr<MuxSession> session,
                                  libhal::rpc_packet &opacket);
        void handle_rpc_hash(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                             std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_endhash(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_usecurrent(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                   std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_pkeyexport(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                   std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_pkeyopen(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                 std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_pkey(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                             std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_pkeyload(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                 std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_pkeyimport(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                   std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_keygen(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                               std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_pkeymatch(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                  std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_getdevice_ip(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                     std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);
        void handle_rpc_getdevice_state(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                        std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket);

        bool choose_rpc_from_master_uuid(uuids::uuid_t master_uuid, std::pair<int, uuids::uuid_t> &result);
        void update_device_weight(int cryptech_device, int amount);

        void callback_rpc_keygen(const std::vector<libhal::rpc_packet> &reply_list, libhal::rpc_packet &opacket);
        void callback_rpc_pkeymatch(const std::vector<libhal::rpc_packet> &reply_list, libhal::rpc_packet &opacket);

        void create_function_table();
        const int last_cryptech_rpc_index = RPC_FUNC_PKEY_GENERATE_HASHSIG;

        const int first_dks_rpc_index = RPC_FUNC_CHECK_TAMPER;
        const int last_dks_rpc_index = RPC_FUNC_USE_INCOMING_MASTER_UUIDS;

        const int dks_rpc_modifier = (-first_dks_rpc_index + last_cryptech_rpc_index) + 1;

        std::string ip_address;

};

}

#endif