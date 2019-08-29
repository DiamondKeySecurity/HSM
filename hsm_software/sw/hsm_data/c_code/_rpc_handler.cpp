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
// #define DEBUG_LIBHAL 1

#if DEBUG_LIBHAL
#include <iostream>
#endif

#include "_rpc_handler.h"

extern "C"
{
#include "libhal/hal.h"
#include "libhal/hal_internal.h"
}

namespace diamond_hsm
{

rpc_handler::rpc_handler(const char *ipaddress)
:current_rpc(-1), hsm_locked(true), c_cache_object(NULL), next_any_device(0), next_any_device_uses(0), function_table(NULL)
{
    // FOR DEBUGGINH
    hsm_locked = false;

    this->ip_address = ipaddress;

    create_function_table();
}

rpc_handler::~rpc_handler()
{
    delete [] function_table;
}

void rpc_handler::set_cache_object(hsm_cache *c_cache_object)
{
    this->c_cache_object = c_cache_object;
}

void rpc_handler::unlock_hsm()
{
    hsm_locked = false;
    for (auto it = rpc_device_states.begin(); it < rpc_device_states.end(); ++it)
    {
        it->unlock_port();
    }
}

bool rpc_handler::is_hsm_locked() const
{
    return (hsm_locked || c_cache_object == NULL || !c_cache_object->is_initialized());
}

int rpc_handler::device_count()
{
    return rpc_list.size();
}

int rpc_handler::get_current_rpc()
{
    return current_rpc;
}

void rpc_handler::set_current_rpc(int index)
{
    current_rpc = index;
}

hal_error_t rpc_handler::sendto_cryptech_device(const libhal::rpc_packet &ipacket,
                                                libhal::rpc_packet &opacket,
                                                const int device_index,
                                                const int session_client_handle,
                                                const uint32_t code,
                                                std::shared_ptr<SafeQueue<libhal::rpc_packet>> queue)
{
    hal_error_t result;
#if DEBUG_LIBHAL
    std::cout << "sending" << std::endl;
#endif
    libhal::rpc_packet packet_to_send(ipacket);
    packet_to_send.encode_int_at(session_client_handle, 4);

    result = this->rpc_list[device_index].write_packet(packet_to_send, session_client_handle);
    if (result != HAL_OK)
        return result;

    uint32_t ocode;

    do
    {
#if DEBUG_LIBHAL
        std::cout << "waiting for queue" << std::endl;
#endif
        queue->dequeue(opacket);

        opacket.decode_int_peak_at(&ocode, 0);

        if(ocode == 0xffffffff)
        {
            return HAL_ERROR_RPC_TRANSPORT;
        }

#if DEBUG_LIBHAL
        std::cout << "Wanted: " << code << " Got: " << ocode << std::endl;
#endif
    } while (ocode != code);
    
    return HAL_OK;
}

int rpc_handler::choose_rpc()
{
    // Simple Heuristic for selecting an alpha RPC channel to use
    const int DEVICE_USES_BEFORE_NEXT = 2;
    int device_count = this->device_count();

    std::unique_lock<std::mutex> lock(choose_any_thread_lock);

    // first try to evenly distribute
    ++next_any_device_uses;
    if(next_any_device_uses > DEVICE_USES_BEFORE_NEXT)
    {
        next_any_device_uses = 0;

        ++next_any_device;

        if(next_any_device >= device_count)
            next_any_device = 0;
    }

    // make sure this has the smallest weight
    // If only one process is using the HSM, next_rpc
    // will probably be ok, but if multiple processes
    // are using the HSM, it's possible that the call
    // may try to use a device that's busy

    // initialize to weight of device
    int device_weight = get_cryptech_device_weight(next_any_device);

    for (int device_index = 0; device_index < device_count; ++device_index)
    {
        // if we find a device with a lower weight, use it
        if (next_any_device != device_index)
        {
            int new_device_weight = get_cryptech_device_weight(device_index);
            if ((new_device_weight+5) < device_weight)
            {
#if DEBUG_LIBHAL
                std::cout << " next_any_device == " << next_any_device;
                std::cout << " device_index == " << device_index;
                std::cout << " device_weight == " << device_weight;
                std::cout << " new_device_weight == " << new_device_weight << std::endl;
#endif
                device_weight = new_device_weight;
                next_any_device = device_index;

                // reset uses
                next_any_device_uses = 0;
            }
        }
    }

    return next_any_device;
}

void rpc_handler::process_incoming_rpc(const libhal::rpc_packet &ipacket, int client, libhal::rpc_packet &opacket)
{
    uint32_t code, incoming_client_handle;

    const uint8_t *decode_ptr = NULL;

    ipacket.decode_int(&code, &decode_ptr);
    ipacket.decode_int(&incoming_client_handle, &decode_ptr);

    auto session_it = sessions.find(client);
    if (session_it != sessions.end())
    {
        std::shared_ptr<MuxSession> session = (*session_it).second;

        int index = (int)code;
        if (index >= first_dks_rpc_index) index += dks_rpc_modifier;

#if DEBUG_LIBHAL
        std::cout << "RPC code received " << code << " handle " << client << std::endl; 
#endif

        (*this.*function_table[index])(code, client, ipacket, session, opacket);

        // set back to caller client handle
        opacket.encode_int_at(incoming_client_handle, 4);
        opacket.reset_head();
// #if DEBUG_LIBHAL
//         std::cout << "sending" << std::endl;
// #endif
//         hal_error_t result = sendto_cryptech_device(ipacket, opacket, 0, client, code, myqueue);
//         if (result != HAL_OK)
//         {
//             opacket.create_error_response(code, incoming_client_handle, result);
//         }
//         else
//         {
//             // set back to caller client handle
//             opacket.encode_int_at(incoming_client_handle, 4);
//             opacket.reset_head();
//         }
    }
    else
    {
        // send error
        opacket.create_error_response(code, incoming_client_handle, (uint32_t)HAL_ERROR_RPC_TRANSPORT);
    }

#if DEBUG_LIBHAL
    std::cout << "out" << std::endl;
#endif
}

void rpc_handler::create_serial_connections(std::vector<std::string> &rpc_list)
{
    for(auto it = rpc_list.begin(); it < rpc_list.end(); ++it)
    {
#if DEBUG_LIBHAL
        std::cout << *it << std::endl;
#endif
        // create the connections to the cryptech devices
        libhal::rpc_serial_stream mystream((*it).c_str(), 921600);
        this->rpc_list.push_back(std::move(mystream));

        // add to the parallel array
        rpc_device_states.push_back(device_state());
    }

    // start listening for reponses from the CrypTech devices
    for(auto it = this->rpc_list.begin(); it < this->rpc_list.end(); ++it)
    {
        (*it).start_read_thread();
    }
}

// creates a session for an incoming connection
void rpc_handler::create_session(uint32_t handle, bool from_ethernet, bool enable_exportable_private_keys)
{
#if DEBUG_LIBHAL
    std::cout << "creating session for " << handle << std::endl;
#endif
    {
        std::unique_lock<std::mutex> session_lock(session_mutex);

        this->sessions[handle] = std::make_shared<MuxSession>(get_current_rpc(), from_ethernet, enable_exportable_private_keys);
    }

    std::shared_ptr<MuxSession> session = sessions[handle];

    for (auto rpc_it = rpc_list.begin(); rpc_it < rpc_list.end(); ++rpc_it)
    {
        (*rpc_it).add_queue(handle, session->myqueue);
    }
}

// deletes a session
void rpc_handler::delete_session(uint32_t handle)
{
#if DEBUG_LIBHAL
    std::cout << "deleting session for " << handle << std::endl;
#endif

    libhal::rpc_packet logout_packet(8);
    logout_packet.encode_int(RPC_FUNC_LOGOUT);
    logout_packet.encode_int(handle);
    logout_packet.reset_head();
 
    for (auto rpc_it = rpc_list.begin(); rpc_it < rpc_list.end(); ++rpc_it)
    {
        // remove response queues because we aren't waiting for the response
        (*rpc_it).remove_queue(handle);

        // log off
        (*rpc_it).write_packet(logout_packet, handle);
    }

    // remove session
    {
        std::unique_lock<std::mutex> session_lock(session_mutex);
        auto it = sessions.find(handle);
        sessions.erase(it);
    }
}

}