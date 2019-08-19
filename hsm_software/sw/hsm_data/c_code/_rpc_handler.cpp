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
#define DEBUG_LIBHAL 1

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
    return 0;
}

void rpc_handler::set_current_rpc(int index)
{
}

void rpc_handler::process_incoming_rpc(libhal::rpc_packet &ipacket, int client, libhal::rpc_packet &opacket)
{
    uint32_t code, incoming_client_handle, ocode;

    ipacket.decode_int(&code);
    ipacket.decode_int(&incoming_client_handle);

    auto session_it = sessions.find(client);
    if (session_it != sessions.end())
    {
        std::shared_ptr<MuxSession> session = (*session_it).second;
        std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

        // add our client id
        ipacket.encode_int_at(client, 4);
        ipacket.reset_head();

#if DEBUG_LIBHAL
        std::cout << "sending" << std::endl;
#endif
        this->rpc_list[0].write_packet(ipacket, client);

        do
        {
#if DEBUG_LIBHAL
            std::cout << "waiting for queue" << std::endl;
#endif
            myqueue->dequeue(opacket);

            opacket.decode_int_peak_at(&ocode, 0);

            if(ocode == 0xffffffff)
            {
                opacket.create_error_response(code, client, (uint32_t)HAL_ERROR_RPC_TRANSPORT);
                ocode = code;
            }

#if DEBUG_LIBHAL
            std::cout << "Wanted: " << code << " Got: " << ocode << std::endl;
#endif
        } while(ocode != code);

        // set back to caller client handle
        opacket.encode_int_at(incoming_client_handle, 4);
        opacket.reset_head();
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

        libhal::rpc_serial_stream mystream((*it).c_str(), 921600);
        this->rpc_list.push_back(std::move(mystream));
    }

    for(auto it = this->rpc_list.begin(); it < this->rpc_list.end(); ++it)
    {
        (*it).start_read_thread();
    }
}

// creates a session for an incoming connection
void rpc_handler::create_session(uint32_t handle, bool from_ethernet)
{
#if DEBUG_LIBHAL
    std::cout << "creating session for " << handle << std::endl;
#endif
    {
        std::unique_lock<std::mutex> session_lock(session_mutex);

        this->sessions[handle] = std::make_shared<MuxSession>(get_current_rpc(),/*cache, settings,*/ from_ethernet);
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