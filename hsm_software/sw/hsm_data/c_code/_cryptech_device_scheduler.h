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

#ifndef CRYPTECH_DEVICE_SCHEDULER_H
#define CRYPTECH_DEVICE_SCHEDULER_H

#include "libhal/rpc_packet.h"
#include "libhal/rpc_stream.h"
#include "libhal/safe_queue.h"

namespace diamond_hsm
{

class cyptech_device_scheduler
// creates a single queue that multiple worker threads can pull from.
// Each thread logs into the HSM and runs commands off of it.
// Authentication on RPC is handled by the HSM single-board computer.
// This setup overcomes the CrypTech Alpha's maximum connected clients,
// because all connections share clients.
{
    private:
        struct QueuedData
        {
            
            libhal::rpc_packet *opacket;

            int worker_thread_index;
        };

    public:
        cyptech_device_scheduler();

        ~cyptech_device_scheduler();

        hal_error_t create(const char * const device, const uint32_t speed, const int num_workers,
                           const hal_user_t user, const char *pin);

    private:


};

}
#endif