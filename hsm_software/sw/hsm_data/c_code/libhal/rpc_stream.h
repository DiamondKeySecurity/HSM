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

#ifndef RPC_SERIAL_STREAM_H
#define RPC_SERIAL_STREAM_H

#include <stdint.h>
#include <sys/types.h>
#include <memory>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>

#include "rpc_packet.h"
#include "safe_queue.h"

extern "C"
{
#include "hal.h"
#include "hal_internal.h"
#include "xdr_internal.h"
}

namespace libhal
{

class rpc_serial_stream
{
    public:
        // construct from serial port address
        rpc_serial_stream(const char * const device, const uint32_t speed);

        // move constructor
        rpc_serial_stream(rpc_serial_stream &&other);

        // destructor
        ~rpc_serial_stream();

        // start a thread to listen 
        hal_error_t start_read_thread();

        // stop the read thread
        hal_error_t stop_read_thread();

        // send packet to the cryptech device and push result to the client's queue
        hal_error_t write_packet(const rpc_packet &packet, const uint32_t client);

        hal_error_t add_queue(const uint32_t client, std::shared_ptr<SafeQueue<rpc_packet>> queue);
        hal_error_t remove_queue(const uint32_t client);

        bool isOpen() const
        {
            return thread_running;
        }

    private:
        void ReadThread();

        hal_error_t read_until(const uint8_t end_char, uint8_t *buf, size_t *len, const size_t max_len);

        // from Cyptech/libhal/rpc_serial.c
        hal_error_t hal_serial_send_char(const uint8_t c);
        hal_error_t hal_serial_recv_char(uint8_t * const c);

        // from Cyptech/libhal/slip.c and Cyptech/libhal/slip_internal.h
        hal_error_t hal_slip_send_char(const uint8_t c);
        hal_error_t hal_slip_send(const uint8_t * const buf, const size_t len);
        hal_error_t hal_slip_process_char(uint8_t c, uint8_t * const buf, size_t * const len, const size_t maxlen, int * const complete);
        hal_error_t hal_slip_recv_char(uint8_t * const buf, size_t * const len, const size_t maxlen, int * const complete);
        hal_error_t hal_slip_recv(uint8_t * const buf, size_t * const len, const size_t maxlen);

        // queues to send responses to
        std::unordered_map<uint32_t, std::shared_ptr<SafeQueue<rpc_packet>>> m_queues;

        // serial connection
        int fd;

        // the read thread
        std::thread read_thread;

        std::atomic_bool thread_running;

        std::mutex queue_mutex;
        std::mutex serial_write_mutex;

        // only the read thread reads from serial so we don't need a read mutex
};

}
#endif