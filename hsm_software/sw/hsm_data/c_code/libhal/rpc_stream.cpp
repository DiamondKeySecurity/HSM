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

#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#if DEBUG_LIBHAL
#include <iostream>
#endif

#include "rpc_packet.h"
#include "rpc_stream.h"

namespace libhal
{

void rpc_serial_stream::ReadThread()
{
#if DEBUG_LIBHAL
    std::cout << "In read thread" << std::endl;
#endif

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    uint8_t buf[HAL_RPC_MAX_PKT_SIZE];
    size_t len;

    while(thread_running == true)
    {
        if(poll(&pfd, 1, 30 * 1000) < 0) continue;

        if(pfd.revents & POLLIN)
        {
            if (read_until(SLIP_END, buf, &len, HAL_RPC_MAX_PKT_SIZE) == HAL_OK)
            {
                if (len >= 12)
                // all commands must be atleast 12 bytes(the code, the client, and the result)
                {
#if DEBUG_LIBHAL
                    std::cout << "got data" << std::endl;
                    std::cout << "packet read: length == " << len << std::endl;
#endif
                    rpc_packet ipacket;
                    ipacket.createFromSlipEncoded((char *)buf);

                    uint32_t client;

                    // get the client handle so we know where to queue the response
                    // first uint32 is code
                    // second is client
                    if(HAL_OK == ipacket.decode_int_peak_at(&client, 4))
                    {
#if DEBUG_LIBHAL
                        uint32_t result;
                        ipacket.decode_int_peak_at(&result, 8);
                        std::cout << "got client " << client << "; result == " << result << std::endl;
#endif

                        auto pos = m_queues.find(client); 
                        if (pos != m_queues.end())
                        {
#if DEBUG_LIBHAL
                            std::cout << "adding to queue" << std::endl;
#endif

                            // push the packet to the queue
                            m_queues[client]->enqueue(std::move(ipacket));

                            // remove our reference to the queue
                            // m_queues.erase(pos);
                        }
                    }
                }
            }
            else
            {
                thread_running = false;

                // message all waiting threads
                for (auto it = m_queues.begin(); it != m_queues.end(); ++it)
                {
                    // make a packet to hold the response
                    rpc_packet packet(4);
                    packet.encode_int(0xffffffff);

#if DEBUG_LIBHAL
                    std::cout << "adding to queue" << std::endl;
#endif

                    // push the packet to the queue
                    (*it).second->enqueue(std::move(packet));
                }

                // stop on an error
                break;
            }   
        }
    }

    thread_running = false;

#if DEBUG_LIBHAL
    std::cout << "finished read thread" << std::endl;
#endif
}

// construct from serial port address
rpc_serial_stream::rpc_serial_stream(const char * const device, const uint32_t speed)
:fd(-1), thread_running(false)
{
    struct termios tty;
    speed_t termios_speed;

    /*
     * Apparently Linux is too cool to need an atomic mechanism for
     * locking an existing file, so we can't uses O_EXLOCK.  Sigh.
     */

    fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd == -1)
    	throw (int)HAL_ERROR_RPC_TRANSPORT;

    if (flock(fd, LOCK_EX) < 0)
        throw (int)HAL_ERROR_RPC_TRANSPORT;

    if (tcgetattr (fd, &tty) != 0)
	    throw (int)HAL_ERROR_RPC_TRANSPORT;

    switch (speed) {
        case 115200:
            termios_speed = B115200;
        	break;
        case 921600:
            termios_speed = B921600;
            break;
        default:
    	    throw (int)HAL_ERROR_RPC_TRANSPORT;
    }

    cfsetospeed (&tty, termios_speed);
    cfsetispeed (&tty, termios_speed);

    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= (CS8 | CLOCAL | CREAD);

    tty.c_iflag = 0;
    tty.c_oflag = 0;
    tty.c_lflag = 0;

    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr (fd, TCSANOW, &tty) != 0)
	    throw (int)HAL_ERROR_RPC_TRANSPORT;
}

// move constructor to put in a list
rpc_serial_stream::rpc_serial_stream(rpc_serial_stream &&other)
:thread_running(false)
{
    if (other.thread_running)
    {
        throw (int)HAL_ERROR_FORBIDDEN;
    }

    fd = other.fd;

    other.fd = -1;
}

// destructor
rpc_serial_stream::~rpc_serial_stream()
{
    stop_read_thread();
    if (fd != -1)
    {
#if DEBUG_LIBHAL
        std::cout << "closing stream" << std::endl;
#endif
        close(fd);
    }
}

// start a thread to listen 
hal_error_t rpc_serial_stream::start_read_thread()
{
    assert(thread_running == false);

    thread_running = true;

    read_thread = std::thread(&rpc_serial_stream::ReadThread, this);

    return HAL_OK;
}

// stop the read thread
hal_error_t rpc_serial_stream::stop_read_thread()
{
    if(thread_running)
    {
        thread_running = false;

        // wait for the thread to complete
        read_thread.join();
    }

    return HAL_OK;
}

// send packet to the cryptech device and push result to the client's queue
hal_error_t rpc_serial_stream::write_packet(const rpc_packet &packet, const uint32_t client)
{
    if (thread_running)
    {
#if DEBUG_LIBHAL
        std::cout << "write_packet" << std::endl;
#endif
        // send the packet
        hal_slip_send(packet.buffer(), packet.size());

        return HAL_OK;
    }
    else
    {
        return HAL_ERROR_RPC_TRANSPORT;
    }
}

hal_error_t rpc_serial_stream::remove_queue(const uint32_t client)
{
    auto pos = m_queues.find(client); 
    if (pos != m_queues.end())
    {
        m_queues.erase(pos);
    }
    return HAL_OK;
}

hal_error_t rpc_serial_stream::add_queue(const uint32_t client, std::shared_ptr<SafeQueue<rpc_packet>> queue)
{
    // add queue to map so the read thread will know where to put it
    m_queues.insert(std::make_pair<>(client, queue));

    return HAL_OK;
}

// from Cyptech/libhal/rpc_serial.c
hal_error_t rpc_serial_stream::hal_serial_send_char(const uint8_t c)
{
    if (write(fd, &c, 1) != 1)
	return perror("write"), HAL_ERROR_RPC_TRANSPORT;
    return HAL_OK;
}

// from Cyptech/libhal/rpc_serial.c
hal_error_t rpc_serial_stream::hal_serial_recv_char(uint8_t * const c)
{
    if (read(fd, c, 1) != 1)
	return perror("read"), HAL_ERROR_RPC_TRANSPORT;
    return HAL_OK;
}

hal_error_t rpc_serial_stream::read_until(const uint8_t end_char, uint8_t *buf, size_t *len, const size_t max_len)
{
    *len = 0;
    uint8_t c;
    hal_error_t result;

    do
    {
        if(*len == max_len) return HAL_ERROR_RPC_PACKET_OVERFLOW;

        result = hal_serial_recv_char(&c);
        if(result != HAL_OK) return result;
        buf[(*len)++] = c;
    } while (c != end_char);
    
    return HAL_OK;
}

// start -> from Cyptech/libhal/slip.c and Cyptech/libhal/slip_internal.h ----
/* SLIP special character codes)
 */
#ifndef HAL_SLIP_DEBUG
#define HAL_SLIP_DEBUG 0
#endif

#if HAL_SLIP_DEBUG
#include <stdio.h>
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) { hal_log(HAL_LOG_DEBUG, "%s returned %d (%s)", #op, _err_, hal_error_string(_err_)); return _err_; } } while (0)
#else
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) { return _err_; } } while (0)
#endif

/* Send a single character with SLIP escaping.
 */
hal_error_t rpc_serial_stream::hal_slip_send_char(const uint8_t c)
{
    switch (c) {
    case SLIP_END:
        check(hal_serial_send_char(SLIP_ESC));
        check(hal_serial_send_char(SLIP_ESC_END));
        break;
    case SLIP_ESC:
        check(hal_serial_send_char(SLIP_ESC));
        check(hal_serial_send_char(SLIP_ESC_ESC));
        break;
    default:
        check(hal_serial_send_char(c));
    }

    return HAL_OK;
}

/* Send a message with SLIP framing.
 */
hal_error_t rpc_serial_stream::hal_slip_send(const uint8_t * const buf, const size_t len)
{
    /* send an initial END character to flush out any data that may
     * have accumulated in the receiver due to line noise
     */
    check(hal_serial_send_char(SLIP_END));

    /* for each byte in the packet, send the appropriate character
     * sequence
     */
    for (size_t i = 0; i < len; ++i) {
        hal_error_t ret;
        if ((ret = hal_slip_send_char(buf[i])) != HAL_OK)
            return ret;
    }

    /* tell the receiver that we're done sending the packet
     */
    check(hal_serial_send_char(SLIP_END));

    return HAL_OK;
}

/* Receive a single character into a buffer, with SLIP un-escaping
 */
hal_error_t rpc_serial_stream::hal_slip_process_char(uint8_t c, uint8_t * const buf, size_t * const len, const size_t maxlen, int * const complete)
{
#define buf_push(c) do { if (*len < maxlen) buf[(*len)++] = c; } while (0)
    static int esc_flag = 0;
    *complete = 0;
    switch (c) {
    case SLIP_END:
        if (*len)
            *complete = 1;
        break;
    case SLIP_ESC:
        esc_flag = 1;
        break;
    default:
        if (esc_flag) {
            esc_flag = 0;
            switch (c) {
            case SLIP_ESC_END:
                buf_push(SLIP_END);
                break;
            case SLIP_ESC_ESC:
                buf_push(SLIP_ESC);
                break;
            default:
                buf_push(c);
            }
        }
        else {
            buf_push(c);
        }
        break;
    }
    return HAL_OK;
}

hal_error_t rpc_serial_stream::hal_slip_recv_char(uint8_t * const buf, size_t * const len, const size_t maxlen, int * const complete)
{
    uint8_t c;
    check(hal_serial_recv_char(&c));
    return hal_slip_process_char(c, buf, len, maxlen, complete);
}

/* Receive a message with SLIP framing, blocking mode.
 */
hal_error_t rpc_serial_stream::hal_slip_recv(uint8_t * const buf, size_t * const len, const size_t maxlen)
{
    int complete;
    hal_error_t ret;

    while (1) {
	ret = hal_slip_recv_char(buf, len, maxlen, &complete);
	if ((ret != HAL_OK) || complete)
	    return ret;
    }
}

}
// end   -> from Cyptech/libhal/slip.c and Cyptech/libhal/slip_internal.h ----