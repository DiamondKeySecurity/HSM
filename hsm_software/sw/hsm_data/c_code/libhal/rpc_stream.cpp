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
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#include "rpc_packet.h"
#include "rpc_stream.h"

void rpc_serial_stream::ReadThread()
{
    std::cout << "In read thread" << std::endl;

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
            std::cout << "got data" << std::endl;
            if (hal_slip_recv(buf, &len, HAL_RPC_MAX_PKT_SIZE) == HAL_OK)
            {
                if (len >= 12)
                // all commands must be atleast 12 bytes(the code, the client, and the result)
                {
                    std::cout << "packet read: length == " << len << std::endl;
                    const uint8_t *inbuf = &buf[4];
                    const uint8_t *limit = inbuf + 4;
                    uint32_t client;

                    // get the client handle so we know where to queue the response
                    // first uint32 is code
                    // second is client
                    if(HAL_OK == hal_xdr_decode_int_peek(&inbuf, limit, &client))
                    {
                        std::cout << "got client " << client << std::endl;
                        auto pos = m_queues.find(client); 
                        if (pos != m_queues.end())
                        {
                            // make a packet to hold the response
                            rpc_packet packet(len);

                            memcpy(packet.buffer(), buf, len);

                            // push the packet to the queue
                            m_queues[client]->enqueue(std::move(packet));

                            // remove our reference to the queue
                            m_queues.erase(pos);
                        }
                    }
                }
            }
        }
    }

    std::cout << "finished read thread" << std::endl;
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
{
    if (thread_running)
    {
        throw (int)HAL_ERROR_FORBIDDEN;
    }
}

// destructor
rpc_serial_stream::~rpc_serial_stream()
{
    stop_read_thread();
    if (fd != -1)
    {
        std::cout << "closing stream" << std::endl;
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
hal_error_t rpc_serial_stream::write_packet(const rpc_packet &packet, const uint32_t client, std::shared_ptr<SafeQueue<rpc_packet>> queue)
{
    // add queue to map so the read thread will know where to put it
    m_queues.insert(std::make_pair<>(client, queue));

    // send the packet
    hal_slip_send(packet.buffer(), packet.size());

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

// start -> from Cyptech/libhal/slip.c and Cyptech/libhal/slip_internal.h ----
/* SLIP special character codes
 */
#define END             0300    /* indicates end of packet */
#define ESC             0333    /* indicates byte stuffing */
#define ESC_END         0334    /* ESC ESC_END means END data byte */
#define ESC_ESC         0335    /* ESC ESC_ESC means ESC data byte */

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
    case END:
        check(hal_serial_send_char(ESC));
        check(hal_serial_send_char(ESC_END));
        break;
    case ESC:
        check(hal_serial_send_char(ESC));
        check(hal_serial_send_char(ESC_ESC));
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
    check(hal_serial_send_char(END));

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
    check(hal_serial_send_char(END));

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
    case END:
        if (*len)
            *complete = 1;
        break;
    case ESC:
        esc_flag = 1;
        break;
    default:
        if (esc_flag) {
            esc_flag = 0;
            switch (c) {
            case ESC_END:
                buf_push(END);
                break;
            case ESC_ESC:
                buf_push(ESC);
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

// end   -> from Cyptech/libhal/slip.c and Cyptech/libhal/slip_internal.h ----