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
#include "utils.h"
#include "libhal/hal_internal.h"
#include "libhal/rpc_packet.h"

#include <iostream>

#define SLIP_END             0300    /* indicates end of packet */
#define SLIP_ESC             0333    /* indicates byte stuffing */
#define SLIP_ESC_END         0334    /* ESC ESC_END means END data byte */
#define SLIP_ESC_ESC         0335    /* ESC ESC_ESC means ESC data byte */

namespace diamond_hsm
{

int CreatePacketFromSlipEncodedBuffer(libhal::rpc_packet &packet, const char *encoded_buffer)
{
    uint8_t decoded_buffer[HAL_RPC_MAX_PKT_SIZE];

    uint8_t *pdbuf = decoded_buffer;
    const uint8_t *pebuf = (const uint8_t *)encoded_buffer;
    size_t len = 0;

    while (*pebuf != SLIP_END)
    {
        if(*pebuf == SLIP_ESC)
        {
            if(*(++pebuf) == SLIP_ESC_END)
                *(pdbuf++) = SLIP_END;
            else
                *(pdbuf++) = SLIP_ESC;
        }
        else
        {
            *(pdbuf++) = *(pebuf++);
        }
        ++len;

        // no end found. must not be formatted correctly
        if (len == HAL_RPC_MAX_PKT_SIZE)
            return 0;
    }

    packet.create(len);
    memcpy(packet.buffer(), decoded_buffer, len);

    return 1;
}

}