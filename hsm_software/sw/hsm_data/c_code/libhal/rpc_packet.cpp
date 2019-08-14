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
#include "hal_internal.h"
#include "rpc_packet.h"

#include <iostream>

#define SLIP_END             0300    /* indicates end of packet */
#define SLIP_ESC             0333    /* indicates byte stuffing */
#define SLIP_ESC_END         0334    /* ESC ESC_END means END data byte */
#define SLIP_ESC_ESC         0335    /* ESC ESC_ESC means ESC data byte */

namespace libhal
{

int rpc_packet::createFromSlipEncoded(const char *encoded_buffer)
{
    uint8_t decoded_buffer[HAL_RPC_MAX_PKT_SIZE];

    uint8_t *pdbuf = decoded_buffer;
    const uint8_t *pebuf = (const uint8_t *)encoded_buffer;
    size_t len = 0;

    // skip initial SLIP_ENDs if present
    while (*pebuf == SLIP_END) ++pebuf;

    // decode
    while (*pebuf != SLIP_END)
    {
        if(*pebuf == SLIP_ESC)
        {
            ++pebuf;
            if(*pebuf == SLIP_ESC_END)
                *(pdbuf++) = SLIP_END;
            else
                *(pdbuf++) = SLIP_ESC;
            ++pebuf;
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

    create(len);

    memcpy(_buf, decoded_buffer, len);

    uint32_t code;
    uint32_t client;

    decode_int_peak_at(&code, 0);
    decode_int_peak_at(&client, 4);

    std::cout << "RPC Packet: Code == " << code << "; Client == " << client << "; Length == " << len << std::endl;
    
    return 1;
}

int rpc_packet::encodeToSlip(char *encoded_result, const int max_len) const
{
    int olen = 0;

    if (_size > (uint32_t)max_len) return 0; // impossible to fit

    for (uint32_t i = 0; i < _size; ++i)
    {
        if (_buf[i] == SLIP_END)
        {
            encoded_result[olen++] = SLIP_ESC;
            encoded_result[olen++] = SLIP_ESC_END;
        }
        else if (_buf[i] == SLIP_ESC)
        {
            encoded_result[olen++] = SLIP_ESC;
            encoded_result[olen++] = SLIP_ESC_ESC;
        }
        else
        {
            encoded_result[olen++] = _buf[i];
        }

        // overflow
        if (olen == max_len) return 0;
    }

    // end
    encoded_result[olen++] = SLIP_END;

    return olen;
}

}