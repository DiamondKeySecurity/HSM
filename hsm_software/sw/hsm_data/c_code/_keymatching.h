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

#ifndef _RPC_KEY_MATCHING_H
#define _RPC_KEY_MATCHING_H

#include <memory>
#include <vector>
#include "libhal/hal_internal.h"
#include "libhal/rpc_packet.h"
#include "_uuid.hpp"

namespace diamond_hsm
{

class KeyAttribute
{
    public:
        KeyAttribute()
        :key(0), bytes_len(0), bytes(NULL)
        {

        }

        ~KeyAttribute()
        {
            delete [] bytes;
        }

        hal_error_t unpack(const libhal::rpc_packet &ipacket, uint8_t **ptr)
        {
            ipacket.decode_int(&key, ptr);
            ipacket.decode_int_peak(&bytes_len);

            size_t actual_len;

            bytes = new uint8_t[bytes_len];
            ipacket.decode_variable_opaque(bytes, &actual_len, bytes_len, ptr);

            if (actual_len != bytes_len) return HAL_ERROR_BAD_ATTRIBUTE_LENGTH;
        }

        hal_error_t pack(libhal::rpc_packet opacket) const
        {
            opacket.encode_int(key);
            opacket.encode_variable_opaque(bytes, bytes_len);
        }

        uint32_t key;

        uint32_t bytes_len;
        uint8_t *bytes;
};

class KeyMatchResult
{
    public:
        KeyMatchResult()
            :code(0), 
             client(0), 
             result(0), 
             pkcs11_session(0)
        {
        }

        void build_result_packet(const int result_max, libhal::rpc_packet &opacket)
        {
            // create maximum size packet to shrink later
            opacket.create(HAL_RPC_MAX_PKT_SIZE);

            // generate complete response
            opacket.encode_int(code);
            opacket.encode_int(client);
            opacket.encode_int(result);
            opacket.encode_int(pkcs11_session);

            // don't return more than the max
            int count = uuid_list.size();
            if(count > result_max)
                count = result_max;
        
            opacket.encode_int(count);
            for (int i = 0; i < count; ++i)
            {
                opacket.encode_variable_opaque(uuid_list[i].bytes(), 16);
            }

            opacket.shrink_to_fit();
        }

        uint32_t code;
        uint32_t client;
        uint32_t result;
        uint32_t pkcs11_session;
        std::vector<uuids::uuid_t> uuid_list;
};

class KeyMatchDetails
{
    public:
        KeyMatchDetails()
        :rpc_index(0),
         pkcs11_session(0),
         type(0),
         curve(0),
         mask(0),
         flags(0),
         status(0),
         result_max(0)
        {
        }

        hal_error_t unpack(const libhal::rpc_packet &ipacket)
        {
            const size_t pkcs11_session_pos = 8;

            uint8_t *ptr = NULL;
            // skip code and client
            ipacket.decode_start(pkcs11_session_pos, &ptr);

            // consume pkcs11 session id
            ipacket.decode_int(&pkcs11_session, &ptr);

            // consume type
            ipacket.decode_int(&type, &ptr);

            // consume curve
            ipacket.decode_int(&curve, &ptr);

            // consume mask
            ipacket.decode_int(&mask, &ptr);

            // consume flags
            ipacket.decode_int(&flags, &ptr);

            // consume attributes
            uint32_t attr_len;
            ipacket.decode_int(&attr_len, &ptr);
            for (uint32_t i = 0; i < attr_len; ++i)
            {
                attributes.push_back(KeyAttribute());
                hal_error_t r = attributes[i].unpack(ipacket, &ptr);

                if (r != HAL_OK) return r;
            }

            // consume status
            ipacket.decode_int(&status, &ptr);

            // max uuid's requested
            ipacket.decode_int(&result_max, &ptr);

            // get the new uuid
            uint8_t uuid_buffer[16];
            size_t incoming_len;
            ipacket.decode_variable_opaque(uuid_buffer, &incoming_len, sizeof(uuid_buffer), &ptr);
            uuid.fromBytes((char*)uuid_buffer);

            return HAL_OK;
        }

        hal_error_t repack(const uint32_t code, const uint32_t client, libhal::rpc_packet &opacket)
        {
            // create maximum size packet to shrink later
            opacket.create(HAL_RPC_MAX_PKT_SIZE);
            
            // generate complete response
            opacket.encode_int(code);
            opacket.encode_int(client);

            // repack altered data
            opacket.encode_int(pkcs11_session);

            // pack type
            opacket.encode_int(type);

            // pack curve
            opacket.encode_int(curve);

            // pack mask
            opacket.encode_int(mask);

            // pack flags
            opacket.encode_int(flags);

            // pack attributes
            opacket.encode_int((uint32_t)attributes.size());
            for (auto it = attributes.begin(); it < attributes.end(); ++it)
            {
                it->pack(opacket);
            }

            // consume status
            opacket.encode_int(status);

            // max uuid's requested
            opacket.encode_int(result_max);

            // get the new uuid
            opacket.encode_variable_opaque(uuid.bytes(), 16);

            opacket.shrink_to_fit();
        }

        int rpc_index;

        // pkcs11 session id
        uint32_t pkcs11_session;

        // type
        uint32_t type;

        // curve
        uint32_t curve;

        // mask
        uint32_t mask;

        // flags
        uint32_t flags;

        // attributes
        std::vector<KeyAttribute> attributes;

        // status
        uint32_t status;

        // max uuid's requested
        uint32_t result_max;

        // get the new uuid
        uuids::uuid_t uuid;
};

}

#endif