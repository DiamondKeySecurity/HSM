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

#ifndef RPC_PACKET_H
#define RPC_PACKET_H

#include <stdint.h>
#include <sys/types.h>
#include <memory>
#include <memory.h>

#if DEBUG_LIBHAL
#include <iostream>
#endif

extern "C"
{
#include "hal.h"
#include "xdr_internal.h"
}

namespace libhal
{

class rpc_packet
{
    public:
        rpc_packet()
        :_buf(NULL), _bptr(NULL), _blimit(NULL), _size(0)
        {
        }

        rpc_packet(uint32_t len)
        {
            create(len);
        }

        rpc_packet(rpc_packet &&other)
        {
#if DEBUG_LIBHAL
            std::cout << "rpc packet move" << std::endl;
#endif

            _size = other._size;
            _buf = other._buf;
            _bptr =  other._bptr;
            _blimit = other._blimit;

            other._buf = NULL;
            other._bptr = NULL;
            other._blimit = NULL;
            other._size = 0;
        }

        rpc_packet & operator= ( rpc_packet && other)
        {
            _size = other._size;
            _buf = other._buf;
            _bptr =  other._buf;
            _blimit = other._blimit;

            other._buf = NULL;
            other._bptr = NULL;
            other._blimit = NULL;
            other._size = 0;

            return *this;
        }

        rpc_packet(const rpc_packet &other)
        {
#if DEBUG_LIBHAL
            std::cout << "rpc packet copy" << std::endl;
#endif

            _size = other._size;
            _buf = new uint8_t[_size];
            _bptr = _buf;
            _blimit = _bptr + _size;

            memcpy(_buf, other._buf, _size);
        }

        ~rpc_packet()
        {
            destroy();
        }

        void create(size_t len)
        {
            destroy();
            
            _size = len;
            _buf = new uint8_t[_size];
            _bptr = _buf;
            _blimit = _bptr + _size;
        }

        int create_error_response(uint32_t code, uint32_t client, uint32_t result);

        int createFromSlipEncoded(const char *encoded_buffer);

        int encodeToSlip(char *encoded_result, const int max_len) const;

        uint8_t *buffer() const
        {
            return _buf;
        }
        uint32_t size() const
        {
            return _size;
        }

        hal_error_t encode_int(uint32_t value)
        {
            return hal_xdr_encode_int(&_bptr, _blimit, value);
        }

        hal_error_t decode_int(uint32_t *value)
        {
            return hal_xdr_decode_int((const uint8_t **)&_bptr, _blimit, value);
        }

        hal_error_t decode_int_peak(uint32_t *value)
        {
            return hal_xdr_decode_int_peek((const uint8_t **)&_bptr, _blimit, value);
        }

        hal_error_t decode_int_peak_at(uint32_t *value, size_t pos)
        {
            const uint8_t *ptr = &_buf[pos];
            return hal_xdr_decode_int_peek(&ptr, _blimit, value);
        }

        hal_error_t encode_int_at(uint32_t value, size_t pos)
        {
            uint8_t *ptr = &_buf[pos];
            return hal_xdr_encode_int(&ptr, _blimit, value);
        }

        hal_error_t encode_fixed_opaque(const uint8_t * const value, const size_t len)
        {
            return hal_xdr_encode_fixed_opaque(&_bptr, _blimit, value, len);
        }

        hal_error_t decode_fixed_opaque(uint8_t * const value, const size_t len)
        {
            return hal_xdr_decode_fixed_opaque((const uint8_t **)&_bptr, _blimit, value, len);
        }

        hal_error_t encode_variable_opaque(const uint8_t * const value, const size_t len)
        {
            return hal_xdr_encode_variable_opaque(&_bptr, _blimit, value, len);
        }

        hal_error_t decode_variable_opaque(uint8_t * const value, size_t * const len, const size_t len_max)
        {
            return hal_xdr_decode_variable_opaque((const uint8_t **)&_bptr, _blimit, value, len, len_max);
        }

        void reset_head()
        {
            _bptr = _buf;
        }

    private:
        void destroy()
        {
            delete [] _buf;

            _buf = NULL;
            _bptr = NULL;
            _blimit = NULL;
            _size = 0;
        }

        uint8_t *_buf;
        uint8_t *_bptr;
        uint8_t *_blimit;
        uint32_t _size;

};

}
#endif