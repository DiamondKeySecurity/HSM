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

#ifndef CONV_H
#define CONV_H

#include <memory.h>

namespace conv
{
extern int sysBigEndian;

void setIsSysBigEndian(int value);

// bytes are always in big-endian format
inline int intFromBytes(unsigned char *_bytes, int _start)
{
    if (sysBigEndian)
    {
        // system in big endian so just do have some pointer fun
        return *((int *)(&_bytes[_start]));
    }
    else
    {
        // convert to little-endian for the system
        return (_bytes[_start + 3]) +
               (_bytes[_start + 2] << 8) +
               (_bytes[_start + 1] << 16) +
               (_bytes[_start + 0] << 24);
    }
    
}

// bytes are always in big-endian format
inline void intToBytes(int _intValue, unsigned char *_bytes)
{
    if (sysBigEndian)
    {
        // system in big endian so just do have some pointer fun
        memcpy(_bytes, &_intValue, sizeof(int));
    }
    else
    {
        // convert to big-endian because we use network byte order
        _bytes[0] = (_intValue & 0xff000000) >> 24;
        _bytes[1] = (_intValue & 0x00ff0000) >> 16;
        _bytes[2] = (_intValue & 0x0000ff00) >> 8;
        _bytes[3] = _intValue & 0x000000ff;
    }
}

}


#endif