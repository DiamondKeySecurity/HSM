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
#ifndef UUID_H
#define UUID_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <time.h>
#include <string>

namespace uuids
{

typedef unsigned char byte;
typedef byte *lpbyte;

class uuid_t
{
public:
    uuid_t()
    {
        memset(uuid, 0, sizeof(uuid));
		generate_hash_code();
    }

	uuid_t(const uuid_t &other)
		:uuid_t(other.uuid)
	{
	}

    uuid_t(const byte binary[16])
    {
		// copy the 
        memcpy(uuid, binary, sizeof(uuid));
		generate_hash_code();
	}

    uuid_t(const char *str)
    {
        // sorry for implementing this this way, but it was so easy.
        char temp[3];
        temp[2] = 0;
        int i = 0, j = 0;

        while (*str != 0 && j < 16)
        {
            if ((*str >= '0' && *str <= '9') ||
                (*str >= 'a' && *str <= 'f') ||
                (*str >= 'A' && *str <= 'F'))
            {
                temp[i++] = *str;
                if(i == 2)
                {
                    unsigned int t;
                    sscanf(temp, "%x", &t);
                    uuid[j++] = (char)t;
                    i = 0;
                }
            }
            ++str;
        }

		generate_hash_code();
    }

	void gen_random()
	{
		// generate a random UUID
		static bool seeded = false;

		if (!seeded)
		{
			srand(time(NULL));
			seeded = true;
		}

		// generate a random UUID
		for (int i = 0; i < 16; ++i)
		{
			uuid[i] = rand() % 256;
		}
		generate_hash_code();
	}

    // buffer must be at least 40 characters
    char *to_string(char *buffer) const
    {
        // sorry for implementing this this way, but it was so easy.
        sprintf(buffer, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                (unsigned int)uuid[0],
                (unsigned int)uuid[1],
                (unsigned int)uuid[2],
                (unsigned int)uuid[3],
                (unsigned int)uuid[4],
                (unsigned int)uuid[5],
                (unsigned int)uuid[6],
                (unsigned int)uuid[7],
                (unsigned int)uuid[8],
                (unsigned int)uuid[9],
                (unsigned int)uuid[10],
                (unsigned int)uuid[11],
                (unsigned int)uuid[12],
                (unsigned int)uuid[13],
                (unsigned int)uuid[14],
                (unsigned int)uuid[15]
                );

        return buffer;
    }

    operator std::string () const
    {
        char buffer[40];

        return std::string(to_string(buffer));
    }

	uuid_t &operator =(const uuid_t &b)
	{
		memcpy(uuid, b.uuid, sizeof(uuid));
		generate_hash_code();

		return *this;
	}


	bool operator ==(const uuid_t &b) const
	{
		return memcmp(uuid, b.uuid, sizeof(uuid)) == 0;
	}

	bool operator !=(const uuid_t &b) const
	{
		return !(*this == b);
	}

	std::size_t hash_code() const
	{
		return _hash_code;
	}

private:
	void generate_hash_code()
	{
		// generate a hash and save it because hashing needs to be fast
		std::hash<std::string> hasher;

		_hash_code = static_cast<std::size_t>(hasher(static_cast<std::string>(*this)));
	}

    uint8_t uuid[16];
	std::size_t _hash_code;
};

static uuid_t uuid_none = uuid_t();

}

// custom specialization of std::hash can be injected in namespace std
namespace std
{
	template<> struct hash<uuids::uuid_t>
	{
		typedef uuids::uuid_t argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& uuid) const noexcept
		{
			return uuid.hash_code();
		}
	};

	template<> struct less<uuids::uuid_t>
	{
		bool operator() (const uuids::uuid_t& lhs, const uuids::uuid_t& rhs) const
		{
			return static_cast<std::string>(lhs) < static_cast<std::string>(rhs);
		}
	};
}
#endif