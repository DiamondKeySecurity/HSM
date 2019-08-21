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

#ifndef TABLE_ROWS_H
#define TABLE_ROWS_H

#include <map>
#include "_uuid.hpp"

namespace advanced_cache
{

// Represents a row in the cache for a specific alpha
struct alpha_table_row
{
	uuids::uuid_t masterListID;

	alpha_table_row()
	{
	}

	alpha_table_row(uuids::uuid_t masterListID)
		:masterListID(masterListID)
	{
	}

	operator std::string() const
	{
		// buffer to hold uuid
		char uuid_buffer[40];

		// buffer to hold complete string
		char buffer[60];

		sprintf(buffer, "{\"masterListID\":%s}", masterListID.to_string(uuid_buffer));

		return std::string(buffer);
	}
};

// Represents a row in the cache's master key list
struct master_table_row
{
	unsigned int keytype;
	unsigned int flags;

	// use a map because keys are not garunteed to be on all devices
	std::map<int, uuids::uuid_t> uuid_dict;

	master_table_row()
	{

	}

	master_table_row(int key_rpc_index, uuids::uuid_t key_uuid, unsigned int keytype = 0, unsigned int flags = 0)
	{
		// key_rpc_index - index of the CrypTech device that the key with the associated key_uuid is on
		// key_uuid - uuid of the key on the CrypTech deviced defined by key_rpc_index
		// keytype - the key's type (eg. HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE)
		// flags - the flags set in the alpha

		this->keytype = keytype;
		this->flags = flags;
		uuid_dict.insert(std::pair<int, uuids::uuid_t>(key_rpc_index, key_uuid));
	}

	bool containsRPCRef(int rpc_index) const
	{
		return uuid_dict.find() != uuid_dict.end()
	}

	operator std::string() const
	{
		std::string uuid_list_str;

		bool first = true;
		for (auto it = uuid_dict.begin(); it != uuid_dict.end(); ++it)
		{
			if (first) first = false;
			else uuid_list_str += ',';

			char buffer[100]; // oh no, please no buffer overflows
			char uuid_buffer[40];

			std::snprintf(buffer, sizeof(buffer), "\"%i\":\"{%s}\"", it->first, it->second.to_string(uuid_buffer));

			uuid_list_str += buffer;
		}

		char buffer[100]; // oh no, please no buffer overflows
		std::snprintf(buffer, sizeof(buffer), "{ \"keytype\":%u, \"flags\" : %u, \"uuid_list\" : {", keytype, flags);
		std::string result(buffer);

		return result + uuid_list_str + "} }";
	}
};
}
#endif