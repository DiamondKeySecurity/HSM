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
#include "_hsm_cache.h"

#include <iostream>

#ifdef WIN32
#include <direct.h>
#define makedir(dir) (_mkdir(dir) == 0)
#else
#include <sys/stat.h>
#define makedir(dir) (mkdir(dir,0777) == 0)
#endif

namespace advanced_cache
{

HSMCache::HSMCache(int rpc_count, const char *_cache_folder)
	:cache_initialized(false), cache_folder(_cache_folder)
{
	// make sure the folder exist
	makedir(cache_folder.c_str());

	// add tables for alphas
	for (int i = 0; i < rpc_count; ++i)
		device_tables.push_back(std::make_unique<BaseDBTable<alpha_table_row>>());
}

// get the master uuid from a device_uuid
uuids::uuid_t HSMCache::get_master_uuid(int device_index, uuids::uuid_t device_uuid)
{
	if (!validate_device_index(device_index)) return uuids::uuid_none;

	try
	{
		alpha_table_row row = device_tables[device_index]->fetch_row(device_uuid);

		return row.masterListID;
	}
	catch (TableException)
	{
		return uuids::uuid_none;
	}
}

// get the lowest device index that the master_uuid has a reference to
int HSMCache::get_master_uuid_lowest_index(uuids::uuid_t master_uuid)
{
	std::pair<int, uuids::uuid_t> lowest_item;
	if (get_device_lowest_index(master_uuid, lowest_item))
	{
		return lowest_item.first;
	}
	else
	{
		return -1;
	}
}

// adds a newly found key to the cache. will add to the alpha table and the master table
// if param_masterListID is None, a new UUID will be generated otherwise, this will
// be added as a duplicate to a key on another alpha
uuids::uuid_t HSMCache::add_key_to_device(int device_index, uuids::uuid_t device_uuid, unsigned int keytype = 0,
	unsigned int flags = 0, uuids::uuid_t param_masterListID = uuids::uuid_none,
	bool auto_backup = true)
{
	if (!validate_device_index(device_index)) return uuids::uuid_none;

	uuids::uuid_t masterListID = uuids::uuid_none;

	if (param_masterListID != uuids::uuid_none)
	{
		// link new uuid to existing key
		try
		{
			master_table_row row = master_table.fetch_row(param_masterListID);

			if (row.uuid_dict.find(device_index) == row.uuid_dict.end())
			{
				row.uuid_dict.insert(std::pair<int, uuids::uuid_t>(device_index, device_uuid));

				master_table.update_row(param_masterListID, row);

				// updates to the mapping must be made right away
				if (auto_backup)
					backup_matching_map();

				masterListID = param_masterListID;
			}
			else
			{
				// TODO: error, master table already has a key for the device index
			}
		}
		catch (TableException)
		{
			// do nothing. the key just isn't in the master table so make a new entry
			// which will be done below
		}
	}

	if (masterListID == uuids::uuid_none)
	{
		// add a new entry to the master table
		// if param_masterListID is not None, we must
		// create an entry in the master table, because
		// this is being reloaded from saved data. if
		// param_masterListID is None, generate a new UUID
		if (param_masterListID == uuids::uuid_none)
			param_masterListID.gen_random();

		masterListID = master_table.add_row(param_masterListID, master_table_row(device_index, device_uuid, keytype, flags));
	}

	device_tables[device_index]->add_row(device_uuid, alpha_table_row(masterListID));

	return masterListID;
}

// removes an entry from all tables based on the master uuid and returns the associated device uuids
void HSMCache::remove_key_from_device(uuids::uuid_t master_uuid, std::map<int, uuids::uuid_t> &device_uuids)
{
	try
	{
		master_table_row row = master_table.fetch_row(master_uuid);

		device_uuids = row.uuid_dict;

		// remove from devices
		for (auto it = device_uuids.begin(); it != device_uuids.end(); ++it)
		{
			try
			{
				device_tables[it->first]->delete_row(it->second);
			}
			catch (TableException)
			{
				// not in table
			}
		}

		// remove from master table
		master_table.delete_row(master_uuid);
	}
	catch (TableException)
	{
		// not in table
	}
}

// get the lowest index device that the master_uuid is on
// Returns information on the alpha with the master_uuid as a tuple.
// The first element is the device index and the second is the device
// uuid. If the master_uuid refers to items on multiple devices,
// the device with the smallest index is returned
bool HSMCache::get_device_lowest_index(uuids::uuid_t master_uuid, std::pair<int, uuids::uuid_t> &result)
{
	try
	{
		master_table_row row = master_table.fetch_row(master_uuid);

		if (row.uuid_dict.size() > 0)
		{
			// maps are ordered so just get the first one
			auto lowest_item = row.uuid_dict.begin();
			result.first = lowest_item->first;
			result.second = lowest_item->second;

			return true;
		}
	}
	catch (TableException)
	{
	}

	return false;
}

// gets a list of the devices that the UUID can be found on
void HSMCache::get_devices(uuids::uuid_t master_uuid, std::map<int, uuids::uuid_t> &results)
{
	try
	{
		master_table_row row = master_table.fetch_row(master_uuid);

		results = row.uuid_dict;
	}
	catch (TableException)
	{
		// don't do anything
	}
}

// clears all tables
void HSMCache::clear()
{
	// clear master table
	master_table.clear();

	// clear device tabkes
	for (auto it = device_tables.begin(); it != device_tables.end(); ++it)
	{
		(*it)->clear();
	}
}

// saves a JSON mapping of all the matching UUIDs in the master table
void HSMCache::backup_matching_map()
{
	std::cout << "backing up matching uuids" << std::endl;

	std::string mapping_path = cache_folder + "/cache_mapping.db";

	// get the rows that we will save
	std::unordered_map<uuids::uuid_t, master_table_row> rows;
	master_table.get_rows(rows);

	// open the file
	std::ofstream file;
	file.open(mapping_path, std::ofstream::out | std::ofstream::trunc);

	if (file.fail())
		return;

	file << "{";

	bool first_row = true;

	for (auto row_it = rows.begin(); row_it != rows.end(); ++row_it)
	{
		if (first_row) first_row = false;
		else file << ",";

		bool first_uuid = true;
		std::map<int, uuids::uuid_t> &uuid_dict = row_it->second.uuid_dict;

		for (auto uuid_it = uuid_dict.begin(); uuid_it != uuid_dict.end(); ++uuid_it)
		{
			if (first_uuid) first_uuid = false;
			else file << ",";

			file << std::endl << "  \"" + static_cast<std::string>(uuid_it->second) + "\": \"";
			file << static_cast<std::string>(row_it->first) << "\"";
		}
	}

	file << std::endl << "}";

	file.close();
}

// saves a copy of all device tables and the master table to JSON files
void HSMCache::backup_tables()
{
	std::cout << "backing up tables" << std::endl;

	std::string master_path = cache_folder + "/cache_master.db";
	master_table.save_table(master_path.c_str());

	for (int device_index = 0; device_index < device_tables.size(); ++device_index)
	{
		char buffer[32];
		snprintf(buffer, 32, "/cache_alpha_%i.db", device_index);
		std::string alpha_path = cache_folder + buffer;

		device_tables[device_index]->save_table(alpha_path.c_str());
	}
}

// saves the tables and the matching map
void HSMCache::backup()
{
	std::cout << "backing up" << std::endl;

	backup_matching_map();
	backup_tables();
}

// returns a list of strings with a list of the keys on all device tables
void HSMCache::getVerboseMapping(std::vector<std::string> &result)
{
	// Return a list of strings with information on the cache and all linked keys
	std::unordered_map<uuids::uuid_t, master_table_row> master_rows;
	master_table.get_rows(master_rows);

	for (auto it = master_rows.begin(); it != master_rows.end(); ++it)
	{
		result.push_back("-----------------------------------------------------");
		char buffer[256], uuid_buffer[40];
		snprintf(buffer, 256, "UUID: %s, Type: %u, Flags: %u",
			     it->first.to_string(uuid_buffer), it->second.keytype, it->second.flags);

		result.push_back(buffer);

		for (auto uuid_it = it->second.uuid_dict.begin(); uuid_it != it->second.uuid_dict.end(); ++uuid_it)
		{
			snprintf(buffer, 256, "-> %s in RPC:%i", uuid_it->second.to_string(uuid_buffer), uuid_it->first);

			result.push_back(buffer);
		}
	}
}

// print verbose mapping to stdout
void HSMCache::printdb()
{
	std::vector<std::string> mapping;

	getVerboseMapping(mapping);

	for (auto it = mapping.begin(); it != mapping.end(); ++it)
	{
		std::cout << *it << std::endl;
	}
}

}