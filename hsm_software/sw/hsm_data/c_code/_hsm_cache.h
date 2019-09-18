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

#ifndef HSM_CACHE_H
#define HSM_CACHE_H

#include <atomic>
#include <map>

#include "_base_db_table.h"
#include "_table_rows.h"

namespace diamond_hsm
{

class hsm_cache
{
	public:
		hsm_cache(int rpc_count, const char *cache_folder);

		const char *get_cache_folder() const
		{
			return cache_folder.c_str();
		}

		// set the cache initialized variable
		void initialize_cache()
		{
			cache_initialized = true;
		}

		// get the cache initialized variable
		bool is_initialized() const 
		{
			return cache_initialized;
		}

    	int get_device_count() const
		{
			return device_tables.size();
		}

		int get_key_count(int device_index) const
		{
			if (device_index < 0 || device_index >= get_device_count())
				return -1;

			return device_tables[device_index]->get_row_count();
		}

		// get all the table rows from the device table cache
		bool get_device_table_rows(int device_index, std::unordered_map<uuids::uuid_t, alpha_table_row> &rows)
		{
			if (!validate_device_index(device_index)) return false;

			device_tables[device_index]->get_rows(rows);

			return true;
		}

		// get all the table rows from the master table cache
		void get_master_table_rows(std::unordered_map<uuids::uuid_t, master_table_row> &rows)
		{
			master_table.get_rows(rows);
		}

		// get the master uuid from a device_uuid
		uuids::uuid_t get_master_uuid(int device_index, uuids::uuid_t device_uuid);

		// get the lowest device index that the master_uuid has a reference to
		int get_master_uuid_lowest_index(uuids::uuid_t master_uuid);

		// adds a newly found key to the cache. will add to the alpha table and the master table
		// if param_masterListID is None, a new UUID will be generated otherwise, this will
		// be added as a duplicate to a key on another alpha
		uuids::uuid_t add_key_to_device(int device_index, uuids::uuid_t device_uuid, unsigned int keytype = 0,
	                                    unsigned int flags = 0, uuids::uuid_t param_masterListID = uuids::uuid_none,
	                                    bool auto_backup = true);

		bool remove_key_from_device_only(int device_index, uuids::uuid_t device_uuid);

		// removes an entry from all tables based on the master uuid and returns the associated device uuids
		void remove_key_from_device(uuids::uuid_t master_uuid, std::map<int, uuids::uuid_t> &device_uuids);

		// get the lowest index device that the master_uuid is on
		// Returns information on the alpha with the master_uuid as a tuple.
		// The first element is the device index and the second is the device
		// uuid. If the master_uuid refers to items on multiple devices,
		// the device with the smallest index is returned
		bool get_device_lowest_index(uuids::uuid_t master_uuid, std::pair<int, uuids::uuid_t> &result);

		// gets a list of the devices that the UUID can be found on
		void get_devices(uuids::uuid_t master_uuid, std::map<int, uuids::uuid_t> &results);
	
		// clears all tables
		void clear();

		// saves a JSON mapping of all the matching UUIDs in the master table
		void backup_matching_map();

		// saves a copy of all device tables and the master table to JSON files
		void backup_tables();

		// saves the tables and the matching map
		void backup();

		// returns a list of strings with a list of the keys on all device tables
		void getVerboseMapping(std::vector<std::string> &result);

		// print verbose mapping to stdout
		void printdb();

	private:
		BaseDBTable<master_table_row> master_table;
		std::vector<std::unique_ptr<BaseDBTable<alpha_table_row>>> device_tables;

		std::atomic_bool cache_initialized;
		std::string cache_folder;

		bool validate_device_index(int device_index)
		{
			return (device_index >= 0 || device_index < (int)device_tables.size());
		}
};

}
#endif