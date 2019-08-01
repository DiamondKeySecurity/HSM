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
#ifndef CACHE_TABLE_H
#define CACHE_TABLE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <ostream>
#include <fstream>
#include <atomic>
#include "_uuid.hpp"

namespace advanced_cache
{

enum TableException
{
	KeyExist = 0,
	KeyNotExist = 1
};

template <class T>
class BaseDBTable
{
	public:
		BaseDBTable()
		:has_unsaved_changes(false)
		{
		}

		// save a table
		bool save_table(const char *fname)
		{
			std::ofstream file;
			file.open(fname, std::ofstream::out | std::ofstream::trunc);

			if(file.fail())
				return false;

			// save to file
			saveToFile(file);

			// saved
			has_unsaved_changes = false;

			file.close();

			return true;
		}

		// add a new row
		uuids::uuid_t add_row(uuids::uuid_t key, T record)
		{
			// get write lock
			std::unique_lock<std::shared_mutex> writelock(_mutex);

			// make sure the key isn't already in the table
			if (key_exist(key))
			{
				// release the write lock
				throw TableException::KeyExist;
			}

			table.insert({ key, record });

			return key;
		}

		// update a record
		void update_row(uuids::uuid_t key, T record)
		{
			// get write lock
			std::unique_lock<std::shared_mutex> writelock(_mutex);

			// make sure the key exist
			if (!key_exist(key))
			{
				// release the write lock
				throw TableException::KeyNotExist;
			}

			table[key] = record;
		}

		// delete a row
		void delete_row(uuids::uuid_t key)
		{
			// get write lock
			std::unique_lock<std::shared_mutex> writelock(_mutex);

			// make sure the key exist
			if (!key_exist(key))
			{
				// release the write lock
				throw TableException::KeyNotExist;
			}

			table.erase(key);
		}

		// get a copy of the entire table
		void get_rows(std::unordered_map<uuids::uuid_t, T> &rows)
		{
			// get a read lock for this table
			std::shared_lock<std::shared_mutex> readlock(_mutex);

			rows = table;
		}

		// get a list of the keys
		void get_keys(std::vector<uuids::uuid_t> &keys)
		{
			// get a read lock for this table
			std::shared_lock<std::shared_mutex> readlock(_mutex);

			// return a list of the keys
			for (auto it = table.begin(); it != table.end(); ++it)
			{
				keys.push_back(it->first);
			}
		}

		// get a row
		T fetch_row(uuids::uuid_t key)
		{
			// get a read lock for this table
			std::shared_lock<std::shared_mutex> readlock(_mutex);

			// make sure the key exist
			if (!key_exist(key))
			{
				// release the read lock
				throw TableException::KeyNotExist;
			}

			T result = table[key];

			return result;
		}

		void clear()
		{
			// get write lock
			std::unique_lock<std::shared_mutex> writelock(_mutex);

			table.clear();
		}

	private:
		// get a read lock and save to a file
		void saveToFile(std::ostream &os)
		{
			// get a read lock for this table
			std::shared_lock<std::shared_mutex> readlock(_mutex);

			os << "[" << std::endl;

			bool first = true;

			for (auto& x : table) {
				if (first) first = false;
				else os << "," << std::endl;

				os << "{ \"" << static_cast<std::string>(x.first) << "\" : " << static_cast<std::string>(x.second) << "}";
			}

			os << std::endl << "]" << std::endl;
		}

		// helper to see if the key exist in the table
		bool key_exist(uuids::uuid_t &uuid)
		{
			return (table.find(uuid) != table.end());
		}

		// private data
		std::unordered_map <uuids::uuid_t, T> table;
		std::shared_mutex _mutex;

		std::atomic<bool> has_unsaved_changes;

};

}
#endif