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

#include <vector>
#include <atomic>
#include <assert.h>

class load_slot
{
    public:
        load_slot()
        :value(0)
        {
        }

        load_slot(const load_slot &other)
        {
            value = (int)other.value;
        }

        load_slot(load_slot &&other)
        {
            value = (int)other.value;
        }

        int get()
        {
            return value;
        }

        int inc(int amount)
        {
            value = value + amount;
            if(value < 0)
                value = 0;
        }

    private:
        std::atomic_int value;
};

class LoadDistribution
// Simple thread-safe class for storing how work
// has been distributed across objects.
{
    public:
        void create(int count)
        {
            assert(m_array.size() == 0);

            for (int i = 0; i < count; ++i)
            {
                m_array.push_back(load_slot());
            }
        }

        void inc(int slot, int amount)
        {
            m_array[slot].inc(amount);
        }

        int get(int slot)
        {
            return m_array[slot].get();
        }

    private:
        std::vector<load_slot> m_array;
};