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

#ifndef INC_ATOMIC_INT_H
#define INC_ATOMIC_INT_H

#include <vector>
#include <atomic>
#include <assert.h>

class inc_atomic_int
// atomic int that can be incremented
{
    public:
        inc_atomic_int()
        :value(0)
        {
        }

        inc_atomic_int(const inc_atomic_int &other)
        {
            value = (int)other.value;
        }

        inc_atomic_int(inc_atomic_int &&other)
        {
            value = (int)other.value;
        }

        int get()
        {
            return value;
        }

        int inc(int amount)
        {
            // value is an std::atomic<int> to there's some overhead in using it
            int v = (value + amount);
            if (v < 0) v = 0;
            value = v;

            return v;
        }

    private:
        std::atomic_int value;
};

#endif