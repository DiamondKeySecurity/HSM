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

#include <atomic>
#include "_inc_atomic_int.h"

namespace diamond_hsm
{

enum CrypTechDeviceState
{
    HSMLocked,
    HSMReady,
    KEYGen,
    BUSY,
    HSMNotReady,
    FAILED,
    TAMPER,
    TAMPER_RESET,
};

class device_state
{
    private:
        std::atomic<CrypTechDeviceState> state;
        inc_atomic_int count;

    public:
        // Provides basic information on an HSM that's needed by the load balancer
        device_state()
        :state(HSMLocked)
        {
        }

        device_state(device_state &&other)
        {
            state = (CrypTechDeviceState)other.state;
            count.inc(other.count.get());
        }

        const char *GetStateString() const
        {
            switch(state)
            {
                case HSMLocked:
                    return "The HSM must be unlocked. Please login using the setup console.";
                case HSMReady:
                    return "Active - Ready";
                case KEYGen:
                    return "Active - Generating a key";
                case BUSY:
                    return "Active - Busy";
                case HSMNotReady:
                    return "Device not ready";
                case FAILED:
                    return "Device failure. Try restarting the HSM.";
                case TAMPER_RESET:
                    return "WARNING - A tamper event has stopped. Please check the HSM and restart it.";
                default:
                    return "ERROR - Tamper detected";
            }
        }

        int get_busy_factor()
        {
            // Returns a number that show how busy the HSM is by the number of operations happening on it"""
            if(state == HSMLocked || state == HSMNotReady || state == TAMPER || state == FAILED)
            {
                // this port can't be used
                return -1;
            }

            int count = this->count.get();

            // key gen's are weighty
            if (state == KEYGen)
                count += 100;

            return count;
        }

        void inc_busy_count(int amount)
        {
            count.inc(amount);
        }

        void change_state(CrypTechDeviceState new_state)
        {
            // Switches to any state as long as the current state is not tamper
            if(state != TAMPER)
                state = new_state;
        }

        void unlock_port()
        {
            // If the port is locked, set it to ready
            if(state == HSMLocked || state == TAMPER_RESET)
                state = HSMReady;
        }

        void clear_tamper(CrypTechDeviceState new_state)
        {
            // change the state, clearing tamper if set
            if (state == TAMPER)
                state = new_state;
        }
};

}