#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.


import hsm_tools.cryptech.muxd

from hsm_tools.threadsafevar import ThreadSafeVariable
from hsm_tools.observerable import observable
from hsm_tools.stoppable_thread import stoppable_thread
from hsm_tools.hsm import PFUNIX_HSM
from hsm_tools.cryptech_port import DKS_HALError

import time

class TamperDetector(observable, PFUNIX_HSM):
    def __init__(self, sockname, rpc_count):
        observable.__init__(self)
        PFUNIX_HSM.__init__(self, sockname)

        self.tamper_event_detected = ThreadSafeVariable(False)
        self.detection_enabled = ThreadSafeVariable(False)
        self.last_rpc_tamper_status = [ThreadSafeVariable(False) for _ in range(rpc_count)]

        self.rpc_count = rpc_count

        print('tamper rpc')

    def enable(self):
        self.detection_enabled.value = True

    def dowork(self, hsm):
        for rpc_index in xrange(self.rpc_count):
            for _ in xrange(15):
                time.sleep(1)

                # if there's been a tamper event, inform the rest of the application every second
                if (self.tamper_event_detected.value is True):
                    self.on_tamper()

            # after at least 15 seconds, ask the HSM if it's in tamper
            if (not self.last_rpc_tamper_status[rpc_index].value and self.detection_enabled.value):
                hsm.rpc_set_device(rpc_index)
                if (hsm.rpc_check_tamper() == DKS_HALError.HAL_ERROR_TAMPER):
                    self.last_rpc_tamper_status[rpc_index].value = True
                    self.on_tamper()

    def stop(self):
        PFUNIX_HSM.stop(self)

    def on_tamper(self):
        if (self.tamper_event_detected.value is not True):
            self.tamper_event_detected.value = True

            print("!!!!!!! TAMPER !!!!!!!!!!")
            hsm_tools.cryptech.muxd.logger.error("!!!!!!! TAMPER !!!!!!!!!!")

        # tell our observers of the tamper event
        # continuously signal
        self.notify()

    def get_tamper_state(self):
        return self.tamper_event_detected.value

    def reset_tamper_state(self):
        self.tamper_event_detected.value = False
        for rpc_index in xrange(self.rpc_count):
            self.last_rpc_tamper_status[rpc_index].value = False

        # notify changed state to all observers
        self.notify()        
