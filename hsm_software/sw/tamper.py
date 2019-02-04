#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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

        self.rpc_count = rpc_count

        print('tamper rpc')

    def dowork(self, hsm):
        for rpc_index in xrange(self.rpc_count):
            hsm.rpc_set_device(rpc_index)
            if (hsm.rpc_check_tamper() == DKS_HALError.HAL_ERROR_TAMPER):
                self.on_tamper()
                return

    def stop(self):
        PFUNIX_HSM.stop(self)

    def on_tamper(self):
        if (self.tamper_event_detected.value is not True):
            self.tamper_event_detected.value = True

            print("!!!!!!! TAMPER !!!!!!!!!!")
            hsm_tools.cryptech.muxd.logger.info("!!!!!!! TAMPER !!!!!!!!!!")

        # tell our observers of the tamper event
        # continuously signal
        self.notify()

    def get_tamper_state(self):
        return self.tamper_event_detected.value

    def reset_tamper_state(self):
        self.tamper_event_detected.value = False

        # notify changed state to all observers
        self.notify()        
