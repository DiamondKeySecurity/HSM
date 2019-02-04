#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import hsm_tools.cryptech.muxd

from hsm_tools.threadsafevar import ThreadSafeVariable
from hsm_tools.observerable import observable
from hsm_tools.stoppable_thread import stoppable_thread
from hsm_tools.hsm import PFUNIX_HSM

import time

class TamperDetector(observable, PFUNIX_HSM):
    def __init__(self, sockname, rpc_count):
        observable.__init__(self)
        PFUNIX_HSM.__init__(self, sockname)

        self.tamper_event_detected = ThreadSafeVariable(False)

        self.rpc_count = rpc_count

        print('tamper rpc')
        self.count = 0

    def dowork(self, hsm):
        # after 2 minutes yell tamper
        time.sleep(1)
        self.count += 1
        if(self.count > 60):
            self.count = 0
            self.on_tamper()

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
