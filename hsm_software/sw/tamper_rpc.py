#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from hsm_tools.observerable import observable
from hsm_tools.stoppable_thread import stoppable_thread
import time


class Tamper_RPC(observable):
    def __init__(self):
        super(Tamper_RPC, self).__init__()

        print('tamper rpc')
        self.count = 0

        self.thread = stoppable_thread(self.tamper_rpc_loop,
                                       name='tamper rpc thread')
        self.thread.start()

    def tamper_rpc_loop(self):
        # after 3 minutes yell tamper
        time.sleep(1)
        self.count += 1
        if(self.count > 180):
            self.count = 0
            print('Interesting')
            self.notify()

        return True

    def stop(self):
        self.thread.stop()

