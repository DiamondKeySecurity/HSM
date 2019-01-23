#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from hsm_tools.observerable import observable
from hsm_tools.stoppable_thread import stoppable_thread
import time

class Tamper_Test(observable):
    def __init__(self):
        print 'tamper test'
        self.thread = stoppable_thread(self.tamper_test_loop, name='tamper test thread')
        self.thread.start()

    def tamper_test_loop(self):
        # after 3 minutes yell tamper
        time.sleep(180)
        self.notify()
        return False


    