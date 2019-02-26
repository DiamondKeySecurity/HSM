#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from hsm_tools.observerable import observable
from hsm_tools.stoppable_thread import stoppable_thread
import time


class Tamper_Test(observable):
    def __init__(self):
        super(Tamper_Test, self).__init__()

        print('tamper test')

    def stop(self):
        pass


    