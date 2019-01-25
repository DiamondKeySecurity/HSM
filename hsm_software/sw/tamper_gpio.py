#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from hsm_tools.observerable import observable

class Tamper_GPIO(observable):
    def __init__(self):
        super(Tamper_GPIO, self).__init__()

        print 'tamper gpio'