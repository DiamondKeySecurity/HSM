#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from hsm_tools.observerable import observable

class Tamper_RPC(observable):
    def __init__(self):
        super(Tamper_RPC, self).__init__()

        print 'tamper rpc'