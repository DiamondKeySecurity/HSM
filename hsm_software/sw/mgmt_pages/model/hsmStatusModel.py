# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

class hsmStatusModel(object):
    def __init__(self, ipaddr, cryptech_device_state = []):
        self.ipaddr = ipaddr
        self.cryptech_device_state = cryptech_device_state

    