#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import atexit
import socket

from settings import CTY_IP_PORT, RPC_IP_PORT
from zeroconf import ServiceInfo, Zeroconf

class HSMZeroConfSetup(object):
    def __init__(self, ip_addr, serial):
        self.zeroconf = None
        self.registered = False

        desc = {'serial': serial,
                'host': 'dks-hsm',
                'type': 'Diamond HSM Prototype',
                'IP'  : ip_addr }

        self.service_info = ServiceInfo("_dks-hsm-cty._tcp.local.",
                                        "%s._dks-hsm-cty._tcp.local."%serial,
                                        socket.inet_aton(ip_addr), 8081, 0, 0,
                                        desc, "dkey.local.")


        atexit.register(self.unregister_service)

    def register_service(self):
        if (not self.registered):
            print "zeroconf registered"
            self.zeroconf = Zeroconf()
            self.zeroconf.register_service(self.service_info)

            self.registered = True


    def unregister_service(self):
        if (self.registered):
            print "zeroconf unregistered"
            self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            self.zeroconf = None

            self.registered = False