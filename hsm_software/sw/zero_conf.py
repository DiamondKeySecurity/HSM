#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import socket

from settings import CTY_IP_PORT, RPC_IP_PORT
from zeroconf import ServiceInfo, Zeroconf

# create our global variables
zeroconf = None
info_cty = None

def register_zeroconf_sevice(ip_addr, serial):
    global zeroconf
    global info_cty

    zeroconf = Zeroconf()
    desc = {'serial': serial,
            'host': 'dks-hsm',
            'type': 'Diamond HSM Prototype',
            'IP'  : ip_addr }

    info_cty = ServiceInfo("_dks-hsm-cty._tcp.local.",
                           "%s._dks-hsm-cty._tcp.local."%serial,
                           socket.inet_aton(ip_addr), 8081, 0, 0,
                           desc, "dkey.local.")

    zeroconf = Zeroconf()
    zeroconf.register_service(info_cty)

def unregister_zeroconf_sevice():
    global zeroconf
    global info_cty
    if (info_cty is not None):
        zeroconf.unregister_service(info_cty)
        zeroconf.close()

        info_cty = None