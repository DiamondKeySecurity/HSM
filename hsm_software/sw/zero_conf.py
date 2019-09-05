#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.

import atexit
import socket

from settings import CTY_IP_PORT, RPC_IP_PORT
from zeroconf import ServiceInfo, Zeroconf

class HSMZeroConfSetup(object):
    def __init__(self, ip_addr, serial, firmware_version, sd_version):
        self.zeroconf = None
        self.registered = False

        caps = ""

        try:
            with open("/etc/diamond-hsm/caps", "rt") as fp:
                for line in fp:
                    caps = "%s %s"%(caps, line.strip("\r\n"))
        except:
            pass

        desc = {'serial'   : serial,
                'host'     : 'dks-hsm',
                'type'     : 'Diamond HSM Prototype',
                'firmware' : firmware_version,
                'sd'       : sd_version,
                'IP'       : ip_addr,
                'caps'     : caps }

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