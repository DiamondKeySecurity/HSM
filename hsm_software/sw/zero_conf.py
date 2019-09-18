#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


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