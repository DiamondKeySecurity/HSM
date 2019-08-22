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

cdef class PFUNIX_HSM:
    cdef object sockname
    cdef object e

    """Connects to an HSM over a PF_UNIX socket and then provides a
    cryptech.libhal.HSM reference to the HSM so rpc commands can be sent to
    it. This will work with diamond_server as long as a
    SecondaryPFUnixListener is being used."""

    def __init__(self, sockname):
        self.sockname = sockname
        self.e = threading.Event()

    def dowork(self, hsm):
        pass

    def process_command_loop(self):
        # connect to the HSM using the PF_UNIX socket
        try:
            hsm = DKS_HSM(sockname = self.sockname)
        except socket.error, exc:
            print "Caught exception socket.error : %s" % exc
            return False

        while not self.e.isSet():
            if(self.dowork(hsm) == True):
                return
            time.sleep(1.0)

    def start(self):
        """Use append_future when working with Tornado"""
        t1 = threading.Thread(name='cty_reponse',
                              target=self.process_command_loop)
        t1.start()

    def stop(self):
        self.e.set()