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