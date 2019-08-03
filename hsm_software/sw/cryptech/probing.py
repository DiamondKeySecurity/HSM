#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
# ------------------------------------------------------------------------------
#
# Copyright (c) 2016-2017, NORDUnet A/S All rights reserved.
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

"""
Modified ProbeIOStream to probe for multiple Cryptech HSMs.
"""
import tornado.gen

import logging
import serial.tools.list_ports_posix

import muxd

from upload import ManagementPortSerial

from hsm import HSMPortInfo, CtyArg

class ProbeMultiIOStream(muxd.ProbeIOStream):
    """
    Tornado IOStream for probing a serial port.
    """

    def __init__(self, device):
        super(ProbeMultiIOStream, self).__init__(device)

    @classmethod
    @tornado.gen.coroutine
    def run_probes(cls, cty_list, rpc_list, args):

        devs = set(str(port)
                   for port, desc, hwid in serial.tools.list_ports_posix.comports()
                   if "VID:PID=0403:6014" in hwid)

        muxd.logger.info("Probing candidate devices %s", " ".join(devs))

        results = yield dict((dev, ProbeMultiIOStream(dev).run_probe()) for dev in devs)

        cty_index = 0
        rpc_index = 0
        for dev, result in results.iteritems():
            if result == "cty":
                muxd.logger.info("Found %s as CTY device", dev)
                # send data directly to the alpha using SerialIOStream
                cty_serial = ManagementPortSerial(CtyArg(dev, args.debug_cty))
                cty_list.append(HSMPortInfo("CTY"+str(cty_index), dev, cty_serial))
                cty_index += 1

            if result == "rpc":
                muxd.logger.info("Found %s as RPC device", dev)
                # send data directly to the alpha using SerialIOStream
                rpc_stream = muxd.RPCIOStream(device = dev)                
                rpc_list.append(HSMPortInfo("RPC"+str(rpc_index), dev, rpc_stream))
                rpc_index += 1

@tornado.gen.coroutine
def main():
    cty_list = []
    rpc_list = []

    yield ProbeMultiIOStream.run_probes(cty_list, rpc_list)

    for cty in cty_list:
        print("\nCTY: %s at %s" % (cty.name, cty.addr))
        cty.close()

    for rpc in rpc_list:
        print("\nRPC: %s at %s" % (rpc.name, rpc.addr))
        rpc.close()

    futures = []

    if futures:
        yield futures

if __name__ == "__main__":
    try:
        tornado.ioloop.IOLoop.current().run_sync(main)
    except (SystemExit, KeyboardInterrupt):
        pass
    except:
        muxd.logger.exception("Unhandled exception")
    else:
        muxd.logger.debug("Main loop exited")