#!/usr/bin/env python
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

class TamperDetector(observable, PFUNIX_HSM):
    def __init__(self, sockname, rpc_count):
        observable.__init__(self)
        PFUNIX_HSM.__init__(self, sockname)

        self.tamper_event_detected = ThreadSafeVariable(False)
        self.detection_enabled = ThreadSafeVariable(False)
        self.last_rpc_tamper_status = [ThreadSafeVariable(False) for _ in range(rpc_count)]

        self.rpc_count = rpc_count

        print('tamper rpc')

    def enable(self):
        self.detection_enabled.value = True

    def dowork(self, hsm):
        for rpc_index in xrange(self.rpc_count):
            for _ in xrange(15):
                time.sleep(1)

                # if there's been a tamper event, inform the rest of the application every second
                if (self.tamper_event_detected.value is True):
                    self.on_tamper()

            # after at least 15 seconds, ask the HSM if it's in tamper
            if (not self.last_rpc_tamper_status[rpc_index].value and self.detection_enabled.value):
                hsm.rpc_set_device(rpc_index)
                if (hsm.rpc_check_tamper() == DKS_HALError.HAL_ERROR_TAMPER):
                    self.last_rpc_tamper_status[rpc_index].value = True
                    self.on_tamper()

    def stop(self):
        PFUNIX_HSM.stop(self)

    def on_tamper(self):
        if (self.tamper_event_detected.value is not True):
            self.tamper_event_detected.value = True

            print("!!!!!!! TAMPER !!!!!!!!!!")
            cryptech.muxd.logger.error("!!!!!!! TAMPER !!!!!!!!!!")

        # tell our observers of the tamper event
        # continuously signal
        self.notify()

    def get_tamper_state(self):
        return self.tamper_event_detected.value

    def reset_tamper_state(self):
        self.tamper_event_detected.value = False
        for rpc_index in xrange(self.rpc_count):
            self.last_rpc_tamper_status[rpc_index].value = False

        # notify changed state to all observers
        self.notify()        
