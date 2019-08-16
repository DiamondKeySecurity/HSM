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

from cython.operator cimport dereference as deref

cdef class rpc_internal_handling(object):
    cdef rpc_handler.rpc_handler *rpc_preprocessor
    cdef bint hsm_locked
    cdef object tamper_detected
    
    """ Python interface to the rpc handler"""
    def __init__(self):
        self.tamper_detected = ThreadSafeVariable(False)
        self.hsm_locked = False

    def __cinit__(self):
        self.rpc_preprocessor = new rpc_handler.rpc_handler()

    def unlock_hsm(self):
        deref(self.rpc_preprocessor).unlock_hsm()

    def device_count(self):
        return deref(self.rpc_preprocessor).device_count()

    def get_current_rpc(self):
        return deref(self.rpc_preprocessor).get_current_rpc()

    def set_current_rpc(self, int index):
        deref(self.rpc_preprocessor).set_current_rpc(index)

    def on_tamper_event(self, object tamper_object):
        new_tamper_state = tamper_object.get_tamper_state()
        old_tamper_state = self.tamper_detected.value

        if(new_tamper_state != old_tamper_state):
            self.tamper_detected.value = new_tamper_state

            # if(new_tamper_state is True):
            #     self.hsm_locked = True
            #     for rpc in self.rpc_list:
            #         rpc.change_state(CrypTechDeviceState.TAMPER)
            # else:
            #     self.hsm_locked = True
            #     for rpc in self.rpc_list:
            #         rpc.clear_tamper(CrypTechDeviceState.TAMPER_RESET)
    
    def process_incoming_rpc(self, bytes decoded_request):
        pass

    def is_rpc_locked(self):
        return False

    def create_session(self, int handle, bint from_ethernet):
        pass

    def delete_session(self, int handle):
        pass

class rpc_interface_handling(object):
    """ Limitted Python interface to the rpc handler"""
    def __init__(self, internal_handler):
        self.internal_handler = internal_handler

    def unlock_hsm(self):
        self.internal_handler.unlock_hsm()

    def device_count(self):
        self.internal_handler.device_count()

    def get_current_rpc(self):
        self.internal_handler.get_current_rpc()

    def set_current_rpc(self, index):
        self.internal_handler.set_current_rpc(index)

    def get_names(self):
        cdef int i
        for i in xrange(self.device_count()):
            yield "RPC%i"%i

    def append_futures(self, futures):
        futures.append(self.rpc_output_loop())

    @tornado.gen.coroutine
    def rpc_output_loop(self):
        "Keep Tornado alive"
        while(True):
            yield time.sleep(0.05)