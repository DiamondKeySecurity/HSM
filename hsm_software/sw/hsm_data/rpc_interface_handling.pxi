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

cdef class rpc_interface_handling(object):
    cdef rpc_handler.rpc_handler *rpc_preprocessor
    cdef bint hsm_locked
    object tamper_detected
    
    """ Python interface to the rpc handler"""
    def _init_(self):
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

    def set_current_rpc(self, index):
        deref(self.rpc_preprocessor).set_current_rpc(index)

    def get_names(self):
        cdef int i
        for i in xrange(self.device_count()):
            yield "RPC%i"%i

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
    
    def process_incoming_rpc(self, decoded_request):
        pass

    def append_futures(self, futures):
        pass