#!/usr/bin/env python
# Copyright (c) 2018, 2019  Diamond Key Security, NFP
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

cdef class rpc_path_object:
    cdef hsm_cache.HSMCache *cache
    cdef object rpc_preprocessor
    cdef object rpc_server
    cdef object rpc_secondary_listener
    cdef object synchronizer
    cdef object tamper

    def __cinit__(self, int num_rpc_devices, char *cache_folder):
        # start the cache
        self.cache = new hsm_cache.HSMCache(num_rpc_devices, cache_folder)

        self.rpc_preprocessor = None
        self.rpc_server = None
        self.rpc_secondary_listener = None
        self.synchronizer = None
        self.tamper = None

    def __dealloc__(self):
        del self.cache

    def create_rpc_objects(self, rpc_list, settings, netiface, futures, ssl_options, RPC_IP_PORT):
        # start the load balancer
        self.rpc_preprocessor = RPCPreprocessor(rpc_list, self.cache, settings, netiface)
        # Listen for incoming TCP/IP connections from remove cryptech.muxd_client
        self.rpc_server = RPCTCPServer(self.rpc_preprocessor, RPC_IP_PORT, ssl_options)
        # set the futures for all of our devices
        self.rpc_preprocessor.append_futures(futures)

    def create_internal_listener(self, internal_rpc_socket, internal_rpc_socket_mode):
        # create a secondary listener to handle PF_UNIX request from subprocesses
        self.rpc_secondary_listener = SecondaryPFUnixListener(self.rpc_server,
                                                              internal_rpc_socket,
                                                              internal_rpc_socket_mode)

    def create_synchronizer(self, internal_rpc_socket, futures):
        self.synchronizer = Synchronizer(internal_rpc_socket, self.cache)

        # start the mirrorer
        self.synchronizer.append_future(futures)

    def create_rpc_tamper(self, num_rpc_devices, internal_rpc_socket, futures, tamper_listener_list):
        self.tamper = TamperDetector(internal_rpc_socket, num_rpc_devices)

        # add basic tamper detection
        self.tamper.add_observer(self.rpc_preprocessor.on_tamper_event)

        # add the listeners / observers
        for listener in tamper_listener_list:
            self.tamper.add_observer(listener)

        # start the listener
        self.tamper.append_future(futures)

    def get_interface_cache(self):
        if (self.cache is None): return None
        return rpc_interface_cache(self.cache)

    def get_interface_handling(self):
        if (self.rpc_preprocessor is None): return None
        return rpc_interface_handling(self.rpc_preprocessor)

    def get_interface_sync(self):
        if (self.synchronizer is None): return None
        return rpc_interface_sync(self.synchronizer)

    def get_interface_tamper(self):
        if (self.tamper is None): return None
        return rpc_interface_tamper(self.tamper)

    def stop(self):
        if(self.tamper != None):
            self.tamper.stop()
        if(self.synchronizer != None):
            self.synchronizer.stop()
