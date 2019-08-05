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

from cache import HSMCache
from rpc_handling import RPCPreprocessor
from rpc_tcp_server import RPCTCPServer, SecondaryPFUnixListener
from sync import Synchronizer
from tamper import TamperDetector

class rpc_path_object(object):
    def __init__(self, num_rpc_devices, cache_folder):
        # start the cache
        self.cache = HSMCache(num_rpc_devices, cache_folder=cache_folder)

        self.rpc_preprocessor = None
        self.rpc_server = None
        self.rpc_secondary_listener = None
        self.synchronizer = None
        self.tamper = None

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

    def stop(self):
        if(self.tamper != None):
            self.tamper.stop()
        if(self.synchronizer != None):
            self.synchronizer.stop()
