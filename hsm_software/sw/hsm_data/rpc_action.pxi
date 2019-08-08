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

class RPCAction(object):
    """After an RPC has been preprocessed by the load balancer, this class is the
    result of that operation and tells RPCTCPServer what action to perform"""
    def __init__(self, result, rpc_list, callback, request = None):
        """result - buffer to immediately send back to the caller
           rpc_list - if result is None, this is the list of alpha's to send the message to
           callback - after the rpcs have been sent, this is the callback so the loadbalancer can see the result
        """
        self.result = result
        self.rpc_list = rpc_list
        self.callback = callback
        self.request = request