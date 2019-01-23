#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import enum

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