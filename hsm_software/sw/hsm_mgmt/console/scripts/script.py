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

from enum import IntEnum

class ValueType(IntEnum):
    AnyString = 0,
    IP4Address = 1,
    AnyInt = 2,
    AnyReal = 3,
    YesNo = 4

class script_node(object):
    def __init__(self, name, prompt, value_type, value_min = 0, value_max = 65535, callback = None):
        self.name = name
        self.prompt = prompt
        self.value_type = value_type
        self.value_min = value_min
        self.value_max = value_max

        # call backs return the ScriptModule to run or None to stop processing a script
        self.callback = callback

class ScriptModule(object):
    def __init__(self, node_list, finished_callback = None, auto_finished_callback = True):
        self.node_list = node_list
        self.current = 0
        self.results = {}
        self.finished_callback = finished_callback
        self.auto_finished_callback = auto_finished_callback
        self.sub_module = None

    def is_done(self):
        return (self.current >= len(self.node_list)) and (self.sub_module is None)

    def getPrompt(self):
        if(self.is_done()): return None

        if(self.sub_module is not None):
            # return from sub module
            return self.sub_module.getPrompt()
        else:
            return self.node_list[self.current].prompt
            

    def validate_response(self, response):
        if(self.is_done()): return None

        if(self.sub_module is not None):
            # return from sub module
            return self.sub_module.validate_response(response)

        node = self.node_list[self.current]

        # make sure the response is of the correct type
        if(node.value_type == ValueType.AnyInt):
            try:
                value = int(response)
                if(value < node.value_min or value > node.value_max): return None
            except ValueError:
                return None
        elif(node.value_type == ValueType.AnyReal):
            try:
                value = float(response)
                if(value < node.value_min or value > node.value_max): return None
            except ValueError:
                return None
        elif(node.value_type == ValueType.AnyString):
            value = response
            if(len(value) < node.value_min or len(value) > node.value_max): return None
        elif(node.value_type == ValueType.YesNo):
            value = response.lower()
            if(value == 'yes' or value == 'y'):
                value = True
            elif(value == 'no' or value == 'n'):
                value = False
            else:
                return None
        elif(node.value_type == ValueType.IP4Address):
            if (response == '0'):
                return '0.0.0.0'

            parts = response.split('.')
            if(len(parts) == 4):
                for i in xrange(4):
                    try:
                        ip_unit = int(parts[i])
                        if(ip_unit < 0 or ip_unit > 255): return None
                    except ValueError:
                        return None

                # reconstuct the value because this is what we parsed
                value = '%s.%s.%s.%s'%(parts[0], parts[1], parts[2], parts[3])
            else:
                return None

        return value

    def accept_validated_response(self, validated_response):
        if(self.is_done()): return None

        if(self.sub_module is not None):
            # use the submodule to process
            self.sub_module = self.sub_module.accept_validated_response(validated_response)

            # always return self if there's a submodule
            if(self.sub_module is not None):
                return self
            if(self.is_done()):
                return None

        # get the node we're working on
        node = self.node_list[self.current]

        # get the callback for later
        callback = node.callback

        # set the reponse
        self.results[node.name] = validated_response

        # move to the next node
        self.current += 1

        rval = self

        # do the callback
        if(callback is not None):
            rval = callback(validated_response)

        if (rval is None or self.is_done()):
            if(self.auto_finished_callback and (self.finished_callback is not None)):
                rval = self.finished_callback(self.results)
            else:
                rval = None

        return rval
