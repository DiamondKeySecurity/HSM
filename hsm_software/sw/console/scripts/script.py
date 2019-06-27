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
    def __init__(self, node_list, finished_callback = None):
        self.node_list = node_list
        self.current = 0
        self.results = {}
        self.finished_callback = finished_callback
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
            return self        

        # get the node we're working on
        node = self.node_list[self.current]

        # get the callback for later
        callback = node.callback

        # set the reponse
        self.results[node.name] = validated_response

        # move to the next node
        self.current += 1

        # do the callback
        if(callback is not None):
            return callback(validated_response)

        if (self.is_done()):
            if(self.finished_callback is not None):
                self.finished_callback(self.results)
            return None
        else:
            return self
