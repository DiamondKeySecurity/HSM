#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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

    def is_done(self):
        return self.current >= len(self.node_list)

    def getPrompt(self):
        if(self.is_done()): return None

        return self.node_list[self.current].prompt

    def getCurrentCallback(self):
        if(self.is_done()): return None

        return self.node_list[self.current].callback

    def validate_response(self, response):
        if(self.is_done()): return None

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
        elif (self.is_done()):
            if(self.finished_callback is not None):
                self.finished_callback(self.results)
            return None
        else:
            return self
