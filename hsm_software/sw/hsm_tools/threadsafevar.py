#!/usr/bin/env python
# Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
#


import threading

class ThreadSafeVariable(object):
    def __init__(self, value):
        self.thread_lock = threading.Lock()
        self.__setval(value)

    def __setval(self, value):
        with(self.thread_lock):
            self.__value = value
    
    def __getval(self):
        with(self.thread_lock):
            return self.__value

    value = property(__getval, __setval)
