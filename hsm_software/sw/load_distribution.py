#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import threading

class load_slot(object):
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.__setval(0)

    def __setval(self, value):
        with(self.thread_lock):
            self.__value = value
    
    def __getval(self):
        with(self.thread_lock):
            return self.__value

    def inc(self, val):
        with(self.thread_lock):
            self.__value += val
            if (self.__value < 0):
                self.__value = 0

    value = property(__getval, __setval)


class LoadDistribution(object):
    """Simple thread-safe class for storing how work
       has been distributed across objects."""

    def __init__(self, count):
        self.array = [load_slot() for _ in range(count)]

    def inc(self, slot, amount):
        self.array[slot].inc(amount)

    def get(self, slot):
        return self.array[slot].value
