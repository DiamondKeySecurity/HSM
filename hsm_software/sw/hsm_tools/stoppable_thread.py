#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import threading

class stoppable_thread(object):
    def __init__(self, function, name = 'stoppable_thread'):
        self.thread = threading.Thread(name=name,
                                       target = self.__loop)
        self.function = function
        self.stop_event = threading.Event()

    def __loop(self):
        while not self.stop_event.isSet():
            result = self.function()
            if(result is False):
                break
            
    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def stop_wait(self, timeout=None):
        self.stop()
        self.thread.join(timeout=timeout)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.thread.isAlive():
            self.stop_wait()