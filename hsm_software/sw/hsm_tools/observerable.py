#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import threading

class observable(object):
    """Simple class used to call multiple callbacks at the same time"""
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.observers = []

    def add_observer(self, callback):
        # add a callback
        # callbacks should take the observable object as a parameter
        with self.thread_lock:
            self.observers.append(callback)

    def notify(self):
        # notify all observers that something has happened
        with self.thread_lock:
            for observer in self.observers:
                observer(self)