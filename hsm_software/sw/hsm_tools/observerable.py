#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

class observable(object):
    """Simple class used to call multiple callbacks at the same time"""
    def __init__(self):
        self.observers = []

    def add_observer(self, callback):
        # add a callback
        # callbacks should take the observable object as a parameter
        self.observers.append(callback)

    def notify(self):
        # notify all observers that something has happened
        for observer in self.observers:
            observer(self)