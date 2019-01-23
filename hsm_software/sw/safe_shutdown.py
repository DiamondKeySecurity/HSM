#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import os

class SafeShutdown(object):
    """Class to ensure the HSM shuts down correctly"""
    def __init__(self):
        self.callbacks = []

    def shutdown(self):        
        self.prepareForShutdown()
        os.system('sudo shutdown -h now')

    def restart(self):        
        self.prepareForShutdown()
        os.system('sudo reboot')

    def prepareForShutdown(self):
        for callback in self.callbacks:
            callback()

    def addOnShutdown(self, callback):
        self.callbacks.append(callback)
