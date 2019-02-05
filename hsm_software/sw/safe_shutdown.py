#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import os

class SafeShutdown(object):
    """Class to ensure the HSM shuts down correctly"""
    def __init__(self, dont_shutdown = False):
        self.callbacks = []
        self.restart_callbacks = []
        self.dont_shutdown = dont_shutdown

    def shutdown(self):        
        self.prepareForShutdown()
        if (self.dont_shutdown):
            exit(0)

        os.system('sudo shutdown -h now')

    def restart(self):  
        # restart only callbacks
        for callback in self.restart_callbacks:
            callback()

        # normal shutdown callbacks
        self.prepareForShutdown()

        if (self.dont_shutdown):
            exit(0)

        os.system('sudo reboot')

    def prepareForShutdown(self):
        for callback in self.callbacks:
            callback()

    def addOnShutdown(self, callback):
        self.callbacks.append(callback)

    def addOnRestartOnly(self, callback):
        self.restart_callbacks.append(callback)