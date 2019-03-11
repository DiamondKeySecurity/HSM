#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import os

class SafeShutdown(object):
    """Class to ensure the HSM shuts down correctly"""
    def __init__(self, debug = False):
        self.debug = debug
        self.callbacks = []
        self.restart_callbacks = []

    def shutdown(self):        
        self.prepareForShutdown()
        if(not self.debug):
            os.system('sudo shutdown -h now')
        else:
            exit(0)

    def restart(self):  
        # restart only callbacks
        for callback in self.restart_callbacks:
            callback()

        # normal shutdown callbacks
        self.prepareForShutdown()

        if(not self.debug):
            os.system('sudo reboot')
        else:
            exit(0)

    def prepareForShutdown(self):
        for callback in self.callbacks:
            callback()

    def addOnShutdown(self, callback):
        self.callbacks.append(callback)

    def addOnRestartOnly(self, callback):
        self.restart_callbacks.append(callback)