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

import os

class SafeShutdown(object):
    """Class to ensure the HSM shuts down correctly"""
    def __init__(self, debug):
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