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