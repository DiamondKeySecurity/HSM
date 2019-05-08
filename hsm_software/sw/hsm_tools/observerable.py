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

class observable(object):
    """Simple class used to call multiple callbacks at the same time"""
    def __init__(self):
        self.observer_thread_lock = threading.Lock()
        self.observers = []

    def add_observer(self, callback):
        # add a callback
        # callbacks should take the observable object as a parameter
        with self.observer_thread_lock:
            self.observers.append(callback)

    def notify(self):
        # notify all observers that something has happened
        with self.observer_thread_lock:
            for observer in self.observers:
                observer(self)

    def stop(self):
        # helper method if need to let object know it needs to stop
        pass