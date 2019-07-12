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

from threading import Lock

class StatusObject(object):
    def __init__(self):
        self._status_lock = Lock()
        self._status_msg = None

    @property
    def is_busy(self):
        with self._status_lock:
            rval = self._status_msg is not None
        
        return rval

    @property
    def status(self):
        with self._status_lock:
            rval = self._status_msg
        
        return rval

    @status.setter
    def status(self, value):
        with self._status_lock:
            self._status_msg = value


class SetStatus(object):
    def __init__(self, busy_object, status):
        self.busy_object = busy_object
        busy_object.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.busy_object.status = None
