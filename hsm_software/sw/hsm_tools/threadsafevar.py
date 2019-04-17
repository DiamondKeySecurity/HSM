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

class ThreadSafeVariable(object):
    def __init__(self, value):
        self.thread_lock = threading.Lock()
        self.__setval(value)

    def __setval(self, value):
        with(self.thread_lock):
            self.__value = value
    
    def __getval(self):
        with(self.thread_lock):
            return self.__value

    value = property(__getval, __setval)
