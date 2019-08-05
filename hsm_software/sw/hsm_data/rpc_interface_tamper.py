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


from cache import HSMCache

class rpc_interface_tamper(object):
    """ "Pure" Python interface to the tamper object"""
    def __init__(self, tamper):
        self.tamper = tamper

    def enable(self):
        self.tamper.enable()

    def add_observer(self, callback):
        self.tamper.add_observer(callback)