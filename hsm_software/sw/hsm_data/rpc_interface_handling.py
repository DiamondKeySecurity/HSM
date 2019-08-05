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


class rpc_interface_handling(object):
    """ "Pure" Python interface to the rpc handler"""
    def __init__(self, rpc_preprocessor):
        self.rpc_preprocessor = rpc_preprocessor

    def unlock_hsm(self):
        self.rpc_preprocessor.unlock_hsm()

    def device_count(self):
        return self.rpc_preprocessor.device_count()

    def get_current_rpc(self):
        return self.rpc_preprocessor.get_current_rpc()

    def set_current_rpc(self, index):
        self.rpc_preprocessor.set_current_rpc(index)

    def get_names(self):
        for d in self.rpc_preprocessor.rpc_list:
            yield d.name