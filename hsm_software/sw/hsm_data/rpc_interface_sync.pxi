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

class SyncCommandEnum(IntEnum):
    OneWayBackup       = 0
    TwoWayBackup       = 1
    Initialize         = 2
    BuildCache         = 3
    RemoteBackup       = 4
    RemoteRestore      = 5
    SetupRemoteRestore = 6

class SyncCommand(object):
    """Class to define a command for the mirrorer"""
    def __init__(self, name, src, dest, callback, param = None, console = None):
        self.name = name
        self.src = src
        self.dest = dest
        self.callback = callback
        self.param = param
        self.console = console

class rpc_interface_sync(object):
    """ "Pure" Python interface to the synchronizer"""
    def __init__(self, sync):
        self.sync = sync

    def cache_initialized(self):
        return self.sync.cache_initialized()

    def initialize(self, rpc_count, username, pin, callback):
        return self.sync.initialize(rpc_count, username, pin, callback)

    @property
    def sync_init_success(self):
        return self.sync.sync_init_success

    def queue_command(self, command):
        self.sync.queue_command(command)
