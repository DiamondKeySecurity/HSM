#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
