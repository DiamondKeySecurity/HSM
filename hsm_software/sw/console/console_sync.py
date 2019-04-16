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


from sync import SyncCommandEnum, SyncCommand


def dks_sync_cache(console_object, args):
    console_object.build_cache(0, self.rpc_preprocessor.device_count())
    return True

def parse_index(index_string, max_value):
    try:
        index = int(index_string)
    except Exception:
        index = -1

    if (max_value > 0 and index >= max_value):
        index = -1

    return index

def dks_sync_oneway(console_object, args):
    src = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (src < 0):
        return "Invalid source parameter. Got '%s'." % args[0]

    dest = parse_index(args[1], console_object.rpc_preprocessor.device_count())
    if (dest < 0):
        return "Invalid destination parameter. Got '%s'." % args[1]

    max_keys = parse_index(args[2], 0)
    if (max_keys < 0):
        return "Invalid max keys parameter. Got '%s'." % args[2]

    cmd = SyncCommand(SyncCommandEnum.OneWayBackup, src, dest,
                            console_object.sync_callback,
                            param=max_keys,
                            console=console_object.cty_direct_call)

    console_object.synchronizer.queue_command(cmd)

    return "command sent to synchronizer"

def dks_sync_twoway(console_object, args):
    src = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (src < 0):
        return "Invalid source parameter. Got '%s'." % args[0]

    dest = parse_index(args[1], console_object.rpc_preprocessor.device_count())
    if (dest < 0):
        return "Invalid destination parameter. Got '%s'." % args[1]

    max_keys = parse_index(args[2], 0)
    if (max_keys < 0):
        return "Invalid max keys parameter. Got '%s'." % args[2]

    cmd = SyncCommand(SyncCommandEnum.TwoWayBackup, src, dest,
                            console_object.sync_callback,
                            param=max_keys,
                            console=console_object.cty_direct_call)

    console_object.synchronizer.queue_command(cmd)

    return "command sent to synchronizer"

def add_sync_commands(console_object):
    sync_node = console_object.add_child('sync')

    sync_node.add_child(name="cache", num_args=0,
                        usage=" - Scans the CrypTech devices to rebuild"
                        " the cache.",
                        callback=dks_sync_cache)
    sync_node.add_child(name="oneway", num_args=3,
                        usage="<source RPC index> <destination RPC index>"
                        " <max copies>  - copies keys from one CrypTech"
                        " device to another.",
                        callback=dks_sync_oneway)
    sync_node.add_child(name="twoway", num_args=3,
                        usage="<source RPC index> <destination RPC index>"
                        " <max copies>  - copies keys from one CrypTech"
                        " device to another.",
                        callback=dks_sync_twoway)