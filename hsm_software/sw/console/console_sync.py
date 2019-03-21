#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from sync import SyncCommandEnum, SyncCommand

from settings import HSMSettings

from scripts.remote_backup import RemoteBackupScript
from scripts.remote_restore import RemoteRestoreScript

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

def received_remote_backup_options(console_object, options):
    pass

def received_remote_retore_options(console_object, options):
    pass

def dks_sync_remote_restore(console_object, args):
    dest = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (dest < 0):
        return "Invalid internal device destination parameter. Got '%s'." % args[0]

    # start the script
    console_object.script_module = RemoteRestoreScript(console_object.cty_direct_call, dest)

    console_object.cty_direct_call(console_object.prompt)

    return True

def dks_sync_remote_backup(console_object, args):
    src = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (src < 0):
        return "Invalid internal device source parameter. Got '%s'." % args[0]

    settings = console_object.settings
    enabled = settings.get_setting(HSMSettings.ENABLE_KEY_EXPORT)

    if(enabled == False):
        return 'Unable to perform backup. Key export not enabled.'

    # start the script
    console_object.script_module = RemoteBackupScript(console_object.cty_direct_call, src, received_remote_backup_options)

    console_object.cty_direct_call(console_object.prompt)

    return True

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

    remote_node = sync_node.add_child(name="remote")

    remote_node.add_child(name="restore", num_args=1,
                          usage="<internal device index> - Restores keys"
                                " from a backup device to an internal device.",
                          callback=dks_sync_remote_restore)

    remote_node.add_child(name="backup", num_args=1,
                          usage="<internal device index> - Back up keys"
                                " from an internal device to an external device.",
                          callback=dks_sync_remote_backup)