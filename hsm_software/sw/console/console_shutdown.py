#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

def dks_shutdown(console_object, args):
    console_object.cty_direct_call('Shutting Down HSM')
    console_object.safe_shutdown.shutdown()
    console_object.cty_direct_call(None)

def dks_shutdown_restart(console_object, args):
    console_object.cty_direct_call('Restarting HSM')
    console_object.safe_shutdown.restart()
    console_object.cty_direct_call(None)

def add_shutdown_commands(console_object):
    shutdown_node = console_object.add_child('shutdown')
    shutdown_node.add_child_tree(['restart', 'YesIAmSure'], num_args=0,
                                    usage=' - Restarts the HSM.',
                                    callback=dks_shutdown_restart)
    shutdown_node.add_child('YesIAmSure', num_args=0,
                            usage=' - Shuts down the HSM.',
                            callback=dks_shutdown)
