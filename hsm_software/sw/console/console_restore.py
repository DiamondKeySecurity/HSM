#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from console_keystore import dks_keystore_erase

def dks_restore_settingsonly(console_object, args):
    # restore settings
    console_object.settings.add_default_settings()

    return 'Restore complete'

def dks_restore(console_object, args):
    # clear the settings
    dks_restore_settingsonly(console_object, args)

    # clear the keystore
    dks_keystore_erase(console_object, args)

    return 'Restore complete'

def add_restore_commands(console_object):
    restore_node = console_object.add_child('restore')
    restore_node.add_child_tree(['preservePINs-KEYs', 'YesIAmSure'],
                                num_args=0,
                                usage=' - Restores the HSM to factory'
                                        ' settings without downgrading the'
                                        ' HSM software. Will not delete'
                                        ' keys or PINS.',
                                callback=dks_restore_settingsonly)
    restore_node.add_child('YesIAmSure', num_args=0,
                            usage=' - Restores the HSM to factory settings'
                                    ' without downgrading the HSM software.',
                            callback=dks_restore)