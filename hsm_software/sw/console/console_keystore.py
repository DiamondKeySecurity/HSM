#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from hsm_tools.cty_connection import CTYError

def dks_keystore_erase(console_object, args):
    if(console_object.cty_conn.clearKeyStore(preservePINs=False) == CTYError.CTY_OK):
        # clear the cache
        console_object.cache.clear()

        return 'keystore cleared. preservePINs == False'

def dks_keystore_erase_preservePINs(console_object, args):
    if(console_object.cty_conn.clearKeyStore(preservePINs=True) == CTYError.CTY_OK):
        # clear the cache
        console_object.cache.clear()

        return 'keystore cleared. preservePINs == True'

def add_keystore_commands(console_object):
    keystore_node = console_object.add_child('keystore')
    keystore_erase_node = keystore_node.add_child('erase')
    keystore_erase_node.add_child('YesIAmSure', num_args=0,
                                    usage=' - Erases the entire keystore'
                                        ' including PINs.',
                                    callback=dks_keystore_erase)

    # use erase_callback to meet PEP8 style
    erase_callback = dks_keystore_erase_preservePINs
    keystore_erase_node.add_child_tree(['preservePINs', 'YesIAmSure'],
                                        num_args=0,
                                        usage=' - Erases the keystore.'
                                                ' Preserves PINs.',
                                        callback=erase_callback)