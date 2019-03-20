#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from scripts.masterkey import MasterKeySetScriptModule

def dks_masterkey_set(console_object, args):
    # use script to set the master key
    console_object.script_module = MasterKeySetScriptModule(console_object.cty_conn,
                                                            console_object.cty_direct_call,
                                                            console_object.settings)

    return ''

def add_masterkey_commands(console_object):
    masterkey_node = console_object.add_child('masterkey')

    masterkey_node.add_child(name="set", num_args=0,
                             usage=" - sets the master key.",
                             callback=dks_masterkey_set)