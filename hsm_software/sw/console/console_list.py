#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

def dks_list_keys(console_object, args):
    cache = console_object.cache
    rpc_count = cache.rpc_count

    console_object.cty_direct_call("CrypTech Device Cached UUIDs---")

    for rpc_index in range(0, rpc_count):
        alphaTable = cache.alphaTables[rpc_index]
        console_object.cty_direct_call("%sDevice:%i------------%s" %
                                (console_object.initial_space,
                                rpc_index,
                                console_object.initial_space))
        for key in alphaTable.get_keys():
            console_object.cty_direct_call(str(key))

    return console_object.initial_space

def add_list_commands(console_object):
    set_node = console_object.add_child('list')

    set_node.add_child(name="keys", num_args=0,
                        usage=" - list the keys in the CrypTech devices.",
                        callback=dks_list_keys)