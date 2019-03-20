#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import logging

def dks_debug_flash_led(console_object, args):
    if (console_object.led is not None):
        console_object.led.system_led.flash_red()
        return 'OK'
    else:
        return 'LED not detected'

def dks_debug_verbose(console_object, args):
    logging.getLogger().setLevel(logging.DEBUG)
    return 'HSM set to verbose debugging'

def dks_reboot_cryptech(console_object, args):
    console_object.cty_direct_call("Rebooting the Cryptech STMs")

    console_object.cty_conn.reboot_stm()

    return "STM rebooted"

def add_debug_commands(console_object):
    debug_node = console_object.add_child('debug')

    debug_node.add_child_tree(['flash', 'system', 'led'], num_args=0,
                                usage=' - Flashes the system LED.',
                                callback=dks_debug_flash_led)

    debug_node.add_child_tree(['reboot', 'cryptech'], num_args=0,
                                usage=' - Reboots the CrypTech devices.',
                                callback=dks_reboot_cryptech)

    debug_node.add_child('verbose', num_args=0,
                            usage=' - Add verbose debugging to log.',
                            callback=dks_debug_verbose)
