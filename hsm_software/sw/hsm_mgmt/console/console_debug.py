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
