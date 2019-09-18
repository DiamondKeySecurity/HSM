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
