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

import time

def CheckValue(value, name, lo_value, hi_value):
    try:
        if (value.startswith("0x") or value.startswith("0X")):
            result = int(value, 16)
        elif (value.startswith("0o") or value.startswith("0O")):
            result = int(value, 8)
        else:
            result = int(value)
    except ValueError:
        return 'Error: %s entered is not a number'%name

    if (result < lo_value):
        return 'Error: %s entered is lower than the minimum value of %i'%(name, lo_value)

    if (result > hi_value):
        return 'Error: %s entered is greater than the maximum value of %i'%(name, hi_value)

    return result

def dks_tamper_threshold_set_disable(console_object, args):
    MIN_VALUE = 0
    MAX_VALUE = 0xFF

    mask_value = CheckValue(args[0],
                            'disable mask',
                            MIN_VALUE,
                            MAX_VALUE)
    if(isinstance(mask_value, int) is False):
        return mask_value

    console_object.tamper_config.update_setting("disable", "tamper threshold set disable", [mask_value])

    cmd = console_object.tamper_config.get_command_string("disable", '\r')

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_threshold_set_enable(console_object, args):
    MIN_VALUE = 0
    MAX_VALUE = 0xFF

    mask_value = CheckValue(args[0],
                            'enable mask',
                            MIN_VALUE,
                            MAX_VALUE)
    if(isinstance(mask_value, int) is False):
        return mask_value

    console_object.tamper_config.update_setting("enable", "tamper threshold set enable", [mask_value])

    cmd = console_object.tamper_config.get_command_string("enable", '\r')

    return console_object.cty_conn.send_raw_all(cmd, 5)


def dks_tamper_threshold_set_light(console_object, args):
    MIN_LIGHT_VALUE = 0
    MAX_LIGHT_VALUE = 0xFFFF

    light_value = CheckValue(args[0],
                             'Light threshold',
                             MIN_LIGHT_VALUE,
                             MAX_LIGHT_VALUE)
    if(isinstance(light_value, int) is False):
        return light_value

    console_object.tamper_config.update_setting("light", "tamper threshold set light", [light_value])

    cmd = console_object.tamper_config.get_command_string("light", '\r')

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_threshold_get_light(console_object, args):
    cmd = 'tamper light value\r'

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_threshold_set_temp(console_object, args):
    MIN_TEMPERATURE_VALUE = 0
    MAX_TEMPERATURE_VALUE = 0xFF

    lo_temp_value = CheckValue(args[0],
                               'Low temperature threshold',
                               MIN_TEMPERATURE_VALUE,
                               MAX_TEMPERATURE_VALUE)
    if(isinstance(lo_temp_value, int) is False):
        return lo_temp_value

    hi_temp_value = CheckValue(args[1],
                               'High temperature threshold',
                               MIN_TEMPERATURE_VALUE,
                               MAX_TEMPERATURE_VALUE)
    if(isinstance(hi_temp_value, int) is False):
        return hi_temp_value

    console_object.tamper_config.update_setting("temphi", "tamper threshold set temphi", [hi_temp_value])
    console_object.tamper_config.update_setting("templo", "tamper threshold set templo", [lo_temp_value])

    # send temphi
    cmd = console_object.tamper_config.get_command_string("temphi", '\r')

    result = console_object.cty_conn.send_raw_all(cmd, 7)

    time.sleep(3)

    # send templo
    cmd = console_object.tamper_config.get_command_string("templo", '\r')

    return result + "\r\n" + console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_threshold_get_temp(console_object, args):
    cmd = 'tamper temperature value\r'

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_threshold_set_accel(console_object, args):
    MIN_ACCEL_VALUE = 0
    MAX_ACCEL_VALUE = 0xFFFF

    accel_value = CheckValue(args[0],
                             'Accelerometer threshold',
                             MIN_ACCEL_VALUE,
                             MAX_ACCEL_VALUE)
    if(isinstance(accel_value, int) is False):
        return accel_value

    console_object.tamper_config.update_setting("vibe", "tamper threshold set accel", [accel_value])

    cmd = console_object.tamper_config.get_command_string("vibe", '\r')

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_threshold_get_accel(console_object, args):
    cmd = 'tamper vibe value\r'

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_set_config(console_object, args):
    cmd = 'tamper set config\r'

    console_object.tamper_config.save_settings()

    result = console_object.cty_conn.send_raw_all(cmd, 5)

    console_object.tamper.enable()

    return result

def dks_tamper_check(console_object, args):
    cmd = 'tamper check\r'

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_fault_check(console_object, args):
    cmd = 'tamper faults\r'

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_config_status(console_object, args):
    cmd = 'tamper config status\r'

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_tamper_extended_faults(console_object, args):
    cmd = 'tamper extended faults\r'

    return console_object.cty_conn.send_raw_all(cmd, 15)

def dks_tamper_test(console_object, args):
    console_object.tamper.on_tamper()

    return "TESTING TAMPER"

def dks_tamper_reset(console_object, args):
    console_object.on_tamper_reset()

    return "RESETING TAMPER\r\nPlease restart the console.\r\n"

def dks_battery_set_enable(console_object, args):
    console_object.tamper_config.update_setting("battery", "tamper threshold set battery", [1])

    cmd = console_object.tamper_config.get_command_string("battery", '\r')

    return console_object.cty_conn.send_raw_all(cmd, 5)

def dks_battery_set_disable(console_object, args):
    console_object.tamper_config.update_setting("battery", "tamper threshold set battery", [0])

    cmd = console_object.tamper_config.get_command_string("battery", '\r')

    return console_object.cty_conn.send_raw_all(cmd, 5)

def add_tamper_commands(console_object):
    tamper_node = console_object.add_child('tamper')

    tamper_node.add_child(name="test", num_args=0,
                          usage=' - Test tamper functionality by '
                                'simulating an event.',
                          callback=dks_tamper_test)
    tamper_node.add_child(name="reset", num_args=0,
                          usage=' - Attempt to reset the tamper flag. This'
                                ' will fail during an ongoing tamper event.',
                          callback=dks_tamper_reset)

    tamper_node.add_child(name="check", num_args=0,
                          callback=dks_tamper_check)

    tamper_node.add_child(name="faults", num_args=0,
                            callback=dks_tamper_fault_check)

    tamper_node.add_child_tree(['config','status'], num_args=0,
                            callback=dks_tamper_config_status)

    tamper_node.add_child_tree(['extended','faults'], num_args=0,
                            callback=dks_tamper_extended_faults)
                            
    # add parent nodes
    set_node = tamper_node.add_child('set')
    get_node = tamper_node.add_child('get')

    # add thresholds
    set_node.add_child('temperature', num_args=2, callback=dks_tamper_threshold_set_temp)
    set_node.add_child('vibe', num_args=1, callback=dks_tamper_threshold_set_accel)
    set_node.add_child('light', num_args=1, callback=dks_tamper_threshold_set_light)
    set_node.add_child('disable', num_args=1, callback=dks_tamper_threshold_set_disable)
    set_node.add_child('enable', num_args=1, callback=dks_tamper_threshold_set_enable)
    set_node.add_child('config', num_args=0, callback=dks_tamper_set_config)

    get_node.add_child('temperature', num_args=0, callback=dks_tamper_threshold_get_temp)
    get_node.add_child('vibe', num_args=0, callback=dks_tamper_threshold_get_accel)
    get_node.add_child('light', num_args=0, callback=dks_tamper_threshold_get_light)

    # battery
    battery_set = console_object.add_child_tree(["battery", "set"])
    battery_set.add_child('enable', num_args=0, callback=dks_battery_set_enable)
    battery_set.add_child('disable', num_args=0, callback=dks_battery_set_disable)
