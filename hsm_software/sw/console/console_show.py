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

import os
import shutil
import time

from settings import HSMSettings, HSM_SOFTWARE_VERSION

def dks_show_firewall_settings(console_object, args):
    if (args[0].lower() == "mgmt"):
        setting = console_object.settings.get_setting(HSMSettings.MGMT_FIREWALL_SETTINGS)
    elif (args[0].lower() == "data"):
        setting = console_object.settings.get_setting(HSMSettings.DATA_FIREWALL_SETTINGS)
    elif (args[0].lower() == "web"):
        setting = console_object.settings.get_setting(HSMSettings.WEB_FIREWALL_SETTINGS)
    else:
        return "Expected 'mgmt', 'data', or 'web'"

    if ((setting is None) or (setting is True)):
        return 'Accepting all connections on the %s port\r\n'%args[0]
    elif (setting is False):
        return 'Blocking all connections to the %s port\r\n'%args[0]
    elif isinstance(setting, tuple):
        return 'Accepting connections from ip range, %s to %s on the %s port\r\n'%(setting[0], setting[1], args[0])
    elif isinstance(setting, list):
        console_object.cty_direct_call('Accepting connections from the following ip address on the %s port\r\n'%args[0])
        for line in setting:
            console_object.cty_direct_call(str(line))
        return '----'

def dks_show_cache(console_object, args):
    results = console_object.cache.getVerboseMapping()

    for line in results:
        console_object.cty_direct_call(line)

    return ''

def dks_show_ipaddr(console_object, args):
    return console_object.netiface.get_ip()

def dks_show_macaddr(console_object, args):
    return console_object.netiface.get_mac()

def dks_show_time(console_object, args):
    return time.strftime("%c")

def dks_show_devices(console_object, args):
    message = "Cryptech devices currently connected to HSM:\r\n"
    cty_result = console_object.check_has_cty()
    if (cty_result is True):
        for d in console_object.cty_conn.cty_list:
            message += "\r\n > " + d.name
    else:
        message += cty_result

    rpc_result = console_object.check_has_rpc()
    if (rpc_result is True):
        for d in console_object.rpc_preprocessor.rpc_list:
            message += "\r\n > " + d.name
    else:
        message += rpc_result

    return message

def dks_show_rpc(console_object, args):
    # make sure a rpc has been connected
    rpc_result = console_object.check_has_rpc()
    if (rpc_result is not True):
        return rpc_result

    return "Current RPC mode: " + console_object.rpc_preprocessor.get_current_rpc()

def dks_show_settings(console_object, args):
    result = '\r\n\r\nDiamond HSM Settings:\r\n\r\n'
    for key, value in console_object.settings.dictionary.iteritems():
        setting = "[%s] = %s\r\n" % (str(key), str(value))
        result += setting

    return result

def dks_show_serialnumber(console_object, args):
    return console_object.args.serial_number

def dks_show_version(console_object, args):
    return HSM_SOFTWARE_VERSION

def dks_show_log(console_object, args):
    try:
        # make a copy of the log to avoid issues
        logfile_read = "%s.2" % console_object.args.log_file

        try:
            os.remove(logfile_read)
        except Exception:
            pass

        shutil.copyfile(console_object.args.log_file, logfile_read)

        with open(logfile_read) as log:
            for line in log:
                console_object.cty_direct_call(' > %s' % line.rstrip("\r\n"))

        return "\r\n\r\n%s\r\n" % console_object.args.log_file
    except Exception as e:
        return e.message

def dks_show_fpga_cores(console_object, args):
    result = console_object.cty_conn.show_fpga_cores()
    for line in result:
        console_object.cty_direct_call(line)

    return '--------'

def dks_show_key_count(console_object, args):
    result = ["\r\nCached Key Count: --------"]
    cache = console_object.cache

    for alpha_index in range(cache.rpc_count):
        alpha_table = cache.get_alphaTable(alpha_index)
        result.append("--CrypTech device:%i count == %i"%(alpha_index, len(alpha_table)))

    for line in result:
        console_object.cty_direct_call(line)

    return '--------'

def add_show_commands(console_object):
    show_node = console_object.add_child('show')

    show_node.add_child(name="rpc", num_args=0,
                        usage=' - Displays the current CrypTech device'
                                ' RPC selection mode.',
                        callback=dks_show_rpc)
    show_node.add_child(name="time", num_args=0,
                        usage=' - Shows the current HSM system time.',
                        callback=dks_show_time)
    show_node.add_child(name="devices", num_args=0,
                        usage=' - Shows the currently connected'
                                ' CrypTech devices.',
                        callback=dks_show_devices)
    show_node.add_child(name="ipaddr", num_args=0,
                        usage=' - Shows the current HSM IP address.',
                        callback=dks_show_ipaddr)
    show_node.add_child(name="macaddr", num_args=0,
                        usage=" - Shows the 'HSM's MAC address.",
                        callback=dks_show_macaddr)
    show_node.add_child(name="settings", num_args=0,
                        usage=' - Lists all HSM overridable settings.',
                        callback=dks_show_settings)
    show_node.add_child(name="serial-number", num_args=0,
                        usage=" - Shows the HSM's serial number.",
                        callback=dks_show_serialnumber)
    show_node.add_child(name="version", num_args=0,
                        usage=' - Shows the HSM firmware version.',
                        callback=dks_show_version)
    show_node.add_child(name="log", num_args=0,
                        usage=' - Displays the system log.',
                        callback=dks_show_log)
    show_node.add_child(name="cache", num_args=0,
                        usage=' - Shows all of the keys that have been '
                                'mapped in the system cache.',
                        callback=dks_show_cache)

    show_node.add_child_tree(token_list=['key','count'],
                             num_args = 0,
                             usage = ' - shows the number of keys',
                             callback = dks_show_key_count)

    fpga_node = show_node.add_child(name="fpga")
    fpga_node.add_child(name="cores", num_args=0,
                        usage=' - Shows the loaded FGPA cores'
                        ' and versions.',
                        callback=dks_show_fpga_cores)

    show_node.add_child_tree(token_list=['firewall', 'settings'],
                                num_args=1, usage=' - <mgmt, data, web> - Shows the firewall settings for a connection type.',
                                callback=dks_show_firewall_settings)