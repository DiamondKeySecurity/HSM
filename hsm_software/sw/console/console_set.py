#!/usr/bin/env python
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


from settings import HSMSettings

from hsm_tools.cryptech_port import DKS_HALUser

from scripts.masterkey import MasterKeySetScriptModule
from scripts.ip_dhcp import DHCPScriptModule
from scripts.ip_static import StaticIPScriptModule
from scripts.updateRestart import UpdateRestartScriptModule
from scripts.password import PasswordScriptModule
from scripts.set_firewall import FirewallChangeSettingScript

def dks_set_firewall_settings(console_object, args):
    if (args[0].lower() == "mgmt"):
        setting = HSMSettings.MGMT_FIREWALL_SETTINGS
    elif (args[0].lower() == "data"):
        setting = HSMSettings.DATA_FIREWALL_SETTINGS
    elif (args[0].lower() == "web"):
        setting = HSMSettings.WEB_FIREWALL_SETTINGS
    elif (args[0].lower() == "ssh" and (console_object.settings.get_setting(HSMSettings.ALLOW_SSH) is True)):
        setting = HSMSettings.SSH_FIREWALL_SETTINGS
    elif (console_object.settings.get_setting(HSMSettings.ALLOW_SSH)):
        return "Expected 'mgmt', 'data', 'web', or 'ssh'"
    else:
        return "Expected 'mgmt', 'data', or 'web'"

    # start the script
    console_object.script_module = FirewallChangeSettingScript(console_object.settings,
                                                               console_object.cty_direct_call,
                                                               setting,
                                                               console_object.update_firewall_from_settings)

    console_object.cty_direct_call(console_object.prompt)

    return True

def dks_set_rpc(console_object, args):
    # make sure a rpc has been connected
    rpc_result = console_object.check_has_rpc()
    if (rpc_result is not True):
        return rpc_result

    try:
        index = int(args[0])
    except ValueError:
        index = 0
        if (args[0].lower() == "auto"):
            index = -1
        else:
            return 'invalid argument "%s"' % args[0]

    return console_object.rpc_preprocessor.set_current_rpc(index)

def dks_set_pin(console_object, args):
    current_user = DKS_HALUser.from_name(console_object.current_user)
    user = DKS_HALUser.from_name(args[0])
    if(user is not None):
        if (user == DKS_HALUser.HAL_USER_NORMAL or user == current_user):
            # start the script
            console_object.script_module = PasswordScriptModule(console_object.cty_direct_call,
                                                        console_object.set_hide_input,
                                                        console_object.cty_conn, user)

            console_object.cty_direct_call(console_object.prompt)

            return True
        else:
            return "Not authorized to change the '%s' password."%args[0]
    else:
        return "<user> must be 'wheel', 'so', or 'user'"

def dks_set_ip_dhcp_onlogin(console_object, pin, username):
    if (username.lower() != 'wheel' and username.lower() != 'so'):
        console_object.cty_direct_call("Insufficient privileges to carry out this operation.\r\nMust be 'wheel' or 'so'.")
        return

    message = ['This will set the HSM to use a DHCP server for IP',
                'address selection. It is recommended to always use DHCP.',
                'When a static ip is needed, it is recommended to',
                'configure the DHCP server to reserve a specific IP',
                'address for the HSM.',
                'If a DHCP cannot be found, the default static IP,',
                "'10.10.10.2' will be used\r\n"]

    for line in message:
        console_object.cty_direct_call(line)

    # start the script
    console_object.script_module = DHCPScriptModule(console_object.settings,
                                                    console_object.cty_direct_call,
                                                    console_object.safe_shutdown)

    console_object.cty_direct_call(console_object.prompt)

def dks_set_ip_static_onlogin(console_object, pin, username):
    if (username.lower() != 'wheel' and username.lower() != 'so'):
        console_object.cty_direct_call("Insufficient privileges to carry out this operation.\r\nMust be 'wheel' or 'so'.")
        return

    message = ['This will set the HSM to use a manually set static IP',
                'address. Please use caution when setting a static IP',
                'because the ethernet port is the only way to communicate',
                'with the HSM.\r\n',
                'While manual static IP selection is supported,',
                'it is recommended to always use DHCP.',
                'When a static ip is needed, it is recommended to',
                'configure the DHCP server to reserve a specific IP',
                'address for the HSM.',
                'If a DHCP cannot be found, the default static IP,',
                "'10.10.10.2' will be used\r\n"]

    for line in message:
        console_object.cty_direct_call(line)

    # start the script
    console_object.script_module = StaticIPScriptModule(console_object.settings,
                                                        console_object.cty_direct_call,
                                                        console_object.safe_shutdown)

    console_object.cty_direct_call(console_object.prompt)

def dks_set_ip(console_object, args):
    if(args[0] == 'dhcp'):
        console_object.redo_login(dks_set_ip_dhcp_onlogin)
        return True
    if(args[0] == 'static'):
        console_object.redo_login(dks_set_ip_static_onlogin)
        return True

def toggle_settings(console_object, setting, value_str):
    if(value_str.lower() == 'true'):
        value = True
    elif(value_str.lower() == 'false'):
        value = False

    console_object.settings.set_setting(setting, value)

    return value

def dks_set_enable_exportable_private_keys(console_object, args):
    result = toggle_settings(console_object, HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS, args[0])
    return 'ENABLE_EXPORTABLE_PRIVATE_KEYS set to %s'%str(result)

def dks_set_enable_key_export(console_object, args):
    result = toggle_settings(console_object, HSMSettings.ENABLE_KEY_EXPORT, args[0])
    return 'ENABLE_KEY_EXPORT set to %s'%str(result)

def dks_set_enable_zeroconf(console_object, args):
    result = toggle_settings(console_object, HSMSettings.ZERO_CONFIG_ENABLED, args[0])

    # update the firewall rules
    console_object.update_firewall_from_settings()

    if (result is True):
        console_object.zero_conf_object.register_service()
    else:
        console_object.zero_conf_object.unregister_service()

    return 'ZERO_CONFIG_ENABLED set to %s'%str(result)

def add_set_commands(console_object):
    set_node = console_object.add_child('set')

    set_node.add_child(name="rpc", num_args=1,
                        usage="<rpc index or 'auto'>",
                        callback=dks_set_rpc)
    set_node.add_child(name="pin", num_args=1,
                        usage="<user name - 'wheel', 'so', or 'user'>",
                        callback=dks_set_pin)
    set_node.add_child(name="ip", num_args=1, usage="<'static' or 'dhcp'>",
                        callback=dks_set_ip)
    set_node.add_child(name="ENABLE_EXPORTABLE_PRIVATE_KEYS",
                        num_args=1, usage="<'true' or 'false'>",
                        callback=dks_set_enable_exportable_private_keys)
    set_node.add_child(name="ENABLE_KEY_EXPORT", num_args=1,
                        usage="<'true' or 'false'>",
                        callback=dks_set_enable_key_export)

    set_node.add_child(name="ENABLE_ZEROCONF", num_args=1,
                        usage=" - <'true' or 'false'>",
                        callback=dks_set_enable_zeroconf)

    set_node.add_child_tree(token_list=['firewall', 'settings'], num_args=1,
                            usage=' - <mgmt, data, web> - Sets the firewall settings for a connection type.',
                            callback=dks_set_firewall_settings)