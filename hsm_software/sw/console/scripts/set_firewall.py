#!/usr/bin/env python
# Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
#
import time
import sys

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class firewall_setting_script(ScriptModule):
    """Base class for a script that sets a firewall settings
    and then updates the firewall"""
    def __init__(self, settings, cty_direct_call, hsm_setting, update_firewall_from_settings, node_list):
        self.settings = settings
        self.cty_direct_call = cty_direct_call
        self.hsm_setting = hsm_setting
        self.update_firewall_from_settings = update_firewall_from_settings
        super(firewall_setting_script, self).__init__(node_list = node_list)

    def update_setting(self, new_value, msg):
        self.settings.set_setting(self.hsm_setting, new_value)

        # update the firewall rules
        self.update_firewall_from_settings()

        self.cty_direct_call("'%s' %s."%(self.hsm_setting.value, msg))

class firewall_all_script(firewall_setting_script):
    """Script to accept all connections"""
    def __init__(self, settings, cty_direct_call, hsm_setting, generate_firewall_rules):
        super(firewall_all_script, self).__init__(settings, cty_direct_call, hsm_setting, generate_firewall_rules,
                                                  node_list = [script_node('continue',
                                                                           "Would you like to set '%s' to allow all? (y/n) "%hsm_setting.value,
                                                                           ValueType.YesNo, callback=self.continuePromptCallback)
                                                              ]
                                                  )

    def continuePromptCallback(self, response):
        if(response == True):
            self.update_setting(True, 'set to allow all connections')

        return None

class firewall_block_script(firewall_setting_script):
    """Script to block all connections"""
    def __init__(self, settings, cty_direct_call, hsm_setting, generate_firewall_rules):
        super(firewall_block_script, self).__init__(settings, cty_direct_call, hsm_setting, generate_firewall_rules,
                                                    node_list = [script_node('continue',
                                                                             "Would you like to set '%s' to block all? (y/n) "%hsm_setting.value,
                                                                             ValueType.YesNo, callback=self.continuePromptCallback)
                                                                ]
                                                    )

    def continuePromptCallback(self, response):
        if(response == True):
            self.update_setting(False, 'set to block all connections')

        return None

class firewall_iprange_script(firewall_setting_script):
    """Script to block all connections"""
    def __init__(self, settings, cty_direct_call, hsm_setting, generate_firewall_rules):
        super(firewall_iprange_script, self).__init__(settings, cty_direct_call, hsm_setting, generate_firewall_rules,
                                                    node_list = [script_node('continue',
                                                                             "Would you like to set '%s' to an IP range? (y/n) "%hsm_setting.value,
                                                                             ValueType.YesNo, callback=self.continuePromptCallback),
                                                                 script_node('startip',
                                                                            'Please enter the start of the address range. (ex. 192.1.1.1) ',
                                                                            ValueType.IP4Address),
                                                                 script_node('endip',
                                                                            'Please enter the end of the address range. (ex. 192.1.1.255) ',
                                                                            ValueType.IP4Address, callback=self.showEnteredSettings),
                                                                 script_node('correct',
                                                                            'Are these settings correct? (y/n) ',
                                                                            ValueType.YesNo, callback=self.setIPSettingsCallback)
                                                                ]
                                                    )

    def continuePromptCallback(self, response):
        if(response == True):
            return self

        return None

    def setIPSettingsCallback(self, response):
        if(response == True):
            start = self.results['startip']
            end = self.results['endip']

            if(self.verify_range(start, end) is False):
                self.cty_direct_call('Error %s is not greater than %s'%(end, start))
            else:
                self.update_setting((start, end), 'set to ip range (%s, %s)'%(start, end))
        else:
            self.cty_direct_call("Firewall settings not changed.")

        return None

    def showEnteredSettings(self, response):
        self.cty_direct_call("Start IP address: %s"%self.results['startip'])
        self.cty_direct_call("End IP address: %s"%self.results['endip'])

        return self

    def verify_range(self, start, end):
        split_start = start.split('.')
        split_end = end.split('.')

        try:
            for i in range(4):
                if (int(split_start[i]) > int(split_end[i])):
                    return False
        except Exception:
            return False

        return True

class firewall_iplist_script(firewall_setting_script):
    """Script to block all connections"""
    def __init__(self, settings, cty_direct_call, hsm_setting, generate_firewall_rules):
        self.ipaddr_list = []

        super(firewall_iplist_script, self).__init__(settings, cty_direct_call, hsm_setting, generate_firewall_rules,
                                                    node_list = [script_node('continue',
                                                                             "Would you like to set '%s' to an IP address list? (y/n) "%hsm_setting.value,
                                                                             ValueType.YesNo, callback=self.continuePromptCallback),
                                                                 script_node('ipaddr',
                                                                            'Please enter one IP address at a time. Enter 0 when done. > ',
                                                                            ValueType.IP4Address, callback=self.addIPAddressCallback)
                                                                ]
                                                    )

    def continuePromptCallback(self, response):
        if(response == True):
            return self

        return None

    def addIPAddressCallback(self, response):
        if(response == '0.0.0.0'):
            if (len(self.ipaddr_list) == 0):
                self.cty_direct_call('Unable to set IP address list. Must include at least one IP address.')
                return None

            self.cty_direct_call('Adding the following IP address')
            for ip in self.ipaddr_list:
                self.cty_direct_call(ip)

            self.node_list.append(script_node('correct',
                                              'Are these settings correct? (y/n) ',
                                              ValueType.YesNo, callback=self.acceptSettingsCallback))
        else:
            self.ipaddr_list.append(response)
            self.node_list.append(script_node('ipaddr',
                                              'Please enter one IP address at a time. Enter 0 when done. > ',
                                              ValueType.IP4Address, callback=self.addIPAddressCallback))

        return self

    def acceptSettingsCallback(self, response):
        if(response == True):
            self.update_setting(self.ipaddr_list, 'set to an IP address list')
        else:
            self.cty_direct_call("Firewall settings not changed.")
    
        return None

class FirewallChangeSettingScript(ScriptModule):
    """script to change a firewall setting"""
    def __init__(self, settings, cty_direct_call, hsm_setting, update_firewall_from_settings):
        self.settings = settings
        self.cty_direct_call = cty_direct_call
        self.hsm_setting = hsm_setting
        self.update_firewall_from_settings = update_firewall_from_settings

        cur_setting_value = self.settings.get_setting(hsm_setting)

        if ((cur_setting_value is None) or (cur_setting_value is True)):
            current_setting = 'accepting all connections'
        elif isinstance(cur_setting_value, tuple):
            current_setting = 'accepting connections from ip range, %s to %s'%(cur_setting_value[0], cur_setting_value[1])
        elif isinstance(cur_setting_value, list):
            current_setting = 'accepting connections from the ip address list'
        elif (cur_setting_value is False):
            current_setting = 'blocking all connections'

        super(FirewallChangeSettingScript, self).__init__(node_list = [
                        script_node('continue',
                                    "%s is currently set to :'%s.'\r\nWould you like to change this? (y/n) "%(hsm_setting.value, current_setting),
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('changeTo',
                                    ("What would you like to change this to?\r\n"
                                     " A - (A)ccept all\r\n"
                                     " R - IP address (R)ange\r\n"
                                     " L - IP address (L)ist\r\n"
                                     " B - (B)lock all connections\r\n\r\n"
                                     "'A', 'R', 'L', or 'B' > "),
                                    ValueType.AnyString, callback=self.changeToPromptCallback)
                        ])

    def continuePromptCallback(self, response):
        if(response == True):
            # continue
            return self

        return None

    def changeToPromptCallback(self, response):
        if (response.lower() == 'a'):
            return firewall_all_script(self.settings, self.cty_direct_call, self.hsm_setting, self.update_firewall_from_settings)
        elif (response.lower() == 'r'):
            return firewall_iprange_script(self.settings, self.cty_direct_call, self.hsm_setting, self.update_firewall_from_settings)
        elif (response.lower() == 'l'):
            return firewall_iplist_script(self.settings, self.cty_direct_call, self.hsm_setting, self.update_firewall_from_settings)
        elif (response.lower() == 'b'):
            return firewall_block_script(self.settings, self.cty_direct_call, self.hsm_setting, self.update_firewall_from_settings)
        else:
            self.cty_direct_call("Unexpected response '%s'.\r\nPlease try again."%response)

        return None