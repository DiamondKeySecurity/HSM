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
import time

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class StaticIPScriptModule(ScriptModule):
    def __init__(self, settings, cty_direct_call, safe_shutdown):
        self.settings = settings
        self.cty_direct_call = cty_direct_call
        self.safe_shutdown = safe_shutdown
        super(StaticIPScriptModule, self).__init__(node_list = [
                        script_node('continue',
                                    'Would you like to set a manual static IP address? (y/n) ',
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('ipaddr',
                                    'Please enter the IP address. (ex. 192.1.1.10) ',
                                    ValueType.IP4Address),
                        script_node('netmask',
                                    'Please enter the net mask. (ex. 255.255.255.0) ',
                                    ValueType.IP4Address),
                        script_node('broadcast',
                                    'Please enter the broadcast address. (ex. 192.1.1.255) ',
                                    ValueType.IP4Address),
                        script_node('gateway',
                                    'Please enter the gateway. (ex. 192.1.1.1) ',
                                    ValueType.IP4Address, callback=self.showEnteredSettings),
                        script_node('correct',
                                    'Are these settings correct? (y/n) ',
                                    ValueType.YesNo, callback=self.setIPSettingsCallback),
                        script_node('restart',
                                    'The HSM will need to restart. Would you like to restart now? (y/n) ',
                                    ValueType.YesNo, callback=self.restartPromptCallback)                                    
                        ])

    def continuePromptCallback(self, response):
        """Process user response about whether they want to set the dhcpcd.conf file"""
        if(response == True):
            return self

        return None

    def setIPSettingsCallback(self, response):
        if(response == True):
            self.settings.set_setting(HSMSettings.IP_ADDRESS_SETTINGS, 'STATIC_IP')
            self.settings.set_setting(HSMSettings.STATICIP_IPADDR, self.results['ipaddr'])
            self.settings.set_setting(HSMSettings.STATICIP_NETMASK, self.results['netmask'])
            self.settings.set_setting(HSMSettings.STATICIP_GATEWAY, self.results['gateway'])
            self.settings.set_setting(HSMSettings.STATICIP_BROADCAST, self.results['broadcast'])

            self.cty_direct_call("Static IP set successfully.")
            return self
        else:
            self.cty_direct_call("Static IP not set.")
            self.cty_direct_call("Please use 'set ip static' to try again.")

        return None        

    def showEnteredSettings(self, response):
        self.cty_direct_call("Static IP address: %s"%self.results['ipaddr'])
        self.cty_direct_call("Broadcast: %s"%self.results['broadcast'])
        self.cty_direct_call("Net mask: %s"%self.results['netmask'])
        self.cty_direct_call("Gateway: %s"%self.results['gateway'])

        return self

    def restartPromptCallback(self, response):
        """Process user response about whether they want to reboot now"""
        if(response == True):
            self.cty_direct_call("HSM Restarting in 5 seconds....")
            time.sleep(5)

            self.safe_shutdown.restart()

        return None