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