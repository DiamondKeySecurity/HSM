#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import time

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class DHCPScriptModule(ScriptModule):
    def __init__(self, settings, cty_direct_call, safe_shutdown):
        self.settings = settings
        self.cty_direct_call = cty_direct_call
        self.safe_shutdown = safe_shutdown
        super(DHCPScriptModule, self).__init__(node_list = [
                        script_node('continue',
                                    'Would you like to set the HSM to use DHCP? (y/n) ',
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('restart',
                                    'The HSM will need to restart. Would you like to restart now? (y/n) ',
                                    ValueType.YesNo, callback=self.restartPromptCallback)                                    
                        ])

    def continuePromptCallback(self, response):
        if(response == True):
            self.settings.set_setting(HSMSettings.IP_ADDRESS_SETTINGS, 'DHCP')

            self.cty_direct_call("DHCP set successfully.")
            return self

        return None

    def restartPromptCallback(self, response):
        if(response == True):
            self.cty_direct_call("HSM Restarting in 5 seconds....")
            time.sleep(5)

            self.safe_shutdown.restart()

        return None