#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from script import ScriptModule, script_node, ValueType

class FirmwareUpdateScriptModule(ScriptModule):
    def __init__(self, cty_mux, cty_direct_call, settings):
        self.cty_mux = cty_mux
        self.cty_direct_call = cty_direct_call
        self.settings = settings

        script_nodes = []

        if (settings.hardware_firmware_match()):
            script_nodes.append(script_node('updateFirmware',
                                            'Because of an HSM update the firmware on the CrypTech devices may not be up-to-date.\r\nWould you like to set it now? (y/n) ',
                                            ValueType.YesNo, callback=self.updateFirmwarePromptCallback))

        elif (settings.hardware_tamper_match()):
            script_nodes.append(script_node('updateTamper',
                                            'Because of an HSM update the tamper firmware on the CrypTech devices may not be up-to-date.\r\nWould you like to set it now? (y/n) ',
                                            ValueType.YesNo, callback=self.updateTamperPromptCallback))

        super(FirmwareUpdateScriptModule, self).__init__(script_nodes)

    def updateFirmwarePromptCallback(self, response):
        """Process user response about whether they want to set the master key"""
        if(response == True):
            self.cty_mux.dks_update_cryptech_firmware(None)

            return None
        else:
            self.cty_direct_call('The console will be locked until the firmware has been updated.')

        return None

    def updateTamperPromptCallback(self, response):
        """Process user response about whether they want to set the master key"""
        if(response == True):
            self.cty_mux.dks_update_cryptech_tamper(None)

            return None
        else:
            self.cty_direct_call('The console will be locked until the tamper firmware has been updated.')

        return None

