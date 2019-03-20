#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from script import ScriptModule, script_node, ValueType

from console.console_update import dks_update_cryptech_firmware, dks_update_cryptech_tamper

class FirmwareUpdateScript(ScriptModule):
    def __init__(self, cty_mux, cty_direct_call, settings):
        self.cty_mux = cty_mux
        self.cty_direct_call = cty_direct_call
        self.settings = settings

        script_nodes = []

        if (not settings.hardware_firmware_match()):
            script_nodes.append(script_node('updateFirmware',
                                            ('Because of an HSM update the '
                                             'firmware on the CrypTech devices'
                                             ' may not be up-to-date.\r\nWould'
                                             ' you like to set it now?'
                                             ' (y/n) '),
                                            ValueType.YesNo,
                                            callback=self.updateFirmwarePrompt)
                                )

        elif (not settings.hardware_tamper_match()):
            script_nodes.append(script_node('updateTamper',
                                            ('Because of an HSM update the'
                                             ' tamper firmware on the'
                                             ' CrypTech devices may not be'
                                             ' up-to-date.\r\nWould you'
                                             ' like to set it now? (y/n) '),
                                            ValueType.YesNo,
                                            callback=self.updateTamperPrompt)
                                )

        super(FirmwareUpdateScript, self).__init__(script_nodes)

    def updateFirmwarePrompt(self, response):
        """Process user response about whether
           they want to set the master key"""
        if(response is True):
            dks_update_cryptech_firmware(self.cty_mux, None)

            return None
        else:
            self.cty_direct_call('You will not be able to use the HSM until the'
                                 ' firmware has been updated.')

        return None

    def updateTamperPrompt(self, response):
        """Process user response about whether
           they want to set the master key"""
        if(response is True):
            dks_update_cryptech_tamper(self.cty_mux, None)

            return None
        else:
            self.cty_direct_call('You will not be able to use the HSM until the'
                                 ' tamper firmware has been updated.')

        return None

