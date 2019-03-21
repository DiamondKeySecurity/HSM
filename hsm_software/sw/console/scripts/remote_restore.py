#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import time

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class RemoteRestoreScript(ScriptModule):
    def __init__(self, cty_direct_call, device_index):
        self.cty_direct_call = cty_direct_call
        self.device_index = device_index
        super(RemoteRestoreScript, self).__init__(node_list = [
                        script_node('continue',
                                    'Are you sure you want to restore the keys from a backup device to an internal device:%i? (y/n) '%device_index,
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('continue',
                                    'Have you connected a CrypTech device to the host computer? (y/n) ',
                                    ValueType.YesNo, callback=self.continueAttachedCrypTech),
                        script_node('continue',
                                    'Has the master key been entered into the CrypTech device? (y/n) ',
                                    ValueType.YesNo, callback=self.continueCrypTechMasterKey)
                        ])

    def continuePromptCallback(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            return self

        return None

    def continueAttachedCrypTech(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            return self

        self.cty_direct_call('A CrypTech device must be connected to the computer to continue.')

        return None

    def continueCrypTechMasterKey(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            return self

        return None
