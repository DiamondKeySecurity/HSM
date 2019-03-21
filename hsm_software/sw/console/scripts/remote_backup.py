#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import time

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class RemoteBackupScript(ScriptModule):
    def __init__(self, cty_direct_call, device_index):
        self.cty_direct_call = cty_direct_call
        self.device_index = device_index
        super(RemoteBackupScript, self).__init__(node_list = [
                        script_node('continue',
                                    'Are you sure you want to back up the keys on device:%i to a remote device? (y/n) '%device_index,
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('continue',
                                    'Have you connected a CrypTech device to the host computer? (y/n) ',
                                    ValueType.YesNo, callback=self.continueAttachedCrypTech),
                        script_node('continue',
                                    'Has the master key been generated on the CrypTech device? (y/n) ',
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

    def addSetMasterKeyScript(self):
        self.node_list.insert(self.current, script_node('masterkey_value',
                                                        ('Please enter the master key or leave it blank to set it to a random value\r\n'
                                                            '  -------- -------- -------- -------- -------- -------- -------- --------\r\n'
                                                            '> '),
                                                        ValueType.AnyString, callback=self.setMasterKeyCallback))

        return self

    def isMasterKeyValid(self, masterkey):
        masterkey = masterkey.strip('\r\n')
        count = 0
        for c in masterkey:
            if (c != ' '):
                count = count + 1
                if c not in 'abcdef0123456789':
                    return False

        return count == 64

    def setMasterKeyCallback(self, response):
        # check masterkey formating
        if (response == ''):
            self.cty_direct_call("A masterkey will be randomly generated on the backup CrypTech device.")
        elif (self.isMasterKeyValid(response)):
            self.cty_direct_call("'%s' will be used as the master key on the backup CrypTech device."%response)

        return self

    def continueCrypTechMasterKey(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            return self
        else:
            return self.addSetMasterKeyScript()

        return None
