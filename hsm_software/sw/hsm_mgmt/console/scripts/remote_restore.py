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
#
import time

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class RemoteRestoreScript(ScriptModule):
    def __init__(self, cty_direct_call, device_index, finished_callback, console_object):
        self.cty_direct_call = cty_direct_call
        self.device_index = device_index
        self.console_object = console_object
        super(RemoteRestoreScript, self).__init__(node_list = [
                        script_node('continue',
                                    'Are you sure you want to restore the keys to device:%i from a remote device? (y/n) '%device_index,
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('continue',
                                    'Have you connected a CrypTech device to the host computer? (y/n) ',
                                    ValueType.YesNo, callback=self.continueAttachedCrypTech),
                        script_node('cryptech_pin',
                                    "Please enter the 'user' pin for the CrypTech device. > " ,
                                    ValueType.AnyString, callback=self.pinEntered),
                        script_node('continue',
                                    'Has the master key been generated on the CrypTech device? (y/n) ',
                                    ValueType.YesNo, callback=self.continueCrypTechMasterKey)
                        ],
                        finished_callback=finished_callback)

    def continuePromptCallback(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            return self

        return None

    def continueAttachedCrypTech(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            # don't show the password
            self.console_object.hide_input = True
            return self

        self.cty_direct_call('A CrypTech device must be connected to the computer to continue.')

        return None

    def pinEntered(self, response):
        # show user input
        self.console_object.hide_input = False

        return self

    def addSetMasterKeyScript(self):
        self.node_list.insert(self.current, script_node('masterkey_value',
                                                        ('Please enter the master key. This cannot be left blank.\r\n'
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
                if (c not in 'abcdef0123456789'):
                    return False

        return count == 64

    def setMasterKeyCallback(self, response):
        # check masterkey formating
        if (self.isMasterKeyValid(response)):
            self.cty_direct_call("'%s' will be used as the master key on the backup CrypTech device."%response)
        else:
            self.cty_direct_call("Invalid master key entered.")
            return None

        return self.addCheckSettings()

    def continueCrypTechMasterKey(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            return self.addCheckSettings()
        else:
            return self.addSetMasterKeyScript()

    def addCheckSettings(self):
        if('masterkey_value' in self.results):
            masterkey_option = self.results['masterkey_value']
        else:
            self.results['masterkey_value'] = None
            masterkey_option = 'The master key was already set on the device.'

        self.results['device_index'] = self.device_index

        self.node_list.insert(self.current, script_node('continue',
                              'Would you like to restore from a CrypTech device using the following options?:\r\n'
                              '  Backup CrypTech device master key: %s\r\n'
                              '  Source internal device index     : %i\r\n'
                              'Continue with these settings? (y/n) '%(masterkey_option,
                                                                      self.results['device_index']),
                              ValueType.YesNo, callback=self.checkSettingsCallback))

        return self
        
    def checkSettingsCallback(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            self.finished_callback(self.console_object, self.results)
            return None
        else:
            self.finished_callback(self.console_object, None)
            return None
