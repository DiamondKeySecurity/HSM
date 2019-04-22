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
#
import time

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class RemoteBackupScript(ScriptModule):
    def __init__(self, cty_direct_call, device_index, finished_callback, console_object):
        self.cty_direct_call = cty_direct_call
        self.device_index = device_index
        self.console_object = console_object
        super(RemoteBackupScript, self).__init__(node_list = [
                        script_node('continue',
                                    'Are you sure you want to back up the keys on device:%i to a remote device? (y/n) '%device_index,
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
                if (c not in 'abcdef0123456789'):
                    return False

        return count == 64

    def setMasterKeyCallback(self, response):
        # check masterkey formating
        if (response == ''):
            self.cty_direct_call("A masterkey will be randomly generated on the backup CrypTech device.")
        elif (self.isMasterKeyValid(response)):
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
            if(self.results['masterkey_value'] == ''):
                masterkey_option = 'Master key will be randomly generated on the backup device.'
            else:
                masterkey_option = self.results['masterkey_value']
        else:
            self.results['masterkey_value'] = None
            masterkey_option = 'The master key was already set on the device.'

        self.results['device_index'] = self.device_index

        self.node_list.insert(self.current, script_node('continue',
                              'Would you like to back up to a CrypTech device using the following options?:\r\n'
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