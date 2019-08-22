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

class SyncImport(ScriptModule):
    def __init__(self, cty_direct_call, device_index, finished_callback, console_object):
        self.cty_direct_call = cty_direct_call
        self.device_index = device_index
        self.console_object = console_object
        super(SyncImport, self).__init__(node_list = [
                        script_node('continue',
                                    ('\r\nAre you sure you want to import CrypTech Json data\r\n'
                                    'from a remote device to this HSM\'s internal device #%i? (y/n) '%device_index),
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('export_json_path',
                                    ('Please enter the file name with path on the host computer\r\n'
                                    'of the export json from the external device. > '),
                                    ValueType.AnyString, callback=self.exportjson_entered)
                        ],
                        finished_callback=finished_callback,
                        auto_finished_callback=False)

    def continuePromptCallback(self, response):
        """Process user response about whether they want to continue"""
        if(response == True):
            return self

        return None

    def exportjson_entered(self, response):
        self.results['device_index'] = self.device_index

        self.node_list.insert(self.current, script_node('continue',
                              'Would you like to generate a KEKEK using the following settings?:\r\n'
                              '  Input export.json path ------------: %s\r\n'
                              '  Destination internal device index -: %i\r\n'
                              'Continue with these settings? (y/n) '%(self.results['export_json_path'],
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