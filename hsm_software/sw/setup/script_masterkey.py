#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class MasterKeySetScriptModule(ScriptModule):
    def __init__(self, cty_conn, cty_direct_call, settings):
        self.cty_conn = cty_conn
        self.cty_direct_call = cty_direct_call
        self.settings = settings
        super(MasterKeySetScriptModule, self).__init__([
                        script_node('setmasterkey',
                                    'Because of a system reset, the master key may not be set.\r\nWould you like to set it now? (y/n) ',
                                    ValueType.YesNo, callback=self.setMasterKeyPromptCallback)
                        ])

    def setMasterKeyPromptCallback(self, response):
        """Process user response about whether they want to set the master key"""
        if(response == True):
            self.node_list.insert(self.current, script_node('masterkey_value',
                                                            ('Please enter the master key or leave it blank to set it to a random value\r\n'
                                                             '  -------- -------- -------- -------- -------- -------- -------- --------\r\n'
                                                             '> '),
                                                            ValueType.AnyString, callback=self.setMasterKeyCallback))
        return self

    def setMasterKeyCallback(self, response):
        """Use the user's response to set the master key"""
        result = self.cty_conn.setMasterKey(response)

        self.cty_direct_call(result)

        if('Success' not in result):
            self.cty_direct_call('\r\nThere was an error setting the master key.\r\nPlease try again later using the "masterkey set" command.\r\n')
        else:
            self.settings.set_setting(HSMSettings.MASTERKEY_SET, True)

        return self

