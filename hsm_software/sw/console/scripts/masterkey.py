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

from settings import HSMSettings

from script import ScriptModule, script_node, ValueType

class MasterKeySetScriptModule(ScriptModule):
    def __init__(self, cty_conn, cty_direct_call, settings, message = None, finished_callback = None):
        self.cty_conn = cty_conn
        self.cty_direct_call = cty_direct_call
        self.settings = settings

        if (message is None):
            message = '\r\nAre you sure you want to set the master key? (y/n) '

        super(MasterKeySetScriptModule, self).__init__([
                        script_node('setmasterkey',
                                    message,
                                    ValueType.YesNo, callback=self.setMasterKeyPromptCallback)
                        ], finished_callback = finished_callback)

    def setMasterKeyPromptCallback(self, response):
        """Process user response about whether they want to set the master key"""
        if(response == True):
            self.node_list.insert(self.current, script_node('masterkey_value',
                                                            ('Please enter the master key or leave it blank to set it to a random value\r\n'
                                                             '  -------- -------- -------- -------- -------- -------- -------- --------\r\n'
                                                             '> '),
                                                            ValueType.AnyString, callback=self.setMasterKeyCallback))
            return self
        else:
            return None

    def setMasterKeyCallback(self, response):
        """Use the user's response to set the master key"""
        result = self.cty_conn.setMasterKey(response)

        self.cty_direct_call(result)

        if('Success' not in result):
            self.cty_direct_call('\r\nThere was an error setting the master key.\r\nPlease try again later using the "masterkey set" command.\r\n')
        else:
            self.settings.set_setting(HSMSettings.MASTERKEY_SET, True)

        return None

