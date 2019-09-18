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

import time

from script import ScriptModule, script_node, ValueType
from hsm_tools.cryptech_port import DKS_HALUser

class PasswordScriptModule(ScriptModule):
    def __init__(self, cty_direct_call, set_hide_input, cty_connection, user, must_set = False, finished_callback = None):
        self.cty_direct_call = cty_direct_call
        self.set_hide_input = set_hide_input
        self.cty_connection = cty_connection
        self.user = user

        node_list = []

        if (not must_set):
            node_list.append(script_node('continue',
                                         "Would you like to set the '%s' PIN? (y/n) "%DKS_HALUser.to_name(user),
                                         ValueType.YesNo, callback=self.continuePromptCallback))
        else:
            self.set_hide_input(True)

        node_list.append(script_node('password',
                                     "Enter the new '%s' PIN: "%DKS_HALUser.to_name(user),
                                     ValueType.AnyString, callback=None))
        node_list.append(script_node('confirm_password',
                                     "Confirm the new '%s' PIN: "%DKS_HALUser.to_name(user),
                                     ValueType.AnyString, callback=self.confirmPassword))


        super(PasswordScriptModule, self).__init__(node_list = node_list, finished_callback = finished_callback)

    def continuePromptCallback(self, response):
        if(response == True):
            self.set_hide_input(True)
            return self

        return None

    def confirmPassword(self, response):
        accepted = False

        if (' ' in self.results['password'] or 
           ('\t' in self.results['password'])):
            self.cty_direct_call('Sorry, but the PIN cannot contain any white space characters. PIN not accepted.')
        elif (self.results['password'] != self.results['confirm_password']):
            self.cty_direct_call('Sorry, but the PIN does not match. PIN not accepted.')
        else:
            accepted = True
            password = self.results['password']

            self.cty_connection.setPassword(DKS_HALUser.to_name(self.user), password)

            self.set_hide_input(False)

        if (accepted == False):
            # go back to the first node
            self.set_hide_input(True)
            self.current = 0
            return self
        else:
            return None