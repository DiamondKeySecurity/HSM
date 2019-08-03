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