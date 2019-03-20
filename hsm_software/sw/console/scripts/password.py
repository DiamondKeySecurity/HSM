#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import time

from script import ScriptModule, script_node, ValueType
from hsm_tools.cryptech_port import DKS_HALUser

class PasswordScriptModule(ScriptModule):
    def __init__(self, cty_direct_call, set_hide_input, cty_connection, user):
        self.cty_direct_call = cty_direct_call
        self.set_hide_input = set_hide_input
        self.cty_connection = cty_connection
        self.user = user
        super(PasswordScriptModule, self).__init__(node_list = [
                        script_node('continue',
                                    "Would you like to set the '%s' PIN? (y/n) "%DKS_HALUser.to_name(user),
                                    ValueType.YesNo, callback=self.continuePromptCallback),
                        script_node('password',
                                    "Enter the new '%s' PIN: "%DKS_HALUser.to_name(user),
                                    ValueType.AnyString, callback=None),
                        script_node('confirm_password',
                                    "Confirm the new '%s' PIN: "%DKS_HALUser.to_name(user),
                                    ValueType.AnyString, callback=self.confirmPassword)
                        ])

    def continuePromptCallback(self, response):
        if(response == True):
            self.set_hide_input(True)
            return self

        return None

    def confirmPassword(self, response):
        if (' ' in self.results['password'] or 
           ('\t' in self.results['password'])):
            self.cty_direct_call('Sorry, but the PIN cannot contain any white space characters. PIN not accepted.')
        elif (self.results['password'] != self.results['confirm_password']):
            self.cty_direct_call('Sorry, but the PIN does not match. PIN not accepted.')
        else:
            password = self.results['password']

            self.cty_connection.setPassword(DKS_HALUser.to_name(self.user), password)

        self.set_hide_input(False)

        return None