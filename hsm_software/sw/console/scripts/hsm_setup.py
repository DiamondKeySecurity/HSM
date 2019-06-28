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

from password import PasswordScriptModule

from hsm_tools.cryptech_port import DKS_HALUser
from hsm_tools.cty_connection import CTYError

class HSMSetupScriptModule(ScriptModule):
    def __init__(self, console_object):
        self.console_object = console_object

        first_time_msg =("\r\nDIAMOND-HSM by Diamond Key Security, NFP\r\n"
                         "\r\nThe HSM is preparing to run for the first time and"
                         "\r\nis now setting up it's authorization security protocal."
                         "\r\nAs a part of this process, the 'so' (Security Officer)"
                         "\r\nand 'wheel' (HSM maintainer) passwords must be set."
                         "\r\nAfter these passwords have been set, either can be"
                         "\r\nused to log into the HSM after a reset, but both will"
                         "\r\nbe needed to perfom certain task on the HSM such as"
                         "\r\nresponding to a tamper event. Once the passwords have"
                         "\r\nbeen set, only that user will be able to change it."
                         "\r\n\r\nWould you like to continue setup now? (y/n) ")

        node_list = []

        node_list.append(script_node('continue',
                                     first_time_msg,
                                     ValueType.YesNo, callback=self.continuePromptCallback))

        super(HSMSetupScriptModule, self).__init__(node_list = node_list)

    def log_into_devices(self, username, password):
        self.console_object.cty_direct_call("\r\nConnecting to the internal CrypTech devices")

        return self.console_object.cty_conn.login(username, password) == CTYError.CTY_OK

    def set_wheel_pw(self):
        self.sub_module = PasswordScriptModule(self.console_object.cty_direct_call,
                                               self.console_object.set_hide_input,
                                               self.console_object.cty_conn,
                                               DKS_HALUser.HAL_USER_WHEEL,
                                               must_set=True)

    def set_so_pw(self):
        self.sub_module = PasswordScriptModule(self.console_object.cty_direct_call,
                                               self.console_object.set_hide_input,
                                               self.console_object.cty_conn,
                                               DKS_HALUser.HAL_USER_SO,
                                               must_set=True)

    def wheel_pw_entered(self, response):
        self.console_object.set_hide_input(False)

        success = self.log_into_devices("wheel", response)

        if (success is False):
            # try again
            self.current = self.password_index

            self.console_object.cty_direct_call("Unable to log into to the CrypTech device.\r\n")

            self.console_object.set_hide_input(True)

        return self

    def continuePromptCallback(self, response):
        if(response == True):
            default_wheel_pin = "YouReallyNeedToChangeThisPINRightNowWeAreNotKidding"

            success = self.log_into_devices("wheel", default_wheel_pin)

            if (success is False):
                self.password_index = len(self.node_list)

                self.console_object.cty_direct_call("Unable to log into to the CrypTech device using the\r\n"
                                                    "default 'wheel' password.\r\n")

                self.console_object.set_hide_input(True)

                self.node_list.append(script_node('password',
                                                "Enter the 'wheel' password: ",
                                                ValueType.AnyString, callback=self.wheel_pw_entered))

            return self
        else:
            self.console_object.cty_direct_call("The HSM will shutdown in 5 seconds....")
            time.sleep(5)

            self.console_object.safe_shutdown.shutdown()
