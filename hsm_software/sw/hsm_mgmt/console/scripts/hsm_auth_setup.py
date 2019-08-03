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

from settings import HSMSettings
from cryptech.cryptech_port import DKS_HALUser
from cryptech.cty_connection import CTYError
from hsm_tools.statusobject import SetStatus

class HSMAuthSetupScriptModule(ScriptModule):
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

        super(HSMAuthSetupScriptModule, self).__init__(node_list = node_list)

    def log_into_devices(self, username, password):
        self.console_object.cty_direct_call("\r\nConnecting to the internal CrypTech devices")

        return self.console_object.cty_conn.login(username, password) == CTYError.CTY_OK

    def set_wheel_pw(self):
        self.console_object.cty_direct_call("\r\nYou will need to set the 'wheel' (HSM Maintainer) password to continue.\r\n")
        self.sub_module = PasswordScriptModule(self.console_object.cty_direct_call,
                                               self.console_object.set_hide_input,
                                               self.console_object.cty_conn,
                                               DKS_HALUser.HAL_USER_WHEEL,
                                               must_set=True,
                                               finished_callback=self.set_so_pw)

    def set_so_pw(self, _):
        self.console_object.cty_direct_call("\r\nYou will need to set the 'so' (Security Officer) password to continue.\r\n")
        self.sub_module = PasswordScriptModule(self.console_object.cty_direct_call,
                                               self.console_object.set_hide_input,
                                               self.console_object.cty_conn,
                                               DKS_HALUser.HAL_USER_SO,
                                               must_set=True,
                                               finished_callback=self.set_user_pw)
        return self.sub_module

    def set_user_pw(self, _):
        self.console_object.cty_direct_call("\r\nYou will need to set the 'user' (PKCS #11 Applications) password to continue.\r\n")
        self.sub_module = PasswordScriptModule(self.console_object.cty_direct_call,
                                               self.console_object.set_hide_input,
                                               self.console_object.cty_conn,
                                               DKS_HALUser.HAL_USER_NORMAL,
                                               must_set=True,
                                               finished_callback=self.finished)
        return self.sub_module

    def check_passwords(self, console_object, pin, username):
        # start the synchronizer
        self.console_object.settings.set_setting(HSMSettings.HSM_AUTHORIZATION_SETUP, True)

    def finished(self, _):
        self.console_object.script_module = None

        self.console_object.cty_direct_call("\r\n'wheel' and 'so' have been set. Please log in again to confirm.\r\n")

        self.console_object.redo_login(self.check_passwords)

        return None

    def wheel_pw_entered(self, response):
        self.console_object.set_hide_input(False)

        success = self.log_into_devices("wheel", response)

        if (success is False):
            # try again
            self.current = self.password_index

            self.console_object.cty_direct_call("Unable to log into to the CrypTech device.\r\n")

            self.console_object.set_hide_input(True)

            return self
        else:
            return self.handle_post_login(response)

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
                return self.handle_post_login(default_wheel_pin)
        else:
            self.console_object.cty_direct_call("The HSM will shutdown in 5 seconds....")
            time.sleep(5)

            self.console_object.safe_shutdown.shutdown()

    def handle_post_login(self, password):
        self.console_object.cty_direct_call("Verifying CrypTech Device FPGA bitstream.")
        with SetStatus(self.console_object, "Initial Setup: Check HSM Hardware---"):
            for cty_index in xrange(self.console_object.cty_conn.cty_count):
                self.console_object.cty_direct_call("Device %i:"%cty_index)
                if (self.console_object.cty_conn.check_fpga(cty_index) is False):
                    self.console_object.cty_direct_call("Alpha cores not detected")
                    status = self.console_object.cty_conn.check_fix_fpga(cty_index, "wheel", password)
                    if (status == False):
                        self.on_error("Unable to load CrypTech device FPGA cores.")
                else:
                    self.console_object.cty_direct_call("OK")

            self.console_object.cty_conn.show_fpga_cores()

            # log back in
            if (self.log_into_devices("wheel", password) is False):
                self.on_error("There was an error resetting the CrypTech device")

        self.set_wheel_pw()

        return self

    def on_error(self, message):
        self.console_object.cty_direct_call("Setup Error: %s"%message)
        self.console_object.cty_direct_call("Please cycle power on the HSM after it shuts down.")
        self.console_object.cty_direct_call("The HSM will shutdown in 5 seconds....")
        time.sleep(5)

        self.console_object.safe_shutdown.shutdown()
