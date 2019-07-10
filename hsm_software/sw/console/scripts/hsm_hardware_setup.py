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

from masterkey import MasterKeySetScriptModule

from settings import HSMSettings
from hsm_tools.cty_connection import CTYError
from hsm_tools.statusobject import SetStatus

class HSMHardwareSetupScriptModule(ScriptModule):
    def __init__(self, console_object, username, pin):
        self.console_object = console_object
        self.settings = self.console_object.settings
        self.username = username
        self.pin = pin

        first_time_msg =("\r\nAfter system resets and updates, the HSM must"
                         "\r\nperform diagnostic procedures on the internal"
                         "\r\nCrypTech devices. During this procedure, the"
                         "\r\nHSM must not lose power."
                         "\r\n\r\nWould you like to continue setup now? (y/n) ")

        node_list = []

        node_list.append(script_node('continue',
                                     first_time_msg,
                                     ValueType.YesNo, callback=self.continuePromptCallback))

        super(HSMHardwareSetupScriptModule, self).__init__(node_list = node_list)

    def log_into_devices(self, username, password):
        self.console_object.cty_direct_call("\r\nConnecting to the internal CrypTech devices")

        return self.console_object.cty_conn.login(username, password) == CTYError.CTY_OK

    def check_firmware(self):
        self.console_object.cty_direct_call("Checking for CrypTech device firmware updates.")
        if(not self.settings.hardware_firmware_match()):
            self.console_object.cty_direct_call("\r\nFirmware update in progress.\r\n")
            if(self.console_object.cty_conn.uploadFirmware(self.username, self.pin) != CTYError.CTY_OK):
                self.on_error("Unable to update firmware. Please cycle power and run setup again.")

            self.settings.set_firmware_updated()

            self.console_object.cty_direct_call("Waiting for devices to start.")
            for _ in range(10):
                self.console_object.cty_direct_call(".")
                time.sleep(3)
        else:
            self.console_object.cty_direct_call("Firmware: OK")

        self.console_object.cty_direct_call("Checking for CrypTech device tamper updates.")
        if(not self.settings.hardware_tamper_match()):
            self.console_object.cty_direct_call("\r\nTamper update in progress.\r\n")
            if(self.console_object.cty_conn.uploadTamperFirmware(self.username, self.pin) != CTYError.CTY_OK):
                self.on_error("Unable to update tamper firmware. Please cycle power and run setup again.")
            self.settings.set_tamper_updated()
        else:
            self.console_object.cty_direct_call("Tamper: OK")

    def check_fpga(self):
        self.console_object.cty_direct_call("Verifying CrypTech Device FPGA bitstream.")
        for cty_index in xrange(self.console_object.cty_conn.cty_count):
            self.console_object.cty_direct_call("Device %i:"%cty_index)
            if (self.console_object.cty_conn.check_fpga(cty_index) is False):
                self.console_object.cty_direct_call("Alpha cores not detected")
                status = self.console_object.cty_conn.check_fix_fpga(cty_index, self.username, self.pin)
                if (status == False):
                    self.on_error("Unable to load CrypTech device FPGA cores.")
            else:
                self.console_object.cty_direct_call("OK")

        self.console_object.cty_conn.show_fpga_cores()

    def check_masterkey(self):
        if(not self.settings.get_setting(HSMSettings.MASTERKEY_SET)):
            self.sub_module = MasterKeySetScriptModule(self.console_object.cty_conn,
                                                self.console_object.cty_direct_call,
                                                self.console_object.settings,
                                                message=('Because of a system reset, the master key '
                                                         'may not be set.\r\nWould you like to set it'
                                                         ' now? (y/n) '),
                                                finished_callback=self.init_cache)
        else:
            self.init_cache(None)

    def init_cache(self, _):
        self.console_object.set_ignore_user("Waiting for HSM cache to initialize.")
        self.console_object.initialize_cache(self.console_object, self.pin, self.username)


    def continuePromptCallback(self, response):
        if(response == True):
            with SetStatus(self.console_object, "Check HSM Hardware---"):
                self.check_firmware()

                # make sure we are still logged in
                if (self.log_into_devices(self.username, self.pin) is False):
                    self.on_error("There was an error resetting the CrypTech device")

                self.check_fpga()

                # make sure we are still logged in
                if (self.log_into_devices(self.username, self.pin) is False):
                    self.on_error("There was an error resetting the CrypTech device")

                self.check_masterkey()
        else:
            self.console_object.cty_direct_call("The HSM will shutdown in 5 seconds....")
            time.sleep(5)

            self.console_object.safe_shutdown.shutdown()

        return self

    def on_error(self, message):
        self.console_object.cty_direct_call("Setup Error: %s"%message)
        self.console_object.cty_direct_call("Please cycle power on the HSM after it shuts down.")
        self.console_object.cty_direct_call("The HSM will shutdown in 5 seconds....")
        time.sleep(5)

        self.console_object.safe_shutdown.shutdown()
