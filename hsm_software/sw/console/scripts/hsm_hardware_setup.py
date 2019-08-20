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
from console.scripts.tamper_settings import TamperSettingsScriptModule

from settings import HSMSettings
from hsm_tools.cty_connection import CTYError
from hsm_tools.statusobject import SetStatus
from hsm_tools.cryptech_port import DKS_HALError

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
        self.console_object.cty_direct_call("Checking the status of the Master Key.")
        masterkey_status = self.console_object.cty_conn.getMasterKeyStatus()
        masterkey_set = True
        for cty_index in range(len(masterkey_status)):
            status = masterkey_status[cty_index]
            if ('volatile' in status):
                self.console_object.cty_direct_call("CTY %i: %s"%(cty_index, DKS_HALError.to_mkm_string(status['volatile'])))
                if (status['volatile'] != DKS_HALError.HAL_OK):
                    masterkey_set = False
            else:
                self.console_object.cty_direct_call("CTY %i: 'volatile' status not found"%(cty_index))
                masterkey_set = False

        # set the master key state in settings
        self.settings.set_setting(HSMSettings.MASTERKEY_SET, masterkey_set)

        if(not masterkey_set):
            self.sub_module = MasterKeySetScriptModule(self.console_object.cty_conn,
                                                self.console_object.cty_direct_call,
                                                self.console_object.settings,
                                                message=('The master key is not in volatile memory.\r\n'
                                                         'The HSM will not be operation and all incoming\r\n'
                                                         'operations will fail until it is set.\r\n'
                                                         'Would you like to set it now? (y/n) '),
                                                finished_callback=self.check_tamper)
        else:
            self.check_tamper(None)

    def check_tamper(self, _):
        self.console_object.cty_direct_call("Verifying tamper configuration")
        tamper_config_set = True

        for cty_index in xrange(self.console_object.cty_conn.cty_count):
            self.console_object.cty_direct_call("Device %i:"%cty_index)
            status = self.console_object.cty_conn.check_tamper_config_status(cty_index)
            if (status is not True):
                tamper_config_set = False
                self.console_object.cty_direct_call("Config Status not OK")
            else:
                self.console_object.cty_direct_call("Config Status == OK")


        if (tamper_config_set):
            self.console_object.cty_direct_call("Tamper configurations have been set.")
            self.console_object.cty_direct_call("If the HSM has been reset, this may mean it's running off the battery.")
            self.console_object.tamper.enable()

        if (not tamper_config_set and len(self.console_object.tamper_config.settings) > 0):
            self.sub_module = TamperSettingsScriptModule(self.console_object.cty_conn,
                                                         self.console_object.cty_direct_call,
                                                         self.console_object.tamper_config,
                                                         finished_callback = self.init_cache)
        else:
            if (not tamper_config_set):
                self.console_object.cty_direct_call("Previous tamper configurations not found.")
                self.console_object.cty_direct_call("You will need to reenter the tamper settings.")

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
