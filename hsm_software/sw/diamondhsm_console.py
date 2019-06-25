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

import os

import console_interface

import time
import sync

import tornado.iostream

from Queue import Queue

from settings import HSMSettings

from hsm_tools.cty_connection import CTYConnection, CTYError

from sync import SyncCommandEnum, SyncCommand

from console.scripts.masterkey import MasterKeySetScriptModule
from console.scripts.firmware_update import FirmwareUpdateScript
from console.scripts.tamper_settings import TamperSettingsScriptModule

from console.console_debug import add_debug_commands
from console.console_keystore import add_keystore_commands
from console.console_list import add_list_commands
from console.console_masterkey import add_masterkey_commands
from console.console_restore import add_restore_commands
from console.console_set import add_set_commands
from console.console_show import add_show_commands
from console.console_shutdown import add_shutdown_commands
from console.console_sync import add_sync_commands
from console.console_tamper import add_tamper_commands
from console.console_update import add_update_commands

from hsm_cache_db.alpha import CacheTableAlpha

from hsm_tools.threadsafevar import ThreadSafeVariable

from hsm_tools.tamper_settings import TamperConfiguration

from firewall import Firewall

class DiamondHSMConsole(console_interface.ConsoleInterface):
    def __init__(self, args, cty_list, rpc_preprocessor, synchronizer,
                 cache, netiface, settings, safe_shutdown, led,
                 zero_conf_object, tamper):
        self.args = args
        self.cty_conn = CTYConnection(cty_list, args.binaries,
                                      self.quick_write)
        self.rpc_preprocessor = rpc_preprocessor
        self.synchronizer = synchronizer
        self.cache = cache
        self.settings = settings
        self.response_queue = Queue()
        self.hide_input = False
        self.dks_command_list = {}
        self.netiface = netiface
        self.file_transfer = None
        self.safe_shutdown = safe_shutdown
        self.led = led
        self.zero_conf_object = zero_conf_object
        self.tamper = tamper
        self.tamper_event_detected = ThreadSafeVariable(False)
        self.console_locked = False
        self.temp_object = None

        self.tamper_config = TamperConfiguration(os.path.dirname(args.settings))
        self.tamper_config.load_saved_settings()

        super(DiamondHSMConsole, self).__init__('Diamond HSM')

        self.banner = ("\r\n\r\n----------------------------------------------"
                       "-----------------------------\r\n"
                       "Diamond HSM powered by CrypTech\r\nThank you for using"
                       " the Diamond HSM by Diamond Key Security, NFP")

        # some commands can only be called if the cryptech devices have the correct firmware
        if (self.is_login_available() or args.debug):
            if(self.settings.hardware_firmware_match() or
               self.settings.hardware_tamper_match() or args.debug):
                if (args.debug): add_debug_commands(self)
                add_keystore_commands(self)
                add_list_commands(self)
                add_masterkey_commands(self)
                add_restore_commands(self)
                add_set_commands(self)
                add_sync_commands(self)
                add_tamper_commands(self)

            add_update_commands(self)

            add_show_commands(self)

        # always allow shutdown
        add_shutdown_commands(self)

        if (self.tamper is not None):
            self.tamper.add_observer(self.on_tamper_event)

    def on_tamper_event(self, tamper_detector):
        if((self.is_logged_in()) and
           (not self.tamper_event_detected.value)):

            self.tamper_event_detected.value = True
            self.cty_direct_call('!!!!!!!!!!TAMPER DETECTED!!!!!!!!!!!!!')

    def on_reset(self):
        """Override to add commands that must be executed to reset the system
         after a new user logs in"""
        self.welcome_shown = False
        self.after_login_callback = None

        self.temp_object = None

        self.on_cryptech_update_finished = None

        # when the console has been locked, no commands will be accepted
        self.console_locked = False

        if(self.file_transfer is not None):
            self.file_transfer.close()
            self.file_transfer = None

        self.tamper_event_detected.value = False

    def is_login_available(self):
        """Override and return true if there is a mechanism
        to login to the system"""
        return self.is_cty_connected()

    def no_login_msg(self):
        """Override and return a message when login is not available"""
        return ("\r\n\r\nWarning: No CrypTech devices have been detected. "
                "Only 'shutdown' is available.")

    def get_login_prompt(self):
        """Override to provide the prompt for logging in"""
        initial_login_msg = ("Before using the HSM, you will need to perform"
                             " a basic setup.\r\n"
                             "Parts of this setup will need to be done every"
                             " time the HSM powers up\r\n"
                             "to ensure that is is running properly.\r\n\r\n"
                             "The HSM will not be operational until this"
                             " setup has completed.")

        login_msg = ("Please login using the 'wheel' user account password"
                     "\r\n\r\nPassword: ")

        # don't show the password
        self.hide_input = True

        # make sure the firmware and tamper are up-to-date
        if(not self.settings.hardware_firmware_match() or
           not self.settings.hardware_tamper_match()):

            self.cty_direct_call(initial_login_msg)

            # prompt the user to update the firmware and the tamper
            # the HSM will remain locked until there's an update
            self.script_module = FirmwareUpdateScript(self,
                                                      self.cty_direct_call,
                                                      self.settings)
        elif ((self.synchronizer is not None) and (self.cache is not None)):
            if(not self.synchronizer.cache_initialized()):
                self.cty_direct_call(initial_login_msg)

                # start up normally
                self.after_login_callback = self.initialize_cache

        # if the masterkey has not been set, prompt
        if(self.script_module is None):
            if (len(self.tamper_config.settings) > 0):
                self.script_module = TamperSettingsScriptModule(self.cty_conn,
                                                                self.cty_direct_call,
                                                                self.tamper_config,
                                                                finished_callback = self.on_tamper_settings_set)
            elif (not self.settings.get_setting(HSMSettings.MASTERKEY_SET)):
                self.script_module = MasterKeySetScriptModule(self.cty_conn,
                                                            self.cty_direct_call,
                                                            self.settings)

        # show login msg
        return login_msg

    def on_tamper_settings_set(self, results):
        print 'sdfa'
        # if the masterkey has not been set, prompt
        if(not self.settings.get_setting(HSMSettings.MASTERKEY_SET)):
            self.script_module = MasterKeySetScriptModule(self.cty_conn,
                                                          self.cty_direct_call,
                                                          self.settings)


    def on_login_pin_entered(self, pin):
        """Override to handle the user logging in.
        Returns true if the login was successful"""
        return (self.cty_conn.login(pin) == CTYError.CTY_OK)

    def on_login(self, pin):
        """Override to handle the user logging in.
        Called after a successful login"""
        self.rpc_preprocessor.unlock_hsm()

        if(self.after_login_callback is not None):
            callback = self.after_login_callback
            self.after_login_callback = None
            callback(self, pin)
        else:
            self.cty_direct_call(self.prompt)

    def redo_login(self, after_login_callback):
        self.cty_direct_call(('\r\n!-----------------------------------------'
                              '-----------------------------!'
                              '\r\n!WARNING!'
                              '\r\nYou will need to re-enter the wheel'
                              ' password to complete this operation.'
                              '\r\nIf this was a mistake, please restart the'
                              ' console.'
                              '\r\n!-----------------------------------------'
                              '-----------------------------!\r\n'))

        self.after_login_callback = after_login_callback

        self.logout()

    def crypTechAvailable(self):
        return (self.cty_conn.is_cty_connected() and
                self.rpc_preprocessor is not None)

    def is_cty_connected(self):
        return self.cty_conn.is_cty_connected()

    def check_has_cty(self):
        if(self.is_cty_connected()):
            return True
        else:
            return "Cryptech CTY device not connected."

    def check_has_rpc(self):
        if(self.rpc_preprocessor is not None):
            return True
        else:
            return "Cryptech RPC device not connected."

    def update_firewall_from_settings(self):
        # update the firewall rules
        Firewall.generate_firewall_rules(self.settings, '/var/tmp')

    def initialize_cache(self, console_object, pin):
        # start the synchronizer
        self.synchronizer.initialize(self.rpc_preprocessor.device_count(), pin,
                                     self.synchronizer_init_callback)

    def synchronizer_init_callback(self, cmd, result):
        if(result != self.synchronizer.sync_init_success):
            self.allow_user_input("The synchronizer failed to initialize\r\n")
        else:
            self.cty_direct_call("The HSM synchronizer has initialized")

            self.build_cache(cmd.src, cmd.dest)

    def build_cache(self, src, dest):
        self.set_ignore_user("Building HSM Cache\r\n")
        self.synchronizer.queue_command(SyncCommand(SyncCommandEnum.BuildCache,
                                        src,
                                        dest,
                                        self.generate_cache_callback,
                                        console=self.cty_direct_call))

    def generate_cache_callback(self, cmd, result):
        self.allow_user_input(result)

    @tornado.gen.coroutine
    def write(self, data):
        if (self.console_locked):
            self.cty_direct_call("This console has been locked."
                                 "\r\nPlease restart the console"
                                 " to connect to the HSM.")
            return

        # This method is name write because the calling method
        # uses it to "write" to the CTY. Instead of directly
        # writing to the CTY, this method processes the data and
        # uses the CTY interface if needed"""
        if(self.file_transfer is not None):
            result = self.file_transfer.recv(data)
            if(result is False):
                if (self.file_transfer is not None):
                    self.cty_direct_call(self.file_transfer.error)
                print "transfer failed"
                self.console_locked = True
            elif (isinstance(result, str)):
                self.quick_write(result)
        else:
            self.readCTYUserData(data)

    def sync_callback(self, cmd, result):
        self.cty_direct_call(result)
