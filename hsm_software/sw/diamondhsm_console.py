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

from console.scripts.hsm_hardware_setup import HSMHardwareSetupScriptModule
from console.scripts.hsm_auth_setup import HSMAuthSetupScriptModule

from console.console_debug import add_debug_commands
from console.console_keystore import add_keystore_commands
from console.console_list import add_list_commands
from console.console_set import add_set_commands
from console.console_show import add_show_commands
from console.console_shutdown import add_shutdown_commands
from console.console_sync import add_sync_commands
from console.console_tamper import add_tamper_commands
from console.console_update import add_update_commands

from console.tmpfs import TMPFS, TMPFSDoesNotExist, TMPFSNotAuthorized

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
        self.tmpfs = TMPFS(self.args.uploads)

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
        self.firmware_checked = False
        self.cache_checked = False

        self.welcome_shown = False
        self.after_login_callback = []

        self.temp_object = None

        self.on_cryptech_update_finished = None

        # when current user is none, the username will be requested at login
        self.current_user = None

        # list of user's that must log in to complete an operation
        self.redo_user_order = []

        # when the console has been locked, no commands will be accepted
        self.console_locked = False

        self.tmpfs.reset()

        if(self.file_transfer is not None):
            self.file_transfer.close()
            self.file_transfer = None

        self.tamper_event_detected.value = False

        if (self.is_login_available()):
            authorization_set = self.settings.get_setting(HSMSettings.HSM_AUTHORIZATION_SETUP)
            if (authorization_set is None or authorization_set is False):
                self.console_state.value = console_interface.ConsoleState.Setup
                self.script_module = HSMAuthSetupScriptModule(self)

    def is_login_available(self):
        """Override and return true if there is a mechanism
        to login to the system"""
        return self.is_cty_connected()

    def no_login_msg(self):
        """Override and return a message when login is not available"""
        return ("\r\n\r\nWarning: No CrypTech devices have been detected. "
                "Only 'shutdown' is available.")

    def get_login_prompt(self):
        self.script_module =  None

        """Override to provide the prompt for logging in"""
        initial_login_msg = ("Before using the HSM, you will need to perform"
                             " a basic setup.\r\n"
                             "Parts of this setup will need to be done every"
                             " time the HSM powers up\r\n"
                             "to ensure that is is running properly.\r\n\r\n"
                             "The HSM will not be operational until this"
                             " setup has completed.\r\n")

        if (self.current_user == 'so'):
            username_msg = "'so'(security officer)"
        elif (self.current_user == 'wheel'):
            username_msg = "'wheel'"
        else:
            self.current_user = None
            username_msg = "'so'(security officer) or\r\n'wheel'"

        if (self.current_user is None):
            prompt = "Username"
        else:
            prompt = "Password"

        login_msg = ("Please login using the %s user account password"
                     "\r\n\r\n%s: ")%(username_msg, prompt)

        # make sure the system has been checked.
        # use cache initialization as the flag
        if ((self.synchronizer is not None) and (self.cache is not None)):
            if(not self.synchronizer.cache_initialized()):
                self.cty_direct_call(initial_login_msg)

                # start up normally
                if (not self.cache_checked):
                    self.after_login_callback.append(self.initialize_hardware)
                    self.cache_checked = True

        # show login msg
        return login_msg

    def check_master_key_set(self, _):
        # if the masterkey has not been set, prompt
        if(not self.settings.get_setting(HSMSettings.MASTERKEY_SET)):
            self.script_module = MasterKeyResetScriptModule(self)

    def on_login_username_entered(self, username):
        """Override to handle the user logging in.
        Returns true if the username is valid"""
        return (username == 'so' or username =='wheel')

    def on_login_pin_entered(self, pin, username):
        """Override to handle the user logging in.
        Returns true if the login was successful"""
        return (self.cty_conn.login(username, pin) == CTYError.CTY_OK)

    def on_login(self, pin, username):
        """Override to handle the user logging in.
        Called after a successful login"""
        self.rpc_preprocessor.unlock_hsm()

        if (len(self.after_login_callback) > 0):

            if(len(self.redo_user_order) > 0):
                self.redo_login(None, False)
            else:
                # do any callbacks
                callbacks = self.after_login_callback

                self.after_login_callback = []

                for callback in callbacks:
                    callback(self, pin, username)
        else:
            self.show_prompt()

    def redo_login(self, after_login_callback, create_redo_list = True):
        if (create_redo_list):
            if(self.current_user =='wheel'):
                self.redo_user_order = ['so', 'wheel']
            else:
                self.redo_user_order = ['wheel', 'so']

        self.current_user = self.redo_user_order.pop(0)

        self.cty_direct_call(("\r\n!-----------------------------------------"
                              "-----------------------------!"
                              "\r\n!WARNING!"
                              "\r\nYou will need to re-enter the '%s'"
                              " password to complete this operation."
                              "\r\nIf this was a mistake, please restart the"
                              " console."
                              "\r\n!-----------------------------------------"
                              "-----------------------------!\r\n")%self.current_user)

        if (after_login_callback is not None):
            self.after_login_callback.append(after_login_callback)

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

    def initialize_hardware(self, console_object, pin, username):
        # start the synchronizer
        self.script_module = HSMHardwareSetupScriptModule(self, username, pin)

        self.show_prompt()

    def initialize_cache(self, console_object, pin, username):
        # start the synchronizer
        self.synchronizer.initialize(self.rpc_preprocessor.device_count(), username, pin,
                                     self.synchronizer_init_callback)

    def synchronizer_init_callback(self, cmd, result):
        if(result != self.synchronizer.sync_init_success):
            self.allow_user_input("The synchronizer failed to initialize\r\n")
        else:
            self.cty_direct_call("The HSM synchronizer has initialized")

            self.build_cache(cmd.src, cmd.dest)

        self.allow_user_input("Ready----")

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
