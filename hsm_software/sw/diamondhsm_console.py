#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import console_interface

import os
import collections
import logging
import shutil

import tornado.iostream
import time
import sync

from enum import IntEnum, Enum
from Queue import Queue

from settings import HSMSettings, HSM_SOFTWARE_VERSION

from hsm_tools.cty_connection import CTYConnection, CTYError
from hsm_tools.cryptech_port import DKS_HALUser

from sync import SyncCommandEnum, SyncCommand

from setup.script import ScriptModule, script_node, ValueType
from setup.script_masterkey import MasterKeySetScriptModule
from setup.script_ip_dhcp import DHCPScriptModule
from setup.script_ip_static import StaticIPScriptModule
from setup.script_updateRestart import UpdateRestartScriptModule
from setup.script_password import PasswordScriptModule

from hsm_cache_db.alpha import CacheTableAlpha

from setup.file_transfer import MGMTCodes, FileTransfer

import zero_conf

class DiamondHSMConsole(console_interface.ConsoleInterface):
    def __init__(self, args, cty_list, rpc_preprocessor, synchronizer, cache, netiface, settings, safe_shutdown, led, tamper):
        self.args = args
        self.cty_conn = CTYConnection(cty_list, args.binaries, self.quick_write)
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
        self.tamper = tamper

        self.initial_login = True

        super(DiamondHSMConsole, self).__init__('Diamond HSM')

        self.banner = ("\r\n\r\n---------------------------------------------------------------------------\r\n"
                       "Diamond HSM powered by CrypTech\r\nThank you for using the Diamond HSM by Diamond Key Security, NFP")

        self.add_debug_commands()
        self.add_keystore_commands()
        self.add_list_commands()
        self.add_masterkey_commands()
        self.add_restore_commands()
        self.add_set_commands()
        self.add_show_commands()
        self.add_shutdown_commands()
        self.add_sync_commands()
        self.add_update_commands()
        self.add_tamper_commands()

        self.tamper.add_observer(self.on_tamper_event)

    def on_tamper_event(self, tamper_detector):
        self.cty_direct_call('!!!!!!!!!!TAMPER DETECTED!!!!!!!!!!!!!')

    def on_reset(self):
        """Override to add commands that must be executed to reset the system after a new user logs in"""
        self.welcome_shown = False
        self.after_login_callback = None

        if(self.file_transfer is not None):
            self.file_transfer.close()
            self.file_transfer = None

    def is_login_available(self):
        """Override and return true if there is a mechanism to login to the system"""
        return self.is_cty_connected()

    def no_login_msg(self):
        """Override and return a message when login is not available"""
        return "\r\n\r\nWarning: No CrypTech devices have been detected. Only 'shutdown' is available."

    def get_login_prompt(self):
        """Override to provide the prompt for logging in"""
        initial_login_msg = ("Before using the HSM, you will need to perform a basic setup.\r\n"
                             "Parts of this setup will need to be done every time the HSM powers up\r\n"
                             "to ensure that is is running properly.\r\n\r\n"
                             "The HSM will not be operational until this setup has completed.")

        login_msg         = ("Please login using the 'wheel' user account password\r\n\r\nPassword: ")

        # don't show the password
        self.hide_input = True

        if (self.initial_login):
            if(self.synchronizer != None and self.cache != None):
                if(not self.synchronizer.cache_initialized()):
                    self.cty_direct_call(initial_login_msg)

                    self.after_login_callback = self.initialize_cache

                    self.script_module = MasterKeySetScriptModule(self.cty_conn, self.cty_direct_call)

            self.initial_login = False

        # show login msg
        return login_msg

    def on_login_pin_entered(self, pin):
        """Override to handle the user logging in. Returns true if the login was successful"""
        return (self.cty_conn.login(pin) == CTYError.CTY_OK)

    def on_login(self, pin):
        """Override to handle the user logging in. Called after a successful login"""
        self.rpc_preprocessor.unlock_hsm()

        if(self.after_login_callback is not None):
            callback = self.after_login_callback
            self.after_login_callback = None
            callback(pin)
        else:
            self.cty_direct_call(self.prompt)

    def redo_login(self, after_login_callback):
        self.cty_direct_call(('\r\n!----------------------------------------------------------------------!'
                              '\r\n!WARNING!'
                              '\r\nYou will need to re-enter the wheel password to complete this operation.'
                              '\r\nIf this was a mistake, please restart the console.'
                              '\r\n!----------------------------------------------------------------------!\r\n'))

        self.after_login_callback = after_login_callback

        self.logout()

    def crypTechAvailable(self):
        return (self.cty_conn.is_cty_connected() and self.rpc_preprocessor is not None)

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

    def initialize_cache(self, pin):
        # start the synchronizer
        self.synchronizer.initialize(self.rpc_preprocessor.device_count(), pin, self.synchronizer_init_callback)


    def synchronizer_init_callback(self, cmd, result):
        if(result != self.synchronizer.sync_init_success):
            self.allow_user_input("The synchronizer failed to initialize\r\n")
        else:
            self.cty_direct_call("The HSM synchronizer has initialized")

            self.build_cache(cmd.src, cmd.dest)

    def build_cache(self, src, dest):
        self.set_ignore_user("Building HSM Cache\r\n")
        self.synchronizer.queue_command(SyncCommand(SyncCommandEnum.BuildCache, src, dest, self.generate_cache_callback, console=self.cty_direct_call))

    def generate_cache_callback(self, cmd, result):
        self.allow_user_input(result)

    @tornado.gen.coroutine
    def write(self, data):
        """This method is name write because the calling method uses it to "write" to the CTY.
           Instead of directly writing to the CTY, this method processes the data and
           uses the CTY interface if needed"""
        if(self.file_transfer is not None):
            result = self.file_transfer.recv(data)
            if(result is not True):
                # result will either be true or an error message
                self.cty_direct_call(result)
                self.cty_direct_call("You will be logged out in 5 seconds.")
                time.sleep(5)
                self.cty_direct_call(None)
        else:
            self.readCTYUserData(data)

    def add_tamper_commands(self):
        tamper_node = self.add_child('tamper')

        tamper_node.add_child(name = "test", num_args = 0, usage = ' - Test tamper functionality by simulating an event.', callback = self.dks_tamper_test)
        tamper_node.add_child(name = "reset", num_args = 0, usage = ' - Attempt to reset the tamper flag. This will fail during an ongoing tamper event.', callback = self.dks_tamper_reset)

    def dks_tamper_test(self, args):
        self.tamper.on_tamper(None)

        return "TESTING TAMPER"

    def dks_tamper_reset(self, args):
        self.tamper.reset_tamper_state()

        return "RESETING TAMPER"

    def add_show_commands(self):
        show_node = self.add_child('show')

        show_node.add_child(name = "rpc", num_args = 0, usage = ' - Displays the current CrypTech device RPC selection mode.', callback = self.dks_show_rpc)
        show_node.add_child(name = "time", num_args = 0, usage = ' - Shows the current HSM system time.', callback = self.dks_show_time)
        show_node.add_child(name = "devices", num_args = 0, usage = ' - Shows the currently connected CrypTech devices.', callback = self.dks_show_devices)
        show_node.add_child(name = "ipaddr", num_args = 0, usage = ' - Shows the current HSM IP address.', callback = self.dks_show_ipaddr)
        show_node.add_child(name = "macaddr", num_args = 0, usage = " - Shows the HSM's MAC address.", callback = self.dks_show_macaddr)
        show_node.add_child(name = "settings", num_args = 0, usage = ' - Lists all HSM overridable settings.', callback = self.dks_show_settings)
        show_node.add_child(name = "serial-number", num_args = 0, usage = " - Shows the HSM's serial number.", callback = self.dks_show_serialnumber)
        show_node.add_child(name = "version", num_args = 0, usage = ' - Shows the HSM firmware version.', callback = self.dks_show_version)
        show_node.add_child(name = "log", num_args = 0, usage = ' - Displays the system log.', callback = self.dks_show_log)
        show_node.add_child(name = "cache", num_args = 0, usage = ' - Shows all of the keys that have been mapped in the system cache.', callback = self.dks_show_cache)

        fpga_node = show_node.add_child(name = "fpga")
        fpga_node.add_child(name = "cores", num_args = 0, usage = ' - Shows the loaded FGPA cores and versions.', callback = self.dks_show_fpga_cores)

    def dks_show_cache(self, args):
        results = self.cache.getVerboseMapping()

        for line in results:
            self.cty_direct_call(line)

        return ''

    def dks_show_ipaddr(self, args):
        return self.netiface.get_ip()

    def dks_show_macaddr(self, args):
        return self.netiface.get_mac()

    def dks_show_time(self, args):
        return time.strftime("%c")

    def dks_show_devices(self, args):
        message = "Cryptech devices currently connected to HSM:\r\n"
        cty_result = self.check_has_cty()
        if (cty_result is True):
            for d in self.cty_conn.cty_list:
                message += "\r\n > " + d.name
        else:
            message += cty_result

        rpc_result = self.check_has_rpc()
        if (rpc_result is True):
            for d in self.rpc_preprocessor.rpc_list:
                message += "\r\n > " + d.name
        else:
            message += rpc_result

        return message

    def dks_show_rpc(self, args):
        # make sure a rpc has been connected
        rpc_result = self.check_has_rpc()
        if (rpc_result is not True):
            return rpc_result

        return "Current RPC mode: " + self.rpc_preprocessor.get_current_rpc()

    def dks_show_settings(self, args):
        result = '\r\n\r\nDiamond HSM Settings:\r\n\r\n'
        for key, value in self.settings.dictionary.iteritems():
            setting = "[%s] = %s\r\n"%(str(key), str(value))
            result += setting

        return result

    def dks_show_serialnumber(self, args):
        return self.args.serial_number

    def dks_show_version(self, args):
        return HSM_SOFTWARE_VERSION

    def dks_show_log(self, args):
        try:
            # make a copy of the log to avoid issues
            logfile_read = "%s.2"%self.args.log_file

            try:
                os.remove(logfile_read)
            except:
                pass

            shutil.copyfile(self.args.log_file, logfile_read)

            with open(logfile_read) as log:
                for line in log:
                    self.cty_direct_call(' > %s'%line.rstrip("\r\n"))

            return "\r\n\r\n%s\r\n"%self.args.log_file
        except Exception as e:
            return e.message

    def dks_show_fpga_cores(self, args):
        result = self.cty_conn.show_fpga_cores()
        for line in result:
            self.cty_direct_call(line)

        return '--------'

    def add_set_commands(self):
        set_node = self.add_child('set')

        set_node.add_child(name = "rpc", num_args = 1, usage = "<rpc index or 'auto'>", callback = self.dks_set_rpc)
        set_node.add_child(name = "pin" , num_args = 1, usage = "<user name - 'wheel', 'so', or 'user'>", callback = self.dks_set_pin)
        set_node.add_child(name = "ip", num_args = 1, usage = "<'static' or 'dhcp'>", callback = self.dks_set_ip)
        set_node.add_child(name = "ENABLE_EXPORTABLE_PRIVATE_KEYS", num_args = 1, usage = "<'true' or 'false'>", callback = self.dks_set_enable_exportable_private_keys)

    def dks_set_rpc(self, args):
        # make sure a rpc has been connected
        rpc_result = self.check_has_rpc()
        if (rpc_result is not True):
            return rpc_result

        try:
            index = int(args[0])
        except ValueError:
            index = 0
            if (args[0].lower() == "auto"):
                index = -1
            else:
                return 'invalid argument "%s"'%args[0]

        return self.rpc_preprocessor.set_current_rpc(index)

    def dks_set_pin(self, args):
        user = DKS_HALUser.from_name(args[0])
        if(user is not None):
            # start the script
            self.script_module = PasswordScriptModule(self.cty_direct_call, self.set_hide_input, self.cty_conn, user)

            self.cty_direct_call(self.prompt)

            return True
        else:
            return "<user> must be 'wheel', 'so', or 'user'"

    def dks_set_ip_dhcp_onlogin(self, pin):
        message = ['This will set the HSM to use a DHCP server for IP',
                   'address selection. It is recommended to always use DHCP.',
                   'When a static ip is needed, it is recommended to configure',
                   'the DHCP server to reserve a specific IP address for the HSM.',
                   'If a DHCP cannot be found, the default static IP,',
                   "'10.10.10.2' will be used\r\n"]

        for line in message:
            self.cty_direct_call(line)

        # start the script
        self.script_module = DHCPScriptModule(self.settings, self.cty_direct_call, self.safe_shutdown)

        self.cty_direct_call(self.prompt)

    def dks_set_ip_static_onlogin(self, pin):
        message = ['This will set the HSM to use a manually set static IP',
                   'address. Please use caution when setting a static IP',
                   'because the ethernet port is the only way to communicate',
                   'with the HSM.\r\n',
                   'While manual static IP selection is supported,',
                   'it is recommended to always use DHCP.',
                   'When a static ip is needed, it is recommended to configure',
                   'the DHCP server to reserve a specific IP address for the HSM.',
                   'If a DHCP cannot be found, the default static IP,',
                   "'10.10.10.2' will be used\r\n"]

        for line in message:
            self.cty_direct_call(line)

        # start the script
        self.script_module = StaticIPScriptModule(self.settings, self.cty_direct_call, self.safe_shutdown)

        self.cty_direct_call(self.prompt)

    def dks_set_ip(self, args):
        if(args[0] == 'dhcp'):
            self.redo_login(self.dks_set_ip_dhcp_onlogin)
            return True
        if(args[0] == 'static'):
            self.redo_login(self.dks_set_ip_static_onlogin)
            return True

    def dks_set_enable_exportable_private_keys(self, args):
        if(args[0].lower() == 'true'):
            self.settings.set_setting(HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS, True)
            return 'ENABLE_EXPORTABLE_PRIVATE_KEYS set to TRUE'
        elif(args[0].lower() == 'false'):
            self.settings.set_setting(HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS, False)
            return 'ENABLE_EXPORTABLE_PRIVATE_KEYS set to FALSE'


    def add_list_commands(self):
        set_node = self.add_child('list')

        set_node.add_child(name = "keys", num_args = 0, usage = " - list the keys in the CrypTech devices.", callback = self.dks_list_keys)

    def dks_list_keys(self, args):
        cache = self.cache
        rpc_count = cache.rpc_count

        self.cty_direct_call("CrypTech Device Cached UUIDs---")

        for rpc_index in xrange(0, rpc_count):
            alphaTable = cache.alphaTables[rpc_index]
            self.cty_direct_call("%sDevice:%i------------%s"%(self.initial_space, rpc_index, self.initial_space))
            for key in alphaTable.get_keys():
                self.cty_direct_call(key)

        return self.initial_space

    def add_masterkey_commands(self):
        masterkey_node = self.add_child('masterkey')

        masterkey_node.add_child(name = "set", num_args = 0, usage = " - sets the master key.", callback = self.dks_masterkey_set)

    def dks_masterkey_set(self, args):
        # use script to set the master key
        self.script_module = MasterKeySetScriptModule(self.cty_conn, self.cty_direct_call)

        return ''

    def add_update_commands(self):
        update_node = self.add_child('update')

        cryptech_node = update_node.add_child('cryptech')
        cryptech_node.add_child('bootloader', num_args=0, usage=' - Updates the bootloaders on the CrypTech devices.', callback=self.dks_update_cryptech_bootloader)
        cryptech_node.add_child('firmware', num_args=0, usage=' - Updates the firmware on the CrypTech devices.', callback=self.dks_update_cryptech_firmware)
        cryptech_node.add_child('fpga', num_args=0, usage=' - Updates the FPGA cores on the CrypTech devices.', callback=self.dks_update_cryptech_fpga)

        update_node.add_child('HSM', num_args=1, usage='<path to file> - Updates the HSM firmware.', callback=self.dks_update_HSM)

    def dks_update_cryptech_fpga(self, args):
        self.cty_direct_call(('\r\n!----------------------------------------------------------------------!'
                              '\r\n!FPGA UPDATE WARNING!'
                              '\r\nThis will update the FPGA inside the CrypTech device. The FPGA bit steam'
                              '\r\nthat will be used was loaded into the HSM on the last HSM update and'
                              '\r\nis probably already on the device.'
                              '\r\n!----------------------------------------------------------------------!\r\n'))

        self.redo_login(self.dks_update_fpga)
        return True

    def dks_update_cryptech_firmware(self, args):
        self.cty_direct_call(('\r\n!----------------------------------------------------------------------!'
                              '\r\n!FIRMWARE UPDATE WARNING!'
                              '\r\nThis will update the firmware inside the CrypTech device. The firmware'
                              '\r\nthat will be used was loaded into the HSM on the last HSM update and'
                              '\r\nis probably already on the device. Failures during the firmware update'
                              '\r\ncan cause the CrypTech device to become inoperable'
                              '\r\n!----------------------------------------------------------------------!\r\n'))

        self.redo_login(self.dks_update_firmware)

        return True

    def dks_update_cryptech_bootloader(self, args):
        self.cty_direct_call(('\r\n!----------------------------------------------------------------------!'
                              '\r\n!BOOTLOADER UPDATE WARNING!'
                              '\r\nThis will update the bootloader inside the CrypTech device. The bootloader'
                              '\r\nthat will be used was loaded into the HSM on the last HSM update and'
                              '\r\nis probably already on the device. Failures during the bootloader update'
                              '\r\ncan cause the CrypTech device to become inoperable'
                              '\r\n!----------------------------------------------------------------------!\r\n'))

        self.redo_login(self.dks_update_bootloader)
        return True

    def dks_update_firmware(self, pin):
        return self.dks_do_update(self.cty_conn.uploadFirmware, pin)

    def dks_update_bootloader(self, pin):
        return self.dks_do_update(self.cty_conn.uploadBootloader, pin)

    def dks_update_fpga(self, pin):
        return self.dks_do_update(self.cty_conn.uploadFPGABitStream, pin)

    def dks_update_HSM(self, args):
        if('~' in args[0]):
            return "You cannot use '~' in the path. You must use the full path."
        if(not args[0].endswith('.tar.gz.signed')):
            return "You must use a '.tar.gz.signed' file from Diamond Key Security, NFP"

        self.request_file_path = args[0]
        self.redo_login(self.dks_do_HSM_update)
        return True

    def dks_do_HSM_update(self, pin):
        try:
            # stop excepting normal user data
            self.set_ignore_user('The HSM is preparing to receive an update')

            mgmt_code = MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value
            # setup a file transfer object
            self.file_transfer = FileTransfer(requested_file_path = self.request_file_path, 
                                            mgmt_code = mgmt_code,
                                            uploads_dir = self.args.uploads,
                                            restart_file = self.args.restart,
                                            public_key = self.args.hsmpublickey,
                                            finished_callback = self.dks_hsm_update_finished)

            # tell dks_setup_console that it can send the data now
            msg = "%s:RECV:%s\r"%(mgmt_code, self.request_file_path)
            self.cty_direct_call(msg)
        except Exception as e:
            self.cty_direct_call('\nThere was an error while receiving the update.\r\n\r\n%s'%e.message)

    def dks_hsm_update_finished(self, result, msg):
        # we don't need to close the file_transfer object because it will
        # do that itself before calling this callback function
        self.file_transfer = None

        if(result is True):
            self.script_module = UpdateRestartScriptModule(self.cty_direct_call, self.safe_shutdown)

        self.allow_user_input(msg)


    def dks_do_update(self, command, pin):
        result = command(pin)
        self.cty_direct_call(self.cty_conn.get_error_msg(result))

        if (result == CTYError.CTY_OK):
            self.cty_direct_call("HSM Restarting in 5 seconds....")
            time.sleep(5)

            self.safe_shutdown.restart()
        else:
            print "finished"
            self.logout("Finished upload")

        return True

    def add_sync_commands(self):
        sync_node = self.add_child('sync')

        sync_node.add_child(name = "cache", num_args = 0, usage = " - Scans the CrypTech devices to rebuild the cache.", callback = self.dks_sync_cache)
        sync_node.add_child(name = "oneway", num_args = 3, usage = "<source RPC index> <destination RPC index> <max copies>  - copies keys from one CrypTech device to another.", callback = self.dks_sync_oneway)
        sync_node.add_child(name = "twoway", num_args = 3, usage = "<source RPC index> <destination RPC index> <max copies>  - copies keys from one CrypTech device to another.", callback = self.dks_sync_twoway)

    def sync_callback(self, cmd, result):
        self.cty_direct_call(result)        
    
    def dks_sync_cache(self, args):
        self.build_cache(0, self.rpc_preprocessor.device_count())
        return True

    def parse_index(self, index_string, max_value):
        try:
            index = int(index_string)
        except:
            index = -1

        if (max_value > 0 and index >= max_value):
            index = -1

        return index

    def dks_sync_oneway(self, args):
        src = self.parse_index(args[0], self.rpc_preprocessor.device_count())
        if (src < 0):
            return "Invalid source parameter. Got '%s'."%args[0]

        dest = self.parse_index(args[1], self.rpc_preprocessor.device_count())
        if (dest < 0):
            return "Invalid destination parameter. Got '%s'."%args[1]

        max_keys = self.parse_index(args[2], 0)
        if (max_keys < 0):
            return "Invalid max keys parameter. Got '%s'."%args[2]

        cmd = sync.SyncCommand(sync.SyncCommandEnum.OneWayBackup, src, dest, self.sync_callback, param=max_keys, console=self.cty_direct_call)

        self.synchronizer.queue_command(cmd)

        return "command sent to synchronizer"

    def dks_sync_twoway(self, args):
        src = self.parse_index(args[0], self.rpc_preprocessor.device_count())
        if (src < 0):
            return "Invalid source parameter. Got '%s'."%args[0]

        dest = self.parse_index(args[1], self.rpc_preprocessor.device_count())
        if (dest < 0):
            return "Invalid destination parameter. Got '%s'."%args[1]

        max_keys = self.parse_index(args[2], 0)
        if (max_keys < 0):
            return "Invalid max keys parameter. Got '%s'."%args[2]

        cmd = sync.SyncCommand(sync.SyncCommandEnum.TwoWayBackup, src, dest, self.sync_callback, param=max_keys, console=self.cty_direct_call)

        self.synchronizer.queue_command(cmd)

        return "command sent to synchronizer"

    def add_keystore_commands(self):
        keystore_node = self.add_child('keystore')
        keystore_erase_node = keystore_node.add_child('erase')
        keystore_erase_node.add_child('YesIAmSure', num_args=0, usage=' - Erases the entire keystore including PINs.', callback = self.dks_keystore_erase)
        keystore_erase_node.add_child_tree(['preservePINs','YesIAmSure'], num_args=0, usage=' - Erases the keystore. Preserves PINs.', callback = self.dks_keystore_erase_preservePINs)

    def dks_keystore_erase(self, args):
        if(self.cty_conn.clearKeyStore(preservePINs=False) == CTYError.CTY_OK):
            # clear the cache
            self.cache.clear()

            return 'keystore cleared. preservePINs == False'

    def dks_keystore_erase_preservePINs(self, args):
        if(self.cty_conn.clearKeyStore(preservePINs=True) == CTYError.CTY_OK):
            # clear the cache
            self.cache.clear()

            return 'keystore cleared. preservePINs == True'

    def add_restore_commands(self):
        restore_node = self.add_child('restore')
        restore_node.add_child_tree(['preservePINs-KEYs','YesIAmSure'], num_args=0, usage=' - Restores the HSM to factory settings without downgrading the HSM software. Will not delete keys or PINS.', callback = self.dks_restore_settingsonly)
        restore_node.add_child('YesIAmSure', num_args=0, usage=' - Restores the HSM to factory settings without downgrading the HSM software.', callback = self.dks_restore)

    def dks_restore(self, args):
        # clear the settings
        self.dks_restore_settingsonly(args)

        # clear the keystore
        self.dks_keystore_erase(args)

        return 'Restore complete'

    def dks_restore_settingsonly(self, args):
        # restore settings
        self.settings.add_default_settings()

        return 'Restore complete'

    def add_shutdown_commands(self):
        shutdown_node = self.add_child('shutdown')
        shutdown_node.add_child_tree(['restart','YesIAmSure'], num_args=0, usage=' - Restarts the HSM.', callback = self.dks_shutdown_restart)
        shutdown_node.add_child('YesIAmSure', num_args=0, usage=' - Shuts down the HSM.', callback = self.dks_shutdown)

    def dks_shutdown(self, args):
        self.cty_direct_call('Shutting Down HSM')
        self.safe_shutdown.shutdown()
        self.cty_direct_call(None)

    def dks_shutdown_restart(self, args):
        self.cty_direct_call('Restarting HSM')
        self.safe_shutdown.restart()
        self.cty_direct_call(None)

    def add_debug_commands(self):
        debug_node = self.add_child('debug')

        debug_node.add_child_tree(['flash','system', 'led'], num_args=0, usage=' - Flashes the system LED.', callback = self.dks_debug_flash_led)

        debug_node.add_child_tree(['reboot','cryptech'], num_args=0, usage=' - Reboots the CrypTech devices.', callback = self.dks_reboot_cryptech)

        debug_node.add_child('verbose', num_args=0, usage=' - Add verbose debugging to log.', callback = self.dks_debug_verbose)

    def dks_debug_flash_led(self, args):
        if (self.led is not None):
            self.led.system_led.flash_red()
            return 'OK'
        else:
            return 'LED not detected'

    def dks_debug_verbose(self, args):
        logging.getLogger().setLevel(logging.DEBUG)
        return 'HSM set to verbose debugging'

    def dks_reboot_cryptech(self, args):
        self.cty_direct_call("Rebooting the Cryptech STMs")

        self.cty_conn.reboot_stm()

        return "STM rebooted"
