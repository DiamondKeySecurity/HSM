#!/usr/bin/env python
# Copyright (c) 2018, 2019  Diamond Key Security, NFP
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



import atexit
import json
import threading
from hsm_tools.cty_connection import HSM_BINARY_FILE

from enum import Enum

HSM_SOFTWARE_VERSION = '19.08.20.field36'

# this is the version of the firmware that's built into the current release
BUILTIN_FIRMWARE_VERSION = HSM_BINARY_FILE
BUILTIN_TAMPER_VERSION = None

RPC_IP_PORT = 8080
CTY_IP_PORT = 8081
WEB_PORT    = 80
SSH_PORT    = 2200

class HSMSettings(str, Enum):
    """Enum where members are also (and must be) strs"""
    ENABLE_EXPORTABLE_PRIVATE_KEYS = 'ENABLE_EXPORTABLE_PRIVATE_KEYS'
    IP_ADDRESS_SETTINGS      = 'IP_ADDRESS_SETTINGS'
    STATICIP_IPADDR          = 'STATICIP_IPADDR'
    STATICIP_NETMASK         = 'STATICIP_NETMASK'
    STATICIP_GATEWAY         = 'STATICIP_GATEWAY'
    STATICIP_BROADCAST       = 'STATICIP_BROADCAST'
    BUILTIN_FIRMWARE_VERSION = 'BUILTIN_FIRMWARE_VERSION'
    BUILTIN_TAMPER_VERSION   = 'BUILTIN_TAMPER_VERSION'
    GPIO_TAMPER              = 'GPIO_TAMPER'
    GPIO_LEDS                = 'GPIO_LEDS'
    DATAPORT_TAMPER          = 'DATAPORT_TAMPER'
    MGMTPORT_TAMPER          = 'MGMTPORT_TAMPER'
    FIRMWARE_OUT_OF_DATE     = 'FIRMWARE_OUT_OF_DATE'
    MASTERKEY_SET            = 'MASTERKEY_SET'
    HSM_RESET_NORMALLY       = 'HSM_RESET_NORMALLY'
    ENABLE_KEY_EXPORT        = 'ENABLE_KEY_EXPORT'
    ZERO_CONFIG_ENABLED      = 'ZERO_CONFIG_ENABLED'
    # for these firwall settings
    # - True or None = accept all on port
    # - False        = block all on port
    # - tuple        = acceptable IP range
    # - list         = list of acceptable IP address
    DATA_FIREWALL_SETTINGS   = 'DATA_FIREWALL_SETTINGS'
    MGMT_FIREWALL_SETTINGS   = 'MGMT_FIREWALL_SETTINGS'
    WEB_FIREWALL_SETTINGS    = 'WEB_FIREWALL_SETTINGS'
    SSH_FIREWALL_SETTINGS    = 'SSH_FIREWALL_SETTINGS'

    HSM_AUTHORIZATION_SETUP  = 'HSM_AUTHORIZATION_SETUP'

    ALLOW_SSH                = 'ALLOW_SSH'

# Changes to hardware settings to apply after a firmware update
HARDWARE_MAPPING = {
    HSMSettings.BUILTIN_FIRMWARE_VERSION : BUILTIN_FIRMWARE_VERSION,
    HSMSettings.BUILTIN_TAMPER_VERSION   : BUILTIN_TAMPER_VERSION,
    HSMSettings.GPIO_LEDS                : True,
    HSMSettings.DATAPORT_TAMPER          : True,
    HSMSettings.MGMTPORT_TAMPER          : True
}

class Settings(object):
    def __init__(self, settings_file, gpio_available = None, safe_shutdown = None, load_only = False):
        self.settings_file = settings_file
        self.dict_sync = threading.Lock()

        try:
            with open(settings_file, "r") as file:
                self.dictionary = json.load(file)
        except IOError:
            self.__add_default_settings()

        if (load_only):
            return

        if (HSMSettings.BUILTIN_FIRMWARE_VERSION not in self.dictionary):
            self.__add_default_hardware_settings()

        if (HSMSettings.MASTERKEY_SET not in self.dictionary):
            self.__add_default_master_key_settings()

        self.__check_master_key_settings()

        self.__check_security_settings()

        self.__check_hardware_settings()

        if (gpio_available is not None):
            if (not gpio_available):
                self.set_setting(HSMSettings.GPIO_LEDS, False)
                self.set_setting(HSMSettings.GPIO_TAMPER, False)
            else:
                self.__init_gpio()

        # save any adjustments that we may have made
        self.save_settings()

        # should save settings even on crashes
        atexit.register(self.save_settings)

        # make sure we shutdown correctly
        if(safe_shutdown is not None):
            safe_shutdown.addOnShutdown(self.save_settings)
            safe_shutdown.addOnRestartOnly(self.on_restart)

    def clear_settings(self):
        firmware_version = self.get_setting(HSMSettings.BUILTIN_FIRMWARE_VERSION)
        tamper_version = self.get_setting(HSMSettings.BUILTIN_TAMPER_VERSION)

        self.dictionary = { }

        if (firmware_version is not None):
            self.set_setting(HSMSettings.BUILTIN_FIRMWARE_VERSION, firmware_version)

        if (tamper_version is not None):
            self.set_setting(HSMSettings.BUILTIN_TAMPER_VERSION, tamper_version)

        self.__check_security_settings()

        self.save_settings()

    def get_setting(self, name):
        try:
            with self.dict_sync:
                return self.dictionary[name]
        except:
            return None

    def set_setting(self, name, value):
        try:
            with self.dict_sync:
                self.dictionary[name] = value

                self.save_settings()
            return True
        except:
            return False

    def hardware_firmware_match(self):
        return self.get_setting(HSMSettings.BUILTIN_FIRMWARE_VERSION) == BUILTIN_FIRMWARE_VERSION

    def hardware_tamper_match(self):
        if (BUILTIN_TAMPER_VERSION is None):
            # we can't update if this version doesn't support tamper firmware
            return True

        return self.get_setting(HSMSettings.BUILTIN_TAMPER_VERSION) == BUILTIN_TAMPER_VERSION

    def on_restart(self):
        # hopefully we have a normal reset without a power failure
        self.set_setting(HSMSettings.HSM_RESET_NORMALLY, True)

    def set_firmware_updated(self):
        self.set_setting(HSMSettings.BUILTIN_FIRMWARE_VERSION, BUILTIN_FIRMWARE_VERSION)
        self.set_setting(HSMSettings.FIRMWARE_OUT_OF_DATE, True)

    def set_tamper_updated(self):
        self.set_setting(HSMSettings.BUILTIN_TAMPER_VERSION, BUILTIN_TAMPER_VERSION)
        self.set_setting(HSMSettings.FIRMWARE_OUT_OF_DATE, True)

    def save_settings(self):
        try:
            with open(self.settings_file, "w") as file:
                json.dump(self.dictionary, file)
        except IOError as e:
            print ("Unable to save settings: I/O error({0}): {1}".format(e.errno, e.strerror))

    def __add_default_settings(self):
        """Not thread-safe. Should only be called from __init__"""
        self.dictionary = {}
        self.dictionary[HSMSettings.IP_ADDRESS_SETTINGS] = 'DHCP'
        self.dictionary[HSMSettings.STATICIP_IPADDR] = '10.10.10.2'
        self.dictionary[HSMSettings.STATICIP_NETMASK] = '255.255.255.0'
        self.dictionary[HSMSettings.STATICIP_GATEWAY] = '10.10.10.1'
        self.dictionary[HSMSettings.STATICIP_BROADCAST] = '10.10.10.255'

    def __add_default_master_key_settings(self):
        """Not thread-safe. Should only be called from __init__"""
        self.dictionary[HSMSettings.MASTERKEY_SET] = False
        self.dictionary[HSMSettings.HSM_RESET_NORMALLY] = False

    def __add_default_hardware_settings(self):
        """Not thread-safe. Should only be called from __init__"""
        # this is the default CrypTech build used by the original prototypes
        self.dictionary[HSMSettings.BUILTIN_FIRMWARE_VERSION] = '2018-09-06'

        # the original prototype builds did not use an upgradable tamper
        self.dictionary[HSMSettings.BUILTIN_TAMPER_VERSION] = None

        # the original prototypes had GPIO tamper
        self.dictionary[HSMSettings.GPIO_TAMPER] = True

        # all versions have GPIO_LEDS
        self.dictionary[HSMSettings.GPIO_LEDS] = True

        # the original prototypes could not update tamper parameters using the CTY
        self.dictionary[HSMSettings.DATAPORT_TAMPER] = False

        # the original prototypes could not request tamper status using an RPC
        self.dictionary[HSMSettings.MGMTPORT_TAMPER] = False

    def __check_master_key_settings(self):
        """Not thread-safe. Should only be called from __init__"""
        # always assume the master key has been lost, the system will check it later
        self.dictionary[HSMSettings.MASTERKEY_SET] = False

        # we've handled the flag so set it to false
        self.dictionary[HSMSettings.HSM_RESET_NORMALLY] = False

    def __check_hardware_settings(self):
        """Not thread-safe. Should only be called from __init__"""
        # make sure the setting actually exist
        if (HSMSettings.FIRMWARE_OUT_OF_DATE not in self.dictionary):
            self.dictionary[HSMSettings.FIRMWARE_OUT_OF_DATE] = False

        if (self.get_setting(HSMSettings.FIRMWARE_OUT_OF_DATE) == True):
            # we were previously out-of-date. See if that's still true
            if(self.hardware_firmware_match() and self.hardware_tamper_match()):
                # we've been updated, change settings to reflect
                self.__update_hardware_settings()

                self.set_setting(HSMSettings.FIRMWARE_OUT_OF_DATE, False)
        else:
            # we weren't out-of-date. See if that's still true
            if(not self.hardware_firmware_match() or not self.hardware_tamper_match()):
                self.set_setting(HSMSettings.FIRMWARE_OUT_OF_DATE, True)

    def __update_hardware_settings(self):
        """Not thread-safe. Should only be called from __init__"""
        for key, value in HARDWARE_MAPPING.iteritems():
            self.dictionary[key] = value

    def __init_gpio(self):
        try:
            import RPi.GPIO as GPIO

            GPIO.setmode(GPIO.BCM)

            self.set_setting(HSMSettings.GPIO_LEDS, True)
        except:
            self.set_setting(HSMSettings.GPIO_LEDS, False)
            self.set_setting(HSMSettings.GPIO_TAMPER, False)

    def __check_security_settings(self):
        """Not thread-safe. Should only be called from __init__"""
        if (HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS not in self.dictionary):
            self.dictionary[HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS] = True

        if (HSMSettings.ENABLE_KEY_EXPORT not in self.dictionary):
            self.dictionary[HSMSettings.ENABLE_KEY_EXPORT] = False

        if (HSMSettings.ZERO_CONFIG_ENABLED not in self.dictionary):
            self.dictionary[HSMSettings.ZERO_CONFIG_ENABLED] = True

        if (HSMSettings.DATA_FIREWALL_SETTINGS not in self.dictionary):
            self.dictionary[HSMSettings.DATA_FIREWALL_SETTINGS] = True

        if (HSMSettings.MGMT_FIREWALL_SETTINGS not in self.dictionary):
            self.dictionary[HSMSettings.MGMT_FIREWALL_SETTINGS] = True

        if (HSMSettings.WEB_FIREWALL_SETTINGS not in self.dictionary):
            self.dictionary[HSMSettings.WEB_FIREWALL_SETTINGS] = True

        if (HSMSettings.SSH_FIREWALL_SETTINGS not in self.dictionary):
            self.dictionary[HSMSettings.SSH_FIREWALL_SETTINGS] = False

        if (HSMSettings.ALLOW_SSH not in self.dictionary):
            self.dictionary[HSMSettings.ALLOW_SSH] = False