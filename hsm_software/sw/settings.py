#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import atexit
import json

from enum import Enum

HSM_SOFTWARE_VERSION = '19.01.31.tamper20'

# this is the version of the firmware that's built into the current release
BUILTIN_FIRMWARE_VERSION = '2019-01-31v2'
BUILTIN_TAMPER_VERSION = None

RPC_IP_PORT = 8080
CTY_IP_PORT = 8081
WEB_PORT    = 80

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
    MGMGPORT_TAMPER          = 'MGMGPORT_TAMPER'
    FIRMWARE_OUT_OF_DATE     = 'FIRMWARE_OUT_OF_DATE'
    MASTERKEY_SET            = 'MASTERKEY_SET'
    HSM_RESET_NORMALLY       = 'HSM_RESET_NORMALLY'

# Changes to hardware settings to apply after a firmware update
HARDWARE_MAPPING = {
    HSMSettings.BUILTIN_FIRMWARE_VERSION : BUILTIN_FIRMWARE_VERSION,
    HSMSettings.BUILTIN_TAMPER_VERSION   : BUILTIN_TAMPER_VERSION,
    HSMSettings.GPIO_TAMPER              : True,
    HSMSettings.GPIO_LEDS                : True,
    HSMSettings.DATAPORT_TAMPER          : False,
    HSMSettings.MGMGPORT_TAMPER          : False
}

class Settings(object):
    def __init__(self, settings_file, gpio_available = None, safe_shutdown = None, load_only = False):
        self.settings_file = settings_file

        try:
            with open(settings_file, "r") as file:
                self.dictionary = json.load(file)
        except IOError:
            self.add_default_settings()

        if (load_only):
            return

        if (HSMSettings.BUILTIN_FIRMWARE_VERSION not in self.dictionary):
            self.add_default_hardware_settings()

        if (HSMSettings.MASTERKEY_SET not in self.dictionary):
            self.add_default_master_key_settings()

        if (gpio_available is not None):
            if (not gpio_available):
                self.set_setting(HSMSettings.GPIO_LEDS, False)
                self.set_setting(HSMSettings.GPIO_TAMPER, False)
            else:
                self.init_gpio()

        self.check_master_key_settings()

        # save any adjustments that we may have made
        self.save_settings()

        # should save settings even on crashes
        atexit.register(self.save_settings)

        # make sure we shutdown correctly
        if(safe_shutdown is not None):
            safe_shutdown.addOnShutdown(self.save_settings)
            safe_shutdown.addOnRestartOnly(self.on_restart)

    def get_setting(self, name):
        try:
            return self.dictionary[name]
        except:
            return None

    def set_setting(self, name, value):
        try:
            self.dictionary[name] = value

            self.save_settings()
            return True
        except:
            return False


    def add_default_settings(self):
        self.dictionary = {}
        self.dictionary[HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS] = False
        self.dictionary[HSMSettings.IP_ADDRESS_SETTINGS] = 'DHCP'
        self.dictionary[HSMSettings.STATICIP_IPADDR] = '10.10.10.2'
        self.dictionary[HSMSettings.STATICIP_NETMASK] = '255.255.255.0'
        self.dictionary[HSMSettings.STATICIP_GATEWAY] = '10.10.10.1'
        self.dictionary[HSMSettings.STATICIP_BROADCAST] = '10.10.10.255'

    def add_default_master_key_settings(self):
        self.dictionary[HSMSettings.MASTERKEY_SET] = False
        self.dictionary[HSMSettings.HSM_RESET_NORMALLY] = False

    def add_default_hardware_settings(self):
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
        self.dictionary[HSMSettings.MGMGPORT_TAMPER] = False

    def check_master_key_settings(self):
        # if we're starting up and not because of a normal reset, assume the masterkey has been lost
        if(self.dictionary[HSMSettings.HSM_RESET_NORMALLY] == False):
            self.dictionary[HSMSettings.MASTERKEY_SET] = False

        # we've handled the flag so set it to false
        self.dictionary[HSMSettings.HSM_RESET_NORMALLY] = False

    def check_hardware_settings(self):
        # make sure the setting actually exist
        if (HSMSettings.FIRMWARE_OUT_OF_DATE not in self.dictionary):
            self.dictionary[HSMSettings.FIRMWARE_OUT_OF_DATE] = False

        if (self.get_setting(HSMSettings.FIRMWARE_OUT_OF_DATE) == True):
            # we were previously out-of-date. See if that's still true
            if(self.hardware_firmware_match() and self.hardware_tamper_match()):
                # we've been updated, change settings to reflect
                self.update_hardware_settings()

                self.set_setting(HSMSettings.FIRMWARE_OUT_OF_DATE, False)
        else:
            # we weren't out-of-date. See if that's still true
            if(not self.hardware_firmware_match() or not self.hardware_tamper_match()):
                self.set_setting(HSMSettings.FIRMWARE_OUT_OF_DATE, True)

    def update_hardware_settings(self):
        for key, value in HARDWARE_MAPPING.iteritems():
            self.dictionary[key] = value

    def hardware_firmware_match(self):
        return self.dictionary[HSMSettings.BUILTIN_FIRMWARE_VERSION] == BUILTIN_FIRMWARE_VERSION

    def hardware_tamper_match(self):
        return self.dictionary[HSMSettings.BUILTIN_TAMPER_VERSION] == BUILTIN_TAMPER_VERSION

    def on_restart(self):
        # hopefully we have a normal reset without a power failure
        self.dictionary[HSMSettings.HSM_RESET_NORMALLY] = True

    def set_firmware_updated(self):
        self.dictionary[HSMSettings.BUILTIN_FIRMWARE_VERSION] = BUILTIN_FIRMWARE_VERSION

        # this is something that must be saved right away
        self.save_settings()

    def set_tamper_updated(self):
        self.dictionary[HSMSettings.BUILTIN_TAMPER_VERSION] = BUILTIN_TAMPER_VERSION

        # this is something that must be saved right away
        self.save_settings()

    def init_gpio(self):
        try:
            import RPi.GPIO as GPIO

            GPIO.setmode(GPIO.BCM)
        except:
            self.set_setting(HSMSettings.GPIO_LEDS, False)
            self.set_setting(HSMSettings.GPIO_TAMPER, False)

    def save_settings(self):
        try:
            with open(self.settings_file, "w") as file:
                json.dump(self.dictionary, file)
        except IOError as e:
            print "Unable to save settings: I/O error({0}): {1}".format(e.errno, e.strerror)
