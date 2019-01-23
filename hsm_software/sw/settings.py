#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import atexit
import json

from enum import Enum

HSM_SOFTWARE_VERSION = '19.01.23.p0'

RPC_IP_PORT = 8080
CTY_IP_PORT = 8081
WEB_PORT    = 80

class HSMSettings(str, Enum):
    """Enum where members are also (and must be) strs"""
    ENABLE_EXPORTABLE_PRIVATE_KEYS = 'ENABLE_EXPORTABLE_PRIVATE_KEYS'
    IP_ADDRESS_SETTINGS = 'IP_ADDRESS_SETTINGS'
    STATICIP_IPADDR  = 'STATICIP_IPADDR'
    STATICIP_NETMASK = 'STATICIP_NETMASK'
    STATICIP_GATEWAY = 'STATICIP_GATEWAY'
    STATICIP_BROADCAST = 'STATICIP_BROADCAST'

class Settings(object):
    def __init__(self, settings_file):
        self.settings_file = settings_file

        try:
            with open(settings_file, "r") as file:
                self.dictionary = json.load(file)
        except IOError:
            self.add_default_settings()

        atexit.register(self.save_settings)

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

    def save_settings(self):
        try:
            with open(self.settings_file, "w") as file:
                json.dump(self.dictionary, file)
        except IOError as e:
            print "Unable to save settings: I/O error({0}): {1}".format(e.errno, e.strerror)