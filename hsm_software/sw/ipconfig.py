#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import os
import argparse
import subprocess
import netifaces

from settings import Settings, HSMSettings

from firewall import Firewall

class IPConfig(object):
    """Program to start HSM software or update it"""
    def __init__(self, netiface, settings, tmp):
        self.netiface = netiface
        self.settings = settings
        self.tmp = tmp

    def do_ipconfig(self):
        setting = HSMSettings.IP_ADDRESS_SETTINGS
        dhcp_or_static = self.settings.get_setting(setting)

        if(dhcp_or_static == 'STATIC_IP'):
            self.startstatic_ip()
        else:
            self.startdhcp()

        Firewall.generate_firewall_rules(self.settings, self.tmp)

    def startdhcp(self):
        print('ipconfig.py is now setting the IP using'
              ' the default DHCP settings.')

        subprocess.call(['/sbin/ifup', self.netiface])

    def startstatic_ip(self):
        print('ipconfig.py is now setting a static IP')

        ipaddr = self.settings.get_setting(HSMSettings.STATICIP_IPADDR)
        netmask = self.settings.get_setting(HSMSettings.STATICIP_NETMASK)
        gateway = self.settings.get_setting(HSMSettings.STATICIP_GATEWAY)
        broadcast = self.settings.get_setting(HSMSettings.STATICIP_BROADCAST)

        os.system('ifconfig %s %s' % (self.netiface, ipaddr))
        os.system('ifconfig %s netmask %s' % (self.netiface, netmask))
        os.system('ifconfig %s broadcast %s' % (self.netiface, broadcast))
        os.system('route add default gw %s %s' % (gateway, self.netiface))


class NetworkInterfaces(object):
    def __init__(self, netInterface, defaults_dir):
        self.addresses = netifaces.ifaddresses(netInterface)
        try:
            addr = self.addresses[netifaces.AF_INET][0]['addr']
            self.ip4addr = addr.encode('utf-8')
        except Exception:
            self.ip4addr = None

        try:
            link = self.addresses[netifaces.AF_LINK][0]['addr']
            self.aflink = link.encode('utf-8')
        except Exception:
            self.aflink = None
        self.defaults_dir = defaults_dir

    def get_ip(self):
        return self.ip4addr

    def get_mac(self):
        return self.aflink


if __name__ == "__main__":
    formatter_class = argparse.ArgumentDefaultsHelpFormatter
    
    parser = argparse.ArgumentParser(formatter_class=formatter_class)

    parser.add_argument("-n", "--netiface",
                        help="Network interface to use in reporting",
                        default="eth0")

    parser.add_argument("-s", "--settings",
                        help="Persistant file to save settings to",
                        default="../settings.json")

    parser.add_argument("--tmp",
                        help = "temp folder",
                        default = "/var/tmp")

    args = parser.parse_args()

    settings = Settings(args.settings, load_only=True)

    IPConfig(args.netiface, settings, args.tmp).do_ipconfig()
