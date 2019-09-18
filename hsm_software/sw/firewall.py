#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
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

import subprocess

from settings import HSMSettings, WEB_PORT, RPC_IP_PORT, CTY_IP_PORT, SSH_PORT

class Firewall(object):
    IP_TABLE_HEADER = ['#!/bin/bash\n',
                       '# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.\n',
                       '#\n',
                       '## Set system variables ##\n',
                       'IPT=/sbin/iptables\n',
                       'SYSCTL=/sbin/sysctl\n',
                       '### Dump old FW Rules if any exist ####\n',
                       '$IPT -F\n',
                       '$IPT -X\n',
                       '$IPT -t nat -F\n',
                       '$IPT -t mangle -F\n',
                       '$IPT -t mangle -X\n',
                       '$IPT -P INPUT ACCEPT\n',
                       '$IPT -P OUTPUT ACCEPT\n',
                       '$IPT -P FORWARD ACCEPT\n',
                       '### Turn on SYN Flooding protection ###\n',
                       '### should be place in /etc/sysctl.conf\n',
                       '$SYSCTL -w net/ipv4/tcp_syncookies=1\n',
                       '### Block all Inbound, outbound and forwarded packets first ###\n',
                       '$IPT -P INPUT DROP   # Drop any packets attempting to enter on eth0\n',
                       '$IPT -P OUTPUT DROP  # Drop any packets attempting to leave out on eth0\n',
                       '$IPT -P FORWARD DROP  # Drop any packets attempting to forward to system\n',
                       '### Allow full access to the loopback interface ###\n',
                       '$IPT -A INPUT  -i lo -j ACCEPT\n',
                       '$IPT -A OUTPUT -o lo -j ACCEPT\n']

    @staticmethod
    def add_ip_rules_any(rules_list, netiface, port):
        rules_list.append('$IPT -A INPUT -i %s -p tcp --dport %i -m state --state NEW,ESTABLISHED -j ACCEPT\n'%(netiface, port))
        rules_list.append('$IPT -A OUTPUT -o %s -p tcp --sport %i -m state --state NEW,ESTABLISHED -j ACCEPT\n'%(netiface, port))

    @staticmethod
    def add_ip_rules_range(rules_list, netiface, port, range):
        rules_list.append('$IPT -A INPUT -i %s -p tcp --dport %i -m iprange --src-range %s-%s -m state --state NEW,ESTABLISHED -j ACCEPT\n'%(netiface, port, range[0], range[1]))
        rules_list.append('$IPT -A OUTPUT -o %s -p tcp --sport %i -m iprange --dst-range %s-%s -m state --state NEW,ESTABLISHED -j ACCEPT\n'%(netiface, port, range[0], range[1]))

    @staticmethod
    def add_ip_rules_list(rules_list, netiface, port, iplist):
        for ipaddr in iplist:
            rules_list.append('$IPT -A INPUT -i %s -p tcp --dport %i -s %s -m state --state NEW,ESTABLISHED -j ACCEPT\n'%(netiface, port, ipaddr))
            rules_list.append('$IPT -A OUTPUT -o %s -p tcp --sport %i -d %s -m state --state NEW,ESTABLISHED -j ACCEPT\n'%(netiface, port, ipaddr))

    @staticmethod
    def add_ip_rules(rules_list, netiface, port, setting):
        if ((setting is None) or (setting is True)):
            Firewall.add_ip_rules_any(rules_list, netiface, port)
            print ("port: %i set to accept all."%port)           
        elif isinstance(setting, tuple):
            Firewall.add_ip_rules_range(rules_list, netiface, port, setting)
            print ("port: %i set to range."%port)
        elif isinstance(setting, list):
            Firewall.add_ip_rules_list(rules_list, netiface, port, setting)
            print ("port: %i set to list."%port)
        else:
            print ("port: %i is blocked."%port)

    @staticmethod
    def generate_iptable_settings(settings, netiface):
        # copy the header
        rules_list = Firewall.IP_TABLE_HEADER[:]

        # firewall rules to allow NTP
        rules_list.append('$IPT -A OUTPUT -p udp --dport 123 -j ACCEPT\n')
        rules_list.append('$IPT -A INPUT -p udp --dport 123 -j ACCEPT\n')

        # rules for zeroconf if enabled
        if (settings[HSMSettings.ZERO_CONFIG_ENABLED]):
            rules_list.append('# rules to open zeroconfig\n')
            rules_list.append('$IPT -A INPUT -i %s -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT\n'%netiface)
            rules_list.append('$IPT -A OUTPUT -o %s -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT\n'%netiface)

        Firewall.add_ip_rules(rules_list, netiface, RPC_IP_PORT, settings[HSMSettings.DATA_FIREWALL_SETTINGS])
        Firewall.add_ip_rules(rules_list, netiface, CTY_IP_PORT, settings[HSMSettings.MGMT_FIREWALL_SETTINGS])
        Firewall.add_ip_rules(rules_list, netiface, WEB_PORT, settings[HSMSettings.WEB_FIREWALL_SETTINGS])
        Firewall.add_ip_rules(rules_list, netiface, SSH_PORT, settings[HSMSettings.SSH_FIREWALL_SETTINGS])

        # allow all direct connections to CTY
        Firewall.add_ip_rules(rules_list, '%s:1'%netiface, CTY_IP_PORT, None)

        return rules_list

    @staticmethod
    def generate_firewall_rules(settings, tmpfolder):
        # get a lists of the settings we need
        set_list = [HSMSettings.ZERO_CONFIG_ENABLED,
                    HSMSettings.DATA_FIREWALL_SETTINGS,
                    HSMSettings.MGMT_FIREWALL_SETTINGS,
                    HSMSettings.WEB_FIREWALL_SETTINGS,
                    HSMSettings.SSH_FIREWALL_SETTINGS,
                    HSMSettings.ALLOW_SSH]

        # extract from settings
        firewall_settings = {}
        for setting in set_list:
            firewall_settings[setting] = settings.get_setting(setting)

        # allow zero conf by default
        if (firewall_settings[HSMSettings.ZERO_CONFIG_ENABLED] is None):
            firewall_settings[HSMSettings.ZERO_CONFIG_ENABLED] = True

        # allow SSH
        allow_ssh = firewall_settings[HSMSettings.ALLOW_SSH]
        if ((allow_ssh is None) or (allow_ssh is False)):
            print 'SSH not allowed'
            firewall_settings[HSMSettings.SSH_FIREWALL_SETTINGS] = False

        # generate our rules
        rules_list = Firewall.generate_iptable_settings(firewall_settings, 'eth0')

        # save
        file_name = '%s/firewall_rules.sh'%tmpfolder

        with open(file_name, "w") as fp:
            # write the header to the file
            for line in rules_list:
                fp.write(line)

            fp.truncate()

        # execute
        cmd = 'sudo sh %s'%file_name
        print subprocess.check_output([cmd], shell=True, stderr=subprocess.STDOUT)