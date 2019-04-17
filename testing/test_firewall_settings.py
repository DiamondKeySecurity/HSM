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


import sys
import os
from enum import Enum

sys.path.insert(0, '../')

from hsm_software.sw.settings import HSMSettings
from hsm_software.sw.firewall import Firewall

TestSettings = { HSMSettings.ZERO_CONFIG_ENABLED : True,
                 HSMSettings.DATA_FIREWALL_SETTINGS : ('10.1.10.1','10.1.10.172'),
                 HSMSettings.MGMT_FIREWALL_SETTINGS : ['10.1.10.172'],
                 HSMSettings.WEB_FIREWALL_SETTINGS : None,
               }

rules_list = Firewall.generate_iptable_settings(TestSettings, 'eth0')

with open("/home/douglas/Documents/iptable_settings.txt", "w") as fp:
    # write the header to the file
    for line in rules_list:
        fp.write(line)

    fp.truncate()