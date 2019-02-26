#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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