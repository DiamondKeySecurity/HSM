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


import time
import threading
import socket

import Queue

import tornado.iostream

from abc import abstractmethod, ABCMeta

from enum import Enum

from cryptech_port import DKS_HSM

import muxd

class UploadArgs(object):
    """Used to match interface in CrypTech code"""
    def __init__(self, fpga = False, firmware = False, bootloader = False, tamper = False, pin = None, username='wheel'):
        self.fpga = fpga
        self.firmware = firmware
        self.bootloader = bootloader
        self.tamper = tamper
        self.username = username

        # this will be changed by the user
        self.pin = pin

class CtyArg(UploadArgs):
    """Used to match interface in CrypTech code"""
    def __init__(self, name, device, debug):
        super(CtyArg, self).__init__()
        self.name = name
        self.device = device
        self.debug = debug

        self.quiet = True
        self.separate_pins = False
