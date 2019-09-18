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


import time
import threading
import socket

import Queue

import tornado.iostream

from abc import abstractmethod, ABCMeta

from enum import Enum

from cryptech_port import DKS_HSM

import cryptech.muxd

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
    def __init__(self, device, debug):
        super(CtyArg, self).__init__()
        self.device = device
        self.debug = debug

        self.quiet = True
        self.separate_pins = False

class CrypTechDeviceState(str, Enum):
    HSMLocked    = 'The HSM must be unlocked. Please login using the setup console.'
    HSMReady     = 'Active - Ready'
    KEYGen       = 'Active - Generating a key'
    BUSY         = 'Active - Busy'
    HSMNotReady  = 'Device not ready'
    FAILED       = 'Device failure. Try restarting the HSM.'
    TAMPER       = 'ERROR - Tamper detected'
    TAMPER_RESET = 'WARNING - A tamper event has stopped. Please check the HSM and restart it.'


class HSMPortInfo:
    """Provides basic information on an HSM that's needed by the load balancer"""
    def __init__(self, name, addr, serial):
        self.name = name
        self.addr = addr
        self.serial = serial
        self.state = CrypTechDeviceState.HSMLocked
        self.state_lock = threading.Lock()
        self.count = 0

    def get_busy_factor(self):
        """Returns a number that show how busy the HSM is by the number of operations happening on it"""
        with self.state_lock:
            state = self.state

        if(state == CrypTechDeviceState.HSMLocked or
           state == CrypTechDeviceState.HSMNotReady or
           state == CrypTechDeviceState.TAMPER or
           state == CrypTechDeviceState.FAILED):
           # this port can't be used
           return -1

        with self.state_lock:
            count = self.count

        # key gen's are weighty
        if (state == CrypTechDeviceState.KEYGen):
            count += 100

        return count

    def inc_busy_count(self):
        with self.state_lock:
            self.count += 1

    def dec_busy_count(self):
        with self.state_lock:
            self.count -= 1

    def change_state(self, new_state):
        """Switches to any state as long as the current state is not tamper"""
        with self.state_lock:
            if(self.state != CrypTechDeviceState.TAMPER):
                self.state = new_state

    def unlock_port(self):
        """If the port is locked, set it to ready"""
        with self.state_lock:
            if(self.state == CrypTechDeviceState.HSMLocked or
               self.state == CrypTechDeviceState.TAMPER_RESET):
                self.state = CrypTechDeviceState.HSMReady

    def clear_tamper(self, new_state):
        """change the state, clearing tamper if set"""
        with self.state_lock:
            if(self.state == CrypTechDeviceState.TAMPER):
                self.state = new_state

    def close(self):
        self.serial.close()


class PFUNIX_HSM(object):
    """Connects to an HSM over a PF_UNIX socket and then provides a
    cryptech.libhal.HSM reference to the HSM so rpc commands can be sent to
    it. This will work with diamond_server as long as a
    SecondaryPFUnixListener is being used."""

    __metaclass__ = ABCMeta

    def __init__(self, sockname):
        self.sockname = sockname
        self.e = threading.Event()

    @abstractmethod
    def dowork(self, hsm):
        pass

    def process_command_loop(self):
        # connect to the HSM using the PF_UNIX socket
        try:
            hsm = DKS_HSM(sockname = self.sockname)
        except socket.error, exc:
            print "Caught exception socket.error : %s" % exc
            return False

        while not self.e.isSet():
            if(self.dowork(hsm) == True):
                return
            time.sleep(1.0)

    def append_future(self, futures):
        """Use append_future when working with Tornado"""
        futures.append(self.start())

    @tornado.gen.coroutine
    def start(self):
        """Use append_future when working with Tornado"""
        t1 = threading.Thread(name='cty_reponse',
                              target=self.process_command_loop)
        t1.start()

    def stop(self):
        self.e.set()