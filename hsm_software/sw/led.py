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

"""This script controls the LED and runs as a separate proccess
the starts as early as possible on the HSMs single board computer.
Other scripts communicate with it using a PF_UNIX socket. Programs
should connect, send one command, and the drop the connection."""

import os
import socket
import time
from hsm_tools.threadsafevar import ThreadSafeVariable

class PFUnixMsgSender(object):
    def __init__(self, socket_filename):
        self.socket_filename = socket_filename
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def connect(self):
        try:
            self.sock.connect(self.socket_filename)
        except socket.error as e:
            print e.message
            return False

        return True

    def send(self, msg):
        try:
            self.sock.sendall("%s,,"%msg)
        except:
            pass

class LEDContainer(object):
    def __init__(self):
        self.tamper_detected = ThreadSafeVariable(False)

        self.sender = PFUnixMsgSender("/tmp/watchdog.tmp.sock")
        self.sender.connect()

    def send_led_state(self, message):
        try:
            self.sender.send(message)
            time.sleep(2)
        except:
            pass

    def led_determine_network_adapter(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_determine_network_adapter")

    def led_off(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_off")

    def led_probe_for_cryptech(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_probe_for_cryptech")

    def led_start_tcp_servers(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_start_tcp_servers")

    def led_ready(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_ready")

    def led_error_cryptech_failure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_cryptech_failure")

    def led_error_cryptech_partial_failure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_cryptech_partial_failure")

    def led_error_login_failure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_login_failure")

    def led_error_login_partialfailure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_login_partialfailure")

    def led_error_tamper(self):
        self.send_led_state("led_error_tamper")

    def on_tamper_notify(self, tamper_object):
        print 'LED GOT A TAMPER'        
        if(self.tamper_detected.value != tamper_object.get_tamper_state()):
            self.tamper_detected.value = tamper_object.get_tamper_state()

            if(self.tamper_detected.value):
                self.led_error_tamper()
            else:
                self.led_probe_for_cryptech()