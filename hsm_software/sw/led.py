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
        self.current_led_function = None

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

            self.current_led_function = "led_determine_network_adapter"

    def led_off(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_off")

            self.current_led_function = "led_off"

    def led_probe_for_cryptech(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_probe_for_cryptech")

            self.current_led_function = "led_probe_for_cryptech"

            self.current_led_function = "led_probe_for_cryptech"

    def led_start_tcp_servers(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_start_tcp_servers")

            self.current_led_function = "led_start_tcp_servers"

            self.current_led_function = "led_start_tcp_servers"

    def led_ready(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_ready")

            self.current_led_function = "led_ready"

            self.current_led_function = "led_ready"

    def led_error_cryptech_failure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_cryptech_failure")

            self.current_led_function = "led_error_cryptech_failure"

            self.current_led_function = "led_error_cryptech_failure"

    def led_error_cryptech_partial_failure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_cryptech_partial_failure")

            self.current_led_function = "led_error_cryptech_partial_failure"

            self.current_led_function = "led_error_cryptech_partial_failure"

    def led_error_login_failure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_login_failure")

            self.current_led_function = "led_error_login_failure"

            self.current_led_function = "led_error_login_failure"

    def led_error_login_partialfailure(self):
        if(self.tamper_detected.value is not True):
            self.send_led_state("led_error_login_partialfailure")

            self.current_led_function = "led_error_login_partialfailure"

            self.current_led_function = "led_error_login_partialfailure"

    def led_error_tamper(self):
        self.send_led_state("led_error_tamper")

    def led_pretamper(self):
        if(self.current_led_function is None):
            self.current_led_function = "led_probe_for_cryptech"

        if (hasattr(self, self.current_led_function)):
            getattr(self, self.current_led_function)()

    def on_tamper_notify(self, tamper_object):
        print 'LED GOT A TAMPER'        
        if(self.tamper_detected.value != tamper_object.get_tamper_state()):
            self.tamper_detected.value = tamper_object.get_tamper_state()

            if(self.tamper_detected.value):
                self.led_error_tamper()
            else:
                self.led_pretamper()
