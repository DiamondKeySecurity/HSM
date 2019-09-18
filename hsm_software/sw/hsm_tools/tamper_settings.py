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

import json
import os

def byteify(input):
    """Converts unicode(2 byte) values stored in a dictionary or string to utf-8"""
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

class TamperConfiguration(object):
    """Database for storing tamper settings between saves"""
    def __init__(self, dbpath, detector):
        self.settings = { }
        self.dbpath = os.path.join(dbpath, "tamper_settings.json")
        self.detector = detector

    def update_setting(self, name, command, values):
        self.settings[name] = (command, values)
        self.save_settings()

    def save_settings(self):
        try:
            with open(self.dbpath, "wt") as fp:
                json.dump(self.settings, fp)
        except:
            pass

    def load_saved_settings(self):
        try:
            with open(self.dbpath, "rt") as fp:
                self.settings = byteify(json.load(fp))
        except:
            pass

    def push_settings(self, console_connect):
        command_order = ["disable", "enable", "templo", "temphi", "light", "vibe"]

        for command in command_order:
            cmd_string = self.get_command_string(command)

            if (cmd_string is not None):
                console_connect.send_raw_all(cmd_string, 5)

        console_connect.send_raw_all("tamper set config", 5)

        if (self.detector is not None):
            self.detector.enable()

    def get_command_string(self, command, suffix = ''):
        if(command in self.settings):
            setting = self.settings[command]
            cmd_string = setting[0]
            for param in setting[1]:
                cmd_string = "%s %s%s"%(cmd_string, str(param), suffix)

            return cmd_string
        else:
            return None

    def clear(self):
        self.settings = { }

if __name__ == "__main__":
    class connect(object):
        def send_raw_all(self, cmd, _):
            print " > %s"%cmd

    tamper = TamperConfiguration("/home/douglas/Documents", None)

    tamper.update_setting("disable", "tamper threshold set disable", [0])
    tamper.update_setting("enable", "tamper threshold set enable", [0])
    tamper.update_setting("temperature", "tamper threshold set temperature", [10,30])
    tamper.update_setting("light", "tamper threshold set light", [0])
    tamper.update_setting("vibe", "tamper threshold set accel", [0])

    tamper.save_settings()
    tamper.load_saved_settings()
    tamper.push_settings(connect())

    print("After HSM reset, the tamper settings on the device need to be reset.")
    print("These are the previous settings:")
    for name, setting in tamper.settings.iteritems():
        setting_string = "    %s : "%name.ljust(12)
        for param in setting[1]:
            setting_string = "%s %s"%(setting_string, str(param))

        print(setting_string)

