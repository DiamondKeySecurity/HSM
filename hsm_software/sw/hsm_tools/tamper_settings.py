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

import json
import os

class TamperConfiguration(object):
    """Database for storing tamper settings between saves"""
    def __init__(self, dbpath):
        self.settings = { }
        self.dbpath = os.path.join(dbpath, "tamper_settings.json")

    def update_setting(self, name, command, values):
        self.settings[name] = (command, values)

    def save_settings(self):
        try:
            with open(self.dbpath, "wt") as fp:
                json.dump(self.settings, fp)
        except:
            pass

    def load_saved_settings(self):
        try:
            with open(self.dbpath, "rt") as fp:
                self.settings = json.load(fp)
        except:
            pass

    def push_settings(self, console_connect):
        command_order = ["disable", "enable", "temperature", "light", "vibe"]

        for command in command_order:
            cmd_string = self.get_command_string(command)

            if (cmd_string is not None):
                console_connect.send_raw(cmd_string, 5)

        console_connect.send_raw("tamper set config", 5)

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
        def send_raw(self, cmd, _):
            print " > %s"%cmd

    tamper = TamperConfiguration("/home/douglas/Documents")

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

