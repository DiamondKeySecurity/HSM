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

from script import ScriptModule, script_node, ValueType

class TamperSettingsScriptModule(ScriptModule):
    def __init__(self, cty_conn, cty_direct_call, tamper_configs, finished_callback):
        self.cty_conn = cty_conn
        self.cty_direct_call = cty_direct_call
        self.tamper_configs = tamper_configs

        setting_string = "\r\nAfter HSM reset, the tamper settings on the device need to be reset.\r\nThese are the previous settings:"
        for name, setting in tamper_configs.settings.iteritems():
            setting_string = "%s\r\n    %s : "%(setting_string, name.ljust(12))
            for param in setting[1]:
                setting_string = "%s %s"%(setting_string, str(param))

        setting_string = "%s\r\nWould you like to use the previous settings now? (y/n) "%setting_string
        
        super(TamperSettingsScriptModule, self).__init__([
                        script_node('usePreviousSettings',
                                    str(setting_string),
                                    ValueType.YesNo, callback=self.setUsePreviousSettings)
                        ], finished_callback = finished_callback)

    def setUsePreviousSettings(self, response):
        """Process user response about whether they want to set the master key"""
        if(response == True):
            self.tamper_configs.push_settings(self.cty_conn)
            self.cty_direct_call("The tamper settings have been applied")
        else:
            self.tamper_configs.clear()
            self.tamper_configs.save_settings()
            self.cty_direct_call("The tamper settings have have not been set. Please enter new tamper settings.")

        return self
