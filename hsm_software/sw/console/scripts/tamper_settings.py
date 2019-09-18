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
