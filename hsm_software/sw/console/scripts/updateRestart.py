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

import os
import time

from script import ScriptModule, script_node, ValueType

class UpdateRestartScriptModule(ScriptModule):
    def __init__(self, cty_direct_call, safe_shutdown):
        self.cty_direct_call = cty_direct_call
        self.safe_shutdown = safe_shutdown
        super(UpdateRestartScriptModule, self).__init__([
                        script_node('restart',
                                    'The HSM will need to restart. Would you like to restart now? (y/n) ',
                                    ValueType.YesNo, callback=self.continuePromptCallback)
                        ])

    def continuePromptCallback(self, response):
        """Process user response about whether they want to reboot now"""
        if(response == True):
            self.cty_direct_call("HSM Restarting in 5 seconds....")
            time.sleep(5)

            self.safe_shutdown.restart()

        return None

