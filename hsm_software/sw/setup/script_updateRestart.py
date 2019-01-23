#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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

