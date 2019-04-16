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


import RPi.GPIO as GPIO

from hsm_tools.observerable import observable
from hsm_tools.stoppable_thread import stoppable_thread
import time

class Tamper_GPIO(observable):
    def __init__(self):
        super(Tamper_GPIO, self).__init__()

        print 'tamper gpio'

        # get the GPIO pins that we will use
        self.tamper_pins = [4, 17]

        # initialize
        for pin in self.tamper_pins:
            GPIO.setup(pin, GPIO.IN)

        self.thread = stoppable_thread(self.tamper_gpio_loop,
                                       name='tamper gpio thread')
        self.thread.start()

    def tamper_gpio_loop(self):
        # after 3 minutes yell tamper
        time.sleep(3)

        tamper_detected = False

        for pin in self.tamper_pins:
            tamper_detected = tamper_detected or (not GPIO.input(pin))

        if (tamper_detected):
            self.notify()

        return True

    def stop(self):
        self.thread.stop()