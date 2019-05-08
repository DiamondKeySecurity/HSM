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

class tampersetter_gpio(object):
    def __init__(self):
        # get the GPIO pins that we will use
        self.tamper_pins = [18, 27]

        # initialize
        for pin in self.tamper_pins:
            GPIO.setup(pin, GPIO.OUT, initial = GPIO.LOW)

    def enable_tamper(self):
        for pin in self.tamper_pins:
            GPIO.output(pin, GPIO.LOW)

    def disable_tamper(self):
        for pin in self.tamper_pins:
            GPIO.output(pin, GPIO.HIGH)
        