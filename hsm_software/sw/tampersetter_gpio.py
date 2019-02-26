#!/usr/bin/env python
# Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
#

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
        