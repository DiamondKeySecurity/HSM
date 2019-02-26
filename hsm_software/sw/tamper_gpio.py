#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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