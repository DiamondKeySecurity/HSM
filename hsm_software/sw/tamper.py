#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

class TamperDetector(object):
    @staticmethod
    def get_object():
        try:
            import RPi.GPIO
        except ImportError:
            import tamper_gpio
            return tamper_gpio.Tamper_GPIO
        else:
            import tamper_test
            return tamper_test.Tamper_Test
