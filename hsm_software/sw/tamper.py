#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import threading
import hsm_tools.cryptech.muxd

from enum import IntEnum
from hsm_tools.observerable import observable

class TamperDetectionMethod(IntEnum):
    GPIO = 0,  # detect tamper events by polling a GPIO port
    RPC  = 1,  # detect tamper events by polling using a CrypTech RPC
    TEST = 2   # fake a tamper event after 3 minutes

class TamperDetector(observable):
    def __init__(self, method):
        super(TamperDetector, self).__init__()

        self.tamper_event_detected = False
        self.thread_lock = threading.Lock()

        # get the required tamper detection device
        if(method == TamperDetectionMethod.GPIO):
            self.detector = TamperDetector.get_gpio_detector()
        elif(method == TamperDetectionMethod.RPC):
            self.detector = TamperDetector.get_rpc_detector()
        elif(method == TamperDetectionMethod.TEST):
            self.detector = TamperDetector.get_test_detector()

        assert self.detector is not None

        # get notification from detector
        self.detector.add_observer(self.on_tamper)

    def on_tamper(self, tamper_object):
        with self.thread_lock:
            # if(self.tamper_event_detected):
            #     # we've already handled the tamper event, don't keep sending it
            #     return

            self.tamper_event_detected = True

        print "!!!!!!! TAMPER !!!!!!!!!!"
        hsm_tools.cryptech.muxd.logger.info("!!!!!!! TAMPER !!!!!!!!!!")

        # tell our observers of the tamper event
        self.notify()

    def get_tamper_state(self):
        with self.thread_lock:
            return self.tamper_event_detected

    def reset_tamper_state(self):
        with self.thread_lock:
            self.tamper_event_detected = False

        # notify changed state to all observers
        self.notify()

    def stop(self):
        self.detector.stop()

    @staticmethod
    def get_test_detector():
        import tamper_test
        return tamper_test.Tamper_Test()

    @staticmethod
    def get_rpc_detector():
        import tamper_rpc
        return tamper_rpc.Tamper_RPC()

    @staticmethod
    def get_gpio_detector():
        try:
            import tamper_gpio
            return tamper_gpio.Tamper_GPIO()
        except ImportError:
            return None
