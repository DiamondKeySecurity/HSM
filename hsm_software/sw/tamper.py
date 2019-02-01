#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import hsm_tools.cryptech.muxd

from hsm_tools.observerable import observable

from hsm_tools.threadsafevar import ThreadSafeVariable
from settings import HSMSettings


class TamperDetector(observable):
    def __init__(self, settings):
        super(TamperDetector, self).__init__()

        self.tamper_event_detected = ThreadSafeVariable(False)

        if (settings.get_setting(HSMSettings.MGMTPORT_TAMPER)):
            self.detector = TamperDetector.get_rpc_detector()
        elif (settings.get_setting(HSMSettings.GPIO_TAMPER)):
            self.detector = TamperDetector.get_gpio_detector()
        else:
            self.detector = TamperDetector.get_test_detector()

        # get notification from detector
        self.detector.add_observer(self.on_tamper)

    def on_tamper(self, tamper_object):
        self.tamper_event_detected.value = True

        print("!!!!!!! TAMPER !!!!!!!!!!")
        hsm_tools.cryptech.muxd.logger.info("!!!!!!! TAMPER !!!!!!!!!!")

        # tell our observers of the tamper event
        self.notify()

    def get_tamper_state(self):
        return self.tamper_event_detected.value

    def reset_tamper_state(self):
        self.tamper_event_detected.value = False

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
