#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
"""This script controls the LED and runs as a separate proccess
the starts as early as possible on the HSMs single board computer.
Other scripts communicate with it using a PF_UNIX socket. Programs
should connect, send one command, and the drop the connection."""

import time
import threading

from hsm_tools.stoppable_thread import stoppable_thread

import RPi.GPIO as GPIO

from enum import Enum

class Color(str, Enum):
    """Enum where members are also (and must be) strs"""
    RED = 'RED'
    GREEN = 'GREEN'
    YELLOW  = 'YELLOW'

class Mode(str, Enum):
    """Enum where members are also (and must be) strs"""
    ON = 'ON'
    OFF = 'OFF'
    BLINK = 'BLINK'

class LED(object):
    def __init__(self, red_gpio, green_gpio):
        self.red_gpio = red_gpio
        self.green_gpio = green_gpio

        self.lock = threading.Lock()

        self.mode = Mode.OFF

        self.blinking_thread = None

        # setup the GPIO
        GPIO.setup(self.red_gpio, GPIO.OUT, initial = GPIO.HIGH)
        GPIO.setup(self.green_gpio, GPIO.OUT, initial = GPIO.HIGH)

        # the current color to show
        self.color = Color.YELLOW

    def set_green(self):
        self.set_color(Color.GREEN)

    def set_red(self):
        self.set_color(Color.RED)

    def set_yellow(self):
        self.set_color(Color.YELLOW)

    def flash_red(self):
        thread = stoppable_thread(self.__flashred_thread)
        thread.start()

    def set_color(self, color):
        with (self.lock):
            if (self.color != color):
                if (self.mode != Mode.OFF):
                    if(self.blinking_thread is not None):
                        self.__stop_blinking()

                    # we're changing the color so turn of the LED if it's alread on
                    self.__set_off()

                # change the color
                self.color = color

                # turn back on if needed
                if(self.mode == Mode.ON):
                    self.__set_on()
                elif (self.mode == Mode.BLINK):
                    self.__start_blinking()


    def on(self):
        with self.lock:
            self.mode = Mode.ON
            self.__set_on()

    def off(self):
        with self.lock:
            if(self.blinking_thread is not None):
                self.__stop_blinking()

            self.mode = Mode.OFF
            self.__set_off()

    def blink(self):
        with self.lock:
            if(self.mode != Mode.BLINK):
                self.__start_blinking()
                self.mode = Mode.BLINK


    def __start_blinking(self):
        self.blink_state = True
        self.blinking_thread = stoppable_thread(self.__blinking_thread)
        self.blinking_thread.start()

    def __stop_blinking(self):
        # tell the thread that's making us blink to stop
        self.blinking_thread.stop_wait()
        self.blinking_thread = None

    def __blinking_thread(self):
        # this is looped by stoppable_thread
        with self.lock:
            if(self.blink_state):
                self.__set_on()
            else:
                self.__set_off()

            self.blink_state = not self.blink_state

        time.sleep(0.25)
        return True

    def __flashred_thread(self):
        color = self.color
        mode = self.mode

        self.set_red()
        self.blink()

        time.sleep(5.0)

        self.off()
        if(mode != Mode.OFF):
            self.set_color(color)
            if (mode == Mode.BLINK):
                self.blink()
            else:
                self.on()

        return False

    def __set_on(self):
        if(self.color == Color.YELLOW):
            GPIO.output(self.red_gpio, GPIO.LOW)
            GPIO.output(self.green_gpio, GPIO.LOW)
        elif(self.color == Color.GREEN):
            GPIO.output(self.red_gpio, GPIO.HIGH)
            GPIO.output(self.green_gpio, GPIO.LOW)
        elif(self.color == Color.RED):
            GPIO.output(self.red_gpio, GPIO.LOW)
            GPIO.output(self.green_gpio, GPIO.HIGH)

    def __set_off(self):
        GPIO.output(self.red_gpio, GPIO.HIGH)
        GPIO.output(self.green_gpio, GPIO.HIGH)

class LEDCommand(object):
    def __init__(self, mode, lednum, color):
        self.mode = mode
        self.lednum = lednum
        self.color = color

class LEDContainer(object):
    def __init__(self):
        GPIO.setmode(GPIO.BCM)
        self.tamper_led = LED(red_gpio =  5, green_gpio =  6)
        self.system_led = LED(red_gpio = 26, green_gpio = 19)

    def led_determine_network_adapter(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_yellow()
        self.tamper_led.set_yellow()

        self.system_led.blink()
        self.tamper_led.on()


    def led_probe_for_cryptech(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_yellow()
        self.tamper_led.set_yellow()

        self.system_led.blink()
        self.tamper_led.blink()

    def led_start_tcp_servers(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_green()
        self.tamper_led.set_green()

        self.system_led.blink()
        self.tamper_led.blink()

    def led_ready(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_green()
        self.tamper_led.set_green()

        self.system_led.on()
        self.tamper_led.on()

    def led_error_cryptech_failure(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_red()
        self.tamper_led.set_yellow()

        self.system_led.blink()
        self.tamper_led.on()

    def led_error_cryptech_partial_failure(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_yellow()
        self.tamper_led.set_green()

        self.system_led.blink()
        self.tamper_led.on()

    def led_error_tamper(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_red()
        self.tamper_led.set_red()

        self.system_led.blink()
        self.tamper_led.blink()

    def on_tamper_notify(self, tamper_object):
        if(tamper_object.get_tamper_state() == True):
            self.led_error_tamper()
        else:
            # set to system and tamper blinking yellow
            self.led_probe_for_cryptech()

    def test(self):
        print 'On Test'
        print 'Tamper'
        print 'RED'
        self.tamper_led.color = Color.RED
        self.tamper_led.on()
        time.sleep(3)
        print 'GREEN'
        self.tamper_led.color = Color.GREEN
        self.tamper_led.on()
        time.sleep(3)
        print 'YELLOW'
        self.tamper_led.color = Color.YELLOW
        self.tamper_led.on()
        time.sleep(3)
        print 'OFF'
        self.tamper_led.off()

        print 'System LED'
        print 'RED'
        self.system_led.color = Color.RED
        self.system_led.on()
        time.sleep(3)
        print 'GREEN'
        self.system_led.color = Color.GREEN
        self.system_led.on()
        time.sleep(3)
        print 'YELLOW'
        self.system_led.color = Color.YELLOW
        self.system_led.on()
        time.sleep(3)
        print 'OFF'
        self.system_led.off()

        print 'Blinking'
        print 'Tamper'
        print 'RED'
        self.tamper_led.color = Color.RED
        self.tamper_led.blink()
        time.sleep(5)
        print 'GREEN'
        self.tamper_led.color = Color.GREEN
        self.tamper_led.blink()
        time.sleep(5)
        print 'YELLOW'
        self.tamper_led.color = Color.YELLOW
        self.tamper_led.blink()
        time.sleep(5)
        print 'OFF'
        self.tamper_led.off()

        print 'System LED'
        print 'RED'
        self.system_led.color = Color.RED
        self.system_led.blink()
        time.sleep(5)
        print 'GREEN'
        self.system_led.color = Color.GREEN
        self.system_led.blink()
        time.sleep(5)
        print 'YELLOW'
        self.system_led.color = Color.YELLOW
        self.system_led.blink()
        time.sleep(5)
        print 'OFF'
        self.system_led.off()

if __name__ == "__main__":
    LEDContainer().test()