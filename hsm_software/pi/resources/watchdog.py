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
#VERSION 2019-08-06-01
import os
import atexit
import socket
import threading
import time

import RPi.GPIO as GPIO
from enum import Enum


class PFUnixMsgListener(object):
    def __init__(self, socket_filename, mode, callback):
        self.socket_filename = socket_filename
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(1.0)
        self.sock.bind(socket_filename)
        self.e = threading.Event()
        self.callback = callback

        self.listening_thread = None

        atexit.register(self.atexit_unlink)

    def atexit_unlink(self):
        try:
            os.unlink(self.socket_filename)
        except:
            pass

    def stop_listening(self):
        self.e.set()

    def start_listening(self):
        self.sock.listen(1)

        thread = threading.Thread(name="pf listener thread",
                                    target=self.listener_thread)
        thread.start()

    def listener_thread(self):
        while not self.e.isSet():
            time.sleep(0.5)
            try:
                client_stream, client_addr = self.sock.accept()
                thread = threading.Thread(name="pf handler thread",
                                          target=self.handler_thread,
                                          args=(client_stream, client_addr))
                thread.start()
            except:
                pass

        self.sock.close()
        os.unlink(self.socket_filename)

    def handler_thread(self, client_stream, client_addr):
        """Simple thread that gets new responses from CTY"""
        delimeter = ",,"
        message_buffer = ""
        while not self.e.isSet():
            try:
                data = client_stream.recv(64)
                if (data == "" or data is None):
                    return
                
                message_buffer += data

                delim_loc = message_buffer.find(delimeter)
                if (delim_loc >= 0):
                    message = message_buffer[:delim_loc]
                    message_buffer = message_buffer[delim_loc+len(delimeter):]
                    if (self.callback is not None):
                        self.callback(message)

                time.sleep(1)
            except socket.timeout:
                pass
            except:
                break

class stoppable_thread(object):
    def __init__(self, function, name = 'stoppable_thread'):
        self.thread = threading.Thread(name=name,
                                       target = self.__loop)
        self.function = function
        self.stop_event = threading.Event()

    def __loop(self):
        while not self.stop_event.isSet():
            result = self.function()
            if(result is False):
                break
            
    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def stop_wait(self, timeout=None):
        self.stop()
        self.thread.join(timeout=timeout)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.thread.isAlive():
            self.stop_wait()

class ThreadSafeVariable(object):
    def __init__(self, value):
        self.thread_lock = threading.Lock()
        self.__setval(value)

    def __setval(self, value):
        with(self.thread_lock):
            self.__value = value
    
    def __getval(self):
        with(self.thread_lock):
            return self.__value

    value = property(__getval, __setval)

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
        self.tamper_led = LED(red_gpio =  5, green_gpio =  6)
        self.system_led = LED(red_gpio = 26, green_gpio = 19)

    def led_off(self):
        self.system_led.off()
        self.tamper_led.off()

    def led_power_on(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_yellow()
        self.tamper_led.set_yellow()

        self.system_led.blink()
        self.tamper_led.blink()

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

    def led_error_login_failure(self):
        self.system_led.off()
        self.tamper_led.off()

        self.system_led.set_red()
        self.tamper_led.set_green()

        self.system_led.blink()
        self.tamper_led.on()

    def led_error_login_partialfailure(self):
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


class WatchDogPlusLED:
    def __init__(self):
        GPIO.setmode(GPIO.BCM)
        self.active = ThreadSafeVariable(False)
        self.led_containter = LEDContainer()
        self.led_containter.led_power_on()

    def start(self):
        self.active.value = True
        self.listener = PFUnixMsgListener("/tmp/watchdog.tmp.sock", 0o600, self.message_callback)
        self.listener.start_listening()

    def stop(self):
        self.active.value = False
        self.listener.stop_listening()
        self.led_containter.led_off()

    def message_callback(self, msg):
        print "recv: '%s'"%msg
        if (msg.startswith("quit")):
            self.active.value = False
        if (msg.startswith("led_")):
            method_name = msg
            if(hasattr(self.led_containter, method_name)):
                getattr(self.led_containter, method_name)()

    def isActive(self):
        return self.active.value

if __name__ == "__main__":
    print 'starting watch dog'

    watchdog = WatchDogPlusLED()

    watchdog.start()

    while watchdog.isActive():
        pass

    watchdog.stop()