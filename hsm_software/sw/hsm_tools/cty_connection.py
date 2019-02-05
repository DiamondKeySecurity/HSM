#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import os

import time

from enum import IntEnum
from cryptech.upload import ManagementPortSerial, send_file

from stoppable_thread import stoppable_thread

from hsm import UploadArgs

class CTYError(IntEnum):
    CTY_OK = 0,
    CTY_NOT_CONNECTED = 1,
    CTY_NOT_LOGGED_IN = 2,
    CTY_INCORRECT_PASSWORD = 3,
    CTY_ERROR = 4

class WaitFeedback(stoppable_thread):
    def __init__(self, feedback_function):
        self.feedback_function = feedback_function
        self.index = -1
        super(WaitFeedback, self).__init__(self.loop, "WaitFeedback")

    def loop(self):
        if (self.index != -1):
            self.feedback_function('\b\b\b')
        else:
            self.feedback_function('\r\n')

        self.index += 1

        if ((self.index % 4) == 0): self.feedback_function(' - ')
        elif ((self.index % 4) == 1): self.feedback_function(' \\ ')
        elif ((self.index % 4) == 2): self.feedback_function(' | ')
        elif ((self.index % 4) == 3): self.feedback_function(' / ')

        time.sleep(0.125)

    @classmethod
    def Start(cls, feedback_function):
        feedback = cls(feedback_function)
        feedback.start()

        return feedback


class CTYConnection(object):
    """High-level interface for connecting to alpha's CTY port """
    def __init__(self, cty_list, binary_path, feedback_function):
        self.cty_list = cty_list
        self.is_logged_in = False
        self.binary_path = binary_path
        self.feedback_function = feedback_function
        self.errors = { CTYError.CTY_OK:"Connection to CrypTech Management Port successful",
                        CTYError.CTY_NOT_CONNECTED:"Not connected to a CrypTech device",
                        CTYError.CTY_NOT_LOGGED_IN:"Not logged in to a CrypTech device",
                        CTYError.CTY_INCORRECT_PASSWORD:"Incorrect password given",
                        CTYError.CTY_ERROR:"Error sending command to CrypTech device" }

    def get_error_msg(self, error):
        if(error in self.errors):
            return self.errors[error]
        else:
            return "Unknown CTY error"

    def is_cty_connected(self):
        return len(self.cty_list) > 0

    def feedback(self, message):
        if (self.feedback_function is not None):
            self.feedback_function(message)

    def send_raw(self, cmd, delay):
        response = '\r\n'

        print cmd

        for i in xrange(0, len(self.cty_list)):
            with WaitFeedback.Start(self.feedback):
                management_port_serial = self.cty_list[i].serial

                management_port_serial.write(cmd)

                time.sleep(delay)

                response = '%s\r\n%s'%(response, management_port_serial.read())

        return response

    def set_tamper_threshold_light(self, value):
        cmd = 'tamper threshold set light %f\r'%(value)

        return self.send_raw(cmd, 5)

    def set_tamper_threshold_temperature(self, lo_value, hi_value):
        cmd = 'tamper threshold set temperature %f %f\r'%(lo_value, hi_value)

        return self.send_raw(cmd, 5)

    def set_tamper_threshold_accel(self, value):
        cmd = 'tamper threshold set accel %f\r'%(value)

        return self.send_raw(cmd, 5)

    def login(self, PIN):
        # make sure we're actually connected to an alpha
        if(not self.is_cty_connected()): return CTYError.CTY_NOT_CONNECTED

        self.logout()

        with WaitFeedback.Start(self.feedback):
            for hsm_cty in self.cty_list:
                management_port_serial = hsm_cty.serial
                management_port_serial.args.pin = PIN

                # use execute to login
                response = management_port_serial.execute("\r")

                if not response.endswith(("> ", "# ")):
                    return CTYError.CTY_INCORRECT_PASSWORD

                # clear PIN
                management_port_serial.args.pin = '1234'

        self.is_logged_in = True

        return CTYError.CTY_OK

    def logout(self):
        # make sure we're actually connected to an alpha
        if(not self.is_cty_connected()): return CTYError.CTY_NOT_CONNECTED

        with WaitFeedback.Start(self.feedback):
            for hsm_cty in self.cty_list:
                management_port_serial = hsm_cty.serial
                management_port_serial.write("\r")
                prompt = management_port_serial.read()

                assert "bootloader" not in prompt

                if not prompt.endswith("Username: "):
                    management_port_serial.write("exit\r")
                    prompt = management_port_serial.read()
                    if not prompt.endswith("Username: "):
                        return CTYError.CTY_ERROR

        self.is_logged_in = False

        return CTYError.CTY_OK

    def setMasterKey(self, masterkey):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        if masterkey is not None:
            cmd = "masterkey set %s\r"%masterkey
        else:
            cmd = "masterkey set\r"

        self.feedback('\r\nSetting master key. This may take upto 45 seconds.')

        for i in xrange(0, len(self.cty_list)):
            with WaitFeedback.Start(self.feedback):
                # set the master key on one alpha and get the result
                management_port_serial = self.cty_list[i].serial

                time.sleep(20)
                management_port_serial.write(cmd)

                response = management_port_serial.read()
                if("Failed" in response):
                    return response
                response.strip("\r\n")

                if(i == 0):
                    # this is the first one
                    # parse the result to get the master key
                    split_reponse = response.split()

                    # find the start
                    start = 1
                    for token in split_reponse:
                        if('key:' in token):
                            break
                        start += 1

                    # tokens from (start) to (start+7) are the master key
                    masterkey = ""
                    for i in xrange(start, start+8):
                        masterkey += "%s "%split_reponse[i]

                    # send master key to all other alphas
                    cmd = "masterkey set %s\r"%masterkey

        # show the result to the user
        return "\r\n\r\nSuccess:%s key:\r\n%s\r\n"%(split_reponse[start-2], masterkey)

    def setPassword(self, user, newPIN):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        cmd = "\rkeystore set pin %s %s\r"%(user, newPIN)

        for hsm_cty in self.cty_list:
            with WaitFeedback.Start(self.feedback):
                management_port_serial = hsm_cty.serial
                management_port_serial.write(cmd)

                time.sleep(8)
                
                # get response
                management_port_serial.read()

                # make sure we get the real prompt
                management_port_serial.write("\r")
                management_port_serial.read()

        return CTYError.CTY_OK

    def clearKeyStore(self, preservePINs):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        cmd = "keystore erase YesIAmSure"
        if(preservePINs):
            cmd += ' preservePINs'
        cmd += '\r'

        self.feedback('\r\nClearing the keystore. This may take upto 45 seconds.')

        with WaitFeedback.Start(self.feedback):
            for hsm_cty in self.cty_list:
                management_port_serial = hsm_cty.serial
                management_port_serial.write(cmd)
                prompt = management_port_serial.read()

                print prompt

            time.sleep(45)

        return CTYError.CTY_OK

    def uploadFPGABitStream(self, PIN):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/alpha_fmc.bit", UploadArgs(fpga = True, pin = PIN))

    def uploadBootloader(self, PIN):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/bootloader.bin", UploadArgs(bootloader = True, pin = PIN))

    def uploadFirmware(self, PIN):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/hsm.bin", UploadArgs(firmware = True, pin = PIN))

    def uploadTamperFirmware(self, PIN):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/tamper.bin", UploadArgs(tamper = True, pin = PIN))

    def check_ready(self):
        # make sure we're actually connected to an alpha
        if(not self.is_cty_connected()): return CTYError.CTY_NOT_CONNECTED

        # make sure we're logged in
        if(not self.is_logged_in): return CTYError.CTY_NOT_LOGGED_IN

        return CTYError.CTY_OK

    def show_fpga_cores(self):
        cmd = "fpga show cores"

        result = []

        device = 0
        result.append('=============================================')

        for hsm_cty in self.cty_list:
            result.append('CTY%i -----------------------------------'%device)

            cty_output = self.send_command(cmd, hsm_cty.serial)
            for line in cty_output.split('\r\n'):
                result.append(line.strip())

            device = device + 1


        result.append('=============================================')
        
        return result

    def send_command(self, cmd, serial):
        fixed_cmd = "\r%s\r"%cmd

        output = ""

        serial.write(fixed_cmd)
        while (cmd not in output) and (not output.endswith('cryptech> ')):
            output = output + serial.read()

        return output


    def _do_upload(self, name, upload_args):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        for hsm_cty in self.cty_list:
            with WaitFeedback.Start(self.feedback):
                self.feedback("Opening Binary")
                src = open(name, "r") # open the file here because send_file closes it
                self.feedback("Binary Opened")
                size = os.fstat(src.fileno()).st_size

                dst = hsm_cty.serial
                args = dst.args
                args.fpga = upload_args.fpga
                args.firmware = upload_args.firmware
                args.bootloader = upload_args.bootloader
                args.tamper = upload_args.tamper
                args.pin = upload_args.pin
                self.feedback("Uploading Binary")
                send_file(src, size, args, dst)
                self.feedback("Binary Uploaded")

                # clear the PIN
                args.pin = None

                time.sleep(10)

        return CTYError.CTY_OK

    def reboot_stm(self):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        cmd = "\rreboot\r"

        with WaitFeedback.Start(self.feedback):
            for hsm_cty in self.cty_list:
                management_port_serial = hsm_cty.serial
                management_port_serial.write(cmd)
                
                # get response
                management_port_serial.read()

                # make sure we get the real prompt
                management_port_serial.write("\r")
                management_port_serial.read()

        return CTYError.CTY_OK