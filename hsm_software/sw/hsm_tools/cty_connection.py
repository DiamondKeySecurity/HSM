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

    @property
    def cty_count(self):
        return len(self.cty_list)

    def is_cty_connected(self):
        return self.cty_count > 0

    def feedback(self, message):
        if (self.feedback_function is not None):
            self.feedback_function(message)

    def login(self, username, pin):
        # make sure we're actually connected to an alpha
        if(not self.is_cty_connected()): return CTYError.CTY_NOT_CONNECTED

        self.logout()

        with WaitFeedback.Start(self.feedback):
            for hsm_cty in self.cty_list:
                management_port_serial = hsm_cty.serial
                management_port_serial.args.username = username
                management_port_serial.args.pin = pin

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

    def uploadFPGABitStream(self, username, PIN, cty_index = None):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/alpha_fmc.bit",
                               UploadArgs(fpga = True, pin = PIN, username=username),
                               cty_index)

    def uploadBootloader(self, username, PIN, cty_index = None):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/bootloader.bin",
                               UploadArgs(bootloader = True, pin = PIN, username=username),
                               cty_index)

    def uploadFirmware(self, username, PIN, cty_index = None):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/hsm.bin",
                               UploadArgs(firmware = True, pin = PIN, username=username),
                               cty_index)

    def uploadTamperFirmware(self, username, PIN, cty_index = None):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        return self._do_upload(self.binary_path + "/tamper.bin",
                               UploadArgs(tamper = True, pin = PIN, username=username),
                               cty_index)

    def check_ready(self):
        # make sure we're actually connected to an alpha
        if(not self.is_cty_connected()): return CTYError.CTY_NOT_CONNECTED

        # make sure we're logged in
        if(not self.is_logged_in): return CTYError.CTY_NOT_LOGGED_IN

        return CTYError.CTY_OK

    def check_fpga(self, cty_index):
        if (cty_index < 0 or cty_index >= self.cty_count):
            # device not found
            return None

        cmd = "fpga show cores"

        hsm_cty = self.cty_list[cty_index]

        cty_output = self.send_command(cmd, hsm_cty.serial)
        print cty_output

        # check for the ALPHA core
        if ('0000: ALPHA' in cty_output):
            return True
        else:
            return False

    def check_fix_fpga(self, cty_index, username, pin):
        attempt = 0
        status = False

        while (attempt < 4 and (status == False)):
            if (attempt < 2 or attempt == 3):
                # update FGPA
                self.feedback("\r\nAttempt %i: Attempting to update FPGA cores in flash.\r\n"%attempt)
                self.uploadFPGABitStream(username, pin, cty_index)
            else:
                # update firmware
                self.feedback("\r\nAttempt %i: Attempting to update firmware.\r\n"%attempt)
                self.uploadFirmware(username, pin, cty_index)

            self.feedback("\r\nWaiting for CrypTech devices to start.  ")
            with WaitFeedback.Start(self.feedback):
                time.sleep(45)

            attempt += 1
            status = self.check_fpga(cty_index)

        if (status == True):
            self.feedback("\r\nOK")
        else:
            self.feedback("\r\nFAILED")

        return status

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


    def _do_upload(self, name, upload_args, cty_index):
        # make sure we have an alpha that's ready to receive commands
        ready_state = self.check_ready()
        if(ready_state is not CTYError.CTY_OK): return ready_state

        for index in range(self.cty_count):
            if (cty_index is None or index == cty_index):
                hsm_cty = self.cty_list[index]

                with WaitFeedback.Start(self.feedback):
                    self.feedback("Opening Binary  \r\n")
                    src = open(name, "r") # open the file here because send_file closes it
                    self.feedback("Binary Opened  \r\n")
                    size = os.fstat(src.fileno()).st_size

                    dst = hsm_cty.serial
                    args = dst.args
                    args.fpga = upload_args.fpga
                    args.firmware = upload_args.firmware
                    args.bootloader = upload_args.bootloader
                    args.tamper = upload_args.tamper
                    args.pin = upload_args.pin
                    self.feedback("Uploading Binary  \r\n")
                    if(send_file(src, size, args, dst) == False):
                        self.feedback("Error: Unable to send binary.  \r\n")
                        return CTYError.CTY_ERROR

                    self.feedback("Binary Uploaded  \r\n")

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