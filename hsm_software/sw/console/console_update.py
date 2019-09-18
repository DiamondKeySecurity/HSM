#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import os

import time

from hsm_tools.cty_connection import CTYError

from console.scripts.updateRestart import UpdateRestartScriptModule

from console.file_transfer import MGMTCodes, FileTransfer

def dks_do_update(console_object, command, pin, username, on_update_finished = None):
    if (username.lower() != 'wheel' and username.lower() != 'so'):
        console_object.cty_direct_call("Insufficient privileges to carry out this operation.\r\nMust be 'wheel' or 'so'.")
        return True

    result = command(username, pin)
    console_object.cty_direct_call(console_object.cty_conn.get_error_msg(result))

    if (result == CTYError.CTY_OK):
        if(on_update_finished is not None):
            on_update_finished()

            on_update_finished = None

        console_object.cty_direct_call("HSM Restarting in 5 seconds....")
        time.sleep(5)

        console_object.safe_shutdown.restart()
    else:
        print("finished")
        console_object.logout("Finished upload")

    return True

def dks_update_tamperfirmware(console_object, pin, username):
    return dks_do_update(console_object,
                         console_object.cty_conn.uploadTamperFirmware,
                         pin, username,
                         console_object.settings.set_tamper_updated)

def dks_update_firmware(console_object, pin, username):
    return dks_do_update(console_object,
                         console_object.cty_conn.uploadFirmware,
                         pin, username,
                         console_object.settings.set_firmware_updated)

def dks_update_bootloader(console_object, pin, username):
    return dks_do_update(console_object,
                         console_object.cty_conn.uploadBootloader,
                         pin, username)

def dks_update_fpga(console_object, pin, username):
    return dks_do_update(console_object,
                         console_object.cty_conn.uploadFPGABitStream,
                         pin, username)

def dks_hsm_update_finished(console_object, result, msg):
    # we don't need to close the file_transfer object because it will
    # do that itself before calling this callback function
    console_object.file_transfer = None

    if(result is True):
        mod = UpdateRestartScriptModule(console_object.cty_direct_call,
                                        console_object.safe_shutdown)
        console_object.script_module = mod

    console_object.allow_user_input(msg)

def dks_do_HSM_update(console_object, pin, username):
    if (username.lower() != 'wheel' and username.lower() != 'so'):
        console_object.cty_direct_call("Insufficient privileges to carry out this operation.\r\nMust be 'wheel' or 'so'.")
        return True
        
    try:
        # stop excepting normal user data
        console_object.set_ignore_user('The HSM is preparing to receive an update')

        mgmt_code = MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value
        # setup a file transfer object
        ft = FileTransfer(mgmt_code=mgmt_code,
                          tmpfs = console_object.tmpfs,
                          requested_file_path=console_object.request_file_path,
                          restart_file=console_object.args.restart,
                          public_key=console_object.args.hsmpublickey,
                          finished_callback=dks_hsm_update_finished,
                          destination_file='update.tar.gz.signed',
                          data_context=console_object)

        console_object.file_transfer = ft

        ft.start(console_object)

        # the file transfer object will signal what to do
        return True
    except Exception as e:
        console_object.cty_direct_call('\nThere was an error while receiving the'
                                       ' update.\r\n\r\n%s' % e.message)

def dks_update_HSM(console_object, args):
    if('~' in args[0]):
        return ("You cannot use '~' in the path. "
                "You must use the full path.")
    if(not args[0].endswith('.tar.gz.signed')):
        return ("You must use a '.tar.gz.signed' "
                "file from Diamond Key Security, NFP")

    console_object.request_file_path = args[0]
    console_object.redo_login(dks_do_HSM_update)
    return True

def dks_update_cryptech_fpga(console_object, args):
    console_object.cty_direct_call(('\r\n!------------------------------------------'
                            '----------------------------!'
                            '\r\n!FPGA UPDATE WARNING!'
                            '\r\nThis will update the FPGA inside the '
                            'CrypTech device. The FPGA bit steam'
                            '\r\nthat will be used was loaded into the HSM '
                            'on the last HSM update and'
                            '\r\nis probably already on the device.'
                            '\r\n!------------------------------------------'
                            '----------------------------!\r\n'))

    console_object.redo_login(dks_update_fpga)
    return True

def dks_update_cryptech_firmware(console_object, args):
    console_object.cty_direct_call(('\r\n!------------------------------------------'
                            '----------------------------!'
                            '\r\n!FIRMWARE UPDATE WARNING!'
                            '\r\nThis will update the firmware inside the '
                            'CrypTech device. The firmware'
                            '\r\nthat will be used was loaded into the HSM '
                            'on the last HSM update and'
                            '\r\nis probably already on the device. Failures'
                            ' during the firmware update'
                            '\r\ncan cause the CrypTech device to become '
                            'inoperable'
                            '\r\n!------------------------------------------'
                            '----------------------------!\r\n'))

    console_object.redo_login(dks_update_firmware)

    return True

def dks_update_cryptech_tamper(console_object, args):
    console_object.cty_direct_call(('\r\n!-----------------------------------------'
                            '-----------------------------!'
                            '\r\n!TAMPER FIRMWARE UPDATE WARNING!'
                            '\r\nThis will update the firmware inside the '
                            'CrypTech device. The firmware'
                            '\r\nthat will be used was loaded into the HSM '
                            'on the last HSM update and'
                            '\r\nis probably already on the device. Failures'
                            ' during the firmware update'
                            '\r\ncan cause the CrypTech device to become '
                            'inoperable'
                            '\r\n!-----------------------------------------'
                            '-----------------------------!\r\n'))

    console_object.redo_login(dks_update_tamperfirmware)

    return True

def dks_update_cryptech_bootloader(console_object, args):
    console_object.cty_direct_call(('\r\n!-----------------------------------------'
                            '-----------------------------!'
                            '\r\n!BOOTLOADER UPDATE WARNING!'
                            '\r\nThis will update the bootloader inside the'
                            ' CrypTech device. The bootloader'
                            '\r\nthat will be used was loaded into the HSM'
                            ' on the last HSM update and'
                            '\r\nis probably already on the device. Failures'
                            ' during the bootloader update'
                            '\r\ncan cause the CrypTech device to become'
                            ' inoperable'
                            '\r\n!-----------------------------------------'
                            '-----------------------------!\r\n'))

    console_object.redo_login(dks_update_bootloader)
    return True

def add_update_commands(console_object):
    update_node = console_object.add_child('update')

    cryptech_node = update_node.add_child('cryptech')
    cryptech_node.add_child('bootloader', num_args=0,
                            usage=' - Updates the bootloaders on the'
                            ' CrypTech devices.',
                            callback=dks_update_cryptech_bootloader)
    cryptech_node.add_child('firmware', num_args=0,
                            usage=' - Updates the firmware on the'
                            ' CrypTech devices.',
                            callback=dks_update_cryptech_firmware)
    cryptech_node.add_child('fpga', num_args=0,
                            usage=' - Updates the FPGA cores on the'
                            ' CrypTech devices.',
                            callback=dks_update_cryptech_fpga)
    cryptech_node.add_child('tamper', num_args=0,
                            usage=' - Updates the tamper firmware on the'
                            ' CrypTech devices.',
                            callback=dks_update_cryptech_tamper)

    update_node.add_child('HSM', num_args=1,
                          usage='<path to file> - Updates the HSM'
                                ' firmware.',
                          callback=dks_update_HSM)
