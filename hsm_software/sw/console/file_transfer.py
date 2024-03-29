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
import shutil
import tarfile

from security import HSMSecurity

from enum import Enum

class MGMTCodes(str, Enum):
    """Enum where members are also (and must be) strs"""
    MGMTCODE_RECEIVEHSM_UPDATE   = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x14)])
    MGMTCODE_RECEIVE_RMT_KEKEK   = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x15)])
    MGMTCODE_SEND_LCL_KEKEK      = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x16)])
    MGMTCODE_SEND_EXPORT_DATA    = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x17)])
    MGMTCODE_RECEIVE_IMPORT_DATA = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x18)])


class FileTransfer(object):
    """Utility object for uploading files to the HSM"""

    def __init__(self, mgmt_code, tmpfs,
                 requested_file_path = None,
                 restart_file = None,
                 public_key = None,
                 finished_callback = None,
                 destination_file = None,
                 json_to_send = None,
                 data_context = None):
        self.mgmt_code = mgmt_code
        self.error = ""
        self.file_obj = None
        self.tmpfs = tmpfs

        # what are we doing
        if (mgmt_code == MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value or
            mgmt_code == MGMTCodes.MGMTCODE_RECEIVE_RMT_KEKEK.value or
            mgmt_code == MGMTCodes.MGMTCODE_RECEIVE_IMPORT_DATA.value):
            self.receiving_mode = True
        else:
            self.receiving_mode = False

        # members required for receiving data
        self.requested_file_path = requested_file_path
        self.restart_file = restart_file
        self.public_key = public_key
        self.destination_file = destination_file

        self.file_size = None
        self.bytes_copied = 0
        self.file_buffer = ""

        # create the file in the tmpfs
        if (self.receiving_mode):
            with self.tmpfs.unprotected_fopen(filename = destination_file,
                                              mode = "w", # remote computer wants to write a file
                                              erase_on_exit = mgmt_code != MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value,
                                              open_mode = "w") as _:
                pass

            if (mgmt_code == MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value):
                # for compatibility with older versions of dks_setup_console
                self.start_message="%s:RECV:%s\r" % (mgmt_code, self.requested_file_path)
            else:
                self.start_message="%s:RECV:{%s}\r" % (mgmt_code, self.requested_file_path)
        else:
            # get the contents of the file that we'll send
            with self.tmpfs.fopen(filename = json_to_send,
                                  mode = "r") as fp:
                self.json_to_send = fp.read()
            self.file_size = len(self.json_to_send)
            self.start_message="%s:SEND:{%s}{%i}\r" % (mgmt_code, self.requested_file_path, self.file_size)

        # context
        self.data_context = data_context

        self.finished_callback = finished_callback

    def __del__(self):
        """backup to make sure the file has been closed"""
        self.close()

    def start(self, console):
        # send message to start transfer
        if (self.start_message is not None):
            msg = self.start_message
            self.start_message = None

            console.quick_write(msg)

    def close(self):
        if(self.file_obj is not None):
            self.file_obj.close()
            self.file_obj = None

    def do_recv_file(self, data):
        if(self.file_size is None):
            # read until 'r' to get file size
            size_end = data.find('\r')
            if(size_end > 0):
                size_string = self.file_buffer[:size_end]
                self.file_buffer = self.file_buffer[size_end+1:]

                self.file_size = int(size_string)

                if(self.file_size == 0):
                    self.stop_transfer(lambda : self.finished_callback(self.data_context, False, "ERROR: File not received.\r\n"))
                    return True

                if(self.mgmt_code == MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value or
                    self.mgmt_code == MGMTCodes.MGMTCODE_RECEIVE_RMT_KEKEK.value or
                    self.mgmt_code == MGMTCodes.MGMTCODE_RECEIVE_IMPORT_DATA.value):

                    filename = self.destination_file

                # get the file from the tmpfs to track
                self.file_obj = self.tmpfs.fopen(filename, "wb")

        if(self.file_size is not None and self.file_size > 0):
            data_size = len(self.file_buffer)

            self.file_size -= data_size
            self.bytes_copied += data_size

            self.file_obj.write(self.file_buffer)

            self.file_buffer = None

            if(self.file_size < 1):
                self.FileTransferComplete()

        return True

    def parse_send_response(self, buffer, header):
        """returns the response size if the response was parsed, else False"""
    
        complete_header = "%s:{"%header

        if (complete_header in buffer and
            buffer.endswith("}")):
            index = buffer.find(complete_header)+len(complete_header)
            sub = buffer[index:-1]

            return int(sub)

        return False

    def do_send_json(self):
        if (self.file_buffer is not None):
            # see if there was a failure
            if ("FAILED" in self.file_buffer):
                error = self.file_buffer
                self.file_buffer = None
                self.stop_transfer(lambda : self.finished_callback(self.data_context, False, error))
                return True

            # wait for OK:{<number of bytes to receive>} and then send everything
            if (self.bytes_copied == 0):
                returned_files_size = self.parse_send_response(self.file_buffer, 'OK')

                if (returned_files_size is not False):
                    if(returned_files_size != self.file_size):
                        self.error = "File size mismatch"
                        return False

                    self.file_buffer = None
                    self.bytes_copied = self.file_size

                    # send the file now
                    return self.json_to_send
            # wait for the signal that the data was received
            elif (self.bytes_copied == self.file_size):
                returned_files_size = self.parse_send_response(self.file_buffer, 'RECEIVED')
                if (returned_files_size is not False):
                    if(returned_files_size != self.file_size):
                        self.error = "File size mismatch"
                        return False

                    self.file_buffer = None

                    self.FileTransferComplete()
  
        return True

    def recv(self, data):
        try:
            """Process data comming in as a file transfer"""
            if(self.file_buffer is not None):
                self.file_buffer += data
            else:
                self.file_buffer = data

            if (self.receiving_mode):
                return self.do_recv_file(data)
            else:
                return self.do_send_json()
        except Exception as e:
            self.error = e.message
            print "error %s"%e.message
            return False

    def stop_transfer(self, result_callback):
        if(self.file_obj is not None):
            self.file_obj.close()
            self.file_obj = None
        self.receiving_file = False

        result_callback()

    def FileTransferComplete(self):
        if(self.mgmt_code == MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value):
            self.stop_transfer(self.ExtractHSMUpdate)
        else:
            self.stop_transfer(lambda : self.finished_callback(self.data_context, True, "Transfer complete\r\n"))

    def ExtractHSMUpdate(self):
        filename_signed = os.path.join(self.tmpfs.directory(), self.destination_file)
        filename = os.path.join(self.tmpfs.directory(), "update.tar.gz")
        digest = os.path.join(self.tmpfs.directory(), "digest")
        ext_dir = os.path.join(self.tmpfs.directory(), "files")

        print "Extraction Folder:%s"%ext_dir

        if(HSMSecurity().extract_signed_update(src_path = filename_signed,
                                               extracted_path = filename,
                                               digest_path = digest,
                                               public_key_path = self.public_key,
                                              ) is not True):

            self.finished_callback(self.data_context, False, "Unable to verify update.\r\n")
            return

        try:
            # delete any previously uploaded files
            shutil.rmtree(ext_dir, ignore_errors=True)

            # make sure theres a folder to extract to
            try:
                os.makedirs(ext_dir)
            except OSError:
                pass


            # extract the files
            with tarfile.open(filename) as tarball:
                tarball.extractall(ext_dir)

            # TODO add signature verification

            # remove uploaded file
            os.remove(filename_signed)
            os.remove(filename)
            os.remove(digest)

            # create a restarts file
            with open(self.restart_file, "wt") as restart:
                restart.write("UPDATE\n")
                restart.write(ext_dir)

            msg = "File transfer complete and verified.\r\nReceived %i bytes\r\n"%self.bytes_copied

            self.finished_callback(self.data_context, True, msg)
        except Exception as e:
            self.finished_callback(self.data_context, False, e.message)


