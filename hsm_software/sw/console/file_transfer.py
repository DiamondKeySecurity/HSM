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
import shutil
import tarfile

from security import HSMSecurity

from enum import Enum

class MGMTCodes(str, Enum):
    """Enum where members are also (and must be) strs"""
    MGMTCODE_RECEIVEHSM_UPDATE = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x14)])
    MGMTCODE_RECIEVE_RMT_KEKEK = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x15)])
    MGMTCODE_SEND_LCL_KEKEK    = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x16)])
    MGMTCODE_SEND_EXPORT_DATA  = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x17)])


class FileTransfer(object):
    """Utility object for uploading files to the HSM"""

    def __init__(self, mgmt_code,
                 requested_file_path = None,
                 uploads_dir = None,
                 restart_file = None,
                 public_key = None,
                 finished_callback = None,
                 destination_file = None,
                 json_to_send = None,
                 data_context = None):
        self.mgmt_code = mgmt_code
        self.error = ""

        # what are we doing
        if (mgmt_code == MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE or
            mgmt_code == MGMTCodes.MGMTCODE_RECIEVE_RMT_KEKEK):
            self.receiving_mode = True
        else:
            self.receiving_mode = False

        # members required for receiving data
        self.requested_file_path = requested_file_path
        self.uploads_dir = uploads_dir
        self.restart_file = restart_file
        self.public_key = public_key
        self.destination_file = '%s/%s'%(self.uploads_dir, destination_file)

        self.file_size = None
        self.bytes_copied = 0
        self.file_buffer = ""

        self.file_obj = None

        # members required for sending data
        self.json_to_send = json_to_send

        if (self.receiving_mode is False):
            self.file_size = len(json_to_send)

        # context
        self.data_context = data_context

        self.finished_callback = finished_callback

    def __del__(self):
        """backup to make sure the file has been closed"""
        self.close()

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
                    self.mgmt_code == MGMTCodes.MGMTCODE_RECIEVE_RMT_KEKEK.value):
                    # make sure the path exist
                    try:
                        os.makedirs(self.uploads_dir)
                    except OSError:
                        pass

                    filename = self.destination_file

                self.file_obj = open(filename, "wb")

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
        if (buffer is not None):
            complete_header = "%s:{"%header

            if (complete_header in buffer and
                buffer.endswith("}")):
                index = buffer.find(complete_header)
                sub = buffer[index:-1]

                return int(sub)

        return False

    def do_send_json(self):
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
        filename_signed = self.destination_file
        filename = self.uploads_dir + "/update.tar.gz"
        digest = self.uploads_dir + "/digest"
        ext_dir = self.uploads_dir + "/files"

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


