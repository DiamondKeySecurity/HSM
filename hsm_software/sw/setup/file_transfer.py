#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import os
import shutil
import tarfile

from security import HSMSecurity

from enum import Enum

class MGMTCodes(str, Enum):
    """Enum where members are also (and must be) strs"""
    MGMTCODE_RECEIVEHSM_UPDATE = "".join([chr(0x11), chr(0x12), chr(0x13), chr(0x14)])

class FileTransfer(object):
    """Utility object for uploading files to the HSM"""

    def __init__(self, requested_file_path, mgmt_code, uploads_dir, restart_file, public_key, finished_callback):
        self.requested_file_path = requested_file_path
        self.mgmt_code = mgmt_code
        self.uploads_dir = uploads_dir
        self.restart_file = restart_file
        self.public_key = public_key

        self.file_size = None
        self.bytes_copied = 0
        self.file_buffer = ""

        self.file_obj = None

        self.finished_callback = finished_callback

    def __del__(self):
        """backup to make sure the file has been closed"""
        self.close()

    def close(self):
        if(self.file_obj is not None):
            self.file_obj.close()
            self.file_obj = None

    def recv(self, data):
        try:
            """Process data comming in as a file transfer"""
            if(self.file_buffer is not None):
                self.file_buffer += data
            else:
                self.file_buffer = data

            if(self.file_size is None):
                # read until 'r' to get file size
                size_end = data.find('\r')
                if(size_end > 0):
                    size_string = self.file_buffer[:size_end]
                    self.file_buffer = self.file_buffer[size_end+1:]

                    self.file_size = int(size_string)

                    if(self.file_size == 0):
                        self.stop_transfer(lambda : self.finished_callback(False, "ERROR: File not received.\r\n"))
                        return True

                    if(self.mgmt_code == MGMTCodes.MGMTCODE_RECEIVEHSM_UPDATE.value):
                        # make sure the path exist
                        try:
                            os.makedirs(self.uploads_dir)
                        except OSError:
                            pass

                        filename = self.uploads_dir + "/update.tar.gz.signed"

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
        except Exception as e:
            return e.message

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
            self.stop_transfer(lambda : self.finished_callback(False, "ERROR: Unexpected file transfer\r\n"))

    def ExtractHSMUpdate(self):
        filename_signed = self.uploads_dir + "/update.tar.gz.signed"
        filename = self.uploads_dir + "/update.tar.gz"
        digest = self.uploads_dir + "/digest"
        ext_dir = self.uploads_dir + "/files"

        print "Extraction Folder:%s"%ext_dir

        if(HSMSecurity().extract_signed_update(src_path = filename_signed,
                                               extracted_path = filename,
                                               digest_path = digest,
                                               public_key_path = self.public_key,
                                              ) is not True):

            self.finished_callback(False, "Unable to verify update.\r\n")
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

            self.finished_callback(True, msg)
        except Exception as e:
            self.finished_callback(False, e.message)

