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

TMPFS_FLAG_READABLE  = 1
TMPFS_FLAG_WRITABLE  = 2
TMPFS_FLAG_REMOVABLE = 4

class TMPFSNotAuthorized(Exception):
    pass

class TMPFSDoesNotExist(Exception):
    pass

class TMPFSFileDesc(object):
    def __init__(self, truepath, flags, erase_on_exit):
        """ Information on a file that's been tracked
        filename      - The filename that will be used to identify the file
        truepath      - The true path and filename on the disk
        flags         - R/W flags for the file
        erase_on_exit - True if this file should always be erased on exit.
        """
        self.truepath = truepath
        self.flags = flags
        self.erase_on_exit = erase_on_exit

    def is_readable(self):
        return (self.flags & TMPFS_FLAG_READABLE) != 0

    def is_writable(self):
        return (self.flags & TMPFS_FLAG_WRITABLE) != 0

    def is_removable(self):
        return (self.flags & TMPFS_FLAG_REMOVABLE) != 0

class TMPFS(object):
    def __init__(self, tmpfolder, handle = None):
        # get the folder for holding our temporary resources
        if (handle is not None):
            self.tmpfolder = os.path.join(tmpfolder, str(handle))
            self.remove_on_exit = True
        else:
            self.tmpfolder = tmpfolder
            self.remove_on_exit = False

        # remove the old folder to delete old contents
        try:
            shutil.rmtree(self.tmpfolder, ignore_errors=True)
        except OSError:
            pass

        # make sure the path exist
        try:
            os.makedirs(self.tmpfolder)
        except OSError:
            pass

        # list of tracked files
        self.files = {}

    def __del__(self):
        self.destroy()

    def reset(self):
        self.destroy()

        # make sure the path exist
        try:
            os.makedirs(self.tmpfolder)
        except OSError:
            pass

    def destroy(self):
        if (self.remove_on_exit):
            try:
                shutil.rmtree(self.tmpfolder, ignore_errors=True)
            except OSError:
                pass
        else:
            for f in self.files.itervalues():
                if (f.erase_on_exit):
                    try:
                        os.remove(f.truepath)
                    except:
                        pass

        self.files = {}

    def directory(self):
        return self.tmpfolder

    def unprotected_fopen(self, filename, mode, erase_on_exit = True, open_mode = None, contents = None):
        """ Used to add new files to the tmpfs
            without checking the file flags.
            Can also open existing files regardless
            of set flags. The mode used determines
            the flags for this file.

            open_mode - use the mode param
                        to set permissions only
                        and open this file with
                        the this mode instead
        """
        # see if the file already exist
        try:
            desc = self.files[filename]
        except:
            flags = 0
            if ('r' in mode or 'R' in mode): flags = flags | TMPFS_FLAG_READABLE
            if ('w' in mode or 'W' in mode): flags = flags | TMPFS_FLAG_WRITABLE
            if ('+' in mode): flags = TMPFS_FLAG_READABLE | TMPFS_FLAG_WRITABLE | TMPFS_FLAG_REMOVABLE

            desc = TMPFSFileDesc(truepath = os.path.join(self.tmpfolder, filename),
                                 flags = flags,
                                 erase_on_exit = erase_on_exit)

            self.files[filename] = desc

        if (contents is not None):
            fp = open(desc.truepath, "wt")
            fp.write(contents)
            return fp

        if (open_mode is not None):
            mode = open_mode

        return open(desc.truepath, mode)

    def unprotected_remove(self, filename):
        """ Uses to remove a file from the tmps
            without checking the file flags
        """
        desc = self.files.pop(filename, None)

        if (desc is not None):
            try:
                os.remove(desc.truepath)
            except:
                raise TMPFSDoesNotExist()


    def fopen(self, filename, mode):
        # see if the file already exist
        try:
            desc = self.files[filename]
        except:
            # the file doesn't exist or we can't make it
            raise TMPFSDoesNotExist()

        # make sure the usage is allowed
        if ((('r' in mode or 'R' in mode or '+' in mode) and not desc.is_readable()) or
            (('w' in mode or 'W' in mode or '+' in mode) and not desc.is_writable()) or
            ('a' in mode or 'A' in mode) or
            (('+' in mode ) and not desc.is_removable())):
            raise TMPFSNotAuthorized()

        return open(desc.truepath, mode)

if __name__ == "__main__":
    import time

    tmpfs = TMPFS("/home/douglas/Documents/tmpfs/test")

    with tmpfs.unprotected_fopen("test.txt", "rt", True, open_mode="wt") as fp:
        fp.write("Hello World\r\nThis is a test\r\n!!!!")

    with tmpfs.fopen("test.txt", "rt") as fp:
        print fp.read()
