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
import shutil
import argparse
import subprocess

class HSM(object):
    """Program to start HSM software or update it"""
    def __init__(self, readonly_dir, writable_dir):
        self.software_dir = '%s/sw'%readonly_dir
        self.settings_dir = writable_dir
        self.uploads_files_dir = '%s/uploads/files'%writable_dir
        self.network_setup = "%s/ipconfig.py"%self.software_dir
        self.watchdog_led_path = '/usr/bin/watchdog.py'

    def run_network_script(self):
        args = ['--netiface eth0',
                '--tmp %s'%self.settings_dir,
                '--settings %s/settings.json'%self.settings_dir
                ]

        # the root command
        cmd = '/usr/bin/python %s'%self.network_setup


        # add arguments to command
        for arg in args:
            cmd = "%s %s"%(cmd, arg)

        print "Now Running\r\n\r\n%s\r\n\r\n"%cmd

        # start
        os.system('%s '%cmd)

    def startdhcp(self):
        subprocess.call(['/sbin/ifup','eth0'])

    def run_script(self, script_path):
        print "Now running: %s"%script_path
        subprocess.call(['/usr/bin/python', script_path])

    def run_script_background(self, script_path):
        print "Now running: %s"%script_path
        os.system('/usr/bin/python %s &'%script_path)

    def start_main_program(self):
        # start the watchdog
        if(os.path.exists(self.watchdog_led_path)):
            self.run_script_background(self.watchdog_led_path)

        # program to run only once
        run_once = "%s/initialize.py"%self.uploads_files_dir
        if(os.path.exists(run_once)):
            self.run_script(run_once)
            os.remove(run_once)

        # program to run to setup network connection
        if(os.path.exists(self.network_setup)):
            self.run_network_script()
        else:
            self.startdhcp()


parser = argparse.ArgumentParser(formatter_class = argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("--ro",
                    help    = "read-only dir",
                    default = "/mnt/dks-hsm/HSM")

parser.add_argument("--rw",
                    help    = "writable dir",
                    default = "/mnt/dks-hsm")


args = parser.parse_args()

HSM(readonly_dir = args.ro, writable_dir = args.rw).start_main_program()
