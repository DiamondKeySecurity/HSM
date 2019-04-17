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
#VERSION 2019-03-11-01

import os
import shutil
import argparse
import subprocess

class HSM(object):
    """Program to start HSM software or update it"""
    def __init__(self, readonly_dir, writable_dir, ethernet, publickey, verbose, no_gpio, testing):
        self.readonly_dir = readonly_dir
        self.writable_dir = writable_dir
        self.ethernet = ethernet
        self.publickey = publickey
        self.no_gpio = no_gpio
        self.testing = testing

        # readonly
        self.software_dir = '%s/sw'%self.readonly_dir
        self.certs_dir = '%s/certs'%self.readonly_dir
        self.defaults_dir = '%s/defaults'%self.readonly_dir
        self.binaries_dir = '%s/binaries'%self.readonly_dir

        # writable
        self.settings_dir = self.writable_dir
        self.uploads_dir = '%s/uploads'%self.writable_dir
        self.restart_file = '%s/restart.txt'%self.uploads_dir
        self.cache_dir = '%s/cache'%self.writable_dir

        self.verbose = verbose

    def get_serialnumber(self):
        snfilename = "/etc/dks-hsm-serial-number.txt"

        try:
            with open(snfilename, "rt") as fp:
                return fp.readline().rstrip("\r\n")
        except:
            return '10000000'


    def start_main_program(self):
        # get the arguments
        args = ['-l %s/dks-report.log.txt'%self.settings_dir,
                '--netiface %s'%self.ethernet,
                '--settings %s/settings.json'%self.settings_dir,
                '--defaults %s'%self.defaults_dir,
                '--uploads %s'%self.uploads_dir,
                '--binaries %s'%self.binaries_dir,
                '--restart %s'%self.restart_file,
                '--certfile %s/domain.crt'%self.certs_dir,
                '--keyfile %s/domain.key'%self.certs_dir,
                '--serial-number %s'%self.get_serialnumber(),
                '--hsmpublickey %s'%self.publickey,
                '--cache-save %s'%self.cache_dir
                ]

        if self.verbose:
            args.append('--verbose')

        if (not self.no_gpio):
            args.append('--gpio-available')

        # the root command
        cmd = 'sudo python diamond_server.py'

        # add arguments to command
        for arg in args:
            cmd = "%s %s"%(cmd, arg)

        if(not self.testing):
            cmd = '%s &'%cmd
        else:
            cmd = '%s --no-web --no-delay --debug'%cmd

        print "Now Running\r\n\r\n%s\r\n\r\n"%cmd

        # start
        os.chdir(self.software_dir)
        os.system(cmd)

    def update_hsm(self, folder):
        print 'updating HSM from %s'%folder

        source_folder = '%s/HSM'%folder

        # before deleting the old files, make sure folder exists
        if(os.path.exists(source_folder) and os.path.isdir(source_folder)):
            # delete old files
            shutil.rmtree(self.readonly_dir)

            # copy the new files
            shutil.move(source_folder,self.readonly_dir)

            # delete restart file
            os.remove(self.restart_file)

            # delete uploaded files
            shutil.rmtree(folder)
        else:
            # just delete the restart file
            os.remove(self.restart_file)

    def check_restart(self):
        try:
            with open(self.restart_file, 'rt') as restartfp:
                command = restartfp.readline()
                path = restartfp.readline()

            command = command.rstrip('\n')
            path = path.rstrip('\n')

            if (command == 'UPDATE'):
                self.update_hsm(path)

                # we need to reboot the HSM to make sure the changes take effect
                os.system('sudo reboot')
                return

        except IOError:
            pass

        # reboot
        self.start_main_program()


parser = argparse.ArgumentParser(formatter_class = argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("--ro",
                    help    = "read-only dir",
                    default = "/mnt/dks-hsm/HSM")

parser.add_argument("--rw",
                    help    = "writable dir",
                    default = "/mnt/dks-hsm")

parser.add_argument("--eth",
                    help    = "ethernet",
                    default = "eth0")

parser.add_argument("--no-update",
                    action = "store_true",
                    help = "Do not update the HSM",
                    )

parser.add_argument("--publickey",
                    default='/etc/dkey-public.pem')

parser.add_argument("--verbose",
                    action = "store_true",
                    help = "Show debug information.",
                    )

parser.add_argument("--no-gpio",
                    action = "store_true",
                    help = "Don't use GPIO features",
                    )

parser.add_argument("--testing",
                    action = "store_true",
                    help = "Launch application for testing",
                    )

args = parser.parse_args()

hsm = HSM(readonly_dir = args.ro,
          writable_dir = args.rw,
          ethernet = args.eth,
          publickey = args.publickey,
          verbose = args.verbose,
          no_gpio = args.no_gpio,
          testing = args.testing)

if(args.no_update):
    hsm.start_main_program()
else:
    hsm.check_restart()