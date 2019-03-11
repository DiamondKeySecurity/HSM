#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

"""
This code is responsible for upgrading the SD card software on 
"""
import os
import shutil
import argparse
import subprocess

# version of the files included in this package
firewall_version = '2019-02-26-01'
hsm_startup_version = '2019-03-11-01'
system_init_version = '2019-02-26-01'

# set all the paths we might need
firewall_path = '/usr/bin/dkey-pi.firewall.sh'
hsm_startup_path = '/usr/bin/hsm_startup.py'
system_init_path = '/usr/bin/system_init.py'

resource_path = "%s/resources"%os.path.dirname(os.path.realpath(__file__))

firewall_resource_path = '%s/dkey-pi.firewall.sh'%resource_path
hsm_startup_resource_path = '%s/hsm_startup.py'%resource_path
system_init_resource_path = '%s/system_init.py'%resource_path

def get_file_version(path):
    """scans a file to get the version"""
    try:
        with open(path, "rt") as fp:
            for line in fp:
                line = line.rstrip('\r\n')
                if (line.startswith('#VERSION ')):
                    return line[9:]
    except:
        pass

    return None

def update_needed(path, package_version):
    """Determines if a file needs to be updated"""
    current_version = get_file_version(path)
    if(current_version is not None):
        needed = current_version != package_version
    else:
        needed = True

    print "Update to '%s' needed == %s"%(path, str(needed))

    return needed

def copyfile(src, dst, needed):
    if(needed):
        shutil.copyfile(src, dst)
        print '%s copied to %s'%(src, dst)
    else:
        print '%s not copied to %s'%(src, dst)

print "Performing after update initialization."

# do we need to update anything
firewall_update_needed = update_needed(firewall_path, firewall_version)
startup_update_needed = update_needed(hsm_startup_path, hsm_startup_version)
system_update_needed = update_needed(system_init_path, system_init_version)

if(firewall_update_needed or startup_update_needed or system_update_needed):
    # make the system read/write
    os.system("mount -o remount,rw /")

    # copy the files
    copyfile(firewall_resource_path, firewall_path, firewall_update_needed)
    copyfile(hsm_startup_resource_path, hsm_startup_path, startup_update_needed)
    copyfile(system_init_resource_path, system_init_path, system_update_needed)

    # make the system read-only
    os.system("mount -o remount,ro /")