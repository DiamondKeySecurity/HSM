#!/bin/sh
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
#
# Prompt user for path and then copies the HSM files to that path
echo "The HSM software will now be copied to a SD card."
while true; do
    read -p "Enter the path of the SD Card: " SDPATH
    export HSM_SOFTWARE_PATH="$SDPATH/HSM"
    read -p "Copying data to $HSM_SOFTWARE_PATH . Is this ok? (yn) " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) ;;
        * ) echo "Please answer yes or no.";;
    esac
done
export HSM_SOFTWARE_BUILD="hsm_software"
rm -rf $HSM_SOFTWARE_PATH/* 
mkdir -p $HSM_SOFTWARE_PATH 
mkdir -p $HSM_SOFTWARE_PATH/certs 
cp -R $HSM_SOFTWARE_BUILD/sw $HSM_SOFTWARE_PATH
cp -R $HSM_SOFTWARE_BUILD/binaries $HSM_SOFTWARE_PATH
cp -R $HSM_SOFTWARE_BUILD/defaults $HSM_SOFTWARE_PATH
