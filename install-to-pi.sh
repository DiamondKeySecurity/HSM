#!/bin/sh
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
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
