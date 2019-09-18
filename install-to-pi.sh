#!/bin/sh
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
