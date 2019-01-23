#!/bin/sh
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
# Script to import CrypTech code into DKS HSM folders.
#
rm -rf hsm_software/sw/hsm_tools/cryptech
mkdir -p hsm_software/sw/hsm_tools/cryptech/cryptech
cp -f ../../CrypTech/sw/libhal/cryptech_muxd hsm_software/sw/hsm_tools/cryptech/muxd.py
cp -f ../../CrypTech/sw/libhal/cryptech_backup hsm_software/sw/hsm_tools/cryptech/backup.py
cp -f ../../CrypTech/sw/libhal/cryptech/* hsm_software/sw/hsm_tools/cryptech/cryptech/
cp -f ../../CrypTech/sw/stm32/projects/hsm/cryptech_upload hsm_software/sw/hsm_tools/cryptech/upload.py
echo '' > hsm_software/sw/hsm_tools/cryptech/__init__.py
echo 'DO NOT add or modify files or sub-folders in this folder. This folder contains unmodified Cryptech code that is automatically pulled from Cryptech. Any changes will be overwritten.' > hsm_software/sw/hsm_tools/cryptech/X_DO_NOT_MODIFY_FOLDER_X.txt
echo 'Copy Complete'
