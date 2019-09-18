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
# Script to import CrypTech code into DKS HSM folders.
#
rm -rf hsm_software/sw/hsm_tools/cryptech
mkdir -p hsm_software/sw/hsm_tools/cryptech/cryptech
cp -f ../../CrypTech/sw/libhal/cryptech_muxd hsm_software/sw/hsm_tools/cryptech/muxd.py
cp -f ../../CrypTech/sw/libhal/cryptech_backup hsm_software/sw/hsm_tools/cryptech/backup.py
cp -f ../../CrypTech/sw/libhal/cryptech/* hsm_software/sw/hsm_tools/cryptech/cryptech/
cp -f ../../CrypTech/sw/stm32/projects/hsm/cryptech_upload hsm_software/sw/hsm_tools/cryptech/upload.py
echo '#!/usr/bin/env python\n# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.\n#\n\n__all__ = ["muxd", "backup", "upload"]' > hsm_software/sw/hsm_tools/cryptech/__init__.py
echo '#!/usr/bin/env python\n# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.\n#\n\n__all__ = ["libhal"]' > hsm_software/sw/hsm_tools/cryptech/cryptech/__init__.py
echo 'DO NOT add or modify files or sub-folders in this folder. This folder contains unmodified Cryptech code that is automatically pulled from Cryptech. Any changes will be overwritten.' > hsm_software/sw/hsm_tools/cryptech/X_DO_NOT_MODIFY_FOLDER_X.txt
echo 'Copy Complete'
