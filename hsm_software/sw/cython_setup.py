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
import os
import sys
import argparse
import subprocess
from setuptools import setup, find_packages, Command
from distutils.extension import Extension
from Cython.Build import cythonize

dir_path = os.path.dirname(os.path.realpath(__file__))

def find_hsm_data_sources(path='.'):
    source_files = []
    for root, _, filenames in os.walk(path):
        for fname in filenames:
            if ((fname.endswith('.cpp') or fname.endswith('.c')) and 'c_code' in root):
                source_files.append(os.path.join(root, fname))

    return source_files

def find_pyx(path='.'):
    extensions = []
    for root, _, filenames in os.walk(path):
        for fname in filenames:
            if fname.endswith('.pyx'):
                basename = os.path.splitext(fname)[0]
                extension_name = (os.path.join(root, basename)[2:]).replace('/','.')
                sources = [os.path.join(root, fname)]

                if ('hsm_data' in sources[0]):
                    sources = sources + find_hsm_data_sources(path)

                extension = Extension(name=extension_name,
                                      sources=sources,
                                      include_dirs=['/usr/include/mysql'],
                                      library_dirs=['/usr/local/mysql/lib'],
                                      libraries=['mysqlclient','mysqlcppconn'],
                                      extra_compile_args=['-lstdc++', "-std=c++17", '-lpthread'],
                                      language="c++")
                extensions.append(extension)
    return extensions

argparser = argparse.ArgumentParser(add_help=False)
argparser.add_argument("--use-gcc", action="store_true")
args, unknown = argparser.parse_known_args()
sys.argv = [sys.argv[0]] + unknown

if (args.use_gcc is True):
    os.environ["CC"] = "gcc"

setup(
    name='dvedit',
    version='0.1',
    ext_modules=cythonize(find_pyx(), language_level=2),
    packages=find_packages(),
    )