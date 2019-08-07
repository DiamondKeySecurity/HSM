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
import sys
import argparse
from setuptools import setup, find_packages, Command
from distutils.extension import Extension
from Cython.Build import cythonize

def find_pyx(path='.'):
    extensions = []
    for root, dirs, filenames in os.walk(path):
        for fname in filenames:
            if fname.endswith('.pyx'):
                basename = os.path.splitext(fname)[0]
                extension_name = (os.path.join(root, basename)[2:]).replace('/','.')
                print extension_name
                extension = Extension(name=extension_name,
                                      sources=[os.path.join(root, fname)],
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