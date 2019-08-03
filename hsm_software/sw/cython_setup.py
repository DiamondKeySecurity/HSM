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
import os
from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

os.environ["CC"] = "gcc"

extensions = [
    Extension("cache", ["cache_object.pyx", "cache_viewer.pyx","c_code/_hsm_cache.cpp"],
        extra_compile_args= ['-lstdc++', "-std=c++17", '-lpthread'])
]

setup(
    name="My hello app",
    ext_modules=cythonize(extensions),
)