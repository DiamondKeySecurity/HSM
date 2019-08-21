#!/usr/bin/env python
# Copyright (c) 2018, 2019  Diamond Key Security, NFP
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
from libcpp.string cimport string

cdef extern from "c_code/_uuid.hpp" namespace "uuids":
    cdef cppclass uuid_t:
        uuid_t()
        uuid_t(const uuid_t &other)
        uuid_t(const unsigned char binary[16])
        uuid_t(const char *str_)
        void fromBytes(char *bytes)
        void gen_random()
        char *to_string(char *buffer) const
        string operator () const
        uuid_t &operator =(const uuid_t &b)
        bint operator ==(const uuid_t &b) const
        bint operator !=(const uuid_t &b) const