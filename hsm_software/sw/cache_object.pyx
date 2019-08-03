# distutils: language = c++
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

from hsm_cache cimport HSMCache

cdef class cache_object:
    cdef HSMCache *lp_cache_object

    """ Root cache object that uses dictionaries to store key information"""
    def ___cinit___(self, int rpc_count, char *cache_folder):
        self.lp_cache_object = new HSMCache(rpc_count, cache_folder)

    def __dealloc___(self):
        print "deleting"
        del self.lp_cache_object