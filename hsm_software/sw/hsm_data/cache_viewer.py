e#!/usr/bin/env python
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


from cache import HSMCache

class cacher_viewer(object):
    """ "Pure" Python interface to the cache_ibject"""
    def __init__(self, cache_object):
        self.cache_object = cache_object

    def is_initialized(self):
        return self.cache_object.is_initialized()

    def clear(self):
        self.cache_object.clear()

    def get_device_count(self):
        return self.cache_object.get_device_count()

    def get_key_count(self, device_index):
        return self.cache_object.get_key_count(device_index)

    def backup_matching_map(self):
        self.cache_object.backup_matching_map()

    def backup_tables(self):
        self.cache_object.backup_tables()

    def backup(self):
        self.cache_object.backup()

    def getVerboseMapping(self):
        return self.cache_object.getVerboseMapping()
