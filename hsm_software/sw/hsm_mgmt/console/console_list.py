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

def dks_list_keys(console_object, args):
    cache = console_object.cache
    rpc_count = cache.rpc_count

    console_object.cty_direct_call("CrypTech Device Cached UUIDs---")

    for rpc_index in range(0, rpc_count):
        alphaTable = cache.alphaTables[rpc_index]
        console_object.cty_direct_call("%sDevice:%i------------%s" %
                                (console_object.initial_space,
                                rpc_index,
                                console_object.initial_space))
        for key in alphaTable.get_keys():
            console_object.cty_direct_call(str(key))

    return console_object.initial_space

def add_list_commands(console_object):
    set_node = console_object.add_child('list')

    set_node.add_child(name="keys", num_args=0,
                        usage=" - list the keys in the CrypTech devices.",
                        callback=dks_list_keys)