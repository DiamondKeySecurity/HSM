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


from scripts.masterkey import MasterKeySetScriptModule

def dks_masterkey_set(console_object, args):
    # use script to set the master key
    console_object.script_module = MasterKeySetScriptModule(console_object.cty_conn,
                                                            console_object.cty_direct_call,
                                                            console_object.settings)

    return ''

def add_masterkey_commands(console_object):
    masterkey_node = console_object.add_child('masterkey')

    masterkey_node.add_child(name="set", num_args=0,
                             usage=" - sets the master key.",
                             callback=dks_masterkey_set)