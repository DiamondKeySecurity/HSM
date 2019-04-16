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

from hsm_tools.cty_connection import CTYError

def dks_keystore_erase(console_object, args):
    if(console_object.cty_conn.clearKeyStore(preservePINs=False) == CTYError.CTY_OK):
        # clear the cache
        console_object.cache.clear()

        return 'keystore cleared. preservePINs == False'

def dks_keystore_erase_preservePINs(console_object, args):
    if(console_object.cty_conn.clearKeyStore(preservePINs=True) == CTYError.CTY_OK):
        # clear the cache
        console_object.cache.clear()

        return 'keystore cleared. preservePINs == True'

def add_keystore_commands(console_object):
    keystore_node = console_object.add_child('keystore')
    keystore_erase_node = keystore_node.add_child('erase')
    keystore_erase_node.add_child('YesIAmSure', num_args=0,
                                    usage=' - Erases the entire keystore'
                                        ' including PINs.',
                                    callback=dks_keystore_erase)

    # use erase_callback to meet PEP8 style
    erase_callback = dks_keystore_erase_preservePINs
    keystore_erase_node.add_child_tree(['preservePINs', 'YesIAmSure'],
                                        num_args=0,
                                        usage=' - Erases the keystore.'
                                                ' Preserves PINs.',
                                        callback=erase_callback)