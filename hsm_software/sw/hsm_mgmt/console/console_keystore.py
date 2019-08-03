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

import time

from scripts.masterkey import MasterKeySetScriptModule

from cryptech.cty_connection import CTYError
from cryptech.cryptech_port import DKS_HALError

def dks_do_erase(console_object, pin, username):
    if(console_object.cty_conn.clearKeyStore(preservePINs=True) == CTYError.CTY_OK):
        # clear the cache
        console_object.cache.clear()

        console_object.cty_direct_call('keystore cleared.')
    else:
        console_object.cty_direct_call('There was an error erasing the keystore.')


def dks_keystore_erase(console_object, args):
    console_object.cty_direct_call(('\r\n!------------------------------------------'
                            '----------------------------!'
                            '\r\n!KEYSTORE ERASURE WARNING!'
                            '\r\nThis will delete the entire keystore on all CrypTech devices.'
                            '\r\nThis is irreversible. '
                            '\r\n!------------------------------------------'
                            '----------------------------!\r\n'))

    console_object.redo_login(dks_do_erase)

    return True

def dks_do_restore(console_object, pin, username):
    if(console_object.cty_conn.clearKeyStore(preservePINs=False) == CTYError.CTY_OK):
        # clear the cache
        console_object.cache.clear()

        console_object.cty_direct_call('keystore cleared.')

        # restore settings
        console_object.settings.clear_settings()

        console_object.cty_direct_call('Restore complete')

        console_object.cty_direct_call("HSM Shutting Down in 5 seconds....")
        time.sleep(5)

        console_object.safe_shutdown.shutdown()
    else:
        console_object.cty_direct_call('There was an error erasing the keystore.')

def dks_restore(console_object, args):
    console_object.cty_direct_call(('\r\n!------------------------------------------'
                            '----------------------------!'
                            '\r\n!RESTORE TO FACTORY SETTINGS WARNING!'
                            '\r\n!KEYSTORE ERASURE WARNING!'
                            '\r\nThis will delete the entire keystore on all CrypTech devices.'
                            '\r\nThis is irreversible. '
                            '\r\n!------------------------------------------'
                            '----------------------------!\r\n'))

    console_object.redo_login(dks_do_restore)

    return True

def dks_do_masterkey_set(console_object, pin, username):
    # use script to set the master key
    console_object.script_module = MasterKeySetScriptModule(console_object.cty_conn,
                                                            console_object.cty_direct_call,
                                                            console_object.settings)

    console_object.cty_direct_call(console_object.prompt)


def dks_masterkey_set(console_object, args):
    console_object.cty_direct_call(('\r\n!------------------------------------------'
                            '----------------------------!'
                            '\r\n!MASTER KEY WARNING!'
                            '\r\nThis will set the master key for the HSM.'
                            '\r\nPrevious values will not be saved.'
                            '\r\n!------------------------------------------'
                            '----------------------------!\r\n'))

    console_object.redo_login(dks_do_masterkey_set)

    return True

def dks_masterkey_status(console_object, args):
    status_all = console_object.cty_conn.getMasterKeyStatus()

    for cty_index in xrange(len(status_all)):
        console_object.cty_direct_call('CTY %i:'%cty_index)
        if ('volatile' in status_all[cty_index]):
            console_object.cty_direct_call('   volatile: %s'%DKS_HALError.to_mkm_string(status_all[cty_index]['volatile']))
        if ('flash' in status_all[cty_index]):
            console_object.cty_direct_call('      flash: %s'%DKS_HALError.to_mkm_string(status_all[cty_index]['flash']))

    return ""

def add_keystore_commands(console_object):
    console_object.add_child_tree(['keystore', 'erase', 'YesIAmSure'],
                                   num_args=0,
                                   usage=' - Erases the entire keystore',
                                   callback=dks_keystore_erase)

    console_object.add_child_tree(['restore', 'ERASE-ALL', 'YesIAmSure'],
                                  num_args=0,
                                  usage=' - Restores the HSM to factory settings'
                                        ' without downgrading the HSM firmware.',
                                  callback=dks_restore)

    masterkey = console_object.add_child('masterkey')

    masterkey.add_child('set',
                        num_args=0,
                        usage=" - sets the master key.",
                        callback=dks_masterkey_set)

    masterkey.add_child('status',
                        num_args=0,
                        usage=" - gets the status of the master key.",
                        callback=dks_masterkey_status)
