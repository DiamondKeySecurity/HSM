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

def dks_shutdown(console_object, args):
    console_object.cty_direct_call('Shutting Down HSM')
    console_object.safe_shutdown.shutdown()
    console_object.cty_direct_call(None)

def dks_shutdown_restart(console_object, args):
    console_object.cty_direct_call('Restarting HSM')
    console_object.safe_shutdown.restart()
    console_object.cty_direct_call(None)

def add_shutdown_commands(console_object):
    shutdown_node = console_object.add_child('shutdown')
    shutdown_node.add_child_tree(['restart', 'YesIAmSure'], num_args=0,
                                    usage=' - Restarts the HSM.',
                                    callback=dks_shutdown_restart)
    shutdown_node.add_child('YesIAmSure', num_args=0,
                            usage=' - Shuts down the HSM.',
                            callback=dks_shutdown)
