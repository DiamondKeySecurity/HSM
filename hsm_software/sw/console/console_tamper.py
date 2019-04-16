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


def dks_tamper_test(console_object, args):
    console_object.tamper.on_tamper(None)

    return "TESTING TAMPER"

def dks_tamper_reset(console_object, args):
    console_object.tamper.reset_tamper_state()

    return "RESETING TAMPER"

def add_tamper_commands(console_object):
    tamper_node = console_object.add_child('tamper')

    tamper_node.add_child(name="test", num_args=0,
                          usage=' - Test tamper functionality by '
                                'simulating an event.',
                          callback=dks_tamper_test)
    tamper_node.add_child(name="reset", num_args=0,
                          usage=' - Attempt to reset the tamper flag. This'
                                ' will fail during an ongoing tamper event.',
                          callback=dks_tamper_reset)
