#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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
