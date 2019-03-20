#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

def CheckValue(value, name, lo_value, hi_value):
      try:
          result = int(value)
      except ValueError:
          return 'Error: %s entered is not a number'%name

      if (result < lo_value):
          return 'Error: %s entered is lower than the minimum value of %i'%(name, lo_value)

      if (result > hi_value):
          return 'Error: %s entered is greater than the maximum value of %i'%(name, hi_value)

      return result

def dks_tamper_threshold_set_light(console_object, args):
      MIN_LIGHT_VALUE = -1
      MAX_LIGHT_VALUE = 100

      light_value = CheckValue(args[0], 
                               'Light threshold',
                               MIN_LIGHT_VALUE,
                               MAX_LIGHT_VALUE)
      if(isinstance(light_value, int) is False):
          return light_value

      return console_object.cty_conn.set_tamper_threshold_light(light_value)

def dks_tamper_threshold_set_temp(console_object, args):
      MIN_TEMPERATURE_VALUE = -1
      MAX_TEMPERATURE_VALUE = 100

      lo_temp_value = CheckValue(args[0], 
                                 'Low temperature threshold',
                                 MIN_TEMPERATURE_VALUE,
                                 MAX_TEMPERATURE_VALUE)
      if(isinstance(lo_temp_value, int) is False):
          return lo_temp_value

      hi_temp_value = CheckValue(args[1], 
                                 'High temperature threshold',
                                 MIN_TEMPERATURE_VALUE,
                                 MAX_TEMPERATURE_VALUE)
      if(isinstance(hi_temp_value, int) is False):
          return hi_temp_value

      return console_object.cty_conn.set_tamper_threshold_temperature(lo_temp_value,
                                                            hi_temp_value)

def dks_tamper_threshold_set_accel(console_object, args):
      MIN_ACCEL_VALUE = -1
      MAX_ACCEL_VALUE = 100

      accel_value = CheckValue(args[0],
                                    'Accelerometer threshold',
                                    MIN_ACCEL_VALUE,
                                    MAX_ACCEL_VALUE)
      if(isinstance(accel_value, int) is False):
          return accel_value

      return console_object.cty_conn.set_tamper_threshold_accel(accel_value)

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

      # add parent nodes
      threshold_node = tamper_node.add_child('threshold')
      threshold_set_node = threshold_node.add_child('set')

      # add thresholds
      threshold_set_node.add_child('temperature', num_args=2, callback=dks_tamper_threshold_set_temp)
      threshold_set_node.add_child('accel', num_args=1, callback=dks_tamper_threshold_set_accel)
      threshold_set_node.add_child('light', num_args=1, callback=dks_tamper_threshold_set_light)
