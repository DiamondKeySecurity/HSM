#!/usr/bin/env python
# Copyright (c) 2018, 2019  Diamond Key Security, NFP
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

import os
import collections
import logging
import shutil

from enum import IntEnum, Enum
from Queue import Queue

from sync import SyncCommandEnum, SyncCommand

from console.scripts.script import ScriptModule, script_node, ValueType

from abc import abstractmethod, ABCMeta

from hsm_tools.threadsafevar import ThreadSafeVariable

# import Python compatibility layer incase we switch to Python 3 later
import six

class CommandNode(object):
    def __init__(self, name, top_parent, parent, num_args, usage, callback):
        """Node that gives information on a command
        name     - name of the command
        parent   - parent node
        num_args - num arguments for the command if this is a leaf node
        usage    - text for parameters if leaf node
        callback - callback funtion for leaf nodes
        """
        self.name = name
        self.top_parent = top_parent
        self.parent = parent
        self.num_args = num_args
        self.usage = usage
        self.callback = callback
        self.child_nodes = { }

    def add_child(self, name, num_args = None, usage = None, callback = None):
        child_node = CommandNode(name, self.top_parent, self, num_args, usage, callback)
        self.child_nodes[name] = child_node

        # nodes with callbacks can't have children
        assert self.callback is None

        return child_node

    def add_child_tree(self, token_list, num_args = None, usage = None, callback = None):

        current_node = self

        while (len(token_list) > 1):
            current_node = current_node.add_child(token_list[0])
            token_list = token_list[1:]

        return current_node.add_child(token_list[0], num_args, usage, callback)


    def get_usage(self):
        leaves = self.__find_leaf_nodes()

        usage = []

        for leaf in leaves:
            usage.append(leaf.__show_upstream_usage())

        return usage

    def get_usage_str(self):
        usage = self.get_usage()
        result = ""

        for line in usage:
            result = '%s%s\r\n'%(result, line)

        return result

    def process_input(self, input):
        input = input.strip('\r\n')

        if(len(input) > 0):
            tokens = input.split()

            if(len(tokens) > 0) and (tokens[0] in self.child_nodes):
                child_node = self.child_nodes[tokens[0]]

                return child_node.do(tokens[1:])

            return self.get_usage_str()

        return ''


    def do(self, command_tokens):
        num_parameters = len(command_tokens)

        if(self.__isLeaf()):
            if(self.num_args == num_parameters):
                if(self.callback is not None):
                    return self.callback(self.top_parent, command_tokens)
                else:
                    return "'%s' does not have a callback\r\n"%(self.__show_upstream_usage())
        elif (num_parameters > 0 and command_tokens[0] in self.child_nodes):
            child_node = self.child_nodes[command_tokens[0]]

            return child_node.do(command_tokens[1:])

        return self.get_usage_str()


    def __find_leaf_nodes(self):
        """Returns a list of all child leaf nodes"""
        if(self.__isLeaf()):
            return [self]

        results = []

        for _, child_node in self.child_nodes.iteritems():
            leaves = child_node.__find_leaf_nodes()
            results = results + leaves

        return results

    def __show_upstream_usage(self):
        """recursively build usage by recursing up the parent tree"""
        if(self.parent is not None):
            usage = self.parent.__show_upstream_usage()
        else:
            usage = ''
        
        usage = '%s %s'%(usage, self.name)

        if(self.usage is not None):
            usage = '{func: <41}{usage}'.format(func=usage, usage=self.usage)

        return usage

    def __isLeaf(self):
        return len(self.child_nodes) == 0


class ConsoleState(IntEnum):
    LoggedOut = 0
    PasswordRequested = 1
    LoggedIn = 2

class ConsoleInterface(CommandNode):
    __metaclass__ = ABCMeta

    @abstractmethod
    def on_reset(self):
        """Override to add commands that must be executed to reset the system after a new user logs in"""
        pass

    @abstractmethod
    def is_login_available(self):
        """Override and return true if there is a mechanism to login to the system"""
        pass

    @abstractmethod
    def no_login_msg(self):
        """Override and return a message when login is not available"""
        pass

    @abstractmethod
    def get_login_prompt(self):
        """Override to provide the prompt for logging in"""
        pass

    @abstractmethod
    def on_login_pin_entered(self, pin):
        """Override to handle the user logging in. Returns true if the login was successful"""
        pass

    @abstractmethod
    def on_login(self, pin):
        """Override to handle the user logging in. Called after a successful login"""
        pass


    """ Implementation of a stream that will write data to multiple consoles """
    def __init__(self, host_prompt):
        self.response_queue = Queue()
        self.hide_input = False

        # reset and create state variables
        self.reset()

        self.initial_space = "\r\n"
        self.host_prompt = '%s%s> '%(self.initial_space, host_prompt)

        self.banner = 'Diamond Key Security'

        super(ConsoleInterface, self).__init__(name = '.', top_parent = self, parent = None, num_args = None, usage = None, callback = None)

        self.add_child('help', num_args=0, usage=None, callback=self.help)


    def reset(self):
        self.console_state = ThreadSafeVariable(ConsoleState.LoggedOut)
        self.banner_shown = False
        self.attached_cty = None
        self.response_queue = Queue()
        self.input_monitor_buffer = ""
        self.hide_input = False
        self.ignore_user_input = False
        self.script_module = None
        self.multiline_input = False
        self.multiline_callback = None
        self.multiline_buffer = []
        self.request_file_path = None
        self.history = collections.deque(maxlen=100)
        self.history_index = 0

        self.on_reset()

    @property
    def prompt(self):
        if (not self.ignore_user_input):
            if (self.console_state.value == ConsoleState.PasswordRequested):
                return '\r\nPassword: '
            elif ((self.script_module is not None) and 
                (not self.script_module.is_done())):
                return self.script_module.getPrompt()
            else:
                return self.host_prompt
        else:
            return ''

    def help(self, top_class, args=None):
        # send one line at a time
        self.cty_direct_call('Usage:')
        for line in self.get_usage():
            self.cty_direct_call(line)

        return '-------'

    def set_hide_input(self, toggle):
        self.hide_input = toggle

    def flush(self):
        self.readCTYUserData('\r')

    def allow_user_input(self, msg):
        if(msg is not None):
            self.cty_direct_call(msg)

        self.ignore_user_input = False
        self.flush()

    def set_ignore_user(self, msg):
        if(msg is not None):
            self.cty_direct_call(msg)
        self.ignore_user_input = True

    def set_multine_input(self, msg, callback):
        """Use multiline input to collect information from
        the user and then send it to the user"""
        if(msg is not None):
            self.cty_direct_call(msg)

        self.multiline_buffer = []
        self.multiline_callback = callback
        self.multiline_input = True

        self.quick_write('\r\n> ')

    def handle_arrow_key(self, char_val):
        UP_ARROW = 65
        DOWN_ARROW = 66

        if (char_val == UP_ARROW):
            if (self.history_index+1 < len(self.history)):
                self.history_index += 1
                self.erase_input_buffer(self.history[self.history_index])
        elif (char_val == DOWN_ARROW):
            if (self.history_index > 0):
                self.history_index -= 1
                self.erase_input_buffer(self.history[self.history_index])
            else:
                self.history_index = -1
                self.erase_input_buffer(None)

    def erase_input_buffer(self, new_data):
        for _ in self.input_monitor_buffer:
            self.quick_write('\b \b')

        if (new_data is not None):
            self.input_monitor_buffer = new_data
            self.quick_write(self.input_monitor_buffer)
        else:
            self.input_monitor_buffer = ''

    def readCTYUserData(self, data):
        """handle data from user"""
        # first, get the data as a string. the string should be one character
        # add to buffer so we can monitor input
        esc = 0
        arrow = False
        for c in data:
            # check for backspace and delete
            char_val = ord(c)
            if (esc > 0):
                if(arrow):
                    # handle the second escape character for an arrow key
                    self.handle_arrow_key(char_val)
                    arrow = False
                elif(char_val != 91): # 91 is for arrow keys and wants another char
                    esc = 0
                else:
                    arrow = True
    
            elif(char_val == 127 or char_val == 8):
                if(len(self.input_monitor_buffer) > 0):
                    self.input_monitor_buffer = self.input_monitor_buffer[:-1]
                    if(self.hide_input is False): self.quick_write('\b \b')
            elif (char_val == 27):
                esc = 1
            elif (char_val == 17): # ctrl-q
                if(self.multiline_input):
                    self.multiline_input = False

                    # add left-over from input buffer
                    self.multiline_buffer.append(self.input_monitor_buffer)
                    self.input_monitor_buffer = ''

                    if (self.multiline_callback is not None):
                        self.multiline_callback(self.multiline_buffer)

                    self.multiline_buffer = []
            else:
                self.input_monitor_buffer += c
                if(self.hide_input is False): self.quick_write(c)

        # did we receive an entire string of text?
        if(self.input_monitor_buffer.endswith('\r')):
            self.quick_write('\n')

            input_buffer = self.input_monitor_buffer
            self.input_monitor_buffer = ""

            if(self.multiline_input):
                self.multiline_buffer.append(input_buffer.rstrip('\r\n'))
                
                self.quick_write('> ')
            else:
                self.process_user_input(input_buffer)

    def cty_direct_call(self, message):
        if(message is None):
            self.response_queue.put(None)
        else:
            """Allows sub-process to send a message to the user"""
            self.response_queue.put(self.initial_space + message)

    def quick_write(self, m):
        """use this instead of calling attached_cty.write() directly to avoid threading issues"""
        self.response_queue.put(m)

    def handle_cty_output(self):
        """send queued responses to the user"""
        while(self.response_queue.empty() is False):
            message = self.response_queue.get()
            if(message is False): # error
                print ("Error")
                break

            # if there aren't any CTY connections the messages
            # will not be sent anywhere
            if (self.attached_cty is not None):
                try:
                    self.attached_cty.write(message)
                except:
                    pass

    def handle_login(self):
        if(not self.banner_shown):
            self.cty_direct_call(self.banner)
            self.banner_shown = True

        # don't show the password
        self.hide_input = True

        if (self.is_login_available()):
            self.cty_direct_call(self.get_login_prompt())
            self.console_state.value = ConsoleState.PasswordRequested
        else:
            self.cty_direct_call(self.no_login_msg())
            self.hide_input = False
            self.console_state.value = ConsoleState.LoggedIn
            self.cty_direct_call(self.prompt)

    def handle_password_entered(self, data):
        pin = data.rstrip('\r\n')

        if (len(pin) > 0):
            result = self.on_login_pin_entered(pin)

            if(result == False):
                self.cty_direct_call("\r\nIncorrect password. Please try again\r\n\r\nPassword: ")
            else:
                self.hide_input = False
                self.console_state.value = ConsoleState.LoggedIn
                self.on_login(pin)

    def process_user_input(self, data):
        if(self.console_state.value == ConsoleState.LoggedOut):
            self.handle_login()
        else:
            input = data.strip('\r\n')
            if ((self.console_state.value == ConsoleState.LoggedIn) and
                (self.script_module is not None) and
                (not self.script_module.is_done())):
                validated_response = self.script_module.validate_response(input)
                if(validated_response is None):
                    if(len(input) > 0):
                        """Only show invalid response if something was entered"""
                        self.cty_direct_call('Invalid response\r\n\r\n')
                        
                    self.cty_direct_call(self.prompt)
                else:
                    self.script_module = self.script_module.accept_validated_response(validated_response)

                    # show the next prompt
                    self.cty_direct_call(self.prompt)

            elif(len(input) > 0):
                if (self.console_state.value == ConsoleState.PasswordRequested):
                    self.handle_password_entered(input)
                elif (self.console_state.value == ConsoleState.LoggedIn):
                    # add to history
                    self.history.appendleft(input)
                    self.history_index = -1

                    result = self.process_input(input)

                    if (result == None): result = "Invalid command"
                    if (isinstance(result, six.string_types)):
                        self.cty_direct_call(result + self.prompt)
            else:
                self.cty_direct_call(self.prompt)

    def logout(self, message = None):
        self.console_state.value = ConsoleState.LoggedOut
        self.allow_user_input(message)

    def is_logged_in(self):
        return self.console_state.value == ConsoleState.LoggedIn