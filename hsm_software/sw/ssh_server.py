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
import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback

import paramiko
from paramiko.py3compat import b, u, decodebytes

# import classes from the original cryptech.muxd
# cryptech_muxd has been renamed to cryptech/muxd.py
import hsm_tools.cryptech.muxd

class ParamikoSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == "wheel") and (password == "1234"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
        # if (username == "robey") and (key == self.good_pub_key):
        #     return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        # if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
        #     return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        # if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
        #     return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return False

    def get_allowed_auths(self, username):
        #return "gssapi-keyex,gssapi-with-mic,password,publickey"
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

class SocketChannel(object):
    def __init__(self, chan):
        self.channel = chan

    def write(self, data):
        if (self.channel is not None):
            self.channel.send(data)

class SSHServer(object):
    """
    Serve Cryptech console over a TCP socket.
    """

    host_key = paramiko.rsakey.RSAKey.generate(2048)

    def __init__(self, cty_mux):
        self.cty_mux = cty_mux
        self.listening_event = None
        self.listening_thread = None

    def start(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 2200))
        except Exception as e:
            print("*** Bind failed: " + str(e))
            traceback.print_exc()
            return False

        try:
            sock.listen(100)
        except Exception as e:
            print("*** Listen/accept failed: " + str(e))
            traceback.print_exc
            return False

        self.listening_event = threading.Event()
        self.listening_thread = threading.Thread(name='cty_reponse',
                                                 target=self.listening_thread_body,
                                                 args=(sock,))

        self.listening_thread.start()

    def stop(self):
        if (self.listening_event is not None):
            self.listening_event.set()

        self.listening_event = None
        self.listening_thread = None

    def response_thread_body(self, e):
        """Simple thread that gets new responses from CTY"""
        while not e.isSet():
            self.cty_mux.handle_cty_output()
            time.sleep(0.01)

    def listening_thread_body(self, sock):
        while not self.listening_event.isSet():
            try:
                print("Listening for connection ...")
                client, addr = sock.accept()
            except Exception as e:
                print("*** Listen/accept failed: " + str(e))
                traceback.print_exc()

            self.handle_stream(client, addr)

    def handle_stream(self, client, address):
        "Handle one network connection."
        try:
            t = paramiko.Transport(client)
            t.set_gss_host(socket.getfqdn(""))
            try:
                t.load_server_moduli()
            except:
                print("(Failed to load moduli -- gex will be unsupported.)")
                raise
            t.add_server_key(SSHServer.host_key)
            server = ParamikoSSHServer()
            try:
                t.start_server(server=server)
            except paramiko.SSHException:
                print("*** SSH negotiation failed.")
                raise paramiko.SSHException

            # wait for auth
            chan = t.accept(20)
            chan.settimeout(1)
            if chan is None:
                print("*** No channel.")
                raise paramiko.ChannelException

            print("Authenticated!")

            server.event.wait(10)
            if not server.event.is_set():
                print("*** Client never asked for a shell.")
                raise paramiko.ChannelException

            if self.cty_mux.attached_cty is not None:
                chan.send("[Console already in use, sorry]\n")
                raise paramiko.ChannelException

            hsm_tools.cryptech.muxd.logger.info("CTY connected to %r", client)

            stream = SocketChannel(chan)

            try:
                self.cty_mux.attached_cty = stream

                e = threading.Event()
                t1 = threading.Thread(name='cty_reponse',
                                    target=self.response_thread_body,
                                    args=(e,))
                t1.start()

                while self.cty_mux.attached_cty is stream:
                    try:
                        buffer = chan.recv(1024)
                    except socket.timeout:
                        continue

                    if (len(buffer) == 0):
                        break

                    self.cty_mux.write(buffer)

            except:
                pass

            finally:
                hsm_tools.cryptech.muxd.logger.info("CTY disconnected from %r", stream)
                e.set()
                if self.cty_mux.attached_cty is stream:
                    self.cty_mux.attached_cty = None
                    self.cty_mux.reset()

        except:
            try:
                t.close()
            except:
                pass
            return
