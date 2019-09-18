# Copyright (c) 2019  Diamond Key Security, NFP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import time
import struct
import atexit
import weakref
import logging
import logging.handlers
import threading
import socket
import json
import serial
import base64

import tornado.tcpserver
import tornado.iostream
import tornado.netutil
import tornado.ioloop
import tornado.queues
import tornado.locks
import tornado.gen

import xdrlib
from uuid import UUID

from Queue import Queue

import enum
from enum import IntEnum

from cython.operator cimport dereference as deref, postincrement

# import classes from the original cryptech.muxd
# cryptech_muxd has been renamed to cryptech/muxd.py
import cryptech.muxd
from cryptech.muxd import logger
from cryptech.libhal import *
from cryptech.cryptech_port import DKS_RPCFunc, DKS_HALKeyType, DKS_HALKeyFlag, DKS_HALError, DKS_HALUser, DKS_HALError, DKS_HSM
from cryptech.tcpserver import TCPServer
from cryptech.backup import b64, b64join, SoftKEKEK

from settings import HSMSettings

from hsm_tools.threadsafevar import ThreadSafeVariable
from hsm_tools.pkcs11_attr import CKA
from hsm_tools.observerable import observable
from hsm_tools.stoppable_thread import stoppable_thread

from cryptech.cryptech_port import DKS_HALUser, DKS_RPCFunc, DKS_HALError, DKS_HALKeyType

cimport c_uuids
cimport hsm_cache
cimport table_rows
cimport conv
cimport inc_atomic_int
cimport safe_queue
cimport libhal
cimport rpc_handler
cimport keydb

include "pfunix_hsm.pxi"

include "rpc_tcp_server.pxi"

include "rpc_interface_keydb.pxi"
include "rpc_interface_cache.pxi"

include "rpc_builder.pxi"
include "rpc_interface_handling.pxi"

include "rpc_interface_sync.pxi"
include "sync.pxi"

include "rpc_interface_tamper.pxi"
include "tamper.pxi"

include "rpc_path_object.pxi"
