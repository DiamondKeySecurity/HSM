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

include "pfunix_hsm.pxi"

include "rpc_tcp_server.pxi"

include "rpc_interface_cache.pxi"

include "rpc_builder.pxi"
include "rpc_interface_handling.pxi"

include "rpc_interface_sync.pxi"
include "sync.pxi"

include "rpc_interface_tamper.pxi"
include "tamper.pxi"

include "rpc_path_object.pxi"
