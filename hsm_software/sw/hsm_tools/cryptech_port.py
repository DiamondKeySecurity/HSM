#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

"""
The CrypTech python code does not use the standard Python enumerator types.
The enumerator type that the code uses is fine =  but it causes Pylint to report
false errors. This file attempts to remedy these problems =  but will need
to be updated if the CrypTech libhal.py interface changes.
"""

import xdrlib


from enum import IntEnum
from cryptech.cryptech.libhal import *

class DKS_HALError(IntEnum):
    HAL_OK                              = 0
    HAL_ERROR_BAD_ARGUMENTS             = 1
    HAL_ERROR_UNSUPPORTED_KEY           = 2
    HAL_ERROR_IO_SETUP_FAILED           = 3
    HAL_ERROR_IO_TIMEOUT                = 4
    HAL_ERROR_IO_UNEXPECTED             = 5
    HAL_ERROR_IO_OS_ERROR               = 6
    HAL_ERROR_IO_BAD_COUNT              = 7
    HAL_ERROR_CSPRNG_BROKEN             = 8
    HAL_ERROR_KEYWRAP_BAD_MAGIC         = 9
    HAL_ERROR_KEYWRAP_BAD_LENGTH        = 10
    HAL_ERROR_KEYWRAP_BAD_PADDING       = 11
    HAL_ERROR_IMPOSSIBLE                = 12
    HAL_ERROR_ALLOCATION_FAILURE        = 13
    HAL_ERROR_RESULT_TOO_LONG           = 14
    HAL_ERROR_ASN1_PARSE_FAILED         = 15
    HAL_ERROR_KEY_NOT_ON_CURVE          = 16
    HAL_ERROR_INVALID_SIGNATURE         = 17
    HAL_ERROR_CORE_NOT_FOUND            = 18
    HAL_ERROR_CORE_BUSY                 = 19
    HAL_ERROR_KEYSTORE_ACCESS           = 20
    HAL_ERROR_KEY_NOT_FOUND             = 21
    HAL_ERROR_KEY_NAME_IN_USE           = 22
    HAL_ERROR_NO_KEY_SLOTS_AVAILABLE    = 23
    HAL_ERROR_PIN_INCORRECT             = 24
    HAL_ERROR_NO_CLIENT_SLOTS_AVAILABLE = 25
    HAL_ERROR_FORBIDDEN                 = 26
    HAL_ERROR_XDR_BUFFER_OVERFLOW       = 27
    HAL_ERROR_RPC_TRANSPORT             = 28
    HAL_ERROR_RPC_PACKET_OVERFLOW       = 29
    HAL_ERROR_RPC_BAD_FUNCTION          = 30
    HAL_ERROR_KEY_NAME_TOO_LONG         = 31
    HAL_ERROR_MASTERKEY_NOT_SET         = 32
    HAL_ERROR_MASTERKEY_FAIL            = 33
    HAL_ERROR_MASTERKEY_BAD_LENGTH      = 34
    HAL_ERROR_KS_DRIVER_NOT_FOUND       = 35
    HAL_ERROR_KEYSTORE_BAD_CRC          = 36
    HAL_ERROR_KEYSTORE_BAD_BLOCK_TYPE   = 37
    HAL_ERROR_KEYSTORE_LOST_DATA        = 38
    HAL_ERROR_BAD_ATTRIBUTE_LENGTH      = 39
    HAL_ERROR_ATTRIBUTE_NOT_FOUND       = 40
    HAL_ERROR_NO_KEY_INDEX_SLOTS        = 41
    HAL_ERROR_KS_INDEX_UUID_MISORDERED  = 42
    HAL_ERROR_KEYSTORE_WRONG_BLOCK_TYPE = 43
    HAL_ERROR_RPC_PROTOCOL_ERROR        = 44
    HAL_ERROR_NOT_IMPLEMENTED           = 45
    HAL_ERROR_CORE_REASSIGNED           = 46
    HAL_ERROR_ASSERTION_FAILED          = 47
    HAL_ERROR_HASHSIG_KEY_EXHAUSTED     = 48
    HAL_ERROR_NOT_READY                 = 49

    # non-standard tamper error
    HAL_ERROR_TAMPER                    = 50

class DKS_RPCFunc(IntEnum):
    RPC_FUNC_GET_VERSION                  = 0
    RPC_FUNC_GET_RANDOM                   = 1
    RPC_FUNC_SET_PIN                      = 2
    RPC_FUNC_LOGIN                        = 3
    RPC_FUNC_LOGOUT                       = 4
    RPC_FUNC_LOGOUT_ALL                   = 5
    RPC_FUNC_IS_LOGGED_IN                 = 6
    RPC_FUNC_HASH_GET_DIGEST_LEN          = 7
    RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID = 8
    RPC_FUNC_HASH_GET_ALGORITHM           = 9
    RPC_FUNC_HASH_INITIALIZE              = 10
    RPC_FUNC_HASH_UPDATE                  = 11
    RPC_FUNC_HASH_FINALIZE                = 12
    RPC_FUNC_PKEY_LOAD                    = 13
    RPC_FUNC_PKEY_OPEN                    = 14
    RPC_FUNC_PKEY_GENERATE_RSA            = 15
    RPC_FUNC_PKEY_GENERATE_EC             = 16
    RPC_FUNC_PKEY_CLOSE                   = 17
    RPC_FUNC_PKEY_DELETE                  = 18
    RPC_FUNC_PKEY_GET_KEY_TYPE            = 19
    RPC_FUNC_PKEY_GET_KEY_FLAGS           = 20
    RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN      = 21
    RPC_FUNC_PKEY_GET_PUBLIC_KEY          = 22
    RPC_FUNC_PKEY_SIGN                    = 23
    RPC_FUNC_PKEY_VERIFY                  = 24
    RPC_FUNC_PKEY_MATCH                   = 25
    RPC_FUNC_PKEY_GET_KEY_CURVE           = 26
    RPC_FUNC_PKEY_SET_ATTRIBUTES          = 27
    RPC_FUNC_PKEY_GET_ATTRIBUTES          = 28
    RPC_FUNC_PKEY_EXPORT                  = 29
    RPC_FUNC_PKEY_IMPORT                  = 30
    RPC_FUNC_PKEY_GENERATE_HASHSIG        = 31

    # non-CrypTech RPC handled by the CrypTech device
    # non-standard order 66. Give some space in case CrypTech
    RPC_FUNC_CHECK_TAMPER                 = 66

    # non-CrypTech RPCs. Handled by the Diamond-HSM
    RPC_FUNC_GET_HSM_STATE                = 1979
    RPC_FUNC_GET_IP                       = 1980
    RPC_FUNC_SET_RPC_DEVICE               = 1981
    RPC_FUNC_DISABLE_CACHE_KEYGEN         = 1982
    RPC_FUNC_ENABLE_CACHE_KEYGEN          = 1983
    RPC_FUNC_USE_INCOMING_DEVICE_UUIDS    = 1984
    RPC_FUNC_USE_INCOMING_MASTER_UUIDS    = 1985

class DKS_HALDigestAlgorithm(IntEnum):
    HAL_DIGEST_ALGORITHM_NONE       = 0
    HAL_DIGEST_ALGORITHM_SHA1       = 1
    HAL_DIGEST_ALGORITHM_SHA224     = 2
    HAL_DIGEST_ALGORITHM_SHA256     = 3
    HAL_DIGEST_ALGORITHM_SHA512_224 = 4
    HAL_DIGEST_ALGORITHM_SHA512_256 = 5
    HAL_DIGEST_ALGORITHM_SHA384     = 6
    HAL_DIGEST_ALGORITHM_SHA512     = 7

class DKS_HALKeyType(IntEnum):
    HAL_KEY_TYPE_NONE            = 0
    HAL_KEY_TYPE_RSA_PRIVATE     = 1
    HAL_KEY_TYPE_RSA_PUBLIC      = 2
    HAL_KEY_TYPE_EC_PRIVATE      = 3
    HAL_KEY_TYPE_EC_PUBLIC       = 4
    HAL_KEY_TYPE_HASHSIG_PRIVATE = 5
    HAL_KEY_TYPE_HASHSIG_PUBLIC  = 6
    HAL_KEY_TYPE_HASHSIG_LMS     = 7
    HAL_KEY_TYPE_HASHSIG_LMOTS   = 8

class DKS_HALCurve(IntEnum):
    HAL_CURVE_NONE = 0
    HAL_CURVE_P256 = 1
    HAL_CURVE_P384 = 2
    HAL_CURVE_P521 = 3

class DKS_HALUser(IntEnum):
    HAL_USER_NONE   = 0
    HAL_USER_NORMAL = 1
    HAL_USER_SO     = 2
    HAL_USER_WHEEL  = 3

    @classmethod
    def to_name(cls, value):
        if (value == cls.HAL_USER_NORMAL):
            return 'user'
        elif (value == cls.HAL_USER_SO):
            return 'so'
        elif (value == cls.HAL_USER_WHEEL):
            return 'wheel'
        else:
            return None

    @classmethod
    def from_name(cls, name):
        if (name == 'user'):
            return cls.HAL_USER_NORMAL
        elif (name == 'so'):
            return cls.HAL_USER_SO
        elif (name == 'wheel'):
            return cls.HAL_USER_WHEEL
        else:
            return None

class DKS_HALKeyFlag(IntEnum):
    HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE     = (1 << 0)
    HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT      = (1 << 1)
    HAL_KEY_FLAG_USAGE_DATAENCIPHERMENT     = (1 << 2)
    HAL_KEY_FLAG_TOKEN                      = (1 << 3)
    HAL_KEY_FLAG_PUBLIC                     = (1 << 4)
    HAL_KEY_FLAG_EXPORTABLE                 = (1 << 5)

class ContextManagedObject(object):
    def __init__(self, on_enter_func, on_exit_func):
        self.on_enter_func = on_enter_func
        self.on_exit_func = on_exit_func

    def __enter__(self):
        self.on_enter_func()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.on_exit_func()

# comment from rpc_client.c
# /*
#  * RPC calls.
#  *
#  * In reading these, it helps to know that every call takes a minimum
#  * of two arguments (function code and client handle, even if the
#  * latter is just a dummy), and that every call returns a minimum of
#  * three values (function code, client handle, and return status).
#  * This may seem a bit redundant, but There Are Reasons:
#  * read_matching_packet() wants to make sure the result we're getting
#  * is from the function we thought we called, and having the client
#  * handle always present in a known place vastly simplifies the task
#  * of the client-side MUX daemon.
#  */
class DKS_HSM(HSM):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.sockfile.close()
        self.socket.close()

    def pkey_generate_hashsig(self, hss_levels, lms_type, lmots_type, flags = 0, client = 0, session = 0):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_HASHSIG, session, hss_levels, lms_type, lmots_type, flags, client = client) as r:
            pkey = PKey(self, r.unpack_uint(), UUID(bytes = r.unpack_bytes()))
            logger.debug("Imported pkey %s", pkey.uuid)
            return pkey

    def rpc_get_hsm_state(self, client = 0):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_GET_HSM_STATE, client = client) as r:
            device_count = r.unpack_uint()
            result = []
            for i in xrange(device_count):
                result.append(r.unpack_bytes())
            return result

    def rpc_get_ip(self, client = 0):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_GET_IP, client = client) as r:
            return r.unpack_bytes()

    def rpc_enable_cache_keygen(self, client = 0):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_ENABLE_CACHE_KEYGEN, client = client):
            return

    def rpc_disable_cache_keygen(self, client = 0):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_DISABLE_CACHE_KEYGEN, client = client):
            return

    def rpc_set_device(self, rpc_index):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_SET_RPC_DEVICE, rpc_index):
            return

    def rpc_check_tamper(self):
        client = 0
        code = DKS_RPCFunc.RPC_FUNC_CHECK_TAMPER

        # use code from libhal.py to send the RPC directly
        # and don't throw exception
        packer = xdrlib.Packer()
        packer.pack_uint(code)
        packer.pack_uint(client)
        self._send(packer)
        unpacker = self._recv(code)
        client = unpacker.unpack_uint()

        return unpacker.unpack_uint()
    def rpc_use_incoming_device_uuids(self, client = 0):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_USE_INCOMING_DEVICE_UUIDS, client = client):
            return

    def rpc_use_incoming_master_uuids(self, client = 0):
        with self.rpc(DKS_RPCFunc.RPC_FUNC_USE_INCOMING_MASTER_UUIDS, client = client):
            return            

    def start_disable_cache_block(self):
        """Returns a ContextManagedObject that can be used with the 'with' keyword to only
         disable caching of a key generation in the 'with' block"""
        return ContextManagedObject(self.rpc_disable_cache_keygen, self.rpc_enable_cache_keygen)

    def start_using_device_uuids_block(self):
        """Returns a ContextManagedObject that can be used with the 'with' keyword to only
         disable caching of a key generation in the 'with' block"""
        return ContextManagedObject(self.rpc_use_incoming_device_uuids, self.rpc_use_incoming_master_uuids)