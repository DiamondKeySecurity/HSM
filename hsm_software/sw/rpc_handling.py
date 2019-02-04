#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import struct

from uuid import UUID

# import classes from the original cryptech.muxd
# cryptech_muxd has been renamed to cryptech/muxd.py
from hsm_tools.cryptech.muxd import logger

from hsm_tools.hsm import CrypTechDeviceState

from settings import HSMSettings

from hsm_tools.cryptech.cryptech.libhal import ContextManagedUnpacker, xdrlib
from hsm_tools.rpc_action import RPCAction
from hsm_tools.cryptech_port import DKS_RPCFunc, DKS_HALKeyType,\
                                    DKS_HALKeyFlag, DKS_HALError
from hsm_tools.threadsafevar import ThreadSafeVariable

from key_matching import KeyMatchDetails


def rpc_get_int(msg, location):
    "Get an int from a location in an RPC message"
    return struct.unpack(">L", msg[location:location+4])[0]


def rpc_set_int(msg, data, location):
    "Set an int from a location in an RPC message"
    return msg[:location] + struct.pack(">L", data) + msg[location+4:]


class KeyHandleDetails:
    """Information on the key that a handle points to"""
    def __init__(self, rpc_index, uuid):
        self.rpc_index = rpc_index
        self.uuid = uuid


class KeyOperationData:
    def __init__(self, rpc_index, handle, uuid):
        self.rpc_index = rpc_index
        self.handle = handle
        self.uuid = uuid


class MuxSession:
    """Simple class for defining the state of a
       connection to the load balancer"""
    def __init__(self, rpc_index, cache, settings, from_ethernet):
        self.cache = cache

        # if true, this session was started by a connection from
        # outside the HSM and is not trusted
        self.from_ethernet = from_ethernet

        # should new keys be added to the cache? The synchronizer
        # manually adds keys
        self.cache_generated_keys = True

        # complete unencoded request that we're working on
        self.current_request = None

        # the current rpc_index to use for this session
        self.rpc_index = rpc_index

        # the index of the rpc that is being used for the
        # initializing hash op
        self.cur_hashing_index = 0

        # dictionary mapping of hash rpc indexes by the hash handle
        self.hash_rpcs = {}

        # dictionary mapping of key rpc indexes by the key handle
        self.key_rpcs = {}

        # parameters for the current key operation
        self.key_op_data = KeyOperationData(None, None, None)

        # should exportable private keys be used for this session?
        # Use 's' for PEP8
        s = settings.get_setting(HSMSettings.ENABLE_EXPORTABLE_PRIVATE_KEYS)
        self.enable_exportable_private_keys = s


class RPCPreprocessor:
    """Able to load balance between multiple rpcs"""
    def __init__(self, rpc_list, cache, settings, netiface):
        self.cache = cache
        self.settings = settings
        self.rpc_list = rpc_list

        # this is the index of the RPC to use. When set to < 0,
        # it will auto set
        self.current_rpc = -1
        self.sessions = {}
        self.function_table = {}
        self.next_rpc = 0
        self.current_rpc_uses = 0
        self.create_function_table()
        self.netiface = netiface
        self.hsm_locked = True
        self.debug = False
        self.tamper_detected = ThreadSafeVariable(False)

    def device_count(self):
        return len(self.rpc_list)

    def get_current_rpc(self):
        if(self.current_rpc < 0):
            return "auto"
        elif (len(self.rpc_list) > self.current_rpc):
            return self.rpc_list[self.current_rpc].name
        else:
            return "INVALID RPC"

    def set_current_rpc(self, index):
        if(isinstance(index, (int, )) is False):
            return "Invalid index. The index must be a valid RPC index."
        elif (index > len(self.rpc_list)):
            return "Index out of range. The index must be a valid RPC index."
        else:
            self.current_rpc = index
            return "RPC is now: " + self.get_current_rpc()

    def create_session(self, client, from_ethernet):
        # make sure we have a session for this handle
        if(client not in self.sessions):
            new_session = MuxSession(self.current_rpc,
                                     self.cache,
                                     self.settings,
                                     from_ethernet)
            self.sessions[client] = new_session

    def delete_session(self, client):
        # update the cache with any changes made during this session
        if(client in self.sessions):
            del self.sessions[client]

    def make_all_rpc_list(self):
        rpc_list = []

        for rpc in self.rpc_list:
            rpc_list.append(rpc)

        return rpc_list

    def get_session(self, client):
        return self.sessions[client]

    def choose_rpc(self):
        """Simple Heuristic for selecting an alpha RPC channel to use"""
        RPC_USES_BEFORE_NEXT = 2

        next_rpc = self.next_rpc

        self.current_rpc_uses += 1
        if(self.current_rpc_uses > RPC_USES_BEFORE_NEXT):
            self.current_rpc_uses = 0

            self.next_rpc += 1
            if(self.next_rpc >= len(self.rpc_list)):
                self.next_rpc = 0

        return next_rpc

    def append_futures(self, futures):
        for rpc in self.rpc_list:
            futures.append(rpc.serial.rpc_output_loop())
            futures.append(rpc.serial.logout_all())

    def is_rpc_locked(self):
        return self.hsm_locked or (not self.cache.is_initialized())

    def unlock_hsm(self):
        self.hsm_locked = False
        for rpc in self.rpc_list:
            rpc.unlock_port()

    def lock_hsm(self):
        self.hsm_locked = True
        for rpc in self.rpc_list:
            rpc.change_state(CrypTechDeviceState.HSMLocked)

    def on_tamper_event(self, tamper_object):
        new_tamper_state = tamper_object.get_tamper_state()
        old_tamper_state = self.tamper_detected.value

        if(new_tamper_state != old_tamper_state):
            self.tamper_detected.value = new_tamper_state

            if(new_tamper_state is True):
                self.hsm_locked = True
                for rpc in self.rpc_list:
                    rpc.change_state(CrypTechDeviceState.TAMPER)
            else:
                self.hsm_locked = True
                for rpc in self.rpc_list:
                    rpc.clear_tamper(CrypTechDeviceState.TAMPER_RESET)
    
    def process_incoming_rpc(self, decoded_request):
        # handle the message normally
        unpacker = ContextManagedUnpacker(decoded_request)

        # get the code of the RPC request
        code = unpacker.unpack_uint()

        # get the handle which identifies the TCP connection that the
        # request came from
        client = unpacker.unpack_uint()

        # get the session so we know where to put the response and
        # which rpc to use
        session = self.get_session(client)

        # save the current request in the session
        session.current_request = decoded_request

        # check to see if there's an ongoing tamper event
        if (self.tamper_detected.value and session.from_ethernet):
            return self.create_error_response(code, client,
                                              DKS_HALError.HAL_ERROR_TAMPER)

        # process the RPC request
        action = self.function_table[code](code, client, unpacker, session)

        # it's possible that the request has been altered so return it
        action.request = session.current_request

        return action

    def create_error_response(self, code, client, hal_error):
        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)
        response.pack_uint(hal_error)

        # TODO log error

        return RPCAction(response.get_buffer(), None, None)

    def handle_set_rpc(self, code, client, unpacker, session):
        """Special DKS RPC to set the RPC to use for all calls"""
        logger.info("RPC code received %s, handle 0x%x",
                    DKS_RPCFunc.RPC_FUNC_SET_RPC_DEVICE, client)

        # get the serial to switch to
        rpc_index = unpacker.unpack_uint()

        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)

        if (session.from_ethernet):
            # the RPC can not be explicitly set from an outside
            # ethernet connection
            response.pack_uint(DKS_HALError.HAL_ERROR_FORBIDDEN)
        elif (rpc_index < len(self.rpc_list)):
            # set the rpc to use for this session
            session.rpc_index = rpc_index

            response.pack_uint(DKS_HALError.HAL_OK)
        else:
            response.pack_uint(DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)

        unencoded_response = response.get_buffer()

        return RPCAction(unencoded_response, None, None)

    def handle_enable_cache_keygen(self, code, client, unpacker, session):
        """Special DKS RPC to enable caching of generated keys"""
        logger.info("RPC code received %s, handle 0x%x",
                    DKS_RPCFunc.RPC_FUNC_ENABLE_CACHE_KEYGEN.name, client)
        print('caching enabled')

        session.cache_generated_keys = True

        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)

        if (session.from_ethernet):
            # keygen caching can not be explicitly set from
            # an ethernet connection
            response.pack_uint(DKS_HALError.HAL_ERROR_FORBIDDEN)
        else:
            response.pack_uint(DKS_HALError.HAL_OK)

        unencoded_response = response.get_buffer()

        return RPCAction(unencoded_response, None, None)

    def handle_disable_cache_keygen(self, code, client, unpacker, session):
        """Special DKS RPC to enable caching of generated keys"""
        logger.info("RPC code received %s, handle 0x%x",
                    DKS_RPCFunc.RPC_FUNC_DISABLE_CACHE_KEYGEN.name, client)
        print('caching disabled')

        session.cache_generated_keys = False

        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)

        if (session.from_ethernet):
            # keygen caching can not be explicitly set from
            # an ethernet connection
            response.pack_uint(DKS_HALError.HAL_ERROR_FORBIDDEN)
        else:
            response.pack_uint(DKS_HALError.HAL_OK)

        unencoded_response = response.get_buffer()

        return RPCAction(unencoded_response, None, None)

    def get_response_unpacker(self, unencoded_response):
        msg = "".join(unencoded_response)
        if not msg:
            return None
        msg = ContextManagedUnpacker(msg)

        # return the unpacker. the first uint is the code followed
        # by the client
        return msg

    def handle_rpc_any(self, code, client, unpacker, session):
        """Can run on any available alpha because this is not alpha specific"""
        rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

        logger.info("any rpc sent to %i", rpc_index)

        return RPCAction(None, [self.rpc_list[rpc_index]], None)

    def handle_rpc_all(self, code, client, unpacker, session):
        """Must run on all alphas to either to keep PINs synchronized
           or because we don't know which alpha we'll need later"""

        # if the rpc_index has been set for the session, always use it
        if(session.rpc_index >= 0):
            return RPCAction(None, [self.rpc_list[session.rpc_index]], None)

        rpc_list = self.make_all_rpc_list()

        return RPCAction(None, rpc_list, self.callback_rpc_all)

    def callback_rpc_all(self, reply_list):
        code = None

        for reply in reply_list:
            unpacker = self.get_response_unpacker(reply)

            new_code = unpacker.unpack_int()

            # get the client
            client = unpacker.unpack_uint()

            if(code is not None and new_code != code):
                # error, the codes don't match
                return self.create_error_response(new_code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

            code = new_code

            status = unpacker.unpack_uint()
            if(status != 0):
                # one of the alpha's returned an error so return that error
                # TODO log error
                return self.create_error_response(code, client, status)

        #all of the replies are the same so just return the first one
        return RPCAction(reply_list[0], None, None)

    def handle_rpc_starthash(self, code, client, unpacker, session):
        """This is the begining of a hash operation. Any RPC can be used."""

        # select an RPC to use for this hashing operation
        session.cur_hashing_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

        logger.info("hashing on RPC: %i", session.cur_hashing_index)

        return RPCAction(None, [self.rpc_list[session.cur_hashing_index]], self.callback_rpc_starthash)

    def callback_rpc_starthash(self, reply_list):
        unpacker = self.get_response_unpacker(reply_list[0])

        code = unpacker.unpack_uint()
        client = unpacker.unpack_uint()

        # hashing only happens on one alpha
        if(len(reply_list) != 1):
            logger.info("callback_rpc_starthash: len(reply_list) != 1")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        result = unpacker.unpack_uint()

        if(code != DKS_RPCFunc.RPC_FUNC_HASH_INITIALIZE):
            logger.info("callback_rpc_starthash: code != RPCFunc.RPC_FUNC_HASH_INITIALIZE")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        # get the session
        session = self.get_session(client)        

        if(result != DKS_HALError.HAL_OK):
            logger.info("callback_rpc_starthash: result != 0")
            return self.create_error_response(code, client, result)

        handle = unpacker.unpack_uint()

        # save the RPC to use for this handle
        session.hash_rpcs[handle] = session.cur_hashing_index

        return RPCAction(reply_list[0], None, None)

    def handle_rpc_hash(self, code, client, unpacker, session):
        """Once a hash has started, we have to continue with it the same RPC"""

        # get the handle of the hash operation
        handle = unpacker.unpack_uint()

        # this handle must be a key
        if(handle not in session.hash_rpcs):
            logger.info("handle_rpc_hash: handle not in session.hash_rpcs")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)

        return RPCAction(None, [self.rpc_list[session.hash_rpcs[handle]]], None)

    def handle_rpc_endhash(self, code, client, unpacker, session):
        """we've finished a hash operation"""

        # get the handle of the hash operation
        handle = unpacker.unpack_uint()

        # this handle must be a key
        if(handle not in session.hash_rpcs):
            logger.info("handle_rpc_hash: handle not in session.hash_rpcs")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)

        # the handle no longer needs to be in the dictionary
        del session.hash_rpcs.pop[handle]

        return RPCAction(None, [self.rpc_list[session.rpc_index]], None)

    def handle_rpc_usecurrent(self, code, client, unpacker, session):
        """The manually selected RPC must be used"""
        rpc_index = session.rpc_index
        if(rpc_index < 0):
            rpc_index = session.key_op_data.rpc_index

        return RPCAction(None, [self.rpc_list[rpc_index]], None)

    def handle_rpc_pkeyopen(self, code, client, unpacker, session):
        # pkcs11 session
        unpacker.unpack_uint()

        # uuid
        u = UUID(bytes = unpacker.unpack_bytes())
        uuid = str(u)

        # get the session to use
        session = self.get_session(client)

        if(session.rpc_index >= 0):
            # just use the set rpc_index
            session.key_op_data.rpc_index = session.rpc_index
        else:
            # find the rpc that this is on
            available_rpcs = session.cache.get_alphas(uuid)
            if(len(available_rpcs) == 0):
                logger.info("handle_rpc_pkeyopen: len(available_rpcs) == 0")
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_KEY_NOT_FOUND)

            for key, value in available_rpcs.iteritems():
                session.key_op_data.rpc_index = key

        # save data about the key we are opening
        session.key_op_data.uuid = uuid

        """uuid is used to select the RPC with the key and the handle is returned"""
        return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_pkeyopen)

    def callback_rpc_pkeyopen(self, reply_list):
        unpacker = self.get_response_unpacker(reply_list[0])

        code = unpacker.unpack_uint()
        client = unpacker.unpack_uint()

        # hashing only happens on one alpha
        if(len(reply_list) != 1):
            logger.info("callback_rpc_pkeyopen: len(reply_list) != 1")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        result = unpacker.unpack_uint()

        if(code != DKS_RPCFunc.RPC_FUNC_PKEY_OPEN):
            logger.info("callback_rpc_pkeyopen: code != RPCFunc.RPC_FUNC_PKEY_OPEN")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        # get the session
        session = self.get_session(client)        

        if(result != 0):
            logger.info("callback_rpc_pkeyopen: result != 0")
            return self.create_error_response(code, client, result)

        session.key_op_data.handle = unpacker.unpack_uint()

        # save the RPC to use for this handle
        session.key_rpcs[session.key_op_data.handle] = KeyHandleDetails(session.key_op_data.rpc_index, session.key_op_data.uuid)

        return RPCAction(reply_list[0], None, None)

    def handle_rpc_pkey(self, code, client, unpacker, session):
        """use handle to select RPC"""

        rpc_index = session.rpc_index

        # get the handle of the hash operation
        handle = unpacker.unpack_uint()

        if(rpc_index < 0):
            # this handle must be a key
            if(handle not in session.key_rpcs):
                logger.info("handle_rpc_pkey: handle not in session.key_rpcs")
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)

            rpc_index = session.key_rpcs[handle].rpc_index

            # logger.info("Using pkey handle:%i RPC:%i", handle, rpc_index)

        session.key_op_data = KeyOperationData(rpc_index, handle, None)

        if (code == DKS_RPCFunc.RPC_FUNC_PKEY_DELETE or 
            code == DKS_RPCFunc.RPC_FUNC_PKEY_CLOSE):
            return RPCAction(None, [self.rpc_list[rpc_index]], self.callback_rpc_close_deletekey)
        else:
            return RPCAction(None, [self.rpc_list[rpc_index]], None)

    def handle_rpc_pkeyload(self, code, client, unpacker, session):
        """use manually selected RPC and get returned uuid and handle"""

        # if the session rpc_index has not be set, this must getting the public key
        # rpc_index = session.rpc_index
        # if(rpc_index < 0):
        #     rpc_index = self.choose_rpc() #session.key_op_data.rpc_index

        # select an RPC to use for this hashing operation
        session.key_op_data.rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

        logger.info("session.rpc_index == %i  session.key_op_data.rpc_index == %i",
                                            session.rpc_index, session.key_op_data.rpc_index)


        # consume pkcs11 session id
        unpacker.unpack_uint()

        # consume der
        unpacker.unpack_bytes()

        # get flags
        session.flags = unpacker.unpack_uint()

        if hasattr(session, 'pkey_type'):
            # treat as the public version of the last privte key generated as this is the standard usage
            if(session.pkey_type == DKS_HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE and
               session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_PUBLIC):
                session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_RSA_PUBLIC
            elif(session.pkey_type == DKS_HALKeyType.HAL_KEY_TYPE_EC_PRIVATE and
               session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_PUBLIC):
                session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_EC_PUBLIC
            elif(session.pkey_type == DKS_HALKeyType.HAL_KEY_TYPE_HASHSIG_PRIVATE and
               session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_PUBLIC):
               session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_HASHSIG_PUBLIC
        else:
            session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_NONE
            session.curve = 0

        return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)

    def handle_rpc_pkeyimport(self, code, client, unpacker, session):
        """use manually selected RPC and get returned uuid and handle"""

        # if the session rpc_index has not be set, this must getting the public key
        # rpc_index = session.rpc_index
        # if(rpc_index < 0):
        #     rpc_index = self.choose_rpc() #session.key_op_data.rpc_index

        # select an RPC to use for this hashing operation
        session.key_op_data.rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

        logger.info("session.rpc_index == %i  session.key_op_data.rpc_index == %i",
                                            session.rpc_index, session.key_op_data.rpc_index)


        # consume pkcs11 session id
        unpacker.unpack_uint()

        # consume kekek
        unpacker.unpack_uint()

        # consume pkcs8
        unpacker.unpack_bytes()

        # consume kek
        unpacker.unpack_bytes()

        # get flags
        session.flags = unpacker.unpack_uint()

        if hasattr(session, 'pkey_type'):
            # treat as the public version of the last privte key generated as this is the standard usage
            if(session.pkey_type == DKS_HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE and
               session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_PUBLIC):
                session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_RSA_PUBLIC
            elif(session.pkey_type == DKS_HALKeyType.HAL_KEY_TYPE_EC_PRIVATE and
               session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_PUBLIC):
                session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_EC_PUBLIC
            elif(session.pkey_type == DKS_HALKeyType.HAL_KEY_TYPE_HASHSIG_PRIVATE and
               session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_PUBLIC):
               session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_HASHSIG_PUBLIC
        else:
            session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_NONE
            session.curve = 0

        return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)


    def handle_rpc_keygen(self, code, client, unpacker, session):
        """A key has been generated. Returns uuid and handle"""

        # consume pkcs11 session id
        unpacker.unpack_uint()

        # save the key settings
        if (code == DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_RSA):
            session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE
            
            # consume keylen
            unpacker.unpack_uint()

            # get the exponent because we need the size
            exponent = unpacker.unpack_bytes()

            # get the location of the flags so we can change if needed
            exp_len = len(exponent)
            exp_padding = (4 - exp_len % 4) % 4
            flag_location = 20 + exp_len + exp_padding

        elif (code == DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_EC):
            session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_EC_PRIVATE

            # get the location of the flags so we can change if needed
            flag_location = 16
        elif (code == DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_HASHSIG):
            session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_HASHSIG_PRIVATE

            # get the location of the flags so we can change if needed
            flag_location = 24

        # get the flags
        session.flags = rpc_get_int(session.current_request, flag_location)

        # check to see if the rpc has been setup to allow exportable private keys
        if ((session.enable_exportable_private_keys == True) and
            (session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT) == 0 and
            (session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_USAGE_DATAENCIPHERMENT) == 0):
    
            new_flag = session.flags | DKS_HALKeyFlag.HAL_KEY_FLAG_EXPORTABLE

            session.current_request = rpc_set_int(session.current_request, new_flag, flag_location)

            # sanity check. Make sure we get back what we just set
            session.flags = rpc_get_int(session.current_request, flag_location)


        logger.info("Key Gen Flags: 0x%X"%session.flags)

        # select an RPC to use for this hashing operation
        session.key_op_data.rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

        logger.info("session.rpc_index == %i  session.key_op_data.rpc_index == %i",
                                            session.rpc_index, session.key_op_data.rpc_index)

        return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)

    def callback_rpc_close_deletekey(self, reply_list):
        unpacker = self.get_response_unpacker(reply_list[0])

        code = unpacker.unpack_uint()
        client = unpacker.unpack_uint()
        result = unpacker.unpack_uint()     

        if(result != DKS_HALError.HAL_OK):
            logger.info("callback_rpc_closekey: result != 0")
            return self.create_error_response(code, client, result)

        # get the session
        session = self.get_session(client)

        handle = session.key_op_data.handle

        # this handle must be a key
        if(handle not in session.key_rpcs):
            logger.info("callback_rpc_close_deletekey: handle not in session.key_rpcs")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)        

        if (code == DKS_RPCFunc.RPC_FUNC_PKEY_DELETE):
            # get the details about the key so we can delete from the cache
            keydetails = session.key_rpcs[handle]
            uuid = keydetails.uuid
            rpc_index = keydetails.rpc_index
            session.cache.remove_key_from_alpha(rpc_index, uuid)

        # clear data
        session.key_rpcs.pop(handle, None)

        # the key was closed so we are not working on anything now
        session.key_op_data = KeyOperationData(None, None, None)

        return RPCAction(reply_list[0], None, None)

    def callback_rpc_keygen(self, reply_list):
        unpacker = self.get_response_unpacker(reply_list[0])

        code = unpacker.unpack_uint()
        client = unpacker.unpack_uint()
        result = unpacker.unpack_uint()

        # keygen only happens on one alpha
        if(len(reply_list) != 1):
            logger.info("callback_rpc_keygen: len(reply_list) != 1")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        if (code != DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_EC and
            code != DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_RSA and
            code != DKS_RPCFunc.RPC_FUNC_PKEY_LOAD and
            code != DKS_RPCFunc.RPC_FUNC_PKEY_IMPORT and
            code != DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_HASHSIG):
            logger.info("callback_rpc_keygen: incorrect code received")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        # get the session
        session = self.get_session(client)        

        if(result != DKS_HALError.HAL_OK):
            logger.info("callback_rpc_keygen: result != 0")
            return self.create_error_response(code, client, result)

        # get the handle
        session.key_op_data.handle = unpacker.unpack_uint()

        #get the new uuid
        u = UUID(bytes = unpacker.unpack_bytes())
        session.key_op_data.uuid = str(u)

        # save the RPC to use for this handle
        session.key_rpcs[session.key_op_data.handle] = KeyHandleDetails(session.key_op_data.rpc_index, session.key_op_data.uuid)

        # add new key to cache
        logger.info("Key generated and added to cache RPC:%i UUID:%s Type:%i Flags:%i",
                                            session.key_op_data.rpc_index, session.key_op_data.uuid, session.pkey_type, session.flags)

        if (session.cache_generated_keys):
            session.cache.add_key_to_alpha(session.key_op_data.rpc_index,
                                           session.key_op_data.uuid,
                                           session.pkey_type,
                                           session.flags)

    
        return RPCAction(reply_list[0], None, None)
        

    def handle_rpc_pkeymatch(self, code, client, unpacker, session):
        """match on all rpcs and then combine results"""

        # if the rpc_index has been set for the session, always use it
        if(session.rpc_index >= 0):
            return RPCAction(None, [self.rpc_list[session.rpc_index]], None)


        session.keymatch_details = KeyMatchDetails()
        
        # unpack and store key match attributes
        session.keymatch_details.unpack(unpacker)

        logger.info("pkey_match: result_max = %i, uuid = %s",
                                            session.keymatch_details.result_max, session.keymatch_details.uuid)

        # if uuid is none, search RPC 0
        # else search starting with the RPC that the uuid is on

        if(session.keymatch_details.uuid == KeyMatchDetails.none_uuid):
            session.keymatch_details.rpc_index = 0
        else:
            # find the rpc that this is on
            available_rpcs = session.cache.get_alphas(session.keymatch_details.uuid)
            if(len(available_rpcs) == 0):
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

            for key, value in available_rpcs.iteritems():
                # match the exact uuid
                if(value == session.keymatch_details.uuid):              
                    session.keymatch_details.rpc_index = key

        # make sure the rpc_index was set
        if(hasattr(session.keymatch_details, 'rpc_index') == False):
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        return RPCAction(None, [self.rpc_list[session.keymatch_details.rpc_index]], self.callback_rpc_pkeymatch)

    def callback_rpc_pkeymatch(self, reply_list):
        reply = reply_list[0]

        unpacker = self.get_response_unpacker(reply)

        code = unpacker.unpack_uint()
        client = unpacker.unpack_uint()
        result = unpacker.unpack_uint()

        # this should have been called on exactly one alpha
        if(len(reply_list) != 1):
            logger.info("callback_rpc_pkeymatch: len(reply_list) != 1")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)


        # get the session
        session = self.get_session(client)        

        if (code != DKS_RPCFunc.RPC_FUNC_PKEY_MATCH):
            logger.info("callback_rpc_pkeymatch: code != RPCFunc.RPC_FUNC_PKEY_MATCH")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

        if(result != 0):
            logger.info("callback_rpc_pkeymatch: result != 0")
            return self.create_error_response(code, client, result)

        session.keymatch_details.result.code = code
        session.keymatch_details.result.client = client
        session.keymatch_details.result.result = result

        # get the pkcs#11 session
        session.keymatch_details.result.session = unpacker.unpack_uint()

        # get the count
        n = unpacker.unpack_uint()

        logger.info("Matching found %i keys", n)

        for i in xrange(n):
            u = UUID(bytes = unpacker.unpack_bytes())

            # TODO, don't return matches
            session.keymatch_details.result.uuid_list.append(u)

        next_rpc = session.keymatch_details.rpc_index + 1

        if (len(session.keymatch_details.result.uuid_list) >= session.keymatch_details.result_max or
            next_rpc >= len(self.rpc_list)):
            result_action = RPCAction(session.keymatch_details.result.build_result_packet(session.keymatch_details.result_max), None, None)
            session.keymatch_details = None

            return result_action

        session.keymatch_details.rpc_index = next_rpc

        # there may be more matching keys so generate another command
        return RPCAction(None, [self.rpc_list[session.keymatch_details.rpc_index]], self.callback_rpc_pkeymatch)

    def handle_rpc_getdevice_ip(self, code, client, unpacker, session):
        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)
        response.pack_uint(DKS_HALError.HAL_OK)
        response.pack_bytes(self.netiface.get_ip())

        return RPCAction(response.get_buffer(), None, None)

    def handle_rpc_getdevice_state(self, code, client, unpacker, session):
        # generate complete response
        response = xdrlib.Packer()
        response.pack_uint(code)
        response.pack_uint(client)
        response.pack_uint(DKS_HALError.HAL_OK)

        response.pack_uint(len(self.rpc_list))
        for rpc in self.rpc_list:
            response.pack_bytes(str(rpc.state.value))

        return RPCAction(response.get_buffer(), None, None)

    def create_function_table(self):
        """Use a table to quickly select the method to handle each RPC request"""
        self.function_table[DKS_RPCFunc.RPC_FUNC_GET_VERSION] = self.handle_rpc_any
        self.function_table[DKS_RPCFunc.RPC_FUNC_GET_RANDOM] = self.handle_rpc_any
        self.function_table[DKS_RPCFunc.RPC_FUNC_SET_PIN] = self.handle_rpc_all
        self.function_table[DKS_RPCFunc.RPC_FUNC_LOGIN] = self.handle_rpc_all
        self.function_table[DKS_RPCFunc.RPC_FUNC_LOGOUT] = self.handle_rpc_all
        self.function_table[DKS_RPCFunc.RPC_FUNC_LOGOUT_ALL] = self.handle_rpc_all
        self.function_table[DKS_RPCFunc.RPC_FUNC_IS_LOGGED_IN] = self.handle_rpc_all
        self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_GET_DIGEST_LEN] = self.handle_rpc_any
        self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID] = self.handle_rpc_any
        self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_GET_ALGORITHM] = self.handle_rpc_hash
        self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_INITIALIZE] = self.handle_rpc_starthash
        self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_UPDATE] = self.handle_rpc_hash
        self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_FINALIZE] = self.handle_rpc_endhash
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_LOAD] = self.handle_rpc_pkeyload
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_OPEN] = self.handle_rpc_pkeyopen
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_RSA] = self.handle_rpc_keygen
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_EC] = self.handle_rpc_keygen
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_CLOSE] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_DELETE] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_KEY_TYPE] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_KEY_CURVE] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_KEY_FLAGS] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_PUBLIC_KEY] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_SIGN] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_VERIFY] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_MATCH] = self.handle_rpc_pkeymatch
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_SET_ATTRIBUTES] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_ATTRIBUTES] = self.handle_rpc_pkey
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_EXPORT] = self.handle_rpc_usecurrent
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_IMPORT] = self.handle_rpc_pkeyimport
        self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_HASHSIG] = self.handle_rpc_keygen
        self.function_table[DKS_RPCFunc.RPC_FUNC_GET_HSM_STATE] = self.handle_rpc_getdevice_state
        self.function_table[DKS_RPCFunc.RPC_FUNC_GET_IP] = self.handle_rpc_getdevice_ip
        self.function_table[DKS_RPCFunc.RPC_FUNC_SET_RPC_DEVICE] = self.handle_set_rpc
        self.function_table[DKS_RPCFunc.RPC_FUNC_ENABLE_CACHE_KEYGEN] = self.handle_enable_cache_keygen
        self.function_table[DKS_RPCFunc.RPC_FUNC_DISABLE_CACHE_KEYGEN] = self.handle_disable_cache_keygen
        