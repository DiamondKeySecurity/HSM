// Copyright(c) 2019  Diamond Key Security, NFP
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2
// of the License only.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
#define DEBUG_LIBHAL 1

#if DEBUG_LIBHAL
#include <iostream>
#endif

#include "_rpc_handler.h"

extern "C"
{
#include "libhal/hal.h"
#include "libhal/hal_internal.h"
}

namespace diamond_hsm
{
rpc_action *rpc_handler::handle_set_rpc(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
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
}

rpc_action *rpc_handler::handle_enable_cache_keygen(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """Special DKS RPC to enable caching of generated keys"""
    logger.info("RPC code received %s, handle 0x%x",
                DKS_RPCFunc.RPC_FUNC_ENABLE_CACHE_KEYGEN.name, client)

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

    session.cache_generated_keys = True
    print('caching enabled')

    return RPCAction(unencoded_response, None, None)
}

rpc_action *rpc_handler::handle_disable_cache_keygen(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """Special DKS RPC to disable caching of generated keys"""
    logger.info("RPC code received %s, handle 0x%x",
                DKS_RPCFunc.RPC_FUNC_DISABLE_CACHE_KEYGEN.name, client)

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

    session.cache_generated_keys = False
    print('caching disabled')

    return RPCAction(unencoded_response, None, None)
}

rpc_action *rpc_handler::handle_use_incoming_device_uuids(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """Special DKS RPC to enable using incoming device uuids"""
    logger.info("RPC code received %s, handle 0x%x",
                DKS_RPCFunc.RPC_FUNC_USE_INCOMING_DEVICE_UUIDS.name, client)

    response = xdrlib.Packer()
    response.pack_uint(code)
    response.pack_uint(client)

    if (session.from_ethernet):
        # using device uuids can not be set fom
        # an ethernet connection
        response.pack_uint(DKS_HALError.HAL_ERROR_FORBIDDEN)
    else:
        response.pack_uint(DKS_HALError.HAL_OK)

    unencoded_response = response.get_buffer()

    session.incoming_uuids_are_device_uuids = True
    print('accepting incoming device uuids')

    return RPCAction(unencoded_response, None, None)
}

rpc_action *rpc_handler::handle_use_incoming_master_uuids(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """Special DKS RPC to enable using incoming master uuids"""
    logger.info("RPC code received %s, handle 0x%x",
                DKS_RPCFunc.RPC_FUNC_USE_INCOMING_MASTER_UUIDS.name, client)

    response = xdrlib.Packer()
    response.pack_uint(code)
    response.pack_uint(client)

    if (session.from_ethernet):
        # using device uuids can not be set fom
        # an ethernet connection
        response.pack_uint(DKS_HALError.HAL_ERROR_FORBIDDEN)
    else:
        response.pack_uint(DKS_HALError.HAL_OK)

    unencoded_response = response.get_buffer()

    session.incoming_uuids_are_device_uuids = False
    print('accepting incoming master uuids')

    return RPCAction(unencoded_response, None, None)
}

rpc_action *rpc_handler::handle_rpc_any(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """Can run on any available alpha because this is not alpha specific"""
    rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

    logger.info("any rpc sent to %i", rpc_index)

    return RPCAction(None, [self.rpc_list[rpc_index]], None)
}

rpc_action *rpc_handler::handle_rpc_all(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """Must run on all alphas to either to keep PINs synchronized
        or because we don't know which alpha we'll need later"""

    # if the rpc_index has been set for the session, always use it
    if(session.rpc_index >= 0):
        return RPCAction(None, [self.rpc_list[session.rpc_index]], None)

    rpc_list = self.make_all_rpc_list()

    return RPCAction(None, rpc_list, self.callback_rpc_all)
}

rpc_action *rpc_handler::callback_rpc_all(std::vector<libhal::rpc_packet> &reply_list)
{
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
}

rpc_action *rpc_handler::handle_rpc_starthash(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """This is the begining of a hash operation. Any RPC can be used."""

    # select an RPC to use for this hashing operation
    session.cur_hashing_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

    logger.info("hashing on RPC: %i", session.cur_hashing_index)

    return RPCAction(None, [self.rpc_list[session.cur_hashing_index]], self.callback_rpc_starthash)
}

rpc_action *rpc_handler::callback_rpc_starthash(std::vector<libhal::rpc_packet> &reply_list)
{
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
}

rpc_action *rpc_handler::handle_rpc_hash(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """Once a hash has started, we have to continue with it the same RPC"""

    # get the handle of the hash operation
    handle = unpacker.unpack_uint()

    # this handle must be a key
    if(handle not in session.hash_rpcs):
        logger.info("handle_rpc_hash: handle not in session.hash_rpcs")
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)

    return RPCAction(None, [self.rpc_list[session.hash_rpcs[handle]]], None)
}

rpc_action *rpc_handler::handle_rpc_endhash(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
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
}

rpc_action *rpc_handler::handle_rpc_usecurrent(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """The manually selected RPC must be used"""
    rpc_index = session.rpc_index
    if(rpc_index < 0):
        rpc_index = session.key_op_data.rpc_index

    return RPCAction(None, [self.rpc_list[rpc_index]], None)
}

rpc_action *rpc_handler::handle_rpc_pkeyexport(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    # make sure pkey export has been enabled. Always allow from internal non-ethernet sources
    if (session.from_ethernet and
        self.settings.get_setting(HSMSettings.ENABLE_KEY_EXPORT) is False):
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_FORBIDDEN)

    """The manually selected RPC must be used"""
    rpc_index = session.rpc_index
    if(rpc_index < 0):
        rpc_index = session.key_op_data.rpc_index

    return RPCAction(None, [self.rpc_list[rpc_index]], None)
}

rpc_action *rpc_handler::handle_rpc_pkeyopen(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    # pkcs11 session
    session_param = unpacker.unpack_uint()

    # uuid
    incoming_uuid = UUID(bytes = unpacker.unpack_bytes())

    # get the session to use
    session = self.get_session(client)

    # what type of uuid are we getting?
    if(session.incoming_uuids_are_device_uuids):
        if(session.rpc_index < 0):
            logger.info("handle_rpc_pkeyopen: using device uuid, but device not set")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_IMPOSSIBLE)

        device_uuid = incoming_uuid

        session.key_op_data.rpc_index = session.rpc_index
    else:
        # find the device uuid from the master uuid
        master_uuid = incoming_uuid

        if(session.rpc_index >= 0):
            # just use the set rpc_index
            session.key_op_data.rpc_index = session.rpc_index

            # see if this uuid is on the alpha we are requesting
            device_list = self.cache.get_alphas(master_uuid)

            if(session.rpc_index not in device_list):
                logger.info("handle_rpc_pkeyopen: session.rpc_index not in device_list")
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_KEY_NOT_FOUND)

            device_uuid = device_list[session.rpc_index]
        else:
            rpc_uuid_pair = self.choose_rpc_from_master_uuid(master_uuid)
            if(rpc_uuid_pair is None):
                logger.info("handle_rpc_pkeyopen: rpc_uuid_pair is None")
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_KEY_NOT_FOUND)

            session.key_op_data.rpc_index = rpc_uuid_pair[0]
            device_uuid = rpc_uuid_pair[1]

    # recreate with the actual uuid
    session.current_request = RPCpkey_open.create(code, client, session_param, device_uuid)

    # save data about the key we are opening
    session.key_op_data.device_uuid = device_uuid

    """uuid is used to select the RPC with the key and the handle is returned"""
    return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_pkeyopen)
}

rpc_action *rpc_handler::callback_rpc_pkeyopen(std::vector<libhal::rpc_packet> &reply_list)
{
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
    session.key_rpcs[session.key_op_data.handle] = KeyHandleDetails(session.key_op_data.rpc_index, session.key_op_data.device_uuid)

    # inform the load balancer that we have an open pkey
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_op_weight)

    return RPCAction(reply_list[0], None, None)
}

rpc_action *rpc_handler::handle_rpc_pkey(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """use handle to select RPC"""

    # get the handle of the hash operation
    handle = unpacker.unpack_uint()

    # this handle must be a key
    if(handle not in session.key_rpcs):
        logger.info("handle_rpc_pkey: handle not in session.key_rpcs")
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_BAD_ARGUMENTS)

    rpc_index = session.key_rpcs[handle].rpc_index
    device_uuid = session.key_rpcs[handle].uuid

    # logger.info("Using pkey handle:%i RPC:%i", handle, rpc_index)

    session.key_op_data = KeyOperationData(rpc_index, handle, device_uuid)

    if (code == DKS_RPCFunc.RPC_FUNC_PKEY_DELETE or 
        code == DKS_RPCFunc.RPC_FUNC_PKEY_CLOSE):
        return RPCAction(None, [self.rpc_list[rpc_index]], self.callback_rpc_close_deletekey)
    else:
        return RPCAction(None, [self.rpc_list[rpc_index]], None)
}

rpc_action *rpc_handler::handle_rpc_pkeyload(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
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

    # inform the load balancer that we are doing an expensive key operation
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_gen_weight)

    return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)
}

rpc_action *rpc_handler::handle_rpc_pkeyimport(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
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

    # inform the load balancer that we are doing an expensive key operation
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_gen_weight)

    return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)
}

rpc_action *rpc_handler::handle_rpc_keygen(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
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

    # inform the load balancer that we are doing an expensive key operation
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_gen_weight)

    return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)
}

rpc_action *rpc_handler::callback_rpc_close_deletekey(std::vector<libhal::rpc_packet> &reply_list)
{
    unpacker = self.get_response_unpacker(reply_list[0])

    code = unpacker.unpack_uint()
    client = unpacker.unpack_uint()
    result = unpacker.unpack_uint()     

    if(result != DKS_HALError.HAL_OK):
        logger.info("callback_rpc_closekey: result != 0")
        return self.create_error_response(code, client, result)

    # get the session
    session = self.get_session(client)

    # inform the load balancer that we have closed a key
    self.update_device_weight(session.key_op_data.rpc_index, -self.pkey_op_weight)

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
}

rpc_action *rpc_handler::callback_rpc_keygen(std::vector<libhal::rpc_packet> &reply_list)
{
    unpacker = self.get_response_unpacker(reply_list[0])

    code = unpacker.unpack_uint()
    client = unpacker.unpack_uint()
    result = unpacker.unpack_uint()

    # get the session
    session = self.get_session(client)        

    # inform the load balancer that we are no longer doing an expensive operation
    self.update_device_weight(session.key_op_data.rpc_index, -self.pkey_gen_weight)

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

    if(result != DKS_HALError.HAL_OK):
        logger.info("callback_rpc_keygen: result != 0")
        return self.create_error_response(code, client, result)

    # inform the load balancer that we have an open pkey
    # keygen automatically opens the key
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_op_weight)

    # get the handle
    session.key_op_data.handle = unpacker.unpack_uint()

    #get the new uuid
    device_uuid = UUID(bytes = unpacker.unpack_bytes())

    # save the RPC to use for this handle
    session.key_rpcs[session.key_op_data.handle] = KeyHandleDetails(session.key_op_data.rpc_index, session.key_op_data.device_uuid)

    # add new key to cache
    logger.info("Key generated and added to cache RPC:%i UUID:%s Type:%i Flags:%i",
                                        session.key_op_data.rpc_index, session.key_op_data.device_uuid, session.pkey_type, session.flags)


    # save the device uuid internally
    session.key_op_data.device_uuid = device_uuid

    # unless we're caching and using master_uuids, return the device uuid
    outgoing_uuid = device_uuid

    if (session.cache_generated_keys):
        master_uuid = session.cache.add_key_to_alpha(session.key_op_data.rpc_index,
                                                        device_uuid,
                                                        session.pkey_type,
                                                        session.flags)

        if (not session.incoming_uuids_are_device_uuids):
            # the master_uuid will always be returned to ethernet connections
            outgoing_uuid = master_uuid

    # generate reply with the outgoing uuid
    reply = RPCKeygen_result.create(code, client, result,
                                    session.key_op_data.handle,
                                    outgoing_uuid)

    return RPCAction(reply, None, None)
}    

rpc_action *rpc_handler::handle_rpc_pkeymatch(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    """match on all rpcs and then combine results
    incoming UUIDs are master table UUIDs"""

    # if the rpc_index has been set for the session, always use it
    if(session.incoming_uuids_are_device_uuids):
        if(session.rpc_index >= 0):
            return RPCAction(None, [self.rpc_list[session.rpc_index]], None)
        else:
            logger.info("handle_rpc_pkeymatch: using device uuid, but device not set")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_IMPOSSIBLE)

    session.keymatch_details = KeyMatchDetails()
    
    # unpack and store key match attributes
    session.keymatch_details.unpack(unpacker)

    logger.info("pkey_match: result_max = %i, uuid = %s",
                session.keymatch_details.result_max, session.keymatch_details.uuid)

    # if uuid is none, search RPC 0
    # else search starting with the RPC that the uuid is on

    if(session.keymatch_details.uuid == KeyMatchDetails.none_uuid):
        if(session.rpc_index >= 0):
            session.keymatch_details.rpc_index = session.rpc_index
        else:
            session.keymatch_details.rpc_index = 0
    else:
        # need to convert master_uuid to device_uuid
        if(session.rpc_index >= 0):
            device_list = session.cache.get_alphas(session.keymatch_details.uuid)
            if (session.rpc_index not in device_list):
                logger.info("handle_rpc_pkeyopen: session.rpc_index not in device_list")
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_KEY_NOT_FOUND)

            session.keymatch_details.rpc_index = session.rpc_index

            # need to update the command with the new UUID
            session.keymatch_details.uuid = device_list[session.rpc_index]
        else:
            # find the rpc that this is on
            device_to_search = session.cache.get_alpha_lowest_index(session.keymatch_details.uuid)
            if(device_to_search is None):
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

            session.keymatch_details.rpc_index = device_to_search[0]

            # need to update the command with the new UUID
            session.keymatch_details.uuid = device_to_search[1]

        session.current_request = session.keymatch_details.repack(code, client)

    # make sure the rpc_index was set
    if(hasattr(session.keymatch_details, 'rpc_index') == False):
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

    return RPCAction(None, [self.rpc_list[session.keymatch_details.rpc_index]], self.callback_rpc_pkeymatch)
}

rpc_action *rpc_handler::callback_rpc_pkeymatch(std::vector<libhal::rpc_packet> &reply_list)
{
    reply = reply_list[0]

    logger.info("callback_rpc_pkeymatch")

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

    rpc_index = session.keymatch_details.rpc_index

    logger.info("Matching found %i keys", n)

    for i in xrange(n):
        u = UUID(bytes = unpacker.unpack_bytes())

        # convert device UUID to master UUID and if uuid is
        # also on a device with a lowee index, don't add
        master_uuid = session.cache.get_master_uuid(rpc_index, u)
        if (master_uuid is not None):
            lowest_index = session.cache.get_master_uuid_lowest_index(master_uuid)
            if(lowest_index == rpc_index):
                session.keymatch_details.result.uuid_list.append(master_uuid)

    next_rpc = rpc_index + 1

    if (len(session.keymatch_details.result.uuid_list) >= session.keymatch_details.result_max or
        next_rpc >= len(self.rpc_list)):
        # we've either reach the max or we've searched all devices
        result_action = RPCAction(session.keymatch_details.result.build_result_packet(session.keymatch_details.result_max), None, None)
        session.keymatch_details = None

        return result_action

    # we're searching a new alpha so start from 0
    session.keymatch_details.rpc_index = next_rpc
    session.keymatch_details.uuid = KeyMatchDetails.none_uuid
    session.current_request = session.keymatch_details.repack(code, client)

    # there may be more matching keys so generate another command
    return RPCAction(None, [self.rpc_list[session.keymatch_details.rpc_index]], self.callback_rpc_pkeymatch)
}

rpc_action *rpc_handler::handle_rpc_getdevice_ip(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    # generate complete response
    response = xdrlib.Packer()
    response.pack_uint(code)
    response.pack_uint(client)
    response.pack_uint(DKS_HALError.HAL_OK)
    response.pack_bytes(self.netiface.get_ip())

    return RPCAction(response.get_buffer(), None, None)
}

rpc_action *rpc_handler::handle_rpc_getdevice_state(uint32_t code, uint32_t client, libhal::rpc_packet &opacket, std::shared_ptr<MuxSession>)
{
    # generate complete response
    response = xdrlib.Packer()
    response.pack_uint(code)
    response.pack_uint(client)
    response.pack_uint(DKS_HALError.HAL_OK)

    response.pack_uint(len(self.rpc_list))
    for rpc in self.rpc_list:
        response.pack_bytes(str(rpc.state.value))

    return RPCAction(response.get_buffer(), None, None)
}

void rpc_handler::create_function_table()
{
    // """Use a table to quickly select the method to handle each RPC request"""
    // self.function_table[DKS_RPCFunc.RPC_FUNC_GET_VERSION] = self.handle_rpc_any
    // self.function_table[DKS_RPCFunc.RPC_FUNC_GET_RANDOM] = self.handle_rpc_any
    // self.function_table[DKS_RPCFunc.RPC_FUNC_SET_PIN] = self.handle_rpc_all
    // self.function_table[DKS_RPCFunc.RPC_FUNC_LOGIN] = self.handle_rpc_all
    // self.function_table[DKS_RPCFunc.RPC_FUNC_LOGOUT] = self.handle_rpc_all
    // self.function_table[DKS_RPCFunc.RPC_FUNC_LOGOUT_ALL] = self.handle_rpc_all
    // self.function_table[DKS_RPCFunc.RPC_FUNC_IS_LOGGED_IN] = self.handle_rpc_all
    // self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_GET_DIGEST_LEN] = self.handle_rpc_any
    // self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID] = self.handle_rpc_any
    // self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_GET_ALGORITHM] = self.handle_rpc_hash
    // self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_INITIALIZE] = self.handle_rpc_starthash
    // self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_UPDATE] = self.handle_rpc_hash
    // self.function_table[DKS_RPCFunc.RPC_FUNC_HASH_FINALIZE] = self.handle_rpc_endhash
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_LOAD] = self.handle_rpc_pkeyload
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_OPEN] = self.handle_rpc_pkeyopen
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_RSA] = self.handle_rpc_keygen
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_EC] = self.handle_rpc_keygen
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_CLOSE] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_DELETE] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_KEY_TYPE] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_KEY_CURVE] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_KEY_FLAGS] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_PUBLIC_KEY] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_SIGN] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_VERIFY] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_MATCH] = self.handle_rpc_pkeymatch
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_SET_ATTRIBUTES] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GET_ATTRIBUTES] = self.handle_rpc_pkey
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_EXPORT] = self.handle_rpc_pkeyexport
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_IMPORT] = self.handle_rpc_pkeyimport
    // self.function_table[DKS_RPCFunc.RPC_FUNC_PKEY_GENERATE_HASHSIG] = self.handle_rpc_keygen
    // self.function_table[DKS_RPCFunc.RPC_FUNC_GET_HSM_STATE] = self.handle_rpc_getdevice_state
    // self.function_table[DKS_RPCFunc.RPC_FUNC_GET_IP] = self.handle_rpc_getdevice_ip
    // self.function_table[DKS_RPCFunc.RPC_FUNC_SET_RPC_DEVICE] = self.handle_set_rpc
    // self.function_table[DKS_RPCFunc.RPC_FUNC_ENABLE_CACHE_KEYGEN] = self.handle_enable_cache_keygen
    // self.function_table[DKS_RPCFunc.RPC_FUNC_DISABLE_CACHE_KEYGEN] = self.handle_disable_cache_keygen
    // self.function_table[DKS_RPCFunc.RPC_FUNC_CHECK_TAMPER] = self.handle_rpc_usecurrent
    // self.function_table[DKS_RPCFunc.RPC_FUNC_USE_INCOMING_DEVICE_UUIDS] = self.handle_use_incoming_device_uuids
    // self.function_table[DKS_RPCFunc.RPC_FUNC_USE_INCOMING_MASTER_UUIDS] = self.handle_use_incoming_master_uuids
}

}