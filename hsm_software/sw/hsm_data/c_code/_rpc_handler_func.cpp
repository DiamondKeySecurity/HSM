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
void rpc_handler::handle_set_rpc(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                 std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // Special DKS RPC to set the RPC to use for all calls

    // 0 - code
    // 4 - client
    // 8 - rpc_index
    int32_t rpc_index;
    const size_t rpc_index_pos = 8;
    ipacket.decode_int_peak_at((uint32_t *)&rpc_index, rpc_index_pos);

    opacket.create(sizeof(uint32_t) * 3);
    // code
    // client
    // result
    opacket.encode_int(code);
    opacket.encode_int(session_client_handle);

    if (session->from_ethernet)
    {
        // the RPC can not be explicitly set from an outside
        // ethernet connection
        opacket.encode_int(HAL_ERROR_FORBIDDEN);
    }
    else if (rpc_index < device_count())
    {
        // set the rpc to use for this session
        session->rpc_index = rpc_index;

        opacket.encode_int(HAL_OK);
    }
    else
    {
        opacket.encode_int(HAL_ERROR_BAD_ARGUMENTS);
    }
}

void rpc_handler::handle_enable_cache_keygen(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                             std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // Special DKS RPC to enable caching of generated keys
    opacket.create(sizeof(uint32_t) * 3);
    // code
    // client
    // result
    opacket.encode_int(code);
    opacket.encode_int(session_client_handle);

    if (session->from_ethernet)
    {
        // keygen caching can not be explicitly set from
        // an ethernet connection
        opacket.encode_int(HAL_ERROR_FORBIDDEN);
    }
    else
    {
        session->cache_generated_keys = true;
        opacket.encode_int(HAL_OK);
    }

#if DEBUG_LIBHAL
    std::cout << "caching enabled" << std::endl;
#endif
}

void rpc_handler::handle_disable_cache_keygen(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                              std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // Special DKS RPC to enable caching of generated keys
    opacket.create(sizeof(uint32_t) * 3);
    // code
    // client
    // result
    opacket.encode_int(code);
    opacket.encode_int(session_client_handle);

    if (session->from_ethernet)
    {
        // keygen caching can not be explicitly set from
        // an ethernet connection
        opacket.encode_int(HAL_ERROR_FORBIDDEN);
    }
    else
    {
        session->cache_generated_keys = false;
        opacket.encode_int(HAL_OK);
    }

#if DEBUG_LIBHAL
    std::cout << "caching disabled" << std::endl;
#endif
}

void rpc_handler::handle_use_incoming_device_uuids(const uint32_t code, const uint32_t session_client_handle,
                                                   const libhal::rpc_packet &ipacket,
                                                   std::shared_ptr<MuxSession> session,
                                                   libhal::rpc_packet &opacket)
{
    // Special DKS RPC to enable using incoming device uuids
    // Special DKS RPC to enable caching of generated keys
    opacket.create(sizeof(uint32_t) * 3);
    // code
    // client
    // result
    opacket.encode_int(code);
    opacket.encode_int(session_client_handle);

    if (session->from_ethernet)
    {
        // using device uuids can not be set fom
        // an ethernet connection
        opacket.encode_int(HAL_ERROR_FORBIDDEN);
    }
    else
    {
        opacket.encode_int(HAL_OK);

        session->incoming_uuids_are_device_uuids = true;
#if DEBUG_LIBHAL
        std::cout << "accepting incoming device uuids" << std::endl;
#endif
    }
}

void rpc_handler::handle_use_incoming_master_uuids(const uint32_t code, const uint32_t session_client_handle,
                                                   const libhal::rpc_packet &ipacket,
                                                   std::shared_ptr<MuxSession> session,
                                                   libhal::rpc_packet &opacket)
{
    // Special DKS RPC to enable using incoming device uuids
    // Special DKS RPC to enable caching of generated keys
    opacket.create(sizeof(uint32_t) * 3);
    // code
    // client
    // result
    opacket.encode_int(code);
    opacket.encode_int(session_client_handle);

    if (session->from_ethernet)
    {
        // using device uuids can not be set fom
        // an ethernet connection
        opacket.encode_int(HAL_ERROR_FORBIDDEN);
    }
    else
    {
        opacket.encode_int(HAL_OK);

        session->incoming_uuids_are_device_uuids = false;
#if DEBUG_LIBHAL
        std::cout << "accepting incoming master uuids" << std::endl;
#endif
    }
}

void rpc_handler::handle_rpc_any(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                 std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // Can run on any available alpha because this is not alpha specific
    int rpc_index = (session->rpc_index >= 0) ? session->rpc_index : choose_rpc();

#if DEBUG_LIBHAL
        std::cout << "any rpc sent to " << rpc_index << std::endl;
#endif
    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

    hal_error_t result = sendto_cryptech_device(ipacket, opacket, rpc_index, session_client_handle, code, myqueue);
    if (result != HAL_OK)
    {
        opacket.create_error_response(code, session_client_handle, result);
    }
}

void rpc_handler::handle_rpc_all(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                 std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // Must run on all alphas to either to keep PINs synchronized
    // or because we don't know which alpha we'll need later
    int first_rpc = 0, last_rpc = 0;

    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

    // if the rpc_index has been set for the session, always use it
    if(session->rpc_index >= 0)
    {
        first_rpc = last_rpc = session->rpc_index;
    }
    else
    {
        last_rpc = device_count();
    }

    uint32_t error_found = HAL_OK;

    for (int rpc_index = first_rpc; rpc_index <= last_rpc; ++rpc_index)
    {
        hal_error_t result = sendto_cryptech_device(ipacket, opacket, rpc_index, session_client_handle, code, myqueue);
        if (result != HAL_OK)
        {
            error_found = result;
        }
        else
        {
            uint32_t error;
            opacket.decode_int_peak_at(&error, 8);
            if (error != HAL_OK) error_found = error;
        }
    }

    // will send the response from the last RPC unless there was an error
    if (error_found != HAL_OK)
    {
        opacket.create_error_response(code, session_client_handle, error_found);
    }
}

void rpc_handler::handle_rpc_starthash(const uint32_t code, const uint32_t session_client_handle,
                                       const libhal::rpc_packet &ipacket,
                                       std::shared_ptr<MuxSession> session,
                                       libhal::rpc_packet &opacket)
{
    // This is the begining of a hash operation. Any RPC can be used.

    // select an RPC to use for this hashing operation
    session->cur_hashing_index = (session->rpc_index >= 0) ? session->rpc_index : choose_rpc();

#if DEBUG_LIBHAL
        std::cout << "hashing on RPC: " << session->cur_hashing_index << std::endl;
#endif
    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

    hal_error_t result = sendto_cryptech_device(ipacket, opacket, session->cur_hashing_index, session_client_handle, code, myqueue);
    if (result != HAL_OK)
    {
        opacket.create_error_response(code, session_client_handle, result);
        return;
    }

    // process result
    uint32_t oresult;
    const uint8_t *ptr = NULL;

    // consume code
    opacket.decode_int(&oresult, &ptr);
    // consume client
    opacket.decode_int(&oresult, &ptr);
    // result
    opacket.decode_int(&oresult, &ptr);

    if(oresult != HAL_OK)
    {
#if DEBUG_LIBHAL
        std::cout << "callback_rpc_starthash: result != 0" << std::endl;
#endif
        // there's already an error so just return it
        opacket.reset_head();
        return;
    }

    uint32_t handle;
    opacket.decode_int(&handle, &ptr);

    // save the RPC to use for this handle
    if (session->hash_rpcs.find(handle) == session->hash_rpcs.end())
    {
        session->hash_rpcs.insert(std::pair<uint32_t, uint32_t>(handle, session->cur_hashing_index));
    }
    else
    {
        opacket.create_error_response(code, session_client_handle, HAL_ERROR_RPC_TRANSPORT);
    }

    opacket.reset_head();
}

void rpc_handler::handle_rpc_hash(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                 std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // Once a hash has started, we have to continue with the same RPC
    // 0 - code
    // 4 - client
    // 8 - handle
    // get the handle of the hash operation
    uint32_t handle;
    const size_t handle_index_pos = 8;
    ipacket.decode_int_peak_at(&handle, handle_index_pos);

    // this handle must be a key
    if (session->hash_rpcs.find(handle) == session->hash_rpcs.end())
    {
#if DEBUG_LIBHAL
        std::cout << "handle_rpc_hash: handle not in session.hash_rpcs" << std::endl;
#endif
        opacket.create_error_response(code, session_client_handle, HAL_ERROR_BAD_ARGUMENTS);
        return;
    }

    int rpc_index = session->hash_rpcs[handle];

    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

    hal_error_t result = sendto_cryptech_device(ipacket, opacket, rpc_index, session_client_handle, code, myqueue);
    if (result != HAL_OK)
    {
        opacket.create_error_response(code, session_client_handle, result);
    }
}

void rpc_handler::handle_rpc_endhash(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                     std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // we've finished a hash operation
    // 0 - code
    // 4 - client
    // 8 - handle
    // get the handle of the hash operation
    uint32_t handle;
    const size_t handle_index_pos = 8;
    ipacket.decode_int_peak_at(&handle, handle_index_pos);

    // this handle must be a key
    auto handle_loc = session->hash_rpcs.find(handle);
    if (handle_loc == session->hash_rpcs.end())
    {
#if DEBUG_LIBHAL
        std::cout << "handle_rpc_hash: handle not in session.hash_rpcs" << std::endl;
#endif
        opacket.create_error_response(code, session_client_handle, HAL_ERROR_BAD_ARGUMENTS);
    }

    int rpc_index = session->hash_rpcs[handle];

    // the handle no longer needs to be in the dictionary
    session->hash_rpcs.erase(handle_loc);

    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

    hal_error_t result = sendto_cryptech_device(ipacket, opacket, rpc_index, session_client_handle, code, myqueue);
    if (result != HAL_OK)
    {
        opacket.create_error_response(code, session_client_handle, result);
    }
}

void rpc_handler::handle_rpc_usecurrent(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                        std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // The manually selected RPC must be used
    int rpc_index = session->rpc_index;
    if(rpc_index < 0)
    {
        opacket.create_error_response(code, session_client_handle, HAL_ERROR_FORBIDDEN);
    }
    else
    {
        std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

        hal_error_t result = sendto_cryptech_device(ipacket, opacket, rpc_index, session_client_handle, code, myqueue);
        if (result != HAL_OK)
        {
            opacket.create_error_response(code, session_client_handle, result);
        }
    }
}

void rpc_handler::handle_rpc_pkeyexport(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                        std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // make sure pkey export has been enabled. Always allow from internal non-ethernet sources
    if (session->from_ethernet == false || session->enable_exportable_private_keys == false)
    {
        opacket.create_error_response(code, session_client_handle, HAL_ERROR_FORBIDDEN);
    }
    else
    {
        handle_rpc_usecurrent(code, session_client_handle, ipacket, session, opacket);
    }
}

bool rpc_handler::choose_rpc_from_master_uuid(uuids::uuid_t master_uuid, std::pair<int, uuids::uuid_t> &result)
{
    std::map<int, uuids::uuid_t> uuid_dict;
    c_cache_object->get_devices(master_uuid, uuid_dict);

    if (uuid_dict.size() == 0) return false;

    // initialize to a high weight
    int device_weight = large_weight;

    for (auto it = uuid_dict.begin(); it != uuid_dict.end(); ++it)
    {
        // for now choose the device with the lowest weight
        int new_device_weight = get_cryptech_device_weight(it->first);
        if (new_device_weight < device_weight)
        {
            device_weight = new_device_weight;
            result.first = it->first;
            result.second = it->second;
        }
    }

    return true;
}

void rpc_handler::handle_rpc_pkeyopen(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                      std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // 0  - code
    // 4  - client
    // 8  - pkcs11_session
    // 12 - uuid
    const size_t pkcs11_session_pos = 8;
    uint32_t pkcs11_session;
    uint8_t uuid_buffer[16];
    size_t incoming_len;
    uuids::uuid_t incoming_uuid;
    uuids::uuid_t device_uuid;
    uuids::uuid_t master_uuid;
    const uint8_t *ptr;

    ipacket.decode_start(pkcs11_session_pos, &ptr);

    // get the pkcs11 session
    ipacket.decode_int(&pkcs11_session, &ptr);

    // get the uuid
    ipacket.decode_variable_opaque(uuid_buffer, &incoming_len, sizeof(uuid_buffer), &ptr);
    incoming_uuid.fromBytes((char*)uuid_buffer);

    // what type of uuid are we getting?
    if(session->incoming_uuids_are_device_uuids)
    {
        if(session->rpc_index < 0)
        {
#if DEBUG_LIBHAL
            std::cout << "handle_rpc_pkeyopen: using device uuid, but device not set" << std::endl;
#endif
            opacket.create_error_response(code, session_client_handle, HAL_ERROR_IMPOSSIBLE);
            return;
        }

        device_uuid = incoming_uuid;

        session->key_op_data.rpc_index = session->rpc_index;
    }
    else
    {
        // find the device uuid from the master uuid
        master_uuid = incoming_uuid;

        if(session->rpc_index >= 0)
        {
            // just use the set rpc_index
            session->key_op_data.rpc_index = session->rpc_index;

            // see if this uuid is on the alpha we are requesting
            std::map<int, uuids::uuid_t> device_list;
            c_cache_object->get_devices(master_uuid, device_list);

            if(device_list.find(session->rpc_index) == device_list.end())
            {
#if DEBUG_LIBHAL
                std::cout << "handle_rpc_pkeyopen: session.rpc_index not in device_list" << std::endl;
#endif
                opacket.create_error_response(code, session_client_handle, HAL_ERROR_KEY_NOT_FOUND);
            }

            device_uuid = device_list[session->rpc_index];
        }
        else
        {
            std::pair<int, uuids::uuid_t> rpc_uuid_pair;
            
            if(choose_rpc_from_master_uuid(master_uuid, rpc_uuid_pair) == false)
            {
#if DEBUG_LIBHAL
                std::cout << "handle_rpc_pkeyopen: rpc_uuid_pair is None" << std::endl;
#endif
                opacket.create_error_response(code, session_client_handle, HAL_ERROR_KEY_NOT_FOUND);
            }

            session->key_op_data.rpc_index = rpc_uuid_pair.first;
            device_uuid = rpc_uuid_pair.second;
        }
    }

    // recreate with the actual uuid
    libhal::rpc_packet packet_to_send;
    packet_to_send.create(sizeof(code) + sizeof(session_client_handle) + sizeof(pkcs11_session) + sizeof(device_uuid) + 16);
    packet_to_send.encode_int(code);
    packet_to_send.encode_int(session_client_handle);
    packet_to_send.encode_int(pkcs11_session);
    packet_to_send.encode_variable_opaque(device_uuid.bytes(), 16);
    packet_to_send.shrink_to_fit();

    // save data about the key we are opening
    session->key_op_data.device_uuid = device_uuid;

    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

    int rpc_index = session->key_op_data.rpc_index;

    hal_error_t result = sendto_cryptech_device(packet_to_send, opacket, rpc_index, session_client_handle, code, myqueue);
    if (result != HAL_OK)
    {
        opacket.create_error_response(code, session_client_handle, result);
    }

    // process result
    uint32_t oresult;
    const uint8_t *optr = NULL;

    // consume code
    opacket.decode_int(&oresult, &optr);
    // consume client
    opacket.decode_int(&oresult, &optr);
    // result
    opacket.decode_int(&oresult, &optr);      

    if(oresult != HAL_OK)
    {
#if DEBUG_LIBHAL
        std::cout << "callback_rpc_pkeyopen: result != 0" << std::endl;
#endif
        opacket.create_error_response(code, session_client_handle, oresult);
    }

    opacket.decode_int(&session->key_op_data.handle, &optr);

    // save the RPC to use for this handle
    uint32_t handle = session->key_op_data.handle;

    // save the RPC to use for this handle
    if (session->key_rpcs.find(handle) == session->key_rpcs.end())
    {
        session->key_rpcs.insert(std::pair<uint32_t, KeyHandleDetails>(handle,
                                                                       KeyHandleDetails(session->key_op_data.rpc_index,
                                                                                        session->key_op_data.device_uuid)));

        update_device_weight(session->key_op_data.rpc_index, pkey_op_weight);
    }
    else
    {
        opacket.create_error_response(code, session_client_handle, HAL_ERROR_RPC_TRANSPORT);
    }

    opacket.reset_head();
}

void rpc_handler::handle_rpc_pkey(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                  std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // use handle to select RPC
    // 0 - code
    // 4 - client
    // 8 - handle
    // get the handle of the hash operation
    uint32_t handle;
    const size_t handle_index_pos = 8;
    ipacket.decode_int_peak_at(&handle, handle_index_pos);

    // this handle must be a key
    if (session->key_rpcs.find(handle) == session->key_rpcs.end())
    {
#if DEBUG_LIBHAL
        std::cout << "handle_rpc_pkey: handle not in session.key_rpcs" << std::endl;
#endif
        opacket.create_error_response(code, session_client_handle, HAL_ERROR_BAD_ARGUMENTS);
        return;
    }

    int rpc_index = session->key_rpcs[handle].rpc_index;

    std::shared_ptr<SafeQueue<libhal::rpc_packet>> myqueue = session->myqueue;

    hal_error_t result = sendto_cryptech_device(ipacket, opacket, rpc_index, session_client_handle, code, myqueue);
    if (result != HAL_OK)
    {
        opacket.create_error_response(code, session_client_handle, result);
    }
    else if (code == RPC_FUNC_PKEY_DELETE || code == RPC_FUNC_PKEY_CLOSE)
    {
        // 0 - code
        // 4 - client
        // 8 - result
        uint32_t oresult;
        const size_t result_pos = 8;

        opacket.decode_int_peak_at(&oresult, result_pos);

        if (oresult == HAL_OK)
        {
            if (code == RPC_FUNC_PKEY_DELETE)
            {
                // get the details about the key so we can delete from the cache
                uuids::uuid_t uuid_to_remove = session->key_rpcs[handle].uuid;
                rpc_index = session->key_rpcs[handle].rpc_index;
                c_cache_object->remove_key_from_device_only(rpc_index, uuid_to_remove);
            }

            // clear data
            auto handle_loc = session->key_rpcs.find(handle);
            session->key_rpcs.erase(handle_loc);

            // the key was closed so we are not working on anything now
            session->key_op_data = KeyOperationData(-1, 0, uuids::uuid_none);
        }
    }
}

void rpc_handler::handle_rpc_pkeyload(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                      std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{ /*
    // use manually selected RPC and get returned uuid and handle

    // if the session rpc_index has not be set, this must getting the public key
    // rpc_index = session.rpc_index
    // if(rpc_index < 0):
    //     rpc_index = self.choose_rpc() #session.key_op_data.rpc_index

    // select an RPC to use for this hashing operation
    session.key_op_data.rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

    logger.info("session.rpc_index == %i  session.key_op_data.rpc_index == %i",
                                        session.rpc_index, session.key_op_data.rpc_index)


    // consume pkcs11 session id
    unpacker.unpack_uint()

    // consume der
    unpacker.unpack_bytes()

    // get flags
    session.flags = unpacker.unpack_uint()

    if hasattr(session, 'pkey_type'):
        // treat as the public version of the last privte key generated as this is the standard usage
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

    // inform the load balancer that we are doing an expensive key operation
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_gen_weight)

    return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)
*/ }

void rpc_handler::handle_rpc_pkeyimport(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                        std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{ /*
    // use manually selected RPC and get returned uuid and handle

    // if the session rpc_index has not be set, this must getting the public key
    // rpc_index = session.rpc_index
    // if(rpc_index < 0):
    //     rpc_index = self.choose_rpc() #session.key_op_data.rpc_index

    // select an RPC to use for this hashing operation
    session.key_op_data.rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

    logger.info("session.rpc_index == %i  session.key_op_data.rpc_index == %i",
                                        session.rpc_index, session.key_op_data.rpc_index)


    // consume pkcs11 session id
    unpacker.unpack_uint()

    // consume kekek
    unpacker.unpack_uint()

    // consume pkcs8
    unpacker.unpack_bytes()

    // consume kek
    unpacker.unpack_bytes()

    // get flags
    session.flags = unpacker.unpack_uint()

    if hasattr(session, 'pkey_type'):
        // treat as the public version of the last privte key generated as this is the standard usage
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

    // inform the load balancer that we are doing an expensive key operation
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_gen_weight)

    return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)
*/ }

void rpc_handler::handle_rpc_keygen(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                    std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{ /*
    // A key has been generated. Returns uuid and handle

    // consume pkcs11 session id
    unpacker.unpack_uint()

    // save the key settings
    if (code == RPC_FUNC_PKEY_GENERATE_RSA):
        session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE
        
        // consume keylen
        unpacker.unpack_uint()

        // get the exponent because we need the size
        exponent = unpacker.unpack_bytes()

        // get the location of the flags so we can change if needed
        exp_len = len(exponent)
        exp_padding = (4 - exp_len % 4) % 4
        flag_location = 20 + exp_len + exp_padding

    elif (code == RPC_FUNC_PKEY_GENERATE_EC):
        session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_EC_PRIVATE

        // get the location of the flags so we can change if needed
        flag_location = 16
    elif (code == RPC_FUNC_PKEY_GENERATE_HASHSIG):
        session.pkey_type = DKS_HALKeyType.HAL_KEY_TYPE_HASHSIG_PRIVATE

        // get the location of the flags so we can change if needed
        flag_location = 24

    // get the flags
    session.flags = rpc_get_int(session.current_request, flag_location)

    // check to see if the rpc has been setup to allow exportable private keys
    if ((session.enable_exportable_private_keys == True) and
        (session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT) == 0 and
        (session.flags & DKS_HALKeyFlag.HAL_KEY_FLAG_USAGE_DATAENCIPHERMENT) == 0):

        new_flag = session.flags | DKS_HALKeyFlag.HAL_KEY_FLAG_EXPORTABLE

        session.current_request = rpc_set_int(session.current_request, new_flag, flag_location)

        // sanity check. Make sure we get back what we just set
        session.flags = rpc_get_int(session.current_request, flag_location)


    logger.info("Key Gen Flags: 0x%X"%session.flags)

    // select an RPC to use for this hashing operation
    session.key_op_data.rpc_index = session.rpc_index if(session.rpc_index >= 0) else self.choose_rpc()

    logger.info("session.rpc_index == %i  session.key_op_data.rpc_index == %i",
                                        session.rpc_index, session.key_op_data.rpc_index)

    // inform the load balancer that we are doing an expensive key operation
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_gen_weight)

    return RPCAction(None, [self.rpc_list[session.key_op_data.rpc_index]], self.callback_rpc_keygen)
*/ }

void rpc_handler::callback_rpc_keygen(const std::vector<libhal::rpc_packet> &reply_list, libhal::rpc_packet &opacket)
{ /*
    unpacker = self.get_response_unpacker(reply_list[0])

    code = unpacker.unpack_uint()
    client = unpacker.unpack_uint()
    result = unpacker.unpack_uint()

    // get the session
    session = self.get_session(client)        

    // inform the load balancer that we are no longer doing an expensive operation
    self.update_device_weight(session.key_op_data.rpc_index, -self.pkey_gen_weight)

    // keygen only happens on one alpha
    if(len(reply_list) != 1):
        logger.info("callback_rpc_keygen: len(reply_list) != 1")
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

    if (code != RPC_FUNC_PKEY_GENERATE_EC and
        code != RPC_FUNC_PKEY_GENERATE_RSA and
        code != RPC_FUNC_PKEY_LOAD and
        code != RPC_FUNC_PKEY_IMPORT and
        code != RPC_FUNC_PKEY_GENERATE_HASHSIG):
        logger.info("callback_rpc_keygen: incorrect code received")
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

    if(result != DKS_HALError.HAL_OK):
        logger.info("callback_rpc_keygen: result != 0")
        return self.create_error_response(code, client, result)

    // inform the load balancer that we have an open pkey
    // keygen automatically opens the key
    self.update_device_weight(session.key_op_data.rpc_index, self.pkey_op_weight)

    // get the handle
    session.key_op_data.handle = unpacker.unpack_uint()

    // get the new uuid
    device_uuid = UUID(bytes = unpacker.unpack_bytes())

    // save the RPC to use for this handle
    session.key_rpcs[session.key_op_data.handle] = KeyHandleDetails(session.key_op_data.rpc_index, session.key_op_data.device_uuid)

    // add new key to cache
    logger.info("Key generated and added to cache RPC:%i UUID:%s Type:%i Flags:%i",
                                        session.key_op_data.rpc_index, session.key_op_data.device_uuid, session.pkey_type, session.flags)


    // save the device uuid internally
    session.key_op_data.device_uuid = device_uuid

    // unless we're caching and using master_uuids, return the device uuid
    outgoing_uuid = device_uuid

    if (session.cache_generated_keys):
        master_uuid = session.cache.add_key_to_alpha(session.key_op_data.rpc_index,
                                                        device_uuid,
                                                        session.pkey_type,
                                                        session.flags)

        if (not session.incoming_uuids_are_device_uuids):
            // the master_uuid will always be returned to ethernet connections
            outgoing_uuid = master_uuid

    // generate reply with the outgoing uuid
    reply = RPCKeygen_result.create(code, client, result,
                                    session.key_op_data.handle,
                                    outgoing_uuid)

    return RPCAction(reply, None, None)
*/ }    

void rpc_handler::handle_rpc_pkeymatch(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                       std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{/* 
    // match on all rpcs and then combine results
    // incoming UUIDs are master table UUIDs

    // if the rpc_index has been set for the session, always use it
    if(session.incoming_uuids_are_device_uuids)
    {
        if(session.rpc_index >= 0)
        {
            return RPCAction(None, [self.rpc_list[session.rpc_index]], None)
        }
        else
        {
            logger.info("handle_rpc_pkeymatch: using device uuid, but device not set")
            return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_IMPOSSIBLE)
        }
    }

    session.keymatch_details = KeyMatchDetails()
    
    // unpack and store key match attributes
    session.keymatch_details.unpack(unpacker)

    logger.info("pkey_match: result_max = %i, uuid = %s",
                session.keymatch_details.result_max, session.keymatch_details.uuid)

    // if uuid is none, search RPC 0
    // else search starting with the RPC that the uuid is on

    if(session.keymatch_details.uuid == KeyMatchDetails.none_uuid)
    {
        if(session.rpc_index >= 0)
        {
            session.keymatch_details.rpc_index = session.rpc_index
        }
        else
        {
            session.keymatch_details.rpc_index = 0
        }
    }
    else
    {
        // need to convert master_uuid to device_uuid
        if(session.rpc_index >= 0)
        {
            device_list = session.cache.get_alphas(session.keymatch_details.uuid)
            if (session.rpc_index not in device_list)
            {
                logger.info("handle_rpc_pkeyopen: session.rpc_index not in device_list")
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_KEY_NOT_FOUND)
            }

            session.keymatch_details.rpc_index = session.rpc_index

            // need to update the command with the new UUID
            session.keymatch_details.uuid = device_list[session.rpc_index]
        }
        else
        {
            // find the rpc that this is on
            device_to_search = session.cache.get_alpha_lowest_index(session.keymatch_details.uuid)
            if(device_to_search is None)
            {
                return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)
            }

            session.keymatch_details.rpc_index = device_to_search[0]

            // need to update the command with the new UUID
            session.keymatch_details.uuid = device_to_search[1]
        }

        session.current_request = session.keymatch_details.repack(code, client)
    }

    // make sure the rpc_index was set
    if(hasattr(session.keymatch_details, 'rpc_index') == False)
    {
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)
    }

    return RPCAction(None, [self.rpc_list[session.keymatch_details.rpc_index]], self.callback_rpc_pkeymatch)
*/}

void rpc_handler::callback_rpc_pkeymatch(const std::vector<libhal::rpc_packet> &reply_list, libhal::rpc_packet &opacket)
{/*
    reply = reply_list[0]

    logger.info("callback_rpc_pkeymatch")

    unpacker = self.get_response_unpacker(reply)

    code = unpacker.unpack_uint()
    client = unpacker.unpack_uint()
    result = unpacker.unpack_uint()

    // this should have been called on exactly one alpha
    if(len(reply_list) != 1):
        logger.info("callback_rpc_pkeymatch: len(reply_list) != 1")
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)


    // get the session
    session = self.get_session(client)        

    if (code != RPC_FUNC_PKEY_MATCH):
        logger.info("callback_rpc_pkeymatch: code != RPCFunc.RPC_FUNC_PKEY_MATCH")
        return self.create_error_response(code, client, DKS_HALError.HAL_ERROR_RPC_TRANSPORT)

    if(result != 0):
        logger.info("callback_rpc_pkeymatch: result != 0")
        return self.create_error_response(code, client, result)

    session.keymatch_details.result.code = code
    session.keymatch_details.result.client = client
    session.keymatch_details.result.result = result

    // get the pkcs#11 session
    session.keymatch_details.result.session = unpacker.unpack_uint()

    // get the count
    n = unpacker.unpack_uint()

    rpc_index = session.keymatch_details.rpc_index

    logger.info("Matching found %i keys", n)

    for i in xrange(n):
        u = UUID(bytes = unpacker.unpack_bytes())

        // convert device UUID to master UUID and if uuid is
        // also on a device with a lowee index, don't add
        master_uuid = session.cache.get_master_uuid(rpc_index, u)
        if (master_uuid is not None):
            lowest_index = session.cache.get_master_uuid_lowest_index(master_uuid)
            if(lowest_index == rpc_index):
                session.keymatch_details.result.uuid_list.append(master_uuid)

    next_rpc = rpc_index + 1

    if (len(session.keymatch_details.result.uuid_list) >= session.keymatch_details.result_max or
        next_rpc >= len(self.rpc_list)):
        // we've either reach the max or we've searched all devices
        result_action = RPCAction(session.keymatch_details.result.build_result_packet(session.keymatch_details.result_max), None, None)
        session.keymatch_details = None

        return result_action

    // we're searching a new alpha so start from 0
    session.keymatch_details.rpc_index = next_rpc
    session.keymatch_details.uuid = KeyMatchDetails.none_uuid
    session.current_request = session.keymatch_details.repack(code, client)

    // there may be more matching keys so generate another command
    return RPCAction(None, [self.rpc_list[session.keymatch_details.rpc_index]], self.callback_rpc_pkeymatch)
*/}

void rpc_handler::handle_rpc_getdevice_ip(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                          std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // make over-sized and shrink later
    opacket.create(HAL_RPC_MAX_PKT_SIZE);

    // add the parameters
    opacket.encode_int(code);
    opacket.encode_int(session_client_handle);
    opacket.encode_int(HAL_OK);
    opacket.encode_variable_opaque((const uint8_t *)ip_address.c_str(), ip_address.size());

    opacket.shrink_to_fit();
}

void rpc_handler::handle_rpc_getdevice_state(const uint32_t code, const uint32_t session_client_handle, const libhal::rpc_packet &ipacket,
                                             std::shared_ptr<MuxSession> session, libhal::rpc_packet &opacket)
{
    // make over-sized and shrink later
    opacket.create(HAL_RPC_MAX_PKT_SIZE);

    // add the parameters
    opacket.encode_int(code);
    opacket.encode_int(session_client_handle);
    opacket.encode_int(HAL_OK);
    opacket.encode_int(device_count());
    
    for (int rpc_index = 0; rpc_index < device_count(); ++rpc_index)
    {
        const char *s = rpc_device_states[rpc_index].GetStateString();
        const size_t string_size = strlen(s);
        
        opacket.encode_variable_opaque((const uint8_t *)s, string_size);
    }

    opacket.shrink_to_fit();
}

void rpc_handler::update_device_weight(int cryptech_device, int amount)
{
    if (cryptech_device >= 0 && cryptech_device < device_count())
    {
        rpc_device_states[cryptech_device].inc_busy_count(amount);
    }
}

void rpc_handler::create_function_table()
{
    function_table = new rpc_handler_func[last_dks_rpc_index + dks_rpc_modifier + 1];

    // Use a table to quickly select the method to handle each RPC request
    function_table[RPC_FUNC_GET_VERSION] = &diamond_hsm::rpc_handler::handle_rpc_any;
    function_table[RPC_FUNC_GET_RANDOM] = &diamond_hsm::rpc_handler::handle_rpc_any;
    function_table[RPC_FUNC_SET_PIN] = &diamond_hsm::rpc_handler::handle_rpc_all;
    function_table[RPC_FUNC_LOGIN] = &diamond_hsm::rpc_handler::handle_rpc_all;
    function_table[RPC_FUNC_LOGOUT] = &diamond_hsm::rpc_handler::handle_rpc_all;
    function_table[RPC_FUNC_LOGOUT_ALL] = &diamond_hsm::rpc_handler::handle_rpc_all;
    function_table[RPC_FUNC_IS_LOGGED_IN] = &diamond_hsm::rpc_handler::handle_rpc_all;
    function_table[RPC_FUNC_HASH_GET_DIGEST_LEN] = &diamond_hsm::rpc_handler::handle_rpc_any;
    function_table[RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID] = &diamond_hsm::rpc_handler::handle_rpc_any;
    function_table[RPC_FUNC_HASH_GET_ALGORITHM] = &diamond_hsm::rpc_handler::handle_rpc_hash;
    function_table[RPC_FUNC_HASH_INITIALIZE] = &diamond_hsm::rpc_handler::handle_rpc_starthash;
    function_table[RPC_FUNC_HASH_UPDATE] = &diamond_hsm::rpc_handler::handle_rpc_hash;
    function_table[RPC_FUNC_HASH_FINALIZE] = &diamond_hsm::rpc_handler::handle_rpc_endhash;
    function_table[RPC_FUNC_PKEY_LOAD] = &diamond_hsm::rpc_handler::handle_rpc_pkeyload;
    function_table[RPC_FUNC_PKEY_OPEN] = &diamond_hsm::rpc_handler::handle_rpc_pkeyopen;
    function_table[RPC_FUNC_PKEY_GENERATE_RSA] = &diamond_hsm::rpc_handler::handle_rpc_keygen;
    function_table[RPC_FUNC_PKEY_GENERATE_EC] = &diamond_hsm::rpc_handler::handle_rpc_keygen;
    function_table[RPC_FUNC_PKEY_CLOSE] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_DELETE] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_GET_KEY_TYPE] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_GET_KEY_CURVE] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_GET_KEY_FLAGS] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_GET_PUBLIC_KEY] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_SIGN] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_VERIFY] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_MATCH] = &diamond_hsm::rpc_handler::handle_rpc_pkeymatch;
    function_table[RPC_FUNC_PKEY_SET_ATTRIBUTES] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_GET_ATTRIBUTES] = &diamond_hsm::rpc_handler::handle_rpc_pkey;
    function_table[RPC_FUNC_PKEY_EXPORT] = &diamond_hsm::rpc_handler::handle_rpc_pkeyexport;
    function_table[RPC_FUNC_PKEY_IMPORT] = &diamond_hsm::rpc_handler::handle_rpc_pkeyimport;
    function_table[RPC_FUNC_PKEY_GENERATE_HASHSIG] = &diamond_hsm::rpc_handler::handle_rpc_keygen;

    // add modifier because there's a gap
    function_table[RPC_FUNC_CHECK_TAMPER+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_rpc_usecurrent;
    function_table[RPC_FUNC_GET_HSM_STATE+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_rpc_getdevice_state;
    function_table[RPC_FUNC_GET_IP+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_rpc_getdevice_ip;
    function_table[RPC_FUNC_SET_RPC_DEVICE+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_set_rpc;
    function_table[RPC_FUNC_ENABLE_CACHE_KEYGEN+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_enable_cache_keygen;
    function_table[RPC_FUNC_DISABLE_CACHE_KEYGEN+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_disable_cache_keygen;
    function_table[RPC_FUNC_USE_INCOMING_DEVICE_UUIDS+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_use_incoming_device_uuids;
    function_table[RPC_FUNC_USE_INCOMING_MASTER_UUIDS+dks_rpc_modifier] = &diamond_hsm::rpc_handler::handle_use_incoming_master_uuids;
}

}