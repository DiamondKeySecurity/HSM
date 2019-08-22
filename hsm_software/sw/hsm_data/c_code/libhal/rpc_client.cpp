// Diamond Key Security, NFP Changes
// Copyright 2019 Diamond Key Security, NFP
// All rights reserved
/*
 * rpc_client.c
 * ------------
 * Remote procedure call client-side private API implementation.
 *
 * Authors: Rob Austein, Paul Selkirk
 * Copyright (c) 2015-2018, NORDUnet A/S All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the NORDUnet nor the names of its contributors may
 *   be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

extern "C"
{
#include "hal.h"
#include "hal_internal.h"
#include "xdr_internal.h"
}

#include "rpc_packet.h"

#ifndef HAL_RPC_CLIENT_DEBUG
#define HAL_RPC_CLIENT_DEBUG 0
#endif

#if HAL_RPC_CLIENT_DEBUG
#include <stdio.h>
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) { hal_log(HAL_LOG_DEBUG, "%s returned %d (%s)", #op, _err_, hal_error_string(_err_)); return _err_; } } while (0)
#else
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) { return _err_; } } while (0)
#endif

#define pad(n) (((n) + 3) & ~3)

#define nargs(n) ((n) * 4)

namespace libhal
{

// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure

/*
 * RPC calls.
 *
 * In reading these, it helps to know that every call takes a minimum
 * of two arguments (function code and client handle, even if the
 * latter is just a dummy), and that every call returns a minimum of
 * three values (function code, client handle, and return status).
 * This may seem a bit redundant, but There Are Reasons:
 * read_matching_packet() wants to make sure the result we're getting
 * is from the function we thought we called, and having the client
 * handle always present in a known place vastly simplifies the task
 * of the client-side MUX daemon.
 */

hal_error_t get_version(rpc_packet **packet, const hal_client_handle_t client)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(2));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_GET_VERSION));
    check(opacket->encode_int(client.handle));

    return HAL_OK;
}

hal_error_t get_random(rpc_packet **packet, const hal_client_handle_t client, const size_t length)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_GET_RANDOM));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int((uint32_t)length));

    return HAL_OK;
}

hal_error_t set_pin(rpc_packet **packet, const hal_client_handle_t client,
                    const hal_user_t user,
                    const char * const pin, const size_t pin_len)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(4) + pad(pin_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_SET_PIN));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(user));
    check(opacket->encode_variable_opaque((const uint8_t *)pin, pin_len));

    return HAL_OK;
}

/*
 * We may end up wanting to wrap a client-side cache around the
 * login()/logout()/logout_all() calls and reimplement is_logged_in()
 * on the client side using that cache, so that access checks don't
 * need to cross the RPC boundary.  Then again, we might not, if the
 * RPC call is fast enough, so implementing all before the RPC would
 * qualify as premature optimization.  There aren't all that many
 * things on the client side that would use this anyway, so the whole
 * question may be moot.
 *
 * For now, we leave all of these as plain RPC calls, but we may want
 * to revisit this if the is_logged_in() call turns into a bottleneck.
 */

hal_error_t login(rpc_packet **packet, const hal_client_handle_t client,
                  const hal_user_t user,
                  const char * const pin, const size_t pin_len)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(4) + pad(pin_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_LOGIN));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(user));
    check(opacket->encode_variable_opaque((const uint8_t *)pin, pin_len));

    return HAL_OK;
}

hal_error_t logout(rpc_packet **packet, const hal_client_handle_t client)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(2));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_LOGOUT));
    check(opacket->encode_int(client.handle));

    return HAL_OK;
}

hal_error_t logout_all(rpc_packet **packet, const hal_client_handle_t client)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(2));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_LOGOUT_ALL));
    check(opacket->encode_int(client.handle));

    return HAL_OK;
}

// RPC Functions added by Diamond Key Security for the Diamond-HSM
hal_error_t check_tamper(rpc_packet **packet, const hal_client_handle_t client)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(2));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_CHECK_TAMPER));
    check(opacket->encode_int(client.handle));

    return HAL_OK;
}

hal_error_t is_logged_in(rpc_packet **packet, const hal_client_handle_t client,
                         const hal_user_t user)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_IS_LOGGED_IN));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(user));

    return HAL_OK;
}

hal_error_t hash_get_digest_len(rpc_packet **packet, const hal_client_handle_t client,
                                const hal_digest_algorithm_t alg)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_HASH_GET_DIGEST_LEN));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(alg));

    return HAL_OK;
}

hal_error_t hash_get_digest_algorithm_id(rpc_packet **packet, const hal_client_handle_t client,
                                         const hal_digest_algorithm_t alg, const size_t len_max)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(4));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(alg));
    check(opacket->encode_int(len_max));

    return HAL_OK;
}

hal_error_t hash_get_algorithm(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_hash_handle_t hash)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_HASH_GET_ALGORITHM));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(hash.handle));

    return HAL_OK;
}

hal_error_t hash_initialize(rpc_packet **packet, const hal_client_handle_t client,
                            const hal_session_handle_t session,
                            const hal_digest_algorithm_t alg,
                            const uint8_t * const key, const size_t key_len)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(5) + pad(key_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_HASH_INITIALIZE));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_int(alg));
    check(opacket->encode_variable_opaque(key, key_len));

    return HAL_OK;
}

hal_error_t hash_update(rpc_packet **packet, const hal_client_handle_t client,
                        const hal_hash_handle_t hash,
                        const uint8_t * data, const size_t length)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(4) + pad(length));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_HASH_UPDATE));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(hash.handle));
    check(opacket->encode_variable_opaque(data, length));

    return HAL_OK;
}

hal_error_t hash_finalize(rpc_packet **packet, const hal_client_handle_t client,
                          const hal_hash_handle_t hash, const size_t length)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(4));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_HASH_FINALIZE));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(hash.handle));
    check(opacket->encode_int(length));

    return HAL_OK;
}

hal_error_t pkey_remote_load(rpc_packet **packet, const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             const uint8_t * const der, const size_t der_len,
                             const hal_key_flags_t flags)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(5) + pad(der_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_LOAD));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_variable_opaque(der, der_len));
    check(opacket->encode_int(flags));

    return HAL_OK;
}

hal_error_t pkey_remote_open(rpc_packet **packet, const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             const hal_uuid_t * const name)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(4) + pad(sizeof(name->uuid)));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_OPEN));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_variable_opaque(name->uuid, sizeof(name->uuid)));

    return HAL_OK;
}

hal_error_t pkey_remote_generate_rsa(rpc_packet **packet, const hal_client_handle_t client,
                                     const hal_session_handle_t session,
                                     const unsigned key_len,
                                     const uint8_t * const exp, const size_t exp_len,
                                     const hal_key_flags_t flags)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(6) + pad(exp_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GENERATE_RSA));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_int(key_len));
    check(opacket->encode_variable_opaque(exp, exp_len));
    check(opacket->encode_int(flags));

    return HAL_OK;
}

hal_error_t pkey_remote_generate_ec(rpc_packet **packet, const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    const hal_curve_name_t curve,
                                    const hal_key_flags_t flags)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(5));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GENERATE_EC));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_int(curve));
    check(opacket->encode_int(flags));

    return HAL_OK;
}

hal_error_t pkey_remote_generate_hashsig(rpc_packet **packet, const hal_client_handle_t client,
                                         const hal_session_handle_t session,
                                         const size_t hss_levels,
                                         const hal_lms_algorithm_t lms_type,
                                         const hal_lmots_algorithm_t lmots_type,
                                         const hal_key_flags_t flags)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(7));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GENERATE_HASHSIG));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_int((uint32_t)hss_levels));
    check(opacket->encode_int((uint32_t)lms_type));
    check(opacket->encode_int((uint32_t)lmots_type));
    check(opacket->encode_int(flags));

    return HAL_OK;
}

hal_error_t pkey_remote_close(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_CLOSE));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));

    return HAL_OK;
}

hal_error_t pkey_remote_delete(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_DELETE));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));

    return HAL_OK;
}

hal_error_t pkey_remote_get_key_type(rpc_packet **packet, const hal_client_handle_t client,
                                            const hal_pkey_handle_t pkey)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GET_KEY_TYPE));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));

    return HAL_OK;
}

hal_error_t pkey_remote_get_key_curve(rpc_packet **packet, const hal_client_handle_t client,
                                      const hal_pkey_handle_t pkey)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GET_KEY_CURVE));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));

    return HAL_OK;
}

hal_error_t pkey_remote_get_key_flags(rpc_packet **packet, const hal_client_handle_t client,
                                      const hal_pkey_handle_t pkey)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GET_KEY_FLAGS));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));

    return HAL_OK;
}

hal_error_t pkey_remote_get_public_key_len(rpc_packet **packet, const hal_client_handle_t client,
                                      const hal_pkey_handle_t pkey)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(3));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));

    return HAL_OK;
}

hal_error_t pkey_remote_get_public_key(rpc_packet **packet, const hal_client_handle_t client,
                                       const hal_pkey_handle_t pkey, const size_t der_max)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(4));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GET_PUBLIC_KEY));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));
    check(opacket->encode_int(der_max));

    return HAL_OK;
}

hal_error_t pkey_remote_sign(rpc_packet **packet, const hal_client_handle_t client,
                             const hal_pkey_handle_t pkey,
                             const hal_hash_handle_t hash,
                             const uint8_t * const input, const size_t input_len, const size_t signature_max)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(6) + pad(input_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_SIGN));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));
    check(opacket->encode_int(hash.handle));
    check(opacket->encode_variable_opaque(input, input_len));
    check(opacket->encode_int(signature_max));

    return HAL_OK;
}

hal_error_t pkey_remote_verify(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_pkey_handle_t pkey,
                               const hal_hash_handle_t hash,
                               const uint8_t * const input, const size_t input_len,
                               const uint8_t * const signature, const size_t signature_len)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(6) + pad(input_len) + pad(signature_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_VERIFY));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));
    check(opacket->encode_int(hash.handle));
    check(opacket->encode_variable_opaque(input, input_len));
    check(opacket->encode_variable_opaque(signature, signature_len));

    return HAL_OK;
}

hal_error_t pkey_remote_match(rpc_packet **packet, const hal_client_handle_t client,
                              const hal_session_handle_t session,
                              const hal_key_type_t type,
                              const hal_curve_name_t curve,
                              const hal_key_flags_t mask,
                              const hal_key_flags_t flags,
                              const hal_pkey_attribute_t *attributes,
                              const unsigned attributes_len,
                              const unsigned *state,
                              const unsigned result_max,
                              const hal_uuid_t * const previous_uuid)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    size_t attributes_buffer_len = 0;
    if (attributes != NULL)
        for (size_t i = 0; i < attributes_len; i++)
            attributes_buffer_len += pad(attributes[i].length);

    rpc_packet *opacket = new rpc_packet(nargs(11 + attributes_len * 2) + 
                                         attributes_buffer_len + pad(sizeof(hal_uuid_t)));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_MATCH));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_int(type));
    check(opacket->encode_int(curve));
    check(opacket->encode_int(mask));
    check(opacket->encode_int(flags));
    check(opacket->encode_int(attributes_len));
    if (attributes != NULL) {
        for (size_t i = 0; i < attributes_len; i++) {
            check(opacket->encode_int(attributes[i].type));
            check(opacket->encode_variable_opaque((const uint8_t *)attributes[i].value, attributes[i].length));
        }
    }
    check(opacket->encode_int(*state));
    check(opacket->encode_int(result_max));
    check(opacket->encode_variable_opaque(previous_uuid->uuid, sizeof(previous_uuid->uuid)));

    return HAL_OK;
}

hal_error_t pkey_remote_set_attributes(rpc_packet **packet, const hal_client_handle_t client,
                                       const hal_pkey_handle_t pkey,
                                       const hal_pkey_attribute_t *attributes,
                                       const unsigned attributes_len)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    size_t outbuf_len = nargs(4 + 2 * attributes_len);
    for (size_t i = 0; i < attributes_len; i++)
        outbuf_len += pad(attributes[i].length);

    rpc_packet *opacket = new rpc_packet(outbuf_len);
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_SET_ATTRIBUTES));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));
    check(opacket->encode_int(attributes_len));
    for (size_t i = 0; i < attributes_len; i++) {
        check(opacket->encode_int(attributes[i].type));
        if (attributes[i].length == HAL_PKEY_ATTRIBUTE_NIL)
            check(opacket->encode_int(HAL_PKEY_ATTRIBUTE_NIL));
        else
            check(opacket->encode_variable_opaque((const uint8_t *)attributes[i].value,
                                                  attributes[i].length));
    }

    return HAL_OK;
}

hal_error_t pkey_remote_get_attributes(rpc_packet **packet, const hal_client_handle_t client,
                                       const hal_pkey_handle_t pkey,
                                       const hal_pkey_attribute_t *attributes,
                                       const unsigned attributes_len,
                                       const uint8_t *attributes_buffer,
                                       const size_t attributes_buffer_len)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    /* inbuf[] here includes one extra word per attribute for padding */
    rpc_packet *opacket = new rpc_packet(nargs(5 + attributes_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_GET_ATTRIBUTES));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));
    check(opacket->encode_int(attributes_len));
    for (size_t i = 0; i < attributes_len; i++)
        check(opacket->encode_int(attributes[i].type));

    check(opacket->encode_int(attributes_buffer_len));

    return HAL_OK;
}

hal_error_t pkey_remote_export(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_pkey_handle_t pkey,
                               const hal_pkey_handle_t kekek,
                               const size_t pkcs8_max,
                               const size_t kek_max)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(6));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_EXPORT));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(pkey.handle));
    check(opacket->encode_int(kekek.handle));
    check(opacket->encode_int(pkcs8_max));
    check(opacket->encode_int(kek_max));

    return HAL_OK;
}

hal_error_t pkey_remote_import(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_session_handle_t session,
                               const hal_pkey_handle_t kekek,
                               const uint8_t * const pkcs8, const size_t pkcs8_len,
                               const uint8_t * const kek,   const size_t kek_len,
                               const hal_key_flags_t flags)
// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure
{
    rpc_packet *opacket = new rpc_packet(nargs(7) + pad(pkcs8_len) + pad(kek_len));
    *packet = opacket;

    check(opacket->encode_int(RPC_FUNC_PKEY_IMPORT));
    check(opacket->encode_int(client.handle));
    check(opacket->encode_int(session.handle));
    check(opacket->encode_int(kekek.handle));
    check(opacket->encode_variable_opaque(pkcs8, pkcs8_len));
    check(opacket->encode_variable_opaque(kek, kek_len));
    check(opacket->encode_int(flags));

    return HAL_OK;
}

}