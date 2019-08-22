// Diamond Key Security, NFP Changes
// Copyright 2019 Diamond Key Security, NFP
// All rights reserved
/*
 * rpc_client.h
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

#ifndef HAL_RPC_CLIENT_H
#define HAL_RPC_CLIENT_H

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

// In Diamond Key's libhal, these functions only create the packet to be sent.
// The caller is reponsible for deleting the resulting packet even on failure

hal_error_t get_version(rpc_packet **packet, const hal_client_handle_t client);

hal_error_t get_random(rpc_packet **packet, const hal_client_handle_t client, const size_t length);

hal_error_t set_pin(rpc_packet **packet, const hal_client_handle_t client, const hal_user_t user,
                    const char * const pin, const size_t pin_len);

hal_error_t login(rpc_packet **packet, const hal_client_handle_t client, const hal_user_t user,
                  const char * const pin, const size_t pin_len);

hal_error_t logout(rpc_packet **packet, const hal_client_handle_t client);

hal_error_t logout_all(rpc_packet **packet, const hal_client_handle_t client);

hal_error_t check_tamper(rpc_packet **packet, const hal_client_handle_t client);

hal_error_t is_logged_in(rpc_packet **packet, const hal_client_handle_t client, const hal_user_t user);

hal_error_t hash_get_digest_len(rpc_packet **packet, const hal_client_handle_t client,
                                const hal_digest_algorithm_t alg);

hal_error_t hash_get_digest_algorithm_id(rpc_packet **packet, const hal_client_handle_t client,
                                         const hal_digest_algorithm_t alg, const size_t len_max);

hal_error_t hash_get_algorithm(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_hash_handle_t hash);

hal_error_t hash_initialize(rpc_packet **packet, const hal_client_handle_t client,
                            const hal_session_handle_t session,
                            const hal_digest_algorithm_t alg,
                            const uint8_t * const key, const size_t key_len);

hal_error_t hash_update(rpc_packet **packet, const hal_client_handle_t client,
                        const hal_hash_handle_t hash,
                        const uint8_t * data, const size_t length);

hal_error_t hash_finalize(rpc_packet **packet, const hal_client_handle_t client,
                          const hal_hash_handle_t hash, const size_t length);

hal_error_t pkey_remote_load(rpc_packet **packet, const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             const uint8_t * const der, const size_t der_len,
                             const hal_key_flags_t flags);

hal_error_t pkey_remote_open(rpc_packet **packet, const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             const hal_uuid_t * const name);

hal_error_t pkey_remote_generate_rsa(rpc_packet **packet, const hal_client_handle_t client,
                                     const hal_session_handle_t session,
                                     const unsigned key_len,
                                     const uint8_t * const exp, const size_t exp_len,
                                     const hal_key_flags_t flags);

hal_error_t pkey_remote_generate_ec(rpc_packet **packet, const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    const hal_curve_name_t curve,
                                    const hal_key_flags_t flags);

hal_error_t pkey_remote_generate_hashsig(rpc_packet **packet, const hal_client_handle_t client,
                                         const hal_session_handle_t session,
                                         const size_t hss_levels,
                                         const hal_lms_algorithm_t lms_type,
                                         const hal_lmots_algorithm_t lmots_type,
                                         const hal_key_flags_t flags);

hal_error_t pkey_remote_close(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey);

hal_error_t pkey_remote_delete(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey);

hal_error_t pkey_remote_get_key_type(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey);

hal_error_t pkey_remote_get_key_curve(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey);

hal_error_t pkey_remote_get_key_flags(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey);

size_t pkey_remote_get_public_key_len(rpc_packet **packet, const hal_client_handle_t client, const hal_pkey_handle_t pkey);

hal_error_t pkey_remote_get_public_key(rpc_packet **packet, const hal_client_handle_t client,
                                       const hal_pkey_handle_t pkey, const size_t der_max);

hal_error_t pkey_remote_sign(rpc_packet **packet, const hal_client_handle_t client,
                             const hal_pkey_handle_t pkey, const hal_hash_handle_t hash,
                             const uint8_t * const input, const size_t input_len, const size_t signature_max);

hal_error_t pkey_remote_verify(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_pkey_handle_t pkey, const hal_hash_handle_t hash,
                               const uint8_t * const input, const size_t input_len,
                               const uint8_t * const signature, const size_t signature_len);

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
                              const hal_uuid_t * const previous_uuid);

hal_error_t pkey_remote_set_attributes(rpc_packet **packet, const hal_client_handle_t client,
                                       const hal_pkey_handle_t pkey,
                                       const hal_pkey_attribute_t *attributes,
                                       const unsigned attributes_len);

hal_error_t pkey_remote_get_attributes(rpc_packet **packet, const hal_client_handle_t client,
                                       const hal_pkey_handle_t pkey,
                                       const hal_pkey_attribute_t *attributes,
                                       const unsigned attributes_len,
                                       const uint8_t *attributes_buffer,
                                       const size_t attributes_buffer_len);

hal_error_t pkey_remote_export(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_pkey_handle_t pkey,
                               const hal_pkey_handle_t kekek,
                               const size_t pkcs8_max,
                               const size_t kek_max);

hal_error_t pkey_remote_import(rpc_packet **packet, const hal_client_handle_t client,
                               const hal_session_handle_t session,
                               const hal_pkey_handle_t kekek,
                               const uint8_t * const pkcs8, const size_t pkcs8_len,
                               const uint8_t * const kek,   const size_t kek_len,
                               const hal_key_flags_t flags);

}

#endif
