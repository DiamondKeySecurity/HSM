#!/usr/bin/env python
#
# Copyright (c) 2018, Diamond Key Security, NFP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# -----------------------------------------------------------------------------
#  This file uses types defined in pkcs11t.h
#  The PKCS #11 License for that file follows:
#  pkcs11t.h include file for PKCS #11 V 2.30 - draft 1

#  License to copy and use this software is granted provided that it is
#  identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
#  (Cryptoki)" in all material mentioning or referencing this software.

#  License is also granted to make and use derivative works provided that
#  such works are identified as "derived from the RSA Security Inc. PKCS #11
#  Cryptographic Token Interface (Cryptoki)" in all material mentioning or
#  referencing the derived work.

#  RSA Security Inc. makes no representations concerning either the
#  merchantability of this software or the suitability of this software for
#  any particular purpose. It is provided "as is" without express or implied
#  warranty of any kind.
# -----------------------------------------------------------------------------
# This file uses tables from the PKCS #11 documentation.
# The copyright and licences follows:
# Copyright (c) OASIS Open 2015. All Rights Reserved.
#
# All capitalized terms in the following text have the meanings assigned to them
# in the OASIS Intellectual Property Rights Policy (the "OASIS IPR Policy").
# The full Policy may be found at the OASIS website.
#
# This document and translations of it may be copied and furnished to others,
# and derivative works that comment on or otherwise explain it or assist in its
# implementation may be prepared, copied, published, and distributed, in whole or
# in part, without restriction of any kind, provided that the above copyright notice
# and this section are included on all such copies and derivative works. However,
# this document itself may not be modified in any way, including by removing the
# copyright notice or references to OASIS, except as needed for the purpose of
# developing any document or deliverable produced by an OASIS Technical Committee
# (in which case the rules applicable to copyrights, as set forth in the OASIS IPR
# Policy, must be followed) or as required to translate it into languages other
# than English.
#
# The limited permissions granted above are perpetual and will not be revoked by
# OASIS or its successors or assigns.
#
# This document and the information contained herein is provided on an "AS IS" basis
# and OASIS DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY
# OWNERSHIP RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A
# PARTICULAR PURPOSE.
#
# OASIS requests that any OASIS Party or any other party that believes it has patent
# claims that would necessarily be infringed by implementations of this OASIS Committee
# Specification or OASIS Standard, to notify OASIS TC Administrator and provide an
# indication of its willingness to grant patent licenses to such patent claims in a
# manner consistent with the IPR Mode of the OASIS Technical Committee that produced
# this specification.
#
# OASIS invites any party to contact the OASIS TC Administrator if it is aware of a
# claim of ownership of any patent claims that would necessarily be infringed by
# implementations of this specification by a patent holder that is not willing to
# provide a license to such patent claims in a manner consistent with the IPR Mode
# of the OASIS Technical Committee that produced this specification. OASIS may
# include such claims on its website, but disclaims any obligation to do so.
#
# OASIS takes no position regarding the validity or scope of any intellectual property
# or other rights that might be claimed to pertain to the implementation or use of the
# technology described in this document or the extent to which any license under such
# rights might or might not be available; neither does it represent that it has made
# any effort to identify any such rights. Information on OASIS' procedures with respect
# to rights in any document or deliverable produced by an OASIS Technical Committee can
# be found on the OASIS website. Copies of claims of rights made available for
# publication and any assurances of licenses to be made available, or the result of an
# attempt made to obtain a general license or permission for the use of such proprietary
# rights by implementers or users of this OASIS Committee Specification or OASIS
# Standard, can be obtained from the OASIS TC Administrator. OASIS makes no
# representation that any information or list of intellectual property rights will at
# any time be complete, or that any claims in such list are, in fact, Essential Claims.
#
# The name "OASIS" is a trademark of OASIS, the owner and developer of this specification,
# and should be used only to refer to the organization and its official outputs. OASIS
# welcomes reference to, and implementation and use of, specifications, while reserving
# the right to enforce its marks against misleading uses.
# Please see https://www.oasis-open.org/policies-guidelines/trademark for above guidance.
# -----------------------------------------------------------------------------

from enum import IntEnum


# The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
# consists of an array of values.
CKF_ARRAY_ATTRIBUTE    = 0x40000000

# The following attribute types are defined:
# encodings can change based on the type of certificate. For example,
# WTLS public key certificates use WTLS-encoding (identifier type).
# See PKCS #11 for specific encodings used.
class CKA(IntEnum):
    CKA_CLASS                       = 0x00000000
    CKA_TOKEN                       = 0x00000001
    CKA_PRIVATE                     = 0x00000002
    CKA_LABEL                       = 0x00000003
    CKA_APPLICATION                 = 0x00000010

    # BER-encoding of the certificate.
    CKA_VALUE                       = 0x00000011

    CKA_OBJECT_ID                   = 0x00000012

    # Type of certificate
    CKA_CERTIFICATE_TYPE            = 0x00000080

    # DER-encoding of the certificate issuer name (default empty)
    CKA_ISSUER                      = 0x00000081

    # DER-encoding of the certificate serial number. (default empty)
    CKA_SERIAL_NUMBER               = 0x00000082

    # DER-encoding of the attribute certificate's issuer field.
    # This is distinct from the CKA_ISSUER attribute contained
    # in CKC_X_509 certificates because the ASN.1 syntax and
    # encoding are different. (default empty)
    CKA_AC_ISSUER                   = 0x00000083

    # DER-encoding of the attribute certificate's subject field.
    # This is distinct from the CKA_SUBJECT attribute contained
    # in CKC_X_509 certificates because the ASN.1 syntax and
    # encoding are different.
    CKA_OWNER                       = 0x00000084

    # BER-encoding of a sequence of object identifier values
    # corresponding to the attribute types contained in the
    # certificate. When present, this field offers an opportunity
    # for applications to search for a particular attribute
    # certificate without fetching and parsing the certificate
    # itself. (default empty)
    CKA_ATTR_TYPES                  = 0x00000085

    # The certificate can be trusted for the application that it
    # was created.
    # The wrapping key can be used to wrap keys with
    # CKA_WRAP_WITH_TRUSTED set to CK_TRUE.
    CKA_TRUSTED                     = 0x00000086

    # (default CK_CERTIFICATE_CATEGORY_UNSPECIFIED)
    CKA_CERTIFICATE_CATEGORY        = 0x00000087

    # Java MIDP security domain.  (default CK_SECURITY_DOMAIN_UNSPECIFIED)
    CKA_JAVA_MIDP_SECURITY_DOMAIN   = 0x00000088

    # If not empty this attribute gives the URL where the complete
    # certificate can be obtained  (default empty)
    CKA_URL                         = 0x00000089

    # Hash of the subject public key (default empty). Hash algorithm
    # is defined by CKA_NAME_HASH_ALGORITHM
    CKA_HASH_OF_SUBJECT_PUBLIC_KEY  = 0x0000008A

    # Hash of the issuer public key (default empty). Hash algorithm
    # is defined by CKA_NAME_HASH_ALGORITHM
    CKA_HASH_OF_ISSUER_PUBLIC_KEY   = 0x0000008B

    # Defines the mechanism used to calculate CKA_HASH_OF_SUBJECT_PUBLIC_KEY
    # and CKA_HASH_OF_ISSUER_PUBLIC_KEY. If the attribute is not present then
    # the type defaults to SHA-1.
    CKA_NAME_HASH_ALGORITHM         = 0x0000008C

    # Checksum
    CKA_CHECK_VALUE                 = 0x00000090

    CKA_KEY_TYPE                    = 0x00000100

    # DER-encoding of the certificate subject name
    CKA_SUBJECT                     = 0x00000101

    # Key identifier for public/private key pair (default empty)
    CKA_ID                          = 0x00000102

    # CK_TRUE if key is sensitive
    CKA_SENSITIVE                   = 0x00000103

    # CK_TRUE if key supports encryption
    CKA_ENCRYPT                     = 0x00000104

    # CK_TRUE if key supports decryption
    CKA_DECRYPT                     = 0x00000105

    # CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)
    CKA_WRAP                        = 0x00000106

    # CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)
    CKA_UNWRAP                      = 0x00000107

    # CK_TRUE if key supports signatures where the signature is an appendix to the data
    CKA_SIGN                        = 0x00000108

    # CK_TRUE if key supports signatures where the data can be recovered from the signature
    CKA_SIGN_RECOVER                = 0x00000109

    # CK_TRUE if key supports verification where the signature
    # is an appendix to the data
    CKA_VERIFY                      = 0x0000010A

    # CK_TRUE if key supports verification where the data is
    # recovered from the signature
    CKA_VERIFY_RECOVER              = 0x0000010B

    # CK_TRUE if key supports key derivation (i.e., if other keys
    # can be derived from this one (default CK_FALSE)
    CKA_DERIVE                      = 0x0000010C

    # Start date for the certificate (default empty)
    CKA_START_DATE                  = 0x00000110

    # End date for the certificate (default empty)
    CKA_END_DATE                    = 0x00000111

    # -------------------------------------------------------------
    # RSA private key objects (object class CKO_PRIVATE_KEY, key 
    # type CKK_RSA) hold RSA private keys.  The following table
    # defines the RSA private key object attributes, in addition
    # to the common attributes defined for this object class:

    # Modulus n
    CKA_MODULUS                     = 0x00000120
    CKA_MODULUS_BITS                = 0x00000121

    # Public exponent e
    CKA_PUBLIC_EXPONENT             = 0x00000122

    # Private exponent d
    CKA_PRIVATE_EXPONENT            = 0x00000123

    # Prime p
    CKA_PRIME_1                     = 0x00000124

    # Prime q
    CKA_PRIME_2                     = 0x00000125

    # Private exponent d modulo p-1
    CKA_EXPONENT_1                  = 0x00000126

    # Private exponent d modulo q-1
    CKA_EXPONENT_2                  = 0x00000127

    # CRT coefficient q-1 mod p 
    CKA_COEFFICIENT                 = 0x00000128
    # -------------------------------------------------------------

    # DER-encoding of the SubjectPublicKeyInfo for the public key
    # contained in this certificate (default empty)
    CKA_PUBLIC_KEY_INFO             = 0x00000129

    CKA_PRIME                       = 0x00000130
    CKA_SUBPRIME                    = 0x00000131
    CKA_BASE                        = 0x00000132

    CKA_PRIME_BITS                  = 0x00000133
    CKA_SUBPRIME_BITS               = 0x00000134

    CKA_VALUE_BITS                  = 0x00000160
    CKA_VALUE_LEN                   = 0x00000161

    # CK_TRUE if key is extractable and can be wrapped
    CKA_EXTRACTABLE                 = 0x00000162

    # CK_TRUE only if key was either
    #  - generated locally (i.e., on the token) with a
    #    C_GenerateKey or C_GenerateKeyPair call
    #  - created with a C_CopyObject call as a copy of
    #    a key which had its CKA_LOCAL attribute set to CK_TRUE
    CKA_LOCAL                       = 0x00000163

    # CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE
    CKA_NEVER_EXTRACTABLE           = 0x00000164

    # CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE
    CKA_ALWAYS_SENSITIVE            = 0x00000165

    # Identifier of the mechanism used to generate the key material.
    CKA_KEY_GEN_MECHANISM           = 0x00000166

    CKA_MODIFIABLE                  = 0x00000170
    CKA_COPYABLE                    = 0x00000171
    CKA_DESTROYABLE                 = 0x00000172
  
    CKA_EC_PARAMS                   = 0x00000180

    CKA_EC_POINT                    = 0x00000181

    # If CK_TRUE, the user has to supply the PIN for each use (sign or decrypt)
    # with the key. Default is CK_FALSE.
    CKA_ALWAYS_AUTHENTICATE         = 0x00000202

    # CK_TRUE if the key can only be wrapped with a wrapping key that has
    # CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE.
    CKA_WRAP_WITH_TRUSTED           = 0x00000210

    # For wrapping keys. The attribute template to match against any keys
    # wrapped using this wrapping key. Keys that do not match cannot be
    # wrapped. The number of attributes in the array is the ulValueLen
    # component of the attribute divided by the size of CK_ATTRIBUTE.
    CKA_WRAP_TEMPLATE               = (CKF_ARRAY_ATTRIBUTE | 0x00000211)

    # For wrapping keys. The attribute template to apply to any keys
    # unwrapped using this wrapping key. Any user supplied template is
    # applied after this template as if the object has already been created.
    # The number of attributes in the array is the ulValueLen component of
    # the attribute divided by the size of CK_ATTRIBUTE.
    CKA_UNWRAP_TEMPLATE             = (CKF_ARRAY_ATTRIBUTE | 0x00000212)

    CKA_DERIVE_TEMPLATE             = (CKF_ARRAY_ATTRIBUTE | 0x00000213)

    CKA_OTP_FORMAT                 = 0x00000220
    CKA_OTP_LENGTH                 = 0x00000221
    CKA_OTP_TIME_INTERVAL          = 0x00000222
    CKA_OTP_USER_FRIENDLY_MODE     = 0x00000223
    CKA_OTP_CHALLENGE_REQUIREMENT  = 0x00000224
    CKA_OTP_TIME_REQUIREMENT       = 0x00000225
    CKA_OTP_COUNTER_REQUIREMENT    = 0x00000226
    CKA_OTP_PIN_REQUIREMENT        = 0x00000227
    CKA_OTP_COUNTER                = 0x0000022E
    CKA_OTP_TIME                   = 0x0000022F
    CKA_OTP_USER_IDENTIFIER        = 0x0000022A
    CKA_OTP_SERVICE_IDENTIFIER     = 0x0000022B
    CKA_OTP_SERVICE_LOGO           = 0x0000022C
    CKA_OTP_SERVICE_LOGO_TYPE      = 0x0000022D

    CKA_GOSTR3410_PARAMS           = 0x00000250
    CKA_GOSTR3411_PARAMS           = 0x00000251
    CKA_GOST28147_PARAMS           = 0x00000252

    CKA_HW_FEATURE_TYPE            = 0x00000300
    CKA_RESET_ON_INIT              = 0x00000301
    CKA_HAS_RESET                  = 0x00000302

    CKA_PIXEL_X                    = 0x00000400
    CKA_PIXEL_Y                    = 0x00000401
    CKA_RESOLUTION                 = 0x00000402
    CKA_CHAR_ROWS                  = 0x00000403
    CKA_CHAR_COLUMNS               = 0x00000404
    CKA_COLOR                      = 0x00000405
    CKA_BITS_PER_PIXEL             = 0x00000406
    CKA_CHAR_SETS                  = 0x00000480
    CKA_ENCODING_METHODS           = 0x00000481
    CKA_MIME_TYPES                 = 0x00000482
    CKA_MECHANISM_TYPE             = 0x00000500
    CKA_REQUIRED_CMS_ATTRIBUTES    = 0x00000501
    CKA_DEFAULT_CMS_ATTRIBUTES     = 0x00000502
    CKA_SUPPORTED_CMS_ATTRIBUTES   = 0x00000503

    # A list of mechanisms allowed to be used with this key. The number
    # of mechanisms in the array is the ulValueLen component of the
    # attribute divided by the size of CK_MECHANISM_TYPE.
    CKA_ALLOWED_MECHANISMS         = (CKF_ARRAY_ATTRIBUTE|0x00000600)

    # CKA_VENDOR_DEFINED             = 0x80000000

    @classmethod
    def nonsyncd_attributes(cls):
        # list of attributes to not retrieve from the HSM for cache
        return [cls.CKA_WRAP_TEMPLATE,
                cls.CKA_UNWRAP_TEMPLATE,
                cls.CKA_DERIVE_TEMPLATE,
                cls.CKA_HW_FEATURE_TYPE,
                cls.CKA_RESET_ON_INIT,
                cls.CKA_HAS_RESET,
                cls.CKA_PIXEL_X,
                cls.CKA_PIXEL_Y,
                cls.CKA_RESOLUTION,
                cls.CKA_CHAR_ROWS,
                cls.CKA_CHAR_COLUMNS,
                cls.CKA_COLOR,
                cls.CKA_BITS_PER_PIXEL,
                cls.CKA_CHAR_SETS,
                cls.CKA_ENCODING_METHODS,
                cls.CKA_MIME_TYPES,
                cls.CKA_MECHANISM_TYPE,
                cls.CKA_REQUIRED_CMS_ATTRIBUTES,
                cls.CKA_DEFAULT_CMS_ATTRIBUTES,
                cls.CKA_SUPPORTED_CMS_ATTRIBUTES,
                cls.CKA_ALLOWED_MECHANISMS,
                cls.CKA_PRIVATE_EXPONENT,
                cls.CKA_PRIME_1,
                cls.CKA_PRIME_2,
                cls.CKA_EXPONENT_1,
                cls.CKA_EXPONENT_2,
                cls.CKA_COEFFICIENT,
                cls.CKA_PUBLIC_KEY_INFO,
                cls.CKA_PRIME,
                cls.CKA_SUBPRIME,
                cls.CKA_BASE,
                cls.CKA_PRIME_BITS,
                cls.CKA_SUBPRIME_BITS,
                cls.CKA_VALUE_BITS,
                cls.CKA_VALUE_LEN
                ]

    @classmethod
    def optional_attributes(cls):
        # list of attributes to copy if not zero
        return [cls.CKA_ISSUER,
                cls.CKA_SERIAL_NUMBER,
                cls.CKA_AC_ISSUER,
                cls.CKA_URL,
                cls.CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
                cls.CKA_HASH_OF_ISSUER_PUBLIC_KEY,
                cls.CKA_START_DATE,
                cls.CKA_END_DATE,
                cls.CKA_PUBLIC_KEY_INFO,
                cls.CKA_OTP_FORMAT,
                cls.CKA_OTP_LENGTH,
                cls.CKA_OTP_TIME_INTERVAL,
                cls.CKA_OTP_USER_FRIENDLY_MODE,
                cls.CKA_OTP_CHALLENGE_REQUIREMENT,
                cls.CKA_OTP_TIME_REQUIREMENT,
                cls.CKA_OTP_COUNTER_REQUIREMENT,
                cls.CKA_OTP_PIN_REQUIREMENT,
                cls.CKA_OTP_COUNTER,
                cls.CKA_OTP_TIME,
                cls.CKA_OTP_USER_IDENTIFIER,
                cls.CKA_OTP_SERVICE_IDENTIFIER,
                cls.CKA_OTP_SERVICE_LOGO,
                cls.CKA_OTP_SERVICE_LOGO_TYPE,
                cls.CKA_GOSTR3410_PARAMS,
                cls.CKA_GOSTR3411_PARAMS,
                cls.CKA_GOST28147_PARAMS
                ]

    @classmethod
    def cached_attributes(cls):
        all_elements = [e for e in cls]
        exclude = cls.nonsyncd_attributes()
        optional = cls.optional_attributes()

        # return a list that doesn't have the elements we have explicitly stated to not include
        return [x.value for x in all_elements if (x not in exclude and x not in optional)]

    @classmethod
    def keydb_attributes(cls):
        return [cls.CKA_CLASS,
                cls.CKA_TOKEN,
                cls.CKA_PRIVATE,
                cls.CKA_LABEL,
                cls.CKA_SERIAL_NUMBER,
                cls.CKA_OWNER,
                cls.CKA_ATTR_TYPES,
                cls.CKA_TRUSTED,
                cls.CKA_KEY_TYPE,
                cls.CKA_SUBJECT,
                cls.CKA_ID,
                cls.CKA_SENSITIVE,
                cls.CKA_ENCRYPT,
                cls.CKA_DECRYPT,
                cls.CKA_WRAP,
                cls.CKA_UNWRAP,
                cls.CKA_SIGN,
                cls.CKA_SIGN_RECOVER,
                cls.CKA_VERIFY,
                cls.CKA_VERIFY_RECOVER,
                cls.CKA_DERIVE,
                cls.CKA_MODULUS,
                cls.CKA_MODULUS_BITS,
                cls.CKA_PUBLIC_EXPONENT,
                cls.CKA_EXTRACTABLE,
                cls.CKA_MODIFIABLE,
                cls.CKA_COPYABLE,
                cls.CKA_DESTROYABLE,
                cls.CKA_EC_PARAMS,
                cls.CKA_EC_POINT,
                cls.CKA_WRAP_WITH_TRUSTED]

# The defines the attributes common to all objects.
# Attribute             Data Type              Meaning
# ------------------------------------------------------------------------------------
# CKA_CLASS             CK_OBJECT_CLASS        Object class (type)

# ***
# Storage Objects
# This is not an object class; hence no CKO_ definition is required. It is a category
# of object classes with common attributes for the object classes that follow.
#
# Attribute             Data Type              Meaning
# ------------------------------------------------------------------------------------
# CKA_TOKEN             CK_BBOOL               CK_TRUE if object is a token object;
#                                              CK_FALSE if object is a session object.
#                                              Default is CK_FALSE.
# CKA_PRIVATE           CK_BBOOL               CK_TRUE if object is a private object;
#                                              CK_FALSE if object is a public object.
#                                              Default value is token-specific, and may
#                                              depend on the values of other attributes
#                                              of the object.
# CKA_MODIFIABLE        CK_BBOOL               CK_TRUE if object can be modified Default
#                                              is CK_TRUE.
# CKA_LABEL             RFC2279 string         Description of the object (default empty).
# CKA_COPYABLE          CK_BBOOL               CK_TRUE if object can be copied using
#                                              C_CopyObject. Defaults to CK_TRUE. Can't
#                                              be set to TRUE once it is set to FALSE.
# CKA_DESTROYABLE       CK_BBOOL               CK_TRUE if the object can be destroyed
#                                              using C_DestroyObject.  Default is CK_TRUE.

# ***
# Data Objects
# Data objects (object class CKO_DATA) hold information defined by an application.
# Other than providing access to it, Cryptoki does not attach any special meaning
# to a data object. The following table lists the attributes supported by data objects,
# in addition to the common attributes defined for this object class:
#
# Attribute             Data Type              Meaning
# ------------------------------------------------------------------------------------
# CKA_APPLICATION       RFC2279 string         Description of the application that manages
#                                              the object (default empty)
# CKA_OBJECT_ID         Byte Array             DER-encoding of the object identifier
#                                              indicating the data object type (default empty)
# CKA_VALUE             Byte array             Value of the object (default empty)

# ***
# Certificate objects
# Certificate objects (object class CKO_CERTIFICATE) hold public-key or attribute
# certificates. Other than providing access to certificate objects, Cryptoki does not
# attach any special meaning to certificates. The following table defines the common
# certificate object attributes, in addition to the common attributes defined for this object class:
#
# Attribute                  Data Type                 Meaning
# ------------------------------------------------------------------------------------
# CKA_CERTIFICATE_TYPE       CK_CERTIFICATE_TYPE       Type of certificate
# CKA_TRUSTED                CK_BBOOL                  The certificate can be trusted for the
#                                                      application that it was created.
# CKA_CERTIFICATE_CATEGORY   CKA_CERTIFICATE_CATEGORY  (default CK_CERTIFICATE_CATEGORY_UNSPECIFIED)
# CKA_CHECK_VALUE            Byte array                Checksum
# CKA_START_DATE             CK_DATE                   Start date for the certificate (default empty)
# CKA_END_DATE               CK_DATE                   End date for the certificate (default empty)
# CKA_PUBLIC_KEY_INFO        Byte Array                DER-encoding of the SubjectPublicKeyInfo for the
#                                                      public key contained in this certificate (default empty)

# X.509 public key certificate objects
# X.509 certificate objects (certificate type CKC_X_509) hold X.509 public key certificates.
# The following table defines the X.509 certificate object attributes, in addition to the common
# attributes defined for this object class
#
# Attribute                       Data Type            Meaning
# ------------------------------------------------------------------------------------
# CKA_SUBJECT                     Byte array           DER-encoding of the certificate subject name
# CKA_ID                          Byte array           Key identifier for public/private key pair (default empty)
# CKA_ISSUER                      Byte array           DER-encoding of the certificate issuer name (default empty)
# CKA_SERIAL_NUMBER               Byte array           DER-encoding of the certificate serial number (default empty)
# CKA_VALUE                       Byte array           BER-encoding of the certificate
# CKA_URL                         RFC2279 string       If not empty this attribute gives the URL where the complete
#                                                      certificate can be obtained  (default empty)
# CKA_HASH_OF_SUBJECT_PUBLIC_KEY  Byte array           Hash of the subject public key (default empty). Hash algorithm
#                                                      is defined by CKA_NAME_HASH_ALGORITHM
# CKA_HASH_OF_ISSUER_PUBLIC_KEY   Byte array           Hash of the issuer public key (default empty). Hash algorithm is
#                                                      defined by CKA_NAME_HASH_ALGORITHM
# CKA_JAVA_MIDP_SECURITY_DOMAIN   CK_JAVA_MIDP_SECURITY_DOMAIN    Java MIDP security domain.
#                                                                 (default CK_SECURITY_DOMAIN_UNSPECIFIED)
# CKA_NAME_HASH_ALGORITHM         CK_MECHANISM_TYPE    Defines the mechanism used to calculate
#                                                      CKA_HASH_OF_SUBJECT_PUBLIC_KEY and CKA_HASH_OF_ISSUER_PUBLIC_KEY.
#                                                      If the attribute is not present then the type defaults to SHA-1.

# WTLS public key certificate objects
# WTLS certificate objects (certificate type CKC_WTLS) hold WTLS public key certificates. The
# following table defines the WTLS certificate object attributes, in addition to the common
# attributes defined for this object class.
#
# Attribute                       Data Type            Meaning
# ------------------------------------------------------------------------------------
# CKA_SUBJECT                     Byte array           WTLS-encoding (Identifier type) of the certificate subject
# CKA_ISSUER                      Byte array           WTLS-encoding (Identifier type) of the certificate issuer (default empty)
# CKA_VALUE                       Byte array           WTLS-encoding of the certificate
# CKA_URL                         RFC2279 string       If not empty this attribute gives the URL where the complete
#                                                      certificate can be obtained
# CKA_HASH_OF_SUBJECT_PUBLIC_KEY  Byte array           SHA-1 hash of the subject public key (default empty). Hash algorithm
#                                                      is defined by CKA_NAME_HASH_ALGORITHM
# CKA_HASH_OF_ISSUER_PUBLIC_KEY   Byte array           SHA-1 hash of the issuer public key (default empty). Hash algorithm is
#                                                      defined by CKA_NAME_HASH_ALGORITHM
# CKA_NAME_HASH_ALGORITHM         CK_MECHANISM_TYPE    Defines the mechanism used to calculate CKA_HASH_OF_SUBJECT_PUBLIC_KEY
#                                                      and CKA_HASH_OF_ISSUER_PUBLIC_KEY. If the attribute is not present then
#                                                      the type defaults to SHA-1.

# X.509 attribute certificate objects
# X.509 attribute certificate objects (certificate type CKC_X_509_ATTR_CERT) hold
# X.509 attribute certificates. The following table defines the X.509 attribute
# certificate object attributes, in addition to the common attributes defined
# for this object class:
#
# Attribute                       Data Type            Meaning
# ------------------------------------------------------------------------------------
# CKA_OWNER                       Byte Array           DER-encoding of the attribute certificate's
#                                                      subject field. This is distinct from the
#                                                      CKA_SUBJECT attribute contained in CKC_X_509
#                                                      certificates because the ASN.1 syntax and
#                                                      encoding are different.
# CKA_AC_ISSUER                   Byte Array           DER-encoding of the attribute certificate's
#                                                      issuer field. This is distinct from the
#                                                      CKA_ISSUER attribute contained in CKC_X_509
#                                                      certificates because the ASN.1 syntax and
#                                                      encoding are different. (default empty)
# CKA_SERIAL_NUMBER               Byte Array           DER-encoding of the certificate serial number.
#                                                      (default empty)
# CKA_ATTR_TYPES                  Byte Array           BER-encoding of a sequence of object identifier
#                                                      values corresponding to the attribute types
#                                                      contained in the certificate. When present, this
#                                                      field offers an opportunity for applications to
#                                                      search for a particular attribute certificate
#                                                      without fetching and parsing the certificate
#                                                      itself. (default empty)
# CKA_VALUE                       Byte Array           BER-encoding of the certificate.

# Key objects
# Key objects hold encryption or authentication keys, which can be public keys,
# private keys, or secret keys.  The following common footnotes apply to all the
# tables describing attributes of keys:
# The following table defines the attributes common to public key, private key and secret
# key classes, in addition to the common attributes defined for this object class:
#
# Attribute                       Data Type                Meaning
# ------------------------------------------------------------------------------------
# CKA_KEY_TYPE                    CK_KEY_TYPE              Type of key
# CKA_ID                          Byte array               Key identifier for key (default empty)
# CKA_START_DATE                  CK_DATE                  Start date for the key (default empty)
# CKA_END_DATE                    CK_DATE                  End date for the key (default empty)
# CKA_DERIVE                      CK_BBOOL                 CK_TRUE if key supports key derivation
#                                                          (i.e., if other keys can be derived from
#                                                          this one (default CK_FALSE)
# CKA_LOCAL                       CK_BBOOL                 CK_TRUE only if key was either
#                                                          - generated locally (i.e., on the token)
#                                                            with a C_GenerateKey or C_GenerateKeyPair call
#                                                          - created with a C_CopyObject call as a copy of
#                                                            a key which had its CKA_LOCAL attribute set to CK_TRUE
# CKA_KEY_GEN_MECHANISM           CK_MECHANISM_TYPE        Identifier of the mechanism used to generate the key material.
# CKA_ALLOWED_MECHANISMS          CK_MECHANISM_TYPE_PTR,   A list of mechanisms allowed to be used with this key.
#                                 pointer to a             The number of mechanisms in the array is the ulValueLen 
#                                 CK_MECHANISM_TYPE array  component of the attribute divided by the size of CK_MECHANISM_TYPE.

# Public key objects
# Public key objects (object class CKO_PUBLIC_KEY) hold public keys. The following table
# defines the attributes common to all public keys, in addition to the common attributes
# defined for this object class:
#
# Attribute                       Data Type                Meaning
# ------------------------------------------------------------------------------------
# CKA_SUBJECT                     Byte array               DER-encoding of the key subject name (default empty)
# CKA_ENCRYPT                     CK_BBOOL                 CK_TRUE if key supports encryption
# CKA_VERIFY                      CK_BBOOL                 CK_TRUE if key supports verification where the signature
#                                                          is an appendix to the data
# CKA_VERIFY_RECOVER              CK_BBOOL                 CK_TRUE if key supports verification where the data is
#                                                          recovered from the signature
# CKA_WRAP                        CK_BBOOL                 CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)
# CKA_TRUSTED                     CK_BBOOL                 The key can be trusted for the application that it was
#                                                          created. The wrapping key can be used to wrap keys with
#                                                          CKA_WRAP_WITH_TRUSTED set to CK_TRUE.
# CKA_WRAP_TEMPLATE               CK_ATTRIBUTE_PTR         For wrapping keys. The attribute template to match against
#                                                          any keys wrapped using this wrapping key. Keys that do not
#                                                          match cannot be wrapped. The number of attributes in the
#                                                          array is the ulValueLen component of the attribute divided
#                                                          by the size of CK_ATTRIBUTE.
# CKA_PUBLIC_KEY_INFO             Byte array               DER-encoding of the SubjectPublicKeyInfo for this public key.
#                                                          (MAY be empty, DEFAULT derived from the underlying public key data)

# Private key objects
# Private key objects (object class CKO_PRIVATE_KEY) hold private keys. The following table
# defines the attributes common to all private keys, in addition to the common attributes
# defined for this object class:
#
# Attribute                       Data Type                Meaning
# ------------------------------------------------------------------------------------
# CKA_SUBJECT                     Byte array               DER-encoding of certificate subject name (default empty)
# CKA_SENSITIVE                   CK_BBOOL                 CK_TRUE if key is sensitive
# CKA_DECRYPT                     CK_BBOOL                 CK_TRUE if key supports decryption
# CKA_SIGN                        CK_BBOOL                 CK_TRUE if key supports signatures where the signature is an appendix to the data
# CKA_SIGN_RECOVER                CK_BBOOL                 CK_TRUE if key supports signatures where the data can be recovered from the signature
# CKA_UNWRAP                      CK_BBOOL                 CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)
# CKA_EXTRACTABLE                 CK_BBOOL                 CK_TRUE if key is extractable and can be wrapped
# CKA_ALWAYS_SENSITIVE            CK_BBOOL                 CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE
# CKA_NEVER_EXTRACTABLE           CK_BBOOL                 CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE
# CKA_WRAP_WITH_TRUSTED           CK_BBOOL                 CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE.
# CKA_UNWRAP_TEMPLATE             CK_ATTRIBUTE_PTR         For wrapping keys. The attribute template to apply to any keys unwrapped using this wrapping key. Any user supplied template is applied after this template as if the object has already been created. The number of attributes in the array is the ulValueLen component of the attribute divided by the size of CK_ATTRIBUTE.
# CKA_ALWAYS_AUTHENTICATE         CK_BBOOL                 If CK_TRUE, the user has to supply the PIN for each use (sign or decrypt) with the key. Default is CK_FALSE.
# CKA_PUBLIC_KEY_INFO             Byte Array               DER-encoding of the SubjectPublicKeyInfo for the associated public key (MAY be empty; DEFAULT derived from the underlying private key data; MAY be manually set for specific key types; if set; MUST be consistent with the underlying private key data)

# RSA private key objects
# RSA private key objects (object class CKO_PRIVATE_KEY, key type CKK_RSA) hold RSA private keys.
# The following table defines the RSA private key object attributes, in addition to the common
# attributes defined for this object class:
#
# Attribute                       Data Type                Meaning
# ------------------------------------------------------------------------------------
# CKA_MODULUS                     Big integer              Modulus n
# CKA_PUBLIC_EXPONENT             Big integer              Public exponent e
# CKA_PRIVATE_EXPONENT            Big integer              Private exponent d
# CKA_PRIME_1                     Big integer              Prime p
# CKA_PRIME_2                     Big integer              Prime q
# CKA_EXPONENT_1                  Big integer              Private exponent d modulo p-1
# CKA_EXPONENT_2                  Big integer              Private exponent d modulo q-1
# CKA_COEFFICIENT                 Big integer              CRT coefficient q-1 mod p 

# Secret key objects
# Secret key objects (object class CKO_SECRET_KEY) hold secret keys. The following table
# defines the attributes common to all secret keys, in addition to the common attributes
# defined for this object class:
#
# Attribute                       Data Type                Meaning
# ------------------------------------------------------------------------------------
# CKA_SENSITIVE                   CK_BBOOL                 CK_TRUE if object is sensitive (default CK_FALSE)
# CKA_ENCRYPT                     CK_BBOOL                 CK_TRUE if key supports encryption
# CKA_DECRYPT                     CK_BBOOL                 CK_TRUE if key supports decryption
# CKA_SIGN                        CK_BBOOL                 CK_TRUE if key supports signatures (i.e.,
#                                                          authentication codes) where the signature is an
#                                                          appendix to the data
# CKA_VERIFY                      CK_BBOOL                 CK_TRUE if key supports verification (i.e., of 
#                                                          authentication codes) where the signature is an appendix to the data
# CKA_WRAP                        CK_BBOOL                 CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)
# CKA_UNWRAP                      CK_BBOOL                 CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)
# CKA_EXTRACTABLE                 CK_BBOOL                 CK_TRUE if key is extractable and can be wrapped
# CKA_ALWAYS_SENSITIVE            CK_BBOOL                 CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE
# CKA_NEVER_EXTRACTABLE           CK_BBOOL                 CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE
# CKA_CHECK_VALUE                 Byte array               Key checksum
# CKA_WRAP_WITH_TRUSTED           CK_BBOOL                 CK_TRUE if the key can only be wrapped with a wrapping key that has
#                                                          CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE.
# CKA_TRUSTED                     CK_BBOOL                 The wrapping key can be used to wrap keys with  CKA_WRAP_WITH_TRUSTED set to CK_TRUE.
# CKA_WRAP_TEMPLATE               CK_ATTRIBUTE_PTR         For wrapping keys. The attribute template to match against any keys wrapped
#                                                          using this wrapping key. Keys that do not match cannot be wrapped. The number
#                                                          of attributes in the array is the ulValueLen component of the attribute
#                                                          divided by the size of CK_ATTRIBUTE
# CKA_UNWRAP_TEMPLATE             CK_ATTRIBUTE_PTR         For wrapping keys. The attribute template to apply to any keys unwrapped
#                                                          using this wrapping key. Any user supplied template is applied after this
#                                                          template as if the object has already been created. The number of attributes
#                                                          in the array is the ulValueLen component of the attribute divided by the size
#                                                          of CK_ATTRIBUTE.
