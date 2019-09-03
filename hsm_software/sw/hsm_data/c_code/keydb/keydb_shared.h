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
#ifndef KEYDB_SHARED_HEADER
#define KEYDB_SHARED_HEADER

#include <string>
#include <map>

namespace diamond_hsm
{
namespace keydb
{

class keydb_shared
{
    public:
        keydb_shared()
        {
            pkcs11attr_to_dbkey.insert(std::pait<uint32_t, std::string>());

        CKA_CLASS,
        CKA_TOKEN,
        CKA_PRIVATE,
        CKA_LABEL,
        CKA_SERIAL_NUMBER,
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
                cls.CKA_LOCAL,
                cls.CKA_MODIFIABLE,
                cls.CKA_COPYABLE,
                cls.CKA_DESTROYABLE,
                cls.CKA_EC_PARAMS,
                cls.CKA_EC_POINT,
                cls.CKA_WRAP_WITH_TRUSTED]

        }

        const std::map<uint32_t, std::string> &get_pkcs11attr_to_dbkey() const
        {
            return pkcs11attr_to_dbkey;
        }

    private:
        std::map<uint32_t, std::string> pkcs11attr_to_dbkey;
};

}

}

#endif