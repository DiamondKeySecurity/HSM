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

enum KeyDBTypes
{
    KeyDBType_Int,
    KeyDBType_Boolean,
    KeyDBType_UUID,
    KeyDBType_Text,
    KeyDBType_Binary,
};

class keydb_shared
{
    public:
        keydb_shared()
        {
            // add mapping so we can take an incoming pkcs11 attribute and map it to SQL
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000000, "CKA_CLASS"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000001, "CKA_TOKEN"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000002, "CKA_PRIVATE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000003, "CKA_LABEL"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000082, "CKA_SERIAL_NUMBER"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000084, "CKA_OWNER"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000085, "CKA_ATTR_TYPES"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000086, "CKA_TRUSTED"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000100, "CKA_KEY_TYPE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000101, "CKA_SUBJECT"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000102, "CKA_ID"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000103, "CKA_SENSITIVE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000104, "CKA_ENCRYPT"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000105, "CKA_DECRYPT"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000106, "CKA_WRAP"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000107, "CKA_UNWRAP"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000108, "CKA_SIGN"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000109, "CKA_SIGN_RECOVER"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x0000010A, "CKA_VERIFY"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x0000010B, "CKA_VERIFY_RECOVER"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x0000010C, "CKA_DERIVE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000120, "CKA_MODULUS"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000121, "CKA_MODULUS_BITS"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000122, "CKA_PUBLIC_EXPONENT"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000162, "CKA_EXTRACTABLE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000170, "CKA_MODIFIABLE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000171, "CKA_COPYABLE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000172, "CKA_DESTROYABLE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000180, "CKA_EC_PARAMS"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000181, "CKA_EC_POINT"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000210, "CKA_WRAP_WITH_TRUSTED"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000110, "CKA_START_DATE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000111, "CKA_END_DATE"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000163, "CKA_LOCAL"));
            pkcs11attr_to_dbkey.insert(std::pair<uint32_t, std::string>(0x00000166, "CKA_KEY_GEN_MECHANISM"));


            // add mapping so we can take an incoming pkcs11 attribute and map it to SQL data type
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000000, KeyDBType_Int));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000001, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000002, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000003, KeyDBType_Text));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000082, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000084, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000085, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000086, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000100, KeyDBType_Int));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000101, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000102, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000103, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000104, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000105, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000106, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000107, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000108, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000109, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x0000010A, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x0000010B, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x0000010C, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000120, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000121, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000122, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000162, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000170, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000171, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000172, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000180, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000181, KeyDBType_Binary));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000210, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000110, KeyDBType_Text));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000111, KeyDBType_Text));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000163, KeyDBType_Boolean));
            db_attr_types.insert(std::pair<uint32_t, KeyDBTypes>(0x00000166, KeyDBType_Int));
        }

        const std::map<uint32_t, std::string> &get_pkcs11attr_to_dbkey() const
        {
            return pkcs11attr_to_dbkey;
        }

        const std::map<uint32_t, KeyDBTypes> &get_db_attr_types() const
        {
            return db_attr_types;
        }

    private:
        std::map<uint32_t, std::string> pkcs11attr_to_dbkey;
        std::map<uint32_t, KeyDBTypes> db_attr_types;
};

}

}

#endif