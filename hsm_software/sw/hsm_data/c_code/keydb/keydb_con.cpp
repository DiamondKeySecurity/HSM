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
#include <string>
#include <vector>
#include <memory>
#include <sstream>

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

#include "keydb_con.h"
#include "keydb_shared.h"


namespace diamond_hsm
{
namespace keydb
{

keydb_con::keydb_con(std::shared_ptr<::sql::Connection> con, const keydb_shared *shared_data)
:con(con), shared_data(shared_data)
{
}

hal_error_t keydb_con::add_key(const uuids::uuid_t master_uuid, const uint32_t key_type, const uint32_t key_flags, const uint32_t curve)
{
    // prepare the UUID for the sql stmt
    std::vector<unsigned char> convertedID;
    master_uuid.get_bytes_vector(convertedID);
    std::stringstream uuid_blob_stream(std::string(convertedID.begin(), convertedID.end()));

    std::unique_ptr<sql::PreparedStatement> pstmt;
    
    try
    {
        pstmt.reset(con->prepareStatement("INSERT INTO domainkeys (uuid, uuid_str, key_type, key_flags, curve) VALUES (?,?,?,?,?);"));
        pstmt->setBlob(1, &uuid_blob_stream);
        pstmt->setString(2, (std::string)master_uuid);
        pstmt->setInt(3, (int)key_type);
        pstmt->setInt(4, (int)key_flags);
        pstmt->setInt(5, (int)curve);
        pstmt->executeUpdate();
    }
    catch(sql::SQLException &e)
    {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;

        return HAL_ERROR_ALLOCATION_FAILURE;
    }

    return HAL_OK;
}

hal_error_t keydb_con::get_key_id(const uuids::uuid_t master_uuid, uint32_t &id)
{
    std::unique_ptr<sql::PreparedStatement> pstmt;
    std::unique_ptr<sql::ResultSet> res;

    pstmt.reset(con->prepareStatement("SELECT id FROM domainkeys WHERE uuid=?;"));

    // prepare the uuid
    std::vector<unsigned char> convertedID;
    master_uuid.get_bytes_vector(convertedID);
    std::stringstream uuid_blob_stream (std::string(convertedID.begin(), convertedID.end()));

    try
    {
        pstmt->setBlob(1, &uuid_blob_stream);
        res.reset(pstmt->executeQuery());
    }
    catch(sql::SQLException &e)
    {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;

        return HAL_ERROR_ALLOCATION_FAILURE;
    }

    if (res->next())
    {
        id = res->getInt(1);
    }
    else
    {
        return HAL_ERROR_ATTRIBUTE_NOT_FOUND;
    }

    return HAL_OK;
}

hal_error_t keydb_con::parse_set_keyattribute_packet(const uuids::uuid_t master_uuid, const libhal::rpc_packet &ipacket)
{
    // attributes must be fed to the keydb
    // 0 - code
    // 4 - client
    // 8 - key handle
    // 12 - num attributes
    // 16 - 1st attribute
    // attributes are
    //     0 - type
    //     4 - variable data
    const size_t num_attr_pos = 12;
    const uint8_t *ptr = NULL;
    uint32_t num_attributes;

    std::cout << "parse_set_keyattribute_packet" << std::endl;

    // the attributes in the packet and the location of the variable data
    std::map<uint32_t, uint32_t> attributes_and_loc;

    ipacket.decode_int_peak_at(&num_attributes, 0);
    std::cout << "ID == " << num_attributes << std::endl;

    ipacket.decode_int_peak_at(&num_attributes, num_attr_pos);
    std::cout << "PEAK SIZE == " << num_attributes << std::endl;

    // go to num attribute position
    ipacket.decode_start(num_attr_pos, &ptr);

    // get the number of attributes
    ipacket.decode_int(&num_attributes, &ptr);

    std::cout << "num_attributes " << num_attributes << std::endl;

    if (num_attributes > 0 && num_attributes < 100)
    {
        std::string sql_expression = "UPDATE domainkeys SET ";
        bool first = true;

        // decode to attributes and location
        for (uint32_t i = 0; i < num_attributes; ++i)
        {
            // type
            uint32_t type;
            ipacket.decode_int(&type, &ptr);

            auto it = shared_data->get_pkcs11attr_to_dbkey().find(type);
            if (it != shared_data->get_pkcs11attr_to_dbkey().end())
            {
                if (!first) sql_expression += ", ";
                else first = false;

                sql_expression += it->second + " = ?";
            }
            else
            {
                std::cout << "uncached attribute: " << type << std::endl;
            }
            

            attributes_and_loc.insert(std::pair<uint32_t, uint32_t>(type, ipacket.getpos(ptr)));

            // move to the next variable
            uint32_t len;
            ipacket.decode_int(&len, &ptr);
            int padding = (4 - len % 4) % 4;
            ptr += len + padding;
        }
        sql_expression += " WHERE uuid = ?;";

        std::cout << sql_expression << std::endl;
    }
}

}

}
