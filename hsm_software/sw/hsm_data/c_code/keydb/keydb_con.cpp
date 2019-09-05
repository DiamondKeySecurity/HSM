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
    uint32_t id = 0;
    get_key_id(master_uuid, id);
    std::string id_str = std::to_string(id);

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

    // go to num attribute position
    ipacket.decode_start(num_attr_pos, &ptr);

    // get the number of attributes
    ipacket.decode_int(&num_attributes, &ptr);

    if (num_attributes > 0 && num_attributes < 100)
    {
        // PASS #1 :go through the elements to build the sql statement
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
            
            // move to the next variable skipping padding
            uint32_t len;
            ipacket.decode_int(&len, &ptr);
            int padding = (4 - len % 4) % 4;
            ptr += len + padding;
        }
        sql_expression += " WHERE id = " + id_str + ";";

        std::cout << sql_expression << std::endl;

        std::unique_ptr<sql::PreparedStatement> pstmt;

        // create prepared statement
        try
        {
            pstmt.reset(con->prepareStatement(sql_expression));
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

        // PASS #2 - get values for prepared statement
        ipacket.decode_start(num_attr_pos+4, &ptr);

        int index = 0;
        // decode to attributes and location
        for (uint32_t i = 0; i < num_attributes; ++i)
        {
            uint8_t buffer[256];

            // type
            uint32_t type;
            ipacket.decode_int(&type, &ptr);

            auto it = shared_data->get_pkcs11attr_to_dbkey().find(type);
            if (it != shared_data->get_pkcs11attr_to_dbkey().end())
            {
                ++index;
                auto type_it = shared_data->get_db_attr_types().find(type);
                if (type_it != shared_data->get_db_attr_types().end())
                {
                    KeyDBTypes datatype = type_it->second;

                    uint32_t len;
                    size_t olen;
                    ipacket.decode_int_peak(&len, &ptr);
                    if (len > 0 && len <= 256)
                    {
                        ipacket.decode_variable_opaque(buffer, &olen, sizeof(buffer), &ptr);

                        try
                        {
                            switch (datatype)
                            {
                                case KeyDBType_Int:
                                    std::cout << "INT: index == " << index << " type == " << std::endl;
                                    if (len == 1) pstmt->setInt(index, (int32_t)buffer[0]);
                                    else if (len == 4)
                                    {
                                        uint32_t value;
                                        const uint8_t *buf = buffer;
                                        hal_xdr_decode_int(&buf, &buffer[4], &value);
                                        pstmt->setInt(index, (int32_t)value);
                                    }
                                    else pstmt->setNull(index, sql::DataType::INTEGER);
                                    break;
                                case KeyDBType_Boolean:
                                    std::cout << "BOOL: index == " << index << " type == " << std::endl;
                                    if (len == 1) pstmt->setBoolean(index, buffer[0] != 0);
                                    else if (len == 4)
                                    {
                                        uint32_t value;
                                        const uint8_t *buf = buffer;
                                        hal_xdr_decode_int(&buf, &buffer[4], &value);
                                        pstmt->setBoolean(index, value != 0);
                                    }
                                    else pstmt->setNull(index, sql::DataType::TINYINT);
                                    break;
                                case KeyDBType_Text:
                                    {
                                        std::string text((char *)buffer, olen);
                                        std::cout << "Text: index == " << index << " type == " << type << "; text == " << text << std::endl;
                                        pstmt->setString(index, text);
                                    }
                                    break;
                                case KeyDBType_Binary:
                                    {
                                        std::vector<uint8_t> temp_buffer;
                                        std::cout << "Binary: index == " << index << " type == " << type << "; binary olen == " << olen << std::endl;
                                        for (int i = 0; i < olen; ++i) temp_buffer.push_back(buffer[i]);
                                        std::stringstream binary_stream(std::string(temp_buffer.begin(), temp_buffer.end()));
                                        pstmt->setBlob(index, &binary_stream);
                                    }
                                    break;
                                default:
                                    std::cout << "NOTHING: index == " << index << " type == " << std::endl;
                            }
                        }
                        catch(sql::SQLException &e)
                        {
                            std::cout << "# ERR: SQLException in " << __FILE__;
                            std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
                            std::cout << "# ERR: " << e.what();
                            std::cout << " (MySQL error code: " << e.getErrorCode();
                            std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;

                            return HAL_ERROR_BAD_ARGUMENTS;
                        }
                        continue;
                    }
                    else if (len == 0)
                    {
                        std::cout << "EMPTY: index == " << index << " type == " << std::endl;
                        // we're deleting an attribute
                        // we still need to read the value
                        ipacket.decode_int(&len, &ptr);

                        try
                        {
                            // set to NULL
                            switch (datatype)
                            {
                                case KeyDBType_Int:
                                    pstmt->setNull(index, sql::DataType::INTEGER);
                                    break;
                                case KeyDBType_Boolean:
                                    pstmt->setNull(index, sql::DataType::TINYINT);
                                    break;
                                case KeyDBType_UUID:
                                case KeyDBType_Binary:
                                    pstmt->setNull(index, sql::DataType::VARBINARY);
                                    break;
                                case KeyDBType_Text:
                                    pstmt->setNull(index, sql::DataType::VARCHAR);
                                    break;
                            }
                        }
                        catch(sql::SQLException &e)
                        {
                            std::cout << "# ERR: SQLException in " << __FILE__;
                            std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
                            std::cout << "# ERR: " << e.what();
                            std::cout << " (MySQL error code: " << e.getErrorCode();
                            std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;

                            return HAL_ERROR_BAD_ARGUMENTS;
                        }
                        continue;
                    }
                }
            }

            // something happened so we need to skip
            {
                std::cout << "uncached attribute: " << type << std::endl;

                // move to the next variable skipping padding
                uint32_t len;
                ipacket.decode_int(&len, &ptr);
                int padding = (4 - len % 4) % 4;
                ptr += len + padding;
            }
        }

        try
        {            
            int rows_updated = pstmt->executeUpdate();
            std::cout << "rows_updated == " << rows_updated << " uuid index == " << index << std::endl;
            std::cout << "master uuid == " << (std::string)master_uuid << std::endl;
        }
        catch(sql::SQLException &e)
        {
            std::cout << "# ERR: SQLException in " << __FILE__;
            std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
            std::cout << "# ERR: " << e.what();
            std::cout << " (MySQL error code: " << e.getErrorCode();
            std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;

            return HAL_ERROR_RPC_PROTOCOL_ERROR;
        }
    }

    return HAL_OK;
}

hal_error_t parse_get_keyattribute_packet(const uuids::uuid_t master_uuid, const uint32_t session_client_handle,
                                            const libhal::rpc_packet &ipacket, libhal::rpc_packet &opacket)
{
}


}

}
