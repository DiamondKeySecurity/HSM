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

#include "../libhal/hal_internal.h"

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

hal_error_t keydb_con::parse_get_keyattribute_packet(const uuids::uuid_t master_uuid, const uint32_t session_client_handle,
                                                     const libhal::rpc_packet &ipacket, libhal::rpc_packet &opacket)
{
    const uint8_t *ptr;

    //  -----------------  0 - code
    //  -----------------  4 - client
    //  -----------------  8 - handle
    //  ----------------- 12 - attr_len
    //  ----------------- 16 - list of attribute types
    // (16 + (attr_len * 4)) - buffer len <- if 0, return size of data only

    // go to the beginning of the data that we care about
    const size_t attr_len_pos = 12;
    ipacket.decode_start(attr_len_pos, &ptr);

    // get the number of attributes
    uint32_t attr_len;
    ipacket.decode_int(&attr_len, &ptr);

    // get the size of the buffer
    const size_t buffer_len_pos = 16 + (attr_len * 4);
    uint32_t buffer_len;
    ipacket.decode_int_peak_at(&buffer_len, buffer_len_pos);

    // counter for remaing data
    uint32_t remaining = buffer_len;

    // create the result packet
    // 0 - code
    // 4 - result
    // 8 - attr_len
    // 12 - list of attributes
    //      uint32_t type
    //      uint32_t length
    //      uint8_t  fixed size data
    opacket.create((3 * 4) + (attr_len * 8) + buffer_len + 12);
    opacket.encode_int(RPC_FUNC_PKEY_GET_ATTRIBUTES);
    opacket.encode_int(HAL_OK);
    opacket.encode_int(attr_len);

    // query sql
    std::unique_ptr<sql::PreparedStatement> pstmt;
    std::unique_ptr<sql::ResultSet> res;

    std::string sql_expression = "SELECT ";
    bool first = true;

    std::vector<uint32_t> cached_attributes;
    std::vector<uint32_t> uncached_attributes;

    for (uint32_t i = 0; i < attr_len; ++i)
    {
        uint32_t type;
        ipacket.decode_int(&type, &ptr);

        auto it = shared_data->get_pkcs11attr_to_dbkey().find(type);
        if (it != shared_data->get_pkcs11attr_to_dbkey().end())
        {
            if (!first) sql_expression += ", ";
            else first = false;

            sql_expression += it->second;

            cached_attributes.push_back(type);
        }
        else
        {
            std::cout << "uncached attribute: " << type << std::endl;
            uncached_attributes.push_back(type);
        }
    }

    sql_expression += " FROM domainkeys WHERE uuid=?;";
    std::cout << sql_expression << std::endl;

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

        return HAL_ERROR_RPC_PROTOCOL_ERROR;
    }
    
    // prepare the uuid
    std::vector<unsigned char> convertedID;
    master_uuid.get_bytes_vector(convertedID);
    std::stringstream uuid_blob_stream (std::string(convertedID.begin(), convertedID.end()));
    pstmt->setBlob(1, &uuid_blob_stream);

    // execute the query with the uuid
    try
    {
        res.reset(pstmt->executeQuery());
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

    if(res->next())
    {
        // read back and build the result
        int index = 0;
        for (auto it = cached_attributes.begin(); it < cached_attributes.end(); ++it)
        {
            ++index;

            uint32_t type = *it;

            // save the type
            opacket.encode_int(type);

            auto type_it = shared_data->get_db_attr_types().find(type);
            if (type_it != shared_data->get_db_attr_types().end() || res->isNull(index))
            {
                KeyDBTypes datatype = type_it->second;
                switch (datatype)
                {
                    case KeyDBType_Int:
                        if (buffer_len == 0)
                        {
                            opacket.encode_int(sizeof(uint32_t));
                        }
                        else
                        {
                            if (remaining < sizeof(uint32_t)) return HAL_ERROR_RPC_PACKET_OVERFLOW;
                            else remaining -= sizeof(uint32_t);

                            uint32_t value = (uint32_t)res->getInt(index);
                            opacket.encode_variable_opaque((const uint8_t *)&value, sizeof(uint32_t));

                            std::cout << type << ": INT == " << value << std::endl;
                        }
                        break;
                    case KeyDBType_Boolean:
                        if (buffer_len == 0)
                        {
                            opacket.encode_int(sizeof(uint8_t));
                        }
                        else
                        {
                            if (remaining < sizeof(uint8_t)) return HAL_ERROR_RPC_PACKET_OVERFLOW;
                            else remaining -= sizeof(uint8_t);

                            uint8_t value = res->getBoolean(index);
                            opacket.encode_variable_opaque((const uint8_t *)&value, sizeof(uint8_t));

                            std::cout << type << ": BOOL == " << value << std::endl;
                        }
                        
                        break;
                    case KeyDBType_Text:
                        {
                            std::string text = res->getString(index);

                            if(buffer_len == 0)
                            {
                                opacket.encode_int(text.size());
                            }
                            else
                            {
                                if (remaining < text.size()) return HAL_ERROR_RPC_PACKET_OVERFLOW;
                                else remaining -= text.size();

                                opacket.encode_variable_opaque((const uint8_t *)text.c_str(), text.size());

                                std::cout << type << ": BOOL == " << text << std::endl;
                            }
                            
                        }
                        break;
                    case KeyDBType_Binary:
                        {
                            std::istream *blob_stream = res->getBlob(index);
                            blob_stream->seekg(std::ios::end);
                            uint32_t blob_size = blob_stream->tellg();
                            blob_stream->seekg(std::ios::beg);

                            if(buffer_len == 0)
                            {
                                opacket.encode_int(blob_size);
                            }
                            else
                            {
                                if (remaining < blob_size) return HAL_ERROR_RPC_PACKET_OVERFLOW;
                                else remaining -= blob_size;

                                uint8_t buffer[blob_size];
                                for (int i = 0; i < blob_size; ++i)
                                    buffer[i] = blob_stream->get();

                                opacket.encode_variable_opaque(buffer, blob_size);

                                std::cout << type << ": BINARY LENGTH == " << blob_size << std::endl;
                            }
                        }
                        break;
                }
            }
            else
            {
                // nothing, this should only be reached if the field is NULL
                opacket.encode_int(0);
            }   
        }
    }
    else
    {
        for (auto it = cached_attributes.begin(); it < cached_attributes.end(); ++it)
        {
            uint32_t type = *it;
            opacket.encode_int(type);
            opacket.encode_int(0);
        }
    }

    for (auto it = uncached_attributes.begin(); it < uncached_attributes.end(); ++it)
    {
        uint32_t type = *it;
        opacket.encode_int(type);
        opacket.encode_int(0);
    }

    opacket.shrink_to_fit();

    return HAL_OK;
}


}

}
