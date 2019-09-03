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

}

}
