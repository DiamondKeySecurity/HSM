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

#include "_201908270_InitialMigration.h"
#include <string>

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>


namespace diamond_hsm
{
namespace keydb
{

void _201908270_InitialMigration::up(std::shared_ptr<sql::Connection> con) const
// commands to alter and create tables for this version
{
    std::unique_ptr<sql::Statement> stmt;
    std::unique_ptr<sql::ResultSet> res;

    char sql_table_statement[] =
"CREATE TABLE domainkeys \
( \
  id                    INT           NOT NULL AUTO_INCREMENT, \
  uuid                  VARBINARY(16) NOT NULL, \
  key_type              TINYINT       NOT NULL, \
  key_flags             TINYINT       NOT NULL, \
  curve                 TINYINT, \
  public_key_spki       VARCHAR(768)  DEFAULT NULL, \
  private_key_pkcs8     VARCHAR(768)  DEFAULT NULL, \
  kek                   VARCHAR(768)  DEFAULT NULL, \
  CKA_CLASS             INT           DEFAULT 0, \
  CKA_TOKEN             BOOLEAN       DEFAULT FALSE, \
  CKA_PRIVATE           BOOLEAN       DEFAULT TRUE, \
  CKA_LABEL             VARCHAR(256)  DEFAULT NULL, \
  CKA_SERIAL_NUMBER     VARCHAR(64)   DEFAULT NULL, \
  CKA_OWNER             VARCHAR(64)   DEFAULT NULL, \
  CKA_ATTR_TYPES        VARCHAR(64)   DEFAULT NULL, \
  CKA_TRUSTED           BOOLEAN       DEFAULT TRUE, \
  CKA_KEY_TYPE          INT           DEFAULT 0, \
  CKA_SUBJECT           VARCHAR(64)   DEFAULT NULL, \
  CKA_ID                VARCHAR(256)  DEFAULT NULL, \
  CKA_SENSITIVE         BOOLEAN       DEFAULT FALSE, \
  CKA_ENCRYPT           BOOLEAN       DEFAULT FALSE, \
  CKA_DECRYPT           BOOLEAN       DEFAULT FALSE, \
  CKA_WRAP              BOOLEAN       DEFAULT FALSE, \
  CKA_UNWRAP            BOOLEAN       DEFAULT FALSE, \
  CKA_SIGN              BOOLEAN       DEFAULT FALSE, \
  CKA_SIGN_RECOVER      BOOLEAN       DEFAULT FALSE, \
  CKA_VERIFY            BOOLEAN       DEFAULT FALSE, \
  CKA_VERIFY_RECOVER    BOOLEAN       DEFAULT FALSE, \
  CKA_DERIVE            BOOLEAN       DEFAULT FALSE, \
  CKA_MODULUS           VARCHAR(32)   DEFAULT NULL, \
  CKA_MODULUS_BITS      VARCHAR(64)   DEFAULT NULL, \
  CKA_PUBLIC_EXPONENT   VARCHAR(64)   DEFAULT NULL, \
  CKA_EXTRACTABLE       BOOLEAN       DEFAULT FALSE, \
  CKA_MODIFIABLE        BOOLEAN       DEFAULT TRUE, \
  CKA_WRAP_WITH_TRUSTED BOOLEAN       DEFAULT FALSE, \
  CKA_EC_PARAMS         VARCHAR(256)  DEFAULT NULL, \
  CKA_EC_POINT          VARCHAR(256)  DEFAULT NULL, \
  PRIMARY KEY (id) \
);";

    stmt.reset(con->createStatement());
    stmt->execute(sql_table_statement);
}

}

}