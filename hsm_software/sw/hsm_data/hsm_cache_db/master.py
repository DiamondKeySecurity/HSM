#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.

import atexit
import threading
import enum
import os
import uuid

from cryptech.muxd import logger

class MasterTableRow(object):
    """Represents a row in the cache's master key list"""
    def __init__(self, keytype = 0, flags = 0):
        """Initialize the rows data
        key_rpc_index - index of the CrypTech device that the key with the associated key_uuid is on
        key_uuid      - uuid of the key on the CrypTech deviced defined by key_rpc_index
        keytype       - the key's type (eg. HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE)
        flags         - the flags set in the alpha
        """
        self.keytype = keytype
        self.flags = flags
        self.uuid_dict = { }

    def __str__(self):
        """Provide override of _str__ for testing"""
        uuids = ''
        uuid_count = len(self.uuid_dict)
        i = 0
        for key, val in self.uuid_dict.iteritems():
            uuid = '"%s": "{%s}"'%(key, val)
            if (i < uuid_count-1):
                uuids = '%s%s,'%(uuids, uuid)
            else:
                uuids = '%s%s'%(uuids, uuid)

            i += 1

        try:
            result = '{"keytype":%d, "flags":%d, "uuid_list":{%s}}'%(self.keytype, self.flags, uuids)
        except Exception as e:
            logger.exception("Exception %s", str(e))
            result = '{}'

        return result