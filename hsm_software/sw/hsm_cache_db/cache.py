#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from abc import abstractmethod, ABCMeta

import threading


class CacheDB(object):
    def __init__(self, rpc_count):
        """Create the internal cache structure"""
        self.rpc_count = rpc_count
        self.lock = threading.Lock()

        self.__masterTable = {}
        self.__rpcTables = []

        for _ in xrange(0, self.rpc_count):
            self.__rpcTables.append({})

        self.clear()

    def clear(self):
        """re-create the internal cache structure to clear"""
        with self.lock:
            self.__masterTable.clear()
            for i in xrange(0, self.rpc_count):
                self.__rpcTables[i].clear()

    def get_masterTable(self):
        return self.__masterTable

    def get_alphaTable(self, rpc_index):
        assert rpc_index >= 0 and rpc_index < self.rpc_count
        return self.__rpcTables[rpc_index]

    def printdb(self):
        # testing show results
        with self.lock:
            print "--Master Table--"
            for key, record in self.__masterTable.iteritems():
                print "(%i, %s)"%(key, record)

            print "--Alpha Table--"
            for i in range(0, self.rpc_count):
                print "--Alpha Table %i--"%i
                table = self.get_alphaTable(i)
                for key, record in table.iteritems():
                    print "(%s, %s)"%(key, record)


class CacheTable(object):
    __metaclass__ = ABCMeta

    def __init__(self, cacheDB):
        self.cacheDB = cacheDB
        self.lock = threading.Lock()

        # flag that if True, this table needs to be saved
        self.dirty = False

    @abstractmethod
    def get_table(self):
        pass

    @abstractmethod
    def check_record_type(self, record):
        pass

    def save_table(self, fname):
        with open(fname, "w") as fh:
            with self.lock:
                table = self.get_table()
                fh.write('[\r\n')

                for key, value in table.iteritems():
                    fh.write(' {"%s" : %s},\r\n'%(str(key), str(value)))

                # we just saved the table so we're no longer dirty
                self.dirty = False

                fh.write(']\r\n')
            fh.truncate()

    def add_row(self, key, record):
        with self.lock:
            # the table has been changed and needs to be saved
            self.dirty = True

            table = self.get_table()

            assert self.check_record_type(record)
            assert key not in table

            table[key] = record

            return key

    def update_row(self, key, record):
        with self.lock:
            # the table has been changed and needs to be saved
            self.dirty = True

            table = self.get_table()

            assert self.check_record_type(record)
            assert key in table

            table[key] = record

    def delete_row(self, key):
        table = self.get_table()

        with self.lock:
            # the table has been changed and needs to be saved
            self.dirty = True

            # get the next index to use
            assert key in table

            table.pop(key, None)

    def get_rows(self):
        table = self.get_table()

        complete_results = {}

        with self.lock:
            complete_results.update(table)

        return complete_results

    def get_keys(self):
        table = self.get_table()

        results = []

        with self.lock:
            for key in table.iterkeys():
                results.append(key)

        return results

    def fetch_row(self, key):
        table = self.get_table()
        
        with self.lock:
            if(key in table):
                return table[key]
            else:
                return None
