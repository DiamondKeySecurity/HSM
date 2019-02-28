#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

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
