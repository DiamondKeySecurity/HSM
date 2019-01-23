# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import sys

sys.path.insert(0, '..')

from hsm_cache_db.alpha import CacheTableAlpha, AlphaCacheRow
from hsm_cache_db.master import CacheTableMaster, MasterKeyListRow
from hsm_cache_db.cache import CacheDB

sys.path.pop(0)

def test_insert_update_remove(cacheDB):
    masterTable = CacheTableMaster(cacheDB)
    masterTable.create_ifnot_exist()

    alpha_list = []
    for alpha_index in range(0, 2):
        alpha_list.append(CacheTableAlpha(cacheDB, alpha_index, masterTable.get_table_name()))
        alpha_list[alpha_index].create_ifnot_exist()


    # ----------------------------------------------
    id = masterTable.add_row(MasterKeyListRow(0, 1, 1, 1, 1))

    alpha_list[0].add_row(AlphaCacheRow(0, "0001-0001-0002-0003", id))
    alpha_list[1].add_row(AlphaCacheRow(0, "2221-0001-0002-2223", id))

    # ---------------------------------------------
    id = masterTable.add_row(MasterKeyListRow(0, 2, 2, 2, 2))
    alpha_list[0].add_row(AlphaCacheRow(0, "0001-0001-0002-0003", id))

    # ---------------------------------------------

    print "Master List Rows:"
    results = masterTable.get_rows()
    for result in results:
        print result

    for alpha_index in range(0,2):
        print "Alpha %d List Rows:"%alpha_index
        results = alpha_list[alpha_index].get_rows()
        for result in results:
            print result

    print 'updating'
    alpha_list[0].update_row(AlphaCacheRow(1, "AAAA-BBBB-CCCC-DDD3", 1))

    attributes = [ { 'asdasd':'wewewqe'}, { 'id':'wewewqe'} ]
    masterTable.update_row(MasterKeyListRow(1, 2, 1, 1, 1, attributes))

    print "Master List Rows:"
    results = masterTable.get_rows()
    for result in results:
        print result

    for alpha_index in range(0,2):
        print "Alpha %d List Rows:"%alpha_index
        results = alpha_list[alpha_index].get_rows()
        for result in results:
            print result 


cache = CacheDB(':memory:')

test_insert_update_remove(cache)
