#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import sys
import time
import threading
import socket
import json

from Queue import Queue
from enum import IntEnum

import tornado.gen

from cache import HSMCache

from hsm_cache_db.master import MasterKeyListRow, CacheTableMaster
from hsm_cache_db.alpha import AlphaCacheRow, CacheTableAlpha

# import classes from the original cryptech.muxd
# cryptech_muxd has been renamed to cryptech/muxd.py
from hsm_tools.cryptech.muxd import logger

from hsm_tools.cryptech.backup import b64, b64join, SoftKEKEK
from hsm_tools.cryptech.cryptech.libhal import *
from hsm_tools.hsm import PFUNIX_HSM
from hsm_tools.pkcs11_attr import CKA

from hsm_tools.cryptech_port import DKS_HALUser, DKS_RPCFunc, DKS_HALError, DKS_HALKeyType

class SyncCommandEnum(IntEnum):
    OneWayBackup = 0
    TwoWayBackup = 1
    Initialize   = 2
    BuildCache   = 3

class SyncCommand(object):
    """Class to define a command for the mirrorer"""
    def __init__(self, name, src, dest, callback, param = None, console = None):
        self.name = name
        self.src = src
        self.dest = dest
        self.callback = callback
        self.param = param
        self.console = console

class Synchronizer(PFUNIX_HSM):
    """Class for providing mirroring services to an HSM"""

    def __init__(self, sockname, cache):
        """
        """
        super(Synchronizer, self).__init__(sockname)
        self.__initialized__ = False
        self.cache = cache
        self.command_queue = Queue()
        self.sync_init_success = "Internal Synchronizer Initialized"

    def cache_initialized(self):
        return self.cache.is_initialized()

    def initialize(self, rpc_count, pin, callback):
        # login to all hsms using the PIN
        self.command_queue.put(SyncCommand(SyncCommandEnum.Initialize, 0,rpc_count, callback, pin))

    def dowork(self, hsm):
        while(self.command_queue.empty() is False):
            self.process_command(hsm, self.command_queue.get())
            
        time.sleep(1.0)

    def do_cmd_callback(self, cmd, result):
        if(cmd.callback is not None):
            cmd.callback(cmd, result)

    def init_device(self, hsm, rpc_index, pin):
        # select the device
        hsm.rpc_set_device(rpc_index)

        # login
        hsm.login(DKS_HALUser.HAL_USER_WHEEL, pin)

    def create_sync_file_from_src_id(self, file_name, mode):
        return open(file_name, mode)

    def setup_dst_hsm(self, hsm, rpc_index):
        # backup.py expects command line style arguments so we need to mimic that
        args = type('', (), {})()
        args.new = False
        args.uuid = None
        args.soft_backup = False
        args.keylen = 2048

        # select the device
        hsm.rpc_set_device(rpc_index)

        # setup the hsm
        return self.cmd_setup(args, hsm)

    def export_from_src_hsm(self, hsm, rpc_index, uuid_list, db):
        # backup.py expects command line style arguments so we need to mimic that
        args = type('', (), {})()

        args.uuid_list = uuid_list
        args.db = db

        # select the device
        hsm.rpc_set_device(rpc_index)

        return self.cmd_export(args, hsm)


    def import_to_dst_hsm(self, hsm, cache_source_rows, rpc_index, db):
        # backup.py expects command line style arguments so we need to mimic that
        args = type('', (), {})()

        args.db = db

        # select the device
        hsm.rpc_set_device(rpc_index)

        self.cmd_import(args, cache_source_rows, hsm, rpc_index)

    def cmd_initialization(self, hsm, cmd):
        # login to all alphas now that we have the wheel pin
        rpc_count = cmd.dest
        pin = cmd.param
        for rpc_index in range(0, rpc_count):
            self.init_device(hsm, rpc_index, pin)

        self.__initialized__ = True

        self.do_cmd_callback(cmd, self.sync_init_success)


    def cmd_OneWayBackup(self, hsm, cmd):
        # Get basic data from the cache -------------

        # this function has been generalized to work on an HSM with n alphas
        source = self.cache.get_alpha_table_object(cmd.src)
        destination = self.cache.get_alpha_table_object(cmd.dest)
        master = self.cache.get_master_table_object()

        # get a copy of the data that won't be affected if there are changes on another thread
        source_list = source.get_rows()
        destination_list = destination.get_rows()
        master_rows = master.get_rows()

        # get the list of keys to copy
        uuid_list = self.buildUUIDCopyList(master_rows = master_rows,
                                           source_list = source_list,
                                           destination_list = destination_list,
                                           max_uuids = cmd.param)

        # setup destination -------------------------
        if(cmd.console is not None):
            cmd.console('Preparing oneway sync transfer from %d to %d\r\n'%(cmd.src, cmd.dest))
        export_db = self.setup_dst_hsm(hsm, cmd.dest)

        # export source -----------------------------
        if(cmd.console is not None):
            cmd.console('Exporting keys from source device, %d\r\n'%(cmd.src))

        export_db = self.export_from_src_hsm(hsm, cmd.src, uuid_list, export_db)

        # import dest -------------------------------
        # get the source alpha
        source = self.cache.get_alpha_table_object(cmd.src)

        # get a copy of the data that won't be affected if there are changes on another thread
        source_list = source.get_rows()

        self.import_to_dst_hsm(hsm, source_list, cmd.dest, export_db)

        self.do_cmd_callback(cmd, "One way backup from %d to %d complete"%(cmd.src, cmd.dest))

    def cmd_TwoWayBackup(self, hsm, cmd):
        # split into 2 one-way commands

        # src -> dest
        cmd0 = SyncCommand(SyncCommandEnum.OneWayBackup, src = cmd.src, dest = cmd.dest, param = cmd.param, callback = None, console = cmd.console)

        # dest -> src
        cmd1 = SyncCommand(SyncCommandEnum.OneWayBackup, src = cmd.dest, dest = cmd.src, param = cmd.param, callback = None, console = cmd.console)

        self.cmd_OneWayBackup(hsm, cmd0)
        self.cmd_OneWayBackup(hsm, cmd1)

        self.do_cmd_callback(cmd, "Two way backup between %d to %d complete"%(cmd.src, cmd.dest))

    def addAlphaData(self, hsm, rpc_index, console, matching_map, first):
        # get master table
        master = self.cache.get_master_table_object()
        master_rows = master.get_rows()

        # select the device
        hsm.rpc_set_device(rpc_index)
        
        # get list of all keys on the alpha
        for uuid in hsm.pkey_match():
            if(console is not None):
                console("Found:%s"%uuid)

            with hsm.pkey_open(uuid) as pkey:
                new_uuid = str(uuid)

                if(first or matching_map is None):
                    # add uuid without matching
                    masterListID = None
                else:
                    masterListID = self.findMatchingMasterListID(new_uuid, matching_map, master_rows)                

                self.cache.add_key_to_alpha(rpc_index, new_uuid, pkey.key_type, pkey.key_flags, param_masterListID = masterListID)

    def byteify(self, input):
        """Converts unicode(2 byte) values stored in a dictionary or string to utf-8"""
        if isinstance(input, dict):
            return {self.byteify(key): self.byteify(value)
                    for key, value in input.iteritems()}
        elif isinstance(input, list):
            return [self.byteify(element) for element in input]
        elif isinstance(input, unicode):
            return input.encode('utf-8')
        else:
            return input

    def findMatchingMasterListID(self, new_uuid, matching_map, master_rows):
        """Uses the matching map to find the masterListID of a matching key"""
        for match in matching_map:
            if(new_uuid in match):
                # we found the row with the new uuid
                for uuid in match:
                    # look through the matches to find in master rows
                    if (uuid != new_uuid):
                        print 'looking for %s in master rows to match %s'%(uuid, new_uuid)
                        for key, value in master_rows.iteritems():
                            uuid_list = value.uuid_list
                            if(uuid in uuid_list):
                                print 'found %i'%key
                                return key
                    
        return None

    def buildUUIDCopyList(self, master_rows, source_list, destination_list, max_uuids):
        """get a list of uuids to copy from one alpha to another"""
        # this function has been generalized to work on an HSM with n alphas

        # look through all of the uuids in the source and add them to our list if they don't
        # already have a match
        results = []
        count = 0

        for key, row in source_list.iteritems():
            masterListID = row.masterListID
            if(masterListID in master_rows):
                master_row = master_rows[masterListID]
                found = False

                # look at the uuids in the master list and see if
                # they match a key in the destination list
                for uuid in master_row.uuid_list:
                    if(uuid != key and uuid in destination_list):
                        found = True
                if (not found):
                    # if the uuid doesn't match anything in the destination,
                    # add it to our results
                    count += 1
                    results.append(key)
            if (count == max_uuids):
                break

        return results

    def cmd_buildcache(self, hsm, cmd):
        # clear remnants
        self.cache.clear()

        rpc_from_index = cmd.src
        rpc_to_index = cmd.dest

        # get the mapping
        try:
            with open('%s/cache_mapping.db'%self.cache.cache_folder, 'r') as fh:
                matching_map = self.byteify(json.load(fh))
        except:
            matching_map = None
        
        first = True

        # build master table from the alphas
        for rpc_index in range(rpc_from_index, rpc_to_index):
            self.addAlphaData(hsm, rpc_index, cmd.console, matching_map, first)

            first = False

        # push changes to cache
        self.cache.initialize_cache()

        self.cache.backup()

        self.do_cmd_callback(cmd, "Cache generated")

    def cmd_setup(self, args, hsm):
        """
        Updated from cmd_export in 'cryptech_backup'.

        Set up backup HSM for subsequent import.
        Generates an RSA keypair with appropriate usage settings
        to use as a key-encryption-key-encryption-key (KEKEK), and
        writes the KEKEK to a JSON file for transfer to primary HSM.
        """

        result = {}
        uuids  = []

        if args.soft_backup:
            SoftKEKEK.generate(args, result)
        elif args.uuid:
            uuids.append(args.uuid)
        elif not args.new:
            uuids.extend(hsm.pkey_match(
                type  = HAL_KEY_TYPE_RSA_PRIVATE,
                mask  = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT | HAL_KEY_FLAG_TOKEN,
                flags = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT | HAL_KEY_FLAG_TOKEN))

        for uuid in uuids:
            with hsm.pkey_open(uuid) as kekek:
                if kekek.key_type != HAL_KEY_TYPE_RSA_PRIVATE:
                    sys.stderr.write("Key {} is not an RSA private key\n".format(uuid))
                elif (kekek.key_flags & HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT) == 0:
                    sys.stderr.write("Key {} does not allow key encipherment\n".format(uuid))
                else:
                    result.update(kekek_uuid   = str(kekek.uuid),
                                kekek_pubkey = b64(kekek.public_key))
                    break

        if not result and not args.uuid:
            with hsm.pkey_generate_rsa(
                    keylen = args.keylen,
                    flags = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT | HAL_KEY_FLAG_TOKEN) as kekek:
                result.update(kekek_uuid   = str(kekek.uuid),
                            kekek_pubkey = b64(kekek.public_key))
        if not result:
            sys.exit("Could not find suitable KEKEK")

        if args.soft_backup:
            result.update(comment = "KEKEK software keypair")
        else:
            result.update(comment = "KEKEK public key")

        return result


    def cmd_export(self, args, hsm):
        """
        Updated from cmd_export in 'cryptech_backup'.

        
        Export encrypted keys from primary HSM.
        Takes a JSON file containing KEKEK (generated by running this
        script's "setup" command against the backup HSM), installs that
        key on the primary HSM, and backs up keys encrypted to the KEKEK
        by writing them to another JSON file for transfer to the backup HSM.
        """

        db = args.db

        result = []

        kekek = None
        try:
            kekek = hsm.pkey_load(der   = b64join(db["kekek_pubkey"]),
                                flags = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT)

            for uuid in hsm.pkey_match(mask  = HAL_KEY_FLAG_EXPORTABLE,
                                    flags = HAL_KEY_FLAG_EXPORTABLE):

                if(str(uuid) in args.uuid_list):
                    # this has been updated to only export keys that are in the list
                    with hsm.pkey_open(uuid) as pkey:

                        # also save the attributes for the key
                        attributes = {}
                        for attr_id in CKA.cached_attributes():
                            try:
                                attr = pkey.get_attributes([attr_id])
                                attributes.update(attr)
                            except HAL_ERROR_ATTRIBUTE_NOT_FOUND:
                                pass

                        if pkey.key_type in (DKS_HALKeyType.HAL_KEY_TYPE_RSA_PRIVATE, DKS_HALKeyType.HAL_KEY_TYPE_EC_PRIVATE):
                            pkcs8, kek = kekek.export_pkey(pkey)
                            result.append(dict(
                                comment = "Encrypted private key",
                                pkcs8   = b64(pkcs8),
                                kek     = b64(kek),
                                uuid    = str(pkey.uuid),
                                flags   = pkey.key_flags,
                                attributes = attributes))

                        elif pkey.key_type in (DKS_HALKeyType.HAL_KEY_TYPE_RSA_PUBLIC, DKS_HALKeyType.HAL_KEY_TYPE_EC_PUBLIC):
                            result.append(dict(
                                comment = "Public key",
                                spki    = b64(pkey.public_key),
                                uuid    = str(pkey.uuid),
                                flags   = pkey.key_flags,
                                attributes = attributes))

        finally:
            if kekek is not None:
                kekek.delete()

        db.update(comment = "Cryptech Alpha encrypted key backup",
                keys    = result)

        return db

    def cmd_import(self, args, cache_source_rows, hsm, dest_index):
        """
        Updated from cmd_export in 'cryptech_backup'.

        Import encrypted keys into backup HSM.
        Takes a JSON file containing a key backup (generated by running
        this script's "export" command against the primary HSM) and imports
        keys into the backup HSM.
        """
        # load the json file with the key information
        db = args.db

        soft_key = SoftKEKEK.is_soft_key(db)

        with (hsm.pkey_load(SoftKEKEK.recover(db), HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT)
            if soft_key else
            hsm.pkey_open(uuid.UUID(db["kekek_uuid"]).bytes)
        ) as kekek:

            for k in db["keys"]:
                pkcs8 = b64join(k.get("pkcs8", ""))
                spki  = b64join(k.get("spki",  ""))
                kek   = b64join(k.get("kek",   ""))
                flags =         k.get("flags",  0)
                attributes = self.clean_attributes(k.get("attributes", {}))

                original_uuid = k["uuid"]
                new_uuid = None

                # get the masterlistID
                try:
                    masterlistID = cache_source_rows[original_uuid].masterListID
                except:
                    # the source key is no longer in the cache so don't copy it
                    continue

                # don't cache the imported key during keygen. we'll do it manually 
                # so we can link the 2 keys
                with hsm.start_disable_cache_block():
                    if pkcs8 and kek:
                        with kekek.import_pkey(pkcs8 = pkcs8, kek = kek, flags = flags) as pkey:

                            new_uuid = str(pkey.uuid)

                            try:
                                if(len(attributes) > 0):
                                    pkey.set_attributes(attributes = attributes)
                            except:
                                # don't fail on attributes just log
                                logger.info("Import attribute failure on %s",  new_uuid)

                            print "Imported {} as {}".format(original_uuid, new_uuid)
                    elif spki:
                        with hsm.pkey_load(der = spki, flags = flags) as pkey:
                            pkey.set_attributes(attributes = attributes)

                            new_uuid = str(pkey.uuid)

                            print "Loaded {} as {}".format(original_uuid, new_uuid)

                if (new_uuid is not None):
                    self.cache.add_key_to_alpha(dest_index, new_uuid, 0, 0, param_masterListID = masterlistID)

                    print '%s linked to %s'%(new_uuid, original_uuid)

            if soft_key:
                kekek.delete()

    def clean_attributes(self, input):
        """Updates attributes dictionary so it can be sent to the HSM"""
        bytified = self.byteify(input)

        return { int(key): value for key, value in bytified.iteritems() }

    def process_command(self, hsm, cmd):
        switcher = {
            SyncCommandEnum.OneWayBackup : self.cmd_OneWayBackup,
            SyncCommandEnum.TwoWayBackup : self.cmd_TwoWayBackup,
            SyncCommandEnum.Initialize : self.cmd_initialization,
            SyncCommandEnum.BuildCache : self.cmd_buildcache,
        }
        func = switcher.get(cmd.name, lambda a: None)
        if(func is not None):
            return func(hsm, cmd)
        else:
            return None

    def queue_command(self, command):
        if(command is not None):
            if(self.__initialized__):
                if(command.name == SyncCommandEnum.Initialize):
                    self.do_cmd_callback(command, "The synchronizer can not be initialized in this manner.")
                else:  
                    self.command_queue.put(command)
            else:
                self.do_cmd_callback(command, "Unable to process command because the synchronizer hasn't been initialized.")