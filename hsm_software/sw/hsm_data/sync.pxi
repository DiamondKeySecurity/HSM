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


def rejoinb64(input):
    if(isinstance(input, int)):
        return base64.b64encode(bytes([input]))
    elif(isinstance(input, str)):
        return input
    else:
        return b64join(input)

def byteify(input):
    """Converts unicode(2 byte) values stored in a dictionary or string to utf-8"""
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def makeDictValuesB64(input):
    if isinstance(input, dict):
        return {key: makeDictValuesB64(value) for key, value in input.iteritems()}
    elif isinstance(input, int):
        return input
    else:
        return b64(input)

cdef class Synchronizer(PFUNIX_HSM):
    """Class for providing mirroring services to an HSM"""
    cdef bint __initialized__
    cdef object cache
    cdef object command_queue
    cdef object settings

    def __init__(self, sockname, cache, settings):
        """
        """
        super(Synchronizer, self).__init__(sockname)
        self.__initialized__ = False
        self.cache = cache
        self.settings = settings
        self.command_queue = Queue()

    @property
    def sync_init_success(self):
        return "Internal Synchronizer Initialized"

    def reset(self):
        self.cache.reset()

    def reset(self):
        self.cache.reset()

    def cache_initialized(self):
        return self.cache.is_initialized()

    def initialize(self, rpc_count, username, pin, callback):
        # login to all hsms using the PIN
        self.command_queue.put(SyncCommand(SyncCommandEnum.Initialize, 0,rpc_count, callback, (username, pin)))

    def dowork(self, hsm):
        while(self.command_queue.empty() is False):
            self.process_command(hsm, self.command_queue.get())

        time.sleep(1.0)

    def do_cmd_callback(self, cmd, result):
        if(cmd.callback is not None):
            cmd.callback(cmd, result)

    def init_device(self, hsm, rpc_index, user, pin):
        # select the device
        hsm.rpc_set_device(rpc_index)

        # login
        hsm.login(user, pin)

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

    def export_from_src_hsm(self, hsm, rpc_index, uuid_list, db, useb64attr = False, print_func = None):
        # backup.py expects command line style arguments so we need to mimic that
        args = type('', (), {})()

        args.uuid_list = uuid_list
        args.db = db
        args.useb64attr = useb64attr

        # select the device
        hsm.rpc_set_device(rpc_index)

        return self.cmd_export(args, hsm, print_func)


    def import_to_dst_hsm(self, hsm, cache_source_rows, rpc_index, db, print_func = None):
        # backup.py expects command line style arguments so we need to mimic that
        args = type('', (), {})()

        args.db = db

        # select the device
        hsm.rpc_set_device(rpc_index)

        self.cmd_import(args, cache_source_rows, hsm, rpc_index, print_func)

    def cmd_remoteBackup(self, hsm, cmd):
        console_object = cmd.param[0]
        db = cmd.param[1]

        # export all of the keys to a db
        # the db will later be sent to the remote device using JSON
        db = self.export_from_src_hsm(hsm, cmd.src, None, db, True, cmd.console)

        self.do_cmd_callback(cmd, (console_object, db))

    def cmd_remoteRestore(self, hsm, cmd):
        console_object = cmd.param[0]

        # we must convert all unicode strings to byte strings
        db = byteify(cmd.param[1])

        self.import_to_dst_hsm(hsm, None, cmd.dest, db, cmd.console)

        self.do_cmd_callback(cmd, (console_object, True))

    def cmd_remoteRestoreSetup(self, hsm, cmd):
        console_object = cmd.param

        # prepare and send our key encipherment key
        # the db will later be sent to the remote device using JSON
        db = self.setup_dst_hsm(hsm, cmd.dest)

        self.do_cmd_callback(cmd, (console_object, db))

    def cmd_initialization(self, hsm, cmd):
        # login to all alphas now that we have the wheel pin
        rpc_count = cmd.dest
        user = DKS_HALUser.from_name(cmd.param[0])
        pin = cmd.param[1]
        for rpc_index in range(0, rpc_count):
            self.init_device(hsm, rpc_index, user, pin)

        self.__initialized__ = True

        self.do_cmd_callback(cmd, self.sync_init_success)


    def cmd_OneWayBackup(self, hsm, cmd):
        # Get basic data from the cache -------------
        # this function has been generalized to work on an HSM with n alphas

        # get a copy of the data that won't be affected if there are changes on another thread
        master_rows = self.cache.get_master_table_rows()

        # get the list of keys to copy
        uuid_list = self.buildUUIDCopyList(master_rows = master_rows,
                                           src_index = cmd.src,
                                           dest_index = cmd.dest,
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
        # get a copy of the data that won't be affected if there are changes on another thread
        source_list = self.cache.get_device_table_rows(cmd.src)

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

    def addAlphaData(self, hsm, rpc_index, console, matching_map):
        # select the device
        hsm.rpc_set_device(rpc_index)

        # get list of all keys on the alpha
        with hsm.start_using_device_uuids_block():
            
            prev_uuid = UUID(int = 0)
            max_uuids = 64
            recv_count = 64

            first_uuid = None

            # keep looping until we get less than what we asked for
            while (recv_count == max_uuids):
                recv_count = 0
                for uuid in hsm.pkey_match(u = prev_uuid,
                                           length = max_uuids):
                    if(console is not None):
                        console("Found:%s"%uuid)

                    if (first_uuid is None):
                        first_uuid = uuid
                    elif (first_uuid == uuid):
                        # if the number of uuids on the device == max_uuids in search,
                        # the CrypTech device will loop forever
                        break

                    with hsm.pkey_open(uuid) as pkey:
                        new_uuid = uuid

                        if(matching_map is None):
                            # add uuid without matching
                            masterListID = None
                        else:
                            masterListID = self.findMatchingMasterListID(new_uuid, matching_map)

                        self.cache.add_key_to_alpha(rpc_index, new_uuid, pkey.key_type, pkey.key_flags, param_masterListID = masterListID, auto_backup=False)

                    prev_uuid = uuid
                    recv_count = recv_count + 1

    def findMatchingMasterListID(self, new_uuid, matching_map):
        """Uses the matching map to find the masterListID of a matching key"""
        if (new_uuid in matching_map):
            return matching_map[new_uuid]

        return None

    def buildUUIDCopyList(self, master_rows, src_index, dest_index, max_uuids):
        """get a list of uuids to copy from one alpha to another"""
        # this function has been generalized to work on an HSM with n alphas

        # look through all of the uuids in the source and add them to our list if they don't
        # already have a match
        results = []
        count = 0

        # look through the master list for uuids that have a src uuid, but not a dest uuid
        for row in master_rows.itervalues():
            if (src_index in row.uuid_dict and
                dest_index not in row.uuid_dict):

                results.append(row.uuid_dict[src_index])
                count += 1

            if (count != 0 and count == max_uuids):
                break

        return results

    def cmd_buildcache(self, hsm, cmd):
        # clear remnants
        self.cache.clear()

        rpc_from_index = cmd.src
        rpc_to_index = cmd.dest

        # get the mapping
        try:
            with open('%s/cache_mapping.db'%self.cache.get_cache_folder(), 'r') as fh:
                base_matching_map = byteify(json.load(fh))

            # convert to UUIDs
            matching_map = {}

            for key, val in base_matching_map.iteritems():
                matching_map[uuid.UUID(key)] = uuid.UUID(val)

        except:
            matching_map = None

        # build master table from the alphas
        for rpc_index in range(rpc_from_index, rpc_to_index):
            self.addAlphaData(hsm, rpc_index, cmd.console, matching_map)

        self.cache.backup()

        # push changes to cache
        self.cache.initialize_cache()

        self.do_cmd_callback(cmd, "Cache generated")

    def cmd_setup(self, args, hsm):
        """
        Updated from cmd_setup in 'cryptech_backup'.

        Set up backup HSM for subsequent import.
        Generates an RSA keypair with appropriate usage settings
        to use as a key-encryption-key-encryption-key (KEKEK), and
        writes the KEKEK to a JSON file for transfer to primary HSM.
        """

        result = {}
        uuids  = []

        with hsm.start_using_device_uuids_block():
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


    def cmd_export(self, args, hsm, print_func = None):
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
            with hsm.start_using_device_uuids_block():
                kekek = hsm.pkey_load(der   = b64join(db["kekek_pubkey"]),
                                    flags = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT)

                prev_uuid = UUID(int = 0)
                max_uuids = 64
                recv_count = 64
                first_uuid = None

                # keep looping until we get less than what we asked for
                while (recv_count == max_uuids):
                    recv_count = 0
                    for uuid in hsm.pkey_match(mask  = HAL_KEY_FLAG_EXPORTABLE,
                                               flags = HAL_KEY_FLAG_EXPORTABLE,
                                               length = max_uuids,
                                               u = prev_uuid):

                        if (first_uuid is None):
                            first_uuid = uuid
                        elif (first_uuid == uuid):
                            # if the number of uuids on the device == max_uuids in search,
                            # the CrypTech device will loop forever
                            break

                        if((args.uuid_list is None) or (uuid in args.uuid_list)):
                            # this has been updated to only export keys that are in the list
                            with hsm.pkey_open(uuid) as pkey:

                                # also save the attributes for the key
                                attributes = {}
                                for attr_id in CKA.cached_attributes():
                                    try:
                                        attr = pkey.get_attributes([attr_id])
                                        if (args.useb64attr):
                                            attributes.update(makeDictValuesB64(attr))
                                        else:
                                            attributes.update(attr)
                                    except HAL_ERROR_ATTRIBUTE_NOT_FOUND:
                                        pass

                                for attr_id in CKA.optional_attributes():
                                    try:
                                        attr = pkey.get_attributes([attr_id])
                                        try:
                                            if (attr[attr_id] is not None and attr[attr_id] != 0):
                                                if (args.useb64attr):
                                                    attributes.update(makeDictValuesB64(attr))
                                                else:
                                                    attributes.update(attr)
                                        except:
                                            pass
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

                                if (print_func is not None):
                                    print_func("'%s' was processed."%str(pkey.uuid))

                        prev_uuid = uuid
                        recv_count = recv_count + 1

        finally:
            if kekek is not None:
                kekek.delete()

        db.update(comment = "Cryptech Alpha encrypted key backup",
                keys    = result)

        return db

    def cmd_import(self, args, cache_source_rows, hsm, dest_index, print_func = None):
        """
        Updated from cmd_import in 'cryptech_backup'.

        Import encrypted keys into backup HSM.
        Takes a JSON file containing a key backup (generated by running
        this script's "export" command against the primary HSM) and imports
        keys into the backup HSM.
        """
        # load the json file with the key information
        db = args.db

        soft_key = SoftKEKEK.is_soft_key(db)

        with hsm.start_using_device_uuids_block():
            with (hsm.pkey_load(SoftKEKEK.recover(db), HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT)
                if soft_key else
                hsm.pkey_open(uuid.UUID(db["kekek_uuid"]).bytes)
            ) as kekek:

                for k in db["keys"]:
                    pkcs8 = b64join(k.get("pkcs8", ""))
                    spki  = b64join(k.get("spki",  ""))
                    kek   = b64join(k.get("kek",   ""))
                    flags =         int(k.get("flags",  0))
                    attributes = k.get("attributes", {})
                    pkeytype = 0

                    original_uuid = uuid.UUID(k["uuid"])
                    new_uuid = None

                    if (cache_source_rows is not None):
                        # get the masterlistID
                        try:
                            masterlistID = cache_source_rows[original_uuid]
                        except:
                            # the source key is no longer in the cache so don't copy it
                            continue
                    else:
                        masterlistID = None

                    # don't cache the imported key during keygen. we'll do it manually 
                    # so we can link the 2 keys
                    with hsm.start_disable_cache_block():
                        if pkcs8 and kek:
                            with kekek.import_pkey(pkcs8 = pkcs8, kek = kek, flags = flags) as pkey:
                                new_uuid = pkey.uuid
                                pkeytype = pkey.key_type
                                if(len(attributes) > 0):
                                    # send attributes one at a time to avoid overflow errors
                                    for key, value in attributes.iteritems():
                                        try:
                                            attr = { int(key): rejoinb64(value) }
                                            pkey.set_attributes(attributes = attr)
                                        except:
                                            # don't fail on attributes just log
                                            logger.exception("Import attribute failure on %s",  new_uuid)

                                log_string = "Imported {} as {}".format(original_uuid, new_uuid)
                                print (log_string)
                                if (print_func is not None): print_func(log_string)

                        elif spki:
                            with hsm.pkey_load(der = spki, flags = flags) as pkey:
                                new_uuid = pkey.uuid
                                pkeytype = pkey.key_type
                                if(len(attributes) > 0):
                                    # send attributes one at a time to avoid overflow errors
                                    for key, value in attributes.iteritems():
                                        try:
                                            attr = { int(key): rejoinb64(value) }
                                            pkey.set_attributes(attributes = attr)
                                        except:
                                            # don't fail on attributes just log
                                            logger.exception("Import attribute failure on %s",  new_uuid)

                                log_string = "Loaded {} as {}".format(original_uuid, new_uuid)
                                print (log_string)
                                if (print_func is not None): print_func(log_string)

                        if (new_uuid is not None):
                            self.cache.add_key_to_alpha(dest_index, new_uuid, pkeytype, flags, param_masterListID = masterlistID)

                            print '%s linked to %s'%(new_uuid, original_uuid)

        if soft_key:
            kekek.delete()

    def process_command(self, hsm, cmd):
        switcher = {
            SyncCommandEnum.OneWayBackup : self.cmd_OneWayBackup,
            SyncCommandEnum.TwoWayBackup : self.cmd_TwoWayBackup,
            SyncCommandEnum.Initialize : self.cmd_initialization,
            SyncCommandEnum.BuildCache : self.cmd_buildcache,
            SyncCommandEnum.RemoteBackup : self.cmd_remoteBackup,
            SyncCommandEnum.RemoteRestore : self.cmd_remoteRestore,
            SyncCommandEnum.SetupRemoteRestore : self.cmd_remoteRestoreSetup
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
