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


import json

from sync import SyncCommandEnum, SyncCommand

from settings import HSMSettings

from scripts.remote_backup import RemoteBackupScript
from scripts.remote_restore import RemoteRestoreScript

from scripts.sync_export import SyncExport
from scripts.sync_import import SyncImport
from scripts.sync_import_setup import SyncImportSetup

from console.file_transfer import MGMTCodes, FileTransfer

# the file name to use when receiving from a remote host
REMOTE_SETUP_JSON = "remote-setup.json"
REMOTE_EXPORT_JSON = "remote-export.json"

# the file name to use when sending to a remote host
LOCAL_SETUP_JSON = "local-setup.json"
LOCAL_EXPORT_JSON = "local-export.json"

def dks_sync_cache(console_object, args):
    console_object.build_cache(0, console_object.rpc_preprocessor.device_count())
    return True

def parse_index(index_string, max_value):
    try:
        index = int(index_string)
    except Exception:
        index = -1

    if (max_value > 0 and index >= max_value):
        index = -1

    return index

def dks_sync_oneway(console_object, args):
    src = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (src < 0):
        return "Invalid source parameter. Got '%s'." % args[0]

    dest = parse_index(args[1], console_object.rpc_preprocessor.device_count())
    if (dest < 0):
        return "Invalid destination parameter. Got '%s'." % args[1]

    max_keys = parse_index(args[2], 0)
    if (max_keys < 0):
        return "Invalid max keys parameter. Got '%s'." % args[2]

    cmd = SyncCommand(SyncCommandEnum.OneWayBackup, src, dest,
                            console_object.sync_callback,
                            param=max_keys,
                            console=console_object.cty_direct_call)

    console_object.synchronizer.queue_command(cmd)

    return "command sent to synchronizer"

def dks_sync_twoway(console_object, args):
    src = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (src < 0):
        return "Invalid source parameter. Got '%s'." % args[0]

    dest = parse_index(args[1], console_object.rpc_preprocessor.device_count())
    if (dest < 0):
        return "Invalid destination parameter. Got '%s'." % args[1]

    max_keys = parse_index(args[2], 0)
    if (max_keys < 0):
        return "Invalid max keys parameter. Got '%s'." % args[2]

    cmd = SyncCommand(SyncCommandEnum.TwoWayBackup, src, dest,
                            console_object.sync_callback,
                            param=max_keys,
                            console=console_object.cty_direct_call)

    console_object.synchronizer.queue_command(cmd)

    return "command sent to synchronizer"

# Import / Export -------------------------------------------------------------------------
def show_cryptech_backup_info(cty_direct_call):
    cty_direct_call('This works by having the destination HSM (the one importing keys)')
    cty_direct_call('create an RSA keypair (the "KEKEK"), the public key of which can then')
    cty_direct_call('be imported into the source HSM (the one exporting keys) and used to')
    cty_direct_call('encrypt AES key encryption keys (KEKs) which in turn can be used to')
    cty_direct_call('wrap the private keys being transfered.  Transfers are encoded in')
    cty_direct_call('JSON; the underlying ASN.1 formats are SubjectPublicKeyInfo (KEKEK')
    cty_direct_call('public key) and PKCS #8 EncryptedPrivateKeyInfo (everything else).')
    cty_direct_call('NOTE WELL: while this process makes it POSSIBLE to back up keys')
    cty_direct_call('securely, it is not sufficient by itself: the operator MUST make')
    cty_direct_call('sure only to export keys using a KEKEK known to have been generated by')
    cty_direct_call('the target HSM.')
    cty_direct_call('- cryptech_backup')

# -- external export ---------------------------------------------
def on_sent_remote_backup_data(console_object, result, msg):
    # we don't need to close the file_transfer object because it will
    # do that itself before calling this callback function
    console_object.file_transfer = None

    console_object.allow_user_input(msg)

def on_remote_backup_prepared(cmd, results):
    console_object = results[0]
    result = results[1]

    export_json_path_remote = console_object.temp_object

    console_object.temp_object = None

    if (result == None):
        console_object.allow_user_input("Sync: Did not return any data to export.")
    else:
        json_to_send = LOCAL_EXPORT_JSON
        with console_object.tmpfs.unprotected_fopen(filename = json_to_send,
                                                    mode = "r",
                                                    erase_on_exit = True,
                                                    open_mode = None,
                                                    contents = json.dumps(result)) as _:
            pass

        # stop excepting normal user data
        console_object.set_ignore_user('The HSM is exporting data.')

        mgmt_code = MGMTCodes.MGMTCODE_SEND_EXPORT_DATA.value

        # setup a file transfer object
        ft = FileTransfer(mgmt_code=mgmt_code,
                          tmpfs = console_object.tmpfs,
                          requested_file_path=export_json_path_remote,
                          json_to_send=json_to_send,
                          finished_callback=on_sent_remote_backup_data,
                          data_context=console_object)

        console_object.file_transfer = ft

        ft.start(console_object)

        # the file transfer object will signal what to do
        return True


def on_received_remote_kekek(console_object, result, msg):
    """Receive kekek for a remote backup"""
    # we don't need to close the file_transfer object because it will
    # do that itself before calling this callback function
    console_object.file_transfer = None

    if(result is True):
        # need to use unprotected_fopen because the will was sent and for fopen is write only
        with console_object.tmpfs.unprotected_fopen(REMOTE_SETUP_JSON, "rt") as json_fp:
            db = json.load(json_fp)

        src = console_object.temp_object[0]

        # make the temp object just the export_json_path
        console_object.temp_object = console_object.temp_object[1]

        console_object.cty_direct_call("Received KEKEK. Waiting for synchronizer. This may take a while.")

        # send the command to the synchronizer
        cmd = SyncCommand(SyncCommandEnum.RemoteBackup, src, -1,
                          on_remote_backup_prepared,
                          param=(console_object, db),
                          console=console_object.cty_direct_call)

        console_object.synchronizer.queue_command(cmd)
    else:
        console_object.temp_object = None
        console_object.allow_user_input("Did not receive setup json with KEKEK.")
        console_object.allow_user_input(msg)

def got_export_options(console_object, results):
    # ask to receive the KEKEK
    device = results['device_index']
    setup_json_path = results['setup_json_path']
    export_json_path = results['export_json_path']

    # save options needed for the next step
    console_object.temp_object = (device, export_json_path)

    try:
        # stop excepting normal user data
        console_object.set_ignore_user('The HSM is preparing an eport')

        mgmt_code = MGMTCodes.MGMTCODE_RECEIVE_RMT_KEKEK.value
        remote_setup = REMOTE_SETUP_JSON

        # setup a file transfer object
        ft = FileTransfer(mgmt_code=mgmt_code,
                          tmpfs = console_object.tmpfs,
                          requested_file_path=setup_json_path,
                          finished_callback=on_received_remote_kekek,
                          destination_file=remote_setup,
                          data_context=console_object)

        console_object.file_transfer = ft

        ft.start(console_object)

        # the file transfer object will signal what to do
        return True

    except Exception as e:
        console_object.cty_direct_call('\nThere was an error while receiving the'
                                       ' update.\r\n\r\n%s' % e.message)

def dks_start_export_script(console_object, pin, username):
    if (username.lower() != 'wheel' and username.lower() != 'so'):
        console_object.cty_direct_call("Insufficient privileges to carry out this operation.\r\nMust be 'wheel' or 'so'.")
        return

    # get the source parameter
    device_index = console_object.temp_object

    console_object.script_module = SyncExport(console_object.cty_direct_call,
                                              device_index,
                                              got_export_options,
                                              console_object)

    console_object.cty_direct_call(console_object.prompt)

def dks_sync_export_HSM(console_object, args):
    console_object.cty_direct_call("Export to external device.-----------------------------\r\n")

    # get the source parameter
    src = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (src < 0):
        return "Invalid source device destination parameter. Got '%s'." % args[0]

    console_object.temp_object = src

    show_cryptech_backup_info(console_object.cty_direct_call)

    console_object.redo_login(dks_start_export_script)
    return True

# -- external import ---------------------------------------------
def on_sync_restore_finished(cmd, results):
    console_object = results[0]
    result = results[1]

    if (result is True):
        console_object.allow_user_input("HSM: Import complete.")
    else:
        console_object.allow_user_input("HSM: There was an error restoring the data to the HSM")

def on_recv_data_to_import(console_object, result, msg):
    # we don't need to close the file_transfer object because it will
    # do that itself before calling this callback function
    dest = console_object.temp_object
    console_object.temp_object = None

    if(result is True):
        json_file = REMOTE_EXPORT_JSON

        try:
            # read the json file that we just received. It contains the KEKEK
            with console_object.tmpfs.unprotected_fopen(json_file, "rt") as json_fp:
                db = json.load(json_fp)
        except:
            console_object.allow_user_input("HSM: There was an error processing the import data.")
            return

        console_object.cty_direct_call("HSM: Import data received. Waiting for synchronizer.")

        # send the command to the synchronizer
        cmd = SyncCommand(SyncCommandEnum.RemoteRestore, -1, dest,
                          on_sync_restore_finished,
                          param=(console_object, db),
                          console=console_object.cty_direct_call)

        console_object.synchronizer.queue_command(cmd)      
        console_object.file_transfer = None
    else:
        console_object.allow_user_input("HSM: Unable to receive import data.")
        console_object.allow_user_input(msg)

def got_import_options(console_object, results):
    device = results['device_index']
    export_json_path_remote = results['export_json_path'] # this is the path on the host computer

    # save option that we'll need later
    console_object.temp_object = device

    mgmt_code = MGMTCodes.MGMTCODE_RECEIVE_IMPORT_DATA.value
    export_json = REMOTE_EXPORT_JSON # this is the file that will be saved on the HSM

    # setup a file transfer object
    ft = FileTransfer(mgmt_code=mgmt_code,
                      tmpfs = console_object.tmpfs,
                      requested_file_path=export_json_path_remote,
                      finished_callback=on_recv_data_to_import,
                      destination_file=export_json,
                      data_context=console_object)

    console_object.file_transfer = ft

    ft.start(console_object)

    # the file transfer object will signal what to do
    return True

def dks_start_import_script(console_object, pin, username):
    if (username.lower() != 'wheel' and username.lower() != 'so'):
        console_object.cty_direct_call("Insufficient privileges to carry out this operation.\r\nMust be 'wheel' or 'so'.")
        return

    device_index = console_object.temp_object

    console_object.script_module = SyncImport(console_object.cty_direct_call,
                                              device_index,
                                              got_import_options,
                                              console_object)

    console_object.cty_direct_call(console_object.prompt)

def dks_sync_import_HSM(console_object, args):
    console_object.cty_direct_call("Import from an external device.------------------------\r\n")

    # get the destination parameter
    dest = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (dest < 0):
        return "Invalid internal device destination parameter. Got '%s'." % args[0]

    console_object.temp_object = dest

    show_cryptech_backup_info(console_object.cty_direct_call)

    console_object.redo_login(dks_start_import_script)
    return True

# -- external import setup ---------------------------------------

def on_sent_local_kekek(console_object, result, msg):
    if(result is True):
        console_object.file_transfer = None
        console_object.allow_user_input("HSM: The KEKEK was sent successfully.")
    else:
        console_object.allow_user_input("HSM: The KEKEK was not sent successfully.")

def send_local_kekek_after_sync(cmd, results):
    console_object = results[0]
    db = results[1]

    setup_json = LOCAL_SETUP_JSON

    setup_json_path_remote = console_object.temp_object # this is the file name and path on the remote computer to save to

    try:
        # write the file that FileTransfer will use
        with console_object.tmpfs.unprotected_fopen(filename = setup_json,
                                                    mode = "r", # after we write this, it can only be opened for reading
                                                    erase_on_exit = True,
                                                    open_mode = None,
                                                    contents = json.dumps(db)) as _:
            pass

        # stop excepting normal user data
        console_object.set_ignore_user('The HSM is sending the public KEKEK.')

        mgmt_code = MGMTCodes.MGMTCODE_SEND_LCL_KEKEK.value

        # setup a file transfer object
        ft = FileTransfer(mgmt_code=mgmt_code,
                          tmpfs = console_object.tmpfs,
                          json_to_send=setup_json,
                          requested_file_path=setup_json_path_remote,
                          finished_callback=on_sent_local_kekek,
                          data_context=console_object)

        console_object.file_transfer = ft

        ft.start(console_object)

        # the file transfer object will signal what to do
        return True
    except Exception as e:
        console_object.cty_direct_call('\nThere was an error while receiving the'
                                       ' update.\r\n\r\n%s' % e.message)

def got_import_setup_options(console_object, results):
    # generate and send KEKEK
    device = results['device_index']
    setup_json_path = results['setup_json_path']

    # save options needed for the next step
    console_object.temp_object = setup_json_path

    console_object.set_ignore_user("command sent to synchronizer.\r\nGenerating KEKEK\r\nThis may take a few minutes.")

    cmd = SyncCommand(SyncCommandEnum.SetupRemoteRestore, -1, device,
                      send_local_kekek_after_sync,
                      param=console_object,
                      console=console_object.cty_direct_call)

    console_object.synchronizer.queue_command(cmd)


def dks_start_import_setup_script(console_object, pin, username):
    if (username.lower() != 'wheel' and username.lower() != 'so'):
        console_object.cty_direct_call("Insufficient privileges to carry out this operation.\r\nMust be 'wheel' or 'so'.")
        return

    device_index = console_object.temp_object

    console_object.script_module = SyncImportSetup(console_object.cty_direct_call,
                                                   device_index,
                                                   got_import_setup_options,
                                                   console_object)

    console_object.cty_direct_call(console_object.prompt)

def dks_sync_import_setup_HSM(console_object, args):
    console_object.cty_direct_call("Generate KEKEK for import.-----------------------------\r\n")
    # get the destination parameter
    dest = parse_index(args[0], console_object.rpc_preprocessor.device_count())
    if (dest < 0):
        return "Invalid internal device destination parameter. Got '%s'." % args[0]

    console_object.temp_object = dest

    show_cryptech_backup_info(console_object.cty_direct_call)

    console_object.redo_login(dks_start_import_setup_script)
    return True

# Command Setup -----------------------------------------------------------------------
def add_sync_commands(console_object):
    sync_node = console_object.add_child('sync')

    sync_node.add_child(name="cache", num_args=0,
                        usage=" - Scans the CrypTech devices to rebuild"
                        " the cache.",
                        callback=dks_sync_cache)

    sync_node.add_child(name="oneway", num_args=3,
                        usage="<source RPC index> <destination RPC index>"
                        " <max copies>  - copies keys from one CrypTech"
                        " device to another.",
                        callback=dks_sync_oneway)

    sync_node.add_child(name="twoway", num_args=3,
                        usage="<source RPC index> <destination RPC index>"
                        " <max copies>  - copies keys from one CrypTech"
                        " device to another.",
                        callback=dks_sync_twoway)

    external_node = sync_node.add_child(name="external")

    external_node.add_child(name="import", num_args=1,
                          usage="<internal device index> - Imports keys"
                                " from an external device using CrypTech Backup JSON.",
                          callback=dks_sync_import_HSM)

    external_node.add_child(name="import_setup", num_args=1,
                          usage="<internal device index> - Generates a KEKEK for an"
                                " external import.",
                          callback=dks_sync_import_setup_HSM)

    external_node.add_child(name="export", num_args=1,
                          usage="<internal device index> - Uses public KEKEK to"
                                " securely export keys using CrypTech Backup JSON.",
                          callback=dks_sync_export_HSM)