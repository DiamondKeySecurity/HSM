#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
#
# This implementation is by Diamond Key Security, NFP using code from
# CrypTech's cryptech_muxd. It is an implementation of the CrypTech
# multiplexer that accepts incoming TCP connections using the
# Tornado library. It then uses PySerial to communicate directly with
# an Alpha.
#
# This Python script uses code from 'cryptech_muxd.'
# The 'cryptech_muxd' copyright is below.
#
# ---------------------------------------------------------------------
# Original cryptech_muxd copyright
#
# Copyright (c) 2016-2017, NORDUnet A/S All rights reserved.
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

"""
This implementation is by Diamond Key Security, NFP using code from
CrypTech's cryptech_muxd. It is an implementation of the CrypTech
multiplexer that accepts incoming TCP connections using the
Tornado library. It then uses PySerial to communicate directly with
an Alpha.
"""

import os
import sys
import time
import atexit
import logging
import logging.handlers
import argparse
import zero_conf

import tornado.netutil
import tornado.ioloop

# import classes from the original cryptech.muxd
# cryptech_muxd has been renamed to cryptech/muxd.py
from hsm_tools.cryptech import muxd

from hsm_tools.probing import ProbeMultiIOStream
from hsm_tools.tcpserver import RPCTCPServer, CTYTCPServer, \
                                SecondaryPFUnixListener

from diamondhsm_console import DiamondHSMConsole

from cache import HSMCache
from rpc_handling import RPCPreprocessor

from ipconfig import NetworkInterfaces
from settings import Settings, RPC_IP_PORT, CTY_IP_PORT, HSMSettings

from safe_shutdown import SafeShutdown

from sync import Synchronizer

from setup.security import HSMSecurity

from tamper import TamperDetector


def register_zeroconf(ip_addr, serial):
    muxd.logger.info("registered to zero config")
    zero_conf.register_zeroconf_sevice(ip_addr, serial)
    atexit.register(zero_conf.unregister_zeroconf_sevice)


synchronizer = None
safe_shutdown = None


def start_leds(use_leds):
    if (use_leds is True):
        from led import LEDContainer

        leds = LEDContainer()

        leds.system_led.set_yellow()
        leds.system_led.on()

        leds.tamper_led.set_yellow()
        leds.tamper_led.on()

        return leds
    else:
        return None


@tornado.gen.coroutine
def main():
    DEVICES_IN_CHASE = 2

    formatter_class = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=formatter_class)

    parser.add_argument("-v", "--verbose",
                        action="count",
                        help="blather about what we're doing")

    parser.add_argument("-l", "--log-file",
                        help="log to file instead of stderr")

    parser.add_argument("--certfile",
                        help="TLS certificate",
                        default="../certs/domain.crt")

    parser.add_argument("--keyfile",
                        help="TLS private key",
                        default="../certs/domain.key")

    parser.add_argument("--hsmpublickey",
                        help="Location of the HSM public key for update"
                             " verification",
                        default="/etc/dkey-public.pem")

    # secondary rpc PF_UNIX listener
    # a secondary PF_UNIX listener is being added for compatibility with
    # special Cryptech code that relies on sending information through
    # cryptech_muxd and that will reside on the Diamond HSM. Using this
    # method, operations such as key backup can be multiplexed and
    # run in the background while processing other RPC request.
    parser.add_argument("--rpc-socket",
                        help="RPC PF_UNIX socket name",
                        default=os.getenv("CRYPTECH_RPC_CLIENT_SOCKET_NAME",
                                          "/var/tmp/.cryptech_muxd.rpc"))

    parser.add_argument("--rpc-socket-mode",
                        help="permission bits for RPC socket inode",
                        default=0o600, type=lambda s: int(s, 8))

    parser.add_argument("-n", "--netiface",
                        help="Network interface to use in reporting",
                        default="eth0")

    parser.add_argument("-s", "--settings",
                        help="Persistant file to save settings to",
                        default="../settings.json")

    parser.add_argument("-d", "--defaults",
                        help="folder with default version of files",
                        default="../defaults")

    parser.add_argument("-u", "--uploads",
                        help="folder where uploads to the HSM are stored",
                        default="../uploads")

    parser.add_argument("-b", "--binaries",
                        help="folder where uploads to the HSM are stored",
                        default="../binaries")

    parser.add_argument("-r", "--restart",
                        help="file with instructions on what to do at restart",
                        default="../uploads/restart.txt")

    parser.add_argument("--debug-cty",
                        action="store_true",
                        help="Show all data sent to the CTY",
                        )

    parser.add_argument("--serial-number",
                        help="The HSM's serial number",
                        default="00-00-00")

    parser.add_argument("--gpio-available",
                        action="store_true",
                        help="Use the GPIO features",
                        )

    parser.add_argument("--no-web",
                        action="store_true",
                        help="Son't start the web server.",
                        )

    parser.add_argument("--no-delay",
                        action="store_true",
                        help="Startup without a delay.",
                        )

    parser.add_argument("--cache-save",
                        default="../cache",
                        help="Folder to backup the cache to."
                        )

    args = parser.parse_args()

    # safe shutdown ----------------------------------
    global safe_shutdown
    safe_shutdown = SafeShutdown()

    # Settings ---------------------------------------
    settings = Settings(settings_file=args.settings,
                        gpio_available=args.gpio_available,
                        safe_shutdown=safe_shutdown)

    # LEDs -------------------------------------------
    led_container = start_leds(settings.get_setting(HSMSettings.GPIO_LEDS))

    # Tamper -----------------------------------------
    # initialize the tamper system
    tamper = TamperDetector(settings)

    safe_shutdown.addOnShutdown(tamper.stop)

    if(led_container is not None):
        tamper.add_observer(led_container.on_tamper_notify)

    # does this HSM support GPIO tamper?
    gpio_tamper_setter = None
    if(settings.get_setting(HSMSettings.GPIO_TAMPER)):
        try:
            import tampersetter_gpio
            gpio_tamper_setter = tampersetter_gpio.tampersetter_gpio()
        except Exception:
            pass
        

    # Make sure the certs exist ----------------------
    HSMSecurity().create_certs_if_not_exist(private_key_name=args.keyfile,
                                            certificate_name=args.certfile)

    # logging ----------------------------------------
    if args.log_file is not None:
        handler = logging.handlers.WatchedFileHandler(args.log_file)
        logging.getLogger().addHandler(handler)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)

    for handler in logging.getLogger().handlers:
        handler.setFormatter(logging.Formatter("%(asctime)-15s %(name)s[%(process)d]:%(levelname)s: %(message)s",
                             "%Y-%m-%d %H:%M:%S"))

    global log_rpc_codes_to_stdin

    if args.verbose:
        level = logging.DEBUG if args.verbose > 1 else logging.INFO
        logging.getLogger().setLevel(level)

    # network interface ------------------------------
    if(led_container is not None):
        led_container.led_determine_network_adapter()

    # wait for the network
    print("Looking for network interface")
    for i in range(3):
        # look for 15 seconds
        netiface = NetworkInterfaces(args.netiface, args.defaults)
        ip = netiface.get_ip()
        if(ip is not None):
            break
        print(".")
        time.sleep(5)

    # try the fall back
    if (ip is None):
        netiface = NetworkInterfaces('%s:1' % args.netiface, args.defaults)
        ip = netiface.get_ip()
        if (ip is not None):
            print("Falling back to %s:1" % args.netiface)
        else:
            print("Unable to establish network address.\r\nShutting down.")
            return

    # Prove for the devices --------------------------
    if(led_container is not None):
        led_container.led_probe_for_cryptech()

    cty_list = []
    rpc_list = []
    yield ProbeMultiIOStream.run_probes(cty_list, rpc_list, args)

    muxd.logger.info("Detected %i CTY connections",
                     len(cty_list))
    muxd.logger.info("Detected %i RPC connections",
                     len(rpc_list))

    futures = []
    ssl_options = {"certfile": args.certfile,
                   "keyfile": args.keyfile}

    rpc_preprocessor = None

    cache = None

    # Get ready to start servers ----------------------------------------
    if(led_container is not None):
        led_container.led_start_tcp_servers()

    # give the cryptech devices time to load up
    if(not args.no_delay):
        time.sleep(30)

    # start the cache
    cache = HSMCache(len(rpc_list), cache_folder=args.cache_save)
    safe_shutdown.addOnShutdown(cache.backup)

    # start the load balancer
    rpc_preprocessor = RPCPreprocessor(rpc_list, cache, settings, netiface,
                                       tamper)
    # Listen for incoming TCP/IP connections from remove cryptech.muxd_client
    rpc_server = RPCTCPServer(rpc_preprocessor, RPC_IP_PORT, ssl_options)
    # set the futures for all of our devices
    rpc_preprocessor.append_futures(futures)

    # create a secondary listener to handle PF_UNIX request from subprocesses
    rpc_secondary_listener = SecondaryPFUnixListener(rpc_server,
                                                     args.rpc_socket,
                                                     args.rpc_socket_mode)

    # only start synchronizer if we have connected RPC and CTYs
    if(len(cty_list) > 0 and len(rpc_list) > 0):
        # connect to the secondary socket for mirroring
        global synchronizer
        synchronizer = Synchronizer(args.rpc_socket, cache)

        # start the mirrorer
        synchronizer.append_future(futures)

    # start the console
    cty_stream = DiamondHSMConsole(args, cty_list, rpc_preprocessor,
                                   synchronizer, cache, netiface,
                                   settings, safe_shutdown, led_container,
                                   tamper, gpio_tamper_setter)

    # Listen for incoming TCP/IP connections from remove cryptech.muxd_client
    cty_server = CTYTCPServer(cty_stream, port=CTY_IP_PORT, ssl=ssl_options)

    # register for zeroconf if we are connected to a network
    ip = netiface.get_ip()
    if(ip is not None):
        register_zeroconf(ip, args.serial_number)

    # start web app ----------------------------------
    if(not args.no_web):
        os.system('/usr/bin/python webapp.py &')

    # because we don't have any CTYs or RPCs, there's nothing to keep
    # tornado going the following loop will prevent the app from
    # closing so the user can still communicate over CTY to diagnose
    # problems
    if(len(rpc_list) < 1):
        if(led_container is not None):
            led_container.led_error_cryptech_failure()

        while(True):
            yield time.sleep(0.05)

    # start our output loops, we can monitor their results if needed but
    #  that's a TODO
    if futures:
        if(led_container is not None):
            if (len(rpc_list) == DEVICES_IN_CHASE):
                led_container.led_ready()
            else:
                led_container.led_error_cryptech_partial_failure()

        wait_iterator = tornado.gen.WaitIterator(*futures)
        while not wait_iterator.done():
            try:
                result = yield wait_iterator.next()
            except Exception as e:
                muxd.logger.info("Error {} from {}".format(e,
                                 wait_iterator.current_future))
            else:
                muxd.logger.info("Result {} received from {} at {}".format(
                                 result, wait_iterator.current_future,
                                 wait_iterator.current_index))


if __name__ == "__main__":
    try:
        tornado.ioloop.IOLoop.current().run_sync(main)
    except (SystemExit, KeyboardInterrupt):
        if(synchronizer is not None):
            synchronizer.stop()
        if (safe_shutdown is not None):
            safe_shutdown.prepareForShutdown()
    except Exception:
        muxd.logger.exception("Unhandled exception")
    else:
        muxd.logger.debug("Main loop exited")