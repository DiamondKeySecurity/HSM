# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

from hsm_tools.cryptech_port import DKS_HSM

class HSMDataContext(object):
    def connect(self, socket = "/var/tmp/.cryptech_muxd.rpc"):
        return DKS_HSM(socket)