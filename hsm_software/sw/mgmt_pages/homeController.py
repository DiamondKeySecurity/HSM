# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#

import tornado.ioloop
import tornado.web

from model.hsmStatusModel import hsmStatusModel

from hsmDataContext import HSMDataContext

class homeController(tornado.web.RequestHandler):
    # def __init__(self):
    #     self.context = HSMDataContext()

    def get(self):
        self.context = HSMDataContext()
        with self.context.connect() as hsm:
            device_state = hsm.rpc_get_hsm_state()
            ip = hsm.rpc_get_ip()

        hsm = hsmStatusModel(ipaddr=ip, cryptech_device_state = device_state)
        self.render("views/homeView.html", title="Diamond HSM", hsm=hsm)
