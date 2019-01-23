# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
import tornado.ioloop
import tornado.web

from hsm_tools.hsm import PFUNIX_HSM
from hsm_tools.cryptech_port import DKS_HALError, DKS_RPCFunc
from mgmt_pages.homeController import homeController

from settings import WEB_PORT

def make_app():
    return tornado.web.Application([
        (r"/", homeController),
        (r"/images/(.*)",tornado.web.StaticFileHandler, {"path": "./mgmt_pages/images"},),
    ], debug=True)

if __name__ == "__main__":
    print 'starting web app'
    app = make_app()
    app.listen(WEB_PORT)
    tornado.ioloop.IOLoop.current().start()