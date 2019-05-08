# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.

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