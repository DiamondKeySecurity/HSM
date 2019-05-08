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
