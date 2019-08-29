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
#
# Script to import CrypTech code into DKS HSM folders.
#
all: keydb.out

keydb.out : keydb.o
	gcc -std=c++17  keydb.o -L/usr/local/mysql/lib -lmysqlclient -lpthread  -lstdc++ -shared-libgcc -o keydb.out

keydb.o : keydb.cpp keydb_connector.h keydb_mysql_connector.h
	g++ -std=c++17 -I/usr/include/mysql -O -c keydb.cpp

clean:
	rm keydb.out
	rm *.o