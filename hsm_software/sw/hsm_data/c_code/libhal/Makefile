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
all: test.out libhal.a

test.out : test.o libhal.a
	gcc -std=c++17  test.o libhal.a -lpthread  -lstdc++ -shared-libgcc -o test.out

test.o : hal.h hal_internal.h test.cpp rpc_packet.h
	g++ -std=c++17 -O -c test.cpp

libhal.a: xdr.o logging.o rpc_stream.o
	${AR} rcs $@ $^ 

xdr.o : xdr.c xdr_internal.h hal.h hal_internal.h
	${CC} -O -c xdr.c

logging.o : logging.c hal.h hal_internal.h
	${CC} -O -c logging.c

rpc_stream.o : rpc_stream.cpp hal.h hal_internal.h rpc_stream.h safe_queue.h rpc_packet.h
	${CXX} -std=c++17  -O -c rpc_stream.cpp

clean:
	rm libhal_lite.a
	rm *.o