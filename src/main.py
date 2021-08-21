#!/usr/bin/env python
import time
import socket
import struct
from typing import Tuple

#from /usr/include/linux/icmp.h
ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')


def dns_lookup(): pass
def reverse_dns_lookup(): pass
def get_lookup(host: str) -> Tuple(str,str):
    addr = socket.gethostbyname_ex(host)[2][0]
    hostname = socket.gethostbyaddr(addr)[0]
    return (hostname, addr)
def checksum(): pass
def ping(): pass
def create_packet(id: int, seq: int = 1):
	# header is
	# type(8)
	# code(8)
	# checksum(16)
	# id(16)
	# sequence(16)
	#header = struct.pack('bbHHH',...)
	pass

if __name__ == '__main__':
	pass
