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
def get_lookup(host: str) -> Tuple[str,str]:
    addr = socket.gethostbyname_ex(host)[2][0]
    hostname = socket.gethostbyaddr(addr)[0]
    return (hostname, addr)
def checksum():
	# TODO:
	return 0
def ping(): pass
def create_packet(id: int, seq: int = 1):
	# header is
	# type(8)
	# code(8)
	# checksum(16)
	# id(16)
	# sequence(16)
	header = struct.pack('bbHHH', ICMP_ECHO_REQUEST,0,0,id,seq)
	data = 64 * b'i'
	pkg_checksum = checksum(header + data)
	header = struct.pack('bbHHH', ICMP_ECHO_REQUEST,0,pkg_checksum,id,seq)
	pass

if __name__ == '__main__':
	pass
