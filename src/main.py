#!/usr/bin/env python
import time
import socket
import struct
import select
from typing import Tuple, Union

#from /usr/include/linux/icmp.h
ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')
DEFAULT_ID = 0

def get_lookup(host: str) -> Union[Tuple[str,str], None]:
	try:
		addr = socket.gethostbyname(host)
		hostname = socket.gethostbyaddr(addr)[0]
		return (hostname, addr)
	except socket.gaierror as gai:
		print('Can not resolve host: name or service not known.')
		#print(gai)
		return None
	except Exception as err:
		print('Unknown exception')
		print(err)
		return None

def checksum(data: bytes):
	x = sum(x << 8 if i % 2 else x for i, x in enumerate(data))
	x = x & 0xFFFFFFFF
	x = (x >> 16) + (x & 0xFFFF)
	x = (x >> 16) + (x & 0xFFFF)
	x = ~x
	x = x & 0xFFFF
	return x

def create_packet(pkg_id: int = DEFAULT_ID, seq: int = 1, data = None):
	# header is
	# type(8 bits) # code(8 bits) # checksum(16 bits)
	# id(16 bits)                 # sequence(16 bits)
	header = struct.pack('bbHHH', ICMP_ECHO_REQUEST,0,0,pkg_id,seq)
	if data is None:
		data = (64 - 8) * b'i'
	pkg_checksum = checksum(header + data)
	header = struct.pack('bbHHH', ICMP_ECHO_REQUEST,0,pkg_checksum,pkg_id,seq)
	return header + data

# ping once
def ping_once():
	pacote = create_packet(seq=1)
	with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
		sock.connect( ('www.google.com',80) )
		sock.send(pacote)
		
		start_time = time.time()

		### RECEIVE
		# timeout 5
		time_left = timeout = 1
		while True:
			started_select = time.time()
			ready = select.select([sock],[],[], time_left)
			time_in_select = (time.time() - started_select)
			if ready[0] == []:
				print('Timeout.')
				return None
			
			time_received = time.time()

			# Listen for 1024 bytes because... reasons... idk
			recv = sock.recv(1024)

			ip_header = recv[:20]

			ip_version, ip_type_svc, ip_length, ip_id, ip_flags, ip_TTL, \
			ip_protocol, ip_checksum, ip_src, ip_dest = struct.unpack(
				"!BBHHHBBHII", ip_header)

			icmp_header = recv[20:28]

			icmp_type, icmp_code, icmp_checksum, icmp_pkg_id, icmp_seq \
				= struct.unpack('bbHHH', icmp_header)

			# dummy 0 id, change later
			if (icmp_type != ICMP_ECHO_REQUEST) and (icmp_pkg_id == DEFAULT_ID):
				return (time_received - start_time), ( len(recv) - 20 ), icmp_seq, ip_TTL

			time_left -= time_in_select
			if time_left <= 0:
				print('Timeout.')
				return None
			pass

if __name__ == '__main__':
	#print(ping_once())
	res = ping_once()
	if res is None:
		exit(0)
	ping_time, data_len, icmp_seq, ip_ttl = res
	print(f'Ping')
	print(f'{ping_time = }')
	print(f'{data_len = }')
	print(f'{icmp_seq = }')
	print(f'{ip_ttl = }')
	pass
