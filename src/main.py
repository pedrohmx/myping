#!/usr/bin/env python
import argparse
import time
import socket
import struct
import select
import signal
from typing import List, Tuple, Union

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
		print('Name or service not known.')
		#print(gai)
		return None
	except Exception as err:
		print('Could not reach name or service.')
		#print(err)
		return None

def checksum(data: bytes):
	x = sum(x << 8 if i % 2 else x for i, x in enumerate(data))
	x = x & 0xFFFFFFFF
	x = (x >> 16) + (x & 0xFFFF)
	x = (x >> 16) + (x & 0xFFFF)
	x = ~x
	x = x & 0xFFFF
	return x

def create_packet(pkt_id: int = DEFAULT_ID, seq: int = 1, data = None):
	# header is
	# type(8 bits) # code(8 bits) # checksum(16 bits)
	# id(16 bits)                 # sequence(16 bits)
	header = struct.pack('bbHHH', ICMP_ECHO_REQUEST,0,0,pkt_id,seq)
	if data is None:
		data = (64 - 8) * b'i'
	pkt_checksum = checksum(header + data)
	header = struct.pack('bbHHH', ICMP_ECHO_REQUEST,0,pkt_checksum,pkt_id,seq)
	return header + data

# ping once
def ping_once(host_name: str, host_addr: str, pkt_id=DEFAULT_ID, seq=1, timeout_ms=1000):
	pacote = create_packet(pkt_id=pkt_id, seq=seq)
	with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
		# Connect
		sock.connect( (host_name,80) )
		sock.send(pacote)
		
		start_time = time.time()

		### RECEIVE
		time_left = timeout_ms / 1000
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

			ip_version, ip_type_svc, ip_length, ip_id, ip_flags, ttl, \
			ip_protocol, ip_checksum, ip_src, ip_dest = struct.unpack(
				"!BBHHHBBHII", ip_header)

			icmp_header = recv[20:28]

			icmp_type, icmp_code, icmp_checksum, icmp_pkt_id, icmp_seq \
				= struct.unpack('bbHHH', icmp_header)

			if (icmp_type != ICMP_ECHO_REQUEST) and (icmp_pkt_id == DEFAULT_ID):
				delta_ms = (time_received - start_time) * 1000
				print(f'{len(recv)-20} bytes from {host_name} ({host_addr}): {icmp_seq=} {ttl=} time={delta_ms:.3f} ms')
				return delta_ms

			time_left -= time_in_select
			if time_left <= 0:
				print('Timeout.')
				return None
			pass

def stats(timing_list: List[float], packets_lost: int):
	rcvd_pkt = len(timing_list)
	total_pkt = rcvd_pkt + packets_lost
	percent = (packets_lost / total_pkt) * 100
	print(f'\n{total_pkt} packets transmitted, {rcvd_pkt} received, {percent}% packet loss.')
	if len(timing_list) == 0:
		return
	rtt_min = min(timing_list)
	rtt_avg = sum(timing_list) / len(timing_list)
	rtt_max = max(timing_list)
	print(f'rtt min/avg/max = {rtt_min:.3f}/{rtt_avg:.3f}/{rtt_max:.3f} ms.')
	pass

def _sigint_handler(signum,frame):
	'''Handle exit via SIG INT'''
	global timing_list
	global lost_packets
	stats(timing_list=timing_list, packets_lost=lost_packets)
	print('\nTerminated with signal SIGINT')
	exit(0)
	pass

if __name__ == '__main__':
	# register signal handler
	signal.signal(signal.SIGINT, _sigint_handler)
	####    argparse
	parser = argparse.ArgumentParser()
	
	parser.add_argument('destination',
		help="DNS name or IPv4 address")
	
	parser.add_argument('--count','-c',
		type=int,
		help='number of echo requests to send',
		default=255)
	
	parser.add_argument('--timeout',
		type=int,
		help='time to wait for response, in ms',
		default=1000)

	args = parser.parse_args()

	HOSTNAME = args.destination
	COUNT = args.count
	TIMEOUT_MS = args.timeout
	####    ####    ####    ####

	# look up address
	res = get_lookup(HOSTNAME)
	if res is None:# if not reachable, exit
		exit(0)
	host_name, host_addr = res

	print(f'PING {host_name} ({host_addr}) with 56 (84: ip(20) + icmp(8) + payload) bytes of data.\n')
	
	global timing_list
	global lost_packets
	timing_list = []
	lost_packets = 0

	seq = 1
	while True:
		# ping
		res = ping_once(
			host_name=host_name, host_addr=host_addr, seq=seq, timeout_ms=TIMEOUT_MS)
		# store result
		if res is None:
			lost_packets += 1
		else:
			timing_list.append(res)
		# check loop
		time.sleep(0.5)
		if COUNT is None:
			continue
		if seq >= COUNT:
			break
		else:
			seq += 1
		pass
	# stats
	stats(timing_list=timing_list, packets_lost=lost_packets)
	pass
