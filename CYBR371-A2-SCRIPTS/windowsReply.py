from scapy.all import *

# function to capture ICMP echo request packets
def spoof_icmp(pkt):
    if pkt[ICMP]:
        print("Received ICMP Echo Request")
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        icmp_id = pkt[ICMP].id
        icmp_seq = pkt[ICMP].seq

        # create ICMP Echo Reply packet with message
        message = "howdy from windows"
        reply_pkt = IP(src=ip_dst, dst=ip_src)/ICMP(type=0, id=icmp_id, seq=icmp_seq)/Raw(load=message)

        # simulate a Windows host by modifying the IP and ICMP fields
        reply_pkt[IP].ttl = 128
        reply_pkt[IP].id = 0
        reply_pkt[ICMP].type = 0  # ICMP Echo Reply

        print("Sending ICMP Echo Reply")
        send(reply_pkt)

# Sniff ICMP packets and process them
sniff(filter="icmp", prn=spoof_icmp)
