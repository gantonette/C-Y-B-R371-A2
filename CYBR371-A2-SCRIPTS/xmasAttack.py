from scapy.all import *

# Set the target IP address
target_ip = "130.195.4.243"  #IP of target machine

#Setting the range of ports to scan
start_port = 1001
end_port = 2000

# Craft and send Xmas Tree packets
for port in range(start_port, end_port + 1):
	# Create a TCP packet with the Xmas Tree flags set
	xmas_packet = IP(dst=target_ip) / TCP(dport=port, flags="UPF")
    
	# Send the packet and receive the response
	response = sr1(xmas_packet, timeout=1, verbose=0)
    
	# Check if the port is open based on the response
	if response is not None and response.haslayer(TCP) and response[TCP].flags == "RA":
    	print(f"Port {port} is closed")
	else:
    	print(f"Port {port} is open")
