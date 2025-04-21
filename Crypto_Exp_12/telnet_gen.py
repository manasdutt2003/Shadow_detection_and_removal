from scapy.all import IP, TCP, Raw, wrpcap

# Simulate a fake Telnet session (IP + TCP port 23 + fake credentials)
packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=23) / Raw(load="Username: admin\r\nPassword: 12345\r\n")

# Save to PCAP
wrpcap("telnet.pcap", [packet])
print("Generated telnet.pcap successfully!")