import os
print("File exists:", os.path.exists("telnet.pcap"))  # Should return True
from scapy.all import rdpcap
packets = rdpcap("telnet.pcap")
print(f"Total packets: {len(packets)}")  # Should show >0 packets
for i, pkt in enumerate(packets[:5]):  # Check first 5 packets
    print(f"\nPacket {i}:")
    pkt.show()  # Display all layers