from scapy.all import *

def analyze_telnet():
    try:
        packets = rdpcap("telnet.pcap")
        
        if not packets:
            print("No packets found in PCAP file")
            return

        print("Analyzing Telnet traffic...\n")
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload:  # Only print non-empty payloads
                        print(f"[+] Telnet Data: {payload}")
                except Exception as e:
                    print(f"Error decoding payload: {e}")

    except Exception as e:
        print(f"Analysis failed: {e}")

if __name__ == "__main__":
    analyze_telnet()