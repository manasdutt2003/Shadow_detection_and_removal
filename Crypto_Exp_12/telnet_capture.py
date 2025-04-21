from scapy.all import *
from scapy.layers.inet import TCP, IP
import sys
from datetime import datetime

def packet_handler(pkt):
    try:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].dport == 2323:
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                try:
                    text = payload.decode('utf-8', errors='replace').strip()
                    if text:
                        timestamp = datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S.%f')[:-3]
                        print(f"[{timestamp}] {pkt[IP].src}: {text}")
                except Exception as e:
                    print(f"Decoding error: {e}")
    except Exception as e:
        print(f"Packet processing error: {e}")

def start_capture():
    print("Starting Telnet capture...")
    try:
        # Try different socket types if default fails
        try:
            sniff(filter="tcp port 2323", prn=packet_handler, store=0)
        except:
            conf.L3socket = L3RawSocket
            sniff(filter="tcp port 2323", prn=packet_handler, store=0)
    except Exception as e:
        print(f"Capture failed: {e}")
        print("\nTROUBLESHOOTING:")
        print("1. Run as Administrator")
        print("2. Install Npcap from npcap.com")
        print("3. Check firewall settings")

if __name__ == "__main__":
    # List available interfaces
    print("Available interfaces:")
    for i, iface in enumerate(get_if_list(), 1):
        print(f"{i}. {iface}")
    
    try:
        start_capture()
    except KeyboardInterrupt:
        print("\nCapture stopped")