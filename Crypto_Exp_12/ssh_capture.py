from scapy.all import *
from scapy.layers.inet import TCP, IP  # Explicitly import required protocol layers
from threading import Event
import sys

stop_capture = Event()

def packet_handler(pkt):
    """Process each SSH packet"""
    try:
        # Verify packet has all required layers
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].dport == 2222:
            size = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
            src_ip = pkt[IP].src
            print(f"SSH Packet from {src_ip}: {size} encrypted bytes")
            
    except Exception as e:
        print(f"Error processing packet: {e}", file=sys.stderr)

def start_capture(interface=None):
    """Start SSH packet capture"""
    print("\nSSH Packet Capture Started (Port 2222)")
    print("Press Ctrl+C to stop...\n")
    
    try:
        sniff(
            iface=interface,
            filter="tcp port 2222",
            prn=packet_handler,
            stop_filter=lambda _: stop_capture.is_set()
        )
    except Exception as e:
        print(f"Capture Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    try:
        # List available interfaces
        print("Available network interfaces:")
        for iface in get_if_list():
            print(f" - {iface}")
        
        # Start capture (uncomment to specify interface)
        # start_capture(interface="Ethernet")  # Windows
        # start_capture(interface="eth0")      # Linux
        start_capture()
        
    except KeyboardInterrupt:
        stop_capture.set()
        print("\nCapture stopped by user")