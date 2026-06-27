import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet contains an IP layer to read network traffic
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        
        # Determine protocol name based on standard IP protocol numbers
        protocol = "Unknown"
        if proto_num == 1:
            protocol = "ICMP"
        elif proto_num == 6:
            protocol = "TCP"
        elif proto_num == 17:
            protocol = "UDP"
            
        print(f"\n[+] Packet Captured:")
        print(f"    Source IP:      {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Protocol:       {protocol}")
        
        # Extract and display payload data if TCP or UDP protocols are present
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload)
            if payload:
                # Convert readable characters, replace non-printable characters with dots
                readable_payload = ''.join([chr(b) if 32 <= b < 127 else '.' for b in payload])
                print(f"    Payload Snippet: {readable_payload[:100]}")
            else:
                print("    Payload:        [Empty]")

def main():
    print("="*60)
    print("                BASIC NETWORK PACKET SNIFFER                  ")
    print("="*60)
    print("[*] Starting packet capture... Press Ctrl+C to stop.")
    
    try:
        # Sniff packets indefinitely without storing them in memory
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("\n[!] Error: Permission denied. Packet sniffing requires root/administrator privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Packet sniffing stopped by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()