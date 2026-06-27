import sys
from scapy.all import sniff, IP, ICMP, TCP

# Define threshold for ICMP Flood detection (Packets per source)
ICMP_TRACKER = {}
ICMP_THRESHOLD = 5

def analyze_packet(packet):
    global ICMP_TRACKER
    
    # Ensure packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # --- RULE 1: DETECT ICMP (PING) FLOOD ---
        if ICMP in packet:
            ICMP_TRACKER[src_ip] = ICMP_TRACKER.get(src_ip, 0) + 1
            if ICMP_TRACKER[src_ip] >= ICMP_THRESHOLD:
                print(f"\n[!!! ALERT !!!] ICMP Flood/Scan Detected!")
                print(f"    Source IP: {src_ip} -> Destination IP: {dst_ip}")
                print(f"    Details: Source triggered {ICMP_TRACKER[src_ip]} ping requests.")
        
        # --- RULE 2: DETECT UNAUTHORIZED SSH ATTEMPTS ---
        elif packet.haslayer(TCP) and packet[TCP].dport == 22:
            # Check for TCP SYN flag (Connection attempt)
            if packet[TCP].flags == "S":
                print(f"\n[!!! ALERT !!!] Inbound SSH Connection Attempt Detected!")
                print(f"    Source IP: {src_ip}:{packet[TCP].sport} -> Destination IP: {dst_ip}:22")
        
        # --- RULE 3: DETECT MALICIOUS WEB XSS RECONNAISSANCE ---
        elif packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            payload = bytes(packet[TCP].payload)
            if payload:
                # Look for common XSS scripts string signatures
                if b"<script>" in payload.lower() or b"alert(" in payload.lower():
                    print(f"\n[!!! ALERT !!!] Potential Web Cross-Site Scripting (XSS) Detected!")
                    print(f"    Source IP: {src_ip} -> Destination IP: {dst_ip}")
                    print(f"    Signature Matched: Executable script tags found in payload.")

def main():
    print("="*60)
    print("             PYTHON NETWORK INTRUSION DETECTION SYSTEM          ")
    print("="*60)
    print("[*] NIDS Active. Monitoring network traffic for signatures...")
    print("[*] Press Ctrl+C to stop evaluation.")
    
    try:
        # Sniff interface indefinitely and process through rule analysis engine
        sniff(prn=analyze_packet, store=False)
    except PermissionError:
        print("\n[!] Error: Administrative privileges required to hook onto the network interface.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] NIDS monitoring halted by user. Exiting cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    main()