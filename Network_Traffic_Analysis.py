from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys

def packet_callback(packet):
    """Callback function to process each captured packet."""
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        proto_name = "Unknown"
        
        # Determine protocol type
        if protocol == 6 and TCP in packet:
            proto_name = "TCP"
            payload = bytes(packet[TCP].payload)
        elif protocol == 17 and UDP in packet:
            proto_name = "UDP"
            payload = bytes(packet[UDP].payload)
        elif protocol == 1 and ICMP in packet:
            proto_name = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            payload = bytes(packet[IP].payload)
        
        # Format payload for display (truncate for readability)
        payload_str = payload[:50].hex() if payload else "No payload"
        if len(payload) > 50:
            payload_str += "..."
        
        # Print packet details
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto_name} ({protocol})")
        print(f"Payload (hex): {payload_str}")
        print("-" * 50)

def main():
    """Main function to start the packet sniffer."""
    try:
        print("Starting network sniffer... Press Ctrl+C to stop.")
        # Sniff packets with a filter for IP traffic, no promiscuous mode
        sniff(filter="ip", prn=packet_callback, store=0)
    except PermissionError:
        print("Error: Packet sniffing requires root/admin privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()