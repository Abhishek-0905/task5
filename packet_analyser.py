import scapy.all as scapy

# Helper function to map protocol numbers to protocol names
def get_protocol_name(proto_num):
    protocol_dict = {
        6: 'TCP',  # TCP protocol
        17: 'UDP',  # UDP protocol
        1: 'ICMP',  # ICMP protocol
    }
    return protocol_dict.get(proto_num, 'Unknown')

# Callback function to handle the packet analysis
def packet_callback(packet):
    if packet.haslayer(scapy.IP):  # Check if the packet contains an IP layer
        src_ip = packet[scapy.IP].src  # Source IP address
        dst_ip = packet[scapy.IP].dst  # Destination IP address
        protocol = packet[scapy.IP].proto  # Protocol type (TCP, UDP, ICMP, etc.)

        # Map protocol number to human-readable protocol name
        protocol_name = get_protocol_name(protocol)

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol_name}")

        # If the packet contains TCP
        if packet.haslayer(scapy.TCP):
            print("TCP Packet:")
            if packet.haslayer(scapy.Raw):  # Check if Raw data exists
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')[:100]  # Decode and limit to 100 characters
                print(f"Payload: {decoded_payload}")
            else:
                print("No Raw data in TCP packet.")

        # If the packet contains UDP
        elif packet.haslayer(scapy.UDP):
            print("UDP Packet:")
            if packet.haslayer(scapy.Raw):  # Check if Raw data exists
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')[:100]  # Decode and limit to 100 characters
                print(f"Payload: {decoded_payload}")
            else:
                print("No Raw data in UDP packet.")

        # If the packet contains ICMP (e.g., ping)
        elif packet.haslayer(scapy.ICMP):
            print("ICMP Packet")
            if packet.haslayer(scapy.Raw):  # Check if Raw data exists
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')[:100]  # Decode and limit to 100 characters
                print(f"Payload: {decoded_payload}")
            else:
                print("No Raw data in ICMP packet.")

def start_sniffing():
    print("Starting network packet sniffing...")
    # Start sniffing and capture packets indefinitely, calling `packet_callback` on each packet
    scapy.sniff(store=False, prn=packet_callback)  # `prn` is the callback function

# Start sniffing
start_sniffing()
