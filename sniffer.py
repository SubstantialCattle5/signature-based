from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw

from scapy.all import *


def extract_packet_data(pcap_file, save_payload=False, payload_threshold=1024):
    packets = rdpcap(pcap_file)
    extracted_data = []

    for packet in packets:
        data = {}

        # Extract basic header information (source/destination IP, protocol)
        if packet.haslayer(IP):
            data["source_ip"] = packet[IP].src
            data["destination_ip"] = packet[IP].dst
            data["protocol"] = packet[IP].proto

        # Access packet payload (if applicable)
        if packet.haslayer(Raw):
            data["payload"] = packet[Raw].load.hex()  # Convert payload to hex string

            if save_payload:
                # Conditionally save payload based on criteria (e.g., signature match)
                if len(packet[Raw].load) <= payload_threshold:
                    data["full_payload"] = packet[Raw].load  # Save complete payload if within limit

        # Extract data from specific layers (e.g., TCP ports, flags)
        if packet.haslayer(TCP):
            data["source_port"] = packet[TCP].sport
            data["destination_port"] = packet[TCP].dport
            data["flags"] = packet[TCP].flags  # Capture TCP flags as a string

        # Handle UDP packets
        elif packet.haslayer(UDP):
            data["source_port"] = packet[UDP].sport
            data["destination_port"] = packet[UDP].dport

        # Handle ICMP packets
        elif packet.haslayer(ICMP):
            data["icmp_type"] = packet[ICMP].type
            data["icmp_code"] = packet[ICMP].code

        # Handle ARP packets
        elif packet.haslayer(ARP):
            data["arp_source_ip"] = packet[ARP].psrc
            data["arp_destination_ip"] = packet[ARP].pdst
            data["arp_source_mac"] = packet[ARP].hwsrc
            data["arp_destination_mac"] = packet[ARP].hwdst

        # Handle Ethernet packets
        elif packet.haslayer(Ether):
            data["source_mac"] = packet[Ether].src
            data["destination_mac"] = packet[Ether].dst
            data["ethertype"] = packet[Ether].type

        # Handle DNS packets
        elif packet.haslayer(DNS):
            data["dns_query"] = packet[DNS].qd.qname.decode('utf-8')

        # You can add more data extraction based on your needs (e.g., timestamps)
        extracted_data.append(data)

    return extracted_data


if __name__ == "__main__":
    # Example usage with payload storage enabled
    pcap_file = "captured_traffic.pcap"
    save_payload = True  # Enable payload storage
    payload_threshold = 1024  # Save payloads up to 1024 bytes
    extracted_data = extract_packet_data(pcap_file, save_payload, payload_threshold)

    # Print or store the extracted data (with optional payload)
    for key in extracted_data[11]:
        print(f"{key} : {extracted_data[11][key]}, \n")
