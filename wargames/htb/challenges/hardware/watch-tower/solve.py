
from scapy.all import *

def parse_modbus_packets(pcap_file):
    packets = rdpcap(pcap_file)  # Read pcap file
    modbus_packets = []

    for packet in packets:
        if packet.haslayer(TCP):
            if packet[TCP].dport == 502:  # Modbus TCP port
                modbus_packet = {
                    'timestamp': packet.time,
                    'source_ip': packet[IP].src,
                    'destination_ip': packet[IP].dst,
                    'source_port': packet[TCP].sport,
                    'destination_port': packet[TCP].dport,
                    'modbus_data': packet[TCP].payload.load  # Extract Modbus payload
                }
                modbus_packets.append(modbus_packet)

    return modbus_packets

# Example usage
if __name__ == "__main__":
    pcap_file = 'tower_logs.pcapng'
    modbus_packets = parse_modbus_packets(pcap_file)

    # Looking at it in wireshark, the 10th byte has the data inside of it
    data = []
    for packet in modbus_packets:
        if len(packet['modbus_data']) == 15:
            data.append(chr(packet['modbus_data'][9]))

    print(''.join(data))
