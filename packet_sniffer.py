from scapy.all import sniff, IP, TCP, UDP, Raw
import csv
from datetime import datetime
from collections import Counter

# Initialize packet counter
ip_counter = Counter()
THRESHOLD = 50  # Alert if an IP sends more than 50 packets

# Create CSV file with headers
with open('packets.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port", "Payload Snippet", "Summary"])

# Define callback function
def packet_callback(packet):
    if packet.haslayer(IP):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = ""
        src_port = ""
        dst_port = ""
        payload_snip = ""

        # TCP/UDP info
        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Capture first 50 characters of payload
        if packet.haslayer(Raw):
            payload_snip = str(packet[Raw].load)[:50]

        summary = packet.summary()

        # Print basic info
        print(f"[{timestamp}] Packet from {src_ip} to {dst_ip} ({proto})")

        # Track high-traffic IPs
        ip_counter[src_ip] += 1
        if ip_counter[src_ip] > THRESHOLD:
            print(f"[ALERT] High traffic from {src_ip}!")

        # Append packet info to CSV
        with open('packets.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, proto, src_port, dst_port, payload_snip, summary])

# Filter only HTTP, HTTPS, and DNS traffic
bpf_filter = "tcp port 80 or tcp port 443 or udp port 53"

print("Sniffing HTTP/HTTPS/DNS packets... Press Ctrl+C to stop.")
sniff(filter=bpf_filter, prn=packet_callback, store=0)
