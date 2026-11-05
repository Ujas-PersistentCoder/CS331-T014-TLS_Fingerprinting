from scapy.all import rdpcap, IP, TCP
from pathlib import Path

packets = rdpcap(str(Path(__file__).resolve().parents[2] / "pcaps/capture.pcap"))

for packet in packets:
    if IP in packet and TCP in packet:
        print(
            packet[IP].src,
            packet[TCP].sport,
            "→",
            packet[IP].dst,
            packet[TCP].dport,
            "Seq:", packet[TCP].seq,
            "Ack:", packet[TCP].ack
        )
