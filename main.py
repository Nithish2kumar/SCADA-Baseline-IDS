from scapy.all import *
from assets import *
from detector import detect

packets = rdpcap("mobile.pcap")

for pkt in packets:
    discovering(pkt)
    detect(pkt)

printAssest()

