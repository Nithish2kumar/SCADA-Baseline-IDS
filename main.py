from scapy.all import *
from assets import *

packets = rdpcap("test.pcap")

for pkt in packets:
    discovering(pkt)

printAssest()