from scapy.all import *
from assets import *
from detector import detect
from parser import parse

packets = rdpcap("test.pcap")

for pkt in packets:
    discovering(pkt)
    detect(pkt)
    parse(pkt)

printAssest()

