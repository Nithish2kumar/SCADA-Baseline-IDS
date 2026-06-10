from scapy.all import *

from assets import *
from detector import *
from parser import *

packets = rdpcap("reg.pcap")

for pkt in packets:
    discovering(pkt)
    detect(pkt)
    register = parse(pkt)
    if register is not None:
        detectRegisterScan(pkt[IP].src,register)

printAssest()