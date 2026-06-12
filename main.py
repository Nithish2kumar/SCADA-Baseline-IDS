from scapy.all import *
from timing import timingCheck
from assets import *
from detector import *
from parser import *
from risk import *
packets = rdpcap("risk.pcap")

for pkt in packets:

    if IP not in pkt:
        continue

    discovering(pkt)
    detect(pkt)

    funcCode, register = parse(pkt)
    alerting(pkt[IP].src, funcCode, register)
    

    timingCheck(pkt)
printAssest()