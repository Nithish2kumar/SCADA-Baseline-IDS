from scapy.all import *
from timing import timingCheck
from assets import *
from detector import *
from parser import *

packets = rdpcap("modbus_only.pcap")

for pkt in packets:

    if IP not in pkt:
        continue

    discovering(pkt)
    detect(pkt)

    register = parse(pkt)

    if register is not None:
        detectRegisterScan(pkt[IP].src, register)

    timingCheck(pkt)
printAssest()