from scapy.all import *
from timing import timingCheck
from assets import *
from detector import *
from parser import *
from risk import *

def process_packet(pkt):

    if IP not in pkt:
        return

    discovering(pkt)
    detect(pkt)

    funcCode, register = parse(pkt)
    alerting(pkt[IP].src, funcCode, register)

    timingCheck(pkt)

print("SCADA IDS Started...")
print("Monitoring Modbus Traffic...")

sniff(
    iface="lo",#You can give your interface like wlan, ethernet.
    prn=process_packet,
    store=False
)
