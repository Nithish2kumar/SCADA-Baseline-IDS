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
<<<<<<< HEAD
    iface="wlo1",
=======
    iface="lo",#You can give your interface like wlan, ethernet.
>>>>>>> 9c99bd83edb1bc41d9b9b1a57c79508ab2357156
    prn=process_packet,
    store=False
)
