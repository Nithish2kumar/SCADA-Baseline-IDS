from scapy.all import *
from timing import timingCheck
from assets import *
from detector import *
from parser import *
from report import generate_report
from session import get_alerts
from risk import *
from verification import verify

if not verify():
    print("⚠️ CONFIGURATION TAMPERING DETECTED")
    exit()

print("✅ Configuration Verified")

def process_packet(pkt):

    if IP not in pkt:
        return

    discovering(pkt)
    detect(pkt)

    funcCode, register=parse(pkt)
    alerting(pkt[IP].src, funcCode, register)

    timingCheck(pkt)


choice=int(input(
    "Enter your choice:\n"
    "1. Live Monitoring\n"
    "2. Analyze PCAP File\n"
))

if choice==1:

    print("SCADA IDS Started...")
    print("Monitoring Modbus Traffic...")

    sniff(
        iface="wlo1",
        prn=process_packet,
        store=False
    )

elif choice==2:

    filename=input("Enter pcap file name: ")

    packets=rdpcap(filename)

    print(f"Loaded {len(packets)} packets")

    for pkt in packets:
        process_packet(pkt)
    
    generate_report(
    get_alerts(),
    filename
    )

else:
    print("Invalid Choice")