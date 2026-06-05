from scapy.all import *

assets = {}

def discovering(pkt):
    if IP in pkt and TCP in pkt:
        src_ip=pkt[IP].src
        dst_ip=pkt[IP].dst
        sport=pkt[TCP].sport
        dport=pkt[TCP].dport

        if sport==502:
            assets[src_ip]="PLC"
            assets[dst_ip]="HMI"
        elif dport==502:
            assets[dst_ip]="PLC"
            assets[src_ip]="HMI"


def printAssest():
    print("\n-----Assest Info-----")
    for ip,role in assets.items():
        print(f"{ip}-->{role}")