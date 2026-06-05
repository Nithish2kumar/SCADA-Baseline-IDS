from scapy.all import *

assets = {}

def discovering(pkt):
    if IP in pkt and TCP in pkt:
        src_ip=pkt[IP].src
        dst_ip=pkt[IP].dst
        sport=pkt[TCP].sport
        dport=pkt[TCP].dport

        if sport == 502:
            if src_ip not in assets:
                assets[src_ip] = "PLC"
            if dst_ip not in assets:
                assets[dst_ip] = "HMI"

        elif dport == 502:
            if dst_ip not in assets:
                assets[dst_ip] = "PLC"
            if src_ip not in assets:
                assets[src_ip] = "HMI"



def printAssest():
    print("\n-----Assest Info-----")
    for ip,role in assets.items():
        print(f"{ip}-->{role}")

