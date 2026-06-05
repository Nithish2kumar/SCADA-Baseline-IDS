from scapy.all import *
from config import knownDevice

def detect(pkt):
    
    if IP in pkt:
        src_ip=pkt[IP].src

        if TCP in pkt:
            dport=pkt[TCP].dport
            if dport==502:
                if src_ip not in knownDevice:
                    print(f"⚠️  Unknown device {src_ip} trying to access")

