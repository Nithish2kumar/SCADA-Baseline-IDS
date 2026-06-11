from scapy.all import *
from config import knownDevice

register_history = {}


def detect(pkt):
    
    if IP in pkt:
        src_ip=pkt[IP].src

        if TCP in pkt:
            dport=pkt[TCP].dport
            if dport==502:
                if src_ip not in knownDevice:
                    print(f"⚠️  Unknown device {src_ip} trying to access")


def detectRegisterScan(src_ip, register):

    if src_ip not in register_history:
        register_history[src_ip] = set()
    register_history[src_ip].add(register)
    
    if len(register_history[src_ip]) >= 10:
        print(f"⚠️ ALERT: Possible Register Scan from {src_ip}")