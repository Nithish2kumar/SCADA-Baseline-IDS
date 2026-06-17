from scapy.all import *
from config import knownDevice
from logger import log_event
register_history = {}


def detect(pkt):
    
    if IP in pkt:
        src_ip=pkt[IP].src

        if TCP in pkt:
            dport=pkt[TCP].dport
            if dport==502:
                if src_ip not in knownDevice:

                    log_event(
                        event_type="UNKNOWN_DEVICE",
                        severity="HIGH",
                        source=src_ip,
                        details="Attempting Modbus access"
                    )
                    print(f"\n⚠️ ALERT: Unknown device {src_ip}")
                    print("Recommended Actions:")
                    print(" - Verify device inventory")
                    print(" - Check switch/router logs")
                    print(" - Block device if unauthorized")
                    print(" - Investigate possible rogue host")
