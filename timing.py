from scapy.all import *
from collections import defaultdict
from parser import parse
from alert import print_alert
import time


last_seen={}
polling_baseline=defaultdict(list)

def timingCheck(pkt):
    if TCP not in pkt:
        return

    if pkt[TCP].dport != 502:
        return
    src_ip=pkt[IP].src
    dst_ip=pkt[IP].dst
    func, reg=parse(pkt)
    if func is not None:
        key=(src_ip, dst_ip,func)
        currentTime=pkt.time

        if key in last_seen:
            TimeDiff=currentTime-last_seen[key]
            

            if len(polling_baseline[key])>=5:
                avg = sum(polling_baseline[key])/len(polling_baseline[key])

                if TimeDiff<4:
                    print_alert(
                        alert_type="High Frequency Polling",

                        severity="MEDIUM",

                        source=src_ip,

                        destination=dst_ip,

                        function_code=func,

                        details=f"Polling interval detected: {TimeDiff:.2f} sec",

                        actions=[
                            "Check for scan activity",
                            "Verify maintenance tasks",
                            "Rate limit source if required"
                        ]
                    )

                elif TimeDiff>avg*2:
                    print(f"⚠️ ALERT: Polling Interval Deviation from {src_ip}")
                    print("Recommended Actions:")
                    print(" - Investigate network latency")
                    print(" - Check HMI configuration")
                    print(" - Verify controller status")

            polling_baseline[key].append(TimeDiff)
        last_seen[key]=currentTime
    

