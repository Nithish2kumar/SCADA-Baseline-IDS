from scapy.all import *
from collections import defaultdict
from parser import parse
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
            
            if len(polling_baseline[key]) > 20:
                polling_baseline[key].pop(0)
            print(f"[Profile]: {src_ip}-->{dst_ip}")
            print(f"FC: {func}")
            print(f"Interval: {TimeDiff:.5f}")

            if len(polling_baseline[key])>=5:
                avg = sum(polling_baseline[key])/len(polling_baseline[key])

                if TimeDiff<avg*0.5:
                    print(f"⚠️ ALERT: High Frequency Polling from {src_ip}")

                elif TimeDiff>avg*2:
                    print(f"⚠️ ALERT: Polling Interval Deviation from {src_ip}")
            polling_baseline[key].append(TimeDiff)
        last_seen[key]=currentTime
    

