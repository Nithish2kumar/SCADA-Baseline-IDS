import sys
import os
from scapy.all import *
from timing import timingCheck
from assets import *
from detector import *
from parser import *
from risk import *

def run_cli():
    # Load default pcap or one provided in arguments
    pcap_file = "risk.pcap"
    if len(sys.argv) > 1 and sys.argv[-1] != "--cli" and not sys.argv[-1].startswith("-"):
        pcap_file = sys.argv[-1]
    
    print(f"Running SCADA Baseline IDS (CLI Mode) on {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error loading PCAP file {pcap_file}: {e}")
        return

    for pkt in packets:
        if IP not in pkt:
            continue

        discovering(pkt)
        detect(pkt)

        funcCode, register = parse(pkt)
        alerting(pkt[IP].src, funcCode, register)

        timingCheck(pkt)
    printAssest()

if __name__ == "__main__":
    # Launch GUI unless --cli is specified or we are running in a headless environment
    if "--cli" in sys.argv or "DISPLAY" not in os.environ:
        run_cli()
    else:
        try:
            import gui
            gui.main()
        except ImportError as e:
            print(f"Could not load GUI dependencies ({e}). Falling back to CLI mode...")
            run_cli()