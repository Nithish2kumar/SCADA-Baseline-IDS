#!/usr/bin/env python3
import os
import sys
import time
import json
import hashlib
import threading
import re
from datetime import datetime

# SCADA IDS Imports
from scapy.all import rdpcap, sniff, IP, TCP
from timing import timingCheck
import timing
from assets import discovering, assets
import assets as assets_module
from detector import detect
import detector as detector_module
from parser import parse
from report import generate_report
from session import get_alerts, clear_alerts, add_alert
import session as session_module
from risk import alerting
import alert as alert_module

# Rich imports
import rich
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt
from rich.align import Align

# Global Console instance
console = Console()

# Global CLI State
cli_instance = None
stop_sniffing = False
is_sniffing_active = False

# Custom Stream to suppress default stdout from detector/risk/timing modules
class DummyStream:
    def write(self, x): pass
    def flush(self): pass

# Custom timing alerts patch
def custom_print_alert(alert_type, severity, source, destination, function_code, details, actions):
    if cli_instance:
        cli_instance.print_timing_alert(alert_type, severity, source, destination, function_code, details, actions)

alert_module.print_alert = custom_print_alert
timing.print_alert = custom_print_alert

class SCADAHackerCLI:
    def __init__(self):
        global cli_instance
        cli_instance = self
        self.interface = "wlo1"
        self.total_packets = 0
        self.log_file = "events.log"

    def verify_integrity(self):
        console.clear()
        console.print(Panel(
            Align.center(f"[bold green]SCADA BASELINE IDS - INTEGRITY SECURE BOOT[/bold green]\n"
                         f"[grey50]System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/grey50]"),
            border_style="grey50",
            width=72
        ))
        
        console.print(" [cyan][i][/cyan] Initializing hardware drivers...")
        time.sleep(0.2)
        console.print(" [cyan][i][/cyan] Querying network sockets...")
        time.sleep(0.2)
        
        with console.status("[bold cyan]LOADING CRYPTOGRAPHIC MODULES...[/bold cyan]", spinner="dots") as status:
            time.sleep(0.8)
            
        console.print(" [cyan][i][/cyan] Loading config integrity hash...")
        try:
            with open("config.hash", "r") as f:
                stored_hash = f.read().strip()
            console.print(f"     Stored SHA256: [cyan]{stored_hash[:32]}...[/cyan]")
        except Exception as e:
            console.print(f" [bold red][ERR] Failed to load config.hash: {e}[/bold red]")
            stored_hash = None
            
        with console.status("[bold cyan]COMPUTING CONFIGURATION CHECKSUM...[/bold cyan]", spinner="dots") as status:
            time.sleep(0.6)
            
        try:
            with open("config.json", "rb") as f:
                data = f.read()
            computed_hash = hashlib.sha256(data).hexdigest()
            console.print(f"     Computed SHA256: [cyan]{computed_hash[:32]}...[/cyan]")
        except Exception as e:
            console.print(f" [bold red][ERR] Failed to compute checksum: {e}[/bold red]")
            computed_hash = None

        if stored_hash and computed_hash and stored_hash == computed_hash:
            console.print(f"\n [bold green][SUCCESS] CONFIGURATION INTEGRITY CHECK PASSED [OK][/bold green]\n")
            time.sleep(0.4)
            return True
        else:
            console.print(f"\n [bold red blink]⚠️ CONFIGURATION TAMPERING DETECTED! ⚠️[/bold red blink]")
            console.print(f" [red]System configuration does not match the cryptographic baseline signature.[/red]")
            console.print(f" [red]Security core has locked initialization.[/red]\n")
            return False

    def print_welcome(self):
        console.clear()
        banner = """
███████╗ ██████╗ █████╗ ██████╗  █████╗     ██╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗    ██║██╔══██╗██╔════╝
███████╗██║     ███████║██║  ██║███████║    ██║██║  ██║███████╗
╚════██║██║     ██╔══██║██║  ██║██╔══██║    ██║██║  ██║╚════██║
███████║╚██████╗██║  ██║██████╔╝██║  ██║    ██║██████╔╝███████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝    ╚═╝╚═════╝ ╚══════╝
"""
        console.print(Text(banner, style="bold green"))

    def draw_status_hud(self):
        alerts = get_alerts()
        total_alerts = len(alerts)
        critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high = sum(1 for a in alerts if a.get("severity") == "HIGH")
        medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
        low = sum(1 for a in alerts if a.get("severity") == "LOW")
        
        cfg = self.load_config_file()
        trusted_count = len(cfg.get("KnownDevices", []))
        discovered_count = len(assets)
        
        status_text = "[bold green]ACTIVE[/bold green]" if is_sniffing_active else "[grey50]IDLE[/grey50]"
        
        grid = Table.grid(padding=(0, 2))
        grid.add_column(width=32)
        grid.add_column(width=32)
        grid.add_row(
            f"[bold]Sniffer State:[/bold] {status_text}",
            f"[bold]Trusted Assets:[/bold] [cyan]{trusted_count}[/cyan]"
        )
        grid.add_row(
            f"[bold]Packets Rx:[/bold] [cyan]{self.total_packets}[/cyan]",
            f"[bold]Devices Discovered:[/bold] [cyan]{discovered_count}[/cyan]"
        )
        
        content = Table.grid(padding=(0, 0))
        content.add_row(grid)
        content.add_row("[grey50]" + "─" * 68 + "[/grey50]")
        
        metrics_text = (
            f"[bold]ALARM METRICS:[/bold]  "
            f"[bold magenta]CRITICAL:[/bold magenta] {critical}    "
            f"[bold red]HIGH:[/bold red] {high}    "
            f"[bold yellow]MEDIUM:[/bold yellow] {medium}    "
            f"[bold cyan]LOW:[/bold cyan] {low}    "
            f"[bold white]TOTAL:[/bold white] {total_alerts}"
        )
        content.add_row(metrics_text)
        
        panel = Panel(
            content,
            title="[bold green]IDS CONSOLE SECURITY MATRIX[/bold green]",
            border_style="grey50",
            width=72
        )
        console.print(panel)

    def print_menu(self):
        self.draw_status_hud()
        console.print(f"\n [bold cyan]Select Operational Subsystem:[/bold cyan]")
        menu_items = [
            ("[bold green][1][/bold green]", "Sniff Live Modbus Traffic (Root Required)"),
            ("[bold green][2][/bold green]", "Analyze Offline PCAP Logs"),
            ("[bold green][3][/bold green]", "Explore Discovered Topology / Devices"),
            ("[bold green][4][/bold green]", "View Console Log History (events.log)"),
            ("[bold green][5][/bold green]", "Manage Trusted Devices Config"),
            ("[bold green][6][/bold green]", "Perform Verification Integrity Audit"),
            ("[bold green][7][/bold green]", "Secure Terminal Exit (Shutdown)")
        ]
        for key, desc in menu_items:
            console.print(f"   {key} {desc}")

    def load_config_file(self):
        try:
            with open("config.json", "r") as f:
                return json.load(f)
        except Exception:
            return {"KnownDevices": []}

    def save_config_file(self, cfg):
        with open("config.json", "w") as f:
            json.dump(cfg, f, indent=4)
        
        detector_module.knownDevices = cfg.get("KnownDevices", [])
        
        with open("config.json", "rb") as f:
            data = f.read()
        hash_val = hashlib.sha256(data).hexdigest()
        with open("config.hash", "w") as f:
            f.write(hash_val)
            
        try:
            with open("config.py", "w") as f:
                f.write("knownDevice = [\n")
                for ip in cfg.get("KnownDevices", []):
                    f.write(f"    \"{ip}\",\n")
                f.write("]\n")
        except Exception:
            pass

    def run(self):
        if not self.verify_integrity():
            return
        
        time.sleep(0.5)
        while True:
            try:
                self.print_welcome()
                self.print_menu()
                choice = Prompt.ask("\n[bold cyan]SCADA_IDS[/bold cyan]").strip()
                
                if choice == '1':
                    self.start_live_sniffing()
                elif choice == '2':
                    self.analyze_pcap_interactive()
                elif choice == '3':
                    self.explore_assets()
                elif choice == '4':
                    self.view_logs()
                elif choice == '5':
                    self.manage_config()
                elif choice == '6':
                    self.run_manual_integrity()
                elif choice == '7':
                    console.print("\n [bold yellow][!][/bold yellow] Initiating secure shutdown sequence...")
                    time.sleep(0.3)
                    console.print(" [bold yellow][!][/bold yellow] Saving logs and metrics to database...")
                    time.sleep(0.2)
                    console.print(" [bold green][SUCCESS][/bold green] System offline. Goodbye hacker.")
                    break
                else:
                    console.print(" [bold red][!] Unauthorized command format. Try again.[/bold red]")
                    time.sleep(0.8)
            except KeyboardInterrupt:
                console.print(f"\n [bold yellow][!] KeyboardInterrupt caught. Returning to command central.[/bold yellow]")
                time.sleep(0.8)

    # --- Live Sniffing ---
    def start_live_sniffing(self):
        global stop_sniffing, is_sniffing_active
        
        if os.geteuid() != 0:
            console.print(f"\n [bold red][ACCESS DENIED] Raw packet sniffing requires root permissions![/bold red]")
            console.print(f" [red]Please relaunch the script using: [bold]sudo python3 hacker_cli.py[/bold][/red]")
            input(f"\n Press Enter to return...")
            return

        console.clear()
        console.print(Panel(
            Align.center(f"[bold green]SCADA IDS - LIVE TRAFFIC COCKPIT[/bold green]\n"
                         f"[grey50]Sniffing Interface: [bold]{self.interface}[/bold] | Modbus TCP Port: [bold]502[/bold]\n"
                         f"[bold yellow]Press Ctrl+C to stop sniffing and return to console.[/bold yellow]"),
            border_style="grey50",
            width=72
        ))
        console.print(" [green][*] Initializing sniffer thread...[/green]")
        time.sleep(0.5)

        stop_sniffing = False
        is_sniffing_active = True
        alerts_count_before = len(get_alerts())

        def should_stop_filter(pkt):
            return stop_sniffing

        def sniff_worker():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.process_live_packet,
                    store=False,
                    stop_filter=should_stop_filter
                )
            except Exception as e:
                console.print(f"\n [bold red][ERROR] Sniffing thread failed: {e}[/bold red]")

        sniff_thread = threading.Thread(target=sniff_worker, daemon=True)
        sniff_thread.start()

        console.print(" [bold green][ACTIVE] Monitoring live Modbus traffic...[/bold green]\n")

        try:
            while not stop_sniffing:
                time.sleep(0.1)
                current_alerts = get_alerts()
                if len(current_alerts) > alerts_count_before:
                    new_alerts = current_alerts[alerts_count_before:]
                    for alert in new_alerts:
                        self.print_hacker_alert(alert)
                    alerts_count_before = len(current_alerts)
        except KeyboardInterrupt:
            console.print(f"\n [bold yellow][*] Halting live traffic sniffer...[/bold yellow]")
        finally:
            stop_sniffing = True
            is_sniffing_active = False
            sniff_thread.join(timeout=2.0)
            console.print(" [green][*] Sniffer deactivated safely.[/green]")
            time.sleep(1.0)

    def process_live_packet(self, pkt):
        self.total_packets += 1
        if IP not in pkt:
            return
        
        old_stdout = sys.stdout
        sys.stdout = DummyStream()
        try:
            discovering(pkt)
            detect(pkt)
            funcCode, register = parse(pkt)
            alerting(pkt[IP].src, funcCode, register)
            timingCheck(pkt)
        finally:
            sys.stdout = old_stdout

        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt and (pkt[TCP].sport == 502 or pkt[TCP].dport == 502):
            func, reg = parse(pkt)
            if func is not None:
                func_name = detector_module.config.get("ModbusFunctions", {}).get(str(func), f"Func Code {func}")
                console.print(f" [grey50][{datetime.now().strftime('%H:%M:%S')}][/grey50] "
                              f"MODBUS TCP: [cyan]{src}[/cyan] -> [blue]{dst}[/blue] | "
                              f"[green]{func_name} (Reg={reg})[/green]")

    def print_hacker_alert(self, alert):
        sev = alert.get("severity", "LOW").upper()
        event = alert.get("event", "UNKNOWN")
        source = alert.get("source", "N/A")
        details = alert.get("details", "")
        
        if sev == "CRITICAL":
            color = "bold magenta"
            border = "magenta"
        elif sev == "HIGH":
            color = "bold red"
            border = "red"
        elif sev == "MEDIUM":
            color = "bold yellow"
            border = "yellow"
        else:
            color = "bold cyan"
            border = "grey50"

        actions = ["Investigate source IP instantly."]
        if event == "UNKNOWN_DEVICE":
            actions = ["Verify inventory database", "Query switch MAC address table", "Deploy firewall drop rule"]
        elif event == "HIGH_POLLING":
            actions = ["Verify against polling baseline", "Check for HMI loop errors", "Limit source transaction rate"]
        else:
            func_code = None
            for code, name in timing.parse.__globals__.get('modbus_func', {}).items():
                if name.lower() in event.lower():
                    func_code = code
                    break
            if func_code and func_code in timing.timingCheck.__globals__.get('MITIGATION', {}):
                actions = timing.timingCheck.__globals__['MITIGATION'][func_code]
            elif "Mitigation" in alert:
                actions = alert["Mitigation"]

        alert_text = Text()
        alert_text.append("ALERT TYPE : ", style="bold")
        alert_text.append(f"{event}\n", style=color)
        alert_text.append("SEVERITY   : ", style="bold")
        alert_text.append(f"{sev}\n", style=color)
        alert_text.append("SOURCE IP  : ", style="bold")
        alert_text.append(f"{source}\n", style="cyan")
        alert_text.append("DETAILS    : ", style="bold")
        alert_text.append(f"{details}\n", style="grey50")
        
        alert_text.append("\nRECOMMENDED MITIGATIONS:\n", style="bold yellow")
        for act in actions:
            alert_text.append(f"  • {act}\n", style="yellow")
            
        panel = Panel(
            alert_text,
            title="[bold blink red]🚨 SCADA SYSTEM ALARM DETECTED 🚨[/bold blink red]",
            border_style=border,
            width=72
        )
        console.print(panel)

    def print_timing_alert(self, alert_type, severity, source, destination, function_code, details, actions):
        border = "yellow" if severity.upper() == "MEDIUM" else "red"
        color = f"bold {border}"
        
        alert_text = Text()
        alert_text.append("ANOMALY    : ", style="bold")
        alert_text.append(f"{alert_type}\n", style="yellow")
        alert_text.append("SEVERITY   : ", style="bold")
        alert_text.append(f"{severity}\n", style=color)
        alert_text.append("SOURCE IP  : ", style="bold")
        alert_text.append(f"{source}\n", style="cyan")
        alert_text.append("TARGET IP  : ", style="bold")
        alert_text.append(f"{destination}\n", style="cyan")
        alert_text.append("DETAILS    : ", style="bold")
        alert_text.append(f"{details}\n", style="grey50")
        
        alert_text.append("\nRECOMMENDED MITIGATIONS:\n", style="bold yellow")
        for act in actions:
            alert_text.append(f"  • {act}\n", style="yellow")
            
        panel = Panel(
            alert_text,
            title="[bold blink yellow]⏰ SCADA TIMING ANOMALY ALERT ⏰[/bold blink yellow]",
            border_style=border,
            width=72
        )
        console.print(panel)

    def print_anomaly(self, anomaly_type, source, details):
        alert_text = Text()
        alert_text.append("TYPE       : ", style="bold")
        alert_text.append(f"{anomaly_type}\n", style="bold red")
        alert_text.append("SOURCE     : ", style="bold")
        alert_text.append(f"{source}\n", style="cyan")
        alert_text.append("DETAILS    : ", style="bold")
        alert_text.append(f"{details}\n", style="grey50")
        
        alert_text.append("\nRECOMMENDED MITIGATIONS:\n", style="bold yellow")
        actions = ["Identify machine hardware address", "Check firewall rules configuration", "Isolate device ports on Switch"]
        for act in actions:
            alert_text.append(f"  • {act}\n", style="yellow")
            
        panel = Panel(
            alert_text,
            title="[bold blink red]☠️ SECURITY CRITICAL VIOLATION DETECTED ☠️[/bold blink red]",
            border_style="red",
            width=72
        )
        console.print(panel)

    # --- PCAP Analyzer ---
    def analyze_pcap_interactive(self):
        console.clear()
        console.print(Panel(
            Align.center("[bold green]SCADA IDS - PCAP FILE OFFLINE AUDITOR[/bold green]\n"
                         "[grey50]Scanning local directory for PCAP logs...[/grey50]"),
            border_style="grey50",
            width=72
        ))
        
        pcap_files = [f for f in os.listdir('.') if f.endswith('.pcap') or f.endswith('.pcapng')]
        
        if not pcap_files:
            console.print(" [yellow][!] No PCAP logs found in current workspace directory.[/yellow]")
            pcap_path = Prompt.ask(" Enter PCAP File Path").strip()
        else:
            table = Table(show_header=True, header_style="bold green", box=rich.box.SIMPLE, border_style="grey50")
            table.add_column("Index", style="cyan", justify="right")
            table.add_column("Filename", style="bold white")
            table.add_column("File Size", style="grey50", justify="right")
            
            for idx, filename in enumerate(pcap_files, 1):
                size_kb = os.path.getsize(filename) / 1024
                table.add_row(str(idx), filename, f"{size_kb:.2f} KB")
            
            console.print(table)
            console.print("  [bold green][M][/bold green] Enter custom filepath manually\n")
            
            choice = Prompt.ask(" Select PCAP index to audit").strip()
            
            if choice.upper() == 'M':
                pcap_path = Prompt.ask(" Enter PCAP File Path").strip()
            else:
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(pcap_files):
                        pcap_path = pcap_files[idx]
                    else:
                        console.print(" [bold red][!] Invalid index choice.[/bold red]")
                        time.sleep(1.0)
                        return
                except ValueError:
                    console.print(" [bold red][!] Invalid choice format.[/bold red]")
                    time.sleep(1.0)
                    return
        
        if not os.path.exists(pcap_path):
            console.print(f" [bold red][!] PCAP file not found: {pcap_path}[/bold red]")
            time.sleep(1.2)
            return

        # Start analysis
        clear_alerts()
        assets.clear()
        detector_module.register_history.clear()
        timing.last_seen.clear()
        timing.polling_baseline.clear()

        console.print(f"\n [green][*] Accessing PCAP file structures...[/green]")
        time.sleep(0.4)
        
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            console.print(f" [bold red][!] Failed to read PCAP packet stream: {e}[/bold red]")
            time.sleep(1.5)
            return

        total_pkts = len(packets)
        console.print(f" [green][*] Found [bold]{total_pkts}[/bold] packets. Initializing signature analysis engines...[/green]\n")
        time.sleep(0.5)

        # Process packets with progress bar
        old_stdout = sys.stdout
        sys.stdout = DummyStream()
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task_id = progress.add_task("[cyan]PROCESSING PACKETS[/cyan]", total=total_pkts)
                
                for i, pkt in enumerate(packets):
                    if IP in pkt:
                        discovering(pkt)
                        detect(pkt)
                        funcCode, register = parse(pkt)
                        alerting(pkt[IP].src, funcCode, register)
                        timingCheck(pkt)
                    progress.update(task_id, advance=1)
        finally:
            sys.stdout = old_stdout

        # Show beautiful analysis report
        alerts = get_alerts()
        critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high = sum(1 for a in alerts if a.get("severity") == "HIGH")
        medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
        low = sum(1 for a in alerts if a.get("severity") == "LOW")
        total_alerts = len(alerts)

        report_table = Table(show_header=False, box=rich.box.DOUBLE_EDGE, border_style="grey50", width=72)
        report_table.add_column("Label", style="bold")
        report_table.add_column("Value")
        
        report_table.add_row("PCAP File Path", pcap_path)
        report_table.add_row("Total Packets", str(total_pkts))
        report_table.add_row("[grey50]" + "─" * 28 + "[/grey50]", "[grey50]" + "─" * 38 + "[/grey50]")
        report_table.add_row("THREAT METRICS DETECTED", "")
        report_table.add_row("  • CRITICAL ALERTS", f"[bold magenta]{critical}[/bold magenta]")
        report_table.add_row("  • HIGH ALERTS", f"[bold red]{high}[/bold red]")
        report_table.add_row("  • MEDIUM ALERTS", f"[bold yellow]{medium}[/bold yellow]")
        report_table.add_row("  • LOW ALERTS", f"[bold cyan]{low}[/bold cyan]")
        report_table.add_row("  • TOTAL INCIDENTS", f"[bold white]{total_alerts}[/bold white]")
        report_table.add_row("[grey50]" + "─" * 28 + "[/grey50]", "[grey50]" + "─" * 38 + "[/grey50]")
        report_table.add_row("ASSETS DISCOVERED", "")
        
        for ip, role in assets.items():
            role_color = "bold cyan" if role == "PLC" else "bold blue"
            report_table.add_row(f"  • Device: {ip}", f"Role: [{role_color}]{role}[/{role_color}]")

        console.print(Panel(report_table, title="[bold green]IDS OFFLINE ANALYSIS AUDIT SUMMARY[/bold green]", border_style="grey50", width=72))

        # Generate PDF Report
        console.print(f"\n [green][*] Compiling PDF incident report...[/green]")
        try:
            generate_report(alerts, pcap_path)
            if pcap_path.endswith(".pcap"):
                report_name = pcap_path.replace(".pcap", "_report.pdf")
            elif pcap_path.endswith(".pcapng"):
                report_name = pcap_path.replace(".pcapng", "_report.pdf")
            else:
                report_name = pcap_path + "_report.pdf"
            console.print(f" [bold green][SUCCESS] PDF report compiled: [bold]{report_name}[/bold][/bold green]")
        except Exception as e:
            console.print(f" [bold red][ERR] Failed to build PDF document: {e}[/bold red]")

        input(f"\n Press Enter to return to control menu...")

    # --- Asset Explorer ---
    def explore_assets(self):
        console.clear()
        console.print(Panel(
            Align.center("[bold green]SCADA IDS - DISCOVERED NETWORK TOPOLOGY[/bold green]\n"
                         "[grey50]Devices captured in database during system lifetime[/grey50]"),
            border_style="grey50",
            width=72
        ))
        
        cfg = self.load_config_file()
        trusted_ips = cfg.get("KnownDevices", [])

        if not assets:
            console.print(" [yellow][!] Topology is currently empty. Start sniffing network traffic first.[/yellow]")
        else:
            table = Table(show_header=True, header_style="bold green", box=rich.box.SIMPLE_HEAVY, border_style="grey50")
            table.add_column("DEVICE IP ADDRESS", style="bold white", width=22)
            table.add_column("NETWORK ROLE", width=18)
            table.add_column("SECURITY STATUS", width=22)
            
            for ip, role in assets.items():
                role_color = "bold cyan" if role == "PLC" else "bold blue"
                if ip in trusted_ips:
                    status = "[bold green]TRUSTED DEVICE[/bold green]"
                elif "Give your trusted" in ip or not ip:
                    status = "[grey50]UNCONFIGURED[/grey50]"
                else:
                    status = "[bold red blink]⚠️ ROGUE HOST[/bold red blink]"
                    
                table.add_row(ip, f"[{role_color}]{role}[/{role_color}]", status)
            
            console.print(table)
            console.print(f"\n [grey50]Total Assets in Database: {len(assets)}[/grey50]")

        input(f"\n Press Enter to return...")

    # --- Log Viewer ---
    def view_logs(self):
        console.clear()
        console.print(Panel(
            Align.center(f"[bold green]SCADA IDS - INCIDENT HISTORICAL ARCHIVES[/bold green]\n"
                         f"[grey50]Displaying last 35 events logged to [bold]{self.log_file}[/bold][/grey50]"),
            border_style="grey50",
            width=72
        ))

        if not os.path.exists(self.log_file):
            console.print(" [yellow][!] Audit file does not exist. No events logged yet.[/yellow]")
        else:
            log_lines = self.tail_file(self.log_file, 35)
            if not log_lines:
                console.print(" [grey50][i] Audit log file is currently empty.[/grey50]")
            else:
                for line in log_lines:
                    line_str = line.strip()
                    if "[CRITICAL]" in line_str:
                        console.print(f" [bold magenta]{line_str}[/bold magenta]")
                    elif "[HIGH]" in line_str:
                        console.print(f" [bold red]{line_str}[/bold red]")
                    elif "[MEDIUM]" in line_str:
                        console.print(f" [bold yellow]{line_str}[/bold yellow]")
                    elif "[LOW]" in line_str:
                        console.print(f" [bold cyan]{line_str}[/bold cyan]")
                    else:
                        console.print(f" [grey50]{line_str}[/grey50]")

        input(f"\n Press Enter to return...")

    def tail_file(self, filepath, n_lines=35):
        try:
            lines = []
            chunk_size = 4096
            with open(filepath, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
                position = file_size
                buffer = b''
                while position > 0 and len(lines) <= n_lines:
                    read_size = min(chunk_size, position)
                    position -= read_size
                    f.seek(position)
                    buffer = f.read(read_size) + buffer
                    lines = buffer.split(b'\n')
                return [line.decode('utf-8', errors='ignore') for line in lines[-n_lines-1:-1]]
        except Exception:
            return []

    # --- Config Manager ---
    def manage_config(self):
        while True:
            console.clear()
            console.print(Panel(
                Align.center("[bold green]SCADA IDS - TRUSTED ASSET DATABASE CONFIG[/bold green]\n"
                             "[grey50]Devices configured in the secure registry whitelist[/grey50]"),
                border_style="grey50",
                width=72
            ))
            
            cfg = self.load_config_file()
            trusted_ips = cfg.get("KnownDevices", [])
            
            if not trusted_ips:
                console.print(" [yellow][!] Whitelist registry is empty.[/yellow]\n")
            else:
                table = Table(show_header=False, box=rich.box.SIMPLE, border_style="grey50")
                table.add_column("Index", style="cyan")
                table.add_column("IP Address", style="bold white")
                for idx, ip in enumerate(trusted_ips, 1):
                    table.add_row(f"[{idx}]", ip)
                console.print(table)
                console.print()
            
            console.print(" [bold cyan]Whitelisting Operations:[/bold cyan]")
            console.print("   [bold green][1][/bold green] Whitelist New Device IP")
            console.print("   [bold green][2][/bold green] Delete Device IP from Whitelist")
            console.print("   [bold green][3][/bold green] Return to Control Menu\n")
            
            choice = Prompt.ask(" CONFIG_CMD").strip()
            
            if choice == '1':
                ip = Prompt.ask(" Enter Device IP Address").strip()
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    console.print(" [bold red][!] Invalid IP format.[/bold red]")
                    time.sleep(1.0)
                    continue
                if ip in trusted_ips:
                    console.print(" [bold yellow][!] IP address already exists in whitelist.[/bold yellow]")
                    time.sleep(1.0)
                    continue
                
                trusted_ips.append(ip)
                cfg["KnownDevices"] = trusted_ips
                
                with console.status(" [bold cyan]RECOMPUTING CONFIGURATION ENCRYPTION CHECKSUM...[/bold cyan]", spinner="dots") as status:
                    time.sleep(0.8)
                self.save_config_file(cfg)
                
                console.print(f" [bold green][SUCCESS] Added IP {ip} to whitelist database.[/bold green]")
                time.sleep(1.0)
                
            elif choice == '2':
                if not trusted_ips:
                    console.print(" [bold red][!] Whitelist registry has no devices to delete.[/bold red]")
                    time.sleep(1.0)
                    continue
                idx_choice = Prompt.ask(" Select Index Number to Delete").strip()
                try:
                    idx = int(idx_choice) - 1
                    if 0 <= idx < len(trusted_ips):
                        removed_ip = trusted_ips.pop(idx)
                        cfg["KnownDevices"] = trusted_ips
                        
                        with console.status(" [bold cyan]RECOMPUTING CONFIGURATION ENCRYPTION CHECKSUM...[/bold cyan]", spinner="dots") as status:
                            time.sleep(0.8)
                        self.save_config_file(cfg)
                        
                        console.print(f" [bold green][SUCCESS] Removed {removed_ip} from whitelist.[/bold green]")
                    else:
                        console.print(" [bold red][!] Out of range index.[/bold red]")
                except ValueError:
                    console.print(" [bold red][!] Invalid numeric index format.[/bold red]")
                time.sleep(1.0)
                
            elif choice == '3':
                break

    # --- Integrity Check ---
    def run_manual_integrity(self):
        console.clear()
        console.print(Panel(
            Align.center("[bold green]SCADA BASELINE SECURITY AUDIT REPORT[/bold green]\n"
                         "[grey50]Initiating on-demand cryptographic verification checks[/grey50]"),
            border_style="grey50",
            width=72
        ))
        
        with console.status(" [bold cyan]CHECKING CRYPTOGRAPHIC SCHEMES...[/bold cyan]", spinner="dots") as status:
            time.sleep(1.0)
        
        cfg_path = "config.json"
        hash_path = "config.hash"
        
        cfg_exists = os.path.exists(cfg_path)
        hash_exists = os.path.exists(hash_path)
        
        cfg_status = "[bold green][FOUND][/bold green]" if cfg_exists else "[bold red][NOT FOUND][/bold red]"
        hash_status = "[bold green][FOUND][/bold green]" if hash_exists else "[bold red][NOT FOUND][/bold red]"
        
        console.print(f"   [+] Registry Config File ({cfg_path}): {cfg_status}")
        console.print(f"   [+] Registry Signature file ({hash_path}): {hash_status}")
        
        if not cfg_exists or not hash_exists:
            console.print(f"\n [bold red][CRITICAL] INTEGRITY CHECK FAILURE: Missing crucial signature components![/bold red]")
            input(f"\n Press Enter to return...")
            return
            
        with open(cfg_path, "rb") as f:
            cfg_data = f.read()
        computed = hashlib.sha256(cfg_data).hexdigest()
        
        with open(hash_path, "r") as f:
            stored = f.read().strip()
            
        console.print(f"   [+] Config File Bytes Checked   : [bold]{len(cfg_data)} bytes[/bold]")
        console.print(f"   [+] Stored Cryptographic Hash   : [cyan]{stored}[/cyan]")
        console.print(f"   [+] Live Computed Checksum Hash : [cyan]{computed}[/cyan]")
        
        if stored == computed:
            console.print(f"\n [bold green][PASS] SECURE SYSTEM MATCH [100% OK][/bold green]")
            console.print(" [green]No unauthorized modifications to system assets whitelist detected.[/green]")
        else:
            console.print(f"\n [bold red][ALERT] SIGNATURE CHECKSUM MISMATCH![/bold red]")
            console.print(" [red]The configuration has been modified without re-signing the integrity hash.[/red]")
            console.print(" [yellow]Recommended actions: Re-sign registry database or restore backup config.[/yellow]")

        input(f"\n Press Enter to return...")

if __name__ == "__main__":
    cli = SCADAHackerCLI()
    cli.run()
