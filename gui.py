import sys
import os
import time
import re
import threading
from collections import defaultdict

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Gdk, GLib, Gio, Adw

from scapy.all import rdpcap, IP
import config
import assets
import detector
import timing
from parser import parse
from risk import alerting

def set_margin_all(widget, val):
    widget.set_margin_start(val)
    widget.set_margin_end(val)
    widget.set_margin_top(val)
    widget.set_margin_bottom(val)



class OutputParser:
    def __init__(self, alert_callback, anomaly_callback):
        self.alert_callback = alert_callback
        self.anomaly_callback = anomaly_callback
        self.buffer = ""
        self.in_alert_block = False
        self.current_alert = {}

    def feed_text(self, text):
        self.buffer += text
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            self.process_line(line.strip())

    def process_line(self, line):
        if not line:
            return

        # Check for start of SCADA IDS ALERT
        if "SCADA IDS ALERT" in line:
            self.in_alert_block = True
            self.current_alert = {}
            return

        if self.in_alert_block:
            if "==============================" in line:
                if self.current_alert.get("Source"):
                    self.alert_callback(self.current_alert)
                    self.in_alert_block = False
                    self.current_alert = {}
                return

            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key, val = parts
                    key = key.strip().lower()
                    val = val.strip()
                    if "source" in key:
                        self.current_alert["Source"] = val
                    elif "function" in key:
                        self.current_alert["Function"] = val
                    elif "address" in key:
                        self.current_alert["Address"] = val
                    elif "risk score" in key:
                        self.current_alert["Score"] = val
                    elif "risk level" in key:
                        self.current_alert["Level"] = val
            return

        # Check for unknown device alert
        if "Unknown device" in line:
            m = re.search(r"Unknown device\s+([\d\.]+)", line)
            if m:
                self.anomaly_callback({
                    "Type": "Unknown Device Access",
                    "Source": m.group(1),
                    "Details": line
                })
            return

        # Check for timing alerts
        if "High Frequency Polling" in line:
            m = re.search(r"High Frequency Polling from\s+([\d\.]+)", line)
            if m:
                self.anomaly_callback({
                    "Type": "High Frequency Polling",
                    "Source": m.group(1),
                    "Details": line
                })
            return

        if "Polling Interval Deviation" in line:
            m = re.search(r"Polling Interval Deviation from\s+([\d\.]+)", line)
            if m:
                self.anomaly_callback({
                    "Type": "Interval Deviation",
                    "Source": m.group(1),
                    "Details": line
                })
            return


class PacketWorker(threading.Thread):
    def __init__(self, pcap_path, on_progress, on_finished, on_stdout):
        super().__init__()
        self.pcap_path = pcap_path
        self.on_progress = on_progress
        self.on_finished = on_finished
        self.on_stdout = on_stdout
        self._is_running = True
        self._is_paused = False
        self.pause_cond = threading.Condition()

    def run(self):
        # Reset detection states
        assets.assets.clear()
        detector.register_history.clear()
        timing.last_seen.clear()
        timing.polling_baseline.clear()

        # Redirect stdout
        old_stdout = sys.stdout
        class ThreadStdout:
            def __init__(self, callback):
                self.callback = callback
            def write(self, text):
                if text:
                    GLib.idle_add(self.callback, text)
            def flush(self):
                pass
        
        sys.stdout = ThreadStdout(self.on_stdout)

        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            sys.stdout = old_stdout
            GLib.idle_add(self.on_stdout, f"Error reading PCAP file: {e}\n")
            GLib.idle_add(self.on_finished)
            return

        total_packets = len(packets)
        
        for idx, pkt in enumerate(packets):
            with self.pause_cond:
                while self._is_paused:
                    self.pause_cond.wait()
                if not self._is_running:
                    break

            if IP in pkt:
                assets.discovering(pkt)
                detector.detect(pkt)
                funcCode, register = parse(pkt)
                alerting(pkt[IP].src, funcCode, register)
                timing.timingCheck(pkt)

            GLib.idle_add(self.on_progress, idx + 1, total_packets)
            # Short sleep to keep UI extremely responsive
            time.sleep(0.002)

        sys.stdout = old_stdout
        GLib.idle_add(self.on_finished)

    def pause(self):
        with self.pause_cond:
            self._is_paused = True

    def resume(self):
        with self.pause_cond:
            self._is_paused = False
            self.pause_cond.notify_all()

    def stop(self):
        with self.pause_cond:
            self._is_running = False
            self._is_paused = False
            self.pause_cond.notify_all()


class SCADAIDSWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("SCADA Baseline IDS")
        self.set_default_size(950, 720)
        
        # State variables
        self.total_packets_processed = 0
        self.total_packets_count = 0
        self.modbus_alerts = []
        self.anomalies = []
        self.selected_pcap_path = ""
        self.worker = None

        self.parser = OutputParser(self.on_modbus_alert, self.on_anomaly_alert)

        # Setup custom dark theme styles
        self.load_css()
        
        # Setup UI
        self.setup_ui()
        self.refresh_devices_list()

    def load_css(self):
        css_provider = Gtk.CssProvider()
        css_provider.load_from_data(b"""
            .metric-card {
                background-color: @theme_bg_color;
                border: 1px solid @borders;
                border-radius: 12px;
                padding: 16px;
            }
            .metric-title {
                font-size: 10px;
                font-weight: bold;
                color: @theme_fg_color;
                opacity: 0.6;
            }
            .metric-value {
                font-size: 24px;
                font-weight: 800;
                margin-top: 4px;
            }
            .badge {
                border-radius: 12px;
                padding: 2px 10px;
                font-size: 11px;
                font-weight: bold;
                color: white;
            }
            .badge-low { background-color: #2ea043; }
            .badge-medium { background-color: #d29922; color: black; }
            .badge-high { background-color: #f0883e; }
            .badge-critical { background-color: #f85149; }
            
            .badge-plc { background-color: #1f6feb; }
            .badge-hmi { background-color: #238636; }
            
            .log-view-text {
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                color: #39ff14;
                background-color: #0b0f19;
            }
        """)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def setup_ui(self):
        # Root layout: ToastOverlay for clean GNOME notifications
        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        # ToolbarView
        toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(toolbar_view)

        # Header Bar
        header_bar = Adw.HeaderBar()
        toolbar_view.add_top_bar(header_bar)

        # View Stack for tabs
        self.stack = Adw.ViewStack()
        toolbar_view.set_content(self.stack)

        # View Switcher linked to the Stack
        self.switcher = Adw.ViewSwitcher()
        self.switcher.set_stack(self.stack)
        header_bar.set_title_widget(self.switcher)

        # ----------------------------------------------------
        # Page 1: Dashboard
        # ----------------------------------------------------
        dash_scroll = Gtk.ScrolledWindow()
        dash_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        dash_clamp = Adw.Clamp()
        dash_clamp.set_maximum_size(800)
        dash_scroll.set_child(dash_clamp)

        dash_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        dash_box.set_margin_top(24)
        dash_box.set_margin_bottom(24)
        dash_box.set_margin_start(16)
        dash_box.set_margin_end(16)
        dash_clamp.set_child(dash_box)

        # Welcome Header
        welcome_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        welcome_title = Gtk.Label()
        welcome_title.set_halign(Gtk.Align.START)
        welcome_title.set_markup("<span weight='bold' size='x-large'>🛡️ SCADA Baseline IDS</span>")
        welcome_subtitle = Gtk.Label(label="Real-time Modbus traffic monitor and intrusion detection system")
        welcome_subtitle.set_halign(Gtk.Align.START)
        welcome_subtitle.add_css_class("dim-label")
        welcome_box.append(welcome_title)
        welcome_box.append(welcome_subtitle)
        dash_box.append(welcome_box)

        # Controls Preferences Group
        controls_group = Adw.PreferencesGroup()
        controls_group.set_title("Analysis Controls")
        dash_box.append(controls_group)

        # File selection row
        self.pcap_row = Adw.ActionRow()
        self.pcap_row.set_title("Selected PCAP File")
        self.pcap_row.set_subtitle("No PCAP file selected")
        self.pcap_row.set_icon_name("document-open-symbolic")
        
        self.browse_btn = Gtk.Button(label="Browse")
        self.browse_btn.set_valign(Gtk.Align.CENTER)
        self.browse_btn.connect("clicked", self.on_browse_clicked)
        self.pcap_row.add_suffix(self.browse_btn)
        controls_group.add(self.pcap_row)

        # Analysis operations row
        self.actions_row = Adw.ActionRow()
        self.actions_row.set_title("Analysis Operations")
        self.actions_row.set_subtitle("Start or stop processing traffic log")
        
        actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        
        self.start_btn = Gtk.Button(label="Start Analysis")
        self.start_btn.set_valign(Gtk.Align.CENTER)
        self.start_btn.add_css_class("suggested-action")
        self.start_btn.set_sensitive(False)
        self.start_btn.connect("clicked", self.on_start_clicked)
        
        self.stop_btn = Gtk.Button(label="Stop")
        self.stop_btn.set_valign(Gtk.Align.CENTER)
        self.stop_btn.add_css_class("destructive-action")
        self.stop_btn.set_sensitive(False)
        self.stop_btn.connect("clicked", self.on_stop_clicked)

        self.clear_btn = Gtk.Button(label="Clear Data")
        self.clear_btn.set_valign(Gtk.Align.CENTER)
        self.clear_btn.connect("clicked", self.on_clear_clicked)

        actions_box.append(self.start_btn)
        actions_box.append(self.stop_btn)
        actions_box.append(self.clear_btn)
        self.actions_row.add_suffix(actions_box)
        controls_group.add(self.actions_row)

        # Progress indicator
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_margin_top(8)
        dash_box.append(self.progress_bar)

        # Metrics section
        metrics_title = Gtk.Label()
        metrics_title.set_halign(Gtk.Align.START)
        metrics_title.set_markup("<span weight='bold' size='large'>System Metrics</span>")
        dash_box.append(metrics_title)

        metrics_grid = Gtk.Grid()
        metrics_grid.set_column_spacing(12)
        metrics_grid.set_row_spacing(12)
        metrics_grid.set_column_homogeneous(True)
        
        self.card_packets = self.create_metric_card("Total Packets", "0 / 0", "accent")
        self.card_alerts = self.create_metric_card("Modbus Alerts", "0", "error")
        self.card_anomalies = self.create_metric_card("Anomalies", "0", "warning")
        self.card_assets = self.create_metric_card("Discovered Assets", "0", "success")

        metrics_grid.attach(self.card_packets, 0, 0, 1, 1)
        metrics_grid.attach(self.card_alerts, 1, 0, 1, 1)
        metrics_grid.attach(self.card_anomalies, 0, 1, 1, 1)
        metrics_grid.attach(self.card_assets, 1, 1, 1, 1)
        dash_box.append(metrics_grid)

        self.stack.add_titled_with_icon(dash_scroll, "dashboard", "Dashboard", "network-workgroup-symbolic")

        # ----------------------------------------------------
        # Page 2: Modbus Alerts
        # ----------------------------------------------------
        alerts_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        set_margin_all(alerts_box, 16)
        
        alerts_title = Gtk.Label()
        alerts_title.set_markup("<span weight='bold' size='large'>Modbus Traffic Alerts</span>")
        alerts_title.set_halign(Gtk.Align.START)
        alerts_box.append(alerts_title)

        alerts_scroll = Gtk.ScrolledWindow()
        alerts_scroll.set_vexpand(True)
        
        self.alerts_list = Gtk.ListBox()
        self.alerts_list.add_css_class("boxed-list")
        self.alerts_list.set_selection_mode(Gtk.SelectionMode.NONE)
        alerts_scroll.set_child(self.alerts_list)
        alerts_box.append(alerts_scroll)

        self.stack.add_titled_with_icon(alerts_box, "alerts", "Alerts", "dialog-warning-symbolic")

        # ----------------------------------------------------
        # Page 3: Discovered Assets
        # ----------------------------------------------------
        assets_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        set_margin_all(assets_box, 16)
        
        assets_title = Gtk.Label()
        assets_title.set_markup("<span weight='bold' size='large'>Network Devices &amp; Assets</span>")
        assets_title.set_halign(Gtk.Align.START)
        assets_box.append(assets_title)

        assets_scroll = Gtk.ScrolledWindow()
        assets_scroll.set_vexpand(True)
        
        self.assets_list = Gtk.ListBox()
        self.assets_list.add_css_class("boxed-list")
        self.assets_list.set_selection_mode(Gtk.SelectionMode.NONE)
        assets_scroll.set_child(self.assets_list)
        assets_box.append(assets_scroll)

        self.stack.add_titled_with_icon(assets_box, "assets", "Assets", "computer-symbolic")

        # ----------------------------------------------------
        # Page 4: Security Anomalies
        # ----------------------------------------------------
        anom_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        set_margin_all(anom_box, 16)
        
        anom_title = Gtk.Label()
        anom_title.set_markup("<span weight='bold' size='large'>Security Anomalies</span>")
        anom_title.set_halign(Gtk.Align.START)
        anom_box.append(anom_title)

        anom_scroll = Gtk.ScrolledWindow()
        anom_scroll.set_vexpand(True)
        
        self.anomalies_list = Gtk.ListBox()
        self.anomalies_list.add_css_class("boxed-list")
        self.anomalies_list.set_selection_mode(Gtk.SelectionMode.NONE)
        anom_scroll.set_child(self.anomalies_list)
        anom_box.append(anom_scroll)

        self.stack.add_titled_with_icon(anom_box, "anomalies", "Anomalies", "security-high-symbolic")

        # ----------------------------------------------------
        # Page 5: Console Logs
        # ----------------------------------------------------
        logs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        set_margin_all(logs_box, 16)
        
        logs_title = Gtk.Label()
        logs_title.set_markup("<span weight='bold' size='large'>IDS Log Terminal</span>")
        logs_title.set_halign(Gtk.Align.START)
        logs_box.append(logs_title)

        logs_scroll = Gtk.ScrolledWindow()
        logs_scroll.set_vexpand(True)
        
        self.console_log = Gtk.TextView()
        self.console_log.set_editable(False)
        self.console_log.set_cursor_visible(False)
        self.console_log.set_monospace(True)
        self.console_log.add_css_class("log-view-text")
        
        logs_scroll.set_child(self.console_log)
        logs_box.append(logs_scroll)

        self.stack.add_titled_with_icon(logs_box, "logs", "Console Logs", "utilities-terminal-symbolic")

        # ----------------------------------------------------
        # Page 6: Known Devices (Configuration)
        # ----------------------------------------------------
        config_scroll = Gtk.ScrolledWindow()
        config_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        config_clamp = Adw.Clamp()
        config_clamp.set_maximum_size(600)
        config_scroll.set_child(config_clamp)

        config_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        set_margin_all(config_box, 16)
        config_clamp.set_child(config_box)

        config_title = Gtk.Label()
        config_title.set_markup("<span weight='bold' size='large'>Trusted Devices Configuration</span>")
        config_title.set_halign(Gtk.Align.START)
        config_box.append(config_title)

        # Appearance Settings Group
        theme_group = Adw.PreferencesGroup()
        theme_group.set_title("Appearance Settings")
        config_box.append(theme_group)

        self.theme_row = Adw.ActionRow()
        self.theme_row.set_title("Dark Mode Theme")
        self.theme_row.set_subtitle("Prefer dark color scheme for the application")
        self.theme_row.set_icon_name("display-brightness-symbolic")
        
        self.theme_switch = Gtk.Switch()
        self.theme_switch.set_valign(Gtk.Align.CENTER)
        self.theme_switch.set_active(True)
        self.theme_switch.connect("state-set", self.on_theme_switch_changed)
        self.theme_row.add_suffix(self.theme_switch)
        theme_group.add(self.theme_row)

        config_desc = Gtk.Label(label="IPs added to this list are recognized as known devices. Packets from other sources trigger 'Unknown Device' warnings.")
        config_desc.set_wrap(True)
        config_desc.add_css_class("dim-label")
        config_desc.set_halign(Gtk.Align.START)
        config_box.append(config_desc)

        add_group = Adw.PreferencesGroup()
        config_box.append(add_group)

        self.ip_entry_row = Adw.ActionRow()
        self.ip_entry_row.set_title("Device IP Address")
        
        self.ip_entry = Gtk.Entry()
        self.ip_entry.set_placeholder_text("e.g. 192.168.1.100")
        self.ip_entry.set_valign(Gtk.Align.CENTER)
        self.ip_entry.set_hexpand(True)
        self.ip_entry_row.add_suffix(self.ip_entry)
        
        self.add_ip_btn = Gtk.Button(label="Add IP")
        self.add_ip_btn.set_valign(Gtk.Align.CENTER)
        self.add_ip_btn.add_css_class("suggested-action")
        self.add_ip_btn.connect("clicked", self.on_add_ip_clicked)
        self.ip_entry_row.add_suffix(self.add_ip_btn)
        add_group.add(self.ip_entry_row)

        devices_group = Adw.PreferencesGroup()
        devices_group.set_title("Configured Trusted Devices")
        config_box.append(devices_group)

        self.devices_list = Gtk.ListBox()
        self.devices_list.add_css_class("boxed-list")
        self.devices_list.set_selection_mode(Gtk.SelectionMode.NONE)
        devices_group.add(self.devices_list)

        self.stack.add_titled_with_icon(config_scroll, "config", "Settings", "preferences-system-symbolic")

    def create_metric_card(self, title, init_val, color_class):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.add_css_class("metric-card")
        
        lbl_title = Gtk.Label(label=title.upper())
        lbl_title.set_halign(Gtk.Align.START)
        lbl_title.add_css_class("metric-title")
        
        lbl_val = Gtk.Label(label=init_val)
        lbl_val.set_halign(Gtk.Align.START)
        lbl_val.add_css_class("metric-value")
        if color_class:
            lbl_val.add_css_class(color_class)
        
        card.append(lbl_title)
        card.append(lbl_val)
        card.value_label = lbl_val
        return card

    def show_toast(self, message):
        toast = Adw.Toast(title=message)
        self.toast_overlay.add_toast(toast)

    def on_browse_clicked(self, button):
        dialog = Gtk.FileChooserNative(
            title="Open Modbus PCAP File",
            action=Gtk.FileChooserAction.OPEN,
            accept_label="Open",
            cancel_label="Cancel"
        )
        dialog.set_transient_for(self)
        
        filter_pcap = Gtk.FileFilter()
        filter_pcap.set_name("PCAP Files (*.pcap)")
        filter_pcap.add_pattern("*.pcap")
        dialog.add_filter(filter_pcap)
        
        def on_dialog_response(dialog, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                path = dialog.get_file().get_path()
                self.selected_pcap_path = path
                self.pcap_row.set_subtitle(os.path.basename(path))
                self.start_btn.set_sensitive(True)
                self.clear_all_data()
            dialog.destroy()
            
        dialog.connect("response", on_dialog_response)
        dialog.show()

    def on_start_clicked(self, button):
        if self.worker and self.worker.is_alive():
            if self.worker._is_paused:
                self.worker.resume()
                self.start_btn.set_label("Pause Analysis")
                self.actions_row.set_subtitle("Analyzing traffic...")
            else:
                self.worker.pause()
                self.start_btn.set_label("Resume Analysis")
                self.actions_row.set_subtitle("Analysis paused")
        else:
            self.start_analysis()

    def start_analysis(self):
        if not self.selected_pcap_path:
            return

        self.clear_all_data()
        
        self.worker = PacketWorker(
            self.selected_pcap_path,
            on_progress=self.on_worker_progress,
            on_finished=self.on_worker_finished,
            on_stdout=self.on_captured_stdout
        )
        
        self.worker.start()
        self.start_btn.set_label("Pause Analysis")
        self.start_btn.set_sensitive(True)
        self.stop_btn.set_sensitive(True)
        self.browse_btn.set_sensitive(False)
        self.clear_btn.set_sensitive(False)
        self.actions_row.set_subtitle("Analyzing traffic...")
        self.show_toast("Started analysis")

    def on_stop_clicked(self, button):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.worker.join()
        
        self.start_btn.set_label("Start Analysis")
        self.start_btn.set_sensitive(True)
        self.stop_btn.set_sensitive(False)
        self.browse_btn.set_sensitive(True)
        self.clear_btn.set_sensitive(True)
        self.refresh_assets_list()
        self.actions_row.set_subtitle("Analysis stopped by user")
        self.show_toast("Analysis stopped")

    def on_clear_clicked(self, button):
        self.clear_all_data()
        self.show_toast("Data cleared")

    def clear_all_data(self):
        self.total_packets_processed = 0
        self.total_packets_count = 0
        self.modbus_alerts.clear()
        self.anomalies.clear()
        
        self.console_log.get_buffer().set_text("")
        
        while True:
            row = self.alerts_list.get_row_at_index(0)
            if row is None:
                break
            self.alerts_list.remove(row)
            
        while True:
            row = self.anomalies_list.get_row_at_index(0)
            if row is None:
                break
            self.anomalies_list.remove(row)
            
        while True:
            row = self.assets_list.get_row_at_index(0)
            if row is None:
                break
            self.assets_list.remove(row)
            
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_text("")
        self.update_stats()

    def on_worker_progress(self, current, total):
        self.total_packets_processed = current
        self.total_packets_count = total
        self.progress_bar.set_fraction(current / total if total > 0 else 0.0)
        self.progress_bar.set_text(f"Processed {current} of {total} packets")
        self.update_stats()
        if current % 10 == 0 or current == total:
            self.refresh_assets_list()

    def on_worker_finished(self):
        self.start_btn.set_label("Start Analysis")
        self.start_btn.set_sensitive(True)
        self.stop_btn.set_sensitive(False)
        self.browse_btn.set_sensitive(True)
        self.clear_btn.set_sensitive(True)
        self.refresh_assets_list()
        
        status_msg = f"Completed: {self.total_packets_count} pkts scanned. Found {len(self.modbus_alerts)} alerts, {len(self.anomalies)} anomalies."
        self.show_toast(status_msg)
        self.actions_row.set_subtitle(status_msg)

    def on_captured_stdout(self, text):
        buffer = self.console_log.get_buffer()
        iter_end = buffer.get_end_iter()
        buffer.insert(iter_end, text)
        
        mark = buffer.get_insert()
        buffer.move_mark(mark, buffer.get_end_iter())
        self.console_log.scroll_to_mark(mark, 0.0, False, 0.0, 0.0)
        
        self.parser.feed_text(text)

    def on_modbus_alert(self, alert_data):
        self.modbus_alerts.append(alert_data)
        
        row = Adw.ActionRow()
        row.set_title(f"Source IP: {alert_data.get('Source', '')}")
        
        func = alert_data.get('Function', '')
        addr = alert_data.get('Address', '')
        score = alert_data.get('Score', '0')
        lvl = alert_data.get('Level', 'LOW')
        
        row.set_subtitle(f"Function: {func}  |  Address: {addr}  |  Risk Score: {score}")
        
        badge = Gtk.Label(label=lvl)
        badge.add_css_class("badge")
        badge.add_css_class(f"badge-{lvl.lower()}")
        badge.set_valign(Gtk.Align.CENTER)
        badge.set_margin_end(6)
        
        row.add_suffix(badge)
        self.alerts_list.append(row)
        self.update_stats()

    def on_anomaly_alert(self, anomaly_data):
        self.anomalies.append(anomaly_data)

        row = Adw.ActionRow()
        row.set_title(anomaly_data.get("Type", "Anomaly Detected"))
        row.set_subtitle(f"Source IP: {anomaly_data.get('Source', 'N/A')}\n{anomaly_data.get('Details', '')}")
        row.set_icon_name("dialog-warning-symbolic")
        
        badge = Gtk.Label(label="VIOLATION")
        badge.add_css_class("badge")
        badge.add_css_class("badge-high")
        badge.set_valign(Gtk.Align.CENTER)
        badge.set_margin_end(6)
        
        row.add_suffix(badge)
        self.anomalies_list.append(row)
        self.update_stats()

    def update_stats(self):
        self.card_packets.value_label.set_text(f"{self.total_packets_processed} / {self.total_packets_count}")
        self.card_alerts.value_label.set_text(str(len(self.modbus_alerts)))
        self.card_anomalies.value_label.set_text(str(len(self.anomalies)))
        self.card_assets.value_label.set_text(str(len(assets.assets)))

    def refresh_assets_list(self):
        while True:
            row = self.assets_list.get_row_at_index(0)
            if row is None:
                break
            self.assets_list.remove(row)
            
        for ip, role in assets.assets.items():
            row = Adw.ActionRow()
            row.set_title(ip)
            row.set_icon_name("network-server-symbolic" if role == "PLC" else "computer-symbolic")
            
            badge = Gtk.Label(label=role)
            badge.add_css_class("badge")
            badge.add_css_class(f"badge-{role.lower()}")
            badge.set_valign(Gtk.Align.CENTER)
            badge.set_margin_end(6)
            
            row.add_suffix(badge)
            self.assets_list.append(row)
            
        self.update_stats()

    def refresh_devices_list(self):
        while True:
            row = self.devices_list.get_row_at_index(0)
            if row is None:
                break
            self.devices_list.remove(row)
            
        for ip in config.knownDevice:
            row = Adw.ActionRow()
            row.set_title(ip)
            row.set_icon_name("network-workgroup-symbolic")
            
            del_btn = Gtk.Button()
            del_btn.set_icon_name("user-trash-symbolic")
            del_btn.set_valign(Gtk.Align.CENTER)
            del_btn.add_css_class("flat")
            del_btn.add_css_class("error")
            del_btn.connect("clicked", self.on_delete_ip_clicked, ip)
            
            row.add_suffix(del_btn)
            self.devices_list.append(row)

    def on_add_ip_clicked(self, button):
        ip = self.ip_entry.get_text().strip()
        if not ip:
            return
            
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            self.show_toast("Invalid IP: Please enter a valid IPv4 address.")
            return

        if ip in config.knownDevice:
            self.show_toast(f"Duplicate: {ip} is already in the list.")
            return

        config.knownDevice.append(ip)
        self.save_config_file()
        self.refresh_devices_list()
        self.ip_entry.set_text("")
        self.show_toast(f"Added {ip} to trusted devices.")

    def on_delete_ip_clicked(self, button, ip):
        if ip in config.knownDevice:
            config.knownDevice.remove(ip)
            self.save_config_file()
            self.refresh_devices_list()
            self.show_toast(f"Removed {ip} from trusted devices.")

    def on_theme_switch_changed(self, widget, state):
        style_manager = Adw.StyleManager.get_default()
        if state:
            style_manager.set_color_scheme(Adw.ColorScheme.PREFER_DARK)
            self.show_toast("Dark theme enabled")
        else:
            style_manager.set_color_scheme(Adw.ColorScheme.PREFER_LIGHT)
            self.show_toast("Light theme enabled")
        return False

    def save_config_file(self):
        try:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.py")
            with open(config_path, "w") as f:
                f.write("knownDevice = [\n")
                for ip in config.knownDevice:
                    f.write(f"    \"{ip}\",\n")
                f.write("]\n")
        except Exception as e:
            self.show_toast(f"Error Saving Config: {e}")


class SCADAIDSApp(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="org.gnome.ScadaIdsApp",
            flags=Gio.ApplicationFlags.NON_UNIQUE
        )

    def do_activate(self):
        win = SCADAIDSWindow(self)
        # Force system theme style preference manager to request dark mode
        style_manager = Adw.StyleManager.get_default()
        style_manager.set_color_scheme(Adw.ColorScheme.PREFER_DARK)
        win.present()


def main():
    app = SCADAIDSApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    main()
