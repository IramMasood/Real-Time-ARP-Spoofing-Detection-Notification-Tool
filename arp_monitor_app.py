#### arp_monitor_app.py with traffic generator
"""
ARP Spoofing Detection Tool
Author: Ben Varkey, Iram Masood

DISCLAIMER:
This tool is intended for educational and defensive security purposes only.
Use only on networks you own or have explicit permission to monitor.
The authors are not responsible for misuse.
"""

import sys
import threading
import logging
import json
import signal
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timezone

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy,
    QAction, QFileDialog, QSpinBox, QPushButton, QToolBar, QMessageBox
)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QFont
import psutil
from scapy.all import sniff, ARP, get_if_hwaddr, conf


# matplotlib for plotting
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Global reference for the window
gui_window = None

# Global references
sniff_thread = None
snapshot_thread = None
metrics_thread = None

# ---------- CONFIG ----------
LOG_DIR = Path("./logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "arp_capture.log"
SNAPSHOT_JSON = LOG_DIR / "arp_table_snapshot.json"
SNAPSHOT_CSV = LOG_DIR / "arp_table_snapshot.csv"
METRICS_JSON = LOG_DIR / "arp_metrics.json"
METRICS_CSV = LOG_DIR / "arp_metrics.csv"
SNAPSHOT_INTERVAL = 30
METRICS_INTERVAL = 30
SPOOF_DETECTION_CONFLICT_THRESHOLD = 1

# ---------- DATA STRUCTURES ----------
ip_mac_table = {}
table_lock = threading.Lock()

metrics = {
    "total_packets": 0,
    "conflict_count": 0,
    "per_ip_packets": {},
    "per_ip_conflicts": {},
    "mac_to_ips": {},
    "first_seen": {},
    "last_seen": {},
    "interval": {"packets": 0, "new_mappings": 0, "conflicts": 0},
    "history": [],
    "spoofing_events": [],
    "spoofing_active": {},
    "per_ip_first_spoof_ts": {},
    "per_ip_last_popup_ts": {}
}
# Metrics are shared between threads and drive both logging and UI updates.
metrics_lock = threading.Lock()
stop_event = threading.Event()

# ---------- LOGGING ----------
logger = logging.getLogger("arp_capture")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(fmt)
logger.addHandler(fh)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(fmt)
logger.addHandler(ch)

# Helper function to get UTC ISO timestamp
def utc_iso_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


'''def show_conflict_popup(ip, old_mac, new_mac, parent=None):
    def popup():
        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("⚠️ ARP Conflict Detected")
      #  msg.setText(f"Conflict detected for IP {ip}!\nOld MAC: {old_mac}\nNew MAC: {new_mac}")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setWindowModality(Qt.ApplicationModal)
        msg.show()
        QApplication.beep()  # optional beep

    # Schedule the popup to run in the main GUI thread
    QTimer.singleShot(0, popup)
    
# Example conflict detection logic
def handle_conflict(ip, old_mac, new_mac, parent=None):
    logging.warning(f"Conflict detected for IP {ip}: {old_mac} new={new_mac}")
    show_conflict_popup(ip, old_mac, new_mac, parent)
    '''
# ---------- AUTO-SELECT INTERFACE ----------
# ------- For upgrade to use other OSs
def auto_select_interface():
    """
    Automatically selects a network interface.
    Works on Linux, Windows, macOS.
    Preference order:
        1. Active, non-loopback interface with IPv4
        2. Fallback to Scapy default
    """
    candidates = []

    for iface, addrs in psutil.net_if_addrs().items():
        has_ipv4 = False
        is_loopback = False

        for addr in addrs:
            if addr.family == 2:  # AF_INET
                if addr.address.startswith("127."):
                    is_loopback = True
                else:
                    has_ipv4 = True

        if has_ipv4 and not is_loopback:
            candidates.append(iface)

    if candidates:
        picked = None
        for iface in candidates:
            if psutil.net_if_stats().get(iface) and psutil.net_if_stats()[iface].isup:   # pick the first active interface
                picked = iface
                break
        conf.iface = picked or candidates[0]
    else:
        conf.iface = conf.iface  # fallback to scapy default

    return conf.iface

# Set interface at startup
iface = auto_select_interface()
logger.info(f"Monitoring on interface: {iface}")

# ---------- ARP FUNCTIONS ----------
try:
    my_mac = get_if_hwaddr(conf.iface)
except Exception:
    my_mac = None

def detect_conflict(ip, mac):
    """Record IP→MAC mapping and return True if the mapping changes."""
    with table_lock:
        if ip in ip_mac_table and ip_mac_table[ip] != mac:
            old = ip_mac_table[ip]
            # update mapping to the new mac (keep latest)
            ip_mac_table[ip] = mac
            logger.warning(f"Conflict detected for IP {ip}: {old} -> {mac}")
            return True, old
        else:
            # establish mapping if not present
            old = ip_mac_table.setdefault(ip, mac)
            return False, None

def metrics_update_for_packet(ip, mac, conflict, old_mac=None):
    """Update packet counters, per-IP stats, and spoofing state for one ARP packet."""
    now = utc_iso_now()
    popup_args = None
    # Initialize latency to 0 so it's always defined
    latency_ms = 0
    with metrics_lock:
        metrics["total_packets"] += 1
        metrics["interval"]["packets"] += 1
        metrics["per_ip_packets"].setdefault(ip, 0)
        metrics["per_ip_packets"][ip] += 1

        if ip not in metrics["first_seen"]:
            metrics["first_seen"][ip] = now
            metrics["interval"]["new_mappings"] += 1
        metrics["last_seen"][ip] = now

        metrics["mac_to_ips"].setdefault(mac, set()).add(ip)
        metrics["unique_macs"] = len(metrics["mac_to_ips"])
        metrics["unique_ips"] = len(metrics["per_ip_packets"])

        if conflict:
            # mark IP as active spoofed
            metrics["per_ip_conflicts"].setdefault(ip, 0)
            metrics["per_ip_conflicts"][ip] += 1
            # Increment interval conflict counter
            metrics["interval"]["conflicts"] += 1
            # Optionally increment overall conflict_count per conflict (tracks cumulative conflicts)
            metrics["conflict_count"] += 1  # treat conflict_count as cumulative conflicts
           
            first_detected = not metrics["spoofing_active"].get(ip, False)
            
            if first_detected:
                metrics["spoofing_active"][ip] = True
                if ip not in metrics["per_ip_first_spoof_ts"]:
                    metrics["per_ip_first_spoof_ts"][ip] = now
                                
                # Compute latency_ms
                try: 
                     # if first_seen stored earlier as ISO timestamp, parse it and compute difference
                    fs = metrics["per_ip_first_spoof_ts"].get(ip)
                    if fs:
                        # fs is ISO string; convert to datetime
                        first_dt = datetime.fromisoformat(fs.replace("Z","+00:00"))
                        latency_ms = int((datetime.now(timezone.utc) - first_dt).total_seconds() * 1000)
                    else:
                        latency_ms = 0
                except Exception:
                    latency_ms = 0

                event = {
                    "ip": ip,
                    "first_spoof_ts": metrics["per_ip_first_spoof_ts"][ip],
                    "detection_ts": now,
                    "conflicts_at_detection": metrics["per_ip_conflicts"][ip],
                    "detection_threshold": SPOOF_DETECTION_CONFLICT_THRESHOLD,
                    "latency_ms": latency_ms,
                    "mac": mac,
                    "type": "first"
                }
                metrics["spoofing_events"].append(event)
                if gui_window:
                    gui_window.save_detection_event(event)
                
                # schedule a popup once (and record last_popup_ts)
                last_popup = metrics["per_ip_last_popup_ts"].get(ip)
                now_ts = datetime.now(timezone.utc).timestamp()
                if not last_popup or (now_ts - last_popup) > 5:  # rate-limit 5s per IP popups
                    metrics["per_ip_last_popup_ts"][ip] = now_ts
                    popup_args = (ip, old_mac if old_mac else "Unknown", mac)

             # ALSO append an "update" event so timeline/event feed always has something to show
            update_event = {
                "ip": ip,
                "conflicts": metrics["per_ip_conflicts"].get(ip, 0),
                "conflicts_at_detection": metrics["per_ip_conflicts"].get(ip, 0),
                "detection_threshold": SPOOF_DETECTION_CONFLICT_THRESHOLD,
                "latency_ms": latency_ms,
                "mac": mac,
                "type": "update"
            }
            metrics["spoofing_events"].append(update_event)
            
    # Use SIGNAL to safely trigger popup from background thread
    if popup_args and gui_window:
        gui_window.conflict_detected_signal.emit(popup_args[0], str(popup_args[1]), popup_args[2])           

def arp_callback(pkt):
    """Handle each sniffed ARP packet and push results into shared state."""
    if pkt.haslayer(ARP):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc.lower()
        if my_mac is not None and mac == my_mac.lower():
            return
            
        conflict, old_mac = detect_conflict(ip, mac)  
        metrics_update_for_packet(ip, mac, conflict, old_mac=old_mac)
       
# ---------- SNAPSHOT & METRICS ----------
def write_snapshot_json(path=SNAPSHOT_JSON):
    """Persist the current ARP table and summary metrics to a JSON snapshot."""
    with table_lock, metrics_lock:
        snapshot = {"generated_at": utc_iso_now(), "entries": ip_mac_table.copy()}
        snapshot["metrics_summary"] = {
            "total_packets": metrics["total_packets"],
            "conflict_count": metrics["conflict_count"],
            "unique_ips": len(metrics["per_ip_packets"]),
            "unique_macs": len(metrics["mac_to_ips"])
        }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)

def write_snapshot_csv(path=SNAPSHOT_CSV):
    """Append the current ARP table to CSV with a timestamp."""
    path = Path(path)
    header_needed = not path.exists()
    with table_lock:
        entries = ip_mac_table.copy()
    ts = utc_iso_now()
    lines = [f"{ip},{mac},{ts}\n" for ip, mac in entries.items()]
    with open(path, "a", encoding="utf-8") as f:
        if header_needed:
            f.write("ip,mac,snapshot_utc\n")
        f.writelines(lines)

def write_metrics_json(path=METRICS_JSON):
    """Persist full metrics, converting sets to lists for JSON safety."""
    with metrics_lock:
        safe_metrics = dict(metrics)
        safe_metrics["mac_to_ips"] = {m: list(s) for m, s in metrics["mac_to_ips"].items()}
        safe_metrics["written_at"] = utc_iso_now()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe_metrics, f, indent=2)

def write_metrics_csv(path=METRICS_CSV):
    """Append summary metrics row to CSV for quick inspection."""
    header_needed = not path.exists()
    with metrics_lock:
        total = metrics["total_packets"]
        conflicts = metrics["conflict_count"]
        unique_ips = len(metrics["per_ip_packets"])
        unique_macs = len(metrics["mac_to_ips"])
        interval = metrics["interval"]
    ts = utc_iso_now()
    line = f"{ts},{total},{conflicts},{unique_ips},{unique_macs},{interval['packets']},{interval['conflicts']},{interval['new_mappings']}\n"
    with open(path, "a", encoding="utf-8") as f:
        if header_needed:
            f.write("written_at,total_packets,conflict_count,unique_ips,unique_macs,interval_packets,interval_conflicts,interval_new_mappings\n")
        f.write(line)

def periodic_snapshots(interval=SNAPSHOT_INTERVAL):
    """Background loop to persist the live ARP table as JSON/CSV snapshots."""
    while not stop_event.is_set():
        try:
            write_snapshot_json()
            write_snapshot_csv()
        except Exception as e:
            logger.exception(f"Snapshot error: {e}")
        stop_event.wait(interval)

def periodic_metrics(interval=METRICS_INTERVAL):
    """Background loop to persist metrics and reset interval counters."""
    while not stop_event.is_set():
        try:
            write_metrics_json()
            write_metrics_csv()
            with metrics_lock:
                metrics["history"].append({
                    "ts": utc_iso_now(),
                    "interval_packets": metrics["interval"]["packets"],
                    "interval_conflicts": metrics["interval"]["conflicts"],
                    "interval_new_mappings": metrics["interval"]["new_mappings"],
                    "total_packets": metrics["total_packets"],
                    "conflict_count": metrics["conflict_count"]
                })
                metrics["interval"] = {"packets":0,"conflicts":0,"new_mappings":0}
        except Exception as e:
            logger.exception(f"Metrics error: {e}")
        stop_event.wait(interval)

def dump_table_and_exit(signum=None, frame=None):
    """On signal, flush snapshots/metrics to disk and exit cleanly if needed."""
    logger.info(f"Signal {signum} received, dumping table...")
    write_snapshot_json()
    write_snapshot_csv()
    write_metrics_json()
    write_metrics_csv()
    if signum == signal.SIGINT:
        stop_event.set()
        sys.exit(0)

signal.signal(signal.SIGINT, dump_table_and_exit)
if hasattr(signal, "SIGUSR1"):
    signal.signal(signal.SIGUSR1, dump_table_and_exit)

# ---------- GUI ----------
class ArpMonitorApp(QMainWindow):
    """Qt main window hosting ARP monitoring views, controls, and alerts."""
    # 1. Define Signal
    conflict_detected_signal = pyqtSignal(str, str, str)
    
    def __init__(self):
        """Build the UI, wire actions, and start the periodic GUI refresh timer."""
        super().__init__()
        self.setWindowIcon(QIcon("logo.png"))
        self.setWindowTitle("ARP Spoofing Detection Tool")
        self.setGeometry(100, 100, 1000, 700)

        # 2. Connect Signal
        self.conflict_detected_signal.connect(self.display_conflict_popup)
        
        self.plot_history = deque(maxlen=120)
        self.plot_ts = deque(maxlen=120)

        # Menu
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        save_action = QAction("Save Snapshot", self)
        save_action.triggered.connect(self.save_snapshot)
        file_menu.addAction(save_action)
        save_metrics_action = QAction("Save Metrics", self)
        save_metrics_action.triggered.connect(self.save_metrics)
        file_menu.addAction(save_metrics_action)
        file_menu.addSeparator()
        report_action = QAction("Export Evaluation Report", self)
        report_action.triggered.connect(self.export_report)
        file_menu.addAction(report_action)
        pdf_action = QAction("Export PDF Report", self)
        pdf_action.triggered.connect(self.export_pdf_report)
        file_menu.addAction(pdf_action)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menubar.addMenu("View")
       
        # Dark mode toggle
        dark_action = QAction("Dark Mode", self, checkable=True)
        dark_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_action)
        
        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        # Layouts
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout()
        central.setLayout(main_layout)

        self.metrics_layout = QHBoxLayout()
        self.iface_label = QLabel(f"Monitoring on: {conf.iface}")
        self.total_label = QLabel("Total Packets: 0")
        self.conflicts_label = QLabel("Conflicts: 0")
        self.unique_ips_label = QLabel("Unique IPs: 0")
        self.unique_macs_label = QLabel("Unique MACs: 0")
        self.latency_label = QLabel("Detection Latency: -")
        self.metrics_layout.addWidget(self.latency_label)
        self.metrics_layout.addWidget(self.iface_label)
        self.metrics_layout.addWidget(self.total_label)
        self.metrics_layout.addWidget(self.conflicts_label)
        self.metrics_layout.addWidget(self.unique_ips_label)
        self.metrics_layout.addWidget(self.unique_macs_label)
        main_layout.addLayout(self.metrics_layout)

        # Content
        content_layout = QHBoxLayout()
        main_layout.addLayout(content_layout)
        left_v = QVBoxLayout()
        content_layout.addLayout(left_v, stretch=2)
        right_v = QVBoxLayout()
        content_layout.addLayout(right_v, stretch=1)

        # To produce headings
        def make_heading(text):
            lbl = QLabel(text)
            lbl.setFont(QFont("Arial", 11, QFont.Bold))
            lbl.setStyleSheet("padding: 6px 4px;")
            return lbl
            
        # Graph
        self.fig = Figure(figsize=(5,3))
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Conflicts over time")
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.canvas.updateGeometry()
        left_v.addWidget(make_heading("Conflicts Over Time"))
        left_v.addWidget(self.canvas)
        
        # Conflicts-Per-IP Graph
        self.fig2 = Figure(figsize=(5,2))
        self.ax2 = self.fig2.add_subplot(111)
        self.canvas2 = FigureCanvas(self.fig2)
        self.canvas2.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.canvas2.updateGeometry()
        left_v.addWidget(make_heading("Conflicts Per IP"))
        left_v.addWidget(self.canvas2)
       
        # Spoofing Timeline Panel
        self.timeline = QTextEdit()
        self.timeline.setReadOnly(True)
        self.timeline.setMaximumHeight(120)
        left_v.addWidget(make_heading("Spoofing Timeline"))
        left_v.addWidget(self.timeline)

        # Event Feed Panel
        self.event_feed = QTextEdit()
        self.event_feed.setReadOnly(True)
        self.event_feed.setMaximumHeight(120)
        left_v.addWidget(make_heading("Event Feed"))
        left_v.addWidget(self.event_feed)

        # ARP Table
        self.arp_table = QTableWidget()
        self.arp_table.setColumnCount(2)
        self.arp_table.setHorizontalHeaderLabels(["IP Address","MAC Address"])
        header = self.arp_table.horizontalHeader()
        font = QFont("Arial", 11, QFont.Bold)
        self.arp_table.setStyleSheet("""
            QHeaderView::section {
                padding: 6px;
                background-color: #e6e6e6;
                font-weight: bold;
                font-size: 11pt;
            }
        """)
        self.arp_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_v.addWidget(self.arp_table)

        # System Stats
        sys_layout = QHBoxLayout()
        self.cpu_label = QLabel("CPU Usage: 0%")
        self.mem_label = QLabel("Memory Usage: 0%")
        sys_layout.addWidget(self.cpu_label)
        sys_layout.addWidget(self.mem_label)
        sys_layout.addStretch()
        right_v.addLayout(sys_layout)

        # Combined bottom bar: threshold + status
        bottom_bar = QHBoxLayout()

        # Threshold label + spin box + button
        bottom_bar.addWidget(QLabel("Alert Threshold:"))
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 100)
        self.threshold_spin.setValue(SPOOF_DETECTION_CONFLICT_THRESHOLD)
        bottom_bar.addWidget(self.threshold_spin)

        set_btn = QPushButton("Set")
        set_btn.clicked.connect(self.set_threshold)
        bottom_bar.addWidget(set_btn)

        bottom_bar.addStretch()  # Push status to the right

        # Status label in the same bar
        self.bottom_status_label = QLabel("Ready")
        bottom_bar.addWidget(self.bottom_status_label)

        # Add to main layout
        main_layout.addLayout(bottom_bar)

        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_gui)
        self.timer.start(1000)

    # 3. New Slot to Handle Popup (Safe Threading)
    def display_conflict_popup(self, ip, old_mac, new_mac):
        """Executed in Main GUI Thread when signal is received."""
        QApplication.beep()
        msg = QMessageBox(self)
        msg.setWindowTitle("⚠️ ARP Spoofing Detected")
        msg.setText(f"Spoofing detected for IP {ip}!\n\nOld MAC: {old_mac}\nNew MAC: {new_mac}")
        msg.setIcon(QMessageBox.Warning)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        
        self.bottom_status_label.setText(f"⚠️ SPOOFING DETECTED for {ip}")
        QTimer.singleShot(5000, lambda: self.bottom_status_label.setText("Ready"))
        
    def export_pdf_report(self):
        try:
            from reportlab.pdfgen import canvas
        except ImportError:
            QMessageBox.warning(self, "Missing Dependency", "reportlab not installed. Install with: pip install reportlab")
            
        path, _ = QFileDialog.getSaveFileName(self, "Save PDF", "arp_report.pdf", "PDF Files (*.pdf)")
        if not path:
            return
        c = canvas.Canvas(path)
        c.setFont("Helvetica", 14)
        c.drawString(40, 800, "ARP Spoofing Detection Report")
        c.setFont("Helvetica", 12)
        c.drawString(40, 770, f"Total Packets: {metrics['total_packets']}")
        c.drawString(40, 750, f"Conflicts: {metrics['conflict_count']}")
        c.drawString(40, 730, f"Unique IPs: {len(metrics['per_ip_packets'])}")
        c.drawString(40, 710, f"Unique MACs: {len(metrics['mac_to_ips'])}")
        c.save()
        self.bottom_status_label.setText(f"PDF saved to {path}")
   
    def save_detection_event(self, event):
        with open(LOG_DIR / "detection_log.csv", "a") as f:
            if f.tell() == 0:
                f.write("time,ip,latency_ms,conflicts,threshold,mac\n")
            f.write(f"{event.get('detection_ts','')},{event.get('ip','')},{event.get('latency_ms','')},{event.get('conflicts_at_detection', event.get('conflicts',''))},{event.get('detection_threshold','')},{event.get('mac','?')}\n")

    def set_threshold(self):
        """Update spoof-detection conflict threshold from the UI spinbox."""
        global SPOOF_DETECTION_CONFLICT_THRESHOLD
        SPOOF_DETECTION_CONFLICT_THRESHOLD = int(self.threshold_spin.value())
        self.bottom_status_label.setText(f"Threshold set to {SPOOF_DETECTION_CONFLICT_THRESHOLD}")

    def show_alert_popup(self, count):
        """Display a simple warning dialog when spoofing is detected."""
        msg = QMessageBox()
        msg.setWindowTitle(" ARP Spoofing Detected")
        msg.setText(f"ARP Spoofing Activity Detected!!! \nConflicts detected: {count}")
        msg.setIcon(QMessageBox.Warning)
        msg.exec_()

    def trigger_alert(self, ip, conflicts):
        """Trigger popup + beep + status flash for a spoofing event."""
        # Beep
        QApplication.beep()
         
        QTimer.singleShot(5000, lambda: self.bottom_status_label.clear())

        # Popup
        msg = QMessageBox()
        msg.setWindowTitle("⚠️ ARP Spoofing Detected")
        msg.setText(f"Spoofing detected for IP {ip}\nConflicts: {conflicts}")
        msg.setIcon(QMessageBox.Warning)
       #msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        # Flash status bar
        self.bottom_status_label.setText(f"⚠️ SPOOFING DETECTED for {ip} (conflicts={conflicts})")
        QTimer.singleShot(5000, lambda: self.bottom_status_label.setText("Ready"))

    def show_about(self):
        """
        Show the 'About' information for the ARP Monitor tool.
        """
        msg = QMessageBox(self)
        msg.setWindowTitle("About ARP Monitor")
        msg.setIcon(QMessageBox.Information)

        # Using HTML for formatting
        msg.setTextFormat(Qt.RichText)
        msg.setText("""
            <h2 style="margin-bottom:10px;">ARP Spoofing Detection Tool</h2>
            <p>This tool monitors your network for <b>ARP spoofing attacks</b> and conflicts.</p>
            <p>It displays the live ARP table, conflict metrics, and graphs.</p>
            <h3>Features:</h3>
            <ul>
                <li>Real-time ARP monitoring</li>
                <li>Conflict detection with alerts</li>
                <li>Export snapshots, metrics, and PDF reports</li>
                <li>Automatic interface selection (Linux, future multi-OS support)</li>
            </ul>
        <p><b>Author:</b> Ben Varkey, Iram Masood </p>
        <p><b>Version:</b> 1.0.0</p>
        <p><i>© 2025 ARP Tool. All rights reserved.</i></p>
        """)

        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()


   # def toggle_console(self, checked):
      #  """Show or hide the embedded console widget (if present)."""
       # self.console.setVisible(checked)

    def toggle_dark_mode(self, enabled):
        """Apply a lightweight dark theme toggle for the main window."""
        if enabled:
            self.setStyleSheet("""
                QMainWindow { background-color: #1e1e1e; color: white; }
                QLabel, QTextEdit, QTableWidget { color: white; }
                QHeaderView::section { background-color: #2e2e2e; color: white; }
                QScrollBar { background: #2e2e2e; }
            """)
        else:
            self.setStyleSheet("")

    def save_snapshot(self):
        """Save a user-chosen ARP snapshot (JSON)."""
        path,_ = QFileDialog.getSaveFileName(self,"Save ARP Snapshot",str(SNAPSHOT_JSON),"JSON Files (*.json)")
        if path:
            write_snapshot_json(path)
            self.bottom_status_label.setText(f"Snapshot saved to {path}")

    def save_metrics(self):
        """Save current metrics to a user-selected JSON file."""
        path,_ = QFileDialog.getSaveFileName(self,"Save Metrics",str(METRICS_JSON),"JSON Files (*.json)")
        if path:
            write_metrics_json(path)
            self.bottom_status_label.setText(f"Metrics saved to {path}")

    def export_report(self):
        """Export a concise CSV report with headline metrics and last spoof event."""
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "arp_report.csv", "CSV Files (*.csv)")
        if not path:
            return
        with metrics_lock:
            with open(path, "w") as f:
                f.write("metric,value\n")
                f.write(f"total_packets,{metrics['total_packets']}\n")
                f.write(f"conflict_count,{metrics['conflict_count']}\n")
                f.write(f"unique_ips,{len(metrics['per_ip_packets'])}\n")
                f.write(f"unique_macs,{len(metrics['mac_to_ips'])}\n")
                if metrics['spoofing_events']:
                    last = metrics['spoofing_events'][-1]
                    f.write(f"last_spoof_ip,{last.get('ip', 'Unknown')}\n")
                    f.write(f"last_spoof_latency_ms,{last.get('latency_ms','')}\n")
        self.bottom_status_label.setText(f"Report saved to {path}")

    def resizeEvent(self, event):
        """Keep plots responsive when the window is resized."""
        self.fig.tight_layout()
        self.canvas.draw()
        self.fig2.tight_layout()
        self.canvas2.draw()
        super().resizeEvent(event)

    def update_gui(self):
        """Refresh UI widgets, plots, and alerts from the current metrics state."""
        # copy a snapshot of metrics we need while holding lock briefly
        with metrics_lock:
            total = metrics.get("total_packets", 0)
            conflicts = metrics.get("conflict_count", 0)
            unique_ips = len(metrics.get("per_ip_packets", {}))
            unique_macs = len(metrics.get("mac_to_ips", {}))
            spoof_events = list(metrics.get("spoofing_events", [])[-20:])
            interval_packets = metrics.get("interval", {}).get("packets", 0)

        # ---- ALWAYS UPDATE SUMMARY METRICS ----
        self.total_label.setText(f"Total Packets: {total}")
        self.conflicts_label.setText(f"Conflicts: {conflicts}")
        self.unique_ips_label.setText(f"Unique IPs: {unique_ips}")
        self.unique_macs_label.setText(f"Unique MACs: {unique_macs}")

        # Build timeline text and event feed from the copied spoof_events (most recent last)
        timeline_msgs = []
        for ev in spoof_events[-6:]:
            detection_ts = str(ev.get("detection_ts", utc_iso_now()))
            ev_ip = ev.get("ip", "?")
            if ev.get("type") == "first":
                latency = ev.get("latency_ms", "-")
                timeline_msgs.append(f"{detection_ts} – IP {ev_ip} first spoofed (latency={latency} ms)")
            else:
                conflicts_val = ev.get("conflicts", ev.get("conflicts_at_detection", "?"))
                timeline_msgs.append(f"{detection_ts} – IP {ev_ip} conflict (IP_count={conflicts_val})")

        # show the short recent timeline in the timeline widget
        # TODO: use HTML to color first events green, update events orange
        # self.timeline.setHtml(...)
        self.timeline.setPlainText("\n".join(timeline_msgs))

        # Event feed: append last event only once
        if spoof_events:
            last = spoof_events[-1]
            last_ts = str(last.get("detection_ts", utc_iso_now()))
            last_ip = last.get("ip", "?")
            conflicts_val = last.get("conflicts", last.get("conflicts_at_detection", "?"))
            feed_msg = f"[{last_ts}] Spoof activity on {last_ip} (IP_count={conflicts_val})"

            if not hasattr(self, "last_event_ts") or self.last_event_ts != last_ts:
                self.event_feed.append(feed_msg)
                self.last_event_ts = last_ts

        last_first = next((e for e in reversed(spoof_events) if e.get("type") == "first"), None)
        if last_first:
            self.latency_label.setText(f"Detection Latency: {last_first.get('latency_ms','-')} ms")
        else:
            self.latency_label.setText("Detection Latency: -")

        with table_lock:
            entries = sorted(ip_mac_table.items())
        self.arp_table.setRowCount(len(entries))
        for row, (ip, mac) in enumerate(entries):
            ip_item = QTableWidgetItem(ip)
            mac_item = QTableWidgetItem(mac)
            if ip in metrics.get("spoofing_active", {}):
                ip_item.setBackground(Qt.red)
                mac_item.setBackground(Qt.red)
            self.arp_table.setItem(row, 0, ip_item)
            self.arp_table.setItem(row, 1, mac_item)

        try:
            self.cpu_label.setText(f"CPU Usage: {psutil.cpu_percent()}%")
            self.mem_label.setText(f"Memory Usage: {psutil.virtual_memory().percent}%")
        except Exception:
            pass

        # Update history buffer only when there are new packets in the interval
        if interval_packets > 0:
            self.plot_history.append(conflicts)
        else:
            self.plot_history.append(self.plot_history[-1] if self.plot_history else 0)

        # Keep sliding window length
        if len(self.plot_history) > 120:
            while len(self.plot_history) > 120:
                self.plot_history.popleft()

        # ---- PLOT 1: Conflicts Over Time ----
        self.ax.clear()
        self.ax.set_xlabel("Sample #")
        self.ax.set_ylabel("Conflicts")

        x_vals = list(range(len(self.plot_history)))
        y_vals = list(self.plot_history) if self.plot_history else [0]

        self.ax.plot(x_vals, y_vals, marker='o')
        # Autoscale Y based on max value, min 0
        max_y = max(y_vals) if y_vals else 1
        self.ax.set_ylim(0, max(max_y + 1, 5))
        self.ax.set_xlim(0, max(len(self.plot_history), 10))
        self.ax.grid(True)
        self.fig.tight_layout()
        self.canvas.draw()
       #self.ax.set_ylim(bottom=0)
       # self.ax.set_xlim(0, max(len(self.plot_history), 10))
        self.canvas.draw()

        # ---- PLOT 2: Conflicts Per IP ----
        self.ax2.clear()
        self.ax2.set_xlabel("IP Address")
        self.ax2.set_ylabel("Conflicts")

        with metrics_lock:
            per_ip_conflicts = dict(metrics.get("per_ip_conflicts", {}))

        ips = list(per_ip_conflicts.keys())
        vals = list(per_ip_conflicts.values())

        max_ips_display = 10
        if ips:
             # Sort IPs by conflicts descending
            sorted_ips = sorted(per_ip_conflicts.items(), key=lambda x: x[1], reverse=True)[:max_ips_display]
            ips, vals = zip(*sorted_ips)
            self.ax2.bar(range(len(ips)), vals, color='orange')
            self.ax2.set_xticks(range(len(ips)))
            self.ax2.set_xticklabels(ips, rotation=45, ha='right')
        else:
            self.ax2.text(0.5, 0.5, "No conflicts yet", fontsize=10, ha='center', va='center')

        self.ax2.set_xlabel("IP Address")
        self.ax2.set_ylabel("Conflicts")
        self.fig2.tight_layout()
        self.canvas2.draw()
        
         # ---- Update CPU + Memory Stats ----
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory().percent
        self.cpu_label.setText(f"CPU Usage: {cpu}%")
        self.mem_label.setText(f"Memory Usage: {mem}%")


    def closeEvent(self, event):
        """Handle application close: stop background loops before window teardown."""
        # Stop periodic threads
        stop_event.set()
        # Join threads with timeout to avoid hanging
        for t in [sniff_thread, snapshot_thread, metrics_thread]:
            if t and t.is_alive():
                t.join(timeout=1)
        event.accept()

        
# ---------- THREADS ----------
def start_sniff_thread():
    """Launch the Scapy ARP sniffer on a daemon thread."""
    global sniff_thread
    sniff_thread = threading.Thread(target=lambda: sniff(filter="arp and arp[6:2] = 2", prn=arp_callback, store=0, iface=conf.iface), daemon=True)
    sniff_thread.start()
    return sniff_thread

def start_periodic_threads():
    """Launch background writers for snapshots and metrics."""
    global snapshot_thread, metrics_thread
    snapshot_thread = threading.Thread(target=periodic_snapshots, daemon=True)
    metrics_thread = threading.Thread(target=periodic_metrics, daemon=True)
    snapshot_thread.start()
    metrics_thread.start()

# ---------- MAIN ----------
def main():
    """Entry point: create the Qt app/window, then start background workers and run the event loop."""
    global gui_window
    app = QApplication(sys.argv)
    
    # create window first so popups scheduled by the sniffer can be delivered
    gui_window = ArpMonitorApp()
    gui_window.show()
    # TEST POPUP
    #show_conflict_popup("192.168.1.50", "00:11:22:33:44:55", "66:77:88:99:AA:BB", gui_window)

    start_sniff_thread()
    start_periodic_threads()
   

    # exit gracefully
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
