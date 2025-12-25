ARP Spoofing Detection Tool

A real-time defensive network security tool that monitors ARP traffic to detect, log, and alert on ARP spoofing (Man-in-the-Middle) attacks.
Built with Python, Scapy, and PyQt5.

🚀 Features
🔍 Real-Time Monitoring

Continuously sniffs ARP packets on the active network interface

🚨 Spoof Detection

Automatically detects conflicting IP-to-MAC address mappings

Flags suspicious behavior indicative of ARP spoofing attacks

📊 Live Dashboard

Traffic Graphs: Visualizes conflict frequency over time and per IP

ARP Table: Displays live IP–MAC mappings and highlights spoofed entries

Event Feed: Scrollable log of detected spoofing activity

🔔 Alerts

Visual pop-up warnings

Audible alerts on detection

📄 Reporting & Forensics

Automatic ARP table snapshots (JSON / CSV)

Exportable PDF reports for analysis or documentation

🌐 Cross-Platform Core

Automatically selects the active network interface

Linux recommended (best Scapy support)

🛠️ Installation
Prerequisites

Python 3.8+

Linux (Kali / Ubuntu recommended)

Install dependencies:

pip install scapy PyQt5 psutil matplotlib reportlab

Linux Notes

Scapy requires elevated privileges to sniff network traffic.
Run the application with sudo.

If PyQt5 system libraries are missing:

sudo apt-get install python3-pyqt5

▶️ Usage

Run the application:

sudo python3 arp_monitor_app.py

Interface Behavior

Automatically selects the active interface (e.g., eth0, wlan0)

Graphs populate as ARP traffic is observed

Alerts trigger when an IP changes its MAC mapping unexpectedly

Exporting Data

File → Save Snapshot: Export current ARP table

File → Export PDF Report: Generate a forensic summary report

📂 Project Structure
.
├── arp_monitor_app.py    # Main application source code
├── logo.png              # Application icon (optional)
├── logs/                 # Auto-generated runtime data (gitignored)
│   ├── arp_capture.log
│   ├── detection_log.csv
│   └── ...
└── README.md

⚙️ Configuration

Detection sensitivity can be adjusted in the GUI:

Alert Threshold
Number of conflicting ARP packets required before triggering an alert
(Default: 1)

⚠️ Disclaimer

This tool is intended for educational and defensive security purposes only.
Use only on networks you own or have explicit authorization to monitor.
The authors are not responsible for misuse.

👤 Authors & Version

Authors: Ben Varkey, Iram Masood
Version: 1.0.0
License: For educational and research use only

## Portfolio Note

This project was developed as part of a university-level cybersecurity course
and received a graded evaluation. It is published here as a demonstration of
defensive network security skills, real-time monitoring, and secure software
design principles.