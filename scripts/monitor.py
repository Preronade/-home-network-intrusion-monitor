import json
import time
import subprocess
import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# MITRE ATT&CK technique mapping
MITRE_MAP = {
    "ET SCAN":    ("T1046",     "Network Service Discovery"),
    "ET SSH":     ("T1021.004", "Remote Services SSH"),
    "ET DNS":     ("T1071.004", "DNS Application Layer Protocol"),
    "ET WEB":     ("T1190",     "Exploit Public Facing Application"),
    "ET POLICY":  ("T1595",     "Active Scanning"),
    "ET TROJAN":  ("T1571",     "Non Standard Port"),
    "ET SQL":     ("T1190",     "SQL Injection Attempt"),
    "ET XSS":     ("T1059.007", "Cross Site Scripting"),
    "ET BRUTE":   ("T1110",     "Brute Force"),
    "GPL ATTACK_RESPONSE": ("T1033", "System Owner User Discovery"),
    "ET EXPLOIT": ("T1203",     "Exploitation for Client Execution"),
    "ET MALWARE": ("T1588",     "Obtain Capabilities Malware"),
    "ET PHISHING":("T1566",     "Phishing"),
}

BLOCKED_IPS = set()

def tag_mitre(alert_msg):
    for keyword, (tid, tname) in MITRE_MAP.items():
        if keyword in alert_msg.upper():
            return tid, tname
    return "T0000", "Unclassified"

def block_ip(ip):
    if ip not in BLOCKED_IPS and not ip.startswith("192.168"):
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        BLOCKED_IPS.add(ip)
        print(f"[BLOCKED] {ip}")

def parse_alert(line):
    try:
        alert = json.loads(line)
        if alert.get("event_type") != "alert":
            return

        src_ip   = alert.get("src_ip", "unknown")
        sig_msg  = alert["alert"]["signature"]
        severity = alert["alert"]["severity"]
        ts       = alert.get("timestamp", str(datetime.datetime.now()))

        tid, tname = tag_mitre(sig_msg)

        log_entry = {
            "timestamp":  ts,
            "src_ip":     src_ip,
            "signature":  sig_msg,
            "mitre_id":   tid,
            "mitre_name": tname,
            "severity":   severity
        }

        print(f"[ALERT] {src_ip} | {tid} | {tname} | {sig_msg}")

        # Auto block if high severity
        if severity <= 2:
            block_ip(src_ip)

        # Write to log file for Splunk
        with open("/var/log/hnm/alerts.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    except (json.JSONDecodeError, KeyError):
        pass

class SuricataHandler(FileSystemEventHandler):
    def __init__(self):
        self.logfile = open("/var/log/suricata/eve.json", "r")
        self.logfile.seek(0, 2)  # seek to end of file

    def on_modified(self, event):
        if "eve.json" in event.src_path:
            for line in self.logfile:
                parse_alert(line.strip())

if __name__ == "__main__":
    import os
    os.makedirs("/var/log/hnm", exist_ok=True)
    print("[HNM] Starting Home Network Intrusion Monitor...")
    print("[HNM] Watching /var/log/suricata/eve.json for alerts...")
    observer = Observer()
    handler = SuricataHandler()
    observer.schedule(handler, "/var/log/suricata/", recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[HNM] Monitor stopped.")
        observer.stop()
    observer.join()