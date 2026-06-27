# Home Network Intrusion Monitor

A real-time network intrusion detection system that watches home WiFi traffic,
tags threats using MITRE ATT&CK, auto-blocks malicious IPs via iptables,
and visualizes everything in a Splunk dashboard.

## Architecture
Suricata IDS → Python Parser → iptables blocking + Splunk SIEM

## Build Progress
- [x] Day 1: Project structure created
- [x] Day 2: Suricata installed and configured on wlo1
- [x] Day 3: Python parser with MITRE ATT&CK tagging
- [x] Day 4: iptables + fail2ban blocking configured
- [x] Day 5: Splunk dashboard live, real alerts visualized
- [x] Day 6: auditd configured, tool's own actions monitored
- [x] Day 7: Documentation complete

## MITRE ATT&CK Coverage
![MITRE Coverage](docs/screenshots/mitre-coverage.png)

## Splunk Dashboard
![Alerts Table](docs/screenshots/splunk-alerts-table.png)
![MITRE Stats](docs/screenshots/splunk-mitre-stats.png)

## Tools Used
- Suricata IDS — 66,733 ET rules, watching wlo1
- Python 3 — real-time alert parser with MITRE tagging
- iptables + fail2ban — automatic IP blocking, persistent across reboots
- auditd — monitors the tool's own actions
- Splunk Free — SIEM dashboard and search

## Real Alert Captured
```json
{
  "timestamp": "2026-06-25T09:01:45",
  "src_ip": "18.161.246.67",
  "signature": "GPL ATTACK_RESPONSE id check returned root",
  "mitre_id": "T1033",
  "mitre_name": "System Owner User Discovery",
  "severity": 2
}
```

## What I Learned
- How Suricata rules detect real attack patterns in live traffic
- How MITRE ATT&CK maps tool alerts to real-world techniques
- How iptables DROP differs from REJECT and why it matters
- How auditd creates accountability for security tools themselves
- How Splunk ingests JSON logs and enables threat hunting queries
