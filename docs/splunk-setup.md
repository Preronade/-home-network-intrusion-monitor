# Splunk Setup

## Installation
Downloaded Splunk Enterprise 10.4.0 .deb from splunk.com
sudo dpkg -i splunk-10.4.0-f798d4d49089-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root

## Data Source
File: /var/log/hnm/alerts.json
Source type: _json
Mode: Continuously Monitor

## Search Queries

### All alerts table
index=main sourcetype=_json
| table timestamp src_ip signature mitre_id severity

### MITRE technique frequency
index=main sourcetype=_json
| stats count by mitre_id mitre_name
| sort -count

### Top attacking IPs
index=main sourcetype=_json
| stats count by src_ip
| sort -count
| head 10

## Results confirmed
3 real alerts captured and visible in Splunk
MITRE techniques: T0000 (2 alerts), T1033 (1 alert)
