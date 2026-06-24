# Suricata Setup

## Installation
sudo apt install suricata -y

## Problem faced
Default config pointed to eth0 which does not exist.
Fixed by changing interface to wlo1 in suricata.yaml.

## Interface configured
wlo1 (home WiFi interface, IP: 192.168.1.6)

## Rules source
Emerging Threats Open via suricata-update
66,733 rules loaded, 50,808 enabled

## Verification
sudo systemctl status suricata → active (running)
sudo tail -f /var/log/suricata/fast.log → monitoring live traffic
