# auditd Setup

## Purpose
Monitor the monitor itself — every write to /var/log/hnm/
and every iptables execution is logged by auditd.
This creates accountability for the security tool itself.

## Installation
sudo apt install auditd -y

## Rules configured
-w /var/log/hnm/ -p wa -k hnm_writes
-w /usr/sbin/iptables -p x -k hnm_blocks
-w /var/log/suricata/ -p wa -k suricata_logs

## Verification
sudo auditctl -l → confirmed all 3 rules loaded
sudo ausearch -k hnm_writes → confirmed writes detected

## Why audit the tool itself
A compromised security tool that deletes its own logs
is a known attacker technique (MITRE T1070).
auditd catches this even if the tool tries to hide it.
