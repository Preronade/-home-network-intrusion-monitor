# Blocking Logic

## Tools used
- iptables — immediate packet blocking
- fail2ban — persistent blocking across reboots
- iptables-persistent — saves rules to disk

## How blocking works
1. Suricata detects threat → writes to eve.json
2. Python parser reads alert severity
3. Severity 1 or 2 → iptables DROP rule added automatically
4. fail2ban protects SSH — bans IP after 3 failed attempts
5. iptables-persistent saves all rules across reboots

## iptables command used
sudo iptables -A INPUT -s <IP> -j DROP

## Why DROP and not REJECT
DROP gives no response to attacker — machine appears non-existent.
REJECT tells attacker the machine is alive and blocking them.

## fail2ban config
bantime  = 3600 seconds (1 hour)
findtime = 600 seconds (10 minutes window)
maxretry = 3 attempts before ban

## Backup and restore
sudo iptables-save > ~/iptables_backup.txt
sudo iptables-restore < ~/iptables_backup.txt
