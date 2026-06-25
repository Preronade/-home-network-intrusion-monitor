# MITRE ATT&CK Mapping

| Suricata Keyword | MITRE ID | Technique Name |
|---|---|---|
| ET SCAN | T1046 | Network Service Discovery |
| ET SSH | T1021.004 | Remote Services SSH |
| ET DNS | T1071.004 | DNS Application Layer Protocol |
| ET WEB | T1190 | Exploit Public Facing Application |
| ET POLICY | T1595 | Active Scanning |
| ET TROJAN | T1571 | Non Standard Port |
| ET SQL | T1190 | SQL Injection Attempt |
| ET XSS | T1059.007 | Cross Site Scripting |
| ET BRUTE | T1110 | Brute Force |
| ET EXPLOIT | T1203 | Exploitation for Client Execution |
| ET MALWARE | T1588 | Obtain Capabilities Malware |
| ET PHISHING | T1566 | Phishing |
| GPL ATTACK_RESPONSE | T1033 | System Owner User Discovery |

## Real alert captured during testing
Signature: GPL ATTACK_RESPONSE id check returned root
Source IP: 18.161.246.67
MITRE ID: T1033
Triggered by: curl http://testmynids.org/uid/index.html
