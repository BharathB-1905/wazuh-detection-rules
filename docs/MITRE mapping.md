#  MITRE ATT&CK® Mapping — Wazuh Custom Detection Ruleset

> Rule IDs `200100–200714` | Wazuh v4.14.5 | Windows 11 Endpoint  
> Framework: [MITRE ATT&CK® Enterprise v14](https://attack.mitre.org/)

---

##  Tactic → Technique → Rule Cross-Reference

### TA0001 — Initial Access

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1566 | T1566.001 | Phishing: Spearphishing Attachment (Office macro C2) | 200105, 200202 |
| T1200 | — | Hardware Additions (new USB device) | 200709 |
| T1091 | — | Replication Through Removable Media | 200707, 200710, 200711 |

---

### TA0002 — Execution

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1059 | T1059.001 | Command and Scripting Interpreter: PowerShell | 200100–200109 |
| T1059 | — | Scripting engine network connection | 200201 |
| T1059 | — | Script executed from removable drive | 200711 |
| T1059 | — | Script created in Temp/AppData | 200610 |
| T1204 | T1204.002 | User Execution: Malicious File (removable drive exec) | 200710 |
| T1218 | — | System Binary Proxy Execution (rundll32, regsvr32, msbuild) | 200203 |

---

### TA0003 — Persistence

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1053 | T1053.005 | Scheduled Task/Job: Scheduled Task | 200107, 200300–200304, 200309 |
| T1543 | T1543.003 | Create or Modify System Process: Windows Service | 200305–200308 |
| T1547 | T1547.001 | Boot/Logon Autostart: Registry Run Keys / Startup Folder | 200609 |
| T1547 | — | PrintNightmare persistence via spoolsv child | 200712 |
| T1546 | T1546.013 | Event Triggered Execution: PowerShell Profile | 200616 |

---

### TA0004 — Privilege Escalation

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1068 | — | Exploitation for Privilege Escalation (PrintNightmare) | 200712–200714 |
| T1078 | T1078.003 | Valid Accounts: Local Accounts (built-in Admin RDP) | 200706, 200309 |
| T1215 | — | Kernel Modules and Extensions (kernel driver as service) | 200307 |

---

### TA0005 — Defense Evasion

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1027 | — | Obfuscated Files or Information (`-enc`, `-encodedcommand`) | 200101 |
| T1036 | — | Masquerading (task/service names mimicking system processes) | 200304, 200306, 200607, 200608 |
| T1070 | T1070.001 | Indicator Removal: Clear Windows Event Logs | 200108 |
| T1070 | T1070.004 | Indicator Removal: File Deletion | 200618 |
| T1218 | — | System Binary Proxy Execution | 200203 |
| T1562 | T1562.001 | Impair Defenses: Disable or Modify Tools | 200108, 200617 |
| T1562 | T1562.004 | Impair Defenses: Disable or Modify System Firewall | 200602–200604 |
| T1574 | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | 200611 |
| T1620 | — | Reflective Code Loading (`Reflection.Assembly`) | 200103 |

---

### TA0006 — Credential Access

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1003 | — | OS Credential Dumping (Mimikatz, lsass) | 200106 |
| T1003 | T1003.001 | LSASS Memory (MiniDumpWriteDump) | 200109 |
| T1003 | T1003.002 | Security Account Manager (SAM/SYSTEM/SECURITY hive modified) | 200615 |
| T1110 | — | Brute Force (RDP failed logon) | 200701 |

---

### TA0007 — Discovery

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1049 | — | System Network Connections Discovery (recon tool network call) | 200209 |
| T1082 | — | System Information Discovery (whoami, systeminfo, ipconfig) | 200104 |

---

### TA0008 — Lateral Movement

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1021 | T1021.001 | Remote Services: Remote Desktop Protocol | 200700–200704, 200706 |
| T1021 | T1021.004 | Remote Services: SSH | 200400 |
| T1021 | — | Lateral movement ports from abnormal process | 200206 |
| T1091 | — | Replication Through Removable Media | 200707, 200710, 200711 |

---

### TA0009 — Collection

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1052 | T1052.001 | Exfiltration Over Physical Medium: USB | 200707, 200708 |
| T1565 | T1565.001 | Data Manipulation: Stored Data Manipulation (hosts file, FIM) | 200600, 200601, 200605, 200612, 200613 |

---

### TA0011 — Command and Control

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1071 | — | Application Layer Protocol (Office C2, FTP, SMTP) | 200201, 200202, 200401, 200402 |
| T1090 | — | Proxy (TOR/anonymity network ports) | 200208 |
| T1095 | — | Non-Application Layer Protocol (raw C2/reverse shell ports) | 200204 |

---

### TA0010 — Exfiltration

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1048 | — | Exfiltration Over Alternative Protocol (FTP/Telnet/TFTP) | 200207 |
| T1052 | T1052.001 | Exfiltration Over Physical Medium: USB | 200707, 200708 |

---

### TA0040 — Impact

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1486 | — | Data Encrypted for Impact (ransomware — mass file modification) | 200619 |
| T1489 | — | Service Stop (aggressive process kill) | 200109 |
| T1496 | — | Resource Hijacking (cryptomining ports) | 200205 |

---

### TA0042 — Resource Development / Other

| Technique | Sub-Technique | Name | Rule IDs |
|-----------|--------------|------|----------|
| T1105 | — | Ingress Tool Transfer (download cradle, LOLBin, FIM drops) | 200102, 200200, 200606, 200607, 200608, 200614 |

---

##  Flat Technique Index (All Techniques Covered)

| MITRE ID | Technique Name | Rules Count | Rule IDs |
|----------|---------------|-------------|----------|
| T1003 | OS Credential Dumping | 3 | 200106, 200109, 200615 |
| T1003.001 | LSASS Memory | 1 | 200109 |
| T1003.002 | Security Account Manager | 1 | 200615 |
| T1021 | Remote Services | 1 | 200206 |
| T1021.001 | Remote Desktop Protocol | 6 | 200700–200704, 200706 |
| T1021.004 | SSH | 1 | 200400 |
| T1027 | Obfuscated Files or Information | 1 | 200101 |
| T1036 | Masquerading | 4 | 200304, 200306, 200607, 200608 |
| T1048 | Exfiltration Over Alt Protocol | 1 | 200207 |
| T1049 | System Network Connections Discovery | 1 | 200209 |
| T1052.001 | Exfiltration Over Physical Medium: USB | 2 | 200707, 200708 |
| T1053.005 | Scheduled Task | 7 | 200107, 200300–200304, 200309 |
| T1059 | Command and Scripting Interpreter | 4 | 200201, 200610, 200711, 200714 |
| T1059.001 | PowerShell | 10 | 200100–200109 |
| T1068 | Exploitation for Privilege Escalation | 3 | 200712–200714 |
| T1070.001 | Clear Windows Event Logs | 1 | 200108 |
| T1070.004 | File Deletion | 1 | 200618 |
| T1071 | Application Layer Protocol | 4 | 200201, 200202, 200401, 200402 |
| T1078.003 | Valid Accounts: Local Accounts | 2 | 200309, 200706 |
| T1082 | System Information Discovery | 1 | 200104 |
| T1090 | Proxy | 1 | 200208 |
| T1091 | Replication Through Removable Media | 3 | 200707, 200710, 200711 |
| T1095 | Non-Application Layer Protocol | 1 | 200204 |
| T1105 | Ingress Tool Transfer | 6 | 200102, 200200, 200606–200608, 200614 |
| T1110 | Brute Force | 1 | 200701 |
| T1200 | Hardware Additions | 1 | 200709 |
| T1204.002 | User Execution: Malicious File | 1 | 200710 |
| T1215 | Kernel Modules and Extensions | 1 | 200307 |
| T1218 | System Binary Proxy Execution | 1 | 200203 |
| T1486 | Data Encrypted for Impact | 1 | 200619 |
| T1489 | Service Stop | 1 | 200109 |
| T1496 | Resource Hijacking | 1 | 200205 |
| T1543.003 | Windows Service | 4 | 200305–200308 |
| T1546.013 | PowerShell Profile | 1 | 200616 |
| T1547.001 | Startup Folder | 1 | 200609 |
| T1562.001 | Disable or Modify Tools | 2 | 200108, 200617 |
| T1562.004 | Disable or Modify System Firewall | 3 | 200602–200604 |
| T1565.001 | Stored Data Manipulation | 5 | 200600, 200601, 200605, 200612, 200613 |
| T1566.001 | Spearphishing Attachment | 2 | 200105, 200202 |
| T1574.001 | DLL Search Order Hijacking | 1 | 200611 |
| T1620 | Reflective Code Loading | 1 | 200103 |

**Total unique MITRE techniques covered: 39**

---

##  References

- [MITRE ATT&CK® Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Wazuh Rule Syntax Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
