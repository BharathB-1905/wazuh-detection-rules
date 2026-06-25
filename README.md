#  Wazuh Custom Detection Ruleset — Windows 11 Endpoint

> **Production-grade SIEM detection rules for Wazuh, mapped to MITRE ATT&CK®**  
> Developed and validated on a live 3-node Wazuh v4.14.5 cluster against a hardened Windows 11 endpoint.

---

##  Overview

This repository contains a custom Wazuh detection ruleset (Rule IDs `200100–200714`) developed for a production SOC environment. The rules were authored, tested, and tuned against real telemetry from a Windows 11 endpoint (`HYDRA`) running Sysmon + Wazuh agent, integrated into a 3-node Wazuh cluster with TheHive 5, Velociraptor, and Suricata IDS.

Each rule is:
- **MITRE ATT&CK® mapped** with explicit technique IDs
- **Severity-graded** (levels 7–12) for alert prioritization
- **Regex-optimized** using PCRE2 patterns for accuracy and low false-positive rate
- **Field-specific** — targeting Sysmon Event Data, Windows Security Events, and FIM alerts

---

##  Repository Structure

```
wazuh-detection-rules/
│
├── README.md
├── rules/
│   ├── fim_firewall_rules.xml     # Rules 200600–200619
│   ├── network_rules.xml          # Rules 200200–200209
│   ├── network_traffic.xml        # Rules 200400–200402
│   ├── powershell_rules.xml       # Rules 200100–200109
│   ├── rdp_usb_print_rules.xml    # Rules 200700–200714
│   └── task_service_rules.xml     # Rules 200300–200309
├── docs/
│   ├── MITRE_mapping.md
│   └── deployment_guide.md
└── LICENSE
```

---

##  Rule Coverage Summary

| File | Rule IDs | Count | Detection Category |
|------|----------|-------|--------------------|
| `powershell_rules.xml` | 200100–200109 | 10 | PowerShell Abuse & Evasion |
| `network_rules.xml` | 200200–200209 | 10 | Network Anomalies & C2 |
| `network_traffic.xml` | 200400–200402 | 3 | Protocol-Specific Traffic |
| `task_service_rules.xml` | 200300–200309 | 9 | Persistence via Tasks & Services |
| `fim_firewall_rules.xml` | 200600–200619 | 20 | File Integrity & Firewall Tampering |
| `rdp_usb_print_rules.xml` | 200700–200714 | 13 | RDP, USB, PrintNightmare |
| **Total** | **200100–200714** | **65** | **Multi-vector Windows Detection** |

---

##  MITRE ATT&CK® Coverage

### PowerShell Detection (`powershell_rules.xml`)

| Rule ID | Level | Technique | Description |
|---------|-------|-----------|-------------|
| 200100 | 7 | T1059.001 | PowerShell process launched by user |
| 200101 | 9 | T1059.001, T1027 | Suspicious flags (`-enc`, `-bypass`, `-hidden`) |
| 200102 | 9 | T1105, T1059.001 | Download cradle (`DownloadString`, `WebClient`) |
| 200103 | 9 | T1059.001, T1620 | In-memory execution (`Invoke-Expression`, `Reflection.Assembly`) |
| 200104 | 7 | T1082, T1059.001 | Recon commands (`whoami`, `net user`, `systeminfo`) |
| 200105 | 9 | T1566.001, T1059.001 | Suspicious parent process (Word, Excel, mshta, cmd) |
| 200106 | 12 | T1003, T1059.001 | **Credential theft** (Mimikatz, lsass, sekurlsa) |
| 200107 | 9 | T1053.005, T1059.001 | Persistence via scheduled task or service creation |
| 200108 | 12 | T1562.001, T1070.001 | **Defense evasion** (Clear-EventLog, DisableRealtimeMonitoring) |
| 200109 | 12 | T1003.001, T1489 | **Memory dump / aggressive process kill** (MiniDumpWriteDump) |

### Network Detection (`network_rules.xml`)

| Rule ID | Level | Technique | Description |
|---------|-------|-----------|-------------|
| 200200 | 10 | T1105 | LOLBin network connection (certutil, bitsadmin, curl, wget) |
| 200201 | 12 | T1059, T1071 | **Scripting engine initiated network connection** |
| 200202 | 12 | T1566, T1071 | **Office application C2 callback** (Word, Excel, PowerPoint) |
| 200203 | 10 | T1218 | System proxy binary (rundll32, regsvr32, msbuild) network call |
| 200204 | 12 | T1095 | **Known reverse shell / C2 ports** (4444, 1337, 31337, 8888) |
| 200205 | 9 | T1496 | Cryptomining pool ports (3333, 14444, 7777) |
| 200206 | 8 | T1021 | Lateral movement ports (3389, 5985, 5986, 445) from abnormal process |
| 200207 | 7 | T1048 | Cleartext protocol (FTP/Telnet/TFTP) connection |
| 200208 | 10 | T1090 | TOR / anonymity network ports (9001, 9050, 1080) |
| 200209 | 9 | T1049 | Recon tool network connection (whoami, net, ipconfig) |

### Network Traffic (`network_traffic.xml`)

| Rule ID | Level | Technique | Description |
|---------|-------|-----------|-------------|
| 200400 | 8 | T1021.004 | SSH connection attempt |
| 200401 | 8 | T1071 | FTP connection attempt |
| 200402 | 8 | T1071 | SMTP connection attempt |

### Scheduled Tasks & Services (`task_service_rules.xml`)

| Rule ID | Level | Technique | Description |
|---------|-------|-----------|-------------|
| 200300 | 9 | T1053.005 | Scheduled task created (Event 4698) |
| 200301 | 9 | T1053.005 | Scheduled task modified (Event 4702) |
| 200302 | 7 | T1053.005 | Scheduled task deleted (Event 4699) |
| 200303 | 7 | T1053.005 | Scheduled task enabled (Event 4700) |
| 200304 | 12 | T1053.005, T1036 | **Suspicious task name** (masquerading as svchost, lsass, csrss) |
| 200305 | 9 | T1543.003 | New Windows service installed (Event 7045) |
| 200306 | 12 | T1543.003, T1036 | **Service from suspicious path** (Temp, AppData, Public) |
| 200307 | 12 | T1543.003, T1215 | **Kernel/filesystem driver installed as service** |
| 200308 | 9 | T1543.003 | Service startup changed to Auto-Start |
| 200309 | 12 | T1053.005, T1078.003 | **Task created by SYSTEM/service account** |

### FIM & Firewall (`fim_firewall_rules.xml`)

| Rule ID | Level | Technique | Description |
|---------|-------|-----------|-------------|
| 200600 | 12 | T1565.001, T1071 | **hosts file modified** |
| 200601 | 12 | T1565.001, T1071 | **hosts file recreated/replaced** |
| 200602 | 9 | T1562.004 | Firewall inbound rule added (Event 4946) |
| 200603 | 9 | T1562.004 | Firewall rule deleted (Event 4947) |
| 200604 | 12 | T1562.004 | **Firewall profile setting changed** (Event 4950) |
| 200605 | 7 | T1565.001 | FIM: monitored file modified |
| 200606 | 7 | T1105 | FIM: new file added to monitored path |
| 200607 | 12 | T1105, T1036 | **New executable dropped in System32** |
| 200608 | 12 | T1105, T1036 | **New executable dropped in SysWOW64** |
| 200609 | 12 | T1547.001 | **File dropped in Startup folder** (persistence) |
| 200610 | 9 | T1059 | Script created in Temp/AppData |
| 200611 | 9 | T1574.001 | DLL dropped in non-standard user path (DLL hijacking) |
| 200612 | 9 | T1565.001 | File added to monitored PRIVATE DOCS folder |
| 200613 | 7 | T1565.001 | File modified in monitored PRIVATE DOCS folder |
| 200614 | 9 | T1105 | Executable downloaded to Downloads folder |
| 200615 | 9 | T1003.002 | **Windows registry hive file modified** (SAM, SYSTEM, SECURITY) |
| 200616 | 9 | T1546.013 | PowerShell profile script modified (persistence) |
| 200617 | 12 | T1562.001 | **Wazuh agent config file modified** (anti-tampering) |
| 200618 | 9 | T1070.004 | FIM: monitored file deleted |
| 200619 | 12 | T1486 | **Mass file modification — ransomware indicator** (20 files/60s) |

### RDP, USB & PrintNightmare (`rdp_usb_print_rules.xml`)

| Rule ID | Level | Technique | Description |
|---------|-------|-----------|-------------|
| 200700 | 9 | T1021.001 | RDP successful logon (LogonType 10) |
| 200701 | 9 | T1021.001, T1110 | RDP failed logon attempt |
| 200703 | 9 | T1021.001 | RDP logon outside business hours (9PM–6AM) |
| 200704 | 9 | T1021.001 | RDP lateral movement from internal IP |
| 200706 | 9 | T1021.001, T1078.003 | RDP logon using built-in Administrator account |
| 200707 | 9 | T1091, T1052.001 | USB device connected (Event 2003) |
| 200708 | 7 | T1052.001 | USB device disconnected (Event 2100) |
| 200709 | 9 | T1200 | New USB device first-time installation (Event 20001) |
| 200710 | 12 | T1091, T1204.002 | **Executable launched from removable drive** |
| 200711 | 12 | T1091, T1059 | **Script executed from removable drive** |
| 200712 | 12 | T1068, T1547 | **PrintNightmare — spoolsv.exe spawned child process** |
| 200713 | 12 | T1068 | **PrintNightmare — DLL loaded from spool drivers path** |
| 200714 | 12 | T1068, T1059 | **PrintNightmare RCE — spoolsv.exe spawned shell** |

---

##  Environment

| Component | Details |
|-----------|---------|
| Wazuh Version | v4.14.5 |
| Cluster Nodes | 3-node (Manager · Indexer · Dashboard) |
| Endpoint | Windows 11 (HYDRA) — Sysmon + Wazuh Agent |
| Sysmon Events Used | Event 1 (Process Create), Event 3 (Network Connect) |
| Windows Events Used | 4624, 4625, 4698, 4699, 4700, 4702, 4946, 4947, 4950, 7040, 7045 |
| FIM Events Used | SID 550 (modified), 553 (deleted), 554 (added) |
| Supporting Stack | TheHive 5 · Velociraptor · Suricata IDS · OpenCanary |

---

##  Deployment Guide

### 1. Copy rules to Wazuh manager

```bash
scp rules/*.xml user@<wazuh-manager>:/var/ossec/etc/rules/
```

### 2. Set correct ownership

```bash
chown root:wazuh /var/ossec/etc/rules/200*.xml
chmod 660 /var/ossec/etc/rules/200*.xml
```

### 3. Validate configuration

```bash
/var/ossec/bin/wazuh-logtest
# Or for full config check:
/var/ossec/bin/ossec-logtest -t
```

### 4. Restart Wazuh manager

```bash
systemctl restart wazuh-manager
```

### 5. Verify rules loaded

```bash
grep -r "200100\|200200\|200300\|200600\|200700" /var/ossec/logs/ossec.log
```

> **Note:** Sysmon must be deployed on the Windows endpoint with a config that enables Event ID 1, 3, and relevant registry/network events. FIM paths must be configured in the Wazuh agent's `ossec.conf`.

---

##  Alert Severity Guide

| Level | Severity | Action |
|-------|----------|--------|
| 7 | Low | Log and monitor |
| 8–9 | Medium | Investigate within 24h |
| 10–11 | High | Investigate same day |
| 12 | Critical | Immediate response |

Rules at level 12 cover: credential theft, PrintNightmare RCE, ransomware mass-modification, kernel driver installs, defense evasion, and Wazuh agent tampering.

---

##  Author

**Bharath B**  

**Certifications:** CHFI · CompTIA Security+ · CCA-CNS (IIT Madras) · CSA1/CSA2 (Mile2) · 

---

##  License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

##  Topics

`wazuh` `siem` `detection-engineering` `mitre-attack` `blue-team` `dfir` `windows-security` `sysmon` `threat-detection` `cybersecurity` `incident-response` `soc`
