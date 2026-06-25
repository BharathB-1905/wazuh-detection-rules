# 🚀 Deployment Guide — Wazuh Custom Detection Ruleset

> Covers deployment on a Wazuh v4.14.x cluster (single-node or multi-node).  
> Tested on: **Wazuh v4.14.5 · 3-node cluster · Windows 11 endpoint with Sysmon**

---

## 📋 Prerequisites

Before deploying these rules, ensure the following are in place:

### On the Wazuh Manager
- Wazuh Manager v4.7+ (rules use PCRE2 syntax)
- SSH access to the manager node
- `root` or `sudo` privileges

### On the Windows Endpoint (Agent)
- Wazuh Agent installed and enrolled
- **Sysmon v13+** installed with a configuration that enables:
  - Event ID 1 — Process Create
  - Event ID 3 — Network Connect
- Windows Security Audit Policy enabled for:
  - Logon/Logoff events (4624, 4625)
  - Object Access
  - Task Scheduler events (4698, 4699, 4700, 4702)
  - System events (7040, 7045)
  - Policy Change events (4946, 4947, 4950)

---

## 🗂️ Step 1 — Prepare the Rule Files

Clone the repository or download the rule files:

```bash
git clone https://github.com/YOUR_USERNAME/wazuh-detection-rules.git
cd wazuh-detection-rules/rules
```

You should have these 6 files:

```
powershell_rules.xml
network_rules.xml
network_traffic.xml
task_service_rules.xml
fim_firewall_rules.xml
rdp_usb_print_rules.xml
```

---

## 📤 Step 2 — Transfer Rules to Wazuh Manager

### Option A — SCP (recommended)

```bash
scp rules/*.xml user@<wazuh-manager-ip>:/tmp/
```

Then SSH into the manager and move them:

```bash
ssh user@<wazuh-manager-ip>
sudo mv /tmp/*_rules.xml /var/ossec/etc/rules/
sudo mv /tmp/network_traffic.xml /var/ossec/etc/rules/
```

### Option B — Direct copy (if on the manager already)

```bash
sudo cp rules/*.xml /var/ossec/etc/rules/
```

---

## 🔐 Step 3 — Set Correct Ownership and Permissions

```bash
sudo chown root:wazuh /var/ossec/etc/rules/powershell_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/network_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/network_traffic.xml
sudo chown root:wazuh /var/ossec/etc/rules/task_service_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/fim_firewall_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/rdp_usb_print_rules.xml

sudo chmod 660 /var/ossec/etc/rules/*_rules.xml
sudo chmod 660 /var/ossec/etc/rules/network_traffic.xml
```

Verify:

```bash
ls -la /var/ossec/etc/rules/ | grep -E "powershell|network|task|fim|rdp"
```

---

## ✅ Step 4 — Validate Rule Syntax

Always validate before restarting the manager:

```bash
sudo /var/ossec/bin/wazuh-logtest -t
```

Expected output — no errors, rules should load cleanly. If you see `Invalid rule` errors, check the specific file and line number reported.

For a quick PCRE2 syntax check:

```bash
sudo /var/ossec/bin/ossec-logtest -t 2>&1 | grep -i "error\|warning"
```

---

## 🔄 Step 5 — Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

Check that the manager came back up cleanly:

```bash
sudo systemctl status wazuh-manager
```

---

## 🔍 Step 6 — Verify Rules Are Loaded

Check that your custom rule IDs appear in the loaded ruleset:

```bash
sudo grep -r "200100\|200200\|200300\|200400\|200600\|200700" /var/ossec/logs/ossec.log | head -20
```

Or test a specific rule by replaying a sample log through `wazuh-logtest`:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a Sysmon Event 1 log entry and check if rule 200100 or similar fires. Type `exit` to quit.

---

## 🖥️ Step 7 — Configure FIM on the Windows Agent

The FIM rules (200600–200619) require File Integrity Monitoring to be configured on the agent. Edit the agent's `ossec.conf`:

**Path:** `C:\Program Files (x86)\ossec-agent\ossec.conf`

Add or verify these `<directories>` blocks under `<syscheck>`:

```xml
<syscheck>
  <frequency>300</frequency>

  <!-- System critical paths -->
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\SysWOW64</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc</directories>

  <!-- Startup persistence path -->
  <directories check_all="yes" realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>

  <!-- User temp/download paths -->
  <directories check_all="yes" realtime="yes">C:\Users\%USERNAME%\AppData\Local\Temp</directories>
  <directories check_all="yes" realtime="yes">C:\Users\%USERNAME%\Downloads</directories>

  <!-- Custom monitored folder (adjust to your environment) -->
  <directories check_all="yes" realtime="yes">D:\PRIVATE\DOCS</directories>

  <!-- Wazuh agent config (anti-tampering) -->
  <directories check_all="yes" realtime="yes">C:\Program Files (x86)\ossec-agent</directories>
</syscheck>
```

After editing, restart the Wazuh agent on the endpoint:

```powershell
Restart-Service -Name "Wazuh"
```

---

## 📡 Step 8 — Configure Windows Audit Policy (on Endpoint)

Enable the required audit categories via PowerShell (run as Administrator):

```powershell
# Logon events (for RDP rules)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Task Scheduler (for task_service_rules)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Policy Change (for firewall rules)
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

# System events (for service rules)
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Verify
auditpol /get /category:*
```

---

## 🔵 Step 9 — (Optional) Sysmon Deployment

If Sysmon is not yet deployed on the Windows endpoint:

```powershell
# Download Sysmon from Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"

# Install with a config (use SwiftOnSecurity or your own)
$sysmonPath = "$env:TEMP\Sysmon\Sysmon64.exe"
& $sysmonPath -accepteula -i sysmonconfig.xml
```

Verify Sysmon is running:

```powershell
Get-Service Sysmon64
```

The Wazuh agent automatically ingests Sysmon events from the Windows Event Log (`Microsoft-Windows-Sysmon/Operational`) — no additional agent config required.

---

## 🧪 Step 10 — Test Rule Firing

Run these safe test commands on the Windows endpoint to verify detection:

### Test PowerShell rule (200101 — suspicious flags)
```powershell
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Write-Host test"
```
Expected: Alert fires on rule 200101, level 9.

### Test FIM rule (200606 — file added to monitored path)
```powershell
New-Item -Path "C:\Windows\System32\test_fim_check.txt" -ItemType File
Remove-Item "C:\Windows\System32\test_fim_check.txt"
```
Expected: Alert fires on rule 200607 or 200606.

### Test scheduled task rule (200300)
```powershell
Register-ScheduledTask -TaskName "TestWazuhRule" -Action (New-ScheduledTaskAction -Execute "notepad.exe") -RunLevel Highest
Unregister-ScheduledTask -TaskName "TestWazuhRule" -Confirm:$false
```
Expected: Alerts fire on rules 200300 (created) and 200302 (deleted).

---

## 🗃️ Multi-Node Cluster Notes

If running a Wazuh cluster (manager + worker nodes), rules only need to be deployed on the **master manager node**. They are automatically synced to worker nodes.

To verify sync status:

```bash
sudo /var/ossec/bin/cluster_control -i
```

Rules directory sync is handled by the cluster daemon. After restarting the master, wait ~60 seconds and check worker nodes:

```bash
# On a worker node
ls /var/ossec/etc/rules/ | grep -E "^200"
```

---

## 🛠️ Troubleshooting

| Issue | Fix |
|-------|-----|
| Rules not loading after restart | Check `/var/ossec/logs/ossec.log` for XML parse errors |
| FIM alerts not firing | Verify `<syscheck>` paths in agent `ossec.conf` and restart agent |
| Sysmon events not ingested | Confirm `win.eventdata` fields exist in Wazuh's raw log view |
| Rule fires on every PowerShell (noisy) | Add `<field name="win.eventdata.parentImage">wazuh-agent.exe</field>` negate to tune |
| PCRE2 syntax error on older Wazuh | Upgrade to Wazuh v4.7+ — PCRE2 is required |
| Cluster rules not syncing | Restart `wazuh-manager` on master; check cluster logs at `/var/ossec/logs/cluster.log` |

---

## 📞 Support

For issues specific to this ruleset, open a GitHub Issue with:
- Wazuh version (`wazuh-manager --version`)
- The rule ID that is misbehaving
- A sanitized sample of the log that triggered (or failed to trigger) the rule
