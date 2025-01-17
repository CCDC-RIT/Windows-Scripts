# Objective: Download Tools needed for Windows to Ansible Controller Box
# These tools will then be moved to each windows machine during Ansible Execution

# Downloading Scripts

# Audit script
curl -o "audit.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.ps1"
# Audit policy file
curl -o "auditpol.csv" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/auditpol.csv"
# Backups script
curl -o "backup.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/backup.ps1"
# Command runbook
curl -o "command_runbook.txt" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/command_runbook.txt"
# Defender exploit guard settings
curl -o "def-eg-settings.xml" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/defender-exploit-guard-settings.xml"
# Firewall script
curl -o "firewall.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.ps1"
# Inventory script
curl -o "inventory.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.ps1"
# Logging script
curl -o "logging.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.ps1"
# Secure baseline script
curl -o "secure.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secure.ps1"
# Wazuh agent config file
curl -o "agent_windows.conf" "https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/agent_windows.conf"
# Yara response script
curl -o "yara.bat" "https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/yara.bat"
# User Management script
curl -o "usermgmt.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/usermgmt.ps1"
# SOAR Agent Script
curl -o "soaragent.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/SOARAgent.ps1"


# Service tooling 
# DC Tooling
curl -o "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip"
curl -o "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip"
curl -o "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip"
curl -o "{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip"
# Reset-KrbtgtKeyInteractive script
curl -o "Reset-KrbtgtKeyInteractive.ps1" "https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1"
# Pingcastle
curl -o "pc.zip" "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip"
# Adalanche
curl -o "adalanche.exe" "https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe"
# Member server/client tools
# Local policy file
curl -o "localpolicy.PolicyRules" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/localpolicy.PolicyRules"
# LGPO tool
curl -o "lg.zip" "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip"
# LGPO extraction

# Server Core
curl -o "epp.zip" "https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip"
curl -o "nm.zip" "https://netresec.com/?download=NetworkMiner"

# Third-party tooling for every system

# Get-InjectedThread and Stop-Thread
curl -o "Get-InjectedThread.ps1" "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1"
curl -o "Stop-Thread.ps1" "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1"
# PrivEsc checker script
curl -o "PrivescCheck.ps1" "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1"
# chainsaw + dependency library
curl -o "cs.zip" "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip"
curl -o "vc_redist.64.exe" "https://aka.ms/vs/17/release/vc_redist.x64.exe"

# hollows hunter
curl -o "hh64.zip" "https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.9/hollows_hunter64.zip"
# Wazuh agent
curl -o "wazuhagent.msi" "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi"
# Basic Sysmon conf file
curl -o "sysmon.xml" "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
# Windows Firewall Control + .NET 4.8
curl -o "wfcsetup.exe" "https://www.binisoft.org/download/wfc6setup.exe"
curl -o "net_installer.exe" "https://go.microsoft.com/fwlink/?LinkId=2088631"
# Wireshark
# (for now) TLS 1.2 link: https://wireshark.marwan.ma/download/win64/Wireshark-win64-latest.exe
curl -o "wsinstall.exe" "https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe"
# Sysinternals
curl -o "ar.zip" "https://download.sysinternals.com/files/Autoruns.zip"
curl -o "dll.zip" "https://download.sysinternals.com/files/dll.zip"

# Sysinternals
curl -o "ar.zip" "https://download.sysinternals.com/files/Autoruns.zip"
curl -o "dll.zip" "https://download.sysinternals.com/files/ListDlls.zip"
curl -o "pe.zip" "https://download.sysinternals.com/files/ProcessExplorer.zip"
curl -o "pm.zip" "https://download.sysinternals.com/files/ProcessMonitor.zip"
curl -o "sc.zip" "https://download.sysinternals.com/files/Sigcheck.zip"
curl -o "tv.zip" "https://download.sysinternals.com/files/TCPView.zip"
curl -o "stm.zip" "https://download.sysinternals.com/files/Streams.zip"
curl -o "sm.zip" "https://download.sysinternals.com/files/Sysmon.zip"
curl -o "ac.zip" "https://download.sysinternals.com/files/AccessChk.zip"
curl -o "str.zip" "https://download.sysinternals.com/files/Strings.zip"

# yara
curl -o "yara.zip" "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip"
curl -o "Windows.zip" "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Windows.zip"
curl -o "Multi.zip" "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Multi.zip"

# Notepad++
curl -o "notepadpp_installer.exe" "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe"

# googoo chrome
curl -o "chromeinstall.exe" "http://dl.google.com/chrome/install/375.126/chrome_installer.exe"

# Floss
curl -o "floss.zip" "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip"

# Antipwny (Meterpreter Detection)
curl -o "AntiPwny.exe" "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe"
curl -o "ObjectListView.dll" "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll"
