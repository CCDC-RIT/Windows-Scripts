# Objective: Download Tools needed for Windows to Ansible Controller Box
# These tools will then be moved to each windows machine during Ansible Execution

# Downloading Scripts

# Audit script
wget -o "audit.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.ps1"
# Audit policy file
wget -o "auditpol.csv" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/auditpol.csv"
# Backups script
wget -o "backup.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/backup.ps1"
# Command runbook
wget -o "command_runbook.txt" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/command_runbook.txt"
# Defender exploit guard settings
wget -o "def-eg-settings.xml" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/defender-exploit-guard-settings.xml"
# Firewall script
wget -o "firewall.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.ps1"
# Inventory script
wget -o "inventory.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.ps1"
# Logging script
wget -o "logging.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.ps1"
# Secure baseline script
wget -o "secure.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secure.ps1"
# Wazuh agent config file
wget -o "agent_windows.conf" "https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/agent_windows.conf"
# Yara response script
wget -o "yara.bat" "https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/yara.bat"
# User Management script
wget -o "usermgmt.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/usermgmt.ps1"
# SOAR Agent Script
wget -o "soaragent.ps1" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/SOARAgent.ps1"


# Service tooling 
# DC Tooling
wget -o "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7BEE3B9E95-9783-474A-86A5-907E93E64F57%7D.zip"
wget -o "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7B40E1EAFA-8121-4FFA-B6FE-BC348636AB83%7D.zip"
wget -o "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7B6136C3E1-B316-4C46-9B8B-8C1FC373F73C%7D.zip"
wget -o "{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7BBEAA6460-782B-4351-B17D-4DC8076633C9%7D.zip"

# Reset-KrbtgtKeyInteractive script
wget -o "Reset-KrbtgtKeyInteractive.ps1" "https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1"
# Pingcastle
wget -o "pc.zip" "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip"
# Adalanche
wget -o "adalanche.exe" "https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe"
# Member server/client tools
# Local policy file
wget -o "localpolicy.PolicyRules" "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/localpolicy.PolicyRules"
# LGPO tool
wget -o "lg.zip" "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip"
# LGPO extraction

# Server Core
wget -o "epp.zip" "https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip"
wget -o "nm.zip" "https://netresec.com/?download=NetworkMiner"

# Third-party tooling for every system

# Get-InjectedThread and Stop-Thread
wget -o "Get-InjectedThread.ps1" "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1"
wget -o "Stop-Thread.ps1" "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1"
# PrivEsc checker script
wget -o "PrivescCheck.ps1" "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1"
# chainsaw + dependency library
wget -o "cs.zip" "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip"
wget -o "vc_redist.64.exe" "https://aka.ms/vs/17/release/vc_redist.x64.exe"

# hollows hunter
wget -o "hh64.zip" "https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.9/hollows_hunter64.zip"
# Wazuh agent
wget -o "wazuhagent.msi" "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi"
# Basic Sysmon conf file
wget -o "sysmon.xml" "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
# Windows Firewall Control + .NET 4.8
wget -o "wfcsetup.exe" "https://www.binisoft.org/download/wfc6setup.exe"
wget -o "net_installer.exe" "https://go.microsoft.com/fwlink/?LinkId=2088631"
# Wireshark
# (for now) TLS 1.2 link: https://wireshark.marwan.ma/download/win64/Wireshark-win64-latest.exe
wget -o "wsinstall.exe" "https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe"

# Sysinternals
wget -o "ar.zip" "https://download.sysinternals.com/files/Autoruns.zip"
wget -o "dll.zip" "https://download.sysinternals.com/files/ListDlls.zip"
wget -o "pe.zip" "https://download.sysinternals.com/files/ProcessExplorer.zip"
wget -o "pm.zip" "https://download.sysinternals.com/files/ProcessMonitor.zip"
wget -o "sc.zip" "https://download.sysinternals.com/files/Sigcheck.zip"
wget -o "tv.zip" "https://download.sysinternals.com/files/TCPView.zip"
wget -o "stm.zip" "https://download.sysinternals.com/files/Streams.zip"
wget -o "sm.zip" "https://download.sysinternals.com/files/Sysmon.zip"
wget -o "ac.zip" "https://download.sysinternals.com/files/AccessChk.zip"
wget -o "str.zip" "https://download.sysinternals.com/files/Strings.zip"

# yara
wget -o "yara.zip" "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip"
wget -o "Windows.zip" "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Windows.zip"
wget -o "Multi.zip" "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Multi.zip"

# Notepad++
wget -o "notepadpp_installer.exe" "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe"

# googoo chrome
wget -o "chromeinstall.exe" "http://dl.google.com/chrome/install/375.126/chrome_installer.exe"

# Floss
wget -o "floss.zip" "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip"

# Antipwny (Meterpreter Detection)
wget -o "AntiPwny.exe" "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe"
wget -o "ObjectListView.dll" "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll"
