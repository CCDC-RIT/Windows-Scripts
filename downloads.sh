# Objective: Download Tools needed for Windows to Ansible Controller Box
# These tools will then be moved to each windows machine during Ansible Execution

# Downloading Scripts

# Audit script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.ps1" -o "audit.ps1"
# Audit policy file
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/auditpol.csv" -o "auditpol.csv"
# Backups script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/backup.ps1" -o "backup.ps1"
# Command runbook
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/command_runbook.txt" -o "command_runbook.txt"
# Defender exploit guard settings
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/defender-exploit-guard-settings.xml" -o "def-eg-settings.xml"
# Firewall script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.ps1" -o "firewall.ps1"
# Inventory script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.ps1" -o "inventory.ps1"
# Logging script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.ps1" -o "logging.ps1"
# Secure baseline script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secure.ps1" -o "secure.ps1"
# Wazuh agent config file
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/agent_windows.conf" -o "agent_windows.conf"
# Yara response script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/yara.bat" -o "yara.bat"
# User Management script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/usermgmt.ps1" -o "usermgmt.ps1"
# SOAR Agent Script
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/SOARAgent.ps1" -o "soaragent.ps1"

# Service tooling 
# DC Tooling
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7BEE3B9E95-9783-474A-86A5-907E93E64F57%7D.zip" -o "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip"
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7B40E1EAFA-8121-4FFA-B6FE-BC348636AB83%7D.zip" -o "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip"
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7B6136C3E1-B316-4C46-9B8B-8C1FC373F73C%7D.zip" -o "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip"
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7BBEAA6460-782B-4351-B17D-4DC8076633C9%7D.zip" -o "{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip"

# Reset-KrbtgtKeyInteractive script
wget -b "https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1" -o "Reset-KrbtgtKeyInteractive.ps1"
# Pingcastle
wget -b "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip" -o "pc.zip"
# Adalanche
wget -b "https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe" -o "adalanche.exe"
# Member server/client tools
# Local policy file
wget -b "https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/localpolicy.PolicyRules" -o "localpolicy.PolicyRules"
# LGPO tool
wget -b "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip" -o "lg.zip"
# LGPO extraction

# Server Core
wget -b "https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip" -o "epp.zip"
wget -b "https://netresec.com/?download=NetworkMiner" -o "nm.zip"

# Third-party tooling for every system

# Get-InjectedThread and Stop-Thread
wget -b "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1" -o "Get-InjectedThread.ps1"
wget -b "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1" -o "Stop-Thread.ps1"
# PrivEsc checker script
wget -b "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1" -o "PrivescCheck.ps1"
# chainsaw + dependency library
wget -b "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip" -o "cs.zip"
wget -b "https://aka.ms/vs/17/release/vc_redist.x64.exe" -o "vc_redist.64.exe"

# hollows hunter
wget -b "https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.9/hollows_hunter64.zip" -o "hh64.zip"
# Wazuh agent
wget -b "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi" -o "wazuhagent.msi"
# Basic Sysmon conf file
wget -b "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -o "sysmon.xml"
# Windows Firewall Control + .NET 4.8
wget -b "https://www.binisoft.org/download/wfc6setup.exe" -o "wfcsetup.exe"
wget -b "https://go.microsoft.com/fwlink/?LinkId=2088631" -o "net_installer.exe"
# Wireshark
wget -b "https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe" -o "wsinstall.exe"
# Sysinternals
wget -b "https://download.sysinternals.com/files/Autoruns.zip" -o "ar.zip"
wget -b "https://download.sysinternals.com/files/ListDlls.zip" -o "dll.zip"
wget -b "https://download.sysinternals.com/files/ProcessExplorer.zip" -o "pe.zip"
wget -b "https://download.sysinternals.com/files/ProcessMonitor.zip" -o "pm.zip"
wget -b "https://download.sysinternals.com/files/Sigcheck.zip" -o "sc.zip"
wget -b "https://download.sysinternals.com/files/TCPView.zip" -o "tv.zip"
wget -b "https://download.sysinternals.com/files/Streams.zip" -o "stm.zip"
wget -b "https://download.sysinternals.com/files/Sysmon.zip" -o "sm.zip"
wget -b "https://download.sysinternals.com/files/AccessChk.zip" -o "ac.zip"
wget -b "https://download.sysinternals.com/files/Strings.zip" -o "str.zip"
# yara
wget -b "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip" -o "yara.zip"
wget -b "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Windows.zip" -o "Windows.zip"
wget -b "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Multi.zip" -o "Multi.zip"
# Notepad++
wget -b "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe" -o "notepadpp_installer.exe"
# googoo chrome
wget -b "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -o "chromeinstall.exe"
# Floss
wget -b "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip" -o "floss.zip"
# Antipwny (Meterpreter Detection)
wget -b "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe" -o "AntiPwny.exe"
wget -b "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll" -o "ObjectListView.dll"