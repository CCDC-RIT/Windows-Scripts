#!/usr/bin/env bash
set -euo pipefail

DEV=false
while [[ $# -gt 0 ]]; do
	case "$1" in
		--dev)
			DEV=true
			shift
			;;
		--help|-h)
			echo "Usage: $0 [--dev]"
			exit 0
			;;
		*)
			# ignore unknown/positional for now
			shift
			;;
	esac
done

# This is just a wget wrapper, that prints nothing if it downloads,
# and prints an error if it doesn't download
download() {
	local tmp
	tmp=$(mktemp) || tmp="/tmp/wget.$$"

	if wget "$@" >"$tmp" 2>&1; then
		# detect -O <outfile> if provided and ensure file is non-empty
		local outfile=""
		local args=("$@")
		for ((i=0;i<${#args[@]};i++)); do
			if [ "${args[i]}" = "-O" ]; then
				outfile="${args[i+1]}"
				break
			fi
		done

		if [ -n "$outfile" ] && [ ! -s "$outfile" ]; then
			echo "[ERROR] Download produced empty file: $outfile"
			cat "$tmp"
			rm -f "$tmp"
			return 1
		fi

		rm -f "$tmp"
		return 0
	else
		echo "[ERROR] wget failed. Log for: ${*: -1}"
		cat "$tmp"
		rm -f "$tmp"
		return 1
	fi
}

# Objective: Download Tools needed for Windows to Ansible Controller Box
# These tools will then be moved to each windows machine during Ansible Execution

# Set up folder for backups

if [ ! -d "backups" ]; then
	mkdir backups
fi
if [ ! -d "ansible/roles/copy-core-scripts/files" ]; then
	mkdir ansible/roles/copy-core-scripts/files
fi
if [ ! -d "ansible/roles/copy-other/files" ]; then
	mkdir ansible/roles/copy-other/files
fi

# Downloading Scripts

# Download script
cp downloads.ps1 ansible/roles/copy-core-scripts/files/downloads.ps1
# Audit script
cp audit.ps1 ansible/roles/copy-other/files/audit.ps1
# Audit policy file
cp auditpol.csv ansible/roles/copy-other/files/auditpol.csv
# Backups script
cp backup.ps1 ansible/roles/copy-core-scripts/files/backup.ps1
# Command runbook
cp command_runbook.txt ansible/roles/copy-other/files/command_runbook.txt
# Defender exploit guard settings
cp defender-exploit-guard-settings.xml ansible/roles/copy-other/files/def-eg-settings.xml
# Firewall script
cp firewall.ps1 ansible/roles/copy-core-scripts/files/firewall.ps1
# Inventory script
cp inventory.ps1 ansible/roles/copy-other/files/inventory.ps1
# Logging script
cp logging.ps1 ansible/roles/copy-other/files/logging.ps1
# Secure script
cp secure.ps1 ansible/roles/copy-other/files/secure.ps1
# Powershell profile
cp profile.ps1 ansible/roles/copy-other/files/profile.ps1
# HTTPS cert template
cp certs/cert.inf ansible/roles/copy-other/files/cert.inf

echo "[SUCCESS] Scripts Copied."

# Service tooling 
# DC Tooling
cp gpos/{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip ansible/roles/copy-other/files/{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip
cp gpos/{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip ansible/roles/copy-other/files/{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip
cp gpos/{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip ansible/roles/copy-other/files/{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip
cp gpos/{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip ansible/roles/copy-other/files/{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip

echo "[SUCCESS] GPO's Copied."

# Reset-KrbtgtKeyInteractive script
download "https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1" -O "ansible/roles/copy-other/files/Reset-KrbtgtKeyInteractive.ps1"
# Pingcastle
download "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip" -O "ansible/roles/copy-other/files/pc.zip"
# Adalanche
download "https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe" -O "ansible/roles/copy-other/files/adalanche.exe"
# Member server/client tools
# Local policy file
cp gpos/localpolicy.PolicyRules ansible/roles/copy-other/files/localpolicy.PolicyRules
# LGPO tool
download "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip" -O "ansible/roles/copy-other/files/lg.zip" --no-check-certificate

echo "[SUCCESS] Client tools downloaded."

# Server Core
download "https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip" -O "ansible/roles/copy-other/files/epp.zip"

download "https://netresec.com/?download=NetworkMiner" -O "ansible/roles/copy-other/files/nm.zip"

echo "[SUCCESS] Server Core tools downloaded."

# Third-party tooling for every system

# Everything search tool
download "https://www.voidtools.com/Everything-1.4.1.1024.x64.zip" -O "ansible/roles/copy-other/files/everything.zip"
download "https://www.voidtools.com/ES-1.1.0.27.x64.zip" -O "ansible/roles/copy-other/files/es.zip"

# BCU
download "https://github.com/Klocman/Bulk-Crap-Uninstaller/releases/download/v5.7/BCUninstaller_5.7_portable.zip" -O "ansible/roles/copy-other/files/bcu.zip"

if [ ! -d "ansible/roles/password-manager-client/files" ]; then
    mkdir -p "ansible/roles/password-manager-client/files"
fi

# Password Manager
download "https://github.com/CCDC-RIT/Password-Manager/raw/refs/heads/main/client/windows.exe" -O "ansible/roles/password-manager-client/files/CCDC-Password-Manager.exe"

if [ ! -d "ansible/roles/birdsnest-owlet/files" ]; then
    mkdir -p "ansible/roles/birdsnest-owlet/files"
fi
if [ ! -d "ansible/roles/birdsnest-stabvest/files" ]; then
    mkdir -p "ansible/roles/birdsnest-stabvest/files"
fi
if [ ! -d "/opt/birdsnest" ]; then
    mkdir -p "/opt/birdsnest"
fi
git clone https://github.com/CCDC-RIT/birdsnest "/opt/birdsnest"
chmod -R 0777 "/opt/birdsnest"
cp -p /opt/birdsnest/birdsnest/agents/owlet ansible/roles/birdsnest-owlet/files
cp -p /opt/birdsnest/birdsnest/agents/stabvest ansible/roles/birdsnest-stabvest/files

# Get-InjectedThread and Stop-Thread
download "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1" -O "ansible/roles/copy-other/files/Get-InjectedThread.ps1"
download "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1" -O "ansible/roles/copy-other/files/Stop-Thread.ps1"
# PrivEsc checker script
download "https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1" -O "ansible/roles/copy-other/files/PrivescCheck.ps1"
# chainsaw + dependency library
download "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip" -O "ansible/roles/copy-other/files/cs.zip"
download "https://aka.ms/vs/17/release/vc_redist.x64.exe" -O "ansible/roles/copy-other/files/vc_redist.64.exe"
# hollows hunter
download "https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.9/hollows_hunter64.zip" -O "ansible/roles/copy-other/files/hh64.zip"
# Basic Sysmon conf file
download "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -O "ansible/roles/copy-other/files/sysmon.xml"
# Windows Firewall Control + .NET 4.8
download "https://www.binisoft.org/download/wfc6setup.exe" -O "ansible/roles/copy-other/files/wfcsetup.exe"
download "https://go.microsoft.com/fwlink/?LinkId=2088631" -O "ansible/roles/copy-other/files/net_installer.exe" --no-check-certificate
# Wireshark
download "https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe" -O "ansible/roles/copy-other/files/wsinstall.exe"
echo "[SUCCESS] Threat-hunting and analysis tools downloaded."

# Sysinternals
download "https://download.sysinternals.com/files/Autoruns.zip" -O "ansible/roles/copy-other/files/ar.zip"
download "https://download.sysinternals.com/files/ListDlls.zip" -O "ansible/roles/copy-other/files/dll.zip"
download "https://download.sysinternals.com/files/ProcessExplorer.zip" -O "ansible/roles/copy-other/files/pe.zip"
download "https://download.sysinternals.com/files/ProcessMonitor.zip" -O "ansible/roles/copy-other/files/pm.zip"
download "https://download.sysinternals.com/files/Sigcheck.zip" -O "ansible/roles/copy-other/files/sc.zip"
download "https://download.sysinternals.com/files/TCPView.zip" -O "ansible/roles/copy-other/files/tv.zip"
download "https://download.sysinternals.com/files/Streams.zip" -O "ansible/roles/copy-other/files/stm.zip"
download "https://download.sysinternals.com/files/Sysmon.zip" -O "ansible/roles/copy-other/files/sm.zip"
download "https://download.sysinternals.com/files/AccessChk.zip" -O "ansible/roles/copy-other/files/ac.zip"
download "https://download.sysinternals.com/files/Strings.zip" -O "ansible/roles/copy-other/files/str.zip"
download "https://download.sysinternals.com/files/PsExec.zip" -O "ansible/roles/copy-other/files/ps.zip"

echo "[SUCCESS] Sysinternals downloaded."

# adfs rapid recreation tool
download "https://download.microsoft.com/download/6/8/a/68af3cd3-1337-4389-967c-a6751182f286/ADFSRapidRecreationTool.msi" --no-check-certificate -O "ansible/roles/copy-core-scripts/files/ADFSRapidRecreationTool.msi"
echo "[SUCCESS] ADFS Rapid Recreation Tool downloaded."
# yara
download "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip" -O "ansible/roles/copy-other/files/yara.zip"
download "https://raw.githubusercontent.com/CCDC-RIT/YaraRules/master/Windows.zip" -O "ansible/roles/copy-other/files/Windows.zip"
download "https://raw.githubusercontent.com/CCDC-RIT/YaraRules/master/Multi.zip" -O "ansible/roles/copy-other/files/Multi.zip"
download "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip" -O "ansible/roles/copy-other/files/yarahq.zip"
echo "[SUCCESS] Yara and Yara rules downloaded."
# Notepad++
download "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe" -O "ansible/roles/copy-other/files/notepadpp_installer.exe"
# googoo chrome
download "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -O "ansible/roles/copy-other/files/chromeinstall.exe"
# Antipwny (Meterpreter Detection)
download "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe" -O "ansible/roles/copy-other/files/AntiPwny.exe"
download "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll" -O "ansible/roles/copy-other/files/ObjectListView.dll"
# Datadog ip addresses
download "https://ip-ranges.us5.datadoghq.com/" -O "ansible/roles/copy-core-scripts/files/datadog_ips.txt"
# Tabula Download
download "https://raw.githubusercontent.com/CCDC-RIT/stabvest-public/refs/heads/main/tabula/tabula.py" -O "ansible/roles/copy-other/files/tabula.py"

echo "[SUCCESS] All tools downloaded"
