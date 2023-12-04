# Objective: downloads scripts/tools needed

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

param (
    [string]$Path = $(throw "-Path is required.")
)

# somehow this block verifies if the path is legit
$ErrorActionPreference = "Stop"
[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Invalid path" -ForegroundColor white
        break
    }
    $true
})]
$InputPath = $Path
Set-Location -Path $InputPath | Out-Null

# Creating all the directories
$ErrorActionPreference = "Continue"
New-Item -Path $InputPath -Name "scripts" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "installers" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "tools" -ItemType "directory" | Out-Null
$ScriptPath = Join-Path -Path $InputPath -ChildPath "scripts"
$SetupPath = Join-Path -Path $InputPath -ChildPath "installers"
$ToolsPath = Join-Path -Path $InputPath -ChildPath "tools"

New-Item -Path $ScriptPath -Name "conf" -ItemType "directory" | Out-Null
New-Item -Path $ScriptPath -Name "results" -ItemType "directory" | Out-Null
$ConfPath = Join-Path -Path $ScriptPath -ChildPath "conf"
$ResultsPath = Join-Path -Path $ScriptPath -ChildPath "results"

New-Item -Path $ResultsPath -Name "artifacts" -ItemType "directory" | Out-Null
New-Item -Path $ToolsPath -Name "sys" -ItemType "directory" | Out-Null
$SysPath = Join-Path -Path $ToolsPath -ChildPath "sys"

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Directories created" -ForegroundColor white

# Custom tooling downloads
# Audit script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.ps1", (Join-Path -Path $ScriptPath -ChildPath "audit.ps1"))
# Audit policy file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/auditpol.csv", (Join-Path -Path $ConfPath -ChildPath "auditpol.csv"))
# Backups script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/backup.ps1", (Join-Path -Path $ScriptPath -ChildPath "backup.ps1"))
# Command runbook
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/command_runbook.txt", (Join-Path -Path $ScriptPath -ChildPath "command_runbook.txt"))
# Defender exploit guard settings
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/defender-exploit-guard-settings.xml", (Join-Path -Path $ConfPath -ChildPath "def-eg-settings.xml"))  
# Firewall script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.ps1", (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))
# Inventory script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.ps1", (Join-Path -Path $ScriptPath -ChildPath "inventory.ps1"))
# Logging script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.ps1", (Join-Path -Path $ScriptPath -ChildPath "logging.ps1"))
# Secure baseline script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secure.ps1", (Join-Path -Path $ScriptPath -ChildPath "sbaseline.ps1"))
# Wazuh agent config file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/master/agent_windows.conf", (Join-Path -Path $ConfPath -ChildPath "agent_windows.conf"))
# User Management script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/usermgmt.ps1", (Join-Path -Path $ScriptPath -ChildPath "usermgmt.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] System scripts and config files downloaded" -ForegroundColor white

# Service tooling 
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') { # DC detection
    # GPO and security template
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/dc/dc-secpol.inf", (Join-Path -Path $ConfPath -ChildPath "dc-secpol.inf"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/dc/%7BF4A70563-32A9-4B5F-83B2-9DBE866D54FC%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{F4A70563-32A9-4B5F-83B2-9DBE866D54FC}.zip"))
    # Reset-KrbtgtKeyInteractive script
    (New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1", (Join-Path -Path $ScriptPath -ChildPath "Reset-KrbtgtKeyInteractive.ps1"))
    # Pingcastle
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/vletoux/pingcastle/releases/download/3.1.0.1/PingCastle_3.1.0.1.zip", (Join-Path -Path $InputPath -ChildPath "pc.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools downloaded" -ForegroundColor white
    # Pingcastle, GPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pc.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "pc") 
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{F4A70563-32A9-4B5F-83B2-9DBE866D54FC}.zip") -DestinationPath (Join-Path -Path $ConfPath -ChildPath "{F4A70563-32A9-4B5F-83B2-9DBE866D54FC}")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools extracted" -ForegroundColor white
} else { # Member server/client tools
    # GPO and security template 
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/web/web-secpol.inf", (Join-Path -Path $ConfPath -ChildPath "web-secpol.inf"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/web/%7B8DBC52E2-C1DF-4D2D-9A84-0F3760FE3147%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{8DBC52E2-C1DF-4D2D-9A84-0F3760FE3147}.zip"))
    # LGPO tool
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip", (Join-Path -Path $InputPath -ChildPath "lg.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Non-DC GPO, security template, and LGPO downloaded" -ForegroundColor white
    # LGPO, GPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "lg.zip") -DestinationPath $ToolsPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{8DBC52E2-C1DF-4D2D-9A84-0F3760FE3147}.zip") -DestinationPath (Join-Path -Path $ConfPath -ChildPath "{8DBC52E2-C1DF-4D2D-9A84-0F3760FE3147}")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO and non-DC GPO extracted" -ForegroundColor white
}

if (Get-Service -Name CertSvc 2>$null) { # ADCS tools
    # Locksmith
    Install-Module -Name Locksmith -Scope CurrentUser
}

# Third-party tooling for every system

# Get-InjectedThread
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
# hollows hunter
(New-Object System.Net.WebClient).DownloadFile("https://github.com/hasherezade/hollows_hunter/releases/latest/download/hollows_hunter64.zip", (Join-Path -Path $InputPath -ChildPath "hh64.zip"))
# Basic Sysmon conf file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", (Join-Path -Path $ConfPath -ChildPath "sysmon.xml"))
# Wazuh agent
(New-Object System.Net.WebClient).DownloadFile("https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi", (Join-Path -Path $SetupPath -ChildPath "wazuhagent.msi"))
# Windows Firewall Control
(New-Object System.Net.WebClient).DownloadFile("https://www.binisoft.org/download/wfc6setup.exe", (Join-Path -Path $SetupPath -ChildPath "wfcsetup.exe"))
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Traditional infra tooling downloaded" -ForegroundColor white
# Wireshark
# (for now) TLS 1.2 link: https://wireshark.marwan.ma/download/win64/Wireshark-win64-latest.exe
(New-Object System.Net.WebClient).DownloadFile("https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe", (Join-Path -Path $SetupPath -ChildPath "wsinstall.exe"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wireshark installer downloaded" -ForegroundColor white
# Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $InputPath -ChildPath "ar.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $InputPath -ChildPath "dll.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $InputPath -ChildPath "pe.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $InputPath -ChildPath "pm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $InputPath -ChildPath "sc.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $InputPath -ChildPath "tv.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Streams.zip", (Join-Path -Path $InputPath -ChildPath "st.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", (Join-Path -Path $InputPath -ChildPath "sm.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools downloaded" -ForegroundColor white

# Explorer++ (only if Server Core)
if ((Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion") -and (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" | Select-Object -ExpandProperty "InstallationType") -eq "Server Core") {
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip", (Join-Path -Path $UserPath -ChildPath "epp.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "epp.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "epp")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Explorer++ downloaded and extracted" -ForegroundColor white
}

# Notepad++
(New-Object System.Net.WebClient).DownloadFile("https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6/npp.8.6.Installer.x64.exe", (Join-Path -Path $SetupPath -ChildPath "notepadpp_installer.exe"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Notepad++ installer downloaded" -ForegroundColor white

# VSCode
# (New-Object System.Net.WebClient).DownloadFile("https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user", (Join-Path -Path $SetupPath -ChildPath "vscodesetup.exe"))
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] VSCode installer downloaded" -ForegroundColor white

# Extraction
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "st.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "st")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sm")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "hh64.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "hh64")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hollows Hunter extracted" -ForegroundColor white