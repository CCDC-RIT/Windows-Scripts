# will download other scripts/tools needed

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

$ErrorActionPreference = "Stop"

[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        throw "Invalid Path"
    }
    $true
})]
$UserPath = Read-Host -Prompt "Input absolute path to download files:"
Set-Location -Path $UserPath

$ErrorActionPreference = "Continue"
New-Item -Path $UserPath -Name "scripts" -ItemType "directory"
New-Item -Path $UserPath -Name "setup" -ItemType "directory"
New-Item -Path $UserPath -Name "tools" -ItemType "directory"
$ScriptPath = Join-Path -Path $UserPath -ChildPath "scripts"
$ToolsPath = Join-Path -Path $UserPath -ChildPath "tools"

# Certain tools are specific to types of systems
if (!(Get-WmiObject -Query 'select * from Win32_OperatingSystem where (ProductType = "2")')) {
    Write-Host "[INFO] Downloading local user management script..."
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/blum.bat", (Join-Path -Path $ScriptPath -ChildPath "blum.bat"))
    # LGPO
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip", (Join-Path -Path $ToolsPath -ChildPath "LGPO.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $ToolsPath -ChildPath "LGPO.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "LGPO")
} 

# Scripts and config files 
New-Item -Path $ScriptPath -Name "conf" -ItemType "directory"
New-Item -Path $ScriptPath -Name "results" -ItemType "directory"
$ConfPath = Join-Path -Path $ScriptPath -ChildPath "conf"

(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.bat", (Join-Path -Path $ScriptPath -ChildPath "audit.bat"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/firewall.ps1", (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/logging.ps1", (Join-Path -Path $ScriptPath -ChildPath "logging.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/sbaseline.ps1", (Join-Path -Path $ScriptPath -ChildPath "sbaseline.ps1"))
# Get-InjectedThread
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
# Hidden services
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/joswr1ght/c5d9773a90a22478309e9e427073fd30/raw/128fd9bde4ef989c7037e1b5c51d14ace823146f/checkhiddensvc.ps1", (Join-Path -Path $ScriptPath -ChildPath "checkhiddensvc.ps1"))
# Security policy file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/wc-client-member-v5.inf", (Join-Path -Path $ConfPath -ChildPath "secpol.inf"))
# Audit policy file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/wc-auditpol-v1.csv", (Join-Path -Path $ConfPath -ChildPath "auditpol.csv"))
# GPO
(New-Object System.Net.WebClient).DownloadFile("https://github.com/CCDC-RIT/Windows-Scripts/raw/master/wc/%7BA1E02EB6-57AA-428A-A17C-2182E09F31F8%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{A1E02EB6-57AA-428A-A17C-2182E09F31F8}.zip"))
Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{A1E02EB6-57AA-428A-A17C-2182E09F31F8}.zip") -DestinationPath (Join-Path -Path $ConfPath -ChildPath "{A1E02EB6-57AA-428A-A17C-2182E09F31F8}")

# Installers for various tools
# Malwarebytes
(New-Object System.Net.WebClient).DownloadFile("https://www.malwarebytes.com/api/downloads/mb-windows?filename=MBSetup.exe", (Join-Path -Path $ToolsPath -ChildPath "MBSetup.exe"))
# PatchMyPC
(New-Object System.Net.WebClient).DownloadFile("https://patchmypc.com/freeupdater/PatchMyPC.exe", (Join-Path -Path $ToolsPath -ChildPath "PatchMyPC.exe"))

# Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $UserPath -ChildPath "ar.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $UserPath -ChildPath "dll.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $UserPath -ChildPath "pe.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $UserPath -ChildPath "pm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $UserPath -ChildPath "sc.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $UserPath -ChildPath "tv.zip"))

# Unzipping stuff
New-Item -Path $ToolsPath -Name "sys" -ItemType "directory"
$SysPath = Join-Path -Path $ToolsPath -ChildPath "sys"
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
Expand-Archive -LiteralPath (Join-Path -Path $UserPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")