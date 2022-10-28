# TODO: Make directory a user-supplied input 
# TODO: create reference page of links, replace links in 5 min plan w/shortened versions

# Deciding what user management tools to download
$ad = Read-Host "Is this a Domain Controller (Y or N)? "
if ($ad -eq "Y") {
    Write-Host "Downloading AD tools in addition to others..."
    # dotnetfx35.exe /q /norestart
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/2/0/E/20E90413-712F-438C-988E-FDAA79A8AC3D/dotnetfx35.exe", "C:\Program Files\WindowsPowershell\pickles\dotnetfx35.exe")
    (New-Object System.Net.WebClient).DownloadFile("https://wisedataman.com/wp-content/uploads/2020/11/WiseSoftBulkADUsers.zip", "C:\Program Files\WindowsPowershell\pickles\badu.zip")
    Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\badu.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\badu"
} else {
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/blum.bat", "C:\Program Files\WindowsPowershell\pickles\blum.bat")
}
$core = Read-Host "Is this server a Core Server (Y or N)? "
if ($core -eq "Y") {
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip", "C:\Program Files\WindowsPowershell\pickles\epp.zip")
    Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\epp.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\epp"
}

# Other scripts/files
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/blum.bat", "C:\Program Files\WindowsPowershell\pickles\blum.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.bat", "C:\Program Files\WindowsPowershell\pickles\audit.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.bat", "C:\Program Files\WindowsPowershell\pickles\firewall.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.bat", "C:\Program Files\WindowsPowershell\pickles\inventory.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.bat", "C:\Program Files\WindowsPowershell\pickles\logging.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/netstat.bat", "C:\Program Files\WindowsPowershell\pickles\netstat.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secure.bat", "C:\Program Files\WindowsPowershell\pickles\secure.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secpol.inf", "C:\Program Files\WindowsPowershell\pickles\secpol.inf")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/folderintegrity.bat", "C:\Program Files\WindowsPowershell\pickles\folderintegrity.bat")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/goldentickets.bat", "C:\Program Files\WindowsPowershell\pickles\goldentickets.bat")

# Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", "C:\Program Files\WindowsPowershell\pickles\ar.zip")
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", "C:\Program Files\WindowsPowershell\pickles\tv.zip")
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", "C:\Program Files\WindowsPowershell\pickles\sm.zip")
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", "C:\Program Files\WindowsPowershell\pickles\pe.zip")
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", "C:\Program Files\WindowsPowershell\pickles\pm.zip")
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", "C:\Program Files\WindowsPowershell\pickles\sc.zip")
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", "C:\Program Files\WindowsPowershell\pickles\dll.zip")

# Windows Firewall Control
(New-Object System.Net.WebClient).DownloadFile("https://www.binisoft.org/download/wfc6setup.exe", "C:\Program Files\WindowsPowershell\cucumbers\wfwcsetup.exe")

# Wireshark
(New-Object System.Net.WebClient).DownloadFile("https://1.na.dl.wireshark.org/win64/Wireshark-win64-latest.exe", "C:\Program Files\WindowsPowershell\cucumbers\wsinstall.exe")

# Basic Sysmon config file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", "C:\Program Files\WindowsPowershell\pickles\sysmonconfig.xml")

# Get-InjectedThread
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", "C:\Program Files\WindowsPowershell\pickles\Get-InjectedThread.ps1")

# Unzipping stuff
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\ar.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\ar"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\tv.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\tv"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\sm.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\sm"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\pe.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\pe"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\pm.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\pm"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\sc.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\sc"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\dll.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\dll"

