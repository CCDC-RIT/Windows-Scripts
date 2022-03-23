# Download other scripts
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", "C:\Program Files\WindowsPowershell\cucumbers\Get-InjectedThread.ps1")

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
# Explorer++
(New-Object System.Net.WebClient).DownloadFile(“https://explorerplusplus.com/software/explorer++_1.3.5_x64.zip”, “C:\Program Files\WindowsPowershell\cucumbers\epp.zip”)
Expand-Archive -LiteralPath explorerplusplus.zip -DestinationPath explorerplusplus

# Basic Sysmon config file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", "C:\Program Files\WindowsPowershell\pickles\sysmonconfig.xml")

# Unzipping stuff
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\ar.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\ar"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\tv.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\tv"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\sm.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\sm"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\pe.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\pe"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\pm.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\pm"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\sc.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\sc"
Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\pickles\dll.zip" -DestinationPath "C:\Program Files\WindowsPowershell\pickles\dll"

Expand-Archive -LiteralPath "C:\Program Files\WindowsPowershell\cucumbers\epp.zip" -DestinationPath "C:\Program Files\WindowsPowershell\cucumbers\epp"