(New-Object System.Net.WebClient).DownloadFile(“https://download.sysinternals.com/files/SysinternalsSuite.zip”, “C:\sysinternals.zip”)
Expand-Archive -LiteralPath C:\sysinternals.zip -DestinationPath C:\sysinternals

(New-Object System.Net.WebClient).DownloadFile(“https://explorerplusplus.com/software/explorer++_1.3.5_x64.zip”, “C:\explorerplusplus.zip”)
Expand-Archive -LiteralPath C:\explorerplusplus.zip -DestinationPath C:\explorerplusplus

(New-Object System.Net.WebClient).DownloadFile(“https://2.na.dl.wireshark.org/win64/Wireshark-win64-3.6.2.exe”, “C:\wireshark.exe”)
Expand-Archive -LiteralPath C:\wireshark.zip -DestinationPath C:\wireshark
