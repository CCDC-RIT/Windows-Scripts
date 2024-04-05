[string]$path = ($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("scripts\backup.ps1"))
New-Item -Path $path -Name "backup" -ItemType "directory" | Out-Null
[string]$backupPath = (Join-Path $path "backup")

if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    New-Item -Path $backupPath -Name "sysvol" -ItemType "directory" | Out-Null
    robocopy c:\windows\sysvol (Join-Path $backupPath "sysvol") /copyall /mir /b /r:0 /xd

    New-Item -Path $backupPath -Name "dns_backup" -ItemType "directory" | Out-Null
    xcopy /E /I C:\Windows\System32\dns (Join-Path -Path $backupPath -childPath "dsn_backup")
}


# Wazuh agent backup 
$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

xcopy "C:\Program Files (x86)\ossec-agent\client.keys" $backupPath /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\ossec.conf" $backupPath /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\internal_options.conf" $backupPath /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" $backupPath /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\*.pem" $backupPath /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\ossec.log" $backupPath /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\logs\*"  $backupPath\logs\ /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\rids\*"  $backupPath\rids\ /H /I /K /S /X
#Chandi Fortnite