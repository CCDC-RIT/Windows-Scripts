[string]$path = ($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("scripts\backup.ps1"))

if (!(Test-Path -Path (Join-Path $path "backup"))) {
    New-Item -Path $path -Name "backup" -ItemType "directory" | Out-Null
}
[string]$backupParentPath = (Join-Path $path "backup")
$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
[string]$backupPath = (Join-Path $backupParentpath $dateTime)

if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    New-Item -Path $backupPath -Name "sysvol" -ItemType "directory" | Out-Null
    robocopy c:\windows\sysvol (Join-Path $backupPath "sysvol") /copyall /mir /b /r:0 /xd | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SYSVOL folder backed up" -ForegroundColor white

    dnscmd /exportsettings | Out-Null
    New-Item -Path $backupPath -Name "dns_backup" -ItemType "directory" | Out-Null
    xcopy /E /I C:\Windows\System32\dns (Join-Path -Path $backupPath -childPath "dns_backup") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DNS folder backed up" -ForegroundColor white
}

if (Get-Service -Name W3SVC 2>$null) {
    xcopy /E /I C:\inetpub (Join-Path -Path $backupPath -childPath "iis_backup") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] IIS folder backed up" -ForegroundColor white
}

if (Get-Service -Name CertSvc 2>$null) {
    Backup-CARoleService -Path (Join-Path -Path $backupPath -childPath "ca_backup")
    certutil -backup (Join-Path -Path $backupPath -childPath "ca_backup") | Out-Null
    certutil -catemplates > (Join-Path -Path $backupPath -childPath "ca_backup\CATemplates.txt") | Out-Null
    reg export HKLM\System\CurrentControlSet\Services\CertSvc\Configuration (Join-Path -Path $backupPath -childPath "ca_backup\regkey.reg") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] CA certs, templates, and settings backed up" -ForegroundColor white
}

# Wazuh agent backup 
xcopy "C:\Program Files (x86)\ossec-agent\client.keys" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\ossec.conf" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\internal_options.conf" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\*.pem" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\ossec.log" $backupPath /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\logs\*"  $backupPath\logs\ /H /I /K /S /X | Out-Null
xcopy "C:\Program Files (x86)\ossec-agent\rids\*"  $backupPath\rids\ /H /I /K /S /X | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh agent files backed up" -ForegroundColor white
#Chandi Fortnite