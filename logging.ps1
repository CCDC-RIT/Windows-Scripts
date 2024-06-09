# Parameter for Wazuh Manager IP Address
param(
    [Parameter(Mandatory=$true)]
    [string]$wazuhIP
)

# Variables for different paths
[string]$currentFullPath = $MyInvocation.MyCommand.Path
[string]$scriptDir = ($currentFullPath.substring(0, $currentFullPath.IndexOf("logging.ps1")))
[string]$rootDir = ($scriptDir.substring(0, $scriptDir.IndexOf("scripts")))

# Turn on Event log service if it's stopped
if (!((Get-Service -Name "EventLog").Status -eq "Running")) {
    Start-Service -Name EventLog
    Write-Host "[INFO] Windows Event Log service started"
}

# setting up logging
WevtUtil sl Application /ms:256000
WevtUtil sl System /ms:256000
WevtUtil sl Security /ms:2048000
WevtUtil sl "Windows PowerShell" /ms:512000
WevtUtil sl "Microsoft-Windows-PowerShell/Operational" /ms:512000
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
Write-Host "[INFO] Log sizes set"

# Setting percentage threshold for security event log
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v WarningLevel /t REG_DWORD /d 90 /f | Out-Null

# Enabling audit policy subcategories
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audit policy subcategories enabled" -ForegroundColor white 

# Powershell logging
$psLogFolder = Join-Path -Path (Get-Item -Path '..').FullName -ChildPath "powershellLogs"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d $psLogFolder /f | Out-Null
# Process Creation events (4688) include command line arguments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[INFO] PowerShell and command-line logging set"

# TODO: import audit policy
[string]$auditpolPath = (Join-Path -Path $scriptDir -ChildPath "\conf\auditpol.csv")
auditpol /restore /file:$auditpolPath
Write-Host "[INFO] System audit policy set"

# Sysmon setup
[string]$sysmonPath = (Join-Path -Path $rootDir -ChildPath "tools\sys\sm\sysmon64.exe")
[string]$xmlPath = (Join-Path -Path $scriptDir -ChildPath "\conf\sysmon.xml")
& $sysmonPath -accepteula -i $xmlPath
WevtUtil sl "Microsoft-Windows-Sysmon/Operational" /ms:1048576000
Write-Host "[INFO] Sysmon installed and configured"

# DNS server logging
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    Set-DnsServerDiagnostics -DebugLogging 0x8000F301 -EventLogLevel 2 -EnableLoggingToFile $true
    dnscmd /config /logfilemaxsize 0xC800000
    Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true -EnableLoggingForServerStartStopEvent $true -EnableLoggingForLocalLookupEvent $true -EnableLoggingForRecursiveLookupEvent $true -EnableLoggingForRemoteServerEvent $true -EnableLoggingForZoneDataWriteEvent $true -EnableLoggingForZoneLoadingEvent $true | Out-Null
    net stop DNS
    net start DNS
    Write-Host "[INFO] DNS Server logging configured"
}

wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
Write-Host "[INFO] DNS Client logging enabled"

# IIS logging
if (Get-Service -Name W3SVC 2>$null) {
    try {
        C:\Windows\System32\inetsrv\appcmd.exe set config /section:httpLogging /dontLog:False
        Write-Host "[INFO] IIS Logging enabled"
    }
    catch {
        Write-Host "[ERROR] IIS Logging failed"
    }
}

if (Get-Service -Name CertSvc 2>$null) {
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD
    # Enabling ADCS auditing
    $domain = (Get-ADDomain).DistinguishedName
    $searchBase = "CN=Configuration,$domain"
    $caName = ((Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -SearchBase $searchBase).Name | Out-String).Trim()
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName" /v AuditFilter /t REG_DWORD /d 127 /f | Out-Null
    Write-Host "[INFO] CA logging enabled"
}

$file = Join-Path -Path $scriptDir -ChildPath "conf\agent_windows.conf"
$content = Get-Content $file
# This line is a work in progress
# $content | ForEach-Object { $_ -replace "<address></address>", "<address>$($wazuhIP)</address>"; $_ -replace "<config-profile>windows, windows2019, windows-server, windows-server-2019</config-profile>", "<config-profile></config-profile>" } | Set-Content $file
$content | ForEach-Object { $_ -replace "<address></address>", "<address>$($wazuhIP)</address>" } | Set-Content $file

# setup wazuh agent, config file, backup
Start-Process -FilePath (Join-Path -Path $rootDir -ChildPath "installers\wazuhagent.msi") -ArgumentList ("/q WAZUH_MANAGER='" + $wazuhIP + "'") -Wait
Remove-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Copy-Item -Path (Join-Path -Path $scriptDir -ChildPath "conf\agent_windows.conf") -Destination "C:\Program Files (x86)\ossec-agent\ossec.conf"

# yara setup
mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'
mkdir 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\'
Copy-Item -Path (Join-Path -Path $rootDir -ChildPath "tools\yara64.exe") -Destination 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'
$rules = Get-ChildItem (Join-Path -Path $rootDir -ChildPath "protections-artifacts-main\yara\rules") -File | Where-Object {$_.Name -like "Windows*" -or $_.Name -like "Multi*"} | ForEach-Object {$_.FullName} | Out-String
$rules = $($rules.Replace("`r`n", " ") -split " ")
& (Join-Path -Path $rootDir -ChildPath "tools\yarac64.exe") $rules 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\compiled.windows'
Copy-Item -Path (Join-Path -Path $rootDir -ChildPath "scripts\yara.bat") -Destination 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\'
net start Wazuh
Write-Host "[INFO] Wazuh installed and configured"
#Chandi Fortnite