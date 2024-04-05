# Parameter for Wazuh Manager IP Address
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $wazuhIP
)

# Variable for the file's current path
[string]$currentPath = $MyInvocation.MyCommand.Path

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
[string]$auditpolPath = (Join-Path ($currentPath.substring(0, $currentPath.IndexOf("logging.ps1"))) "\conf\auditpol.csv")
auditpol /restore /file:$auditpolPath
Write-Host "[INFO] System audit policy set"

# Sysmon setup
[string]$sysmonPath = (Join-Path ($currentPath.substring(0,$currentPath.IndexOf("scripts\logging.ps1"))) "tools\sys\sm\sysmon64.exe")
[string]$xmlPath = (Join-Path ($currentPath.substring(0,$currentPath.IndexOf("logging.ps1"))) "\conf\sysmon.xml")
& $sysmonPath -accepteula -i $xmlPath
WevtUtil sl "Microsoft-Windows-Sysmon/Operational" /ms:1048576000
Write-Host "[INFO] Sysmon installed and configured"

# DNS server logging
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    dnscmd /config /loglevel 0x8000F301
    dnscmd /config /logfilemaxsize 0xC800000
    # Enabling logging for 
    Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true | Out-Null

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

# TODO: CA auditing 
if (Get-Service -Name CertSvc 2>$null) {
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD
    Write-Host "[ERROR] CA logging enabled"
}

# Turns on Event log service if it's stopped
Start-Service -Name EventLog
Write-Host "[INFO] Windows Event Log Service Started"

$file = Join-Path -Path ($currentPath.substring(0,$currentPath.indexOf("logging.ps1"))) -ChildPath "conf\agent_windows.conf"
$content = Get-Content $file
$content | ForEach-Object { $_ -replace "<address></address>", "<address>$($wazuhIP)</address>" } | Set-Content $file

# setup wazuh agent, config file, backup
Start-Process -FilePath (Join-Path ($currentPath.Substring(0,$currentPath.IndexOf("scripts\logging.ps1"))) "installers\wazuhagent.msi") -ArgumentList ("/q WAZUH_MANAGER='" + $wazuhIP + "'") -Wait
Remove-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Copy-Item -Path (Join-Path ($currentPath.substring(0,$currentPath.indexOf("logging.ps1"))) "conf\agent_windows.conf") -Destination "C:\Program Files (x86)\ossec-agent\ossec.conf"
net start Wazuh
Write-Host "[INFO] Wazuh installed and configured"
#Chandi Fortnite