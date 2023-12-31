# Lorge secure script
$Error.Clear()
$ErrorActionPreference = "Continue"

# DC detection
$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
}

# IIS detection
$IIS = $false
if (Get-Service -Name W3SVC 2>$null) {
    $IIS = $true
}

# CA detection
$CA = $false
if (Get-Service -Name CertSvc 2>$null) {
    $CA = $true
}

# Securing RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
## Requiring encrypted RPC connections
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f | Out-Null
## Disabling remote assistance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f | Out-Null
## Prevent sharing of local drives via Remote Desktop Session Hosts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f | Out-Null
## Enabling support for Restricted Admin/Remote Credential Guard
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f | Out-Null
## Enabling Restricted Admin mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f | Out-Null
## Disabling Restricted Admin Outbound Creds
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f | Out-Null
# Enabling Credential Delegation (Restrict Credential Delegation)
reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v RestrictedRemoteAdministration /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v RestrictedRemoteAdministrationType /t REG_DWORD /d 3 /f | Out-Null

Write-Host "[INFO] RDP hardening in place"

# Disabling RDP (only if not needed)
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
# Write-Host "[INFO] RDP disabled"

# Securing WinRM
## Disallowing unencrypted traffic
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f | Out-Null

# Disabling WinRM
# Disable-PSRemoting -Force
# Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
# Stop-Service WinRM -PassThru
# Set-Service WinRM -StartupType Disabled -PassThru
# Write-Host "[INFO] WinRM disabled and listeners removed"

# Uninstalling SSH
Remove-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
Remove-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"
Write-Host "[INFO] SSH Client and Server removed"

# RPC settings
## Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f | Out-Null
## Disabling RPC usage from a remote asset interacting with services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f | Out-Null
## Restricting unauthenticated RPC clients
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f | Out-Null

# Enforcing LDAP client signing (always)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null

Function Write-Results {
Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Path,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$Domain
    )

    $Acl = Get-Acl -Path $Path 
    Write-Host $Domain -ForegroundColor DarkRed -BackgroundColor White
    Write-Host ($Path.Substring($Path.IndexOf(":") + 1)) -ForegroundColor DarkRed -BackgroundColor White
    Write-Output -InputObject $Acl.Access
}

Function Set-Auditing {
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Domain,

        [Parameter(Position=1,Mandatory=$true)]
        [AllowEmptyString()]
        [String]$ObjectCN,

        [Parameter(Position=2,Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectoryAuditRule[]]$Rules 
    )
    
    $DN = (Get-ADDomain -Identity $Domain).DistinguishedName
    [String[]]$Drives = Get-PSDrive | Select-Object -ExpandProperty Name

    $TempDrive = "tempdrive"

    if ($Drives.Contains($TempDrive)) {
        Write-Host "An existing PSDrive exists with name $TempDrive, temporarily removing" -ForegroundColor Yellow
        $OldDrive = Get-PSDrive -Name $TempDrive
        Remove-PSDrive -Name $TempDrive
    }

    $Drive = New-PSDrive -Name $TempDrive -Root "" -PSProvider ActiveDirectory -Server $Domain
    Push-Location -Path "$Drive`:\"
    
    if ($ObjectCN -eq "") {
        $ObjectDN = $DN
    } else {
        $ObjectDN = $ObjectCN + "," + $DN
    }
    
    $ObjectToChange = Get-ADObject -Identity $ObjectDN -Server $Domain
    $Path = $ObjectToChange.DistinguishedName

    try {
        $Acl = Get-Acl -Path $Path -Audit

        if ($Acl -ne $null) {
            foreach ($Rule in $Rules) {
                $Acl.AddAuditRule($Rule)
            }
            Set-Acl -Path $Path -AclObject $Acl
            # Write-Results -Path $Path -Domain $Domain
        } else {
            Write-Warning "Could not retrieve the ACL for $Path"
        }
    } catch [System.Exception] {
        Write-Warning $_.ToString()
    }
    Pop-Location
    
    Remove-PSDrive $Drive

    if ($OldDrive -ne $null) {
        Write-Host "Recreating original PSDrive" -ForegroundColor Yellow
        New-PSDrive -Name $OldDrive.Name -PSProvider $OldDrive.Provider -Root $OldDrive.Root | Out-Null
        $OldDrive = $null
    }
}
Function New-EveryoneAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, 
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        
    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-DomainControllersAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneWriteDaclSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneWritePropertySuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneWriteDaclSuccess, $EveryoneWritePropertySuccess)

    Write-Output -InputObject $Rules
}
Function New-InfrastructureObjectAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    #$objectguid = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd" #Guid for change infrastructure master extended right if it was needed
    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-PolicyContainerAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    
    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-DomainAuditRuleSet {
    Param (
        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
        [System.Security.Principal.SecurityIdentifier]$DomainSID    
    )

    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    $DomainUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)
    $Administrators = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $DomainUsersSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($DomainUsers, 
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $AdministratorsSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Administrators, 
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner), 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $DomainUsersSuccess, $AdministratorsSuccess, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
    
Function New-RIDManagerAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}

# Reset local group policy
Copy-Item C:\Windows\System32\GroupPolicy* C:\gp -Recurse | Out-Null
Remove-Item C:\Windows\System32\GroupPolicy* -Recurse -Force | Out-Null
gpupdate /force
Write-Output "[INFO] Local Group Policy reset" 

# Reset domain GPOs
if ($DC) { 
    $DomainGPO = Get-GPO -All
    foreach ($GPO in $DomainGPO) {
        # Prompt user to decide which GPOs to disable
        $Ans = Read-Host "Reset $($GPO.DisplayName) (y/N)?"
        if ($Ans.ToLower() -eq "y") {
            $GPO.gpostatus = "AllSettingsDisabled"
        }
    }

    # apply dc security template
    secedit /configure /db $env:windir\security\local.sdb /cfg 'conf\dc-secpol.inf'

    # import DC GPO
    Import-GPO -BackupId "F4A70563-32A9-4B5F-83B2-9DBE866D54FC" -TargetName "secure-gpo" -path "conf\{F4A70563-32A9-4B5F-83B2-9DBE866D54FC}" -CreateIfNeeded

    gpupdate /force
} else {
    # apply client/member server security template
    secedit /configure /db $env:windir\security\local.sdb /cfg 'conf\web-secpol.inf'
    
    # import local GPO
    ..\tools\LGPO_30\LGPO.exe /g "conf\{8DBC52E2-C1DF-4D2D-9A84-0F3760FE3147}" 
    
    gpupdate /force
}

# T1557 - Countering poisoning via WPAD - Disabling WPAD
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHTTPAutoProxySvc" /v Start /t REG_DWORD /d 4 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DisableWpad /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WPAD disabled" -ForegroundColor white 

# T1557.001 - Countering poisoning via LLMNR/NBT-NS/MDNS
## Disabling LLMNR
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /f | Out-Null
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LLMNR disabled" -ForegroundColor white 
## Disabling smart multi-homed name resolution
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SMHNR disabled" -ForegroundColor white 
## Disabling NBT-NS via registry for all interfaces (might break something)
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\"
Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose }
## Disabling NetBIOS broadcast-based name resolution
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v NodeType /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] NBT-NS disabled" -ForegroundColor white 
## Disabling mDNS
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableMDNS /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] mDNS disabled" -ForegroundColor white 

# Printer NIGHTMARE NIGHTMARE NIGHTMARE
## I hate print spooler
net stop spooler | Out-Null
sc.exe config spooler start=disabled | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Print Spooler service shut down and disabled" -ForegroundColor white 
## Mitigating CVE-2021-1675 and CVE 2021-34527 (PrintNightmare)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v CopyFilesPolicy /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f | Out-Null
## Mitigating CVE-2021-1678
reg add "HKLM\System\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] PrintNightmare mitigations in place" -ForegroundColor white 
## Disabling downloading of print drivers over HTTP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f | Out-Null
## Disabling printing over HTTP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f | Out-Null

# CVE-2021-36934 (HiveNightmare/SeriousSAM) - workaround (patch at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
icacls $env:windir\system32\config\*.* /inheritance:e
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] HiveNightmare mitigations in place" -ForegroundColor white 

# Changing file associations to make sure they have to be executed manually
cmd /c 'ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'
cmd /c 'ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'
cmd /c 'ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'
cmd /c 'ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'
cmd /c 'ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'
cmd /c 'ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'
cmd /c 'ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'
cmd /c 'ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"'

# Strengthening default permissions of internal system objects
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f | Out-Null

## Starting Windows Defender service
Start-Service WinDefend

## Enabling Windows Defender sandboxing
cmd /c "setx /M MP_FORCE_USE_SANDBOX 1"

## Removing and updating Windows Defender signatures
& 'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All
Update-MpSignature
Write-Host "[INFO] Defender signatures updated"

## Enabling PUA Protection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d 1 /f | Out-Null

## Enabling cloud functionality of Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 1 /f | Out-Null

## Enabling early launch antimalware boot-start driver scan (good, unknown, and bad but critical)
reg add "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v "DriverLoadPolicy" /t REG_DWORD /d 3 /f | Out-Null

## Setting exploit guard settings via config file
try {
    Set-ProcessMitigation -PolicyFilePath conf\def-eg-settings.xml
    Write-Output "[INFO] Exploit Guard settings set"
} catch {
    Write-Host "[INFO] Old defender version detected, skipping Exploit Guard settings" 
}

## ASR rules
try {
    # Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Win32 API calls from Office macro
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Use advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    Write-Output "[INFO] Defender Attack Surface Reduction rules enabled" 
    # Removing ASR exceptions
    ForEach ($ex_asr in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ex_asr | Out-Null
    }
    Write-Host "[INFO] ASR exceptions removed" 
} catch {
    Write-Host "[INFO] Old defender version detected, skipping ASR rules" 
}

# Removing other exclusions in Defender
ForEach ($ex_extension in (Get-MpPreference).ExclusionExtension) {
    Remove-MpPreference -ExclusionExtension $ex_extension | Out-Null
}
ForEach ($ex_dir in (Get-MpPreference).ExclusionPath) {
    Remove-MpPreference -ExclusionPath $ex_dir | Out-Null
}
ForEach ($ex_proc in (Get-MpPreference).ExclusionProcess) {
    Remove-MpPreference -ExclusionProcess $ex_proc | Out-Null
}
ForEach ($ex_ip in (Get-MpPreference).ExclusionIpAddress) {
    Remove-MpPreference -ExclusionIpAddress $ex_ip | Out-Null
}
Write-Host "[INFO] Defender exclusions removed"



# doesn't work, access denied
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f | Out-Null
Write-Host "[INFO] Windows Defender fully configured"

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "HideExclusionsFromLocalAdmins" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null

## Enabling Defender Exploit Guard network protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection /t REG_DWORD /d 1 /f | Out-Null

Write-Host "[INFO] Windows Defender options set" 

ipconfig /flushdns
Write-Host "[SUCCESS] DNS Cache flushed"

# User Account Control (UAC)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[INFO] UAC set up"

# LSASS Protections
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f | Out-Null
## Allowing Local System to use computer identity for NTLM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f | Out-Null
## Preventing null session fallback
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f | Out-Null
## Setting amount of time to clear logged-off users' credentials from memory (secs)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f | Out-Null
## Restricting remote calls to SAM to just Administrators
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f | Out-Null
## Enabling Credential Guard depends on if the VM can support it
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[INFO] LSASS protections in place"

# MSS (Legacy) Settings
## Disabling autologon
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f | Out-Null
## Enabling AutoReboot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 1 /f | Out-Null
## Disabling SMB admin shares (Server)
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f | Out-Null
## Disabling SMB admin shares (Workstation)
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f | Out-Null
## Disabling source routing for IPv4 and IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f | Out-Null
## Disable password saving for dial-up (lol)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v DisableSavePassword /t REG_DWORD /d 1 /f | Out-Null
## Disable automatic detection of dead network gateways
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 0 /f | Out-Null
## Enable ICMP redirect using OSPF
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f | Out-Null
## Hide computer from browse list
reg add "HKLM\System\CurrentControlSet\Services\Lanmanserver\Parameters" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
## Setting how often keep-alive packets are sent (ms)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v KeepAliveTime /t REG_DWORD /d 300000 /f | Out-Null
## Configuring IPSec exemptions 
reg add "HKLM\System\CurrentControlSet\Services\IPSEC" /v NoDefaultExempt /t REG_DWORD /d 3 /f | Out-Null
## Enabling ability to ignore NetBIOS name release requests except from WINS servers
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f | Out-Null
## Disabling 8.3 filename creation
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f | Out-Null
## Disabling IRDP
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /t REG_DWORD /d 0 /f | Out-Null
## Enabling Safe DLL search mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f | Out-Null 
## Setting screen saver grace period
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 0 /f | Out-Null
## Setting SYN attack protection level
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 1 /f | Out-Null
## Setting SYN-ACK retransmissions when a connection request is not acknowledged
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxConnectResponseRetransmissions /t REG_DWORD /d 2 /f | Out-Null
## Setting how many times unacknowledged data is retransmitted for IPv4 and IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f | Out-Null
## Setting percentage threshold for security event log
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v WarningLevel /t REG_DWORD /d 90 /f | Out-Null

# MS Security Guide + PtH mitigations
## Applying UAC restrictions to local accounts on network logons
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
## Block activiation in Office documents (skipped)
## Disabling client-side processing of SMBv1 protocol (pre-Win8.1/2012R2)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v DependOnService /t REG_MULTI_SZ /d "Bowser\0MRxSMB20\0NSI" /f | Out-Null
## Disabling SMB1 client driver
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MrxSmb10" /v Start /t REG_DWORD /d 4 /f | Out-Null
## Enabling SEHOP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f | Out-Null
## Enabling LSA protection mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
## Enabling LSASS audit mode
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
## Removing "Run As Different User" from context menus
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartBanner /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\batfile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\exefile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\mscfile\shell\runasuser" /v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
## Enabling Windows Defender PUP protection (DEPRECATED, but why not leave it in just in case?)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d 1 /f | Out-Null
## Disabling WDigest, removing storing plain text passwords in LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null




# Disable ipv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f | Out-null

# Disabling IGMP
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f | Out-Null

# Misc settings
# set font reg keys
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black (TrueType)" /t REG_SZ /d "seguibl.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black Italic (TrueType)" /t REG_SZ /d "seguibli.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold (TrueType)" /t REG_SZ /d "segoeuib.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold Italic (TrueType)" /t REG_SZ /d "segoeuiz.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Emoji (TrueType)" /t REG_SZ /d "seguiemj.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Historic (TrueType)" /t REG_SZ /d "seguihis.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Italic (TrueType)" /t REG_SZ /d "segoeuii.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light (TrueType)" /t REG_SZ /d "segoeuil.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light Italic (TrueType)" /t REG_SZ /d "seguili.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold (TrueType)" /t REG_SZ /d "seguisb.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold Italic (TrueType)" /t REG_SZ /d "seguisbi.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight (TrueType)" /t REG_SZ /d "seguisli.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight Italic (TrueType)" /t REG_SZ /d "seguisl.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Symbol (TrueType)" /t REG_SZ /d "seguisym.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Variable (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe MDL2 Assets (TrueType)" /t REG_SZ /d "segmdl2.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print (TrueType)" /t REG_SZ /d "segoepr.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print Bold (TrueType)" /t REG_SZ /d "segoeprb.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script (TrueType)" /t REG_SZ /d "segoesc.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script Bold (TrueType)" /t REG_SZ /d "segoescb.ttf" /f | Out-Null
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /v "Segoe UI" /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Auto Activation Mode" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "InstallAsLink" /t REG_DWORD /d 0 /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Inactive Fonts" /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Active Languages" /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management\Auto Activation Languages" /f | Out-Null
# set keyboard language to english
Remove-ItemProperty -Path 'HKCU:\Keyboard Layout\Preload' -Name * -Force | Out-Null
reg add "HKCU\Keyboard Layout\Preload" /v 1 /t REG_SZ /d "00000409" /f | Out-Null
# set default theme
Start-Process -Filepath "C:\Windows\Resources\Themes\aero.theme"
# set UI lang to english
reg add "HKCU\Control Panel\Desktop" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\MUI\Settings" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
Write-Host "[INFO] Font, Themes, and Languages set to default" 

# funny file explorer keys
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "CheckedValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "CheckedValue" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | Out-Null

# resetting sdmanager sddl
sc.exe sdset scmanager "D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)" | Out-Null
Write-Host "[INFO] scmanager SDDL reset"

# Disable loading of test signed kernel-drivers
bcdedit.exe /set TESTSIGNING OFF
bcdedit.exe /set loadoptions ENABLE_INTEGRITY_CHECKS 
# Enabling driver signature enforcement
bcdedit.exe /set nointegritychecks off
# Enable DEP for all processes
bcdedit.exe /set "{current}" nx AlwaysOn 

# Enabling DEP and heap termination on corruption for File Explorer
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f | Out-Null

# Enabling shell protocol protected mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f | Out-Null

# More misc settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f | Out-Null
# no alwaysinstallelevated
reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f | Out-Null
reg add "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[INFO] Windows Installer set to not always install w/elevated privileges"

# Stopping psexec with the power of svchost
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PSEXESVC.exe" /v Debugger /t REG_SZ /d "svchost.exe" /f | Out-Null

# File explorer options
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null

# Disable offline files
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v Start /t REG_DWORD /d 4 /f | Out-Null

# Disabling autorun
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f | Out-Null

# Require a password on wakeup
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1 | Out-Null

# Ease of Access
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f | Out-Null
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f | Out-Null
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /t REG_DWORD /d 8 /f | Out-Null

TAKEOWN /F C:\Windows\System32\sethc.exe /A | Out-Null
ICACLS C:\Windows\System32\sethc.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\sethc.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Utilman.exe /A | Out-Null
ICACLS C:\Windows\System32\Utilman.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Utilman.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\osk.exe /A | Out-Null
ICACLS C:\Windows\System32\osk.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\osk.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Narrator.exe /A | Out-Null
ICACLS C:\Windows\System32\Narrator.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Narrator.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Magnify.exe /A | Out-Null
ICACLS C:\Windows\System32\Magnify.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Magnify.exe -Force | Out-Null

# AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f | Out-Null
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f

# Caching logons
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f | Out-Null
# Clear cached credentials [TEST]
cmdkey /list | ForEach-Object{if($_ -like "*Target:*" -and $_ -like "*microsoft*"){cmdkey /del:($_ -replace " ","" -replace "Target:","")}}

# Remote Registry Path Denial
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /f | Out-Null

# Not processing RunOnce List (located at HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, in HKCU, and Wow6432Node)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null



Write-Host "[INFO] Misc settings set"

# ----------- Service security ------------
# SMB protections
## Yeeting SMB1 as a feature (modern Windows)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -norestart
## Disabling SMB1 server-side processing (Win 7 and below)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
## Enabling SMB2/3 (modern Windows)
Set-SmbServerConfiguration -EnableSMB2Protocol $true
## Enabling SMB2/3 (Win 7 and below)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 1 /f | Out-Null
## Strengthen SMB
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f | Out-Null
## Restricting access to null session pipes and shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /f | Out-Null
## Enable SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
## Disable SMB compression (CVE-2020-0796 - SMBGhost)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f | Out-Null
Set-SmbServerConfiguration -EncryptData $true -Force | Out-Null

# Microsoft-Windows-SMBServer\Audit event 3000 shows attempted connections [TEST]
Set-SmbServerConfiguration -AuditSmb1Access $true | Out-Null

Write-Host "[INFO] SMB hardening in place"

# Limiting BITS transfer
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxTransferRateOffSchedule /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[INFO] BITS transfers limited" 

# Prevent insecure encryption suites for Kerberos (need to test)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG /d 2147483640 | Out-Null

# Enforcing encryption of outgoing secure channel traffic
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f | Out-Null
# Encrypt and sign outgoing secure channel traffic
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f | Out-Null

# DC security - put DNS under here?
if ($DC) {
    # CVE-2020-1472 - ZeroLogon
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v vulnerablechannelallowlist /f | Out-Null
    # Enable netlogon debug logging - %windir%\debug\netlogon.log - watch for event IDs 5827 & 5828
    nltest /DBFlag:2080FFFF

    # CVE-2021-42287/CVE-2021-42278 (SamAccountName / nopac)
    Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null

    # MS Security Guide
    ## Enabling extended protection for LDAP authentication (always)
    reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f | Out-Null 

    # Only allowing DSRM Administrator account to be used when ADDS is stopped 
    reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 1 /f | Out-Null

    # Disable unauthenticated LDAP 
    $RootDSE = Get-ADRootDSE
    $ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
    Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1'}

    # setting max connection time 
    [string]$DomainDN = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser -Server $env:COMPUTERNAME).RootDomain -Server $env:COMPUTERNAME | Select-Object -ExpandProperty DistinguishedName
    [System.Int32]$MaxConnIdleTime = 180
    [string]$SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + $DomainDN
	[Microsoft.ActiveDirectory.Management.ADEntity]$Policies = get-adobject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties *
	$AdminLimits = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$Policies.lDAPAdminLimits

    for ($i = 0; $i -lt $AdminLimits.Count; $i++) {
		if ($AdminLimits[$i] -match "MaxConnIdleTime=*") {
			break
		}
	}   
    if ($i -lt $AdminLimits.Count) {
		$AdminLimits[$i] = "MaxConnIdleTime=$MaxConnIdleTime" 
	} else {
		$AdminLimits.Add("MaxConnIdleTime=$MaxConnIdleTime")
	}
    Set-ADObject -Identity $Policies -Clear lDAPAdminLimits
    foreach ($Limit in $AdminLimits) {
		Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit}
	}
    Write-Output -InputObject (Get-ADObject -Identity $Policies -Properties * | Select-Object -ExpandProperty lDAPAdminLimits | Where-Object {$_ -match "MaxConnIdleTime=*"})

    # Setting dsHeuristics (disable anon LDAP)
    $DN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain -Identity (Get-ADForest -Current LocalComputer).RootDomain).DistinguishedName)
    $DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
    [string]$Heuristic = $DirectoryService.dsHeuristics

    [array]$Array = @()
    if (($Heuristic -ne $null) -and ($Heuristic -ne [System.String]::Empty) -and ($Heuristic.Length -ge 7)) {
        $Array = $Heuristic.ToCharArray()
        $Array[6] = "0";
    } else {
        $Array = "0000000"
    }

    [string]$Heuristic = "$Array".Replace(" ", [System.String]::Empty)
    if ($Heuristic -ne $null -and $Heuristic -ne [System.String]::Empty) {
        Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic}
    }
    $Result = Get-ADObject -Identity $DirectoryService -Properties dsHeuristics | Select-Object -ExpandProperty dsHeuristics
    if ($Result -ne $null) {
        Write-Output ("dsHeuristics: " + $Result)
    } else {
        Write-Warning "dsHeuristics is not set"
    }

    # Resetting NTDS folder and file permissions
    $BuiltinAdministrators = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $CreatorOwner = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)
    $LocalService = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalServiceSid, $null)

    $AdministratorAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow       
    )

    $SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $CreatorOwnerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $LocalServiceAce = New-Object System.Security.AccessControl.FileSystemAccessRule($LocalService,
        @([System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateDirectories),
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $NTDS = Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    $DSA = $NTDS.'DSA Database File'
    $Logs = $NTDS.'Database log files path'
    $DSA = $DSA.Substring(0, $DSA.LastIndexOf("\"))
    
    $ACL1 = Get-Acl -Path $DSA
    foreach ($Rule in $ACL1.Access) {
        $ACL1.RemoveAccessRule($Rule) | Out-Null
    }
    $ACL1.AddAccessRule($AdministratorAce)
    $ACL1.AddAccessRule($SystemAce)

    Write-Host "[INFO] Setting $DSA ACL"

    # need to change perms on folder to set file perms correctly
    Set-Acl -Path $DSA -AclObject $ACL1
    Get-ChildItem -Path $DSA | ForEach-Object {
        $Acl = Get-Acl -Path $_.FullName
        foreach ($Rule in $Acl.Access) {
            if (-not $Rule.IsInherited) {
                $Acl.RemoveAccessRule($Rule) | Out-Null
            }
        }
        Set-Acl -Path $_.FullName -AclObject $Acl
    }

    # $Logs = path to the NTDS folder, so this fixes perms on that
    $ACL2 = Get-Acl -Path $Logs
    foreach ($Rule in $ACL2.Access) {
        $ACL2.RemoveAccessRule($Rule) | Out-Null
    }
    $ACL2.AddAccessRule($AdministratorAce)
    $ACL2.AddAccessRule($SystemAce)
    $ACL2.AddAccessRule($LocalServiceAce)
    $ACL2.AddAccessRule($CreatorOwnerAce)

    Write-Host "[INFO] Setting $Logs ACL"

    Set-Acl -Path $Logs -AclObject $ACL2
    Get-ChildItem -Path $Logs | ForEach-Object {
        $Acl = Get-Acl -Path $_.FullName
        foreach ($Rule in $Acl.Access) {
            if (-not $Rule.IsInherited) {
                $Acl.RemoveAccessRule($Rule) | Out-Null
            }
        }
        Set-Acl -Path $_.FullName -AclObject $Acl
    }

    # surely this will not break things
    $Domain = (Get-ADDomain -Current LocalComputer).DNSRoot

    # Set RID Manager Auditing
    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-RIDManagerAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=RID Manager$,CN=System"
    Write-Host "[INFO] RID Manager Auditing Set"

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-PolicyContainerAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Policies,CN=System"
    Write-Host "[INFO] GPO Auditing set"

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainAuditRuleSet -DomainSID (Get-ADDomain -Identity $Domain | Select-Object -ExpandProperty DomainSID)
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN ""
    Write-Host "[INFO] Domain Object Auditing Set"

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-InfrastructureObjectAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Infrastructure"
    Write-Host "[INFO] Infrastructure Object Auditing Set"

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainControllersAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "OU=Domain Controllers"
    Write-Host "[INFO] Domain Controller OU Object Auditing Set"

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-EveryoneAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=AdminSDHolder,CN=System"
    Write-Host "[INFO] AdminSDHolder Object Auditing Set"

    # T1003.001 - delete vss shadow copies
    vssadmin.exe delete shadows /all /quiet

    ## TODO: Split DNS secure settings into own category
    # DNS - SIGRed Workaround
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize /t REG_DWORD /d 0xFF00 /f | Out-Null
    # CVE-2020-25705
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v MaximumUdpPacketSize /t REG_DWORD /d 0x4C5 /f | Out-Null
    dnscmd /config /enableglobalqueryblocklist 1
    Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true
    Set-DnsServerRRL -Mode Enable -Force | Out-Null
    Set-DnsServerResponseRateLimiting -ResetToDefault -Force | Out-Null
    net stop DNS
    net start DNS
    Write-Host "[INFO] AD/DNS hardening in place"
}

# IIS security
if ($IIS) {
    # # Set application privileges to minimum
    # Foreach($item in (Get-ChildItem IIS:\AppPools)) { $tempPath="IIS:\AppPools\"; $tempPath+=$item.name; Set-ItemProperty -Path $tempPath -name processModel.identityType -value 4}

    # # Disable directory browsing
    # ForEach ($site in (Get-ChildItem IIS:\Sites)) {
    #     C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/directoryBrowse /enabled:"False"
    # } 

    # Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Allow -PSPath IIS:/
    # # Disable Anonymous Authenitcation
    # Foreach($item in (Get-ChildItem IIS:\Sites)) { $tempPath="IIS:\Sites\"; $tempPath+=$item.name; Set-WebConfiguration -filter /system.webServer/security/authentication/anonymousAuthentication $tempPath -value 0}
    # #Deny Powershell to Write the anonymousAuthentication value
    # Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Deny-PSPath IIS:/

    # # reg add "HKLM\Software\Microsoft\WebManagement\Server" /v EnableRemoteManagement /t REG_DWORD /d 1 /f | Out-Null
    # # net start WMSVC | Out-Null
    # # sc.exe config WMSVC start= auto | Out-Null
    # Write-Host "[INFO] Most of IIS security set"
}

# CA security?
if ($CA) {

}

# UPnP
reg add "HKLM\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" /v UPnPMode /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[INFO] UPnP disabled"

# Restrict Internet Communication of several Windows features [TEST]
# reg add "HKLM\SOFTWARE\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d 1 /f | Out-Null

# Yeet Powershell v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart

# make backup admin account
net user cucumber "Passw0rd-123*" /add
net localgroup Administrators cucumber /add

# ----------- Constrained Language Mode ------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t REG_SZ /d 4 /f | Out-Null
# Report errors (TODO: change file path)
$Error | Out-File $env:USERPROFILE\Desktop\hard.txt -Append -Encoding utf8

# Windows Update
## Prevent Delivery Optimization from downloading Updates from other computers across the internet
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 1 /f | Out-Null

# :: Import secpol file here
# :: One secpol file for "domain policy" - not editing default domain policy but creating gpo to apply across domain 
#     :: This file will also serve as local secpol file
#     :: Will contain account and local policies
# set /p choice="Is this a domain controller (Y or N)? "
# if %choice%=="N" (
#     secedit /configure /db %windir%\security\local.sdb /cfg conf/secpol.inf
#     gpupdate /force
# ) else (
#     echo:
#     echo Skipping import of secpol file...
#     echo: 
#     echo Please use the Group Policy Management GUI to create a GPO and import the file into it. Make sure to do gpupdate /force after!
#     timeout 5
# )

######### Reset Policies #########
# Copy-Item C:\Windows\System32\GroupPolicy* C:\gp -Recurse | Out-Null
# Remove-Item C:\Windows\System32\GroupPolicy* -Recurse -Force | Out-Null
# gpupdate /force
# Write-Output "$Env:ComputerName [INFO] Group Policy reset" 

# # Create report
# Get-GPOReport -All -ReportType Html -Path "C:\All-GPOs.html"

# reset domain gpos
# # Prompt user to decide which GPOs to disalbe
# $DomainGPO = Get-GPO -All
# foreach ($GPO in $DomainGPO) {
#     $Ans = Read-Host "Reset $($GPO.DisplayName) (y/N)?"
#     if ($Ans.ToLower() -eq "y") {
#         $GPO.gpostatus = "AllSettingsDisabled"
#     }
# }
# gpupdate.exe /force

# :: Stopping "easy wins" for red team - following https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg

# :: MS08-068 (placeholder as it's for older systems)

# :: CVE-2019-1040 - covered by LSASS protections (LmCompatibilityLevels)

# :: Enable SMB signing
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

# :: Roasting of all varieties
# :: ASREPRoast - Look for accounts with "Do not require kerberos authentication", limit perms for service accounts, detect by looking for event ID 4768 from service account
# :: kerberoasting

# :: CVE-2022-33679 - (placeholder b/c only mitigation I could find was patches, although there was a related regkey - AllowOldNt4Crypto)


# :: Classic compromisation methods
# :: MS17-010 - EternalBlue
# :: (insert mitigation here)

# :: MS14-025 - SYSVOL & GPP (placeholder b/c requires DC to be 2008 or 2012 and a patch - KB2962486) 
# :: Don't set passwords via group policy ig

# :: proxylogon, proxyshell (placeholder b/c no Exchange this year)


# :: Mitigating some privesc methods

# :: CVE-2020-0796 (SMBGhost) - Affects Windows build versions 1903, 1909; patch at https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796
# :: Workaround will only work on servers, clients would have to connect to malicious SMB server
# :: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f

# :: CVE-2021-36934 (HiveNightmare/SeriousSAM) - workaround (patch at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
# icacls %windir%\system32\config\*.* /inheritance:e
# :: delete vss shadow copies

# :: RoguePotato and literally all the other potatoes and PrintSpoofer
# :: bruh idk how to mitigate this, something about restricting service account privileges (https://assets.sentinelone.com/labs/rise-of-potatoes#page=1)

# :: KrbRelayUp - literally a no fix exploit smh my head
# :: Mitigations located at https://pyrochiliarch.com/2022/04/28/krbrelayup-mitigations/
# :: Mitigations could break scoring/injects or might not be possible


# :: Trying to block common things done after getting valid creds
# :: bloodhound - dude idk

# :: kerberoasting - https://www.netwrix.com/cracking_kerberos_tgs_tickets_using_kerberoasting.html
# :: Events 4769 and 4770, look for use of RC4 encryption and large volume of requests
# :: Reject auth requests not using Kerberos FAST
# :: Disable insecure protocols (not sure abt this) - attribute msDs-SupportedEncryptionTypes set to 0x18
# :: Response: quarantine and reset passwords

# :: certipy - bruh idk, requires ADCS anyways

# :: coercer.py - oof idk but might not be effective given SMB security settings


# :: Known vulns that require valid creds
# :: MS14-068
# :: (Mitigations go here)

# :: CVE-2019-0724, CVE-2019-0686 (privexchange) - placeholder b/c requires MS Exchange

# :: CVE-2021-42287/CVE-2021-42278 (SamAccountName / nopac) - patching required; easy to exploit, kinda hard to detect
# :: Limit users' abilities to join workstations to domain 

# :: CVE-2021-1675 / CVE-2021-42278 (PrintNightmare)
# reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f

# :: CVE-2022-26923 (Certifried) - placeholder b/c needs ADCS


# :: Mitigating common things tried after getting local admin
# :: Extracting creds from LSASS - LSASS Protections
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f 
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /t REG_DWORD /d 0 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f 
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
# :: Disable plain text passwords stored in LSASS
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f 

# :: Extracting creds from SAM, LSA - should be covered by above otherwise idk

# :: dpapi extract - lol idl

# :: Extract creds w/cert auth - placeholder b/c no ADCS, but still idk


# :: Messing w/ACLs and permissions
# :: dcsync

# :: perms on groups, computers, users, gpos

# :: CVE-2021-40469 - DNSadmins abuse
# :: probs remove this from general script, specify in docs


# :: Lateral movement attacks
# :: Pass The Hash
# :: https://www.netwrix.com/pass_the_hash_attack_explained.html

# :: Pass The Ticket
# :: https://www.netwrix.com/pass_the_ticket.html

# :: overpass the hash
# :: https://blog.netwrix.com/2022/10/04/overpass-the-hash-attacks/


# :: Kerberos delegation
# :: Unconstrained delegation

# :: Contstrained delegation

# :: Resource-based Constrained delegation (RBCD)


# :: Trust relationships
# :: Parent/child domain relations - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain?q=trust


# :: Persistence
# :: Golden Ticket - https://www.netwrix.com/how_golden_ticket_attack_works.html

# :: Silver Ticket - https://www.netwrix.com/silver_ticket_attack_forged_service_tickets.html

# :: Diamond Ticket??? Sapphire Ticket???


# :: They got domain admin - rip bozo
# :: ntds.dit extraction - https://www.netwrix.com/ntds_dit_security_active_directory.html



# :: TODO: One secpol file for default domain controller policy (that contains user right assignments for DC's)

# :: Done through secpol file
# @REM :: Disable Guest user + rename
# @REM net user Guest /active:no
# @REM wmic useraccount where "name='Guest'" rename lettuce
# @REM :: Rename Administrator
# @REM wmic useraccount where "name='Administrator'" rename tomato

# :: Create backup admin(s)
# net user cucumber Passw0rd-123* /add
# net localgroup Administrators cucumber /add

# :: Most keys that exist in the SOFTWARE hive also exist under SOFTWARE\Wow6432Node but I am too lazy to add them


# :: Stopping psexec with the power of svchost
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PSEXESVC.exe" /v Debugger /t REG_SZ /d "svchost.exe" /f

# :: Securing RDP
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f 
# :: Disabling RDP (only if not needed)
# ::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
# ::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fLogonDisabled /t REG_DWORD /d 1 /f



# :: Ease of Access
# reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
# reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
# reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
# reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f
# reg add "HKLM\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /t REG_DWORD /d 8 /f

# :: Disable SMBv1
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
# :: Strengthen SMB
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f

# :: UPnP
# reg add "HKLM\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" /v UPnPMode /t REG_DWORD /d 2 /f


# :: AppInit_DLLs
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
# reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
# :: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f

# :: Caching logons
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 1

# :: Remote Registry Path Denial
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f

# :: Not processing RunOnce List (located at HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, in HKCU, and Wow6432Node)
# reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
# reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
# reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
# reg add "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f

# :: Removing exclusions in Defender
# powershell -Command "& { Get-MpPreference | Select-Object -Property ExclusionExtension | ForEach-Object { if ($_.ExclusionExtension -ne $null) {Remove-MpPreference -ExclusionExtension $_.ExclusionExtension}}; Get-MpPreference | Select-Object -Property ExclusionPath | ForEach-Object {if ($_.ExclusionPath -ne $null) {Remove-MpPreference -ExclusionPath $_.ExclusionPath}}; Get-MpPreference | Select-Object -Property ExclusionProcess | ForEach-Object {if ($_.ExclusionProcess -ne $null) {Remove-MpPreference -ExclusionProcess $_.ExclusionProcess}} }"

# :: Yeeting things
# @REM net share admin$ /del
# @REM net share c$ /del
# @REM reg delete hklm\software\microsoft\windows\currentversion\runonce /f
# @REM reg delete hklm\software\microsoft\windows\currentversion\run /f
# @REM del /S "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
# @REM del /S "C:\Users\LocalGuard\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
# @REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
# @REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f 
