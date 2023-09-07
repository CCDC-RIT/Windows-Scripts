$VerbosePreference = "SilentlyContinue"

#split into different files

Function Show-Firewall{
    function Get-FirewallProfiles {
        $profiles = Get-NetFirewallProfile | Select-Object -Property Name, Enabled
        return $profiles
    }
    function Get-FirewallRulesForProfile {
        param (
            [string]$ProfileName
        )
        $rules = Get-NetFirewallRule | Where-Object { $_.Profile -contains $ProfileName } | Select-Object -Property Name, DisplayName, Direction, Action, Enabled
        return $rules
    }
    $firewallProfiles = Get-FirewallProfiles
    foreach ($profile in $firewallProfiles){
        Write-Host "Firewall Profile: $($profile.Name)"
        Write-Host "Enabled: $($profile.Enabled)"
        $profileName = $profile.Name
        $rules = Get-FirewallRulesForProfile -ProfileName $profileName
        Write-Host "========================================================="
        foreach ($rule in $rules){
            Write-Host "Rule Name: $($rule.Name)"
            Write-Host "Display Name: $($rule.DisplayName)"
            Write-Host "Direction: $($rule.Direction)"
            Write-Host "Action: $($rule.Action)"
            Write-Host "Enabled: $($rule.Enabled)"
        }
        Write-Host "End Profile : $($profile.Name)"
    }
}

Function Process-Audit{
    $processList = Get-Process -IncludeUserName
    Write-Host "Process List with Usernames: "
    Write-Host "$($processList)"
}

Function Hidden-Services{
    $hidden = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace ""_[0-9a-f]{2,8}$\"" }) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace ""HKEY_LOCAL_MACHINE\\\\\"", ""HKLM:\\\"" } | ? { Get-ItemProperty -Path ""$_\"" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq ""=>\""}
    Write-Host "Hidden Service List: "
    Write-Host "$($hidden)"
}

Function Scheduled-Tasks{
    $scheduled = Get-ScheduledTask
    Write-Host "Scheduled Task List: "
    Write-Host "$($scheduled)"
}

Function StartUp-Programs{
    $startup = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location
    Write-Host "$($startup)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
}

Function StratUp-Scripts{
    Write-Host "$(reg query "HKLM\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
    Write-Host "$(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" /s)"
    Write-Host "$(reg query "HKCU\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
}

Function Boot-Keys{
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell")"
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Host "$(reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Host "$(reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
}

Function Startup-Services{
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Host "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Host "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
}

Function Run-Keys{
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Host "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Host "$(reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Host "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run")"
    Write-Host "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Host "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Host "$(reg query "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Host "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run")"
    Write-Host "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce")"
    Write-Host "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx")"
    Write-Host "$(reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms")"
}

Function RDP-Debugger-Persistance{
    Write-Host "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs" /s /v "StartExe")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v "Debugger")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v "Debugger")"
    Write-Host "RDP enabled if 0, disabled if 1"
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections")"
}

Function COM-Hijacking{
    Write-Host "$(reg query "HKLM\Software\Classes\Protocols\Filter" /s)"
    Write-Host "$(reg query "HKLM\Software\Classes\Protocols\Handler" /s)"
    Write-Host "$(reg query "HKLM\Software\Classes\CLSID" /s /v "InprocServer32")"
    Write-Host "$(reg query "HKLM\Software\Classes\CLSID" /s /v "LocalServer32")"
    Write-Host "$(reg query "HKLM\Software\Classes\CLSID" /s /v "TreatAs")"
    Write-Host "$(reg query "HKLM\Software\Classes\CLSID" /s /v "ProcID")"
}

Function Password-Filter{
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages")"
}

Function Authentication-Packages{
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages")"
}

Function Security-Packages{
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" )"
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages")"
}

Function Security-Providers{
    Write-Host "Including WDigest"
    Write-Host "$(reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders" /v SecurityProviders)"
    Write-Host "$(reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest")"
}

Function Networker-Provider-Order{
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" /v "ProviderOrder")"
}

Function Netsh-DLL{
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\NetSh")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\NetSh")"
}

Function AppInit-DLL{
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs)"
}

Function AppCert-DLL{
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs")"
}

Function Winlogon-DLL{
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify)"
}

Function Print-Monitor-Ports{
    Write-Host "$(reg query "HKLM\System\CurrentControlSet\Control\Print\Monitors" /s)"
}

Function Windows-Defender-Exclusions{
    $exclusions = Get-MpPreference | findstr /b Exclusion
    Write-Host "$($exclusions)"
}

Function Injected-Threads{
    .\Get-InjectedThread.ps1
}

Function Random-Directories{
    $sus = ["C:\Intel", "C:\Temp"]
    foreach ($directory in $sus){
        Write-Host "$(Get-ChildItem $directory)"
    }
}

Function Exporting-Sec-Policy{
    SecEdit /export /cfg c:/old_secpol.cfg
}

Function Current-Audit-Policy{
    auditpol /get /category:*
}

Function Programs-Registry{
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "DisplayName")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "UninstallString")"
}

Function Unsigned-Files{
    cd ../tools/sys/sc
    sigcheck64 -accepteula -u -e c:\windows\system32
    cd ../../../scripts
}