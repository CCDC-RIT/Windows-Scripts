$VerbosePreference = "SilentlyContinue"

#split into different files

Function Show-Firewall{#good
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

Function Process-Audit{#good
    $processList = Get-Process -IncludeUserName
    Write-Host "Process List with Usernames: "
    Write-Host "$($processList)"
}

Function Hidden-Services{#not good
    $hidden = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace ""_[0-9a-f]{2,8}$\"" }) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace ""HKEY_LOCAL_MACHINE\\\\\"", ""HKLM:\\\"" } | ? { Get-ItemProperty -Path ""$_\"" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq ""=>\""}
    Write-Host "Hidden Service List: "
    Write-Host "$($hidden)"
}

Function Scheduled-Tasks{#good
    $scheduled = Get-ScheduledTask
    Write-Host "Scheduled Task List: "
    Write-Host "$($scheduled)"
}

Function StartUp-Programs{ #good
    $startup = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location
    Write-Host "$($startup)"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
}

Function StratUp-Scripts{#good cant find reg keys 
    Write-Host "$(reg query "HKLM\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
    Write-Host "$(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" /s)"
    Write-Host "$(reg query "HKCU\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
}

Function Boot-Keys{ #good
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell")"
    Write-Host "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Host "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Host "$(reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Host "$(reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
}

Function Startup-Services{ #good can't find reg key
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Host "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Host "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Host "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
}

Function Run-Keys{ #good - could not find smoe of the regs keys 
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
    # Specify the path where you want to save the audit policy export
    $exportFilePath = "C:\path\to\audit_policy_export.txt"
    # Use auditpol to get the current audit policy settings and export them to a text file
    auditpol /get /category:* | Out-File -FilePath $exportFilePath
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

Function Ripper{
    # Function to check if the service's binary path is suspicious
    function IsSuspiciousPath($path) {
        return ($path -like "C:\Users\*")
    }

    # Function to check if the service's binary is unsigned
    function IsUnsigned($path) {
        try {
            $Signatures = Get-AuthenticodeSignature -FilePath $path
            return ($Signatures.Status -ne "Valid")
        }
        catch {
            return $true
        }
    }

    # Function to check if the service has a suspicious file extension
    function HasSuspiciousExtension($path) {
        $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
        $extension = [IO.Path]::GetExtension($path)
        return ($suspiciousExtensions -contains $extension)
    }

    $AllServices = Get-WmiObject -Class Win32_Service
    # Create an empty array to store detected suspicious services
    $DetectedServices = New-Object System.Collections.ArrayList
    foreach ($Service in $AllServices){
        $BinaryPathName = $Service.PathName.Trim('"')
        # Check for suspicious characteristics
        $PathSuspicious = IsSuspiciousPath($BinaryPathName)
        $LocalSystemAccount = ($Service.StartName -eq "LocalSystem")
        $NoDescription = ([string]::IsNullOrEmpty($Service.Description))
        $Unsigned = IsUnsigned($BinaryPathName)
        $SuspiciousExtension = HasSuspiciousExtension($BinaryPathName)
        if ($PathSuspicious -or $LocalSystemAccount -or $NoDescription -or $Unsigned -or $SuspiciousExtension){
            $DetectedServices.Add($Service) | Out-Null
        }
    }
    if ($DetectedServices.Count -gt 0) {
        Write-Host "Potentially Suspicious Services Detected"
        Write-Host "----------------------------------------"
        foreach ($Service in $DetectedServices) {
            Write-Host "Name: $($Service.Name) - Display Name: $($Service.DisplayName) - Status: $($Service.State) - StartName: $($Service.StartName) - Description: $($Service.Description) - Binary Path: $($Service.PathName.Trim('"'))"
            # Output verbose information about each suspicious characteristic
            if ($PathSuspicious) {
                Write-Host "`t- Running from a potentially suspicious path"
            }
            if ($LocalSystemAccount) {
                Write-Host "`t- Running with a LocalSystem account"
            }
            if ($NoDescription) {
                Write-Host "`t- No description provided"
            }
            if ($Unsigned) {
                Write-Host "`t- Unsigned executable"
            }
            if ($SuspiciousExtension) {
                Write-Host "`t- Suspicious file extension"
            }
            Write-Host ""
        }
    } else {
        Write-Host "No potentially suspicious services detected."
    }
}
#only if server 
Function Windows-Features{
    $featureList = Get-WindowsFeature | Where-Object Installed
    Write-Host "Windows Features"
    Write-Host "$(featureList)"
}

Function Uninstall-Keys{
    $productNames = @("*google*")
    $UninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
                        )
    $results = foreach ($key in (Get-ChildItem $UninstallKeys) ) {
        foreach ($product in $productNames) {
            if ($key.GetValue("DisplayName") -like "$product") {
                [pscustomobject]@{
                    KeyName = $key.Name.split('\')[-1];
                    DisplayName = $key.GetValue("DisplayName");
                    UninstallString = $key.GetValue("UninstallString");
                    Publisher = $key.GetValue("Publisher");
                }
            }
        }
    }
    $results
}

# Get a list of all services
$services = Get-Service

# Iterate through each service and retrieve command line arguments
foreach ($service in $services) {
    $serviceName = $service.DisplayName
    $serviceStatus = $service.Status
    $serviceCommand = $null

    try {
        # Access the service's executable path which typically contains command line arguments
        $serviceCommand = (Get-CimInstance Win32_Service | Where-Object { $_.Name -eq $serviceName }).PathName
    }
    catch {
        $serviceCommand = "Error: Unable to retrieve command line arguments"
    }

    # Output service information
    Write-Host "Service Name: $serviceName"
    Write-Host "Service Status: $serviceStatus"
    Write-Host "Command Line Arguments: $serviceCommand"
    Write-Host "-----------------------------------"
}

