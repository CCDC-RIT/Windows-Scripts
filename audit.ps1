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

Function Current-local-gpo{
    # Use auditpol to get the current local gpo
    gpresult /h LocalGrpPolReport.html
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

Function UnquotedServicePathCheck {
    Write-Host "Fetching the list of services, this may take a while...";
    $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
    if ($($services | Measure-Object).Count -lt 1) {
    Write-Host "No unquoted service paths were found";
    }
    else {
        $services | ForEach-Object {
            Write-Host "Unquoted Service Path found!" -ForegroundColor red
            Write-Host Name: $_.Name
            Write-Host PathName: $_.PathName
            Write-Host StartName: $_.StartName 
            Write-Host StartMode: $_.StartMode
            Write-Host Running: $_.State
        } 
    }
}

Function Recently-Run-Commands{
    Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
        # get the SID from output
        $HKUSID = $_.Name.Replace('HKEY_USERS\', "")
        $property = (Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
        $HKUSID | ForEach-Object {
            if (Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
                Write-Host -ForegroundColor Blue "=========||HKU Recently Run Commands"
                foreach ($p in $property) {
                    Write-Host "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($p))" 
                }
            }
        }
    }
}

function Get-ConsoleHostHistory {
    $historyFilePath = "$env:APPDATA\Microsoft\Windows\PowerShell\consolehost-history.txt"
    if (Test-Path $historyFilePath) {
        try {
            $historyContent = Get-Content -Path $historyFilePath
            Write-Host "Console Host Command History:"
            Write-Host "-----------------------------"
            foreach ($command in $historyContent) {
                Write-Host $command
            }
        }
        catch {
            Write-Error "Error occurred while reading the console host history: $_"
        }
    }
    else {
        Write-Warning "Console host history file not found."
    }
}

function Get-Installed{
    Get-CimInstance -class win32_Product | Select-Object Name, Version | 
    ForEach-Object {
        Write-Host $("{0} : {1}" -f $_.Name, $_.Version)  
    }
}

Function Start-ACLCheck {
    param(
        $Target, $ServiceName)
    # Gather ACL of object
    if ($null -ne $target) {
        try {
            $ACLObject = Get-Acl $target -ErrorAction SilentlyContinue
        }
        catch { $null }
        
        # If Found, Evaluate Permissions
        if ($ACLObject) { 
            $Identity = @()
            $Identity += "$env:COMPUTERNAME\$env:USERNAME"
            if ($ACLObject.Owner -like $Identity ) { Write-Host "$Identity has ownership of $Target" -ForegroundColor Red }
            whoami.exe /groups /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty 'group name' | ForEach-Object { $Identity += $_ }
            $IdentityFound = $false
            foreach ($i in $Identity) {
                $permission = $ACLObject.Access | Where-Object { $_.IdentityReference -like $i }
                $UserPermission = ""
                switch -WildCard ($Permission.FileSystemRights) {
                    "FullControl" { $userPermission = "FullControl"; $IdentityFound = $true }
                    "Write*" { $userPermission = "Write"; $IdentityFound = $true }
                    "Modify" { $userPermission = "Modify"; $IdentityFound = $true }
                }
                Switch ($permission.RegistryRights) {
                    "FullControl" { $userPermission = "FullControl"; $IdentityFound = $true }
                }
                if ($UserPermission) {
                    if ($ServiceName) { Write-Host "$ServiceName found with permissions issue:" -ForegroundColor Red }
                    Write-Host -ForegroundColor red  "Identity $($permission.IdentityReference) has '$userPermission' perms for $Target"
                }
            }    
            # Identity Found Check - If False, loop through and stop at root of drive
            if ($IdentityFound -eq $false) {
                if ($Target.Length -gt 3) {
                    $Target = Split-Path $Target
                    Start-ACLCheck $Target -ServiceName $ServiceName
                }
            }
        }
        else {
        # If not found, split path one level and Check again
            $Target = Split-Path $Target
            Start-ACLCheck $Target $ServiceName
        }
    }
}

Function Get-Process-ACL{
    Get-Process | Select-Object Path -Unique | ForEach-Object { Start-ACLCheck -Target $_.path }
}

Function Get-Registry-ACL{
    Get-ChildItem 'HKLM:\System\CurrentControlSet\services\' | ForEach-Object {
        $target = $_.Name.Replace("HKEY_LOCAL_MACHINE", "hklm:")
        Start-aclcheck -Target $target
    }
}

Function Get-ScheduledTask-ACL{
    if (Get-ChildItem "c:\windows\system32\tasks" -ErrorAction SilentlyContinue) {
        Write-Host "Access confirmed, may need futher investigation"
        Get-ChildItem "c:\windows\system32\tasks"
    }
    else {
        Write-Host "No admin access to scheduled tasks folder."
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
            $Actions = $_.Actions.Execute
            if ($Actions -ne $null) {
                foreach ($a in $actions) {
                    if ($a -like "%windir%*") { $a = $a.replace("%windir%", $Env:windir) }
                    elseif ($a -like "%SystemRoot%*") { $a = $a.replace("%SystemRoot%", $Env:windir) }
                    elseif ($a -like "%localappdata%*") { $a = $a.replace("%localappdata%", "$env:UserProfile\appdata\local") }
                    elseif ($a -like "%appdata%*") { $a = $a.replace("%localappdata%", $env:Appdata) }
                    $a = $a.Replace('"', '')
                    Start-ACLCheck -Target $a
                    Write-Host "`n"
                    Write-Host "TaskName: $($_.TaskName)"
                    Write-Host "-------------"
                    [pscustomobject]@{
                        LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
                        NextRun    = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
                        Status     = $_.State
                        Command    = $_.Actions.execute
                        Arguments  = $_.Actions.Arguments 
                    } | Write-Host
                } 
            }
        }
    }
}

Function Get-Startup-ACL{
    @("C:\Documents and Settings\All Users\Start Menu\Programs\Startup",
    "C:\Documents and Settings\$env:Username\Start Menu\Programs\Startup", 
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", 
    "$env:Appdata\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object {
        if (Test-Path $_) {
            # CheckACL of each top folder then each sub folder/file
            Start-ACLCheck $_
            Get-ChildItem -Recurse -Force -Path $_ | ForEach-Object {
                $SubItem = $_.FullName
                if (Test-Path $SubItem) { 
                    Start-ACLCheck -Target $SubItem
                }
            }
        }
    }
    @("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
    # CheckACL of each Property Value found
        $ROPath = $_
        (Get-Item $_) | ForEach-Object {
            $ROProperty = $_.property
            $ROProperty | ForEach-Object {
                Start-ACLCheck ((Get-ItemProperty -Path $ROPath).$_ -split '(?<=\.exe\b)')[0].Trim('"')
            }
        }
    }
}