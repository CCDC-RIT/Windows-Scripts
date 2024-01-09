$VerbosePreference = "SilentlyContinue"
$currentDir = (Get-Location).Path
$firewallPath = Join-Path -Path $currentDir -ChildPath 'results\firewallaudit.txt'
$registryPath = Join-Path -Path $currentDir -ChildPath 'results\registryaudit.txt'
$processPath = Join-Path -Path $currentDir -ChildPath 'results\processaudit.txt'
$thruntingPath = Join-Path -Path $currentDir -ChildPath 'results\threathuntingaudit.txt'
$windowsPath = Join-Path -Path $currentDir -ChildPath 'results\windowsaudit.txt'
$aclPath = Join-Path -Path $currentDir -ChildPath 'results\aclaudit.txt'
#split into different files
Function Get-KeysValues {
    param(
        [hashtable]$hash
    )

    $key_test = ""
    foreach ($Key in $hash.Keys) {
        # drop wildcard character
        if ($Key -like '*\`**') {
            $key_test = "Registry::" + $Key.TrimEnd("\*")
        } else {
            $key_test = "Registry::" + $Key
        }

        if (Test-Path -Path $key_test) {
            if ($hash[$key].Count -eq 0) { # querying only key/subkeys
                $properties = Get-ItemProperty ("Registry::" + $Key)
            } else {
                $properties = Get-ItemProperty ("Registry::" + $Key) -Name $hash[$Key] -ErrorAction SilentlyContinue
            }
            foreach ($property in $properties) {
                $key_path = "Key -",(Convert-Path $property.PSPath | Out-String) -join " "
                Write-Output $key_path
                Write-Output ($property | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider | Format-List | Out-String).Trim()
                Write-Output "`r`n"
            }         
        } else {
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewline; Write-Host $key -ForegroundColor Magenta -NoNewline; Write-Host " not found" -ForegroundColor White
        }
    }
}
Function Write-KeysValues {
    param (
        [string]$header,
        [hashtable]$keysvalues,
        [string]$filepath
    )
    Write-Output $header | Out-File -FilePath $filepath -Append
    Get-KeysValues $keysvalues | Out-File -FilePath $filepath -Append
}
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
        Write-Output "Firewall Profile: $($profile.Name)"
        Write-Output "Enabled: $($profile.Enabled)"
        $profileName = $profile.Name
        $rules = Get-FirewallRulesForProfile -ProfileName $profileName
        Write-Output "========================================================="
        foreach ($rule in $rules){
            Write-Output "Rule Name: $($rule.Name)"
            Write-Output "Display Name: $($rule.DisplayName)"
            Write-Output "Direction: $($rule.Direction)"
            Write-Output "Action: $($rule.Action)"
            Write-Output "Enabled: $($rule.Enabled)"
        }
        Write-Output "End Profile : $($profile.Name)"
    }
}

Function Process-Audit{#good
    $processList = Get-Process -IncludeUserName | Format-List
    Write-Output "Process List with Usernames: "
    Write-Output "$($processList)"
}

Function Hidden-Services{#not good
    $hidden = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}
    Write-Output "Hidden Service List: "
    Write-Output "$($hidden)"
}

Function Scheduled-Tasks{#good
    $scheduled = Get-ScheduledTask | Format-List
    Write-Output "Scheduled Task List: "
    Write-Output "$($scheduled)"
}

Function Windows-Defender-Exclusions{
    $exclusions = Get-MpPreference | findstr /b Exclusion
    Write-Output "$($exclusions)"
}

Function Injected-Threads{
    .\Get-InjectedThread.ps1
}

Function Random-Directories{
    $sus = @("C:\Intel", "C:\Temp")
    foreach ($directory in $sus){
        Write-Output "$(Get-ChildItem $directory)"
    }
}

Function Exporting-Sec-Policy{
    SecEdit /export /cfg "results\artifacts\old_secpol.cfg"
}

Function Current-local-gpo{
    # Use auditpol to get the current local gpo
    gpresult /h "results\artifacts\LocalGrpPolReport.html"
}

Function Programs-Registry{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "DisplayName")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "UninstallString")"
}

Function Unsigned-Files{
    ..\tools\sys\sc\sigcheck64 -accepteula -u -e c:\windows\system32
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
        Write-Output "Potentially Suspicious Services Detected"
        Write-Output "----------------------------------------"
        foreach ($Service in $DetectedServices) {
            Write-Output "Name: $($Service.Name) - Display Name: $($Service.DisplayName) - Status: $($Service.State) - StartName: $($Service.StartName) - Description: $($Service.Description) - Binary Path: $($Service.PathName.Trim('"'))"
            # Output verbose information about each suspicious characteristic
            if ($PathSuspicious) {
                Write-Output "`t- Running from a potentially suspicious path`n"
            }
            if ($LocalSystemAccount) {
                Write-Output "`t- Running with a LocalSystem account`n"
            }
            if ($NoDescription) {
                Write-Output "`t- No description provided`n"
            }
            if ($Unsigned) {
                Write-Output "`t- Unsigned executable`n"
            }
            if ($SuspiciousExtension) {
                Write-Output "`t- Suspicious file extension`n"
            }
            Write-Output ""
        }
    } else {
        Write-Output "No potentially suspicious services detected.`n"
    }
}
#only if server 
Function Windows-Features{
    $featureList = Get-WindowsFeature | Where-Object Installed
    Write-Output "Windows Features"
    Write-Output "$(featureList)"
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

Function Service-CMD-Line{
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
        Write-Output "`nService Name: $serviceName"
        Write-Output "`nService Status: $serviceStatus"
        Write-Output "`nCommand Line Arguments: $serviceCommand"
        Write-Output "`n-----------------------------------"
    }
}

Function UnquotedServicePathCheck {
    Write-Output "Fetching the list of services, this may take a while...";
    $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
    if ($($services | Measure-Object).Count -lt 1) {
    Write-Output "No unquoted service paths were found";
    }
    else {
        $services | ForEach-Object {
            Write-Output "Unquoted Service Path found!`n" -ForegroundColor red
            Write-Output `nName: $_.Name
            Write-Output `nPathName: $_.PathName
            Write-Output `nStartName: $_.StartName 
            Write-Output `nStartMode: $_.StartMode
            Write-Output `nRunning: $_.State
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
                Write-Output -ForegroundColor Blue "=========||HKU Recently Run Commands"
                foreach ($p in $property) {
                    Write-Output "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($p))" 
                }
            }
        }
    }
}

function Get-ConsoleHostHistory {
    Write-Output $(Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String pa)
    $historyFilePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    if (Test-Path $historyFilePath) {
        try {
            $historyContent = Get-Content -Path $historyFilePath
            Write-Output "Console Host Command History:"
            Write-Output "-----------------------------"
            foreach ($command in $historyContent) {
                Write-Output $command
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
        Write-Output $("{0} : {1}" -f $_.Name, $_.Version)  
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
            if ($ACLObject.Owner -like $Identity ) { Write-Output "$Identity has ownership of $Target" -ForegroundColor Red }
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
                    if ($ServiceName) { Write-Output "$ServiceName found with permissions issue:" -ForegroundColor Red }
                    Write-Output -ForegroundColor red  "Identity $($permission.IdentityReference) has '$userPermission' perms for $Target"
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
        Write-Output "Access confirmed, may need futher investigation"
        Get-ChildItem "c:\windows\system32\tasks"
    }
    else {
        Write-Output "No admin access to scheduled tasks folder."
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
                    Write-Output "`n"
                    Write-Output "TaskName: $($_.TaskName)"
                    Write-Output "-------------"
                    [pscustomobject]@{
                        LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
                        NextRun    = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
                        Status     = $_.State
                        Command    = $_.Actions.execute
                        Arguments  = $_.Actions.Arguments 
                    } | Write-Output
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

# T1546.007 - Event Triggered Execution: Netsh Helper DLL
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\NetSh" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\NetSh" = @()
}
Write-KeysValues "----------- netsh Helper DLL Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited netsh Helper DLL keys" -ForegroundColor white
# T1546.009 - Event Triggered Execution: AppCert DLLs
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs" = @()
}
Write-KeysValues "----------- AppCert DLLs -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited AppCert DLL values" -ForegroundColor white
# T1546.010 - Event Triggered Execution: AppCert DLLs
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" = @("AppInit_DLLs");
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" = @("AppInit_DLLs")
}
Write-KeysValues "----------- AppInit DLLs -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited AppInit DLL values" -ForegroundColor white
# T1546.012 - Event Triggered Execution: Image File Execution Options Injection
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" = @("Debugger");
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" = @("Debugger")
}
Write-KeysValues "----------- IFEO Debugger Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited IFEO keys" -ForegroundColor white
# T1546.015 - Event Triggered Execution: Component Object Model Hijacking
$keysvalues = @{
    "HKLM\Software\Classes\CLSID\*" = @("InprocServer", "InprocServer32","LocalServer","LocalServer32","TreatAs","ProcID");
    "HKCU\Software\Classes\CLSID\*" = @("InprocServer", "InprocServer32","LocalServer","LocalServer32","TreatAs","ProcID")
}
Write-KeysValues "----------- COM Hijacking Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited COM keys" -ForegroundColor white

# T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
## ye olde run keys
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"= @();
    "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"= @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"= @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"= @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"= @();
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"= @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"= @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"= @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"= @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"= @();
    "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"= @();
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run"= @();
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce"= @();
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx"= @();
    "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms"= @()
}
Write-KeysValues "----------- Run Key Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited run keys" -ForegroundColor white
## Automatic service startup keys
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @();
    "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @()
}
Write-KeysValues "----------- Automatic Service Startup Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited service run keys" -ForegroundColor white
## Startup folder items
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" = @()
}
Write-KeysValues "----------- StartUp Folder Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited startup folder keys" -ForegroundColor white
## BootExecute key - default of "autocheck autochk /q /v *"
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" = @("BootExecute")
}
Write-KeysValues "----------- Boot Execute Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited BootExecute value" -ForegroundColor white

# T1547.002 - Boot or Logon Autostart Execution: Authentication Package
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @("Authentication Packages")
}
Write-KeysValues "----------- Authentication Packages -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Authentication Packages value" -ForegroundColor white
# T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @("Shell","Userinit","Notify");
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" = @("Shell","Userinit","Notify")
}
Write-KeysValues "----------- Winlogon Helper DLLs -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Winlogon Helper DLL keys" -ForegroundColor white
# T1547.005 - Boot or Logon Autostart Execution: Security Support Provider
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @("Security Packages");
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" = @("Security Packages")
}
Write-KeysValues "----------- Security Packages -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Security Packages value" -ForegroundColor white
# T1547.010 - Boot or Logon Autostart Execution: Port Monitors
$keysvalues = @{
    "HKLM\System\CurrentControlSet\Control\Print\Monitors\*" = @()
}
Write-KeysValues "----------- Port Monitor Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Port Monitor keys" -ForegroundColor white
# T1547.014 - Boot or Logon Autostart Execution: Active Setup
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\*" = @("StubPath");
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\*" = @("StubPath");
    "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\*" = @("StubPath");
    "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\*" = @("StubPath")
}
Write-KeysValues "----------- Active Startup Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Active Setup keys" -ForegroundColor white

# Alternate Shell
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" = @("AlternateShell")
}
Write-KeysValues "----------- Alternate Shell Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited AlternateShell value" -ForegroundColor white

# Startup/shutdown script keys
$keysvalues = @{
    "HKLM\Software\Policies\Microsoft\Windows\System\Scripts\*" = @();
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\*" = @();
    "HKCU\Software\Policies\Microsoft\Windows\System\Scripts\*" = @()
}
Write-KeysValues "----------- Startup/Shutdown Script Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited startup/shutdown script keys" -ForegroundColor white

# Assistive Technology 
$keysvalues = @{
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\*" = @("StartExe");
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" = @("Configuration")
}
Write-KeysValues "----------- Assistive Technology Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Assistive Technology keys" -ForegroundColor white

# Protocol filtering and handling
$keysvalues = @{
    "HKLM\Software\Classes\Protocols\Filter\*" = @(); 
    "HKLM\Software\Classes\Protocols\Handler\*" = @();
    "HKLM\Software\Wow6432Node\Classes\Protocols\Filter\*" = @(); 
    "HKLM\Software\Wow6432Node\Classes\Protocols\Handler\*" = @();
    "HKCU\Software\Classes\Protocols\Filter\*" = @();
    "HKCU\Software\Classes\Protocols\Handler\*" = @()
}
Write-KeysValues "----------- Protocol Filtering/Handling Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Protocol Filtering & Handling keys" -ForegroundColor white

# T1556.002 - Modify Authentication Process: Password Filter DLL
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @("Notification Packages")
}
Write-KeysValues "----------- Password Filter Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Password Filter DLL value" -ForegroundColor white
# T1556.008 - Modify Authentication Process: Network Provider DLL
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" = @("ProviderOrder")
}
Write-KeysValues "----------- Network Provider Order Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Network Provider DLL value" -ForegroundColor white

# Security Providers
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders" = @("SecurityProviders")
}
Write-KeysValues "----------- Security Provider Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Security Providers" -ForegroundColor white

# $firewallfunction = Show-Firewall
# $firewallfunction | Out-File -FilePath $firewallPath

# $registryfunction = Get-StartupFolderItems
# $registryfunction | Out-File -FilePath C:\Users\bikel\Desktop\test_output.txt
# $registryfunction = StartUp-Programs
# $registryfunction += StratUp-Scripts
# $registryfunction += Boot-Keys
# $registryfunction += Startup-Services
# $registryfunction += Run-Keys
# $registryfunction += RDP-Debugger-Persistance
# $registryfunction += COM-Hijacking
# $registryfunction += Password-Filter
# $registryfunction += Authentication-Packages
# $registryfunction += Security-Packages
# $registryfunction += Security-Providers
# $registryfunction += Networker-Provider-Order
# $registryfunction += Netsh-DLL
# $registryfunction += AppInit-DLL
# $registryfunction += AppCert-DLL
# $registryfunction += Winlogon-DLL
# $registryfunction += Print-Monitor-Ports
# $registryfunction += Programs-Registry
# $registryfunction += Uninstall-Keys
# $registryfunction | Out-File -FilePath $registryPath

# $processfunction = Process-Audit
# $processfunction += Hidden-Services
# $processfunction += Scheduled-Tasks
# $processfunction | Out-File -FilePath $processPath

# $thruntingfunction = Windows-Defender-Exclusions
# $thruntingfunction += Random-Directories
# $thruntingfunction += Unsigned-Files
# $thruntingfunction += Ripper 
# $thruntingfunction += UnquotedServicePathCheck
# $thruntingfunction += Recently-Run-Commands
# $thruntingfunction += Get-ConsoleHostHistory
# $thruntingfunction | Out-File -FilePath $thruntingPath

# $windowsfunction = Get-Installed
# $windowsfunction += Current-local-gpo
# $windowsfunction += Windows-Features
# $windowsfunction | Out-File -FilePath $windowsPath

# $aclfunction = Get-Process-ACL
# $aclfunction = Get-Registry-ACL
# $aclfunction = Get-ScheduledTask-ACL
# $aclfunction = Get-Startup-ACL
# $aclfunction | Out-File -FilePath $aclPath

#TODO: Print user properties