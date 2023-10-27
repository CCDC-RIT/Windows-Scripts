$VerbosePreference = "SilentlyContinue"
$currentDir = Get-Location
$registryPath = Join-Path -Path $currentDir -ChildPath 'registryaudit.txt'

Function StartUp-Programs{ #good
    $startup = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location
    Write-Output "$($startup)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
}

Function StratUp-Scripts{#good cant find reg keys 
    Write-Output "$(reg query "HKLM\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" /s)"
    Write-Output "$(reg query "HKCU\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
}

Function Boot-Keys{ #good
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell")"
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Output "$(reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Output "$(reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
}

Function Startup-Services{ #good can't find reg key
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Output "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
}

Function Run-Keys{ #good - could not find smoe of the regs keys 
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce")"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx")"
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms")"
}

Function RDP-Debugger-Persistance{
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs" /s /v "StartExe")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v "Debugger")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v "Debugger")"
    Write-Output "RDP enabled if 0, disabled if 1"
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections")"
}

Function COM-Hijacking{
    Write-Output "$(reg query "HKLM\Software\Classes\Protocols\Filter" /s)"
    Write-Output "$(reg query "HKLM\Software\Classes\Protocols\Handler" /s)"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "InprocServer32")"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "LocalServer32")"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "TreatAs")"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "ProcID")"
}

Function Password-Filter{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages")"
}

Function Authentication-Packages{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages")"
}

Function Security-Packages{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" )"
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages")"
}

Function Security-Providers{
    Write-Output "Including WDigest"
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders" /v SecurityProviders)"
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest")"
}

Function Networker-Provider-Order{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" /v "ProviderOrder")"
}

Function Netsh-DLL{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\NetSh")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\NetSh")"
}

Function AppInit-DLL{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs)"
}

Function AppCert-DLL{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs")"
}

Function Winlogon-DLL{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify)"
}

Function Print-Monitor-Ports{
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\Print\Monitors" /s)"
}

Function Programs-Registry{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "DisplayName")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "UninstallString")"
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

$registryfunction = StartUp-Programs
$registryfunction += StratUp-Scripts
$registryfunction += Boot-Keys
$registryfunction += Startup-Services
$registryfunction += Run-Keys
$registryfunction += RDP-Debugger-Persistance
$registryfunction += COM-Hijacking
$registryfunction += Password-Filter
$registryfunction += Authentication-Packages
$registryfunction += Security-Packages
$registryfunction += Security-Providers
$registryfunction += Networker-Provider-Order
$registryfunction += Netsh-DLL
$registryfunction += AppInit-DLL
$registryfunction += AppCert-DLL
$registryfunction += Winlogon-DLL
$registryfunction += Print-Monitor-Ports
$registryfunction += Programs-Registry
$registryfunction += Uninstall-Keys
$registryfunction | Out-File -FilePath $registryPath