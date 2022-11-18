@echo off

::TODO: WMI audit 

call :sub >system_audit.txt
exit /b

:sub
:: Firewall status, settings, and rules
netsh advfirewall show allprofiles
netsh advfirewall firewall show rule name=all

:: processes
echo:
echo ----------- Processes -----------
tasklist /svc /FO table

:: services
echo:
echo ----------- Services -----------
net start

:: hidden services?
:: https://gist.github.com/joswr1ght/c5d9773a90a22478309e9e427073fd30 but base64 lol
echo:
echo ----------- Hidden Services -----------
powershell -encodedCommand "QwBvAG0AcABhAHIAZQAtAE8AYgBqAGUAYwB0ACAALQBSAGUAZgBlAHIAZQBuAGMAZQBPAGIAagBlAGMAdAAgACgARwBlAHQALQBTAGUAcgB2AGkAYwBlACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAE4AYQBtAGUAIAB8ACAAJQAgAHsAIAAkAF8AIAAtAHIAZQBwAGwAYQBjAGUAIAAiAF8AWwAwAC0AOQBhAC0AZgBdAHsAMgAsADgAfQAkACIAIAB9ACAAKQAgAC0ARABpAGYAZgBlAHIAZQBuAGMAZQBPAGIAagBlAGMAdAAgACgAZwBjAGkAIAAtAHAAYQB0AGgAIABoAGsAbABtADoAXABzAHkAcwB0AGUAbQBcAGMAdQByAHIAZQBuAHQAYwBvAG4AdAByAG8AbABzAGUAdABcAHMAZQByAHYAaQBjAGUAcwAgAHwAIAAlACAAewAgACQAXwAuAE4AYQBtAGUAIAAtAFIAZQBwAGwAYQBjAGUAIAAiAEgASwBFAFkAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAFwAXAAiACwAIgBIAEsATABNADoAXAAiACAAfQAgAHwAIAA/ACAAewAgAEcAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAiACQAXwAiACAALQBuAGEAbQBlACAAbwBiAGoAZQBjAHQAbgBhAG0AZQAgAC0AZQByAHIAbwByAGEAYwB0AGkAbwBuACAAJwBpAGcAbgBvAHIAZQAnACAAfQAgAHwAIAAlACAAewAgACQAXwAuAHMAdQBiAHMAdAByAGkAbgBnACgANAAwACkAIAB9ACkAIAAtAFAAYQBzAHMAVABoAHIAdQAgAHwAIAA/AHsAJABfAC4AcwBpAGQAZQBJAG4AZABpAGMAYQB0AG8AcgAgAC0AZQBxACAAIgA9AD4AIgB9AA=="

:: list of scheduled tasks
echo: 
echo ----------- Scheduled Tasks -----------
schtasks /query
powershell -Command "get-scheduledtask"

:: Check startup programs
echo:
echo ----------- Startup Programs (all users) -----------
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"

:: Check for stuff running on boot
echo:
echo ----------- Boot Execution Keys -----------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute"
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath"
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath"
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath"

:: Check for startup services
echo:
echo ----------- Startup Services Keys -----------
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce"

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce"

:: Printing run keys
echo:
echo ----------- Run Keys -----------
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

:: Apparently there are run keys for Terminal Server
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx"

:: RDP/login screen keys
echo:
echo ----------- RDP/Ease of Use Persistence -----------
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger"
:: RDP enabled if 0, disabled if 1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections"

:: LSA
:: Check password filters
echo:
echo ----------- Password filters -----------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages"
:: Check authentication packages
echo: 
echo ----------- Authentication Packages -----------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages"
:: Check Security Support Providers
echo:
echo ----------- Security Packages -----------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" 
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages"

:: Network Provider
echo:
echo ----------- Network Provider Order -----------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" /v "ProviderOrder"

:: bro you can load dlls into firewall
echo: 
echo ----------- netsh DLLs -----------
reg query "HKLM\SOFTWARE\Microsoft\NetSh"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\NetSh"

:: Check custom DLLs
echo:
echo ----------- AppInit_DLLs -----------
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs

:: AppCert DLLs (doesn't exist natively)
echo:
echo ----------- AppCertDLLs -----------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\" /v AppCertDLLs

:: Check for Custom DLLs in Winlogon
echo:
echo ----------- Winlogon DLLs -----------
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify

:: Check for Windows Defender exclusions 
echo:
echo ----------- Windows Defender Exclusions -----------
powershell -Command "Get-MpPreference | findstr /b Exclusion"

echo: 
echo ----------- Injected Threads -----------
powershell -Command ".\Get-InjectedThread.ps1"

:: Sus directories
echo:
echo ----------- Random Directories -----------
dir "C:\Intel"
dir "C:\Temp"

:: Export secpol file so we can take a look at it later
echo ----------- Exporting Local Security Policy -----------
secedit /export /cfg secpol.cfg

:: Audit the current audit policy
echo:
echo ----------- Current Audit Policy -----------
auditpol /get /category:*

:: Check for unsigned files (run this in the same directory as sigcheck!)
:: Might want to comment out to make script faster
echo:
echo ----------- Unsigned Files -----------
sigcheck64 -accepteula -u -e c:\windows\system32