@echo off

:: Import secpol file here
:: One secpol file for "domain policy" - not editing default domain policy but creating gpo to apply across domain 
    :: This file will also serve as local secpol file
    :: Will contain account and local policies
set /p choice="Is this a domain controller (Y or N)? "
if %choice%=="Y" (
    echo:
    echo Skipping import of secpol file...
    echo: 
    echo Please use the GUI to import the file into a GPO. Make sure to do gpupdate /force after!
) else (
    secedit /configure /db %windir%\security\local.sdb /cfg secpol.inf
    gpupdate /force
)

:: TODO: One secpol file for default domain controller policy (that contains user right assignments for DC's)

:: Done through secpol file
@REM :: Disable Guest user + rename
@REM net user Guest /active:no
@REM wmic useraccount where "name='Guest'" rename lettuce
@REM :: Rename Administrator
@REM wmic useraccount where "name='Administrator'" rename tomato

:: Create backup admin(s)
net user cucumber Passw0rd-123* /add
net localgroup Administrators cucumber /add

:: Most keys that exist in the SOFTWARE hive also exist under SOFTWARE\Wow6432Node but I am too lazy to add them

:: UAC - idk if these sync up w/secpol, oh well
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
:: Not sure if this should be set to 1 or 0
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
:: Remote UAC moment
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f

:: Stopping psexec with the power of svchost
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PSEXESVC.exe" /v Debugger /t REG_SZ /d "svchost.exe" /f

:: Securing RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f 
:: Disabling RDP (only if not needed)
::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fLogonDisabled /t REG_DWORD /d 1 /f

:: LSASS Protections
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 

:: Disable plain text passwords stored in LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f 

:: Ease of Access
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /t REG_DWORD /d 8 /f

:: Disable SMBv1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
:: Strengthen SMB
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
:: Enable SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

:: UPnP
reg add "HKLM\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" /v UPnPMode /t REG_DWORD /d 2 /f

:: Disable LLMNR
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f

:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\, set NetbiosOptions to 2 for all interfaces

:: Limiting BITS transfer
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f

:: Print?
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f

:: Hive?
icacls %windir%\system32\config\*.* /inheritance:e

:: AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f

:: Caching logons
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 1

:: Remote Registry Path Denial
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f

:: Not processing RunOnce List (located at HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, in HKCU, and Wow6432Node)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f

:: Removing exclusions in Defender - trust me bro
powershell -encodedCommand "RwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBQAHIAbwBwAGUAcgB0AHkAIABFAHgAYwBsAHUAcwBpAG8AbgBFAHgAdABlAG4AcwBpAG8AbgAgAHwAIAAlACAAewAgAGkAZgAgACgAJABfAC4ARQB4AGMAbAB1AHMAaQBvAG4ARQB4AHQAZQBuAHMAaQBvAG4AIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewBSAGUAbQBvAHYAZQAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAALQBFAHgAYwBsAHUAcwBpAG8AbgBFAHgAdABlAG4AcwBpAG8AbgAgACQAXwAuAEUAeABjAGwAdQBzAGkAbwBuAEUAeAB0AGUAbgBzAGkAbwBuAH0AfQA7AEcAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0AUAByAG8AcABlAHIAdAB5ACAARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgAHwAIAAlACAAewBpAGYAIAAoACQAXwAuAEUAeABjAGwAdQBzAGkAbwBuAFAAYQB0AGgAIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewBSAGUAbQBvAHYAZQAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAALQBFAHgAYwBsAHUAcwBpAG8AbgBQAGEAdABoACAAJABfAC4ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAB9AH0AOwBHAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAFAAcgBvAHAAZQByAHQAeQAgAEUAeABjAGwAdQBzAGkAbwBuAFAAcgBvAGMAZQBzAHMAIAB8ACAAJQAgAHsAaQBmACAAKAAkAF8ALgBFAHgAYwBsAHUAcwBpAG8AbgBQAHIAbwBjAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsAUgBlAG0AbwB2AGUALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUAByAG8AYwBlAHMAcwAgACQAXwAuAEUAeABjAGwAdQBzAGkAbwBuAFAAcgBvAGMAZQBzAHMAfQB9AA=="

:: Yeeting things
@REM net share admin$ /del
@REM net share c$ /del
@REM reg delete hklm\software\microsoft\windows\currentversion\runonce /f
@REM reg delete hklm\software\microsoft\windows\currentversion\run /f
@REM del /S "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
@REM del /S "C:\Users\LocalGuard\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
@REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
@REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f 
