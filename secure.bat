:: Audit policy
auditpol /set /category:* /success:enable /failure:enable

:: Disable Guest user + rename
net user Guest /active:no
wmic useraccount where "name='Guest'" rename veggie

:: Rename Administrator
wmic useraccount where "name='Administrator'" rename pickle

:: Create backup admin(s)
net user cucumber P@ssw0rd-123* /add
net localgroup Administrators cucumber /add

:: Powershell logging
mkdir C:\scrips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d C:\scrips /f

:: UAC
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
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
:: Enable SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

:: Limiting BITS transfer
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f

:: Print?
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f

:: Hive?
icacls %windir%\system32\config\*.* /inheritance:e

:: AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f

:: Caching logons
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 1

:: Remote Registry Path Denial
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f

:: Not processing RunOnce List (located at HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce and in HKCU)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f

:: Yeeting things
@REM net share admin$ /del
@REM net share c$ /del
@REM reg delete hklm\software\microsoft\windows\currentversion\runonce /f
@REM reg delete hklm\software\microsoft\windows\currentversion\run /f
@REM del /S "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
@REM del /S "C:\Users\LocalGuard\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
@REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
@REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f 
