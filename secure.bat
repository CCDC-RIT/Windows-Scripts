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

