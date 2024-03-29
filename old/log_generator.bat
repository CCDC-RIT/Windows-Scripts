:: Success & Failed Logons
wevtUtil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]" /c:5 /rd:true /f:text >Parsed\%computername%_Logon_Events_Win7.log

:: User Account Change
wevtUtil qe Security /q:"*[System[(EventID=4738)]]" /c:5 /rd:true /f:text >Parsed\R_%computername%_User_Account_Change_Win7.log

:: Specific User Account Changes
wevtutil qe Security /q:"*[System[(EventID=4725 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4726 or EventID=4767)]]" /c:10 /f:text

:: New Service Installed
wevtUtil qe Security /q:"*[System[(EventID=7045)]]" /c:5 /rd:true /f:text >Parsed\R_%computername%_New_Service_Installed_Win7.log

:: Registry Changed - "Object Name"
WevtUtil qe Security /q:"*[System[(EventID=4657)]]" /c:5 /rd:true /f:text |find /i "Object Name"

:: File or Registry Changed - "Object Name"
WevtUtil qe Security /q:"*[System[(EventID=4663)]]" /c:50 /rd:true /f:text |find /i "Object Name"

:: Files - New files w/"webm"
WevtUtil qe Security /q:"*[System[(EventID=4663)]]" /c:50 /rd:true /f:text |find /i "wbem"

:: Process Launches
WevtUtil qe Security /q:"*[System[(EventID=4688)]]" /c:5 /rd:true /f:text 

:: Modified Service Stopped
WevtUtil qe Security /q:"*[System[(EventID=4656)]]" /c:5 /rd:true /f:text

:: Scheduled Task Installed or Modified
WevtUtil qe Security /q:"*[System[(EventID=4698 or EventID=4702)]]" /c:5 /rd:true /f:text

:: Special Privileges assigned
WevtUtil qe Security /q:"*[System[(EventID=4672)]]" /c:5 /rd:true /f:text

:: PowerShell executed
WevtUtil qe "Windows PowerShell" /q:"*[System[(EventID=501)]]" /c:5 /rd:true /f:text >Parsed\%computername%_PS_Cmds_Executed_Win7.log

:: Specific "Command Name" executed
WevtUtil qe "Windows PowerShell" /q:"*[System[(EventID=500)]]" /c:5 /rd:true /f:text | find /I "CommandName" 

:: Specific "Command Line" executed
WevtUtil qe "Windows PowerShell" /q:"*[System[(EventID=500)]]" /c:5 /rd:true /f:text | find /I "CommandLine"

:: Specifc Cmdlet and Scripts executed
WevtUtil qe "Windows PowerShell" /q:"*[System[(EventID=501)]]" /c:1000 /rd:true /f:text | findstr "Logged CommandLine Cmdlet Script"

:: PowerShell 4 and 5, Event ID 4104
:: Anything that is a "Get-" call
WevtUtil qe "Microsoft-Windows-PowerShell/Operational" /q:"*[System[(EventID=4104)]]" /c:1000 /rd:true /f:text | findstr /i "Get-"

:: Anything that is an "iex" call
WevtUtil qe "Microsoft-WindowsPowerShell/Operational" /q:"*[System[(EventID=4104)]]" /c:1000 /rd:true /f:text | findstr /i "iex"

:: querying logs through powershell example
:: get-eventlog -logname "Windows PowerShell" -computername <your_systemname> | where {$_.eventID -eq 400}
