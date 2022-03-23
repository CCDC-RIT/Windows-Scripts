@echo off

call :sub >output.txt
exit /b

:sub
::basic inventory
echo Hostname:
hostname
echo:
echo Ipconfig:
ipconfig /all
echo:
echo Operating System:
systeminfo | findstr OS

::check for listening ports
echo:
echo Listening Ports:
netstat -ano | findstr LIST | findstr /V ::1 | findstr /V 127.0.0.1

::users and groups
echo:
echo Users:
net user
echo:
echo Groups:
net localgroup
echo:
echo Administrators Users:
net localgroup "Administrators"

::looking for network shares
echo:
echo Network Shares:
net share

::Check startup programs
echo:
echo Startup Programs:
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

::services
echo:
echo Services:
net start

::processes
echo:
echo Processes:
tasklist /svc /FO table