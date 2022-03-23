:: Make sure to change password in the scoring engine whenever scored user password is changed
net user Administrator *
net user [username] *

:: Renmae Administrator
wmic useraccount where “name=’Administrator’” rename cucumber

:: Backup Admin
net user /add pickle
net localgroup Administrators pickle /add

:: Disable guests
net user Guest /active:no
