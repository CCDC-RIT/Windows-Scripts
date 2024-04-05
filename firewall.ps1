# Parameter for enabling/disabling lockout prevention
param(
    [Parameter(Mandatory=$true)]
    [bool]$EnableLockoutPrevention
)


# Delete all rules
netsh advfirewall set allprofiles state off | Out-Null
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
netsh advfirewall firewall delete rule name=all | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] All firewall rules deleted" -ForegroundColor white

# Configure logging
netsh advfirewall set allprofiles logging filename C:\Windows\fw.log | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 32676 | Out-Null
netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Firewall logging enabled" -ForegroundColor white

# if key doesn't already exist, install WFC
if (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Windows Firewall Control")) {
    $currentDir = ($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("scripts\firewall.ps1"))
    $toolInstallPath = Join-Path -Path $currentDir -ChildPath "installers\wfcinstall.exe"
    $installerPath = Join-Path -Path $currentDir -ChildPath "installers\wfcsetup.exe"
    & $installerPath -i -r -noshortcuts -norules $toolInstallPath
}

# Rules!
# Common Scored Services
## Domain Controller Rules (includes DNS server)
if (Get-WmiObject -Query 'select * from Win32_OperatingSystem where (ProductType = "2")') {
    ## Inbound rules
    netsh adv f a r n=DC-TCP-In dir=in act=allow prof=any prot=tcp localport=88,135,389,445,464,636,3268 | Out-Null
    netsh adv f a r n=DC-UDP-In dir=in act=allow prof=any prot=udp localport=88,123,135,389,445,464,636 | Out-Null
    netsh adv f a r n=RPC-In dir=in act=allow prof=any prot=tcp localport=rpc | Out-Null
    netsh adv f a r n=EPMAP-In dir=in act=allow prof=any prot=tcp localport=rpc-epmap | Out-Null
    netsh adv f a r n=DNS-Server dir=in act=allow prof=any prot=udp localport=53 | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Domain Controller firewall rules set" -ForegroundColor white

    ## Outbound rules (for cross-forest trust w/RHEL IdM)
    ## TODO: test
    netsh adv f a r n=Domain-Trust-TCP-Out dir=out act=allow prof=any prot=tcp remoteport=88,135,138,139,389,445,464,3268 | Out-Null
    netsh adv f a r n=Domain-Trust-UDP-Out dir=out act=allow prof=any prot=udp remoteport=88,138,139,389,445,464 | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Cross-forest trust firewall rules set" -ForegroundColor white
} else {
    ## If not a DC it's probably domain-joined so add client rules
    netsh adv f a r n=DC-TCP-Out dir=out act=allow prof=any prot=tcp remoteport=88,135,389,445,636,3268 | Out-Null
    netsh adv f a r n=DC-UDP-Out dir=out act=allow prof=any prot=udp remoteport=88,123,135,389,445,636 | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Domain-joined system firewall rules set" -ForegroundColor white
}

# DNS client
netsh adv f a r n=DNS-Client dir=out act=allow prof=any prot=udp remoteport=53 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DNS Client firewall rules set" -ForegroundColor white

# LSASS (needed for authentication and NLA)
# is this a bad idea? probably. keep an eye on network connections made by this program
netsh adv f a r n=LSASS-Out dir=out act=allow prof=any prog="C:\Windows\System32\lsass.exe" | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LSASS firewall rule set" -ForegroundColor white

## Certificate Authority
if (Get-Service -Name CertSvc 2>$null) {
    netsh adv f a r n=RPC-In dir=in act=allow prof=any prot=tcp localport=rpc | Out-Null
    netsh adv f a r n=EPMAP-In dir=in act=allow prof=any prot=tcp localport=rpc-epmap | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Certificate Authority server firewall rule set" -ForegroundColor white
}
netsh adv f a r n=CA-Client dir=out act=allow prof=any prot=tcp remoteport=135 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Certificate Authority client firewall rule set" -ForegroundColor white

## ICMP/Ping
# netsh adv f a r n=ICMP-In dir=in act=allow prof=any prot=icmpv4:8,any 
# netsh adv f a r n=ICMP-Out dir=out act=allow prof=any prot=icmpv4:8,any 

## HTTP(S) (might have to open server for CA)
# netsh adv f a r n=HTTP-Server dir=in act=allow prof=any prot=tcp localport=80,443
# netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443

# Remoting Protocols

## RDP
# netsh adv f a r n=RDP-TCP-Client dir=out act=allow prof=any prot=tcp remoteport=3389 
# netsh adv f a r n=RDP-UDP-Client dir=out act=allow prof=any prot=udp remoteport=3389 
netsh adv f a r n=RDP-TCP-Server dir=in act=allow prof=any prot=tcp localport=3389 | Out-Null
netsh adv f a r n=RDP-UDP-Server dir=in act=allow prof=any prot=udp localport=3389 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] RDP inbound firewall rules set" -ForegroundColor white

## WinRM
# netsh adv f a r n=WinRM-Client dir=out act=allow prof=any prot=tcp remoteport=5985,5986
netsh adv f a r n=WinRM-Server dir=in act=allow prof=any prot=tcp localport=5985,5986 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WinRM inbound firewall rule set" -ForegroundColor white

## SSH 
# netsh adv f a r n=SSH-Client dir=out act=allow prof=any prot=tcp remoteport=22
# netsh adv f a r n=SSH-Server dir=in act=allow prof=any prot=tcp localport=22

## VNC
# netsh adv f a r n=VNC-Server-TCP dir=in act=allow prof=any prot=tcp localport=5900 | Out-Null
# netsh adv f a r n=VNC-Server-UDP dir=in act=allow prof=any prot=udp localport=5900 | Out-Null
# Write-Host "[INFO] VNC inbound rules set"

# Uncommon Services
## LDAP
# netsh adv f a r n=LDAP-Client dir=out act=allow prof=any prot=tcp remoteport=389
# netsh adv f a r n=LDAP-Server dir=in act=allow prof=any prot=tcp localport=389

## SMB
# netsh adv f a r n=SMB-Client dir=out act=allow prof=any prot=tcp remoteport=445
# netsh adv f a r n=SMB-Server dir=in act=allow prof=any prot=tcp localport=445

## DHCP 
# netsh adv f a r n=DHCP-Client dir=out act=allow prof=any prot=udp remoteport=67,68
# netsh adv f a r n=DHCP-Server dir=in act=allow prof=any prot=udp localport=67,68

## S(FTP)
# netsh adv f a r n=FTP-Client dir=out act=allow prof=any prot=tcp remoteport=20,21
# netsh adv f a r n=SFTP-Client dir=out act=allow prof=any prot=tcp remoteport=22
# netsh adv f a r n=FTP-Server dir=in act=allow prof=any prot=tcp localport=20,21
# netsh adv f a r n=SFTP-Server dir=in act=allow prof=any prot=tcp localport=22

## OpenVPN
# netsh adv f a r n=OpenVPN-Client-UDP dir=out act=allow prof=any prot=udp remoteport=1194
# netsh adv f a r n=OpenVPN-Client-TCP dir=out act=allow prof=any prot=tcp remoteport=443
# netsh adv f a r n=OpenVPN-Server-UDP dir=in act=allow prof=any prot=udp localport=1194
# netsh adv f a r n=OpenVPN-Server-TCP dir=in act=allow prof=any prot=tcp localport=443

## Hyper-V VM Console
# netsh adv f a r n=Hyper-V-Client dir=out act=allow prof=any prot=tcp remoteport=2179
# netsh adv f a r n=Hyper-V-Server dir=in act=allow prof=any prot=tcp localport=2179

## SMTP(S)
# netsh adv f a r n=SMTP-Client dir=out act=allow prof=any prot=tcp remoteport=25
# netsh adv f a r n=SMTPS-Client dir=out act=allow prof=any prot=tcp remoteport=465,587
# netsh adv f a r n=SMTP-Server dir=out act=allow prof=any prot=tcp localport=25
# netsh adv f a r n=SMTPS-Server dir=out act=allow prof=any prot=tcp localport=465,587

## IMAP
# netsh adv f a r n=IMAP-Client dir=out act=allow prof=any prot=tcp remoteport=143
# netsh adv f a r n=IMAPS-Client dir=out act=allow prof=any prot=tcp remoteport=993
# netsh adv f a r n=IMAP-Server dir=in act=allow prof=any prot=tcp localport=143
# netsh adv f a r n=IMAPS-Server dir=in act=allow prof=any prot=tcp localport=993

## POP3
# netsh adv f a r n=POP3-Client dir=out act=allow prof=any prot=tcp remoteport=110
# netsh adv f a r n=POP3S-Client dir=out act=allow prof=any prot=tcp remoteport=995
# netsh adv f a r n=POP3-Server dir=in act=allow prof=any prot=tcp localport=110
# netsh adv f a r n=POP3S-Server dir=in act=allow prof=any prot=tcp localport=995

# Logging Protocols
## Wazuh 
netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteport=1514 | Out-Null
### Temporary rule to allow enrollment of an agent
netsh adv f a r n=Wazuh-Agent-Enrollment dir=out prof=any prot=tcp remoteport=1515 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh firewall rules set" -ForegroundColor white

## Pandora 
# netsh adv f a r n=Pandora-Client dir=out act=allow prof=any prot=tcp remoteport=41121
# netsh adv f a r n=Pandora-Server dir=in act=allow prof=any prot=tcp localport=41121

## Syslog
# netsh adv f a r n=Syslog-Client dir=out act=allow prof=any prot=udp remoteport=514
# netsh adv f a r n=Syslog-Server dir=in act=allow prof=any prot=udp localport=514

# blocking win32/64 lolbins from making network connections when they shouldn't
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null 
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null

# Logic to add all fw rules to group for WFC
Get-NetFirewallRule -All | ForEach-Object {$_.Group = 'bingus'; $_ | Set-NetFirewallRule}

# Turn on firewall and default block
netsh advfirewall set allprofiles state on | Out-Null
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Firewall on, set to block for all inbound and outbound traffic" -ForegroundColor white

# Lockout prevention
if ($EnableLockoutPrevention) {
    timeout 60
    netsh advfirewall set allprofiles state off
}
#Chandi Fortnite