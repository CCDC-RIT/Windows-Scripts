:: Delete all rules
netsh advfirewall set allprofiles state off
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound
netsh advfirewall firewall delete rule name=all

:: Configure logging
netsh advfirewall set allprofiles logging filename C:\Windows\fw.log
netsh advfirewall set allprofiles logging maxfilesize 32676
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable

:: ICMP/Ping
netsh adv f a r n=PingIn dir=in act=allow prof=any prot=icmpv4:8,any 

netsh adv f a r n=PingOut dir=out act=allow prof=any prot=icmpv4:8,any 

:: Delete this rule when not needed
:: HTTP(S) Client (to access web)
netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443

:: Remoting Protocols
:: RDP
netsh adv f a r n=RDP-TCP-Client dir=out act=allow prof=any prot=tcp remoteport=3389 
netsh adv f a r n=RDP-UDP-Client dir=out act=allow prof=any prot=udp remoteport=3389 

netsh adv f a r n=RDP-TCP-Server dir=in act=allow prof=any prot=tcp localport=3389 
netsh adv f a r n=RDP-UDP-Server dir=in act=allow prof=any prot=udp localport=3389 

:: WinRM
netsh adv f a r n=WinRM-Client dir=out act=allow prof=any prot=tcp remoteport=5985,5986

netsh adv f a r n=WinRM-Server dir=in act=allow prof=any prot=tcp localport=5985,5986

:: SSH 
netsh adv f a r n=SSH-Client dir=out act=allow prof=any prot=tcp remoteport=22

netsh adv f a r n=SSH-Server dir=in act=allow prof=any prot=tcp localport=22

:: Common Scored Services
:: HTTP(S)
netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443

netsh adv f a r n=HTTP-Server dir=in act=allow prof=any prot=tcp localport=80,443

:: DNS 
netsh adv f a r n=DNS-Client dir=out act=allow prof=any prot=udp remoteport=53

netsh adv f a r n=DNS-Server dir=in act=allow prof=any prot=udp localport=53

:: LDAP
netsh adv f a r n=LDAP-Client dir=out act=allow prof=any prot=tcp remoteport=389

netsh adv f a r n=LDAP-Server dir=in act=allow prof=any prot=tcp localport=389

:: Uncommon Services
:: ICMP 
netsh adv f a r n=ICMP-In dir=in act=allow prof=any prot=icmpv4:8,any 

netsh adv f a r n=ICMP-Out dir=out act=allow prof=any prot=icmpv4:8,any 

:: SMB
netsh adv f a r n=SMB-Client dir=out act=allow prof=any prot=tcp remoteport=445

netsh adv f a r n=SMB-Server dir=in act=allow prof=any prot=tcp localport=445

:: Certificate Authority 
netsh adv f a r n=CA-Client dir=out act=allow prof=any prot=tcp remoteport=135

netsh adv f a r n=CA-Server dir=in act=allow prof=any prot=tcp localport=135

:: DHCP 
netsh adv f a r n=DHCP-Client dir=out act=allow prof=any prot=udp remoteport=67,68

netsh adv f a r n=DHCP-Server dir=in act=allow prof=any prot=udp localport=67,68

:: S(FTP)
netsh adv f a r n=FTP-Client dir=out act=allow prof=any prot=tcp remoteport=20,21
netsh adv f a r n=SFTP-Client dir=out act=allow prof=any prot=tcp remoteport=22

netsh adv f a r n=FTP-Server dir=in act=allow prof=any prot=tcp localport=20,21
netsh adv f a r n=SFTP-Server dir=in act=allow prof=any prot=tcp localport=22

:: SMTP(S)
netsh adv f a r n=SMTP-Client dir=out act=allow prof=any prot=tcp remoteport=25
netsh adv f a r n=SMTPS-Client dir=out act=allow prof=any prot=tcp remoteport=465,587

netsh adv f a r n=SMTP-Server dir=out act=allow prof=any prot=tcp localport=25
netsh adv f a r n=SMTPS-Server dir=out act=allow prof=any prot=tcp localport=465,587

:: IMAP
netsh adv f a r n=IMAP-Client dir=out act=allow prof=any prot=tcp remoteport=143
netsh adv f a r n=IMAPS-Client dir=out act=allow prof=any prot=tcp remoteport=993

netsh adv f a r n=IMAP-Server dir=in act=allow prof=any prot=tcp localport=143
netsh adv f a r n=IMAPS-Server dir=in act=allow prof=any prot=tcp localport=993

:: POP3
netsh adv f a r n=POP3-Client dir=out act=allow prof=any prot=tcp remoteport=110
netsh adv f a r n=POP3S-Client dir=out act=allow prof=any prot=tcp remoteport=995

netsh adv f a r n=POP3-Server dir=in act=allow prof=any prot=tcp localport=110
netsh adv f a r n=POP3S-Server dir=in act=allow prof=any prot=tcp localport=995

:: OpenVPN
netsh adv f a r n=OpenVPN-Client-UDP dir=out act=allow prof=any prot=udp remoteport=1194
netsh adv f a r n=OpenVPN-Client-TCP dir=out act=allow prof=any prot=tcp remoteport=443

netsh adv f a r n=OpenVPN-Server-UDP dir=in act=allow prof=any prot=udp localport=1194
netsh adv f a r n=OpenVPN-Server-TCP dir=in act=allow prof=any prot=tcp localport=443

:: Hyper-V VM Console
netsh adv f a r n=Hyper-V-Client dir=out act=allow prof=any prot=tcp remoteport=2179

netsh adv f a r n=Hyper-V-Server dir=in act=allow prof=any prot=tcp localport=2179

:: Domain Controller Rules
netsh adv f a r n=DC-TCP-In dir=in act=allow prof=any prot=tcp localport=88,135,389,445,636,3268
netsh adv f a r n=DC-UDP-In dir=in act=allow prof=any prot=udp localport=88,123,135,389,445,636
netsh adv f a r n=RPC-In dir=in act=allow prof=any prot=tcp localport=rpc
netsh adv f a r n=EPMAP-In dir=in act=allow prof=any prot=tcp localport=rpc-epmap

:: Logging Protocols
:: Wazuh 
netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteport=1514

netsh adv f a r n=Wazuh-Server dir=in act=allow prof=any prot=tcp localport=1514

:: Pandora 
netsh adv f a r n=Pandora-Client dir=out act=allow prof=any prot=tcp remoteport=41121

netsh adv f a r n=Pandora-Server dir=in act=allow prof=any prot=tcp localport=41121

:: Syslog
netsh adv f a r n=Syslog-Client dir=out act=allow prof=any prot=udp remoteport=514

netsh adv f a r n=Syslog-Server dir=in act=allow prof=any prot=udp localport=514

:: Turn on firewall and default block
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

:: Lockout prevention
timeout 5
netsh advfirewall set allprofiles state off
