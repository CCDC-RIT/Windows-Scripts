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
netsh adv firewall a r n=”PingIn” dir=in act=allow prof=any prot=icmpv4:8,any 
netsh adv firewall a r n=”PingOut” dir=out act=allow prof=any prot=icmpv4:8,any 

:: Delete this rule when not needed
:: HTTP(S) Client (to access web)
netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443

:: Add more rules here

:: Turn on firewall and default block
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

:: Lockout prevention
timeout 5
netsh advfirewall set allprofiles state off
