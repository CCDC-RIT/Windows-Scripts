# Parameter for enabling/disabling lockout prevention
param(
    [Parameter(Mandatory=$true)]
    [bool]$LockoutPrevention,
    [Parameter(Mandatory=$false)]
    [array]$extrarules,
    [Parameter(Mandatory=$false)]
    [string]$ansibleIP="any",
    [Parameter(Mandatory=$false)]
    [string]$wazuhIP="any",
    [Parameter(Mandatory=$false)]
    [array]$scoringIP = @("protocol","0.0.0.0")
)

if (!((Get-Service -Name "MpsSvc").Status -eq "Running")) {
    Start-Service -Name MpsSvc
    Write-Host "[INFO] Windows Defender Firewall service started"
}

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
    $toolInstallPath = Join-Path -Path $currentDir -ChildPath "installers\wfcinstall"
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

# All possible ports needed to be allowed through firewall for various services/scorechecks
# Determined by $extrarules parameter

# This array contains all of the possible services that we would want to allow in the firewall, along with what protocol and ports they use
$protocolArray = @(
    [pscustomobject]@{Service="icmp";Protocol="none";Ports="none"}
    [pscustomobject]@{Service="http";Protocol="tcp";Ports="80,443"}
    [pscustomobject]@{Service="rdp";Protocol="both";Ports="3389"}
    [pscustomobject]@{Service="winrm";Protocol="tcp";Ports="5985,5986"}
    [pscustomobject]@{Service="ssh";Protocol="tcp";Ports="22"}
    [pscustomobject]@{Service="vnc";Protocol="both";Ports="5900"}
    [pscustomobject]@{Service="ldap";Protocol="tcp";Ports="389"}
    [pscustomobject]@{Service="smb";Protocol="tcp";Ports="445"}
    [pscustomobject]@{Service="dhcp";Protocol="udp";Ports="67,68"}
    [pscustomobject]@{Service="ftp";Protocol="tcp";Ports="20,21"}
    [pscustomobject]@{Service="sftp";Protocol="tcp";Ports="22"}
    [pscustomobject]@{Service="openvpn";Protocol="udp";Ports="1194"}
    [pscustomobject]@{Service="hyperv";Protocol="tcp";Ports="2179"}
    [pscustomobject]@{Service="smtp";Protocol="tcp";Ports="25"}
    [pscustomobject]@{Service="smtps";Protocol="tcp";Ports="465,587"}
    [pscustomobject]@{Service="imap";Protocol="tcp";Ports="143"}
    [pscustomobject]@{Service="imaps";Protocol="tcp";Ports="993"}
    [pscustomobject]@{Service="pop3";Protocol="tcp";Ports="110"}
    [pscustomobject]@{Service="pop3s";Protocol="tcp";Ports="995"}
    [pscustomobject]@{Service="pandora";Protocol="tcp";Ports="41121"}
    [pscustomobject]@{Service="syslog";Protocol="udp";Ports="514"}

)
if($extrarules.count -ne 0){
    foreach($rule in $extrarules){
        # in, out, or both
        $direction = "both"
        $service = ""
        # The if/else statement below determines if the extra rule is meant as inbound/outbound, and for what protocol
        if($rule[-1] -eq "i"){
            $direction = "in"
            $service = $rule.substring(0,$rule.length-1)
        }
        elseif($rule[-1] -eq "o"){
            if($rule[$rule.length-2] -eq "i"){
                $direction = "both"
                $service = $rule.substring(0,$rule.length-2)
            }
            else{
                $direction = "out"
                $service = $rule.substring(0,$rule.length-1)
            }
        }
        $service = $service.toLower()

        $ruleObject = ($protocolArray | Where-Object {$_.Service -eq $service})

        if($ruleObject.Service -eq "icmp"){
            # Is the service ICMP? Logic is different because ICMP is only layers 1-3, no ports are used
            
            if($direction -eq "both"){
                netsh adv f a r n=ICMP-In dir=in act=allow prof=any prot=icmpv4:8,any | Out-Null
                netsh adv f a r n=ICMP-Out dir=out act=allow prof=any prot=icmpv4:8,any | Out-Null
            }
            else{
                $name = "ICMP-" + $direction
                netsh adv f a r n=$name dir=$direction act=allow prof=any prot=icmpv4:8,any | Out-Null
            }
        }
        else{
            # All other Services possible

            if($direction -eq "both"){
                # rule should be applied both inbound and outbound

                $nameServer = $service.toUpper() + "-Server"
                $nameClient = $service.toUpper() + "-Client"

                if($ruleObject.protocol -eq "both"){
                    # Rule should be applied for both tcp and udp ports

                    $tcpNameServer = $nameServer + "-TCP"
                    $tcpNameClient = $nameServer + "-TCP"
                    $udpNameServer = $nameServer + "-TCP"
                    $udpNameClient = $nameServer + "-UDP"

                    netsh adv f a r n=$tcpNameServer dir=in act=allow prof=any prot=tcp localport=($ruleObject.Ports) | Out-Null
                    netsh adv f a r n=$tcpNameClient dir=out act=allow prof=any prot=tcp remoteport=($ruleObject.Ports) | Out-Null
                    netsh adv f a r n=$udpNameServer dir=in act=allow prof=any prot=udp localport=($ruleObject.Ports) | Out-Null
                    netsh adv f a r n=$udpNameClient dir=out act=allow prof=any prot=udp remoteport=($ruleObject.Ports) | Out-Null
                }
                else{
                    # Rule is only tcp or udp

                    netsh adv f a r n=$nameServer dir=in act=allow prof=any prot=($ruleObject.Protocol) localport=($ruleObject.Ports) | Out-Null
                    netsh adv f a r n=$nameClient dir=out act=allow prof=any prot=($ruleObject.Protocol) remoteport=($ruleObject.Ports) | Out-Null
                }

                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] " -ForegroundColor White -NoNewLine; Write-Host $service.ToUpper() -NoNewLine; Write-Host " firewall rules set" 
            }
            else{
                # Rule should only be applied one way
                
                $name = $service.toUpper() + "-" + $direction.toUpper()
                if($ruleObject.protocol -eq "both"){
                    # Rule should be applied for both tcp and udp ports
                    $tcpName = $name + "-TCP"
                    $udpName = $name + "-UDP"
                    
                    if($direction -eq "in"){
                        netsh adv f a r n=$tcpName dir=$direction act=allow prof=any prot=tcp localport=($ruleObject.Ports) | Out-Null
                        netsh adv f a r n=$udpName dir=$direction act=allow prof=any prot=udp localport=($ruleObject.Ports) | Out-Null
                    }
                    else{
                        netsh adv f a r n=$tcpName dir=$direction act=allow prof=any prot=tcp remoteport=($ruleObject.Ports) | Out-Null
                        netsh adv f a r n=$udpName dir=$direction act=allow prof=any prot=udp remoteport=($ruleObject.Ports) | Out-Null
                    }
                }
                else{
                    # Rule is only tcp or udp

                    if($direction -eq "in"){
                        netsh adv f a r n=$name dir=$direction act=allow prof=any prot=($ruleObject.Protocol) localport=($ruleObject.Ports) | Out-Null
                    }
                    else{
                        netsh adv f a r n=$name dir=$direction act=allow prof=any prot=($ruleObject.Protocol) remoteport=($ruleObject.Ports) | Out-Null
                    }
                }
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] " -ForegroundColor White -NoNewLine; Write-Host $service.ToUpper() -NoNewLine; Write-Host " " -NoNewLine; Write-Host $direction -NoNewline; Write-Host "bound firewall rules set"
            }
        }
    }
}

if($extrarules.count -ne 0){
    switch -exact ($extrarules){
        "icmpi" {
            ## ICMP/Ping inbound
            netsh adv f a r n=ICMP-In dir=in act=allow prof=any prot=icmpv4:8,any | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ICMP inbound firewall rules set" -ForegroundColor white 
        }
        "icmpo" {
            ## ICMP/Ping outbound
            netsh adv f a r n=ICMP-In dir=out act=allow prof=any prot=icmpv4:8,any | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ICMP outbound firewall rules set" -ForegroundColor white 
        }
        "icmpio" {
            ## ICMP/Ping
            netsh adv f a r n=ICMP-In dir=in act=allow prof=any prot=icmpv4:8,any | Out-Null
            netsh adv f a r n=ICMP-Out dir=out act=allow prof=any prot=icmpv4:8,any | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ICMP firewall rules set" -ForegroundColor white 
        }
        "httpi" {
            ## HTTP(S) inbound (might have to open server for CA)
            netsh adv f a r n=HTTP-Server dir=in act=allow prof=any prot=tcp localport=80,443 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] HTTP(S) inbound firewall rules set" -ForegroundColor white 
        }
        "httpo" {
            ## HTTP(S) outbound(might have to open server for CA)
            netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] HTTP(S) outbound firewall rules set" -ForegroundColor white 
        }
        "httpio" {
            ## HTTP(S) outbound(might have to open server for CA)
            netsh adv f a r n=HTTP-Server dir=in act=allow prof=any prot=tcp localport=80,443 | Out-Null
            netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] HTTP(S) firewall rules set" -ForegroundColor white 
        }
        # remoting services
        "rdpo" {
            # RDP out
            netsh adv f a r n=RDP-TCP-Client dir=out act=allow prof=any prot=tcp remoteport=3389 | Out-Null
            netsh adv f a r n=RDP-UDP-Client dir=out act=allow prof=any prot=udp remoteport=3389 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] RDP outbound firewall rules set" -ForegroundColor white
        }
        "winrmo" {
            # WinRM out
            netsh adv f a r n=WinRM-Client dir=out act=allow prof=any prot=tcp remoteport=5985,5986 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WinRM outbound firewall rules set" -ForegroundColor white
        }
        "sshi" {
            # SSH inbound
            netsh adv f a r n=SSH-Server dir=in act=allow prof=any prot=tcp localport=22 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SSH inbound firewall rules set" -ForegroundColor white
        }
        "ssho" {
            # SSH outbound
            netsh adv f a r n=SSH-Client dir=out act=allow prof=any prot=tcp remoteport=22 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SSH outbound firewall rules set" -ForegroundColor white
        }
        "sshio" {
            # SSH
            netsh adv f a r n=SSH-Client dir=out act=allow prof=any prot=tcp remoteport=22 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SSH firewall rules set" -ForegroundColor white
        }
        "vnci" {
            # VNC in
            netsh adv f a r n=VNC-Server-TCP dir=in act=allow prof=any prot=tcp localport=5900 | Out-Null
            netsh adv f a r n=VNC-Server-UDP dir=in act=allow prof=any prot=udp localport=5900 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] VNC inbound firewall rules set" -ForegroundColor white
        }
        #Uncommon Services
        "ldapi" {
            # LDAP in
            netsh adv f a r n=LDAP-Server dir=in act=allow prof=any prot=tcp localport=389 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LDAP inbound firewall rules set" -ForegroundColor white
        }
        "ldapo" {
            # LDAP out
            netsh adv f a r n=LDAP-Client dir=out act=allow prof=any prot=tcp remoteport=389 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LDAP outbound firewall rules set" -ForegroundColor white
        }
        "ldapio" {
            # LDAP
            netsh adv f a r n=LDAP-Server dir=in act=allow prof=any prot=tcp localport=389 | Out-Null
            netsh adv f a r n=LDAP-Client dir=out act=allow prof=any prot=tcp remoteport=389 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LDAP firewall rules set" -ForegroundColor white
        }
        "smbi" {
            # SMB in
            netsh adv f a r n=SMB-Server dir=in act=allow prof=any prot=tcp localport=445 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SMB inbound firewall rules set" -ForegroundColor white
        }
        "smbo" {
            # SMB out
            netsh adv f a r n=SMB-Client dir=out act=allow prof=any prot=tcp remoteport=445 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SMB outbound firewall rules set" -ForegroundColor white
        }
        "smbio" {
            # SMB
            netsh adv f a r n=SMB-Client dir=out act=allow prof=any prot=tcp remoteport=445 | Out-Null
            netsh adv f a r n=SMB-Server dir=in act=allow prof=any prot=tcp localport=445 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SMB firewall rules set" -ForegroundColor white
        }
        "dhcpi" {
            # DHCP in
            netsh adv f a r n=DHCP-Server dir=in act=allow prof=any prot=udp localport=67,68 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DHCP inbound firewall rules set" -ForegroundColor white
        }
        "dhcpo" {
            # DHCP out
            netsh adv f a r n=DHCP-Client dir=out act=allow prof=any prot=udp remoteport=67,68 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DHCP outbound firewall rules set" -ForegroundColor white
        }
        "dhcpio" {
            # DHCP
            netsh adv f a r n=DHCP-Client dir=out act=allow prof=any prot=udp remoteport=67,68 | Out-Null
            netsh adv f a r n=DHCP-Server dir=in act=allow prof=any prot=udp localport=67,68 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DHCP firewall rules set" -ForegroundColor white
        }
        "ftpi" {
            # S(FTP) in
            netsh adv f a r n=FTP-Server dir=in act=allow prof=any prot=tcp localport=20,21 | Out-Null
            netsh adv f a r n=SFTP-Server dir=in act=allow prof=any prot=tcp localport=22 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] S(FTP) inbound firewall rules set" -ForegroundColor white
        }
        "ftpo" {
            # S(FTP) out
            netsh adv f a r n=FTP-Client dir=out act=allow prof=any prot=tcp remoteport=20,21 | Out-Null
            netsh adv f a r n=SFTP-Client dir=out act=allow prof=any prot=tcp remoteport=22 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] S(FTP) outbound firewall rules set" -ForegroundColor white
        }
        "ftpio" {
            # S(FTP)
            netsh adv f a r n=FTP-Client dir=out act=allow prof=any prot=tcp remoteport=20,21 | Out-Null
            netsh adv f a r n=SFTP-Client dir=out act=allow prof=any prot=tcp remoteport=22 | Out-Null
            netsh adv f a r n=FTP-Server dir=in act=allow prof=any prot=tcp localport=20,21 | Out-Null
            netsh adv f a r n=SFTP-Server dir=in act=allow prof=any prot=tcp localport=22 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] S(FTP) firewall rules set" -ForegroundColor white
        }
        "openvpni" {
            # OpenVPN in
            netsh adv f a r n=OpenVPN-Server-UDP dir=in act=allow prof=any prot=udp localport=1194 | Out-Null
            netsh adv f a r n=OpenVPN-Server-TCP dir=in act=allow prof=any prot=tcp localport=443 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] OpenVPN inbound firewall rules set" -ForegroundColor white
        }
        "openvpno" {
            # OpenVPN out
            netsh adv f a r n=OpenVPN-Client-UDP dir=out act=allow prof=any prot=udp remoteport=1194 | Out-Null
            netsh adv f a r n=OpenVPN-Client-TCP dir=out act=allow prof=any prot=tcp remoteport=443 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] OpenVPN outbound firewall rules set" -ForegroundColor white
        }
        "openvpnio" {
            # OpenVPN
            netsh adv f a r n=OpenVPN-Client-UDP dir=out act=allow prof=any prot=udp remoteport=1194 | Out-Null
            netsh adv f a r n=OpenVPN-Client-TCP dir=out act=allow prof=any prot=tcp remoteport=443 | Out-Null
            netsh adv f a r n=OpenVPN-Server-UDP dir=in act=allow prof=any prot=udp localport=1194 | Out-Null
            netsh adv f a r n=OpenVPN-Server-TCP dir=in act=allow prof=any prot=tcp localport=443 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] OpenVPN firewall rules set" -ForegroundColor white
        }
        "hypervi" {
            # Hyper-V VM Console in
            netsh adv f a r n=Hyper-V-Server dir=in act=allow prof=any prot=tcp localport=2179 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hyper-V VM Console inbound firewall rules set" -ForegroundColor white
        }
        "hypervo" {
            # Hyper-V VM Console out
            netsh adv f a r n=Hyper-V-Client dir=out act=allow prof=any prot=tcp remoteport=2179 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hyper-V VM Console outbound firewall rules set" -ForegroundColor white
        }
        "hypervio" {
            # Hyper-V VM Console
            netsh adv f a r n=Hyper-V-Client dir=out act=allow prof=any prot=tcp remoteport=2179 | Out-Null
            netsh adv f a r n=Hyper-V-Server dir=in act=allow prof=any prot=tcp localport=2179 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hyper-V VM Console firewall rules set" -ForegroundColor white
        }
        "smtpi" {
            # SMTP(S) in
            netsh adv f a r n=SMTP-Server dir=in act=allow prof=any prot=tcp localport=25 | Out-Null
            netsh adv f a r n=SMTPS-Server dir=in act=allow prof=any prot=tcp localport=465,587 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SMTP(S) inbound firewall rules set" -ForegroundColor white
        }
        "smtpo" {
            # SMTP(S) out
            netsh adv f a r n=SMTP-Client dir=out act=allow prof=any prot=tcp remoteport=25 | Out-Null
            netsh adv f a r n=SMTPS-Client dir=out act=allow prof=any prot=tcp remoteport=465,587 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SMTP(S) outbound firewall rules set" -ForegroundColor white
        }
        "smtpio" {
            # SMTP(S)
            netsh adv f a r n=SMTP-Client dir=out act=allow prof=any prot=tcp remoteport=25 | Out-Null
            netsh adv f a r n=SMTPS-Client dir=out act=allow prof=any prot=tcp remoteport=465,587 | Out-Null
            netsh adv f a r n=SMTP-Server dir=in act=allow prof=any prot=tcp localport=25 | Out-Null
            netsh adv f a r n=SMTPS-Server dir=in act=allow prof=any prot=tcp localport=465,587 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SMTP(S) firewall rules set" -ForegroundColor white
        }
        "imapi" {
            # IMAP in
            netsh adv f a r n=IMAP-Server dir=in act=allow prof=any prot=tcp localport=143 | Out-Null
            netsh adv f a r n=IMAPS-Server dir=in act=allow prof=any prot=tcp localport=993 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] IMAP inbound firewall rules set" -ForegroundColor white
        }
        "imapo" {
            # IMAP out
            netsh adv f a r n=IMAP-Client dir=out act=allow prof=any prot=tcp remoteport=143 | Out-Null
            netsh adv f a r n=IMAPS-Client dir=out act=allow prof=any prot=tcp remoteport=993 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] IMAP outbound firewall rules set" -ForegroundColor white
        }
        "imapio" {
            # IMAP
            netsh adv f a r n=IMAP-Client dir=out act=allow prof=any prot=tcp remoteport=143 | Out-Null
            netsh adv f a r n=IMAPS-Client dir=out act=allow prof=any prot=tcp remoteport=993 | Out-Null
            netsh adv f a r n=IMAP-Server dir=in act=allow prof=any prot=tcp localport=143 | Out-Null
            netsh adv f a r n=IMAPS-Server dir=in act=allow prof=any prot=tcp localport=993 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] IMAP firewall rules set" -ForegroundColor white
        }
        "pop3i" {
            ## POP3 in
            netsh adv f a r n=POP3-Server dir=in act=allow prof=any prot=tcp localport=110 | Out-Null
            netsh adv f a r n=POP3S-Server dir=in act=allow prof=any prot=tcp localport=995 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] POP3 inbound firewall rules set" -ForegroundColor white
        }
        "pop3o" {
            ## POP3 out
            netsh adv f a r n=POP3-Client dir=out act=allow prof=any prot=tcp remoteport=110 | Out-Null
            netsh adv f a r n=POP3S-Client dir=out act=allow prof=any prot=tcp remoteport=995 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] POP3 outbound firewall rules set" -ForegroundColor white
        }
        "pop3io" {
            ## POP3
            netsh adv f a r n=POP3-Client dir=out act=allow prof=any prot=tcp remoteport=110 | Out-Null
            netsh adv f a r n=POP3S-Client dir=out act=allow prof=any prot=tcp remoteport=995 | Out-Null
            netsh adv f a r n=POP3-Server dir=in act=allow prof=any prot=tcp localport=110 | Out-Null
            netsh adv f a r n=POP3S-Server dir=in act=allow prof=any prot=tcp localport=995 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] POP3 firewall rules set" -ForegroundColor white
        }
        "pandorai" {
            # Pandora in
            netsh adv f a r n=Pandora-Server dir=in act=allow prof=any prot=tcp localport=41121 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Pandora inbound firewall rules set" -ForegroundColor white
        }
        #logging
        "pandorao" {
            # Pandora out 
            netsh adv f a r n=Pandora-Client dir=out act=allow prof=any prot=tcp remoteport=41121 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Pandora outbound firewall rules set" -ForegroundColor white
        }
        "pandoraio" {
            # Pandora 
            netsh adv f a r n=Pandora-Client dir=out act=allow prof=any prot=tcp remoteport=41121 | Out-Null
            netsh adv f a r n=Pandora-Server dir=in act=allow prof=any prot=tcp localport=41121 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Pandora firewall rules set" -ForegroundColor white
        }
        "syslogi" {
            # Syslog in
            netsh adv f a r n=Syslog-Server dir=in act=allow prof=any prot=udp localport=514 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysLog inbound firewall rules set" -ForegroundColor white
        }
        "syslogo" {
            # Syslog out
            netsh adv f a r n=Syslog-Client dir=out act=allow prof=any prot=udp remoteport=514 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysLog outbound firewall rules set" -ForegroundColor white
        }
        "syslogio" {
            # Syslog
            netsh adv f a r n=Syslog-Client dir=out act=allow prof=any prot=udp remoteport=514 | Out-Null
            netsh adv f a r n=Syslog-Server dir=in act=allow prof=any prot=udp localport=514 | Out-Null
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysLog firewall rules set" -ForegroundColor white
        }
    }
}
# Remoting Protocols

## RDP in
netsh adv f a r n=RDP-TCP-Server dir=in act=allow prof=any prot=tcp localport=3389 | Out-Null
netsh adv f a r n=RDP-UDP-Server dir=in act=allow prof=any prot=udp localport=3389 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] RDP inbound firewall rules set" -ForegroundColor white

## WinRM
netsh adv f a r n=WinRM-Server dir=in act=allow prof=any prot=tcp remoteip=$ansibleIP localport=5985,5986 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WinRM inbound firewall rule set" -ForegroundColor white

# Logging Protocols
## Wazuh 
netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteip=$wazuhIP remoteport=1514 | Out-Null
if($wazuhIP -ne "Any"){
    netsh adv f a r n=Wazuh-HTTP-Dashboard dir=out act=allow prof=any prot=tcp remoteip=$wazuhIP remoteport=80,443 | Out-Null
}
### Temporary rule to allow enrollment of an agent
netsh adv f a r n=Wazuh-Agent-Enrollment dir=out prof=any prot=tcp removeip=$wazuhIP remoteport=1515 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh firewall rules set" -ForegroundColor white


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
if ($LockoutPrevention) {
    timeout 60
    netsh advfirewall set allprofiles state off
}
#Chandi Fortnite