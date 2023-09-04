# Objective: Gather basic information about the system

# TODO: Write to both file and terminal

# DC detection
$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Import-Module ActiveDirectory
    Write-Host "[INFO] Domain Controller detected"
}

# IIS detection
$IIS = $false
if (Get-Service -Name W3SVC) {
    $IIS = $true
    Import-Module WebAdministration
    Import-Module IISAdministration
    Write-Host "[INFO] IIS detected"
}

# CA detection
$CA = $false
if (Get-Service -Name CertSvc) {
    $CA = $true
    Import-Module ADCSAdministration
    Write-Host "[INFO] CA detected"
}

# Hostname, domain
Get-CimInstance -Class Win32_ComputerSystem | Format-Table Name, Domain

# Operating System information
Get-CimInstance -Class Win32_OperatingSystem | Format-Table Caption, Version, ServicePackMajorVersion, OSArchitecture, WindowsDirectory

# MAC address, IP address, Subnet mask, Default gateway
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | Format-Table ServiceName, MACAddress, IPAddress, IPSubnet, DefaultIPGateway

# DNS Servers
Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Select-Object -expand ifindex) | Format-Table InterfaceAlias, ServerAddresses 

# Network connections/listening ports
Get-NetTCPConnection -State Listen,Established -ErrorAction "SilentlyContinue" | Sort-Object state,localport | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,@{'Name'='CommandLine';'Expression'={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | Format-Table -AutoSize

# Listing all users
Get-CimInstance -Class Win32_UserAccount | Format-Table Name, Domain

# Listing group membership
if ($DC) { ## Domain groups
    $Groups = Get-ADGroup -Filter 'SamAccountName -NotLike "Domain Users"' | Select-Object -ExpandProperty name
    $Groups | ForEach-Object {
        $Users = Get-ADGroupMember -Identity $_ | Format-Table name, objectclass
        if ($Users.Count -gt 0) {
            # must be Write-Output
            Write-Output "Group: $_"
            Write-Output "$Users"
        }
    }
} else { # Local groups
    $Groups = Get-LocalGroup | Select-Object -ExpandProperty Name
    $Groups | ForEach-Object {
        # Get-LocalGroupMember is unreliable
        $Users = net localgroup $_ | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -Skip 4
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Output "Group: $_"
            Write-Output "`nname"
            Write-Output "----"
            Write-Output "$Users`n"
        }
    }
}

# If IIS, site bindings
if ($IIS) {
    Write-Output "#### IIS Site Bindings ####"
    $websites = Get-ChildItem IIS:\Sites | Sort-Object name

    foreach ($site in $websites) {
        Write-Output "Website Name: $($site.Name)"
        $bindings = Get-WebBinding -Name $site.name
        foreach ($binding in $bindings) {
            Write-Output "    Binding Information:"
            Write-Output "        Protocol: $($binding.protocol)"
            Write-Output "        IP Address: $($binding.bindingInformation.split(":")[0])"
            Write-Output "        Port: $($binding.bindingInformation.split(":")[1])"
            Write-Output "        Hostname: $($binding.hostHeader)"
        }
        Write-Output ""
    }
}

# If CA, list certificates?