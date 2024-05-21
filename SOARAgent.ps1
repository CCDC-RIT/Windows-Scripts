# RIT CCDC Security Orchestration and Automated Response tool

# Built to run on every windows machine in a domain. All alerts are sent to the local machine,
# where the user operating the machine will have the option to take action or not. 


$currentDir = (($MyInvocation.MyCommand.Path).Substring(0,($MyInvocation.MyCommand.Path).IndexOf("SOARAgent.ps1")))
$auditResultsPath = Join-Path -Path $currentDir -ChildPath "results"

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-output "[INFO] Domain Controller detected"
}

$IIS = $false
if (Get-Service -Name W3SVC 2>$null) {
    $IIS = $true
    Write-output "[INFO] IIS Server detected"
}

$CA = $false
if (Get-Service -Name CertSvc 2>$null) {
    $CA = $true
    Write-output "[INFO] Certificate Authority detected"
}

[array]$goodusers = "Administrator","Guest","WDAGUtilityAccount","DefaultAccount","cucumber"
if($DC){
    $goodusers += "krbtgt"
}
elseif($IIS){
    $goodusers += "IUSR"
}

function runDefenderScan{
    start-mpscan -scantype QuickScan
    Get-MpThreatDetection
    #prompt if we should delete or not
    remove-mpthreat
}

# This function goes through the current list of local users, and checks against a predetermined list to see if they are potentially malicious or not. 
# User is then given the option to disable the user, do nothing, or add them to the predetermined list if they.
function auditLocalUsers{
    [array]$users = Get-LocalUser
    
    foreach($user in $users){
        if($user.enabled){
            if(!($user.Name -in $goodusers)){
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Unauthorized user " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor Red -NoNewLine; Write-Host " detected" -ForegroundColor white 
                $answer = Read-Host "Take Action? [yes/no/add (adds user to authorized user list)]"
                
                if($answer -ieq "yes"){
                    Disable-LocalUser $user
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Unauthorized user " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor Red -NoNewLine; Write-Host " removed" -ForegroundColor white 
                }
                elseif($answer -ieq "add"){
                    $goodusers += $user.Name
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user -ForegroundColor Rreen -NoNewLine; Write-Host " is now authorized" -ForegroundColor white 
                }
            }
        }
    }
}

# All of the authorized users for the highly privileged AD groups
$authorizedEnterpriseAdmins = "black-team","blackteam"
$authorizedSchemaAdmins = "black-team","blackteam"
$authorizedDnsAdmins = "black-team","blackteam"

$authorizedPrivilegedGroups = $authorizedEnterpriseAdmins, $authorizedSchemaAdmins, $authorizedDnsAdmins

Function auditDomainUsers {
    # This function finds all of the members of the Enterprise Admins, Schema Admins, and DNS Admins. 
    # The user operating the Domain controller an then remove users from these accounts as they see
    # fit to follow the principle of least privilege
    $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins"
    $schemaAdmins = Get-ADGroupMember -Identity "Schema Admins"
    $dnsAdmins = Get-ADGroupMember -Identity "DnsAdmins"

    $privilegedGroups = $enterpriseAdmins, $schemaAdmins, $dnsAdmins

    $i = 0
    foreach($group in $privilegedGroups){
        $i++
        foreach($user in $group){
            if(!($user.name -in $authorizedPrivilegedGroups[$i])){
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor white -NoNewLine; Write-Host " is a member of " -ForegroundColor white -NoNewline; Write-Host $group.Name -ForegroundColor White
                $answer = Read-Host "Remove from group? [yes/no/add (adds user to authorized user list)]"

                if($answer -ieq "yes"){
                    Remove-ADGroupMember -Identity $group.Name -Members $user.Name -Confirm:$false
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor White -NoNewLine; Write-Host " removed from " -ForegroundColor white -NoNewline; Write-Host $group.Name -ForegroundColor White 
                }
                elseif($answer -ieq "add"){
                    $authorizedPrivilegedGroups[$i] += $user.Name
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor White -NoNewLine; Write-Host " is an authorized member of " -ForegroundColor white -NoNewline; Write-Host $group.Name -ForegroundColor
                }
            }
        }
    }
}

function checkDLLs{
    $registryAuditPath = Join-Path -Path $auditResultsPath -ChildPath "registryaudit.txt"
    # Get all of content from registryaudit.txt, which holds all of the results of the Dll's that were audited from the audit script 
    [array]$currentDLLs = Get-Content -Path $registryAuditPath
    # Whatever the current key that is being iterated over is
    [string]$currentKey = ""
    # known good dll's
    # TODO: Complete all of these lists
    [array]$goodnetshDLLs = "ifmon.dll","rasmontr.dll","authfwcfg.dll","dhcpmonitor.dll","dot3cfg.dll","fwcfg.dll","hnetmon.dll","nettrace.dll","netiohlp.dll","nshhttp.dll","nshipsec.dll","nshwfp.dll","peerdistsh.dll","rpcnsh.dll","whhelper.dll","wshelper.dll","wwancfg.dll","netprofm.dll","p2pnetsh.dll","wcnetsh.dll","wlancfg.dll"
    [array]$goodAppCertDLLs = ""
    [array]$goodAppInitDLLS = ""
    [array]$goodLsaDLLS = "{msv1_0}",""
    [array]$goodWinlogonDLLs = "explorer.exe","C:\Windows\System32\userinit.exe"
    [array]$goodLocalPortDLLs = "localspl.dll"
    [array]$goodIPPortDLLs = "tcpmon.dll"
    [array]$goodUSBMonitorDLLs = "usbmon.dll"
    [array]$goodWSDPortDLLs = "APMon.dll"
    [hashtable]$hashTable = @{"NetSh" = $goodnetshDLLs; "AppCertDLLs" = $goodAppCertDLLs; "Windows" = $goodAppInitDLLs; "Lsa" = $goodLsaDLLs; "Winlogon" = $goodWinlogonDLLs;"Local Port" = $goodLocalPortDLLs; "IP Port" = $goodIPPortDLLs; "USB Monitor" = $goodUSBMonitorDLLs; "WSD Port" = $goodWSDPortDLLs;}
    # This loop iterates through every line in the file registryaudit.txt. If the line is a registry key, then it updates the currentKey variable
    # If the current key is a key that we have a list of known good dll's for, and the line is a line that contains a dll, the dll on that line
    # is checked against the list of the known good DLL's. If it is not in the list, then an alert is triggered, and the user has the option 
    # to remove the dll. 
    foreach($line in $currentDLLs){
        $tokens = $line.split(" ")
        if($tokens[0] -ieq "key"){
            # If the line is a key, update the current key. 
            $keyTokens = $tokens.split("\")
            $currentKey = $keyTokens[-1]
        }
        elseif((!($line -eq "" -or $tokens[-1] -ieq ":")) -and $currentKey -in $hashTable.Keys){
            if(!($tokens[-1]) -in $hashTable.$currentKey){ 
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Potentially Malicious " -ForegroundColor White -NoNewline; Write-Host $currentKey -ForegroundColor White -NoNewline; Write-Host " DLL Found: " -ForegroundColor white -NoNewLine; Write-Host $tokens[-1] -ForegroundColor Red
                $answer = Read-Host "Take Action? [yes/no]"

                if($answer -ieq "yes"){
                    # Hopefully this works
                    regsvr32 /u $tokens[-1]
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Malicious DLL " -ForegroundColor white -NoNewLine; Write-Host $tokens[-1] -ForegroundColor Red -NoNewLine; Write-Host " removed" -ForegroundColor white 
                }
            }
        }
    }
}

Function removeProcessesServices{
    param(
        $ProcessID
    )

    [string]$processName = (Get-Process -Id $ProcessID).ProcessName

    # Get Service name from process
    [string]$query = "ProcessId='" + $ProcessID + "'"
    $serviceInfo = Get-WmiObject Win32_Service -Filter $query
    

    # Get path of process/service from PID
    $path = Get-process -id $ProcessID | select-object -expandproperty path

    # Inform User of the malicious process/service and ask if program should take action
    
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Malicious Process " -ForegroundColor white -NoNewLine
    Write-Host $processName -ForegroundColor Red -NoNewLine; Write-Host " with PID: " -ForegroundColor White -NoNewLine; Write-Host $ProcessID -ForegroundColor Red -NoNewLine
    if($serviceInfo){
        Write-Host " With Service Name: " -ForegroundColor White -NoNewline; Write-Host $serviceInfo.Name -ForegroundColor Red -NoNewLine
    }
    Write-Host " and Path: " -ForegroundColor White -NoNewline; Write-Host $path -ForegroundColor Red

    # Get the owner of the process, for IR purposes
    $processTable = get-process -id $ProcessID -IncludeUserName
    $processOwner = $processTable.UserName
    Write-Host "Owner of the Process is " -ForegroundColor White -NoNewline; Write-Host $processOwner -ForegroundColor Red

    $answer = Read-Host "Take Action? [yes/no]"
    
    if($answer -ieq "yes"){
        Stop-Process -ID $ProcessID -Force
        if($serviceInfo){
            stop-service -Name $serviceInfo.Name -Force
            if($PSVersionTable.PSVersion.Major -ge 6){
                # if powershell is version 6 or up
                remove-service -name $serviceInfo.Name -Force
            }
        }
        Remove-Item -path $path
        if(!(Test-Path -LiteralPath $path)){
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Process/Service " -ForegroundColor white -NoNewLine; 
            Write-Host $process -ForegroundColor Red -NoNewLine; Write-Host " with PID: " -ForegroundColor White -NoNewline; Write-Host $ProcessID -ForegroundColor Red -NoNewline; Write-Host " removed" -ForegroundColor white 
        }
    }
}

Function checkProcessesServices {
    $processAuditPath = Join-Path -Path $auditResultsPath -ChildPath "processaudit.txt"

    # Removing processes deemed to be suspicious by hollows hunter

    # Hopefully there shouldn't be more than 40 suspicious processes found by hollos hunter
    [array]$hollowsHunterProcesses = Get-content $processAuditPath -Tail 40

    # Iterate through all of the lines grabbed
    for ($i = 0; $i -lt 40; $i++){
        [array]$tokens = ($hollowsHunterProcesses[$i]).split(" ")
        
        if($tokens[0] -eq "[*]" -and $tokens[2] -eq "suspicious:"){
            # Once the line is found that indicates there are suspicious processes, iterate through the processes
            # Get their PID, and call the removeProcessesServices Function with the PID of the suspicious process.
            for($j = 0; $j -lt $tokens[-1]; $j++){
                [array]$processTokens = ($hollowsHunterProcesses[$i + $j + 2]).split(" ")
                $ProcessID = ($processTokens[2]).trim(",")
                removeProcessesServices -ProcessID $ProcessID
            }
            break
        }
    }

    # Removing processes found with known bad names

    [array]$knownBadProcessNames = "MeshAgent.exe","tacticalrmm.exe"

    [array]$allProcesses = Get-Content $processAuditPath

    foreach($line in $allProcesses){
        if($line -eq "----------- Interesting Process ACLs -----------"){
            break
        }
        elseif($line -ne ""){
            $line = $line.strip()
            $tokens = $line.split(" ")
            if($tokens[1] -in $knownBadProcessNames){
                removeProcessesServices -ProcessID $tokens[0]
            }
        }
    }
}