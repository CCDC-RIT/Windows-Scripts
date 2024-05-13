# Security Orchestration and Automated Response tool, built to run as a standalone agent on a system. 

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

function runDefenderScan(){
    start-mpscan -scantype QuickScan
    Get-MpThreatDetection
    #prompt if we should delete or not
    remove-mpthreat
}

# This function goes through the current list of local users, and checks against a predetermined list to see if they are potentially malicious or not. 
# User is then given the option to disable the user, do nothing, or add them to the predetermined list if they.
function auditLocalUsers(){
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

function checkDLLs(){
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
    [hashtable]$hashTable = @{"NetSh" = $goodnetshDLLs; "Windows" = $goodAppInitDLLs; "Lsa" = $goodLsaDLLs; "Winlogon" = $goodWinlogonDLLs;"Local Port" = $goodLocalPortDLLs; "IP Port" = $goodIPPortDLLs; "USB Monitor" = $goodUSBMonitorDLLs; "WSD Port" = $goodWSDPortDLLs;}
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
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Potentially Malicious NETSH Helper DLL Found: " -ForegroundColor white -NoNewLine; Write-Host $tokens[-1] -ForegroundColor Red
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