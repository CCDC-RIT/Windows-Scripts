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
    # Get the first 70 lines from the registry audit path, should be enough for all of theDLL's
    [array]$currentDLLs = Get-Content -Path $registryAuditPath
    # If sentinel = 1, then the next lines contain either junk, or a netsh helper dll
    # if sentinel = 2, then AppInit dll's
    # 3 = AppInit dll's
    # 4 = no more dll's to check
    [int]$sentinel = 0
    # known good netsh dll's
    [array]$knownGoodnetshDLLs = "ifmon.dll","rasmontr.dll","authfwcfg.dll","dhcpmonitor.dll","dot3cfg.dll","fwcfg.dll","hnetmon.dll","nettrace.dll","netiohlp.dll","nshhttp.dll","nshipsec.dll","nshwfp.dll","peerdistsh.dll","rpcnsh.dll","whhelper.dll","wshelper.dll","wwancfg.dll","netprofm.dll","p2pnetsh.dll","wcnetsh.dll","wlancfg.dll"
    foreach($line in $currentDLLs){
        # TODO: Start at line 3, not at line 0
        $tokens = $line.split(" ")
        if($line -eq "----------- netsh Helper DLL Items -----------"){
            $sentinel = 1
        }
        if($sentinel -eq 1){
            if($line -eq "----------- AppCert DLLs -----------"){
                $sentinel = 2
            }
            else{
                if(!($tokens[0] -ieq "key" -or $line -eq "")){
                    if(!($tokens[-1]) -in $knownGoodnetshDLLs){
                        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Potentially Malicious NETSH Helper DLL Found: " -ForegroundColor white -NoNewLine; Write-Host $tokens[-1] -ForegroundColor Red
                        $answer = Read-Host "Take Action? [yes/no]"
                        if($answer -ieq "yes"){
                            # TODO: Figure out how to remove the malicious DLL
                            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Malicious DLL " -ForegroundColor white -NoNewLine; Write-Host $tokens[-1] -ForegroundColor Red -NoNewLine; Write-Host " removed" -ForegroundColor white 
                        }
                    }
                }
            }
        }
        elseif($sentinel -eq 2){
            if($line -eq "----------- AppInit DLLs -----------"){
                $sentinel = 3
            }
            else{
                if(!($tokens[0] -ieq "key" -or $line -eq "")){
                    # TODO: check for bad AppCert Dll's
                }
            }
        }
        elseif($sentinel -eq 3){
            if($line -eq "----------- IFEO Debugger Items -----------"){
                $sentinel = 4
            }
            else{
                if(!($tokens[0] -ieq "key" -or $line -eq "")){
                    # TODO: Check for bad AppInit Dll's
                }
            }
        }
        elseif($sentinel -eq 4){
            if($line -eq "----------- Authentication Packages -----------"){
                $sentinel = 5
            }
        }
        elseif($sentinel -eq 5){
            # TODO: Fix this line
            if($line -eq "whatever dll is next"){
                $sentinel = 6
            }
            else{
                #TODO: Figure out what dll should be loaded by LSA
            }
        }
    }
}