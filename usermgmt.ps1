param(
    [Parameter()]
    [String]$filepath 
)

[string]$cmdPath = $MyInvocation.MyCommand.Path
$currentDir = $cmdPath.substring(0, $cmdPath.IndexOf("usermgmt.ps1"))

try {
    [string[]]$AllowUsers = Get-Content $filepath
} catch {
    Write-Host "[ERROR] Unable to get list of users"
    exit 1
}

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-Host "[INFO] Domain Controller Detected"
}

Function Set-krbtgtPassword([bool] $IsDC) {
    Clear-Host
    if ($IsDC) {
        $krbtgtPath = Join-Path -Path $currentDir -ChildPath "Reset-KrbtgtKeyInteractive.ps1"
        & $krbtgtPath
    } else {
        Write-Host "[ERROR] Computer is not a domain controller"
        exit
    }
}
Function Set-Password([string]$UserName, [bool]$IsDC, [SecureString]$Password, [SecureString]$Password2) {
    $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2))

    if ($pwd1_text -cne $pwd2_text) {
        Write-Host "[ERROR] Passwords don't match" 
        exit
    } else {
        if ($IsDC) {
            Set-ADAccountPassword -Identity $UserName -NewPassword $Password
            Write-Host "[INFO] Password set for" $UserName
        } else {
            Set-LocalUser -Name $UserName -Password $Password
            Write-Host "[INFO] Password set for" $UserName
        }
    }
}

Function Set-UserProperties([string[]]$UserList, [bool]$IsDC, [string]$action) {
    if ($IsDC) {
        $DomainUsers = Get-ADUser -filter *
        foreach ($DomainUser in $DomainUsers) {
            if ($DomainUser.Name -in $UserList) {
                if($action -eq "Enable"){
                    Enable-ADAccount -Identity $DomainUser.Name
                    if($DomainUser.enabled -eq "True"){
                        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] $($DomainUser.name) Enabled" -ForegroundColor White
                    }
                    else{
                        Write-Host "[" -NoNewline; Write-Host "Error" -ForegroundColor Red -NoNewline; Write-Host "] $($DomainUser.name) Could not be enabled" -ForegroundColor White
                    }
                } elseif($action -eq "Secure"){
                    $DomainUser | Set-ADUser -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -PasswordNotRequired $false -AccountNotDelegated $true 
                    $DomainUser | Set-ADAccountControl -DoesNotRequirePreAuth $false
                    Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] $($DomainUser.name) Secured" -ForegroundColor White
                } else{
                    Disable-ADAccount -Identity $DomainUser
                    if(!($DomainUser.enabled -eq "True")){
                        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] $($DomainUser.name) Disabled" -ForegroundColor White
                    }
                    else{
                        Write-Host "[" -NoNewline; Write-Host "Error" -ForegroundColor Red -NoNewline; Write-Host "] $($DomainUser.name) Could not be disabled" -ForegroundColor White
                    }
                }
            }
        }
    } else {
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
        foreach ($LocalUser in $LocalUsers) {
            if ($LocalUser.Name -in $UserList) {
                if($action -eq "Enable"){
                    Enable-LocalUser -Identity $LocalUser.Name
                    if(!($LocalUser.disabled)){
                        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] $($LocalUseUser.name) Enabled" -ForegroundColor White
                    } else {
                        Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Green -NoNewline; Write-Host "] $($LocalUser.name) Could not be enabled" -ForegroundColor White
                    }
                } elseif($action -eq "Secure"){
                    $LocalUser | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires
                    Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] $($LocalUser.name) Secured" -ForegroundColor White
                } else {
                    Disable-LocalUser -Identity $LocalUser.Name
                    if($LocalUser.disabled){
                        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] $($LocalUser.name) Disabled" -ForegroundColor White
                    } else {
                        Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Green -NoNewline; Write-Host "] $($LocalUser.name) Could not be disabled" -ForegroundColor White
                    }
                }
            }
        }
    }
}

while ($true) {
    Write-Host "Options:"
    Write-Host "1. Change passwords for all users in list"
    Write-Host "2. Change password for current user"
    Write-Host "3. Disable all users in list"
    Write-Host "4. Secure all users in list"
    Write-Host "5. Enable all users in list"
    Write-Host "6. Reset krbtgt password"
    Write-Host "7. Exit"
    $option = Read-Host "Enter an option"
    
    if ($option -eq '1') {
        Clear-Host
        $Password = Read-Host -AsSecureString "Password"
        $Password2 = Read-Host -AsSecureString "Confirm Password"
        foreach ($user in $AllowUsers) {
            Set-Password -UserName $user -IsDC $DC -Password $Password -Password2 $Password2
        }
    } elseif ($option -eq '2') {
        Clear-Host
        $Password = Read-Host -AsSecureString "Password"
        $Password2 = Read-Host -AsSecureString "Confirm Password"
        Set-Password -UserName $Env:UserName -IsDC $DC -Password $Password -Password2 $Password2
    } elseif ($option -eq '3') {
        Set-UserProperties -UserList $AllowUsers -IsDC $DC -action "Disable"
    } elseif ($option -eq '4') {
        Set-UserProperties -UserList $AllowUsers -IsDC $DC -action "Secure"
    } elseif($option -eq '5') {
        Set-UserProperties -UserList $AllowUsers -IsDC $DC -action "Enable"
    } elseif ($option -eq '6') {
        Set-krbtgtPassword -IsDC $DC
    } elseif ($option -eq '7') {
        exit 0
    } else {
        Write-Host "Invalid option, try again"
    }
}
#Chandi Fortnite
