param (
    [switch]$disable,
    [switch]$delete,
    [switch]$DryRun
)

# 1. Define the Whitelist (Exact matches)
$whitelist = @(
    "admiral", "emperor", "orion", "bigdipper",
    "captain", "ambassador", "challenger", "nebula", "neo",
    "soldier", "apollo", "explorer", "nova", "leia", "littledipper",
    "sol", "astronaut", "spacerock", "luna", "navigator", "halley", "luke", "callisto",
    "krbtgt", "whiteteam", "white-team", "black-team", "datadog", "dd-dog", "dd-agent", "blackteam", "administrator",
    "cloudbase-init"
)

# Accounts Windows needs to stay alive
$systemAccounts = @("WDAGUtilityAccount", "DefaultAccount", "UtilityAccount")

if ($DryRun) { 
    Write-Host "!!! DRY RUN MODE ENABLED - No changes will be made !!!" -ForegroundColor Cyan 
}

Write-Host "--- Starting Account Processing ---" -ForegroundColor Yellow

# Function to check if a user should be skipped
function Test-IsWhitelisted($UserName) {
    # 1. Check exact matches in whitelist or system accounts
    if ($whitelist -contains $UserName -or $systemAccounts -contains $UserName) { return $true }
    
    # 2. Check for Machine Accounts (ending in $)
    if ($UserName.EndsWith("$")) { return $true }
    
    # 3. Check for partial matches (datadog or dd-dog)
    if ($UserName -like "*datadog*" -or $UserName -like "*dd-dog*") { return $true }
    
    return $false
}

# --- SECTION 1: ACTIVE DIRECTORY USERS ---
if (Get-Module -ListAvailable ActiveDirectory) {
    Write-Host "[AD] Processing Domain Accounts..." -ForegroundColor Cyan
    try {
        $adUsers = Get-ADUser -Filter * -Properties Enabled
        foreach ($u in $adUsers) {
            $sam = $u.SamAccountName
            
            if (Test-IsWhitelisted -UserName $sam) {
                Write-Host "[AD] Skipping Protected/Whitelisted: $sam" -ForegroundColor Green
                continue
            }

            if ($sam -eq "Guest") {
                Write-Host "[AD] Guest Account: Forced Disabled (Never Deleted)" -ForegroundColor Gray
                if (-not $DryRun) { Disable-ADAccount -Identity $sam -ErrorAction SilentlyContinue }
                continue
            }

            if ($disable) {
                Write-Host "[AD] Disabling: $sam" -ForegroundColor Red
                if (-not $DryRun) { Disable-ADAccount -Identity $sam }
            }
            if ($delete) {
                Write-Host "[AD] DELETING: $sam" -ForegroundColor DarkRed
                if (-not $DryRun) { Remove-ADUser -Identity $sam -Confirm:$false }
            }
        }
    } catch {
        Write-Host "[AD] Error accessing Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- SECTION 2: LOCAL USERS ---
Write-Host "[Local] Processing Local Accounts..." -ForegroundColor Cyan
try {
    $localUsers = Get-LocalUser
    foreach ($l in $localUsers) {
        $name = $l.Name

        if (Test-IsWhitelisted -UserName $name) {
            Write-Host "[Local] Skipping Protected/Whitelisted: $name" -ForegroundColor Green
            continue
        }

        if ($name -eq "Guest") {
            Write-Host "[Local] Guest Account: Forced Disabled (Never Deleted)" -ForegroundColor Gray
            if (-not $DryRun) { Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue }
            continue
        }

        if ($disable) {
            Write-Host "[Local] Disabling: $name" -ForegroundColor Red
            if (-not $DryRun) { Disable-LocalUser -Name $name }
        }
        if ($delete) {
            Write-Host "[Local] DELETING: $name" -ForegroundColor DarkRed
            if (-not $DryRun) { Remove-LocalUser -Name $name }
        }
    }
} catch {
    Write-Host "[Local] Error accessing local users: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "--- Processing Complete ---" -ForegroundColor Yellow