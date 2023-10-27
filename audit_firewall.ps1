$VerbosePreference = "SilentlyContinue"
$currentDir = Get-Location
$firewallPath = Join-Path -Path $currentDir -ChildPath 'firewallaudit.txt'

Function Show-Firewall{#good
    function Get-FirewallProfiles {
        $profiles = Get-NetFirewallProfile | Select-Object -Property Name, Enabled
        return $profiles
    }
    function Get-FirewallRulesForProfile {
        param (
            [string]$ProfileName
        )
        $rules = Get-NetFirewallRule | Where-Object { $_.Profile -contains $ProfileName } | Select-Object -Property Name, DisplayName, Direction, Action, Enabled
        return $rules
    }
    $firewallProfiles = Get-FirewallProfiles
    foreach ($profile in $firewallProfiles){
        Write-Output "Firewall Profile: $($profile.Name)"
        Write-Output "Enabled: $($profile.Enabled)"
        $profileName = $profile.Name
        $rules = Get-FirewallRulesForProfile -ProfileName $profileName
        Write-Output "========================================================="
        foreach ($rule in $rules){
            Write-Output "Rule Name: $($rule.Name)"
            Write-Output "Display Name: $($rule.DisplayName)"
            Write-Output "Direction: $($rule.Direction)"
            Write-Output "Action: $($rule.Action)"
            Write-Output "Enabled: $($rule.Enabled)"
        }
        Write-Output "End Profile : $($profile.Name)"
    }
}

$firewallfunction = Show-Firewall
$firewallfunction | Out-File -FilePath $firewallPath