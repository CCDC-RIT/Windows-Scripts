$VerbosePreference = "SilentlyContinue"
$currentDir = Get-Location
$processPath = Join-Path -Path $currentDir -ChildPath 'processaudit.txt'

Function Process-Audit{#good
    $processList = Get-Process -IncludeUserName
    Write-Output "Process List with Usernames: "
    Write-Output "$($processList)"
}

Function Hidden-Services{#not good
    $hidden = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}
    Write-Output "Hidden Service List: "
    Write-Output "$($hidden)"
}

Function Scheduled-Tasks{#good
    $scheduled = Get-ScheduledTask
    Write-Output "Scheduled Task List: "
    Write-Output "$($scheduled)"
}

$processfunction = Process-Audit
$processfunction += Hidden-Services
$processfunction += Scheduled-Tasks
$processfunction | Out-File -FilePath $processPath