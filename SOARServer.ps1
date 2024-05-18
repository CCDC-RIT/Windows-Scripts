# Security Orchestration and Automated Response Centralized Server Tools

# This is meant to be Server that can handle all of the Windows Clients on a given system,
# So that it is only necessary to monitor one powershell Terminal for alerts for the entire domain.

# Listen for connections on port 1738
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any,1738)
$listener.start()

$clients = @()
$clientIPs = @()
$readers = @()
$writers = @()

Function getClient {
    $client = $listener.AcceptTcpClient()
    $clientIP = $client.Client.RemoteEndPoint.Address.IPAddressToString
    Write-Host "[INFO] New Client at " -NoNewline; Write-Host $clientIP
    $stream = $client.getStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $writer = New-Object System.IO.StreamWriter($stream)
    $Writer.AutoFlush = $true

    $clients += $client
    $clientIPs += $clientIP
    $readers += $reader
    $writers += $writer
}

Function readFromClients {
    for($i = 0; $i -lt $readers.count; $i++){
        $reader = $readers[$i]
        while($reader.peek() -ne -1){
            $line = $reader.readline()

            $tokens = $line.split(" ")
            switch -exact ($tokens[0]){
                "user" {
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Unauthorized user " -ForegroundColor white -NoNewLine; Write-Host $tokens[1] -ForegroundColor Red -NoNewLine; Write-Host " detected" -ForegroundColor white
                    $answer = Read-Host "Take Action? [yes/no/add (adds user to authorized user list)]"
                    $writers[$i].WriteLine($answer)
                }
                "dll" {
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Potentially Malicious " -ForegroundColor White -NoNewline; Write-Host $tokens[1] -ForegroundColor White -NoNewline; Write-Host " DLL Found: " -ForegroundColor white -NoNewLine; Write-Host $tokens[2] -ForegroundColor Red
                    $answer = Read-Host "Take Action? [yes/no]"
                    $writers[$i].WriteLine($answer)
                }
                "process" {
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Malicious Process " -ForegroundColor white -NoNewLine
                    Write-Host $tokens[1] -ForegroundColor Red -NoNewLine; Write-Host " with PID: " -ForegroundColor White -NoNewLine; Write-Host $tokens[2] -ForegroundColor Red -NoNewLine
                    if($tokens[3]){
                        Write-Host " With Service Name: " -ForegroundColor White -NoNewline; Write-Host $tokens[4] -ForegroundColor Red -NoNewLine
                    }
                    Write-Host " and Path: " -ForegroundColor White -NoNewline; Write-Host $tokens[5] -ForegroundColor Red
                    Write-Host "Owner of the Process is " -ForegroundColor White -NoNewline; Write-Host $tokens[6] -ForegroundColor Red
                    $answer = Read-Host "Take Action? [yes/no]"
                    $writers[$i].WriteLine($answer)
                }
            }
        }
    }
}

while($true){
    while($listener.Pending()){
        getClient
    }
    for($j = 0; $j -lt 3; $j++){
        readFromClients
        Start-Sleep -seconds 10
    }
}