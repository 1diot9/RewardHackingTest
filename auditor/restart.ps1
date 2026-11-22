$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Test-PortOpen {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect("127.0.0.1", $Port)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

Write-Host "正在停止 Auditor..."
& (Join-Path $PSScriptRoot "stop.ps1")

$deadline = (Get-Date).AddSeconds(10)
do {
    $openPorts = @(8787, 5179 | Where-Object { Test-PortOpen $_ })
    if ($openPorts.Count -eq 0) {
        break
    }
    Start-Sleep -Milliseconds 200
} while ((Get-Date) -lt $deadline)

if ($openPorts.Count -gt 0) {
    throw "端口仍被占用，无法重启 Auditor: $($openPorts -join ', ')"
}

Write-Host "正在启动 Auditor..."
& (Join-Path $PSScriptRoot "start.ps1")
