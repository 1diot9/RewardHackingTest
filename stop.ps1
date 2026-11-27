$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$RunDir = Join-Path $PSScriptRoot ".run"
$BackendPidFile = Join-Path $RunDir "backend.pid"
$FrontendPidFile = Join-Path $RunDir "frontend.pid"

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

function Get-ProcessCommandLine {
    param([int]$ProcessId)
    try {
        return (Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId").CommandLine
    }
    catch {
        return $null
    }
}

function Test-ExpectedProcess {
    param(
        [int]$ProcessId,
        [ValidateSet("backend", "frontend")][string]$Role
    )
    $commandLine = Get-ProcessCommandLine $ProcessId
    if (-not $commandLine) {
        return $false
    }
    if ($Role -eq "backend") {
        return $commandLine -match "(?i)uvicorn" -and
            $commandLine -match "app\.main:app" -and
            $commandLine -match "--port\s+8787"
    }
    return ($commandLine -match "(?i)npm(?:\.cmd)?" -and
            $commandLine -match "--prefix\s+frontend" -and
            $commandLine -match "run\s+dev") -or
        ($commandLine -match "(?i)frontend[\\/]node_modules[\\/]vite")
}

function Stop-ProcessTree {
    param([int]$ProcessId)
    & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null
}

function Get-ListenerProcessId {
    param([int]$Port)
    try {
        return Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $Port -State Listen `
            -ErrorAction Stop | Select-Object -First 1 -ExpandProperty OwningProcess
    }
    catch {
        return $null
    }
}

function Stop-AuditorProcess {
    param(
        [ValidateSet("backend", "frontend")][string]$Role,
        [int]$Port,
        [string]$PidFile
    )

    $stopped = $false
    if (Test-Path -LiteralPath $PidFile -PathType Leaf) {
        $savedProcessId = 0
        $rawProcessId = (Get-Content -LiteralPath $PidFile -Raw).Trim()
        if ([int]::TryParse($rawProcessId, [ref]$savedProcessId) -and
            (Test-ExpectedProcess $savedProcessId $Role)) {
            Stop-ProcessTree $savedProcessId
            $stopped = $true
        }
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    }

    $deadline = (Get-Date).AddSeconds(3)
    while ($stopped -and (Get-Date) -lt $deadline -and (Test-PortOpen $Port)) {
        Start-Sleep -Milliseconds 200
    }

    if (Test-PortOpen $Port) {
        $listenerProcessId = Get-ListenerProcessId $Port
        if ($listenerProcessId -and (Test-ExpectedProcess $listenerProcessId $Role)) {
            Stop-ProcessTree $listenerProcessId
            $stopped = $true
        }
        elseif ($listenerProcessId) {
            Write-Warning "$Port 端口由非 auditor 进程占用，已跳过，PID: $listenerProcessId"
        }
    }

    if ($stopped) {
        Write-Host "已停止 $Role"
    }
    elseif (-not (Test-PortOpen $Port)) {
        Write-Host "$Role 未运行"
    }
}

Stop-AuditorProcess -Role "frontend" -Port 5179 -PidFile $FrontendPidFile
Stop-AuditorProcess -Role "backend" -Port 8787 -PidFile $BackendPidFile

if ((Test-Path -LiteralPath $RunDir -PathType Container) -and
    -not (Get-ChildItem -LiteralPath $RunDir -Force | Select-Object -First 1)) {
    Remove-Item -LiteralPath $RunDir -Force
}

Write-Host "Auditor 已停止。"
