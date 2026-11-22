# 一键启动审计前端和接口。端口已在监听时不重复拉起，只打开页面。

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$BackendPort = 8787
$FrontendPort = 5179
$Page = "http://127.0.0.1:$FrontendPort/"
$RunDir = Join-Path $PSScriptRoot ".run"
$BackendPidFile = Join-Path $RunDir "backend.pid"
$FrontendPidFile = Join-Path $RunDir "frontend.pid"

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

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

function Wait-PortOpen {
    param([int]$Port, [int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortOpen $Port) {
            return $true
        }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

python -c "import fastapi, uvicorn, claude_agent_sdk, yaml" 2>$null
if ($LASTEXITCODE -ne 0) {
    python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Python 依赖安装失败"
    }
}

if (-not (Test-Path (Join-Path $PSScriptRoot "frontend\node_modules"))) {
    npm install --prefix (Join-Path $PSScriptRoot "frontend")
    if ($LASTEXITCODE -ne 0) {
        throw "前端依赖安装失败"
    }
}

if (-not (Test-PortOpen $BackendPort)) {
    $backendProcess = Start-Process -FilePath "python" -ArgumentList @(
        "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$BackendPort"
    ) -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
    Set-Content -LiteralPath $BackendPidFile -Value $backendProcess.Id -Encoding ASCII
    if (-not (Wait-PortOpen $BackendPort 40)) {
        throw "接口没有在 $BackendPort 端口起来"
    }
}

if (-not (Test-PortOpen $FrontendPort)) {
    $npm = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
    if (-not $npm) {
        throw "找不到 npm.cmd"
    }
    $frontendProcess = Start-Process -FilePath $npm -ArgumentList @(
        "--prefix", "frontend", "run", "dev"
    ) -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
    Set-Content -LiteralPath $FrontendPidFile -Value $frontendProcess.Id -Encoding ASCII
    if (-not (Wait-PortOpen $FrontendPort 40)) {
        throw "前端没有在 $FrontendPort 端口起来"
    }
}

Start-Process $Page
Write-Host "已打开 $Page"
