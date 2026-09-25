param(
    [ValidateSet("start", "stop", "toggle", "status")]
    [string]$Action = "toggle"
)

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$RuntimeDir = Join-Path $ProjectRoot ".run"
$PidFile = Join-Path $RuntimeDir "server.pid"
$StateFile = Join-Path $RuntimeDir "server.json"

function Get-ServerPid {
    if (Test-Path $PidFile) {
        try {
            return [int](Get-Content $PidFile -Raw)
        }
        catch {
            return $null
        }
    }
    return $null
}

function Test-ServerRunning {
    param([int]$ServerPid)

    if (-not $ServerPid) {
        return $false
    }

    try {
        Get-Process -Id $ServerPid -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Write-State {
    param(
        [int]$ServerPid,
        [string]$Status,
        [string]$Url
    )

    $state = [ordered]@{
        pid = $ServerPid
        status = $Status
        url = $Url
        updated_at = (Get-Date).ToString("o")
    }

    New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
    $state | ConvertTo-Json -Depth 4 | Set-Content -Path $StateFile -Encoding UTF8
}

function Start-Servers {
    $serverPid = Get-ServerPid
    if (Test-ServerRunning -ServerPid $serverPid) {
        Write-Host "Server already running at http://127.0.0.1:8000 (PID $serverPid)"
        return
    }

    if (-not (Test-Path $VenvPython)) {
        throw "Expected virtualenv python not found at $VenvPython"
    }

    New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null

    $process = Start-Process -FilePath $VenvPython -WorkingDirectory $ProjectRoot -ArgumentList @(
        "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"
    ) -PassThru

    $process.Id | Set-Content -Path $PidFile -Encoding ASCII
    Write-State -ServerPid $process.Id -Status "running" -Url "http://127.0.0.1:8000"
    Write-Host "Started server at http://127.0.0.1:8000 (PID $($process.Id))"
}

function Stop-Servers {
    $serverPid = Get-ServerPid
    if (Test-ServerRunning -ServerPid $serverPid) {
        Stop-Process -Id $serverPid -Force
        Write-Host "Stopped server (PID $serverPid)"
    }
    else {
        Write-Host "No running server found"
    }

    Remove-Item $PidFile -ErrorAction SilentlyContinue
    Remove-Item $StateFile -ErrorAction SilentlyContinue
}

switch ($Action) {
    "start" { Start-Servers }
    "stop" { Stop-Servers }
    "status" {
        $serverPid = Get-ServerPid
        if (Test-ServerRunning -ServerPid $serverPid) {
            Write-Host "Running at http://127.0.0.1:8000 (PID $serverPid)"
        }
        else {
            Write-Host "Stopped"
        }
    }
    "toggle" {
        $serverPid = Get-ServerPid
        if (Test-ServerRunning -ServerPid $serverPid) {
            Stop-Servers
        }
        else {
            Start-Servers
        }
    }
}