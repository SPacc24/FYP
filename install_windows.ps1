param(
    [switch]$SkipPythonPackages
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Project = Join-Path $Root "project"
$Python = Join-Path $Project ".venv\Scripts\python.exe"

Write-Host "AutoPenTest setup" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python was not found in PATH. Install Python 3.10+ first."
}

if (-not (Test-Path (Join-Path $Project ".venv"))) {
    python -m venv (Join-Path $Project ".venv")
}

if (-not $SkipPythonPackages) {
    & $Python -m pip install --upgrade pip setuptools wheel
    & $Python -m pip install -r (Join-Path $Project "requirements.txt")
}

Write-Host "Creating complete local runtime configuration..." -ForegroundColor Cyan
& $Python (Join-Path $Project "runtime_env.py")

Write-Host "Checking external tooling..." -ForegroundColor Cyan
& $Python (Join-Path $Project "scripts\check_tooling.py")
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Some core external tools are unavailable. Live scanning may be limited."
}

Write-Host "Setup complete. Start the application with .\start_windows.ps1" -ForegroundColor Green
