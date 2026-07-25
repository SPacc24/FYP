param(
    [switch]$SkipPythonPackages
)

$ErrorActionPreference = "Stop"
Write-Host "AutoPenTest Recon - Windows/VS Code setup" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python was not found in PATH. Install Python 3.10+ first."
}

if (-not (Test-Path "project/.venv")) {
    python -m venv project/.venv
}

if (-not $SkipPythonPackages) {
    project/.venv/Scripts/python -m pip install --upgrade pip
    project/.venv/Scripts/python -m pip install -r project/requirements.txt
}

Write-Host "\nCreating local runtime configuration..." -ForegroundColor Cyan
project/.venv/Scripts/python project/scripts/bootstrap_env.py

Write-Host "\nChecking external recon tools..." -ForegroundColor Cyan
project/.venv/Scripts/python project/scripts/check_tooling.py

Write-Host "\nRun in VS Code with: Run and Debug -> Run AutoPenTest Recon Flask App" -ForegroundColor Green
Write-Host "Or run manually:" -ForegroundColor Green
Write-Host ".\\start_windows.ps1"
