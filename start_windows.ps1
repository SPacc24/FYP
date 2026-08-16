$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Project = Join-Path $Root "project"
$Python = Join-Path $Project ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Python virtual environment is missing. Run .\install_windows.ps1 first."
}

Set-Location $Project
& $Python runtime_env.py | Out-Null
& $Python app.py @args
