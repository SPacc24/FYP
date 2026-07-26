$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectVenvPython = Join-Path $RootDir "project\.venv\Scripts\python.exe"
$RootVenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"

if (Test-Path $ProjectVenvPython) {
    $PythonBin = $ProjectVenvPython
} elseif (Test-Path $RootVenvPython) {
    $PythonBin = $RootVenvPython
} else {
    $PythonBin = "python"
}

Set-Location (Join-Path $RootDir "project")
& $PythonBin app.py @args
