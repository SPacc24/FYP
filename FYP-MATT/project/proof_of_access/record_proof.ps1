param(
    [Parameter(Mandatory = $true)]
    [string]$TicketFile,

    [Parameter(Mandatory = $true)]
    [string]$ValidatorUrl,

    [string]$OutputDir = ".\proof-of-access"
)

$ErrorActionPreference = "Stop"
$ScriptPath = Join-Path $PSScriptRoot "record_proof.py"

python $ScriptPath `
    --ticket-file $TicketFile `
    --validator-url $ValidatorUrl `
    --output-dir $OutputDir

exit $LASTEXITCODE
