param(
    [Parameter(Mandatory = $true)]
    [string]$HostAddress,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

$currentVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$hotFixIds = @(
    Get-HotFix |
        ForEach-Object { $_.HotFixID } |
        Where-Object { $_ -match "^KB\d{5,8}$" } |
        Sort-Object -Unique
)

$inventory = [ordered]@{
    host = $HostAddress
    ProductName = [string]$currentVersion.ProductName
    EditionID = [string]$currentVersion.EditionID
    DisplayVersion = [string]$currentVersion.DisplayVersion
    CurrentBuildNumber = [string]$currentVersion.CurrentBuildNumber
    UBR = [string]$currentVersion.UBR
    OSArchitecture = [string]$operatingSystem.OSArchitecture
    HotFixIDs = $hotFixIds
}

$destination = [System.IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $destination
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

$inventory |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $destination -Encoding UTF8

Write-Host "Read-only Windows inventory written to $destination"
