param(
    [Parameter(Mandatory=$true)][string]$ProblemName,
    [Parameter(Mandatory=$true)][ValidateSet("crypto","pwn","web","rev","web3","forensics","ai","misc")][string]$Category,
    [string]$SourceZip = ""
)

$ErrorActionPreference = "Stop"
$BASE = "$PSScriptRoot\.."
$downloads = Join-Path $BASE "_downloads"
$chalDir = Join-Path $BASE "challenges" $ProblemName

# Auto-detect zip if not provided
if (-not $SourceZip) {
    $zips = Get-ChildItem -Path $downloads -Filter "*.zip" | Sort-Object LastWriteTime -Descending
    if ($zips.Count -eq 0) {
        Write-Error "No zip files found in $downloads"
        exit 1
    }
    $SourceZip = $zips[0].FullName
    Write-Host "[*] Auto-detected: $SourceZip" -ForegroundColor Cyan
}

if (-not (Test-Path $SourceZip)) {
    Write-Error "Source zip not found: $SourceZip"
    exit 1
}

# Scaffold if not exists
if (-not (Test-Path $chalDir)) {
    & "$PSScriptRoot\scaffold.ps1" -Name $ProblemName -Category $Category
}

# Create deploy directory and extract
$deployDir = Join-Path $chalDir "deploy"
New-Item -ItemType Directory -Path $deployDir -Force | Out-Null

Write-Host "[*] Extracting $SourceZip -> $deployDir" -ForegroundColor Cyan
Expand-Archive -Path $SourceZip -DestinationPath $deployDir -Force

# If zip contains a single subdirectory, flatten it
$items = Get-ChildItem -Path $deployDir
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
    $innerDir = $items[0].FullName
    Get-ChildItem -Path $innerDir | Move-Item -Destination $deployDir -Force
    Remove-Item $innerDir -Force
}

Write-Host "[+] Intake complete: $chalDir" -ForegroundColor Green
Write-Host "    Deploy files in: $deployDir"
