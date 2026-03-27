param(
    [Parameter(Mandatory=$true)][string]$Path,
    [ValidateSet("local","remote")][string]$Mode = "local",
    [string]$Host = "",
    [string]$Port = "",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"

# Resolve challenge directory
if (-not (Test-Path $Path)) {
    $BASE = "$PSScriptRoot\.."
    $Path = Join-Path $BASE "challenges" $Path
}

if (-not (Test-Path $Path)) {
    Write-Error "Challenge path not found: $Path"
    exit 1
}

# Read meta.yaml for remote info if not provided
$metaPath = Join-Path $Path "meta.yaml"
if ((Test-Path $metaPath) -and ($Mode -eq "remote") -and (-not $Host)) {
    $meta = Get-Content $metaPath -Raw
    if ($meta -match "remote_host:\s*(.+)") { $Host = $Matches[1].Trim() }
    if ($meta -match "remote_port:\s*(.+)") { $Port = $Matches[1].Trim() }
}

# Find entrypoint
$entrypoint = ""
foreach ($f in @("exploit.py", "solve.py")) {
    $candidate = Join-Path $Path $f
    if (Test-Path $candidate) { $entrypoint = $candidate; break }
}

if (-not $entrypoint) {
    Write-Error "No solve.py or exploit.py found in $Path"
    exit 1
}

# Set environment
$env:HOST = $Host
$env:PORT = $Port

$logFile = Join-Path $Path "LAST_RUN.log"

Write-Host "[*] Running: $Python $entrypoint" -ForegroundColor Cyan
if ($Mode -eq "remote") {
    Write-Host "[*] Target: ${Host}:${Port}" -ForegroundColor Cyan
}

# Execute and tee output
& $Python $entrypoint 2>&1 | Tee-Object -FilePath $logFile

$exitCode = $LASTEXITCODE
if ($exitCode -eq 0) {
    Write-Host "`n[+] Solver exited successfully" -ForegroundColor Green
} else {
    Write-Host "`n[-] Solver exited with code $exitCode" -ForegroundColor Red
}

exit $exitCode
