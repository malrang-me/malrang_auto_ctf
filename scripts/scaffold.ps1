param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][ValidateSet("crypto","pwn","web","rev","web3","forensics","ai","misc")][string]$Category,
    [string]$Remote = "",
    [string]$Platform = "unknown"
)

$ErrorActionPreference = "Stop"
$BASE = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$BASE = "$PSScriptRoot\.."
$ChalDir = Join-Path $BASE "challenges" $Name

if (Test-Path $ChalDir) {
    Write-Host "[!] Challenge folder already exists: $ChalDir" -ForegroundColor Yellow
    exit 1
}

# Create directory structure
New-Item -ItemType Directory -Path $ChalDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ChalDir "memory") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ChalDir "artifacts") -Force | Out-Null

# Parse remote
$RemoteHost = ""
$RemotePort = ""
if ($Remote -ne "") {
    $parts = $Remote -split "\s+"
    if ($parts.Count -ge 2) {
        $RemoteHost = $parts[0]
        $RemotePort = $parts[1]
    }
}

# Create meta.yaml
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$meta = @"
name: $Name
category: $Category
platform: $Platform
remote_host: $RemoteHost
remote_port: $RemotePort
status: init
created_at: $timestamp
"@
Set-Content -Path (Join-Path $ChalDir "meta.yaml") -Value $meta -Encoding UTF8

# Copy solver template
$templateName = if ($Category -in @("pwn", "web")) { "exploit.py" } else { "solve.py" }
$entrypoint = if ($Category -in @("pwn", "web")) { "exploit.py" } else { "solve.py" }
$templateSrc = Join-Path $BASE "templates" $templateName
if (Test-Path $templateSrc) {
    Copy-Item $templateSrc (Join-Path $ChalDir $entrypoint)
} else {
    # Inline minimal template
    Set-Content -Path (Join-Path $ChalDir $entrypoint) -Value "#!/usr/bin/env python3`nimport os`n`nHOST = os.getenv('HOST', '')`nPORT = int(os.getenv('PORT', '0'))`n`ndef main():`n    pass`n`nif __name__ == '__main__':`n    main()" -Encoding UTF8
}

# Create memory files with headers
@("recon", "strategy", "discoveries", "failures") | ForEach-Object {
    $header = "# " + $_.Substring(0,1).ToUpper() + $_.Substring(1)
    Set-Content -Path (Join-Path $ChalDir "memory" "$_.md") -Value "$header`n" -Encoding UTF8
}

Write-Host "[+] Scaffolded: $ChalDir" -ForegroundColor Green
Write-Host "    Category:   $Category"
Write-Host "    Entrypoint: $entrypoint"
if ($RemoteHost) { Write-Host "    Remote:     ${RemoteHost}:${RemotePort}" }
