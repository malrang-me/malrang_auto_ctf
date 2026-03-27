param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][ValidateSet("start","attempt","success","fail","gate")][string]$Event,
    [string]$Branch = "",
    [string]$Summary = ""
)

$BASE = "$PSScriptRoot\.."
$metricsFile = Join-Path $BASE "metrics" "ctf_runs.jsonl"

# Read challenge name and category from meta.yaml
$challengeName = Split-Path $Path -Leaf
$category = ""
$metaPath = Join-Path $Path "meta.yaml"
if (Test-Path $metaPath) {
    $meta = Get-Content $metaPath -Raw
    if ($meta -match "category:\s*(.+)") { $category = $Matches[1].Trim() }
    if ($meta -match "name:\s*(.+)") { $challengeName = $Matches[1].Trim() }
}

$entry = @{
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")
    challenge = $challengeName
    category  = $category
    event     = $Event
    branch    = $Branch
    summary   = $Summary
} | ConvertTo-Json -Compress

Add-Content -Path $metricsFile -Value $entry -Encoding UTF8
Write-Host "[metrics] $Event logged for $challengeName" -ForegroundColor DarkGray
