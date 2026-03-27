param(
    [Parameter(Mandatory=$true)][string]$Path
)

$pass = $true
$checks = @()

# 1. meta.yaml exists
$metaPath = Join-Path $Path "meta.yaml"
if (Test-Path $metaPath) {
    $checks += "[PASS] meta.yaml exists"
} else {
    $checks += "[FAIL] meta.yaml missing"
    $pass = $false
}

# 2. solve.py or exploit.py exists and non-trivial (>200 bytes)
$solver = $null
foreach ($f in @("exploit.py", "solve.py")) {
    $candidate = Join-Path $Path $f
    if (Test-Path $candidate) { $solver = $candidate; break }
}
if ($solver) {
    $size = (Get-Item $solver).Length
    if ($size -gt 200) {
        $checks += "[PASS] $((Split-Path $solver -Leaf)) exists ($size bytes)"
    } else {
        $checks += "[FAIL] $((Split-Path $solver -Leaf)) is still template ($size bytes)"
        $pass = $false
    }
} else {
    $checks += "[FAIL] No solve.py or exploit.py"
    $pass = $false
}

# 3. memory/recon.md non-empty
$reconPath = Join-Path $Path "memory" "recon.md"
if ((Test-Path $reconPath) -and ((Get-Item $reconPath).Length -gt 20)) {
    $checks += "[PASS] memory/recon.md populated"
} else {
    $checks += "[FAIL] memory/recon.md empty or missing"
    $pass = $false
}

# 4. memory/strategy.md non-empty
$stratPath = Join-Path $Path "memory" "strategy.md"
if ((Test-Path $stratPath) -and ((Get-Item $stratPath).Length -gt 20)) {
    $checks += "[PASS] memory/strategy.md populated"
} else {
    $checks += "[FAIL] memory/strategy.md empty or missing"
    $pass = $false
}

# Report
Write-Host ""
$checks | ForEach-Object { Write-Host $_ }
Write-Host ""

if ($pass) {
    Write-Host "[GATE] PASS" -ForegroundColor Green
} else {
    Write-Host "[GATE] FAIL" -ForegroundColor Red
}
