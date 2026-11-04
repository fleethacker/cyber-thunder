<#
.SYNOPSIS
  Idempotent dev-machine setup for Cyber Thunder. Safe to re-run. No admin required.
  - Ollama (per-user) + models
  - Python requirements + vendored wheels for offline install
  - Runs the unit tests
#>
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }

Step "Git hooks (strip AI attribution trailers; per-clone setting)"
git config core.hooksPath .githooks
"hooksPath = $(git config core.hooksPath)"

Step "Ollama"
$ol = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
if (-not (Test-Path $ol)) {
    winget install --id Ollama.Ollama -e --scope user --silent --accept-source-agreements --accept-package-agreements
}
if (-not (Test-Path $ol)) { $ol = (Get-Command ollama -ErrorAction SilentlyContinue).Source }
if (-not $ol) { Write-Warning "ollama not found; install manually from ollama.com"; }
else {
    $up = $false
    try { Invoke-WebRequest -Uri http://localhost:11434/api/version -UseBasicParsing -TimeoutSec 3 | Out-Null; $up = $true } catch {}
    if (-not $up) { Start-Process -FilePath $ol -ArgumentList "serve" -WindowStyle Hidden; Start-Sleep -Seconds 6 }
    foreach ($m in @("qwen2.5:3b", "qwen2.5:7b-instruct")) { & $ol pull $m }
    & $ol list
}

Step "Python packages"
python -m pip install -q -r requirements-dev.txt
python -m pip download -q -r requirements.txt -d vendor
"vendor wheels: $((Get-ChildItem vendor -Filter *.whl).Count)"

Step "Tests"
python -m unittest discover -s tests

Step "Done"
"Offline install later:  python -m pip install --no-index --find-links vendor -r requirements.txt"
