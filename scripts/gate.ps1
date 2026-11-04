# Pre-push gate. Run from the repository root: powershell -File scripts/gate.ps1
# Prints PASS or FAIL for each step and ends with "GATE GREEN <sha>" or "GATE RED <sha>".
# Exit code is 0 only when every step passes.
#
# GATE_TEST_CMD overrides the test command (default: python -m pytest -q). It exists so the gate itself
# can be exercised in a scratch repository that has no test suite.
$ErrorActionPreference = 'Continue'
$top = (git rev-parse --show-toplevel) 2>$null
if (-not $top) { Write-Output 'not inside a git repository'; exit 2 }
Set-Location $top

$script:red = $false
function Step($name, $ok) {  # print the result and remember any failure
    if ($ok) { Write-Output "PASS  $name" } else { Write-Output "FAIL  $name"; $script:red = $true }
}

# The banned words are assembled from character codes so this file never contains them itself.
function Word($codes) { -join ([char[]]$codes) }
$wordA = Word 67, 108, 97, 117, 100, 101                     # first banned name
$wordB = Word 65, 110, 116, 104, 114, 111, 112, 105, 99      # second banned name
$banned = "$wordA|$wordB"
$handoff = (Word 67, 76, 65, 85, 68, 69) + '.md'             # handoff notes file, must stay untracked

# 1. Full test suite. Show only the tail so a failure is readable.
$testCmd = if ($env:GATE_TEST_CMD) { $env:GATE_TEST_CMD } else { 'python -m pytest -q' }
$out = Invoke-Expression "$testCmd 2>&1" | Out-String
$testRc = $LASTEXITCODE
$out.TrimEnd() -split "`r?`n" | Select-Object -Last 15 | ForEach-Object { Write-Output $_ }
Step "tests ($testCmd)" ($testRc -eq 0)

# 2. Forbidden references: the banned names in any tracked text file or in the last 50 commit messages,
#    plus automated-trailer phrases in those commit messages.
$bad = $false
$refs = git grep -I -i -l -E $banned -- . ':!vendor' 2>$null
if ($refs) { $bad = $true; $refs | ForEach-Object { Write-Output "  file: $_" } }
$msgs = git log -50 --format=%B 2>$null | Out-String
if ($msgs -match "(?i)$banned|Co-Authored-By:|Generated with") {
    $bad = $true; Write-Output '  a recent commit message has a forbidden reference'
}
Step 'forbidden references' (-not $bad)

# 3. Secrets in tracked files (vendor wheels and test fixtures are skipped): private key headers,
#    cloud access key ids, API-style tokens, and password assignments outside the docs.
$bad = $false
$skip = @(':!vendor', ':!tests/fixtures')
$hits = git grep -I -n -E -e '-{5}BEGIN' -e 'AKIA[0-9A-Z]{16}' -e 'sk-[A-Za-z0-9]{20,}' -- . @skip 2>$null
if ($hits) { $bad = $true; $hits | ForEach-Object { Write-Output "  $_" } }
# \" survives Windows PowerShell 5.1 native-argument passing (a bare " is stripped); a stray backslash in a
# bracket set is harmless on newer PowerShell.
$pw = '(password|passwd)[[:space:]]*[:=][[:space:]]*[\"''][^\"'']{4,}[\"'']'
$hits = git grep -I -n -i -E $pw -- . @skip ':!docs' ':!*.md' 2>$null
if ($hits) { $bad = $true; $hits | ForEach-Object { Write-Output "  $_" } }
Step 'secret scan' (-not $bad)

# 4. Whitespace errors in the latest commit (trailing spaces, stray conflict markers).
git show --check --format= HEAD *> $null
Step 'git diff --check' ($LASTEXITCODE -eq 0)

# 5. The handoff notes file must never be committed.
$tracked = git ls-files | Where-Object { $_ -match "(?i)(^|/)$([regex]::Escape($handoff))$" }
if ($tracked) { $tracked | ForEach-Object { Write-Output "  tracked: $_" } }
Step 'handoff file untracked' (-not $tracked)

$sha = git rev-parse --short HEAD 2>$null
if (-not $sha) { $sha = 'none' }
if (-not $script:red) { Write-Output "GATE GREEN $sha"; exit 0 }
Write-Output "GATE RED $sha"; exit 1
