#requires -version 5
<#
.SYNOPSIS
  Build the disposable Cyber Thunder range VM "acd-target-01" (Rocky Linux 9) without the VMware GUI.

.DESCRIPTION
  End to end, with no interaction:
    1. Load (or generate) the untracked secrets in range/.local/range.env.
    2. Fill range/vmware/ks.cfg and bake it onto a small ISO labelled OEMDRV (build_oemdrv.py).
    3. Create a 40 GB growable disk with vmware-vdiskmanager and write the .vmx.
    4. Boot from the Rocky ISO; Anaconda finds OEMDRV and installs hands-off, then powers off.
    5. Detach the install media, boot the clean system, wait for its IP via VMware Tools.
    6. Confirm `ssh acd@<ip> sudo -n true`, then snapshot "clean".

  Everything it writes (disk, vmx, OEMDRV ISO, filled kickstart) stays outside the repository or in
  the git-ignored range/.local/. Isolated range only: the NIC is NAT on VMnet8, never bridged.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File range\vmware\new-range-vm.ps1
#>
[CmdletBinding()]
param(
  [string]$VmName   = "acd-target-01",
  [string]$VmDir    = "C:\VM\acd-target-01",
  [string]$Iso      = "C:\VM\ISO\rocky9\Rocky-9-latest-x86_64-minimal.iso",
  [string]$VmwareDir= "C:\Program Files (x86)\VMware\VMware Workstation",
  [int]$MemoryMB    = 8192,
  [int]$Cpus        = 2,
  [int]$DiskGB      = 40,
  [int]$InstallTimeoutSec = 2400,
  [switch]$Force,          # recreate the VM even if the .vmx already exists
  [switch]$SkipSnapshot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptDir = $PSScriptRoot
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$LocalDir  = Join-Path $RepoRoot "range\.local"
$EnvFile   = Join-Path $LocalDir "range.env"
$KsTemplate= Join-Path $ScriptDir "ks.cfg"
$KsFilled  = Join-Path $LocalDir "ks.filled.cfg"
$Builder   = Join-Path $ScriptDir "build_oemdrv.py"

$VmRun     = Join-Path $VmwareDir "vmrun.exe"
$VdiskMgr  = Join-Path $VmwareDir "vmware-vdiskmanager.exe"
$Vmx       = Join-Path $VmDir "$VmName.vmx"
$Vmdk      = Join-Path $VmDir "$VmName.vmdk"
$Oemdrv    = Join-Path $VmDir "oemdrv.iso"

function Info($m){ Write-Host "[range] $m" -ForegroundColor Cyan }
function Warn($m){ Write-Host "[range] $m" -ForegroundColor Yellow }
function Die($m){ Write-Host "[range] ERROR: $m" -ForegroundColor Red; exit 1 }

function Require-File($path,$what){ if(-not (Test-Path -LiteralPath $path)){ Die "$what not found: $path" } }

function Find-OpenSsl {
  $c = Get-Command openssl.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  foreach ($p in @("C:\Program Files\Git\usr\bin\openssl.exe","C:\Program Files\Git\mingw64\bin\openssl.exe")) {
    if (Test-Path -LiteralPath $p) { return $p }
  }
  return $null
}

# ---- 0. prerequisites ------------------------------------------------------------
Require-File $VmRun "vmrun.exe (set -VmwareDir)"
Require-File $VdiskMgr "vmware-vdiskmanager.exe (set -VmwareDir)"
Require-File $Iso "Rocky 9 ISO (set -Iso)"
Require-File $KsTemplate "kickstart template ks.cfg"
Require-File $Builder "build_oemdrv.py"
$python = (Get-Command python.exe -ErrorAction SilentlyContinue)
if (-not $python) { Die "python.exe not on PATH (needed for the OEMDRV ISO builder)" }
New-Item -ItemType Directory -Force -Path $VmDir,$LocalDir | Out-Null

if ((Test-Path -LiteralPath $Vmx) -and -not $Force) {
  Die "$Vmx already exists. Use -Force to recreate, or delete $VmDir first."
}

# ---- 1. secrets (range/.local/range.env) -----------------------------------------
$cfg = @{}
if (Test-Path -LiteralPath $EnvFile) {
  Info "loading secrets from range/.local/range.env"
  foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $t = $line.Trim()
    if ($t -and -not $t.StartsWith("#") -and $t.Contains("=")) {
      $i = $t.IndexOf("="); $cfg[$t.Substring(0,$i).Trim()] = $t.Substring($i+1)
    }
  }
} else {
  Info "range.env missing; generating a password, hash and SSH key"
  $ssl = Find-OpenSsl
  if (-not $ssl) { Die "openssl not found (install Git for Windows, or create range/.local/range.env by hand)" }
  $alnum = ([char[]](48..57 + 65..90 + 97..122))
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $buf = New-Object byte[] 20
  $rng.GetBytes($buf)
  $pw = -join ($buf | ForEach-Object { $alnum[$_ % $alnum.Length] })
  $hash = (& $ssl passwd -6 $pw).Trim()
  $key = Join-Path $env:USERPROFILE ".ssh\ct_range_ed25519"
  if (-not (Test-Path -LiteralPath $key)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $key) | Out-Null
    & ssh-keygen -t ed25519 -N '""' -C "cyberthunder-range" -f $key | Out-Null
  }
  $pub = (Get-Content -LiteralPath "$key.pub" -Raw).Trim()
  @(
    "# Untracked range secrets for $VmName. Generated locally; never commit.",
    "ACD_USER=acd","ACD_PASSWORD=$pw","ACD_PWHASH=$hash",
    "SSH_KEY=$key","SSH_PUBKEY=$pub"
  ) | Set-Content -LiteralPath $EnvFile -Encoding ASCII
  foreach ($k in "ACD_USER","ACD_PASSWORD","ACD_PWHASH","SSH_KEY","SSH_PUBKEY") {
    $cfg[$k] = (Get-Content -LiteralPath $EnvFile | Where-Object { $_ -like "$k=*" }) -replace "^$k=",""
  }
}
foreach ($k in "ACD_PWHASH","SSH_PUBKEY","SSH_KEY") {
  if (-not $cfg.ContainsKey($k) -or [string]::IsNullOrWhiteSpace($cfg[$k])) { Die "range.env is missing $k" }
}
$SshKey = $cfg["SSH_KEY"]

# ---- 2. fill kickstart + build the OEMDRV ISO ------------------------------------
Info "filling kickstart -> range/.local/ks.filled.cfg"
$ks = Get-Content -LiteralPath $KsTemplate -Raw
$ks = $ks.Replace("@@ACD_PWHASH@@", $cfg["ACD_PWHASH"]).Replace("@@SSH_PUBKEY@@", $cfg["SSH_PUBKEY"])
if ($ks.Contains("@@")) { Die "kickstart still has an unfilled @@placeholder@@" }
# write without a BOM so Anaconda reads the first line cleanly
[System.IO.File]::WriteAllText($KsFilled, $ks, (New-Object System.Text.UTF8Encoding($false)))

Info "building OEMDRV ISO -> $Oemdrv"
& $python.Source -P $Builder --ks $KsFilled --out $Oemdrv
if ($LASTEXITCODE -ne 0) { Die "OEMDRV ISO build failed" }

# ---- 3. disk + vmx ---------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Vmdk) -or $Force) {
  if (Test-Path -LiteralPath $Vmdk) { Get-ChildItem -LiteralPath $VmDir -Filter "$VmName*.vmdk" | Remove-Item -Force }
  Info "creating ${DiskGB}GB growable disk with vmware-vdiskmanager"
  & $VdiskMgr -c -s "${DiskGB}GB" -a lsilogic -t 0 $Vmdk
  if ($LASTEXITCODE -ne 0) { Die "vmware-vdiskmanager failed" }
}

function Write-Vmx([bool]$MediaConnected) {
  $cd = if ($MediaConnected) { "TRUE" } else { "FALSE" }
  $lines = @(
    '.encoding = "windows-1252"',
    'config.version = "8"',
    'virtualHW.version = "21"',
    "displayName = `"$VmName`"",
    'guestOS = "rhel9-64"',
    'firmware = "efi"',
    'uefi.secureBoot.enabled = "FALSE"',
    "numvcpus = `"$Cpus`"",
    "memsize = `"$MemoryMB`"",
    # boot disk on NVMe (no legacy SCSI driver needed on RHEL 9)
    'nvme0.present = "TRUE"',
    'nvme0:0.present = "TRUE"',
    "nvme0:0.fileName = `"$VmName.vmdk`"",
    # two optical drives on SATA: Rocky ISO + the OEMDRV kickstart ISO
    'sata0.present = "TRUE"',
    'sata0:0.present = "TRUE"',
    'sata0:0.deviceType = "cdrom-image"',
    "sata0:0.fileName = `"$Iso`"",
    "sata0:0.startConnected = `"$cd`"",
    'sata0:1.present = "TRUE"',
    'sata0:1.deviceType = "cdrom-image"',
    "sata0:1.fileName = `"$Oemdrv`"",
    "sata0:1.startConnected = `"$cd`"",
    # NAT on VMnet8 only; never bridged
    'ethernet0.present = "TRUE"',
    'ethernet0.connectionType = "nat"',
    'ethernet0.virtualDev = "e1000e"',
    'ethernet0.addressType = "generated"',
    'vmci0.present = "TRUE"',
    'svga.present = "TRUE"',
    'tools.syncTime = "TRUE"',
    'pciBridge0.present = "TRUE"',
    'pciBridge4.present = "TRUE"',
    'pciBridge4.virtualDev = "pcieRootPort"',
    'pciBridge4.functions = "8"',
    'pciBridge5.present = "TRUE"',
    'pciBridge5.virtualDev = "pcieRootPort"',
    'pciBridge5.functions = "8"',
    'pciBridge6.present = "TRUE"',
    'pciBridge6.virtualDev = "pcieRootPort"',
    'pciBridge6.functions = "8"',
    'pciBridge7.present = "TRUE"',
    'pciBridge7.virtualDev = "pcieRootPort"',
    'pciBridge7.functions = "8"'
  )
  Set-Content -LiteralPath $Vmx -Value $lines -Encoding ASCII
}

Info "writing $Vmx (install media connected)"
Write-Vmx $true

# ---- 4. unattended install -------------------------------------------------------
Info "starting the VM for the unattended install (nogui)"
& $VmRun -T ws start $Vmx nogui
if ($LASTEXITCODE -ne 0) { Die "vmrun start failed" }

Info "waiting for the install to finish (the kickstart powers the VM off); timeout ${InstallTimeoutSec}s"
$deadline = (Get-Date).AddSeconds($InstallTimeoutSec)
Start-Sleep -Seconds 20
while ($true) {
  $running = (& $VmRun list) -join "`n"
  if ($running -notmatch [regex]::Escape($Vmx)) { Info "install finished; VM powered off"; break }
  if ((Get-Date) -ge $deadline) { Die "install did not finish within ${InstallTimeoutSec}s (inspect with: vmrun captureScreen)" }
  Start-Sleep -Seconds 15
}

# ---- 5. detach media, boot clean, get IP, verify sudo ----------------------------
Info "detaching install media and booting the clean system"
Write-Vmx $false
& $VmRun -T ws start $Vmx nogui
if ($LASTEXITCODE -ne 0) { Die "vmrun start (clean boot) failed" }

Info "waiting for VMware Tools to report an IP address"
$ip = (& $VmRun getGuestIPAddress $Vmx -wait).Trim()
if ($LASTEXITCODE -ne 0 -or -not $ip) { Die "could not get the guest IP (is open-vm-tools running?)" }
Info "guest IP: $ip"

Info "checking SSH and passwordless sudo as acd"
$sshArgs = @("-i",$SshKey,"-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=NUL",
             "-o","BatchMode=yes","-o","ConnectTimeout=10","acd@$ip","sudo -n true && echo SUDO_OK")
$ok = $false
for ($i=0; $i -lt 30; $i++) {
  $out = (& ssh.exe @sshArgs 2>$null)
  if ($out -match "SUDO_OK") { $ok = $true; break }
  Start-Sleep -Seconds 5
}
if (-not $ok) { Die "ssh acd@$ip 'sudo -n true' did not succeed (sshd/cloud still coming up?)" }
Info "SSH + passwordless sudo OK"

# ---- 6. snapshot -----------------------------------------------------------------
if (-not $SkipSnapshot) {
  Info "taking snapshot 'clean'"
  & $VmRun -T ws snapshot $Vmx clean
  if ($LASTEXITCODE -ne 0) { Die "snapshot failed" }
}

Write-Host ""
Info "DONE. acd-target-01 is up at $ip with snapshot 'clean'."
Info "Next: install k3s + podman and run the seed scripts, then snapshot 'seeded' (see range/vmware/README.md)."
Write-Output $ip
