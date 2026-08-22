# =============================================================================
# tactusbox Windows guest bootstrap
# =============================================================================
# Runs ONCE, elevated, at the built-in Administrator's first logon
# (FirstLogonCommands in autounattend.xml). Everything is logged to
# C:\provision\provision.log; the host waits for C:\provision\DONE.
#
# Order matters only in one place: OpenSSH comes up FIRST so the guest is
# reachable (and debuggable over ssh) while the long installs run. The host's
# wait loop keys on the DONE marker, not on port 22, so early ssh does not
# fool it.
# =============================================================================
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path C:\provision | Out-Null
Start-Transcript -Path C:\provision\provision.log -Append

# Pinned versions. Bump deliberately; the point of this box is repeatability.
$GIT_URL    = 'https://github.com/git-for-windows/git/releases/download/v2.50.1.windows.1/Git-2.50.1-64-bit.exe'
$VSBT_URL   = 'https://aka.ms/vs/17/release/vs_buildtools.exe'
$RUSTUP_URL = 'https://win.rustup.rs/x86_64'
$MSRV       = '1.85.0'
$REPO_URL   = 'https://github.com/keybindings/tactus'

function Fetch($url, $out) {
  # curl.exe ships with the OS and is far less flaky than Invoke-WebRequest
  # for large binaries (no IE engine, real retries).
  & curl.exe -fsSL --retry 3 --retry-delay 5 -o $out $url
  if ($LASTEXITCODE -ne 0) { throw "download failed: $url" }
}

# --- 1. OpenSSH server + key auth -------------------------------------------
# Server 2025 ships the sshd binaries in some SKUs; the capability add is a
# no-op when already present.
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
  $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
  Add-WindowsCapability -Online -Name $cap.Name | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
# The OpenSSH capability PRE-CREATES this rule on Server 2025 but leaves it
# unusable here: the virtio NIC lands on the Public profile and the shipped
# rule does not apply there. A create-if-missing check therefore sees the
# rule, skips, and the guest is silently unreachable (cost: one debugging
# session via virsh send-key, 2026-08-18). Enforce the end state instead.
try {
  Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled True -Profile Any -ErrorAction Stop
} catch {
  New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
    -Enabled True -Profile Any -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

# Administrators authenticate against THIS file, not ~/.ssh/authorized_keys.
# sshd refuses it outright if the ACL is wider than SYSTEM + Administrators.
Copy-Item "$PSScriptRoot\authorized_keys" C:\ProgramData\ssh\administrators_authorized_keys -Force
# The copy came off a CD-ROM and keeps its read-only attribute; appending a
# key later then fails with a misleading "access denied" despite a correct
# ACL. Clear it here.
Set-ItemProperty C:\ProgramData\ssh\administrators_authorized_keys -Name IsReadOnly -Value $false
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r `
  /grant 'SYSTEM:F' /grant 'BUILTIN\Administrators:F' | Out-Null
Write-Output 'sshd up, key auth configured'

# --- 2. virtio guest tools (qemu-ga + the drivers WinPE did not load) -------
$vcd = Get-PSDrive -PSProvider FileSystem |
  Where-Object { Test-Path "$($_.Root)virtio-win-guest-tools.exe" } |
  Select-Object -First 1
if ($vcd) {
  Start-Process -Wait -FilePath "$($vcd.Root)virtio-win-guest-tools.exe" `
    -ArgumentList '/install','/passive','/norestart'
  Write-Output 'virtio guest tools installed'
} else {
  Write-Output 'WARN: virtio-win CD not found; qemu-ga skipped'
}

# --- 3. Git ------------------------------------------------------------------
Fetch $GIT_URL C:\provision\git-setup.exe
Start-Process -Wait C:\provision\git-setup.exe -ArgumentList '/VERYSILENT','/NORESTART','/NOCANCEL'
Write-Output 'git installed'

# --- 4. VS Build Tools: MSVC v143 + Windows SDK ------------------------------
# This is the linker and CRT rustc's *-msvc target needs. rustc finds the
# installation itself (registry/COM), so no vcvars in ssh sessions.
# 3010 = success, reboot required — we reboot at the end anyway.
Fetch $VSBT_URL C:\provision\vs_buildtools.exe
$p = Start-Process -Wait -PassThru C:\provision\vs_buildtools.exe -ArgumentList `
  '--quiet','--wait','--norestart','--nocache', `
  '--add','Microsoft.VisualStudio.Workload.VCTools','--includeRecommended'
if ($p.ExitCode -notin 0, 3010) { throw "vs_buildtools exited $($p.ExitCode)" }
Write-Output 'VS Build Tools installed'

# --- 5. rustup: stable MSVC + the 1.85.0 MSRV toolchain ----------------------
Fetch $RUSTUP_URL C:\provision\rustup-init.exe
& C:\provision\rustup-init.exe -y --default-host x86_64-pc-windows-msvc --default-toolchain stable
if ($LASTEXITCODE -ne 0) { throw "rustup-init exited $LASTEXITCODE" }
$rustup = "$env:USERPROFILE\.cargo\bin\rustup.exe"
& $rustup toolchain install $MSRV
if ($LASTEXITCODE -ne 0) { throw "rustup toolchain install $MSRV exited $LASTEXITCODE" }
& $rustup component add rustfmt clippy
Write-Output 'rust toolchains installed'

# --- 6. repo checkout --------------------------------------------------------
# phase9's Windows leg pushes the host's HEAD here (unpushed work included),
# then checks out the sha detached. denyCurrentBranch=ignore covers the case
# where a pushed ref collides with the checked-out branch.
$git = "$env:ProgramFiles\Git\cmd\git.exe"
if (-not (Test-Path C:\tactus)) { & $git clone $REPO_URL C:\tactus }
& $git -C C:\tactus config receive.denyCurrentBranch ignore

# Defender exclusions for the hot paths: link.exe output and rustc temp churn
# are exactly the access patterns real-time scanning is slowest at.
Add-MpPreference -ExclusionPath 'C:\tactus', "$env:USERPROFILE\.cargo", "$env:USERPROFILE\.rustup" `
  -ErrorAction SilentlyContinue

# --- 7. done -----------------------------------------------------------------
Set-Content C:\provision\DONE ("ok " + (Get-Date -Format s))
Write-Output 'provisioning complete, rebooting'
Stop-Transcript
Restart-Computer -Force
