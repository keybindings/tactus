#!/usr/bin/env bash
# =============================================================================
# tactusbox — full rebuild script
# =============================================================================
#
# Reproduces phases 1-4, 6 and 10 of the tactusbox build on a FRESH OVHcloud
# (or equivalent) dedicated server running Ubuntu Server 24.04 LTS.
#
# WHY THIS EXISTS
#   Neither OVH nor Hetzner resizes a dedicated box in place. Scaling means
#   rebuilding on new hardware. With this script that is 1-3 hours; without it,
#   most of a day.
#
# THIS SCRIPT DOES NOT INSTALL THE OS.
#   The OS install happens before any shell exists, so it cannot live here.
#   Replay `ovh-install-settings.json` (kept alongside this file) through the
#   OVHcloud API console FIRST, then run this script. That JSON pins the
#   critical detail: `"mountPoint": "/", "size": 0` means "all remaining space",
#   which is what keeps / at ~890 GiB instead of a ~20 GB root with the bulk on
#   /home. sccache lives in /var/cache and Docker in /var/lib, both under /.
#
# ENVIRONMENT ASSUMPTIONS (verified on the original build, 2026-08-17)
#   - Ubuntu 24.04.x LTS, kernel 6.8.x
#   - Login is the `ubuntu` user with passwordless sudo. NOT root: OVH's Ubuntu
#     template follows the cloud-image convention and refuses root SSH with
#     "Please login as the user ubuntu rather than the user root."
#   - 2x NVMe in soft RAID1 (md2 -> /boot, md3 -> /), both [UU]
#   - 32 threads, ~125 GB RAM
#
# INTERACTIVE STEPS ARE NOT AUTOMATED AND MUST NOT BE.
#   Three things need a human. The script stops and tells you:
#     1. `tailscale up --ssh`      (browser login URL)
#     2. `claude setup-token`      (paste-back OAuth flow)
#     3. `codex login --device-auth` (device code at chatgpt.com)
#   No credential is ever written into this script or echoed by it.
#
# USAGE
#   ./setup.sh              # run every phase in order
#   ./setup.sh 2 3 4        # run only the named phases
#   ./setup.sh --list       # show phases
#
# =============================================================================

set -euo pipefail

readonly TACTUS_REPO="https://github.com/keybindings/tactus.git"
readonly TACTUS_DIR="/srv/tactus"
readonly TACTUS_ENV="$HOME/.tactus-env"
readonly RAMTARGET="/mnt/ramtarget"
readonly RAMTARGET_SIZE="48G"
readonly SCCACHE_DIR="/var/cache/sccache"
readonly SCCACHE_SIZE="100G"
readonly MSRV="1.85.0"
readonly NODE_MAJOR="22"
readonly CODEX_VERSION="0.147.0"
readonly SWAPFILE="/swapfile"
readonly SWAPFILE_SIZE="32G"

# ---------------------------------------------------------------- output ------
readonly C_OK=$'\033[32m'; readonly C_ERR=$'\033[31m'
readonly C_WARN=$'\033[33m'; readonly C_HEAD=$'\033[1;36m'; readonly C_OFF=$'\033[0m'

phase()  { printf '\n%s=== PHASE %s: %s ===%s\n' "$C_HEAD" "$1" "$2" "$C_OFF"; }
ok()     { printf '  %s[ ok ]%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn()   { printf '  %s[warn]%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
fail()   { printf '  %s[FAIL]%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; return 1; }
note()   { printf '         %s\n' "$*"; }

# Halt for a human. Never try to automate past this.
handback() {
  printf '\n%s>>> MANUAL STEP REQUIRED <<<%s\n' "$C_WARN" "$C_OFF"
  printf '%s\n' "$@"
  printf '\nRe-run this script with the remaining phases once done.\n\n'
}

have() { command -v "$1" >/dev/null 2>&1; }

# Assert a binary exists; collect failures rather than dying on the first.
require_bins() {
  local missing=() c
  for c in "$@"; do
    if have "$c"; then ok "$c -> $(command -v "$c")"; else missing+=("$c"); fi
  done
  if (( ${#missing[@]} )); then fail "missing: ${missing[*]}"; fi
}

# Append a line to a file only if it is not already present (idempotency).
ensure_line() {
  local line="$1" file="$2"
  touch "$file"
  grep -qxF "$line" "$file" || printf '%s\n' "$line" >> "$file"
}

# Same, for root-owned system files.
#
# This exists because the first version of this script used plain ensure_line on
# /etc/fstab, which fails with "Permission denied" -- and because the tmpfs and
# swapfile had ALREADY been mounted imperatively by that point, everything looked
# fine. The failure only shows up at the next reboot, when /mnt/ramtarget is not
# mounted and every build silently writes to disk instead of RAM, and swap drops
# back to 1 GiB. Nothing errors; it just gets slow. Caught 2026-08-17.
ensure_line_sudo() {
  local line="$1" file="$2"
  sudo grep -qxF "$line" "$file" 2>/dev/null \
    || printf '%s\n' "$line" | sudo tee -a "$file" >/dev/null
}

# Make the build env visible to NON-INTERACTIVE shells.
#
# THIS IS NOT COSMETIC. Ubuntu's stock ~/.bashrc opens with
#     case $- in *i*) ;; *) return;; esac
# so anything APPENDED to it is invisible to non-interactive shells. Agent
# subprocesses (claude -p, codex exec) and `ssh host 'cmd'` are non-interactive.
# Append instead of prepend and those workers silently build with no
# RUSTC_WRAPPER and no CARGO_INCREMENTAL=0 -- i.e. no sccache and a near-zero
# hit rate, with nothing in the output to tell you. So: PREPEND to .bashrc
# (above the early return) and also append to .profile for login shells.
readonly ENV_BLOCK_START='# --- tactus build env (must precede the non-interactive early return) ---'
readonly ENV_BLOCK_END='# --- end tactus build env ---'

ensure_shell_env() {
  local f block
  block=$(cat <<EOF
${ENV_BLOCK_START}
[ -f "\$HOME/.cargo/env" ]  && . "\$HOME/.cargo/env"
[ -f "\$HOME/.tactus-env" ] && . "\$HOME/.tactus-env"
${ENV_BLOCK_END}
EOF
)
  for f in "$HOME/.bashrc" "$HOME/.profile"; do
    touch "$f"
    # Idempotent: drop any previous block and stray sourcing lines first.
    sed -i "/^${ENV_BLOCK_START}$/,/^${ENV_BLOCK_END}$/d" "$f"
    sed -i '/\.cargo\/env/d; /tactus-env/d' "$f"
  done
  # .bashrc must be PREPENDED (early return lives near the top).
  { printf '%s\n' "$block"; cat "$HOME/.bashrc"; } > "$HOME/.bashrc.tmp"
  mv "$HOME/.bashrc.tmp" "$HOME/.bashrc"
  # .profile has no such guard; appending is fine.
  printf '%s\n' "$block" >> "$HOME/.profile"

  # Verify in a real non-interactive shell rather than trusting the edit.
  local got
  got=$(bash -lc 'printf "%s|%s" "${RUSTC_WRAPPER:-UNSET}" "${CARGO_INCREMENTAL:-UNSET}"')
  ok "non-interactive shell sees RUSTC_WRAPPER|CARGO_INCREMENTAL = ${got}"
  case "$got" in
    UNSET*|*UNSET) warn "env NOT visible to non-interactive shells -- sccache will be bypassed" ;;
  esac
}

# =============================================================================
# PHASE 1 — Access: hostname, tmux, Tailscale, firewall, sshd hardening
# =============================================================================
#
# ORDERING IS SAFETY-CRITICAL. Read before editing.
#
# `ufw` here allows ONLY tailscale0. Enabling it before the tailnet is up and
# independently verified locks you out of the box completely -- the public IP
# stops answering and there is no other route in except OVH Serial-over-LAN.
#
# So phase 1 is deliberately split:
#   1a  hostname + tmux + install tailscale   (safe, no lockout risk)
#   1b  tailscale up --ssh                    (MANUAL: browser login)
#   1c  ufw + PasswordAuthentication no       (ONLY after 1b is verified)
#
# Before running 1c you must have proven, from a SECOND machine already on the
# tailnet, that `ssh <box>` works over the tailnet -- while the original
# public-IP session is still open. Verify, do not assume.
#
phase_1a() {
  phase 1a "hostname, tmux, Tailscale install"

  sudo hostnamectl set-hostname tactusbox
  # Keep /etc/hosts in step or sudo emits "unable to resolve host" on every call.
  if ! grep -q tactusbox /etc/hosts; then
    printf '127.0.1.1 tactusbox\n' | sudo tee -a /etc/hosts >/dev/null
  fi
  ok "hostname: $(hostname)"

  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tmux
  # Long agent stages run 10-40 min detached; without tmux a dropped SSH
  # connection kills a 40-minute worker.
  ensure_line 'set -g history-limit 200000' "$HOME/.tmux.conf"
  ensure_line 'set -g mouse on'             "$HOME/.tmux.conf"
  ok "tmux $(tmux -V | awk '{print $2}') configured"

  if ! have tailscale; then
    curl -fsSL https://tailscale.com/install.sh | sh
  fi
  ok "tailscale $(tailscale version | head -1)"
  systemctl is-active --quiet tailscaled && ok "tailscaled active" || fail "tailscaled not active"
}

phase_1b() {
  phase 1b "Tailscale authentication (MANUAL)"
  if tailscale status >/dev/null 2>&1; then
    ok "already authenticated to tailnet"
    tailscale status | head -5
    return 0
  fi
  handback \
"Run this INSIDE tmux so the login survives a dropped connection:

    tmux new-session -s tsup 'sudo tailscale up --ssh'

Visit the printed https://login.tailscale.com/... URL to authorise the node.

You must ALSO install Tailscale on whichever machine you drive this box from
and join it to the same tailnet, or phase 1c will lock you out."
  return 1
}

phase_1c() {
  phase 1c "Firewall + sshd hardening (DESTRUCTIVE IF UNVERIFIED)"

  # Refuse to proceed unless the tailnet is genuinely up. This guard is the
  # difference between a hardened box and a bricked one.
  if ! tailscale status >/dev/null 2>&1; then
    fail "tailnet is NOT up. Enabling ufw now would lock you out. Run phase 1b."
    return 1   # `|| warn` in main suppresses errexit here; fail alone does NOT stop us
  fi
  if ! ip link show tailscale0 >/dev/null 2>&1; then
    fail "tailscale0 interface does not exist. Refusing to enable ufw."
    return 1   # see above: without this, "Refusing" is a lie and ufw is enabled
  fi
  ok "tailscale0 present, tailnet up"

  warn "About to restrict inbound traffic to tailscale0 only."
  note "Confirm NOW, from a second machine on the tailnet, that ssh works,"
  note "with your current public-IP session still open. Ctrl-C if unsure."
  read -r -p "  Type YES to continue: " confirm
  [ "$confirm" = "YES" ] || { note "aborted"; return 1; }

  # DEADMAN SWITCH. If the rules below are wrong, the box becomes unreachable
  # and the only way back in is OVH Serial-over-LAN. This timer disables ufw
  # after 5 minutes unless we cancel it, turning a lockout into a wait.
  # A stale ufw-deadman unit makes this fail. Without the guard the phase
  # continued and enabled ufw with NO deadman, converting a recoverable
  # 5-minute lockout into a permanent one needing OVH Serial-over-LAN.
  sudo systemctl reset-failed ufw-deadman.service 2>/dev/null || true
  sudo systemctl stop ufw-deadman.timer 2>/dev/null || true
  if ! sudo systemd-run --on-active=300 --unit=ufw-deadman /usr/sbin/ufw --force disable; then
    fail "could not arm the deadman -- refusing to touch ufw"
    return 1
  fi
  # Prove it is actually armed rather than trusting the exit code.
  if ! sudo systemctl is-active ufw-deadman.timer >/dev/null 2>&1; then
    fail "ufw-deadman.timer is not active -- refusing to touch ufw"
    return 1
  fi
  warn "deadman armed: ufw auto-disables in 5 min unless cancelled"

  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow in on tailscale0
  # Not in the original brief, added deliberately: without inbound 41641/udp,
  # Tailscale cannot accept direct WireGuard connections and silently falls back
  # to relaying via DERP. Still works, but slower -- and we have just made the
  # tailnet the ONLY route in, so its performance now matters. Authenticated
  # WireGuard, so opening it costs nothing security-wise.
  sudo ufw allow 41641/udp comment 'tailscale direct (else it relays via DERP)'
  sudo ufw --force enable
  sudo ufw status verbose

  echo
  warn "VERIFY NOW from the other machine: ssh over the tailnet must work."
  note "If it does not, do nothing -- the deadman will restore access in <5 min."
  read -r -p "  Tailnet ssh confirmed working? Type YES to cancel the deadman: " confirm2
  if [ "$confirm2" = "YES" ]; then
    sudo systemctl stop ufw-deadman.timer 2>/dev/null || true
    sudo systemctl reset-failed ufw-deadman.service 2>/dev/null || true
    ok "deadman cancelled; firewall stands"
  else
    warn "deadman left armed -- ufw will disable itself shortly"
    return 1
  fi

  # Password auth. NOTE: on the OVH Ubuntu 24.04 template this is ALREADY `no`,
  # set by /etc/ssh/sshd_config.d/60-cloudimg-settings.conf, which takes
  # precedence over sshd_config. We write it explicitly anyway so that removing
  # that drop-in cannot silently re-enable password login.
  if ! grep -qE '^PasswordAuthentication no' /etc/ssh/sshd_config; then
    printf '\n# tactus: explicit, redundant with sshd_config.d/60-cloudimg-settings.conf.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
      | sudo tee -a /etc/ssh/sshd_config >/dev/null
  fi
  # Validate BEFORE reloading. A bad config plus a reload is how people lose a box.
  #
  # sshd -t needs the privilege separation directory to exist. Ubuntu 24.04 uses
  # SOCKET ACTIVATION (ssh.socket active, ssh.service inactive until a connection
  # arrives), and /run/sshd is created by ssh.service's RuntimeDirectory=sshd.
  # So on a freshly booted box /run/sshd does not exist and `sshd -t` fails with
  # "Missing privilege separation directory" -- a FALSE negative that looks like
  # a broken config. Create it first so the check tests what we think it tests.
  sudo mkdir -p /run/sshd
  if ! sudo sshd -t; then
    fail "sshd config invalid -- NOT reloading, you would lose access"
    return 1   # this used to fall through to `systemctl reload ssh` regardless
  fi
  ok "sshd config validates"
  sudo systemctl reload ssh
  ok "password auth disabled: $(sudo sshd -T | grep -i '^passwordauthentication')"
  note "Verify a fresh session works before closing this one."
}

# =============================================================================
# PREFLIGHT — install the token health check and its cron
# =============================================================================
#
# Expects ~/bin/tactus-preflight and 99-tactus-preflight to sit alongside this
# script (they travel together). Run AFTER phase 5, since the preflight proves
# tokens with live calls and cannot pass before they exist.
#
phase_preflight() {
  phase preflight "token health check + cron"
  [ -x "$HOME/bin/tactus-preflight" ] || fail "~/bin/tactus-preflight missing"

  "$HOME/bin/tactus-preflight" || fail "preflight does not pass -- fix auth before installing cron"

  # 6-hourly, offset off the hour to avoid the cron stampede.
  ( crontab -l 2>/dev/null | grep -v 'tactus-preflight'
    echo "7 */6 * * * $HOME/bin/tactus-preflight --quiet >> $HOME/.tactus-preflight.cron.log 2>&1" ) | crontab -
  ok "cron installed: $(crontab -l | grep tactus-preflight)"

  # No MTA and no push channel on this box, so failures surface at login.
  if [ -f "$(dirname "$0")/99-tactus-preflight" ]; then
    sudo install -m 755 "$(dirname "$0")/99-tactus-preflight" /etc/update-motd.d/99-tactus-preflight
    ok "MOTD banner installed"
  else
    warn "99-tactus-preflight not found alongside setup.sh; MOTD banner skipped"
  fi
}

# =============================================================================
# PHASE 2 — Base packages
# =============================================================================
#
# Two are load-bearing and easy to skip:
#   jq         - 5 of the 7 CI gate scripts in .github/scripts/ invoke it.
#   bubblewrap - enforces Codex's read-only sandbox. Without the system copy,
#                `codex exec` warns "could not find bubblewrap on PATH" and
#                silently falls back to a bundled one. It works either way, but
#                this is the ONLY containment mechanism for the reviewer, so we
#                want the real /usr/bin/bwrap.
#
phase_2() {
  phase 2 "Base packages"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential pkg-config libssl-dev \
    git curl jq tmux mosh ripgrep unzip rsync bubblewrap \
    ca-certificates gnupg netcat-openbsd

  # gh is NOT in Ubuntu's repos; it comes from GitHub's. preflight [7/8] and
  # review-pr.sh both shell out to it, and tactus-winguest's wait loop needs nc
  # (above) -- without it the guest finishes while the script waits 100 minutes.
  if ! have gh; then
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg status=none
    sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gh
  fi
  require_bins git curl jq tmux mosh rg rsync bwrap cc gh nc
  ok "jq $(jq --version), bubblewrap $(bwrap --version | awk '{print $2}')"
}

# =============================================================================
# PHASE tools — put the ops tooling where every later phase expects it
# =============================================================================
#
# Ordered BEFORE `preflight`, which hard-fails without ~/bin/tactus-preflight.
# That circularity is why a "fresh rebuild" previously needed a human to copy
# files in by hand. Everything here travels alongside setup.sh in infra/.
#
phase_tools() {
  phase tools "Ops tooling into ~/bin"
  local here f
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  mkdir -p "$HOME/bin"

  for f in tactus-build tactus-preflight tactus-watch tactus-session \
           tactus-claude tactus-grab tactus-winguest; do
    if [ -f "$here/$f" ]; then
      install -m 755 "$here/$f" "$HOME/bin/$f"
    else
      warn "$f not found next to setup.sh"
    fi
  done
  ok "installed: $(ls "$HOME/bin" | tr '\n' ' ')"

  # phase9.sh is invoked as ~/phase9.sh, not from ~/bin.
  if [ -f "$here/phase9.sh" ]; then
    install -m 755 "$here/phase9.sh" "$HOME/phase9.sh"
    ok "installed ~/phase9.sh"
  fi

  # The orchestrator session must survive logout, which needs BOTH the user unit
  # and lingering. Without lingering systemd kills the session at logout and the
  # tmux orchestrator dies with it.
  if [ -f "$here/tactus-session.service" ]; then
    mkdir -p "$HOME/.config/systemd/user"
    install -m 644 "$here/tactus-session.service" \
      "$HOME/.config/systemd/user/tactus-session.service"
    systemctl --user daemon-reload 2>/dev/null || true
    sudo loginctl enable-linger "$USER" \
      && ok "tactus-session unit installed, lingering enabled" \
      || warn "lingering NOT enabled -- the orchestrator will die at logout"
  fi
}

# =============================================================================
# PHASE 3 — Rust toolchain
# =============================================================================
#
# 1.85.0 is REQUIRED: the MSRV gate is
#   cargo +1.85.0 check --locked --all-targets --all-features
# There is no rust-toolchain.toml in the repo -- toolchain selection is explicit
# at call sites, so nothing auto-corrects a wrong default.
#
phase_3() {
  phase 3 "Rust toolchain (stable + ${MSRV} MSRV)"
  if ! have rustup; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --component rustfmt,clippy
  fi
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
  rustup toolchain install "$MSRV"

  ok "$(rustc --version)"
  ok "$(cargo --version)"
  ok "$(rustfmt --version)"
  ok "$(cargo clippy --version)"
  cargo "+${MSRV}" --version >/dev/null 2>&1 \
    && ok "MSRV resolves: $(cargo "+${MSRV}" --version)" \
    || fail "cargo +${MSRV} does not resolve"

  ensure_shell_env
}

# =============================================================================
# PHASE 4 — Node and the two agent CLIs
# =============================================================================
#
# codex is pinned to EXACTLY 0.147.0 -- the workflow depends on that version's
# semantics. Invocation notes worth keeping with the install:
#   - `codex exec` in 0.147.0 REJECTS `-a never`; that flag no longer exists.
#   - working review invocation:
#       codex exec -m gpt-5.6-sol -c 'model_reasoning_effort="max"' \
#         --strict-config -s read-only --ephemeral -C <dir> -o <file> -
#   - `--skip-git-repo-check` is REQUIRED whenever -C points outside a git repo,
#     or codex exits "Not inside a trusted directory" before making any call.
#
phase_4() {
  phase 4 "Node ${NODE_MAJOR}, claude-code, codex ${CODEX_VERSION}"
  if ! have node; then
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo -E bash -
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs
  fi
  ok "node $(node --version), npm $(npm --version)"

  sudo npm install -g @anthropic-ai/claude-code
  sudo npm install -g "@openai/codex@${CODEX_VERSION}"

  # codex sandboxes every filesystem command through bubblewrap, and Ubuntu 24.04
  # ships kernel.apparmor_restrict_unprivileged_userns=1, which blocks the user
  # namespace bwrap needs. Without this profile every codex FILE READ fails while
  # text round-trips keep working -- the failure that had a reviewer returning
  # confident empty results for seven hours (2026-08-17), and which preflight
  # [4b/8] exists to catch. The profile grants userns to /usr/bin/bwrap ONLY; the
  # system-wide sysctl stays at 1.
  #
  # This was documented in comments but never provisioned, so a rebuild recreated
  # the denial it warned about. Frontier review of PR #19, finding 2.
  local aa_src
  aa_src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/apparmor-bwrap"
  if [ -f "$aa_src" ]; then
    sudo install -m 644 "$aa_src" /etc/apparmor.d/bwrap
    sudo systemctl reload apparmor || warn "apparmor reload failed -- codex file reads may fail"
    if bwrap --ro-bind / / --unshare-net --dev /dev true 2>/dev/null; then
      ok "bwrap userns profile installed and verified"
    else
      warn "bwrap still cannot create a user namespace -- codex file reads will fail"
    fi
  else
    warn "apparmor-bwrap missing next to setup.sh -- codex file reads will fail on Ubuntu 24.04"
  fi

  ok "claude $(claude --version)"
  local cv; cv="$(codex --version)"
  [ "$cv" = "codex-cli ${CODEX_VERSION}" ] \
    && ok "codex $cv" \
    || fail "codex version is '$cv', expected 'codex-cli ${CODEX_VERSION}'"
}

# =============================================================================
# PHASE 5 — Authentication (MANUAL) and the preflight check
# =============================================================================
phase_5() {
  phase 5 "Authentication (MANUAL)"
  handback \
"Both flows are proven to work headless -- no tunnelling or workarounds needed.

  1. claude setup-token
     Prints a URL using redirect_uri=platform.claude.com/oauth/code/callback
     &code=true -- a paste-back flow, so no localhost callback and no SSH
     tunnel. It emits a long-lived token that it saves NOWHERE. Put it in
     ${TACTUS_ENV} (mode 600) as:
         export CLAUDE_CODE_OAUTH_TOKEN=<token>

  2. codex login --device-auth
     Prints a chatgpt.com URL and a short code.

Then run: ./setup.sh preflight"
  return 1
}

# =============================================================================
# PHASE 6 — Build caching
# =============================================================================
#
# CARGO_INCREMENTAL=0 is REQUIRED, not stylistic: sccache cannot cache
# incremental artifacts and silently drops to a near-zero hit rate otherwise.
# It costs a little on rebuilds of the same tree and wins substantially across
# different worktrees, which is the actual pattern here.
#
# Target dirs go on tmpfs -- the single biggest wall-clock win available with
# 128 GB. They must be PER-WORKTREE: a shared target dir serialises builds on
# cargo's directory lock, which silently destroys the parallelism this box
# exists to provide.
#
phase_6() {
  phase 6 "Build caching: sccache + tmpfs + swap"
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"

  have sccache || cargo install sccache --locked
  ok "$(sccache --version)"

  sudo mkdir -p "$SCCACHE_DIR"
  sudo chown "$(id -u):$(id -g)" "$SCCACHE_DIR"

  sudo mkdir -p "$RAMTARGET"
  if ! mountpoint -q "$RAMTARGET"; then
    sudo mount -t tmpfs -o "size=${RAMTARGET_SIZE},mode=1777" tmpfs "$RAMTARGET"
  fi
  ensure_line_sudo "tmpfs	${RAMTARGET}	tmpfs	size=${RAMTARGET_SIZE},mode=1777	0	0" /etc/fstab
  ok "tmpfs at ${RAMTARGET} ($(df -h "$RAMTARGET" | awk 'NR==2{print $2}'))"

  # The OVH install leaves only ~1 GiB of swap across two unmirrored 512M
  # partitions. With a 48G tmpfs competing for RAM, give the kernel somewhere to
  # evict cold pages instead of invoking the OOM killer on a 40-minute worker.
  if ! swapon --show=NAME --noheadings | grep -q "$SWAPFILE"; then
    sudo fallocate -l "$SWAPFILE_SIZE" "$SWAPFILE"
    sudo chmod 600 "$SWAPFILE"
    sudo mkswap "$SWAPFILE" >/dev/null
    sudo swapon "$SWAPFILE"
  fi
  # Outside the branch deliberately: if the swapfile was activated imperatively
  # and its fstab entry is missing or commented, the old code skipped this and
  # the reboot silently lost 32 GiB of swap. ensure_line_sudo is idempotent.
  ensure_line_sudo "${SWAPFILE}	none	swap	sw	0	0" /etc/fstab
  ok "swap total: $(free -h | awk '/Swap/{print $2}')"

  # Persistence is not optional here and is invisible until a reboot, so assert
  # it rather than assuming the fstab edits landed.
  # grep -q "$X" matches a COMMENTED line too, so the old check certified
  # persistence that a reboot would disprove. Require a live (uncommented) entry.
  sudo grep -qE "^[[:space:]]*[^#[:space:]].*${RAMTARGET}[[:space:]]" /etc/fstab \
    && ok "tmpfs persisted in /etc/fstab" \
    || fail "tmpfs NOT live in /etc/fstab -- it will vanish on reboot"
  sudo grep -qE "^[[:space:]]*${SWAPFILE}[[:space:]]" /etc/fstab \
    && ok "swapfile persisted in /etc/fstab" \
    || fail "swapfile NOT live in /etc/fstab -- swap drops to ~1 GiB on reboot"
  sudo findmnt --verify >/dev/null 2>&1 \
    && ok "fstab validates" \
    || warn "findmnt --verify reported issues -- inspect before rebooting"

  cat > "$TACTUS_ENV.phase6" <<EOF
# Build caching -- sourced from ${TACTUS_ENV}
export RUSTC_WRAPPER=sccache
export SCCACHE_DIR=${SCCACHE_DIR}
export SCCACHE_CACHE_SIZE=${SCCACHE_SIZE}
# REQUIRED: sccache cannot cache incremental artifacts.
export CARGO_INCREMENTAL=0
# Size of the target-dir slot pool used by tactus-build. Set at or above your
# maximum concurrent build count: too few and builds queue on a slot lock, too
# many and you dilute cache reuse across more distinct paths.
export TACTUS_SLOTS=8
export TACTUS_RAMTARGET=${RAMTARGET}

# ~/bin holds tactus-build, tactus-preflight, tactus-watch, tactus-claude.
# Ubuntu puts ~/bin on PATH from .profile, which ONLY LOGIN SHELLS READ. A tmux
# pane running plain bash does not, and neither does any agent subprocess. The
# failure is silent and expensive: cargo still works, so a build that cannot
# find tactus-build just uses a per-invocation target dir and gets zero cache
# reuse. Set it here, where every shell that sources the env picks it up.
export PATH="\$HOME/bin:\$PATH"

# DO NOT set CARGO_TARGET_DIR per worktree. Use \`tactus-build <cmd>\` instead.
#
# Measured on this box 2026-08-17 with two worktrees at an identical commit:
#     source differs, target same   -> 54/55 sccache hits (98.18%)
#     source same,    target differs->  0/55 sccache hits ( 0.00%)
# The cache key is poisoned by CARGO_TARGET_DIR, not by the source path: every
# rustc call carries -L dependency=<target>/... and --extern <target>/...
#
# A target dir per worktree is an UNBOUNDED set of paths, so no two worktrees
# ever share cache entries. A bounded slot pool keeps isolation (cargo's lock
# only conflicts between CONCURRENT builds) while making paths repeat.
#
# Wall clock, second worktree, this project: 8.80s -> 4.62s.
tactus_target() {
  echo "tactus_target is deprecated -- use: tactus-build cargo <args>" >&2
  return 1
}
EOF
  touch "$TACTUS_ENV"; chmod 600 "$TACTUS_ENV"
  ensure_line "source ${TACTUS_ENV}.phase6" "$TACTUS_ENV"
  ensure_shell_env
  ok "build env written to ${TACTUS_ENV}.phase6"

  # SOLVED (2026-08-17). Earlier note here said cross-worktree hits were 0% and
  # probably unfixable. A controlled experiment showed otherwise -- see the
  # comment block in ~/bin/tactus-build. Short version: the cache key is poisoned
  # by CARGO_TARGET_DIR, NOT by the source path, so a bounded slot pool restores
  # reuse while keeping concurrent builds isolated. 8.80s -> 4.62s on the second
  # worktree. Use `tactus-build cargo ...`, never a per-worktree CARGO_TARGET_DIR.
  if [ -x "$HOME/bin/tactus-build" ]; then
    ok "tactus-build present -- use it instead of setting CARGO_TARGET_DIR"
  else
    warn "~/bin/tactus-build missing; it should travel alongside setup.sh"
  fi
}

# =============================================================================
# PHASE 7 — Windows guest VM (the Windows test leg)
# =============================================================================
#
# A Server 2025 KVM guest so `ssh windowsguest 'cargo test ...'` surfaces
# Windows-only failures in minutes instead of after a push. CI already covers
# windows-latest; this is for SPEED, not coverage — and Server 2025 is the
# same OS as GitHub's windows-latest image, so failures reproduce CI
# faithfully.
#
# The heavy lifting is in tactus-winguest (idempotent subcommands; `up`
# chains download → ISO repack → unattended install → provisioning → verify).
# The guest install is fully unattended via autounattend.xml.in; the three
# guest files (autounattend.xml.in, winguest-provision.ps1, tactus-winguest)
# travel alongside this script, like tactus-build does.
#
phase_7() {
  phase 7 "Windows guest VM (Server 2025 on KVM)"
  [ -e /dev/kvm ] || { fail "/dev/kvm missing — KVM not available on this box"; return 1; }

  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    qemu-kvm libvirt-daemon-system libvirt-clients virtinst ovmf \
    swtpm swtpm-tools genisoimage xorriso wimtools
  sudo systemctl enable --now libvirtd
  sudo usermod -aG libvirt,kvm "$USER"
  # sudo, not the libvirt group: on a fresh rebuild the group membership
  # above is not in this shell's token yet (needs a re-login). tactus-winguest
  # detects the same and prefixes sudo when the group is missing.
  sudo virsh net-start default 2>/dev/null || true
  sudo virsh net-autostart default >/dev/null
  ok "libvirt up, default NAT network autostarted"

  # Stage the guest sources where tactus-winguest looks for them.
  mkdir -p "$HOME/winguest" "$HOME/bin"
  local here f
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  for f in autounattend.xml.in winguest-provision.ps1; do
    if [ -f "$here/$f" ]; then install -m 644 "$here/$f" "$HOME/winguest/$f"; else warn "$f not found next to setup.sh"; fi
  done
  if [ -f "$here/tactus-winguest" ]; then install -m 755 "$here/tactus-winguest" "$HOME/bin/tactus-winguest"; fi

  # The ssh alias the whole workflow keys on (phase9's windows leg, and you).
  touch "$HOME/.ssh/config"; chmod 600 "$HOME/.ssh/config"
  if ! grep -q '^Host windowsguest$' "$HOME/.ssh/config"; then
    printf '\nHost windowsguest\n  HostName 192.168.122.25\n  User Administrator\n  StrictHostKeyChecking accept-new\n' >> "$HOME/.ssh/config"
  fi
  ok "ssh alias windowsguest -> 192.168.122.25"

  "$HOME/bin/tactus-winguest" up
}

# =============================================================================
# PHASE 8 — Antigravity CLI (the S9 panel's third reviewer)
# =============================================================================
#
# Gemini 3.1 Pro as an independent reviewer alongside Sol (codex) and Fable
# (claude). PR4's evidence for wanting a third: three SERIAL confirmations by
# one model each returned CHANGES_REQUIRED and each found a different class the
# previous passes had read straight past — including a production defect on the
# third. A single model re-samples its own blind spot.
#
# Google shut Gemini CLI down on 2026-06-18. `agy` (Antigravity CLI) is the
# successor and the only supported path for a Pro/Ultra subscription. It is a
# flat Go binary; the official installer is user-local by default, which is why
# this phase does NOT fight npm's unwritable /usr prefix the way phase 4 does.
#
# THE INVOCATION IS LOAD-BEARING. Four flags, each mandatory, each learned by
# watching it fail on this box (2026-08-20):
#   --output-format=json  text mode HANGS on a denied tool permission —
#                         observed >10 min on a `cat` — while json returns a
#                         structured ERROR in ~12 s. Never run this leg in text
#                         mode; a hang in a 6-hourly preflight is a false green
#                         waiting to happen.
#   --add-dir=<dir>       without it the agent searches /workspace and fails
#                         "search directory /workspace does not exist", even
#                         with cwd correct.
#   --mode=plan           read-only agent mode. Unlike codex this needs no
#                         bwrap, so the AppArmor/userns hazard that blinded a
#                         reviewer for seven hours on PR3 does not apply here.
#   --model=<pinned>      a lapsed or quota-exhausted subscription does not
#                         error, it silently serves Flash.
#
# `agy` EXITS 0 EVEN WHEN IT PRODUCED NOTHING. The exit code is worthless;
# assert on the JSON status and on a marker, the way [3/8] ignores codex's.
#
# The tool permission model denies everything in headless mode unless allowed
# in settings.json, so the read-only command set is written there explicitly.
#
phase_8() {
  phase 8 "Antigravity CLI (Gemini 3.1 Pro reviewer)"
  if ! have agy; then
    curl -fsSL https://antigravity.google/cli/install.sh | bash
  fi
  export PATH="$HOME/.local/bin:$PATH"
  ensure_line 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.profile"
  have agy || fail "agy not on PATH after install"
  ok "agy $(agy --version 2>&1 | head -1)"

  # Read-only command allow-list. Headless mode cannot prompt, so anything not
  # listed here is auto-denied — and in text mode that denial HANGS.
  # `realpath` is not optional: the agent resolves paths before reading them.
  # python3 is NOT optional: reviewer prompts query the 645 KB packet with
  # `python3 -c` rather than cat it, so omitting it auto-denies the one tool
  # the review depends on. Cost of getting this wrong, measured: five resumed
  # turns, ~1.4M tokens, zero output — a denial in headless mode CANCELs the
  # turn with an empty response. `realpath` is likewise required: the agent
  # resolves a path before reading it.
  local settings="$HOME/.gemini/antigravity-cli/settings.json"
  mkdir -p "$(dirname "$settings")"
  [ -f "$settings" ] || echo '{}' > "$settings"
  python3 - "$settings" <<'PYEOF'
import json, sys
p = sys.argv[1]
s = json.load(open(p))
cmds = ["cat","ls","rg","git","find","head","sed","realpath","pwd","stat","wc",
        "grep","awk","tail","cut","sort","uniq","nl","basename","dirname",
        "readlink","file","tree","du","echo","test","which","diff",
        "python3","jq","tr","xargs","comm","sha256sum"]
s.setdefault("permissions", {})["allow"] = ["command(%s)" % c for c in cmds]
s.setdefault("enableTelemetry", False)
json.dump(s, open(p, "w"), indent=2)
PYEOF
  ok "read-only command allow-list written to $settings"

  # OAuth only — there is no API-key path today (upstream issue #78). The
  # browser half cannot be automated and must not be faked.
  if [ ! -d "$HOME/.gemini/antigravity-cli" ] || ! agy models >/dev/null 2>&1; then
    handback \
      "Run:  agy" \
      "" \
      "Choose 'Login with Google' and authorise as the account holding the" \
      "Google AI Pro subscription (Gemini 3.1 Pro is a paid-tier model; the" \
      "free tier silently serves Flash instead). Then /quit." \
      "" \
      "Verify with: tactus-preflight   — checks [5/8], [5b/8] and [6/8]."
    return 0
  fi
  agy models 2>/dev/null | grep -q 'gemini-3.1-pro-high' \
    && ok "gemini-3.1-pro-high offered by this credential" \
    || warn "gemini-3.1-pro-high NOT offered — check the AI Pro subscription"
}

# =============================================================================
# PHASE 10 — Docker
# =============================================================================
phase_10() {
  phase 10 "Docker CE"
  if ! have docker; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' \
      "$(dpkg --print-architecture)" "$(. /etc/os-release && echo "$VERSION_CODENAME")" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  sudo systemctl enable --now docker
  sudo usermod -aG docker "$USER" || true
  ok "$(sudo docker --version)"
  sudo docker run --rm hello-world >/dev/null 2>&1 \
    && ok "docker run --rm hello-world succeeded" \
    || fail "hello-world failed"
  note "Group change needs a new login before rootless 'docker' works for $USER."
}

# =============================================================================
# main
# =============================================================================
readonly PHASES=(1a 1b 1c 2 tools 3 4 5 preflight 6 7 8 10)

usage() {
  printf 'usage: %s [phase ...]\n\nphases: %s\n' "$0" "${PHASES[*]}"
  printf '  1a  hostname, tmux, tailscale install\n'
  printf '  1b  tailscale auth              (MANUAL)\n'
  printf '  1c  ufw + sshd hardening        (verify tailnet first!)\n'
  printf '  2   base packages\n'
  printf '  3   rust toolchain + MSRV\n'
  printf '  4   node, claude-code, codex\n'
  printf '  5   claude/codex auth           (MANUAL)\n'
  printf '  preflight  token health check + 6-hourly cron + MOTD banner\n'
  printf '  6   sccache, tmpfs, swap\n'
  printf '  tools  ops tooling into ~/bin (must precede preflight)\n'
  printf '  7   windows guest VM (Server 2025 on KVM)\n'
  printf '  8   antigravity CLI (gemini 3.1 pro reviewer)\n'
  printf '  10  docker\n'
}

main() {
  if [ "${1:-}" = "--list" ] || [ "${1:-}" = "-h" ]; then usage; exit 0; fi
  local want=("$@")
  (( ${#want[@]} )) || want=("${PHASES[@]}")
  local p
  for p in "${want[@]}"; do
    if declare -F "phase_${p}" >/dev/null; then
      "phase_${p}" || warn "phase ${p} stopped (see above)"
    else
      warn "unknown phase: ${p}"
    fi
  done
  printf '\n%sdone%s\n' "$C_HEAD" "$C_OFF"
}

main "$@"
