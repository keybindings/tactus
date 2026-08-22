#!/usr/bin/env bash
# Make the tactus build environment visible to NON-INTERACTIVE shells.
#
# Ubuntu's stock ~/.bashrc opens with:
#     case $- in *i*) ;; *) return;; esac
# so anything appended to the end is invisible to non-interactive shells. Agent
# subprocesses (claude -p, codex exec) and `ssh host 'cmd'` are non-interactive,
# which means they would inherit NO RUSTC_WRAPPER and NO CARGO_INCREMENTAL=0 --
# building without sccache at a near-zero hit rate, silently.
#
# Fix: source the tactus env from ABOVE that early return, and from ~/.profile.
set -euo pipefail

BLOCK_START='# --- tactus build env (must precede the non-interactive early return) ---'
BLOCK_END='# --- end tactus build env ---'

strip_old() {
  local f="$1"
  [ -f "$f" ] || return 0
  # Drop any previous tactus block and any bare appended sourcing lines.
  sed -i "/^${BLOCK_START}$/,/^${BLOCK_END}$/d" "$f"
  sed -i '/\.cargo\/env/d' "$f"
  sed -i '/tactus-env/d' "$f"
}

block() {
  cat <<'EOF'
# --- tactus build env (must precede the non-interactive early return) ---
[ -f "$HOME/.cargo/env" ]        && . "$HOME/.cargo/env"
[ -f "$HOME/.tactus-env" ]       && . "$HOME/.tactus-env"
# --- end tactus build env ---
EOF
}

echo "=== patching ~/.bashrc (prepend) ==="
strip_old "$HOME/.bashrc"
{ block; cat "$HOME/.bashrc"; } > "$HOME/.bashrc.new"
mv "$HOME/.bashrc.new" "$HOME/.bashrc"
head -8 "$HOME/.bashrc"

echo
echo "=== patching ~/.profile (append; login shells) ==="
strip_old "$HOME/.profile"
block >> "$HOME/.profile"
tail -5 "$HOME/.profile"

echo
echo "=== VERIFY: non-interactive login shell ==="
bash -lc 'printf "RUSTC_WRAPPER=%s\nSCCACHE_DIR=%s\nSCCACHE_CACHE_SIZE=%s\nCARGO_INCREMENTAL=%s\ncargo=%s\nsccache=%s\n" \
  "${RUSTC_WRAPPER:-UNSET}" "${SCCACHE_DIR:-UNSET}" "${SCCACHE_CACHE_SIZE:-UNSET}" \
  "${CARGO_INCREMENTAL:-UNSET}" "$(command -v cargo || echo MISSING)" "$(command -v sccache || echo MISSING)"'

echo
echo "=== VERIFY: tactus_target helper ==="
bash -lc 'type tactus_target >/dev/null 2>&1 && echo "tactus_target: defined" || echo "tactus_target: MISSING"'
