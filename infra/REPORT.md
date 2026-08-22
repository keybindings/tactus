# tactusbox build report

**Box:** OVHcloud RISE-L (AMD Ryzen 9 9950X, 16c/32t, 128 GB DDR5, 2x960 GB NVMe soft RAID1), Gravelines. Host identifiers redacted.
**Built:** 2026-08-17
**OS:** Ubuntu 24.04.4 LTS, kernel 6.8.0-137-generic, UEFI
**Login:** `ubuntu` + passwordless sudo (NOT root — see difference #2)

---

## 0. Final state (updated after Phase 8 restore)

`/srv/tactus` is at **`73cd006`** (fast-forwarded from `df05503`) with the
in-flight snapshot restored:

```
 M src/lib.rs        (one added line: pub mod topology;)
?? src/topology/     (mod.rs 703 B, registry.rs 127,593 B)
```

This reproduces `in-flight/WORKTREE-STATUS.txt` exactly. **All four gates pass in
this state**, and `git diff` reports `index cfcb0b1..88a040f` — the identical blob
hashes recorded in `in-flight/lib.rs.diff`, proving the restored `src/lib.rs` is
the same git object as the original work.

`time cargo test --all-targets --all-features` in this state:

| Condition | real |
|---|---|
| **Warm** | **4.65 s** |
| **Cold** (target wiped + sccache cleared) | **13.97 s** |

Test count here: **618 passed, 0 failed, 9 ignored**.

Progression: 575 (`df05503`) → 594 (`+3 unpushed commits`) → **618** (`+topology`).

> Note on `src/lib.rs` in the snapshot: the captured copy had **CRLF on every
> line** while the repo file is LF. Copying it verbatim would have shown all 51
> lines as modified and, with `core.autocrlf false`, carried CRLF into any commit.
> Restored instead by inserting the single `pub mod topology;` line into the
> repo's LF file. The two topology files were already LF and were copied
> byte-for-byte (SHA256 verified).

> Note on upstream: no PR has merged since **#14 on 2026-08-14**. PR **#2** was
> closed *without* merging and targeted `review-base-v01`, not `master`; #15 was
> also closed unmerged; #16 and #17 remain open. `src/topology/` exists in **zero**
> upstream refs, so the migration snapshot was genuinely its only copy.

---

## 1. Phase 9 baseline

All four gates pass **at `73cd006`** (i.e. with the three unpushed commits applied):

| Gate | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --all-targets --all-features` | pass |
| `cargo +1.85.0 check --locked --all-targets --all-features` | clean |

`time cargo test --all-targets --all-features` at `73cd006`:

| Condition | real | user | sys |
|---|---|---|---|
| **Warm** (target populated — your brief's sequence: gates, then time) | **5.02 s** | 8.14 s | 8.55 s |
| **Cold** (target wiped *and* sccache cache cleared — true from-scratch) | **13.44 s** | 19.45 s | 10.34 s |

Both figures are on tmpfs (`/mnt/ramtarget`), `CARGO_INCREMENTAL=0`, 32 threads.

Read the **13.44 s** as "this box builds and tests the whole project from nothing in
under fourteen seconds". The warm 5.02 s is almost entirely test *execution*
(4.69 s of it), which is dominated by test logic rather than CPU count — so a
faster machine compresses the compile half far more than the run half.

Context for why these numbers are small: 60 packages in `Cargo.lock`, 32 Rust
source files, ~46,150 lines. Only 55 compilation units. `user+sys ≈ 30 s` over
13.4 s wall is ~2.2× parallelism — the build is dependency-chain-bound, not
core-bound, so most of the 32 threads sit idle. More cores would not help much;
this is close to the floor for the crate graph.

## 2. Test count

At `73cd006`: **594 passed, 0 failed, 9 ignored, 0 measured, 0 filtered out**
(plus two additional test binaries reporting 0 tests each).

At `df05503` (pushed HEAD, no unpushed work): 575 passed, 0 failed, 9 ignored.
So the three unpushed commits add **19 tests**.

## 3. Seven bash gates

All 7 `test-*.sh` gates pass. All 15 scripts in `.github/scripts/` are
`#!/usr/bin/env bash` with `set -euo pipefail`, and all 15 pass `bash -n`.

---

## 4. Differences from the brief

### Blocking, resolved

1. **The box had no OS.** The brief opens "Freshly installed Ubuntu Server 24.04
   LTS, root SSH access via key." It was bare — OVH panel read *"There is no
   operating system installed on your server"*, boot was set to
   `rescue12-customer`, and no SSH key was registered. That is why port 22 timed
   out (dropped, not refused). You ran the template install; everything after
   Phase 0 was built on the fresh result.

2. **Root SSH is disabled.** The box answers
   `Please login as the user "ubuntu" rather than the user "root"` — OVH's Ubuntu
   template follows the cloud-image convention. Kept as-is rather than
   re-enabling root: sudo covers everything, and running model-generated code
   (`claude -p`, `codex exec`) as an unprivileged user is a real improvement on a
   box whose entire job is executing it. `~/.ssh/config` on CameronPC uses
   `User ubuntu`.

3. **OVH's default partitioning was already correct.** The brief predicted a
   ~20 GB `/` with the bulk on `/home` and said to stop if found. The wizard
   proposed **no `/home` at all** and gave `/` 892.6 GiB on RAID1 (878 G as
   formatted, `/dev/md3`). The stop condition never fired. The load-bearing
   detail is `"mountPoint": "/", "size": 0` in the install JSON — `0` means
   "all remaining space".

### Environment / correctness findings

4. **Non-interactive shells could not see the build environment.** Ubuntu's
   stock `~/.bashrc` opens with `case $- in *i*) ;; *) return;; esac`. Appending
   the env sourcing put it at lines 118–119, *after* that return, so a
   non-interactive shell reported `RUSTC_WRAPPER=UNSET` and
   `CARGO_INCREMENTAL=UNSET`. Agent subprocesses and `ssh host 'cmd'` are
   non-interactive — they would have built **without sccache and with
   incremental enabled**, silently, which is exactly the near-zero-hit-rate
   failure the brief warns about. Fixed by *prepending* the block above the early
   return and also adding it to `~/.profile`; verified in a real non-interactive
   shell. `setup.sh` now does this via `ensure_shell_env()`.

5. **sccache cross-worktree hits: diagnosed and FIXED.** The first measurement
   was 0% across worktrees, and an earlier draft of this report wrote that off as
   probably unfixable. A controlled experiment proved otherwise.

   Two worktrees at an identical commit (verified byte-identical), varying source
   path and target path independently:

   | condition | source | target | hits | rate |
   |---|---|---|---|---|
   | CONTROL | wtA | expA | 0/55 | 0% (cold) |
   | TEST-A | wtA **same** | expB **differs** | **0/55** | **0%** |
   | TEST-B | wtB **differs** | expA **same** | **54/55** | **98.18%** |
   | REPEAT | wtA | expA | 55/55 | 100% |

   **The cache key is poisoned by `CARGO_TARGET_DIR`, not by the source path.**
   Every rustc invocation carries `-L dependency=<target>/debug/deps` and
   `--extern name=<target>/debug/deps/libfoo.rlib`. Changing the source
   directory costs nothing; changing the target directory costs everything.
   (`SCCACHE_BASEDIR` is irrelevant here and had no effect — stats still report
   `Base directories (none)` after a restart with it exported.)

   That means **the brief's own guidance was the cause**:
   `CARGO_TARGET_DIR=/mnt/ramtarget/$(basename "$PWD")` creates an *unbounded*
   set of target paths, one per worktree, so no two worktrees ever share a cache
   entry.

   Per-worktree isolation was never the real requirement — cargo's directory lock
   only conflicts between **concurrent** builds. So the fix is a *bounded slot
   pool*: `~/bin/tactus-build` takes an exclusive `flock` on one of
   `TACTUS_SLOTS` (default 8) target dirs and runs the command with
   `CARGO_TARGET_DIR` pointed at it. Full isolation, but paths repeat, so cache
   entries are reused.

   Measured payoff, second worktree at a *different* commit, verified after a
   reboot with a cold cache:

   | build | approach | wall clock | crates rebuilt |
   |---|---|---|---|
   | wtA (cold) | slot1 | 8.89 s | 55 |
   | **wtB** | **recycled slot1** | **4.94 s** | **1** |
   | wtB control | per-worktree dir (old guidance) | 8.82 s | 55 |

   **44% faster.** And the mechanism is better than sccache: when the recycled
   slot already holds valid artifacts, cargo reuses them *directly* without
   invoking rustc at all, so sccache is never even consulted (hence `hits=0,
   misses=1` on that run — one genuinely-changed crate). Slot reuse buys you a
   cargo-level hit, which beats an sccache-level hit outright. sccache remains
   useful as the second line, for when cargo *does* have to recompile.

   **A bug in the first version of `tactus-build`, worth recording.** It took the
   slot lock with `flock <lockfile> <command>`, where the lock file lived inside
   the target dir. `flock(1)` passes its open fd through to the command; cargo
   started the **sccache server daemon** under that lock; the daemon inherited
   the fd; and because the server is long-lived it kept the lock held after the
   build exited. `fuser` confirmed it:
   `/mnt/ramtarget/slot1/.lock: ubuntu 2191 f.... sccache`.

   Every later build therefore saw slot1 as busy and moved to slot2, then slot3,
   and so on — walking the whole pool and achieving **zero** reuse, the exact
   opposite of the script's purpose. It presented as "the second build was
   *slower* than the first", which is what prompted the investigation.

   Fixed by starting the sccache server *before* acquiring any lock (so it
   inherits nothing) and moving lock files to `$RAMTARGET/.locks/` outside the
   target dirs. Verified: three consecutive builds all select `slot1`, only one
   slot directory is created, and no process holds a lock afterwards.

   **Usage:** `tactus-build cargo test --all-targets --all-features`. Never set
   `CARGO_TARGET_DIR` per worktree. Set `TACTUS_SLOTS` at or above your maximum
   concurrent build count.

   Caveat on scale: this was measured on a 60-package, 46k-line project whose
   cold build is ~14 s. The *ratio* should hold or improve on larger codebases;
   the absolute seconds will grow.

6. **`cargo fmt --check` fails at `df05503` — but this is pre-existing and your
   unpushed work fixes it.** 12 diffs, all in `src/engine/tests.rs`, the file
   created by `df05503 refactor(engine): extract inline tests`. Pinned down by
   bisecting with the *same* toolchain:
   - `13c5d0a` (parent) → fmt clean
   - `df05503` (pushed HEAD) → **12 diffs**
   - `73cd006` (with unpushed commits) → fmt clean

   So the environment was never wrong; that commit was committed without a fmt
   pass. Since `ci.yml:81` runs `cargo fmt --check`, **CI should be red on
   `df05503` as pushed** — worth knowing independently of this box. No action
   taken: running `cargo fmt` would have rewritten your branch and destroyed the
   baseline Phase 9 exists to establish.

7. **`git rev-parse <full-sha>` is not an existence check.** The brief's
   verification `git rev-parse 73cd006a…  # must resolve` passes even when the
   object is absent — `rev-parse` echoes a well-formed 40-char SHA back
   regardless. It "passed" while `git log df05503..73cd006` failed with *unknown
   revision*. The honest check is
   `git cat-file -e <sha>^{commit}`. Same class of lie as the `exp`-claim warning
   in Phase 5.

8. **`git fetch <bundle> 'refs/*:refs/*'` is refused.** The bundle's ref is
   `refs/heads/codex/parallelism-design`, which is the branch checked out at
   `/srv/tactus`, so git blocks the update. Fetched into `refs/bundle/*` instead —
   objects present, working tree untouched. Note `git bundle verify` *succeeded*
   here rather than reporting "lacks prerequisite commits", because it was run
   from inside a repo that already has `df05503`.

9. **`test-pr-policy.sh` is sensitive to invocation form.** Line 5 is
   `script_dir="${BASH_SOURCE[0]%/*}"`. Invoked as a bare filename there is no
   slash, `%/*` strips nothing, and line 6 attempts
   `cd test-pr-policy.sh/../..`. It fails under the brief's suggested
   `cd .github/scripts && bash test-*.sh`, and passes when invoked from the repo
   root as `bash .github/scripts/test-pr-policy.sh` — which is what `ci.yml`
   does. Not an environment problem; a latent script bug.

10. **`jq` count.** The brief says five of seven gate scripts invoke it. Four of
    the seven `test-*.sh` call `jq` directly; several others reach it through the
    `validate-*` / `frontier-*` helpers, so the effective dependency is broader
    than four but the literal "five of seven" does not match. Either way `jq` is
    required and installed (`jq-1.7`).

### Hardware / config notes

11. **Install swap was 1023 MiB** across two *unmirrored* 512 M partitions
    (`nvme0n1p4` pri −2, `nvme1n1p4` pri −3). `free -g` reported `0` purely from
    GB truncation. Added a **32 GiB swapfile** in Phase 6 — with a 48 G tmpfs
    competing for RAM, the kernel needs somewhere to evict cold pages rather than
    OOM-killing a 40-minute worker.

12. ~~**The EFI system partition is not mirrored.**~~ **RETRACTED — this was
    wrong.** An earlier draft of this report claimed a boot single-point-of-
    failure because only `nvme1n1p1` is mounted at `/boot/efi`. Investigating
    properly showed OVH configured EFI redundancy correctly and completely:

    - **Both ESPs are populated and byte-for-byte identical** — `grubx64.efi`,
      `grub.cfg` and `BOOTX64.EFI` all match across `nvme0n1p1` and `nvme1n1p1`.
    - **Both have firmware boot entries**, and both are in `BootOrder`:
      `Boot0004* ubuntu HD(1,GPT,1057dd1e-…)` → nvme0n1p1
      `Boot0005* ubuntu HD(1,GPT,7ed014e6-…)` → nvme1n1p1
    - **`grub-efi/install_devices` lists both disks**, so every kernel and grub
      update writes to both ESPs and they cannot drift.
    - `grub.cfg` resolves `/boot` via `mduuid/f80d7940…`, i.e. through the RAID
      array, so it does not care which disk it booted from.

    Either disk can fail and the box still boots. No action taken or needed.

    The one residual oddity: `/etc/fstab` mounts `/boot/efi` by
    `LABEL=EFI_SYSPART` and **both** partitions carry that label, so which one
    mounts is not deterministic. Harmless while grub keeps them identical, and
    editing `fstab` to pin a UUID would add real risk (a bad `fstab` can block
    boot) for no benefit. Deliberately left alone.

    Lesson for the record: the original claim came from observing one mount point
    and inferring the rest. `lsblk` showing an unmounted partition says nothing
    about whether it is populated or bootable.

13. **No mdadm resync was pending** at first contact — both members already
    `active sync`, so the baseline timings are not skewed by background disk
    traffic.

14. **The monitoring-disable step was unnecessary.** That warning is on the
    IPMI panel and applies to installing an OS manually through the KVM. The
    template install is orchestrated by OVH, which knows the downtime is
    expected. (I advised disabling it earlier; that was over-applied.)

15. **Tailscale authentication is interactive** and the brief did not flag it —
    only Phase 5 was marked as such. `tailscale up --ssh` prints a browser login
    URL. More importantly, the Phase 1 firewall (`ufw` allowing only
    `tailscale0`) is a **guaranteed lockout** if enabled before the tailnet is up
    *and* independently verified from a second machine. Phase 1 was therefore
    split 1a/1b/1c in `setup.sh`, with 1c refusing to run unless `tailscale0`
    exists and `tailscale status` succeeds.

16. **`codex login status` exits 0 while printing "Not logged in".** Measured on
    codex-cli 0.147.0. The exit code is worthless as a signal, so
    `tactus-preflight` string-matches the output *and* does a real `codex exec`
    round-trip. Same class of lie as the `exp`-claim warning in the brief.

17. **`claude setup-token` prints the token once and saves it nowhere**, and the
    token is long enough to wrap in a standard terminal. Selecting the wrapped
    text by hand silently captured a **92-character fragment** that looked
    entirely plausible — `~/.tactus-env` was written, the variable was set, the
    length was non-zero — and returned `401 Invalid bearer token` on first use.
    Captured correctly on the second attempt by running the command under
    `script(1)`, which records the byte stream the program writes rather than the
    wrapped terminal rendering, then extracting with a regex. Log shredded after.
    **This is the single best argument in the build for why the preflight must
    make live calls**: every cheap check said the token was fine.

18. **The preflight's first version had a false pass.** Its `codex exec` check
    fell back to grepping stderr for the marker — but codex echoes the prompt
    back in its error output, and the prompt *contains* the marker. It therefore
    reported success while codex was demonstrably logged out. Caught only because
    the negative test was run. The stderr fallback is removed and commented
    against reintroduction; only the `-o` output file counts as proof.

19. **`PasswordAuthentication no` was already set** by the cloud image's
    `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf`, which takes precedence
    over `sshd_config`. Written explicitly into `sshd_config` anyway so removing
    that drop-in cannot silently re-enable password login.

20. **`ufw allow 41641/udp` added, beyond the brief's rule set.** Without it
    Tailscale cannot accept direct inbound WireGuard and silently falls back to
    relaying via DERP — still functional, but slower, and the tailnet is now the
    only route in, so its performance matters. Authenticated WireGuard, so
    opening it costs nothing security-wise.

21. **The tmpfs and swapfile were never persisted to `/etc/fstab`.** The first
    version of `setup.sh` used a non-sudo helper to append to `/etc/fstab`, which
    failed with *Permission denied*. Because both had already been mounted
    imperatively in the same run, everything looked correct — `df` showed the
    48 G tmpfs, `free` showed 32 GiB swap — and the failure would only have
    surfaced at the next reboot, when `/mnt/ramtarget` would not mount and every
    build would silently write to **disk instead of RAM**, with swap dropping
    back to ~1 GiB. No error, just a slow box.

    Fixed: added `ensure_line_sudo()`, wrote both entries, and `setup.sh` now
    *asserts* persistence rather than assuming it. Verified by unmounting both
    and running `mount -a` + `swapon -a` — exactly what boot does — which
    restored the 48 G tmpfs and 32 GiB swap. `findmnt --verify`: 0 errors.

    Worth noting as a pattern: this is the third failure in this build that was
    invisible to the obvious check (the others being the 92-char token and the
    preflight's stderr false-pass). Imperative success does not imply persistent
    success.

22. **Reboot test passed.** Rebooted deliberately to verify nothing was
    imperative-only. Back on the tailnet in **~70 s**, boot id changed
    (`552de24b…` → `db8d5e7b…`) confirming a real reboot, reached over Tailscale
    with the public IP still firewalled. All verified after the reboot:

    - tmpfs 48 G mounted, swap 32 GiB active (the `/etc/fstab` fix holding)
    - both RAID arrays `[2/2] [UU]`
    - tailnet on the same IP `<tailnet-ip>`, `ufw` active, all services up
    - `RUSTC_WRAPPER`/`CARGO_INCREMENTAL`/`TACTUS_SLOTS` present in a
      non-interactive shell
    - sccache disk cache survived (it lives on `/var/cache`, not the tmpfs)
    - repo at `73cd006` with the in-flight work intact
    - preflight passes

23. **`sshd -T` and `sshd -t` fail on a freshly booted box.** Ubuntu 24.04 uses
    socket activation: `ssh.socket` is active and `ssh.service` is *inactive*
    until a connection arrives, and `/run/sshd` is created by that service's
    `RuntimeDirectory=sshd`. So on a fresh boot the directory does not exist and
    both commands abort with `Missing privilege separation directory: /run/sshd`
    — a **false negative** that looks like a broken sshd config.

    This mattered: `setup.sh` validates with `sshd -t` before reloading sshd, so
    on a rebuild it would have refused to reload and reported an invalid config
    that was in fact fine. Fixed with `sudo mkdir -p /run/sshd` before the check.
    (Password auth was confirmed `no` once the directory existed.)

24. **`rsync` is absent on CameronPC.** Irrelevant — the migration bundle is
    2.7 MB / 92 files and went over `scp`, which copies bytes verbatim (no CRLF
    rewriting). `rsync` is installed server-side per Phase 2.

---

## 5. Verified state

| Component | Version / value |
|---|---|
| `/` | 878 G avail, `/dev/md3` ext4, RAID1 `[2/2] [UU]` |
| `/boot` | `/dev/md2`, RAID1 `[2/2] [UU]` |
| CPU / RAM | 32 threads, 125 GB (123 available) |
| swap | 32 GiB (1023 M partitions + 32 G swapfile) |
| tmpfs | 48 G at `/mnt/ramtarget` |
| rustc / cargo | `1.97.1 (8bab26f4f 2026-07-14)` / `1.97.1 (c980f4866 2026-06-30)` |
| rustfmt / clippy | `1.9.0-stable` / `0.1.97` |
| MSRV | `1.85.0 (4d91de4e4 2025-02-17)` resolves |
| node / npm | `v22.23.2` / `10.9.8` |
| claude | `2.1.233` |
| codex | `codex-cli 0.147.0` |
| sccache | `0.17.0` |
| docker | `29.7.2`, `hello-world` OK |
| tailscale | `1.102.2`, daemon active+enabled, **not yet authenticated** |
| tmux | `3.4`, `history-limit 200000`, `mouse on` (verified live) |
| bubblewrap | `0.9.0` at `/usr/bin/bwrap` (system copy, not bundled) |
| jq | `jq-1.7` |
| repo | `/srv/tactus` at `df05503`, porcelain clean, `core.autocrlf false` |
| migration bundle | 91/91 hashes OK **after** transfer |
| design packet | `02bfed75…55df6` — exact match |
| artifacts | 83 files, 2.4 M at `~/tactus-artifacts/` |
| unpushed commits | fetched to `refs/bundle/codex/parallelism-design`, `73cd006` present, exactly 3 commits |

## 5b. Access hardening (Phase 1c) — DONE

```
ufw: active
  Anywhere on tailscale0      ALLOW IN
  41641/udp                   ALLOW IN   # tailscale direct (else DERP relay)
  Default: deny (incoming), allow (outgoing), deny (routed)

sshd:  passwordauthentication no
       kbdinteractiveauthentication no
       pubkeyauthentication yes
```

Verified after enabling, with a **deadman switch armed** (`systemd-run
--on-active=300` to auto-disable ufw) so a wrong rule would have self-healed in
five minutes instead of requiring Serial-over-LAN:

| Route | Result |
|---|---|
| `ssh tactusbox` (tailnet <tailnet-ip>) | **works** |
| `tailscale ssh ubuntu@tactusbox` (identity-based) | **works** |
| `ssh tactusbox-pub` (public IP) | **blocked, times out** |

Two independent routes confirmed before the deadman was cancelled. `sshd -t`
validated the config *before* the reload.

`~/.ssh/config` on CameronPC now defines `tactusbox` (tailnet, durable) and
`tactusbox-pub` (public, now firewalled). Break-glass beyond both is OVH
Serial-over-LAN.

## 5c. Preflight (Phase 5) — DONE

`~/bin/tactus-preflight`, 4 checks, all live:

```
[1/4] claude: token present        108 chars, sk-ant-oat01-...
[2/4] claude: live round-trip      claude -p returned the marker
[3/4] codex: login status          Logged in using ChatGPT
[4/4] codex: live round-trip       codex exec returned the marker
PASS
```

- **Negative-tested.** Run against a bogus token with an isolated `HOME`, it
  fails all four checks and exits 1. A health check that has never been seen to
  fail is not a health check.
- **Cron-tested.** Run under `env -i HOME=... SHELL=... PATH=/usr/bin:/bin` it
  still passes, so it will not silently die at 00:07.
- **Cron:** `7 */6 * * *`, offset off the hour.
- **Alerting:** syslog (`journalctl -t tactus-preflight`) + a status file read by
  `/etc/update-motd.d/99-tactus-preflight`, so a failure is the first thing you
  see at login. There is no MTA and no push channel on this box — if you want
  this on your phone, a webhook needs wiring in, and that needs a URL only you
  can supply.

## 6. Outstanding

**Needs a decision:**
- **Phase 8 step 3** — restoring `in-flight/` overwrites `src/lib.rs` and adds
  two files (`src/topology/mod.rs`, `src/topology/registry.rs`) that exist in no
  commit, no index and no bundle. Not touched.
- Whether to fast-forward `/srv/tactus` from `df05503` to `73cd006` (a
  fast-forward — no commits lost).
- ~~Whether to mirror the ESP~~ — investigated and closed, see #12. Already
  correct, nothing to do.
- ~~Whether to pursue cross-worktree sccache hits~~ — investigated and **fixed**,
  see #5. Use `tactus-build`; 8.80 s → 4.62 s on the second worktree.
- Whether to revoke the first Claude token (#17). It is visible in a screenshot
  but truncated by ~28 of 108 characters, so not practically recoverable.
  Console-side; low priority.

## 7. Deliverables on the box

- `~/setup.sh` — phases 1a/1b/1c, 2, 3, 4, 5, 6, 10. `./setup.sh --list` for
  usage; individual phases runnable (`./setup.sh 2 3 4`). `bash -n` clean.
  Phases 6 and 10 were executed *through* this script, so they are known to work
  rather than merely transcribed.
- `~/ovh-install-settings.json` — the OS install itself, which `setup.sh` cannot
  reproduce because it runs before any shell exists. Replay through the OVH API
  console first, then run `setup.sh`.
- `~/fix-shellenv.sh` — standalone version of the non-interactive-shell fix
  (#4); also folded into `setup.sh`.
- `~/phase9.sh` — the gate runner used for the baseline above.
- `~/REPORT.md` — this file.
