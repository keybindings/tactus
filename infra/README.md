# infra/

Provisioning and operations tooling for the dedicated build box that runs the
multi-agent workflow.

Neither OVH nor Hetzner resizes a dedicated server in place, so scaling means
rebuilding on new hardware. With this directory that is 1–3 hours; without it,
most of a day.

## Rebuilding from nothing

1. **`ovh-install-settings.json`** — replay through the OVHcloud API console.
   This step cannot live in `setup.sh` because it happens before any shell
   exists. Substitute your own `sshKey` first.

   The load-bearing value is `"mountPoint": "/", "size": 0`. `0` means *use all
   remaining space*, which yields ~890 GiB on `/`. OVH's default is a ~20 GB
   root with the bulk on `/home`, and sccache (`/var/cache`) plus Docker
   (`/var/lib`) both live under `/`, so a small root fills during the first
   real build.

2. **`setup.sh`** — everything else. `./setup.sh --list` for phases; individual
   phases are runnable (`./setup.sh 2 3 4`).

   ```
   1a  hostname, tmux, tailscale install
   1b  tailscale auth              (MANUAL — browser login)
   1c  ufw + sshd hardening        (verify tailnet first, deadman-switched)
   2   base packages
   3   rust toolchain + MSRV
   4   node, claude-code, codex
   5   claude/codex auth           (MANUAL — paste-back + device code)
   preflight  token health check + 6-hourly cron + MOTD banner
   6   sccache, tmpfs, swap
   7   windows guest VM      (Server 2025 on KVM, fully unattended)
   8   antigravity CLI       (Gemini 3.1 Pro, the S9 panel's third seat)
   10  docker
   ```

   The three manual steps are deliberately not automated: they are interactive
   OAuth flows, and a script that pretends otherwise would only fail later and
   less clearly.

## Operations

| File | Purpose |
|---|---|
| `tactus-preflight` | Proves both agent CLIs can make a **live call**. Cron'd 6-hourly. |
| `tactus-watch` | Polls the watched branch; runs the full gates on each new commit. |
| `tactus-build` | Wraps cargo with a slot-pooled `CARGO_TARGET_DIR`. **Use instead of setting it yourself.** |
| `tactus-winguest` | Builds and operates the Windows Server 2025 guest (`up` = fetch ISOs, repack, unattended install, provision, verify). |
| `autounattend.xml.in` + `winguest-provision.ps1` | Unattended Windows install + guest bootstrap: OpenSSH, Git, VS Build Tools (MSVC), rustup stable + 1.85.0. Password placeholder is substituted at build time, never committed. |
| `phase9.sh` | The gate runner: 4 cargo gates, 7 bash CI gates, `bash -n` on all scripts, timed baseline. Exits non-zero on failure. |
| `tactus-session` + `.service` | Long-lived tmux orchestrator session, started at boot via a lingering systemd user service. |
| `99-tactus-preflight` | MOTD banner surfacing failing tokens or failing gates at login. |
| `fix-shellenv.sh` | Standalone version of the non-interactive-shell fix (also in `setup.sh`). |

## Windows test leg

`ssh windowsguest 'cd /d C:\tactus && cargo test --all-targets --all-features'`
runs the suite on a Server 2025 KVM guest — the same OS as GitHub's
windows-latest runner — so Windows-only failures surface in minutes, not
after a push. phase9.sh has a `win-test` gate that ships HEAD (as a git bundle) to the
guest's clone and tests that exact sha (unpushed commits: covered;
uncommitted changes: not). `TACTUS_NO_WINDOWS=1` skips the gate loudly;
an unreachable guest fails it rather than skipping, on purpose.

## Reviewer CLIs and the preflight

Three reviewer CLIs run on this box: `claude` (Fable/Opus), `codex` (Sol), and
`agy` (Antigravity CLI, Gemini 3.1 Pro). `tactus-preflight` proves all three
live on a 6-hourly cron and is the only thing standing between a broken
credential and a reviewer that agrees with everything.

Each CLI has its own silent-failure mode, and each has a check aimed at it:

| check | what it catches |
|---|---|
| `[2b/8]` | the env token and `~/.claude/.credentials.json` disagreeing — i.e. a half-finished rotation certifying an account nothing runs on |
| `[4b/8]` | codex's bwrap sandbox failing to launch, which makes every FILE READ fail while text round-trips keep working |
| `[5b/8]` | the same for `agy`, by a marker written to disk and never put in the prompt |
| `[6/8]` | a lapsed Google AI Pro subscription silently serving Flash instead of 3.1 Pro |
| `[8/8]` | `GH_TOKEN` gaining attestation rights it must never have |

`agy` specifics worth knowing before debugging it, each learned by watching it
fail on this box (2026-08-20):

- It **exits 0 even when it produced nothing.** The exit code is worthless;
  assert on the JSON `status` *and* a marker, the way `[3/8]` ignores codex's
  exit code.
- `--output-format=json` is **mandatory**: text mode **hangs** on a denied tool
  permission (observed >10 min on a `cat`) where json returns a structured
  error in ~12 s. A hang inside a 6-hourly preflight is a false green waiting
  to happen.
- `--add-dir` is **mandatory** or the agent searches `/workspace` and fails
  "search directory /workspace does not exist", whatever the cwd is.
- Headless mode auto-denies every command not in `permissions.allow`
  (`~/.gemini/antigravity-cli/settings.json`). `realpath` and `python3` are
  both required — the first because the agent resolves paths before reading
  them, the second because reviewer prompts query the packet with `python3 -c`.
- A path that does not exist is classified as **`invalid_args` — malformed
  model output** rather than a tool failure, so it ends the turn instead of
  being handed back for the model to recover from. The partial response
  survives in the `response` field, and `--conversation=<id>` resumes the
  conversation, so a driver should **resume rather than restart**.
- `status` is **sticky across a resumed conversation**: a resumed turn that
  succeeds still reports the *original* turn's `ERROR`. Judge success on the
  response content, never on `status` alone.
- Retry logic must detect an **unchanged failure signature** and stop. Resuming
  into the same permission denial four times cost ~23 minutes and ~1.4M tokens
  and learned nothing.

## Findings worth keeping

`REPORT.md` records the full build with 24 numbered differences from the
original plan. Four are worth knowing before touching any of this:

**Never set `CARGO_TARGET_DIR` per worktree.** Measured with two worktrees at an
identical commit: source path differs / target path same → **98% sccache hits**;
source path same / target path differs → **0%**. The cache key is poisoned by
the target directory, not the source. A directory per worktree is an unbounded
set of paths, so nothing is ever reused. `tactus-build` uses a bounded slot pool
instead — full isolation between concurrent builds, but repeating paths.
Second-worktree build: **8.82 s → 4.94 s**, 1 crate rebuilt instead of 55.

**Environment must be sourced above the non-interactive guard.** Ubuntu's
`.bashrc` opens with `case $- in *i*) ;; *) return;; esac`. Anything appended is
invisible to non-interactive shells — which is what agent subprocesses and
`ssh host 'cmd'` are. Get this wrong and workers build with no sccache and
`CARGO_INCREMENTAL` unset, silently, at a near-zero hit rate. The tmux
auto-attach is the mirror image and must sit *below* that guard.

**Check exit codes, not output.** `codex login status` prints "Not logged in"
and exits **0**. `git rev-parse <unknown-ref>` prints its argument to stdout and
errors only on stderr. Both produce confident false results in a naive check.

**Imperative success does not imply persistent success.** A tmpfs and swapfile
were mounted correctly but never written to `/etc/fstab`; everything looked
right until a reboot would have silently moved every build from RAM to disk.
Assert persistence, then reboot and verify.
