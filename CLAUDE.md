# CLAUDE.md

Context for Claude Code sessions working on this repository.

## What tactus is

A headless orchestration engine for AI coding agents, in Rust. It normalises an
annotated markdown plan into a dependency graph of typed tasks, dispatches each
to an existing coding-agent CLI with a model chosen per task, verifies results
through objective gates and strong-model review, escalates failures up an
explicit model chain, and commits only what passes.

The one-line framing: **it is the conductor, not an instrument.** It never edits
a file, never implements an agentic loop, and never calls a model API. Agents
edit; the engine subprocesses their official CLIs and owns git.

The binding invariants are **`DESIGN.md` §4**, and there are seven, not three.
The ones a change is most likely to trip over:

- **Agents edit files; the engine owns git.** Agents are told never to commit.
- **The engine never speaks HTTP.** All model interaction is inside agent
  subprocesses. `tactus connect` shells out to each vendor CLI and asks it about
  its own account — no token is ever handled.
- **Ground truth is the diff, not the transcript.** Gates check, reviewers
  judge, feedback quotes `git diff` captured by the engine.
- **Every state transition is an event.** State is derived by replaying
  `events.jsonl`; resume is replay-then-continue. There is no second path.
- **Official CLIs only.** No ToS-violating proxies. The trust wedge is part of
  the product.

Read §4 in full before touching the engine, the event log, or anything that
handles capacity or questions.

## Where the project is

**v0.1 is complete** and released as `0.1.0` — the sequential conductor works,
end to end, against a real repository. **v0.2 is in progress**: parallel
execution over isolated worktrees, a compare-and-swap merge queue, an optional
container runner, capacity-driven routing, more adapters (Aider, task-master and
other plan formats), notifiers, and `export-decisions`. The capacity engine
currently ships **read-only** — `connect`, `capacity` and dry-run preview
estimate and report; nothing routes on it yet.

The build order is `DESIGN.md` §21 and it is deliberate. Check where the
project actually is before adding something out of sequence.

**`DESIGN.md` is the only living authority.** `decisions/` are dated, immutable
records of why; `proposals/` are inputs that bind nothing until a decision
cites them. When a decision changes the spec, `DESIGN.md` gets the compressed
edit and the record is cited. Read `decisions/README.md` and
`proposals/README.md` before adding to either.

## Gates

CI enforces these on every pull request to master. Run them before proposing a
change:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo +1.85.0 check --locked --all-targets --all-features   # MSRV
```

`--all-features` is what CI runs, and `CONTRIBUTING.md` states the same four
commands. The crate defines no features today, so the flag is a no-op for now —
use the CI form regardless, so the two stay equivalent when that changes.

`1.85.0` is required and pinned by CI. There is **no `rust-toolchain.toml`** —
toolchain selection is explicit at call sites, so nothing auto-corrects a wrong
default. Install 1.85.0 alongside stable.

8 `test-*.sh` gates in `.github/scripts/` also run in CI's `lint` job.
Invoke them **from the repository root**, the way `ci.yml` does:

```bash
bash .github/scripts/test-pr-policy.sh
```

Repository-root invocation is the convention, not a shared implementation
requirement: most of the gates resolve their own directory and run from anywhere.
The one that does not is `test-pr-policy.sh`, which derives its location with
`${BASH_SOURCE[0]%/*}` -- that strips nothing when the argument carries no slash,
so it fails outright from inside `.github/scripts/`. Run them all the way `ci.yml`
does and the difference never matters. Four of the eight need `jq`.

## Hard conventions

- **Edition 2024**, MSRV 1.85.
- **No panicking `.unwrap()` or `.expect()` outside tests.**
- **`anyhow` only at the binary edge.** Libraries return `thiserror` types.
- **All paths through `std::path`.** Windows is a first-class target — CI runs
  the full test and MSRV matrix on ubuntu, macos and windows.
- **Conventional commit titles**, enforced on PR titles by
  `.github/scripts/validate-pr-body.sh`: `type(optional-scope): summary`, where type is
  one of feat, fix, docs, refactor, test, chore, ci, build, perf, security,
  release, revert.

## How a change lands

`MAINTAINING.md` is authoritative for the full lifecycle. In outline:

1. Open a **draft PR early**.
2. Deterministic CI and PR-policy gates go green. `tactus-ci` aggregates lint,
   msrv and the test matrix and is a required context.
3. An independent **frontier-model review** of the exact green head, recorded
   as a PR comment.
4. The attestation workflow reruns the mechanical gates on that SHA and
   publishes the required `tactus-frontier-review` check.
5. **Merge commits only.** Resolve every review conversation first.

The PR body must contain all six sections — Summary, Scope, Validation, Review
evidence, Risk and rollback, Review finding ledger — and the ledger must use the
exact canonical header. `validate-pr-body.sh` rejects anything else; run it
locally against your body before pushing.

**A new push invalidates the attestation and restarts the sequence** — with one
exception: a push whose entire diff from the reviewed head is confined to
`reviews/FINDINGS.md` (not yet on master; it arrives with the parallelism slice)
keeps the review, and the trusted workflow re-attests the current head after
verifying ancestry and the exempt-only diff itself
(`decisions/2026-08-20-review-invalidation-scope.md`). The exemption is about
the path, not about the file already existing: a push that only *adds*
`reviews/FINDINGS.md` is itself exempt-only, which is how that standing ledger
-- it arrives with the parallelism slice -- can land without costing the review
it is meant to record. Everything else
invalidates, deliberately. Only the repository owner may attest; that check
cannot be satisfied by an agent.

## Where things are

| Path | What |
|---|---|
| `DESIGN.md` | The design; §4 invariants, §21 build order |
| `MAINTAINING.md` | Full merge lifecycle, attestation, emergency policy |
| `CONTRIBUTING.md` | Contributor rules and CLA |
| `decisions/` | Dated, immutable decision records |
| `proposals/` | Dated design proposals and their critiques |
| `.github/scripts/` | The 8 `test-*.sh` gates and the `validate-*` helpers they exercise |
| `acceptance/RESULT.md` | The v0.1 acceptance run write-up |
| `reviews/` | Review records, and the standing finding ledger once it lands |

`src/` is one crate. On master it is `plan/`, `agent/` (Claude Code, Copilot,
Codex adapters), and flat modules — `engine.rs`, `events.rs`, `review.rs`,
`gates.rs`, `ladder.rs`, `route.rs`, `capacity.rs`, `rundir.rs`, `workspace.rs`
among them. **Check the tree rather than this list**: the v0.2 topology work
splits `engine.rs` into `engine/` and adds `topology/`, and it reaches master
only when its pull request merges.

## On the dedicated build box

If you are on the build box rather than a workstation, read `infra/README.md`
(it arrives with the build-box provisioning pull request; until that merges the
rules below are the whole contract).
The rule that matters most:

**Use `tactus-build`, never set `CARGO_TARGET_DIR` yourself.**

```bash
tactus-build cargo test --all-targets --all-features
```

sccache keys on the target directory, not the source path. One target dir per
worktree is an unbounded set of paths, so no two worktrees ever share a cache
entry. `tactus-build` allocates from a bounded slot pool: full isolation between
concurrent builds, repeating paths, cache hits.

## Traps that have already cost time

**Exit codes and output disagree.** `codex login status` prints "Not logged in"
and exits **0**. `git rev-parse <unknown-ref>` echoes its argument to stdout and
errors only on stderr, so `[ -n "$sha" ]` passes with a literal `origin/branch`.
Use `git rev-parse --verify --quiet`, and never trust a bare `$?`.

**Non-interactive shells get nothing from `~/.bashrc`.** It opens with
`case $- in *i*) ;; *) return;; esac`. Agent subprocesses and `ssh host 'cmd'`
are non-interactive; anything they need must be sourced above that guard.

**Verify by hash, not by line count.** A one-character edit to production code
does not move a line count. When checking that a region is unchanged, hash it.

**A worker that dies without a report may have left a mutation applied.** No
completion record means no report *and* a possibly contaminated tree. Diff
against the last verified state before trusting it.

**Imperative success is not persistent success.** Verify that state survives a
reboot, not just that a command returned 0.
