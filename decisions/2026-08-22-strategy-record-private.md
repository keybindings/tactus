# 2026-08-22 — the strategy layer lives outside the public repository

**Verdict.** Competitive analysis, kill criteria, positioning, and the enterprise and
commercial path are maintained in a private companion repository, not in `DESIGN.md` or
anywhere under `keybindings/tactus`. The public repository carries the engine, its technical
design, its trust model, its process records, and the **engineering consequences** of
strategy decisions — never the strategy itself. Moved today, from `DESIGN.md` at
`0cc44d8255620b2c935156e28c6b5bcb080dc0ab`: the §2 "competitive reality" paragraph, the
competitive bullets of §23 (first-party absorption and its kill criterion, the Context
Foundry threshold, the name collision), all of §23.1, the companion-research names in the
Status line and §24. The headings stay, so every existing cross-reference to §23 and §23.1
still resolves to a stub that says *that* the content moved and retains what other
documents rely on.

## Why

- **The engine's contract must be public; its positioning gains nothing from being.** The
  trust model, the review process, the ledger and the self-hosting receipt
  (`2026-08-11-self-hosting-v02.md`) are only worth anything if a stranger can read them.
  Why the project believes it will win is not part of that contract.
- **The engine's source is public either way.** `tactus` 0.1.0 is on crates.io and a
  published crate cannot be unpublished. Privacy can still cover the strategy layer, so
  that is the layer that moves.
- **Taking the whole repository private was weighed and rejected.** Actions minutes become
  a paid cost at the 2× Windows and 10× macOS multipliers for the legs the attestation
  workflow re-runs on every dispatch, and the obvious escape — self-hosted runners on
  `pull_request` — is exactly what `2026-08-20-automated-review-gate.md` forbids. It would
  also end the public self-hosting receipt. The marginal secrecy it buys over moving the
  strategy layer alone is the v0.2 topology, which lands in public as slices regardless.

## The rule

- **Product and strategy documents are private by default.** Engine proposals stay public
  under `proposals/`: they are executed in the open within weeks and gain from the review
  gate, the ledger, and critiques on the record.
- **Promotion is demand-driven.** A private document reaches this repository only when a
  pull request here first *needs to cite it* — a decision record, a slice contract, or a
  `DESIGN.md` edit — and then it arrives with a `Provenance:` line naming the private
  commit, never as a pointer to a document the reader cannot open.
- **Nothing public references a private document by path or name.** The stubs left in
  `DESIGN.md` say that content moved, not what it says.
- **What stays public regardless:** everything the trust model rests on — this folder,
  `MAINTAINING.md`, the workflows and validators, `reviews/FINDINGS.md`, and the technical
  sections of `DESIGN.md`.

## Measured vs assumed

Measured: the repository has no forks (2026-08-22), so nothing already copied is being
chased; `tactus` 0.1.0 is on crates.io; a warm CI run on this repository costs roughly 35
billable minute-equivalents at the Windows and macOS multipliers, and the prior seven days
saw 83 CI runs and 11 attestation reruns. Assumed, and named: that the strategy record is
what a competitor would copy, and that the engine's ideas are not — they are executed in
public regardless, so secrecy buys nothing there.

## Rejected options

- **Whole repository private.** See above.
- **Leave everything public.** The strategy layer has option value in secrecy and no
  auditability value in public.
- **Strip the engineering consequences along with the strategy.** Rejected: per-seat
  deployment, the org-shared-pool `Unknown` rule, policy distribution through `tactus.toml`,
  the refinement metric and the importer's priority are cited by `acceptance/RESULT.md`,
  two decision records and three proposals. They stay in the §23.1 stub, unchanged in
  substance.

## Cross-references

- `DESIGN.md` §2, §23, §23.1, §24 — the stubs.
- [2026-08-11 — self-hosting v0.2](2026-08-11-self-hosting-v02.md) — the public receipt
  this record keeps public.
- [2026-08-20 — the automated review gate](2026-08-20-automated-review-gate.md) — the
  self-hosted-runner rule that makes a private repository expensive.
