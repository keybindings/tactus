## Summary

<!-- What changes, and why is this the smallest coherent outcome? -->

## Scope

<!-- What is intentionally included and excluded? Link any issue or decision. -->

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-targets --all-features`
- [ ] `cargo +1.85.0 check --locked --all-targets --all-features`

Exact commands and results:

## Review evidence

Implementation model and effort (or `human`):

Reviewed head SHA:

Frontier reviewer model and effort:

Review transport and per-pass wall-clock limit:

Passing review evidence URL:

<!-- Two of the six rows below are attestation-specific -- the evidence comment
     and the App-owned check -- and apply only to pull requests into `master`. A
     slice pull request into an integration branch is reviewed but never
     attested, so those two stay unchecked — decisions/2026-08-21-stacked-slice-prs.md. -->

- [ ] `tactus-ci` and `tactus-pr-policy` passed before frontier review began
- [ ] The independent frontier review used `max` effort on the exact current head
- [ ] Every actionable finding is fixed; follow-ups contain only non-blocking suggestions or feature ideas
- [ ] The evidence comment contains only `TACTUS_FRONTIER_REVIEW: 1`, `VERDICT: PASS`, and `REVIEWED_SHA: <full SHA>`
- [ ] The App-owned `tactus-frontier-review` check succeeded on the current head
- [ ] Every review conversation is resolved

## Risk and rollback

<!-- Failure modes, compatibility impact, and the concrete revert/recovery path. -->

## Review finding ledger

| ID | Severity | Reviewed SHA / location | Failure sequence | Provenance | Category | First bad / prior ID | Regression or documented guard | Disposition |
|---|---|---|---|---|---|---|---|---|
| None yet | — | — | — | — | — | — | — | — |
