# decisions/

Dated decision records: verdict first, the reasoning that earned it, measured vs.
assumed named explicitly, rejected options recorded with why.

The contract that keeps this folder safe:

- **DESIGN.md remains the only living authority.** Records here are history, not
  spec. When a record's outcome changes the spec, DESIGN.md gets the compressed
  edit at the time of the decision, citing the record.
- **One decision per file**, named `YYYY-MM-DD-<slug>.md`. Do not accumulate
  addenda about unrelated decisions in one file. This is not filing tidiness: an
  append-only ledger in a single file conflicts on every concurrent branch, and
  it did — two branches open on 2026-08-11 both appended an "Addendum D" and an
  "Addendum E" with unrelated content, turning a documentation merge into manual
  reconciliation. Separate files merge without touching each other.
- **Records are immutable once landed.** Corrections and follow-ups are dated
  sections appended to *their own* record, never silent edits. A record whose
  conclusion is later overturned says so and links forward; it does not get
  rewritten to look right.
- **Design documents do not live here.** Proposals live in
  [`proposals/`](../proposals/README.md) and reach this folder only as a
  decision record citing the proposal and its critiques as inputs. (Convention
  since 2026-08-13; before that, drafts stayed outside the repo entirely.)
- **Cross-link freely.** A decision that constrains another should say so in both
  directions.

When design work runs through tactus itself, council ledgers land as run
artifacts (§15); records promoted here are the durable subset.

## Index

- [2026-08-11 — multi-model design council](2026-08-11-design-council.md): adopt
  the council manual-first, ≤3 family seats, critique-heavy; machinery deferred.
- [2026-08-11 — self-hosting v0.2](2026-08-11-self-hosting-v02.md): v0.2
  development runs through tactus; the claim is auditable from commit tags.
- [2026-08-11 — gate config across a resume](2026-08-11-resume-gate-config.md):
  resume runs the gates the record carries, warning on config drift; verified live.
- [2026-08-11 — Codex reasoning effort](2026-08-11-codex-reasoning-effort.md):
  every Codex review had run at `low`; effort is now a routing axis, verified live.
- [2026-08-11 — decision export schema](2026-08-11-export-decisions-schema.md):
  local schema-2 JSONL/CSV projection, one row per recorded worker attempt.
- [2026-08-12 — v0.2 merge queue and execution topology](2026-08-12-merge-queue-execution-topology.md):
  schema-4 immutable candidates, exact-tree verification, crash-safe CAS
  integration, bounded human-gated repair tasks, and the shared worktree/runner
  boundary.
- [2026-08-20 — the automated review gate](2026-08-20-automated-review-gate.md):
  single reviewer every head, three-model panel once on the merge candidate; S9's
  remit moves to it. Stage 1 (comment-only) authorised; auto-merge is not, and the
  reviewer's credential separation is advisory, not enforced.
- [2026-08-20 — what invalidates a frontier review](2026-08-20-review-invalidation-scope.md):
  reviews bind to the exact tree modulo an explicit exempt set — exactly
  `reviews/FINDINGS.md` to start; ancestor + exempt-only diff re-attests via owner
  dispatch, computed on the trusted side. Ends ledger edits discarding max-effort
  reviews of unchanged code.
- [2026-08-21 — slices land as pull requests into their integration branch](2026-08-21-stacked-slice-prs.md):
  slice PRs into `codex/parallelism-design` get CI, policy, and a single-reviewer
  review of each head; attestation stays master-only and happens once on #18's
  merge candidate. Merge commits only — a rewrite orphans ledger rows.
- [2026-08-22 — the strategy layer lives outside the public repository](2026-08-22-strategy-record-private.md):
  competitive analysis, kill criteria, positioning and the commercial path are
  maintained privately; `DESIGN.md` keeps stubs plus the engineering consequences;
  promotion is demand-driven, by the pull request that first needs to cite a document.
