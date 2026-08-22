# Decision record — reviewer effort levels and review fan-out width

**Date:** 2026-08-17
**Status:** Decided — applies from PR4 onward.
**Inputs:** the PR3 slice run on the dedicated build box (three implementation
calls, a 196-finding review round, a repair round, and a `CHANGES_REQUIRED`
final confirmation); `~/.codex/models_cache.json` as shipped with codex-cli
0.147.0; the workflow brief `tactus-workflow-brief.md`; and `HANDOVER.md`, whose
"vocabulary trap" note this record corrects. Decision: project owner, on the
measured cost and yield below.

**Supersedes:** the claim in `HANDOVER.md` that Sol's `ultra` is "a single agent
thinking longer" and that it shares only a name with Claude Code's multi-agent
`/code-review ultra`.

---

## Verdict

**`ultra` is not a deeper `max`. It is `max` plus internal task delegation.**
Use `max` for every bounded review judgement, and `ultra` only for a broad
open-ended sweep of a large unexamined surface. Narrow the review fan-out from
six lenses to three. Keep the single independent final confirmation.

## What the model actually reports

`gpt-5.6-sol`'s own `supported_reasoning_levels`, in the order the API returns
them:

    low → medium → high → xhigh → max → ultra

with the top two described as:

| effort | description |
|---|---|
| `max` | "Maximum reasoning depth for the hardest problems" |
| `ultra` | "Maximum reasoning with **automatic task delegation**" |

So `ultra` does not buy depth beyond `max`. It buys fan-out *inside* the call.
`HANDOVER.md`'s framing — that Sol's `ultra` and Claude Code's `/code-review
ultra` are "unrelated mechanisms" — is wrong in the direction that matters:
both delegate.

## Why that changed the answer

The PR3 review ran **six lens reviewers at `ultra`**, then **34 refutation calls
at `ultra`**, then **one final confirmation at `max`**. Because each `ultra` call
delegates internally, six lenses at `ultra` is fan-out on top of fan-out. It
produced 196 findings and multi-megabyte transcripts, and the width of the first
stage set the cost of the second: 196 findings needed 34 batched refutation calls
to sort, of which **114 findings — 58% — were killed.**

Yield per lens was also very uneven. Every *fidelity* defect (production wrong
against the frozen packet) came from the **correctness** lens. The
test-sufficiency lens produced 73 findings and one material one. The seams lens
produced four.

And the single `max` final confirmation — bounded remit, no authorship stake,
no delegation — returned `CHANGES_REQUIRED` with 14 high findings including six
real fold defects, and correctly overturned three claims in the orchestrator's
own disposition ledger. Per call it out-yielded all forty `ultra` calls.

## Rules

1. **`max` for bounded, deep judgements.** Refutation ("kill this one finding"),
   the final confirmation, and cumulative gate reviews. When the task is one
   coherent verdict, delegation adds coordination cost without adding depth.
2. **`ultra` only for a broad open-ended sweep** of a large surface nobody has
   examined — realistically at most the first pass over a fresh slice.
3. **Three lenses, not six**: correctness; fidelity/reconciliation against the
   packet's named enumerations; and seams with previously approved slices. Drop
   the standalone test-sufficiency, ownership and refusal-message lenses — their
   findings were mostly absorbed by refutation or by the correctness lens.
4. **Keep the refutation pass.** A 58% kill rate is its justification. Two
   independent skeptics per finding, prompted to kill, defaulting to refuted.
5. **Keep the blind canaries.** Findings already confirmed by the orchestrator,
   planted unlabelled among the refutation batches. They cost nothing — the
   batches were running anyway — and a skeptic that kills a confirmed defect
   discredits its other verdicts. Without them a kill rate is unfalsifiable.
6. **Keep the single independent final confirmation at `max`.** It is the one
   stage that has caught what earlier stages accepted in four consecutive
   slices, and on PR3 it was the highest-yield call of the entire run.
7. **A boundary drawn elsewhere is not a defect when the design is frozen.** Every reviewer
   contract must carry this. The test: can you quote a *live* packet passage the current behaviour
   fails to satisfy? Yes → a defect even if the boundary was deliberate and documented. No → a
   preference, and it belongs in `disagreements_with_the_orchestrator`, not in `findings`. Stated in
   full in `reviews/FINDINGS.md`, which every review reads first. Without it a review loop does not
   terminate: each fix draws fresh boundaries to object to, which is what happened for three
   consecutive rounds on PR3.
8. **Withheld mutation catalogues only for slices that ship production
   behaviour**, and if one is authored it **must be measured**. On PR3 the A3
   catalogue was authored and the measurement was cut for cost; the final
   confirmation then found five framework defects and reported that several of
   the withheld mutations *were* the shipped implementation. An unmeasured
   catalogue is spend with no yield.

## Cost

PR3 consumed roughly 44 Sol calls and 7 Claude calls. Under these rules the
equivalent review is about 20 Sol calls, and on the PR3 evidence it loses little:
what caught the material defects was one lens, a reconciliation obligation, and
the final confirmation — not breadth.

## What this does not change

Implementation stays `claude-opus-5` at `xhigh`. The three-stage chain stays
(implement → review → repair → independent final confirmation). Frozen contracts
stay frozen. Commits happen only after the final stage approves. Nothing is
pushed without the owner's authorisation.

## Round count is itself a metric

PR3 ran **five repair rounds and five independent confirmations**. That is not five times the
assurance; it is a signal that the first pass was not deep enough, and the later rounds were partly
paying for that.

The evidence for treating it as a metric rather than a virtue:

- **Rounds 3 and 4 each introduced defects that the next round had to fix.** `PR3-ST07-011` and
  `-012` attacked code round 3 wrote; `PR3-ST07-014` attacked code round 4 wrote. Every repair round
  rewrites tests and inverts assertions, and each rewrite is an opportunity to encode a defect as an
  expectation — which happened literally, in `FOLD-004`, whose existing test asserted the opposite of
  `transaction_fault_matrix[T-ATTEMPT]`.
- **Round 5 is repairing work that was wrongly deferred, not newly found.** Four of confirmation 4's
  five findings are ST-14 obligations the frozen contract names in `proof_tests`, which a previous
  confirmation deferred wholesale to PR10 and the orchestrator recorded as settled.

**So the target is depth at round one, not more rounds.** Concretely, what would have moved PR3's
work earlier:

1. **Measure every withheld catalogue before the first confirmation, and triage every survivor.**
   Nine of confirmation 1's fourteen findings were already predicted in writing. That is the single
   highest-yield change available, and it costs one worker call per catalogue.
2. **Require a reconciliation table against the packet's named enumerations** for any slice whose
   work is transcription. Mutation witnessing cannot detect an omitted field.
3. **Verify every scope-based deferral against the frozen contract's `scope` and `proof_tests`**
   before recording it. One command; it would have prevented rounds 4 and 5 entirely.

## What a cumulative gate does and does not do

G1's `pass_fail_rule` requires **"no open critical/high finding"** — that is a *precondition*, not a
discovery mechanism. Its remit is composition: the range reviewed as one system, the module map
closed on sibling edges, the vocabulary complete for every later slice's transitions, and the
standing questions answered. Its `adversarial_fault_tests` are a named list of seven families.

It therefore does **not** substitute for per-slice review: it runs no mutation measurement, and it
never asks whether a test proves or merely exercises — the project's dominant defect class. And a
defect found there is far more expensive: `blocks_later_prs` stops PR4 onward, and a failed gate
re-runs over the whole integrated range rather than a slice diff.
