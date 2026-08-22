# tactus — Design Document v2.1

> **Name:** `tactus` — the Renaissance term for the shared steady pulse every performer synchronizes to. Verified free on crates.io and npm (2026-08-08, live API check). Known adjacent collision: AnthusAI/Tactus, an alpha Lua DSL for agent orchestration (~3★) — assessed as tolerable, but the decision is deliberate: we differentiate hard rather than share ground by accident. **Action on repo creation: publish a placeholder crate immediately.**

**Status:** v2 — consolidates the original architecture, the two-phase lifecycle, the interaction model, the capacity engine, and two rounds of research whose companion reports are maintained in the strategy record outside this repository, plus the v2.1 late-binding refinement: connect your plans; tiers bind to concrete models and pools at attempt time.
**Language:** Rust · **License:** AGPL-3.0-only · **Form factor:** single static binary, Windows first-class

---

## 1. Summary

`tactus` is a headless orchestration engine for AI coding agents. A frontier model and the user design a piece of work together in an interactive session; `tactus` then executes that plan unattended — normalizing it into a dependency graph of typed tasks, dispatching each task to an existing coding-agent CLI (Claude Code, GitHub Copilot CLI, Aider) with a **model chosen per task**, verifying every result through objective gates and strong-model review, escalating failures up an explicit model chain, and **scheduling all of it against the user's actual subscription capacity** so that prepaid frontier-tier quota never expires unused.

It never edits a file, never implements an agentic loop, and never calls a model API. It is the conductor, not an instrument — and it treats your Claude Max windows, Copilot credits, API dollars, and local models as one portfolio to be spent optimally.

When it gets stuck at 2am it doesn't stop the run: it parks only the blocked branch, keeps everything else moving, and pings you as the top rung of the escalation chain.

## 2. The nine pillars

| # | Pillar | One line |
|---|---|---|
| P1 | Plan-agnostic ingestion | Any plan (Claude Code plan-mode markdown, checklists, JSON, task-master output) → typed task DAG via an annotation grammar |
| P2 | Agent-agnostic conducting | Drives official agent CLIs headlessly through an adapter trait; no native loop, no API calls, no subscription proxies |
| P3 | Per-task model routing | Difficulty chains + blast-radius floors + designer-suggested tiers + user override |
| P4 | Verification-driven escalation | Gates → structured strong-model review → retry via session resume → escalate rungs; cross-vendor second opinion |
| P5 | Git discipline | Engine owns git; commit-per-task; v0.2 worktrees, merge queue, conflict→fix-task |
| P6 | Ops backbone | Event-sourced JSONL, resumable, cost ledger + budgets, dry-run preview, TOML, CI-embeddable |
| P7 | Two-phase lifecycle | Interactive frontier design (question exhaustion → decisions record) → headless execution bound to the same work unit |
| P8 | Interrupt-driven interaction | Non-blocking questions; park affected tasks, continue the rest; human = top escalation rung |
| P9 | Capacity engine | Connect your plans; late-bound tier→(model, pool) selection with conserve / value-max / spend-down strategies and affinity-aware assignment |

The design's emphasis is P4, P8 and above all P9; the competitive analysis that ranks the pillars this way is maintained in the strategy record outside this repository and is not part of the engine's contract.

## 3. Goals and non-goals

**Goals**

- Take a designed piece of work from plan to verified, committed code without supervision, asking only the questions that genuinely block progress.
- Route every task to the cheapest worker that can pass verification — where "cheapest" is measured against the user's real capacity pools, not list prices.
- Maximize the value of prepaid subscriptions: spend-down surplus capacity at the top tier, conserve when scarce, always leave a reserve for interactive use.
- Be agent-agnostic and vendor-neutral: official CLIs only, one adapter file per agent, cross-vendor review as a feature.
- Single static binary; first-class on Windows, macOS, Linux. Resumable, auditable, CI-embeddable.

**Non-goals**

- Not an agent: no file editing, no tool-use loop, no context management, no HTTP client, no model API keys.
- Not a subscription proxy: never spoofs headers or re-exposes a subscription as an API endpoint. Subprocesses of official binaries only.
- Not a UI (the engine): panes, dashboards, and notifiers are thin clients of the event log. The design-pane product is v0.3, built *on* the engine.
- Does not repair bad plans. The design phase exists to make plans good; execution assumes they are.
- No cross-run learning in v0.x — but every routing decision is logged so a learned router is possible later.

## 4. Invariants

1. **Agents edit files; the engine owns git.** Agents are instructed never to commit. The engine creates branches, stages, commits, and (v0.2) merges.
2. **The engine never speaks HTTP.** All model interaction happens inside agent subprocesses.
3. **Ground truth is the diff, not the transcript.** Gates check, reviewers judge, and feedback quotes `git diff` captured by the engine.
4. **Every state transition is an event.** State is derived by replaying `events.jsonl`. Resume = replay + continue.
5. **Official CLIs only.** No ToS-violating proxies, ever — the trust wedge is part of the product.
6. **Questions never stop the runnable frontier.** A question parks exactly the tasks it affects; the run hard-blocks only when nothing remains runnable.
7. **Capacity is estimated conservatively.** Safety margins on every pool, a reserve floor for the user's own interactive use, and rate-limit signals treated as ground truth over any estimate.

## 5. The work unit: a two-phase lifecycle (P7)

Every piece of work lives in one unit (a "pane" in the eventual UI; a run directory today) with two phases that have opposite attention models.

**Phase 1 — Design (interactive, frontier-tier).** The user and a frontier model iterate on the work with constant feedback. The designer's explicit objectives, in its prompt:

1. Produce the task breakdown (typed tasks, dependencies, acceptance criteria, path hints).
2. **Question exhaustion:** enumerate every decision execution will face; resolve each with the user *now*, while the human is present and cheap to consult.
3. Emit three artifacts: the **task plan** (annotated markdown), the **conventions brief** (one page, injected into every downstream prompt), and the **decisions record** (every resolved ambiguity, with rationale).
4. Annotate each task with a suggested tier and minimum tier (`tier=`, `min=`).

**Phase 2 — Execution (headless, interrupt-driven).** The plan is frozen; the engine takes over. Runtime questions pass through a pre-filter before ever reaching the human: the question plus the decisions record go to the frontier (architect) profile — *"was this already answered?"* Only genuinely novel questions escalate to the user.

**The defect loop:** every question that reaches the human at runtime is, by definition, a design-phase defect. It is logged as one (`design_defect` event, with the question and eventual answer), and the accumulated defects become review material for the designer prompt. The system learns to need the user less.

## 6. Architecture

```
            ┌────────────── Phase 1: Design (interactive) ─────────────┐
 user ◄────►│ frontier designer → tasks + conventions + decisions +    │
            │ per-task tier/min annotations                            │
            └───────────────────────────┬──────────────────────────────┘
                                        ▼ (plan frozen)
 plan.md ──► PlanAdapter ──► Plan IR (typed task DAG + artifacts)
                                   │
                                   ▼
                     Router (config ⊕ annotations ⊕ user override)
                     + CapacityEngine (pools, strategies, affinity)
                                   │
        ┌────────────── Scheduler ──┴──────────────────────────┐
        │  v0.1 sequential (skip-ahead past parked tasks)      │
        │  v0.2 tokio DAG + worktrees + merge queue            │
        │                                                      │
        │  Workspace ──► AgentAdapter ──► official CLI proc    │
        │      ▲               │                               │
        │      │               ▼                               │
        │    Gates ◄─── Outcome (diff, usage, session)         │
        │      │                                               │
        │      ▼                                               │
        │  Reviewer (read-only; optionally cross-vendor)       │
        │      │                                               │
        │      ▼ fail → retry (resume) → escalate rung → human │
        └──────┬───────────────────────────────────────────────┘
               ▼
      events.jsonl ──► resume · status · ledger · questions ──► notifiers (CLI / desktop / Telegram / Slack)
```

| Component | Responsibility |
|---|---|
| **PlanAdapter** | Parse a raw plan into the IR. One per format; `sniff()` for auto-detection. |
| **Router** | Resolve each task to an escalation chain of abstract tiers from three sources (config defaults, designer annotations, user override), applying blast-radius floors and `min` clips. |
| **Binder** | Resolve each tier to a concrete (agent × model × pool) at attempt time from everything connected — scoring capability fit (catalog), capacity headroom under the active strategy, and affinity; rebinds across pools on rate limits. Pins force fixed bindings. |
| **CapacityEngine** | Track every quota pool (windows, credits, dollars, local), estimate remaining capacity, expose strategy decisions (conserve / value-max / spend-down) to the router and scheduler. |
| **Scheduler** | Drain the DAG. Sequential in v0.1 — advancing past parked tasks to the next ready independent task. In v0.2 one coordinator owns events/admission while task pipelines run concurrently and one queue serializes integration. |
| **Workspace** | Git state: v0.1 run branch + per-task commits; v0.2 detached worktree-per-task, immutable candidate refs, staging worktree, and compare-and-swap integration. |
| **AgentAdapter** | Turn a `TaskRun` into a data-only `CommandSpec` for an official CLI and parse the outcome. One file per agent; it does not decide where the process runs. |
| **Runner** | Execute probes, workers, gates, and reviewers on the host or in a role-scoped container; owns cwd, mounts, environment, supervision, and timeout, never agent semantics or Git. |
| **Gates** | Configured shell commands (compile/test/lint) executed by the selected runner in the candidate workspace; failure logs become retry feedback. |
| **Reviewer** | Ordinary read-only worker profile emitting a structured verdict; optionally a different vendor from the implementer. |
| **Interaction** | Question/answer events, parking semantics, notifier plugins, CI degradation. |
| **Event log** | Append-only JSONL; source of truth for state, resume, status, questions, ledger, and the future decision-export dataset. |

## 7. Core data model

```rust
struct Plan {
    source: PlanSource,               // adapter id + original hash
    tasks: Vec<Task>,
    artifacts: Vec<Artifact>,         // conventions brief, decisions record, contracts
}

struct Task {
    id: TaskId,
    kind: TaskKind,                   // Design | Implement | Fix | Refactor | Test | Docs | Chore
    title: String,
    body: String,
    depends_on: Vec<TaskId>,
    acceptance: Vec<String>,
    path_hints: Vec<String>,          // globs — blast-radius routing + v0.2 overlap prediction
    suggested_tier: Option<Tier>,     // from the designer (advisory)
    min_tier: Option<Tier>,           // clips the chain start (binding)
    artifacts_in: Vec<ArtifactId>,
    artifacts_out: Vec<ArtifactId>,
}

struct WorkerProfile {                // v2.1: an optional PIN — tiers bind late by default;
                                      // a pin forces a fixed binding for one tier
    name: String,
    agent: AgentId,                   // claude-code | copilot | aider
    model: String,
    pool: PoolId,                     // which capacity pool this profile drains
    permissions: PermissionMode,      // Edit | ReadOnly
    effort: Option<Effort>,           // low | medium | high | xhigh | max — role policy, then pin,
                                      // then tier default; each built-in adapter states it explicitly
    max_turns: Option<u32>,
    extra_args: Vec<String>,
}

struct Outcome {
    status: OutcomeStatus,            // Completed | AgentError | Timeout | RateLimited
    diff: String,                     // engine-captured
    session_id: Option<String>,
    usage: Option<Usage>,
    cost_usd: Option<f64>,            // API-equivalent, as reported
    pool_drain: Option<PoolDrain>,    // pool units consumed (tokens / credits / $)
    transcript_path: PathBuf,
    duration: Duration,
}

struct Question {
    id: QuestionId,
    kind: QuestionKind,               // Unblock | ApproveSpend | Continue | Clarify
    affected_tasks: Vec<TaskId>,      // exactly these park
    context: String,                  // includes architect pre-filter result
    options: Vec<String>,
}

struct Verdict { pass: bool, reasons: Vec<String>, required_changes: Vec<String> }
```

### Task state machine

```
Pending ─► Ready ─► Running(attempt n, rung r) ─► Gating ─► Reviewing ─► Done
              ▲            ▲                         │           │
              │            │        feedback         │           │
              │            └──(retry same rung ──────┴───────────┘
              │            │   or escalate rung+1)
              │            ▼
              │      AwaitingInput ◄─── question raised (parks THIS task only)
              │            │ answer event
              │            ▼
              └──────── Ready (re-enters queue)

   chain exhausted ─► escalate to HUMAN (a question) ─► answered ─► retry
                                                     └─ declined ─► Failed ─► dependents Blocked
```

v0.2 replaces the terminal edge with `Reviewing ─► AwaitingMerge(candidate) ─► Merged | AwaitingRepair(fix task)`. There is no pre-merge `Done`: **dependency readiness is `Merged`** — a dependent's worktree must branch from an integration head that already contains its dependencies' code. `Ready`, the attempt phases, and `MergeVerifying` are derived views; the durable fold stores candidates, repair lineage, and the one prepared merge transaction ([decision](decisions/2026-08-12-merge-queue-execution-topology.md)).

## 8. Trait surface

```rust
use async_trait::async_trait;

trait PlanAdapter {
    fn id(&self) -> &'static str;
    fn sniff(&self, raw: &str) -> bool;
    fn parse(&self, raw: &str) -> Result<Plan>;
}

#[async_trait]
trait AgentAdapter {
    fn id(&self) -> &'static str;
    async fn probe(&self, runner: &dyn Runner) -> Result<Caps>; // probes the boundary that will execute
    fn build(&self, run: &TaskRun) -> Result<CommandSpec>;
    fn parse(&self, out: &ProcessOutput) -> Result<Outcome>;
}
// Caps: json_output, session_resume, cost_reporting, read_only_mode, acp, model_list

struct CommandSpec { program: String, args: Vec<String>, env: Vec<(String, String)>, stdin: Vec<u8> } // env is an overlay
struct RunnerRequest { command: CommandSpec, workspace: PathBuf, role: ExecutionRole, timeout: Duration, agent: Option<AgentId> }
enum ExecutionRole { Probe, Implement, Gate, Review }

#[async_trait]
trait Runner {
    async fn run(&self, request: &RunnerRequest) -> Result<ProcessOutput>;
}

#[async_trait]
trait Gate {
    fn name(&self) -> &str;
    async fn check(&self, runner: &dyn Runner, ws: &Workspace) -> GateResult; // Pass | Fail { log }
}

#[async_trait]
trait Notifier {
    fn id(&self) -> &'static str;                          // cli | desktop | telegram | slack
    async fn ask(&self, q: &Question) -> Result<()>;       // delivery only; answers arrive as events
    async fn info(&self, msg: &RunEvent) -> Result<()>;    // milestones, completion, budget alerts
}

#[async_trait]
trait CapacitySource {
    fn pool(&self) -> PoolId;
    async fn estimate(&self) -> Result<CapacityEstimate>;  // remaining, window ends, confidence
}
```

The attributes above are a contract, not decorative pseudocode: every async
trait used behind `dyn` returns a boxed `Send` future (whether generated by
`async-trait` or written explicitly), so the final Tokio surface is object-safe.
The pre-Tokio runner steps use the same request/output contract through a
synchronous `run`; step 5 changes that call shape to the boxed-future surface
while parity tests hold process and parsing semantics fixed.

`CommandSpec.env` overlays a runner-owned base rather than replacing it. The
host runner starts from the Tactus environment and the container runner from the
image environment; each supplies role-scoped `HOME`, `PATH`, and credential
locations. Adapter overrides may select profiles or CLI behavior but may not
conflict with runner-reserved keys. Probe and execution compose the same base,
mounts, reserved values, and overlay, so pre-flight certifies the environment
that will actually spend.

Deliberate omissions: no `Router` trait (config-evaluating struct until a second policy exists) and no `Executor` trait beyond `AgentAdapter` (a native agentic loop remains explicitly out of scope; the seam exists if that ever changes).

## 9. Plan ingestion (P1)

**v0.1 adapters:** Claude Code plan-mode markdown (primary) and the annotation grammar that upgrades *any* markdown. **v0.2:** generic checklist, JSON schema, and claude-task-master import — turning the most popular DAG generator into an upstream feeder rather than a competitor.

**Backlog adapters (v0.2+):** Jira, Azure DevOps work items, GitHub Issues. These feed **Phase 1, not Phase 2** — a backlog item is not a plan: no dependency DAG, no acceptance criteria a gate can check, no tier annotations, no conventions brief. The importer emits a *draft* plan that the designer then subjects to question exhaustion (§5); execution still runs only frozen, annotated plans. Feeding a backlog straight to Phase 2 would point unattended agents at under-specified stories, which is the failure the two-phase lifecycle exists to prevent. Invariant 2 holds by subprocessing the vendor's own CLI (`az boards`, `acli`, `gh`) from a separate `tactus import` command — the network stays out of the engine and reuses auth the user already has. **Write-back is a different seam:** transitioning the item on commit, attaching branch and shas, moving it to Blocked when a question parks the task is a `Notifier` over the event log (§8), not a plan adapter. `Task` gains an `external_ref` so a run traces back to the item that spawned it.

Parsing rules (markdown): each `##`/`###` section or top-level checklist item becomes a task (heading → title, body → body); a bullet list under `Acceptance` / `Done when` / `Success criteria` → acceptance; file paths in the body are collected into `path_hints`; **default dependencies are document order** (task N depends on N−1) unless annotations say otherwise.

Annotation grammar — HTML comments, invisible in rendered markdown:

```markdown
## Design the pagination API
<!-- tactus: id=api-design kind=design depends= tier=frontier out=api-contract -->

## Fix off-by-one in list endpoint
<!-- tactus: id=fix-obo kind=fix depends=api-design min=mid needs=api-contract paths=src/api/** -->
```

Attributes: `id`, `kind`, `depends` (empty = none, breaking the chain), `tier` (designer suggestion), `min` (binding floor), `needs`/`out` (artifact wiring), `paths` (globs). Unknown attributes warn, never error. Un-annotated plans still run: kinds by keyword heuristic, dependencies by document order, artifacts defaulting to a conventions brief from the first Design task.

## 10. Routing (P3) — three sources, then capacity and affinity

Assignment resolves in layers:

1. **Config baseline:** each `TaskKind` maps to an escalation chain, e.g. `fix = { chain = ["small","mid","frontier"], attempts_per = 2 }`.
2. **Blast-radius floors:** path-glob overrides truncate the chain start (`src/auth/**` starts at frontier). Blast radius beats nominal difficulty.
3. **Designer annotations:** `tier=` is advisory (becomes the chain start if it outranks the baseline), `min=` is binding (clips anything below it).
4. **User override:** the dry-run routing preview is where the user edits any assignment before spend.
5. **Late binding (v2.1):** chains are abstract tiers; the **binder** resolves each tier to a concrete (agent × model × pool) per attempt from everything the user has connected — scoring capability fit against the model catalog, capacity headroom under the active strategy (spend-down may raise the effective start, never below `min`), and affinity (ties break toward the previous task's binding; same-profile streaks batch). Rate-limit failover is the binder rebinding the same rung to another pool. Pins force a fixed binding where determinism matters. Floors, including a merge repair's `min_tier = mid`, are intersected with the run's frozen hard pins and ceilings; an empty intersection parks at the human rung instead of silently overriding policy.

**A tier resolves an effort as well as a binding.** The engine states it on every attempt — an explicit `[routing.effort]` role policy first, then a pin, then `small→low`, `mid→medium`, `frontier→high` — because a vendor default is not a routing decision. Codex made the case concretely: its default comes from the *provider's roster* rather than its flag set, `gpt-5.6-sol` carries `low`, and until step 10 every review this project ran was judged there silently (`decisions/2026-08-11-codex-reasoning-effort.md`). A chain that escalates rungs while every rung thinks equally hard has escalated nothing. Effort remains abstract for the same reason tiers are, but the shared built-in vocabulary is now five levels (`low, medium, high, xhigh, max`): Codex, Claude Code, and Copilot all advertise them and each adapter maps them explicitly. A role policy is the deliberate opt-in for a run-wide implementation/review standard; without one, `max` remains reachable through a pin. `ultra` stays excluded because Codex couples it to automatic delegation, which changes orchestration rather than only reasoning depth. **Effort is not identity:** §11.3's rebind compares who a binding *is*, so an effort difference must never make a reviewer look like a different model from the implementer that shares its name.

**The affinity gradient** (context-switch cost, warmest → coldest): resume the *same session* (whole conversation cached) → new session, *same model*, within the provider's cache window (prefix hits on the system-and-repo preamble — the mechanism behind the ~97% cache-read rates heavy Claude Code users see) → same vendor, different model (cache-cold, harness-warm) → different vendor (cold everything: full context re-ingestion plus a different harness reading the conventions brief fresh). Copilot adds a useful middle rung: a cross-*vendor model* switch without a harness switch. v0.1 implements affinity as a tie-break plus streak batching; the full switch-cost model waits for real decision-log data — guessing reload costs is worse than measuring them.

Every routing decision and outcome is logged with the task's features. `tactus export-decisions` (v0.2) is a local, read-only, versioned projection of the frozen plan and attempt log: one attempt-start-ordered row per worker attempt, JSONL by default or the same rectangular data as CSV on stdout. It refuses a live run rather than export a moving partial record. Its purpose is human interpretation and the prediction-calibration record (§23.2); learned routing is parked indefinitely (§21), not the live consumer. The schema and provenance rules are recorded in `decisions/2026-08-11-export-decisions-schema.md`.

## 11. Verification ladder (P4)

An **attempt** = agent run → gates → review. The ladder:

1. **Gates first** — configured commands (compile, tests, lint), sequential, short-circuit; output tail (8 KB) becomes feedback. Gates are what make cheap models affordable: objective, free, and they catch most small-model failures before any frontier tokens are spent. Evidence-gate axes adopted from the field's best practice: **an empty diff can never pass** ("done" claims require changed code), red tests block, and **test provenance is enforced for Test tasks — a new test must fail on the base commit and pass on HEAD**, or it proves nothing. The **secret-leak axis belongs here too, not with the reviewer**: added lines are checked for credential shapes deterministically, or by a scanner the user configures as a gate command. A regex beats a frontier model at this, costs nothing, and runs on every attempt — model judgement should carry the axes that actually need judgement.
2. **Review** — a read-only worker profile receives task + acceptance + conventions brief + the complete engine-captured diff, and is instructed to reply with nothing except one `json`-labelled fenced verdict (`pass`, `reasons`, `required_changes`). That complete trimmed envelope is the authority boundary: prose, bare objects, examples, extra fences, and trailing commentary are not verdicts, even when they contain a filled `pass: true` object. One re-ask follows an unparseable answer, then it counts as failure. Each pass has an independent wall-clock budget (90 minutes by default), and the re-ask shares that pass's deadline rather than starting a second clock. A diff above the complete-review limit refuses before reviewer spend and must be split; tactus never drops paths and calls the remainder reviewed. The reviewer prompt includes an anti-sycophancy instruction: its job is to find reasons to fail, not to agree.
3. **Cross-vendor second opinion** — for paths matching configured globs, a second reviewer from a *different model family* judges the same diff (e.g. GPT-via-Copilot reviewing Claude-written code). Different families share fewer blind spots; one Copilot subscription makes this a `--model` flag rather than a second product. Both verdicts must pass, and the two reviewers are **independent** — neither is told the other's verdict, because a reviewer who knows the change was already approved stops looking. Turned on per override with `second_opinion = "different-vendor"` rather than applied to every blast-radius path by default: §11.5's cost argument applies here too, and an unrecognised value for that key is a hard config error, because a typo must not silently delete a verification layer. **"Vendor" here means model family, not CLI**: Copilot serves Anthropic models too, so an agent-id comparison would happily pair `claude-opus-5` with itself through a different harness and keep every blind spot. Where the configured second opinion cannot resolve — no other family at that tier has an adapter that probes — the run refuses at pre-flight rather than quietly running one pass.

   The same family axis settles a defect this ladder had until step 9: at the frontier rung the implementer's binder and the reviewer's binder resolve identically, so **a frontier task was reviewed by the model that wrote it**. The reviewer now rebinds to a different family whenever it would otherwise be the *same model* (exact identity, not family similarity — sonnet judged by opus is a genuine second look). That rebind is opportunistic: on a single-vendor install it warns — naming the tasks — and reviews same-model rather than refusing, because nobody asked for it. It is also suppressed when a second opinion is already configured for the task — rebinding there would resolve both passes onto the same different-family model and drop the original family's review entirely, which is worse than the self-review it was avoiding. Who reviews is recorded in `run_started`, so a CLI installed between a run and its resume cannot quietly become its judge; a log that predates that record re-derives and says so, because an *absent* record is not a record of "no reviewers". The recorded cross-family reviewer stays opportunistic on resume too: refusing to continue over a judge that may never have judged anything costs more than it protects, and the per-attempt record names who judged each attempt either way.
4. **Retry, then escalate** — failure feedback (gate log or `required_changes`) goes back to the *same rung* via session resume where the adapter supports it (in-context feedback lands far better than a fresh start); `attempts_per` exhausted → next rung, fresh session, accumulated feedback summary included. Chain exhausted → **the human is the top rung**: an `Unblock` question with full context. Declined or unanswered under CI mode → task `Failed`, dependents `Blocked`, independent work continues.
5. **Security lens (v0.2)** — the cross-vendor second opinion generalizes the reviewer from a single pass into a **list of passes, each with a lens and a pass rule** (shipped in step 9: passes run in order, short-circuiting like gates, and each receives the frozen per-pass review timeout); a mandatory security review is then that same mechanism with an adversarial prompt and, ideally, a different model family. Scoped through the existing blast-radius overrides rather than applied globally: a mandatory frontier security pass on every task roughly doubles review spend, while scoping it to `src/auth/**` and `migrations/**` costs almost nothing and hits where blast radius already said to look. **Its ladder dispatch differs deliberately** — a security finding must never enter the retry-until-it-passes loop, which is how a real finding gets laundered into a commit. It goes to an `Unblock` question with the finding attached instead of round the rungs again.

## 12. Interaction model (P8)

- **Questions are events**, scoped to `affected_tasks`. Exactly those park in `AwaitingInput`; the scheduler keeps draining everything else — in v0.1's sequential mode by skipping ahead to the next ready independent task, in v0.2 across parallel worktrees.
- **Raised eagerly** — at detection, not at attempt: the designer resolves most at design time; at runtime a worker can flag uncertainty in its outcome and the reviewer can emit a `needs-human` verdict, both of which raise the question immediately while unrelated work proceeds.
- **Pre-filtered by the architect**: question + decisions record → frontier profile → "already answered?" Only novel questions reach a human, and every one that does is logged as a `design_defect`.
- **Hard block has a precise definition**: the runnable frontier is empty and every remaining task transitively depends on an open question. Anything less keeps running.
- **Channels**: `tactus answer <id>` and attached-terminal prompts in v0.1, desktop notifications in v0.1, Telegram/Slack notifier plugins in v0.2 (delivery only — answers always arrive as events, so a run survives its notifier). `tactus answer` writes a file beside the question rather than appending to the log, keeping `events.jsonl` single-writer; the engine ingests it and records the `question_answered` event itself, on its next scheduler turn if it is live or at the next resume if it is not. Which channel a hard block uses is not a mode question alone: `on_block` at an attached terminal prompts, and the identical config detached waits for `tactus answer` up to `[interaction] wait_on_block_secs`.
- **Spend approvals**: `ask_before` thresholds (e.g. frontier escalation projected over $N, or any run past its soft budget) raise `ApproveSpend` questions instead of silently spending.
- **CI mode** (`interaction = "never"`): questions degrade to parked-task reporting; exit status distinguishes clean completion from completion-with-parked-tasks.

## 13. Capacity engine (P9)

The router's economics depend on which pool pays. Pools have different shapes, and the engine models them explicitly:

| Pool kind | Example | Unit | Reset shape |
|---|---|---|---|
| Subscription windows | Claude Max 5x/20x | tokens (est.) | 5-hour rolling + weekly cap |
| Metered credits | Copilot on AI-Credit billing (post-Jun 2026) | credits ≈ $ | monthly allowance + PAYG |
| Legacy request pools | Copilot annual plans | premium requests × per-model multiplier | monthly |
| API keys | Anthropic/OpenAI direct | dollars | none (budget only) |
| Local | home-server models via an OpenAI-compatible endpoint | unlimited | none (hardware-bound) |

**Estimation sources**, in trust order: (1) rate-limit signals from the CLIs — ground truth; a `RateLimited` outcome immediately marks the pool exhausted, demotes or parks frontier-hungry tasks, and sets a retry-at-reset timer; (2) self-metering of everything the engine spawned; (3) ccusage-style parsing of local agent logs, which captures the user's *interactive* sessions drawing from the same pool; (4) optionally, provider usage endpoints where they exist — treated as fragile (several are reverse-engineered and break silently) and never load-bearing. Estimates are always conservative: a per-pool `safety_margin` (usage on other machines is invisible to local log parsing) and a `reserve` floor that keeps headroom for the user's own interactive work.

**Discovery — `tactus connect`.** Pools are connected, not configured: `connect` scans PATH for official CLIs, checks auth state, detects each plan's quota shape, enumerates available models, and writes the user-level pools file. Tier classification comes from a **capability catalog** shipped with the binary (static data — the no-HTTP invariant holds), with a pragmatic prior for unknowns: providers price their own models, so per-model multipliers and per-token rates rank capability. A model absent from the catalog is never auto-selected — pin it or update. Decision logs later calibrate the catalog with measured pass rates per tier and task kind.

`connect` enumerates **credential profiles, not just installed binaries**: one vendor can back several pools — two Claude Max accounts, say — and the binder selects between them per attempt through the provider's own profile mechanism, an environment variable on the subprocess rather than a token the engine ever handles (invariants 2 and 5). Whether the CLI honours profile selection is a `probe()` axis like any other, verified at pre-flight instead of discovered mid-spend. Several same-kind pools change three things: estimates must **attribute** usage per profile rather than aggregate it (local-log parsing reads per-account state, so summing reports one healthy pool where there is one exhausted and one fresh); `reserve` becomes asymmetric, since a plan bought for unattended work has no interactive use to protect; and independent reset windows turn a rate limit from *wait* into *rebind and continue* (§10.5) — the single biggest practical gain for an overnight run. Affinity still governs the order: prompt caches are per-account, so the binder drains one pool toward its reserve and then switches, rather than round-robining and paying cache-cold on every task.

**Strategies** (`routing.strategy.mode`):

- `conserve` — classic cost minimization: route down aggressively, escalate only on failure, defer frontier-hungry tasks toward window resets when a pool is projected to run dry.
- `value-max` — subscription yield management: prepaid capacity that would expire unused has zero marginal cost, so surplus near a reset biases default tiers **up** (spend-down mode) — Opus for implementation, frontier review everywhere — subject to `min`/`max` bounds and the reserve floor. *No shipped tool does this (verified Aug 2026); it is the headline.*
- `deadline` — wall-clock first: maximize parallel throughput within capacity, spilling to API dollars when justified by a configured $/hour ceiling.

The ledger accounts every attempt in both currencies: API-equivalent dollars (honestly labeled — subscription spend is notional) and pool units drained. Where a worker's route reports no spend at all — Copilot's does not (§16) — the total it contributes to is marked `?` rather than presented as complete, since a cross-vendor review makes that the normal case rather than a corner of it. Budgets exist per run ($), per task ($), and per pool (fraction).

**Sequencing:** v0.1 ships the capacity engine **read-only** — the dry-run preview and `tactus capacity` show each pool's estimated remaining capacity, resets, and what each strategy *would* do. v0.2 wires it into live routing. This de-risks estimator fragility before any routing depends on it, and the preview alone is the demo that sells the product.

## 14. Execution engine

### v0.1 — sequential

- **Pre-flight:** clean working tree required; every gate command resolves; every referenced agent binary probed (`probe()` logs version + capabilities — Copilot's CLI auto-updates and has shipped breaking flag removals, so capability probing is not optional); effort support is proven rather than inferred from a flag name (Claude Code and Copilot must advertise all five shared levels, while Codex must pass the exact `model_reasoning_effort=xhigh|max` assignments through `--strict-config` on fresh and resume until a deliberately missing local output-schema file stops the command before any model turn, then expose every level for each known model in its local `debug models` catalog); plan parses cycle-free; capacity snapshot taken. Unreadable capability output is not evidence and refuses before spend.
- **Run branch:** `tactus/run-<ulid>` from HEAD; the user's branch is never dirtied.
- **Order:** stable topological sort (ties by plan order), with skip-ahead past `AwaitingInput` tasks to the next ready independent task.
- **Per task:** materialize prompt (body + acceptance + artifacts_in + conventions brief) → agent runs in repo root → engine captures `git diff` → gates → review(s) → **engine commits** `[tactus] <task-id>: <title>` on pass.
- **Rollback on failed attempt:** `git checkout . && git clean -fd` back to the last commit — unless the retry resumes the same session, in which case the tree stays and the *cumulative* diff is re-gated.
- **Timeouts:** per-attempt wall clock (default 30 min, per-profile override); timeout = attempt failure with partial transcript as feedback.

### v0.2 — isolated candidates, serialized integration

- **Dispatch:** leave the user's checkout untouched. A task becomes runnable only when every dependency is `Merged`, then receives a detached linked worktree at the current integration SHA. One generation names one worktree/base lineage, not one attempt: an immediate same-rung session-resume retry keeps it so the cumulative diff survives, while every fresh retry, unpark, or defer recovery branches from the then-current head under a new generation. `path_hints` provide conservative dispatch leases (no hints means repo-wide); parking or deferring releases the predicted lease and active-pipeline permit. Actual changed paths replace the prediction once a candidate exists. Independent tasks may start from different integration snapshots.
- **Candidate:** the existing capture → gates → review pipeline fixes an exact tree, which the engine commits under an immutable internal candidate ref. `candidate_prepared` is the sole successful-attempt settlement for that path and contributes its embedded attempt record exactly once to replay, status, budgets, ledger, and export. Success means `AwaitingMerge`, not dependency-ready. The active-pipeline permit is released while queued, while the candidate's actual-path lease remains until integration or repair. The coordinator is the only event/ref writer; task pipelines return typed results to it.
- **Integration:** one FIFO queue (candidate-created event order, with skip-ahead past repair-path leases) fast-forwards an exact-base candidate or cherry-picks a stale one into a detached staging worktree. A stale proposal reruns every recorded gate and review pass on the exact combined tree. `merge_prepared` is both the successful terminal verification record and the durable authorization for compare-and-swap advancement of `tactus/run-<ulid>`; a code failure instead terminates atomically in `merge_rejected`, so no separate finished event creates a crash gap before either outcome. `task_merged` alone releases dependents. A stale patch already wholly present is reverified and records `expected_head == proposed_sha`, making publication a validation-only no-op before it settles explicitly at the unchanged head. The live run ref must not be checked out in any worktree.
- **Repair:** a conflict or code-attributed integration gate/review rejection publishes nothing. One `merge_rejected` append embeds the complete frozen Fix-task payload — task text, resolved ladder/binding constraints and review passes, candidate/base lineage, evidence, and `min_tier = mid` — and atomically moves the rejected task to `AwaitingRepair` while registering that repair as `Pending` or `AwaitingInput`. The rejecting head remains evidence; actual dispatch materializes the candidate against the then-current integration head so a queued or human-gated repair is not stale by construction. Later auto-binding may use only agents this run already probed; hard pins and ceilings still win over the repair floor. `run_started` freezes `max_merge_repairs` (default 2) for the whole lineage, so a new synthetic task cannot reset the autonomous budget; an over-limit or policy-blocked repair is registered with a complete frozen human question and cannot spend until an answer activates it. Provider, rate-limit, process-spawn, and runner failures retain their defer/rebind/halt semantics and never become prompts to edit product code. The repair's actual-path lease prevents known overlapping candidates overtaking it while disjoint work can continue.
- **Sequencing:** build worktrees, runner, events, and this queue under `max_parallel = 1` first; prove crash recovery; only then replace the drain loop with Tokio task pipelines, global/per-agent permits, and the same single queue. The protocol and fault matrix are fixed in [the 2026-08-12 decision](decisions/2026-08-12-merge-queue-execution-topology.md).

## 15. Event log, resume, run layout (P6)

The durable run artifacts are **split in two**, by who is allowed to read each half. v0.2 adds a third, disposable execution root that contains code but no authority:

```
<repo>/.tactus/runs/<run-id>/     # run-id = ULID — the ops surface
    events.jsonl                  # append-only source of truth
    plan.normalized.json          # the frozen plan this run executes
    artifacts/                    # conventions-brief.md, decisions-record.md, contracts
    questions/<question-id>.json  # rendered question payloads for notifiers
    answers/<question-id>.json    # answers dropped by `tactus answer`
    run.lock                      # advisory; OS-released, so a crash leaves nothing stale
    report.json                   # projection of the log for humans; never read back
~/.tactus/runs/<run-id>/          # agent-authored — outside every agent's reach
    transcripts/<task>-<attempt>.json
    reviews/<task>-<attempt>-review.json
    settings/<task>-<attempt>.json    # the per-attempt permission surface
    gates/<task>-<attempt>-<gate>.log
    gate-worktrees/                    # synced intents + disposable exact snapshots
~/.tactus/workspaces/<repo-key>/<run-id>/  # v0.2; exact path recorded on run_started
    tasks/<task>-<generation>/          # detached linked worktrees
    merge/                              # detached integration staging worktree
tactus.toml                       # repo-root config, checked in
```

The split keeps transcripts and reviewer records out of ordinary workspace reads, but the shipped host runner does **not** make the public half authoritative against hostile candidate code. Adapter deny rules reduce direct agent-tool access; they are defence in depth, not an OS boundary. Repository-controlled gates execute candidate build/test code as the Tactus user and can discover the source worktree and modify `.tactus`. A host-run event log is therefore an operational recovery record for trusted repositories and plans, not a tamper-resistant attestation. Moving coordinator authority outside every role mount and enforcing that with the external/container runner is a blocking backlog item before any stronger claim; use a dedicated OS account or VM for untrusted input.

The v0.2 execution root is deliberately non-authoritative. A container receives only its role's one worktree mount; it never receives the public log, sibling worktrees, or private artifacts. On the host runner the agent permission surface remains the boundary and gate code is not OS-confined — the reason the container runner exists. Worktree disappearance is recoverable from events and internal refs, and cleanup follows a terminal event rather than creating one.

Current host-process crash containment is deliberately platform-specific. On Unix, ordinary descendants remain in an isolated process group and a separate cleanup reaper retains the run's cleanup lease if the conductor is killed; code that deliberately daemonises out of that group remains outside the host-runner contract. On Windows, each command is created suspended, assigned to a private kill-on-close Job Object, and only then resumed. Direct-child success and timeout both terminate and boundedly observe that job empty; abrupt conductor death closes its non-inheritable handle and lets the kernel terminate ordinary descendants. PID scanning and `taskkill` are not part of the ownership protocol. Exact gate/review worktrees likewise record and sync a private intent before `git worktree add`; resume reclaims every such registration before it switches branches or dispatches another worker.

Every transition is an event `{ts, event, task?, attempt?, rung?, profile?, data}` — including `question_raised`, `question_answered`, `design_defect`, `capacity_snapshot`, `pool_exhausted`, and `spend_down_engaged`. `status`, the ledger, and the capacity view are pure folds over this file.

**One fold, not two.** The engine never mutates run state directly: it appends an event and folds it back in through the same function `resume` and `status` use to rebuild state from the file, and it applies the event *as it will be read back* rather than as constructed. A live run and a replay of its own log are therefore the same computation, not two that agree by inspection. Two things deliberately do not survive replay — a session id and its `resume_next` flag, because both describe a conversation that believed it had left edits in a working tree that a crash has since rolled back (§14 pairs session-resume with tree retention precisely so the two never diverge).

`tactus resume <run-id>` replays, verifies the run branch HEAD matches the last committed event (mismatch = refuse with an explanation), re-probes agents, re-snapshots capacity, and continues — parked questions intact. Git and the log cannot be updated atomically, so schema 3 makes the successful settlement itself carry the exact prepared identity: captured full run-branch ref, parent and tree feed hook-free `commit-tree`; the resulting commit, message, and deterministic private pin are verified before `attempt_finished` is appended. Publication compare-and-swaps the **recorded full branch ref**, never mutable symbolic `HEAD`, from the recorded parent to that commit, removes the pin with a non-dereferencing compare-and-swap, and then appends `task_committed`. Resume accepts only the resulting exact crash prefixes: parent plus matching pin means publish that object; commit plus matching pin means remove the pin; commit with the pin already gone means append the missing `task_committed`. A pin without a successful settlement is orphan residue and is removed without dereferencing symbolic refs. Any substituted or symbolic pin, third branch SHA, changed branch identity, or mismatched commit object refuses while preserving evidence. Schema-1/2 success has no prepared identity, so it is **never** adopted from parent plus subject alone; even a matching message can name an arbitrary tree. It also refuses when the frozen plan's digest moved, when the recorded chain structure no longer matches (a rung is an index into that chain), when the branch is gone, and when another process owns either the run or its physical worktree.

v0.2 extends that shipped exact-identity rule into two candidate/merge transactions. After fixing the verified tree, the engine creates and temporarily pins an immutable commit object; `candidate_prepared` is the sole successful settlement for that candidate-producing attempt and records exactly one complete attempt/base/commit/tree identity before the authoritative candidate ref moves, so resume adopts only that exact shape. Recovery then appends the missing `task_candidate_created`, whose append position establishes FIFO order. `merge_rejected` similarly embeds the complete frozen repair-task payload and admission state so rejection, task registration, key assignment, `AwaitingRepair`, and either runnable or human-gated repair state are one append rather than a rejection/spawn/question crash window. A human-gated admission's embedded question is itself authoritative for status, notification, and `tactus answer`; it is not followed by a duplicate `question_raised`. Each `merge_verification_started` has exactly one terminal record: successful evidence lives inside `merge_prepared`, code failure inside `merge_rejected`, and infrastructure/crash outcomes inside unavailable/interrupted events. There is no standalone successful or failed finish event before the state-changing append. `merge_prepared` records disposition, expected integration SHA, proposed SHA, candidate, verification evidence, and repair lineage before `git update-ref` advances the run ref by compare-and-swap. On resume, expected-old means retry that same transition and append `task_merged`, proposed means append the missing `task_merged`, and any third SHA means refuse; `already_present` uses equal expected/proposed SHAs, so the same rule becomes a checked no-op. A proposed commit with no prepared/rejected terminal event is residue and is reverified; a dangling merge-review process is settled as interrupted with unknown spend first. The event schema moves rather than teaching `task_committed` a second meaning. The complete protocol and fault table live in [the merge-queue decision](decisions/2026-08-12-merge-queue-execution-topology.md).

**Gates are taken from the record, not re-derived — and not refused over.** `run_started` records each effective gate in full (name, command, shell, timeout) and a resume rebuilds and runs *those*, exactly as it reads the review plan from the record rather than re-resolving who judges. This is the property a live run already has for free: config is parsed once at pre-flight and gates execute from memory, so a mid-run edit to `tactus.toml` cannot change what a running task is verified against. Honouring the same snapshot across an interruption is what makes every `task_committed` in one log mean the same thing — and it matters concretely once runs self-host, because the workspace an implementer edits *contains the `tactus.toml` its own gates come from*. Refusing on a mismatch was the first design and was worse in both directions: it left the weakened-gate case detected but the run dead, and it made a gate edit that the run's own reviewed task legitimately committed permanently unresumable. A config that differs today is a warning naming the difference, not an error; the edit simply applies to the next run. Logs predating the record re-derive and warn, saying whether the recorded gate *names* still match — which is proof rather than suspicion when they do not — and that resume writes what it settled on into its own `run_resumed`, so the next one is an ordinary record-bearing resume rather than a second re-derivation that could land somewhere else. `shell` is recorded because it is half of what a command means (`cmd = "true"` always passes under `sh` and is not a program at all under `cmd.exe`); the portability that argued against pinning it does not exist anyway, since `private_dir` already records an absolute host path. The finding, the refusal remedy that was withdrawn, and why, are in `decisions/2026-08-11-resume-gate-config.md`. An attempt the log ends mid-flight is settled as `attempt_interrupted`: recorded in the ledger with unknown spend, but not counted against the rung's allowance, because nothing judged the code — the same rule §19 applies to an outage.

**Effort and worker bindings are taken from the same run snapshot.** `run_started.effort_policy` records the resolved implementation value at small, mid, and frontier plus the review value, while every chain records each rung's exact agent and model plus whether it was pinned. Every worker and every review pass reads those snapshots, so editing `[routing.effort]`, adding a pin, or installing another CLI between processes cannot change one run's execution identity or standard. A mismatch warns and continues with the record; a changed chain shape refuses because recorded rung indices would no longer mean the same thing. Start a new run to adopt current routing.

Those identity fields require event schema 2. A schema-1 log remains readable by a current binary: its first resume re-derives the missing policy and bindings once with explicit warnings, then records them on `run_resumed`. Before it appends any event whose meaning depends on the new identity, it appends `run_schema_upgraded { from: 1, to: 2 }`. Current replay validates that transition; an old binary does not know the marker and therefore refuses instead of silently continuing a run whose new fields it would ignore. Later resumes are record-bound and do not append a second marker.

The complete-review and atomic sequential-settlement contracts begin at event
schema 3. A schema-2 binary ignores the recorded per-pass timeout and retains
its 60 KiB prompt truncation; it would also ignore the ladder transition now
embedded in a failed `attempt_finished` and could spend the same known failure
again after a crash. Fresh runs therefore write schema 3, and a current binary
resuming a schema-1 or schema-2 run appends a transition to 3 before another
attempt. Older binaries refuse that opening schema or transition instead of
silently applying weaker verification or replay semantics. Every failed
sequential attempt embeds its retry, escalation, deferral, terminal failure, or
parking decision in the same durable settlement. A parking settlement carries
the authoritative question too; it is not followed by separate ladder,
`question_raised`, or `task_parked` events that a crash could strand between.
A declined `question_answered` likewise freezes the contemporaneous
`on_task_failure` decision, so resume can append a missing task settlement
without reinterpreting the human's already-durable answer through edited config.

The v0.2 execution topology consequently begins at event schema 4 because its
task states and transactions change execution meaning. Fresh topology runs write
schema 4 in `run_started`; older binaries reject them before folding. Existing
schema-1 through schema-3 runs finish through the sequential path, including the
review-contract upgrade when needed. No in-flight run appends a 3 → 4 upgrade:
starting a new run is the compatibility boundary for adopting worktrees,
candidates, and the merge queue.

## 16. Agent adapters (P2)

**Claude Code** (v0.1): `claude -p` via stdin, `--output-format json` (result, session id, cost/usage parsed defensively), `--model`, `--max-turns`, `--resume <session-id>` for same-rung retries. Permissions: never the skip-all flag — the adapter materializes a per-run `.claude/settings.json` granting file tools plus `Bash(<each gate cmd>)` to edit profiles and read-only tools to reviewers. Docs: https://docs.claude.com/en/docs/claude-code/headless (flags verified Aug 2026).

Both Claude Code and Copilot also state `--effort` on every attempt. Their probes validate the complete shared enum (`low`, `medium`, `high`, `xhigh`, `max`) in the option's own help block; merely advertising the flag is insufficient because an older CLI may expose a narrower choice set.

**GitHub Copilot CLI** (v0.1): the multi-vendor pool — Claude, GPT, and Gemini models through one harness and one subscription. **Route A ships; ACP does not, and the reason is the same one that makes this the churniest adapter.** Neither `--acp` nor `--stdio` appears in GitHub's programmatic reference, so there is no documented surface to pin known-good behavior against — and pinning per version is precisely what this adapter must do. ACP also needs a persistent bidirectional JSON-RPC session, where the rest of v0.1 spawns a process, feeds it, and reads what came back. `probe()` records `acp` as a capability axis regardless, so Route B stays a change inside one file once it is documented and stable.

Route A concretely: `-s` (response only, no decoration), `--no-ask-user`, `--model=`, and granular `--allow-tool='shell(cargo test)'` / `--deny-tool=` mapping one-to-one onto profile permissions — never the `--allow-all*` / `--yolo` class (§20). **The prompt goes on stdin and `-p` is never passed**: GitHub documents `echo … | copilot` as a programmatic form and documents that piped input is *ignored* when `-p` is also given, so passing both would silently discard the real prompt. Stdin is also the only delivery that survives Windows, where npm installs `copilot.cmd` and `cmd /C` caps the command line near 8 KB — far below a complete review prompt.

What this route does not give us is recorded honestly rather than assumed: no JSON envelope, so no session id, no usage, and no cost — Copilot attempts appear in the ledger unpriced rather than free — and no documented session resume, so §11.4's same-rung retry starts fresh with accumulated feedback. Both are `Caps` axes the engine already dispatches on, and both default *pessimistic* here (advertised in `--help` or assumed absent), because claiming a capability this CLI lacks breaks every retry rather than merely degrading one. Its billing moved to AI Credits in June 2026 with legacy annual plans keeping request multipliers — both shapes are handled by the capacity engine, not the adapter. Docs: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference.

**Aider** (v0.2): `--yes`, `--model`; brings local models via OpenAI-compatible endpoints — the free pool for the home-server tier.

Adapter rule inherited as an invariant: subprocess the real binary, official CLIs only, no spoofed headers — ToS safety is a feature, not a compliance chore.

## 17. Configuration reference

Config splits along its natural seam (v2.1): **pools are user-level** — subscriptions travel with the person, discovered and written by `tactus connect` — while **routing and gates are repo-level overrides** on derived defaults. A fresh repo runs with zero config.

`~/.tactus/pools.toml` (written by `connect`, hand-editable):

```toml
[pools.claude-max]
kind = "subscription-window"
agent = "claude-code"
window = "5h"
weekly = true
sources = ["signals", "self", "local-logs"]
safety_margin = 0.15
reserve = 0.20                      # headroom for the user's interactive sessions

[pools.copilot]
kind = "credits"                    # "request-pool" on legacy annual plans
agent = "copilot"
sources = ["signals", "self"]
monthly_allowance = "auto"

[pools.local]                       # v0.2
kind = "unmetered"
agent = "aider"
endpoint = "http://homeserver:11434/v1"
```

Repo-level `tactus.toml` — overrides only; everything below has a derived default:

```toml
[engine]
on_task_failure = "halt"            # halt | continue
max_parallel    = 1                 # >1 requires v0.2
max_merge_repairs = 2               # autonomous generations per original task; then HUMAN
shell           = "powershell"      # gate shell; default = platform native

[interaction]
mode      = "on_block"              # never | on_block | on_milestone
notify    = ["cli", "desktop"]      # + "telegram", "slack" in v0.2
ask_before = { frontier_escalation_over_usd = 5.0 }

[budgets]
run_usd  = 15.0                     # API-equivalent; omit = unlimited
task_usd = 4.0
# Both ceilings sum REPORTED dollars, so they bound only the routes that report
# any. A run whose implementer is Codex and whose reviewer is Claude Code is
# bounded on the review half alone — the Codex half reports tokens and no price
# (§21), and is bounded by its own subscription window instead. The ledger says
# so with `?`; this comment exists because `--budget 15` otherwise reads like a
# guarantee about the whole run. A token-denominated ceiling is v0.2 capacity
# work if it is ever wanted.

[routing.strategy]
mode = "value-max"                  # conserve | value-max | deadline
spend_down_after = 0.7              # >70% of window left near reset → bias tiers up

[routing]                           # chains are ABSTRACT TIERS — the binder picks models and pools
fix       = { chain = ["small", "mid", "frontier"], attempts_per = 2 }
implement = { chain = ["mid", "frontier"], attempts_per = 2 }
review    = { tier = "frontier", timeout_secs = 5400 }
                                      # independent budget per pass; includes one format re-ask

[routing.effort]                    # optional role-wide standard; outranks pins and tier defaults
implementation = "xhigh"
review = "max"

[[routing.overrides]]                 # at least one of start_at / second_opinion
paths = ["src/auth/**", "migrations/**"]
start_at = "frontier"                 # optional — omit to add a reviewer without raising the floor
second_opinion = "different-vendor"   # binder must add a reviewer from another model family

[[pins]]                            # optional determinism — otherwise the binder chooses
tier  = "frontier"
agent = "claude-code"
model = "claude-opus-4-8"
effort = "max"                      # optional; default is the tier's when no role policy applies.
                                    # Validated at load —
                                    # the provider rejects an unknown level with a 400 mid-turn,
                                    # so a typo would otherwise cost a whole attempt.

[[gates]]
name = "check"
cmd  = "cargo check --all-targets"
timeout_secs = 600

[[gates]]
name = "test"
cmd  = "cargo test"
timeout_secs = 1200
```

## 18. CLI surface

```
tactus connect                     # discover installed agent CLIs, auth, plans; writes ~/.tactus/pools.toml
tactus design <brief>              # v0.3: interactive design phase (until then: Claude Code plan mode)
tactus validate <plan>             # parse, task table, routing + capacity preview
tactus run <plan> [--dry-run] [--budget <usd>] [--config <path>]
tactus resume <run-id>
tactus status [<run-id>] [--follow]
tactus answer <question-id> [--option N | --text "..."]
tactus capacity                    # all pools: remaining, resets, active strategy effect
tactus export-decisions <run-id> [--format jsonl|csv] # v0.2: local versioned attempt projection to stdout
```

The export reads only the named, non-live run's event log and `plan.normalized.json`: it makes no HTTP request, branch switch, lock acquisition, or write. JSONL is the default; CSV has the same logical rows, with nested review passes and path hints represented as quoted JSON cells. See `decisions/2026-08-11-export-decisions-schema.md` for schema 2, legacy unknowns, and the measured/derived boundary.

`--dry-run` executes everything except agents: parse, route, and print task → kind → chain (with source of each decision: config/annotation/override) → gates → pool + strategy effect, at zero spend. It exists from day one; it is both the config-iteration loop and the sales demo.

## 19. Failure handling

| Failure | Detection | Handling |
|---|---|---|
| Agent binary missing / probe failure | pre-flight | refuse to start |
| Agent spawn error | engine | halt run (environment, not task) |
| Agent non-zero / timeout | adapter | attempt failure; feedback = stderr/transcript tail |
| Rate-limited | adapter signal | pool marked exhausted; task deferred to reset or demoted per strategy (never below min) |
| Gate failure | gate runner | attempt failure; feedback = log tail |
| Review failure | verdict | attempt failure; feedback = required_changes |
| Chain exhausted | router | `Unblock` question to human (top rung); declined/CI → task Failed, dependents Blocked |
| Question parked, frontier non-empty | scheduler | continue independent tasks |
| Runnable frontier empty | scheduler | hard block (interactive) / end run reporting parked tasks (CI) |
| Budget or pool budget exceeded | ledger | stop scheduling; run ends `BudgetExceeded` |
| Merge conflict or code-attributed stale integration rejection (v0.2) | merge queue | publish nothing; atomically append rejection plus its replayable frozen Fix task, respecting hard pins/ceilings and the lineage-wide `max_merge_repairs`; infrastructure keeps its ordinary policy |
| Engine crash / power loss | — | `tactus resume` replays the event log |

## 20. Safety and permissions

- Unattended agents run with pre-granted, **narrow** permissions materialized per profile (Claude Code settings; Copilot `--allow-tool`; Codex `--sandbox`). The skip-all-permissions class of flags is never used, with one scoped exception decided alongside the v0.2 runner (§21): under a runner that is genuinely external — container-per-attempt — Codex runs its `external-sandbox` mode, because a container kept at standard hardening with the CLI's sandbox stood down beats one granted `SYS_ADMIN` so the inner sandbox can initialise. The exception exists only while the external boundary does. Edit profiles get no network tools; gates are the only commands they may run; reviewers are read-only.
- The engine refuses dirty trees, never force-pushes, never touches remotes.
- Plans are data, but an agent executing a malicious plan step with edit rights is not: trust in the plan's source is a prerequisite. For untrusted plans, run in a container or dedicated user; the engine never elevates.
- Before public launch: re-verify each provider's terms on headless/automated CLI use. This includes two specifics the design deliberately leaves to that check. **Multi-account pooling** (§13): profiles the operator holds and pays for is a different question from pooling accounts across people, which is account sharing and out of scope whatever the answer. **Spend-down** (§13's `value-max`): using prepaid capacity is not a violation, but a strategy whose stated purpose is to consume quota before it expires sits close to the usage pattern rate limits exist to shape — which is why `conserve` is the derived default and spend-down is opt-in. In both cases the mechanism is the vendor's own sanctioned surface, so an unfavourable answer costs a config option rather than an architecture. The official-CLI-only stance is the defensible posture; keep it clean.

## 21. Versioned scope

**v0.1 — the conductor works (sequential).** Claude Code plan-mode adapter + annotation grammar; Claude Code AND Copilot CLI adapters (Copilot promoted to v0.1 — it buys cross-vendor models and a second pool in one move); sequential engine with skip-ahead; run branch + engine-owned commits + rollback; gates with evidence axes; reviewer with structured verdicts + optional cross-vendor second opinion; retry-with-resume + rung escalation with the human as top rung; questions with CLI/desktop delivery and `tactus answer`; event log, resume, status, ledger; capacity engine **read-only** (`tactus connect` discovery, preview + `tactus capacity`); `validate` and `--dry-run`; pre-flight probing.

Build order (each step leaves a runnable binary): 1 IR + config + validate → 2 plan adapter + annotations → 3 Claude Code adapter → 4 sequential engine + git ownership → 5 gates → 6 reviewer + verdicts → 7 retry/escalation ladder + human rung + questions → 8 events/resume/status/ledger → 9 Copilot adapter + cross-vendor review → 10 connect + capacity read-only + dry-run + polish.

**v0.1 definition of done:** in a real git repository — real gates, real agent CLIs, real spend, nothing mocked; seeded for the purpose counts, inherited history is not required — a 3–5 task annotated plan completes end-to-end where (a) a small-model task passes gates first try, (b) a gate failure recovers via same-rung session-resume feedback, (c) one task escalates a rung and passes, (d) one question parks a task while an independent task proceeds, answered via `tactus answer`, and (e) the summary reports per-task attempts, models, API-equivalent cost, and per-pool drain, with the dry-run having previewed capacity beforehand. Then kill the engine mid-run and `resume` finishes it.

**v0.1 was met on 2026-08-10.** A five-task plan ran unattended against a scratch repository through all five criteria and the kill/resume test, and the engine was then used on a real published library. `acceptance/RESULT.md` records both, with the evidence for each criterion and the engine defects found: **three from the acceptance run and a fourth from the real-library run that followed** — all fixed. (The count is stated per-run wherever it appears, because "three" and "four" are both true of different things and the difference is which run is being talked about.) The definition of done above said "on a real repo" until after the run, and was tightened afterwards to say which part of "real" it meant — that is a clarification made with hindsight, and the ambiguity it removes is the one that had the README calling a scratch repository real. Released as `0.1.0`; `0.0.1` was a name reservation only.

**v0.2 — parallel + capacity-driven.** Detached worktree-per-task with immutable verified candidates; **execution runner — container-per-attempt as an optional layer, decided 2026-08-11 and concretized with the worktree boundary below**; Tokio coordinator with global/per-agent semaphores and one event/ref writer; readiness = Merged; conservative path-hint admission plus actual-path repair leases; one compare-and-swap merge queue with exact-tree re-verification for stale candidates and conflict or code-attributed gate/review rejection → recorded Fix task ([protocol decided 2026-08-12](decisions/2026-08-12-merge-queue-execution-topology.md)); capacity-driven routing live (conserve / value-max / spend-down, reserve floors, rate-limit adaptation); affinity assignment (streak batching + measured switch costs from decision logs); Telegram/Slack notifiers; **OpenAI Codex adapter (landed 2026-08-11, ahead of the rest of v0.2)**; Aider adapter + local pool; task-master/JSON/checklist plan adapters; `export-decisions`.

**Why the Codex adapter came first, and what it turned out to be.** Copilot was promoted into v0.1 because it bought cross-vendor models and a second pool in one move; this one buys the second pool *directly*, and that turned out to be the binding constraint rather than a convenience. §13's capacity engine assumes several subscriptions with independent windows, and v0.1 shipped able to drive exactly one — so a week of real work exhausts a single vendor's quota and the engine stops, with the design's whole answer to that sitting unreachable. Everything else in v0.2 is throughput; this is capacity, and capacity is what ran out first.

**Its implementer path is Linux-only, and that is a platform fact rather than a CLI one.** Codex sandboxes through an external helper: `codex doctor` reports a path for it on Linux and `none` on Windows. With nothing to enforce a boundary, Windows `exec` — which forces `approval_policy = never` — degrades to read-only and then *accepts `--sandbox workspace-write` while writing nothing*, exit 0, no warning; run `01KZRMHA28M5CM88VAXP613X9P` spent both attempts on empty diffs before parking to ask for access it had. Its only writing mode there (`--approve-for-me`) auto-approves writes anywhere on the filesystem, including outside the repository, which §14's `git clean -fd` rollback cannot undo — so §20 rules it out and the adapter refuses at build time (§19). On Linux the same flags behave: writes land inside the workspace and are blocked outside it, both measured, so implementation is open there. Containerising it needs `--security-opt seccomp=unconfined --cap-add SYS_ADMIN`, or the sandbox fails to initialise and produces the same empty diff by a third route. All measured against codex-cli 0.147.0 with ChatGPT-plan auth on 2026-08-11; `src/agent/codex.rs` carries the detail.

**The reviewer seat works everywhere and is the immediate win** — `read-only` is enforced on every platform, the family is genuinely non-Anthropic, and a judge that spends nothing on the Claude window is worth having by itself. Verified end to end on run `01KZRN48A4ZK3AEDST3RJ8HMA4`: the first §11.3 cross-family review this project has ever actually run, after claiming the capability since v0.1. **That run, and every Codex review before step 10, judged at `low` reasoning effort** — the CLI takes its default from the provider's model roster (`gpt-5.6-sol`: `default_reasoning_level: low`) rather than its flags, and the adapter passed none, so the setting was never tactus's to begin with and never appeared in the record. The adapter now states `model_reasoning_effort` on both the fresh and resumed shapes (§10), proves the exact `xhigh` and `max` assignments with Codex's strict local config parser on both surfaces before a deliberately missing schema file prevents any model turn, and cross-checks every known Codex model against the installed CLI's local `debug models` effort list before spend. **Re-established on run `01KZS7R0V1ZD6MC290MG350QXF`**: Claude implementing at mid, Codex judging at frontier, and codex's own session rollout recording `"effort":"high"` — the CLI's account of what it received rather than ours of what we sent, which is the pair that had silently disagreed until then. It also carries a `Caps` axis the others do not — usage without pricing — recorded per attempt and rendered as `?`, exactly as §13 says an unpriced route should be.

**The runner layer (v0.2): the container is the floor, not the ceiling.** The Codex findings raised the obvious question — with agent sandboxes this uneven (Codex has none on Windows; Copilot's deny-by-default is admitted unverifiable in its own adapter), why not run every agent in an OS-level container and stop caring about their surfaces? The answer that survived scrutiny is a *layer*, not a replacement; the premise is about 60% true, and the design is knowing which 60%. What a container uniquely buys, in order: it is the first mechanism in this design that confines **gate-executed repository code** — gates run the diff's own build scripts with the tactus process's full authority, which no agent permission surface can ever bound and which is why §15 moved transcripts out of the workspace rather than trying; a `:ro` mount makes the reviewer's read-only *mechanically* perfect instead of flag-deep, ending the reviewer-edits-what-it-judges class outright; and an image with version-pinned CLIs makes the mid-run self-update that killed acceptance run 1 structurally impossible. What it cannot replace: **the network**. An agent's entire function is a network conversation with its vendor, so the container cannot close the channel, and selective egress — allow the vendor API, deny everything else — is a proxy project, not a docker flag. Until one exists, §20's no-URL-grant agent policy remains the only control on the largest exfiltration channel, which alone kills "we don't need to care about the agents." Adapters also keep every duty that is not filesystem confinement — prompt delivery, output parsing, resume semantics, rate-limit phrasing, each CLI's suppress-prompts flag; the permission surface is roughly a fifth of each adapter, and the runner touches only that fifth.

**Runner design commitments, recorded now so the build inherits them.** (1) A runner is orthogonal to an adapter: `[runner]` config selects `host` or `container` (image, mounts), the adapter builds a data-only `CommandSpec`, and the runner decides where it executes — adapters never learn about containers, and the runner learns nothing about agent semantics beyond which per-agent credential volume to mount (persistent volumes, not ephemeral copies: some CLIs rotate refresh tokens on use, and a discarded rotation forces re-login). Probes run through that same runner, or pre-flight could certify a host CLI/version different from the one the attempt executes. Workers, **repository-controlled gates**, and reviewers all cross the boundary; authoritative Git and the event log never do. Because a linked worktree's `.git` points back into the real repository, the container overlays a disposable role-scoped Git view — exact detached HEAD/index, no engine refs, read-only objects — so Git-dependent tools work without exposing or mutating the coordinator's refs. This is the same seam §23's runner-fleet model and v0.3's GitHub Action plug into, so the layer is on the roadmap's path regardless. (2) Defence in depth stays the default: agent surfaces remain ON inside the container wherever they work; the container catches what they miss. (3) Codex under a runner uses its `external-sandbox` mode — measured 2026-08-11: its own sandbox needs `seccomp=unconfined` plus `SYS_ADMIN` to initialise under Docker's defaults, and granting the container more so the inner layer can grant less is the wrong trade; one standard-strength boundary beats two weakened ones. §20's ban on the skip-sandbox class gains exactly that one scoped exception, stated there. (4) Sequenced with worktree-per-task because both redesign where an attempt executes; first make the host and container runners exercise the same detached-worktree protocol at `max_parallel = 1`, then add concurrency without changing it. On Windows the honest cost is named now: container-per-attempt means the repository living WSL-side for filesystem performance — an operator-environment migration, not a footnote. Until the runner exists, the zero-code path stands: run the conductor itself on Linux or WSL, where all three CLIs work, the engine is best-tested since the lock rework, and the Windows-only Codex implementer refusal opens by construction. That path, not the reviewer seat, is where the quota relief lives — in the frontier-implementer regime the implementation half dominates spend (§23.2 as scoped), so relief means moving the *worker* off the Claude window; a free cross-family reviewer is worth having for §11.3's own sake, not as the savings.

**v0.2 definition of done:** a plan with two independent branches runs at `max_parallel = 3`, visibly interleaves in `status --follow`, and a dependent starts only from a head containing both; the user's checkout stays untouched; a stale clean candidate is re-gated and re-reviewed before compare-and-swap integration; one deliberate merge conflict is auto-resolved by an atomically recorded replayable Fix task, while repeated rejections stop at the frozen repair limit; kill tests at every candidate/merge/rejection transaction boundary neither duplicate nor lose a commit or attempt settlement; schema-3 resume stays sequential and a schema-3 binary refuses schema 4; the host/container runner parity tests prove object-safe execution, identical environment composition, read-only review, and confinement of gate writes; one question is answered from a phone while the run keeps moving after releasing its pipeline permit and dispatch lease; and near a window reset with surplus capacity, spend-down mode observably biases assignments up-tier — with the ledger proving worker, candidate re-verification, reviewer, and pool spend exactly once.

**v0.3 — direction.** The design pane (interactive Phase-1 product) and a web dashboard, both as thin clients over the event log; a GitHub Action wrapping `tactus run`; the design-defect feedback loop surfacing into the designer prompt; and routing *prediction* — a frontier model predicting rung and cost at `--dry-run`, shipped only if §23.2's calibration test passes. Learned routing from exported decisions is parked indefinitely at personal scale — single-digit samples per routing cell, and quarterly model churn decays the dataset about as fast as it grows (`decisions/2026-08-11-design-council.md`); the telemetry keeps landing because it is what makes small data interpretable, not because it will train anything.

**v0.3+ — repository review attestation is a notary, not another reviewer.** A forge integration may turn Tactus's final integration verdict into an enforced pull-request requirement, but publication must never spend a second frontier review merely to tell the forge what Tactus already proved. Open the draft pull request early and let cheap forge CI run first. Strong forge-enforced mode reviews a provider-native merge-result or merge-group object that the forge guarantees represents exactly what will be appended to the protected target: the cumulative target-base-to-result diff and resulting repository state. The model judges the canonical semantic identity—base tree, canonical diff, result tree, immutable scope, and frozen policy—while the attestation separately binds that verdict to the repository, target, ordered source commits, and exact provider result commit after the adapter proves semantic-key equivalence. An ephemeral pull-request test-merge is eligible only when the adapter proves that exact checked object is the published object; otherwise it remains owner-attestation mode even if its tree is identical. The provider must also expose a merge predicate that distinguishes admission from the attested result and enforces the semantic identity plus publication binding; a commit-SHA status shared by both phases is insufficient. Task, candidate, or merge-verification verdicts may be reused only when their recorded semantic scope is exactly the full semantic identity. Code implemented manually or outside Tactus enters through a review-only Tactus run that produces the same final settlement.

**One authoritative settlement, append-only history.** The coordinator attester owns a repository-scoped append-only event ledger, separate from each run's `events.jsonl` and authoritative only for final-review settlement and cross-run uniqueness. It is keyed by the full enforced identity: repository audience, target ref, base/ordered-source/result commits and trees, immutable review scope, and frozen final-review policy. Settlement also derives a separately schema-versioned semantic key from repository audience, target ref, base tree, a canonical base-to-result diff under an identified algorithm, result tree, immutable scope digest, and frozen policy tuple; commit and merge-group SHAs are publication bindings, not reset authority. `REJECTED`, `NEEDS_HUMAN`, `INDETERMINATE`, and `WAIVED` tombstone every publication identity with that semantic key, so an empty commit, metadata-only rewrite, rebase, or regenerated merge group cannot authorize a fresh judgement. A prior `PASS` may be rebound to a new provider commit without model spend only after the adapter proves the semantic key is identical; otherwise a changed semantic key requires review. A compare-and-swap claim serializes exactly one settlement sequence per `(semantic-key schema/version, semantic key)` across every publication identity that projects to it. Semantic-key schema or canonical-diff upgrades do not create a new shopping namespace. Migration is one ledger-root CAS transaction: it authenticates the predecessor root and schema epoch, blocks and drains claim and terminal writers, computes the total mapping of every extant lineage, resolves every many-to-one collision, appends the authenticated migration root, activates exactly one successor epoch, and retires every predecessor claim namespace atomically. Every later claim, terminal append, rebind, and attestation authenticates the expected epoch and CASes the canonical alias representative; stale-epoch operations fail. Multiple active sequences, incompatible terminal outcomes, or any tombstone colliding with `PASS` fail the migration closed; they can never reduce to `PASS` or authorize rebinding. Claims resolve the complete migration and alias lineage before CAS, and the signed envelope binds the migration root and epoch lineage so the verifier can replay it. If any prior key cannot be migrated or equivalence cannot be proved, forge-enforced settlement under the new version remains disabled. No second sequence may start while that semantic key is active or after it is terminal; only a provably pre-dispatch `INCOMPLETE` may append the next numbered execution inside the same sequence. Rebinding a `PASS` creates a newly signed publication binding from that same terminal sequence, never a new review sequence. Within the sequence, each required pass slot has durably numbered executions, and the ledger records every execution start and exactly one terminal outcome before another execution of that slot may begin. A provably pre-dispatch infrastructure failure records `INCOMPLETE` and may retry that slot under the same frozen policy. Once dispatch may have reached the reviewer, an outcome-free interruption may only idempotently recover that same provider invocation, session, and content-addressed output; it may not start a fresh judgement. If recovery is impossible, the identity becomes terminally `INDETERMINATE`. A recovered semantic failure records `REJECTED` immediately and short-circuits unstarted later slots; `NEEDS_HUMAN` is likewise terminal. `PASS` requires the current settlement sequence to contain exactly one recovered semantic verdict for every frozen pass slot, in order, and every verdict must pass. Human adjudication is a separately signed `WAIVED` outcome with actor and reason and never masquerades as `PASS`. `REJECTED`, `NEEDS_HUMAN`, `INDETERMINATE`, or `WAIVED` terminally close the sequence and require a changed semantic key before `PASS`; only a pre-dispatch `INCOMPLETE` may append another execution for the same slot and identity. All outcomes remain append-only history, so another run cannot shop the same tuple for a friendlier verdict. Any publication-identity change invalidates its status binding; it requires a new model review only when the semantic key changes.

**The attestation is a protocol, not a prose blob.** After an execution run has otherwise completed successfully, Tactus projects the current passing settlement from the supported attester ledger together with its content-addressed completed-run record into a separately versioned, exporter-local, canonically encoded envelope. It binds the attestation-schema and digest-algorithm identifiers; semantic-key schema/version and canonical-diff algorithm/digest identifiers; engine build and event-protocol versions; anti-replay run and settlement-sequence identities; repository audience; target/base/ordered-source/result commit and tree identities; frozen policy id, schema, version, and digest; the normalized-plan hash; canonical digests of acceptance, conventions, decisions, immutable review scope, and the fully rendered final-review prompt; immutable template and verdict-parser schema/version identifiers; every required pass in execution order (ordinal, lens, agent, adapter, model, model family, pre-flight CLI version, effort, outcome, and content-addressed evidence); the aggregate verdict derived fail-closed from that complete list; and a domain-separated digest of the evidence manifest and authoritative attester-ledger/completed-run settlement roots. In forge-enforced mode, every acceptance, convention, decision, plan, prompt, and scope input that can change review meaning must be immutable content reachable from the reviewed result tree, except the target and exact policy tuple selected by the statically required context. An envelope-only digest is audit evidence, not merge-bound identity; an adapter that cannot prove this anchoring refuses strong mode. Pull-request number, branch name, title, body, and other mutable metadata are display-only and cannot alter semantic scope. Two publication identities with the same semantic key deliberately share one settlement through signed rebinding; reuse across different semantic keys is forbidden. Unknown, retired, missing, non-canonical, or unsupported schema, engine, policy, prompt, parser, or digest versions fail closed without discarding or bypassing any prior settlement, tombstone, or migration lineage.

**Trust and publication stay outside judged code and outside the execution engine.** Forge-enforced mode requires workers, repository-controlled gates, and reviewers to run behind an external boundary with no access to coordinator state, settlement/evidence/attestation storage, or forge credentials; host-run mode remains local-only. After settlement, a post-run `ForgeAdapter` client—outside the core engine, preserving the engine's no-remotes invariant—uses the forge's official CLI only to transport the canonical envelope. CLI authentication proves transport identity, not provenance. The coordinator signs the envelope with an attester key unavailable to attempts and distinct from the publisher credential, or with an OIDC-bound keyless signature whose verifier pins issuer, audience, subject, workflow identity and immutable workflow blob SHA/trusted ref, protected environment, and repository; repository audience alone is insufficient. A trusted default-branch workflow first verifies canonical encoding, signature, every pinned issuer/key/workflow claim, repository audience, anti-replay identity, the complete enforced tuple, policy and pass completeness, derived verdict, and evidence root, then reruns repository-controlled gates in a secretless job. Only after that succeeds may a protected publisher job that executes no repository-controlled code obtain the forge's dedicated publisher credential and publish its provider-native required status. The publisher is only a machine identity: it hosts no model, webhook, or review service.

**The merge rule must enforce the same semantic identity and publication binding the attestation records.** A head-only exact-SHA status—including this repository's current App check—is a useful owner attestation but cannot claim strong enforcement of pull-request scope, exact base, or policy. GitHub's current required-check predicate is App, context, and commit, while merge-queue admission requires those coupled contexts to pass before the distinct `merge_group` commit exists. Withholding the strong context from the source head therefore deadlocks admission; emitting a cheap success there permits that commit-scoped result to alias an attested result in another pull request because phase labels, pull-request identity, `external_id`, details, and evidence are outside the merge predicate. GitHub strong mode consequently remains disabled until GitHub exposes a merge rule that independently enforces the attested result and phase; the GitHub `ForgeAdapter` initially implements only the weaker owner-attestation mode. Every variable review-semantic input, including plan and scope, must be content-addressed by the reviewed result or fixed by immutable target policy. Another forge is supported in strong mode only when its native status, protected publisher identity, trusted execution, admission protocol, and merge rule enforce the equivalent semantic identity and exact publication binding without a phase-confusable status. Repositories that do not want forge enforcement keep the local headless workflow unchanged. This protects the process from stale, spoofed, self-minted, reuse across different semantic keys, and pass-shopped output; an operator who controls the coordinator attester, publisher credential, or forge administration remains outside the threat model.

## 22. Adopted from the field (with credit)

- **Fresh-context-per-stage** discipline — every worker starts clean and receives only curated artifacts (Context Foundry).
- **Evidence-gate taxonomy** — empty-diff refusal, red-test blocking, test provenance (fail-on-base/pass-on-HEAD), secret-leak axis — and the anti-sycophancy reviewer stance (Loki Mode).
- **ACP (`--acp --stdio`)** as the durable programmatic surface for the Copilot adapter (GitHub).
- **Notifier transport abstraction** and the "subprocess the real binary, no spoofed headers" ToS posture (ductor).
- **Local-log usage parsing** as a capacity source that sees interactive sessions too (ccusage lineage).

## 23. Risks and kill criteria

- **Competitive risks, kill criteria, and positioning** are maintained in the strategy record outside this repository (moved 2026-08-22); the engineering risks stay here.
- **Estimator fragility:** provider usage endpoints break silently; hence signals-first trust order, read-only capacity in v0.1, and log-parse fallbacks.
- **Catalog staleness:** model rosters churn monthly; unknown models are never auto-selected, the catalog ships with releases, and pricing-derived priors bridge gaps.
- **Adapter churn:** Copilot's CLI has removed flags without deprecation; probing at pre-flight and per-version pinning are load-bearing, not nice-to-haves.

### 23.1 Deployment model and the enterprise path (recorded 2026-08-10)

The deployment model, the enterprise path, the positioning arguments and their kill
criteria moved to the strategy record outside this repository on 2026-08-22. The
engineering consequences other documents rely on are retained here, unchanged in substance:

- **Per-seat deployment.** tactus runs on a developer's own machine, subprocessing a CLI
  signed in as *that developer* — through corporate SSO where there is one. There is no
  service account and no shared credential; a fleet of shared runners under a service
  account is not built without written terms saying it may be.
- **An org-shared pool cannot be estimated from one seat.** Every §13 source except provider
  endpoints is local to the seat, so against an org-level pool each instance estimates a
  shared resource from a fraction of the evidence. `Remaining::AtMost` stays correct but
  degrades toward vacuous; v0.2's answer is a pool flag — an org-shared pool returns
  `Unknown` with a note naming why — not a better estimator. Provider endpoints are the
  only org-level signal and remain a hint, never a floor.
- **Two features already serve a team without being built for it.** Repo-level
  `tactus.toml` is policy distribution (a required second opinion on `src/auth/**` is
  committed to git and reviewable in a PR), and `reserve` reads as headroom for colleagues
  exactly as it reads as headroom for one's own interactive work.
- **The engine's record is the auditable account of what agents did**: engine-owned
  commits, the append-only event log, the engine-captured diff as ground truth, the
  reviewer's model family recorded per attempt, narrow permissions, and per-pool cost
  attribution — on any host, pre-commit. This is what the self-hosting record's "pen"
  refers to.
- **A refined story maps onto the IR nearly 1:1** (key → `id`, story → `implement`, bug →
  `fix`, spike → `design`, acceptance criteria → `acceptance`, component → `path_hints`,
  blocked-by → `depends_on`), so backlog import is translation, not authoring — an importer
  under §9's posture, never HTTP of our own. Writeback is a `Notifier` over the event log.
  Every `design_defect` is attributable to a story and aggregable per sprint: a badly
  refined story parks on a recorded question naming exactly what refinement failed to
  settle — a Definition of Ready with a failure signal. The importer is the
  highest-leverage unbuilt item; the near-term version is one developer hand-translating
  two stories in ten minutes.
- **Sequencing.** Prove the loop unattended (§21's acceptance run), use it on real work
  until it would survive a stranger's scrutiny, then build what real teams ask for. One
  cheap early check: confirm against real enterprise terms whether agent CLIs may run under
  anything other than a named seat.

### 23.2 What the first real runs measured (recorded 2026-08-10)

- **Review is charged per attempt, so attempt count dominates cost — and §13's `conserve` framing names the wrong lever.** Measured on one task, same base commit and same reviewer, with only `attempts_per` differing: escalating on the first failure cost **$2.73** over two attempts, while retrying on the cheap rung cost **$3.21** over three — *despite* the cheaper arm using the cheaper worker throughout. A frontier review costs the same whatever rung it judges, and it was 44–77% of spend across four runs, so one extra attempt costs more than one cheaper worker saves. "Route down aggressively, escalate only on failure" therefore optimises the smaller half of the bill and can lose money doing it; what reduces spend is **fewer attempts**, which often means starting *higher*. Two things keep this honest. The cheap rung does genuinely recover — §21(b)'s same-rung retry is real, and a retry succeeded here on the third attempt — so this is an argument about price, not capability. And the shape the data points at is inexpressible today: `attempts_per` is one `u32` per kind (`config.rs`), not per rung, so "one shot on the cheapest rung, a retry higher up" is a v0.2 config change rather than a settings tweak. **When cost has to come down _while the implementer is cheap_, the lever is the reviewer, not the worker** — a cheaper judge on early rungs — and that trade must be made deliberately, because on this evidence the reviewer is the half that earns its keep: it rejected an emission that built clean and passed all 722 tests but was not a compile-time constant, and so would have failed CS0133 in a consumer's build. No gate can catch that. **The scoping matters and the emphasis above is deliberate:** every run behind these numbers started at `small` and the ones that succeeded landed at `small` or `mid`, so nothing here measures a frontier *implementer*. The sentence beside it — a frontier review costs the same whatever rung it judges — is what says the ratio must invert: review is a roughly fixed cost per attempt, while implementation scales with tier and with how much agentic work the task takes. Review's 44–77% share is therefore a fact about cheap workers, not a law. Read as a general finding it would send someone optimising the wrong half of a frontier-implemented run, which is the regime the Codex adapter (§21) exists to make affordable, and the one this project still has no numbers for. That gap is now recordable rather than merely regrettable: `AttemptRecord.usage` carries the tokens a CLI reports even when it reports no dollars, because a run that did not record its usage can never be re-measured.
- **The routing dataset is better than §10 implies and the prize is smaller than it sounds — bound it before building anything.** §10 promises `export-decisions` "emits the dataset a learned router would train on" and v0.3 lists learned routing. Two corrections, pulling opposite ways. In its favour: **escalation yields paired observations** — `small failed → mid ok` is two models attempted against an identical task, treatment varying with the task held constant, produced free as a side effect of the ladder. That is a better structure than most off-policy settings ever get, and the label (passed every gate and an independent frontier reviewer) is objective and adversarially generated, which is rare in this domain. Only one direction is censored: when the cheap rung succeeds, nothing learns whether the expensive one would have, and buying those cells means occasionally double-running on purpose. Against it: **a perfect oracle is worth only the attempts it would have skipped, measured at 15–25% of spend** — real at scale, transformative for nobody — and the residual doubt is about *features*, not sample count, since the task that defeated both cheap attempts here read as trivial from its text and was hard for a reason living in the codebase's semantics rather than in anything a feature vector recovers. **The cheap test is to ask a frontier model to predict rung and cost against runs whose outcome is already known**; if it is calibrated, ship that as a `--dry-run` step and drop the learned policy entirely. One methodological finding stands behind all of the above and generalises past it: two runs of an identical configuration on one task produced two *different failure modes* — a review rejection and a parked question — so a single-run A/B comparison of agent behaviour is not evidence, however clean its numbers look. **Sharpened 2026-08-11**: the same reviewer, same model, same effort, passed `u8::try_from(v).unwrap_or(100)` on one run ("not the prohibited panicking `unwrap`") and rejected it on another ("still an unwrap-family shortcut") — one judge disagreeing with itself on one line, which puts the noise floor of review across pass and fail on identical input (`decisions/2026-08-11-codex-reasoning-effort.md`). The corollary is for plans, not judges: acceptance criteria naming a forbidden *idiom* invite that judgement call, where ones naming a forbidden *behaviour* ("must not panic on any input") can be checked.

## 24. References

- Claude Code headless mode: https://docs.claude.com/en/docs/claude-code/headless — and overview: https://docs.claude.com/en/docs/claude-code/overview (flags verified Aug 2026)
- Copilot CLI programmatic reference: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference · running programmatically: https://docs.github.com/en/copilot/how-tos/copilot-cli/automate-copilot-cli/run-cli-programmatically (verified Aug 2026)
- Companion research reports (prior art, competitive landscape, demand evidence) are maintained in the strategy record outside this repository.
