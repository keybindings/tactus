//! The event log and the state it folds to (DESIGN.md §15, invariant 4).
//!
//! `events.jsonl` is the run's source of truth: every state transition is an
//! event, and state is what you get by replaying them. `status`, the ledger,
//! and `resume` are all folds over this file; `report.json` is a projection of
//! the same fold, written for humans and never read back as state.
//!
//! The load-bearing decision here is that **there is one fold, not two**.
//! [`RunState::apply`] is the only thing that mutates run state, and the live
//! engine reaches it the same way replay does — by emitting an event and
//! applying it. A live run and a replay of its own log cannot drift, because
//! neither has a private path to the state. Any bug is a bug in both, which is
//! a property a test can actually pin (see `live_state_equals_replayed_state`
//! in `engine.rs`).
//!
//! Two things deliberately do *not* survive replay, both for the same reason:
//! a session id and a `resume_next` flag describe a conversation that believed
//! it had left edits in the working tree. After a crash that tree is rolled
//! back, so the belief is false and §14's pairing of session-resume with
//! tree-retention is broken. `run_resumed` clears both.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fmt;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::TactusError;
use crate::interaction::QuestionRecord;
use crate::ir::{Answer, Effort, Question, QuestionId, ResolvedEffortPolicy, Tier};
use crate::ladder::{FailureKind, FailureOrigin};
use crate::util;

pub mod log;

// The public paths are unchanged: `crate::events::EventLog`,
// `crate::events::read_all` and `crate::events::LogTail` are what every caller
// outside this module already names, and `decisions.pr_sequence[6].scope`
// requires the first of those to stay put ("EventLog writer moved to
// src/events/log.rs (**public path crate::events::EventLog unchanged**)").
pub use log::{EventLog, LogTail, read_all};
pub(crate) use log::{ParsedLines, parse_bytes, read_bytes};

/// Bumped when an event's meaning changes in a way an older binary would
/// **misread**. A newer log is refused rather than folded on a guess — silently
/// deriving the wrong state from a log we half-understand is the one failure
/// mode an event-sourced design must not have.
///
/// Misread is the operative word. Step 10's additive reporting fields stayed in
/// schema 1 because ignoring them did not change execution. Schema 2 froze
/// effort and resolved worker bindings because they are execution identity.
/// Schema 3 freezes the complete-review and atomic-attempt contracts: a
/// schema-2 binary would ignore the per-pass timeout and still truncate review
/// prompts at 60 KiB, and would ignore an embedded ladder transition and
/// repeat a settled failure after a crash.
/// Fresh runs therefore say `3` in `run_started`; when this binary resumes an
/// older run it appends `run_schema_upgraded` before another attempt, so older
/// binaries refuse the changed verification standard rather than misread it.
pub const SCHEMA_VERSION: u32 = 3;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// One line of `events.jsonl`, in §15's shape:
/// `{ts, event, task?, attempt?, rung?, profile?, data}`.
///
/// `ts`, and the routing fields hoisted out of each variant, are what make the
/// raw file greppable — `rung` and `profile` in particular answer "what ran
/// where" without a JSON parser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub ts: String,
    #[serde(flatten)]
    pub body: EventBody,
}

impl Event {
    /// Stamp a body with the current time.
    pub fn now(body: EventBody) -> Self {
        Self {
            ts: util::rfc3339_utc_now(),
            body,
        }
    }

    /// The task this event concerns, if any.
    pub fn task(&self) -> Option<&str> {
        self.body.task()
    }
}

/// Every transition the engine records.
///
/// Internally tagged on `event`, with the routing fields alongside the tag and
/// the payload under `data` — one Rust type per event kind, so a variant and
/// its payload cannot disagree.
///
/// Two things are deliberately *not* events. **Blocked and skipped settlement**
/// is derived in `finish()` rather than recorded, because it is a view of an
/// ended run: a task blocked behind an unanswered question must become runnable
/// again the moment that question is answered, which a recorded state would
/// fight. And **an unreachable answer channel** is process-local — a question
/// nobody could answer at 2am is exactly the one the operator answers when they
/// come back, so `resume` must be free to ask again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EventBody {
    RunStarted {
        data: Box<RunStarted>,
    },
    RunResumed {
        data: RunResumed,
    },
    /// Append-only downgrade barrier for a run whose `run_started` cannot be
    /// rewritten from an older schema. Schema-1 binaries fail on the unknown
    /// event tag; schema-2 binaries understand the tag but reject a transition
    /// to schema 3 before they can apply the old partial-review contract.
    RunSchemaUpgraded {
        data: RunSchemaUpgraded,
    },
    AttemptStarted {
        task: String,
        attempt: u32,
        rung: u32,
        profile: String,
        data: AttemptStarted,
    },
    AttemptFinished {
        task: String,
        attempt: u32,
        rung: u32,
        profile: String,
        data: Box<AttemptRecord>,
        /// A policy refusal that must finish the paid attempt and park the
        /// task atomically. Without this, a crash between `attempt_finished`
        /// and the separate question/parking events can replay the task as
        /// pending and pay for the same known-unreviewable attempt again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parking: Option<Box<AttemptParking>>,
        /// The ladder decision caused by this failed attempt. It is part of
        /// the same durable append as the attempt record: a crash must not
        /// replay a known failure as pending work on its old rung.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transition: Option<Box<AttemptTransition>>,
        /// The exact commit object prepared from the reviewed index for a
        /// successful attempt. Creating the object does not move a ref; the
        /// event is therefore durable before the branch advances, and resume
        /// can finish either side of that CAS without re-running paid work.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prepared_commit: Option<Box<PreparedCommit>>,
    },
    /// The `attempt_finished` a dead process never got to write.
    ///
    /// Recorded by the resume that finds the attempt dangling, rather than
    /// merely derived in memory: a settlement that lives only in a reader's
    /// head is lost the moment the log is replayed by someone else, taking the
    /// ledger line *and* the rung's refunded allowance with it.
    AttemptInterrupted {
        task: String,
        attempt: u32,
        rung: u32,
        profile: String,
        data: Box<AttemptRecord>,
    },
    /// §11.4: feed the failure back and try the same rung again.
    LadderRetry {
        task: String,
        attempt: u32,
        rung: u32,
        data: LadderRetry,
    },
    /// §11.4: next rung, fresh session, accumulated feedback.
    LadderEscalated {
        task: String,
        attempt: u32,
        rung: u32,
        data: LadderEscalated,
    },
    /// §19: an outage, so the attempt is given back rather than spent.
    TaskDeferred {
        task: String,
        data: TaskDeferred,
    },
    /// The scheduler waited out a deferral and made that work runnable again.
    DeferWaitElapsed {
        data: DeferWaitElapsed,
    },
    TaskParked {
        task: String,
        data: TaskParked,
    },
    TaskCommitted {
        task: String,
        data: TaskCommitted,
    },
    TaskFailed {
        task: String,
        data: TaskFailed,
    },
    QuestionRaised {
        task: String,
        data: Box<QuestionRaised>,
    },
    QuestionAnswered {
        data: QuestionAnswered,
    },
    /// §5: every question that reaches a human at runtime is a design-phase
    /// defect, logged as one so the designer prompt can learn from it.
    DesignDefect {
        data: DesignDefect,
    },
    /// §14's pre-flight capacity snapshot, taken again after every `run_resumed`
    /// because a resume re-establishes everything a fresh run does (§15).
    ///
    /// Folds to **nothing**, like `design_defect`: v0.1's capacity engine is
    /// read-only (§13), so nothing routes on it and recording it as state would
    /// imply otherwise. It is in the log because "what did the pools look like
    /// when this run made its choices" is unanswerable afterwards.
    CapacitySnapshot {
        data: CapacitySnapshot,
    },
    /// §15: a rate-limit signal attributed to a pool — §13's source 1, and the
    /// only thing in v0.1 that can say a pool is empty rather than unmeasured.
    ///
    /// Separate from the `task_deferred` that follows it because they are
    /// different facts with different lifetimes: the deferral is about one
    /// task's next move, while this is about a subscription, and a later fold
    /// reads it back as ground truth for every pool estimate ([`crate::capacity::observe`]).
    PoolExhausted {
        task: String,
        data: PoolExhausted,
    },
    /// §13's budget ceiling stopped the run before an attempt was spawned.
    ///
    /// **Downgrade consequence, stated plainly:** `SCHEMA_VERSION` does not
    /// bump for this (see its docs), so a binary older than step 10 folding a
    /// budget-stopped log fails on an unknown variant — a loud refusal naming
    /// the log, never a silent misread. That is the trade the version contract
    /// is written around.
    BudgetExceeded {
        data: BudgetExceeded,
    },
    RunFinished {
        data: RunFinished,
    },
}

impl EventBody {
    pub fn task(&self) -> Option<&str> {
        match self {
            Self::AttemptStarted { task, .. }
            | Self::AttemptFinished { task, .. }
            | Self::AttemptInterrupted { task, .. }
            | Self::LadderRetry { task, .. }
            | Self::LadderEscalated { task, .. }
            | Self::TaskDeferred { task, .. }
            | Self::TaskParked { task, .. }
            | Self::TaskCommitted { task, .. }
            | Self::TaskFailed { task, .. }
            | Self::PoolExhausted { task, .. }
            | Self::QuestionRaised { task, .. } => Some(task),
            Self::RunStarted { .. }
            | Self::RunResumed { .. }
            | Self::RunSchemaUpgraded { .. }
            | Self::DeferWaitElapsed { .. }
            | Self::QuestionAnswered { .. }
            | Self::DesignDefect { .. }
            | Self::CapacitySnapshot { .. }
            | Self::BudgetExceeded { .. }
            | Self::RunFinished { .. } => None,
        }
    }

    /// The `event` tag as it appears in the log — for status rendering.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::RunStarted { .. } => "run_started",
            Self::RunResumed { .. } => "run_resumed",
            Self::RunSchemaUpgraded { .. } => "run_schema_upgraded",
            Self::AttemptStarted { .. } => "attempt_started",
            Self::AttemptFinished { .. } => "attempt_finished",
            Self::AttemptInterrupted { .. } => "attempt_interrupted",
            Self::LadderRetry { .. } => "ladder_retry",
            Self::LadderEscalated { .. } => "ladder_escalated",
            Self::TaskDeferred { .. } => "task_deferred",
            Self::DeferWaitElapsed { .. } => "defer_wait_elapsed",
            Self::TaskParked { .. } => "task_parked",
            Self::TaskCommitted { .. } => "task_committed",
            Self::TaskFailed { .. } => "task_failed",
            Self::QuestionRaised { .. } => "question_raised",
            Self::QuestionAnswered { .. } => "question_answered",
            Self::DesignDefect { .. } => "design_defect",
            Self::CapacitySnapshot { .. } => "capacity_snapshot",
            Self::PoolExhausted { .. } => "pool_exhausted",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::RunFinished { .. } => "run_finished",
        }
    }
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// Everything `resume` needs to decide whether continuing is still safe, plus
/// enough context that the log explains itself without the repo beside it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunStarted {
    pub schema: u32,
    pub tactus_version: String,
    pub run_id: String,
    pub branch: String,
    /// Full sha of the commit the run branched from — the expected HEAD until
    /// the first task commits.
    pub base_sha: String,
    /// Plan path as given, relative to the repo root where possible so the
    /// record survives the repo moving.
    pub plan_path: String,
    pub config_path: Option<String>,
    /// Content hash of the plan text (`ir::content_hash`). A run is bound to
    /// the plan it froze; a different hash means the task graph moved under it.
    pub plan_hash: String,
    /// Digest of the exact bytes written to `plan.normalized.json`.
    ///
    /// `plan_hash` above belongs to the source document and is also serialized
    /// inside the normalized plan. It cannot authenticate that file against
    /// itself. Fresh schema-3 runs record this independent byte digest; legacy
    /// runs establish it on their first schema-3 resume after comparing the
    /// old snapshot with a canonical serialization of the validated source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_plan_digest: Option<String>,
    /// Where the agent-authored half of this run lives (§15 split).
    pub private_dir: String,
    pub gates: Vec<String>,
    pub gates_from_config: bool,
    pub interaction_mode: String,
    /// The resolved chain per task, in plan order. Recorded so resume can tell
    /// that config moved: `Progress.rung` is an index into this chain, and
    /// re-resolving a different one would silently point it at another tier.
    pub chains: Vec<ChainSummary>,
    /// The concrete effort standard this run resolved at pre-flight.
    ///
    /// Like gates and reviewers, effort is part of the run's verification and
    /// execution identity: changing today's config must not make the back half
    /// of a resumed run think harder or less hard than the front half. `None`
    /// means a legacy log predating this record; its first resume re-derives,
    /// warns, and establishes the value in [`RunResumed::effort_policy`].
    #[serde(default)]
    pub effort_policy: Option<ResolvedEffortPolicy>,
    /// The effective gates in full, as the run resolved them at pre-flight —
    /// **the gates a resume runs**, not merely a fingerprint it compares.
    /// `gates` above names them for the reader; this is the executable record.
    ///
    /// A live run is snapshot-safe by construction: config is parsed once into
    /// the analysis and gates execute from memory, so a mid-run edit to
    /// `tactus.toml` cannot change what a running task is verified against.
    /// Resume honours the same snapshot by rebuilding these gates and running
    /// them, which is what makes every `task_committed` in one log mean the
    /// same thing. Re-deriving from today's config instead would let the
    /// workspace an implementer edits — which contains the very `tactus.toml`
    /// the gates come from — set the standard for the tasks that follow.
    ///
    /// This is the `reviews` contract below, applied to the other half of §14's
    /// verification: recorded because it is a fact about the run, not about
    /// today's machine. Budgets stay deliberately re-derived
    /// ([`ResumeOptions::budget_usd`](crate::engine::ResumeOptions)) because a
    /// ceiling on one's own spending is not identity.
    ///
    /// `None` means the log predates this record and says nothing about the
    /// gates — not that there were none. Absent means re-derive and warn,
    /// exactly as an absent `reviews` does. Pure addition otherwise:
    /// `#[serde(default)]` folds an old log to the state it always had, so
    /// `SCHEMA_VERSION` does not move.
    #[serde(default)]
    pub gate_cmds: Option<Vec<GateSummary>>,
    /// Who judges this run's code (§11.2–§11.3), resolved at pre-flight.
    ///
    /// Recorded because it is a fact about the run, not about today's machine.
    /// The cross-family reviewer is chosen from what has an adapter *and*
    /// probes, so a Copilot CLI installed or removed between a run and its
    /// resume would otherwise change the verification standard halfway through
    /// — the same reasoning that made resume honour the recorded `private_dir`.
    ///
    /// `None` means the log predates step 9 and says nothing about reviewers —
    /// which is emphatically **not** the same as saying there were none. A
    /// default-constructed plan has no primary, and every reader treats that as
    /// `review = { enabled = false }`; a resume that made that mistake would
    /// finish the run with verification silently switched off (step-6 finding
    /// #10, from the other direction). Absent means re-derive and say so.
    #[serde(default)]
    pub reviews: Option<crate::review::ReviewPlan>,
}

/// One task's resolved escalation chain, as it stood when the run started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSummary {
    pub task: String,
    pub tiers: Vec<Tier>,
    pub attempts_per: u32,
    /// The exact binding each rung resolved to at pre-flight, aligned with
    /// `tiers`. `None` means a schema-1 log predating this snapshot; its first
    /// schema-2 resume re-derives once, warns, and records the result on
    /// [`RunResumed::chains`]. `Some([])` is a real empty chain list.
    #[serde(default)]
    pub bindings: Option<Vec<BindingSummary>>,
}

/// One rung's execution identity. `pinned` remains explicit so the event log
/// preserves why the binding was fixed as well as which adapter/model ran it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingSummary {
    pub tier: Tier,
    pub agent: String,
    pub model: String,
    pub pinned: bool,
}

/// One effective gate as it stood when the run started — everything needed to
/// run it again, because a resume does exactly that.
///
/// All four fields, not just name and command. An earlier draft recorded the
/// pair alone on the theory that `timeout` and `shell` are operational settings
/// a resume may re-read; that is wrong about `shell`, which is half of what a
/// command *means* (see [`ShellKind`](crate::gates::ShellKind)) — the same
/// `cmd = "true"` passes always under `sh` and fails always under `cmd.exe`.
/// And it is wrong about `timeout` in the same direction, one step weaker: a
/// gate that was given twenty minutes and is given one verifies less.
///
/// The portability this costs is smaller than it looks. Resuming a run on a
/// machine whose shell it never had is already impossible for an unrelated
/// reason — `run_started.private_dir` records an absolute host path — so the
/// case the pair-only record was protecting does not exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    pub name: String,
    pub cmd: String,
    #[serde(rename = "timeout_ms", with = "crate::util::duration_millis")]
    pub timeout: Duration,
    pub shell: crate::gates::ShellKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResumed {
    /// HEAD at the moment the run was picked up — the sha the continued work
    /// builds on.
    pub head_sha: String,
    /// Attempts that were in flight when the previous process died.
    pub interrupted_attempts: u32,
    /// Uncommitted paths this resume threw away: a dead agent's half-written
    /// edits (§14). Recorded rather than only warned about, so someone reading
    /// the run tomorrow can still see that work was discarded and what it was.
    #[serde(default)]
    pub discarded: Vec<String>,
    /// The gates this resume **established**, for a run whose log had none.
    ///
    /// `run_started.gate_cmds` is the usual home for this, and where it exists
    /// this is `None` — a fact belongs in one place, and re-stating an unchanged
    /// list on every resume would give the log two authorities that could
    /// disagree. But a log written before that field existed has no home for it,
    /// and the first resume of one has to re-derive from today's config. Left
    /// unrecorded, *every* later resume re-derives too, so a gate weakened
    /// between two of them is adopted silently — the very substitution the
    /// record exists to prevent, surviving in the one population that cannot
    /// carry the record.
    ///
    /// So the resume that re-derives writes down what it settled on, and every
    /// resume after it is an ordinary record-bearing resume. `Some(vec![])` is
    /// meaningful and distinct from `None`: it says this run established that it
    /// has no gates, which is what makes a gate appearing later a difference
    /// worth warning about rather than a silent new standard.
    ///
    /// Folds to no state, like `capacity_snapshot`: its reader is the *next*
    /// resume, which takes it from the log directly ([`recorded_gates`]).
    #[serde(default)]
    pub gates: Option<Vec<GateSummary>>,
    /// The effort policy established by the first resume of a legacy log.
    ///
    /// Current runs record this on `run_started`, so ordinary resumes leave it
    /// `None`. Once an old log establishes a value here, later resumes use the
    /// first recorded value and never re-derive it again.
    #[serde(default)]
    pub effort_policy: Option<ResolvedEffortPolicy>,
    /// The review plan established by the first current-binary resume of a
    /// legacy log.
    ///
    /// Current runs record this on `run_started`. An older run has to derive
    /// the missing plan once, but leaving that derivation only in memory lets
    /// every later resume silently adopt a different reviewer or timeout.
    /// The first resume therefore appends the plan it established; later
    /// resumes read the first recorded value and leave this `None`.
    #[serde(default)]
    pub reviews: Option<crate::review::ReviewPlan>,
    /// The resolved chain bindings established by the first schema-2 resume of
    /// a schema-1 log. Current runs carry them on `run_started`; later resumes
    /// use the first recorded snapshot and leave this `None`.
    #[serde(default)]
    pub chains: Option<Vec<ChainSummary>>,
    /// Exact normalized-plan byte digest established by the first schema-3
    /// resume of a legacy run. Current runs carry it in `run_started`, and
    /// subsequent resumes leave this absent so the first authority wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_plan_digest: Option<String>,
}

/// A schema transition appended to an old run without rewriting its beginning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSchemaUpgraded {
    pub from: u32,
    pub to: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptStarted {
    pub tier: String,
    pub agent: String,
    pub model: String,
    /// Adapter id used for this attempt. `agent` remains for wire compatibility.
    #[serde(default)]
    pub adapter: Option<String>,
    /// CLI version observed during pre-flight; this is not a per-attempt probe.
    #[serde(default)]
    pub preflight_cli_version: Option<String>,
    /// Resolved effort passed to the adapter.
    #[serde(default)]
    pub effort: Option<Effort>,
    /// Why this binding was selected. `None` means an old log did not record
    /// this fact; `unknown` deliberately is not a value writers can emit.
    #[serde(default)]
    pub selection_origin: Option<SelectionOrigin>,
    /// The capacity pool this attempt draws on (§13), recorded before the
    /// spawn so an attempt the engine died inside can still be attributed: it
    /// really ran and really drained a subscription, and the settlement record
    /// has no other way to know which.
    #[serde(default)]
    pub pool: Option<String>,
    /// The session this attempt resumed, if any (§11.4).
    pub resume_session: Option<String>,
}

/// One attempt's ledger line: which rung it ran on, what it cost, and what
/// went wrong. Shared by the log and `report.json` so the ledger has exactly
/// one shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt: u32,
    pub tier: String,
    pub model: String,
    /// Which capacity pool this attempt drained (§13), where the pools file
    /// names one for its agent. Pure addition: `#[serde(default)]` means a log
    /// written before step 10 folds to exactly the same state it always did,
    /// which is why `SCHEMA_VERSION` did not move for it.
    #[serde(default)]
    pub pool: Option<String>,
    /// Whether this attempt resumed the previous one's session (§11.4).
    pub resumed: bool,
    #[serde(rename = "duration_ms", with = "crate::util::duration_millis")]
    pub duration: Duration,
    pub cost_usd: Option<f64>,
    /// The review passes that actually ran, in order (§11.3). Empty when the
    /// gates failed first and nothing was reviewed.
    ///
    /// A list rather than the single `review_model`/`review_cost_usd` pair it
    /// replaces: §11.5 generalizes review into a list of passes, and a
    /// second-opinion verdict has to be attributable to the model that gave it.
    /// Logs written before step 9 read back with this empty — their review
    /// spend does not replay, which is the price of the shape being right.
    #[serde(default)]
    pub reviews: Vec<ReviewRecord>,
    pub session_id: Option<String>,
    /// Token accounting as the CLI reported it, where it reports any.
    ///
    /// Kept beside `cost_usd` rather than folded into it, because dollars and
    /// tokens are different claims and only the vendor gets to make the first
    /// one. Claude Code computes its own api-equivalent cost and tactus records
    /// it; Codex reports usage and no price. Pricing those tokens here would
    /// mean shipping a rate table inside a published binary, where it goes
    /// stale silently and — on subscription auth, where the marginal dollar is
    /// zero and the real currency is the rate-limit window — produces a number
    /// that is notional twice over. §13's rule holds: an estimate that flatters
    /// is worse than none.
    ///
    /// So the ledger keeps saying `?` for a route that reports no dollars, and
    /// the evidence survives anyway. That matters more than it sounds: a run
    /// that did not record its usage can never be re-measured, and §23.2's
    /// conclusions about where spend goes were drawn entirely from
    /// cheap-implementer runs. Adapters have been parsing this into
    /// [`Outcome::usage`](crate::ir::Outcome) since step 3 and the engine threw
    /// it away.
    ///
    /// Pure addition, like `pool` above: `#[serde(default)]` means a log
    /// written before this folds to exactly the state it always did, so
    /// `SCHEMA_VERSION` does not move.
    #[serde(default)]
    pub usage: Option<crate::ir::Usage>,
    /// `None` when the attempt passed.
    pub failure: Option<FailureRecord>,
}

/// A hook-free commit object prepared from the exact staged tree that gates
/// and reviewers accepted. The event log records the owning full branch ref as
/// well as every object identity because a subject, parent, and mutable HEAD do
/// not distinguish an amended tree or the ref the run is authorized to move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedCommit {
    pub branch_ref: String,
    pub parent_sha: String,
    pub tree_sha: String,
    pub commit_sha: String,
    pub message: String,
    /// Private ref that keeps the prepared object reachable until HEAD has
    /// advanced. Its target is CAS-created and CAS-deleted.
    pub pin_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptParking {
    pub question: Question,
    pub refund_attempt: bool,
}

/// The non-parking state transition settled by one failed attempt.
///
/// Parking remains beside this on `attempt_finished` because escalation can
/// both move to the next rung and ask for spend approval atomically. Legacy
/// standalone ladder events remain readable, but new attempts record their
/// decision with the attempt they settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "data", rename_all = "snake_case")]
pub enum AttemptTransition {
    Retry(LadderRetry),
    Escalate(LadderEscalated),
    Defer(TaskDeferred),
    Fail(TaskFailed),
}

impl AttemptRecord {
    /// Total review spend for this attempt, or `None` when nothing reported any
    /// — which is not the same as nothing costing anything (§13: the Copilot
    /// route reports no spend at all).
    pub fn review_cost_usd(&self) -> Option<f64> {
        let reported: Vec<f64> = self.reviews.iter().filter_map(|r| r.cost_usd).collect();
        (!reported.is_empty()).then(|| reported.iter().sum())
    }

    /// Whether any pass that ran reported nothing, making the total above a
    /// floor rather than a figure.
    ///
    /// This is not pedantry: a cross-vendor review is the normal case for the
    /// paths §11.3 covers, and the Copilot route reports no spend at all — so
    /// "review: $0.05" on a two-pass attempt is one reviewer's bill presented
    /// as the whole. `render_ledger`'s own contract is that a ledger which
    /// cannot tell free from unreported is worse than no ledger.
    pub fn review_cost_incomplete(&self) -> bool {
        self.reviews.iter().any(|r| r.cost_usd.is_none())
    }

    /// The models that judged this attempt, in pass order.
    pub fn review_models(&self) -> Vec<String> {
        self.reviews.iter().map(|r| r.model.clone()).collect()
    }
}

/// One review pass's ledger line (§11.2–§11.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewRecord {
    /// The lens that ran — `review` or `second-opinion`.
    pub pass: String,
    pub agent: String,
    pub model: String,
    /// Adapter id used for this pass. `agent` remains for wire compatibility.
    #[serde(default)]
    pub adapter: Option<String>,
    /// CLI version observed during pre-flight; this is not a per-pass probe.
    #[serde(default)]
    pub preflight_cli_version: Option<String>,
    /// Resolved review effort passed to the adapter.
    #[serde(default)]
    pub effort: Option<Effort>,
    /// Which capacity pool this pass drained (§13). A cross-vendor second
    /// opinion draws on a *different* subscription than the implementer, so a
    /// per-pool ledger that read only the implementer's line would attribute
    /// the whole attempt to one pool that did not pay for all of it.
    #[serde(default)]
    pub pool: Option<String>,
    /// `None` where the agent's route reports no spend.
    pub cost_usd: Option<f64>,
    /// What this pass concluded. A later pass only exists because every earlier
    /// one approved, so at most the last entry is ever anything else.
    pub outcome: ReviewPassOutcome,
}

/// Where the worker binding came from. The latter two variants are reserved
/// for future selectors and deliberately have no producer yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionOrigin {
    Auto,
    Pin,
    UserOverride,
    Exploration,
}

/// How one review pass ended.
///
/// Three states, not two: step-6 finding #8 established that a reviewer which
/// could not run says nothing about the code, and the ladder already dispatches
/// on that distinction. Recording it as a plain "did not pass" would put a
/// rejection in the ledger against a model that never read the diff — and the
/// ledger is what a person reads when deciding whether to trust a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPassOutcome {
    Passed,
    Failed,
    /// Rate-limited, timed out, or otherwise never reached a verdict.
    Unavailable,
}

impl ReviewPassOutcome {
    pub fn passed(self) -> bool {
        self == Self::Passed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    pub kind: FailureKind,
    pub origin: FailureOrigin,
    pub reason: String,
}

/// What the next attempt is told. Carried on the ladder events rather than on
/// the attempt record because this is the full text — a gate log tail runs to
/// kilobytes, and `report.json` should not grow one per attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderRetry {
    /// §14: a resumed retry keeps the working tree, so the *cumulative* diff
    /// is what gets re-gated.
    pub resume: bool,
    pub tier: String,
    pub summary: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderEscalated {
    /// The rung index being moved to. Recorded rather than derived as "+1" so
    /// replay lands where the run actually went.
    pub to_rung: u32,
    pub tier: String,
    pub summary: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDeferred {
    pub reason: String,
    /// Deferrals this task has taken, after this one.
    pub defers: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferWaitElapsed {
    #[serde(rename = "waited_ms", with = "crate::util::duration_millis")]
    pub waited: Duration,
    pub round: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskParked {
    pub question: String,
    /// Whether the rung's allowance is given back. A worker or reviewer that
    /// stopped to ask never had its code judged (§12), so it costs nothing.
    pub refund_attempt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCommitted {
    /// Full sha. `resume` compares this against HEAD, and `--short` length
    /// varies with `core.abbrev`.
    pub sha: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFailed {
    pub kind: FailureKind,
    pub reason: String,
    /// Whether this failure halts the run (`[engine] on_task_failure`).
    /// Recorded rather than re-derived so a config edit between a run and its
    /// resume cannot rewrite which task the report blames.
    pub halts_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionRaised {
    pub question: Question,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionAnswered {
    pub question: QuestionId,
    pub answer: Answer,
    /// The halt policy frozen when a decline became durable. `None` is a
    /// legacy answer whose older writer did not record the policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_halts_run: Option<bool>,
    /// Which channel produced it — a terminal, an out-of-band `tactus answer`,
    /// or a resume picking up an answer written while the run was dead.
    pub via: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignDefect {
    pub question: QuestionId,
    /// The decision execution had to stop for — review material for the
    /// designer prompt (§5).
    pub context: String,
    pub answer: String,
}

/// §14's pre-flight capacity snapshot: what every pool looked like at the
/// moment the run made its choices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacitySnapshot {
    /// `[routing.strategy] mode`, echoed because what a snapshot *means*
    /// depends on which strategy was reading it.
    pub strategy: String,
    pub pools: Vec<PoolSnapshot>,
}

/// One pool's line in a snapshot, already rendered.
///
/// Strings rather than the [`crate::capacity`] enums: this is a record of what
/// a past run believed, and pinning it to today's variants would make a future
/// rename either break old logs or silently re-interpret them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolSnapshot {
    pub pool: String,
    pub agent: String,
    pub kind: String,
    pub remaining: String,
    pub confidence: String,
    pub reset_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolExhausted {
    pub pool: String,
    pub agent: String,
    /// When the signal said the window reopens, where it said so at all.
    pub reset_at: Option<String>,
    /// The CLI's own words, quoted — the evidence for calling the pool empty.
    pub detail: String,
}

/// Which ceiling stopped the run (§17 `[budgets]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    Run,
    Task,
}

impl fmt::Display for BudgetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Run => "run_usd",
            Self::Task => "task_usd",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetExceeded {
    pub budget: BudgetKind,
    pub limit_usd: f64,
    /// Reported spend to date. A floor where any attempt's route reports no
    /// spend at all (§13) — which is why the ceiling is checked against
    /// *reported* dollars and the report says so.
    pub spent_usd: f64,
    /// The task whose next attempt was refused. Not a failed task: nothing
    /// judged it, and nothing was spent on it.
    pub task: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Complete,
    Parked,
    Halted,
    /// §13's ceiling stopped the run. Distinct from `Halted` because `resume`
    /// means something different afterwards — raise the ceiling and continue —
    /// and CI needs to tell "your budget stopped it" from "a task failed".
    BudgetExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunFinished {
    pub outcome: RunOutcome,
    pub halted_at: Option<String>,
    pub committed: u32,
    pub parked: u32,
}

// ---------------------------------------------------------------------------
// Derived state
// ---------------------------------------------------------------------------

/// Scheduler state for one task. Readiness is derived (deps all `Done`), not
/// stored, so it can never drift from the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// Runnable once its dependencies are done — the state a task returns to
    /// after an answer un-parks it.
    Pending,
    /// A pool was busy. No attempt was spent; try again after a wait (§19).
    Deferred,
    /// Parked on a question (§12). Exactly this task, never its neighbours.
    AwaitingInput(QuestionId),
    Done(String),
    Failed {
        kind: FailureKind,
        reason: String,
    },
    /// Settlement only: derived when a run ends, never applied from an event,
    /// because an answered question has to make these runnable again.
    Blocked(String),
    /// Settlement only: the run stopped before this task got its turn.
    Skipped,
}

/// An attempt that started and never reported back — the shape a killed
/// process leaves in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    pub attempt: u32,
    pub rung: u32,
    pub tier: String,
    pub model: String,
    pub profile: String,
    pub pool: Option<String>,
}

/// A dangling attempt, with the task it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptedAttempt {
    pub task: String,
    pub flight: InFlight,
}

impl InterruptedAttempt {
    /// The event that stands in for the `attempt_finished` never written.
    pub fn event(&self) -> EventBody {
        EventBody::AttemptInterrupted {
            task: self.task.clone(),
            attempt: self.flight.attempt,
            rung: self.flight.rung,
            profile: self.flight.profile.clone(),
            data: Box::new(AttemptRecord {
                attempt: self.flight.attempt,
                tier: self.flight.tier.clone(),
                model: self.flight.model.clone(),
                // Its spend is unknown, but which subscription it drew on is
                // not: the pool was recorded before the spawn precisely so this
                // line does not have to shrug.
                pool: self.flight.pool.clone(),
                resumed: false,
                duration: Duration::ZERO,
                cost_usd: None,
                // Nothing judged the code, so nothing is attributed to a
                // reviewer.
                reviews: Vec::new(),
                session_id: None,
                // Same reason as `cost_usd` above: the process died before the
                // CLI reported anything, so the tokens it spent are as unknown
                // as the dollars.
                usage: None,
                failure: Some(FailureRecord {
                    kind: FailureKind::Interrupted,
                    origin: FailureOrigin::Worker,
                    reason: "the engine stopped while this attempt was running; whatever it \
                             spent is unknown and nothing judged the result"
                        .to_owned(),
                }),
            }),
        }
    }
}

/// One thing the next attempt should know. `human` matters: an operator's
/// answer is an instruction, while a gate log or a reviewer's demand is
/// tool-authored text quoted back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feedback {
    pub attempt: u32,
    pub tier: String,
    pub summary: String,
    pub detail: Option<String>,
    pub human: bool,
}

/// Everything one task accumulates across its attempts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Progress {
    /// Index into the resolved chain.
    pub rung: usize,
    /// Attempts spent on the current rung.
    pub attempts_on_rung: u32,
    /// Total attempts, which also numbers this task's run artifacts.
    pub attempts: u32,
    /// Session id from the most recent attempt, for §11.4's resume.
    pub session: Option<String>,
    /// Whether the next attempt should resume `session`.
    pub resume_next: bool,
    pub feedback: Vec<Feedback>,
    pub defers: u32,
    pub records: Vec<AttemptRecord>,
    /// Set while an attempt is running; a value that survives to the end of a
    /// replay is an attempt the engine died inside.
    pub in_flight: Option<InFlight>,
}

/// The run state every reader derives and the engine mutates — the only thing
/// [`apply`](RunState::apply) touches.
#[derive(Debug, Clone, PartialEq)]
pub struct RunState {
    /// Task ids in plan order; every other vector here is aligned to it.
    pub task_ids: Vec<String>,
    pub states: Vec<TaskState>,
    pub progress: Vec<Progress>,
    pub questions: Vec<QuestionRecord>,
    /// Task indices in the order they first ran, so a report reads as the run
    /// happened.
    pub order: Vec<usize>,
    pub halted_at: Option<String>,
    /// The ceiling that stopped the run (§13), if one did. Folded from the
    /// event rather than recomputed by each reader, so a `status` looking at a
    /// finished run and the engine that finished it reach the same verdict —
    /// the reader has no config and could not recompute it anyway.
    ///
    /// First stop wins, like `halted_at`: the scheduler stops scheduling once
    /// this is set, so a second one would describe a spawn that never happened.
    pub budget_stop: Option<BudgetExceeded>,
    pub finished: Option<RunFinished>,
}

impl RunState {
    /// A fresh state for a plan's tasks, before any event.
    pub fn new(task_ids: Vec<String>) -> Self {
        let count = task_ids.len();
        Self {
            task_ids,
            states: vec![TaskState::Pending; count],
            progress: (0..count).map(|_| Progress::default()).collect(),
            questions: Vec::new(),
            order: Vec::new(),
            halted_at: None,
            budget_stop: None,
            finished: None,
        }
    }

    pub fn index_of(&self, task: &str) -> Option<usize> {
        self.task_ids.iter().position(|id| id == task)
    }

    /// Fold one event in.
    ///
    /// The engine calls this immediately after appending the event, and replay
    /// calls it for every event in the file. Unknown tasks are skipped rather
    /// than panicking: a log paired with a plan that no longer contains the
    /// task is a resume refusal, caught before this is ever reached.
    pub fn apply(&mut self, event: &Event) {
        match &event.body {
            // Metadata for the reader; contributes no task state.
            //
            // `capacity_snapshot` and `pool_exhausted` sit here for opposite
            // reasons. The snapshot folds to nothing because nothing routes on
            // capacity in v0.1 (§13 read-only) — state it produced would be
            // state no branch consults. `pool_exhausted` folds to nothing
            // because its consumer is a *later* run's estimator, which reads it
            // out of the log directly ([`crate::capacity::observe`]); the task
            // consequence of the same rate limit rides on `task_deferred`,
            // which is where the scheduler already looks.
            EventBody::RunStarted { .. }
            | EventBody::RunSchemaUpgraded { .. }
            | EventBody::DesignDefect { .. }
            | EventBody::CapacitySnapshot { .. }
            | EventBody::PoolExhausted { .. } => {}

            // §13: the run's ceiling refused the next attempt. It stops the
            // drain but fails nothing — the task it names never ran, and the
            // tasks behind it settle as skipped exactly as they do after a halt.
            EventBody::BudgetExceeded { data } => {
                self.budget_stop.get_or_insert_with(|| data.clone());
            }

            // §14: a resumed run cannot trust a session that believed it left
            // edits in a tree that has since been rolled back, and deferred
            // work has by definition already waited.
            EventBody::RunResumed { .. } => {
                // `run_finished` describes the previous driver invocation, not
                // an immutable terminal once a later resume is durable. Status,
                // follow, and crash reporting must project the latest epoch.
                self.finished = None;
                for progress in &mut self.progress {
                    progress.session = None;
                    progress.resume_next = false;
                }
                for state in &mut self.states {
                    if *state == TaskState::Deferred {
                        *state = TaskState::Pending;
                    }
                }
                // A budget stop is cleared here for the same reason deferred
                // work wakes: it describes a *ceiling a previous process was
                // working under*, and the resume has just re-read the ceiling
                // from today's config and flags (§13/D4). Leaving it folded in
                // would make `tactus resume --budget` a command that changes
                // nothing — the run would replay straight back into the stop it
                // was resumed to get past. If the new ceiling is still too low,
                // the very next `step_task` records a fresh stop and says so.
                self.budget_stop = None;
            }

            EventBody::AttemptStarted {
                task,
                attempt,
                rung,
                profile,
                data,
            } => {
                let Some(index) = self.index_of(task) else {
                    return;
                };
                if !self.order.contains(&index) {
                    self.order.push(index);
                }
                let progress = &mut self.progress[index];
                progress.rung = *rung as usize;
                progress.attempts = *attempt;
                progress.attempts_on_rung = progress.attempts_on_rung.saturating_add(1);
                progress.in_flight = Some(InFlight {
                    attempt: *attempt,
                    rung: *rung,
                    tier: data.tier.clone(),
                    model: data.model.clone(),
                    profile: profile.clone(),
                    pool: data.pool.clone(),
                });
                // A fresh attempt has no conversation paired with its fresh
                // tree. Replace, rather than preserve, the previous identity;
                // otherwise a sessionless failure can resurrect a discarded
                // session on the following retry.
                progress.session = data.resume_session.clone();
            }

            // The attempt nobody was alive to finish. Recorded — it really ran
            // and really drained a pool, and a ledger that hides that is lying
            // — but it does not spend the rung's allowance, because nothing
            // judged the code. That is the rule §19 applies to an outage and
            // step 7 applies to a worker that stopped to ask.
            //
            // `attempts` is deliberately not rolled back: it numbers this
            // task's artifacts, and reusing the interrupted attempt's number
            // would overwrite its transcript with the retry's.
            EventBody::AttemptInterrupted { task, data, .. } => {
                let Some(index) = self.index_of(task) else {
                    return;
                };
                let progress = &mut self.progress[index];
                progress.in_flight = None;
                progress.attempts_on_rung = progress.attempts_on_rung.saturating_sub(1);
                // §14: whatever session that attempt held described a working
                // tree that has since been rolled back.
                progress.session = None;
                progress.resume_next = false;
                progress.records.push((**data).clone());
            }

            EventBody::AttemptFinished {
                task,
                attempt,
                data,
                parking,
                transition,
                ..
            } => {
                let Some(index) = self.index_of(task) else {
                    return;
                };
                {
                    let progress = &mut self.progress[index];
                    progress.in_flight = None;
                    if let Some(session) = &data.session_id {
                        progress.session = Some(session.clone());
                    }
                    progress.records.push((**data).clone());
                }
                if let Some(transition) = transition {
                    self.apply_attempt_transition(task, *attempt, transition);
                }
                if let Some(parking) = parking {
                    // Parking discards the attempt's working tree. Its model
                    // session therefore describes edits that no longer exist
                    // and must not survive as a candidate for a later retry.
                    self.progress[index].session = None;
                    self.progress[index].resume_next = false;
                    if parking.refund_attempt {
                        self.progress[index].attempts_on_rung =
                            self.progress[index].attempts_on_rung.saturating_sub(1);
                    }
                    self.questions
                        .push(QuestionRecord::open(parking.question.clone()));
                    self.states[index] = TaskState::AwaitingInput(parking.question.id.clone());
                }
            }

            EventBody::LadderRetry {
                task,
                attempt,
                data,
                ..
            } => self.apply_ladder_retry(task, *attempt, data),

            EventBody::LadderEscalated {
                task,
                attempt,
                data,
                ..
            } => self.apply_ladder_escalated(task, *attempt, data),

            EventBody::TaskDeferred { task, data } => self.apply_task_deferred(task, data),

            EventBody::DeferWaitElapsed { .. } => {
                for state in &mut self.states {
                    if *state == TaskState::Deferred {
                        *state = TaskState::Pending;
                    }
                }
            }

            EventBody::TaskParked { task, data } => {
                let Some(index) = self.index_of(task) else {
                    return;
                };
                self.progress[index].session = None;
                self.progress[index].resume_next = false;
                if data.refund_attempt {
                    let progress = &mut self.progress[index];
                    progress.attempts_on_rung = progress.attempts_on_rung.saturating_sub(1);
                }
                self.states[index] = TaskState::AwaitingInput(QuestionId(data.question.clone()));
            }

            EventBody::TaskCommitted { task, data } => {
                let Some(index) = self.index_of(task) else {
                    return;
                };
                self.states[index] = TaskState::Done(data.sha.clone());
            }

            EventBody::TaskFailed { task, data } => self.apply_task_failed(task, data),

            EventBody::QuestionRaised { data, .. } => {
                self.questions
                    .push(QuestionRecord::open(data.question.clone()));
            }

            EventBody::QuestionAnswered { data } => self.answer_question(data),

            EventBody::RunFinished { data } => self.finished = Some(data.clone()),
        }
    }

    fn apply_attempt_transition(
        &mut self,
        task: &str,
        attempt: u32,
        transition: &AttemptTransition,
    ) {
        match transition {
            AttemptTransition::Retry(data) => self.apply_ladder_retry(task, attempt, data),
            AttemptTransition::Escalate(data) => {
                self.apply_ladder_escalated(task, attempt, data);
            }
            AttemptTransition::Defer(data) => self.apply_task_deferred(task, data),
            AttemptTransition::Fail(data) => self.apply_task_failed(task, data),
        }
    }

    fn apply_ladder_retry(&mut self, task: &str, attempt: u32, data: &LadderRetry) {
        let Some(index) = self.index_of(task) else {
            return;
        };
        let progress = &mut self.progress[index];
        progress.feedback.push(Feedback {
            attempt,
            tier: data.tier.clone(),
            summary: data.summary.clone(),
            detail: data.detail.clone(),
            human: false,
        });
        progress.resume_next = data.resume;
    }

    fn apply_ladder_escalated(&mut self, task: &str, attempt: u32, data: &LadderEscalated) {
        let Some(index) = self.index_of(task) else {
            return;
        };
        let progress = &mut self.progress[index];
        progress.feedback.push(Feedback {
            attempt,
            tier: data.tier.clone(),
            summary: data.summary.clone(),
            detail: data.detail.clone(),
            human: false,
        });
        progress.rung = data.to_rung as usize;
        progress.attempts_on_rung = 0;
        // §11.4: a different model cannot inherit another's conversation; the
        // accumulated feedback carries the history.
        progress.session = None;
        progress.resume_next = false;
    }

    fn apply_task_deferred(&mut self, task: &str, data: &TaskDeferred) {
        let Some(index) = self.index_of(task) else {
            return;
        };
        let progress = &mut self.progress[index];
        // No attempt was spent on the work itself (§19), and the discarded tree
        // makes every session that described it invalid.
        progress.attempts_on_rung = progress.attempts_on_rung.saturating_sub(1);
        progress.defers = data.defers;
        progress.session = None;
        progress.resume_next = false;
        self.states[index] = TaskState::Deferred;
    }

    fn apply_task_failed(&mut self, task: &str, data: &TaskFailed) {
        let Some(index) = self.index_of(task) else {
            return;
        };
        self.states[index] = TaskState::Failed {
            kind: data.kind,
            reason: data.reason.clone(),
        };
        if data.halts_run {
            // First failure wins: `halted_at` is what the report and CLI name
            // as the cause.
            self.halted_at.get_or_insert_with(|| task.to_owned());
        }
    }

    /// Record an answer and un-park what it releases.
    ///
    /// A decline changes no task state here — the caller emits `task_failed`
    /// for that, so the halt policy lives in exactly one place.
    fn answer_question(&mut self, data: &QuestionAnswered) {
        let Some(position) = self
            .questions
            .iter()
            .position(|record| record.question.id == data.question)
        else {
            return;
        };
        // An answer that arrives twice — a late file alongside a terminal
        // reply — must not push the operator's words into the prompt twice.
        if !self.questions[position].is_open() {
            return;
        }
        self.questions[position].answer = Some(data.answer.clone());
        let Answer::Answered { text } = &data.answer else {
            return;
        };
        let kind = self.questions[position].question.kind;
        let affected = self.questions[position].question.affected_tasks.clone();
        for task_id in affected {
            let Some(index) = self.index_of(task_id.as_str()) else {
                continue;
            };
            if self.states[index] != TaskState::AwaitingInput(data.question.clone()) {
                continue;
            }
            let progress = &mut self.progress[index];
            // An `ApproveSpend` answer is a yes/no about money, and its whole
            // meaning was consumed by the un-park above. Pushing it as feedback
            // would put "approve: run the escalated attempt" into the next
            // prompt under `feedback_section`'s human framing — "an instruction
            // from a person, and it takes precedence over your earlier
            // assumptions" — handing a coding agent a billing decision as task
            // guidance.
            //
            // The same objection applies to any canned option, whatever the
            // kind, and for a reason the first version of this missed: the
            // options are the engine's instructions *to the operator*, not the
            // operator's instructions to anyone. `tactus answer <id> --option
            // 1` on an unblock question resolves to "retry this task with
            // guidance you type below" — a sentence about where to type, which
            // then reached the implementer as binding guidance and, since §12's
            // decisions were routed to the judge, reached the reviewer as "a
            // decision from a person… a change that departs from it is a defect
            // however well argued". A judge grading a diff against meta-UI text
            // can only reject it, every attempt, until the ladder runs out.
            //
            // An operator's own words are guidance. A label they picked off a
            // list is the un-park, and nothing more.
            let canned = self.questions[position]
                .question
                .options
                .iter()
                .any(|option| option == text);
            if kind != crate::ir::QuestionKind::ApproveSpend && !canned {
                progress.feedback.push(Feedback {
                    attempt: progress.attempts,
                    tier: String::new(),
                    summary: "the operator answered the open question".to_owned(),
                    detail: Some(text.clone()),
                    human: true,
                });
            }
            // The answer buys a fresh allowance on the rung the task is
            // standing on, and clears the deferrals a pool outage racked up.
            // It never moves the rung: if the chain exhausted, the task is
            // already at the top of it.
            if kind == crate::ir::QuestionKind::Unblock {
                progress.attempts_on_rung = 0;
            }
            progress.defers = 0;
            // Never resume out of a park, however warm the session looks:
            // parking always discards the working tree, so the session's
            // account of what it wrote no longer matches the repository (§14).
            progress.resume_next = false;
            self.states[index] = TaskState::Pending;
        }
    }

    /// Attempts this log ends mid-flight — one per process that died inside
    /// an attempt without a resume having settled it since.
    pub fn interrupted_attempts(&self) -> Vec<InterruptedAttempt> {
        self.task_ids
            .iter()
            .zip(&self.progress)
            .filter_map(|(task, progress)| {
                progress.in_flight.clone().map(|flight| InterruptedAttempt {
                    task: task.clone(),
                    flight,
                })
            })
            .collect()
    }

    /// Settle dangling attempts *in memory*, for readers.
    ///
    /// `status` uses this so an interrupted run reads correctly without
    /// writing anything. A `resume` deliberately does not: it emits the same
    /// events instead, so the settlement lands in the log where the next
    /// reader will find it. Both go through [`RunState::apply`], so what a
    /// reader sees and what a resume records cannot disagree.
    pub fn settle_interrupted(&mut self) -> u32 {
        let dangling = self.interrupted_attempts();
        for interrupted in &dangling {
            self.apply(&Event::now(interrupted.event()));
        }
        u32::try_from(dangling.len()).unwrap_or(u32::MAX)
    }

    /// Open questions, oldest first.
    pub fn open_questions(&self) -> Vec<&QuestionRecord> {
        self.questions
            .iter()
            .filter(|record| record.is_open())
            .collect()
    }
}

/// The result of folding a log: the state, plus the run metadata a reader
/// needs but that is not task state.
///
/// The state is **not** settled — attempts left mid-flight are still marked as
/// such. Settling is the caller's decision, because a reader does it in memory
/// and a resume records it (see [`RunState::settle_interrupted`]).
#[derive(Debug)]
pub struct Replay {
    pub state: RunState,
    pub started: RunStarted,
    /// How many times this run has been picked up again.
    pub resumes: u32,
    pub events: Vec<Event>,
}

/// Stable digest for the exact bytes of `plan.normalized.json`.
///
/// This deliberately differs from [`crate::ir::content_hash`]: the source-plan
/// identity normalizes CRLF, while this value authenticates the snapshot bytes
/// themselves. The algorithm is named in the value so a future schema can add
/// a different digest without silently changing what an existing record means.
pub(crate) fn normalized_plan_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// The first exact normalized-plan digest this run established.
///
/// A fresh schema-3 run carries it in `run_started`; a legacy run gains it on
/// the first schema-3 `run_resumed`. First-in-log-order wins, matching the gate,
/// review, effort, and chain identity records above.
pub(crate) fn recorded_normalized_plan_digest(events: &[Event]) -> Option<&str> {
    let mut schema = 0;
    for event in events {
        match &event.body {
            EventBody::RunStarted { data } => {
                schema = data.schema;
                if schema >= 3 {
                    if let Some(digest) = data.normalized_plan_digest.as_deref() {
                        return Some(digest);
                    }
                }
            }
            EventBody::RunSchemaUpgraded { data } => schema = data.to,
            EventBody::RunResumed { data } if schema >= 3 => {
                if let Some(digest) = data.normalized_plan_digest.as_deref() {
                    return Some(digest);
                }
            }
            _ => {}
        }
    }
    None
}

/// The gates this run is bound to, from wherever the log records them.
///
/// `run_started` for anything written since the gate record existed; otherwise
/// the first `run_resumed` that had to establish them (see
/// [`RunResumed::gates`]). First-in-log-order wins, which is the same rule
/// stated two ways: `run_started` comes first, and among resumes the one that
/// established the standard is the one the committed work was verified under.
///
/// `None` only for a log that predates the record and has never been resumed —
/// the single case where nothing can be said about what verified this run.
pub fn recorded_gates(events: &[Event]) -> Option<&Vec<GateSummary>> {
    events.iter().find_map(|event| match &event.body {
        EventBody::RunStarted { data } => data.gate_cmds.as_ref(),
        EventBody::RunResumed { data } => data.gates.as_ref(),
        _ => None,
    })
}

/// The effort standard this run is bound to, wherever the log first records it.
///
/// A current `run_started` wins. For a legacy start, the first resume that had
/// to establish the missing value wins; a later conflicting entry cannot
/// rewrite the run's execution standard.
pub fn recorded_effort_policy(events: &[Event]) -> Option<ResolvedEffortPolicy> {
    events.iter().find_map(|event| match &event.body {
        EventBody::RunStarted { data } => data.effort_policy,
        EventBody::RunResumed { data } => data.effort_policy,
        _ => None,
    })
}

/// The review plan this run is bound to, wherever the log first records it.
///
/// A current run carries the plan in `run_started`. A legacy run gains it on
/// the first current-binary `run_resumed`, so subsequent resumes cannot
/// re-derive a different reviewer, model, effort, or pass timeout.
pub fn recorded_reviews(events: &[Event]) -> Option<&crate::review::ReviewPlan> {
    recorded_complete_reviews(events).or_else(|| {
        events.iter().find_map(|event| match &event.body {
            EventBody::RunStarted { data } => data.reviews.as_ref(),
            EventBody::RunResumed { data } => data.reviews.as_ref(),
            _ => None,
        })
    })
}

/// The first review plan recorded while the complete-review contract was in
/// force.
///
/// Schema 1 and 2 plans preserve an absent `pass_timeout_secs` as `None`. That
/// makes their reviewer binding usable as a legacy identity snapshot, but not
/// authoritative for the timeout: a later binary could have a different
/// default. A current start is complete in place. A legacy start becomes
/// complete only when a schema-3 resume explicitly serializes the upgraded
/// plan after the downgrade barrier.
pub fn recorded_complete_reviews(events: &[Event]) -> Option<&crate::review::ReviewPlan> {
    let started = events.iter().find_map(|event| match &event.body {
        EventBody::RunStarted { data } => Some(&**data),
        _ => None,
    })?;
    if started.schema >= 3 {
        return started
            .reviews
            .as_ref()
            .filter(|plan| plan.pass_timeout_secs.is_some());
    }

    let mut schema = started.schema;
    events.iter().find_map(|event| match &event.body {
        EventBody::RunSchemaUpgraded { data } if data.from == schema && data.to > schema => {
            schema = data.to;
            None
        }
        EventBody::RunResumed { data } if schema >= 3 => data
            .reviews
            .as_ref()
            .filter(|plan| plan.pass_timeout_secs.is_some()),
        _ => None,
    })
}

/// The resolved worker bindings this run is bound to, wherever they first
/// become available. Schema-2 runs carry them in `run_started`; a schema-1 run
/// gains them on the first schema-2 `run_resumed` event.
pub fn recorded_chains(events: &[Event]) -> Option<&Vec<ChainSummary>> {
    events.iter().find_map(|event| match &event.body {
        EventBody::RunStarted { data }
            if data.chains.iter().all(|chain| chain.bindings.is_some()) =>
        {
            Some(&data.chains)
        }
        EventBody::RunResumed { data } => data.chains.as_ref(),
        _ => None,
    })
}

/// The `run_started` a log opens with — how a run describes itself.
pub fn started_of<'a>(events: &'a [Event], path: &Path) -> Result<&'a RunStarted, TactusError> {
    events
        .iter()
        .find_map(|event| match &event.body {
            EventBody::RunStarted { data } => Some(&**data),
            _ => None,
        })
        .ok_or_else(|| TactusError::EventLog {
            path: path.to_path_buf(),
            message: "no run_started event — this log never recorded how the run began, so \
                      there is nothing to verify a resume against"
                .to_owned(),
        })
}

/// Replay a log into state.
///
/// The plan's task ids are supplied rather than read from the log: they define
/// the index space every `Progress` lives in, and the caller has already
/// checked the plan is the one this run froze.
pub fn replay(
    events: Vec<Event>,
    task_ids: Vec<String>,
    path: &Path,
) -> Result<Replay, TactusError> {
    let started = started_of(&events, path)?.clone();
    ensure_supported_schema(&started, &events, path)?;

    let mut state = RunState::new(task_ids);
    let mut resumes = 0;
    for event in &events {
        if matches!(event.body, EventBody::RunResumed { .. }) {
            resumes += 1;
        }
        state.apply(event);
    }
    Ok(Replay {
        state,
        started,
        resumes,
        events,
    })
}

/// Apply the event-schema compatibility boundary shared by every whole-log
/// interpretation. Additive fields are safe inside the current schema; a
/// future schema is not something an older binary may silently project.
pub(crate) fn ensure_supported_schema(
    started: &RunStarted,
    events: &[Event],
    path: &Path,
) -> Result<u32, TactusError> {
    let mut effective = started.schema;
    for event in events {
        let EventBody::RunSchemaUpgraded { data } = &event.body else {
            continue;
        };
        if data.from != effective || data.to <= data.from {
            return Err(TactusError::EventLog {
                path: path.to_path_buf(),
                message: format!(
                    "invalid schema transition {} -> {} while the log was at schema {}",
                    data.from, data.to, effective
                ),
            });
        }
        effective = data.to;
    }
    if effective > SCHEMA_VERSION {
        return Err(TactusError::EventLog {
            path: path.to_path_buf(),
            message: format!(
                "written by a newer tactus (event schema {}, this binary understands {}). \
                 Upgrade rather than interpret it — reading a log we only half understand would \
                 derive the wrong state silently.",
                effective, SCHEMA_VERSION
            ),
        });
    }
    let mut event_schema = started.schema;
    let mut pending_prepared: Option<(String, PreparedCommit)> = None;
    for event in events {
        if let EventBody::RunSchemaUpgraded { data } = &event.body {
            event_schema = data.to;
            continue;
        }
        if event_schema < 3 {
            continue;
        }
        if let Some((task, prepared)) = pending_prepared.as_ref() {
            match &event.body {
                EventBody::TaskCommitted {
                    task: committed_task,
                    data,
                } if committed_task == task
                    && data.sha == prepared.commit_sha
                    && data.message == prepared.message =>
                {
                    pending_prepared = None;
                    continue;
                }
                _ => {
                    return Err(TactusError::EventLog {
                        path: path.to_path_buf(),
                        message: format!(
                            "event schema 3 requires the successful settlement for `{task}` to \
                             be followed by task_committed for its exact prepared commit"
                        ),
                    });
                }
            }
        }
        match &event.body {
            EventBody::AttemptFinished {
                task,
                attempt,
                data,
                parking,
                transition,
                prepared_commit,
                ..
            } => {
                let failed = data.failure.is_some();
                if data.attempt != *attempt {
                    return Err(TactusError::EventLog {
                        path: path.to_path_buf(),
                        message: "event schema 3 attempt_finished envelope and record disagree on the attempt number".to_owned(),
                    });
                }
                let decided = parking.is_some() || transition.is_some();
                if failed != decided {
                    return Err(TactusError::EventLog {
                        path: path.to_path_buf(),
                        message: "event schema 3 requires every failed attempt_finished to carry its ladder/parking decision, and forbids one on a successful attempt".to_owned(),
                    });
                }
                match (failed, prepared_commit.as_deref()) {
                    (true, Some(_)) => {
                        return Err(TactusError::EventLog {
                            path: path.to_path_buf(),
                            message: "event schema 3 forbids a failed attempt_finished from carrying a prepared commit".to_owned(),
                        });
                    }
                    (false, None) => {
                        return Err(TactusError::EventLog {
                            path: path.to_path_buf(),
                            message: "event schema 3 requires every successful attempt_finished to bind the exact prepared commit".to_owned(),
                        });
                    }
                    (false, Some(prepared)) if !valid_prepared_commit_shape(prepared) => {
                        return Err(TactusError::EventLog {
                            path: path.to_path_buf(),
                            message: "event schema 3 successful attempt_finished carries an invalid prepared commit identity".to_owned(),
                        });
                    }
                    (false, Some(prepared)) => {
                        let Some(task_index) =
                            started.chains.iter().position(|chain| chain.task == *task)
                        else {
                            return Err(TactusError::EventLog {
                                path: path.to_path_buf(),
                                message: format!(
                                    "event schema 3 successful settlement names unknown task `{task}`"
                                ),
                            });
                        };
                        let expected_pin = format!(
                            "refs/tactus/prepared/{}/{task_index}-{}",
                            started.run_id, attempt
                        );
                        let expected_branch = format!("refs/heads/{}", started.branch);
                        let expected_prefix = format!("[tactus] {task}: ");
                        if prepared.branch_ref != expected_branch
                            || prepared.pin_ref != expected_pin
                            || !prepared.message.starts_with(&expected_prefix)
                        {
                            return Err(TactusError::EventLog {
                                path: path.to_path_buf(),
                                message: format!(
                                    "event schema 3 successful settlement for `{task}` carries a \
                                     branch, prepared ref, or message that is not deterministic for this run"
                                ),
                            });
                        }
                        pending_prepared = Some((task.clone(), prepared.clone()));
                    }
                    _ => {}
                }
                if failed
                    && !valid_attempt_decision(
                        task,
                        data.failure.as_ref().expect("checked failed"),
                        transition.as_deref(),
                        parking.as_deref(),
                    )
                {
                    return Err(TactusError::EventLog {
                        path: path.to_path_buf(),
                        message: "event schema 3 attempt_finished carries a ladder/parking decision inconsistent with its failure".to_owned(),
                    });
                }
            }
            EventBody::QuestionAnswered { data }
                if data.answer == Answer::Declined && data.decline_halts_run.is_none() =>
            {
                return Err(TactusError::EventLog {
                    path: path.to_path_buf(),
                    message: "event schema 3 requires a declined question_answered to record its contemporaneous halt policy".to_owned(),
                });
            }
            EventBody::TaskCommitted { task, .. } => {
                return Err(TactusError::EventLog {
                    path: path.to_path_buf(),
                    message: format!(
                        "event schema 3 task_committed for `{task}` has no immediately preceding \
                         successful settlement with an exact prepared commit"
                    ),
                });
            }
            _ => {}
        }
    }
    if started.schema >= 3 {
        if !started
            .normalized_plan_digest
            .as_deref()
            .is_some_and(valid_normalized_plan_digest)
        {
            return Err(TactusError::EventLog {
                path: path.to_path_buf(),
                message: "event schema 3 requires run_started.normalized_plan_digest to bind the exact frozen plan bytes".to_owned(),
            });
        }
        let plan = started.reviews.as_ref().ok_or_else(|| TactusError::EventLog {
            path: path.to_path_buf(),
            message: "event schema 3 requires run_started.reviews; refusing to re-derive a missing verification identity".to_owned(),
        })?;
        match plan.pass_timeout_secs {
            Some(seconds) if seconds > 0 => {}
            Some(_) => {
                return Err(TactusError::EventLog {
                    path: path.to_path_buf(),
                    message: "event schema 3 requires run_started.reviews.pass_timeout_secs to be positive".to_owned(),
                });
            }
            None => {
                return Err(TactusError::EventLog {
                    path: path.to_path_buf(),
                    message: "event schema 3 requires run_started.reviews.pass_timeout_secs to be present; refusing to inherit a binary default".to_owned(),
                });
            }
        }
        validate_review_identity(plan, started.chains.len(), path)?;
    } else if effective >= 3 {
        let mut schema = started.schema;
        let mut complete = false;
        for event in events {
            match &event.body {
                EventBody::RunSchemaUpgraded { data } => schema = data.to,
                EventBody::RunResumed { data } if schema >= 3 => {
                    if !data
                        .normalized_plan_digest
                        .as_deref()
                        .is_some_and(valid_normalized_plan_digest)
                    {
                        return Err(TactusError::EventLog {
                            path: path.to_path_buf(),
                            message: "the first schema-3 run_resumed must record the exact normalized-plan byte digest".to_owned(),
                        });
                    }
                    let plan = data.reviews.as_ref().ok_or_else(|| TactusError::EventLog {
                        path: path.to_path_buf(),
                        message: "the first schema-3 run_resumed must record the complete review identity".to_owned(),
                    })?;
                    match plan.pass_timeout_secs {
                        Some(seconds) if seconds > 0 => {}
                        _ => {
                            return Err(TactusError::EventLog {
                                path: path.to_path_buf(),
                                message: "the first schema-3 run_resumed requires a positive recorded review timeout".to_owned(),
                            });
                        }
                    }
                    validate_review_identity(plan, started.chains.len(), path)?;
                    complete = true;
                }
                _ => {}
            }
            if complete {
                break;
            }
        }
    }
    Ok(effective)
}

fn valid_normalized_plan_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_prepared_commit_shape(prepared: &PreparedCommit) -> bool {
    let valid_oid = |oid: &str| {
        matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    prepared.branch_ref.starts_with("refs/heads/")
        && !prepared.branch_ref.contains("..")
        && valid_oid(&prepared.parent_sha)
        && valid_oid(&prepared.tree_sha)
        && valid_oid(&prepared.commit_sha)
        && prepared.parent_sha.len() == prepared.tree_sha.len()
        && prepared.parent_sha.len() == prepared.commit_sha.len()
        && prepared.parent_sha != prepared.commit_sha
        && !prepared.message.trim().is_empty()
        && !prepared.message.contains('\r')
        && !prepared.message.contains('\n')
        && prepared.pin_ref.starts_with("refs/tactus/prepared/")
        && !prepared.pin_ref.contains("..")
        && prepared
            .pin_ref
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
}

/// A failed attempt written before schema 3 was settled in two appends: first
/// `attempt_finished`, then its ladder/parking decision. A process can die
/// between them. Upgrading that prefix would make the known failed task
/// runnable again, spending another attempt under a decision the log never
/// durably recorded. New writers avoid the gap by embedding the decision; old
/// prefixes must be refused when their second append is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyUnsettledFailure {
    pub task: String,
    pub attempt: u32,
    pub rung: u32,
    pub kind: LegacyUnsettledFailureKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyUnsettledFailureKind {
    MissingDecision,
    MissingSpendParking,
}

pub(crate) fn legacy_unsettled_failure(
    started_schema: u32,
    events: &[Event],
) -> Option<LegacyUnsettledFailure> {
    let mut schema = started_schema;
    let mut pending = Vec::<LegacyUnsettledFailure>::new();
    let mut latest_escalations = Vec::<LegacyUnsettledFailure>::new();
    let mut pending_spend_parks = Vec::<LegacyUnsettledFailure>::new();

    for event in events {
        match &event.body {
            EventBody::RunSchemaUpgraded { data } => schema = data.to,
            EventBody::AttemptFinished {
                task,
                attempt,
                rung,
                data,
                parking,
                transition,
                ..
            } if schema < 3
                && data.failure.is_some()
                && parking.is_none()
                && transition.is_none() =>
            {
                pending.push(LegacyUnsettledFailure {
                    task: task.clone(),
                    attempt: *attempt,
                    rung: *rung,
                    kind: LegacyUnsettledFailureKind::MissingDecision,
                });
            }
            EventBody::LadderRetry {
                task,
                attempt,
                rung,
                ..
            } => pending.retain(|failure| {
                failure.task != *task || failure.attempt != *attempt || failure.rung != *rung
            }),
            EventBody::LadderEscalated {
                task,
                attempt,
                rung,
                ..
            } => {
                pending.retain(|failure| {
                    failure.task != *task || failure.attempt != *attempt || failure.rung != *rung
                });
                latest_escalations.retain(|failure| failure.task != *task);
                latest_escalations.push(LegacyUnsettledFailure {
                    task: task.clone(),
                    attempt: *attempt,
                    rung: *rung,
                    kind: LegacyUnsettledFailureKind::MissingSpendParking,
                });
            }
            EventBody::QuestionRaised { task, data }
                if data.question.kind == crate::ir::QuestionKind::ApproveSpend =>
            {
                if let Some(escalation) = latest_escalations
                    .iter()
                    .rev()
                    .find(|failure| failure.task == *task)
                    .cloned()
                {
                    pending_spend_parks.retain(|failure| failure.task != *task);
                    pending_spend_parks.push(escalation);
                }
            }
            EventBody::TaskDeferred { task, .. } | EventBody::TaskFailed { task, .. } => {
                pending.retain(|failure| failure.task != *task);
                latest_escalations.retain(|failure| failure.task != *task);
            }
            EventBody::TaskParked { task, .. } => {
                pending.retain(|failure| failure.task != *task);
                latest_escalations.retain(|failure| failure.task != *task);
                pending_spend_parks.retain(|failure| failure.task != *task);
            }
            EventBody::AttemptStarted { task, .. } => {
                // A next attempt proves an escalation with no approval question
                // was complete. It does not excuse a question raised without
                // the TaskParked append that made the approval binding.
                latest_escalations.retain(|failure| failure.task != *task);
            }
            _ => {}
        }
    }

    pending_spend_parks
        .into_iter()
        .next()
        .or_else(|| pending.into_iter().next())
}

pub(crate) fn validate_review_identity(
    plan: &crate::review::ReviewPlan,
    task_count: usize,
    path: &Path,
) -> Result<(), TactusError> {
    let enabled = plan.enabled.ok_or_else(|| TactusError::EventLog {
        path: path.to_path_buf(),
        message: "event schema 3 requires reviews.enabled; refusing to infer whether verification was intentionally disabled".to_owned(),
    })?;
    if enabled != plan.primary.is_some() {
        return Err(TactusError::EventLog {
            path: path.to_path_buf(),
            message: "event schema 3 reviews.enabled does not match the recorded primary reviewer"
                .to_owned(),
        });
    }
    let alternative_available =
        plan.alternative_available
            .ok_or_else(|| TactusError::EventLog {
                path: path.to_path_buf(),
                message: "event schema 3 requires reviews.alternative_available; refusing to infer a missing reviewer binding".to_owned(),
            })?;
    if alternative_available != plan.alternative.is_some() {
        return Err(TactusError::EventLog {
            path: path.to_path_buf(),
            message: "event schema 3 reviews.alternative_available does not match the recorded alternative reviewer".to_owned(),
        });
    }
    if enabled && plan.second_opinion.len() != task_count {
        return Err(TactusError::EventLog {
            path: path.to_path_buf(),
            message: format!(
                "event schema 3 records {task_count} task chains but {} second-opinion slots; refusing a misaligned review identity",
                plan.second_opinion.len()
            ),
        });
    }
    if !enabled && (plan.alternative.is_some() || plan.second_opinion.iter().any(Option::is_some)) {
        return Err(TactusError::EventLog {
            path: path.to_path_buf(),
            message: "event schema 3 disables review but still records review-pass bindings"
                .to_owned(),
        });
    }
    Ok(())
}

fn valid_attempt_decision(
    task: &str,
    failure: &FailureRecord,
    transition: Option<&AttemptTransition>,
    parking: Option<&AttemptParking>,
) -> bool {
    let associated = |parking: &AttemptParking| {
        parking.question.affected_tasks.len() == 1
            && parking.question.affected_tasks[0].as_str() == task
    };
    let outage = matches!(
        (failure.kind, failure.origin),
        (FailureKind::RateLimited | FailureKind::ReviewUnavailable, _)
            | (FailureKind::Timeout, FailureOrigin::Reviewer)
    );

    // These categories have policy-independent semantics. Accepting a generic
    // retry/escalation here would turn a request for a person, an outage, or an
    // unreviewable diff into spend the ladder explicitly forbids.
    if failure.kind == FailureKind::NeedsHuman {
        return transition.is_none()
            && parking.is_some_and(|parking| {
                associated(parking)
                    && parking.question.kind == crate::ir::QuestionKind::Clarify
                    && parking.refund_attempt
            });
    }
    if matches!(
        failure.kind,
        FailureKind::ReviewInputTooLarge | FailureKind::ReviewInputOpaque
    ) {
        return failure.origin == FailureOrigin::Reviewer
            && transition.is_none()
            && parking.is_some_and(|parking| {
                associated(parking)
                    && parking.question.kind == crate::ir::QuestionKind::Unblock
                    && !parking.refund_attempt
            });
    }
    if outage {
        return matches!(
            (transition, parking),
            (Some(AttemptTransition::Defer(_)), None)
        ) || matches!((transition, parking), (None, Some(parking))
                if associated(parking)
                    && parking.question.kind == crate::ir::QuestionKind::Unblock
                    && parking.refund_attempt);
    }
    if matches!(
        failure.kind,
        FailureKind::Declined | FailureKind::Interrupted
    ) {
        return false;
    }

    match (transition, parking) {
        (Some(AttemptTransition::Retry(_)), None)
        | (Some(AttemptTransition::Escalate(_)), None) => true,
        (Some(AttemptTransition::Escalate(_)), Some(parking)) => {
            associated(parking)
                && parking.question.kind == crate::ir::QuestionKind::ApproveSpend
                && !parking.refund_attempt
        }
        (Some(AttemptTransition::Fail(data)), None) => data.kind == failure.kind,
        (None, Some(parking)) => {
            associated(parking)
                && parking.question.kind == crate::ir::QuestionKind::Unblock
                && !parking.refund_attempt
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{QuestionKind, TaskId};
    use crate::topology::effects::EventSite;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;

    fn effort_policy() -> ResolvedEffortPolicy {
        ResolvedEffortPolicy {
            small: Effort::Low,
            mid: Effort::Medium,
            frontier: Effort::XHigh,
            review: Effort::Max,
        }
    }

    fn started() -> EventBody {
        EventBody::RunStarted {
            data: Box::new(RunStarted {
                schema: SCHEMA_VERSION,
                tactus_version: "0.0.1".to_owned(),
                run_id: "01RUN".to_owned(),
                branch: "tactus/run-01RUN".to_owned(),
                base_sha: "abc123".to_owned(),
                plan_path: "plan.md".to_owned(),
                config_path: None,
                plan_hash: "deadbeef".to_owned(),
                normalized_plan_digest: Some(format!("sha256:{}", "0".repeat(64))),
                private_dir: "/home/x/.tactus/runs/01RUN".to_owned(),
                gates: vec!["check".to_owned()],
                gates_from_config: true,
                reviews: Some(crate::review::ReviewPlan::default()),
                interaction_mode: "on_block".to_owned(),
                chains: vec![ChainSummary {
                    task: "t1".to_owned(),
                    tiers: vec![Tier::Small, Tier::Mid],
                    attempts_per: 2,
                    bindings: Some(vec![
                        BindingSummary {
                            tier: Tier::Small,
                            agent: "claude-code".to_owned(),
                            model: "claude-haiku-4-5".to_owned(),
                            pinned: false,
                        },
                        BindingSummary {
                            tier: Tier::Mid,
                            agent: "claude-code".to_owned(),
                            model: "claude-sonnet-5".to_owned(),
                            pinned: false,
                        },
                    ]),
                }],
                effort_policy: Some(effort_policy()),
                gate_cmds: Some(vec![GateSummary {
                    name: "check".to_owned(),
                    cmd: "cargo check".to_owned(),
                    timeout: Duration::from_secs(600),
                    shell: crate::gates::ShellKind::Sh,
                }]),
            }),
        }
    }

    fn legacy_started() -> EventBody {
        let mut body = started();
        let EventBody::RunStarted { data } = &mut body else {
            unreachable!();
        };
        data.schema = 2;
        data.normalized_plan_digest = None;
        body
    }

    fn attempt_started(task: &str, attempt: u32, rung: u32, tier: &str) -> EventBody {
        EventBody::AttemptStarted {
            task: task.to_owned(),
            attempt,
            rung,
            profile: format!("{tier}-model"),
            data: AttemptStarted {
                adapter: None,
                preflight_cli_version: None,
                effort: None,
                selection_origin: None,
                tier: tier.to_owned(),
                agent: "claude-code".to_owned(),
                model: "model".to_owned(),
                pool: Some("claude-max".to_owned()),
                resume_session: None,
            },
        }
    }

    fn attempt_finished(task: &str, attempt: u32, rung: u32, tier: &str) -> EventBody {
        EventBody::AttemptFinished {
            task: task.to_owned(),
            attempt,
            rung,
            profile: format!("{tier}-model"),
            parking: None,
            transition: None,
            prepared_commit: Some(Box::new(PreparedCommit {
                branch_ref: "refs/heads/tactus/run-01RUN".to_owned(),
                parent_sha: "1".repeat(40),
                tree_sha: "2".repeat(40),
                commit_sha: "3".repeat(40),
                message: "[tactus] t1: task".to_owned(),
                pin_ref: format!("refs/tactus/prepared/01RUN/0-{attempt}"),
            })),
            data: Box::new(AttemptRecord {
                attempt,
                tier: tier.to_owned(),
                model: "model".to_owned(),
                pool: Some("claude-max".to_owned()),
                resumed: false,
                duration: Duration::from_millis(1500),
                cost_usd: Some(0.01),
                reviews: Vec::new(),
                session_id: Some("s0".to_owned()),
                usage: None,
                failure: None,
            }),
        }
    }

    fn question(id: &str, task: &str) -> Question {
        Question {
            id: QuestionId::from(id),
            kind: QuestionKind::Unblock,
            affected_tasks: vec![TaskId::from(task)],
            context: "nothing else can move this".to_owned(),
            options: vec!["retry".to_owned()],
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tactus-events-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn the_envelope_matches_the_shape_the_spec_documents() {
        // §15: {ts, event, task?, attempt?, rung?, profile?, data}. The
        // routing fields are hoisted so the raw file is greppable.
        let event = Event::now(attempt_started("t1", 2, 1, "mid"));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).expect("serialize"))
                .expect("valid json");
        assert_eq!(json["event"], "attempt_started");
        assert_eq!(json["task"], "t1");
        assert_eq!(json["attempt"], 2);
        assert_eq!(json["rung"], 1);
        assert_eq!(json["profile"], "mid-model");
        assert_eq!(json["data"]["tier"], "mid");
        assert!(
            json["ts"].as_str().is_some_and(|ts| ts.ends_with('Z')),
            "{json}"
        );
        // An event with no task omits the field rather than nulling it.
        let plain = Event::now(EventBody::DeferWaitElapsed {
            data: DeferWaitElapsed {
                waited: Duration::from_secs(60),
                round: 0,
            },
        });
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&plain).expect("serialize"))
                .expect("valid json");
        assert!(json.get("task").is_none(), "{json}");
        assert_eq!(json["data"]["waited_ms"], 60_000);
    }

    #[test]
    fn every_event_kind_round_trips() {
        let bodies = vec![
            started(),
            EventBody::RunResumed {
                data: RunResumed {
                    head_sha: "abc".to_owned(),
                    interrupted_attempts: 1,
                    discarded: Vec::new(),
                    gates: None,
                    effort_policy: None,
                    reviews: None,
                    chains: None,
                    normalized_plan_digest: None,
                },
            },
            EventBody::RunSchemaUpgraded {
                data: RunSchemaUpgraded { from: 1, to: 2 },
            },
            attempt_started("t1", 1, 0, "small"),
            attempt_finished("t1", 1, 0, "small"),
            EventBody::LadderRetry {
                task: "t1".to_owned(),
                attempt: 1,
                rung: 0,
                data: LadderRetry {
                    resume: true,
                    tier: "small".to_owned(),
                    summary: "gate failed".to_owned(),
                    detail: Some("error[E0308]".to_owned()),
                },
            },
            EventBody::LadderEscalated {
                task: "t1".to_owned(),
                attempt: 2,
                rung: 0,
                data: LadderEscalated {
                    to_rung: 1,
                    tier: "small".to_owned(),
                    summary: "still failing".to_owned(),
                    detail: None,
                },
            },
            EventBody::TaskDeferred {
                task: "t1".to_owned(),
                data: TaskDeferred {
                    reason: "rate limited".to_owned(),
                    defers: 1,
                },
            },
            EventBody::DeferWaitElapsed {
                data: DeferWaitElapsed {
                    waited: Duration::from_secs(60),
                    round: 0,
                },
            },
            EventBody::TaskParked {
                task: "t1".to_owned(),
                data: TaskParked {
                    question: "q-1".to_owned(),
                    refund_attempt: true,
                },
            },
            EventBody::TaskCommitted {
                task: "t1".to_owned(),
                data: TaskCommitted {
                    sha: "abc123".to_owned(),
                    message: "[tactus] t1: do it".to_owned(),
                },
            },
            EventBody::TaskFailed {
                task: "t1".to_owned(),
                data: TaskFailed {
                    kind: FailureKind::Declined,
                    reason: "declined".to_owned(),
                    halts_run: true,
                },
            },
            EventBody::QuestionRaised {
                task: "t1".to_owned(),
                data: Box::new(QuestionRaised {
                    question: question("q-1", "t1"),
                }),
            },
            EventBody::QuestionAnswered {
                data: QuestionAnswered {
                    question: QuestionId::from("q-1"),
                    answer: Answer::Answered {
                        text: "use base64".to_owned(),
                    },
                    decline_halts_run: None,
                    via: "terminal".to_owned(),
                },
            },
            EventBody::DesignDefect {
                data: DesignDefect {
                    question: QuestionId::from("q-1"),
                    context: "cursor format was never decided".to_owned(),
                    answer: "use base64".to_owned(),
                },
            },
            EventBody::RunFinished {
                data: RunFinished {
                    outcome: RunOutcome::Parked,
                    halted_at: None,
                    committed: 2,
                    parked: 1,
                },
            },
        ];
        for body in bodies {
            let event = Event::now(body);
            let line = serde_json::to_string(&event).expect("serialize");
            let back: Event = serde_json::from_str(&line).expect(&line);
            assert_eq!(back, event, "{line}");
        }
    }

    #[test]
    fn durations_are_milliseconds_not_a_struct() {
        // Readability in the log, and it survives serde's internally-tagged
        // buffering, which the default Duration shape does not reliably do.
        let event = Event::now(attempt_finished("t1", 1, 0, "small"));
        let line = serde_json::to_string(&event).expect("serialize");
        assert!(line.contains("\"duration_ms\":1500"), "{line}");
        assert!(!line.contains("nanos"), "{line}");
        let back: Event = serde_json::from_str(&line).expect("round-trip");
        assert_eq!(back, event);
    }

    #[test]
    fn a_torn_final_line_is_dropped_but_committed_invalid_events_are_errors() {
        let dir = scratch("torn");
        let path = dir.join("events.jsonl");
        let good = serde_json::to_string(&Event::now(started())).expect("serialize");
        let also_good = serde_json::to_string(&Event::now(attempt_started("t1", 1, 0, "small")))
            .expect("serialize");

        // A kill mid-write: the last line stops partway through.
        let torn = format!("{good}\n{also_good}\n{{\"ts\":\"2026-01-0");
        std::fs::write(&path, &torn).expect("write");
        let mut warnings = Vec::new();
        let events = read_all(&path, &mut warnings).expect("torn tail is recoverable");
        assert_eq!(events.len(), 2);
        assert!(
            warnings.iter().any(|w| w.contains("incomplete final line")),
            "warnings: {warnings:?}"
        );

        // `serde_json` may write Unicode from a recorded reason or path. A kill
        // can split that code point, but bytes after the commit newline are no
        // less recoverable merely because they are not yet valid UTF-8.
        let mut invalid_utf8_tail = format!("{good}\n").into_bytes();
        invalid_utf8_tail.extend_from_slice(&[0xf0, 0x9f]);
        std::fs::write(&path, invalid_utf8_tail).expect("write split UTF-8 tail");
        let mut warnings = Vec::new();
        let events = read_all(&path, &mut warnings).expect("split UTF-8 tail is recoverable");
        assert_eq!(events.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("2 trailing byte(s)"));

        // Damage anywhere else means the file was rewritten, not interrupted.
        let corrupt = format!("{good}\nnot json at all\n{also_good}\n");
        std::fs::write(&path, corrupt).expect("write");
        let mut warnings = Vec::new();
        let err = read_all(&path, &mut warnings).expect_err("must not fold a rewritten log");
        assert!(err.to_string().contains("line 2"), "got: {err}");
        assert!(err.to_string().contains("confidently wrong"), "got: {err}");

        // Being last is not enough to make an event recoverable. This record is
        // complete JSON and newline-terminated, but its domain value is invalid.
        let mut invalid: serde_json::Value =
            serde_json::from_str(&also_good).expect("attempt-start JSON");
        invalid["data"]["selection_origin"] = serde_json::json!("unknown");
        let invalid = serde_json::to_string(&invalid).expect("invalid event JSON");
        std::fs::write(&path, format!("{good}\n{invalid}\n")).expect("write invalid tail");
        let mut warnings = Vec::new();
        let err = read_all(&path, &mut warnings).expect_err("semantic errors are not torn tails");
        assert!(err.to_string().contains("line 2"), "got: {err}");
        assert!(err.to_string().contains("unknown variant"), "got: {err}");
        assert!(warnings.is_empty(), "corruption is an error, not a warning");
    }

    #[test]
    fn a_valid_json_event_without_its_commit_newline_is_a_torn_tail() {
        let dir = scratch("uncommitted-valid-tail");
        let path = dir.join("events.jsonl");
        let good = serde_json::to_string(&Event::now(started())).expect("serialize");
        let uncommitted = serde_json::to_string(&Event::now(attempt_started("t1", 1, 0, "small")))
            .expect("serialize");
        std::fs::write(&path, format!("{good}\n{uncommitted}")).expect("write uncommitted tail");

        let mut warnings = Vec::new();
        let events = read_all(&path, &mut warnings).expect("uncommitted tail is recoverable");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].body.kind(), "run_started");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("incomplete final line"));
    }

    #[test]
    fn appending_after_a_torn_line_discards_it_rather_than_splicing() {
        let dir = scratch("repair");
        let path = dir.join("events.jsonl");
        let good = serde_json::to_string(&Event::now(started())).expect("serialize");
        std::fs::write(&path, format!("{good}\n{{\"ts\":\"trunc")).expect("write");

        let mut warnings = Vec::new();
        let mut log = EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("open");
        assert!(
            warnings.iter().any(|w| w.contains("never finished")),
            "the discard is reported, not silent: {warnings:?}"
        );
        log.append(
            EventSite::LegacyAppend,
            attempt_started("t1", 1, 0, "small"),
        )
        .expect("append");

        // Splicing would have lost both the fragment and the new event;
        // newline-terminating the fragment would have left an unparseable
        // line in the middle, which the reader must refuse outright.
        let mut warnings = Vec::new();
        let events = read_all(&path, &mut warnings).expect("the log is clean again");
        assert_eq!(events.len(), 2, "the good first line and the new one");
        assert_eq!(events[1].body.kind(), "attempt_started");
        assert!(
            warnings.is_empty(),
            "nothing left to warn about: {warnings:?}"
        );
    }

    #[test]
    fn a_log_that_is_nothing_but_a_torn_line_opens_empty() {
        // The pathological case: killed while writing the very first event.
        let dir = scratch("alltorn");
        let path = dir.join("events.jsonl");
        std::fs::write(&path, "{\"ts\":\"2026").expect("write");

        let mut warnings = Vec::new();
        let mut log = EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("open");
        log.append(EventSite::LegacyAppend, started())
            .expect("append");

        let mut warnings = Vec::new();
        let events = read_all(&path, &mut warnings).expect("read");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].body.kind(), "run_started");
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_guessed_at() {
        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        data.schema = SCHEMA_VERSION + 1;
        let events = vec![Event::now(EventBody::RunStarted { data })];
        let err = replay(events, vec!["t1".to_owned()], Path::new("events.jsonl"))
            .expect_err("must refuse a newer log");
        assert!(err.to_string().contains("Upgrade"), "got: {err}");
    }

    #[test]
    fn a_schema_upgrade_event_is_a_real_downgrade_barrier() {
        #[derive(Debug, serde::Deserialize)]
        struct SchemaOneEvent {
            #[allow(dead_code)]
            ts: String,
            #[serde(flatten)]
            #[allow(dead_code)]
            body: SchemaOneBody,
        }
        #[derive(Debug, serde::Deserialize)]
        #[serde(tag = "event", rename_all = "snake_case")]
        #[allow(dead_code)]
        enum SchemaOneBody {
            RunStarted { data: serde_json::Value },
            RunResumed { data: serde_json::Value },
        }

        let marker = Event::now(EventBody::RunSchemaUpgraded {
            data: RunSchemaUpgraded { from: 1, to: 2 },
        });
        let line = serde_json::to_string(&marker).expect("serialize marker");
        let error = serde_json::from_str::<SchemaOneEvent>(&line)
            .expect_err("a schema-1 reader must refuse the new event");
        assert!(error.to_string().contains("run_schema_upgraded"), "{error}");

        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        data.schema = 1;
        for chain in &mut data.chains {
            chain.bindings = None;
        }
        let events = vec![Event::now(EventBody::RunStarted { data }), marker];
        let replayed = replay(events, vec!["t1".to_owned()], Path::new("events.jsonl"))
            .expect("the current binary follows the valid 1 -> 2 transition");
        assert_eq!(replayed.started.schema, 1);
    }

    #[test]
    fn a_future_appended_schema_transition_is_refused() {
        let events = vec![
            Event::now(started()),
            Event::now(EventBody::RunSchemaUpgraded {
                data: RunSchemaUpgraded {
                    from: SCHEMA_VERSION,
                    to: SCHEMA_VERSION + 1,
                },
            }),
        ];
        let error = replay(events, vec!["t1".to_owned()], Path::new("events.jsonl"))
            .expect_err("the opening schema is not the only compatibility boundary");
        assert!(error.to_string().contains("Upgrade"), "{error}");
    }

    #[test]
    fn run_resumed_clears_the_prior_terminal_marker() {
        let mut state = RunState::new(vec!["t1".to_owned()]);
        state.apply(&Event::now(EventBody::RunFinished {
            data: RunFinished {
                outcome: RunOutcome::Parked,
                halted_at: None,
                committed: 0,
                parked: 1,
            },
        }));
        assert!(state.finished.is_some());

        state.apply(&Event::now(EventBody::RunResumed {
            data: RunResumed {
                head_sha: "abc".to_owned(),
                interrupted_attempts: 0,
                discarded: Vec::new(),
                gates: None,
                effort_policy: None,
                reviews: None,
                chains: None,
                normalized_plan_digest: None,
            },
        }));
        assert_eq!(state.finished, None);
    }

    #[test]
    fn schema_three_rejects_incomplete_review_identity_without_legacy_defaults() {
        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        data.reviews = None;
        let error = replay(
            vec![Event::now(EventBody::RunStarted { data })],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect_err("schema 3 cannot re-derive a missing reviewer identity");
        assert!(error.to_string().contains("run_started.reviews"), "{error}");

        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        data.reviews
            .as_mut()
            .expect("current start records reviews")
            .pass_timeout_secs = None;
        let error = replay(
            vec![Event::now(EventBody::RunStarted { data })],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect_err("schema 3 cannot inherit a timeout from this binary");
        assert!(error.to_string().contains("pass_timeout_secs"), "{error}");

        let complete = || {
            let EventBody::RunStarted { mut data } = started() else {
                unreachable!();
            };
            let plan = data.reviews.as_mut().expect("review plan");
            plan.enabled = Some(true);
            plan.alternative_available = Some(false);
            plan.primary = Some(crate::review::PassBinding::new("codex", "gpt-5.6-sol"));
            plan.second_opinion = vec![None];
            Event::now(EventBody::RunStarted { data })
        };

        for missing in ["enabled", "alternative_available", "primary"] {
            let mut json = serde_json::to_value(complete()).expect("serialize");
            json["data"]["reviews"]
                .as_object_mut()
                .expect("review object")
                .remove(missing);
            let event: Event = serde_json::from_value(json).expect("additive field parses");
            let error = replay(
                vec![event],
                vec!["t1".to_owned()],
                Path::new("events.jsonl"),
            )
            .expect_err("schema 3 cannot default away a reviewer identity field");
            assert!(error.to_string().contains("review"), "{missing}: {error}");
        }

        let mut json = serde_json::to_value(complete()).expect("serialize");
        json["data"]["reviews"]["second_opinion"] = serde_json::json!([]);
        let event: Event = serde_json::from_value(json).expect("short vector parses");
        let error = replay(
            vec![event],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect_err("a short pass vector silently removes required task reviews");
        assert!(error.to_string().contains("misaligned"), "{error}");

        let mut undecided = attempt_finished("t1", 1, 0, "small");
        let EventBody::AttemptFinished { data, .. } = &mut undecided else {
            unreachable!();
        };
        data.failure = Some(FailureRecord {
            kind: FailureKind::GateFailed,
            origin: FailureOrigin::Worker,
            reason: "failed".to_owned(),
        });
        let error = replay(
            vec![
                Event::now(started()),
                Event::now(attempt_started("t1", 1, 0, "small")),
                Event::now(undecided),
            ],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect_err("schema 3 cannot replay a failed attempt without its decision");
        assert!(
            error.to_string().contains("ladder/parking decision"),
            "{error}"
        );
    }

    #[test]
    fn schema_three_rejects_human_outage_and_review_input_decision_contradictions() {
        let retry = || {
            Some(Box::new(AttemptTransition::Retry(LadderRetry {
                resume: false,
                tier: "small".to_owned(),
                summary: "retry".to_owned(),
                detail: None,
            })))
        };
        let escalate = || {
            Some(Box::new(AttemptTransition::Escalate(LadderEscalated {
                to_rung: 1,
                tier: "small".to_owned(),
                summary: "escalate".to_owned(),
                detail: None,
            })))
        };
        let park = |kind, refund_attempt| {
            let mut question = question("q-special", "t1");
            question.kind = kind;
            Some(Box::new(AttemptParking {
                question,
                refund_attempt,
            }))
        };
        let cases = vec![
            (
                FailureKind::NeedsHuman,
                FailureOrigin::Worker,
                retry(),
                None,
            ),
            (
                FailureKind::NeedsHuman,
                FailureOrigin::Reviewer,
                None,
                park(QuestionKind::Unblock, true),
            ),
            (
                FailureKind::RateLimited,
                FailureOrigin::Worker,
                retry(),
                None,
            ),
            (
                FailureKind::Timeout,
                FailureOrigin::Reviewer,
                escalate(),
                None,
            ),
            (
                FailureKind::ReviewUnavailable,
                FailureOrigin::Reviewer,
                None,
                park(QuestionKind::Unblock, false),
            ),
            (
                FailureKind::ReviewInputTooLarge,
                FailureOrigin::Reviewer,
                retry(),
                None,
            ),
            (
                FailureKind::ReviewInputOpaque,
                FailureOrigin::Worker,
                None,
                park(QuestionKind::Unblock, false),
            ),
        ];

        for (kind, origin, transition, parking) in cases {
            let mut finished = attempt_finished("t1", 1, 0, "small");
            let EventBody::AttemptFinished {
                data,
                transition: recorded_transition,
                parking: recorded_parking,
                prepared_commit,
                ..
            } = &mut finished
            else {
                unreachable!();
            };
            data.failure = Some(FailureRecord {
                kind,
                origin,
                reason: "special failure".to_owned(),
            });
            *recorded_transition = transition;
            *recorded_parking = parking;
            *prepared_commit = None;
            let error = replay(
                vec![
                    Event::now(started()),
                    Event::now(attempt_started("t1", 1, 0, "small")),
                    Event::now(finished),
                ],
                vec!["t1".to_owned()],
                Path::new("events.jsonl"),
            )
            .expect_err("schema 3 must reject a policy-contradictory settlement");
            assert!(
                error.to_string().contains("inconsistent with its failure"),
                "{kind:?}/{origin:?}: {error}"
            );
        }
    }

    #[test]
    fn legacy_schema_two_spend_question_without_task_parked_is_unsettled() {
        let mut failed = attempt_finished("t1", 1, 0, "small");
        let EventBody::AttemptFinished {
            data,
            prepared_commit,
            ..
        } = &mut failed
        else {
            unreachable!();
        };
        data.failure = Some(FailureRecord {
            kind: FailureKind::GateFailed,
            origin: FailureOrigin::Worker,
            reason: "failed".to_owned(),
        });
        *prepared_commit = None;
        let mut approval = question("q-spend", "t1");
        approval.kind = QuestionKind::ApproveSpend;
        let mut log = vec![
            Event::now(legacy_started()),
            Event::now(attempt_started("t1", 1, 0, "small")),
            Event::now(failed),
            Event::now(EventBody::LadderEscalated {
                task: "t1".to_owned(),
                attempt: 1,
                rung: 0,
                data: LadderEscalated {
                    to_rung: 1,
                    tier: "small".to_owned(),
                    summary: "escalate".to_owned(),
                    detail: None,
                },
            }),
            Event::now(EventBody::QuestionRaised {
                task: "t1".to_owned(),
                data: Box::new(QuestionRaised { question: approval }),
            }),
        ];
        let unsettled = legacy_unsettled_failure(2, &log).expect("parking append is missing");
        assert_eq!(
            unsettled.kind,
            LegacyUnsettledFailureKind::MissingSpendParking
        );

        log.push(Event::now(EventBody::TaskParked {
            task: "t1".to_owned(),
            data: TaskParked {
                question: "q-spend".to_owned(),
                refund_attempt: false,
            },
        }));
        assert_eq!(legacy_unsettled_failure(2, &log), None);
    }

    #[test]
    fn schema_three_binds_task_committed_to_the_immediately_prepared_object() {
        let success = attempt_finished("t1", 1, 0, "small");
        let EventBody::AttemptFinished {
            prepared_commit: Some(prepared),
            ..
        } = &success
        else {
            unreachable!();
        };
        let prepared = (**prepared).clone();
        let committed = EventBody::TaskCommitted {
            task: "t1".to_owned(),
            data: TaskCommitted {
                sha: prepared.commit_sha.clone(),
                message: prepared.message.clone(),
            },
        };
        replay(
            vec![
                Event::now(started()),
                Event::now(attempt_started("t1", 1, 0, "small")),
                Event::now(success.clone()),
                Event::now(committed),
            ],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect("the exact prepared identity closes the settlement");

        let mut wrong_branch = success.clone();
        let EventBody::AttemptFinished {
            prepared_commit: Some(wrong_prepared),
            ..
        } = &mut wrong_branch
        else {
            unreachable!();
        };
        wrong_prepared.branch_ref = "refs/heads/unrelated".to_owned();
        let branch_error = replay(
            vec![
                Event::now(started()),
                Event::now(attempt_started("t1", 1, 0, "small")),
                Event::now(wrong_branch),
            ],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect_err("the prepared identity cannot substitute another branch");
        assert!(
            branch_error.to_string().contains("branch"),
            "{branch_error}"
        );

        let error = replay(
            vec![
                Event::now(started()),
                Event::now(attempt_started("t1", 1, 0, "small")),
                Event::now(success),
                Event::now(EventBody::TaskCommitted {
                    task: "t1".to_owned(),
                    data: TaskCommitted {
                        sha: "4".repeat(40),
                        message: prepared.message.clone(),
                    },
                }),
            ],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect_err("same subject cannot substitute another commit tree");
        assert!(
            error.to_string().contains("exact prepared commit"),
            "{error}"
        );
    }

    #[test]
    fn pre_upgrade_digest_fields_cannot_bless_a_legacy_snapshot() {
        let spoofed = format!("sha256:{}", "1".repeat(64));
        let authoritative = format!("sha256:{}", "2".repeat(64));
        let resumed = |digest| {
            Event::now(EventBody::RunResumed {
                data: RunResumed {
                    head_sha: "abc".to_owned(),
                    interrupted_attempts: 0,
                    discarded: Vec::new(),
                    gates: None,
                    effort_policy: None,
                    reviews: None,
                    chains: None,
                    normalized_plan_digest: Some(digest),
                },
            })
        };
        let mut start = legacy_started();
        let EventBody::RunStarted { data } = &mut start else {
            unreachable!();
        };
        data.normalized_plan_digest = Some(spoofed.clone());

        let before_upgrade = vec![Event::now(start.clone()), resumed(spoofed.clone())];
        assert_eq!(
            recorded_normalized_plan_digest(&before_upgrade),
            None,
            "schema-1/2 additive fields are not an authority"
        );

        let after_upgrade = vec![
            Event::now(start),
            resumed(spoofed),
            Event::now(EventBody::RunSchemaUpgraded {
                data: RunSchemaUpgraded { from: 2, to: 3 },
            }),
            resumed(authoritative.clone()),
        ];
        assert_eq!(
            recorded_normalized_plan_digest(&after_upgrade),
            Some(authoritative.as_str()),
            "only the first schema-3 resume can establish a legacy digest"
        );
    }

    #[test]
    fn a_run_started_without_gate_commands_reads_as_unrecorded() {
        // The shape every log written before the gate record has. `None`, not
        // an empty list: "said nothing about the gates" and "said there were
        // none" must stay distinguishable — the same rule `reviews` follows for
        // logs that predate step 9, and the difference between re-deriving with
        // a warning and running a run with verification switched off.
        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        data.schema = 1;
        for chain in &mut data.chains {
            chain.bindings = None;
        }
        let mut json =
            serde_json::to_value(Event::now(EventBody::RunStarted { data })).expect("serialize");
        assert!(
            json["data"]
                .as_object_mut()
                .expect("data")
                .remove("gate_cmds")
                .is_some(),
            "a fresh run records its gates"
        );
        let event: Event = serde_json::from_value(json).expect("an old log still parses");
        let EventBody::RunStarted { data } = event.body else {
            panic!("still a run_started");
        };
        assert_eq!(data.gate_cmds, None);
    }

    #[test]
    fn a_run_started_without_an_effort_policy_reads_as_unrecorded() {
        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        data.schema = 1;
        for chain in &mut data.chains {
            chain.bindings = None;
        }
        let mut json =
            serde_json::to_value(Event::now(EventBody::RunStarted { data })).expect("serialize");
        assert!(
            json["data"]
                .as_object_mut()
                .expect("data")
                .remove("effort_policy")
                .is_some(),
            "a fresh run records its effort policy"
        );
        let event: Event = serde_json::from_value(json).expect("a legacy log still parses");
        let EventBody::RunStarted { data } = &event.body else {
            panic!("still a run_started");
        };
        assert_eq!(data.schema, 1, "the legacy opening remains schema 1");
        assert_eq!(data.effort_policy, None);
        assert_eq!(recorded_effort_policy(&[event]), None);
    }

    #[test]
    fn a_recorded_effort_policy_round_trips_every_role_and_tier_exactly() {
        let EventBody::RunStarted { data } = started() else {
            panic!("started() builds a run_started");
        };
        let event = Event::now(EventBody::RunStarted { data });
        let line = serde_json::to_string(&event).expect("serialize");
        let json: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        assert_eq!(json["data"]["effort_policy"]["small"], "low");
        assert_eq!(json["data"]["effort_policy"]["mid"], "medium");
        assert_eq!(json["data"]["effort_policy"]["frontier"], "xhigh");
        assert_eq!(json["data"]["effort_policy"]["review"], "max");

        let read_back: Event = serde_json::from_str(&line).expect("round trip");
        assert_eq!(recorded_effort_policy(&[read_back]), Some(effort_policy()));
    }

    #[test]
    fn the_first_recorded_effort_policy_is_the_run_authority() {
        let original = effort_policy();
        let later = ResolvedEffortPolicy {
            small: Effort::High,
            mid: Effort::High,
            frontier: Effort::High,
            review: Effort::High,
        };
        let resumed = |policy| {
            Event::now(EventBody::RunResumed {
                data: RunResumed {
                    head_sha: "abc".to_owned(),
                    interrupted_attempts: 0,
                    discarded: Vec::new(),
                    gates: None,
                    effort_policy: Some(policy),
                    reviews: None,
                    chains: None,
                    normalized_plan_digest: None,
                },
            })
        };

        let EventBody::RunStarted { data } = started() else {
            panic!("started() builds a run_started");
        };
        let current = vec![Event::now(EventBody::RunStarted { data }), resumed(later)];
        assert_eq!(recorded_effort_policy(&current), Some(original));

        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        data.effort_policy = None;
        let legacy = vec![
            Event::now(EventBody::RunStarted { data }),
            resumed(original),
            resumed(later),
        ];
        assert_eq!(
            recorded_effort_policy(&legacy),
            Some(original),
            "the first establishing resume wins"
        );
    }

    #[test]
    fn the_first_complete_binding_snapshot_is_the_run_authority() {
        let EventBody::RunStarted { data } = started() else {
            panic!("started() builds a run_started");
        };
        let original = data.chains.clone();
        let current = vec![Event::now(EventBody::RunStarted { data })];
        assert_eq!(recorded_chains(&current), Some(&original));

        let EventBody::RunStarted { mut data } = started() else {
            panic!("started() builds a run_started");
        };
        for chain in &mut data.chains {
            chain.bindings = None;
        }
        let later = original
            .iter()
            .cloned()
            .map(|mut chain| {
                for binding in chain.bindings.iter_mut().flatten() {
                    binding.model = "later-model-must-not-win".to_owned();
                }
                chain
            })
            .collect();
        let legacy = vec![
            Event::now(EventBody::RunStarted { data }),
            Event::now(EventBody::RunResumed {
                data: RunResumed {
                    head_sha: "abc".to_owned(),
                    interrupted_attempts: 0,
                    discarded: Vec::new(),
                    gates: None,
                    effort_policy: None,
                    reviews: None,
                    chains: Some(original.clone()),
                    normalized_plan_digest: None,
                },
            }),
            Event::now(EventBody::RunResumed {
                data: RunResumed {
                    head_sha: "def".to_owned(),
                    interrupted_attempts: 0,
                    discarded: Vec::new(),
                    gates: None,
                    effort_policy: None,
                    reviews: None,
                    chains: Some(later),
                    normalized_plan_digest: None,
                },
            }),
        ];
        assert_eq!(recorded_chains(&legacy), Some(&original));
    }

    #[test]
    fn a_recorded_gate_survives_the_wire_intact_enough_to_run_again() {
        // Resume rebuilds its gates from this record and executes them, so a
        // field that does not round-trip is a gate that runs differently the
        // second time. `shell` in particular: the same `cmd` is an always-pass
        // builtin under one and not a program at all under another.
        let EventBody::RunStarted { data } = started() else {
            panic!("started() builds a run_started");
        };
        let recorded_gates = data.gate_cmds.clone();
        let line =
            serde_json::to_string(&Event::now(EventBody::RunStarted { data })).expect("serialize");
        let json: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        // Readable in the raw log, like every other duration in it.
        assert_eq!(json["data"]["gate_cmds"][0]["timeout_ms"], 600_000);
        assert_eq!(json["data"]["gate_cmds"][0]["shell"], "sh");

        let event: Event = serde_json::from_str(&line).expect("round trip");
        let EventBody::RunStarted { data: read_back } = event.body else {
            panic!("still a run_started");
        };
        assert_eq!(read_back.gate_cmds, recorded_gates);
        // And the shell spells the same way in the log as in `tactus.toml`, so
        // an operator comparing the two is comparing like with like.
        let recorded = read_back.gate_cmds.expect("gates");
        assert_eq!(
            crate::gates::ShellKind::parse("sh"),
            Some(recorded[0].shell)
        );
    }

    #[test]
    fn selection_origins_round_trip_and_old_starts_stay_absent() {
        for origin in [
            SelectionOrigin::Auto,
            SelectionOrigin::Pin,
            SelectionOrigin::UserOverride,
            SelectionOrigin::Exploration,
        ] {
            let json = serde_json::to_string(&origin).expect("serialize origin");
            assert_eq!(
                serde_json::from_str::<SelectionOrigin>(&json).expect("read origin"),
                origin
            );
        }

        let mut json = serde_json::to_value(Event::now(attempt_started("t1", 1, 0, "small")))
            .expect("serialize start");
        let data = json["data"].as_object_mut().expect("start data");
        data.remove("adapter");
        data.remove("preflight_cli_version");
        data.remove("effort");
        data.remove("selection_origin");
        let event: Event = serde_json::from_value(json).expect("old start still parses");
        let EventBody::AttemptStarted { data, .. } = event.body else {
            panic!("still an attempt start");
        };
        assert_eq!(data.adapter, None);
        assert_eq!(data.preflight_cli_version, None);
        assert_eq!(data.effort, None);
        assert_eq!(data.selection_origin, None);
        assert!(
            serde_json::from_str::<SelectionOrigin>("\"unknown\"").is_err(),
            "unknown is an export-only sentinel"
        );

        let review = ReviewRecord {
            pass: "review".to_owned(),
            agent: "claude-code".to_owned(),
            model: "claude-opus-5".to_owned(),
            adapter: Some("claude-code".to_owned()),
            preflight_cli_version: Some("1.2.3".to_owned()),
            effort: Some(Effort::High),
            pool: Some("claude-max".to_owned()),
            cost_usd: Some(0.05),
            outcome: ReviewPassOutcome::Passed,
        };
        let mut json = serde_json::to_value(review).expect("serialize review");
        let data = json.as_object_mut().expect("review data");
        data.remove("adapter");
        data.remove("preflight_cli_version");
        data.remove("effort");
        let review: ReviewRecord = serde_json::from_value(json).expect("old review still parses");
        assert_eq!(review.adapter, None);
        assert_eq!(review.preflight_cli_version, None);
        assert_eq!(review.effort, None);
        assert_eq!(
            SCHEMA_VERSION, 3,
            "the complete-review contract must remain behind a schema boundary"
        );
    }

    #[test]
    fn a_log_without_a_beginning_cannot_be_verified() {
        let events = vec![Event::now(attempt_started("t1", 1, 0, "small"))];
        let err = replay(events, vec!["t1".to_owned()], Path::new("events.jsonl"))
            .expect_err("no run_started");
        assert!(err.to_string().contains("run_started"), "got: {err}");
    }

    #[test]
    fn an_interrupted_attempt_is_recorded_but_does_not_spend_the_rung() {
        // Decision 3, and the property a killed run depends on: the attempt
        // shows up in the ledger, the allowance does not.
        let events = vec![
            Event::now(started()),
            Event::now(attempt_started("t1", 1, 0, "small")),
        ];
        let mut replayed =
            replay(events, vec!["t1".to_owned()], Path::new("events.jsonl")).expect("replay");
        assert_eq!(replayed.state.settle_interrupted(), 1);

        let progress = &replayed.state.progress[0];
        assert_eq!(progress.attempts, 1, "the attempt happened");
        assert_eq!(
            progress.attempts_on_rung, 0,
            "but nothing judged it, so the rung's allowance is intact"
        );
        assert_eq!(progress.rung, 0, "and it did not escalate");
        assert!(
            progress.session.is_none(),
            "§14: the session is not trusted"
        );
        assert!(!progress.resume_next);
        assert!(progress.in_flight.is_none(), "settled");

        let record = progress.records.last().expect("a ledger line");
        assert_eq!(
            record.failure.as_ref().map(|f| f.kind),
            Some(FailureKind::Interrupted)
        );
        assert_eq!(record.cost_usd, None, "unknown spend stays unknown");
        assert_eq!(
            replayed.state.states[0],
            TaskState::Pending,
            "the scheduler picks it straight back up"
        );
    }

    #[test]
    fn a_finished_attempt_leaves_nothing_in_flight() {
        let events = vec![
            Event::now(started()),
            Event::now(attempt_started("t1", 1, 0, "small")),
            Event::now(attempt_finished("t1", 1, 0, "small")),
        ];
        let mut replayed =
            replay(events, vec!["t1".to_owned()], Path::new("events.jsonl")).expect("replay");
        assert_eq!(replayed.state.settle_interrupted(), 0);
        assert_eq!(replayed.state.progress[0].records.len(), 1);
        assert_eq!(replayed.state.progress[0].attempts_on_rung, 1);
        assert_eq!(
            replayed.state.progress[0].session.as_deref(),
            Some("s0"),
            "a live session survives within one process"
        );
    }

    #[test]
    fn resume_repairs_each_attempt_settlement_transition_prefix() {
        let cases = [
            AttemptTransition::Retry(LadderRetry {
                resume: true,
                tier: "small".to_owned(),
                summary: "retry".to_owned(),
                detail: Some("fix it".to_owned()),
            }),
            AttemptTransition::Escalate(LadderEscalated {
                to_rung: 1,
                tier: "small".to_owned(),
                summary: "escalate".to_owned(),
                detail: None,
            }),
            AttemptTransition::Defer(TaskDeferred {
                reason: "outage".to_owned(),
                defers: 1,
            }),
            AttemptTransition::Fail(TaskFailed {
                kind: FailureKind::NoChain,
                reason: "no chain".to_owned(),
                halts_run: true,
            }),
        ];

        for transition in cases {
            let mut finished = attempt_finished("t1", 1, 0, "small");
            let EventBody::AttemptFinished {
                data,
                transition: recorded,
                prepared_commit,
                ..
            } = &mut finished
            else {
                unreachable!();
            };
            data.failure = Some(FailureRecord {
                kind: match &transition {
                    AttemptTransition::Defer(_) => FailureKind::RateLimited,
                    AttemptTransition::Fail(data) => data.kind,
                    _ => FailureKind::GateFailed,
                },
                origin: FailureOrigin::Worker,
                reason: "settled".to_owned(),
            });
            *prepared_commit = None;
            *recorded = Some(Box::new(transition.clone()));
            let replayed = replay(
                vec![
                    Event::now(started()),
                    Event::now(attempt_started("t1", 1, 0, "small")),
                    Event::now(finished),
                ],
                vec!["t1".to_owned()],
                Path::new("events.jsonl"),
            )
            .expect("the settlement prefix is complete on its own");
            let progress = &replayed.state.progress[0];
            match transition {
                AttemptTransition::Retry(_) => {
                    assert_eq!(replayed.state.states[0], TaskState::Pending);
                    assert!(progress.resume_next);
                    assert_eq!(progress.feedback.len(), 1);
                }
                AttemptTransition::Escalate(_) => {
                    assert_eq!(progress.rung, 1);
                    assert_eq!(progress.attempts_on_rung, 0);
                    assert!(progress.session.is_none());
                }
                AttemptTransition::Defer(_) => {
                    assert_eq!(replayed.state.states[0], TaskState::Deferred);
                    assert_eq!(progress.attempts_on_rung, 0);
                    assert_eq!(progress.defers, 1);
                }
                AttemptTransition::Fail(_) => {
                    assert!(matches!(replayed.state.states[0], TaskState::Failed { .. }));
                    assert_eq!(replayed.state.halted_at.as_deref(), Some("t1"));
                }
            }
        }
    }

    #[test]
    fn defer_then_sessionless_fresh_attempt_never_resumes_stale_session() {
        let mut first = attempt_finished("t1", 1, 0, "small");
        let EventBody::AttemptFinished { data, .. } = &mut first else {
            unreachable!();
        };
        data.session_id = Some("stale-session".to_owned());

        let mut second = attempt_finished("t1", 2, 0, "small");
        let EventBody::AttemptFinished {
            data,
            transition,
            prepared_commit,
            ..
        } = &mut second
        else {
            unreachable!();
        };
        data.session_id = None;
        data.failure = Some(FailureRecord {
            kind: FailureKind::GateFailed,
            origin: FailureOrigin::Worker,
            reason: "failed without a session".to_owned(),
        });
        *prepared_commit = None;
        *transition = Some(Box::new(AttemptTransition::Retry(LadderRetry {
            resume: false,
            tier: "small".to_owned(),
            summary: "retry fresh".to_owned(),
            detail: None,
        })));

        let replayed = replay(
            vec![
                Event::now(legacy_started()),
                Event::now(attempt_started("t1", 1, 0, "small")),
                Event::now(first),
                Event::now(EventBody::TaskDeferred {
                    task: "t1".to_owned(),
                    data: TaskDeferred {
                        reason: "review outage".to_owned(),
                        defers: 1,
                    },
                }),
                Event::now(attempt_started("t1", 2, 0, "small")),
                Event::now(second),
            ],
            vec!["t1".to_owned()],
            Path::new("events.jsonl"),
        )
        .expect("replay");
        assert!(replayed.state.progress[0].session.is_none());
        assert!(!replayed.state.progress[0].resume_next);
    }

    #[test]
    fn atomic_attempt_parking_discards_the_finished_sessions_tree_identity() {
        let mut finished = attempt_finished("t1", 1, 0, "small");
        let EventBody::AttemptFinished {
            data,
            parking,
            prepared_commit,
            ..
        } = &mut finished
        else {
            unreachable!("the helper always returns an attempt settlement");
        };
        data.failure = Some(FailureRecord {
            kind: FailureKind::ReviewInputTooLarge,
            origin: FailureOrigin::Reviewer,
            reason: "too large".to_owned(),
        });
        *prepared_commit = None;
        *parking = Some(Box::new(AttemptParking {
            question: question("q-parked", "t1"),
            refund_attempt: false,
        }));
        let events = vec![
            Event::now(started()),
            Event::now(attempt_started("t1", 1, 0, "small")),
            Event::now(finished),
        ];
        let replayed =
            replay(events, vec!["t1".to_owned()], Path::new("events.jsonl")).expect("replay");

        let progress = &replayed.state.progress[0];
        assert!(
            progress.session.is_none(),
            "parking discarded the tree, so its session cannot be resumed"
        );
        assert!(!progress.resume_next);
        assert_eq!(
            replayed.state.states[0],
            TaskState::AwaitingInput(QuestionId::from("q-parked"))
        );
        assert_eq!(replayed.state.open_questions().len(), 1);
    }

    #[test]
    fn resuming_drops_the_session_and_wakes_deferred_work() {
        // §14's pairing: tree retention and session resume travel together, so
        // a resume that discards the tree must also drop the session.
        let events = vec![
            Event::now(legacy_started()),
            Event::now(attempt_started("t1", 1, 0, "small")),
            Event::now(attempt_finished("t1", 1, 0, "small")),
            Event::now(EventBody::TaskDeferred {
                task: "t1".to_owned(),
                data: TaskDeferred {
                    reason: "rate limited".to_owned(),
                    defers: 1,
                },
            }),
            Event::now(EventBody::RunResumed {
                data: RunResumed {
                    head_sha: "abc".to_owned(),
                    interrupted_attempts: 0,
                    discarded: Vec::new(),
                    gates: None,
                    effort_policy: None,
                    reviews: None,
                    chains: None,
                    normalized_plan_digest: None,
                },
            }),
        ];
        let replayed =
            replay(events, vec!["t1".to_owned()], Path::new("events.jsonl")).expect("replay");
        assert!(replayed.state.progress[0].session.is_none());
        assert!(!replayed.state.progress[0].resume_next);
        assert_eq!(
            replayed.state.states[0],
            TaskState::Pending,
            "the wait already happened; do not wait again"
        );
        assert_eq!(replayed.resumes, 1);
    }

    #[test]
    fn answering_unparks_the_task_and_carries_the_operators_words() {
        let events = vec![
            Event::now(legacy_started()),
            Event::now(attempt_started("t1", 1, 0, "small")),
            Event::now(attempt_finished("t1", 1, 0, "small")),
            Event::now(EventBody::QuestionRaised {
                task: "t1".to_owned(),
                data: Box::new(QuestionRaised {
                    question: question("q-1", "t1"),
                }),
            }),
            Event::now(EventBody::TaskParked {
                task: "t1".to_owned(),
                data: TaskParked {
                    question: "q-1".to_owned(),
                    refund_attempt: false,
                },
            }),
            Event::now(EventBody::QuestionAnswered {
                data: QuestionAnswered {
                    question: QuestionId::from("q-1"),
                    answer: Answer::Answered {
                        text: "write it in src/widget.rs".to_owned(),
                    },
                    decline_halts_run: None,
                    via: "answer-file".to_owned(),
                },
            }),
        ];
        let replayed =
            replay(events, vec!["t1".to_owned()], Path::new("events.jsonl")).expect("replay");
        assert_eq!(replayed.state.states[0], TaskState::Pending, "un-parked");

        let progress = &replayed.state.progress[0];
        assert_eq!(
            progress.attempts_on_rung, 0,
            "an Unblock answer buys a fresh allowance on the same rung"
        );
        assert!(
            progress.session.is_none(),
            "a parked tree has no live session"
        );
        assert!(!progress.resume_next, "never resume out of a park (§14)");
        let last = progress.feedback.last().expect("the answer is feedback");
        assert!(last.human, "labelled as an instruction, not quoted data");
        assert_eq!(last.detail.as_deref(), Some("write it in src/widget.rs"));
        assert!(replayed.state.open_questions().is_empty());
    }

    #[test]
    fn an_answer_that_arrives_twice_is_applied_once() {
        // A terminal reply racing an out-of-band answer file must not push the
        // operator's words into the prompt twice.
        let mut state = RunState::new(vec!["t1".to_owned()]);
        state.apply(&Event::now(EventBody::QuestionRaised {
            task: "t1".to_owned(),
            data: Box::new(QuestionRaised {
                question: question("q-1", "t1"),
            }),
        }));
        state.apply(&Event::now(EventBody::TaskParked {
            task: "t1".to_owned(),
            data: TaskParked {
                question: "q-1".to_owned(),
                refund_attempt: false,
            },
        }));
        let answered = Event::now(EventBody::QuestionAnswered {
            data: QuestionAnswered {
                question: QuestionId::from("q-1"),
                answer: Answer::Answered {
                    text: "once".to_owned(),
                },
                decline_halts_run: None,
                via: "terminal".to_owned(),
            },
        });
        state.apply(&answered);
        state.apply(&answered);
        assert_eq!(state.progress[0].feedback.len(), 1);
    }

    #[test]
    fn a_decline_leaves_the_task_to_the_failure_event() {
        // The halt policy lives in exactly one place: task_failed.
        let mut state = RunState::new(vec!["t1".to_owned()]);
        state.apply(&Event::now(EventBody::QuestionRaised {
            task: "t1".to_owned(),
            data: Box::new(QuestionRaised {
                question: question("q-1", "t1"),
            }),
        }));
        state.apply(&Event::now(EventBody::TaskParked {
            task: "t1".to_owned(),
            data: TaskParked {
                question: "q-1".to_owned(),
                refund_attempt: false,
            },
        }));
        state.apply(&Event::now(EventBody::QuestionAnswered {
            data: QuestionAnswered {
                question: QuestionId::from("q-1"),
                answer: Answer::Declined,
                decline_halts_run: Some(true),
                via: "terminal".to_owned(),
            },
        }));
        assert!(state.questions[0].answer.is_some(), "recorded");
        assert!(
            matches!(state.states[0], TaskState::AwaitingInput(_)),
            "still parked until task_failed says otherwise"
        );

        state.apply(&Event::now(EventBody::TaskFailed {
            task: "t1".to_owned(),
            data: TaskFailed {
                kind: FailureKind::Declined,
                reason: "declined at the human rung".to_owned(),
                halts_run: true,
            },
        }));
        assert!(matches!(state.states[0], TaskState::Failed { .. }));
        assert_eq!(state.halted_at.as_deref(), Some("t1"));
    }

    #[test]
    fn the_first_failure_keeps_the_halt_label() {
        let mut state = RunState::new(vec!["t1".to_owned(), "t2".to_owned()]);
        for task in ["t1", "t2"] {
            state.apply(&Event::now(EventBody::TaskFailed {
                task: task.to_owned(),
                data: TaskFailed {
                    kind: FailureKind::GateFailed,
                    reason: "no".to_owned(),
                    halts_run: true,
                },
            }));
        }

        assert_eq!(
            state.halted_at.as_deref(),
            Some("t1"),
            "a later failure must not relabel the cause"
        );
    }

    #[test]
    fn escalation_moves_to_the_recorded_rung_and_starts_cold() {
        let mut state = RunState::new(vec!["t1".to_owned()]);
        state.apply(&Event::now(attempt_started("t1", 1, 0, "small")));
        state.apply(&Event::now(attempt_finished("t1", 1, 0, "small")));
        state.apply(&Event::now(EventBody::LadderEscalated {
            task: "t1".to_owned(),
            attempt: 1,
            rung: 0,
            data: LadderEscalated {
                to_rung: 1,
                tier: "small".to_owned(),
                summary: "empty diff".to_owned(),
                detail: None,
            },
        }));
        let progress = &state.progress[0];
        assert_eq!(progress.rung, 1);
        assert_eq!(progress.attempts_on_rung, 0);
        assert!(progress.session.is_none(), "a new rung is a new session");
        assert!(!progress.resume_next);
        assert_eq!(progress.feedback.len(), 1, "the history travels with it");
    }

    #[test]
    fn a_tail_never_yields_half_an_event() {
        let dir = scratch("tail");
        let path = dir.join("events.jsonl");
        let mut warnings = Vec::new();
        let mut log = EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("open");
        log.append(EventSite::LegacyAppend, started())
            .expect("append");

        let mut tail = LogTail::new(path.clone());
        assert_eq!(tail.poll(&mut warnings).expect("poll").len(), 1);
        assert!(tail.poll(&mut warnings).expect("poll").is_empty());

        log.append(
            EventSite::LegacyAppend,
            attempt_started("t1", 1, 0, "small"),
        )
        .expect("append");
        let seen = tail.poll(&mut warnings).expect("poll");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body.kind(), "attempt_started");

        // A partial line is left for the next poll rather than parsed.
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"{\"ts\":\"2026").expect("partial write");
        assert!(tail.poll(&mut warnings).expect("poll").is_empty());
        assert!(warnings.is_empty(), "not an error, just not finished yet");
    }
}
