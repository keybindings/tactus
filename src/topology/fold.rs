//! The checked fold: one transition function for a live run and for a replay.
//!
//! **INV-02 — an invalid transition is never appended, and never applied.**
//! [`TopologyFold::plan_transition`] decides whether an event may be applied
//! and returns a [`TopologyDelta`] when it may; [`TopologyFold::apply_delta`]
//! is the only thing that changes the state, and a `TopologyDelta` is the only
//! thing it accepts. The delta has no public constructor, so there is no way to
//! reach the state except through the check — which is what makes "the live run
//! and the replay use one transition" a property of the types rather than a
//! convention two call sites are expected to keep.
//!
//! A live emission is `plan_transition` → append the exact bytes → `apply_delta`
//! only after the append returned `Ok`. A replay is
//! [`TopologyFold::replay`], which is those same two calls per event with the
//! append taken out. Nothing else exists.
//!
//! # What the fold refuses
//!
//! Everything in `decisions.schema_compatibility.refusals`, less the four the
//! header probe answers before a fold exists ([`crate::topology::schema`]).
//! The refusals are not a validation pass bolted onto a fold: they *are* the
//! fold, because a transition this module cannot state the effect of is a
//! transition it must not pretend to have applied.
//!
//! Three of them are worth naming here because they are relations rather than
//! shapes, and a reader looking for them in one event will not find them:
//!
//! * **The publication relations** (INV-09). A `merge_prepared` is checked
//!   against the candidate's own record, the pinned proposal, and the head the
//!   verification read — three records elsewhere in the log.
//! * **The derived outcome** (INV-15). `run_finished` carries an outcome, and
//!   the fold accepts it only when it equals [`TopologyFold::derived_outcome`],
//!   which is computed from durable state alone and never consults spend,
//!   capacity, or runner availability.
//! * **Queue order** (`decisions.coordinator_integration.queue`). An
//!   integration may only start for the first *eligible* candidate, which is
//!   not the same as the first queued one.
//!
//! # What it does not do
//!
//! No production path writes or reads a schema-4 log yet, and nothing here
//! performs an effect: no ref moves, no worktree is created, no report is
//! written. The fold decides what a log *means*; the effects that log
//! authorizes, and the typed sites they run through, arrive in later slices.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::events::RunOutcome;
use crate::ir::{Plan, QuestionId, Tier};
use crate::topology::events::{
    Answer4, AttemptFinished4, AttemptInterrupted4, AttemptNumber, AttemptSettlement,
    AttemptStarted4, BindingOverride, BudgetExceeded4, BudgetStop, CandidateLeaseEffect,
    CandidatePrepared, CandidateRef, CommitSha, DerivedOutcome, Epoch, FrozenQuestion, FrozenSpawn,
    GenerationClosed, GenerationId, GitRef, IncarnationId, LeaseDisposition, LeaseGrant,
    MergeLeaseRelease, MergePrepared, MergeRejected, MergeVerificationInterrupted,
    MergeVerificationStarted, MergeVerificationUnavailable, PreparedDisposition, QuestionAnswered4,
    RejectionDisposition, RejectionLeaseEffect, RunFinished4, RunResumed4, RunStarted4, SequenceId,
    SessionId, SettlementTransition, SpawnAdmission, TaskCandidateCreated, TaskDispatched,
    TaskMerged, TopologyEvent, TopologyEventBody, UnavailableCause, UnavailableOutcome,
    VerificationBasis, VerificationSource, VerificationVerdict,
};
use crate::topology::leases::{GenerationLease, LeaseOwner, LeaseTable};
use crate::topology::paths::{GitPath, PathSet};
use crate::topology::queue::{CandidateQueue, Ineligible, QueueEntry};
use crate::topology::registry::{Admission, FrozenLadder, TaskEntry, TaskKey, TaskRegistry};

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a transition was refused.
///
/// Every message names the record it refused and the value it disagreed with,
/// because a fold error reaches an operator as "your log is invalid" unless it
/// says which line and which field.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FoldError {
    #[error(
        "a `{kind}` arrived before this log's `run_started`; the first event of a topology log \
         records the registry, the runner and the limits every later event is checked against"
    )]
    NotStarted { kind: &'static str },

    #[error(
        "a second `run_started` in one log; a run begins once, and a second beginning would \
         replace the registry every event so far was folded against"
    )]
    AlreadyStarted,

    #[error(
        "this `run_started` records event schema {schema}, not the topology schema; a log that \
         does not say it is a topology run cannot be folded as one"
    )]
    NotTopologySchema { schema: u32 },

    #[error("the run's runner record is unusable: {defect}")]
    IncompleteRunner { defect: String },

    #[error(
        "this incarnation established a different runner from the one the run started with: the \
         {field} differs. A run's confinement boundary and image are fixed for its life."
    )]
    RunnerMoved { field: String },

    #[error(
        "the recorded {what} digest `{recorded}` does not match `{actual}`, derived here from the \
         frozen inputs; the plan or the run record moved underneath the log"
    )]
    DigestMismatch {
        what: &'static str,
        recorded: String,
        actual: String,
    },

    #[error("the registry could not be rebuilt from the frozen plan and this record: {detail}")]
    RegistryUnbuildable { detail: String },

    #[error(
        "task {key}'s frozen ladder is malformed: {defect}. A ladder is frozen at registration \
         and every later attempt is checked against it, so one that cannot be escalated through \
         is refused before it is stored rather than when it is climbed."
    )]
    MalformedLadder { key: u32, defect: String },

    #[error("`{kind}` names task {key}, which this run has no entry for")]
    UnknownKey { kind: &'static str, key: u32 },

    #[error(
        "`{kind}` registers key {key}, but the registry holds {len} entries; a key is the next \
         dense index at the event that registers it"
    )]
    NonDenseKey {
        kind: &'static str,
        key: u32,
        len: usize,
    },

    #[error("`{kind}` for task {key} is inconsistent with what a registered entry is: {detail}")]
    MalformedEntry {
        kind: &'static str,
        key: u32,
        detail: String,
    },

    #[error(
        "task {key} is `{state}`, and `{kind}` applies to a task that is `{expected}`; the fold \
         holds one state per task and this event would apply to another run's"
    )]
    WrongTaskState {
        kind: &'static str,
        key: u32,
        state: &'static str,
        expected: &'static str,
    },

    #[error(
        "`{kind}` names generation {generation} of task {key}, which is not the open one \
         ({detail}); a completion applies only while its identity is the current open one"
    )]
    NotTheOpenGeneration {
        kind: &'static str,
        key: u32,
        generation: u32,
        detail: String,
    },

    #[error(
        "`{kind}` names attempt {attempt} of task {key} generation {generation}, and the open \
         attempt is {expected}"
    )]
    WrongAttempt {
        kind: &'static str,
        key: u32,
        generation: u32,
        attempt: u32,
        expected: String,
    },

    #[error(
        "attempt {attempt} of task {key} resumes a session this incarnation may not resume: \
         {detail}. A session belongs to the process that retained it."
    )]
    StaleIncarnation {
        key: u32,
        attempt: u32,
        detail: String,
    },

    #[error(
        "attempt {attempt} of task {key} runs a binding the run never froze for it: {detail}. \
         Run-start exact bindings are execution identity."
    )]
    BindingMismatch {
        key: u32,
        attempt: u32,
        detail: String,
    },

    #[error(
        "`{kind}` for task {key} records the lease disposition `{recorded}`, and a {owner} \
         generation that {fate} records `{expected}`"
    )]
    InvalidLeaseDisposition {
        kind: &'static str,
        key: u32,
        recorded: String,
        owner: &'static str,
        fate: &'static str,
        expected: String,
    },

    #[error(
        "`{kind}` opens integration sequence {sequence}, and this run has consumed {next}; \
         sequences are dense from 0 across the run"
    )]
    NonDenseSequence {
        kind: &'static str,
        sequence: u32,
        next: u32,
    },

    #[error(
        "`{kind}` names integration sequence {sequence}, and the open transaction is {open}; an \
         event applies to the transaction it belongs to or to none"
    )]
    WrongSequence {
        kind: &'static str,
        sequence: u32,
        open: String,
    },

    #[error(
        "`{kind}` opens integration sequence {sequence} while sequence {open} is unresolved; one \
         integration transaction runs at a time"
    )]
    TransactionAlreadyOpen {
        kind: &'static str,
        sequence: u32,
        open: u32,
    },

    #[error(
        "`{kind}` starts an integration for task {key} generation {generation}, which is not the \
         first eligible candidate in the queue ({detail})"
    )]
    NotFirstEligible {
        kind: &'static str,
        key: u32,
        generation: u32,
        detail: String,
    },

    #[error("`{kind}` disagrees with the record it cites: {detail}")]
    InconsistentRecord { kind: &'static str, detail: String },

    #[error(
        "`{kind}` settles {recorded:?}, and the fold derives {derived:?} as this publication's \
         closure"
    )]
    InvalidSatisfies {
        kind: &'static str,
        recorded: Vec<u32>,
        derived: Vec<u32>,
    },

    #[error(
        "a verification outage records {defers} deferral(s) for this candidate, and {detail}; an \
         outage that has waited its allowance parks for a human instead"
    )]
    InvalidDefers { defers: u32, detail: String },

    #[error("`{kind}` carries a question that cannot be answered: {detail}")]
    UnanswerableQuestion { kind: &'static str, detail: String },

    #[error("`{kind}` names question `{question}`, which {detail}")]
    WrongQuestion {
        kind: &'static str,
        question: String,
        detail: String,
    },

    #[error(
        "`{kind}` arrived after {what} in this epoch; the run has stopped admitting work and an \
         answer ingested now would restart a run that already ended"
    )]
    RunEnding {
        kind: &'static str,
        what: &'static str,
    },

    #[error(
        "`{kind}` continues a run that finished `{outcome}`; a {outcome} run is terminal — it is \
         finalized and then refused, never continued"
    )]
    RunIsOver {
        kind: &'static str,
        outcome: &'static str,
    },

    #[error(
        "`run_finished` records `{recorded}`, and the outcome derived from durable state is \
         {derived}; a run ends at the outcome its state implies or not at all"
    )]
    OutcomeMismatch {
        recorded: &'static str,
        derived: String,
    },

    #[error(
        "the fold is poisoned by an append whose outcome is unknown; this process appends nothing \
         further and derives nothing further from memory — the state is re-derived only by reopen \
         and the stable-prefix barrier"
    )]
    Poisoned,

    #[error(
        "line {line} of the log is newline-terminated and is not a valid event ({detail}). This \
         is not a torn tail — the line was committed, so the log has been rewritten, and state \
         derived from what is left would be confidently wrong."
    )]
    RewrittenLog { line: usize, detail: String },
}

// ---------------------------------------------------------------------------
// Fold state
// ---------------------------------------------------------------------------

/// What a task is doing, as the log says.
///
/// The topology's own states, not [`crate::events::TaskState`]: a task with an
/// open generation is `Pending` here and is kept out of admission by the
/// generation rather than by a state of its own, because the thing that has to
/// be closed before the run may end is the generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Runnable once its dependencies are merged and nothing else holds it.
    Pending,
    /// A candidate exists and is queued for integration.
    AwaitingMerge,
    /// Its candidate was rejected and a repair carries it.
    AwaitingRepair,
    /// Parked on a question.
    AwaitingInput,
    /// Backing off after an outage, until `defer_wait_elapsed` or a resume.
    Deferred,
    /// Its work is in the integration ref.
    Merged,
    /// Terminal.
    Failed,
}

impl TaskState {
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AwaitingMerge => "awaiting merge",
            Self::AwaitingRepair => "awaiting repair",
            Self::AwaitingInput => "awaiting input",
            Self::Deferred => "deferred",
            Self::Merged => "merged",
            Self::Failed => "failed",
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Merged | Self::Failed)
    }
}

/// Where one generation of one task is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerationClass {
    /// Dispatched; no attempt has started.
    OpenNoAttempt,
    /// An attempt is running.
    InFlight { attempt: AttemptNumber },
    /// Settled holding a session, for a same-session retry by the incarnation
    /// that retained it.
    RetainedIdle {
        session: SessionId,
        incarnation: Epoch,
    },
    /// An attempt succeeded; the candidate is being promoted to its
    /// authoritative ref.
    Promoting,
    /// Over.
    Closed,
}

impl GenerationClass {
    fn name(&self) -> &'static str {
        match self {
            Self::OpenNoAttempt => "open with no attempt",
            Self::InFlight { .. } => "in flight",
            Self::RetainedIdle { .. } => "retained idle",
            Self::Promoting => "promoting",
            Self::Closed => "closed",
        }
    }

    /// Whether this generation holds a pipeline entitlement.
    fn holds_pipeline(&self) -> bool {
        matches!(
            self,
            Self::OpenNoAttempt | Self::InFlight { .. } | Self::Promoting
        )
    }

    /// Whether the run may end while this generation is in this class.
    fn blocks_run_end(&self) -> bool {
        !matches!(self, Self::Closed)
    }
}

/// One generation of one task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationFold {
    pub id: GenerationId,
    pub class: GenerationClass,
    /// The commit the worktree was created at.
    pub base_sha: CommitSha,
    pub lease: GenerationLease,
    /// The highest attempt number started in this generation.
    pub attempts: u32,
    /// The candidate this generation prepared, once it has.
    pub candidate: Option<PreparedCandidate>,
}

/// What `candidate_prepared` recorded, kept for the relations a publication is
/// checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCandidate {
    pub candidate: CandidateRef,
    /// The base the work started from, and the parent of the commit.
    pub base_sha: CommitSha,
    pub paths: PathSet,
}

/// One task's fold state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskFold {
    pub state: TaskState,
    pub generations: Vec<GenerationFold>,
}

impl TaskFold {
    fn new() -> Self {
        Self {
            state: TaskState::Pending,
            generations: Vec::new(),
        }
    }

    /// The generation that is not closed, if any. At most one exists: a new one
    /// is only opened when the previous closed.
    fn open(&self) -> Option<&GenerationFold> {
        self.generations
            .iter()
            .find(|generation| generation.class != GenerationClass::Closed)
    }

    fn open_mut(&mut self) -> Option<&mut GenerationFold> {
        self.generations
            .iter_mut()
            .find(|generation| generation.class != GenerationClass::Closed)
    }
}

/// Why a question is open, which is what decides where its answer returns the
/// task to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuestionOrigin {
    /// A verification could not be run. An answer returns the task to awaiting
    /// merge, to be re-verified under a new sequence.
    VerificationPark,
    /// An attempt parked, or a repair's admission is gated. An answer returns
    /// the task to pending.
    Admission,
}

/// An open question and what raised it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenQuestion {
    pub question: FrozenQuestion,
    pub origin: QuestionOrigin,
    /// The frozen binding options this question's admission authorized, for a
    /// `HumanBinding` admission and for nothing else.
    ///
    /// `decisions.task_registry.binding_override` validates an override
    /// "against the frozen options of that task's open `HumanBinding`
    /// question", so the authority has to survive from the `task_spawned` that
    /// froze it to the `question_answered` that draws on it. Kept here rather
    /// than re-read from the registry entry because it is the *question's*
    /// authority: two questions of one task are answered separately and only
    /// one of them ever authorized a binding.
    pub binding: Option<Vec<String>>,
}

/// Where an integration transaction is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionClass {
    /// A verification is running against a recorded head.
    VerificationStarted {
        basis: VerificationBasis,
        expected_head: CommitSha,
        proposed_sha: CommitSha,
    },
    /// The publication is authorized and the ref move is owed.
    Prepared {
        proposed_sha: CommitSha,
        satisfies: Vec<TaskKey>,
    },
}

/// The one unresolved integration transaction, if there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub sequence: SequenceId,
    pub candidate: CandidateRef,
    pub class: TransactionClass,
}

/// Everything one topology run has recorded.
///
/// `PartialEq` and not `Eq`: the run record it holds carries the reported
/// spend of a budget stop, and a float has no total equality. Comparing two of
/// these is how a live fold and a replayed one are proved identical (INV-02).
#[derive(Debug, Clone, PartialEq)]
pub struct RunState {
    started: Box<RunStarted4>,
    registry: TaskRegistry,
    tasks: Vec<TaskFold>,
    epoch: Epoch,
    incarnation: IncarnationId,
    questions: BTreeMap<QuestionId, OpenQuestion>,
    /// Every question id this log has used, open or not: an id is never reused.
    seen_questions: BTreeSet<QuestionId>,
    overrides: BTreeMap<TaskKey, BindingOverride>,
    queue: CandidateQueue,
    leases: LeaseTable,
    transaction: Option<Transaction>,
    next_sequence: u32,
    halted_at: Option<TaskKey>,
    /// The epoch the halting settlement was recorded in. `halted_at` is never
    /// cleared, and the answer-ingestion refusal is epoch-scoped.
    halted_epoch: Option<Epoch>,
    budget_stop: Option<BudgetStop>,
    finished: Option<RunOutcome>,
}

/// The frozen inputs a fold is derived against.
///
/// Both are read before the first event: the plan the run normalized, and the
/// digest of the exact bytes it was normalized to. The fold rebuilds the
/// registry from the plan and refuses a `run_started` whose recorded digests do
/// not match, which is the whole of `refusals[4]` — a plan that moved
/// underneath a log is refused rather than folded on a guess.
#[derive(Debug, Clone)]
pub struct FrozenInputs {
    pub plan: Plan,
    /// Digest of the exact `plan.normalized.json` bytes, in the
    /// `sha256:<hex>` shape the registry digest uses.
    pub normalized_plan_digest: String,
}

/// One checked transition, ready to apply.
///
/// Deliberately opaque and deliberately unconstructible outside this module:
/// [`TopologyFold::apply_delta`] takes one of these and nothing else, so the
/// only path into the state runs through [`TopologyFold::plan_transition`].
/// That is INV-02 expressed as a type rather than as a rule two call sites are
/// asked to remember.
#[derive(Debug, Clone, PartialEq)]
pub struct TopologyDelta {
    event: TopologyEvent,
    derived: Derived,
}

impl TopologyDelta {
    /// The event this delta applies. Readable so a caller can append the exact
    /// bytes it checked.
    pub fn event(&self) -> &TopologyEvent {
        &self.event
    }
}

/// What the check derived and the application would otherwise have to look up
/// again.
#[derive(Debug, Clone, PartialEq)]
enum Derived {
    None,
    /// The registry rebuilt from the frozen plan and this record, already
    /// authenticated against the recorded digest.
    Registry(Box<TaskRegistry>),
    /// Where an answered question returns its task to.
    Answer(QuestionOrigin),
}

/// The state of one topology run, and the only way to change it.
#[derive(Debug, Clone)]
pub struct TopologyFold {
    inputs: FrozenInputs,
    run: Option<RunState>,
    poisoned: bool,
}

impl TopologyFold {
    /// A fold over a run that has recorded nothing yet.
    pub fn new(inputs: FrozenInputs) -> Self {
        Self {
            inputs,
            run: None,
            poisoned: false,
        }
    }

    /// Fold `events` from nothing, refusing the first transition that does not
    /// apply.
    ///
    /// This *is* the live path with the append removed: one `plan_transition`
    /// and one `apply_delta` per event, in order. There is no second reader.
    ///
    /// # Errors
    ///
    /// The [`FoldError`] of the first event that does not apply.
    pub fn replay(inputs: FrozenInputs, events: &[TopologyEvent]) -> Result<Self, FoldError> {
        let mut fold = Self::new(inputs);
        for event in events {
            let delta = fold.plan_transition(event)?;
            fold.apply_delta(delta);
        }
        Ok(fold)
    }

    /// Every committed line of a topology log, in order.
    ///
    /// The newline is the commit marker: an unterminated final line is a torn
    /// tail and is dropped, exactly as [`crate::events`] drops it. A
    /// newline-terminated line that will not parse is the opposite situation —
    /// the line was committed and is not an event, which means the log was
    /// rewritten rather than appended to, and no amount of reading further
    /// recovers it.
    ///
    /// # Errors
    ///
    /// [`FoldError::RewrittenLog`] naming the first committed line that is not
    /// a valid event.
    pub fn parse_log(bytes: &[u8]) -> Result<Vec<TopologyEvent>, FoldError> {
        let committed_end = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
        let committed = std::str::from_utf8(&bytes[..committed_end]).map_err(|error| {
            FoldError::RewrittenLog {
                line: bytes[..error.valid_up_to()]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count()
                    + 1,
                detail: error.to_string(),
            }
        })?;

        let mut events = Vec::new();
        for (position, line) in committed.lines().enumerate() {
            // Every committed line is one event, including a blank or
            // whitespace-only one. refusals[23] is about the *commit marker*,
            // not about what the bytes look like: a newline-terminated line
            // that is not a valid event means the log was rewritten, and a line
            // that is empty is not a valid event. Skipping it would fold a log
            // whose physical shape nobody can account for.
            events.push(
                serde_json::from_str::<TopologyEvent>(line).map_err(|error| {
                    FoldError::RewrittenLog {
                        line: position + 1,
                        detail: error.to_string(),
                    }
                })?,
            );
        }
        Ok(events)
    }

    /// Mark this process's fold unusable after an append whose outcome is
    /// unknown.
    ///
    /// Not a state transition and not reversible. The command has already
    /// ended; what remains is to refuse everything that would derive an effect
    /// from a state this process can no longer vouch for.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn started(&self) -> Option<&RunStarted4> {
        self.run.as_ref().map(|run| &*run.started)
    }

    pub fn registry(&self) -> Option<&TaskRegistry> {
        self.run.as_ref().map(|run| &run.registry)
    }

    pub fn task(&self, key: TaskKey) -> Option<&TaskFold> {
        self.run.as_ref()?.tasks.get(key.index())
    }

    pub fn task_state(&self, key: TaskKey) -> Option<TaskState> {
        self.task(key).map(|task| task.state)
    }

    pub fn queue(&self) -> Option<&CandidateQueue> {
        self.run.as_ref().map(|run| &run.queue)
    }

    pub fn leases(&self) -> Option<&LeaseTable> {
        self.run.as_ref().map(|run| &run.leases)
    }

    pub fn transaction(&self) -> Option<&Transaction> {
        self.run.as_ref()?.transaction.as_ref()
    }

    pub fn epoch(&self) -> Option<Epoch> {
        self.run.as_ref().map(|run| run.epoch)
    }

    pub fn halted_at(&self) -> Option<TaskKey> {
        self.run.as_ref()?.halted_at
    }

    pub fn budget_stop(&self) -> Option<BudgetStop> {
        self.run.as_ref()?.budget_stop
    }

    pub fn finished(&self) -> Option<&RunOutcome> {
        self.run.as_ref()?.finished.as_ref()
    }

    /// This run's folded state, or `None` before its `run_started`.
    ///
    /// The value two folds are compared as: a live fold and a replay of the
    /// bytes it appended hold the same `RunState` or INV-02 does not hold.
    pub fn state(&self) -> Option<&RunState> {
        self.run.as_ref()
    }

    pub fn open_questions(&self) -> Option<&BTreeMap<QuestionId, OpenQuestion>> {
        self.run.as_ref().map(|run| &run.questions)
    }

    pub fn binding_override(&self, key: TaskKey) -> Option<&BindingOverride> {
        self.run.as_ref()?.overrides.get(&key)
    }

    // -----------------------------------------------------------------------
    // The transition
    // -----------------------------------------------------------------------

    /// Whether `event` may be applied to this state, and what applying it does.
    ///
    /// # Errors
    ///
    /// The [`FoldError`] naming what the event disagrees with. A refusal is a
    /// statement about the pair — this event against this state — and never a
    /// statement that the event is malformed in isolation, which is
    /// serialization's business.
    pub fn plan_transition(&self, event: &TopologyEvent) -> Result<TopologyDelta, FoldError> {
        // refusals[24]: a process whose fold is poisoned by a returned append
        // error attempts no further transition. The command has already ended.
        if self.poisoned {
            return Err(FoldError::Poisoned);
        }
        let kind = event.body.kind();
        match &event.body {
            TopologyEventBody::RunStarted { data } => {
                let registry = self.check_run_started(data)?;
                Ok(self.delta(event, Derived::Registry(Box::new(registry))))
            }
            _ => {
                let run = self.run.as_ref().ok_or(FoldError::NotStarted { kind })?;
                self.check_started_run(run, event, kind)
            }
        }
    }

    /// Apply a checked transition. Total: every value it needs was decided by
    /// the check that produced the delta.
    pub fn apply_delta(&mut self, delta: TopologyDelta) {
        let TopologyDelta { event, derived } = delta;
        if let (TopologyEventBody::RunStarted { data }, Derived::Registry(registry)) =
            (&event.body, &derived)
        {
            self.run = Some(RunState::start(data.clone(), (**registry).clone()));
            return;
        }
        let Some(run) = self.run.as_mut() else {
            return;
        };
        run.apply(&event.body, &derived);
    }

    fn delta(&self, event: &TopologyEvent, derived: Derived) -> TopologyDelta {
        TopologyDelta {
            event: event.clone(),
            derived,
        }
    }

    // -----------------------------------------------------------------------
    // run_started
    // -----------------------------------------------------------------------

    fn check_run_started(&self, started: &RunStarted4) -> Result<TaskRegistry, FoldError> {
        if self.run.is_some() {
            return Err(FoldError::AlreadyStarted);
        }
        if !started.is_topology_schema() {
            return Err(FoldError::NotTopologySchema {
                schema: started.schema,
            });
        }
        // refusals[5], first half: the record must name everything needed to
        // re-establish the runner. The digest is not required — it is the
        // manifest digest when the runtime reported one (INV-23).
        started
            .runner
            .completeness()
            .map_err(|defect| FoldError::IncompleteRunner {
                defect: defect.to_string(),
            })?;

        // refusals[4]: both digests, against the bytes this reader was handed.
        if started.normalized_plan_digest != self.inputs.normalized_plan_digest {
            return Err(FoldError::DigestMismatch {
                what: "normalized plan",
                recorded: started.normalized_plan_digest.clone(),
                actual: self.inputs.normalized_plan_digest.clone(),
            });
        }
        let registry = TaskRegistry::originals_with_agents(
            &self.inputs.plan,
            &started.registry_record(),
            &started.probed_agents,
        )
        .map_err(|error| FoldError::RegistryUnbuildable {
            detail: error.to_string(),
        })?;
        let actual = registry.digest();
        if actual != started.registry_digest {
            return Err(FoldError::DigestMismatch {
                what: "registry",
                recorded: started.registry_digest.clone(),
                actual,
            });
        }

        // Ladder validation at the fold boundary: a malformed ladder is refused
        // before it is stored, not when something tries to climb it.
        for entry in registry.entries() {
            check_ladder(entry.key, &entry.ladder)?;
        }
        Ok(registry)
    }

    // -----------------------------------------------------------------------
    // Everything after run_started
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_lines)]
    fn check_started_run(
        &self,
        run: &RunState,
        event: &TopologyEvent,
        kind: &'static str,
    ) -> Result<TopologyDelta, FoldError> {
        // refusals[21]: a Complete or Halted run is finalized and then refused,
        // never continued. A Parked or BudgetExceeded run continues, and the
        // only event that continues it is the resume that opens the next epoch.
        if let Some(outcome) = run.finished.clone() {
            match outcome {
                RunOutcome::Complete | RunOutcome::Halted => {
                    return Err(FoldError::RunIsOver {
                        kind,
                        outcome: outcome_name(&outcome),
                    });
                }
                RunOutcome::Parked | RunOutcome::BudgetExceeded => {
                    if !matches!(event.body, TopologyEventBody::RunResumed { .. }) {
                        return Err(FoldError::RunIsOver {
                            kind,
                            outcome: outcome_name(&outcome),
                        });
                    }
                }
            }
        }

        match &event.body {
            TopologyEventBody::RunStarted { .. } => Err(FoldError::AlreadyStarted),
            TopologyEventBody::RunResumed { data } => run
                .check_run_resumed(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::TaskSpawned { data } => run
                .check_spawn(&data.spawn, kind)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::TaskDispatched { data } => run
                .check_dispatched(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::AttemptStarted { data } => run
                .check_attempt_started(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::AttemptFinished { data } => run
                .check_attempt_finished(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::AttemptInterrupted { data } => run
                .check_attempt_interrupted(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::GenerationClosed { data } => run
                .check_generation_closed(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::DeferWaitElapsed { .. } => run
                .check_defer_wait_elapsed()
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::CandidatePrepared { data } => run
                .check_candidate_prepared(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::TaskCandidateCreated { data } => run
                .check_candidate_created(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::MergeVerificationStarted { data } => run
                .check_verification_started(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::MergeVerificationUnavailable { data } => run
                .check_verification_unavailable(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::MergeVerificationInterrupted { data } => run
                .check_verification_interrupted(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::MergePrepared { data } => run
                .check_merge_prepared(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::MergeRejected { data } => run
                .check_merge_rejected(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::TaskMerged { data } => run
                .check_task_merged(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::QuestionRaised { data } => run
                .check_question_raised(&data.question)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::QuestionAnswered { data } => run
                .check_question_answered(data)
                .map(|origin| self.delta(event, Derived::Answer(origin))),
            TopologyEventBody::BudgetExceeded { data } => run
                .check_budget_exceeded(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::RunFinished { data } => run
                .check_run_finished(data)
                .map(|()| self.delta(event, Derived::None)),
            TopologyEventBody::CapacitySnapshot { .. }
            | TopologyEventBody::PoolExhausted { .. }
            | TopologyEventBody::DesignDefect { .. } => Ok(self.delta(event, Derived::None)),
        }
    }

    // -----------------------------------------------------------------------
    // The derived outcome
    // -----------------------------------------------------------------------

    /// The total outcome function (`decisions.run_end_policy.derived_outcome`).
    ///
    /// Computed from durable state alone: no spend, no capacity, no runner
    /// availability, no clock. The legacy precedence is preserved —
    /// halt > budget > parked > complete — and pending backoff makes `Parked`
    /// and `Complete` [`DerivedOutcome::NotEnding`] without ever blocking
    /// `Halted` or `BudgetExceeded`.
    ///
    /// A run that has not started is [`DerivedOutcome::NotEnding`]: nothing has
    /// been recorded, so nothing has ended.
    pub fn derived_outcome(&self) -> DerivedOutcome {
        self.run
            .as_ref()
            .map_or(DerivedOutcome::NotEnding, RunState::derived_outcome)
    }
}

fn outcome_name(outcome: &RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Complete => "complete",
        RunOutcome::Parked => "parked",
        RunOutcome::Halted => "halted",
        RunOutcome::BudgetExceeded => "budget exceeded",
    }
}

/// Whether a frozen ladder is one an attempt could actually climb.
///
/// Fold-boundary work rather than registry work: the registry derives a ladder
/// from whatever the run recorded, and this decides whether that ladder may
/// enter a fold's state. Both malformations it names are invisible to the
/// registry — a floor above its ceiling clips to nothing on the first
/// escalation, and a tier list that does not ascend makes "the next rung" mean
/// two different things depending on whether it is read by position or by tier.
fn check_ladder(key: TaskKey, ladder: &FrozenLadder) -> Result<(), FoldError> {
    let malformed = |defect: String| FoldError::MalformedLadder { key: key.0, defect };

    if let (Some(floor), Some(ceiling)) = (ladder.floor, ladder.ceiling) {
        if floor > ceiling {
            return Err(malformed(format!(
                "its floor is `{floor}` and its ceiling is `{ceiling}`, so no tier satisfies both"
            )));
        }
    }
    if ladder.attempts_per == 0 {
        return Err(malformed(
            "it allows 0 attempts per rung, so no attempt is ever permitted".to_owned(),
        ));
    }
    let mut previous: Option<Tier> = None;
    for tier in &ladder.tiers {
        if let Some(previous) = previous {
            if *tier <= previous {
                return Err(malformed(format!(
                    "its tiers are recorded as `{}`, which does not escalate: `{tier}` does not \
                     outrank `{previous}`",
                    ladder
                        .tiers
                        .iter()
                        .map(Tier::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        previous = Some(*tier);
    }
    if ladder.ceiling != ladder.tiers.iter().copied().max() {
        return Err(malformed(format!(
            "its recorded ceiling is {:?} and its highest rung is {:?}",
            ladder.ceiling.map(|tier| tier.to_string()),
            ladder
                .tiers
                .iter()
                .copied()
                .max()
                .map(|tier| tier.to_string())
        )));
    }
    match &ladder.admission {
        Admission::Runnable => {
            if ladder.rungs.is_empty() {
                return Err(malformed(
                    "it is admitted as runnable and has no rungs, so there is no binding to run"
                        .to_owned(),
                ));
            }
        }
        Admission::HumanBinding { options } => {
            if !ladder.rungs.is_empty() {
                return Err(malformed(
                    "it waits for a human binding and already has rungs, so two authorities name \
                     what runs"
                        .to_owned(),
                ));
            }
            if options.is_empty() {
                return Err(malformed(
                    "it waits for a human binding and offers no agent to choose from".to_owned(),
                ));
            }
        }
    }
    if !ladder.rungs.is_empty() && ladder.rungs.len() != ladder.tiers.len() {
        return Err(malformed(format!(
            "it has {} rung binding(s) for {} tier(s)",
            ladder.rungs.len(),
            ladder.tiers.len()
        )));
    }
    for (rung, tier) in ladder.rungs.iter().zip(&ladder.tiers) {
        if rung.tier != *tier {
            return Err(malformed(format!(
                "its `{tier}` rung is bound at `{}`",
                rung.tier
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RunState: the checks
// ---------------------------------------------------------------------------

impl RunState {
    fn start(started: Box<RunStarted4>, registry: TaskRegistry) -> Self {
        let tasks = (0..registry.len()).map(|_| TaskFold::new()).collect();
        let incarnation = started.incarnation.clone();
        Self {
            started,
            registry,
            tasks,
            epoch: Epoch(0),
            incarnation,
            questions: BTreeMap::new(),
            seen_questions: BTreeSet::new(),
            overrides: BTreeMap::new(),
            queue: CandidateQueue::new(),
            leases: LeaseTable::new(),
            transaction: None,
            next_sequence: 0,
            halted_at: None,
            halted_epoch: None,
            budget_stop: None,
            finished: None,
        }
    }

    fn entry(&self, kind: &'static str, key: TaskKey) -> Result<&TaskEntry, FoldError> {
        self.registry
            .get(key)
            .ok_or(FoldError::UnknownKey { kind, key: key.0 })
    }

    fn task(&self, kind: &'static str, key: TaskKey) -> Result<&TaskFold, FoldError> {
        self.tasks
            .get(key.index())
            .ok_or(FoldError::UnknownKey { kind, key: key.0 })
    }

    /// The pipeline entitlement this state holds.
    fn pipeline_held(&self) -> usize {
        self.tasks
            .iter()
            .filter(|task| {
                task.open()
                    .is_some_and(|generation| generation.class.holds_pipeline())
            })
            .count()
            + usize::from(self.transaction.is_some())
    }

    fn run_is_ending(&self) -> bool {
        self.halted_at.is_some() || self.budget_stop_is_current()
    }

    fn budget_stop_is_current(&self) -> bool {
        self.budget_stop
            .is_some_and(|stop| stop.epoch == self.epoch)
    }

    fn open_question_for(&self, key: TaskKey) -> Option<&OpenQuestion> {
        self.questions
            .values()
            .find(|open| open.question.key == key)
    }

    // --- run_resumed -------------------------------------------------------

    fn check_run_resumed(&self, resumed: &RunResumed4) -> Result<(), FoldError> {
        // refusals[5], second half: exact equality, field for field (INV-23).
        if let Some(field) = self.started.runner.difference(&resumed.runner) {
            return Err(FoldError::RunnerMoved {
                field: field.to_string(),
            });
        }
        Ok(())
    }

    // --- task_spawned ------------------------------------------------------

    fn check_spawn(&self, spawn: &FrozenSpawn, kind: &'static str) -> Result<(), FoldError> {
        let malformed = |detail: String| FoldError::MalformedEntry {
            kind,
            key: spawn.key.0,
            detail,
        };
        // refusals[10]: a dynamic task's key is the registry's length at the
        // event that registers it.
        if spawn.key.index() != self.registry.len() {
            return Err(FoldError::NonDenseKey {
                kind,
                key: spawn.key.0,
                len: self.registry.len(),
            });
        }
        let entry = &spawn.entry;
        if entry.key != spawn.key {
            return Err(malformed(format!(
                "the embedded entry calls itself {} and the event registers {}",
                entry.key, spawn.key
            )));
        }
        if self.registry.key_of(entry.display_id.as_str()).is_some() {
            return Err(malformed(format!(
                "the display id `{}` already names another task",
                entry.display_id
            )));
        }
        let Some(lineage) = entry.lineage else {
            return Err(malformed(
                "a registered task descends from the rejection that produced it, and this one \
                 records no lineage"
                    .to_owned(),
            ));
        };
        if lineage.root >= spawn.key || lineage.parent >= spawn.key {
            return Err(malformed(format!(
                "its lineage names root {} and parent {}, and a key may only refer backwards from \
                 {}",
                lineage.root, lineage.parent, spawn.key
            )));
        }
        // The allow-list is the run's, not the registering event's: an entry
        // that widened it would admit an agent pre-flight never probed.
        if entry.allowed_agents != self.started.probed_agents {
            return Err(malformed(format!(
                "it allows {:?} and this run probed {:?}",
                entry.allowed_agents, self.started.probed_agents
            )));
        }
        // Dependencies: every one exists, refers backwards, and the display
        // list is the same list.
        if entry.deps.len() != entry.display_deps.len() {
            return Err(malformed(format!(
                "it records {} dependency key(s) and {} display dependency(ies)",
                entry.deps.len(),
                entry.display_deps.len()
            )));
        }
        for (dep, display) in entry.deps.iter().zip(&entry.display_deps) {
            if *dep >= spawn.key {
                return Err(malformed(format!(
                    "it depends on {dep}, which is not registered before it"
                )));
            }
            let known = self.entry(kind, *dep)?;
            if known.display_id != *display {
                return Err(malformed(format!(
                    "it names dependency {dep} as `{display}`, and that key is `{}`",
                    known.display_id
                )));
            }
            // A repair rebases work that was already integrated; a dependency
            // that is not merged has nothing for it to build on.
            if self.task(kind, *dep)?.state != TaskState::Merged {
                return Err(malformed(format!(
                    "it depends on {dep}, which is `{}` — a repair's dependencies are merged \
                     before it is registered",
                    self.task(kind, *dep)?.state.name()
                )));
            }
        }
        check_ladder(spawn.key, &entry.ladder)?;
        self.check_admission(spawn, &malformed)?;
        Ok(())
    }

    /// The registered entry's admission and the event's must be the same
    /// statement about the same task.
    fn check_admission<F>(&self, spawn: &FrozenSpawn, malformed: &F) -> Result<(), FoldError>
    where
        F: Fn(String) -> FoldError,
    {
        match (&spawn.admission, &spawn.entry.ladder.admission) {
            (SpawnAdmission::Runnable, Admission::Runnable) => {}
            (SpawnAdmission::HumanRequired { limit, .. }, Admission::Runnable) => {
                if *limit != self.started.limits.max_merge_repairs {
                    return Err(malformed(format!(
                        "it reports the automatic-repair limit as {limit} and this run froze {}",
                        self.started.limits.max_merge_repairs
                    )));
                }
            }
            (
                SpawnAdmission::HumanBinding { options, .. },
                Admission::HumanBinding {
                    options: frozen, ..
                },
            ) => {
                if options != frozen {
                    return Err(malformed(
                        "the event and the entry offer different bindings to choose from"
                            .to_owned(),
                    ));
                }
            }
            (event, _) => {
                return Err(malformed(format!(
                    "its admission is `{}` and its entry's is `{}`",
                    spawn_admission_name(event),
                    admission_name(&spawn.entry.ladder.admission)
                )));
            }
        }
        if let Some(question) = spawn.admission.question() {
            self.check_new_question("task_spawned", question, spawn.key)?;
        }
        Ok(())
    }

    fn check_new_question(
        &self,
        kind: &'static str,
        question: &FrozenQuestion,
        key: TaskKey,
    ) -> Result<(), FoldError> {
        if !question.is_complete() {
            return Err(FoldError::UnanswerableQuestion {
                kind,
                detail: format!(
                    "`{}` has no identity, no context, or no options, so the task it parks has no \
                     way to continue",
                    question.id
                ),
            });
        }
        if question.key != key {
            return Err(FoldError::UnanswerableQuestion {
                kind,
                detail: format!(
                    "`{}` is keyed to task {} and this event parks task {key}",
                    question.id, question.key
                ),
            });
        }
        if self.seen_questions.contains(&question.id) {
            return Err(FoldError::WrongQuestion {
                kind,
                question: question.id.to_string(),
                detail: "this log has already used that identity; a question is asked once"
                    .to_owned(),
            });
        }
        Ok(())
    }

    // --- task_dispatched ---------------------------------------------------

    fn check_dispatched(&self, dispatched: &TaskDispatched) -> Result<(), FoldError> {
        const KIND: &str = "task_dispatched";
        let entry = self.entry(KIND, dispatched.key)?;
        let task = self.task(KIND, dispatched.key)?;

        if task.state != TaskState::Pending {
            return Err(FoldError::WrongTaskState {
                kind: KIND,
                key: dispatched.key.0,
                state: task.state.name(),
                expected: "pending",
            });
        }
        if let Some(open) = task.open() {
            return Err(FoldError::NotTheOpenGeneration {
                kind: KIND,
                key: dispatched.key.0,
                generation: dispatched.generation.0,
                detail: format!("generation {} is still {}", open.id.0, open.class.name()),
            });
        }
        // refusals[10]: generations are dense per task.
        if usize::try_from(dispatched.generation.0).unwrap_or(usize::MAX) != task.generations.len()
        {
            return Err(FoldError::NonDenseKey {
                kind: KIND,
                key: dispatched.generation.0,
                len: task.generations.len(),
            });
        }

        let is_repair = entry.lineage.is_some();
        match (&dispatched.lease, entry.lineage) {
            (LeaseGrant::Predicted { .. }, None) => {}
            (LeaseGrant::InheritedLineage { root }, Some(lineage)) => {
                if *root != lineage.root {
                    return Err(FoldError::MalformedEntry {
                        kind: KIND,
                        key: dispatched.key.0,
                        detail: format!(
                            "it executes inside lineage {root} and its entry descends from {}",
                            lineage.root
                        ),
                    });
                }
            }
            (LeaseGrant::Predicted { .. }, Some(_)) => {
                return Err(FoldError::MalformedEntry {
                    kind: KIND,
                    key: dispatched.key.0,
                    detail: "a repair takes no lease of its own; it executes inside the lineage \
                             lease its root already holds"
                        .to_owned(),
                });
            }
            (LeaseGrant::InheritedLineage { .. }, None) => {
                return Err(FoldError::MalformedEntry {
                    kind: KIND,
                    key: dispatched.key.0,
                    detail: "an ordinary task belongs to no lineage and cannot inherit one's lease"
                        .to_owned(),
                });
            }
        }
        if is_repair != dispatched.source_candidate.is_some() {
            return Err(FoldError::MalformedEntry {
                kind: KIND,
                key: dispatched.key.0,
                detail: if is_repair {
                    "a repair is materialized from the candidate its lineage rejected, and this \
                     dispatch names none"
                        .to_owned()
                } else {
                    "an ordinary dispatch materializes nothing and this one names a source \
                     candidate"
                        .to_owned()
                },
            });
        }
        Ok(())
    }

    // --- attempt_started ---------------------------------------------------

    fn check_attempt_started(&self, started: &AttemptStarted4) -> Result<(), FoldError> {
        const KIND: &str = "attempt_started";
        let entry = self.entry(KIND, started.key)?;
        let task = self.task(KIND, started.key)?;
        let generation = self.open_generation(KIND, task, started.key, started.generation)?;

        // ST-06: a retry names the generation it is retrying, and a fresh
        // attempt names one nothing has run in yet.
        match (&generation.class, &started.resume_session) {
            (GenerationClass::OpenNoAttempt, None) => {}
            (
                GenerationClass::RetainedIdle {
                    session,
                    incarnation,
                },
                Some(resumed),
            ) => {
                // refusals[12]: a session belongs to the incarnation that
                // retained it, and only that incarnation may resume it.
                if session != resumed {
                    return Err(FoldError::StaleIncarnation {
                        key: started.key.0,
                        attempt: started.attempt.0,
                        detail: format!(
                            "it resumes session `{resumed}` and the generation retained `{session}`"
                        ),
                    });
                }
                if *incarnation != self.epoch {
                    return Err(FoldError::StaleIncarnation {
                        key: started.key.0,
                        attempt: started.attempt.0,
                        detail: format!(
                            "the session was retained by incarnation {} and this run has resumed \
                             {} time(s)",
                            incarnation.0, self.epoch.0
                        ),
                    });
                }
            }
            (class, resumed) => {
                return Err(FoldError::NotTheOpenGeneration {
                    kind: KIND,
                    key: started.key.0,
                    generation: started.generation.0,
                    detail: if resumed.is_some() {
                        format!(
                            "it resumes a session and the generation is {}, not retained idle",
                            class.name()
                        )
                    } else {
                        format!(
                            "the generation is {} and a fresh attempt starts in one nothing has \
                             run in",
                            class.name()
                        )
                    },
                });
            }
        }

        // ST-06: attempts are dense from 1 within a generation.
        if started.attempt.0 != generation.attempts + 1 {
            return Err(FoldError::WrongAttempt {
                kind: KIND,
                key: started.key.0,
                generation: started.generation.0,
                attempt: started.attempt.0,
                expected: (generation.attempts + 1).to_string(),
            });
        }

        // refusals[11] / INV-19: the binding is the override when one was
        // recorded, and the frozen rung binding otherwise.
        let mismatch = |detail: String| FoldError::BindingMismatch {
            key: started.key.0,
            attempt: started.attempt.0,
            detail,
        };
        if let Some(binding) = self.overrides.get(&started.key) {
            if !started.binding.matches_override(binding) {
                return Err(mismatch(format!(
                    "a human named `{}`/`{}` at effort `{}` for this task and it ran `{}`/`{}` at \
                     effort `{}`",
                    binding.agent,
                    binding.model,
                    binding.effort,
                    started.binding.agent,
                    started.binding.model,
                    started.binding.effort
                )));
            }
        } else {
            let rung = usize::try_from(started.rung).unwrap_or(usize::MAX);
            let frozen = entry.ladder.rungs.get(rung).ok_or_else(|| {
                mismatch(format!(
                    "it climbs rung {rung} of a ladder with {} rung(s)",
                    entry.ladder.rungs.len()
                ))
            })?;
            let effort = entry.ladder.effort.implementation_for(frozen.tier);
            if !started.binding.matches_frozen(frozen, effort) {
                return Err(mismatch(format!(
                    "rung {rung} is frozen as `{}`/`{}` at tier `{}` effort `{}` and it ran \
                     `{}`/`{}` at tier `{}` effort `{}`",
                    frozen.agent,
                    frozen.model,
                    frozen.tier,
                    effort,
                    started.binding.agent,
                    started.binding.model,
                    started.binding.tier,
                    started.binding.effort
                )));
            }
        }

        if entry.lineage.is_some() != started.materialization_observed.is_some() {
            return Err(FoldError::MalformedEntry {
                kind: KIND,
                key: started.key.0,
                detail: if entry.lineage.is_some() {
                    "a repair's attempt records what its worktree was materialized from".to_owned()
                } else {
                    "an ordinary attempt materializes nothing".to_owned()
                },
            });
        }
        Ok(())
    }

    /// The open generation this event must be naming (ST-06).
    fn open_generation<'a>(
        &self,
        kind: &'static str,
        task: &'a TaskFold,
        key: TaskKey,
        generation: GenerationId,
    ) -> Result<&'a GenerationFold, FoldError> {
        let open = task.open().ok_or_else(|| FoldError::NotTheOpenGeneration {
            kind,
            key: key.0,
            generation: generation.0,
            detail: "no generation of this task is open".to_owned(),
        })?;
        if open.id != generation {
            return Err(FoldError::NotTheOpenGeneration {
                kind,
                key: key.0,
                generation: generation.0,
                detail: format!("generation {} is the open one", open.id.0),
            });
        }
        Ok(open)
    }

    /// The open generation, additionally required to be running `attempt`.
    fn in_flight<'a>(
        &self,
        kind: &'static str,
        task: &'a TaskFold,
        key: TaskKey,
        generation: GenerationId,
        attempt: AttemptNumber,
    ) -> Result<&'a GenerationFold, FoldError> {
        let open = self.open_generation(kind, task, key, generation)?;
        let GenerationClass::InFlight { attempt: running } = &open.class else {
            return Err(FoldError::NotTheOpenGeneration {
                kind,
                key: key.0,
                generation: generation.0,
                detail: format!(
                    "the generation is {}, and no attempt is running",
                    open.class.name()
                ),
            });
        };
        if *running != attempt {
            return Err(FoldError::WrongAttempt {
                kind,
                key: key.0,
                generation: generation.0,
                attempt: attempt.0,
                expected: running.0.to_string(),
            });
        }
        Ok(open)
    }

    // --- attempt_finished --------------------------------------------------

    fn check_attempt_finished(&self, finished: &AttemptFinished4) -> Result<(), FoldError> {
        const KIND: &str = "attempt_finished";
        let task = self.task(KIND, finished.key)?;
        let generation = self.in_flight(
            KIND,
            task,
            finished.key,
            finished.generation,
            finished.attempt,
        )?;

        match &finished.settlement {
            AttemptSettlement::Retained {
                retained_incarnation,
                ..
            } => {
                if *retained_incarnation != self.epoch {
                    return Err(FoldError::StaleIncarnation {
                        key: finished.key.0,
                        attempt: finished.attempt.0,
                        detail: format!(
                            "it retains the session for incarnation {} and this run has resumed \
                             {} time(s)",
                            retained_incarnation.0, self.epoch.0
                        ),
                    });
                }
            }
            AttemptSettlement::Closed { transition, lease } => {
                let survives = matches!(transition, SettlementTransition::Succeeded);
                check_lease_disposition(KIND, finished.key, generation.lease, survives, *lease)?;
                if let SettlementTransition::Parked { question } = transition {
                    self.check_new_question(KIND, question, finished.key)?;
                }
            }
        }
        Ok(())
    }

    // --- attempt_interrupted -----------------------------------------------

    fn check_attempt_interrupted(
        &self,
        interrupted: &AttemptInterrupted4,
    ) -> Result<(), FoldError> {
        const KIND: &str = "attempt_interrupted";
        let task = self.task(KIND, interrupted.key)?;
        let generation = self.in_flight(
            KIND,
            task,
            interrupted.key,
            interrupted.generation,
            interrupted.attempt,
        )?;
        // The generation does *not* survive an interruption.
        // `transaction_fault_matrix[T-ATTEMPT].resume_action` is explicit:
        // "append attempt_interrupted (unknown spend, allowance refunded,
        // generation Closed, lease by kind) ... task returns Pending; later
        // dispatch new generation". Nothing was judged and the spend is
        // unknown, so the worktree is scrubbed with force rather than reused —
        // which is why an ordinary generation releases its predicted region
        // here and a lineage member goes on holding its root's.
        check_lease_disposition(
            KIND,
            interrupted.key,
            generation.lease,
            false,
            interrupted.lease,
        )
    }

    // --- generation_closed -------------------------------------------------

    fn check_generation_closed(&self, closed: &GenerationClosed) -> Result<(), FoldError> {
        const KIND: &str = "generation_closed";
        let task = self.task(KIND, closed.key)?;
        let generation = self.open_generation(KIND, task, closed.key, closed.generation)?;
        // refusals[15]: an open generation with no attempt in flight. A
        // promoting generation is not closed — it is promoted.
        match generation.class {
            GenerationClass::OpenNoAttempt | GenerationClass::RetainedIdle { .. } => {}
            ref class => {
                return Err(FoldError::NotTheOpenGeneration {
                    kind: KIND,
                    key: closed.key.0,
                    generation: closed.generation.0,
                    detail: format!(
                        "it is {}, and a generation is closed only from open-with-no-attempt or \
                         retained-idle",
                        class.name()
                    ),
                });
            }
        }
        check_lease_disposition(KIND, closed.key, generation.lease, false, closed.lease)
    }

    // --- defer_wait_elapsed ------------------------------------------------

    fn check_defer_wait_elapsed(&self) -> Result<(), FoldError> {
        // refusals[18]: halt and budget outrank backoff, so no wait elapses
        // under either.
        if self.halted_at.is_some() {
            return Err(FoldError::RunEnding {
                kind: "defer_wait_elapsed",
                what: "a halting settlement",
            });
        }
        if self.budget_stop_is_current() {
            return Err(FoldError::RunEnding {
                kind: "defer_wait_elapsed",
                what: "the budget stop",
            });
        }
        Ok(())
    }

    // --- candidate_prepared ------------------------------------------------

    fn check_candidate_prepared(&self, prepared: &CandidatePrepared) -> Result<(), FoldError> {
        const KIND: &str = "candidate_prepared";
        let entry = self.entry(KIND, prepared.key)?;
        let task = self.task(KIND, prepared.key)?;
        let generation = self.open_generation(KIND, task, prepared.key, prepared.generation)?;
        if generation.class != GenerationClass::Promoting {
            return Err(FoldError::NotTheOpenGeneration {
                kind: KIND,
                key: prepared.key.0,
                generation: prepared.generation.0,
                detail: format!(
                    "the generation is {}, and a candidate is prepared by a generation whose \
                     attempt succeeded",
                    generation.class.name()
                ),
            });
        }
        // INV-06: "at most one candidate per generation", enforced_by "fold
        // refuses a second candidate for a generation". Refused here, before
        // any lease or candidate-state mutation could be planned: a second
        // record would replace the first and hand a later
        // `task_candidate_created` a candidate the queue never saw prepared.
        if generation.candidate.is_some() {
            return Err(FoldError::NotTheOpenGeneration {
                kind: KIND,
                key: prepared.key.0,
                generation: prepared.generation.0,
                detail: "the generation has already prepared a candidate, and one generation \
                         prepares at most one"
                    .to_owned(),
            });
        }
        // ST-06: a candidate is prepared *by the attempt that succeeded*, so
        // the embedded record names the generation's current attempt. Without
        // this the record is inert data and a candidate can be published
        // attributed to an attempt that did not produce it.
        if prepared.attempt.attempt != generation.attempts {
            return Err(FoldError::WrongAttempt {
                kind: KIND,
                key: prepared.key.0,
                generation: prepared.generation.0,
                attempt: prepared.attempt.attempt,
                expected: generation.attempts.to_string(),
            });
        }
        // INV-09 depends on this: the exact-base decision compares the
        // integration head against `base_sha` and then publishes `commit_sha`,
        // so a commit parented anywhere else would fast-forward the integration
        // ref onto history nobody judged.
        if !prepared.parent_is_base() {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: format!(
                    "the candidate is parented on {} and the work started from {}",
                    prepared.parent_sha, prepared.base_sha
                ),
            });
        }
        if prepared.base_sha != generation.base_sha {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: format!(
                    "it records base {} and generation {} was dispatched at {}",
                    prepared.base_sha, prepared.generation.0, generation.base_sha
                ),
            });
        }
        match (&prepared.lease_effect, entry.lineage) {
            (CandidateLeaseEffect::ReplacesPredicted { paths }, None) => {
                if *paths != prepared.actual_paths {
                    return Err(FoldError::InconsistentRecord {
                        kind: KIND,
                        detail: "the region it takes is not the region its diff touched".to_owned(),
                    });
                }
            }
            (CandidateLeaseEffect::WidensLineage { root, paths }, Some(lineage)) => {
                if *root != lineage.root {
                    return Err(FoldError::InconsistentRecord {
                        kind: KIND,
                        detail: format!(
                            "it widens lineage {root} and its task descends from {}",
                            lineage.root
                        ),
                    });
                }
                if *paths != prepared.actual_paths {
                    return Err(FoldError::InconsistentRecord {
                        kind: KIND,
                        detail: "the region it widens by is not the region its diff touched"
                            .to_owned(),
                    });
                }
            }
            _ => {
                return Err(FoldError::InconsistentRecord {
                    kind: KIND,
                    detail: "a lineage member widens its lineage and an ordinary candidate \
                             replaces its predicted region; this does the other one"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    // --- task_candidate_created --------------------------------------------

    fn check_candidate_created(&self, created: &TaskCandidateCreated) -> Result<(), FoldError> {
        const KIND: &str = "task_candidate_created";
        let candidate = &created.candidate;
        let task = self.task(KIND, candidate.key)?;
        let generation = self.open_generation(KIND, task, candidate.key, candidate.generation)?;
        // ST-06: a mismatched task_candidate_created.
        let prepared = match &generation.candidate {
            Some(prepared) if generation.class == GenerationClass::Promoting => prepared,
            _ => {
                return Err(FoldError::NotTheOpenGeneration {
                    kind: KIND,
                    key: candidate.key.0,
                    generation: candidate.generation.0,
                    detail: format!(
                        "the generation is {} and has prepared no candidate",
                        generation.class.name()
                    ),
                });
            }
        };
        if prepared.candidate != *candidate {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: format!(
                    "it promotes commit {} at `{}` and the prepared candidate is {} at `{}`",
                    candidate.commit_sha,
                    candidate.candidate_ref,
                    prepared.candidate.commit_sha,
                    prepared.candidate.candidate_ref
                ),
            });
        }
        Ok(())
    }

    // --- integration: starting a transaction --------------------------------

    /// The checks every first append of an integration transaction shares:
    /// nothing else is open, the sequence is the next dense one, and the
    /// candidate is the first *eligible* entry in the queue.
    fn check_transaction_start(
        &self,
        kind: &'static str,
        sequence: SequenceId,
        candidate: &CandidateRef,
    ) -> Result<&QueueEntry, FoldError> {
        // refusals[7]: one integration transaction at a time.
        if let Some(open) = &self.transaction {
            return Err(FoldError::TransactionAlreadyOpen {
                kind,
                sequence: sequence.0,
                open: open.sequence.0,
            });
        }
        // refusals[6] / refusals[10]: sequences are dense from 0 across the run.
        if sequence.0 != self.next_sequence {
            return Err(FoldError::NonDenseSequence {
                kind,
                sequence: sequence.0,
                next: self.next_sequence,
            });
        }
        // refusals[8]: the first eligible entry is integrated, and the fold
        // refuses an integration start for any other candidate.
        let first = self
            .queue
            .first_eligible(
                |key| self.task_is_awaiting_input(key),
                &self.leases,
                &self.started.path_policy,
            )
            .ok_or_else(|| FoldError::NotFirstEligible {
                kind,
                key: candidate.key.0,
                generation: candidate.generation.0,
                detail: "no queued candidate is eligible".to_owned(),
            })?;
        if first.candidate != *candidate {
            let detail = self
                .queue
                .get(candidate.key, candidate.generation)
                .map_or_else(
                    || "it holds no queue position at all".to_owned(),
                    |entry| {
                        CandidateQueue::ineligible(
                            entry,
                            &|key| self.task_is_awaiting_input(key),
                            &self.leases,
                            &self.started.path_policy,
                        )
                        .map_or_else(
                            || {
                                format!(
                                    "task {} generation {} is queued ahead of it and eligible",
                                    first.key().0,
                                    first.generation().0
                                )
                            },
                            |why| format!("it is not eligible: {}", ineligible_detail(why)),
                        )
                    },
                );
            return Err(FoldError::NotFirstEligible {
                kind,
                key: candidate.key.0,
                generation: candidate.generation.0,
                detail,
            });
        }
        Ok(first)
    }

    fn task_is_awaiting_input(&self, key: TaskKey) -> bool {
        self.tasks
            .get(key.index())
            .is_some_and(|task| task.state == TaskState::AwaitingInput)
    }

    /// The open transaction this event must belong to (refusals[6]).
    fn open_transaction(
        &self,
        kind: &'static str,
        sequence: SequenceId,
    ) -> Result<&Transaction, FoldError> {
        let open = self
            .transaction
            .as_ref()
            .ok_or_else(|| FoldError::WrongSequence {
                kind,
                sequence: sequence.0,
                open: "none".to_owned(),
            })?;
        if open.sequence != sequence {
            return Err(FoldError::WrongSequence {
                kind,
                sequence: sequence.0,
                open: open.sequence.0.to_string(),
            });
        }
        Ok(open)
    }

    // --- merge_verification_started ----------------------------------------

    fn check_verification_started(
        &self,
        started: &MergeVerificationStarted,
    ) -> Result<(), FoldError> {
        const KIND: &str = "merge_verification_started";
        let queued = self.check_transaction_start(KIND, started.sequence, &started.candidate)?;
        let prepared = self.prepared_candidate(KIND, &started.candidate)?;

        // INV-09: the exact-base decision is made before any staging effect, so
        // a candidate whose base *is* the head is published fast and is never
        // cherry-picked or re-verified.
        if started.expected_head == prepared.base_sha {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: format!(
                    "the head is {} and the candidate's base is the same commit, which is the \
                     exact-base case and publishes the candidate itself",
                    started.expected_head
                ),
            });
        }
        let _ = queued;
        match &started.basis {
            VerificationBasis::AlreadyPresent => {
                if started.proposed_sha != started.expected_head {
                    return Err(FoldError::InconsistentRecord {
                        kind: KIND,
                        detail: format!(
                            "an already-present verification judges the head itself, and this one \
                             judges {} against head {}",
                            started.proposed_sha, started.expected_head
                        ),
                    });
                }
            }
            VerificationBasis::StaleClean { .. } => {
                if started.proposed_sha == started.expected_head {
                    return Err(FoldError::InconsistentRecord {
                        kind: KIND,
                        detail: "a stale-clean verification judges the proposal the cherry-pick \
                                 produced, and this one judges the head"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// What `candidate_prepared` recorded for this candidate.
    fn prepared_candidate(
        &self,
        kind: &'static str,
        candidate: &CandidateRef,
    ) -> Result<&PreparedCandidate, FoldError> {
        let task = self.task(kind, candidate.key)?;
        task.generations
            .iter()
            .filter_map(|generation| generation.candidate.as_ref())
            .find(|prepared| prepared.candidate.generation == candidate.generation)
            .filter(|prepared| prepared.candidate == *candidate)
            .ok_or_else(|| FoldError::InconsistentRecord {
                kind,
                detail: format!(
                    "no `candidate_prepared` in this log records task {} generation {} as commit \
                     {}",
                    candidate.key.0, candidate.generation.0, candidate.commit_sha
                ),
            })
    }

    // --- merge_verification_unavailable ------------------------------------

    fn check_verification_unavailable(
        &self,
        unavailable: &MergeVerificationUnavailable,
    ) -> Result<(), FoldError> {
        const KIND: &str = "merge_verification_unavailable";
        let transaction = self.open_transaction(KIND, unavailable.sequence)?;
        if !matches!(
            transaction.class,
            TransactionClass::VerificationStarted { .. }
        ) {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: "the transaction is already authorized to publish; an outage refuses a \
                         verification that is still running"
                    .to_owned(),
            });
        }
        unavailable
            .self_consistency()
            .map_err(|defect| FoldError::InconsistentRecord {
                kind: KIND,
                detail: defect.to_string(),
            })?;

        let queued = self
            .queue
            .get(transaction.candidate.key, transaction.candidate.generation)
            .ok_or_else(|| FoldError::InconsistentRecord {
                kind: KIND,
                detail: "the candidate under verification holds no queue position".to_owned(),
            })?;
        // The boundary is the same number read from both sides: the deferral
        // this outage *would* be. `coordinator_integration.dispositions` gives
        // Infrastructure `Deferred{defers}` while `defers < max_defers` and
        // `Parked{question}` at `max_defers`, so the two arms partition on
        // `next` and neither may take the other's cell.
        let max = self.started.limits.max_defers;
        let next = queued.defers.saturating_add(1);
        match &unavailable.outcome {
            UnavailableOutcome::Deferred { defers } => {
                // refusals[17]: consecutive, and within the frozen allowance.
                if *defers != next {
                    return Err(FoldError::InvalidDefers {
                        defers: *defers,
                        detail: format!(
                            "this candidate has been deferred {} time(s), so the next deferral is \
                             {next}",
                            queued.defers,
                        ),
                    });
                }
                // refusals[16]: "Deferred at max_defers" is refused. The
                // allowance is the number of deferrals the run may *take*, so
                // the last one it may take is `max_defers - 1` and the outage
                // that would be the `max_defers`th parks instead.
                if *defers >= max {
                    return Err(FoldError::InvalidDefers {
                        defers: *defers,
                        detail: format!(
                            "this run allows {max}, and the {max}th outage parks rather than \
                             defers"
                        ),
                    });
                }
            }
            UnavailableOutcome::Parked { question } => {
                self.check_new_question(KIND, question, transaction.candidate.key)?;
                // refusals[16], the other half: `HumanRequired` always parks,
                // whatever the count, and an Infrastructure outage parks
                // exactly at the boundary — one earlier would consume an
                // allowance the run still has.
                if matches!(unavailable.cause, UnavailableCause::Infrastructure { .. })
                    && next != max
                {
                    return Err(FoldError::InvalidDefers {
                        defers: next,
                        detail: format!(
                            "an infrastructure outage parks at {max} deferral(s) and this \
                             candidate has been deferred {} time(s), so this one defers",
                            queued.defers
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    // --- merge_verification_interrupted ------------------------------------

    fn check_verification_interrupted(
        &self,
        interrupted: &MergeVerificationInterrupted,
    ) -> Result<(), FoldError> {
        const KIND: &str = "merge_verification_interrupted";
        let transaction = self.open_transaction(KIND, interrupted.sequence)?;
        if !matches!(
            transaction.class,
            TransactionClass::VerificationStarted { .. }
        ) {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: "the transaction is already authorized to publish; an authorized \
                         publication is completed, never abandoned"
                    .to_owned(),
            });
        }
        Ok(())
    }

    // --- merge_prepared ----------------------------------------------------

    fn check_merge_prepared(&self, prepared: &MergePrepared) -> Result<(), FoldError> {
        const KIND: &str = "merge_prepared";
        // A1's intra-event relations first: a record that disagrees with itself
        // is refused before it is compared with anything else.
        prepared
            .self_consistency()
            .map_err(|defect| FoldError::InconsistentRecord {
                kind: KIND,
                detail: defect.to_string(),
            })?;

        let candidate_record = self.prepared_candidate(KIND, &prepared.candidate())?;
        let inconsistent = |detail: String| FoldError::InconsistentRecord { kind: KIND, detail };

        match prepared.disposition {
            PreparedDisposition::Fast => {
                // A fast publication opens and closes its own transaction: no
                // verification ran, so there is nothing already open.
                self.check_transaction_start(KIND, prepared.sequence, &prepared.candidate())?;
                // refusals[9]: expected_head == the candidate's recorded base,
                // proposed_sha == the candidate's recorded commit.
                if prepared.expected_head != candidate_record.base_sha {
                    return Err(inconsistent(format!(
                        "a fast publication expects the head to be the candidate's base {} and \
                         this one expects {}",
                        candidate_record.base_sha, prepared.expected_head
                    )));
                }
                if prepared.proposed_sha != candidate_record.candidate.commit_sha {
                    return Err(inconsistent(format!(
                        "it publishes {} and the candidate's recorded commit is {}",
                        prepared.proposed_sha, candidate_record.candidate.commit_sha
                    )));
                }
                match &prepared.verification_source {
                    VerificationSource::CandidatePrepared { key, generation } => {
                        if *key != prepared.key || *generation != prepared.generation {
                            return Err(inconsistent(format!(
                                "it cites the record of task {} generation {} and publishes task \
                                 {} generation {}",
                                key.0, generation.0, prepared.key.0, prepared.generation.0
                            )));
                        }
                    }
                    VerificationSource::Verification { .. } => {
                        return Err(inconsistent(
                            "a fast publication cites the candidate's own record".to_owned(),
                        ));
                    }
                }
            }
            PreparedDisposition::StaleClean | PreparedDisposition::AlreadyPresent => {
                let transaction = self.open_transaction(KIND, prepared.sequence)?;
                let TransactionClass::VerificationStarted {
                    basis,
                    expected_head,
                    proposed_sha,
                } = &transaction.class
                else {
                    return Err(inconsistent(
                        "the transaction is already authorized to publish".to_owned(),
                    ));
                };
                if transaction.candidate != prepared.candidate() {
                    return Err(inconsistent(format!(
                        "it publishes task {} generation {} and the open transaction is verifying \
                         task {} generation {}",
                        prepared.key.0,
                        prepared.generation.0,
                        transaction.candidate.key.0,
                        transaction.candidate.generation.0
                    )));
                }
                let stale = prepared.disposition == PreparedDisposition::StaleClean;
                if stale != matches!(basis, VerificationBasis::StaleClean { .. }) {
                    return Err(inconsistent(
                        "the disposition it publishes under is not the basis its verification ran \
                         on"
                        .to_owned(),
                    ));
                }
                // refusals[22], fold half: the head the CAS expects is the head
                // the transaction read.
                if prepared.expected_head != *expected_head {
                    return Err(inconsistent(format!(
                        "it expects head {} and the verification recorded head {expected_head}",
                        prepared.expected_head
                    )));
                }
                // refusals[9]: the proposal is the one that was verified — the
                // pinned proposal for a stale publication, the head itself for
                // an already-present one.
                if prepared.proposed_sha != *proposed_sha {
                    return Err(inconsistent(format!(
                        "it publishes {} and the verification judged {proposed_sha}",
                        prepared.proposed_sha
                    )));
                }
                if let VerificationBasis::StaleClean { prepared_ref } = basis {
                    if prepared.prepared_ref.as_ref() != Some(prepared_ref) {
                        return Err(inconsistent(format!(
                            "it pins the proposal at {:?} and the verification pinned it at `{}`",
                            prepared.prepared_ref.as_ref().map(GitRefName::name),
                            prepared_ref
                        )));
                    }
                }
                match &prepared.verification_source {
                    VerificationSource::Verification { sequence } => {
                        if *sequence != prepared.sequence {
                            return Err(inconsistent(format!(
                                "it cites verification {} and belongs to transaction {}",
                                sequence.0, prepared.sequence.0
                            )));
                        }
                    }
                    VerificationSource::CandidatePrepared { .. } => {
                        return Err(inconsistent(
                            "a verified publication cites the verification that judged what it \
                             publishes"
                                .to_owned(),
                        ));
                    }
                }
            }
        }

        // refusals[10]: the closure this publication settles is derived, not
        // asserted.
        let derived = self.satisfies_closure(prepared.key);
        if prepared.satisfies != derived {
            return Err(FoldError::InvalidSatisfies {
                kind: KIND,
                recorded: prepared.satisfies.iter().map(|key| key.0).collect(),
                derived: derived.iter().map(|key| key.0).collect(),
            });
        }
        Ok(())
    }

    /// Every task one publication settles: the candidate's own task and, for a
    /// repair, every entry back up its lineage to the root.
    ///
    /// A repair carries the work of everything it descends from — that is what
    /// it was materialized from — so publishing it settles the whole chain.
    /// Ascending key order, because the value is derived and two readers must
    /// derive the same list.
    fn satisfies_closure(&self, key: TaskKey) -> Vec<TaskKey> {
        let mut chain = vec![key];
        let mut current = key;
        while let Some(lineage) = self.registry.get(current).and_then(|entry| entry.lineage) {
            if lineage.parent >= current {
                break;
            }
            chain.push(lineage.parent);
            current = lineage.parent;
        }
        chain.sort_unstable();
        chain.dedup();
        chain
    }

    // --- merge_rejected ----------------------------------------------------

    fn check_merge_rejected(&self, rejected: &MergeRejected) -> Result<(), FoldError> {
        const KIND: &str = "merge_rejected";
        let inconsistent = |detail: String| FoldError::InconsistentRecord { kind: KIND, detail };
        match &rejected.disposition {
            RejectionDisposition::Conflict { .. } => {
                // A conflict is decided at the cherry-pick, before any
                // verification starts: it opens and closes its own transaction.
                self.check_transaction_start(KIND, rejected.sequence, &rejected.candidate)?;
            }
            RejectionDisposition::CodeRejected { verification } => {
                let transaction = self.open_transaction(KIND, rejected.sequence)?;
                let TransactionClass::VerificationStarted { expected_head, .. } =
                    &transaction.class
                else {
                    return Err(inconsistent(
                        "the transaction is already authorized to publish".to_owned(),
                    ));
                };
                if transaction.candidate != rejected.candidate {
                    return Err(inconsistent(format!(
                        "it rejects task {} generation {} and the open transaction is verifying \
                         task {} generation {}",
                        rejected.candidate.key.0,
                        rejected.candidate.generation.0,
                        transaction.candidate.key.0,
                        transaction.candidate.generation.0
                    )));
                }
                if rejected.rejecting_head != *expected_head {
                    return Err(inconsistent(format!(
                        "it was judged against head {} and the verification recorded head \
                         {expected_head}",
                        rejected.rejecting_head
                    )));
                }
                if verification.verdict == VerificationVerdict::Passed {
                    return Err(inconsistent(
                        "a code rejection carries the verification that rejected it, and this one \
                         passed"
                            .to_owned(),
                    ));
                }
            }
        }

        // The lease effect and the repair are one decision: a non-lineage
        // candidate's lease becomes the new lineage's, and a lineage member's
        // rejection widens the lineage it already belongs to.
        let entry = self.entry(KIND, rejected.candidate.key)?;
        let root = match (&rejected.lease_effect, entry.lineage) {
            (RejectionLeaseEffect::CreatesLineage { root, .. }, None) => {
                if *root != rejected.candidate.key {
                    return Err(inconsistent(format!(
                        "it creates lineage {root} from the rejection of task {}",
                        rejected.candidate.key.0
                    )));
                }
                *root
            }
            (RejectionLeaseEffect::WidensLineage { root, .. }, Some(lineage)) => {
                if *root != lineage.root {
                    return Err(inconsistent(format!(
                        "it widens lineage {root} and the rejected task descends from {}",
                        lineage.root
                    )));
                }
                *root
            }
            _ => {
                return Err(inconsistent(
                    "a rejection creates a lineage from an ordinary candidate and widens the \
                     lineage of a member; this does the other one"
                        .to_owned(),
                ));
            }
        };

        self.check_spawn(&rejected.repair, KIND)?;
        let lineage =
            rejected.repair.entry.lineage.ok_or_else(|| {
                inconsistent("the repair it registers records no lineage".to_owned())
            })?;
        if lineage.root != root {
            return Err(inconsistent(format!(
                "the repair descends from lineage {} and the rejection widens {root}",
                lineage.root
            )));
        }
        if lineage.parent != rejected.candidate.key {
            return Err(inconsistent(format!(
                "the repair's parent is {} and the rejected candidate is task {}",
                lineage.parent, rejected.candidate.key.0
            )));
        }
        let index = self.lineage_members(root);
        if lineage.index != index {
            return Err(inconsistent(format!(
                "the repair is the {} member of lineage {root} and records index {}",
                ordinal(index),
                lineage.index
            )));
        }
        Ok(())
    }

    /// How many repairs lineage `root` already holds.
    fn lineage_members(&self, root: TaskKey) -> u32 {
        u32::try_from(
            self.registry
                .entries()
                .iter()
                .filter(|entry| entry.lineage.is_some_and(|lineage| lineage.root == root))
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    // --- task_merged -------------------------------------------------------

    fn check_task_merged(&self, merged: &TaskMerged) -> Result<(), FoldError> {
        const KIND: &str = "task_merged";
        let transaction = self.open_transaction(KIND, merged.sequence)?;
        let TransactionClass::Prepared {
            proposed_sha,
            satisfies,
        } = &transaction.class
        else {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: "the integration ref moves only after `merge_prepared`, and this \
                         transaction has not authorized a publication"
                    .to_owned(),
            });
        };
        if merged.merged_sha != *proposed_sha {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: format!(
                    "the ref now points at {} and the authorization proposed {proposed_sha}",
                    merged.merged_sha
                ),
            });
        }
        // "copied exactly from the authorization", not re-derived here.
        if merged.satisfies != *satisfies {
            return Err(FoldError::InvalidSatisfies {
                kind: KIND,
                recorded: merged.satisfies.iter().map(|key| key.0).collect(),
                derived: satisfies.iter().map(|key| key.0).collect(),
            });
        }
        let root_settled = self
            .registry
            .get(transaction.candidate.key)
            .and_then(|entry| entry.lineage)
            .map(|lineage| lineage.root);
        match (&merged.lease_release, root_settled) {
            (MergeLeaseRelease::Candidate { key, generation }, None) => {
                if *key != transaction.candidate.key
                    || *generation != transaction.candidate.generation
                {
                    return Err(FoldError::InconsistentRecord {
                        kind: KIND,
                        detail: format!(
                            "it releases the lease of task {} generation {} and publishes task {} \
                             generation {}",
                            key.0,
                            generation.0,
                            transaction.candidate.key.0,
                            transaction.candidate.generation.0
                        ),
                    });
                }
            }
            (MergeLeaseRelease::Lineage { root }, Some(settled)) => {
                if *root != settled {
                    return Err(FoldError::InconsistentRecord {
                        kind: KIND,
                        detail: format!("it releases lineage {root} and settles lineage {settled}"),
                    });
                }
            }
            _ => {
                return Err(FoldError::InconsistentRecord {
                    kind: KIND,
                    detail: "a publication releases the candidate's lease, or the lineage lease \
                             when it settles that lineage's root; this releases the other one"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    // --- questions ---------------------------------------------------------

    fn check_question_raised(&self, question: &FrozenQuestion) -> Result<(), FoldError> {
        const KIND: &str = "question_raised";
        self.entry(KIND, question.key)?;
        self.check_new_question(KIND, question, question.key)
    }

    fn check_question_answered(
        &self,
        answered: &QuestionAnswered4,
    ) -> Result<QuestionOrigin, FoldError> {
        const KIND: &str = "question_answered";
        // refusals[20]: answers are not ingested in an epoch after a halting
        // settlement or a budget stop.
        if self.halted_epoch == Some(self.epoch) {
            return Err(FoldError::RunEnding {
                kind: KIND,
                what: "a halting settlement",
            });
        }
        if self.budget_stop_is_current() {
            return Err(FoldError::RunEnding {
                kind: KIND,
                what: "the budget stop",
            });
        }
        // refusals[13], A1's half: the answer must agree with itself.
        answered
            .self_consistency()
            .map_err(|defect| FoldError::InconsistentRecord {
                kind: KIND,
                detail: defect.to_string(),
            })?;

        let open =
            self.questions
                .get(&answered.question)
                .ok_or_else(|| FoldError::WrongQuestion {
                    kind: KIND,
                    question: answered.question.to_string(),
                    detail: if self.seen_questions.contains(&answered.question) {
                        "has already been answered; a question is answered once".to_owned()
                    } else {
                        "this log never asked".to_owned()
                    },
                })?;
        if open.question.key != answered.key {
            return Err(FoldError::WrongQuestion {
                kind: KIND,
                question: answered.question.to_string(),
                detail: format!(
                    "was asked about task {} and this answers it for task {}",
                    open.question.key, answered.key
                ),
            });
        }
        if let Answer4::Answered {
            option_index,
            binding_override,
        } = &answered.answer
        {
            let options = open.question.options.len();
            let chosen = usize::try_from(*option_index).unwrap_or(usize::MAX);
            if chosen >= options {
                return Err(FoldError::WrongQuestion {
                    kind: KIND,
                    question: answered.question.to_string(),
                    detail: format!("offered {options} option(s) and this chose {option_index}"),
                });
            }
            // refusals[12] / `task_registry.binding_override`: an override is
            // validated "against the frozen options of that task's open
            // HumanBinding question". A1's `self_consistency` has already
            // proved the override names this answer's task, question and
            // option; what is left — and what no other check makes — is that
            // there *is* such an authority and that the agent it names is the
            // one that authority froze at that index.
            match (binding_override, &open.binding) {
                (Some(_), None) => {
                    return Err(FoldError::WrongQuestion {
                        kind: KIND,
                        question: answered.question.to_string(),
                        detail: "carries a binding override and did not ask for a binding; only a \
                                 HumanBinding admission authorizes one"
                            .to_owned(),
                    });
                }
                (None, Some(_)) => {
                    return Err(FoldError::WrongQuestion {
                        kind: KIND,
                        question: answered.question.to_string(),
                        detail: "asked for a binding and this answer names none, so its task has \
                                 no binding to run"
                            .to_owned(),
                    });
                }
                (Some(binding), Some(authorized)) => {
                    let Some(agent) = authorized.get(chosen) else {
                        return Err(FoldError::WrongQuestion {
                            kind: KIND,
                            question: answered.question.to_string(),
                            detail: format!(
                                "authorized {} binding(s) and this chose {option_index}",
                                authorized.len()
                            ),
                        });
                    };
                    if binding.agent != *agent {
                        return Err(FoldError::WrongQuestion {
                            kind: KIND,
                            question: answered.question.to_string(),
                            detail: format!(
                                "authorized `{agent}` at option {option_index} and the override \
                                 names `{}`",
                                binding.agent
                            ),
                        });
                    }
                }
                (None, None) => {}
            }
        }
        Ok(open.origin)
    }

    // --- budget_exceeded ---------------------------------------------------

    fn check_budget_exceeded(&self, exceeded: &BudgetExceeded4) -> Result<(), FoldError> {
        const KIND: &str = "budget_exceeded";
        if let Some(key) = exceeded.key {
            self.entry(KIND, key)?;
        }
        if exceeded.epoch != self.epoch {
            return Err(FoldError::InconsistentRecord {
                kind: KIND,
                detail: format!(
                    "it belongs to epoch {} and this run is in epoch {}",
                    exceeded.epoch.0, self.epoch.0
                ),
            });
        }
        Ok(())
    }

    // --- run_finished ------------------------------------------------------

    fn check_run_finished(&self, finished: &RunFinished4) -> Result<(), FoldError> {
        // refusals[19] / INV-15: the recorded outcome is the derived one, and
        // the derived one is not NotEnding.
        let derived = self.derived_outcome();
        let matches = match &derived {
            DerivedOutcome::Ending(outcome) => *outcome == finished.outcome,
            DerivedOutcome::NotEnding | DerivedOutcome::FoldError => false,
        };
        if !matches {
            return Err(FoldError::OutcomeMismatch {
                recorded: outcome_name(&finished.outcome),
                derived: match &derived {
                    DerivedOutcome::NotEnding => "not ending".to_owned(),
                    DerivedOutcome::Ending(outcome) => outcome_name(outcome).to_owned(),
                    DerivedOutcome::FoldError => "unreachable".to_owned(),
                },
            });
        }
        if finished.halted_at != self.halted_at {
            return Err(FoldError::InconsistentRecord {
                kind: "run_finished",
                detail: format!(
                    "it attributes the halt to {:?} and the fold recorded {:?}",
                    finished.halted_at.map(|key| key.0),
                    self.halted_at.map(|key| key.0)
                ),
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // derived_outcome
    // -----------------------------------------------------------------------

    fn derived_outcome(&self) -> DerivedOutcome {
        if !self.common() {
            return DerivedOutcome::NotEnding;
        }
        if self.halted_at.is_some() {
            return DerivedOutcome::Ending(RunOutcome::Halted);
        }
        if self.budget_stop_is_current() {
            return DerivedOutcome::Ending(RunOutcome::BudgetExceeded);
        }
        if self.structurally_admissible() || self.backoff_pending() {
            return DerivedOutcome::NotEnding;
        }
        if self.questions_open() {
            return DerivedOutcome::Ending(RunOutcome::Parked);
        }
        if self.complete_shape() {
            return DerivedOutcome::Ending(RunOutcome::Complete);
        }
        DerivedOutcome::FoldError
    }

    /// No generation is open and no integration transaction is unresolved.
    fn common(&self) -> bool {
        self.tasks.iter().all(|task| {
            task.open()
                .is_none_or(|generation| !generation.class.blocks_run_end())
        }) && self.transaction.is_none()
    }

    /// Some task could be dispatched, retried, or integrated from this state
    /// alone. Budget, capacity and runner availability are not consulted.
    fn structurally_admissible(&self) -> bool {
        (0..self.tasks.len())
            .map(|index| TaskKey(u32::try_from(index).unwrap_or(u32::MAX)))
            .any(|key| self.ready(key) || self.ready_retry(key))
            || self.integration_admissible()
    }

    fn ready(&self, key: TaskKey) -> bool {
        let (Some(task), Some(entry)) = (self.tasks.get(key.index()), self.registry.get(key))
        else {
            return false;
        };
        task.state == TaskState::Pending
            && task.open().is_none()
            && entry.deps.iter().all(|dep| {
                self.tasks
                    .get(dep.index())
                    .is_some_and(|dep| dep.state == TaskState::Merged)
            })
            && self.open_question_for(key).is_none()
            && !self.queue.holds_task(key)
            && self
                .transaction
                .as_ref()
                .is_none_or(|open| open.candidate.key != key)
            && self.dispatch_lease_check(key, entry)
            && self.pipeline_reservable()
            && !self.run_is_ending()
    }

    /// A repair dispatch is never lease-blocked; an ordinary one is blocked by
    /// any overlapping active lease of another owner.
    ///
    /// The predicted region is not in the log until the dispatch that takes it,
    /// so the check the *fold* can make is over the run's own leases: a task
    /// with a repo-wide prediction is admissible exactly when nothing is held.
    fn dispatch_lease_check(&self, key: TaskKey, entry: &TaskEntry) -> bool {
        if entry.lineage.is_some() {
            return true;
        }
        let predicted = predicted_region(entry);
        !self.leases.overlaps_another(
            LeaseOwner::Generation {
                key,
                generation: GenerationId(
                    u32::try_from(
                        self.tasks
                            .get(key.index())
                            .map_or(0, |task| task.generations.len()),
                    )
                    .unwrap_or(u32::MAX),
                ),
            },
            &predicted,
            &self.started.path_policy,
        )
    }

    fn ready_retry(&self, key: TaskKey) -> bool {
        let Some(task) = self.tasks.get(key.index()) else {
            return false;
        };
        let retained = task.open().is_some_and(|generation| {
            matches!(
                &generation.class,
                GenerationClass::RetainedIdle { incarnation, .. } if *incarnation == self.epoch
            )
        });
        task.state == TaskState::Pending
            && retained
            && self.open_question_for(key).is_none()
            && self
                .transaction
                .as_ref()
                .is_none_or(|open| open.candidate.key != key)
            && self.pipeline_reservable()
            && !self.run_is_ending()
    }

    fn pipeline_reservable(&self) -> bool {
        self.pipeline_held()
            < usize::try_from(self.started.limits.max_parallel).unwrap_or(usize::MAX)
    }

    fn integration_admissible(&self) -> bool {
        self.transaction.is_none()
            && !self.run_is_ending()
            && self
                .queue
                .first_eligible(
                    |key| self.task_is_awaiting_input(key),
                    &self.leases,
                    &self.started.path_policy,
                )
                .is_some()
    }

    fn backoff_pending(&self) -> bool {
        self.tasks
            .iter()
            .any(|task| task.state == TaskState::Deferred)
            || self
                .queue
                .entries()
                .iter()
                .any(|entry| entry.verification_deferred)
    }

    fn questions_open(&self) -> bool {
        !self.questions.is_empty()
    }

    fn complete_shape(&self) -> bool {
        let blocked = self.blocked_tasks();
        self.tasks.iter().enumerate().all(|(index, task)| {
            task.state.is_terminal()
                || (task.state == TaskState::Pending && blocked.contains(&index))
        }) && self.queue.is_empty()
            && !self.leases.any_candidate_or_lineage()
    }

    /// Every task that can never run because a failure sits in its transitive
    /// dependency closure.
    fn blocked_tasks(&self) -> BTreeSet<usize> {
        let mut blocked = BTreeSet::new();
        // To a fixed point, not in one pass. A *repair*'s dependencies refer
        // only backwards, but an original's keys are assigned in plan order
        // (`keys_by_display_id`) and plan order is not topological order, so
        // an ordinary plan can have a task depend on a later key. One forward
        // pass would then decide that task before it had decided what the task
        // waits on, and a failure two hops away would go unseen — which is the
        // difference between "directly failed dependency" and the transitive
        // closure the packet asks for.
        //
        // Each round adds at least one member or stops, and membership only
        // grows, so this runs at most `tasks.len()` rounds.
        loop {
            let mut grew = false;
            for (index, task) in self.tasks.iter().enumerate() {
                if task.state != TaskState::Pending || blocked.contains(&index) {
                    continue;
                }
                let Some(entry) = self
                    .registry
                    .get(TaskKey(u32::try_from(index).unwrap_or(u32::MAX)))
                else {
                    continue;
                };
                let poisoned = entry.deps.iter().any(|dep| {
                    blocked.contains(&dep.index())
                        || self
                            .tasks
                            .get(dep.index())
                            .is_some_and(|dep| dep.state == TaskState::Failed)
                });
                if poisoned {
                    blocked.insert(index);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        blocked
    }
}

// ---------------------------------------------------------------------------
// RunState: the application
// ---------------------------------------------------------------------------

impl RunState {
    /// Apply a transition the check accepted.
    ///
    /// Total by construction: every lookup here was proved to succeed by the
    /// check that produced the delta, and each one is written so that a miss
    /// leaves the state alone rather than panicking. Nothing in this function
    /// decides anything — a decision made here would be a decision the live
    /// path and the replay path could reach differently, which is the one thing
    /// INV-02 forbids.
    #[allow(clippy::too_many_lines)]
    fn apply(&mut self, body: &TopologyEventBody, derived: &Derived) {
        match body {
            TopologyEventBody::RunStarted { .. } => {}
            TopologyEventBody::RunResumed { data } => self.apply_resumed(data),
            TopologyEventBody::TaskSpawned { data } => self.register(&data.spawn),
            TopologyEventBody::TaskDispatched { data } => self.apply_dispatched(data),
            TopologyEventBody::AttemptStarted { data } => {
                if let Some(generation) = self.open_generation_mut(data.key) {
                    generation.class = GenerationClass::InFlight {
                        attempt: data.attempt,
                    };
                    generation.attempts = data.attempt.0;
                }
            }
            TopologyEventBody::AttemptFinished { data } => self.apply_settlement(data),
            TopologyEventBody::AttemptInterrupted { data } => {
                // T-ATTEMPT: generation Closed, task Pending, later dispatch a
                // new generation. The close releases the ordinary generation's
                // own region exactly as every other closing settlement does.
                self.close_generation(data.key);
                self.set_state(data.key, TaskState::Pending);
            }
            TopologyEventBody::GenerationClosed { data } => {
                self.close_generation(data.key);
            }
            TopologyEventBody::DeferWaitElapsed { .. } => self.wake_backoff(),
            TopologyEventBody::CandidatePrepared { data } => self.apply_candidate_prepared(data),
            TopologyEventBody::TaskCandidateCreated { data } => {
                self.apply_candidate_created(&data.candidate);
            }
            TopologyEventBody::MergeVerificationStarted { data } => {
                self.apply_verification_started(data);
            }
            TopologyEventBody::MergeVerificationUnavailable { data } => {
                self.apply_verification_unavailable(data);
            }
            TopologyEventBody::MergeVerificationInterrupted { .. } => {
                self.release_transaction();
            }
            TopologyEventBody::MergePrepared { data } => self.apply_merge_prepared(data),
            TopologyEventBody::MergeRejected { data } => self.apply_merge_rejected(data),
            TopologyEventBody::TaskMerged { data } => self.apply_task_merged(data),
            TopologyEventBody::QuestionRaised { data } => {
                // A bare `question_raised` carries no admission and so
                // authorizes no binding.
                self.open_question(&data.question, QuestionOrigin::Admission, None);
                self.set_state(data.question.key, TaskState::AwaitingInput);
            }
            TopologyEventBody::QuestionAnswered { data } => self.apply_answer(data, derived),
            TopologyEventBody::BudgetExceeded { data } => {
                if !self.budget_stop_is_current() {
                    self.budget_stop = Some(data.stop());
                }
            }
            TopologyEventBody::RunFinished { data } => {
                self.finished = Some(data.outcome.clone());
            }
            TopologyEventBody::CapacitySnapshot { .. }
            | TopologyEventBody::PoolExhausted { .. }
            | TopologyEventBody::DesignDefect { .. } => {}
        }
    }

    fn apply_resumed(&mut self, resumed: &RunResumed4) {
        self.epoch = Epoch(self.epoch.0.saturating_add(1));
        self.incarnation = resumed.incarnation.clone();
        // The stop belongs to the epoch that hit the old ceiling; the next
        // epoch starts without one, which is what makes "raise the budget and
        // resume" the response to it.
        self.budget_stop = None;
        self.finished = None;
        // Deferred items are woken by a resume exactly as they are by an
        // elapsed wait.
        self.wake_backoff();
    }

    fn wake_backoff(&mut self) {
        self.queue.wake_deferred();
        for task in &mut self.tasks {
            if task.state == TaskState::Deferred {
                task.state = TaskState::Pending;
            }
        }
    }

    fn register(&mut self, spawn: &FrozenSpawn) {
        self.registry.register(spawn.entry.clone());
        self.tasks.push(TaskFold::new());
        match &spawn.admission {
            SpawnAdmission::Runnable => {}
            SpawnAdmission::HumanRequired { question, .. } => {
                self.open_question(question, QuestionOrigin::Admission, None);
                self.set_state(spawn.key, TaskState::AwaitingInput);
            }
            SpawnAdmission::HumanBinding { options, question } => {
                // The one admission that authorizes an override, and the one
                // place its option list is frozen.
                self.open_question(question, QuestionOrigin::Admission, Some(options.clone()));
                self.set_state(spawn.key, TaskState::AwaitingInput);
            }
        }
    }

    fn apply_dispatched(&mut self, dispatched: &TaskDispatched) {
        let (lease, region) = match &dispatched.lease {
            LeaseGrant::Predicted { paths } => (GenerationLease::Own, Some(paths.clone())),
            LeaseGrant::InheritedLineage { root } => {
                (GenerationLease::InheritedLineage { root: *root }, None)
            }
        };
        if let Some(paths) = region {
            self.leases.grant(
                LeaseOwner::Generation {
                    key: dispatched.key,
                    generation: dispatched.generation,
                },
                paths,
            );
        }
        if let Some(task) = self.tasks.get_mut(dispatched.key.index()) {
            task.generations.push(GenerationFold {
                id: dispatched.generation,
                class: GenerationClass::OpenNoAttempt,
                base_sha: dispatched.base_sha.clone(),
                lease,
                attempts: 0,
                candidate: None,
            });
        }
    }

    fn apply_settlement(&mut self, finished: &AttemptFinished4) {
        match &finished.settlement {
            AttemptSettlement::Retained {
                retained_session,
                retained_incarnation,
            } => {
                if let Some(generation) = self.open_generation_mut(finished.key) {
                    generation.class = GenerationClass::RetainedIdle {
                        session: retained_session.clone(),
                        incarnation: *retained_incarnation,
                    };
                }
            }
            AttemptSettlement::Closed { transition, .. } => match transition {
                SettlementTransition::Succeeded => {
                    if let Some(generation) = self.open_generation_mut(finished.key) {
                        generation.class = GenerationClass::Promoting;
                    }
                }
                SettlementTransition::Retry | SettlementTransition::Escalated { .. } => {
                    self.close_generation(finished.key);
                }
                SettlementTransition::Deferred { .. } => {
                    self.close_generation(finished.key);
                    self.set_state(finished.key, TaskState::Deferred);
                }
                SettlementTransition::Parked { question } => {
                    self.close_generation(finished.key);
                    self.open_question(question, QuestionOrigin::Admission, None);
                    self.set_state(finished.key, TaskState::AwaitingInput);
                }
                SettlementTransition::Failed { halts_run, .. } => {
                    self.close_generation(finished.key);
                    self.set_state(finished.key, TaskState::Failed);
                    if *halts_run {
                        self.record_halt(finished.key);
                    }
                }
            },
        }
    }

    /// `halted_at` is first in wins, and is never cleared.
    fn record_halt(&mut self, key: TaskKey) {
        if self.halted_at.is_none() {
            self.halted_at = Some(key);
            self.halted_epoch = Some(self.epoch);
        }
    }

    fn apply_candidate_prepared(&mut self, prepared: &CandidatePrepared) {
        let record = PreparedCandidate {
            candidate: prepared.candidate(),
            base_sha: prepared.base_sha.clone(),
            paths: prepared.actual_paths.clone(),
        };
        if let Some(generation) = self.open_generation_mut(prepared.key) {
            generation.candidate = Some(record);
        }
        match &prepared.lease_effect {
            CandidateLeaseEffect::ReplacesPredicted { paths } => {
                self.leases.release(LeaseOwner::Generation {
                    key: prepared.key,
                    generation: prepared.generation,
                });
                self.leases.grant(
                    LeaseOwner::Candidate {
                        key: prepared.key,
                        generation: prepared.generation,
                    },
                    paths.clone(),
                );
            }
            CandidateLeaseEffect::WidensLineage { root, paths } => {
                self.leases.widen_lineage(*root, paths);
            }
        }
        self.set_state(prepared.key, TaskState::AwaitingMerge);
    }

    fn apply_candidate_created(&mut self, candidate: &CandidateRef) {
        let paths = self
            .tasks
            .get(candidate.key.index())
            .and_then(TaskFold::open)
            .and_then(|generation| generation.candidate.as_ref())
            .map_or(PathSet::RepoWide, |prepared| prepared.paths.clone());
        let lineage_root = self
            .registry
            .get(candidate.key)
            .and_then(|entry| entry.lineage)
            .map(|lineage| lineage.root);
        self.close_generation(candidate.key);
        self.queue.push(QueueEntry {
            candidate: candidate.clone(),
            paths,
            lineage_root,
            verification_deferred: false,
            defers: 0,
            sequence: None,
        });
    }

    fn apply_verification_started(&mut self, started: &MergeVerificationStarted) {
        self.next_sequence = self.next_sequence.saturating_add(1);
        if let Some(entry) = self
            .queue
            .get_mut(started.candidate.key, started.candidate.generation)
        {
            entry.sequence = Some(started.sequence);
        }
        self.transaction = Some(Transaction {
            sequence: started.sequence,
            candidate: started.candidate.clone(),
            class: TransactionClass::VerificationStarted {
                basis: started.basis.clone(),
                expected_head: started.expected_head.clone(),
                proposed_sha: started.proposed_sha.clone(),
            },
        });
    }

    fn apply_verification_unavailable(&mut self, unavailable: &MergeVerificationUnavailable) {
        let Some(transaction) = self.transaction.take() else {
            return;
        };
        let candidate = transaction.candidate;
        if let Some(entry) = self.queue.get_mut(candidate.key, candidate.generation) {
            entry.sequence = None;
            if let UnavailableOutcome::Deferred { defers } = &unavailable.outcome {
                entry.verification_deferred = true;
                entry.defers = *defers;
            }
        }
        if let UnavailableOutcome::Parked { question } = &unavailable.outcome {
            self.open_question(question, QuestionOrigin::VerificationPark, None);
            self.set_state(candidate.key, TaskState::AwaitingInput);
        }
    }

    fn release_transaction(&mut self) {
        let Some(transaction) = self.transaction.take() else {
            return;
        };
        if let Some(entry) = self
            .queue
            .get_mut(transaction.candidate.key, transaction.candidate.generation)
        {
            entry.sequence = None;
        }
    }

    fn apply_merge_prepared(&mut self, prepared: &MergePrepared) {
        if prepared.disposition == PreparedDisposition::Fast {
            self.next_sequence = self.next_sequence.saturating_add(1);
        }
        self.transaction = Some(Transaction {
            sequence: prepared.sequence,
            candidate: prepared.candidate(),
            class: TransactionClass::Prepared {
                proposed_sha: prepared.proposed_sha.clone(),
                satisfies: prepared.satisfies.clone(),
            },
        });
    }

    fn apply_merge_rejected(&mut self, rejected: &MergeRejected) {
        if matches!(rejected.disposition, RejectionDisposition::Conflict { .. }) {
            self.next_sequence = self.next_sequence.saturating_add(1);
        }
        self.transaction = None;
        let candidate = &rejected.candidate;
        self.queue.remove(candidate.key, candidate.generation);
        match &rejected.lease_effect {
            RejectionLeaseEffect::CreatesLineage { root, paths } => {
                // The rejected candidate's own holding becomes the lineage's,
                // widened by the region the conflict named.
                let held = self
                    .tasks
                    .get(candidate.key.index())
                    .and_then(|task| {
                        task.generations
                            .iter()
                            .find(|generation| generation.id == candidate.generation)
                    })
                    .and_then(|generation| generation.candidate.as_ref())
                    .map(|prepared| prepared.paths.clone());
                if let Some(held) = held {
                    self.leases.widen_lineage(*root, &held);
                }
                self.leases.widen_lineage(*root, paths);
                self.leases.release(LeaseOwner::Candidate {
                    key: candidate.key,
                    generation: candidate.generation,
                });
            }
            RejectionLeaseEffect::WidensLineage { root, paths } => {
                self.leases.widen_lineage(*root, paths);
            }
        }
        self.set_state(candidate.key, TaskState::AwaitingRepair);
        self.register(&rejected.repair);
    }

    fn apply_task_merged(&mut self, merged: &TaskMerged) {
        let Some(transaction) = self.transaction.take() else {
            return;
        };
        let candidate = transaction.candidate;
        self.queue.remove(candidate.key, candidate.generation);
        for key in &merged.satisfies {
            self.set_state(*key, TaskState::Merged);
        }
        match &merged.lease_release {
            MergeLeaseRelease::Candidate { key, generation } => {
                self.leases.release(LeaseOwner::Candidate {
                    key: *key,
                    generation: *generation,
                });
            }
            MergeLeaseRelease::Lineage { root } => {
                self.leases.release(LeaseOwner::Lineage { root: *root });
            }
        }
    }

    fn apply_answer(&mut self, answered: &QuestionAnswered4, derived: &Derived) {
        self.questions.remove(&answered.question);
        match &answered.answer {
            Answer4::Answered {
                binding_override, ..
            } => {
                if let Some(binding) = binding_override {
                    self.overrides.insert(answered.key, binding.clone());
                }
                let state = match derived {
                    Derived::Answer(QuestionOrigin::VerificationPark) => TaskState::AwaitingMerge,
                    _ => TaskState::Pending,
                };
                self.set_state(answered.key, state);
            }
            Answer4::Declined { decline_halts_run } => {
                self.set_state(answered.key, TaskState::Failed);
                self.release_holdings_of(answered.key);
                if *decline_halts_run {
                    self.record_halt(answered.key);
                }
            }
        }
    }

    /// A declined question consumes the task's queue position and releases what
    /// it held: its candidate lease, or the lineage lease when the task belongs
    /// to a lineage — a declined lineage fails as a whole.
    fn release_holdings_of(&mut self, key: TaskKey) {
        let generations: Vec<GenerationId> = self
            .tasks
            .get(key.index())
            .map(|task| {
                task.generations
                    .iter()
                    .map(|generation| generation.id)
                    .collect()
            })
            .unwrap_or_default();
        for generation in generations {
            self.queue.remove(key, generation);
            self.leases
                .release(LeaseOwner::Candidate { key, generation });
        }
        let root = self
            .registry
            .get(key)
            .and_then(|entry| entry.lineage)
            .map(|lineage| lineage.root);
        if let Some(root) = root {
            self.leases.release(LeaseOwner::Lineage { root });
        } else if self.leases.holds(LeaseOwner::Lineage { root: key }) {
            self.leases.release(LeaseOwner::Lineage { root: key });
        }
    }

    /// Open a question, carrying the binding authority it was asked under.
    ///
    /// `binding` is `Some` for a `HumanBinding` admission and `None` for every
    /// other question this run can ask — a `HumanRequired` admission, a parked
    /// settlement, a verification park, a bare `question_raised`. That is the
    /// whole of what an override may be validated against.
    fn open_question(
        &mut self,
        question: &FrozenQuestion,
        origin: QuestionOrigin,
        binding: Option<Vec<String>>,
    ) {
        self.seen_questions.insert(question.id.clone());
        self.questions.insert(
            question.id.clone(),
            OpenQuestion {
                question: question.clone(),
                origin,
                binding,
            },
        );
    }

    fn set_state(&mut self, key: TaskKey, state: TaskState) {
        if let Some(task) = self.tasks.get_mut(key.index()) {
            task.state = state;
        }
    }

    fn open_generation_mut(&mut self, key: TaskKey) -> Option<&mut GenerationFold> {
        self.tasks.get_mut(key.index())?.open_mut()
    }

    /// Close the open generation, releasing the region it held on its own.
    fn close_generation(&mut self, key: TaskKey) {
        let Some(generation) = self.open_generation_mut(key) else {
            return;
        };
        let id = generation.id;
        let own = generation.lease == GenerationLease::Own;
        generation.class = GenerationClass::Closed;
        if own {
            self.leases.release(LeaseOwner::Generation {
                key,
                generation: id,
            });
        }
    }
}

/// The region an ordinary dispatch of this entry would predict.
///
/// The plan's path hints, taken literally: a hint with no glob metacharacter is
/// its own literal prefix. Anything else — an absent hint list, or a hint whose
/// literal prefix is empty — classifies repo-wide, which overlaps everything.
fn predicted_region(entry: &TaskEntry) -> PathSet {
    if entry.spec.path_hints.is_empty() {
        return PathSet::RepoWide;
    }
    let mut paths = Vec::with_capacity(entry.spec.path_hints.len());
    for hint in &entry.spec.path_hints {
        let literal: String = hint
            .replace('\\', "/")
            .chars()
            .take_while(|character| !matches!(character, '*' | '?' | '[' | '{'))
            .collect();
        let trimmed = literal.trim_end_matches('/');
        if trimmed.is_empty() {
            return PathSet::RepoWide;
        }
        paths.push(GitPath(trimmed.to_owned()));
    }
    PathSet::Prefixes { paths }
}

/// A ref name, for a diagnostic that has to print an `Option<GitRef>`.
trait GitRefName {
    fn name(&self) -> &str;
}

impl GitRefName for GitRef {
    fn name(&self) -> &str {
        self.as_str()
    }
}

fn ineligible_detail(why: Ineligible) -> String {
    match why {
        Ineligible::AwaitingInput => "its task is parked on a question".to_owned(),
        Ineligible::VerificationDeferred => {
            "its verification is deferred until the backoff elapses".to_owned()
        }
        Ineligible::InsideLineage { root } => {
            format!("it overlaps the region lineage {root} holds")
        }
        Ineligible::BehindOlderLineage { root } => {
            format!("it overlaps the region the older lineage {root} holds")
        }
    }
}

fn spawn_admission_name(admission: &SpawnAdmission) -> &'static str {
    match admission {
        SpawnAdmission::Runnable => "runnable",
        SpawnAdmission::HumanRequired { .. } => "human-required",
        SpawnAdmission::HumanBinding { .. } => "human-binding",
    }
}

fn admission_name(admission: &Admission) -> &'static str {
    match admission {
        Admission::Runnable => "runnable",
        Admission::HumanBinding { .. } => "human-binding",
    }
}

fn ordinal(index: u32) -> String {
    format!("#{index}")
}

/// refusals[14]: the disposition an event records must be the one this
/// generation's holding admits.
fn check_lease_disposition(
    kind: &'static str,
    key: TaskKey,
    lease: GenerationLease,
    survives: bool,
    recorded: LeaseDisposition,
) -> Result<(), FoldError> {
    let expected = lease.expected(survives);
    if recorded == expected {
        return Ok(());
    }
    Err(FoldError::InvalidLeaseDisposition {
        kind,
        key: key.0,
        recorded: format!("{recorded:?}"),
        owner: match lease {
            GenerationLease::Own => "leaseholding",
            GenerationLease::InheritedLineage { .. } => "lineage",
        },
        fate: if survives { "stays open" } else { "closes" },
        expected: format!("{expected:?}"),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::events::{
        AttemptRecord, BindingSummary, BudgetKind, CapacitySnapshot, ChainSummary, DesignDefect,
        GateSummary, PoolExhausted, PoolSnapshot, ReviewPassOutcome, ReviewRecord,
    };
    use crate::gates::ShellKind;
    use crate::ir::{
        Artifact, ArtifactId, Effort, PlanSource, QuestionKind, ResolvedEffortPolicy, Task, TaskId,
        TaskKind, Usage,
    };
    use crate::review::{PassBinding, ReviewPlan};
    use crate::topology::events::{
        DeferWaitElapsed4, GenerationCloseReason, ImageIdentity, InfrastructureKind,
        Materialization, QuestionRaised4, RungBinding, RunnerContract, RunnerKind, RunnerPolicy,
        TOPOLOGY_EVENT_KINDS, TaskSpawned, TopologyLimits, UnavailableCause, VerificationRecord,
        VerificationVerdict as Verdict,
    };
    use crate::topology::leases::regions_overlap;
    use crate::topology::paths::{PathGrammar, PathPolicy, PathPolicyVersion};
    use crate::topology::registry::{FrozenReviews, FrozenRung, FrozenTaskSpec, Lineage, Origin};
    use crate::topology::schema::TOPOLOGY_SCHEMA;

    const RUN_ID: &str = "01FOLD0000000000000000000A";

    /// One way to damage an otherwise valid record, for the refusal tables.
    type BreakRunner = fn(&mut RunnerPolicy);
    type BreakLadder = fn(&mut FrozenLadder);
    type BreakFrozenInputs = fn(&mut Plan, &mut ChainSummary);
    type BreakSpawn = fn(&mut FrozenSpawn);
    type BreakBinding = fn(&mut RungBinding);
    type BreakPublication = fn(&mut MergePrepared);

    /// One coordinate of an embedded candidate identity, forged.
    type ForgeCandidate = fn(&mut MergePrepared);

    /// One residue a Complete run refuses to leave behind.
    type AddResidue = fn(&mut RunState);
    type BreakRejection = fn(&mut MergeRejected);
    const ZETA: TaskKey = TaskKey(0);
    const ALPHA: TaskKey = TaskKey(1);
    const MID: TaskKey = TaskKey(2);

    // -----------------------------------------------------------------------
    // Fixtures
    //
    // Every independently meaningful field varies independently. Nothing sits
    // at a default, no two fields that could be read for one another hold the
    // same value, and every list that has an order is written in one that is
    // neither sorted nor reversed. Where a value could be confused with
    // another of its type — a commit sha with a tree sha, a task's floor with
    // its ceiling, one epoch with another — the two are different literals.
    // -----------------------------------------------------------------------

    /// A distinct 40-character hex-shaped sha per label.
    ///
    /// Distinct per role rather than per value: a base, a parent, a tree, a
    /// commit and a head are five different claims, and a fixture that let any
    /// two of them share a literal would pass under a relation that compared
    /// the wrong pair.
    fn sha(label: &str) -> CommitSha {
        let mut value: String = label
            .bytes()
            .map(|byte| char::from(b'a' + byte % 6))
            .collect();
        value.push_str(&"0".repeat(40));
        value.truncate(40);
        CommitSha(value)
    }

    fn git_ref(name: &str) -> GitRef {
        GitRef(format!("refs/tactus/runs/{RUN_ID}/{name}"))
    }

    /// The agents this run's pre-flight probed: padded, mixed case, multi-byte
    /// and over-length, in an order that is neither sorted nor reversed, and
    /// deliberately a superset of the agents the ladders bind.
    fn probed_agents() -> Vec<String> {
        vec![
            "  Codex-CLI  ".to_owned(),
            "ÜBER-agent-Ωmega".to_owned(),
            "claude-code".to_owned(),
            "z".repeat(200),
            "copilot".to_owned(),
        ]
    }

    fn task_of(id: &str, deps: &[&str], hints: &[&str], min_tier: Option<Tier>) -> Task {
        Task {
            id: TaskId::from(id),
            kind: match id {
                "zeta" => TaskKind::Fix,
                "alpha" => TaskKind::Refactor,
                _ => TaskKind::Test,
            },
            title: format!("  {id} — Ünicode title  "),
            body: format!("{id} body, {}", "long ".repeat(20)),
            depends_on: deps.iter().copied().map(TaskId::from).collect(),
            acceptance: vec![format!("{id} passes"), "and keeps passing".to_owned()],
            path_hints: hints.iter().copied().map(str::to_owned).collect(),
            suggested_tier: match id {
                "zeta" => Some(Tier::Frontier),
                "alpha" => None,
                _ => Some(Tier::Small),
            },
            min_tier,
            artifacts_in: vec![ArtifactId::from("contract")],
            artifacts_out: vec![ArtifactId::from(format!("{id}-out").as_str())],
        }
    }

    /// Plan order, display-id order and topological order all disagree, and the
    /// three tasks touch three disjoint regions so that a lease check has
    /// something to be wrong about in both directions.
    fn plan() -> Plan {
        Plan {
            source: PlanSource {
                adapter: "markdown".to_owned(),
                hash: "frozen-Ünicode-hash".to_owned(),
            },
            tasks: vec![
                task_of("zeta", &["alpha"], &["src/Zebra/"], Some(Tier::Small)),
                task_of("alpha", &[], &["src/alpha/*.rs"], None),
                task_of(
                    "mid",
                    &["alpha", "zeta"],
                    &["src/mid/", "build.rs"],
                    Some(Tier::Mid),
                ),
            ],
            artifacts: vec![Artifact {
                id: ArtifactId::from("contract"),
                produced_by: Some(TaskId::from("alpha")),
            }],
        }
    }

    /// A ladder that belongs to one task and to no other: different length,
    /// different attempts allowance, and every rung's agent, model and pin
    /// derived from the task's own id.
    fn chain(task: &str) -> ChainSummary {
        let tiers = match task {
            "zeta" => vec![Tier::Small, Tier::Mid, Tier::Frontier],
            "alpha" => vec![Tier::Mid],
            _ => vec![Tier::Small, Tier::Frontier],
        };
        ChainSummary {
            task: task.to_owned(),
            attempts_per: match task {
                "zeta" => 2,
                "alpha" => 3,
                _ => 1,
            },
            bindings: Some(
                tiers
                    .iter()
                    .map(|tier| BindingSummary {
                        tier: *tier,
                        agent: format!("{task}-{tier}-agent"),
                        model: format!("{task}-{tier}-model"),
                        pinned: *tier == Tier::Frontier,
                    })
                    .collect(),
            ),
            tiers,
        }
    }

    /// Four distinct efforts, so a rung bound at the wrong tier's effort is a
    /// different value rather than the same one.
    fn effort_policy() -> ResolvedEffortPolicy {
        ResolvedEffortPolicy {
            small: Effort::Low,
            mid: Effort::XHigh,
            frontier: Effort::Max,
            review: Effort::Medium,
        }
    }

    fn review_plan(tasks: usize) -> ReviewPlan {
        ReviewPlan {
            enabled: Some(true),
            alternative_available: Some(true),
            pass_timeout_secs: Some(1_337),
            primary: Some(PassBinding::new("claude-code", "claude-opus-5")),
            alternative: Some(PassBinding::new("copilot", "gpt-5.6")),
            second_opinion: (0..tasks)
                .map(|index| (index == 2).then(|| PassBinding::new("second-agent", "second-model")))
                .collect(),
        }
    }

    fn gate_summaries() -> Vec<GateSummary> {
        vec![GateSummary {
            name: "  Clippy Ünicode  ".to_owned(),
            cmd: "cargo clippy -- -D warnings".to_owned(),
            timeout: Duration::from_secs(909),
            shell: ShellKind::Bash,
        }]
    }

    fn path_policy() -> PathPolicy {
        PathPolicy {
            version: PathPolicyVersion::V1,
            case_fold: true,
            grammar: PathGrammar::Globset,
        }
    }

    fn container_runner() -> RunnerPolicy {
        RunnerPolicy {
            kind: RunnerKind::Container,
            policy: RunnerContract::ContainerV1,
            image: Some(ImageIdentity {
                reference: "ghcr.io/example/Tactus-Runner:2.1".to_owned(),
                id: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
                digest: Some(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                ),
            }),
            credential_volumes: Some(
                [
                    ("claude-code".to_owned(), "tactus-creds-Ünicode".to_owned()),
                    ("  Codex-CLI  ".to_owned(), "tactus-creds-codex".to_owned()),
                ]
                .into_iter()
                .collect(),
            ),
        }
    }

    const NORMALIZED_DIGEST: &str =
        "sha256:9999999999999999999999999999999999999999999999999999999999999999";

    fn inputs() -> FrozenInputs {
        FrozenInputs {
            plan: plan(),
            normalized_plan_digest: NORMALIZED_DIGEST.to_owned(),
        }
    }

    /// A three-task chain whose dependencies all refer *forward* in key
    /// order: `aay`(0) depends on `bee`(1), which depends on `cee`(2).
    ///
    /// Keys are assigned in plan order (`keys_by_display_id`), and plan order
    /// is not topological order, so this shape is an ordinary plan rather than
    /// a contrived one. It is the shape the derived-`Blocked` predicate has to
    /// be right about: `aay`'s only failure is two hops away, and a derivation
    /// that decided each task from what it had decided so far would reach
    /// `aay` before it had decided `bee`.
    fn chain_plan() -> Plan {
        Plan {
            source: PlanSource {
                adapter: "markdown".to_owned(),
                hash: "frozen-chain-Ünicode-hash".to_owned(),
            },
            tasks: vec![
                task_of("aay", &["bee"], &["src/aay/"], None),
                task_of("bee", &["cee"], &["src/bee/"], None),
                task_of("cee", &[], &["src/cee/"], None),
            ],
            artifacts: vec![Artifact {
                id: ArtifactId::from("contract"),
                produced_by: Some(TaskId::from("cee")),
            }],
        }
    }

    const AAY: TaskKey = TaskKey(0);
    const BEE: TaskKey = TaskKey(1);
    const CEE: TaskKey = TaskKey(2);

    fn chain_inputs() -> FrozenInputs {
        FrozenInputs {
            plan: chain_plan(),
            normalized_plan_digest: NORMALIZED_DIGEST.to_owned(),
        }
    }

    /// The chain plan's `run_started`, authenticated against its own registry.
    fn chain_run_started_event() -> TopologyEvent {
        let plan = chain_plan();
        let unauthenticated = RunStarted4 {
            plan_hash: plan.source.hash.clone(),
            chains: plan.tasks.iter().map(|t| chain(t.id.as_str())).collect(),
            reviews: review_plan(plan.tasks.len()),
            registry_digest: String::new(),
            ..run_started_unauthenticated()
        };
        let digest = TaskRegistry::originals_with_agents(
            &plan,
            &unauthenticated.registry_record(),
            &unauthenticated.probed_agents,
        )
        .expect("the chain record derives a registry")
        .digest();
        ev(TopologyEventBody::RunStarted {
            data: Box::new(RunStarted4 {
                registry_digest: digest,
                ..unauthenticated
            }),
        })
    }

    fn registry_digest() -> String {
        let plan = plan();
        let started = run_started_unauthenticated();
        TaskRegistry::originals_with_agents(
            &plan,
            &started.registry_record(),
            &started.probed_agents,
        )
        .expect("the fixture record derives a registry")
        .digest()
    }

    /// The run record with a digest field nothing has filled in yet, so that
    /// the digest can be derived from it without deriving it from itself.
    fn run_started_unauthenticated() -> RunStarted4 {
        let plan = plan();
        RunStarted4 {
            schema: TOPOLOGY_SCHEMA,
            tactus_version: "0.2.0-Ünicode".to_owned(),
            run_id: RUN_ID.to_owned(),
            incarnation: IncarnationId("01J8ZQKB2M7NC5PQR0TVWXYZ12".to_owned()),
            runner: container_runner(),
            probed_agents: probed_agents(),
            branch: format!("tactus/run-{RUN_ID}"),
            integration_ref: git_ref("integration"),
            base_sha: sha("base"),
            execution_root: "/var/lib/Tactus/execution roots".to_owned(),
            private_dir: "/var/lib/Tactus/private runs".to_owned(),
            plan_path: "docs/Plan Ünicode.md".to_owned(),
            config_path: Some("tactus.toml".to_owned()),
            plan_hash: plan.source.hash.clone(),
            normalized_plan_digest: NORMALIZED_DIGEST.to_owned(),
            registry_digest: String::new(),
            path_policy: path_policy(),
            // Three different numbers: a fold that read one limit where it
            // meant another lands on a value this fixture does not hold.
            limits: TopologyLimits {
                max_parallel: 3,
                max_defers: 2,
                max_merge_repairs: 1,
            },
            gates: vec!["fmt".to_owned(), "clippy".to_owned()],
            gates_from_config: true,
            gate_cmds: gate_summaries(),
            interaction_mode: "never".to_owned(),
            chains: plan.tasks.iter().map(|t| chain(t.id.as_str())).collect(),
            effort_policy: effort_policy(),
            reviews: review_plan(plan.tasks.len()),
        }
    }

    fn run_started() -> RunStarted4 {
        RunStarted4 {
            registry_digest: registry_digest(),
            ..run_started_unauthenticated()
        }
    }

    fn ev(body: TopologyEventBody) -> TopologyEvent {
        TopologyEvent {
            ts: "2026-08-17T09:41:02Z".to_owned(),
            body,
        }
    }

    fn run_started_event() -> TopologyEvent {
        ev(TopologyEventBody::RunStarted {
            data: Box::new(run_started()),
        })
    }

    /// A fold that has recorded its `run_started` and nothing else.
    fn started() -> TopologyFold {
        let mut fold = TopologyFold::new(inputs());
        apply(&mut fold, &run_started_event());
        fold
    }

    #[track_caller]
    fn apply(fold: &mut TopologyFold, event: &TopologyEvent) {
        let delta = fold
            .plan_transition(event)
            .unwrap_or_else(|error| panic!("`{}` must apply: {error}", event.body.kind()));
        fold.apply_delta(delta);
    }

    #[track_caller]
    fn refuse(fold: &TopologyFold, event: &TopologyEvent) -> FoldError {
        fold.plan_transition(event).expect_err(&format!(
            "`{}` must be refused by this state",
            event.body.kind()
        ))
    }

    #[track_caller]
    fn accepts(fold: &TopologyFold, event: &TopologyEvent) {
        if let Err(error) = fold.plan_transition(event) {
            panic!("`{}` must apply: {error}", event.body.kind());
        }
    }

    // --- event builders ----------------------------------------------------

    fn attempt_record(attempt: u32) -> AttemptRecord {
        AttemptRecord {
            attempt,
            tier: "mid".to_owned(),
            model: "zeta-mid-model".to_owned(),
            pool: Some("codex-plus".to_owned()),
            resumed: false,
            duration: Duration::from_millis(123_456),
            cost_usd: Some(1.25),
            reviews: vec![ReviewRecord {
                pass: "second-opinion".to_owned(),
                agent: "copilot".to_owned(),
                model: "gpt-5.6".to_owned(),
                adapter: Some("copilot".to_owned()),
                preflight_cli_version: Some("0.9.3".to_owned()),
                effort: Some(Effort::Medium),
                pool: Some("copilot-business".to_owned()),
                cost_usd: None,
                outcome: ReviewPassOutcome::Passed,
            }],
            session_id: Some("sess-ÜNI-0042".to_owned()),
            usage: Some(Usage {
                input_tokens: Some(9_001),
                output_tokens: Some(313),
                cache_creation_input_tokens: Some(17),
                cache_read_input_tokens: Some(4_096),
                num_turns: Some(6),
                reasoning_output_tokens: Some(101),
            }),
            failure: None,
        }
    }

    fn question(id: &str, key: TaskKey) -> FrozenQuestion {
        FrozenQuestion {
            id: QuestionId::from(id),
            key,
            kind: QuestionKind::Unblock,
            context: "  A licence question only a person may settle.  ".to_owned(),
            options: vec![
                "  Codex-CLI  ".to_owned(),
                "ÜBER-agent-Ωmega".to_owned(),
                "claude-code".to_owned(),
            ],
        }
    }

    /// The region a task's candidate touches. Disjoint per task, so an overlap
    /// in a test is one the test put there.
    fn region(key: TaskKey) -> PathSet {
        let paths = match key {
            ZETA => vec!["src/Zebra"],
            ALPHA => vec!["src/alpha"],
            MID => vec!["src/mid", "build.rs"],
            _ => vec!["src/repairs"],
        };
        PathSet::Prefixes {
            paths: paths.into_iter().map(GitPath::from).collect(),
        }
    }

    fn dispatch(key: TaskKey, generation: u32, base: &CommitSha) -> TopologyEvent {
        ev(TopologyEventBody::TaskDispatched {
            data: TaskDispatched {
                key,
                generation: GenerationId(generation),
                base_sha: base.clone(),
                worktree_path: format!("/private/workspaces/tasks/k{}-g{generation}", key.0),
                lease: LeaseGrant::Predicted { paths: region(key) },
                source_candidate: None,
            },
        })
    }

    fn frozen_binding(fold: &TopologyFold, key: TaskKey, rung: usize) -> RungBinding {
        let entry = fold
            .registry()
            .expect("the run has started")
            .get(key)
            .expect("the fixture task");
        let frozen = &entry.ladder.rungs[rung];
        RungBinding::from_frozen(frozen, entry.ladder.effort.implementation_for(frozen.tier))
    }

    fn attempt_started(
        fold: &TopologyFold,
        key: TaskKey,
        generation: u32,
        attempt: u32,
        rung: u32,
    ) -> TopologyEvent {
        ev(TopologyEventBody::AttemptStarted {
            data: AttemptStarted4 {
                key,
                generation: GenerationId(generation),
                attempt: AttemptNumber(attempt),
                rung,
                binding: frozen_binding(fold, key, rung as usize),
                pool: Some("codex-plus".to_owned()),
                resume_session: None,
                materialization_observed: None,
            },
        })
    }

    fn settle(
        key: TaskKey,
        generation: u32,
        attempt: u32,
        settlement: AttemptSettlement,
    ) -> TopologyEvent {
        ev(TopologyEventBody::AttemptFinished {
            data: Box::new(AttemptFinished4 {
                key,
                generation: GenerationId(generation),
                attempt: AttemptNumber(attempt),
                record: Box::new(attempt_record(attempt)),
                settlement,
            }),
        })
    }

    fn succeeded(key: TaskKey, generation: u32, attempt: u32) -> TopologyEvent {
        settle(
            key,
            generation,
            attempt,
            AttemptSettlement::Closed {
                transition: SettlementTransition::Succeeded,
                lease: LeaseDisposition::PredictedRetained,
            },
        )
    }

    fn candidate_of(key: TaskKey, generation: u32) -> CandidateRef {
        CandidateRef {
            key,
            generation: GenerationId(generation),
            commit_sha: sha(&format!("commit-{}-{generation}", key.0)),
            candidate_ref: git_ref(&format!("candidates/{}/{generation}", key.0)),
        }
    }

    fn candidate_prepared(key: TaskKey, generation: u32, base: &CommitSha) -> TopologyEvent {
        candidate_prepared_at(key, generation, 1, base)
    }

    /// A `candidate_prepared` naming the attempt that produced it.
    ///
    /// ST-06 binds the embedded record to the generation's current successful
    /// attempt, so a fixture whose generation retried has to say so: after one
    /// retry the candidate belongs to attempt 2, and a builder that hard-coded
    /// 1 would be asserting the very mismatch the fold refuses.
    fn candidate_prepared_at(
        key: TaskKey,
        generation: u32,
        attempt: u32,
        base: &CommitSha,
    ) -> TopologyEvent {
        ev(TopologyEventBody::CandidatePrepared {
            data: Box::new(CandidatePrepared {
                key,
                generation: GenerationId(generation),
                attempt: Box::new(attempt_record(attempt)),
                base_sha: base.clone(),
                parent_sha: base.clone(),
                tree_sha: sha(&format!("tree-{}-{generation}", key.0)),
                commit_sha: sha(&format!("commit-{}-{generation}", key.0)),
                message: format!("  {} candidate  ", key.0),
                prepared_ref: git_ref(&format!("candidate-prepared/{}/{generation}", key.0)),
                candidate_ref: git_ref(&format!("candidates/{}/{generation}", key.0)),
                actual_paths: region(key),
                lease_effect: CandidateLeaseEffect::ReplacesPredicted { paths: region(key) },
            }),
        })
    }

    fn candidate_created(key: TaskKey, generation: u32) -> TopologyEvent {
        ev(TopologyEventBody::TaskCandidateCreated {
            data: TaskCandidateCreated {
                candidate: candidate_of(key, generation),
            },
        })
    }

    fn fast_publication(
        key: TaskKey,
        generation: u32,
        sequence: u32,
        head: &CommitSha,
        satisfies: Vec<TaskKey>,
    ) -> TopologyEvent {
        let candidate = candidate_of(key, generation);
        ev(TopologyEventBody::MergePrepared {
            data: Box::new(MergePrepared {
                sequence: SequenceId(sequence),
                disposition: PreparedDisposition::Fast,
                expected_head: head.clone(),
                proposed_sha: sha(&format!("commit-{}-{generation}", key.0)),
                key: candidate.key,
                generation: candidate.generation,
                candidate_sha: candidate.commit_sha,
                candidate_ref: candidate.candidate_ref,
                prepared_ref: None,
                verification_source: VerificationSource::CandidatePrepared {
                    key,
                    generation: GenerationId(generation),
                },
                verification: None,
                satisfies,
            }),
        })
    }

    fn merged(
        key: TaskKey,
        generation: u32,
        sequence: u32,
        satisfies: Vec<TaskKey>,
    ) -> TopologyEvent {
        ev(TopologyEventBody::TaskMerged {
            data: TaskMerged {
                sequence: SequenceId(sequence),
                merged_sha: sha(&format!("commit-{}-{generation}", key.0)),
                satisfies,
                lease_release: MergeLeaseRelease::Candidate {
                    key,
                    generation: GenerationId(generation),
                },
            },
        })
    }

    /// Drive one task from pending to merged over the fast path, at the head
    /// the integration ref is currently at.
    fn merge_task(fold: &mut TopologyFold, key: TaskKey, generation: u32, sequence: u32) {
        let base = sha("base");
        apply(fold, &dispatch(key, generation, &base));
        let start = attempt_started(fold, key, generation, 1, 0);
        apply(fold, &start);
        apply(fold, &succeeded(key, generation, 1));
        apply(fold, &candidate_prepared(key, generation, &base));
        apply(fold, &candidate_created(key, generation));
        apply(
            fold,
            &fast_publication(key, generation, sequence, &base, vec![key]),
        );
        apply(fold, &merged(key, generation, sequence, vec![key]));
    }

    // -----------------------------------------------------------------------
    // The header: what a fold may be started with (refusals 4, 5, and the
    // ladder validation the fold boundary owns)
    // -----------------------------------------------------------------------

    #[test]
    fn a_topology_log_is_folded_from_its_run_started_and_from_nothing_else() {
        // Every kind, not a sample: the first line of a topology log records
        // the registry, the runner and the limits that every later event is
        // checked against, so there is no event that means anything without it
        // — including the informational ones, which a poisoned or unstarted
        // process still may not append.
        let fold = TopologyFold::new(inputs());
        let mut refused = 0;
        for event in every_kind() {
            if matches!(event.body, TopologyEventBody::RunStarted { .. }) {
                accepts(&fold, &event);
                continue;
            }
            assert_eq!(
                refuse(&fold, &event),
                FoldError::NotStarted {
                    kind: event.body.kind()
                },
                "`{}` was folded into a run that has not started",
                event.body.kind()
            );
            refused += 1;
        }
        assert_eq!(
            refused,
            TOPOLOGY_EVENT_KINDS.len() - 1,
            "every kind but `run_started` has to be refused before a run starts"
        );
    }

    #[test]
    fn a_run_begins_once_and_says_it_is_a_topology_run() {
        let fold = started();
        assert_eq!(
            refuse(&fold, &run_started_event()),
            FoldError::AlreadyStarted
        );

        // A record that does not claim the topology schema is not one this
        // fold may interpret, whatever else it says.
        for schema in [0, 1, 2, 3, 5, 99] {
            let event = ev(TopologyEventBody::RunStarted {
                data: Box::new(RunStarted4 {
                    schema,
                    ..run_started()
                }),
            });
            assert_eq!(
                refuse(&TopologyFold::new(inputs()), &event),
                FoldError::NotTopologySchema { schema }
            );
        }
    }

    #[test]
    fn a_run_started_carries_a_runner_record_that_could_be_re_established() {
        // refusals[5], first half, over every defect the record can exhibit —
        // and, at the top, over the one shape that is *not* a defect: a
        // container whose runtime reported no manifest digest. INV-23 makes the
        // digest "the manifest digest when reported", so a record without one
        // is complete, and a fold that refused it would refuse a legitimate
        // run on a runtime that reports none.
        let mut runner = container_runner();
        if let Some(image) = runner.image.as_mut() {
            image.digest = None;
        }
        accepts(
            &TopologyFold::new(inputs()),
            &ev(TopologyEventBody::RunStarted {
                data: Box::new(RunStarted4 {
                    runner,
                    ..run_started()
                }),
            }),
        );

        let cases: [(&str, BreakRunner); 5] = [
            ("contract does not match kind", |runner| {
                runner.policy = RunnerContract::HostV1;
            }),
            ("container without an image", |runner| {
                runner.image = None;
            }),
            ("image without a reference", |runner| {
                if let Some(image) = runner.image.as_mut() {
                    image.reference = String::new();
                }
            }),
            ("container without credential volumes", |runner| {
                runner.credential_volumes = None;
            }),
            ("host carrying container fields", |runner| {
                runner.kind = RunnerKind::Host;
                runner.policy = RunnerContract::HostV1;
            }),
        ];
        let mut messages: BTreeSet<String> = BTreeSet::new();
        for (label, break_it) in cases {
            let mut runner = container_runner();
            break_it(&mut runner);
            let event = ev(TopologyEventBody::RunStarted {
                data: Box::new(RunStarted4 {
                    runner,
                    ..run_started()
                }),
            });
            let error = refuse(&TopologyFold::new(inputs()), &event);
            let FoldError::IncompleteRunner { defect } = error else {
                panic!("the {label} case was refused for another reason: {error}");
            };
            assert!(
                messages.insert(defect.clone()),
                "the {label} case reports what another case reports: {defect}"
            );
        }
    }

    #[test]
    fn a_resume_that_established_a_different_runner_is_refused_field_by_field() {
        // refusals[5], second half / INV-23: exact equality, and the refusal
        // names *which* field moved, because a config edit, a moved tag and a
        // rebuilt image behind an unchanged tag are indistinguishable as
        // "runner mismatch" and have completely different fixes.
        let fold = started();
        accepts(&fold, &resume(container_runner()));

        let cases: [(&str, &str, BreakRunner); 7] = [
            ("kind", "runner kind", |runner| {
                runner.kind = RunnerKind::Host;
            }),
            ("policy", "runner policy", |runner| {
                runner.policy = RunnerContract::HostV1;
            }),
            ("image presence", "presence of an image record", |runner| {
                runner.image = None;
            }),
            ("image reference", "image reference", |runner| {
                if let Some(image) = runner.image.as_mut() {
                    image.reference = "ghcr.io/example/other:2.1".to_owned();
                }
            }),
            ("image id", "image id", |runner| {
                if let Some(image) = runner.image.as_mut() {
                    image.id =
                        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                            .to_owned();
                }
            }),
            ("image digest", "image digest", |runner| {
                if let Some(image) = runner.image.as_mut() {
                    image.digest = None;
                }
            }),
            ("credential volumes", "credential volume set", |runner| {
                if let Some(volumes) = runner.credential_volumes.as_mut() {
                    volumes.insert("copilot".to_owned(), "tactus-creds-copilot".to_owned());
                }
            }),
        ];
        for (label, field, break_it) in cases {
            let mut runner = container_runner();
            break_it(&mut runner);
            assert_eq!(
                refuse(&fold, &resume(runner)),
                FoldError::RunnerMoved {
                    field: field.to_owned()
                },
                "the {label} case"
            );
        }

        // And the set is a set: the same volumes enumerated in another order
        // established the same runner.
        let mut reordered = container_runner();
        if let Some(volumes) = reordered.credential_volumes.as_mut() {
            let entries: Vec<(String, String)> = volumes.clone().into_iter().rev().collect();
            *volumes = entries.into_iter().collect();
        }
        accepts(&fold, &resume(reordered));
    }

    fn resume(runner: RunnerPolicy) -> TopologyEvent {
        ev(TopologyEventBody::RunResumed {
            data: Box::new(RunResumed4 {
                incarnation: IncarnationId("01J9AAAAAAAAAAAAAAAAAAAAAA".to_owned()),
                runner,
                probed_agents: probed_agents(),
                tactus_version: "0.2.1-Ünicode".to_owned(),
            }),
        })
    }

    #[test]
    fn a_resume_is_compared_with_run_started_by_value_and_by_agent() {
        // refusals[5]: a `run_resumed` "whose runner kind, policy, image
        // reference, image id, image digest, or credential-volume set differs
        // from run_started(4).runner" is refused. Two things that a
        // field-by-field fixture leaves unpinned: the credential volumes are a
        // *map*, so its cardinality and its keys are not its value; and the
        // record it is compared with is `run_started`'s, not the previous
        // resume's.
        let mut fold = started();
        accepts(&fold, &resume(container_runner()));

        // Same size, same agents, one value moved — and then the values
        // swapped between the two agents, which keeps the multiset of values
        // as well.
        let renamed = || {
            let mut runner = container_runner();
            if let Some(volumes) = runner.credential_volumes.as_mut() {
                volumes.insert("claude-code".to_owned(), "tactus-creds-renamed".to_owned());
            }
            runner
        };
        let swapped = || {
            let mut runner = container_runner();
            if let Some(volumes) = runner.credential_volumes.as_mut() {
                volumes.insert("claude-code".to_owned(), "tactus-creds-codex".to_owned());
                volumes.insert(
                    "  Codex-CLI  ".to_owned(),
                    "tactus-creds-Ünicode".to_owned(),
                );
            }
            runner
        };
        for (label, runner) in [
            ("a renamed volume", renamed()),
            ("swapped volumes", swapped()),
        ] {
            let original = container_runner()
                .credential_volumes
                .expect("the fixture mounts credentials");
            let moved = runner
                .credential_volumes
                .clone()
                .expect("the fixture mounts credentials");
            assert_eq!(
                moved.len(),
                original.len(),
                "{label} changed the cardinality"
            );
            assert_eq!(
                moved.keys().collect::<Vec<_>>(),
                original.keys().collect::<Vec<_>>(),
                "{label} changed the agent set"
            );
            assert!(
                matches!(
                    refuse(&fold, &resume(runner)),
                    FoldError::RunnerMoved { .. }
                ),
                "{label} re-established a runner the run never started with"
            );
        }

        // The baseline is `run_started`, so an accepted resume does not become
        // the thing the next one is measured against. Drift A -> A -> B -> A:
        // B is refused where it stands, and A is still the record afterwards.
        apply(&mut fold, &resume(container_runner()));
        assert_eq!(fold.epoch(), Some(Epoch(1)));
        apply(&mut fold, &resume(container_runner()));
        assert_eq!(fold.epoch(), Some(Epoch(2)));
        assert!(matches!(
            refuse(&fold, &resume(renamed())),
            FoldError::RunnerMoved { .. }
        ));
        accepts(&fold, &resume(container_runner()));
        assert_eq!(
            fold.started().expect("started").runner,
            container_runner(),
            "the stored runner record is the one run_started froze"
        );
    }

    #[test]
    fn both_recorded_digests_are_checked_against_the_frozen_inputs() {
        // refusals[4]. Two digests, moved one at a time: a fold that compared
        // one where it meant the other, or that compared neither, is caught by
        // whichever case it does not implement.
        let moved_plan = ev(TopologyEventBody::RunStarted {
            data: Box::new(RunStarted4 {
                normalized_plan_digest: "sha256:0".to_owned() + &"1".repeat(63),
                ..run_started()
            }),
        });
        assert_eq!(
            refuse(&TopologyFold::new(inputs()), &moved_plan),
            FoldError::DigestMismatch {
                what: "normalized plan",
                recorded: "sha256:0".to_owned() + &"1".repeat(63),
                actual: NORMALIZED_DIGEST.to_owned(),
            }
        );

        let moved_registry = ev(TopologyEventBody::RunStarted {
            data: Box::new(RunStarted4 {
                registry_digest: "sha256:2".to_owned() + &"3".repeat(63),
                ..run_started()
            }),
        });
        let error = refuse(&TopologyFold::new(inputs()), &moved_registry);
        assert_eq!(
            error,
            FoldError::DigestMismatch {
                what: "registry",
                recorded: "sha256:2".to_owned() + &"3".repeat(63),
                actual: registry_digest(),
            }
        );

        // The refusal is about the *plan* as much as the record: the same
        // record against a plan that moved by one field is the same refusal,
        // which is the case the digest exists for.
        let mut moved = plan();
        moved.tasks[0].body.push('!');
        let elsewhere = TopologyFold::new(FrozenInputs {
            plan: moved,
            normalized_plan_digest: NORMALIZED_DIGEST.to_owned(),
        });
        assert!(matches!(
            refuse(&elsewhere, &run_started_event()),
            FoldError::DigestMismatch {
                what: "registry",
                ..
            }
        ));

        // And the allow-list is one of the inputs it authenticates: a run that
        // probed something else derives a different registry.
        let probed_elsewhere = ev(TopologyEventBody::RunStarted {
            data: Box::new(RunStarted4 {
                probed_agents: vec!["codex".to_owned()],
                ..run_started()
            }),
        });
        assert!(matches!(
            refuse(&TopologyFold::new(inputs()), &probed_elsewhere),
            FoldError::DigestMismatch {
                what: "registry",
                ..
            }
        ));

        // The comparison is of the whole value. The cases above move a digest
        // to something unrelated, which a truncated or prefix comparison
        // rejects just as well; these move the *last* character of each,
        // independently, so a comparison of anything short of the whole
        // accepts them. The two digests are pairwise unrelated in this
        // fixture, so neither can supply the other's expected equality.
        let nudge = |value: &str| {
            let mut moved = value.to_owned();
            let last = moved.pop().expect("a digest has characters");
            moved.push(if last == '0' { '1' } else { '0' });
            moved
        };
        assert_ne!(registry_digest(), NORMALIZED_DIGEST);
        for (what, event) in [
            (
                "normalized plan",
                ev(TopologyEventBody::RunStarted {
                    data: Box::new(RunStarted4 {
                        normalized_plan_digest: nudge(NORMALIZED_DIGEST),
                        ..run_started()
                    }),
                }),
            ),
            (
                "registry",
                ev(TopologyEventBody::RunStarted {
                    data: Box::new(RunStarted4 {
                        registry_digest: nudge(&registry_digest()),
                        ..run_started()
                    }),
                }),
            ),
        ] {
            let error = refuse(&TopologyFold::new(inputs()), &event);
            assert!(
                matches!(&error, FoldError::DigestMismatch { what: named, .. } if *named == what),
                "a {what} digest differing in its last character alone was authenticated: \
                 {error:?}"
            );
        }
    }

    #[test]
    fn a_malformed_ladder_is_refused_before_it_is_stored() {
        // Fold-boundary work, not registry work: the registry derives whatever
        // the record says, and this decides whether that ladder may enter a
        // fold's state.
        //
        // The three cases here are the ones a *frozen plan and run record* can
        // express — every one of them is a registry the derivation builds
        // without complaint, which is precisely why the check has to live
        // here. The rest of the malformations cannot be written into a chain
        // at all (the derivation recomputes the ceiling, refuses an empty
        // ladder, refuses a misaligned binding) and are exercised below on the
        // path where an entry *is* the record: a spawn.
        let cases: [(&str, BreakFrozenInputs); 3] = [
            ("floor above ceiling", |plan, chain| {
                plan.tasks[ZETA.index()].min_tier = Some(Tier::Frontier);
                chain.tiers = vec![Tier::Small, Tier::Mid];
                chain.bindings = Some(bindings_for(&chain.tiers));
            }),
            ("tiers that do not escalate", |_, chain| {
                chain.tiers = vec![Tier::Mid, Tier::Small, Tier::Frontier];
                chain.bindings = Some(bindings_for(&chain.tiers));
            }),
            ("a repeated tier", |_, chain| {
                chain.tiers = vec![Tier::Mid, Tier::Mid];
                chain.bindings = Some(bindings_for(&chain.tiers));
            }),
        ];
        let mut defects: BTreeSet<String> = BTreeSet::new();
        for (label, break_it) in cases {
            let (inputs, event) = run_started_with_ladder(break_it);
            let error = refuse(&TopologyFold::new(inputs), &event);
            let FoldError::MalformedLadder { key, defect } = error else {
                panic!("the {label} case was refused for another reason: {error}");
            };
            assert_eq!(key, ZETA.0, "the {label} case names the wrong task");
            assert!(
                defects.insert(defect.clone()),
                "the {label} case reports what another case reports: {defect}"
            );
        }

        // The same check on the way in through a spawn, over every
        // malformation an embedded entry can carry.
        let spawn_cases: [(&str, BreakLadder); 8] = [
            ("floor above ceiling", |ladder| {
                ladder.tiers = vec![Tier::Mid];
                ladder.rungs = rungs_for(&ladder.tiers);
                ladder.ceiling = Some(Tier::Mid);
                ladder.floor = Some(Tier::Frontier);
            }),
            ("tiers that do not escalate", |ladder| {
                ladder.tiers = vec![Tier::Frontier, Tier::Mid];
                ladder.rungs = rungs_for(&ladder.tiers);
                ladder.ceiling = Some(Tier::Frontier);
            }),
            ("a repeated tier", |ladder| {
                ladder.tiers = vec![Tier::Mid, Tier::Mid];
                ladder.rungs = rungs_for(&ladder.tiers);
                ladder.ceiling = Some(Tier::Mid);
            }),
            ("zero attempts per rung", |ladder| ladder.attempts_per = 0),
            ("a ceiling that is not the highest rung", |ladder| {
                ladder.ceiling = Some(Tier::Small);
            }),
            ("runnable with no rungs", |ladder| ladder.rungs.clear()),
            ("a human binding that already has rungs", |ladder| {
                ladder.admission = Admission::HumanBinding {
                    options: vec!["  Codex-CLI  ".to_owned()],
                };
            }),
            ("a rung bound at another tier", |ladder| {
                ladder.rungs[0].tier = Tier::Small;
            }),
        ];
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        let mut spawn_defects: BTreeSet<String> = BTreeSet::new();
        for (label, break_it) in spawn_cases {
            let mut spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
            break_it(&mut spawn.entry.ladder);
            let error = refuse(&fold, &spawn_event(spawn));
            let FoldError::MalformedLadder { key, defect } = error else {
                panic!("the {label} spawn case was refused for another reason: {error}");
            };
            assert_eq!(key, 3, "the {label} spawn case names the wrong task");
            assert!(
                spawn_defects.insert(defect.clone()),
                "the {label} spawn case reports what another reports: {defect}"
            );
        }

        // An empty clipped ladder waiting for a human binding is not malformed
        // — it is the shape a repair takes when its floor and its root's
        // ceiling do not intersect — but one that offers nothing to choose
        // from is.
        let mut spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        clip_to_human_binding(&mut spawn, vec!["  Codex-CLI  ".to_owned()]);
        accepts(&fold, &spawn_event(spawn.clone()));
        clip_to_human_binding(&mut spawn, Vec::new());
        assert!(matches!(
            refuse(&fold, &spawn_event(spawn)),
            FoldError::MalformedLadder { key: 3, .. }
        ));
    }

    fn bindings_for(tiers: &[Tier]) -> Vec<BindingSummary> {
        tiers
            .iter()
            .map(|tier| BindingSummary {
                tier: *tier,
                agent: format!("zeta-{tier}-agent"),
                model: format!("zeta-{tier}-model"),
                pinned: *tier == Tier::Frontier,
            })
            .collect()
    }

    fn rungs_for(tiers: &[Tier]) -> Vec<FrozenRung> {
        tiers
            .iter()
            .map(|tier| FrozenRung {
                tier: *tier,
                agent: format!("repair-{tier}-agent"),
                model: format!("repair-{tier}-model"),
                pinned: *tier == Tier::Frontier,
            })
            .collect()
    }

    /// A `run_started` whose frozen inputs give `zeta` a broken ladder, with
    /// the recorded digest recomputed so the fold reaches the ladder check
    /// rather than stopping at the digest.
    fn run_started_with_ladder(break_it: BreakFrozenInputs) -> (FrozenInputs, TopologyEvent) {
        let started = run_started();
        let mut plan = plan();
        let mut chains = started.chains.clone();
        let index = chains
            .iter()
            .position(|chain| chain.task == "zeta")
            .expect("zeta's chain");
        break_it(&mut plan, &mut chains[index]);
        let record = RunStarted4 { chains, ..started };
        let digest = TaskRegistry::originals_with_agents(
            &plan,
            &record.registry_record(),
            &record.probed_agents,
        )
        .expect("the derivation accepts every ladder in this table")
        .digest();
        // The fold derives from *its* frozen plan, so the frozen inputs move
        // with the record: the floor lives in the plan, and a fixture that
        // moved only the record would be refused for the digest instead.
        (
            FrozenInputs {
                plan,
                normalized_plan_digest: NORMALIZED_DIGEST.to_owned(),
            },
            ev(TopologyEventBody::RunStarted {
                data: Box::new(RunStarted4 {
                    registry_digest: digest,
                    ..record
                }),
            }),
        )
    }

    // -----------------------------------------------------------------------
    // Registration and dispatch (refusals 10, and what a registered entry is)
    // -----------------------------------------------------------------------

    /// A repair entry, complete, as its registering event carries it.
    fn repair_spawn(key: TaskKey, root: TaskKey, parent: TaskKey) -> FrozenSpawn {
        FrozenSpawn {
            key,
            entry: TaskEntry {
                key,
                display_id: TaskId::from(
                    crate::topology::registry::repair_display_id(0, &TaskId::from("alpha"))
                        .as_str(),
                ),
                origin: Origin::MergeRepair,
                spec: FrozenTaskSpec {
                    kind: TaskKind::Fix,
                    title: "  Repair the alpha rejection — Ünicode  ".to_owned(),
                    body: "Conflict against `src/Zebra/ÜBER.rs`; preserve merged behaviour."
                        .to_owned(),
                    acceptance: vec!["the conflict is resolved".to_owned()],
                    path_hints: vec!["src/repairs/".to_owned()],
                    suggested_tier: Some(Tier::Frontier),
                    min_tier: Some(Tier::Mid),
                    artifacts_in: vec![ArtifactId::from("contract")],
                    artifacts_out: vec![ArtifactId::from("repair-out")],
                },
                deps: vec![parent],
                display_deps: vec![TaskId::from("alpha")],
                ladder: FrozenLadder {
                    tiers: vec![Tier::Mid, Tier::Frontier],
                    attempts_per: 4,
                    rungs: rungs_for(&[Tier::Mid, Tier::Frontier]),
                    floor: Some(Tier::Mid),
                    ceiling: Some(Tier::Frontier),
                    effort: effort_policy(),
                    admission: Admission::Runnable,
                },
                reviews: FrozenReviews {
                    enabled: true,
                    alternative_available: true,
                    pass_timeout_secs: 1_337,
                    primary: Some(PassBinding::new("claude-code", "claude-opus-5")),
                    alternative: Some(PassBinding::new("copilot", "gpt-5.6")),
                    second_opinion: None,
                },
                allowed_agents: probed_agents(),
                lineage: Some(Lineage {
                    root,
                    parent,
                    index: 0,
                }),
            },
            admission: SpawnAdmission::Runnable,
        }
    }

    fn spawn_event(spawn: FrozenSpawn) -> TopologyEvent {
        ev(TopologyEventBody::TaskSpawned {
            data: Box::new(TaskSpawned { spawn }),
        })
    }

    fn clip_to_human_binding(spawn: &mut FrozenSpawn, options: Vec<String>) {
        spawn.entry.ladder.rungs.clear();
        spawn.entry.ladder.admission = Admission::HumanBinding {
            options: options.clone(),
        };
        spawn.admission = SpawnAdmission::HumanBinding {
            options,
            question: question("q-binding-Ünicode", spawn.key),
        };
    }

    #[test]
    fn a_registered_entry_is_the_entry_the_event_registers() {
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        accepts(&fold, &spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)));

        // Each case moves exactly one thing about an otherwise valid spawn,
        // and each reports something no other case reports.
        let cases: [(&str, BreakSpawn); 9] = [
            ("a key that is not the next dense index", |spawn| {
                spawn.key = TaskKey(4);
                spawn.entry.key = TaskKey(4);
            }),
            ("an entry that calls itself something else", |spawn| {
                spawn.entry.key = TaskKey(7);
            }),
            ("a display id another task already has", |spawn| {
                spawn.entry.display_id = TaskId::from("alpha");
            }),
            ("no lineage", |spawn| spawn.entry.lineage = None),
            ("a lineage root that refers forwards", |spawn| {
                spawn.entry.lineage = Some(Lineage {
                    root: TaskKey(3),
                    parent: ALPHA,
                    index: 0,
                });
            }),
            ("a lineage parent that refers forwards", |spawn| {
                spawn.entry.lineage = Some(Lineage {
                    root: ALPHA,
                    parent: TaskKey(9),
                    index: 0,
                });
            }),
            ("an allow-list the run never probed", |spawn| {
                spawn.entry.allowed_agents.push("smuggled-agent".to_owned());
            }),
            ("a dependency named as another task", |spawn| {
                spawn.entry.display_deps = vec![TaskId::from("zeta")];
            }),
            ("a dependency that is not merged", |spawn| {
                spawn.entry.deps = vec![ZETA];
                spawn.entry.display_deps = vec![TaskId::from("zeta")];
            }),
        ];
        let mut messages: BTreeSet<String> = BTreeSet::new();
        for (label, break_it) in cases {
            let mut spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
            break_it(&mut spawn);
            let error = refuse(&fold, &spawn_event(spawn));
            assert!(
                messages.insert(error.to_string()),
                "the {label} case reports what another case reports: {error}"
            );
        }

        // The dependency-count mismatch is its own case: two lists that
        // describe one relation have to describe the same one.
        let mut spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        spawn.entry.display_deps.push(TaskId::from("zeta"));
        assert!(matches!(
            refuse(&fold, &spawn_event(spawn)),
            FoldError::MalformedEntry { key: 3, .. }
        ));
    }

    #[test]
    fn a_spawns_admission_and_its_entrys_admission_are_one_statement() {
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);

        // The three legal pairings, and the run's frozen repair limit.
        let mut human_required = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        human_required.admission = SpawnAdmission::HumanRequired {
            limit: 1,
            question: question("q-admission-Ünicode", TaskKey(3)),
        };
        accepts(&fold, &spawn_event(human_required.clone()));

        let mut wrong_limit = human_required.clone();
        wrong_limit.admission = SpawnAdmission::HumanRequired {
            limit: 5,
            question: question("q-admission-Ünicode", TaskKey(3)),
        };
        assert!(matches!(
            refuse(&fold, &spawn_event(wrong_limit)),
            FoldError::MalformedEntry { key: 3, .. }
        ));

        // A binding question whose options are not the entry's.
        let mut clipped = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        clip_to_human_binding(&mut clipped, vec!["  Codex-CLI  ".to_owned()]);
        let mut disagreeing = clipped.clone();
        disagreeing.admission = SpawnAdmission::HumanBinding {
            options: vec!["copilot".to_owned()],
            question: question("q-binding-Ünicode", TaskKey(3)),
        };
        assert!(matches!(
            refuse(&fold, &spawn_event(disagreeing)),
            FoldError::MalformedEntry { key: 3, .. }
        ));

        // A runnable event over an entry that has no binding, and the reverse.
        let mut runnable_over_clipped = clipped.clone();
        runnable_over_clipped.admission = SpawnAdmission::Runnable;
        assert!(matches!(
            refuse(&fold, &spawn_event(runnable_over_clipped)),
            FoldError::MalformedEntry { key: 3, .. }
        ));

        let mut binding_over_runnable = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        binding_over_runnable.admission = SpawnAdmission::HumanBinding {
            options: vec!["  Codex-CLI  ".to_owned()],
            question: question("q-binding-Ünicode", TaskKey(3)),
        };
        assert!(matches!(
            refuse(&fold, &spawn_event(binding_over_runnable)),
            FoldError::MalformedEntry { key: 3, .. }
        ));

        // And a question nobody could answer parks a task nothing un-parks.
        let mut unanswerable = clipped;
        unanswerable.admission = SpawnAdmission::HumanBinding {
            options: vec!["  Codex-CLI  ".to_owned()],
            question: FrozenQuestion {
                options: Vec::new(),
                ..question("q-binding-Ünicode", TaskKey(3))
            },
        };
        assert!(matches!(
            refuse(&fold, &spawn_event(unanswerable)),
            FoldError::UnanswerableQuestion { .. }
        ));
    }

    #[test]
    fn a_spawn_parks_exactly_when_its_admission_needs_a_person() {
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        let mut runnable = fold.clone();
        apply(
            &mut runnable,
            &spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)),
        );
        assert_eq!(runnable.task_state(TaskKey(3)), Some(TaskState::Pending));
        assert!(runnable.open_questions().expect("started").is_empty());

        let mut clipped_fold = fold.clone();
        let mut spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        clip_to_human_binding(&mut spawn, vec!["  Codex-CLI  ".to_owned()]);
        apply(&mut clipped_fold, &spawn_event(spawn));
        assert_eq!(
            clipped_fold.task_state(TaskKey(3)),
            Some(TaskState::AwaitingInput)
        );
        assert_eq!(clipped_fold.open_questions().expect("started").len(), 1);
    }

    #[test]
    fn a_dispatch_opens_one_dense_generation_of_a_pending_task() {
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));

        // A second generation while one is open.
        assert!(matches!(
            refuse(&fold, &dispatch(ZETA, 1, &base)),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));
        // A generation that skips a number, once the first has closed.
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);
        apply(
            &mut fold,
            &settle(
                ZETA,
                0,
                1,
                AttemptSettlement::Closed {
                    transition: SettlementTransition::Retry,
                    lease: LeaseDisposition::PredictedReleased,
                },
            ),
        );
        assert!(matches!(
            refuse(&fold, &dispatch(ZETA, 2, &base)),
            FoldError::NonDenseKey { key: 2, len: 1, .. }
        ));
        accepts(&fold, &dispatch(ZETA, 1, &base));

        // A task that is not pending.
        let mut merged_fold = started();
        merge_task(&mut merged_fold, ALPHA, 0, 0);
        assert!(matches!(
            refuse(&merged_fold, &dispatch(ALPHA, 1, &base)),
            FoldError::WrongTaskState {
                key: 1,
                state: "merged",
                ..
            }
        ));
        // And a task nobody registered.
        assert!(matches!(
            refuse(&merged_fold, &dispatch(TaskKey(9), 0, &base)),
            FoldError::UnknownKey { key: 9, .. }
        ));
    }

    #[test]
    fn a_dispatch_takes_the_holding_its_origin_implies() {
        let base = sha("base");
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        apply(
            &mut fold,
            &spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)),
        );

        // An ordinary task may not inherit a lineage lease, and a repair may
        // not take one of its own; a repair names the candidate it was
        // materialized from, and an ordinary dispatch names none.
        let repair_dispatch = |lease: LeaseGrant, source: Option<CandidateRef>| {
            ev(TopologyEventBody::TaskDispatched {
                data: TaskDispatched {
                    key: TaskKey(3),
                    generation: GenerationId(0),
                    base_sha: base.clone(),
                    worktree_path: "/private/workspaces/tasks/k3-g0".to_owned(),
                    lease,
                    source_candidate: source,
                },
            })
        };
        accepts(
            &fold,
            &repair_dispatch(
                LeaseGrant::InheritedLineage { root: ALPHA },
                Some(candidate_of(ALPHA, 0)),
            ),
        );
        assert!(matches!(
            refuse(
                &fold,
                &repair_dispatch(
                    LeaseGrant::Predicted {
                        paths: region(TaskKey(3))
                    },
                    Some(candidate_of(ALPHA, 0))
                )
            ),
            FoldError::MalformedEntry { key: 3, .. }
        ));
        assert!(matches!(
            refuse(
                &fold,
                &repair_dispatch(
                    LeaseGrant::InheritedLineage { root: ZETA },
                    Some(candidate_of(ALPHA, 0))
                )
            ),
            FoldError::MalformedEntry { key: 3, .. }
        ));
        assert!(matches!(
            refuse(
                &fold,
                &repair_dispatch(LeaseGrant::InheritedLineage { root: ALPHA }, None)
            ),
            FoldError::MalformedEntry { key: 3, .. }
        ));

        let ordinary = ev(TopologyEventBody::TaskDispatched {
            data: TaskDispatched {
                key: ZETA,
                generation: GenerationId(0),
                base_sha: base.clone(),
                worktree_path: "/private/workspaces/tasks/k0-g0".to_owned(),
                lease: LeaseGrant::InheritedLineage { root: ALPHA },
                source_candidate: None,
            },
        });
        assert!(matches!(
            refuse(&fold, &ordinary),
            FoldError::MalformedEntry { key: 0, .. }
        ));
        let materializing = ev(TopologyEventBody::TaskDispatched {
            data: TaskDispatched {
                key: ZETA,
                generation: GenerationId(0),
                base_sha: base,
                worktree_path: "/private/workspaces/tasks/k0-g0".to_owned(),
                lease: LeaseGrant::Predicted {
                    paths: region(ZETA),
                },
                source_candidate: Some(candidate_of(ALPHA, 0)),
            },
        });
        assert!(matches!(
            refuse(&fold, &materializing),
            FoldError::MalformedEntry { key: 0, .. }
        ));
    }

    // -----------------------------------------------------------------------
    // ST-06: a completion applies only while its identity is the open one
    // -----------------------------------------------------------------------

    #[test]
    fn an_attempt_starts_in_the_open_generation_at_the_next_number() {
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));

        // The generation: not another task's, not a closed one, not one that
        // does not exist.
        let elsewhere = attempt_started(&fold, ZETA, 1, 1, 0);
        assert!(matches!(
            refuse(&fold, &elsewhere),
            FoldError::NotTheOpenGeneration {
                key: 0,
                generation: 1,
                ..
            }
        ));
        let unopened = attempt_started(&fold, ALPHA, 0, 1, 0);
        assert!(matches!(
            refuse(&fold, &unopened),
            FoldError::NotTheOpenGeneration { key: 1, .. }
        ));

        // The number: dense from 1 within the generation, in both directions.
        for attempt in [0, 2, 7] {
            let event = attempt_started(&fold, ZETA, 0, attempt, 0);
            assert_eq!(
                refuse(&fold, &event),
                FoldError::WrongAttempt {
                    kind: "attempt_started",
                    key: 0,
                    generation: 0,
                    attempt,
                    expected: "1".to_owned(),
                }
            );
        }
        let first = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &first);

        // A second attempt starts only after the first settles, and then at 2.
        assert!(matches!(
            refuse(&fold, &attempt_started(&fold, ZETA, 0, 2, 0)),
            FoldError::NotTheOpenGeneration { .. }
        ));
        apply(
            &mut fold,
            &settle(
                ZETA,
                0,
                1,
                AttemptSettlement::Retained {
                    retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                    retained_incarnation: Epoch(0),
                },
            ),
        );
        let resumed = |attempt: u32, session: &str, generation: u32| {
            ev(TopologyEventBody::AttemptStarted {
                data: AttemptStarted4 {
                    key: ZETA,
                    generation: GenerationId(generation),
                    attempt: AttemptNumber(attempt),
                    rung: 0,
                    binding: frozen_binding(&fold, ZETA, 0),
                    pool: Some("codex-plus".to_owned()),
                    resume_session: Some(SessionId(session.to_owned())),
                    materialization_observed: None,
                },
            })
        };
        assert_eq!(
            refuse(&fold, &resumed(3, "sess-ÜNI-0042", 0)),
            FoldError::WrongAttempt {
                kind: "attempt_started",
                key: 0,
                generation: 0,
                attempt: 3,
                expected: "2".to_owned(),
            }
        );
        accepts(&fold, &resumed(2, "sess-ÜNI-0042", 0));
    }

    #[test]
    fn a_retained_session_belongs_to_the_incarnation_that_retained_it() {
        // refusals[12], over the three ways a resume can be wrong and the one
        // way it can be right.
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);

        // A settlement cannot retain a session for another incarnation.
        assert!(matches!(
            refuse(
                &fold,
                &settle(
                    ZETA,
                    0,
                    1,
                    AttemptSettlement::Retained {
                        retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                        retained_incarnation: Epoch(4),
                    }
                )
            ),
            FoldError::StaleIncarnation { key: 0, .. }
        ));
        apply(
            &mut fold,
            &settle(
                ZETA,
                0,
                1,
                AttemptSettlement::Retained {
                    retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                    retained_incarnation: Epoch(0),
                },
            ),
        );

        let resume_with = |fold: &TopologyFold, session: &str| {
            ev(TopologyEventBody::AttemptStarted {
                data: AttemptStarted4 {
                    key: ZETA,
                    generation: GenerationId(0),
                    attempt: AttemptNumber(2),
                    rung: 0,
                    binding: frozen_binding(fold, ZETA, 0),
                    pool: Some("codex-plus".to_owned()),
                    resume_session: Some(SessionId(session.to_owned())),
                    materialization_observed: None,
                },
            })
        };
        // Another session than the one retained.
        assert!(matches!(
            refuse(&fold, &resume_with(&fold, "sess-other")),
            FoldError::StaleIncarnation { key: 0, .. }
        ));
        // The right session, in the incarnation that retained it.
        accepts(&fold, &resume_with(&fold, "sess-ÜNI-0042"));

        // And the same event after a resume: the working tree was rolled back,
        // so the conversation's belief about what it left behind is false.
        let mut next_epoch = fold.clone();
        apply(&mut next_epoch, &resume(container_runner()));
        assert_eq!(next_epoch.epoch(), Some(Epoch(1)));
        let error = refuse(&next_epoch, &resume_with(&next_epoch, "sess-ÜNI-0042"));
        let FoldError::StaleIncarnation { detail, .. } = error else {
            panic!("a stale incarnation must be refused as one");
        };
        assert!(
            detail.contains("incarnation 0") && detail.contains("1 time(s)"),
            "the refusal has to say which incarnation retained it: {detail}"
        );

        // A fresh attempt in a retained generation is not a resume, and a
        // resume in a fresh generation is not a retry.
        assert!(matches!(
            refuse(&fold, &attempt_started(&fold, ZETA, 0, 2, 0)),
            FoldError::NotTheOpenGeneration { .. }
        ));
        let mut fresh = started();
        apply(&mut fresh, &dispatch(ALPHA, 0, &base));
        let mistaken = ev(TopologyEventBody::AttemptStarted {
            data: AttemptStarted4 {
                key: ALPHA,
                generation: GenerationId(0),
                attempt: AttemptNumber(1),
                rung: 0,
                binding: frozen_binding(&fresh, ALPHA, 0),
                pool: None,
                resume_session: Some(SessionId("sess-invented".to_owned())),
                materialization_observed: None,
            },
        });
        assert!(matches!(
            refuse(&fresh, &mistaken),
            FoldError::NotTheOpenGeneration { key: 1, .. }
        ));
    }

    #[test]
    fn an_attempt_runs_the_frozen_binding_or_the_validated_override() {
        // refusals[11] / INV-19, one component at a time. Each case moves one
        // field of an otherwise exact binding: a check that compared the whole
        // record, or that compared none of it, fails on the case it skipped.
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        let exact = attempt_started(&fold, ZETA, 0, 1, 0);
        accepts(&fold, &exact);

        let cases: [(&str, BreakBinding); 4] = [
            ("agent", |binding| binding.agent = "copilot".to_owned()),
            ("model", |binding| {
                binding.model = "another-model".to_owned()
            }),
            ("tier", |binding| binding.tier = Tier::Frontier),
            ("effort", |binding| binding.effort = Effort::Medium),
        ];
        for (label, break_it) in cases {
            let mut binding = frozen_binding(&fold, ZETA, 0);
            break_it(&mut binding);
            let event = ev(TopologyEventBody::AttemptStarted {
                data: AttemptStarted4 {
                    key: ZETA,
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    rung: 0,
                    binding,
                    pool: Some("codex-plus".to_owned()),
                    resume_session: None,
                    materialization_observed: None,
                },
            });
            assert!(
                matches!(
                    refuse(&fold, &event),
                    FoldError::BindingMismatch { key: 0, .. }
                ),
                "the {label} case ran a binding the run never froze and was folded anyway"
            );
        }

        // The effort is the ladder's effort *for that rung's tier*, not the
        // run's default and not another tier's: zeta's rungs are small, mid and
        // frontier, resolving to three different efforts.
        for rung in 0..3u32 {
            accepts(&fold, &attempt_started(&fold, ZETA, 0, 1, rung));
            let entry = fold.registry().expect("started").get(ZETA).expect("zeta");
            let tier = entry.ladder.rungs[rung as usize].tier;
            let mut wrong_effort = frozen_binding(&fold, ZETA, rung as usize);
            wrong_effort.effort = entry.ladder.effort.review;
            assert_ne!(
                wrong_effort.effort,
                entry.ladder.effort.implementation_for(tier),
                "the fixture's review effort must differ from every rung's, or this proves nothing"
            );
            let event = ev(TopologyEventBody::AttemptStarted {
                data: AttemptStarted4 {
                    key: ZETA,
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    rung,
                    binding: wrong_effort,
                    pool: None,
                    resume_session: None,
                    materialization_observed: None,
                },
            });
            assert!(matches!(
                refuse(&fold, &event),
                FoldError::BindingMismatch { .. }
            ));
        }

        // A rung the ladder does not have.
        let mut off_the_end = attempt_started(&fold, ZETA, 0, 1, 0);
        if let TopologyEventBody::AttemptStarted { data } = &mut off_the_end.body {
            data.rung = 9;
        }
        assert!(matches!(
            refuse(&fold, &off_the_end),
            FoldError::BindingMismatch { .. }
        ));

        // A repair's attempt records what its worktree was materialized from,
        // and an ordinary one records nothing.
        let mut materializing = attempt_started(&fold, ZETA, 0, 1, 0);
        if let TopologyEventBody::AttemptStarted { data } = &mut materializing.body {
            data.materialization_observed = Some(Materialization::Clean);
        }
        assert!(matches!(
            refuse(&fold, &materializing),
            FoldError::MalformedEntry { key: 0, .. }
        ));
    }

    #[test]
    fn an_override_is_the_binding_the_frozen_admission_authorized_and_no_other() {
        // `task_registry.binding_override`: the override is "validated against
        // the frozen options of that task's open HumanBinding question", and
        // refusals[12] refuses one "for a wrong question ... or mismatched
        // fields". A1 proves the override names the same task, question and
        // option as the answer carrying it; the authority it is measured
        // against is the fold's, and it has to survive from the `task_spawned`
        // that froze it to the answer that draws on it.
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        let mut spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        let options = vec!["  Codex-CLI  ".to_owned(), "copilot".to_owned()];
        clip_to_human_binding(&mut spawn, options.clone());
        apply(&mut fold, &spawn_event(spawn));

        let override_for = |option_index: u32, agent: &str| BindingOverride {
            key: TaskKey(3),
            question: QuestionId::from("q-binding-Ünicode"),
            option_index,
            agent: agent.to_owned(),
            model: "gpt-5.6".to_owned(),
            effort: Effort::XHigh,
        };
        let answer = |option_index: u32, binding: Option<BindingOverride>| {
            answered(
                TaskKey(3),
                "q-binding-Ünicode",
                Answer4::Answered {
                    option_index,
                    binding_override: binding,
                },
            )
        };

        // Every option, named exactly, is authorized.
        for (index, agent) in options.iter().enumerate() {
            let index = u32::try_from(index).expect("two options");
            accepts(&fold, &answer(index, Some(override_for(index, agent))));
        }

        // An option the admission froze for somebody else. Both directions of
        // the pairing are wrong: the agent of the *other* option, and an agent
        // the option list never held at all. Neither is caught by the range
        // check or by A1's internal agreement, because both are self-consistent
        // and in range.
        for (label, index, agent) in [
            ("the other option's agent", 0_u32, "copilot"),
            ("the other option's agent", 1, "  Codex-CLI  "),
            ("an unauthorized agent", 0, "claude-code"),
            ("an unauthorized agent", 1, "ÜBER-agent-Ωmega"),
        ] {
            assert!(
                matches!(
                    refuse(&fold, &answer(index, Some(override_for(index, agent)))),
                    FoldError::WrongQuestion { .. }
                ),
                "{label}: option {index} authorized `{}` and `{agent}` was installed anyway",
                options[index as usize]
            );
        }

        // An answer to a HumanBinding admission with no override at all leaves
        // its task with an empty ladder and nothing to run: `Admission::
        // HumanBinding` says the entry "cannot move until an answer records an
        // explicit one-off binding", and `Answer4.binding_override` is
        // "present exactly when the question was asking for a binding".
        assert!(matches!(
            refuse(&fold, &answer(0, None)),
            FoldError::WrongQuestion { .. }
        ));

        // And the converse, which is the half nothing checked: an override on
        // a question that authorized no binding. The question here is an
        // ordinary park of another task, and the override is internally exact
        // — it names that question, that task and that option — so only the
        // admission authority distinguishes it.
        apply(&mut fold, &raised("q-park-Ünicode", ZETA));
        let smuggled = answered(
            ZETA,
            "q-park-Ünicode",
            Answer4::Answered {
                option_index: 1,
                binding_override: Some(BindingOverride {
                    key: ZETA,
                    question: QuestionId::from("q-park-Ünicode"),
                    option_index: 1,
                    agent: "ÜBER-agent-Ωmega".to_owned(),
                    model: "a-model-nobody-froze".to_owned(),
                    effort: Effort::XHigh,
                }),
            },
        );
        assert!(
            matches!(refuse(&fold, &smuggled), FoldError::WrongQuestion { .. }),
            "an ordinary park installed a binding its admission never authorized"
        );
        // The same answer without the override is the ordinary one.
        accepts(
            &fold,
            &answered(
                ZETA,
                "q-park-Ünicode",
                Answer4::Answered {
                    option_index: 1,
                    binding_override: None,
                },
            ),
        );
        assert_eq!(
            fold.binding_override(ZETA),
            None,
            "no refused override was installed"
        );

        // A `HumanRequired` admission asks for a person, not for a binding.
        let mut required = repair_spawn(TaskKey(4), ALPHA, ALPHA);
        required.entry.display_id = TaskId::from(
            crate::topology::registry::repair_display_id(1, &TaskId::from("alpha")).as_str(),
        );
        required.admission = SpawnAdmission::HumanRequired {
            limit: 1,
            question: question("q-required-Ünicode", TaskKey(4)),
        };
        apply(&mut fold, &spawn_event(required));
        assert!(matches!(
            refuse(
                &fold,
                &answered(
                    TaskKey(4),
                    "q-required-Ünicode",
                    Answer4::Answered {
                        option_index: 0,
                        binding_override: Some(BindingOverride {
                            key: TaskKey(4),
                            question: QuestionId::from("q-required-Ünicode"),
                            option_index: 0,
                            agent: "  Codex-CLI  ".to_owned(),
                            model: "gpt-5.6".to_owned(),
                            effort: Effort::XHigh,
                        }),
                    },
                )
            ),
            FoldError::WrongQuestion { .. }
        ));
    }

    #[test]
    fn an_interruption_closes_its_generation_and_returns_its_task_to_pending() {
        // transaction_fault_matrix[T-ATTEMPT].resume_action: "append
        // attempt_interrupted (unknown spend, allowance refunded, generation
        // Closed, lease by kind); discard residue ... the task worktree
        // scrubbed with force ... task returns Pending; later dispatch new
        // generation". Nothing was judged and the spend is unknown, so the
        // generation is over — not idled and not reusable.
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);
        assert!(
            fold.leases()
                .expect("started")
                .holds(LeaseOwner::Generation {
                    key: ZETA,
                    generation: GenerationId(0),
                })
        );

        let interrupt = |lease| {
            ev(TopologyEventBody::AttemptInterrupted {
                data: AttemptInterrupted4 {
                    key: ZETA,
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    lease,
                    detail: "  the coordinator died  ".to_owned(),
                },
            })
        };
        // "lease by kind", for a generation that closes: an ordinary one gives
        // up the region it predicted.
        assert!(matches!(
            refuse(&fold, &interrupt(LeaseDisposition::PredictedRetained)),
            FoldError::InvalidLeaseDisposition { .. }
        ));
        assert!(matches!(
            refuse(&fold, &interrupt(LeaseDisposition::LineageHeld)),
            FoldError::InvalidLeaseDisposition { .. }
        ));
        apply(&mut fold, &interrupt(LeaseDisposition::PredictedReleased));

        assert_eq!(fold.task_state(ZETA), Some(TaskState::Pending));
        assert!(
            !fold
                .leases()
                .expect("started")
                .holds(LeaseOwner::Generation {
                    key: ZETA,
                    generation: GenerationId(0),
                }),
            "the ordinary lease survived a generation that closed"
        );
        let task = fold.task(ZETA).expect("zeta");
        assert!(
            task.open().is_none(),
            "the interrupted generation is still open"
        );
        assert_eq!(task.generations.len(), 1);

        // Generation 0 is over, so it is not closed again and not restarted;
        // the run continues by dispatching the *next* dense generation.
        assert!(matches!(
            refuse(
                &fold,
                &ev(TopologyEventBody::GenerationClosed {
                    data: GenerationClosed {
                        key: ZETA,
                        generation: GenerationId(0),
                        reason: GenerationCloseReason::WorktreeMissing,
                        lease: LeaseDisposition::PredictedReleased,
                    },
                })
            ),
            FoldError::NotTheOpenGeneration { .. }
        ));
        assert!(matches!(
            refuse(&fold, &attempt_started(&fold, ZETA, 0, 2, 0)),
            FoldError::NotTheOpenGeneration { .. }
        ));
        assert!(matches!(
            refuse(&fold, &dispatch(ZETA, 0, &base)),
            FoldError::NonDenseKey { .. }
        ));
        accepts(&fold, &dispatch(ZETA, 1, &base));

        // refusals[15], the coordinate that only matters once a *later*
        // generation is open: `generation_closed(0)` names generation 0, and
        // generation 1 is the open one. A close that took "whatever is open"
        // would close the newer generation under the older one's name, which
        // is a state no reader could recompute from the log.
        apply(&mut fold, &dispatch(ZETA, 1, &base));
        let close = |generation: u32| {
            ev(TopologyEventBody::GenerationClosed {
                data: GenerationClosed {
                    key: ZETA,
                    generation: GenerationId(generation),
                    reason: GenerationCloseReason::WorktreeMissing,
                    lease: LeaseDisposition::PredictedReleased,
                },
            })
        };
        for stale in [0_u32, 2, 9] {
            assert!(
                matches!(
                    refuse(&fold, &close(stale)),
                    FoldError::NotTheOpenGeneration { .. }
                ),
                "a close naming generation {stale} was applied while 1 was the open one"
            );
        }
        let before = fold.task(ZETA).expect("zeta").generations.clone();
        let _ = fold.plan_transition(&close(0));
        assert_eq!(
            fold.task(ZETA).expect("zeta").generations,
            before,
            "a refused close changed the generation it was refused about"
        );
        accepts(&fold, &close(1));

        // A repair holds nothing of its own, so its interruption records
        // `LineageHeld` and its lineage lease is untouched.
        let mut lineage = started();
        merge_task(&mut lineage, ALPHA, 0, 0);
        apply(
            &mut lineage,
            &spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)),
        );
        apply(
            &mut lineage,
            &ev(TopologyEventBody::TaskDispatched {
                data: TaskDispatched {
                    key: TaskKey(3),
                    generation: GenerationId(0),
                    base_sha: base.clone(),
                    worktree_path: "/private/workspaces/tasks/k3-g0".to_owned(),
                    lease: LeaseGrant::InheritedLineage { root: ALPHA },
                    source_candidate: Some(candidate_of(ALPHA, 0)),
                },
            }),
        );
        let repair_start = ev(TopologyEventBody::AttemptStarted {
            data: AttemptStarted4 {
                key: TaskKey(3),
                generation: GenerationId(0),
                attempt: AttemptNumber(1),
                rung: 0,
                binding: frozen_binding(&lineage, TaskKey(3), 0),
                pool: None,
                resume_session: None,
                materialization_observed: Some(Materialization::Clean),
            },
        });
        apply(&mut lineage, &repair_start);
        let held = lineage.leases().cloned();
        apply(
            &mut lineage,
            &ev(TopologyEventBody::AttemptInterrupted {
                data: AttemptInterrupted4 {
                    key: TaskKey(3),
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    lease: LeaseDisposition::LineageHeld,
                    detail: "  the coordinator died  ".to_owned(),
                },
            }),
        );
        assert_eq!(lineage.task_state(TaskKey(3)), Some(TaskState::Pending));
        assert!(lineage.task(TaskKey(3)).expect("repair").open().is_none());
        assert_eq!(
            lineage.leases().cloned(),
            held,
            "an interrupted repair changed a holding, and a lineage member holds none of its own"
        );
    }

    #[test]
    fn an_override_replaces_the_frozen_binding_for_every_later_attempt() {
        // The other half of refusals[11]: when a human named a binding, that is
        // the authority, and the frozen rung is no longer one.
        let base = sha("base");
        let mut fold = started();
        let mut spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        merge_task(&mut fold, ALPHA, 0, 0);
        clip_to_human_binding(
            &mut spawn,
            vec!["  Codex-CLI  ".to_owned(), "copilot".to_owned()],
        );
        apply(&mut fold, &spawn_event(spawn));

        let override_binding = BindingOverride {
            key: TaskKey(3),
            question: QuestionId::from("q-binding-Ünicode"),
            option_index: 1,
            agent: "copilot".to_owned(),
            model: "gpt-5.6".to_owned(),
            effort: Effort::XHigh,
        };
        apply(
            &mut fold,
            &answered(
                TaskKey(3),
                "q-binding-Ünicode",
                Answer4::Answered {
                    option_index: 1,
                    binding_override: Some(override_binding.clone()),
                },
            ),
        );
        assert_eq!(
            fold.binding_override(TaskKey(3)),
            Some(&override_binding),
            "an accepted override is what later attempts are checked against"
        );
        assert_eq!(fold.task_state(TaskKey(3)), Some(TaskState::Pending));

        apply(
            &mut fold,
            &ev(TopologyEventBody::TaskDispatched {
                data: TaskDispatched {
                    key: TaskKey(3),
                    generation: GenerationId(0),
                    base_sha: base,
                    worktree_path: "/private/workspaces/tasks/k3-g0".to_owned(),
                    lease: LeaseGrant::InheritedLineage { root: ALPHA },
                    source_candidate: Some(candidate_of(ALPHA, 0)),
                },
            }),
        );
        let attempt = |agent: &str, model: &str, effort: Effort, tier: Tier| {
            ev(TopologyEventBody::AttemptStarted {
                data: AttemptStarted4 {
                    key: TaskKey(3),
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    rung: 0,
                    binding: RungBinding {
                        tier,
                        agent: agent.to_owned(),
                        model: model.to_owned(),
                        pinned: false,
                        effort,
                    },
                    pool: None,
                    resume_session: None,
                    materialization_observed: Some(Materialization::Conflict),
                },
            })
        };
        // The tier is not compared: an override chooses an agent from a frozen
        // option list, and the tier it lands on is whatever that agent is
        // bound at.
        accepts(
            &fold,
            &attempt("copilot", "gpt-5.6", Effort::XHigh, Tier::Small),
        );
        accepts(
            &fold,
            &attempt("copilot", "gpt-5.6", Effort::XHigh, Tier::Frontier),
        );
        for (label, agent, model, effort) in [
            ("agent", "  Codex-CLI  ", "gpt-5.6", Effort::XHigh),
            ("model", "copilot", "claude-opus-5", Effort::XHigh),
            ("effort", "copilot", "gpt-5.6", Effort::Low),
        ] {
            assert!(
                matches!(
                    refuse(&fold, &attempt(agent, model, effort, Tier::Mid)),
                    FoldError::BindingMismatch { key: 3, .. }
                ),
                "the {label} case ran something the human did not name"
            );
        }
    }

    #[test]
    fn a_settlement_records_the_disposition_its_holding_admits() {
        // refusals[14], as a crossed grid: two kinds of holding, three events
        // (one that keeps the generation, two that end it), three dispositions.
        // Exactly one cell per (holding, fate) is accepted.
        let base = sha("base");
        let mut ordinary = started();
        apply(&mut ordinary, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&ordinary, ZETA, 0, 1, 0);
        apply(&mut ordinary, &start);

        let mut lineage = started();
        merge_task(&mut lineage, ALPHA, 0, 0);
        apply(
            &mut lineage,
            &spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)),
        );
        apply(
            &mut lineage,
            &ev(TopologyEventBody::TaskDispatched {
                data: TaskDispatched {
                    key: TaskKey(3),
                    generation: GenerationId(0),
                    base_sha: base.clone(),
                    worktree_path: "/private/workspaces/tasks/k3-g0".to_owned(),
                    lease: LeaseGrant::InheritedLineage { root: ALPHA },
                    source_candidate: Some(candidate_of(ALPHA, 0)),
                },
            }),
        );
        let repair_start = ev(TopologyEventBody::AttemptStarted {
            data: AttemptStarted4 {
                key: TaskKey(3),
                generation: GenerationId(0),
                attempt: AttemptNumber(1),
                rung: 0,
                binding: frozen_binding(&lineage, TaskKey(3), 0),
                pool: None,
                resume_session: None,
                materialization_observed: Some(Materialization::Clean),
            },
        });
        apply(&mut lineage, &repair_start);

        let dispositions = [
            LeaseDisposition::PredictedReleased,
            LeaseDisposition::PredictedRetained,
            LeaseDisposition::LineageHeld,
        ];
        for (holding, fold, key) in [
            ("ordinary", &ordinary, ZETA),
            ("lineage", &lineage, TaskKey(3)),
        ] {
            for disposition in dispositions {
                // A terminal failure ends the generation.
                let closing = settle(
                    key,
                    0,
                    1,
                    AttemptSettlement::Closed {
                        transition: SettlementTransition::Failed {
                            halts_run: false,
                            reason: "  the ladder ran out  ".to_owned(),
                        },
                        lease: disposition,
                    },
                );
                let closing_ok = disposition
                    == if holding == "ordinary" {
                        LeaseDisposition::PredictedReleased
                    } else {
                        LeaseDisposition::LineageHeld
                    };
                assert_eq!(
                    fold.plan_transition(&closing).is_ok(),
                    closing_ok,
                    "a {holding} generation that closes and records {disposition:?}"
                );

                // An interruption *closes* the generation
                // (transaction_fault_matrix[T-ATTEMPT]: "generation Closed,
                // lease by kind"), so it records the same disposition a
                // terminal failure does — an ordinary generation releases its
                // predicted region, a lineage member goes on holding its
                // root's.
                let interrupted = ev(TopologyEventBody::AttemptInterrupted {
                    data: AttemptInterrupted4 {
                        key,
                        generation: GenerationId(0),
                        attempt: AttemptNumber(1),
                        lease: disposition,
                        detail: "  the coordinator died  ".to_owned(),
                    },
                });
                assert_eq!(
                    fold.plan_transition(&interrupted).is_ok(),
                    closing_ok,
                    "a {holding} generation that is interrupted and records {disposition:?}"
                );

                // A success is the one settlement that leaves the generation
                // open: it hands the region to the candidate, so the
                // generation keeps holding it.
                let surviving_ok = disposition
                    == if holding == "ordinary" {
                        LeaseDisposition::PredictedRetained
                    } else {
                        LeaseDisposition::LineageHeld
                    };
                let succeeded = settle(
                    key,
                    0,
                    1,
                    AttemptSettlement::Closed {
                        transition: SettlementTransition::Succeeded,
                        lease: disposition,
                    },
                );
                assert_eq!(
                    fold.plan_transition(&succeeded).is_ok(),
                    surviving_ok,
                    "a {holding} generation that succeeded and records {disposition:?}"
                );
            }
        }
    }

    #[test]
    fn a_settlement_applies_only_to_the_attempt_that_is_running() {
        // refusals[16] / ST-06 for settlements, over each coordinate of the
        // identity in turn.
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        let closed = || AttemptSettlement::Closed {
            transition: SettlementTransition::Retry,
            lease: LeaseDisposition::PredictedReleased,
        };
        // No attempt is running yet.
        assert!(matches!(
            refuse(&fold, &settle(ZETA, 0, 1, closed())),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);
        accepts(&fold, &settle(ZETA, 0, 1, closed()));
        // Another task, another generation, another attempt.
        assert!(matches!(
            refuse(&fold, &settle(ALPHA, 0, 1, closed())),
            FoldError::NotTheOpenGeneration { key: 1, .. }
        ));
        assert!(matches!(
            refuse(&fold, &settle(ZETA, 1, 1, closed())),
            FoldError::NotTheOpenGeneration {
                key: 0,
                generation: 1,
                ..
            }
        ));
        assert_eq!(
            refuse(&fold, &settle(ZETA, 0, 2, closed())),
            FoldError::WrongAttempt {
                kind: "attempt_finished",
                key: 0,
                generation: 0,
                attempt: 2,
                expected: "1".to_owned(),
            }
        );
        // The same three, for an interruption.
        let interrupt = |key: TaskKey, generation: u32, attempt: u32| {
            ev(TopologyEventBody::AttemptInterrupted {
                data: AttemptInterrupted4 {
                    key,
                    generation: GenerationId(generation),
                    attempt: AttemptNumber(attempt),
                    // T-ATTEMPT closes the generation, so an ordinary one
                    // releases the region it predicted.
                    lease: LeaseDisposition::PredictedReleased,
                    detail: "  the coordinator died  ".to_owned(),
                },
            })
        };
        accepts(&fold, &interrupt(ZETA, 0, 1));
        assert!(fold.plan_transition(&interrupt(ALPHA, 0, 1)).is_err());
        assert!(fold.plan_transition(&interrupt(ZETA, 1, 1)).is_err());
        assert!(fold.plan_transition(&interrupt(ZETA, 0, 2)).is_err());
    }

    #[test]
    fn a_generation_is_closed_only_from_an_open_class_with_no_attempt() {
        // refusals[15], over every class a generation can be in.
        let base = sha("base");
        let closed_event = |key: TaskKey, generation: u32, lease: LeaseDisposition| {
            ev(TopologyEventBody::GenerationClosed {
                data: GenerationClosed {
                    key,
                    generation: GenerationId(generation),
                    reason: GenerationCloseReason::RunEnding {
                        outcome: RunOutcome::Parked,
                    },
                    lease,
                },
            })
        };

        // OpenNoAttempt: closable.
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        accepts(
            &fold,
            &closed_event(ZETA, 0, LeaseDisposition::PredictedReleased),
        );

        // InFlight: not closable — the attempt is settled or interrupted first.
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);
        assert!(matches!(
            refuse(
                &fold,
                &closed_event(ZETA, 0, LeaseDisposition::PredictedReleased)
            ),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));

        // RetainedIdle: closable — this is how a resume discards a session it
        // may not resume.
        let mut retained = fold.clone();
        apply(
            &mut retained,
            &settle(
                ZETA,
                0,
                1,
                AttemptSettlement::Retained {
                    retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                    retained_incarnation: Epoch(0),
                },
            ),
        );
        accepts(
            &retained,
            &closed_event(ZETA, 0, LeaseDisposition::PredictedReleased),
        );

        // Promoting: not closable — a promoting generation is promoted.
        let mut promoting = fold.clone();
        apply(&mut promoting, &succeeded(ZETA, 0, 1));
        assert!(matches!(
            refuse(
                &promoting,
                &closed_event(ZETA, 0, LeaseDisposition::PredictedReleased)
            ),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));

        // Closed: not closable twice.
        let mut over = promoting.clone();
        apply(&mut over, &candidate_prepared(ZETA, 0, &base));
        apply(&mut over, &candidate_created(ZETA, 0));
        assert!(matches!(
            refuse(
                &over,
                &closed_event(ZETA, 0, LeaseDisposition::PredictedReleased)
            ),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Candidates, the queue, and the publication relations
    // -----------------------------------------------------------------------

    #[test]
    fn a_candidate_is_prepared_by_the_generation_whose_attempt_succeeded() {
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);

        // ST-06: not while the attempt is still running.
        assert!(matches!(
            refuse(&fold, &candidate_prepared(ZETA, 0, &base)),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));
        apply(&mut fold, &succeeded(ZETA, 0, 1));
        accepts(&fold, &candidate_prepared(ZETA, 0, &base));

        // ST-06: not another generation's, and not another task's.
        assert!(matches!(
            refuse(&fold, &candidate_prepared(ZETA, 1, &base)),
            FoldError::NotTheOpenGeneration {
                key: 0,
                generation: 1,
                ..
            }
        ));
        assert!(matches!(
            refuse(&fold, &candidate_prepared(ALPHA, 0, &base)),
            FoldError::NotTheOpenGeneration { key: 1, .. }
        ));

        // The commit is parented on the base the work started from, and that
        // base is the one the generation was dispatched at. INV-09's
        // exact-base decision compares the head against `base_sha` and then
        // publishes `commit_sha`, so both claims have to hold.
        let mut reparented = candidate_prepared(ZETA, 0, &base);
        if let TopologyEventBody::CandidatePrepared { data } = &mut reparented.body {
            data.parent_sha = sha("elsewhere");
        }
        assert!(matches!(
            refuse(&fold, &reparented),
            FoldError::InconsistentRecord { .. }
        ));
        let moved_base = candidate_prepared(ZETA, 0, &sha("another-base"));
        assert!(matches!(
            refuse(&fold, &moved_base),
            FoldError::InconsistentRecord { .. }
        ));

        // The region it takes is the region its diff touched.
        let mut inconsistent_region = candidate_prepared(ZETA, 0, &base);
        if let TopologyEventBody::CandidatePrepared { data } = &mut inconsistent_region.body {
            data.lease_effect = CandidateLeaseEffect::ReplacesPredicted { paths: region(MID) };
        }
        assert!(matches!(
            refuse(&fold, &inconsistent_region),
            FoldError::InconsistentRecord { .. }
        ));

        // An ordinary candidate replaces its predicted region; only a lineage
        // member widens a lineage.
        let mut widening = candidate_prepared(ZETA, 0, &base);
        if let TopologyEventBody::CandidatePrepared { data } = &mut widening.body {
            data.lease_effect = CandidateLeaseEffect::WidensLineage {
                root: ALPHA,
                paths: region(ZETA),
            };
        }
        assert!(matches!(
            refuse(&fold, &widening),
            FoldError::InconsistentRecord { .. }
        ));

        // ST-06's "wrong attempt number", for the record the candidate
        // carries. The generation ran attempt 1, so 0, 2 and 9 all name an
        // attempt that did not produce this commit. Without this the embedded
        // record is inert data and a candidate can be published attributed to
        // an attempt that failed.
        for wrong in [0, 2, 9] {
            let mut misattributed = candidate_prepared(ZETA, 0, &base);
            if let TopologyEventBody::CandidatePrepared { data } = &mut misattributed.body {
                *data.attempt = attempt_record(wrong);
            }
            assert!(
                matches!(
                    refuse(&fold, &misattributed),
                    FoldError::WrongAttempt {
                        kind: "candidate_prepared",
                        key: 0,
                        ..
                    }
                ),
                "a candidate attributed to attempt {wrong} of a generation that ran 1 was folded"
            );
        }

        // Preparing takes the actual region and gives up the predicted one.
        apply(&mut fold, &candidate_prepared(ZETA, 0, &base));
        let leases = fold.leases().expect("started");
        assert!(leases.holds(LeaseOwner::Candidate {
            key: ZETA,
            generation: GenerationId(0)
        }));
        assert!(!leases.holds(LeaseOwner::Generation {
            key: ZETA,
            generation: GenerationId(0)
        }));
        assert_eq!(fold.task_state(ZETA), Some(TaskState::AwaitingMerge));

        // INV-06: "at most one candidate per generation", enforced_by "fold
        // refuses a second candidate for a generation". The second record is
        // valid in isolation — it is the *same* event that was just accepted,
        // and so is a differing one — and it is refused because the generation
        // has already prepared.
        assert!(matches!(
            refuse(&fold, &candidate_prepared(ZETA, 0, &base)),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));
        let mut second = candidate_prepared(ZETA, 0, &base);
        if let TopologyEventBody::CandidatePrepared { data } = &mut second.body {
            data.commit_sha = sha("a-second-commit");
            data.candidate_ref = git_ref("candidates/0/0-again");
        }
        assert!(
            matches!(
                refuse(&fold, &second),
                FoldError::NotTheOpenGeneration { key: 0, .. }
            ),
            "a second candidate replaced the first and left it abandoned"
        );
        // And the first candidate is still the one the generation holds, so a
        // promotion of the second has nothing to promote.
        let mut promotes_second = candidate_created(ZETA, 0);
        if let TopologyEventBody::TaskCandidateCreated { data } = &mut promotes_second.body {
            data.candidate.commit_sha = sha("a-second-commit");
            data.candidate.candidate_ref = git_ref("candidates/0/0-again");
        }
        assert!(matches!(
            refuse(&fold, &promotes_second),
            FoldError::InconsistentRecord { .. }
        ));
        accepts(&fold, &candidate_created(ZETA, 0));
    }

    #[test]
    fn a_candidate_names_the_attempt_that_produced_it_live_and_on_replay() {
        // ST-06 for `candidate_prepared`, through the durable path as well as
        // the live one: the generation retried, so attempt 2 is the authority
        // and the number the earlier attempt carried is no longer one.
        let base = sha("base");
        let mut live = started();
        let mut trace = vec![run_started_event()];
        let push =
            |live: &mut TopologyFold, trace: &mut Vec<TopologyEvent>, event: TopologyEvent| {
                apply(live, &event);
                trace.push(event);
            };
        push(&mut live, &mut trace, dispatch(ALPHA, 0, &base));
        let start = attempt_started(&live, ALPHA, 0, 1, 0);
        push(&mut live, &mut trace, start);
        push(
            &mut live,
            &mut trace,
            settle(
                ALPHA,
                0,
                1,
                AttemptSettlement::Retained {
                    retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                    retained_incarnation: Epoch(0),
                },
            ),
        );
        let retry = ev(TopologyEventBody::AttemptStarted {
            data: AttemptStarted4 {
                key: ALPHA,
                generation: GenerationId(0),
                attempt: AttemptNumber(2),
                rung: 0,
                binding: frozen_binding(&live, ALPHA, 0),
                pool: None,
                resume_session: Some(SessionId("sess-ÜNI-0042".to_owned())),
                materialization_observed: None,
            },
        });
        push(&mut live, &mut trace, retry);
        push(&mut live, &mut trace, succeeded(ALPHA, 0, 2));

        // Attempt 1 ran and did not produce this candidate; attempt 2 did.
        assert!(matches!(
            refuse(&live, &candidate_prepared_at(ALPHA, 0, 1, &base)),
            FoldError::WrongAttempt { .. }
        ));
        accepts(&live, &candidate_prepared_at(ALPHA, 0, 2, &base));

        // The same pair over the wire: a log whose candidate names attempt 1
        // stops at that line, and the authoritative one replays.
        let bytes = |trace: &[TopologyEvent]| -> Vec<u8> {
            let mut log = Vec::new();
            for event in trace {
                log.extend_from_slice(serde_json::to_string(event).expect("serialize").as_bytes());
                log.push(b'\n');
            }
            log
        };
        let mut hostile = trace.clone();
        hostile.push(candidate_prepared_at(ALPHA, 0, 1, &base));
        let parsed = TopologyFold::parse_log(&bytes(&hostile)).expect("the log parses");
        assert!(matches!(
            TopologyFold::replay(inputs(), &parsed)
                .expect_err("a misattributed candidate is refused on replay"),
            FoldError::WrongAttempt { .. }
        ));

        push(
            &mut live,
            &mut trace,
            candidate_prepared_at(ALPHA, 0, 2, &base),
        );
        let parsed = TopologyFold::parse_log(&bytes(&trace)).expect("the log parses");
        let replayed =
            TopologyFold::replay(inputs(), &parsed).expect("the authoritative log replays");
        assert_eq!(live.state(), replayed.state());
    }

    #[test]
    fn a_promotion_names_the_candidate_that_was_prepared() {
        // ST-06's "a mismatched task_candidate_created", over every coordinate
        // of the reference: a promotion that named another commit would give
        // the queue a position pointing at an object nothing judged.
        let base = sha("base");
        let mut fold = started();
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);
        apply(&mut fold, &succeeded(ZETA, 0, 1));

        // Before anything was prepared.
        assert!(matches!(
            refuse(&fold, &candidate_created(ZETA, 0)),
            FoldError::NotTheOpenGeneration { key: 0, .. }
        ));
        apply(&mut fold, &candidate_prepared(ZETA, 0, &base));
        accepts(&fold, &candidate_created(ZETA, 0));

        let mismatched = |mutate: fn(&mut CandidateRef)| {
            let mut candidate = candidate_of(ZETA, 0);
            mutate(&mut candidate);
            ev(TopologyEventBody::TaskCandidateCreated {
                data: TaskCandidateCreated { candidate },
            })
        };
        assert!(matches!(
            refuse(
                &fold,
                &mismatched(|candidate| candidate.commit_sha = sha("smuggled"))
            ),
            FoldError::InconsistentRecord { .. }
        ));
        assert!(matches!(
            refuse(
                &fold,
                &mismatched(|candidate| candidate.candidate_ref = git_ref("candidates/9/9"))
            ),
            FoldError::InconsistentRecord { .. }
        ));
        assert!(matches!(
            refuse(
                &fold,
                &mismatched(|candidate| candidate.generation = GenerationId(1))
            ),
            FoldError::NotTheOpenGeneration { .. }
        ));
        assert!(matches!(
            refuse(&fold, &mismatched(|candidate| candidate.key = ALPHA)),
            FoldError::NotTheOpenGeneration { key: 1, .. }
        ));

        // Promotion ends the generation and takes the queue position.
        apply(&mut fold, &candidate_created(ZETA, 0));
        assert_eq!(fold.queue().expect("started").len(), 1);
        assert_eq!(
            fold.task(ZETA).expect("zeta").generations[0].class,
            GenerationClass::Closed
        );
    }

    /// Two candidates queued in an order the fixture chose, so "first" is a
    /// position rather than a coincidence.
    fn two_queued() -> TopologyFold {
        let base = sha("base");
        let mut fold = started();
        for (key, generation) in [(MID, 0), (ZETA, 0)] {
            apply(&mut fold, &dispatch(key, generation, &base));
            let start = attempt_started(&fold, key, generation, 1, 0);
            apply(&mut fold, &start);
            apply(&mut fold, &succeeded(key, generation, 1));
            apply(&mut fold, &candidate_prepared(key, generation, &base));
            apply(&mut fold, &candidate_created(key, generation));
        }
        fold
    }

    fn verification_started(
        key: TaskKey,
        generation: u32,
        sequence: u32,
        head: &CommitSha,
        proposal: &CommitSha,
    ) -> TopologyEvent {
        ev(TopologyEventBody::MergeVerificationStarted {
            data: MergeVerificationStarted {
                sequence: SequenceId(sequence),
                candidate: candidate_of(key, generation),
                basis: VerificationBasis::StaleClean {
                    prepared_ref: git_ref(&format!("prepared/{sequence}")),
                },
                expected_head: head.clone(),
                proposed_sha: proposal.clone(),
            },
        })
    }

    #[test]
    fn an_integration_starts_only_for_the_first_eligible_candidate() {
        // refusals[8]. The queue is FIFO by promotion order and the *first
        // eligible* entry is integrated, which is not the same as the first
        // one: three of the four ineligibility rules move the answer past the
        // head of the queue, and the fourth is the head itself being fine.
        let head = sha("head");
        let proposal = sha("proposal");
        let fold = two_queued();
        let queued: Vec<u32> = fold
            .queue()
            .expect("started")
            .entries()
            .iter()
            .map(|entry| entry.key().0)
            .collect();
        assert_eq!(queued, vec![MID.0, ZETA.0], "the queue is promotion order");

        accepts(&fold, &verification_started(MID, 0, 0, &head, &proposal));
        assert!(matches!(
            refuse(&fold, &verification_started(ZETA, 0, 0, &head, &proposal)),
            FoldError::NotFirstEligible { key: 0, .. }
        ));

        // A candidate holding no position at all.
        assert!(matches!(
            refuse(&fold, &verification_started(ALPHA, 0, 0, &head, &proposal)),
            FoldError::NotFirstEligible { key: 1, .. }
        ));

        // Its task parked: the entry keeps its place and the next eligible one
        // is integrated instead.
        let mut parked = fold.clone();
        apply(
            &mut parked,
            &ev(TopologyEventBody::QuestionRaised {
                data: QuestionRaised4 {
                    question: question("q-park-Ünicode", MID),
                },
            }),
        );
        assert!(matches!(
            refuse(&parked, &verification_started(MID, 0, 0, &head, &proposal)),
            FoldError::NotFirstEligible { key: 2, .. }
        ));
        accepts(&parked, &verification_started(ZETA, 0, 0, &head, &proposal));
    }

    #[test]
    fn sequences_are_dense_and_one_transaction_runs_at_a_time() {
        // refusals[6], [7] and the sequence half of [10].
        let head = sha("head");
        let proposal = sha("proposal");
        let mut fold = two_queued();

        for sequence in [1, 2, 9] {
            assert_eq!(
                refuse(
                    &fold,
                    &verification_started(MID, 0, sequence, &head, &proposal)
                ),
                FoldError::NonDenseSequence {
                    kind: "merge_verification_started",
                    sequence,
                    next: 0,
                }
            );
        }
        apply(
            &mut fold,
            &verification_started(MID, 0, 0, &head, &proposal),
        );

        // A second transaction while one is unresolved.
        assert_eq!(
            refuse(&fold, &verification_started(ZETA, 0, 1, &head, &proposal)),
            FoldError::TransactionAlreadyOpen {
                kind: "merge_verification_started",
                sequence: 1,
                open: 0,
            }
        );

        // An event that names a sequence other than the open one.
        let unavailable = |sequence: u32| {
            ev(TopologyEventBody::MergeVerificationUnavailable {
                data: MergeVerificationUnavailable {
                    sequence: SequenceId(sequence),
                    cause: UnavailableCause::Infrastructure {
                        kind: InfrastructureKind::RateLimited,
                    },
                    outcome: UnavailableOutcome::Deferred { defers: 1 },
                },
            })
        };
        assert_eq!(
            refuse(&fold, &unavailable(1)),
            FoldError::WrongSequence {
                kind: "merge_verification_unavailable",
                sequence: 1,
                open: "0".to_owned(),
            }
        );
        accepts(&fold, &unavailable(0));

        // Resolving one consumes its number: the next transaction is 1.
        apply(&mut fold, &unavailable(0));
        assert!(matches!(
            refuse(&fold, &verification_started(ZETA, 0, 0, &head, &proposal)),
            FoldError::NonDenseSequence { next: 1, .. }
        ));
        accepts(&fold, &verification_started(ZETA, 0, 1, &head, &proposal));

        // And an event that belongs to no transaction at all.
        assert_eq!(
            refuse(&two_queued(), &unavailable(0)),
            FoldError::WrongSequence {
                kind: "merge_verification_unavailable",
                sequence: 0,
                open: "none".to_owned(),
            }
        );
    }

    #[test]
    fn a_stale_verification_runs_only_on_a_candidate_that_is_actually_stale() {
        // INV-09: the exact-base decision is made from the head before any
        // staging effect, so a candidate whose base *is* the head is published
        // fast and is never cherry-picked or re-verified.
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let fold = two_queued();
        assert!(matches!(
            refuse(&fold, &verification_started(MID, 0, 0, &base, &proposal)),
            FoldError::InconsistentRecord { .. }
        ));
        accepts(&fold, &verification_started(MID, 0, 0, &head, &proposal));

        // A stale-clean verification judges the proposal the cherry-pick
        // produced; an already-present one judges the head itself. Each refuses
        // the other's shape.
        let mut stale_at_head = verification_started(MID, 0, 0, &head, &head);
        assert!(matches!(
            refuse(&fold, &stale_at_head),
            FoldError::InconsistentRecord { .. }
        ));
        if let TopologyEventBody::MergeVerificationStarted { data } = &mut stale_at_head.body {
            data.basis = VerificationBasis::AlreadyPresent;
        }
        accepts(&fold, &stale_at_head);

        let mut already_present_elsewhere = stale_at_head;
        if let TopologyEventBody::MergeVerificationStarted { data } =
            &mut already_present_elsewhere.body
        {
            data.proposed_sha = proposal;
        }
        assert!(matches!(
            refuse(&fold, &already_present_elsewhere),
            FoldError::InconsistentRecord { .. }
        ));
    }

    fn verification_record(verdict: Verdict) -> VerificationRecord {
        VerificationRecord {
            verdict,
            gates_passed: verdict != Verdict::GatesFailed,
            reviews: Vec::new(),
            detail: "  the integration verification  ".to_owned(),
        }
    }

    #[test]
    fn the_publication_relations_hold_over_the_crossed_disposition_grid() {
        // refusals[9] and the fold half of refusals[22], as relations rather
        // than examples: for each disposition, the accepted publication and
        // every single-field departure from it. A lookup table keyed on these
        // inputs would have to hold every row of this grid, and the rows are
        // generated from the same fixture the accepted case is.
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");

        // --- fast: the head is exactly the candidate's base -----------------
        let fold = two_queued();
        let fast = fast_publication(MID, 0, 0, &base, vec![MID]);
        accepts(&fold, &fast);

        let fast_cases: [(&str, BreakPublication); 5] = [
            ("a head that is not the candidate's base", |prepared| {
                prepared.expected_head = sha("moved-head");
            }),
            (
                "a proposal that is not the candidate's commit",
                |prepared| {
                    prepared.proposed_sha = sha("smuggled");
                    prepared.candidate_sha = sha("smuggled");
                },
            ),
            ("a proposal pin", |prepared| {
                prepared.prepared_ref = Some(git_ref("prepared/0"));
            }),
            ("a verification as its source", |prepared| {
                prepared.verification_source = VerificationSource::Verification {
                    sequence: SequenceId(0),
                };
            }),
            ("another candidate's record as its source", |prepared| {
                prepared.verification_source = VerificationSource::CandidatePrepared {
                    key: ZETA,
                    generation: GenerationId(0),
                };
            }),
        ];
        for (label, break_it) in fast_cases {
            let mut event = fast.clone();
            if let TopologyEventBody::MergePrepared { data } = &mut event.body {
                break_it(data);
            }
            assert!(
                fold.plan_transition(&event).is_err(),
                "a fast publication with {label} was authorized"
            );
        }

        // --- stale_clean: the pinned proposal, at the head that was read ----
        let mut stale = two_queued();
        apply(
            &mut stale,
            &verification_started(MID, 0, 0, &head, &proposal),
        );
        let stale_publication = |mutate: Option<BreakPublication>| {
            let mut prepared = MergePrepared {
                sequence: SequenceId(0),
                disposition: PreparedDisposition::StaleClean,
                expected_head: head.clone(),
                proposed_sha: proposal.clone(),
                key: MID,
                generation: GenerationId(0),
                candidate_sha: candidate_of(MID, 0).commit_sha,
                candidate_ref: candidate_of(MID, 0).candidate_ref,
                prepared_ref: Some(git_ref("prepared/0")),
                verification_source: VerificationSource::Verification {
                    sequence: SequenceId(0),
                },
                verification: Some(verification_record(Verdict::Passed)),
                satisfies: vec![MID],
            };
            if let Some(mutate) = mutate {
                mutate(&mut prepared);
            }
            ev(TopologyEventBody::MergePrepared {
                data: Box::new(prepared),
            })
        };
        accepts(&stale, &stale_publication(None));

        let stale_cases: [(&str, BreakPublication); 7] = [
            ("a head the verification did not read", |prepared| {
                prepared.expected_head = sha("moved-head");
            }),
            ("a proposal the verification did not judge", |prepared| {
                prepared.proposed_sha = sha("another-proposal");
            }),
            ("no proposal pin", |prepared| prepared.prepared_ref = None),
            ("another pin than the one it verified", |prepared| {
                prepared.prepared_ref = Some(git_ref("prepared/9"));
            }),
            ("no verification record", |prepared| {
                prepared.verification = None;
            }),
            ("a verification that did not pass", |prepared| {
                prepared.verification = Some(VerificationRecord {
                    verdict: Verdict::Rejected,
                    gates_passed: true,
                    reviews: Vec::new(),
                    detail: "  rejected  ".to_owned(),
                });
            }),
            ("the candidate's own record as its source", |prepared| {
                prepared.verification_source = VerificationSource::CandidatePrepared {
                    key: MID,
                    generation: GenerationId(0),
                };
            }),
        ];
        for (label, break_it) in stale_cases {
            assert!(
                stale
                    .plan_transition(&stale_publication(Some(break_it)))
                    .is_err(),
                "a stale-clean publication with {label} was authorized"
            );
        }

        // --- already_present: the head is what was verified -----------------
        let mut present = two_queued();
        let mut basis = verification_started(MID, 0, 0, &head, &head);
        if let TopologyEventBody::MergeVerificationStarted { data } = &mut basis.body {
            data.basis = VerificationBasis::AlreadyPresent;
        }
        apply(&mut present, &basis);
        let present_publication = |mutate: Option<BreakPublication>| {
            let mut prepared = MergePrepared {
                sequence: SequenceId(0),
                disposition: PreparedDisposition::AlreadyPresent,
                expected_head: head.clone(),
                proposed_sha: head.clone(),
                key: MID,
                generation: GenerationId(0),
                candidate_sha: candidate_of(MID, 0).commit_sha,
                candidate_ref: candidate_of(MID, 0).candidate_ref,
                prepared_ref: None,
                verification_source: VerificationSource::Verification {
                    sequence: SequenceId(0),
                },
                verification: Some(verification_record(Verdict::Passed)),
                satisfies: vec![MID],
            };
            if let Some(mutate) = mutate {
                mutate(&mut prepared);
            }
            ev(TopologyEventBody::MergePrepared {
                data: Box::new(prepared),
            })
        };
        accepts(&present, &present_publication(None));
        let present_cases: [(&str, BreakPublication); 3] = [
            ("a proposal that is not the head", |prepared| {
                prepared.proposed_sha = sha("another-proposal");
            }),
            ("a head the verification did not read", |prepared| {
                prepared.expected_head = sha("moved-head");
                prepared.proposed_sha = sha("moved-head");
            }),
            ("a verification that did not pass", |prepared| {
                prepared.verification = Some(verification_record(Verdict::GatesFailed));
            }),
        ];
        for (label, break_it) in present_cases {
            assert!(
                present
                    .plan_transition(&present_publication(Some(break_it)))
                    .is_err(),
                "an already-present publication with {label} was authorized"
            );
        }

        // --- the dispositions do not stand in for one another ---------------
        assert!(
            stale
                .plan_transition(&stale_publication(Some(|prepared| {
                    prepared.disposition = PreparedDisposition::AlreadyPresent;
                })))
                .is_err(),
            "a stale-clean verification published as already-present"
        );
        assert!(
            present
                .plan_transition(&present_publication(Some(|prepared| {
                    prepared.disposition = PreparedDisposition::StaleClean;
                    prepared.prepared_ref = Some(git_ref("prepared/0"));
                })))
                .is_err(),
            "an already-present verification published as stale-clean"
        );
        // And a verified publication cannot open its own transaction, nor a
        // fast one join somebody else's.
        assert!(
            two_queued()
                .plan_transition(&stale_publication(None))
                .is_err()
        );
        assert!(
            stale
                .plan_transition(&fast_publication(MID, 0, 0, &base, vec![MID]))
                .is_err()
        );
    }

    #[test]
    fn a_publication_names_the_candidate_durable_history_recorded_and_no_decoy() {
        // refusals[8]: a publication's relations are against "the candidate's
        // recorded base_sha" and "the candidate's recorded commit_sha" — the
        // record `candidate_prepared` left and the queue entry
        // `task_candidate_created` took, not a copy the event brought with it.
        //
        // The disposition grid moves one field of the *event* and leaves the
        // record alone, so an event that disagrees with itself is what it
        // catches. What it cannot catch is a forgery: an embedded CandidateRef
        // that is internally exact and agrees with every intra-event relation
        // A1 checks, and simply names something durable history never
        // recorded. Each case below moves exactly one coordinate of that
        // identity away from history while keeping the event self-consistent,
        // so a fold that matched on the remaining coordinates accepts it.
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let recorded = candidate_of(MID, 0);

        // --- fast ----------------------------------------------------------
        // A1 pins proposed_sha == candidate_sha for a fast publication, so the
        // one coordinate a forger is free to move is the ref.
        let fold = two_queued();
        let mut decoy_ref = fast_publication(MID, 0, 0, &base, vec![MID]);
        if let TopologyEventBody::MergePrepared { data } = &mut decoy_ref.body {
            data.candidate_ref = git_ref("candidates/2/0-decoy");
            assert_ne!(data.candidate_ref, recorded.candidate_ref);
            assert_eq!(
                data.candidate_sha, recorded.commit_sha,
                "only the ref moved"
            );
            assert_eq!(data.proposed_sha, recorded.commit_sha, "only the ref moved");
        }
        assert!(
            matches!(
                refuse(&fold, &decoy_ref),
                FoldError::InconsistentRecord {
                    kind: "merge_prepared",
                    ..
                }
            ),
            "a fast publication naming a candidate ref no `candidate_prepared` recorded was \
             authorized"
        );

        // --- stale_clean and already_present --------------------------------
        // Here the proposal is the pinned one rather than the candidate's
        // commit, so `candidate_sha` is free too: both coordinates of the
        // cross-record identity can be forged one at a time.
        let verified = |basis_stale: bool| {
            let mut fold = two_queued();
            let event = if basis_stale {
                verification_started(MID, 0, 0, &head, &proposal)
            } else {
                ev(TopologyEventBody::MergeVerificationStarted {
                    data: MergeVerificationStarted {
                        sequence: SequenceId(0),
                        candidate: candidate_of(MID, 0),
                        basis: VerificationBasis::AlreadyPresent,
                        expected_head: head.clone(),
                        proposed_sha: head.clone(),
                    },
                })
            };
            apply(&mut fold, &event);
            fold
        };
        let publication = |basis_stale: bool| MergePrepared {
            sequence: SequenceId(0),
            disposition: if basis_stale {
                PreparedDisposition::StaleClean
            } else {
                PreparedDisposition::AlreadyPresent
            },
            expected_head: head.clone(),
            proposed_sha: if basis_stale {
                proposal.clone()
            } else {
                head.clone()
            },
            key: MID,
            generation: GenerationId(0),
            candidate_sha: recorded.commit_sha.clone(),
            candidate_ref: recorded.candidate_ref.clone(),
            prepared_ref: basis_stale.then(|| git_ref("prepared/0")),
            verification_source: VerificationSource::Verification {
                sequence: SequenceId(0),
            },
            verification: Some(verification_record(Verdict::Passed)),
            satisfies: vec![MID],
        };

        let forgeries: [(&str, ForgeCandidate); 2] = [
            ("commit_sha", |prepared| {
                prepared.candidate_sha = sha("a-commit-nobody-prepared");
            }),
            ("candidate_ref", |prepared| {
                prepared.candidate_ref = git_ref("candidates/2/0-decoy");
            }),
        ];
        for basis_stale in [true, false] {
            let fold = verified(basis_stale);
            let disposition = if basis_stale {
                "stale_clean"
            } else {
                "already_present"
            };
            // The unforged shape is authorized, so the refusals below are
            // about the forged coordinate and about nothing else.
            accepts(
                &fold,
                &ev(TopologyEventBody::MergePrepared {
                    data: Box::new(publication(basis_stale)),
                }),
            );
            for (label, forge) in forgeries {
                let mut prepared = publication(basis_stale);
                forge(&mut prepared);
                let event = ev(TopologyEventBody::MergePrepared {
                    data: Box::new(prepared),
                });
                // Self-consistent: A1 has nothing to say about it.
                if let TopologyEventBody::MergePrepared { data } = &event.body {
                    data.self_consistency()
                        .expect("the forgery agrees with itself, which is what makes it one");
                }
                assert!(
                    matches!(
                        refuse(&fold, &event),
                        FoldError::InconsistentRecord {
                            kind: "merge_prepared",
                            ..
                        }
                    ),
                    "a {disposition} publication whose {label} names nothing in durable history \
                     was authorized"
                );
            }
        }

        // --- and the same, through the durable path -------------------------
        // A forged publication in a log must stop the replay at its own line,
        // not be applied and then contradicted later.
        let mut trace = vec![run_started_event()];
        let mut live = started();
        for (key, generation) in [(MID, 0), (ZETA, 0)] {
            push(&mut live, &mut trace, dispatch(key, generation, &base));
            let start = attempt_started(&live, key, generation, 1, 0);
            push(&mut live, &mut trace, start);
            push(&mut live, &mut trace, succeeded(key, generation, 1));
            push(
                &mut live,
                &mut trace,
                candidate_prepared(key, generation, &base),
            );
            push(&mut live, &mut trace, candidate_created(key, generation));
        }
        let mut forged = trace.clone();
        forged.push(decoy_ref);
        forged.push(merged(MID, 0, 0, vec![MID]));
        let parsed = TopologyFold::parse_log(&wire(&forged)).expect("the log parses");
        assert!(
            matches!(
                TopologyFold::replay(inputs(), &parsed)
                    .expect_err("a forged publication is refused on replay"),
                FoldError::InconsistentRecord {
                    kind: "merge_prepared",
                    ..
                }
            ),
            "a forged publication was applied on replay and its `task_merged` followed it"
        );
    }

    /// The same SHA with its last character moved: a value that differs from
    /// the original in one position out of forty and agrees on every prefix
    /// shorter than the whole.
    fn nudge_last(value: &CommitSha) -> CommitSha {
        let mut moved = value.0.clone();
        let last = moved.pop().expect("a SHA has characters");
        moved.push(if last == 'f' { 'e' } else { 'f' });
        assert_eq!(moved.len(), value.0.len());
        assert_ne!(moved, value.0);
        CommitSha(moved)
    }

    #[test]
    fn a_publication_compares_whole_shas_and_not_prefixes() {
        // refusals[8] names four SHA relations, and every one of them is
        // equality of a commit identity. A comparison that truncated, folded
        // case, or matched a prefix would still reject the grid's cases, which
        // move a SHA to an unrelated value. These move one character of forty,
        // at the end, so a comparison of anything less than the whole accepts
        // them.
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let recorded = candidate_of(MID, 0);

        let fold = two_queued();
        let mut moved_head = fast_publication(MID, 0, 0, &base, vec![MID]);
        if let TopologyEventBody::MergePrepared { data } = &mut moved_head.body {
            data.expected_head = nudge_last(&base);
        }
        assert!(
            fold.plan_transition(&moved_head).is_err(),
            "a fast publication expecting a head one character from the candidate's base was \
             authorized"
        );
        let mut moved_commit = fast_publication(MID, 0, 0, &base, vec![MID]);
        if let TopologyEventBody::MergePrepared { data } = &mut moved_commit.body {
            data.proposed_sha = nudge_last(&recorded.commit_sha);
            data.candidate_sha = nudge_last(&recorded.commit_sha);
        }
        assert!(
            fold.plan_transition(&moved_commit).is_err(),
            "a fast publication proposing a commit one character from the candidate's was \
             authorized"
        );

        let mut stale = two_queued();
        apply(
            &mut stale,
            &verification_started(MID, 0, 0, &head, &proposal),
        );
        let publication = |expected_head: CommitSha, proposed_sha: CommitSha| {
            ev(TopologyEventBody::MergePrepared {
                data: Box::new(MergePrepared {
                    sequence: SequenceId(0),
                    disposition: PreparedDisposition::StaleClean,
                    expected_head,
                    proposed_sha,
                    key: MID,
                    generation: GenerationId(0),
                    candidate_sha: recorded.commit_sha.clone(),
                    candidate_ref: recorded.candidate_ref.clone(),
                    prepared_ref: Some(git_ref("prepared/0")),
                    verification_source: VerificationSource::Verification {
                        sequence: SequenceId(0),
                    },
                    verification: Some(verification_record(Verdict::Passed)),
                    satisfies: vec![MID],
                }),
            })
        };
        accepts(&stale, &publication(head.clone(), proposal.clone()));
        assert!(
            stale
                .plan_transition(&publication(nudge_last(&head), proposal.clone()))
                .is_err(),
            "a stale publication expecting a head one character from the verification's was \
             authorized"
        );
        assert!(
            stale
                .plan_transition(&publication(head.clone(), nudge_last(&proposal)))
                .is_err(),
            "a stale publication proposing a commit one character from the judged one was \
             authorized"
        );
    }

    #[test]
    fn a_verified_publication_belongs_to_its_own_sequence_and_its_own_candidate() {
        // refusals[8] for the two coordinates that identify *which* verification
        // authorized a publication: the source's sequence, and the candidate
        // the open transaction is verifying. Any `Verification` source and any
        // open transaction are the right ones as long as only one exists, so
        // both need a state where more than one identity is available.
        let head = sha("head");
        let proposal = sha("proposal");
        let recorded = candidate_of(MID, 0);
        let publication = |mutate: &dyn Fn(&mut MergePrepared)| {
            let mut prepared = MergePrepared {
                sequence: SequenceId(1),
                disposition: PreparedDisposition::StaleClean,
                expected_head: head.clone(),
                proposed_sha: proposal.clone(),
                key: MID,
                generation: GenerationId(0),
                candidate_sha: recorded.commit_sha.clone(),
                candidate_ref: recorded.candidate_ref.clone(),
                prepared_ref: Some(git_ref("prepared/1")),
                verification_source: VerificationSource::Verification {
                    sequence: SequenceId(1),
                },
                verification: Some(verification_record(Verdict::Passed)),
                satisfies: vec![MID],
            };
            mutate(&mut prepared);
            ev(TopologyEventBody::MergePrepared {
                data: Box::new(prepared),
            })
        };

        // Sequence 0 ran and was interrupted; sequence 1 is the open one. Both
        // are `Verification` sources, so the variant alone no longer decides.
        let mut fold = two_queued();
        apply(
            &mut fold,
            &verification_started(MID, 0, 0, &head, &proposal),
        );
        apply(
            &mut fold,
            &ev(TopologyEventBody::MergeVerificationInterrupted {
                data: MergeVerificationInterrupted {
                    sequence: SequenceId(0),
                    detail: "  the coordinator died  ".to_owned(),
                },
            }),
        );
        apply(
            &mut fold,
            &verification_started(MID, 0, 1, &head, &proposal),
        );
        accepts(&fold, &publication(&|_| {}));
        assert!(
            matches!(
                refuse(
                    &fold,
                    &publication(&|prepared| {
                        prepared.verification_source = VerificationSource::Verification {
                            sequence: SequenceId(0),
                        };
                    })
                ),
                FoldError::InconsistentRecord { .. }
            ),
            "a publication citing a verification that is not the one that authorized it was \
             accepted"
        );

        // The open transaction is verifying mid; a publication of zeta copies
        // its head, proposal, pin and source and is refused because the
        // transaction is not about zeta.
        let zeta = candidate_of(ZETA, 0);
        assert!(
            matches!(
                refuse(
                    &fold,
                    &publication(&|prepared| {
                        prepared.key = ZETA;
                        prepared.candidate_sha = zeta.commit_sha.clone();
                        prepared.candidate_ref = zeta.candidate_ref.clone();
                        prepared.satisfies = vec![ZETA];
                    })
                ),
                FoldError::InconsistentRecord { .. }
            ),
            "a publication of a candidate the open transaction never verified was authorized"
        );
    }

    #[test]
    fn an_already_present_publication_expects_the_head_its_verification_read() {
        // refusals[8]: "merge_prepared(already_present) whose proposed_sha
        // differs from expected_head **or from the verified head**". The two
        // are separate relations, and a self-consistent event satisfies the
        // first while contradicting the second: H2/H2 agrees with itself and
        // names a head no verification of this sequence ever read.
        let head = sha("head");
        let mut fold = two_queued();
        apply(
            &mut fold,
            &ev(TopologyEventBody::MergeVerificationStarted {
                data: MergeVerificationStarted {
                    sequence: SequenceId(0),
                    candidate: candidate_of(MID, 0),
                    basis: VerificationBasis::AlreadyPresent,
                    expected_head: head.clone(),
                    proposed_sha: head.clone(),
                },
            }),
        );
        let recorded = candidate_of(MID, 0);
        let publication = |value: &CommitSha| {
            ev(TopologyEventBody::MergePrepared {
                data: Box::new(MergePrepared {
                    sequence: SequenceId(0),
                    disposition: PreparedDisposition::AlreadyPresent,
                    expected_head: value.clone(),
                    proposed_sha: value.clone(),
                    key: MID,
                    generation: GenerationId(0),
                    candidate_sha: recorded.commit_sha.clone(),
                    candidate_ref: recorded.candidate_ref.clone(),
                    prepared_ref: None,
                    verification_source: VerificationSource::Verification {
                        sequence: SequenceId(0),
                    },
                    verification: Some(verification_record(Verdict::Passed)),
                    satisfies: vec![MID],
                }),
            })
        };
        accepts(&fold, &publication(&head));
        let elsewhere = sha("a-head-nobody-verified");
        assert_ne!(elsewhere, head);
        let event = publication(&elsewhere);
        if let TopologyEventBody::MergePrepared { data } = &event.body {
            data.self_consistency()
                .expect("H2/H2 agrees with itself, which is what makes this the missing case");
        }
        assert!(
            matches!(refuse(&fold, &event), FoldError::InconsistentRecord { .. }),
            "an already-present publication at a head the verification never read was authorized"
        );
    }

    #[test]
    fn one_integration_transaction_at_a_time_including_an_authorized_one() {
        // refusals[7], and the class it is easiest to lose: a fast
        // `merge_prepared` opens a transaction that stays unresolved until
        // `task_merged`. "An authorized publication is always completed
        // (recovery or run-end closure), never abandoned" (INV-09), so the
        // next start waits for it.
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let mut fold = two_queued();
        apply(&mut fold, &fast_publication(MID, 0, 0, &base, vec![MID]));
        assert!(fold.transaction().is_some());

        assert!(
            matches!(
                refuse(&fold, &verification_started(ZETA, 0, 1, &head, &proposal)),
                FoldError::TransactionAlreadyOpen { .. }
            ),
            "an integration started while a fast publication was still owed"
        );
        assert!(
            matches!(
                refuse(&fold, &fast_publication(ZETA, 0, 1, &base, vec![ZETA])),
                FoldError::TransactionAlreadyOpen { .. }
            ),
            "a second fast publication opened while the first was still owed"
        );

        // Once the ref has moved and the merge is recorded, the next one may
        // start — at the adjacent sequence.
        apply(&mut fold, &merged(MID, 0, 0, vec![MID]));
        assert!(fold.transaction().is_none());
        accepts(&fold, &verification_started(ZETA, 0, 1, &head, &proposal));
    }

    #[test]
    fn the_queue_is_ordered_by_creation_and_not_by_preparation() {
        // `coordinator_integration.queue`: "FIFO by **task_candidate_created**
        // append order". Preparation and creation are separate events and a
        // fixture that always pairs them cannot tell which clock the order
        // came from. Here they are deliberately crossed: mid prepares first
        // and zeta is created first, so the two clocks disagree and only one
        // of them produces the queue the packet describes.
        let base = sha("base");
        let mut fold = started();
        for (key, generation) in [(MID, 0), (ZETA, 0)] {
            apply(&mut fold, &dispatch(key, generation, &base));
            let start = attempt_started(&fold, key, generation, 1, 0);
            apply(&mut fold, &start);
            apply(&mut fold, &succeeded(key, generation, 1));
            apply(&mut fold, &candidate_prepared(key, generation, &base));
        }
        // Prepared mid, then zeta. Created zeta, then mid.
        apply(&mut fold, &candidate_created(ZETA, 0));
        apply(&mut fold, &candidate_created(MID, 0));

        let entries = fold.queue().expect("started").entries();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.candidate.key)
                .collect::<Vec<_>>(),
            vec![ZETA, MID],
            "the queue is in preparation order rather than creation order"
        );
        // And the first *eligible* entry is the one an integration may start
        // for, which is the same statement read through the refusal.
        let head = sha("head");
        let proposal = sha("proposal");
        assert!(matches!(
            refuse(&fold, &verification_started(MID, 0, 0, &head, &proposal)),
            FoldError::NotFirstEligible { .. }
        ));
        accepts(&fold, &verification_started(ZETA, 0, 0, &head, &proposal));
    }

    #[test]
    fn keys_and_generations_are_dense_in_both_directions() {
        // refusals[10]: "non-dense keys, generations". The tested direction has
        // always been the gap above; the direction nothing reached is the one
        // below, where a duplicate or earlier key would re-register a task or
        // re-open a generation that is over.
        let base = sha("base");
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        let registry_len = fold.registry().expect("started").len();
        assert_eq!(registry_len, 3);

        for key in [0_u32, 1, 2, 4, 9] {
            let mut spawn = repair_spawn(TaskKey(key), ALPHA, ALPHA);
            spawn.entry.key = TaskKey(key);
            assert!(
                matches!(
                    refuse(&fold, &spawn_event(spawn)),
                    FoldError::NonDenseKey { len: 3, .. }
                ),
                "a spawn at key {key} was registered where the registry holds 3"
            );
        }
        accepts(&fold, &spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)));

        // Generations are dense per task, and alpha's generation 0 is over.
        let mut reopened = started();
        merge_task(&mut reopened, ALPHA, 0, 0);
        let mut run = reopened.run.take().expect("started");
        run.tasks[ALPHA.index()].state = TaskState::Pending;
        reopened.run = Some(run);
        assert_eq!(reopened.task(ALPHA).expect("alpha").generations.len(), 1);
        for generation in [0_u32, 2, 9] {
            assert!(
                matches!(
                    refuse(&reopened, &dispatch(ALPHA, generation, &base)),
                    FoldError::NonDenseKey { len: 1, .. }
                ),
                "generation {generation} was dispatched where the task holds 1"
            );
        }
        accepts(&reopened, &dispatch(ALPHA, 1, &base));
    }

    #[test]
    fn a_wake_clears_every_waiter_in_one_delta() {
        // `defer_wait_elapsed` is a run-level event, not a per-item one: the
        // closure procedure's step (5b) and `coordinator_integration.queue`
        // both describe deferral as a flag cleared "until the next
        // defer_wait_elapsed or run_resumed", with no notion of which waiter it
        // is about. A wake that cleared the first of each kind is
        // indistinguishable from one that cleared all of them unless more than
        // one of each is waiting.
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let mut fold = started();

        // Two tasks deferred by their settlements.
        for key in [ALPHA, MID] {
            apply(&mut fold, &dispatch(key, 0, &base));
            let start = attempt_started(&fold, key, 0, 1, 0);
            apply(&mut fold, &start);
            apply(
                &mut fold,
                &settle(
                    key,
                    0,
                    1,
                    AttemptSettlement::Closed {
                        transition: SettlementTransition::Deferred {
                            defers: 1,
                            reason: "  the pool is down  ".to_owned(),
                        },
                        lease: LeaseDisposition::PredictedReleased,
                    },
                ),
            );
        }
        assert_eq!(fold.task_state(ALPHA), Some(TaskState::Deferred));
        assert_eq!(fold.task_state(MID), Some(TaskState::Deferred));

        // And a candidate deferred by an outage.
        apply(&mut fold, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);
        apply(&mut fold, &succeeded(ZETA, 0, 1));
        apply(&mut fold, &candidate_prepared(ZETA, 0, &base));
        apply(&mut fold, &candidate_created(ZETA, 0));
        apply(
            &mut fold,
            &verification_started(ZETA, 0, 0, &head, &proposal),
        );
        apply(
            &mut fold,
            &unavailable_event(0, outage(), UnavailableOutcome::Deferred { defers: 1 }),
        );
        assert!(fold.queue().expect("started").entries()[0].verification_deferred);

        apply(
            &mut fold,
            &ev(TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 30_000,
                    round: 1,
                },
            }),
        );
        assert_eq!(
            fold.task_state(ALPHA),
            Some(TaskState::Pending),
            "the first deferred task woke"
        );
        assert_eq!(
            fold.task_state(MID),
            Some(TaskState::Pending),
            "the second deferred task did not wake"
        );
        assert!(
            !fold.queue().expect("started").entries()[0].verification_deferred,
            "the deferred candidate did not wake"
        );
        assert_eq!(fold.derived_outcome(), DerivedOutcome::NotEnding);

        // The count survives the wake, so the next deferral is the next
        // consecutive one rather than a restart.
        assert_eq!(fold.queue().expect("started").entries()[0].defers, 1);
        apply(
            &mut fold,
            &verification_started(ZETA, 0, 1, &head, &proposal),
        );
        assert!(matches!(
            refuse(
                &fold,
                &unavailable_event(1, outage(), UnavailableOutcome::Deferred { defers: 1 })
            ),
            FoldError::InvalidDefers { .. }
        ));
    }

    #[test]
    fn a_publication_settles_the_closure_the_fold_derives() {
        // refusals[10]'s "invalid satisfies", over a lineage deep enough that
        // the closure is neither the candidate alone nor the whole registry.
        let base = sha("base");
        let fold = two_queued();
        for satisfies in [vec![], vec![ZETA], vec![MID, ZETA], vec![MID, MID]] {
            let event = fast_publication(MID, 0, 0, &base, satisfies.clone());
            assert!(
                matches!(
                    fold.plan_transition(&event),
                    Err(FoldError::InvalidSatisfies { .. })
                ),
                "a publication settling {satisfies:?} was authorized"
            );
        }
        accepts(&fold, &fast_publication(MID, 0, 0, &base, vec![MID]));

        // A repair carries the work of everything it descends from, so
        // publishing it settles the whole chain back to the root.
        let mut lineage = started();
        merge_task(&mut lineage, ALPHA, 0, 0);
        apply(
            &mut lineage,
            &spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)),
        );
        let mut second = repair_spawn(TaskKey(4), ALPHA, TaskKey(3));
        second.entry.display_id = TaskId::from(
            crate::topology::registry::repair_display_id(1, &TaskId::from("alpha")).as_str(),
        );
        second.entry.lineage = Some(Lineage {
            root: ALPHA,
            parent: TaskKey(3),
            index: 1,
        });
        second.entry.deps = vec![ALPHA];
        second.entry.display_deps = vec![TaskId::from("alpha")];
        apply(&mut lineage, &spawn_event(second));
        assert_eq!(
            lineage
                .state()
                .expect("started")
                .satisfies_closure(TaskKey(4)),
            vec![ALPHA, TaskKey(3), TaskKey(4)],
            "a repair settles itself, its parent and its root"
        );
        assert_eq!(
            lineage.state().expect("started").satisfies_closure(ZETA),
            vec![ZETA],
            "an ordinary candidate settles itself alone"
        );
    }

    #[test]
    fn a_merge_copies_the_authorization_exactly() {
        let base = sha("base");
        let mut fold = two_queued();
        // The ref moves only after a publication was authorized.
        assert!(matches!(
            refuse(&fold, &merged(MID, 0, 0, vec![MID])),
            FoldError::WrongSequence { .. }
        ));
        apply(
            &mut fold,
            &verification_started(MID, 0, 0, &sha("head"), &sha("proposal")),
        );
        assert!(matches!(
            refuse(&fold, &merged(MID, 0, 0, vec![MID])),
            FoldError::InconsistentRecord { .. }
        ));

        let mut fast = two_queued();
        apply(&mut fast, &fast_publication(MID, 0, 0, &base, vec![MID]));
        accepts(&fast, &merged(MID, 0, 0, vec![MID]));

        // A different commit than the one authorized.
        let mut elsewhere = merged(MID, 0, 0, vec![MID]);
        if let TopologyEventBody::TaskMerged { data } = &mut elsewhere.body {
            data.merged_sha = sha("smuggled");
        }
        assert!(matches!(
            refuse(&fast, &elsewhere),
            FoldError::InconsistentRecord { .. }
        ));
        // A closure that is not the authorization's — as a *vector*, so a
        // duplicated or emptied list is as wrong as a widened one and a
        // set-shaped comparison is not enough.
        for wrong in [vec![MID, ZETA], vec![MID, MID], Vec::new(), vec![ZETA]] {
            assert!(
                matches!(
                    refuse(&fast, &merged(MID, 0, 0, wrong.clone())),
                    FoldError::InvalidSatisfies { .. }
                ),
                "a merge settling {wrong:?} was copied from an authorization of [MID]"
            );
        }
        // A lease release that is not the one this publication owes.
        let mut lineage_release = merged(MID, 0, 0, vec![MID]);
        if let TopologyEventBody::TaskMerged { data } = &mut lineage_release.body {
            data.lease_release = MergeLeaseRelease::Lineage { root: MID };
        }
        assert!(matches!(
            refuse(&fast, &lineage_release),
            FoldError::InconsistentRecord { .. }
        ));
        let mut other_candidate = merged(MID, 0, 0, vec![MID]);
        if let TopologyEventBody::TaskMerged { data } = &mut other_candidate.body {
            data.lease_release = MergeLeaseRelease::Candidate {
                key: ZETA,
                generation: GenerationId(0),
            };
        }
        assert!(matches!(
            refuse(&fast, &other_candidate),
            FoldError::InconsistentRecord { .. }
        ));

        // Merging settles the closure, frees the position and the region.
        apply(&mut fast, &merged(MID, 0, 0, vec![MID]));
        assert_eq!(fast.task_state(MID), Some(TaskState::Merged));
        assert_eq!(fast.queue().expect("started").len(), 1);
        assert!(
            !fast
                .leases()
                .expect("started")
                .holds(LeaseOwner::Candidate {
                    key: MID,
                    generation: GenerationId(0)
                })
        );
        assert!(fast.transaction().is_none());
    }

    // -----------------------------------------------------------------------
    // Outages, rejections and lineage
    // -----------------------------------------------------------------------

    fn unavailable_event(
        sequence: u32,
        cause: UnavailableCause,
        outcome: UnavailableOutcome,
    ) -> TopologyEvent {
        ev(TopologyEventBody::MergeVerificationUnavailable {
            data: MergeVerificationUnavailable {
                sequence: SequenceId(sequence),
                cause,
                outcome,
            },
        })
    }

    fn outage() -> UnavailableCause {
        UnavailableCause::Infrastructure {
            kind: InfrastructureKind::ReviewerTimeout,
        }
    }

    #[test]
    fn a_deferred_verification_is_consecutive_and_within_the_frozen_allowance() {
        // refusals[16] and `coordinator_integration.dispositions`, as the
        // partition they are: an Infrastructure outage defers "while defers <
        // the frozen max_defers" and parks "at max_defers". The run froze
        // max_defers = 2, so exactly one deferral is available and the second
        // outage parks. Both arms are crossed against every count, so a fold
        // that moved the boundary either way is caught in one direction or the
        // other.
        //
        // The allowance is read from the frozen record and the expected
        // verdicts are computed from the packet's inequality, not from the
        // function under test.
        let head = sha("head");
        let proposal = sha("proposal");
        let mut fold = two_queued();
        let max = fold.started().expect("started").limits.max_defers;
        assert_eq!(max, 2, "the fixture's allowance is what this test is about");

        // Count 0 -> the run may still defer, and may not yet park.
        apply(
            &mut fold,
            &verification_started(MID, 0, 0, &head, &proposal),
        );
        for count in [0, 2, 3, 9] {
            assert!(
                matches!(
                    fold.plan_transition(&unavailable_event(
                        0,
                        outage(),
                        UnavailableOutcome::Deferred { defers: count }
                    )),
                    Err(FoldError::InvalidDefers { .. })
                ),
                "a deferral counted {count} where the candidate has 0 was folded"
            );
        }
        assert!(
            matches!(
                refuse(
                    &fold,
                    &unavailable_event(
                        0,
                        outage(),
                        UnavailableOutcome::Parked {
                            question: question("q-outage-early-Ünicode", MID),
                        },
                    )
                ),
                FoldError::InvalidDefers { .. }
            ),
            "an infrastructure outage parked one deferral early, spending an allowance the run \
             still had"
        );
        accepts(
            &fold,
            &unavailable_event(0, outage(), UnavailableOutcome::Deferred { defers: 1 }),
        );
        apply(
            &mut fold,
            &unavailable_event(0, outage(), UnavailableOutcome::Deferred { defers: 1 }),
        );
        assert!(
            fold.queue().expect("started").entries()[0].verification_deferred,
            "a deferred candidate is ineligible until the backoff elapses"
        );
        assert_eq!(fold.task_state(MID), Some(TaskState::AwaitingMerge));
        apply(
            &mut fold,
            &ev(TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 30_000,
                    round: 1,
                },
            }),
        );

        // Count 1 -> the next deferral would be the max_defers'th, so the
        // allowance is spent: the outage parks and may not defer at all. This
        // is the cell `defers > max_defers` accepted and `defers >= max_defers`
        // refuses.
        apply(
            &mut fold,
            &verification_started(MID, 0, 1, &head, &proposal),
        );
        for count in [0, 1, 2, 3, 9] {
            assert!(
                matches!(
                    fold.plan_transition(&unavailable_event(
                        1,
                        outage(),
                        UnavailableOutcome::Deferred { defers: count }
                    )),
                    Err(FoldError::InvalidDefers { .. })
                ),
                "the allowance was spent and a deferral counted {count} was folded"
            );
        }
        accepts(
            &fold,
            &unavailable_event(
                1,
                outage(),
                UnavailableOutcome::Parked {
                    question: question("q-outage-Ünicode", MID),
                },
            ),
        );

        // The count is this candidate's own history, not the run's. The second
        // queued candidate has deferred nothing, so its own first deferral is
        // still 1 while MID sits at 1 — a fold that summed the queue would
        // demand 2 here and refuse the count the packet requires.
        apply(
            &mut fold,
            &unavailable_event(
                1,
                outage(),
                UnavailableOutcome::Parked {
                    question: question("q-outage-Ünicode", MID),
                },
            ),
        );
        let other = fold.queue().expect("started").entries()[1]
            .candidate
            .clone();
        assert_ne!(other.key, MID, "the fixture queues two distinct candidates");
        assert_eq!(
            fold.queue().expect("started").entries()[1].defers,
            0,
            "the second candidate has deferred nothing"
        );
        apply(
            &mut fold,
            &verification_started(other.key, other.generation.0, 2, &head, &proposal),
        );
        assert!(
            matches!(
                fold.plan_transition(&unavailable_event(
                    2,
                    outage(),
                    UnavailableOutcome::Deferred { defers: 2 }
                )),
                Err(FoldError::InvalidDefers { .. })
            ),
            "a defer count summed across the queue was accepted for a candidate with none"
        );
        accepts(
            &fold,
            &unavailable_event(2, outage(), UnavailableOutcome::Deferred { defers: 1 }),
        );
    }

    #[test]
    fn an_outage_that_needs_a_person_parks_with_a_question_that_can_be_answered() {
        let head = sha("head");
        let proposal = sha("proposal");
        let mut fold = two_queued();
        apply(
            &mut fold,
            &verification_started(MID, 0, 0, &head, &proposal),
        );

        // A human finding cannot be waited out.
        assert!(matches!(
            refuse(
                &fold,
                &unavailable_event(
                    0,
                    UnavailableCause::HumanRequired {
                        verdict: "  a licence question  ".to_owned(),
                    },
                    UnavailableOutcome::Deferred { defers: 1 },
                )
            ),
            FoldError::InconsistentRecord { .. }
        ));
        // A park that offers nothing to answer with.
        assert!(matches!(
            refuse(
                &fold,
                &unavailable_event(
                    0,
                    outage(),
                    UnavailableOutcome::Parked {
                        question: FrozenQuestion {
                            options: Vec::new(),
                            ..question("q-outage-Ünicode", MID)
                        },
                    },
                )
            ),
            FoldError::InconsistentRecord { .. }
        ));
        // A park whose question is about somebody else.
        assert!(matches!(
            refuse(
                &fold,
                &unavailable_event(
                    0,
                    outage(),
                    UnavailableOutcome::Parked {
                        question: question("q-outage-Ünicode", ZETA),
                    },
                )
            ),
            FoldError::UnanswerableQuestion { .. }
        ));

        // Parking moves the task to awaiting input, and its answer returns it
        // to awaiting merge to be re-verified under a new sequence.
        apply(
            &mut fold,
            &unavailable_event(
                0,
                UnavailableCause::HumanRequired {
                    verdict: "  a licence question  ".to_owned(),
                },
                UnavailableOutcome::Parked {
                    question: question("q-outage-Ünicode", MID),
                },
            ),
        );
        assert_eq!(fold.task_state(MID), Some(TaskState::AwaitingInput));
        apply(
            &mut fold,
            &answered(
                MID,
                "q-outage-Ünicode",
                Answer4::Answered {
                    option_index: 2,
                    binding_override: None,
                },
            ),
        );
        assert_eq!(
            fold.task_state(MID),
            Some(TaskState::AwaitingMerge),
            "an answered verification park returns to the queue, not to dispatch"
        );
        accepts(&fold, &verification_started(MID, 0, 1, &head, &proposal));
    }

    #[test]
    fn a_rejection_creates_or_widens_exactly_one_lineage_and_registers_its_repair() {
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let mut fold = two_queued();
        apply(
            &mut fold,
            &verification_started(MID, 0, 0, &head, &proposal),
        );

        let rejection = |sequence: u32, mutate: Option<BreakRejection>| {
            let mut rejected = MergeRejected {
                sequence: SequenceId(sequence),
                candidate: candidate_of(MID, 0),
                rejecting_head: head.clone(),
                disposition: RejectionDisposition::CodeRejected {
                    verification: verification_record(Verdict::Rejected),
                },
                repair: repair_spawn(TaskKey(3), MID, MID),
                lease_effect: RejectionLeaseEffect::CreatesLineage {
                    root: MID,
                    paths: region(MID),
                },
            };
            rejected.repair.entry.deps = vec![ALPHA];
            rejected.repair.entry.display_deps = vec![TaskId::from("alpha")];
            if let Some(mutate) = mutate {
                mutate(&mut rejected);
            }
            ev(TopologyEventBody::MergeRejected {
                data: Box::new(rejected),
            })
        };
        // The repair's dependency has to be merged, and `alpha` is not yet.
        assert!(matches!(
            refuse(&fold, &rejection(0, None)),
            FoldError::MalformedEntry { key: 3, .. }
        ));

        let mut ready = started();
        merge_task(&mut ready, ALPHA, 0, 0);
        apply(&mut ready, &dispatch(MID, 0, &base));
        let start = attempt_started(&ready, MID, 0, 1, 0);
        apply(&mut ready, &start);
        apply(&mut ready, &succeeded(MID, 0, 1));
        apply(&mut ready, &candidate_prepared(MID, 0, &base));
        apply(&mut ready, &candidate_created(MID, 0));
        apply(
            &mut ready,
            &verification_started(MID, 0, 1, &head, &proposal),
        );
        accepts(&ready, &rejection(1, None));

        let cases: [(&str, BreakRejection); 6] = [
            ("a head the verification did not read", |rejected| {
                rejected.rejecting_head = sha("moved-head");
            }),
            ("a verification that passed", |rejected| {
                rejected.disposition = RejectionDisposition::CodeRejected {
                    verification: VerificationRecord {
                        verdict: Verdict::Passed,
                        gates_passed: true,
                        reviews: Vec::new(),
                        detail: "  passed  ".to_owned(),
                    },
                };
            }),
            ("a lineage rooted elsewhere", |rejected| {
                rejected.lease_effect = RejectionLeaseEffect::CreatesLineage {
                    root: ZETA,
                    paths: region(MID),
                };
            }),
            ("a widening of a lineage that does not exist", |rejected| {
                rejected.lease_effect = RejectionLeaseEffect::WidensLineage {
                    root: MID,
                    paths: region(MID),
                };
            }),
            ("a repair parented on another task", |rejected| {
                rejected.repair.entry.lineage = Some(Lineage {
                    root: MID,
                    parent: ALPHA,
                    index: 0,
                });
            }),
            ("a repair numbered as another member", |rejected| {
                rejected.repair.entry.lineage = Some(Lineage {
                    root: MID,
                    parent: MID,
                    index: 3,
                });
            }),
        ];
        for (label, break_it) in cases {
            assert!(
                ready
                    .plan_transition(&rejection(1, Some(break_it)))
                    .is_err(),
                "a rejection with {label} was folded"
            );
        }

        // Applying it: the candidate leaves the queue, the task awaits its
        // repair, and the lineage holds the region.
        apply(&mut ready, &rejection(1, None));
        assert_eq!(ready.task_state(MID), Some(TaskState::AwaitingRepair));
        assert_eq!(ready.task_state(TaskKey(3)), Some(TaskState::Pending));
        assert!(
            ready
                .queue()
                .expect("started")
                .get(MID, GenerationId(0))
                .is_none()
        );
        assert!(
            ready
                .leases()
                .expect("started")
                .holds(LeaseOwner::Lineage { root: MID })
        );
        assert!(
            !ready
                .leases()
                .expect("started")
                .holds(LeaseOwner::Candidate {
                    key: MID,
                    generation: GenerationId(0)
                })
        );
        assert!(ready.transaction().is_none());
    }

    #[test]
    fn a_conflict_opens_and_closes_its_own_transaction() {
        // A conflict is decided at the cherry-pick, before any verification
        // starts, so it is the first append of its sequence rather than a
        // terminal of somebody else's.
        let base = sha("base");
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        apply(&mut fold, &dispatch(MID, 0, &base));
        let start = attempt_started(&fold, MID, 0, 1, 0);
        apply(&mut fold, &start);
        apply(&mut fold, &succeeded(MID, 0, 1));
        apply(&mut fold, &candidate_prepared(MID, 0, &base));
        apply(&mut fold, &candidate_created(MID, 0));

        let conflict = |sequence: u32| {
            let mut repair = repair_spawn(TaskKey(3), MID, MID);
            repair.entry.deps = vec![ALPHA];
            repair.entry.display_deps = vec![TaskId::from("alpha")];
            ev(TopologyEventBody::MergeRejected {
                data: Box::new(MergeRejected {
                    sequence: SequenceId(sequence),
                    candidate: candidate_of(MID, 0),
                    rejecting_head: sha("head"),
                    disposition: RejectionDisposition::Conflict {
                        paths: region(ZETA),
                    },
                    repair,
                    lease_effect: RejectionLeaseEffect::CreatesLineage {
                        root: MID,
                        paths: region(ZETA),
                    },
                }),
            })
        };
        assert!(matches!(
            refuse(&fold, &conflict(3)),
            FoldError::NonDenseSequence { .. }
        ));
        apply(&mut fold, &conflict(1));
        assert!(fold.transaction().is_none());

        // The lineage holds the candidate's region *and* the conflict's.
        let leases = fold.leases().expect("started");
        let lineage = leases.lineage(MID).expect("the lineage exists");
        let mut held: Vec<&str> = lineage
            .paths
            .prefixes()
            .expect("a bounded region")
            .iter()
            .map(GitPath::as_str)
            .collect();
        held.sort_unstable();
        assert_eq!(held, vec!["build.rs", "src/Zebra", "src/mid"]);
    }

    // -----------------------------------------------------------------------
    // Questions, budget, and the end of a run
    // -----------------------------------------------------------------------

    fn answered(key: TaskKey, id: &str, answer: Answer4) -> TopologyEvent {
        ev(TopologyEventBody::QuestionAnswered {
            data: QuestionAnswered4 {
                key,
                question: QuestionId::from(id),
                answer,
                via: "  tactus answer  ".to_owned(),
            },
        })
    }

    fn raised(id: &str, key: TaskKey) -> TopologyEvent {
        ev(TopologyEventBody::QuestionRaised {
            data: QuestionRaised4 {
                question: question(id, key),
            },
        })
    }

    #[test]
    fn an_answer_names_an_open_question_of_that_task_and_an_option_it_offered() {
        // refusals[13]. A1's half — the override must name the same question,
        // task and option as the answer carrying it — is wired in; this adds
        // the three the fold owns.
        let mut fold = started();
        apply(&mut fold, &raised("q-park-Ünicode", ZETA));

        // A question this log never asked.
        assert!(matches!(
            refuse(
                &fold,
                &answered(
                    ZETA,
                    "q-invented",
                    Answer4::Answered {
                        option_index: 0,
                        binding_override: None
                    }
                )
            ),
            FoldError::WrongQuestion { .. }
        ));
        // The right question, about another task.
        assert!(matches!(
            refuse(
                &fold,
                &answered(
                    ALPHA,
                    "q-park-Ünicode",
                    Answer4::Answered {
                        option_index: 0,
                        binding_override: None
                    }
                )
            ),
            FoldError::WrongQuestion { .. }
        ));
        // An option it did not offer: the fixture's question has three.
        for option_index in [3, 4, 99] {
            assert!(matches!(
                refuse(
                    &fold,
                    &answered(
                        ZETA,
                        "q-park-Ünicode",
                        Answer4::Answered {
                            option_index,
                            binding_override: None
                        }
                    )
                ),
                FoldError::WrongQuestion { .. }
            ));
        }
        for option_index in 0..3 {
            accepts(
                &fold,
                &answered(
                    ZETA,
                    "q-park-Ünicode",
                    Answer4::Answered {
                        option_index,
                        binding_override: None,
                    },
                ),
            );
        }

        // An override that disagrees with the answer carrying it.
        let mismatched = answered(
            ZETA,
            "q-park-Ünicode",
            Answer4::Answered {
                option_index: 1,
                binding_override: Some(BindingOverride {
                    key: ZETA,
                    question: QuestionId::from("q-park-Ünicode"),
                    option_index: 2,
                    agent: "copilot".to_owned(),
                    model: "gpt-5.6".to_owned(),
                    effort: Effort::Low,
                }),
            },
        );
        assert!(matches!(
            refuse(&fold, &mismatched),
            FoldError::InconsistentRecord { .. }
        ));

        // Answered once: the second answer has no open question to name.
        apply(
            &mut fold,
            &answered(
                ZETA,
                "q-park-Ünicode",
                Answer4::Answered {
                    option_index: 1,
                    binding_override: None,
                },
            ),
        );
        let error = refuse(
            &fold,
            &answered(
                ZETA,
                "q-park-Ünicode",
                Answer4::Answered {
                    option_index: 0,
                    binding_override: None,
                },
            ),
        );
        let FoldError::WrongQuestion { detail, .. } = error else {
            panic!("an already-answered question must be refused as one");
        };
        assert!(
            detail.contains("already been answered"),
            "the refusal has to distinguish an answered question from an invented one: {detail}"
        );
        // And its id is never reused for a new question either.
        assert!(matches!(
            refuse(&fold, &raised("q-park-Ünicode", ALPHA)),
            FoldError::WrongQuestion { .. }
        ));
    }

    #[test]
    fn a_decline_fails_its_task_and_halts_only_when_its_recorded_policy_says_so() {
        let mut lenient = started();
        apply(&mut lenient, &raised("q-park-Ünicode", ZETA));
        apply(
            &mut lenient,
            &answered(
                ZETA,
                "q-park-Ünicode",
                Answer4::Declined {
                    decline_halts_run: false,
                },
            ),
        );
        assert_eq!(lenient.task_state(ZETA), Some(TaskState::Failed));
        assert_eq!(lenient.halted_at(), None);

        let mut halting = started();
        apply(&mut halting, &raised("q-park-Ünicode", ZETA));
        apply(
            &mut halting,
            &answered(
                ZETA,
                "q-park-Ünicode",
                Answer4::Declined {
                    decline_halts_run: true,
                },
            ),
        );
        assert_eq!(halting.task_state(ZETA), Some(TaskState::Failed));
        assert_eq!(halting.halted_at(), Some(ZETA));
    }

    #[test]
    fn an_answer_is_refused_after_a_halt_or_a_budget_stop_in_the_same_epoch() {
        // refusals[20], and the epoch scope that makes a resume the way back:
        // a budget-stopped run ingests the answer after its resume, and a
        // halted one never does, because `halted_at` is never cleared.
        let base = sha("base");
        let mut budget = started();
        apply(&mut budget, &raised("q-park-Ünicode", ZETA));
        apply(&mut budget, &budget_exceeded(0, Some(ZETA)));
        let answer = answered(
            ZETA,
            "q-park-Ünicode",
            Answer4::Answered {
                option_index: 0,
                binding_override: None,
            },
        );
        assert_eq!(
            refuse(&budget, &answer),
            FoldError::RunEnding {
                kind: "question_answered",
                what: "the budget stop",
            }
        );
        apply(&mut budget, &resume(container_runner()));
        accepts(&budget, &answer);

        let mut halted = started();
        apply(&mut halted, &dispatch(ALPHA, 0, &base));
        let start = attempt_started(&halted, ALPHA, 0, 1, 0);
        apply(&mut halted, &start);
        apply(&mut halted, &raised("q-park-Ünicode", ZETA));
        apply(
            &mut halted,
            &settle(
                ALPHA,
                0,
                1,
                AttemptSettlement::Closed {
                    transition: SettlementTransition::Failed {
                        halts_run: true,
                        reason: "  the ladder ran out  ".to_owned(),
                    },
                    lease: LeaseDisposition::PredictedReleased,
                },
            ),
        );
        assert_eq!(
            refuse(&halted, &answer),
            FoldError::RunEnding {
                kind: "question_answered",
                what: "a halting settlement",
            }
        );
        // A halt is epoch-scoped for ingestion and permanent for the outcome:
        // the answer file stays on disk, and a resumed halted run still
        // derives Halted.
        apply(&mut halted, &resume(container_runner()));
        assert_eq!(halted.halted_at(), Some(ALPHA));
    }

    fn budget_exceeded(epoch: u32, key: Option<TaskKey>) -> TopologyEvent {
        ev(TopologyEventBody::BudgetExceeded {
            data: BudgetExceeded4 {
                epoch: Epoch(epoch),
                budget: BudgetKind::Run,
                limit_usd: 12.5,
                spent_usd: 13.75,
                key,
            },
        })
    }

    #[test]
    fn a_budget_stop_belongs_to_the_epoch_that_hit_the_ceiling() {
        let mut fold = started();
        assert!(matches!(
            refuse(&fold, &budget_exceeded(3, None)),
            FoldError::InconsistentRecord { .. }
        ));
        assert!(matches!(
            refuse(&fold, &budget_exceeded(0, Some(TaskKey(9)))),
            FoldError::UnknownKey { key: 9, .. }
        ));
        apply(&mut fold, &budget_exceeded(0, Some(ZETA)));
        assert_eq!(
            fold.budget_stop(),
            Some(BudgetStop {
                epoch: Epoch(0),
                budget: BudgetKind::Run,
            })
        );
        // A resume starts a new epoch without one, and the next breach belongs
        // to that epoch rather than the old one.
        apply(&mut fold, &resume(container_runner()));
        assert_eq!(fold.budget_stop(), None);
        assert!(matches!(
            refuse(&fold, &budget_exceeded(0, None)),
            FoldError::InconsistentRecord { .. }
        ));
        accepts(&fold, &budget_exceeded(1, None));
    }

    #[test]
    fn a_wait_never_elapses_under_a_halt_or_a_budget_stop() {
        // refusals[18]: halt and budget outrank backoff.
        let base = sha("base");
        let elapsed = ev(TopologyEventBody::DeferWaitElapsed {
            data: DeferWaitElapsed4 {
                waited_ms: 30_000,
                round: 1,
            },
        });

        let mut deferred = started();
        apply(&mut deferred, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&deferred, ZETA, 0, 1, 0);
        apply(&mut deferred, &start);
        apply(
            &mut deferred,
            &settle(
                ZETA,
                0,
                1,
                AttemptSettlement::Closed {
                    transition: SettlementTransition::Deferred {
                        defers: 1,
                        reason: "  the pool was down  ".to_owned(),
                    },
                    lease: LeaseDisposition::PredictedReleased,
                },
            ),
        );
        assert_eq!(deferred.task_state(ZETA), Some(TaskState::Deferred));
        accepts(&deferred, &elapsed);

        let mut budget = deferred.clone();
        apply(&mut budget, &budget_exceeded(0, None));
        assert_eq!(
            refuse(&budget, &elapsed),
            FoldError::RunEnding {
                kind: "defer_wait_elapsed",
                what: "the budget stop",
            }
        );
        // Cleared by the resume that raises the ceiling.
        apply(&mut budget, &resume(container_runner()));
        assert_eq!(
            budget.task_state(ZETA),
            Some(TaskState::Pending),
            "a resume wakes what the wait would have"
        );

        let mut halted = deferred.clone();
        apply(&mut halted, &dispatch(ALPHA, 0, &base));
        let start = attempt_started(&halted, ALPHA, 0, 1, 0);
        apply(&mut halted, &start);
        apply(
            &mut halted,
            &settle(
                ALPHA,
                0,
                1,
                AttemptSettlement::Closed {
                    transition: SettlementTransition::Failed {
                        halts_run: true,
                        reason: "  the ladder ran out  ".to_owned(),
                    },
                    lease: LeaseDisposition::PredictedReleased,
                },
            ),
        );
        assert_eq!(
            refuse(&halted, &elapsed),
            FoldError::RunEnding {
                kind: "defer_wait_elapsed",
                what: "a halting settlement",
            }
        );

        // And what it does when it is allowed: wakes every deferred task and
        // every verification-deferred candidate at once.
        let head = sha("head");
        let proposal = sha("proposal");
        let mut both = two_queued();
        apply(
            &mut both,
            &verification_started(MID, 0, 0, &head, &proposal),
        );
        apply(
            &mut both,
            &unavailable_event(0, outage(), UnavailableOutcome::Deferred { defers: 1 }),
        );
        assert!(both.queue().expect("started").entries()[0].verification_deferred);
        apply(&mut both, &elapsed);
        assert!(
            both.queue()
                .expect("started")
                .entries()
                .iter()
                .all(|entry| !entry.verification_deferred),
            "one wait wakes every waiter, so the order they deferred in cannot become an order \
             they retry in"
        );
    }

    // -----------------------------------------------------------------------
    // The derived outcome (INV-15, refusals[19])
    // -----------------------------------------------------------------------

    /// What is holding the run open, if anything.
    ///
    /// Every open generation class and both transaction classes, because
    /// `common` is the claim that *none* of them is outstanding: a fold that
    /// counted only the ones somebody remembered would end a run holding a
    /// retained session or an authorized publication.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Blocker {
        Nothing,
        OpenNoAttempt,
        OpenGeneration,
        Promoting,
        RetainedIdle,
        Transaction,
        VerifyingTransaction,
    }

    /// Every value of [`Blocker`], so the grid crosses the whole dimension.
    const BLOCKERS: [Blocker; 7] = [
        Blocker::Nothing,
        Blocker::OpenNoAttempt,
        Blocker::OpenGeneration,
        Blocker::Promoting,
        Blocker::RetainedIdle,
        Blocker::Transaction,
        Blocker::VerifyingTransaction,
    ];

    /// Whether a budget stop exists, and whether it belongs to this epoch.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Budget {
        None,
        Older,
        Current,
    }

    /// What is backing off, if anything.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Backoff {
        None,
        DeferredTask,
        DeferredCandidate,
    }

    /// The shape of the task set. Chosen so that "some task could still be
    /// admitted" and "every task has settled" are both determined by it, since
    /// no state can hold them independently.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shape {
        /// Every task merged.
        AllTerminal,
        /// A failure, and the tasks that can never run because of it.
        BlockedByFailure,
        /// A task that could be dispatched right now.
        AdmissiblePending,
        /// Neither settled nor admissible: the shape the design argues is
        /// unreachable, kept here because "unreachable" is a claim about
        /// histories and this is a claim about states.
        Stuck,
    }

    impl Shape {
        fn admissible(self) -> bool {
            self == Self::AdmissiblePending
        }

        fn complete(self) -> bool {
            matches!(self, Self::AllTerminal | Self::BlockedByFailure)
        }
    }

    /// The packet's total function, written from its text over the dimensions
    /// rather than over a state.
    ///
    /// This is the whole point of the grid: production derives each dimension
    /// from state and then applies the precedence, and this applies the
    /// precedence to the dimensions directly. A defect in either half — a
    /// dimension read wrongly from state, or a precedence applied in the wrong
    /// order — separates the two.
    fn expected_outcome(
        blocker: Blocker,
        halting: bool,
        budget: Budget,
        backoff: Backoff,
        questions: bool,
        shape: Shape,
    ) -> DerivedOutcome {
        if blocker != Blocker::Nothing {
            return DerivedOutcome::NotEnding;
        }
        if halting {
            return DerivedOutcome::Ending(RunOutcome::Halted);
        }
        if budget == Budget::Current {
            return DerivedOutcome::Ending(RunOutcome::BudgetExceeded);
        }
        if shape.admissible() || backoff != Backoff::None {
            return DerivedOutcome::NotEnding;
        }
        if questions {
            return DerivedOutcome::Ending(RunOutcome::Parked);
        }
        if shape.complete() {
            return DerivedOutcome::Ending(RunOutcome::Complete);
        }
        DerivedOutcome::FoldError
    }

    /// A state realizing one cell of the grid.
    ///
    /// Built by writing the fold's own state rather than by replaying a
    /// history: the obligation is that the function is total over states, and
    /// which of those states a history can reach is the bounded census's
    /// question, not this one's.
    fn grid_state(
        blocker: Blocker,
        halting: bool,
        budget: Budget,
        backoff: Backoff,
        questions: bool,
        shape: Shape,
    ) -> TopologyFold {
        let mut fold = started();
        fold.run = Some({
            let mut run = fold.run.take().expect("started");
            match shape {
                Shape::AllTerminal => {
                    for task in &mut run.tasks {
                        task.state = TaskState::Merged;
                    }
                }
                Shape::BlockedByFailure => {
                    run.tasks[ALPHA.index()].state = TaskState::Failed;
                    run.tasks[ZETA.index()].state = TaskState::Pending;
                    run.tasks[MID.index()].state = TaskState::Pending;
                }
                Shape::AdmissiblePending => {
                    run.tasks[ALPHA.index()].state = TaskState::Merged;
                    run.tasks[ZETA.index()].state = TaskState::Pending;
                    run.tasks[MID.index()].state = TaskState::Merged;
                }
                Shape::Stuck => {
                    run.tasks[ALPHA.index()].state = TaskState::Merged;
                    run.tasks[ZETA.index()].state = TaskState::AwaitingRepair;
                    run.tasks[MID.index()].state = TaskState::Merged;
                }
            }
            let open = |class: GenerationClass| GenerationFold {
                id: GenerationId(0),
                class,
                base_sha: sha("base"),
                lease: GenerationLease::Own,
                attempts: 1,
                candidate: None,
            };
            let generations = &mut run.tasks[MID.index()].generations;
            match blocker {
                Blocker::Nothing => {}
                Blocker::OpenNoAttempt => generations.push(open(GenerationClass::OpenNoAttempt)),
                Blocker::OpenGeneration => generations.push(open(GenerationClass::InFlight {
                    attempt: AttemptNumber(1),
                })),
                Blocker::Promoting => generations.push(open(GenerationClass::Promoting)),
                Blocker::RetainedIdle => {
                    let incarnation = run.epoch;
                    run.tasks[MID.index()]
                        .generations
                        .push(open(GenerationClass::RetainedIdle {
                            session: SessionId("sess-ÜNI-0042".to_owned()),
                            incarnation,
                        }));
                }
                Blocker::Transaction => {
                    run.transaction = Some(Transaction {
                        sequence: SequenceId(0),
                        candidate: candidate_of(MID, 0),
                        class: TransactionClass::Prepared {
                            proposed_sha: sha("commit-2-0"),
                            satisfies: vec![MID],
                        },
                    });
                }
                Blocker::VerifyingTransaction => {
                    run.transaction = Some(Transaction {
                        sequence: SequenceId(0),
                        candidate: candidate_of(MID, 0),
                        class: TransactionClass::VerificationStarted {
                            basis: VerificationBasis::AlreadyPresent,
                            expected_head: sha("head"),
                            proposed_sha: sha("head"),
                        },
                    });
                }
            }
            if halting {
                run.halted_at = Some(ALPHA);
                run.halted_epoch = Some(run.epoch);
            }
            run.budget_stop = match budget {
                Budget::None => None,
                Budget::Older => Some(BudgetStop {
                    epoch: Epoch(run.epoch.0 + 1),
                    budget: BudgetKind::Task,
                }),
                Budget::Current => Some(BudgetStop {
                    epoch: run.epoch,
                    budget: BudgetKind::Run,
                }),
            };
            match backoff {
                Backoff::None => {}
                Backoff::DeferredTask => run.tasks[MID.index()].state = TaskState::Deferred,
                Backoff::DeferredCandidate => run.queue.push(QueueEntry {
                    candidate: candidate_of(MID, 0),
                    paths: region(MID),
                    lineage_root: None,
                    verification_deferred: true,
                    defers: 1,
                    sequence: None,
                }),
            }
            if questions {
                run.open_question(
                    &question("q-grid-Ünicode", MID),
                    QuestionOrigin::Admission,
                    None,
                );
            }
            run
        });
        fold
    }

    #[test]
    fn the_derived_outcome_is_total_over_the_crossed_fold_state() {
        // 1008 cells: seven blockers (nothing, each of the four open
        // generation classes, and each of the two transaction classes),
        // halting or not, three budget scopes, three backoff shapes, questions
        // or not, four task-set shapes.
        let mut cells = 0;
        let mut reached: BTreeSet<String> = BTreeSet::new();
        for blocker in BLOCKERS {
            for halting in [false, true] {
                for budget in [Budget::None, Budget::Older, Budget::Current] {
                    for backoff in [
                        Backoff::None,
                        Backoff::DeferredTask,
                        Backoff::DeferredCandidate,
                    ] {
                        for questions in [false, true] {
                            for shape in [
                                Shape::AllTerminal,
                                Shape::BlockedByFailure,
                                Shape::AdmissiblePending,
                                Shape::Stuck,
                            ] {
                                let fold =
                                    grid_state(blocker, halting, budget, backoff, questions, shape);
                                let expected = expected_outcome(
                                    blocker, halting, budget, backoff, questions, shape,
                                );
                                assert_eq!(
                                    fold.derived_outcome(),
                                    expected,
                                    "blocker {blocker:?}, halting {halting}, budget {budget:?}, \
                                     backoff {backoff:?}, questions {questions}, shape {shape:?}"
                                );
                                reached.insert(format!("{expected:?}"));
                                cells += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cells, 1008);
        // Every arm of the function, including the one the design argues is
        // unreachable: a value a census can assert about rather than a panic.
        assert_eq!(reached.len(), 6, "arms reached: {reached:?}");
    }

    #[test]
    fn pending_backoff_blocks_parked_and_complete_and_never_blocks_halted_or_budget() {
        // The one precedence consequence the packet states in its own words,
        // asserted as a relation over the crossed grid rather than as an
        // example: for every cell, adding backoff moves Parked and Complete to
        // NotEnding and leaves every other answer exactly where it was.
        for blocker in BLOCKERS {
            for halting in [false, true] {
                for budget in [Budget::None, Budget::Current] {
                    for questions in [false, true] {
                        for shape in [
                            Shape::AllTerminal,
                            Shape::BlockedByFailure,
                            Shape::AdmissiblePending,
                            Shape::Stuck,
                        ] {
                            let without = grid_state(
                                blocker,
                                halting,
                                budget,
                                Backoff::None,
                                questions,
                                shape,
                            )
                            .derived_outcome();
                            for backoff in [Backoff::DeferredTask, Backoff::DeferredCandidate] {
                                let with =
                                    grid_state(blocker, halting, budget, backoff, questions, shape)
                                        .derived_outcome();
                                let expected = match &without {
                                    DerivedOutcome::Ending(RunOutcome::Parked)
                                    | DerivedOutcome::Ending(RunOutcome::Complete)
                                    | DerivedOutcome::FoldError => DerivedOutcome::NotEnding,
                                    other => other.clone(),
                                };
                                assert_eq!(
                                    with, expected,
                                    "{backoff:?} against {without:?} (blocker {blocker:?}, \
                                     halting {halting}, budget {budget:?}, questions {questions}, \
                                     shape {shape:?})"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn run_finished(outcome: RunOutcome, halted_at: Option<TaskKey>) -> TopologyEvent {
        ev(TopologyEventBody::RunFinished {
            data: RunFinished4 {
                outcome,
                halted_at,
                merged: 1,
                parked: 0,
            },
        })
    }

    #[test]
    fn a_run_ends_at_the_outcome_its_state_implies_or_not_at_all() {
        // refusals[19]: every outcome has an accepted and a refused instance,
        // and the refusals are the four the packet names by hand.
        let outcomes = [
            RunOutcome::Complete,
            RunOutcome::Parked,
            RunOutcome::Halted,
            RunOutcome::BudgetExceeded,
        ];

        // Complete: every task settled, nothing queued, nothing held.
        let complete = grid_state(
            Blocker::Nothing,
            false,
            Budget::None,
            Backoff::None,
            false,
            Shape::AllTerminal,
        );
        assert_accepts_exactly(&complete, &outcomes, RunOutcome::Complete, None);

        // Parked: an open question and nothing admissible.
        let parked = grid_state(
            Blocker::Nothing,
            false,
            Budget::None,
            Backoff::None,
            true,
            Shape::AllTerminal,
        );
        assert_accepts_exactly(&parked, &outcomes, RunOutcome::Parked, None);

        // Halted: a halting settlement, whatever else is true.
        let halted = grid_state(
            Blocker::Nothing,
            true,
            Budget::Current,
            Backoff::DeferredTask,
            true,
            Shape::Stuck,
        );
        assert_accepts_exactly(&halted, &outcomes, RunOutcome::Halted, Some(ALPHA));

        // BudgetExceeded: a stop in this epoch and no halting settlement —
        // accepted with a deferred task present, which Parked and Complete are
        // not.
        let budget = grid_state(
            Blocker::Nothing,
            false,
            Budget::Current,
            Backoff::DeferredCandidate,
            true,
            Shape::Stuck,
        );
        assert_accepts_exactly(&budget, &outcomes, RunOutcome::BudgetExceeded, None);

        // NotEnding: nothing is accepted at all.
        let running = grid_state(
            Blocker::OpenGeneration,
            false,
            Budget::None,
            Backoff::None,
            false,
            Shape::AdmissiblePending,
        );
        for outcome in &outcomes {
            assert!(matches!(
                refuse(&running, &run_finished(outcome.clone(), None)),
                FoldError::OutcomeMismatch { .. }
            ));
        }

        // And the attribution has to be the fold's: a halt recorded against
        // another task, or none at all, is a report of a run that did not
        // happen.
        assert!(matches!(
            refuse(&halted, &run_finished(RunOutcome::Halted, None)),
            FoldError::InconsistentRecord { .. }
        ));
        assert!(matches!(
            refuse(&halted, &run_finished(RunOutcome::Halted, Some(MID))),
            FoldError::InconsistentRecord { .. }
        ));
        assert!(matches!(
            refuse(&complete, &run_finished(RunOutcome::Complete, Some(ALPHA))),
            FoldError::InconsistentRecord { .. }
        ));
    }

    #[track_caller]
    fn assert_accepts_exactly(
        fold: &TopologyFold,
        outcomes: &[RunOutcome; 4],
        accepted: RunOutcome,
        halted_at: Option<TaskKey>,
    ) {
        for outcome in outcomes {
            let event = run_finished(outcome.clone(), halted_at);
            if *outcome == accepted {
                accepts(fold, &event);
            } else {
                assert!(
                    matches!(
                        fold.plan_transition(&event),
                        Err(FoldError::OutcomeMismatch { .. })
                    ),
                    "`{outcome:?}` was accepted where the state implies `{accepted:?}`"
                );
            }
        }
    }

    #[test]
    fn a_finished_run_is_continued_only_by_the_resume_its_outcome_allows() {
        // refusals[21]: Complete and Halted are terminal — finalized and then
        // refused. Parked and BudgetExceeded resume, and the only event that
        // continues them is that resume.
        let base = sha("base");
        for (outcome, resumable) in [
            (RunOutcome::Complete, false),
            (RunOutcome::Halted, false),
            (RunOutcome::Parked, true),
            (RunOutcome::BudgetExceeded, true),
        ] {
            let (mut fold, halted_at) = match outcome {
                RunOutcome::Complete => (
                    grid_state(
                        Blocker::Nothing,
                        false,
                        Budget::None,
                        Backoff::None,
                        false,
                        Shape::AllTerminal,
                    ),
                    None,
                ),
                RunOutcome::Parked => (
                    grid_state(
                        Blocker::Nothing,
                        false,
                        Budget::None,
                        Backoff::None,
                        true,
                        Shape::AllTerminal,
                    ),
                    None,
                ),
                RunOutcome::Halted => (
                    grid_state(
                        Blocker::Nothing,
                        true,
                        Budget::None,
                        Backoff::None,
                        false,
                        Shape::AllTerminal,
                    ),
                    Some(ALPHA),
                ),
                RunOutcome::BudgetExceeded => (
                    grid_state(
                        Blocker::Nothing,
                        false,
                        Budget::Current,
                        Backoff::None,
                        false,
                        Shape::AllTerminal,
                    ),
                    None,
                ),
            };
            apply(&mut fold, &run_finished(outcome.clone(), halted_at));
            assert_eq!(fold.finished(), Some(&outcome));

            let continuation = dispatch(ZETA, 0, &base);
            assert!(
                matches!(
                    refuse(&fold, &continuation),
                    FoldError::RunIsOver {
                        kind: "task_dispatched",
                        ..
                    }
                ),
                "a {outcome:?} run continued with ordinary work"
            );
            let resumption = resume(container_runner());
            if resumable {
                accepts(&fold, &resumption);
                apply(&mut fold, &resumption);
                assert_eq!(
                    fold.finished(),
                    None,
                    "a resume reopens the run it continues"
                );
                assert!(
                    !matches!(
                        fold.plan_transition(&continuation),
                        Err(FoldError::RunIsOver { .. })
                    ),
                    "a resumed run still refuses ordinary work as a finished one"
                );
            } else {
                assert!(
                    matches!(refuse(&fold, &resumption), FoldError::RunIsOver { .. }),
                    "a {outcome:?} run was resumed"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // INV-02: one transition, poisoning, and the whole-log parse
    // -----------------------------------------------------------------------

    /// One of every kind, so a table over the vocabulary is a table over all of
    /// it rather than over the ones somebody remembered.
    fn every_kind() -> Vec<TopologyEvent> {
        let base = sha("base");
        let events = vec![
            run_started_event(),
            resume(container_runner()),
            spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)),
            dispatch(ZETA, 0, &base),
            ev(TopologyEventBody::AttemptStarted {
                data: AttemptStarted4 {
                    key: ZETA,
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    rung: 0,
                    binding: RungBinding {
                        tier: Tier::Small,
                        agent: "zeta-small-agent".to_owned(),
                        model: "zeta-small-model".to_owned(),
                        pinned: false,
                        effort: Effort::Low,
                    },
                    pool: None,
                    resume_session: None,
                    materialization_observed: None,
                },
            }),
            succeeded(ZETA, 0, 1),
            ev(TopologyEventBody::AttemptInterrupted {
                data: AttemptInterrupted4 {
                    key: ZETA,
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    // T-ATTEMPT closes the generation, so an ordinary one
                    // releases the region it predicted.
                    lease: LeaseDisposition::PredictedReleased,
                    detail: "  the coordinator died  ".to_owned(),
                },
            }),
            ev(TopologyEventBody::GenerationClosed {
                data: GenerationClosed {
                    key: ZETA,
                    generation: GenerationId(0),
                    reason: GenerationCloseReason::WorktreeMissing,
                    lease: LeaseDisposition::PredictedReleased,
                },
            }),
            ev(TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 30_000,
                    round: 1,
                },
            }),
            candidate_prepared(ZETA, 0, &base),
            candidate_created(ZETA, 0),
            verification_started(ZETA, 0, 0, &sha("head"), &sha("proposal")),
            unavailable_event(0, outage(), UnavailableOutcome::Deferred { defers: 1 }),
            ev(TopologyEventBody::MergeVerificationInterrupted {
                data: MergeVerificationInterrupted {
                    sequence: SequenceId(0),
                    detail: "  the coordinator died  ".to_owned(),
                },
            }),
            fast_publication(ZETA, 0, 0, &base, vec![ZETA]),
            ev(TopologyEventBody::MergeRejected {
                data: Box::new(MergeRejected {
                    sequence: SequenceId(0),
                    candidate: candidate_of(ZETA, 0),
                    rejecting_head: sha("head"),
                    disposition: RejectionDisposition::Conflict { paths: region(MID) },
                    repair: repair_spawn(TaskKey(3), ZETA, ZETA),
                    lease_effect: RejectionLeaseEffect::CreatesLineage {
                        root: ZETA,
                        paths: region(MID),
                    },
                }),
            }),
            merged(ZETA, 0, 0, vec![ZETA]),
            raised("q-park-Ünicode", ZETA),
            answered(
                ZETA,
                "q-park-Ünicode",
                Answer4::Declined {
                    decline_halts_run: true,
                },
            ),
            budget_exceeded(0, Some(ZETA)),
            run_finished(RunOutcome::Complete, None),
            ev(TopologyEventBody::CapacitySnapshot {
                data: CapacitySnapshot {
                    strategy: "  Least-Loaded  ".to_owned(),
                    pools: vec![PoolSnapshot {
                        pool: "codex-plus".to_owned(),
                        agent: "  Codex-CLI  ".to_owned(),
                        kind: "session".to_owned(),
                        remaining: "3".to_owned(),
                        confidence: "reported".to_owned(),
                        reset_at: Some("2026-08-17T10:00:00Z".to_owned()),
                    }],
                },
            }),
            ev(TopologyEventBody::PoolExhausted {
                data: PoolExhausted {
                    pool: "codex-plus".to_owned(),
                    agent: "  Codex-CLI  ".to_owned(),
                    reset_at: Some("2026-08-17T10:00:00Z".to_owned()),
                    detail: "  rate limited  ".to_owned(),
                },
            }),
            ev(TopologyEventBody::DesignDefect {
                data: DesignDefect {
                    question: QuestionId::from("q-design"),
                    context: "  the contract is ambiguous  ".to_owned(),
                    answer: "  ask the designer  ".to_owned(),
                },
            }),
        ];
        assert_eq!(
            events.len(),
            TOPOLOGY_EVENT_KINDS.len(),
            "the table has to hold one of every kind"
        );
        for (event, kind) in events.iter().zip(TOPOLOGY_EVENT_KINDS) {
            assert_eq!(event.body.kind(), kind, "the table is in vocabulary order");
        }
        events
    }

    #[test]
    fn a_poisoned_fold_refuses_every_transition() {
        // refusals[24]: the command has already ended. Nothing is appended and
        // nothing is derived from memory — including the informational records,
        // which a process that cannot vouch for its own state may not write
        // either.
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        fold.poison();
        assert!(fold.is_poisoned());
        for event in every_kind() {
            assert_eq!(
                refuse(&fold, &event),
                FoldError::Poisoned,
                "`{}` was folded into a poisoned state",
                event.body.kind()
            );
        }
        // And it is not a state a later event clears.
        let mut clean = started();
        merge_task(&mut clean, ALPHA, 0, 0);
        assert!(
            clean
                .plan_transition(&raised("q-park-Ünicode", ZETA))
                .is_ok(),
            "the same event applies to the same state when it is not poisoned"
        );
    }

    #[test]
    fn a_committed_line_that_is_not_an_event_is_a_rewritten_log() {
        // refusals[23], and the boundary it is distinguished from: the newline
        // is the commit marker, so an unterminated final line is a torn tail
        // and is dropped, while a terminated one that will not parse means the
        // log was rewritten.
        let first = serde_json::to_string(&run_started_event()).expect("serialize");
        let second = serde_json::to_string(&raised("q-park-Ünicode", ZETA)).expect("serialize");

        let whole = format!("{first}\n{second}\n");
        assert_eq!(
            TopologyFold::parse_log(whole.as_bytes())
                .expect("a whole log parses")
                .len(),
            2
        );

        // A torn tail: syntactically complete and never committed.
        let torn = format!("{first}\n{second}");
        let parsed = TopologyFold::parse_log(torn.as_bytes()).expect("a torn tail is not an error");
        assert_eq!(parsed.len(), 1, "an uncommitted line is not an event");

        // A committed line that is not an event, at every position.
        for position in 0..3 {
            let mut lines = [first.clone(), second.clone(), second.clone()];
            lines[position] = "{\"event\":\"not_a_kind\"}".to_owned();
            let log = lines.join("\n") + "\n";
            let error = TopologyFold::parse_log(log.as_bytes())
                .expect_err("a committed invalid line is refused");
            let FoldError::RewrittenLog { line, .. } = error else {
                panic!("a rewritten log must be refused as one");
            };
            assert_eq!(line, position + 1, "the refusal names the line it refused");
        }

        // Invalid UTF-8 inside a committed line is the same situation.
        let mut bytes = format!("{first}\n").into_bytes();
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
        assert!(matches!(
            TopologyFold::parse_log(&bytes),
            Err(FoldError::RewrittenLog { line: 2, .. })
        ));

        // A committed line that is *blank* is the same situation again, and
        // the one the refusal is easiest to lose: the newline is the commit
        // marker, so an empty or whitespace-only terminated line is a
        // committed record that is not an event. Skipping it would fold a log
        // whose physical shape no reader can account for — and would let a
        // rewrite that blanked a line read back as a shorter valid log.
        for (label, blank) in [
            ("empty", ""),
            ("spaces", "   "),
            ("tab", "\t"),
            ("unicode space", "\u{00a0}"),
        ] {
            for position in 0..3 {
                let mut lines = [first.clone(), second.clone(), second.clone()];
                lines[position] = blank.to_owned();
                let log = lines.join("\n") + "\n";
                let Err(error) = TopologyFold::parse_log(log.as_bytes()) else {
                    panic!("a committed {label} line at {position} was skipped");
                };
                let FoldError::RewrittenLog { line, .. } = error else {
                    panic!("a committed {label} line at {position} was not a rewritten log");
                };
                assert_eq!(
                    line,
                    position + 1,
                    "the refusal names the {label} line it refused"
                );
            }
        }
    }

    /// Apply an event to a live fold and record it in the trace it came from.
    fn push(live: &mut TopologyFold, trace: &mut Vec<TopologyEvent>, event: TopologyEvent) {
        apply(live, &event);
        trace.push(event);
    }

    /// A run that retries on a retained session, merges fast, verifies stale,
    /// defers on an outage, wakes, is rejected into a repair, exceeds its
    /// budget and resumes.
    fn long_trace() -> Vec<TopologyEvent> {
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let mut live = started();
        let mut trace = vec![run_started_event()];

        // alpha: dispatched, retried on a retained session, then merged fast.
        push(&mut live, &mut trace, dispatch(ALPHA, 0, &base));
        let start = attempt_started(&live, ALPHA, 0, 1, 0);
        push(&mut live, &mut trace, start);
        push(
            &mut live,
            &mut trace,
            settle(
                ALPHA,
                0,
                1,
                AttemptSettlement::Retained {
                    retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                    retained_incarnation: Epoch(0),
                },
            ),
        );
        let resumed = ev(TopologyEventBody::AttemptStarted {
            data: AttemptStarted4 {
                key: ALPHA,
                generation: GenerationId(0),
                attempt: AttemptNumber(2),
                rung: 0,
                binding: frozen_binding(&live, ALPHA, 0),
                pool: None,
                resume_session: Some(SessionId("sess-ÜNI-0042".to_owned())),
                materialization_observed: None,
            },
        });
        push(&mut live, &mut trace, resumed);
        push(&mut live, &mut trace, succeeded(ALPHA, 0, 2));
        // Attempt 2 is the one that succeeded, so it is the one the candidate
        // is attributed to.
        push(
            &mut live,
            &mut trace,
            candidate_prepared_at(ALPHA, 0, 2, &base),
        );
        push(&mut live, &mut trace, candidate_created(ALPHA, 0));
        push(
            &mut live,
            &mut trace,
            fast_publication(ALPHA, 0, 0, &base, vec![ALPHA]),
        );
        push(&mut live, &mut trace, merged(ALPHA, 0, 0, vec![ALPHA]));

        // zeta: verified stale, deferred by an outage, woken, then rejected —
        // which registers a repair — and the repair is dispatched and parked.
        push(&mut live, &mut trace, dispatch(ZETA, 0, &base));
        let start = attempt_started(&live, ZETA, 0, 1, 0);
        push(&mut live, &mut trace, start);
        push(&mut live, &mut trace, succeeded(ZETA, 0, 1));
        push(&mut live, &mut trace, candidate_prepared(ZETA, 0, &base));
        push(&mut live, &mut trace, candidate_created(ZETA, 0));
        push(
            &mut live,
            &mut trace,
            verification_started(ZETA, 0, 1, &head, &proposal),
        );
        push(
            &mut live,
            &mut trace,
            unavailable_event(1, outage(), UnavailableOutcome::Deferred { defers: 1 }),
        );
        push(
            &mut live,
            &mut trace,
            ev(TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 30_000,
                    round: 1,
                },
            }),
        );
        push(
            &mut live,
            &mut trace,
            verification_started(ZETA, 0, 2, &head, &proposal),
        );
        let mut repair = repair_spawn(TaskKey(3), ZETA, ZETA);
        repair.entry.deps = vec![ALPHA];
        repair.entry.display_deps = vec![TaskId::from("alpha")];
        push(
            &mut live,
            &mut trace,
            ev(TopologyEventBody::MergeRejected {
                data: Box::new(MergeRejected {
                    sequence: SequenceId(2),
                    candidate: candidate_of(ZETA, 0),
                    rejecting_head: head.clone(),
                    disposition: RejectionDisposition::CodeRejected {
                        verification: verification_record(Verdict::Rejected),
                    },
                    repair,
                    lease_effect: RejectionLeaseEffect::CreatesLineage {
                        root: ZETA,
                        paths: region(MID),
                    },
                }),
            }),
        );
        push(&mut live, &mut trace, budget_exceeded(0, Some(MID)));
        push(&mut live, &mut trace, resume(container_runner()));

        assert!(
            trace.len() >= 20,
            "the trace has to exercise more than a path"
        );
        trace
    }

    /// A run that is interrupted, closes a generation, merges, registers a
    /// repair by hand, has a verification interrupted, and parks and answers a
    /// question — the guarded kinds the long trace does not reach.
    fn settled_trace() -> Vec<TopologyEvent> {
        let base = sha("base");
        let head = sha("head");
        let proposal = sha("proposal");
        let mut live = started();
        let mut trace = vec![run_started_event()];

        // An interruption closes generation 0 and returns zeta to pending.
        push(&mut live, &mut trace, dispatch(ZETA, 0, &base));
        let start = attempt_started(&live, ZETA, 0, 1, 0);
        push(&mut live, &mut trace, start);
        push(
            &mut live,
            &mut trace,
            ev(TopologyEventBody::AttemptInterrupted {
                data: AttemptInterrupted4 {
                    key: ZETA,
                    generation: GenerationId(0),
                    attempt: AttemptNumber(1),
                    lease: LeaseDisposition::PredictedReleased,
                    detail: "  the coordinator died  ".to_owned(),
                },
            }),
        );
        // Generation 1 is dispatched and closed without an attempt.
        push(&mut live, &mut trace, dispatch(ZETA, 1, &base));
        push(
            &mut live,
            &mut trace,
            ev(TopologyEventBody::GenerationClosed {
                data: GenerationClosed {
                    key: ZETA,
                    generation: GenerationId(1),
                    reason: GenerationCloseReason::WorktreeMissing,
                    lease: LeaseDisposition::PredictedReleased,
                },
            }),
        );

        // alpha merges fast, which gives a repair something to depend on.
        push(&mut live, &mut trace, dispatch(ALPHA, 0, &base));
        let start = attempt_started(&live, ALPHA, 0, 1, 0);
        push(&mut live, &mut trace, start);
        push(&mut live, &mut trace, succeeded(ALPHA, 0, 1));
        push(&mut live, &mut trace, candidate_prepared(ALPHA, 0, &base));
        push(&mut live, &mut trace, candidate_created(ALPHA, 0));
        push(
            &mut live,
            &mut trace,
            fast_publication(ALPHA, 0, 0, &base, vec![ALPHA]),
        );
        push(&mut live, &mut trace, merged(ALPHA, 0, 0, vec![ALPHA]));
        push(
            &mut live,
            &mut trace,
            spawn_event(repair_spawn(TaskKey(3), ALPHA, ALPHA)),
        );

        // zeta's third generation prepares a candidate whose verification is
        // interrupted.
        push(&mut live, &mut trace, dispatch(ZETA, 2, &base));
        let start = attempt_started(&live, ZETA, 2, 1, 0);
        push(&mut live, &mut trace, start);
        push(&mut live, &mut trace, succeeded(ZETA, 2, 1));
        push(&mut live, &mut trace, candidate_prepared(ZETA, 2, &base));
        push(&mut live, &mut trace, candidate_created(ZETA, 2));
        push(
            &mut live,
            &mut trace,
            verification_started(ZETA, 2, 1, &head, &proposal),
        );
        push(
            &mut live,
            &mut trace,
            ev(TopologyEventBody::MergeVerificationInterrupted {
                data: MergeVerificationInterrupted {
                    sequence: SequenceId(1),
                    detail: "  the coordinator died  ".to_owned(),
                },
            }),
        );

        // And a question is asked about a third task and answered.
        push(&mut live, &mut trace, raised("q-park-Ünicode", MID));
        push(
            &mut live,
            &mut trace,
            answered(
                MID,
                "q-park-Ünicode",
                Answer4::Answered {
                    option_index: 2,
                    binding_override: None,
                },
            ),
        );
        trace
    }

    /// Every task merged, and the run saying so.
    fn finished_trace() -> Vec<TopologyEvent> {
        let mut live = started();
        let mut trace = vec![run_started_event()];
        let base = sha("base");
        for (key, sequence) in [(ALPHA, 0), (ZETA, 1), (MID, 2)] {
            push(&mut live, &mut trace, dispatch(key, 0, &base));
            let start = attempt_started(&live, key, 0, 1, 0);
            push(&mut live, &mut trace, start);
            push(&mut live, &mut trace, succeeded(key, 0, 1));
            push(&mut live, &mut trace, candidate_prepared(key, 0, &base));
            push(&mut live, &mut trace, candidate_created(key, 0));
            push(
                &mut live,
                &mut trace,
                fast_publication(key, 0, sequence, &base, vec![key]),
            );
            push(&mut live, &mut trace, merged(key, 0, sequence, vec![key]));
        }
        push(
            &mut live,
            &mut trace,
            run_finished(RunOutcome::Complete, None),
        );
        trace
    }

    #[test]
    fn live_and_replay_reach_the_same_state_over_a_long_trace() {
        // INV-02, as the property rather than as the claim: a fold driven
        // event by event and a fold replayed from the same bytes hold the same
        // state — and the bytes are what a writer would have appended, so the
        // comparison is over a serialization round trip too.
        for trace in [long_trace(), settled_trace(), finished_trace()] {
            let mut live = TopologyFold::new(inputs());
            for event in &trace {
                apply(&mut live, event);
            }
            // Through the wire, not through the values: a replay reads bytes.
            let parsed = TopologyFold::parse_log(&wire(&trace)).expect("the log parses");
            assert_eq!(parsed, trace, "every event survives the round trip");
            let replayed = TopologyFold::replay(inputs(), &parsed).expect("the log replays");

            assert_eq!(
                live.state(),
                replayed.state(),
                "a live fold and a replay of what it appended have to be one state"
            );
            assert_eq!(live.derived_outcome(), replayed.derived_outcome());
        }
    }

    /// Serialize a trace the way a writer would append it.
    fn wire(trace: &[TopologyEvent]) -> Vec<u8> {
        let mut log = Vec::new();
        for event in trace {
            log.extend_from_slice(serde_json::to_string(event).expect("serialize").as_bytes());
            log.push(b'\n');
        }
        log
    }

    /// Copies of `event` with exactly one coordinate moved to a value the fold
    /// must refuse *in this event's own position*.
    ///
    /// One field at a time is the whole point: an event that disagreed with its
    /// state in several places at once could be caught by any one of the
    /// relations, and would not say which. Everything here is a relation the
    /// fold owns — an identity, a count, a SHA, a disposition — never a shape
    /// serialization would already have refused.
    #[allow(clippy::too_many_lines)]
    fn one_field_invalid(event: &TopologyEvent) -> Vec<(String, TopologyEvent)> {
        let mut out = Vec::new();
        let mut case = |label: &str, body: TopologyEventBody| {
            out.push((format!("{}/{label}", event.body.kind()), ev(body)));
        };
        match &event.body {
            TopologyEventBody::RunStarted { data } => {
                let mut moved = data.clone();
                moved.registry_digest = format!(
                    "{}0",
                    &data.registry_digest[..data.registry_digest.len() - 1]
                );
                case(
                    "registry_digest",
                    TopologyEventBody::RunStarted { data: moved },
                );
                let mut moved = data.clone();
                moved.normalized_plan_digest =
                    "sha256:8888888888888888888888888888888888888888888888888888888888888888"
                        .to_owned();
                case(
                    "normalized_plan_digest",
                    TopologyEventBody::RunStarted { data: moved },
                );
            }
            TopologyEventBody::RunResumed { data } => {
                let mut moved = data.clone();
                if let Some(image) = moved.runner.image.as_mut() {
                    image.reference = "ghcr.io/example/Another-Runner:2.1".to_owned();
                }
                case(
                    "runner.image.reference",
                    TopologyEventBody::RunResumed { data: moved },
                );
                let mut moved = data.clone();
                if let Some(volumes) = moved.runner.credential_volumes.as_mut() {
                    volumes.insert("claude-code".to_owned(), "tactus-creds-codex".to_owned());
                }
                case(
                    "runner.credential_volumes",
                    TopologyEventBody::RunResumed { data: moved },
                );
            }
            TopologyEventBody::TaskSpawned { data } => {
                let mut moved = data.clone();
                moved.spawn.key = TaskKey(moved.spawn.key.0 + 1);
                moved.spawn.entry.key = moved.spawn.key;
                case("key", TopologyEventBody::TaskSpawned { data: moved });
                let mut moved = data.clone();
                moved
                    .spawn
                    .entry
                    .allowed_agents
                    .push("an-unprobed-agent".to_owned());
                case(
                    "allowed_agents",
                    TopologyEventBody::TaskSpawned { data: moved },
                );
            }
            TopologyEventBody::TaskDispatched { data } => {
                let mut moved = data.clone();
                moved.generation = GenerationId(moved.generation.0 + 1);
                case(
                    "generation",
                    TopologyEventBody::TaskDispatched { data: moved },
                );
            }
            TopologyEventBody::AttemptStarted { data } => {
                let mut moved = data.clone();
                moved.attempt = AttemptNumber(moved.attempt.0 + 1);
                case("attempt", TopologyEventBody::AttemptStarted { data: moved });
                let mut moved = data.clone();
                moved.binding.agent = "an-agent-nobody-froze".to_owned();
                case(
                    "binding.agent",
                    TopologyEventBody::AttemptStarted { data: moved },
                );
            }
            TopologyEventBody::AttemptFinished { data } => {
                let mut moved = data.clone();
                moved.attempt = AttemptNumber(moved.attempt.0 + 1);
                case(
                    "attempt",
                    TopologyEventBody::AttemptFinished { data: moved },
                );
                let mut moved = data.clone();
                if let AttemptSettlement::Closed { lease, .. } = &mut moved.settlement {
                    *lease = LeaseDisposition::LineageHeld;
                    case(
                        "settlement.lease",
                        TopologyEventBody::AttemptFinished { data: moved },
                    );
                }
            }
            TopologyEventBody::AttemptInterrupted { data } => {
                let mut moved = data.clone();
                moved.generation = GenerationId(moved.generation.0 + 1);
                case(
                    "generation",
                    TopologyEventBody::AttemptInterrupted { data: moved },
                );
                let mut moved = data.clone();
                moved.lease = LeaseDisposition::PredictedRetained;
                case(
                    "lease",
                    TopologyEventBody::AttemptInterrupted { data: moved },
                );
            }
            TopologyEventBody::GenerationClosed { data } => {
                let mut moved = data.clone();
                moved.generation = GenerationId(moved.generation.0 + 1);
                case(
                    "generation",
                    TopologyEventBody::GenerationClosed { data: moved },
                );
            }
            TopologyEventBody::DeferWaitElapsed { .. } => {}
            TopologyEventBody::CandidatePrepared { data } => {
                let mut moved = data.clone();
                moved.attempt = Box::new(attempt_record(moved.attempt.attempt + 1));
                case(
                    "attempt",
                    TopologyEventBody::CandidatePrepared { data: moved },
                );
                let mut moved = data.clone();
                moved.parent_sha = sha("somewhere-else");
                case(
                    "parent_sha",
                    TopologyEventBody::CandidatePrepared { data: moved },
                );
            }
            TopologyEventBody::TaskCandidateCreated { data } => {
                let mut moved = data.clone();
                moved.candidate.commit_sha = sha("a-commit-nobody-prepared");
                case(
                    "candidate.commit_sha",
                    TopologyEventBody::TaskCandidateCreated { data: moved },
                );
            }
            TopologyEventBody::MergeVerificationStarted { data } => {
                let mut moved = data.clone();
                moved.sequence = SequenceId(moved.sequence.0 + 1);
                case(
                    "sequence",
                    TopologyEventBody::MergeVerificationStarted { data: moved },
                );
                let mut moved = data.clone();
                moved.candidate.commit_sha = sha("a-commit-nobody-prepared");
                case(
                    "candidate.commit_sha",
                    TopologyEventBody::MergeVerificationStarted { data: moved },
                );
            }
            TopologyEventBody::MergeVerificationUnavailable { data } => {
                let mut moved = data.clone();
                if let UnavailableOutcome::Deferred { defers } = &mut moved.outcome {
                    *defers += 1;
                    case(
                        "outcome.defers",
                        TopologyEventBody::MergeVerificationUnavailable { data: moved },
                    );
                }
                let mut moved = data.clone();
                moved.sequence = SequenceId(moved.sequence.0 + 1);
                case(
                    "sequence",
                    TopologyEventBody::MergeVerificationUnavailable { data: moved },
                );
            }
            TopologyEventBody::MergeVerificationInterrupted { data } => {
                let mut moved = data.clone();
                moved.sequence = SequenceId(moved.sequence.0 + 1);
                case(
                    "sequence",
                    TopologyEventBody::MergeVerificationInterrupted { data: moved },
                );
            }
            TopologyEventBody::MergePrepared { data } => {
                let mut moved = data.clone();
                moved.expected_head = sha("a-head-nobody-read");
                case(
                    "expected_head",
                    TopologyEventBody::MergePrepared { data: moved },
                );
                let mut moved = data.clone();
                moved.candidate_ref = git_ref("candidates/decoy");
                case(
                    "candidate_ref",
                    TopologyEventBody::MergePrepared { data: moved },
                );
            }
            TopologyEventBody::MergeRejected { data } => {
                let mut moved = data.clone();
                moved.sequence = SequenceId(moved.sequence.0 + 1);
                case("sequence", TopologyEventBody::MergeRejected { data: moved });
                let mut moved = data.clone();
                moved.candidate.commit_sha = sha("a-commit-nobody-prepared");
                case(
                    "candidate.commit_sha",
                    TopologyEventBody::MergeRejected { data: moved },
                );
            }
            TopologyEventBody::TaskMerged { data } => {
                let mut moved = data.clone();
                moved.merged_sha = sha("a-sha-nobody-authorized");
                case("merged_sha", TopologyEventBody::TaskMerged { data: moved });
                let mut moved = data.clone();
                moved.sequence = SequenceId(moved.sequence.0 + 1);
                case("sequence", TopologyEventBody::TaskMerged { data: moved });
            }
            TopologyEventBody::QuestionRaised { data } => {
                let mut moved = data.clone();
                moved.question.key = TaskKey(9);
                case(
                    "question.key",
                    TopologyEventBody::QuestionRaised { data: moved },
                );
                let mut moved = data.clone();
                moved.question.options.clear();
                case(
                    "question.options",
                    TopologyEventBody::QuestionRaised { data: moved },
                );
            }
            TopologyEventBody::QuestionAnswered { data } => {
                let mut moved = data.clone();
                moved.question = QuestionId::from("q-this-log-never-asked");
                if let Answer4::Answered {
                    binding_override, ..
                } = &mut moved.answer
                {
                    if let Some(binding) = binding_override.as_mut() {
                        binding.question = QuestionId::from("q-this-log-never-asked");
                    }
                }
                case(
                    "question",
                    TopologyEventBody::QuestionAnswered { data: moved },
                );
            }
            TopologyEventBody::BudgetExceeded { data } => {
                let mut moved = data.clone();
                moved.epoch = Epoch(moved.epoch.0 + 1);
                case("epoch", TopologyEventBody::BudgetExceeded { data: moved });
            }
            TopologyEventBody::RunFinished { data } => {
                let mut moved = data.clone();
                moved.outcome = match moved.outcome {
                    RunOutcome::Complete => RunOutcome::Halted,
                    _ => RunOutcome::Complete,
                };
                case("outcome", TopologyEventBody::RunFinished { data: moved });
            }
            TopologyEventBody::CapacitySnapshot { .. }
            | TopologyEventBody::PoolExhausted { .. }
            | TopologyEventBody::DesignDefect { .. } => {}
        }
        out
    }

    #[test]
    fn every_guarded_event_is_refused_the_same_way_live_and_on_a_hostile_replay() {
        // INV-02: "Live state and replay use one checked transition over the
        // exact wire event; an invalid transition is never appended."
        //
        // Equal *valid* traces cannot prove this: a replay that applied every
        // event unchecked, or that skipped the ones the checked transition
        // refused and carried on, reaches exactly the same state over a valid
        // log. The witness has to be a log a writer would never have produced —
        // a valid prefix, one event with one field moved, and a valid suffix —
        // and the claim is that replay stops on that line with the refusal the
        // live path gives, rather than reaching a state at all.
        //
        // The expected refusal is taken from the live path over the same
        // prefix, which is the other half of the invariant and not the
        // function under test explaining itself: two independent entry points
        // are required to answer identically.
        let mut covered: BTreeSet<&'static str> = BTreeSet::new();
        let mut cases = 0_u32;
        for trace in [long_trace(), settled_trace(), finished_trace()] {
            for index in 0..trace.len() {
                let kind = trace[index].body.kind();
                let variants = one_field_invalid(&trace[index]);
                if variants.is_empty() {
                    continue;
                }
                let prefix = TopologyFold::replay(inputs(), &trace[..index])
                    .unwrap_or_else(|error| panic!("the prefix before {kind} replays: {error}"));
                let before = prefix.state().cloned();
                for (label, invalid) in variants {
                    // Live: refused, and asking left the state exactly as it
                    // was.
                    let live_error = prefix
                        .plan_transition(&invalid)
                        .err()
                        .unwrap_or_else(|| panic!("{label} is not an invalid transition"));
                    assert_eq!(
                        prefix.state().cloned(),
                        before,
                        "{label} mutated on refusal"
                    );

                    // Replay: the same refusal, over the wire, with a valid
                    // suffix behind it that a lenient reader would have gone on
                    // to apply.
                    let mut hostile = trace[..index].to_vec();
                    hostile.push(invalid);
                    hostile.extend_from_slice(&trace[index + 1..]);
                    assert!(
                        hostile.len() == trace.len() && index < trace.len(),
                        "{label}: the hostile log is the trace with one line replaced"
                    );
                    let parsed =
                        TopologyFold::parse_log(&wire(&hostile)).expect("the hostile log parses");
                    let replay_error = TopologyFold::replay(inputs(), &parsed)
                        .err()
                        .unwrap_or_else(|| {
                            panic!("{label}: a hostile log replayed to a state instead of refusing")
                        });
                    assert_eq!(
                        replay_error, live_error,
                        "{label}: replay and live disagree about the same event over the same \
                         prefix"
                    );
                }
                covered.insert(kind);
                cases += 1;
            }
        }

        // The sweep is over the vocabulary, not over what was remembered. The
        // three informational kinds are never refused, and `defer_wait_elapsed`
        // carries no field a fold relation reads — both are witnessed on their
        // own below.
        let unguarded: BTreeSet<&'static str> = [
            "defer_wait_elapsed",
            "capacity_snapshot",
            "pool_exhausted",
            "design_defect",
        ]
        .into_iter()
        .collect();
        let expected: BTreeSet<&'static str> = TOPOLOGY_EVENT_KINDS
            .iter()
            .copied()
            .filter(|kind| !unguarded.contains(kind))
            .collect();
        assert_eq!(
            covered, expected,
            "a guarded kind was never swept for a hostile replay"
        );
        assert!(cases > 20, "the sweep was not vacuous: {cases}");

        // `defer_wait_elapsed`'s guard is the state rather than a field
        // (refusals[18]: no wait elapses under a halt or the epoch's budget
        // stop), so its hostile witness is one appended where the prefix
        // forbids it.
        let mut live = started();
        let mut trace = vec![run_started_event()];
        push(&mut live, &mut trace, budget_exceeded(0, Some(ZETA)));
        let elapsed = ev(TopologyEventBody::DeferWaitElapsed {
            data: DeferWaitElapsed4 {
                waited_ms: 30_000,
                round: 1,
            },
        });
        let live_error = refuse(&live, &elapsed);
        let mut hostile = trace.clone();
        hostile.push(elapsed);
        hostile.push(resume(container_runner()));
        let parsed = TopologyFold::parse_log(&wire(&hostile)).expect("the hostile log parses");
        assert_eq!(
            TopologyFold::replay(inputs(), &parsed)
                .expect_err("a wait that elapsed under a budget stop is refused on replay"),
            live_error
        );
    }

    #[test]
    fn a_delta_carries_the_exact_event_it_was_checked_against() {
        // The emit contract is: build the event, round-trip it, plan the
        // transition, append *the exact bytes*, apply the delta. A delta whose
        // event is a rebuilt or normalized copy of the one it was asked about
        // would let a writer append one record and fold another — which is the
        // divergence between live state and replay that INV-02 forbids, in the
        // one place the two are not literally the same call.
        let base = sha("base");
        let mut fold = TopologyFold::new(inputs());
        for event in [
            run_started_event(),
            dispatch(ZETA, 0, &base),
            raised("q-park-Ünicode", ALPHA),
            ev(TopologyEventBody::CapacitySnapshot {
                data: CapacitySnapshot {
                    strategy: "  Least-Loaded  ".to_owned(),
                    pools: Vec::new(),
                },
            }),
        ] {
            let delta = fold
                .plan_transition(&event)
                .unwrap_or_else(|error| panic!("`{}` must apply: {error}", event.body.kind()));
            assert_eq!(
                delta.event(),
                &event,
                "`{}` was checked against a copy of itself",
                event.body.kind()
            );
            assert_eq!(
                serde_json::to_string(delta.event()).expect("serialize"),
                serde_json::to_string(&event).expect("serialize"),
                "`{}` would be appended as different bytes from the ones checked",
                event.body.kind()
            );
            fold.apply_delta(delta);
        }
    }

    #[test]
    fn a_refused_transition_changes_nothing() {
        // The other half of INV-02: an invalid transition is never applied,
        // which is a property of `plan_transition` being a question rather
        // than an action.
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        let before = fold.state().cloned();
        for event in every_kind() {
            let _ = fold.plan_transition(&event);
        }
        assert_eq!(
            fold.state().cloned(),
            before,
            "asking whether an event applies must not apply it"
        );
    }

    #[test]
    fn the_registry_digest_does_not_widen_when_a_repair_is_registered() {
        // The authentication value is over the *originals*: a reader rebuilds
        // them from the frozen plan and the run record and compares. A dynamic
        // entry has no frozen input behind it to rebuild from, so a digest that
        // grew with one would be a value no reader could recompute.
        let mut fold = started();
        merge_task(&mut fold, ALPHA, 0, 0);
        let before = fold.registry().expect("started").digest();
        let before_bytes = fold.registry().expect("started").canonical_bytes();
        assert_eq!(before, run_started().registry_digest);

        let spawn = repair_spawn(TaskKey(3), ALPHA, ALPHA);
        let registered = spawn.entry.clone();
        apply(&mut fold, &spawn_event(spawn));
        let registry = fold.registry().expect("started");
        assert_eq!(registry.len(), 4, "the repair joined the registry");
        assert_eq!(registry.originals_len(), 3);
        assert_eq!(
            registry.digest(),
            before,
            "registering a repair moved the value that authenticates the frozen plan"
        );

        // The other half, and the one that has no producer yet: the canonical
        // serialization is of the *registry*, so it covers every constructible
        // entry. The digest is narrow because a reader rebuilds only the
        // originals; the encoding is not, because a dynamic entry no encoder
        // ever visits is a value nothing downstream can compare — which is how
        // a stored entry can differ from the event that registered it and
        // nobody notices.
        let bytes = registry.canonical_bytes();
        assert_ne!(
            bytes, before_bytes,
            "a registered repair left the canonical serialization unchanged"
        );
        assert!(
            bytes.len() > before_bytes.len(),
            "the encoding did not grow by an entry"
        );
        // Its own fields are in there, including the allow-list, which is the
        // field a derivation could quietly substitute for.
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains(registered.display_id.as_str()));
        assert!(text.contains("Repair the alpha rejection"));
        for agent in &registered.allowed_agents {
            assert!(
                text.contains(agent.as_str()),
                "the stored allow-list entry `{agent}` is not in the canonical encoding"
            );
        }

        // And the stored entry is the entry the event registered, field for
        // field — not one derived from its ladder rungs or its admission
        // options. Nothing else in this slice reads a dynamic entry back.
        assert_eq!(
            registry.get(TaskKey(3)),
            Some(&registered),
            "the registry stored something other than what the event carried"
        );
        assert_eq!(
            registry.get(TaskKey(3)).expect("the repair").allowed_agents,
            run_started().probed_agents,
            "the stored allow-list is the run's probe list"
        );
        let rung_agents: Vec<String> = registered
            .ladder
            .rungs
            .iter()
            .map(|rung| rung.agent.clone())
            .collect();
        assert_ne!(
            registry.get(TaskKey(3)).expect("the repair").allowed_agents,
            rung_agents,
            "the fixture's rung agents must differ from the probe list, or this proves nothing"
        );
        // And the repair is addressable by both of its identities.
        assert_eq!(
            registry.key_of(
                registry
                    .get(TaskKey(3))
                    .expect("the repair")
                    .display_id
                    .as_str()
            ),
            Some(TaskKey(3))
        );
    }

    // -----------------------------------------------------------------------
    // Regions, holdings and queue eligibility
    // -----------------------------------------------------------------------

    fn prefixes(paths: &[&str]) -> PathSet {
        PathSet::Prefixes {
            paths: paths.iter().copied().map(GitPath::from).collect(),
        }
    }

    #[test]
    fn regions_overlap_component_wise_and_repo_wide_overlaps_everything() {
        let sensitive = PathPolicy {
            case_fold: false,
            ..path_policy()
        };
        let folding = path_policy();

        // Equal, ancestor and descendant overlap; a byte prefix that is not a
        // component prefix does not. `src/foo` and `src/foobar` are the case
        // that separates a component comparison from a `starts_with`.
        for (left, right, overlaps) in [
            ("src/foo", "src/foo", true),
            ("src/foo", "src/foo/bar.rs", true),
            ("src/foo/bar.rs", "src/foo", true),
            ("src/foo", "src/foobar", false),
            ("src/foobar", "src/foo", false),
            ("src/foo", "src/bar", false),
            ("src", "docs", false),
            ("src/foo/", "src/foo", true),
            ("", "src/foo", true),
        ] {
            assert_eq!(
                regions_overlap(&prefixes(&[left]), &prefixes(&[right]), &sensitive),
                overlaps,
                "`{left}` against `{right}`"
            );
        }

        // Case folding is the run's, resolved once, and it folds beyond ASCII:
        // a case-folding filesystem folds `Ü` the same way it folds `U`.
        for (left, right) in [("src/Zebra", "src/zebra"), ("src/ÜBER", "src/über")] {
            assert!(
                !regions_overlap(&prefixes(&[left]), &prefixes(&[right]), &sensitive),
                "`{left}` and `{right}` are two files where case is significant"
            );
            assert!(
                regions_overlap(&prefixes(&[left]), &prefixes(&[right]), &folding),
                "`{left}` and `{right}` are one file where it is not"
            );
        }

        // Repo-wide overlaps everything, including the empty region — the
        // asymmetry the variant exists for.
        for other in [PathSet::RepoWide, prefixes(&[]), prefixes(&["src/foo"])] {
            assert!(regions_overlap(&PathSet::RepoWide, &other, &folding));
            assert!(regions_overlap(&other, &PathSet::RepoWide, &folding));
        }
        // And an empty region overlaps nothing else: a diff that touched
        // nothing is not a diff that touched everything.
        assert!(!regions_overlap(
            &prefixes(&[]),
            &prefixes(&["src/foo"]),
            &folding
        ));

        // A set overlaps when any member does, not only the first.
        assert!(regions_overlap(
            &prefixes(&["docs", "src/foo"]),
            &prefixes(&["build.rs", "src/foo/bar.rs"]),
            &folding
        ));
    }

    #[test]
    fn an_ordinary_candidate_waits_for_any_lineage_and_a_member_only_for_older_ones() {
        // `decisions.coordinator_integration.queue`, as the relation it is: a
        // lineage holds the region a rejection made contentious, so ordinary
        // work stays out of it entirely, and two lineages contending for one
        // region resolve by age rather than taking turns blocking each other.
        let policy = path_policy();
        let mut leases = LeaseTable::new();
        leases.grant(
            LeaseOwner::Lineage { root: ZETA },
            prefixes(&["src/shared"]),
        );
        leases.grant(LeaseOwner::Lineage { root: MID }, prefixes(&["src/shared"]));
        assert_eq!(leases.lineage(ZETA).expect("older").age, 0);
        assert_eq!(leases.lineage(MID).expect("younger").age, 1);

        let entry = |lineage_root: Option<TaskKey>| QueueEntry {
            candidate: candidate_of(ALPHA, 0),
            paths: prefixes(&["src/shared/thing.rs"]),
            lineage_root,
            verification_deferred: false,
            defers: 0,
            sequence: None,
        };
        let never_parked = |_: TaskKey| false;

        assert_eq!(
            CandidateQueue::ineligible(&entry(None), &never_parked, &leases, &policy),
            Some(Ineligible::InsideLineage { root: ZETA }),
            "an ordinary candidate waits for the oldest lineage it overlaps"
        );
        assert_eq!(
            CandidateQueue::ineligible(&entry(Some(ZETA)), &never_parked, &leases, &policy),
            None,
            "the oldest lineage's own member is not held back by the lineage it belongs to"
        );
        assert_eq!(
            CandidateQueue::ineligible(&entry(Some(MID)), &never_parked, &leases, &policy),
            Some(Ineligible::BehindOlderLineage { root: ZETA }),
            "a younger lineage's member waits for the older one"
        );

        // Parking and deferral outrank both, and are distinguished from each
        // other so a queue that reported one for the other is visible.
        assert_eq!(
            CandidateQueue::ineligible(&entry(Some(ZETA)), &|key| key == ALPHA, &leases, &policy),
            Some(Ineligible::AwaitingInput)
        );
        let deferred = QueueEntry {
            verification_deferred: true,
            ..entry(Some(ZETA))
        };
        assert_eq!(
            CandidateQueue::ineligible(&deferred, &never_parked, &leases, &policy),
            Some(Ineligible::VerificationDeferred)
        );

        // A region nobody holds is eligible whatever the lineages are.
        let elsewhere = QueueEntry {
            paths: prefixes(&["docs/guide.md"]),
            ..entry(None)
        };
        assert_eq!(
            CandidateQueue::ineligible(&elsewhere, &never_parked, &leases, &policy),
            None
        );
    }

    #[test]
    fn a_lineage_lease_only_ever_grows_and_a_released_one_is_gone() {
        let policy = path_policy();
        let mut leases = LeaseTable::new();
        leases.widen_lineage(ZETA, &prefixes(&["src/a"]));
        leases.widen_lineage(ZETA, &prefixes(&["src/b", "src/a"]));
        let held = leases.lineage(ZETA).expect("the lineage");
        let mut paths: Vec<&str> = held
            .paths
            .prefixes()
            .expect("bounded")
            .iter()
            .map(GitPath::as_str)
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["src/a", "src/b"],
            "widening is a union, not an append"
        );

        // Repo-wide absorbs: a region nobody could read stays unbounded.
        leases.widen_lineage(ZETA, &PathSet::RepoWide);
        assert!(
            leases
                .lineage(ZETA)
                .expect("the lineage")
                .paths
                .is_repo_wide()
        );
        leases.widen_lineage(ZETA, &prefixes(&["src/a"]));
        assert!(
            leases
                .lineage(ZETA)
                .expect("the lineage")
                .paths
                .is_repo_wide()
        );

        // A holding belongs to its owner: the same region held by somebody
        // else is a collision, and held by yourself is not.
        let mut table = LeaseTable::new();
        let owner = LeaseOwner::Generation {
            key: ZETA,
            generation: GenerationId(0),
        };
        table.grant(owner, prefixes(&["src/foo"]));
        assert!(!table.overlaps_another(owner, &prefixes(&["src/foo/bar.rs"]), &policy));
        assert!(table.overlaps_another(
            LeaseOwner::Generation {
                key: ALPHA,
                generation: GenerationId(0)
            },
            &prefixes(&["src/foo/bar.rs"]),
            &policy
        ));
        assert!(!table.any_candidate_or_lineage());
        table.grant(
            LeaseOwner::Candidate {
                key: ZETA,
                generation: GenerationId(0),
            },
            prefixes(&["src/foo"]),
        );
        assert!(table.any_candidate_or_lineage());
        table.release(LeaseOwner::Candidate {
            key: ZETA,
            generation: GenerationId(0),
        });
        assert!(!table.any_candidate_or_lineage());
        // Releasing what nobody holds is a statement, not an operation.
        table.release(LeaseOwner::Lineage { root: MID });
        assert!(!table.holds(LeaseOwner::Lineage { root: MID }));
    }

    #[test]
    fn a_generations_holding_decides_the_disposition_its_settlements_record() {
        // The relation refusals[14] is checked against, stated on its own: two
        // holdings, two fates, and exactly one disposition per cell.
        for (lease, survives, expected) in [
            (
                GenerationLease::Own,
                true,
                LeaseDisposition::PredictedRetained,
            ),
            (
                GenerationLease::Own,
                false,
                LeaseDisposition::PredictedReleased,
            ),
            (
                GenerationLease::InheritedLineage { root: ZETA },
                true,
                LeaseDisposition::LineageHeld,
            ),
            (
                GenerationLease::InheritedLineage { root: ZETA },
                false,
                LeaseDisposition::LineageHeld,
            ),
        ] {
            assert_eq!(lease.expected(survives), expected, "{lease:?} / {survives}");
        }
    }

    #[test]
    fn a_predicted_region_is_the_literal_prefix_of_every_hint() {
        // `admission_and_leases.path_policy.prediction`: the literal prefix
        // before the first glob metacharacter, and repo-wide for anything
        // unsafe or absent — the classification that costs parallelism and
        // never costs correctness.
        let registry = started().registry().expect("started").clone();
        let zeta = registry.get(ZETA).expect("zeta");
        assert_eq!(
            predicted_region(zeta),
            prefixes(&["src/Zebra"]),
            "a trailing separator is not part of the prefix"
        );
        let alpha = registry.get(ALPHA).expect("alpha");
        assert_eq!(
            predicted_region(alpha),
            prefixes(&["src/alpha"]),
            "the literal prefix stops at the first metacharacter"
        );
        let mid = registry.get(MID).expect("mid");
        assert_eq!(predicted_region(mid), prefixes(&["src/mid", "build.rs"]));

        // Absent, and unsafe, both classify repo-wide.
        let mut hintless = zeta.clone();
        hintless.spec.path_hints.clear();
        assert!(predicted_region(&hintless).is_repo_wide());
        for unsafe_hint in ["*.rs", "**/mod.rs", "/", "{a,b}/c"] {
            let mut entry = zeta.clone();
            entry.spec.path_hints = vec![unsafe_hint.to_owned()];
            assert!(
                predicted_region(&entry).is_repo_wide(),
                "`{unsafe_hint}` bounds nothing and must classify repo-wide"
            );
        }
        // A backslash-separated hint is a Windows spelling of the same region,
        // not a one-component path with a backslash in its name.
        let mut windows = zeta.clone();
        windows.spec.path_hints = vec!["src\\Zebra\\mod.rs".to_owned()];
        assert_eq!(predicted_region(&windows), prefixes(&["src/Zebra/mod.rs"]));
    }

    #[test]
    fn the_pipeline_entitlement_is_what_the_fold_derives_it_to_be() {
        // `admission_and_leases.permits.pipeline`: held by generations that are
        // open with no attempt, in flight, or promoting, plus one for an
        // unresolved integration transaction — and by nothing else. Retained
        // and closed generations hold none, and neither does a queued
        // candidate.
        let base = sha("base");
        let mut fold = started();
        let run = |fold: &TopologyFold| fold.state().expect("started").pipeline_held();
        assert_eq!(run(&fold), 0);

        apply(&mut fold, &dispatch(ZETA, 0, &base));
        assert_eq!(run(&fold), 1, "open with no attempt holds one");
        let start = attempt_started(&fold, ZETA, 0, 1, 0);
        apply(&mut fold, &start);
        assert_eq!(run(&fold), 1, "in flight holds the same one");

        let mut retained = fold.clone();
        apply(
            &mut retained,
            &settle(
                ZETA,
                0,
                1,
                AttemptSettlement::Retained {
                    retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                    retained_incarnation: Epoch(0),
                },
            ),
        );
        assert_eq!(run(&retained), 0, "a retained generation holds none");

        apply(&mut fold, &succeeded(ZETA, 0, 1));
        assert_eq!(run(&fold), 1, "promoting still holds it");
        apply(&mut fold, &candidate_prepared(ZETA, 0, &base));
        assert_eq!(run(&fold), 1);
        apply(&mut fold, &candidate_created(ZETA, 0));
        assert_eq!(
            run(&fold),
            0,
            "promotion releases it and a queued candidate holds none"
        );

        apply(&mut fold, &fast_publication(ZETA, 0, 0, &base, vec![ZETA]));
        assert_eq!(run(&fold), 1, "an unresolved transaction holds one");
        apply(&mut fold, &merged(ZETA, 0, 0, vec![ZETA]));
        assert_eq!(run(&fold), 0, "and the terminal releases it");
    }

    #[test]
    fn a_run_reaches_complete_only_when_every_task_has_settled() {
        // The end-to-end shape, driven by events rather than by writing state:
        // three tasks merged over the fast path, and the outcome moving from
        // NotEnding to Complete exactly at the last one.
        let mut fold = started();
        assert_eq!(fold.derived_outcome(), DerivedOutcome::NotEnding);
        merge_task(&mut fold, ALPHA, 0, 0);
        assert_eq!(fold.derived_outcome(), DerivedOutcome::NotEnding);
        merge_task(&mut fold, ZETA, 0, 1);
        assert_eq!(fold.derived_outcome(), DerivedOutcome::NotEnding);
        merge_task(&mut fold, MID, 0, 2);
        assert_eq!(
            fold.derived_outcome(),
            DerivedOutcome::Ending(RunOutcome::Complete)
        );
        assert!(fold.queue().expect("started").is_empty());
        assert!(!fold.leases().expect("started").any_candidate_or_lineage());
        apply(&mut fold, &run_finished(RunOutcome::Complete, None));
        assert_eq!(fold.finished(), Some(&RunOutcome::Complete));
    }

    #[test]
    fn halt_and_budget_outrank_every_structural_source_that_can_coexist_with_them() {
        // `run_end_policy.derived_outcome`'s precedence, source by source:
        // "if not common -> NotEnding; else if halting -> Halted; else if
        // budget -> BudgetExceeded; else if structurally_admissible or
        // backoff_pending -> NotEnding". A singleton example cannot reveal an
        // order, so each structural source is isolated and then crossed with a
        // halt and with the epoch's budget stop.
        let base = sha("base");

        // Source 1: a dispatchable task. A fresh run has exactly one — alpha
        // depends on nothing; zeta and mid wait on it — and an empty queue, so
        // `ready` is the only source alight.
        let ready_state = || started();
        assert_eq!(ready_state().derived_outcome(), DerivedOutcome::NotEnding);

        // Source 2: an eligible queued candidate and nothing dispatchable.
        // alpha is failed so no task is ready, and the two prepared candidates
        // are eligible, so `integration_admissible` is the only source alight.
        let integration_state = || {
            let mut fold = two_queued();
            let mut run = fold.run.take().expect("started");
            run.tasks[ALPHA.index()].state = TaskState::Failed;
            fold.run = Some(run);
            fold
        };
        let staged = integration_state();
        assert_eq!(staged.derived_outcome(), DerivedOutcome::NotEnding);
        assert!(
            !staged.queue().expect("started").is_empty(),
            "the integration source has to be a queued candidate"
        );

        for (label, build) in [
            (
                "a dispatchable task",
                &ready_state as &dyn Fn() -> TopologyFold,
            ),
            ("an eligible integration", &integration_state),
        ] {
            let mut halted = build();
            let mut run = halted.run.take().expect("started");
            let epoch = run.epoch;
            run.halted_at = Some(ALPHA);
            run.halted_epoch = Some(epoch);
            halted.run = Some(run);
            assert_eq!(
                halted.derived_outcome(),
                DerivedOutcome::Ending(RunOutcome::Halted),
                "{label} outranked a halting settlement"
            );

            let mut stopped = build();
            let mut run = stopped.run.take().expect("started");
            let epoch = run.epoch;
            run.budget_stop = Some(BudgetStop {
                epoch,
                budget: BudgetKind::Run,
            });
            stopped.run = Some(run);
            assert_eq!(
                stopped.derived_outcome(),
                DerivedOutcome::Ending(RunOutcome::BudgetExceeded),
                "{label} outranked the epoch's budget stop"
            );
        }

        // Source 3, and why it can never be crossed with either: a retry is
        // admissible only while a RetainedIdle generation is open, and an open
        // generation of any class makes `common` false, which outranks
        // everything. The state is recorded here rather than argued, because
        // "unreachable" is the kind of claim that stops being true quietly.
        let mut retained = started();
        apply(&mut retained, &dispatch(ZETA, 0, &base));
        let start = attempt_started(&retained, ZETA, 0, 1, 0);
        apply(&mut retained, &start);
        apply(
            &mut retained,
            &settle(
                ZETA,
                0,
                1,
                AttemptSettlement::Retained {
                    retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                    retained_incarnation: Epoch(0),
                },
            ),
        );
        assert_eq!(retained.task_state(ZETA), Some(TaskState::Pending));
        assert!(matches!(
            retained
                .task(ZETA)
                .expect("zeta")
                .open()
                .map(|generation| &generation.class),
            Some(GenerationClass::RetainedIdle { .. })
        ));
        let mut run = retained.run.take().expect("started");
        let epoch = run.epoch;
        run.halted_at = Some(ALPHA);
        run.halted_epoch = Some(epoch);
        retained.run = Some(run);
        assert_eq!(
            retained.derived_outcome(),
            DerivedOutcome::NotEnding,
            "an open generation is not common, and not-common outranks the halt"
        );
    }

    #[test]
    fn complete_refuses_each_residue_it_leaves_behind_one_at_a_time() {
        // The Complete arm's conjuncts past the task predicate: "the queue is
        // empty (no R6 open), and no candidate or lineage lease is active
        // (R7/R8 none)". Every task is held terminal throughout, so each
        // residue is the only thing between this state and Complete and a
        // conjunct that was dropped shows up as Complete rather than as a
        // different refusal.
        let terminal = || {
            let mut fold = started();
            let mut run = fold.run.take().expect("started");
            for task in &mut run.tasks {
                task.state = TaskState::Merged;
            }
            fold.run = Some(run);
            fold
        };
        assert_eq!(
            terminal().derived_outcome(),
            DerivedOutcome::Ending(RunOutcome::Complete),
            "the fixture has to be Complete before a residue is added, or nothing is isolated"
        );

        let residues: [(&str, AddResidue); 3] = [
            ("a queue position", |run| {
                run.queue.push(QueueEntry {
                    candidate: candidate_of(MID, 0),
                    paths: region(MID),
                    lineage_root: None,
                    verification_deferred: false,
                    defers: 0,
                    sequence: None,
                });
            }),
            ("a candidate lease", |run| {
                run.leases.grant(
                    LeaseOwner::Candidate {
                        key: MID,
                        generation: GenerationId(0),
                    },
                    region(MID),
                );
            }),
            ("a lineage lease", |run| {
                run.leases
                    .grant(LeaseOwner::Lineage { root: ALPHA }, region(ALPHA));
            }),
        ];
        for (label, add) in residues {
            let mut fold = terminal();
            let mut run = fold.run.take().expect("started");
            add(&mut run);
            fold.run = Some(run);
            assert_ne!(
                fold.derived_outcome(),
                DerivedOutcome::Ending(RunOutcome::Complete),
                "a run that still holds {label} was Complete"
            );
            assert!(
                matches!(
                    refuse(&fold, &run_finished(RunOutcome::Complete, None)),
                    FoldError::OutcomeMismatch { .. }
                ),
                "a run that still holds {label} said it was Complete"
            );
        }

        // A generation lease is not one of the two: an ordinary generation's
        // predicted region is released when the generation closes, and the
        // Complete arm names the candidate and lineage holdings only.
        let mut generation_only = terminal();
        let mut run = generation_only.run.take().expect("started");
        run.leases.grant(
            LeaseOwner::Generation {
                key: MID,
                generation: GenerationId(0),
            },
            region(MID),
        );
        generation_only.run = Some(run);
        assert_eq!(
            generation_only.derived_outcome(),
            DerivedOutcome::Ending(RunOutcome::Complete)
        );
    }

    #[test]
    fn backoff_is_what_is_waiting_now_and_not_what_once_waited() {
        // `backoff_pending` is "any task is Deferred or any candidate is
        // verification_deferred (both are woken only by the durable
        // defer_wait_elapsed or run_resumed)". The historical defer *count* is
        // kept for the consecutiveness rule and is not a waiting state, so a
        // candidate that has deferred once and been woken does not block a
        // closure. The two stay correlated unless a fixture separates them.
        let head = sha("head");
        let proposal = sha("proposal");
        let mut fold = two_queued();
        apply(
            &mut fold,
            &verification_started(MID, 0, 0, &head, &proposal),
        );
        apply(
            &mut fold,
            &unavailable_event(0, outage(), UnavailableOutcome::Deferred { defers: 1 }),
        );
        assert_eq!(fold.derived_outcome(), DerivedOutcome::NotEnding);
        apply(
            &mut fold,
            &ev(TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 30_000,
                    round: 1,
                },
            }),
        );

        // Woken: the flag is clear and the history is not.
        let entry = &fold.queue().expect("started").entries()[0];
        assert!(!entry.verification_deferred, "the wake cleared the flag");
        assert_eq!(entry.defers, 1, "and kept the count it is measured against");

        // Settle everything around it, so the only thing that could still make
        // this run NotEnding is that retained count.
        let woken = fold.clone();
        let mut run = fold.run.take().expect("started");
        run.queue = CandidateQueue::new();
        run.leases = LeaseTable::new();
        for task in &mut run.tasks {
            task.state = TaskState::Merged;
        }
        let carried = QueueEntry {
            candidate: candidate_of(MID, 0),
            paths: region(MID),
            lineage_root: None,
            verification_deferred: false,
            defers: 1,
            sequence: None,
        };
        fold.run = Some(run);
        assert_eq!(
            fold.derived_outcome(),
            DerivedOutcome::Ending(RunOutcome::Complete)
        );
        // And with the same entry still queued but *not* waiting, the queue
        // conjunct is what stops it — not the count.
        let mut with_entry = fold.clone();
        let mut run = with_entry.run.take().expect("started");
        run.queue.push(carried);
        with_entry.run = Some(run);
        assert_eq!(with_entry.derived_outcome(), DerivedOutcome::NotEnding);
        assert!(
            !with_entry.queue().expect("started").entries()[0].verification_deferred,
            "the entry that blocks Complete is queued, not backing off"
        );

        // The state where the two readings disagree about an *outcome* rather
        // than about a reason: a parked verification. The candidate stays
        // queued and ineligible with its history intact and its flag clear,
        // the task is AwaitingInput, and `derived_outcome` is Parked — which
        // `backoff_pending` outranks. A fold that read the retained count as a
        // waiting state answers NotEnding here and refuses the closure the
        // packet requires.
        let mut parked = woken;
        apply(
            &mut parked,
            &verification_started(MID, 0, 1, &head, &proposal),
        );
        apply(
            &mut parked,
            &unavailable_event(
                1,
                outage(),
                UnavailableOutcome::Parked {
                    question: question("q-outage-Ünicode", MID),
                },
            ),
        );
        // Silence the other structural sources so the Parked arm is what is
        // being read: alpha is terminal, and zeta's candidate leaves the queue
        // with the holding it took.
        let mut run = parked.run.take().expect("started");
        run.tasks[ALPHA.index()].state = TaskState::Failed;
        run.queue.remove(ZETA, GenerationId(0));
        run.leases.release(LeaseOwner::Candidate {
            key: ZETA,
            generation: GenerationId(0),
        });
        parked.run = Some(run);

        let entry = &parked.queue().expect("started").entries()[0];
        assert_eq!(entry.candidate.key, MID);
        assert_eq!(entry.defers, 1, "the history the mutation would read");
        assert!(
            !entry.verification_deferred,
            "and the flag, which is what backoff_pending is about"
        );
        assert_eq!(parked.task_state(MID), Some(TaskState::AwaitingInput));
        assert_eq!(
            parked.derived_outcome(),
            DerivedOutcome::Ending(RunOutcome::Parked),
            "a candidate that has deferred before and is now parked is parked, not backing off"
        );
        accepts(&parked, &run_finished(RunOutcome::Parked, None));
    }

    #[test]
    fn a_failure_blocks_the_whole_dependency_closure_and_not_only_its_neighbours() {
        // `run_end_policy.derived_outcome`: Complete requires "every task is
        // Merged, Failed, or Pending with a Failed task in its **transitive**
        // dependency closure (derived Blocked)".
        //
        // The 1008-cell grid cannot prove this, because its BlockedByFailure
        // fixture makes every pending task depend on the failed one directly:
        // there, "directly failed dependency" and "failed anywhere in the
        // closure" are the same predicate. Here they are not. `cee` fails,
        // `bee` depends on `cee` and is blocked directly, and `aay` depends
        // only on `bee` and is blocked by two hops and by nothing else. A
        // derivation that recognized only a directly failed dependency leaves
        // `aay` Pending-and-unblocked, so no arm of the total function claims
        // the state and it lands on FoldError.
        let base = sha("base");
        let started_event = chain_run_started_event();
        let mut live = TopologyFold::new(chain_inputs());
        apply(&mut live, &started_event);
        let mut trace = vec![started_event];
        let push =
            |live: &mut TopologyFold, trace: &mut Vec<TopologyEvent>, event: TopologyEvent| {
                apply(live, &event);
                trace.push(event);
            };

        // The dependency shape is the fixture's, read back rather than assumed.
        let registry = live.registry().expect("started");
        assert_eq!(registry.get(AAY).expect("aay").deps, vec![BEE]);
        assert_eq!(registry.get(BEE).expect("bee").deps, vec![CEE]);
        assert!(registry.get(CEE).expect("cee").deps.is_empty());
        assert!(
            !registry.get(AAY).expect("aay").deps.contains(&CEE),
            "the first task must not depend on the failure directly, or this proves nothing"
        );

        push(&mut live, &mut trace, dispatch(CEE, 0, &base));
        let start = attempt_started(&live, CEE, 0, 1, 0);
        push(&mut live, &mut trace, start);
        assert_eq!(live.derived_outcome(), DerivedOutcome::NotEnding);
        push(
            &mut live,
            &mut trace,
            settle(
                CEE,
                0,
                1,
                AttemptSettlement::Closed {
                    transition: SettlementTransition::Failed {
                        halts_run: false,
                        reason: "  the ladder ran out  ".to_owned(),
                    },
                    lease: LeaseDisposition::PredictedReleased,
                },
            ),
        );

        // Nothing else can move: `bee` waits on a task that failed and `aay`
        // waits on `bee`. Every Complete conjunct holds.
        assert_eq!(live.task_state(CEE), Some(TaskState::Failed));
        assert_eq!(live.task_state(BEE), Some(TaskState::Pending));
        assert_eq!(live.task_state(AAY), Some(TaskState::Pending));
        assert!(live.queue().expect("started").is_empty());
        assert!(!live.leases().expect("started").any_candidate_or_lineage());
        assert!(live.open_questions().expect("started").is_empty());
        assert_eq!(live.halted_at(), None);
        assert_eq!(
            live.derived_outcome(),
            DerivedOutcome::Ending(RunOutcome::Complete),
            "a transitively blocked task is Blocked, and a run of Merged, Failed and Blocked \
             tasks is Complete"
        );

        // Live and replay, through the wire, reach the same verdict — and the
        // run may say so.
        push(
            &mut live,
            &mut trace,
            run_finished(RunOutcome::Complete, None),
        );
        assert_eq!(live.finished(), Some(&RunOutcome::Complete));

        let mut log = Vec::new();
        for event in &trace {
            log.extend_from_slice(serde_json::to_string(event).expect("serialize").as_bytes());
            log.push(b'\n');
        }
        let parsed = TopologyFold::parse_log(&log).expect("the log parses");
        assert_eq!(parsed, trace);
        let replayed =
            TopologyFold::replay(chain_inputs(), &parsed).expect("a blocked-closure log replays");
        assert_eq!(live.state(), replayed.state());
        assert_eq!(
            replayed.derived_outcome(),
            DerivedOutcome::Ending(RunOutcome::Complete)
        );

        // And the direction that says the predicate is not vacuous: with `cee`
        // still Pending rather than Failed, nothing is Blocked, `cee` is
        // admissible, and the run is not ending.
        let prefix = TopologyFold::replay(chain_inputs(), &trace[..1]).expect("the prefix replays");
        assert_eq!(prefix.task_state(CEE), Some(TaskState::Pending));
        assert_eq!(prefix.derived_outcome(), DerivedOutcome::NotEnding);
    }
}
