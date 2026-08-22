//! The fault-seam framework: typed effect sites, the hook harness, and the
//! fault-injection registry format.
//!
//! Nothing here performs an effect, and nothing here is wired into a funnel
//! yet. What is here is the *vocabulary* every later slice's proof is written
//! in: an inventory of the external-effect contexts a schema-4 run has, typed
//! so that "which resource row does this touch", "which durable append is it
//! ordered against", and "which fault-matrix row does a kill here land in" are
//! compile-time exhaustive functions rather than comments.
//!
//! # Why a type and not a string
//!
//! The claim ST-07 makes is a *bijection*: every effect site, in both hook
//! phases and at every parent-side sub-effect point, is observed executed at
//! least once, has a registry entry for every observable order, and every entry
//! has evidence. A bijection over a set of strings is a bijection over whatever
//! the strings happened to be that day. [`EffectSiteId`] is closed — a site
//! that is not a variant does not exist, and an entry naming one is refused —
//! so the left-hand side of the bijection is fixed by the compiler and the
//! right-hand side is what the suite must fill in.
//!
//! # The three kinds of thing a registry entry can be about
//!
//! They are different in kind and the framework keeps them apart by type,
//! because conflating them is how a coverage report claims coverage it does
//! not have:
//!
//! * A **hook phase** ([`HookPhase::Before`], [`HookPhase::After`]) — parent
//!   code that runs immediately either side of the primitive. Observed by
//!   execution.
//! * A **parent-side sub-effect point** ([`SubEffectPoint`]) — parent code
//!   inside a funnel, between two steps of one logical effect, in one
//!   [`InjectionMode`]. Also observed by execution.
//! * A **command-internal residue class** ([`ResidueClass`]) — a durable prefix
//!   *inside* an external command that the parent provably cannot hook. Its
//!   evidence is [`EvidenceLabel::RecoveryProven`]: synthetic construction of
//!   every residue element plus a kill-sampling record. It is **never** an
//!   executed hook, and [`FaultRegistry::insert`] refuses any entry that claims
//!   it is.
//!
//! That last refusal is the load-bearing one. A framework that accepted a
//! residue-class entry carrying an executed-hook claim would report that the
//! suite had observed something no portable mechanism can observe.
//!
//! # What is not here
//!
//! The funnels themselves, the clippy disallowed lists, the allow-placement
//! scan, and every real site's implementation. This slice builds the frame such
//! that those can be dropped in; it asserts nothing about code that does not
//! exist yet.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// The eleven funnel API groups (`decisions.effect_site_inventory.identity`).
///
/// A group is an API surface, not a resource: one group can span several
/// [`ResourceRow`]s, and one row can be reached from several groups. The
/// grouping is what makes `hook(Before, site) -> primitive -> hook(After, site)`
/// implementable once per funnel rather than once per site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunnelGroup {
    Worktree,
    Snapshot,
    Ref,
    Object,
    RunDir,
    Event,
    Answer,
    Lock,
    Report,
    Process,
    Container,
}

impl FunnelGroup {
    /// Every group, in the order `identity` names them.
    pub const ALL: &'static [Self] = &[
        Self::Worktree,
        Self::Snapshot,
        Self::Ref,
        Self::Object,
        Self::RunDir,
        Self::Event,
        Self::Answer,
        Self::Lock,
        Self::Report,
        Self::Process,
        Self::Container,
    ];

    /// The group's name as it appears in a site's dotted name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Worktree => "Worktree",
            Self::Snapshot => "Snapshot",
            Self::Ref => "Ref",
            Self::Object => "Object",
            Self::RunDir => "RunDir",
            Self::Event => "Event",
            Self::Answer => "Answer",
            Self::Lock => "Lock",
            Self::Report => "Report",
            Self::Process => "Process",
            Self::Container => "Container",
        }
    }

    /// The funnel module this group's effects are confined to
    /// (`decisions.effect_site_inventory.mechanism`, the funnel-module list).
    ///
    /// Recorded per group rather than per site because the allow-placement scan
    /// PR6 builds works on modules: a module either performs effects only
    /// inside site-taking APIs, or it does not.
    pub const fn module(self) -> &'static str {
        match self {
            Self::Worktree | Self::Snapshot | Self::Ref | Self::Object => {
                "src/workspace_manager.rs"
            }
            Self::RunDir | Self::Lock => "src/rundir.rs",
            Self::Event => "src/events/log.rs",
            Self::Answer => "src/interaction.rs",
            Self::Report => "src/util.rs",
            Self::Process => "src/runner/host.rs",
            Self::Container => "src/runner/container.rs",
        }
    }
}

impl fmt::Display for FunnelGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The resource-ledger rows an effect site can touch
/// (`decisions.resource_accounting.rows`).
///
/// Only the external-physical and process-local-OS rows appear: R1–R8 and
/// R13–R16 are the logical fold/broker domain, which
/// `resource_accounting.enforcement_domains` says takes no effect-site mapping
/// at all — "no effect-site mapping required or allowed". Their absence from
/// this enum is that rule expressed as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceRow {
    /// Task worktree + its durable synced intent, and the objects its index or
    /// HEAD references.
    R9,
    /// Staging worktree `merge/<seq>` + its intent (stale candidates only).
    R10,
    /// Candidates ref: authoritative candidate identity.
    R11,
    /// `prepared/<seq>` proposal pin (stale candidates only).
    R12,
    /// The coordinator's own lock holds (OS lock state only).
    R17,
    /// Execution root directory.
    R18,
    /// Disposable Git view directory (container runner).
    R19,
    /// Integration ref and run-scoped run-directory contents, public and
    /// private.
    R21,
    /// Host process handle / private job object / ambient job membership.
    R22,
    /// Candidate-prepared pin (non-authoritative).
    R23,
    /// Exact gate/review snapshot worktree + its intent.
    R24,
    /// The repository-scoped `tactus-worktree.lock` file itself.
    R25,
    /// Container invocation: the container, its labels, and its global intent.
    R26,
    /// Engine-created Git objects no engine ref, pin, or worktree references.
    R27,
    /// A surviving Unix reaper's shared `cleanup.lock` hold.
    R28,
}

impl ResourceRow {
    /// Every row an effect site may name, in ledger order.
    pub const ALL: &'static [Self] = &[
        Self::R9,
        Self::R10,
        Self::R11,
        Self::R12,
        Self::R17,
        Self::R18,
        Self::R19,
        Self::R21,
        Self::R22,
        Self::R23,
        Self::R24,
        Self::R25,
        Self::R26,
        Self::R27,
        Self::R28,
    ];

    /// The row's ledger id.
    pub const fn name(self) -> &'static str {
        match self {
            Self::R9 => "R9",
            Self::R10 => "R10",
            Self::R11 => "R11",
            Self::R12 => "R12",
            Self::R17 => "R17",
            Self::R18 => "R18",
            Self::R19 => "R19",
            Self::R21 => "R21",
            Self::R22 => "R22",
            Self::R23 => "R23",
            Self::R24 => "R24",
            Self::R25 => "R25",
            Self::R26 => "R26",
            Self::R27 => "R27",
            Self::R28 => "R28",
        }
    }

    /// Which enforcement domain the row belongs to.
    ///
    /// The distinction matters to ST-09 rather than to ST-07, but it is a
    /// property of the row and belongs beside it: a process-local row is
    /// released by the OS at process death and is never released by cleanup,
    /// so an entry that tables a cleanup step for one is wrong on its face.
    pub const fn domain(self) -> EnforcementDomain {
        match self {
            Self::R17 | Self::R22 | Self::R28 => EnforcementDomain::ProcessLocalOs,
            Self::R9
            | Self::R10
            | Self::R11
            | Self::R12
            | Self::R18
            | Self::R19
            | Self::R21
            | Self::R23
            | Self::R24
            | Self::R25
            | Self::R26
            | Self::R27 => EnforcementDomain::ExternalPhysical,
        }
    }
}

impl fmt::Display for ResourceRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The two enforcement domains an effect site's row can belong to.
///
/// The logical fold/broker domain is deliberately absent: it has no sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementDomain {
    /// State on a real filesystem, ref store, or container runtime.
    ExternalPhysical,
    /// OS state bound to a process lifetime, released by the OS at its death.
    ProcessLocalOs,
}

/// Every tag the schema-4 vocabulary can write.
///
/// A mirror of [`crate::topology::events::TOPOLOGY_EVENT_KINDS`], typed so that
/// a site's adjacency is a value the compiler checks rather than a string a
/// typo can invent. The two lists are asserted equal element-for-element by a
/// unit test, so a change to the vocabulary breaks this module rather than
/// silently leaving a site pointing at an append that no longer exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableEvent {
    RunStarted,
    RunResumed,
    TaskSpawned,
    TaskDispatched,
    AttemptStarted,
    AttemptFinished,
    AttemptInterrupted,
    GenerationClosed,
    DeferWaitElapsed,
    CandidatePrepared,
    TaskCandidateCreated,
    MergeVerificationStarted,
    MergeVerificationUnavailable,
    MergeVerificationInterrupted,
    MergePrepared,
    MergeRejected,
    TaskMerged,
    QuestionRaised,
    QuestionAnswered,
    BudgetExceeded,
    RunFinished,
    CapacitySnapshot,
    PoolExhausted,
    DesignDefect,
}

impl DurableEvent {
    /// Every kind, in the vocabulary's declaration order.
    pub const ALL: &'static [Self] = &[
        Self::RunStarted,
        Self::RunResumed,
        Self::TaskSpawned,
        Self::TaskDispatched,
        Self::AttemptStarted,
        Self::AttemptFinished,
        Self::AttemptInterrupted,
        Self::GenerationClosed,
        Self::DeferWaitElapsed,
        Self::CandidatePrepared,
        Self::TaskCandidateCreated,
        Self::MergeVerificationStarted,
        Self::MergeVerificationUnavailable,
        Self::MergeVerificationInterrupted,
        Self::MergePrepared,
        Self::MergeRejected,
        Self::TaskMerged,
        Self::QuestionRaised,
        Self::QuestionAnswered,
        Self::BudgetExceeded,
        Self::RunFinished,
        Self::CapacitySnapshot,
        Self::PoolExhausted,
        Self::DesignDefect,
    ];

    /// This kind's tag, as the log writes it.
    pub const fn kind(self) -> &'static str {
        match self {
            Self::RunStarted => "run_started",
            Self::RunResumed => "run_resumed",
            Self::TaskSpawned => "task_spawned",
            Self::TaskDispatched => "task_dispatched",
            Self::AttemptStarted => "attempt_started",
            Self::AttemptFinished => "attempt_finished",
            Self::AttemptInterrupted => "attempt_interrupted",
            Self::GenerationClosed => "generation_closed",
            Self::DeferWaitElapsed => "defer_wait_elapsed",
            Self::CandidatePrepared => "candidate_prepared",
            Self::TaskCandidateCreated => "task_candidate_created",
            Self::MergeVerificationStarted => "merge_verification_started",
            Self::MergeVerificationUnavailable => "merge_verification_unavailable",
            Self::MergeVerificationInterrupted => "merge_verification_interrupted",
            Self::MergePrepared => "merge_prepared",
            Self::MergeRejected => "merge_rejected",
            Self::TaskMerged => "task_merged",
            Self::QuestionRaised => "question_raised",
            Self::QuestionAnswered => "question_answered",
            Self::BudgetExceeded => "budget_exceeded",
            Self::RunFinished => "run_finished",
            Self::CapacitySnapshot => "capacity_snapshot",
            Self::PoolExhausted => "pool_exhausted",
            Self::DesignDefect => "design_defect",
        }
    }
}

impl fmt::Display for DurableEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind())
    }
}

/// The durable append a site's effect is ordered against.
///
/// `Before` means the effect is designed to be durable before the append is;
/// `After` means the append is durable first. `None` is not "unknown": it is
/// the answer for a site that *is* the append (the whole [`EventSite`] append
/// group), and for a site that runs outside any run's log at all — the husk
/// census removes a run directory belonging to a run whose log it has refused
/// to fold.
///
/// The value decides [`EffectSiteId::observable_orders`], which is what the
/// registry's order axis ranges over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Adjacent {
    /// The effect precedes this append.
    Before(DurableEvent),
    /// This append precedes the effect.
    After(DurableEvent),
    /// No append is adjacent.
    None,
}

impl Adjacent {
    /// The append this site is ordered against, where there is one.
    pub const fn event(self) -> Option<DurableEvent> {
        match self {
            Self::Before(kind) | Self::After(kind) => Some(kind),
            Self::None => None,
        }
    }
}

/// The transaction fault-matrix row a fault at a site lands in.
///
/// One variant per row of `transaction_fault_matrix`, in its order. The row is
/// what says which durable prefix the fault leaves and what a resume does about
/// it; the site says where the fault can happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultRow {
    TRunstart,
    TDispatch,
    TAttempt,
    TRetry,
    TCandObj,
    TCandRef,
    TScrub,
    TFailed,
    TRetained,
    TFast,
    TProposal,
    TVerify,
    TPrepared,
    TReject,
    TRepairDispatch,
    TContainer,
    TAppend,
    TAnswer,
    TFinish,
    TFinalize,
    TResume,
}

impl FaultRow {
    /// Every row, in matrix order.
    pub const ALL: &'static [Self] = &[
        Self::TRunstart,
        Self::TDispatch,
        Self::TAttempt,
        Self::TRetry,
        Self::TCandObj,
        Self::TCandRef,
        Self::TScrub,
        Self::TFailed,
        Self::TRetained,
        Self::TFast,
        Self::TProposal,
        Self::TVerify,
        Self::TPrepared,
        Self::TReject,
        Self::TRepairDispatch,
        Self::TContainer,
        Self::TAppend,
        Self::TAnswer,
        Self::TFinish,
        Self::TFinalize,
        Self::TResume,
    ];

    /// The row's id, exactly as the matrix writes it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::TRunstart => "T-RUNSTART",
            Self::TDispatch => "T-DISPATCH",
            Self::TAttempt => "T-ATTEMPT",
            Self::TRetry => "T-RETRY",
            Self::TCandObj => "T-CAND-OBJ",
            Self::TCandRef => "T-CAND-REF",
            Self::TScrub => "T-SCRUB",
            Self::TFailed => "T-FAILED",
            Self::TRetained => "T-RETAINED",
            Self::TFast => "T-FAST",
            Self::TProposal => "T-PROPOSAL",
            Self::TVerify => "T-VERIFY",
            Self::TPrepared => "T-PREPARED",
            Self::TReject => "T-REJECT",
            Self::TRepairDispatch => "T-REPAIR-DISPATCH",
            Self::TContainer => "T-CONTAINER",
            Self::TAppend => "T-APPEND",
            Self::TAnswer => "T-ANSWER",
            Self::TFinish => "T-FINISH",
            Self::TFinalize => "T-FINALIZE",
            Self::TResume => "T-RESUME",
        }
    }
}

impl fmt::Display for FaultRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Which claim a site is inside (`decisions.effect_site_inventory.scope`).
///
/// `Topology` and `Shared` carry the full ST-07 requirement. `Legacy` sites are
/// inventoried and row-mapped and carry no fault-registry requirement beyond
/// today's legacy tests — they exist because the Event funnel is shared and its
/// legacy callers have to pass *something*, and a scope is a safer thing for
/// them to pass than a site that also claims topology coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteScope {
    /// Reached only by schema-4 paths.
    Topology,
    /// Reached by both schema-4 and legacy paths through one funnel.
    Shared,
    /// Reached only by schema-1..3 paths.
    Legacy,
}

impl SiteScope {
    /// Whether this scope carries the ST-07 bijection requirement.
    pub const fn is_claimed(self) -> bool {
        match self {
            Self::Topology | Self::Shared => true,
            Self::Legacy => false,
        }
    }
}

/// How a fault is introduced at a parent-side sub-effect point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionMode {
    /// The process dies at the point.
    Kill,
    /// The funnel returns `Err` from the point, after performing or partially
    /// performing the primitive.
    ErrorReturn,
}

impl InjectionMode {
    /// Both modes.
    pub const ALL: &'static [Self] = &[Self::Kill, Self::ErrorReturn];
}

/// Which host a sub-effect point exists on.
///
/// The containment steps are the only points that differ: a Windows ambient
/// job has no Unix counterpart and a Unix reaper has no Windows one. ST-07's
/// evidence "executes each point on its platform", so the bijection check is
/// told which platform it is running on and does not require a point that
/// cannot exist there.
///
/// This is a property of a *point*, not a machine: [`Self::Any`] means "exists
/// wherever the parent runs". A host is [`Host`], which has no such value —
/// see the type for why the two are not one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Present on every host.
    Any,
    /// Present only on Windows.
    Windows,
    /// Present only on Unix.
    Unix,
}

/// The host a bijection check is running on.
///
/// Two values, and deliberately not [`Platform`]'s three. `required_on` used to
/// take a `Platform` as its host and answer the `(Windows, Any)` and
/// `(Unix, Any)` pairs through a `(Self::Windows, _) | (Self::Unix, _) => false`
/// wildcard — so `Platform::Any` named a host on which *neither* platform's
/// containment points were required, and `check_bijection` returned success for
/// `Process.Spawn` with all eight containment points unobserved and unentered.
/// A checker that can be handed a host meaning "no platform" is a checker whose
/// strongest claim is optional.
///
/// The fix is the type rather than a guard: a machine is Windows or it is Unix,
/// and there is no third value to reject at a boundary, forget to reject at the
/// next one, or serialize into a registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    /// A Windows host: the ambient- and private-job containment steps exist.
    Windows,
    /// A Unix host: the reaper containment steps exist.
    Unix,
}

impl Host {
    /// Both hosts. Every self-test that asserts a platform-dependent shape runs
    /// over this slice rather than over [`Self::current`], because a build that
    /// only ever checks its own host cannot fail on the other one until the
    /// other one's CI cell does.
    pub const ALL: &'static [Self] = &[Self::Windows, Self::Unix];

    /// The host's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Unix => "unix",
        }
    }

    /// The host this build is running on.
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }

    /// The other host.
    pub const fn other(self) -> Self {
        match self {
            Self::Windows => Self::Unix,
            Self::Unix => Self::Windows,
        }
    }

    /// This host as a point platform: the platform whose points it requires.
    pub const fn platform(self) -> Platform {
        match self {
            Self::Windows => Platform::Windows,
            Self::Unix => Platform::Unix,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Platform {
    /// Whether a point declared for `self` has to be observed on `host`.
    ///
    /// Every pair is written out. No wildcard stands in for the two negative
    /// answers, so a host value added later fails to compile here instead of
    /// quietly joining the `false` arm and excusing a platform's points from
    /// the bijection.
    pub const fn required_on(self, host: Host) -> bool {
        match (self, host) {
            (Self::Any, Host::Windows) | (Self::Any, Host::Unix) => true,
            (Self::Windows, Host::Windows) | (Self::Unix, Host::Unix) => true,
            (Self::Windows, Host::Unix) | (Self::Unix, Host::Windows) => false,
        }
    }
}

/// A parent-side point inside a funnel, between two steps of one logical
/// effect.
///
/// A hook is parent-executed code and can be executed only where the parent
/// runs. These are the places inside a funnel where that is still true: after
/// a child has exited but before the parent recorded what it printed
/// ([`Self::IdUnread`]), between a write and its sync ([`Self::Written`],
/// [`Self::Synced`]), inside the log-open sequence, and at the containment
/// steps of a spawn — which are parent-side or, for
/// [`Self::PreExecPgidAndRegister`], run in the forked child before `exec`,
/// which is still this crate's code and still under the harness's control.
///
/// Everything that is *not* on this list and not a hook phase is a command-
/// internal residue class instead. The distinction is the whole point:
/// `claim_scope` claims parent-observed execution only for parent-executed
/// code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubEffectPoint {
    /// A commit-tree child has exited with its object written; the coordinator
    /// has not read or recorded the printed id. R27 residue.
    IdUnread,
    /// Bytes written, possibly partially, not yet synced.
    ///
    /// In kill mode this is the whole of what the packet tables for a written
    /// append — "torn: truncated on the next open, previous prefix;
    /// complete-unsynced: either prefix". In error-return mode it is the
    /// *first* of three separately required cases: the partial write that
    /// returned `Err` before a newline was committed.
    Written,
    /// The complete newline-terminated line is written and the flush has not
    /// run.
    ///
    /// The second required error-return case
    /// (`fault_injection_registry.structure`: "error-return entries for
    /// Written-partial-then-Err, **Written-full-then-flush-Err**, and
    /// Synced-Err"). A separate point rather than a second entry at
    /// `Written/ErrorReturn`, because that key is one key: the registry is
    /// keyed by site x phase x order x mode, so two cases at one coordinate
    /// are a duplicate the format refuses, and one of the two would go
    /// unexecuted while the coordinate read as complete. The durable shapes
    /// differ too — a partial line is a torn tail the next open truncates, a
    /// complete unsynced line is a prefix the barrier makes durable — so they
    /// are two rows, not one row observed twice.
    ///
    /// Kill mode is deliberately absent: `structure` tables kill entries for
    /// `Written` and `Synced` only, and a kill here leaves the
    /// complete-unsynced prefix `Written`'s kill entry already covers.
    /// Declaring one would manufacture a coverage obligation the design does
    /// not make.
    WrittenFull,
    /// The append is synced.
    Synced,
    /// The log file was created (and its directory fsynced) because it was
    /// absent.
    Create,
    /// An unterminated final line was truncated before the append handle was
    /// taken.
    TruncateTornTail,
    /// The complete surviving prefix was synced — the durable half of the
    /// stable-prefix barrier.
    SyncPrefix,
    /// Windows: the coordinator process joined the ambient job at startup.
    AmbientJobJoined,
    /// Windows: the child was created suspended, already an ambient-job member.
    CreatedSuspended,
    /// Windows: the child was assigned to its private job object.
    PrivateJobAssigned,
    /// Windows: the suspended child was resumed.
    Resumed,
    /// Unix: the per-invocation reaper was forked and took its cleanup hold.
    ReaperStarted,
    /// Unix: in the forked child, before `exec`, the pgid was set and the group
    /// registered.
    PreExecPgidAndRegister,
    /// Unix: the child `exec`ed.
    Exec,
    /// Unix: the parent registered the running group.
    Registered,
}

impl SubEffectPoint {
    /// Every point.
    pub const ALL: &'static [Self] = &[
        Self::IdUnread,
        Self::Written,
        Self::WrittenFull,
        Self::Synced,
        Self::Create,
        Self::TruncateTornTail,
        Self::SyncPrefix,
        Self::AmbientJobJoined,
        Self::CreatedSuspended,
        Self::PrivateJobAssigned,
        Self::Resumed,
        Self::ReaperStarted,
        Self::PreExecPgidAndRegister,
        Self::Exec,
        Self::Registered,
    ];

    /// The point's name inside its site.
    pub const fn name(self) -> &'static str {
        match self {
            Self::IdUnread => "IdUnread",
            Self::Written => "Written",
            Self::WrittenFull => "WrittenFull",
            Self::Synced => "Synced",
            Self::Create => "Create",
            Self::TruncateTornTail => "TruncateTornTail",
            Self::SyncPrefix => "SyncPrefix",
            Self::AmbientJobJoined => "AmbientJobJoined",
            Self::CreatedSuspended => "CreatedSuspended",
            Self::PrivateJobAssigned => "PrivateJobAssigned",
            Self::Resumed => "Resumed",
            Self::ReaperStarted => "ReaperStarted",
            Self::PreExecPgidAndRegister => "PreExecPgidAndRegister",
            Self::Exec => "Exec",
            Self::Registered => "Registered",
        }
    }

    /// The injection modes this point supports.
    ///
    /// Kill is universal: a coordinator can die anywhere. Error-return is
    /// narrower — it exists where the design gives the funnel an error contract
    /// to return *through*. The Event points all have one (the append-error
    /// protocol, and `SyncPrefix`'s resumable refusal), and Windows'
    /// `AmbientJobJoined` has one ("failure refuses the write command").
    /// [`Self::IdUnread`] has none: the packet describes it only as a durable
    /// prefix a kill leaves, and inventing an error contract for it would be
    /// inventing a resume action nothing tables.
    pub const fn modes(self) -> &'static [InjectionMode] {
        match self {
            Self::Written
            | Self::Synced
            | Self::Create
            | Self::TruncateTornTail
            | Self::SyncPrefix
            | Self::AmbientJobJoined => InjectionMode::ALL,
            Self::WrittenFull => &[InjectionMode::ErrorReturn],
            Self::IdUnread
            | Self::CreatedSuspended
            | Self::PrivateJobAssigned
            | Self::Resumed
            | Self::ReaperStarted
            | Self::PreExecPgidAndRegister
            | Self::Exec
            | Self::Registered => &[InjectionMode::Kill],
        }
    }

    /// The host this point exists on.
    pub const fn platform(self) -> Platform {
        match self {
            Self::AmbientJobJoined
            | Self::CreatedSuspended
            | Self::PrivateJobAssigned
            | Self::Resumed => Platform::Windows,
            Self::ReaperStarted | Self::PreExecPgidAndRegister | Self::Exec | Self::Registered => {
                Platform::Unix
            }
            Self::IdUnread
            | Self::Written
            | Self::WrittenFull
            | Self::Synced
            | Self::Create
            | Self::TruncateTornTail
            | Self::SyncPrefix => Platform::Any,
        }
    }

    /// Whether this point supports `mode`.
    pub fn supports(self, mode: InjectionMode) -> bool {
        self.modes().contains(&mode)
    }
}

impl fmt::Display for SubEffectPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What `classify_object_residue` answers about one site's worktree.
///
/// Total over exactly these three for every [`ObjectSite`] and for
/// [`WorktreeSite::Add`] / [`SnapshotSite::Add`]. Totality is the property that
/// matters: a sampled residue that classifies into none of them fails ST-07,
/// because the run would then have durable state no tabled action recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectResidue {
    /// Nothing was written: the before-phase state.
    None,
    /// Objects written, their reference unpublished — the command-internal
    /// prefix no parent hook can observe.
    Internal,
    /// The object is present and referenced as the site's row says: the
    /// after-phase state.
    After,
}

impl ObjectResidue {
    /// The classifier's whole codomain.
    pub const ALL: &'static [Self] = &[Self::None, Self::Internal, Self::After];
}

/// A residue class an entry can be about.
///
/// One exists at design time. It is a separate type from [`ObjectResidue`] on
/// purpose: `ObjectResidue::None` and `ObjectResidue::After` are *outcomes of
/// the classifier*, not classes anything registers, and a registry keyed on the
/// classifier's codomain would let a slice register an entry for "nothing
/// happened" and count it as coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidueClass {
    /// `ObjectResidue::Internal`: objects written into the store before the
    /// command published their reference.
    ObjectInternal,
}

impl ResidueClass {
    /// Every registrable class.
    pub const ALL: &'static [Self] = &[Self::ObjectInternal];

    /// The classifier outcome this class is the class *of*.
    pub const fn classified_as(self) -> ObjectResidue {
        match self {
            Self::ObjectInternal => ObjectResidue::Internal,
        }
    }

    /// The label every entry about this class must carry.
    ///
    /// Constant, and constant on purpose: no residue class has, or can have,
    /// execution-observed evidence.
    pub const fn label(self) -> EvidenceLabel {
        match self {
            Self::ObjectInternal => EvidenceLabel::RecoveryProven,
        }
    }

    /// The class's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ObjectInternal => "ObjectResidue::Internal",
        }
    }
}

/// One concrete artifact a residue class's synthetic construction must build.
///
/// The list comes from `command_internal_sub_effects` and from the fault
/// matrix's per-transaction residue descriptions; which elements a given site
/// can leave differs by command, which is why the list is per site rather than
/// per class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidueElement {
    /// An object in the store that nothing references (R27).
    UnreferencedObject,
    /// One of Git's own temporary object files; Git prunes them itself.
    TemporaryObjectFile,
    /// `index.lock` in the owning worktree's git dir.
    IndexLock,
    /// `CHERRY_PICK_HEAD`.
    CherryPickHead,
    /// `MERGE_HEAD`.
    MergeHead,
    /// `MERGE_MSG`.
    MergeMsg,
    /// `ORIG_HEAD`.
    OrigHead,
    /// Sequencer state left by an interrupted cherry-pick.
    SequencerState,
    /// A worktree Git registered but never populated.
    RegisteredUnpopulatedWorktree,
}

impl ResidueElement {
    /// Every element the classifier recognises.
    pub const ALL: &'static [Self] = &[
        Self::UnreferencedObject,
        Self::TemporaryObjectFile,
        Self::IndexLock,
        Self::CherryPickHead,
        Self::MergeHead,
        Self::MergeMsg,
        Self::OrigHead,
        Self::SequencerState,
        Self::RegisteredUnpopulatedWorktree,
    ];

    /// The class an element of this kind classifies into.
    ///
    /// Every one of them is `Internal`: that is what makes the classifier's
    /// answer a class rather than a list of files.
    pub const fn classifies_as(self) -> ObjectResidue {
        match self {
            Self::UnreferencedObject
            | Self::TemporaryObjectFile
            | Self::IndexLock
            | Self::CherryPickHead
            | Self::MergeHead
            | Self::MergeMsg
            | Self::OrigHead
            | Self::SequencerState
            | Self::RegisteredUnpopulatedWorktree => ObjectResidue::Internal,
        }
    }
}

/// How an entry's evidence was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLabel {
    /// A hook ran and the harness recorded it.
    ExecutionObserved,
    /// Nothing was executed: the residue was constructed and the tabled
    /// recovery converged. Never counted as an observed execution.
    RecoveryProven,
}

/// Which durable order a fault at a site can leave observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservableOrder {
    /// The effect is durable, the adjacent append is not.
    EffectBeforeEvent,
    /// The adjacent append is durable, the effect is not.
    EventBeforeEffect,
}

// ---------------------------------------------------------------------------
// The residue and recovery vocabulary
// ---------------------------------------------------------------------------

/// What a site's *before* phase finds already durable.
///
/// The other per-site half of the residue authority, and the one a generic
/// answer got wrong. `EntryPhase::Before => rows: Vec::new()` reads as a
/// statement about effects in general — nothing has been performed, so nothing
/// is there — and it is false for every site whose primitive acts on something
/// that has to exist first. `transaction_fault_matrix[T-SCRUB]`, which is live
/// and binding, puts the boundary at "task_candidate_created appended;
/// worktree, its intent, or snapshots **not yet removed**": a fault at
/// `Worktree.Remove`'s before hook leaves the task worktree and its
/// administrative residue exactly where they were, held by R9. Under the
/// generic answer the framework refused that packet-correct entry
/// (`WrongResidueRows`) and accepted an entry claiming the worktree was
/// already gone — the inversion of what the registry exists to catch.
///
/// **Scope, and where it now stops.** A site's own artifact is not always one
/// object: eight of the seventy are the *second half of a two-step protocol
/// the packet names as a pair*, and after the first half the artifact exists
/// in its intermediate form. `transaction_fault_matrix[T-DISPATCH]` puts the
/// boundary at "worktree **intent** or worktree not yet created" and tables
/// the resume as "remove it with force and recreate it (**intent then add**)";
/// [`ResourceRow::R9`] is, in the ledger's own words, "Task worktree **plus
/// its durable synced intent**". So a kill at `Worktree.Add`'s before hook leaves
/// R9 holding that intent, and an entry saying the row holds nothing is false
/// — which is what [`Self::PrecursorDurable`] is for.
///
/// What these rows still do **not** name is the whole durable prefix of the
/// transaction the site sits in. `Event.Append`'s before phase names the line
/// it is about to append, not the log `Event.OpenLog` created;
/// `RunDir.CreatePrivateDir`'s names nothing, though the public directory and
/// its marker are durable and R21 accounts for both. That boundary is not a
/// preference. `structure` keys an entry by
/// `EffectSiteId x phase x order x injection mode` and by nothing else, and a
/// cumulative prefix is not a function of that key: `Event.Append` occurs at
/// every prefix of every transaction, `Worktree.Remove` occurs in T-SCRUB, in
/// T-ATTEMPT's resume and in T-FINALIZE's cleanup, and each of those is a
/// different prefix at the same coordinate. Naming a prefix here would need a
/// prefix axis the frozen key does not have. What *is* a function of the site
/// is its own artifact, including the intermediate state its own two-step
/// protocol leaves — because that ordering is invariant: the primitive cannot
/// add a worktree that no intent registered, and a rename cannot publish what
/// was never staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BeforeState {
    /// The artifact this site's primitive acts on does not exist yet in any
    /// form, so no row holds it: every one-step creation, and the read-only
    /// observations, which perform nothing at either phase.
    ///
    /// `structure` says it of the whole Object group in its own words —
    /// "Object sites carry entries — before: no object (hook)".
    Absent,
    /// The artifact does not exist yet, and the first half of this site's own
    /// two-step protocol has already left a durable artifact that the row
    /// [`EffectSiteId::row`] names accounts for: the intent behind an add, the
    /// staged temporary behind an atomic publication.
    ///
    /// The rows are [`Self::Present`]'s and the words are not, deliberately.
    /// The row holds something, so the entry must say so; the thing it holds
    /// is not the target intact, so the entry must not say that either.
    PrecursorDurable,
    /// The artifact this site's primitive acts on is already durable and the
    /// row [`EffectSiteId::row`] names holds it: every removal, every release,
    /// and every in-place replacement of an artifact that has to exist for the
    /// primitive to be issued at all.
    Present,
}

/// What a site's *after* phase leaves durable.
///
/// The per-site half of the residue authority, and the reason
/// [`EffectSiteId::semantics`] has no generic arm. `structure` does not give
/// every site the same after-phase: an effect that publishes something leaves
/// it referenced by the site's own row, a commit-tree leaves an object nothing
/// references, "the pruning sites' after-phase entries record the released
/// objects as R27 residue", and a removal that releases nothing leaves the row
/// that accounted for what it removed holding nothing. One `vec![self.row()]`
/// answers all five the same way and is wrong for four of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AfterEffect {
    /// The site performs no effect at all, so its after phase leaves nothing.
    NoEffect,
    /// The artifact is durable and the row [`EffectSiteId::row`] names
    /// references it.
    Referenced,
    /// The object is durable and nothing references it yet: R27.
    Unreferenced,
    /// The removal is durable, releasing the objects it referenced to R27 and
    /// taking its administrative residue with it.
    Released,
    /// The removal is durable and released no object: the row that accounted
    /// for what it removed holds nothing.
    Removed,
}

/// The concrete artifacts a fault at one `(site, phase)` leaves, in the fault
/// matrix's own words.
///
/// `structure` requires each entry to record "the expected residue
/// (refs/worktrees/pins/intents/containers/marker, owner-record, and
/// commit-record files/objects and the row referencing them/administrative
/// residue)". An entry free to write that prose itself is a second authority on
/// the same question — the argument [`EffectSiteId::expected_rows`] already
/// makes about the rows, and the rows were only half the claim. So the artifact
/// is a value, [`Self::detail`] is its words, and [`ExpectedResidue`]'s own
/// detail is checked against them rather than being read by nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidueArtifact {
    /// The before phase of a site whose primitive brings its own artifact into
    /// existence — [`BeforeState::Absent`].
    Nothing,
    /// The before phase of a site whose primitive acts on something that is
    /// already there — [`BeforeState::Present`].
    TargetIntact,
    /// The before phase of a site whose own two-step protocol has already made
    /// its first half durable — [`BeforeState::PrecursorDurable`].
    PrecursorDurable,
    /// The no-execution record: the site was never reached.
    NotReached,
    /// The after phase of a read-only observation.
    NoEffectPerformed,
    /// The artifact is present and the site's own row references it.
    Referenced,
    /// The object is present and unreferenced.
    Unreferenced,
    /// A pruning site's after phase: the objects it referenced are released.
    Released,
    /// A removal that released no object.
    Removed,
    /// The `IdUnread` point of the two commit-tree sites.
    IdNotRecorded,
    /// The `Internal` residue class at a site whose own row is R27.
    ObjectsUnreferenced,
    /// The `Internal` residue class at a site with an owning worktree.
    ObjectsAndAdministrativeResidue,
    /// The `Written` append point.
    UnsyncedBytes,
    /// The `WrittenFull` append point.
    UnsyncedLine,
    /// The `Synced` append point.
    SyncedLine,
    /// `Event.OpenLog`'s `Create` point.
    LogCreated,
    /// `Event.OpenLog`'s `TruncateTornTail` point.
    TornTailTruncated,
    /// `Event.OpenLog`'s `SyncPrefix` point.
    PrefixPossiblyNonDurable,
    /// A Windows containment point.
    NoHostProcess,
    /// A Unix containment point.
    ReaperHeldGroup,
}

impl ResidueArtifact {
    /// Every artifact, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Nothing,
        Self::TargetIntact,
        Self::PrecursorDurable,
        Self::NotReached,
        Self::NoEffectPerformed,
        Self::Referenced,
        Self::Unreferenced,
        Self::Released,
        Self::Removed,
        Self::IdNotRecorded,
        Self::ObjectsUnreferenced,
        Self::ObjectsAndAdministrativeResidue,
        Self::UnsyncedBytes,
        Self::UnsyncedLine,
        Self::SyncedLine,
        Self::LogCreated,
        Self::TornTailTruncated,
        Self::PrefixPossiblyNonDurable,
        Self::NoHostProcess,
        Self::ReaperHeldGroup,
    ];

    /// The words an entry's `expected_residue.detail` must carry.
    pub const fn detail(self) -> &'static str {
        match self {
            Self::Nothing => "nothing has been performed, so no row holds anything",
            Self::TargetIntact => {
                "nothing has been performed: the artifact this site acts on is present and \
                 unchanged, held by the row row() names"
            }
            Self::PrecursorDurable => {
                "nothing has been performed: the artifact this site creates does not exist, and \
                 the durable first half of its own two-step protocol — the intent behind an add, \
                 the staged temporary behind an atomic publication — is held by the row row() \
                 names"
            }
            Self::NotReached => {
                "the site was not reached: an exact-base fast publication creates no staging \
                 worktree, cherry-picks nothing, and takes no prepared pin"
            }
            Self::NoEffectPerformed => {
                "no effect was performed: the site is a read-only observation"
            }
            Self::Referenced => "the artifact is present and referenced by the row row() names",
            Self::Unreferenced => "the object is present and unreferenced, R27",
            Self::Released => {
                "the removal is durable; the objects it referenced are released to R27 and its \
                 administrative residue went with it"
            }
            Self::Removed => {
                "the removal is durable and released no object; the row that accounted for what \
                 it removed holds nothing"
            }
            Self::IdNotRecorded => {
                "an R27 object without a recorded id: the child has exited with the object \
                 written and the coordinator has not read the printed id"
            }
            Self::ObjectsUnreferenced => "objects present and unreferenced, R27",
            Self::ObjectsAndAdministrativeResidue => {
                "objects present and unreferenced, R27, with administrative residue in the owning \
                 worktree or a registered-but-unpopulated worktree"
            }
            Self::UnsyncedBytes => "bytes written, possibly partially, and not synced",
            Self::UnsyncedLine => "a complete newline-terminated line written and not synced",
            Self::SyncedLine => "the appended line is synced",
            Self::LogCreated => "the log file exists and its directory is fsynced",
            Self::TornTailTruncated => "the unterminated final line is truncated",
            Self::PrefixPossiblyNonDurable => "the surviving prefix is possibly non-durable",
            Self::NoHostProcess => {
                "no host process: the ambient handle closes and the kernel terminates the stub or \
                 tree"
            }
            Self::ReaperHeldGroup => {
                "a process group the reaper settles while holding its shared cleanup hold, R28"
            }
        }
    }
}

impl fmt::Display for ResidueArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail())
    }
}

/// What a resume does about this entry's durable residue.
///
/// `structure` requires "the tabled resume action" per entry, and before this
/// type the format required only that the string be non-blank — so an entry
/// could table a recovery the matrix does not give it and read as accounted
/// for. The recovery is a value for the same reason the residue is: the site
/// and the phase decide it, not the document that reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeAction {
    /// The before-phase action: resume from the prefix in which nothing was
    /// performed. `structure` gives this to `IdUnread` and to the `Internal`
    /// residue class in the same words.
    ResumeUnperformed,
    /// Nothing ran at all.
    NotExecuted,
    /// The effect is durable: the resume adopts it.
    AdoptPerformed,
    /// The removal is durable and released objects Git prunes.
    ReclaimReleased,
    /// A read-only observation: it is repeated, and there is nothing to undo.
    RepeatObservation,
    /// The append-error protocol, with the barrier at its reopen.
    AppendErrorProtocol,
    /// No live action: the next open converges the surviving prefix.
    NextOpenConverges,
    /// The write command refuses resumably, and the next open repeats the
    /// barrier.
    RefuseResumably,
    /// A Windows containment point: the ambient handle closes.
    AmbientHandleTerminates,
    /// A Unix containment point: the reaper settles the group.
    ReaperSettlesGroup,
}

impl ResumeAction {
    /// Every action, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::ResumeUnperformed,
        Self::NotExecuted,
        Self::AdoptPerformed,
        Self::ReclaimReleased,
        Self::RepeatObservation,
        Self::AppendErrorProtocol,
        Self::NextOpenConverges,
        Self::RefuseResumably,
        Self::AmbientHandleTerminates,
        Self::ReaperSettlesGroup,
    ];

    /// The words an entry's `resume_action` must carry.
    pub const fn text(self) -> &'static str {
        match self {
            Self::ResumeUnperformed => {
                "resume from the prefix in which nothing was performed: the site's before-phase \
                 action"
            }
            Self::NotExecuted => "nothing to resume: the site performed no effect",
            Self::AdoptPerformed => "resume adopting the completed effect",
            Self::ReclaimReleased => {
                "resume adopting the completed removal; the released objects are unreferenced and \
                 Git prunes them"
            }
            Self::RepeatObservation => {
                "nothing to resume: the observation performs no effect and is repeated"
            }
            Self::AppendErrorProtocol => {
                "the append-error protocol, with the stable-prefix barrier at its reopen"
            }
            Self::NextOpenConverges => {
                "no live action: the next open converges the surviving prefix through its \
                 stable-prefix barrier before any fold-derived effect"
            }
            Self::RefuseResumably => {
                "the write command refuses resumably with no fold-derived effect, and the next \
                 open repeats the barrier"
            }
            Self::AmbientHandleTerminates => {
                "nothing to resume: the ambient handle closes and the kernel terminates the stub \
                 or tree"
            }
            Self::ReaperSettlesGroup => {
                "nothing to resume: the reaper settles the group while holding its cleanup hold"
            }
        }
    }
}

impl fmt::Display for ResumeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// The residue and recovery semantics of one `(site, phase)` — the whole of
/// what a registry entry may claim about them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseSemantics {
    /// The ledger rows still holding something.
    pub rows: Vec<ResourceRow>,
    /// The concrete artifacts.
    pub artifact: ResidueArtifact,
    /// The tabled recovery.
    pub action: ResumeAction,
}

// ---------------------------------------------------------------------------
// Site enums, one per funnel group
// ---------------------------------------------------------------------------

/// The task, staging and execution-root contexts of the worktree funnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorktreeSite {
    /// The run's execution root, inside which every worktree is created (R18).
    CreateExecutionRoot,
    /// Removing the execution root at finalization, when it is empty.
    RemoveExecutionRoot,
    /// The durable synced intent for a task worktree.
    WriteIntent,
    /// `git worktree add` for a task worktree.
    Add,
    /// Read-only quiescence observation: present, HEAD at the recorded base,
    /// index unlocked, no cherry-pick/merge/sequencer state. Performs no
    /// effect; its failure routes to forced removal and a fresh add.
    Verify,
    /// Forced removal of a task worktree, releasing its index-referenced
    /// objects to R27 and taking its administrative residue with it.
    Remove,
    /// Removing a task worktree's intent.
    RemoveIntent,
    /// The durable synced intent for a `merge/<seq>` staging worktree.
    WriteStagingIntent,
    /// `git worktree add` for a staging worktree — never executed for an
    /// exact-base fast sequence.
    AddStaging,
    /// Forced removal of a staging worktree.
    RemoveStaging,
    /// Removing a staging worktree's intent.
    RemoveStagingIntent,
}

impl WorktreeSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::CreateExecutionRoot,
        Self::RemoveExecutionRoot,
        Self::WriteIntent,
        Self::Add,
        Self::Verify,
        Self::Remove,
        Self::RemoveIntent,
        Self::WriteStagingIntent,
        Self::AddStaging,
        Self::RemoveStaging,
        Self::RemoveStagingIntent,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CreateExecutionRoot => "CreateExecutionRoot",
            Self::RemoveExecutionRoot => "RemoveExecutionRoot",
            Self::WriteIntent => "WriteIntent",
            Self::Add => "Add",
            Self::Verify => "Verify",
            Self::Remove => "Remove",
            Self::RemoveIntent => "RemoveIntent",
            Self::WriteStagingIntent => "WriteStagingIntent",
            Self::AddStaging => "AddStaging",
            Self::RemoveStaging => "RemoveStaging",
            Self::RemoveStagingIntent => "RemoveStagingIntent",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::CreateExecutionRoot | Self::RemoveExecutionRoot => ResourceRow::R18,
            Self::WriteIntent | Self::Add | Self::Verify | Self::Remove | Self::RemoveIntent => {
                ResourceRow::R9
            }
            Self::WriteStagingIntent
            | Self::AddStaging
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => ResourceRow::R10,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::CreateExecutionRoot => Adjacent::Before(DurableEvent::RunStarted),
            Self::RemoveExecutionRoot => Adjacent::After(DurableEvent::RunFinished),
            Self::WriteIntent | Self::Add => Adjacent::After(DurableEvent::TaskDispatched),
            Self::Verify => Adjacent::Before(DurableEvent::AttemptStarted),
            Self::Remove | Self::RemoveIntent => {
                Adjacent::After(DurableEvent::TaskCandidateCreated)
            }
            Self::WriteStagingIntent | Self::AddStaging => {
                Adjacent::Before(DurableEvent::MergeVerificationStarted)
            }
            Self::RemoveStaging | Self::RemoveStagingIntent => {
                Adjacent::After(DurableEvent::TaskMerged)
            }
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::CreateExecutionRoot => FaultRow::TRunstart,
            Self::RemoveExecutionRoot => FaultRow::TFinalize,
            Self::WriteIntent | Self::Add => FaultRow::TDispatch,
            Self::Verify => FaultRow::TRetry,
            Self::Remove | Self::RemoveIntent => FaultRow::TScrub,
            Self::WriteStagingIntent
            | Self::AddStaging
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => FaultRow::TProposal,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::CreateExecutionRoot
            | Self::RemoveExecutionRoot
            | Self::WriteIntent
            | Self::Add
            | Self::Verify
            | Self::Remove
            | Self::RemoveIntent
            | Self::WriteStagingIntent
            | Self::AddStaging
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => SiteScope::Topology,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::Verify => true,
            Self::CreateExecutionRoot
            | Self::RemoveExecutionRoot
            | Self::WriteIntent
            | Self::Add
            | Self::Remove
            | Self::RemoveIntent
            | Self::WriteStagingIntent
            | Self::AddStaging
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::CreateExecutionRoot
            | Self::RemoveExecutionRoot
            | Self::WriteIntent
            | Self::Add
            | Self::Verify
            | Self::Remove
            | Self::RemoveIntent
            | Self::WriteStagingIntent
            | Self::AddStaging
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::Add | Self::AddStaging => &[ResidueClass::ObjectInternal],
            Self::CreateExecutionRoot
            | Self::RemoveExecutionRoot
            | Self::WriteIntent
            | Self::Verify
            | Self::Remove
            | Self::RemoveIntent
            | Self::WriteStagingIntent
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::Add | Self::AddStaging => &[ResidueElement::RegisteredUnpopulatedWorktree],
            Self::CreateExecutionRoot
            | Self::RemoveExecutionRoot
            | Self::WriteIntent
            | Self::Verify
            | Self::Remove
            | Self::RemoveIntent
            | Self::WriteStagingIntent
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => &[],
        }
    }
}

/// The gate/review snapshot contexts (R24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SnapshotSite {
    /// The durable synced intent for a snapshot worktree.
    WriteIntent,
    /// `git worktree add` for a snapshot worktree; its detached HEAD picks up
    /// the ephemeral commit and moves it out of R27.
    Add,
    /// Forced removal, releasing an ephemeral commit back to R27.
    Remove,
    /// Removing a snapshot's intent.
    RemoveIntent,
}

impl SnapshotSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::WriteIntent,
        Self::Add,
        Self::Remove,
        Self::RemoveIntent,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::WriteIntent => "WriteIntent",
            Self::Add => "Add",
            Self::Remove => "Remove",
            Self::RemoveIntent => "RemoveIntent",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::WriteIntent | Self::Add | Self::Remove | Self::RemoveIntent => ResourceRow::R24,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::WriteIntent | Self::Add => Adjacent::After(DurableEvent::AttemptStarted),
            Self::Remove | Self::RemoveIntent => Adjacent::Before(DurableEvent::AttemptFinished),
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::WriteIntent | Self::Add => FaultRow::TAttempt,
            Self::Remove | Self::RemoveIntent => FaultRow::TScrub,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::WriteIntent | Self::Add | Self::Remove | Self::RemoveIntent => {
                SiteScope::Topology
            }
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::WriteIntent | Self::Add | Self::Remove | Self::RemoveIntent => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::WriteIntent | Self::Add | Self::Remove | Self::RemoveIntent => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::Add => &[ResidueClass::ObjectInternal],
            Self::WriteIntent | Self::Remove | Self::RemoveIntent => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::Add => &[ResidueElement::RegisteredUnpopulatedWorktree],
            Self::WriteIntent | Self::Remove | Self::RemoveIntent => &[],
        }
    }
}

/// The ref-store contexts: the integration ref, the candidates ref, and the two
/// pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefSite {
    /// Creating the run's integration ref (R21).
    CreateIntegration,
    /// The compare-and-swap that publishes an integration.
    CompareAndSwapIntegration,
    /// Creating a candidate's authoritative candidates ref (R11).
    CreateCandidates,
    /// Deleting a candidates ref at Complete finalization.
    DeleteCandidatesRef,
    /// Pinning the candidate commit before `candidate_prepared` (R23).
    PinCandidatePrepared,
    /// Deleting that pin expected-old once the candidate ref exists.
    DeleteCandidatePin,
    /// Pinning the proposal as `prepared/<seq>` (R12) — never executed for an
    /// exact-base fast sequence.
    PinPrepared,
    /// Deleting a prepared pin.
    DeletePreparedPin,
}

impl RefSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::CreateIntegration,
        Self::CompareAndSwapIntegration,
        Self::CreateCandidates,
        Self::DeleteCandidatesRef,
        Self::PinCandidatePrepared,
        Self::DeleteCandidatePin,
        Self::PinPrepared,
        Self::DeletePreparedPin,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CreateIntegration => "CreateIntegration",
            Self::CompareAndSwapIntegration => "CompareAndSwapIntegration",
            Self::CreateCandidates => "CreateCandidates",
            Self::DeleteCandidatesRef => "DeleteCandidatesRef",
            Self::PinCandidatePrepared => "PinCandidatePrepared",
            Self::DeleteCandidatePin => "DeleteCandidatePin",
            Self::PinPrepared => "PinPrepared",
            Self::DeletePreparedPin => "DeletePreparedPin",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::CreateIntegration | Self::CompareAndSwapIntegration => ResourceRow::R21,
            Self::CreateCandidates | Self::DeleteCandidatesRef => ResourceRow::R11,
            Self::PinCandidatePrepared | Self::DeleteCandidatePin => ResourceRow::R23,
            Self::PinPrepared | Self::DeletePreparedPin => ResourceRow::R12,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::CreateIntegration => Adjacent::Before(DurableEvent::RunStarted),
            Self::CompareAndSwapIntegration => Adjacent::Before(DurableEvent::TaskMerged),
            Self::CreateCandidates => Adjacent::Before(DurableEvent::TaskCandidateCreated),
            Self::DeleteCandidatesRef => Adjacent::After(DurableEvent::RunFinished),
            Self::PinCandidatePrepared => Adjacent::Before(DurableEvent::CandidatePrepared),
            Self::DeleteCandidatePin => Adjacent::After(DurableEvent::TaskCandidateCreated),
            Self::PinPrepared => Adjacent::Before(DurableEvent::MergeVerificationStarted),
            Self::DeletePreparedPin => Adjacent::After(DurableEvent::TaskMerged),
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::CreateIntegration => FaultRow::TRunstart,
            Self::CompareAndSwapIntegration => FaultRow::TFast,
            Self::CreateCandidates | Self::DeleteCandidatePin => FaultRow::TCandRef,
            Self::DeleteCandidatesRef | Self::DeletePreparedPin => FaultRow::TFinalize,
            Self::PinCandidatePrepared => FaultRow::TCandObj,
            Self::PinPrepared => FaultRow::TProposal,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::CreateIntegration
            | Self::CompareAndSwapIntegration
            | Self::CreateCandidates
            | Self::DeleteCandidatesRef
            | Self::PinCandidatePrepared
            | Self::DeleteCandidatePin
            | Self::PinPrepared
            | Self::DeletePreparedPin => SiteScope::Topology,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::CreateIntegration
            | Self::CompareAndSwapIntegration
            | Self::CreateCandidates
            | Self::DeleteCandidatesRef
            | Self::PinCandidatePrepared
            | Self::DeleteCandidatePin
            | Self::PinPrepared
            | Self::DeletePreparedPin => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::CreateIntegration
            | Self::CompareAndSwapIntegration
            | Self::CreateCandidates
            | Self::DeleteCandidatesRef
            | Self::PinCandidatePrepared
            | Self::DeleteCandidatePin
            | Self::PinPrepared
            | Self::DeletePreparedPin => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::CreateIntegration
            | Self::CompareAndSwapIntegration
            | Self::CreateCandidates
            | Self::DeleteCandidatesRef
            | Self::PinCandidatePrepared
            | Self::DeleteCandidatePin
            | Self::PinPrepared
            | Self::DeletePreparedPin => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::CreateIntegration
            | Self::CompareAndSwapIntegration
            | Self::CreateCandidates
            | Self::DeleteCandidatesRef
            | Self::PinCandidatePrepared
            | Self::DeleteCandidatePin
            | Self::PinPrepared
            | Self::DeletePreparedPin => &[],
        }
    }
}

/// One site per Git-object creation context.
///
/// `row()` names the row that references the object *immediately after* the
/// effect, which is why the two commit-tree sites are R27: a commit-tree writes
/// its object and nothing points at it until a later site does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectSite {
    /// `git add -A` in the task worktree: blobs behind the worktree index.
    CandidateStage,
    /// `git write-tree`: trees behind the worktree index.
    CandidateWriteTree,
    /// The ephemeral commit for a tree-only snapshot input; unreferenced until
    /// `Snapshot::Add` makes it the snapshot HEAD.
    SnapshotCommitTree,
    /// The candidate commit; unreferenced until `Ref::PinCandidatePrepared`.
    CandidateCommitTree,
    /// `git cherry-pick` in the staging worktree of a stale candidate; never
    /// executed for a fast sequence.
    ProposalCherryPick,
    /// `git cherry-pick --no-commit` in a repair worktree.
    RepairMaterialize,
}

impl ObjectSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::CandidateStage,
        Self::CandidateWriteTree,
        Self::SnapshotCommitTree,
        Self::CandidateCommitTree,
        Self::ProposalCherryPick,
        Self::RepairMaterialize,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CandidateStage => "CandidateStage",
            Self::CandidateWriteTree => "CandidateWriteTree",
            Self::SnapshotCommitTree => "SnapshotCommitTree",
            Self::CandidateCommitTree => "CandidateCommitTree",
            Self::ProposalCherryPick => "ProposalCherryPick",
            Self::RepairMaterialize => "RepairMaterialize",
        }
    }

    /// The row that references the created object immediately after the effect.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::CandidateStage | Self::CandidateWriteTree | Self::RepairMaterialize => {
                ResourceRow::R9
            }
            Self::SnapshotCommitTree | Self::CandidateCommitTree => ResourceRow::R27,
            Self::ProposalCherryPick => ResourceRow::R10,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::CandidateStage | Self::CandidateWriteTree | Self::SnapshotCommitTree => {
                Adjacent::After(DurableEvent::AttemptStarted)
            }
            Self::CandidateCommitTree => Adjacent::Before(DurableEvent::CandidatePrepared),
            Self::ProposalCherryPick => Adjacent::Before(DurableEvent::MergeVerificationStarted),
            Self::RepairMaterialize => Adjacent::After(DurableEvent::TaskDispatched),
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::CandidateStage | Self::CandidateWriteTree | Self::SnapshotCommitTree => {
                FaultRow::TAttempt
            }
            Self::CandidateCommitTree => FaultRow::TCandObj,
            Self::ProposalCherryPick => FaultRow::TProposal,
            Self::RepairMaterialize => FaultRow::TRepairDispatch,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::CandidateStage
            | Self::CandidateWriteTree
            | Self::SnapshotCommitTree
            | Self::CandidateCommitTree
            | Self::ProposalCherryPick
            | Self::RepairMaterialize => SiteScope::Topology,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::CandidateStage
            | Self::CandidateWriteTree
            | Self::SnapshotCommitTree
            | Self::CandidateCommitTree
            | Self::ProposalCherryPick
            | Self::RepairMaterialize => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    ///
    /// Only the two commit-tree sites have one. Every other Object site's
    /// post-child prefix is command-internal: the parent has no place to stand
    /// between the object writes and the reference publication.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::SnapshotCommitTree | Self::CandidateCommitTree => &[SubEffectPoint::IdUnread],
            Self::CandidateStage
            | Self::CandidateWriteTree
            | Self::ProposalCherryPick
            | Self::RepairMaterialize => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::CandidateStage
            | Self::CandidateWriteTree
            | Self::SnapshotCommitTree
            | Self::CandidateCommitTree
            | Self::ProposalCherryPick
            | Self::RepairMaterialize => &[ResidueClass::ObjectInternal],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    ///
    /// Per command, from the fault matrix's own residue descriptions: a killed
    /// `git add` leaves an `index.lock`, a killed cherry-pick leaves sequencer
    /// state as well, and a killed `commit-tree` leaves neither because it
    /// writes one object by temp-file-and-rename and touches no index.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::CandidateStage | Self::CandidateWriteTree => &[
                ResidueElement::UnreferencedObject,
                ResidueElement::TemporaryObjectFile,
                ResidueElement::IndexLock,
            ],
            Self::SnapshotCommitTree | Self::CandidateCommitTree => &[
                ResidueElement::UnreferencedObject,
                ResidueElement::TemporaryObjectFile,
            ],
            Self::ProposalCherryPick => &[
                ResidueElement::UnreferencedObject,
                ResidueElement::TemporaryObjectFile,
                ResidueElement::IndexLock,
                ResidueElement::CherryPickHead,
                ResidueElement::MergeHead,
                ResidueElement::MergeMsg,
                ResidueElement::SequencerState,
            ],
            Self::RepairMaterialize => &[
                ResidueElement::UnreferencedObject,
                ResidueElement::TemporaryObjectFile,
                ResidueElement::IndexLock,
                ResidueElement::CherryPickHead,
            ],
        }
    }
}

/// The run-directory funnel: everything under a run's public and private
/// halves. Every site is R21.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RunDirSite {
    /// P0: the bare public run directory.
    CreatePublicDir,
    /// P1: `.creating.tmp`.
    StageMarker,
    /// P1: the atomic rename to `.creating`.
    PublishMarker,
    /// P6: removing the marker once `run_started` is durable.
    RemoveMarker,
    /// P2: the private half.
    CreatePrivateDir,
    /// P3a: `owner.json.tmp`.
    StageOwnerRecord,
    /// P3b: the atomic rename publishing the reciprocal ownership record.
    PublishOwnerRecord,
    /// P5a: `committed.json.tmp`.
    StageCommitRecord,
    /// P5b: the atomic rename publishing the private commit record.
    ///
    /// The one deletion boundary: after this site returns, or when a read-only
    /// stat after its error shows the record present, no path — creator or
    /// census — deletes the private half.
    PublishCommitRecord,
    /// P4: `plan.normalized.json`.
    WritePlan,
    /// `report.json`.
    WriteReport,
    /// A question's payload file, written before the question is announced.
    WriteQuestionPayload,
    /// Removing the private half of a husk, under the ownership proof.
    RemovePrivateHusk,
    /// Removing the public half of a husk.
    RemovePublicHusk,
}

impl RunDirSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::CreatePublicDir,
        Self::StageMarker,
        Self::PublishMarker,
        Self::RemoveMarker,
        Self::CreatePrivateDir,
        Self::StageOwnerRecord,
        Self::PublishOwnerRecord,
        Self::StageCommitRecord,
        Self::PublishCommitRecord,
        Self::WritePlan,
        Self::WriteReport,
        Self::WriteQuestionPayload,
        Self::RemovePrivateHusk,
        Self::RemovePublicHusk,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CreatePublicDir => "CreatePublicDir",
            Self::StageMarker => "StageMarker",
            Self::PublishMarker => "PublishMarker",
            Self::RemoveMarker => "RemoveMarker",
            Self::CreatePrivateDir => "CreatePrivateDir",
            Self::StageOwnerRecord => "StageOwnerRecord",
            Self::PublishOwnerRecord => "PublishOwnerRecord",
            Self::StageCommitRecord => "StageCommitRecord",
            Self::PublishCommitRecord => "PublishCommitRecord",
            Self::WritePlan => "WritePlan",
            Self::WriteReport => "WriteReport",
            Self::WriteQuestionPayload => "WriteQuestionPayload",
            Self::RemovePrivateHusk => "RemovePrivateHusk",
            Self::RemovePublicHusk => "RemovePublicHusk",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::RemoveMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload
            | Self::RemovePrivateHusk
            | Self::RemovePublicHusk => ResourceRow::R21,
        }
    }

    /// The append this site's effect is ordered against.
    ///
    /// The husk-removal pair is `None`: a census removes the halves of a run
    /// whose log never committed, so there is no append on the other side of
    /// the order.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan => Adjacent::Before(DurableEvent::RunStarted),
            Self::RemoveMarker => Adjacent::After(DurableEvent::RunStarted),
            Self::WriteReport => Adjacent::After(DurableEvent::RunFinished),
            Self::WriteQuestionPayload => Adjacent::Before(DurableEvent::QuestionRaised),
            Self::RemovePrivateHusk | Self::RemovePublicHusk => Adjacent::None,
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::RemoveMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::RemovePrivateHusk
            | Self::RemovePublicHusk => FaultRow::TRunstart,
            Self::WriteReport => FaultRow::TFinalize,
            Self::WriteQuestionPayload => FaultRow::TFailed,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::RemoveMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload
            | Self::RemovePrivateHusk
            | Self::RemovePublicHusk => SiteScope::Shared,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::RemoveMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload
            | Self::RemovePrivateHusk
            | Self::RemovePublicHusk => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::RemoveMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload
            | Self::RemovePrivateHusk
            | Self::RemovePublicHusk => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::RemoveMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload
            | Self::RemovePrivateHusk
            | Self::RemovePublicHusk => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::RemoveMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload
            | Self::RemovePrivateHusk
            | Self::RemovePublicHusk => &[],
        }
    }
}

/// The event-log funnel. Shared: legacy callers pass the Legacy-scoped sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventSite {
    /// Create the log if absent and fsync its directory; truncate an
    /// unterminated final line; sync the complete surviving prefix. Supersedes
    /// the run directory's create-log site.
    OpenLog,
    /// The read-only half of the stable-prefix barrier: reread the file, prove
    /// bytes and boundary equal to the synced prefix, checked-replay exactly
    /// those bytes. No effect.
    ProvePrefixStable,
    /// The `run_started` append: the commitment boundary.
    AppendFirst,
    /// Every later transaction append.
    Append,
    /// A lenient informational append.
    AppendInformational,
    /// A schema-1..3 caller opening its own log through this funnel.
    LegacyOpenLog,
    /// A schema-1..3 caller appending through this funnel.
    LegacyAppend,
}

impl EventSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::OpenLog,
        Self::ProvePrefixStable,
        Self::AppendFirst,
        Self::Append,
        Self::AppendInformational,
        Self::LegacyOpenLog,
        Self::LegacyAppend,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenLog => "OpenLog",
            Self::ProvePrefixStable => "ProvePrefixStable",
            Self::AppendFirst => "AppendFirst",
            Self::Append => "Append",
            Self::AppendInformational => "AppendInformational",
            Self::LegacyOpenLog => "LegacyOpenLog",
            Self::LegacyAppend => "LegacyAppend",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::OpenLog
            | Self::ProvePrefixStable
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => ResourceRow::R21,
        }
    }

    /// The append this site's effect is ordered against.
    ///
    /// Always `None`, and not because it is unknown: an append site *is* the
    /// durable event, so there is no second thing for it to be ordered against
    /// and no observable order for the registry to range over. What a fault
    /// here leaves is a torn, unsynced, or synced *prefix*, which is what the
    /// site's sub-effect points are for.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::OpenLog
            | Self::ProvePrefixStable
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => Adjacent::None,
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::OpenLog
            | Self::ProvePrefixStable
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => FaultRow::TAppend,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::OpenLog
            | Self::ProvePrefixStable
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational => SiteScope::Shared,
            Self::LegacyOpenLog | Self::LegacyAppend => SiteScope::Legacy,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::ProvePrefixStable => true,
            Self::OpenLog
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    ///
    /// The Legacy sites expose none: they are inventoried and row-mapped and
    /// carry no fault-registry requirement, so declaring points for them would
    /// manufacture a coverage obligation the design explicitly does not make.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::OpenLog => &[
                SubEffectPoint::Create,
                SubEffectPoint::TruncateTornTail,
                SubEffectPoint::SyncPrefix,
            ],
            Self::AppendFirst | Self::Append | Self::AppendInformational => &[
                SubEffectPoint::Written,
                SubEffectPoint::WrittenFull,
                SubEffectPoint::Synced,
            ],
            Self::ProvePrefixStable | Self::LegacyOpenLog | Self::LegacyAppend => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::OpenLog
            | Self::ProvePrefixStable
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::OpenLog
            | Self::ProvePrefixStable
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => &[],
        }
    }
}

/// The answer funnel: the `tactus answer` command's two writes, and the
/// coordinator's read-only ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnswerSite {
    /// `answers/<qid>.json.partial`, writer-owned staging residue.
    StageWrite,
    /// The atomic rename publishing `answers/<qid>.json`.
    PublishRename,
    /// Reading a published answer. No effect; a file for a closed or void
    /// question is inert.
    Ingest,
}

impl AnswerSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[Self::StageWrite, Self::PublishRename, Self::Ingest];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::StageWrite => "StageWrite",
            Self::PublishRename => "PublishRename",
            Self::Ingest => "Ingest",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::StageWrite | Self::PublishRename | Self::Ingest => ResourceRow::R21,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::StageWrite | Self::PublishRename | Self::Ingest => {
                Adjacent::Before(DurableEvent::QuestionAnswered)
            }
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::StageWrite | Self::PublishRename | Self::Ingest => FaultRow::TAnswer,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::StageWrite | Self::PublishRename | Self::Ingest => SiteScope::Shared,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::Ingest => true,
            Self::StageWrite | Self::PublishRename => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::StageWrite | Self::PublishRename | Self::Ingest => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::StageWrite | Self::PublishRename | Self::Ingest => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::StageWrite | Self::PublishRename | Self::Ingest => &[],
        }
    }
}

/// The lock funnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LockSite {
    /// The run-scoped `run.lock` exclusive hold.
    AcquireRun,
    /// The repository-scoped `tactus-worktree.lock` exclusive hold — the first
    /// effect of every write command, after its read-only refusals.
    AcquireWorktree,
    /// The momentary exclusive `cleanup.lock` probe (Unix).
    ProbeCleanupExclusive,
    /// Releasing a hold this process took.
    Release,
    /// Creating the `tactus-worktree.lock` file itself (R25), which spans runs
    /// and is never removed by one.
    CreateWorktreeLockFile,
    /// Observing a surviving reaper's shared cleanup hold (R28). Never owned,
    /// never reset; read-only.
    ObserveCleanupHold,
}

impl LockSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::AcquireRun,
        Self::AcquireWorktree,
        Self::ProbeCleanupExclusive,
        Self::Release,
        Self::CreateWorktreeLockFile,
        Self::ObserveCleanupHold,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AcquireRun => "AcquireRun",
            Self::AcquireWorktree => "AcquireWorktree",
            Self::ProbeCleanupExclusive => "ProbeCleanupExclusive",
            Self::Release => "Release",
            Self::CreateWorktreeLockFile => "CreateWorktreeLockFile",
            Self::ObserveCleanupHold => "ObserveCleanupHold",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::Release => ResourceRow::R17,
            Self::CreateWorktreeLockFile => ResourceRow::R25,
            Self::ObserveCleanupHold => ResourceRow::R28,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::CreateWorktreeLockFile
            | Self::ObserveCleanupHold => Adjacent::Before(DurableEvent::RunStarted),
            Self::Release => Adjacent::After(DurableEvent::RunFinished),
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::CreateWorktreeLockFile
            | Self::ObserveCleanupHold => FaultRow::TRunstart,
            Self::Release => FaultRow::TFinalize,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::Release
            | Self::CreateWorktreeLockFile
            | Self::ObserveCleanupHold => SiteScope::Shared,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::ObserveCleanupHold => true,
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::Release
            | Self::CreateWorktreeLockFile => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::Release
            | Self::CreateWorktreeLockFile
            | Self::ObserveCleanupHold => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::Release
            | Self::CreateWorktreeLockFile
            | Self::ObserveCleanupHold => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::Release
            | Self::CreateWorktreeLockFile
            | Self::ObserveCleanupHold => &[],
        }
    }
}

/// The report funnel.
///
/// One site. `report.json` is also named by [`RunDirSite::WriteReport`] in the
/// frozen inventory; both are implemented because both are named, and the two
/// are the same durable object reached through two funnels — see this module's
/// worker report for the note against the design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportSite {
    /// Writing `report.json`.
    Write,
}

impl ReportSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[Self::Write];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Write => "Write",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::Write => ResourceRow::R21,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::Write => Adjacent::After(DurableEvent::RunFinished),
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::Write => FaultRow::TFinalize,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::Write => SiteScope::Shared,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::Write => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::Write => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::Write => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::Write => &[],
        }
    }
}

/// The process funnel (R22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessSite {
    /// Spawning a host process, with the platform containment steps as its
    /// sub-effect points.
    Spawn,
    /// Killing a host process group or closing its job handle on exit,
    /// timeout, cancel, or shutdown.
    Terminate,
}

impl ProcessSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[Self::Spawn, Self::Terminate];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Spawn => "Spawn",
            Self::Terminate => "Terminate",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::Spawn | Self::Terminate => ResourceRow::R22,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::Spawn => Adjacent::After(DurableEvent::AttemptStarted),
            Self::Terminate => Adjacent::Before(DurableEvent::AttemptFinished),
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::Spawn | Self::Terminate => FaultRow::TAttempt,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::Spawn | Self::Terminate => SiteScope::Topology,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::Spawn | Self::Terminate => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    ///
    /// All eight containment steps, Windows and Unix. Which of them a given
    /// suite has to observe is decided by [`Platform::required_on`], not by
    /// omitting the other platform's points from the inventory: a Windows CI
    /// run and a Unix one have to be checkable against the same enum.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::Spawn => &[
                SubEffectPoint::AmbientJobJoined,
                SubEffectPoint::CreatedSuspended,
                SubEffectPoint::PrivateJobAssigned,
                SubEffectPoint::Resumed,
                SubEffectPoint::ReaperStarted,
                SubEffectPoint::PreExecPgidAndRegister,
                SubEffectPoint::Exec,
                SubEffectPoint::Registered,
            ],
            Self::Terminate => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::Spawn | Self::Terminate => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::Spawn | Self::Terminate => &[],
        }
    }
}

/// The container funnel (R19 for the Git view, R26 for the container itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContainerSite {
    /// The durable global intent record, named with the run id and incarnation.
    WriteIntent,
    /// Creating the container from the recorded image id, verifying the created
    /// container's image id against the record before start.
    Create,
    /// Starting it.
    Start,
    /// Mounting the disposable Git view (R19).
    MountGitView,
    /// Stopping it.
    Stop,
    /// Removing it.
    Remove,
    /// Unmounting the Git view.
    UnmountGitView,
    /// Removing the intent record.
    RemoveIntent,
}

impl ContainerSite {
    /// Every site of the group.
    pub const ALL: &'static [Self] = &[
        Self::WriteIntent,
        Self::Create,
        Self::Start,
        Self::MountGitView,
        Self::Stop,
        Self::Remove,
        Self::UnmountGitView,
        Self::RemoveIntent,
    ];

    /// The variant's name inside its group.
    pub const fn name(self) -> &'static str {
        match self {
            Self::WriteIntent => "WriteIntent",
            Self::Create => "Create",
            Self::Start => "Start",
            Self::MountGitView => "MountGitView",
            Self::Stop => "Stop",
            Self::Remove => "Remove",
            Self::UnmountGitView => "UnmountGitView",
            Self::RemoveIntent => "RemoveIntent",
        }
    }

    /// The row that accounts for what this site touches.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::MountGitView | Self::UnmountGitView => ResourceRow::R19,
            Self::WriteIntent
            | Self::Create
            | Self::Start
            | Self::Stop
            | Self::Remove
            | Self::RemoveIntent => ResourceRow::R26,
        }
    }

    /// The append this site's effect is ordered against.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::WriteIntent | Self::Create | Self::Start | Self::MountGitView => {
                Adjacent::After(DurableEvent::AttemptStarted)
            }
            Self::Stop | Self::Remove | Self::UnmountGitView | Self::RemoveIntent => {
                Adjacent::Before(DurableEvent::AttemptFinished)
            }
        }
    }

    /// The fault-matrix row a fault here lands in.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::WriteIntent
            | Self::Create
            | Self::Start
            | Self::MountGitView
            | Self::Stop
            | Self::Remove
            | Self::UnmountGitView
            | Self::RemoveIntent => FaultRow::TContainer,
        }
    }

    /// Which claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::WriteIntent
            | Self::Create
            | Self::Start
            | Self::MountGitView
            | Self::Stop
            | Self::Remove
            | Self::UnmountGitView
            | Self::RemoveIntent => SiteScope::Topology,
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::WriteIntent
            | Self::Create
            | Self::Start
            | Self::MountGitView
            | Self::Stop
            | Self::Remove
            | Self::UnmountGitView
            | Self::RemoveIntent => false,
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::WriteIntent
            | Self::Create
            | Self::Start
            | Self::MountGitView
            | Self::Stop
            | Self::Remove
            | Self::UnmountGitView
            | Self::RemoveIntent => &[],
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::WriteIntent
            | Self::Create
            | Self::Start
            | Self::MountGitView
            | Self::Stop
            | Self::Remove
            | Self::UnmountGitView
            | Self::RemoveIntent => &[],
        }
    }

    /// The residue elements a class at this site must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::WriteIntent
            | Self::Create
            | Self::Start
            | Self::MountGitView
            | Self::Stop
            | Self::Remove
            | Self::UnmountGitView
            | Self::RemoveIntent => &[],
        }
    }
}

// ---------------------------------------------------------------------------
// The per-site and per-point residue authority
// ---------------------------------------------------------------------------
//
// One table, in one place, and every arm of it is checked exhaustive by rustc
// because each `match` is over a concrete site enum and carries no wildcard.
// That is the exhaustiveness argument: a twelfth group, or a twelfth variant of
// any of the eleven, does not compile until someone says what its after phase
// leaves. The alternative the framework shipped with — one
// `After | Point => vec![self.row()]` arm over `EffectSiteId` — is a table that
// answers for sites nobody has classified, which is how
// `Worktree.Remove`'s after phase came to claim R9 for a worktree that had
// just been removed.

impl WorktreeSite {
    /// What this site's before phase finds already durable.
    ///
    /// The five removals act on something that has to be there:
    /// `transaction_fault_matrix[T-SCRUB]` puts `Remove` and `RemoveIntent` at
    /// "worktree, its intent, or snapshots not yet removed"; T-PROPOSAL's
    /// resume — "reclaim the staging worktree residue with force (intent then
    /// worktree, incl. any administrative residue)" — puts `RemoveStaging` and
    /// `RemoveStagingIntent` at a staging worktree that exists; and
    /// T-FINALIZE's "cleanup steps (worktrees, snapshots, staging, pins,
    /// candidates refs at Complete, execution root) partially applied" puts
    /// `RemoveExecutionRoot` at a root still there. The creations create —
    /// T-DISPATCH's boundary is "worktree intent or worktree not yet created"
    /// and T-FAST's is "no staging worktree, intent, cherry-pick, object, or
    /// pin exists at any point of a fast sequence" — and `Verify` performs no
    /// effect at either phase.
    ///
    /// The two *adds* are neither. Each is the second half of a pair the
    /// packet names as a pair — T-DISPATCH's resume is "recreate it (intent
    /// then add)" and T-PROPOSAL's is "reclaim the staging worktree residue
    /// with force (intent then worktree, incl. any administrative residue)" —
    /// and their rows account for the first half by name: R9 is "Task
    /// worktree plus its durable synced intent" and R10 is "Staging worktree
    /// `merge/<seq>` plus its intent". A kill at either add's before hook
    /// leaves that intent, and the row it leaves it in is this site's own.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::RemoveExecutionRoot
            | Self::Remove
            | Self::RemoveIntent
            | Self::RemoveStaging
            | Self::RemoveStagingIntent => BeforeState::Present,
            Self::Add | Self::AddStaging => BeforeState::PrecursorDurable,
            Self::CreateExecutionRoot
            | Self::WriteIntent
            | Self::Verify
            | Self::WriteStagingIntent => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// The two forced removals are pruning sites: `Remove` releases "its
    /// index-referenced objects to R27 and takes its administrative residue
    /// with it", and `RemoveStaging` does the same for the staging worktree's
    /// cherry-pick objects (`effect_phases_covered`: "worktree/staging/snapshot
    /// intents and adds and removals (forced; with the objects they referenced
    /// released to R27 and administrative residue removed)"). The intent
    /// removals and the empty execution root release nothing.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::Verify => AfterEffect::NoEffect,
            Self::CreateExecutionRoot
            | Self::WriteIntent
            | Self::Add
            | Self::WriteStagingIntent
            | Self::AddStaging => AfterEffect::Referenced,
            Self::Remove | Self::RemoveStaging => AfterEffect::Released,
            Self::RemoveExecutionRoot | Self::RemoveIntent | Self::RemoveStagingIntent => {
                AfterEffect::Removed
            }
        }
    }
}

impl SnapshotSite {
    /// What this site's before phase finds already durable.
    ///
    /// `transaction_fault_matrix[T-SCRUB]`: "worktree, its intent, or
    /// snapshots not yet removed" — both removals find their snapshot there,
    /// held by R24.
    ///
    /// `Add` is the second half of its own pair: T-ATTEMPT (d) is "snapshot
    /// intent written **and** snapshot worktree added", and R24 is "Exact
    /// gate/review snapshot worktree plus its intent".
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::Remove | Self::RemoveIntent => BeforeState::Present,
            Self::Add => BeforeState::PrecursorDurable,
            Self::WriteIntent => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// `Remove` is a pruning site: "Forced removal, releasing an ephemeral
    /// commit back to R27."
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::WriteIntent | Self::Add => AfterEffect::Referenced,
            Self::Remove => AfterEffect::Released,
            Self::RemoveIntent => AfterEffect::Removed,
        }
    }
}

impl RefSite {
    /// What this site's before phase finds already durable.
    ///
    /// The three deletions delete something that exists: T-CAND-REF's boundary
    /// leaves the candidate pin "not yet pruned", T-VERIFY's resume is "delete
    /// pin expected-old", and T-FINALIZE's cleanup steps name "pins,
    /// candidates refs at Complete".
    ///
    /// `CompareAndSwapIntegration` is the group's one in-place replacement and
    /// the one non-deletion here: T-FAST's boundary is "assert_publishable read
    /// the integration ref head H == candidate.base_sha", and a CAS is issued
    /// against that existing head, which R21 holds. The creations create, and
    /// the matrix says so of each — "no ref until P8" (T-RUNSTART), "candidates
    /// ref (R11) missing" (T-CAND-REF), "no pin exists" (T-CAND-OBJ), "no
    /// `prepared/<seq>` pin" (T-PROPOSAL).
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::CompareAndSwapIntegration
            | Self::DeleteCandidatesRef
            | Self::DeleteCandidatePin
            | Self::DeletePreparedPin => BeforeState::Present,
            Self::CreateIntegration
            | Self::CreateCandidates
            | Self::PinCandidatePrepared
            | Self::PinPrepared => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// `identity` names `Ref.Delete*` among the pruning sites, so all three
    /// deletions release what their ref referenced to R27.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::CreateIntegration
            | Self::CompareAndSwapIntegration
            | Self::CreateCandidates
            | Self::PinCandidatePrepared
            | Self::PinPrepared => AfterEffect::Referenced,
            Self::DeleteCandidatesRef | Self::DeleteCandidatePin | Self::DeletePreparedPin => {
                AfterEffect::Released
            }
        }
    }
}

impl ObjectSite {
    /// What this site's before phase finds already durable.
    ///
    /// Nothing, for the whole group, and `structure` says it in its own words:
    /// "Object sites carry entries — before: no object (hook)".
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::CandidateStage
            | Self::CandidateWriteTree
            | Self::SnapshotCommitTree
            | Self::CandidateCommitTree
            | Self::ProposalCherryPick
            | Self::RepairMaterialize => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// `structure`, exactly: "after: the object present and referenced by the
    /// row named by `row()`, or unreferenced R27 for the commit-tree sites".
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::CandidateStage
            | Self::CandidateWriteTree
            | Self::ProposalCherryPick
            | Self::RepairMaterialize => AfterEffect::Referenced,
            Self::SnapshotCommitTree | Self::CandidateCommitTree => AfterEffect::Unreferenced,
        }
    }
}

impl RunDirSite {
    /// What this site's before phase finds already durable.
    ///
    /// The three removals. `transaction_fault_matrix[T-RUNSTART]` walks its
    /// prefixes "P6 run_started durable ..., marker still present; P7 marker
    /// removed", so `RemoveMarker` finds its marker there; a husk removal is
    /// the removal of a husk that exists, and `identity` gives
    /// `RemovePrivateHusk` a proof token that "returns no token when
    /// committed.json exists" — a token about a private half that is there.
    ///
    /// Every other site of the group writes or publishes a file of its own,
    /// `WriteReport` included: T-FINALIZE regenerates the report "if missing or
    /// stale", and the primitive writes it either way rather than requiring one
    /// to be there.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::RemoveMarker | Self::RemovePrivateHusk | Self::RemovePublicHusk => {
                BeforeState::Present
            }
            // The three atomic publications, each renaming a temporary its
            // own staging site made durable: T-RUNSTART's "P1 marker staged
            // (.creating.tmp) **or** published (.creating ...)", and
            // `effect_phases_covered`'s "marker staging and atomic
            // publication", "private-half creation and atomic owner-record
            // publication", "private commit-record staging and atomic
            // publication". R21 holds the staged temporary as it holds the
            // published record — "committed.json.tmp leaves with the private
            // half".
            Self::PublishMarker | Self::PublishOwnerRecord | Self::PublishCommitRecord => {
                BeforeState::PrecursorDurable
            }
            // `CreatePrivateDir` is *not* one of them, and the difference is
            // the whole boundary of this classification: the public directory
            // and its marker are durable at P3a and R21 accounts for both, but
            // neither is an earlier state of the private directory. A before
            // phase names the site's own artifact, not the transaction's
            // prefix.
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::StageCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// Run-directory contents are files, not Git objects, so the three
    /// removals release nothing to R27; they leave R21 holding nothing of what
    /// they removed.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::CreatePublicDir
            | Self::StageMarker
            | Self::PublishMarker
            | Self::CreatePrivateDir
            | Self::StageOwnerRecord
            | Self::PublishOwnerRecord
            | Self::StageCommitRecord
            | Self::PublishCommitRecord
            | Self::WritePlan
            | Self::WriteReport
            | Self::WriteQuestionPayload => AfterEffect::Referenced,
            Self::RemoveMarker | Self::RemovePrivateHusk | Self::RemovePublicHusk => {
                AfterEffect::Removed
            }
        }
    }
}

impl EventSite {
    /// What this site's before phase finds already durable.
    ///
    /// Nothing, group-wide. Each append brings its own line into existence and
    /// requires no previous one — T-APPEND's durable shapes are all shapes of
    /// the line being appended. `OpenLog` "create\[s\] the log if absent", so its
    /// primitive does not require the log either, and `ProvePrefixStable`
    /// performs no effect at either phase.
    ///
    /// The log R21 accounts for is `OpenLog`'s own after-phase claim; a before
    /// phase that repeated it would make every append restate the open.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::OpenLog
            | Self::ProvePrefixStable
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// `ProvePrefixStable` is the read-only half of the stable-prefix barrier
    /// and performs no effect; every other site of the group leaves the log,
    /// R21.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::ProvePrefixStable => AfterEffect::NoEffect,
            Self::OpenLog
            | Self::AppendFirst
            | Self::Append
            | Self::AppendInformational
            | Self::LegacyOpenLog
            | Self::LegacyAppend => AfterEffect::Referenced,
        }
    }
}

impl AnswerSite {
    /// What this site's before phase finds already durable.
    ///
    /// Nothing: `T-ANSWER`'s boundary is "answer staged as
    /// `answers/<qid>.json.partial`, **or** published as `answers/<qid>.json`",
    /// two artifacts and one site each, and `Ingest` performs no effect.
    pub const fn before_state(self) -> BeforeState {
        match self {
            // `effect_phases_covered`: "answer staging (.partial) **and**
            // publication by the answer command". The rename publishes the
            // `.partial` the stage wrote, and R21 holds it either way.
            Self::PublishRename => BeforeState::PrecursorDurable,
            Self::StageWrite | Self::Ingest => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::StageWrite | Self::PublishRename => AfterEffect::Referenced,
            Self::Ingest => AfterEffect::NoEffect,
        }
    }
}

impl LockSite {
    /// What this site's before phase finds already durable.
    ///
    /// `Release` releases a hold that is held, and R17 is "the coordinator's
    /// own lock holds (OS lock state only)" — it accounts for that hold until
    /// the release ends it. The acquisitions and the lock-file creation create.
    /// `ObserveCleanupHold` performs no effect: the R28 hold it observes is a
    /// surviving reaper's, never this coordinator's to leave behind.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::Release => BeforeState::Present,
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::CreateWorktreeLockFile
            | Self::ObserveCleanupHold => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// A hold is process-local OS state the row accounts for while it is held;
    /// `Release` ends it and releases no object.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::AcquireRun
            | Self::AcquireWorktree
            | Self::ProbeCleanupExclusive
            | Self::CreateWorktreeLockFile => AfterEffect::Referenced,
            Self::Release => AfterEffect::Removed,
            Self::ObserveCleanupHold => AfterEffect::NoEffect,
        }
    }
}

impl ReportSite {
    /// What this site's before phase finds already durable.
    ///
    /// Nothing: the write produces the report it writes.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::Write => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::Write => AfterEffect::Referenced,
        }
    }
}

impl ProcessSite {
    /// What this site's before phase finds already durable.
    ///
    /// `Terminate` terminates a process that is running, and R22 — "host
    /// process handle / private job object / ambient job membership" —
    /// accounts for it until it ends. `Spawn` creates one.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::Terminate => BeforeState::Present,
            Self::Spawn => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::Spawn => AfterEffect::Referenced,
            Self::Terminate => AfterEffect::Removed,
        }
    }
}

impl ContainerSite {
    /// What this site's before phase finds already durable.
    ///
    /// `transaction_fault_matrix[T-CONTAINER]` walks the boundary in order:
    /// "global container intent written (name incl. incarnation; record incl.
    /// runner_policy_sha256); container created from the recorded image id and
    /// verified; docker start issued; Git view mounted; the invocation running
    /// or completed; coordinator dies at any of these points". So `Start`,
    /// `Stop` and `Remove` are each issued against a container that exists —
    /// R26 accounts for "the container, its labels, and its global intent" —
    /// `RemoveIntent` against the written intent, and `UnmountGitView` against
    /// the mounted view, R19. `Create` creates the container; `WriteIntent` and
    /// `MountGitView` each bring their own artifact into existence.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::Start | Self::Stop | Self::Remove | Self::UnmountGitView | Self::RemoveIntent => {
                BeforeState::Present
            }
            // `effect_phases_covered`: "container intent write (name incl.
            // incarnation; record incl. runner digest), container creation
            // from the recorded image id with image-id verification", and R26
            // is "Container invocation: the container, its labels, and its
            // **global intent**".
            Self::Create => BeforeState::PrecursorDurable,
            Self::WriteIntent | Self::MountGitView => BeforeState::Absent,
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// A stopped container is still a container: `Stop` leaves the row holding
    /// it, and only `Remove` ends it.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::WriteIntent | Self::Create | Self::Start | Self::MountGitView | Self::Stop => {
                AfterEffect::Referenced
            }
            Self::Remove | Self::UnmountGitView | Self::RemoveIntent => AfterEffect::Removed,
        }
    }
}

impl SubEffectPoint {
    /// The rows a fault at this point leaves holding something, given the
    /// site's own row.
    ///
    /// A list, and not one row, because two of the four answers the packet
    /// gives are not the site's row at all and one of them is *no* row. The
    /// predecessor of this function returned `site_row` for every point but
    /// `IdUnread`, so `Process.Spawn`'s eight containment points all claimed
    /// R22 — while their own `residue_artifact` said `NoHostProcess` on
    /// Windows and `ReaperHeldGroup` ("... its shared cleanup hold, R28") on
    /// Unix. The registry read as accounted for while its two halves
    /// contradicted each other at every containment coordinate.
    ///
    /// The four answers, each in `containment_sub_effects`' or `structure`'s
    /// own words:
    ///
    /// * `IdUnread` — "R27 object without a recorded id". Stated here rather
    ///   than inherited from `row()`, which happens to be R27 for both
    ///   commit-tree sites today — a coincidence that let a mutation move
    ///   `SnapshotCommitTree` to R24 without a test noticing.
    /// * the append and open points — the log the site's own row accounts for.
    /// * the Windows containment points — "a coordinator kill after any of
    ///   these leaves **no host process** (the ambient handle closes and the
    ///   kernel terminates the stub or tree; a private-job handle close does
    ///   the same)". No row holds anything: R22 is the row for a host process
    ///   handle, and there is none.
    /// * the Unix containment points — "a coordinator kill after any of these
    ///   leaves a group the reaper settles **while holding R28**". R28 is
    ///   "a surviving Unix reaper's shared `cleanup.lock` hold"; R22 is not
    ///   left holding a handle the dying coordinator owned.
    ///
    /// The platform is not a new axis of the authority: it is already a
    /// function of the point ([`Self::platform`]), and this match is over the
    /// same fifteen variants with no wildcard, so it stays total by
    /// exhaustiveness rather than by a default.
    pub fn residue_rows(self, site_row: ResourceRow) -> Vec<ResourceRow> {
        match self {
            Self::IdUnread => vec![ResourceRow::R27],
            Self::Written
            | Self::WrittenFull
            | Self::Synced
            | Self::Create
            | Self::TruncateTornTail
            | Self::SyncPrefix => vec![site_row],
            Self::AmbientJobJoined
            | Self::CreatedSuspended
            | Self::PrivateJobAssigned
            | Self::Resumed => Vec::new(),
            Self::ReaperStarted | Self::PreExecPgidAndRegister | Self::Exec | Self::Registered => {
                vec![ResourceRow::R28]
            }
        }
    }

    /// The artifacts a fault at this point leaves.
    pub const fn residue_artifact(self) -> ResidueArtifact {
        match self {
            Self::IdUnread => ResidueArtifact::IdNotRecorded,
            Self::Written => ResidueArtifact::UnsyncedBytes,
            Self::WrittenFull => ResidueArtifact::UnsyncedLine,
            Self::Synced => ResidueArtifact::SyncedLine,
            Self::Create => ResidueArtifact::LogCreated,
            Self::TruncateTornTail => ResidueArtifact::TornTailTruncated,
            Self::SyncPrefix => ResidueArtifact::PrefixPossiblyNonDurable,
            Self::AmbientJobJoined
            | Self::CreatedSuspended
            | Self::PrivateJobAssigned
            | Self::Resumed => ResidueArtifact::NoHostProcess,
            Self::ReaperStarted | Self::PreExecPgidAndRegister | Self::Exec | Self::Registered => {
                ResidueArtifact::ReaperHeldGroup
            }
        }
    }

    /// The tabled recovery for a fault at this point in this mode.
    ///
    /// The mode is part of the coordinate, not a decoration on it: an `Err`
    /// from an append point drives the append-error protocol, and a kill at the
    /// same point drives nothing live at all — "a fully written but unsynced
    /// line converges to whichever tabled prefix survives the next open". A
    /// table that answered per point and ignored the mode would give a kill the
    /// live protocol only an error contract has.
    ///
    /// Total over every `(point, mode)` pair, including the pairs
    /// [`Self::modes`] does not admit: the format refuses those separately
    /// (`RegistryError::NoSuchPoint`), and a partial table here would be a
    /// second place for an unsupported mode to be decided.
    pub const fn resume_action(self, mode: InjectionMode) -> ResumeAction {
        match self {
            // "resume action = the before-phase action"
            Self::IdUnread => ResumeAction::ResumeUnperformed,
            Self::Written | Self::WrittenFull | Self::Synced => match mode {
                InjectionMode::Kill => ResumeAction::NextOpenConverges,
                InjectionMode::ErrorReturn => ResumeAction::AppendErrorProtocol,
            },
            // A kill leaves the created log or the truncated tail for the next
            // open; an Err from either fails the open itself.
            Self::Create | Self::TruncateTornTail => match mode {
                InjectionMode::Kill => ResumeAction::NextOpenConverges,
                InjectionMode::ErrorReturn => ResumeAction::RefuseResumably,
            },
            // "a kill before it or an Err from it ... the command refuses
            // resumably, and the next open repeats the barrier" — one action
            // for both modes, and the packet says so of both.
            Self::SyncPrefix => ResumeAction::RefuseResumably,
            // "Spawn.AmbientJobJoined (once per process at startup; failure
            // refuses the write command)".
            Self::AmbientJobJoined => match mode {
                InjectionMode::Kill => ResumeAction::AmbientHandleTerminates,
                InjectionMode::ErrorReturn => ResumeAction::RefuseResumably,
            },
            Self::CreatedSuspended | Self::PrivateJobAssigned | Self::Resumed => {
                ResumeAction::AmbientHandleTerminates
            }
            Self::ReaperStarted | Self::PreExecPgidAndRegister | Self::Exec | Self::Registered => {
                ResumeAction::ReaperSettlesGroup
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EffectSiteId
// ---------------------------------------------------------------------------

/// `(funnel group, site variant)` — the inventory unit.
///
/// Serialized as the dotted name (`"RunDir.PublishCommitRecord"`), and
/// deserialized only into a name a group enum actually declares. That is what
/// makes `fault_injection_registry.completeness_rule`'s "entries for sites
/// absent from the enums are refused" true of the wire format and not only of
/// the Rust API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum EffectSiteId {
    Worktree(WorktreeSite),
    Snapshot(SnapshotSite),
    Ref(RefSite),
    Object(ObjectSite),
    RunDir(RunDirSite),
    Event(EventSite),
    Answer(AnswerSite),
    Lock(LockSite),
    Report(ReportSite),
    Process(ProcessSite),
    Container(ContainerSite),
}

/// A site name that no group enum declares.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "`{name}` is not a site any funnel group declares; a fault-injection entry names a site the \
     enums define, or it names nothing at all"
)]
pub struct UnknownSite {
    /// The name as it was written.
    pub name: String,
}

impl EffectSiteId {
    /// Every site of every group, group by group.
    ///
    /// Derived from the groups' `ALL` slices rather than written out again:
    /// two hand-maintained lists of seventy sites would disagree eventually,
    /// and the one that disagreed silently would be this one.
    pub fn all() -> Vec<Self> {
        let mut sites = Vec::new();
        sites.extend(WorktreeSite::ALL.iter().copied().map(Self::Worktree));
        sites.extend(SnapshotSite::ALL.iter().copied().map(Self::Snapshot));
        sites.extend(RefSite::ALL.iter().copied().map(Self::Ref));
        sites.extend(ObjectSite::ALL.iter().copied().map(Self::Object));
        sites.extend(RunDirSite::ALL.iter().copied().map(Self::RunDir));
        sites.extend(EventSite::ALL.iter().copied().map(Self::Event));
        sites.extend(AnswerSite::ALL.iter().copied().map(Self::Answer));
        sites.extend(LockSite::ALL.iter().copied().map(Self::Lock));
        sites.extend(ReportSite::ALL.iter().copied().map(Self::Report));
        sites.extend(ProcessSite::ALL.iter().copied().map(Self::Process));
        sites.extend(ContainerSite::ALL.iter().copied().map(Self::Container));
        sites
    }

    /// Every site whose scope carries the ST-07 requirement.
    pub fn claimed() -> Vec<Self> {
        Self::all()
            .into_iter()
            .filter(|site| site.scope().is_claimed())
            .collect()
    }

    /// Which funnel group declares this site.
    pub const fn group(self) -> FunnelGroup {
        match self {
            Self::Worktree(_) => FunnelGroup::Worktree,
            Self::Snapshot(_) => FunnelGroup::Snapshot,
            Self::Ref(_) => FunnelGroup::Ref,
            Self::Object(_) => FunnelGroup::Object,
            Self::RunDir(_) => FunnelGroup::RunDir,
            Self::Event(_) => FunnelGroup::Event,
            Self::Answer(_) => FunnelGroup::Answer,
            Self::Lock(_) => FunnelGroup::Lock,
            Self::Report(_) => FunnelGroup::Report,
            Self::Process(_) => FunnelGroup::Process,
            Self::Container(_) => FunnelGroup::Container,
        }
    }

    /// The variant's name inside its group.
    pub const fn variant(self) -> &'static str {
        match self {
            Self::Worktree(site) => site.name(),
            Self::Snapshot(site) => site.name(),
            Self::Ref(site) => site.name(),
            Self::Object(site) => site.name(),
            Self::RunDir(site) => site.name(),
            Self::Event(site) => site.name(),
            Self::Answer(site) => site.name(),
            Self::Lock(site) => site.name(),
            Self::Report(site) => site.name(),
            Self::Process(site) => site.name(),
            Self::Container(site) => site.name(),
        }
    }

    /// Exactly one resource row.
    pub const fn row(self) -> ResourceRow {
        match self {
            Self::Worktree(site) => site.row(),
            Self::Snapshot(site) => site.row(),
            Self::Ref(site) => site.row(),
            Self::Object(site) => site.row(),
            Self::RunDir(site) => site.row(),
            Self::Event(site) => site.row(),
            Self::Answer(site) => site.row(),
            Self::Lock(site) => site.row(),
            Self::Report(site) => site.row(),
            Self::Process(site) => site.row(),
            Self::Container(site) => site.row(),
        }
    }

    /// The adjacent durable append.
    pub const fn adjacent(self) -> Adjacent {
        match self {
            Self::Worktree(site) => site.adjacent(),
            Self::Snapshot(site) => site.adjacent(),
            Self::Ref(site) => site.adjacent(),
            Self::Object(site) => site.adjacent(),
            Self::RunDir(site) => site.adjacent(),
            Self::Event(site) => site.adjacent(),
            Self::Answer(site) => site.adjacent(),
            Self::Lock(site) => site.adjacent(),
            Self::Report(site) => site.adjacent(),
            Self::Process(site) => site.adjacent(),
            Self::Container(site) => site.adjacent(),
        }
    }

    /// The fault-matrix row.
    pub const fn fault_row(self) -> FaultRow {
        match self {
            Self::Worktree(site) => site.fault_row(),
            Self::Snapshot(site) => site.fault_row(),
            Self::Ref(site) => site.fault_row(),
            Self::Object(site) => site.fault_row(),
            Self::RunDir(site) => site.fault_row(),
            Self::Event(site) => site.fault_row(),
            Self::Answer(site) => site.fault_row(),
            Self::Lock(site) => site.fault_row(),
            Self::Report(site) => site.fault_row(),
            Self::Process(site) => site.fault_row(),
            Self::Container(site) => site.fault_row(),
        }
    }

    /// The claim this site is inside.
    pub const fn scope(self) -> SiteScope {
        match self {
            Self::Worktree(site) => site.scope(),
            Self::Snapshot(site) => site.scope(),
            Self::Ref(site) => site.scope(),
            Self::Object(site) => site.scope(),
            Self::RunDir(site) => site.scope(),
            Self::Event(site) => site.scope(),
            Self::Answer(site) => site.scope(),
            Self::Lock(site) => site.scope(),
            Self::Report(site) => site.scope(),
            Self::Process(site) => site.scope(),
            Self::Container(site) => site.scope(),
        }
    }

    /// Whether the site performs no effect at all.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::Worktree(site) => site.is_read_only(),
            Self::Snapshot(site) => site.is_read_only(),
            Self::Ref(site) => site.is_read_only(),
            Self::Object(site) => site.is_read_only(),
            Self::RunDir(site) => site.is_read_only(),
            Self::Event(site) => site.is_read_only(),
            Self::Answer(site) => site.is_read_only(),
            Self::Lock(site) => site.is_read_only(),
            Self::Report(site) => site.is_read_only(),
            Self::Process(site) => site.is_read_only(),
            Self::Container(site) => site.is_read_only(),
        }
    }

    /// The parent-side sub-effect points this site exposes.
    pub const fn sub_effects(self) -> &'static [SubEffectPoint] {
        match self {
            Self::Worktree(site) => site.sub_effects(),
            Self::Snapshot(site) => site.sub_effects(),
            Self::Ref(site) => site.sub_effects(),
            Self::Object(site) => site.sub_effects(),
            Self::RunDir(site) => site.sub_effects(),
            Self::Event(site) => site.sub_effects(),
            Self::Answer(site) => site.sub_effects(),
            Self::Lock(site) => site.sub_effects(),
            Self::Report(site) => site.sub_effects(),
            Self::Process(site) => site.sub_effects(),
            Self::Container(site) => site.sub_effects(),
        }
    }

    /// The command-internal residue classes registered for this site.
    pub const fn residue_classes(self) -> &'static [ResidueClass] {
        match self {
            Self::Worktree(site) => site.residue_classes(),
            Self::Snapshot(site) => site.residue_classes(),
            Self::Ref(site) => site.residue_classes(),
            Self::Object(site) => site.residue_classes(),
            Self::RunDir(site) => site.residue_classes(),
            Self::Event(site) => site.residue_classes(),
            Self::Answer(site) => site.residue_classes(),
            Self::Lock(site) => site.residue_classes(),
            Self::Report(site) => site.residue_classes(),
            Self::Process(site) => site.residue_classes(),
            Self::Container(site) => site.residue_classes(),
        }
    }

    /// The residue elements this site's class must construct synthetically.
    pub const fn residue_elements(self) -> &'static [ResidueElement] {
        match self {
            Self::Worktree(site) => site.residue_elements(),
            Self::Snapshot(site) => site.residue_elements(),
            Self::Ref(site) => site.residue_elements(),
            Self::Object(site) => site.residue_elements(),
            Self::RunDir(site) => site.residue_elements(),
            Self::Event(site) => site.residue_elements(),
            Self::Answer(site) => site.residue_elements(),
            Self::Lock(site) => site.residue_elements(),
            Self::Report(site) => site.residue_elements(),
            Self::Process(site) => site.residue_elements(),
            Self::Container(site) => site.residue_elements(),
        }
    }

    /// The module the site's funnel lives in.
    pub const fn module(self) -> &'static str {
        self.group().module()
    }

    /// The durable orders a fault here can leave observable.
    ///
    /// One order, not two, wherever the design fixes which of the effect and
    /// the append is durable first — which it does everywhere it names an
    /// adjacency. A site with no adjacency has no order at all, and its entry
    /// carries `None` rather than an arbitrary one.
    pub const fn observable_orders(self) -> &'static [ObservableOrder] {
        match self.adjacent() {
            Adjacent::Before(_) => &[ObservableOrder::EffectBeforeEvent],
            Adjacent::After(_) => &[ObservableOrder::EventBeforeEffect],
            Adjacent::None => &[],
        }
    }

    /// The dotted name.
    pub fn name(self) -> String {
        format!("{}.{}", self.group().name(), self.variant())
    }

    /// The site a dotted name refers to, or an error naming what was written.
    pub fn from_name(name: &str) -> Result<Self, UnknownSite> {
        Self::all()
            .into_iter()
            .find(|site| site.name() == name)
            .ok_or_else(|| UnknownSite {
                name: name.to_owned(),
            })
    }

    /// Whether this site exposes `point` in `mode`.
    pub fn exposes(self, point: SubEffectPoint, mode: InjectionMode) -> bool {
        self.sub_effects().contains(&point) && point.supports(mode)
    }

    /// What this site's before phase finds already durable.
    ///
    /// Delegated to the group enums for the same reason [`Self::after_effect`]
    /// is: their matches are exhaustive over their own variants and carry no
    /// wildcard, so a site added to a group has to be classified rather than
    /// inheriting whatever a default said.
    ///
    /// Declared per group rather than derived from [`Self::after_effect`], and
    /// the two are close enough that the temptation is real. A derivation would
    /// make one table the sole authority for both phases: a mutation to
    /// `after_effect` would move the before phase with it and stay invisible to
    /// every test that checks the two against each other. That is the shape of
    /// the defect this function exists to repair, one level up.
    pub const fn before_state(self) -> BeforeState {
        match self {
            Self::Worktree(site) => site.before_state(),
            Self::Snapshot(site) => site.before_state(),
            Self::Ref(site) => site.before_state(),
            Self::Object(site) => site.before_state(),
            Self::RunDir(site) => site.before_state(),
            Self::Event(site) => site.before_state(),
            Self::Answer(site) => site.before_state(),
            Self::Lock(site) => site.before_state(),
            Self::Report(site) => site.before_state(),
            Self::Process(site) => site.before_state(),
            Self::Container(site) => site.before_state(),
        }
    }

    /// What this site's after phase leaves durable.
    ///
    /// Delegated to the group enums, whose `after_effect` matches are
    /// exhaustive over their own variants and carry no wildcard, so the
    /// classification cannot silently acquire a default.
    pub const fn after_effect(self) -> AfterEffect {
        match self {
            Self::Worktree(site) => site.after_effect(),
            Self::Snapshot(site) => site.after_effect(),
            Self::Ref(site) => site.after_effect(),
            Self::Object(site) => site.after_effect(),
            Self::RunDir(site) => site.after_effect(),
            Self::Event(site) => site.after_effect(),
            Self::Answer(site) => site.after_effect(),
            Self::Lock(site) => site.after_effect(),
            Self::Report(site) => site.after_effect(),
            Self::Process(site) => site.after_effect(),
            Self::Container(site) => site.after_effect(),
        }
    }

    /// The whole of what a fault at `phase` of this site leaves durable and
    /// what a resume does about it — `fault_injection_registry.structure`'s
    /// "expected residue ... resume action", as values.
    ///
    /// The authority, not the entry: an entry that named its own rows, its own
    /// artifacts and its own recovery would be a second authority on three
    /// questions and could name anything for all three. The rows have been
    /// derived here since the format was written; the artifacts and the
    /// recovery were the two the format asked only to be non-empty, which is
    /// why an entry could carry a unique false claim in either and pass.
    ///
    /// Phase by phase:
    ///
    /// * *before* — [`Self::before_state`], per site. Nothing has been
    ///   performed, so the rows are whatever the site's primitive was about to
    ///   act on and has not yet, in three answers: nothing at all for a
    ///   one-step creation ("Object sites carry entries — before: no object");
    ///   the row `row()` names for a removal or an in-place replacement, whose
    ///   target has to be there for the primitive to be issued
    ///   (`transaction_fault_matrix[T-SCRUB]`: "worktree, its intent, or
    ///   snapshots **not yet removed**"); and *the same row with different
    ///   words* for the second half of a two-step protocol, where what the row
    ///   holds is the intent or the staged temporary rather than the target
    ///   (T-DISPATCH: "worktree **intent** or worktree not yet created"). Its
    ///   recovery is the before-phase action by definition — uniformly, for
    ///   all three classifications — and it is the action `structure` binds
    ///   `IdUnread` and `Internal` to.
    /// * *after* — [`Self::after_effect`], per site. A publication leaves its
    ///   artifact referenced by [`Self::row`]; a commit-tree leaves an
    ///   unreferenced object; "the pruning sites' after-phase entries record
    ///   the released objects as R27 residue"; a removal that releases nothing
    ///   leaves nothing; and a read-only observation performs no effect at all.
    /// * *a sub-effect point* — [`SubEffectPoint::residue_rows`],
    ///   [`SubEffectPoint::residue_artifact`] and
    ///   [`SubEffectPoint::resume_action`], the last of which reads the mode
    ///   because the mode is half the coordinate. The rows are the point's, not
    ///   the site's: a Windows containment kill leaves no host process and so
    ///   no row, and a Unix one leaves the reaper's R28 hold rather than the
    ///   R22 handle the coordinator no longer has.
    /// * *a residue class* — "objects present and unreferenced, R27, with
    ///   administrative residue in the owning worktree", so R27 and the row
    ///   that holds the administrative residue. The list never repeats a row,
    ///   so a site whose own row is R27 lists it once and has no separate
    ///   administrative row to name. "resume action equal to the before-phase
    ///   action".
    /// * *no-execution* — nothing ran.
    pub fn semantics(self, phase: EntryPhase) -> PhaseSemantics {
        match phase {
            // The recovery is `ResumeUnperformed` for all three
            // classifications and
            // deliberately so: `resumes_as_before` binds `IdUnread` and the
            // `Internal` residue class to *this* action, and a before phase
            // whose action varied by site would make that binding a different
            // claim at every site it holds at.
            EntryPhase::Before => match self.before_state() {
                BeforeState::Absent => PhaseSemantics {
                    rows: Vec::new(),
                    artifact: ResidueArtifact::Nothing,
                    action: ResumeAction::ResumeUnperformed,
                },
                BeforeState::PrecursorDurable => PhaseSemantics {
                    rows: vec![self.row()],
                    artifact: ResidueArtifact::PrecursorDurable,
                    action: ResumeAction::ResumeUnperformed,
                },
                BeforeState::Present => PhaseSemantics {
                    rows: vec![self.row()],
                    artifact: ResidueArtifact::TargetIntact,
                    action: ResumeAction::ResumeUnperformed,
                },
            },
            EntryPhase::NoExecution => PhaseSemantics {
                rows: Vec::new(),
                artifact: ResidueArtifact::NotReached,
                action: ResumeAction::NotExecuted,
            },
            EntryPhase::After => match self.after_effect() {
                AfterEffect::NoEffect => PhaseSemantics {
                    rows: Vec::new(),
                    artifact: ResidueArtifact::NoEffectPerformed,
                    action: ResumeAction::RepeatObservation,
                },
                AfterEffect::Referenced => PhaseSemantics {
                    rows: vec![self.row()],
                    artifact: ResidueArtifact::Referenced,
                    action: ResumeAction::AdoptPerformed,
                },
                AfterEffect::Unreferenced => PhaseSemantics {
                    rows: vec![ResourceRow::R27],
                    artifact: ResidueArtifact::Unreferenced,
                    action: ResumeAction::AdoptPerformed,
                },
                AfterEffect::Released => PhaseSemantics {
                    rows: vec![ResourceRow::R27],
                    artifact: ResidueArtifact::Released,
                    action: ResumeAction::ReclaimReleased,
                },
                AfterEffect::Removed => PhaseSemantics {
                    rows: Vec::new(),
                    artifact: ResidueArtifact::Removed,
                    action: ResumeAction::AdoptPerformed,
                },
            },
            EntryPhase::Point { point, mode } => PhaseSemantics {
                rows: point.residue_rows(self.row()),
                artifact: point.residue_artifact(),
                action: point.resume_action(mode),
            },
            EntryPhase::Residue { .. } => {
                let rows = if self.row() == ResourceRow::R27 {
                    vec![ResourceRow::R27]
                } else {
                    vec![ResourceRow::R27, self.row()]
                };
                PhaseSemantics {
                    artifact: if rows.len() == 1 {
                        ResidueArtifact::ObjectsUnreferenced
                    } else {
                        ResidueArtifact::ObjectsAndAdministrativeResidue
                    },
                    rows,
                    action: ResumeAction::ResumeUnperformed,
                }
            }
        }
    }

    /// The ledger rows a fault at `phase` of this site leaves holding
    /// something — [`Self::semantics`]'s rows.
    pub fn expected_rows(self, phase: EntryPhase) -> Vec<ResourceRow> {
        self.semantics(phase).rows
    }

    /// Whether this site registers `class`.
    pub fn registers(self, class: ResidueClass) -> bool {
        self.residue_classes().contains(&class)
    }

    /// Whether a fast integration sequence skips this site entirely.
    ///
    /// Exactly the three the design names: an exact-base fast publication
    /// creates no staging worktree, cherry-picks nothing, and takes no prepared
    /// pin. They are the only sites a `NoExecution` entry may be written for.
    ///
    /// Being one of them exempts a site from nothing. All three are
    /// Topology-scoped and all three execute on the stale-candidate path, so
    /// `completeness_rule` requires their hook phases and points observed like
    /// any other site's; the no-execution entry is a second, trace-scoped
    /// claim laid on top of that one. See [`check_bijection`].
    pub const fn skipped_on_fast_path(self) -> bool {
        matches!(
            self,
            Self::Worktree(WorktreeSite::AddStaging)
                | Self::Object(ObjectSite::ProposalCherryPick)
                | Self::Ref(RefSite::PinPrepared)
        )
    }
}

// ---------------------------------------------------------------------------
// The compile-time contract
// ---------------------------------------------------------------------------
//
// `effect_site_inventory.identity`: "every variant carries, through
// compile-time exhaustive const fns, its ResourceKind row (row(): ...), its
// adjacent durable event ..., its fault-matrix row id, and its scope ...; each
// enum exposes a const ALL slice".
//
// Every one of those functions was declared `const fn` and then called only
// from ordinary code — unit tests, `effect_sites()`, the registry — so the
// whole compile-time half of the contract was asserted in prose and checked at
// run time. Demote `pub const fn row` to `pub fn row` and the crate, its tests
// and its generated inventory all still build; the frozen API is broken and
// nothing says so. A compile-time contract is stated where the compiler
// enforces it, which is here: none of this module builds unless the four
// functions are callable in a const context over values taken from the groups'
// const `ALL` slices.

/// Walk every group's `ALL` slice at compile time and put every site of it
/// through the four `identity` functions and the residue authority.
///
/// A `while` over the slice rather than a list of variants, so the walk covers
/// whatever `ALL` holds and cannot fall behind a group that grows one.
macro_rules! const_identity_walk {
    ($($group:ident => $wrap:ident),+ $(,)?) => {
        const _: () = {
            $(
                let mut index = 0;
                while index < $group::ALL.len() {
                    let site = EffectSiteId::$wrap($group::ALL[index]);
                    let _ = site.row();
                    let _ = site.adjacent();
                    let _ = site.fault_row();
                    let _ = site.scope();
                    let _ = site.before_state();
                    let _ = site.after_effect();
                    index += 1;
                }
            )+
        };
    };
}

const_identity_walk! {
    WorktreeSite => Worktree,
    SnapshotSite => Snapshot,
    RefSite => Ref,
    ObjectSite => Object,
    RunDirSite => RunDir,
    EventSite => Event,
    AnswerSite => Answer,
    LockSite => Lock,
    ReportSite => Report,
    ProcessSite => Process,
    ContainerSite => Container,
}

/// How many sites the eleven groups declare, summed from their `ALL` slices at
/// compile time.
///
/// `EffectSiteId::all()` is a `Vec` and cannot be one; this is the const half
/// of the same count, and `the_generated_inventory_describes_every_site_and_invents_none`
/// asserts the two agree.
pub const INVENTORY_SIZE: usize = WorktreeSite::ALL.len()
    + SnapshotSite::ALL.len()
    + RefSite::ALL.len()
    + ObjectSite::ALL.len()
    + RunDirSite::ALL.len()
    + EventSite::ALL.len()
    + AnswerSite::ALL.len()
    + LockSite::ALL.len()
    + ReportSite::ALL.len()
    + ProcessSite::ALL.len()
    + ContainerSite::ALL.len();

const _: () = assert!(INVENTORY_SIZE == 70, "the inventory this slice ships");

/// One site's row, resolved at compile time — the downstream `const`
/// declaration `identity` promises a caller of [`EffectSiteId::row`] can write.
///
/// The commit-tree sites are the ones worth stating: `row()` names the row that
/// references the created object *immediately after* the effect, and nothing
/// references a commit-tree's object until a later site does.
pub const CANDIDATE_COMMIT_TREE_ROW: ResourceRow =
    EffectSiteId::Object(ObjectSite::CandidateCommitTree).row();

// And the values, in a const context, so the walk above is not a compile-time
// call over an answer nothing pins. The two commit-tree sites are R27 because
// nothing references what a commit-tree writes; a forced worktree removal is
// R9 because R9 is the row the worktree it removes occupies.
const _: () = {
    assert!(matches!(
        EffectSiteId::Object(ObjectSite::SnapshotCommitTree).row(),
        ResourceRow::R27
    ));
    assert!(matches!(CANDIDATE_COMMIT_TREE_ROW, ResourceRow::R27));
    assert!(matches!(
        EffectSiteId::Worktree(WorktreeSite::Remove).row(),
        ResourceRow::R9
    ));
    assert!(matches!(
        EffectSiteId::Event(EventSite::AppendFirst).row(),
        ResourceRow::R21
    ));
    assert!(matches!(
        EffectSiteId::Event(EventSite::AppendFirst).adjacent(),
        Adjacent::None
    ));
    assert!(matches!(
        EffectSiteId::Object(ObjectSite::CandidateCommitTree).fault_row(),
        FaultRow::TCandObj
    ));
    assert!(matches!(
        EffectSiteId::Event(EventSite::LegacyAppend).scope(),
        SiteScope::Legacy
    ));
    assert!(matches!(
        EffectSiteId::Worktree(WorktreeSite::Remove).after_effect(),
        AfterEffect::Released
    ));
    assert!(matches!(
        EffectSiteId::Worktree(WorktreeSite::Verify).after_effect(),
        AfterEffect::NoEffect
    ));
};

impl fmt::Display for EffectSiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.group().name(), self.variant())
    }
}

impl From<EffectSiteId> for String {
    fn from(site: EffectSiteId) -> Self {
        site.name()
    }
}

impl TryFrom<String> for EffectSiteId {
    type Error = UnknownSite;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_name(&value)
    }
}

// ---------------------------------------------------------------------------
// The hook harness
// ---------------------------------------------------------------------------

/// A phase at which the parent executes a hook.
///
/// There is deliberately no residue-class variant. A residue class is not an
/// executed hook, and the type is the first of the two places this framework
/// says so — the second is [`FaultRegistry::insert`], which refuses an entry
/// that claims otherwise even though this type made the claim unsayable to the
/// harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HookPhase {
    /// Before the primitive.
    Before,
    /// After the primitive.
    After,
    /// At a parent-side sub-effect point, in one injection mode.
    Point {
        /// Which point.
        point: SubEffectPoint,
        /// Which mode the injection is armed in.
        mode: InjectionMode,
    },
}

impl HookPhase {
    /// The two hook phases every site has.
    pub const PHASES: &'static [Self] = &[Self::Before, Self::After];
}

impl fmt::Display for HookPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Before => f.write_str("before"),
            Self::After => f.write_str("after"),
            Self::Point { point, mode } => write!(
                f,
                "{point}/{}",
                match mode {
                    InjectionMode::Kill => "kill",
                    InjectionMode::ErrorReturn => "error-return",
                }
            ),
        }
    }
}

/// What a funnel must do when it returns from a hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Injection {
    /// Nothing is armed here: carry on.
    Proceed,
    /// Die at this point.
    Kill,
    /// Return `Err` from this point.
    Error,
}

/// One `(site, phase)` the harness saw executed, and how often.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// The site whose funnel called the hook.
    pub site: EffectSiteId,
    /// The phase it called it at.
    pub phase: HookPhase,
    /// How many times.
    pub count: u32,
}

/// Why the harness refused to arm an injection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HarnessError {
    #[error(
        "`{site}` exposes no parent-side sub-effect point `{point}`; arming one would record an \
         execution of a point that does not exist"
    )]
    NoSuchPoint {
        /// The site.
        site: String,
        /// The point that was asked for.
        point: SubEffectPoint,
    },

    #[error("`{site}`'s `{point}` point does not support {mode:?} injection")]
    UnsupportedMode {
        /// The site.
        site: String,
        /// The point.
        point: SubEffectPoint,
        /// The mode that was asked for.
        mode: InjectionMode,
    },
}

/// Records what the funnels actually executed.
///
/// The whole value of this type is negative: it can only report an execution
/// that a funnel told it about by calling [`Self::hook`]. Arming an injection
/// records nothing, because an armed injection that never fired is exactly the
/// case a coverage report must not count. A harness that recorded at arming
/// time would report full coverage for a suite that never reached a single
/// site.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookHarness {
    armed: Vec<(EffectSiteId, SubEffectPoint, InjectionMode)>,
    /// What executed: both hook phases, and the injected modes that fired.
    observed: Vec<Observation>,
    /// What a funnel walked past at a point, whether or not anything fired.
    reached: Vec<Observation>,
    /// The fast integration sequences the suite exercised, in order.
    fast: Vec<FastSequence>,
    /// The one being recorded, if a sequence is open.
    open_fast: Option<usize>,
}

/// One exercised fast integration sequence, and every site its funnels ran.
///
/// ST-07's no-execution claim is "no staging, cherry-pick, or prepared-pin
/// site executed **for any fast sequence**" — a statement about traces, not a
/// statement about a process. A harness that had run nothing satisfies "the
/// site was never touched" trivially, so the absence has to be proved *inside*
/// a sequence that demonstrably happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastSequence {
    name: String,
    touched: Vec<EffectSiteId>,
}

impl FastSequence {
    /// What the suite called this sequence.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Every site whose funnel ran during it, in first-execution order.
    pub fn touched(&self) -> &[EffectSiteId] {
        &self.touched
    }

    /// Whether `site` ran during this sequence.
    pub fn ran(&self, site: EffectSiteId) -> bool {
        self.touched.contains(&site)
    }
}

impl HookHarness {
    /// A harness that has armed nothing and seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm an injection at one point of one site.
    ///
    /// Refuses a point the site does not expose and a mode the point does not
    /// support, so a suite cannot quietly arm a fault that no funnel will ever
    /// consult.
    pub fn arm(
        &mut self,
        site: EffectSiteId,
        point: SubEffectPoint,
        mode: InjectionMode,
    ) -> Result<(), HarnessError> {
        if !site.sub_effects().contains(&point) {
            return Err(HarnessError::NoSuchPoint {
                site: site.name(),
                point,
            });
        }
        if !point.supports(mode) {
            return Err(HarnessError::UnsupportedMode {
                site: site.name(),
                point,
                mode,
            });
        }
        if !self.armed.contains(&(site, point, mode)) {
            self.armed.push((site, point, mode));
        }
        Ok(())
    }

    /// Disarm every injection, keeping everything already observed.
    pub fn disarm(&mut self) {
        self.armed.clear();
    }

    /// The call a funnel makes. Answers what to do, and records an execution
    /// only of what actually happened.
    ///
    /// The two are not the same claim, and the difference is the whole reason
    /// this type exists.
    /// `fault_injection_registry.completeness_rule` requires every point to be
    /// "observed executed at least once by the suite **in every injection mode
    /// it supports**", and a mode is executed when its fault fired — not when
    /// a funnel walked past the place it would have fired. A harness that
    /// counted the walk-past would report both modes of every point covered
    /// for a suite that armed nothing, which is the same false report as
    /// counting at arming time, one step later.
    ///
    /// So: `Before` and `After` are reachability and are counted whenever the
    /// funnel calls them; a `Point` is counted only when that exact `(site,
    /// point, mode)` was armed and therefore returns its specified `Kill` or
    /// `Error`. Reachability of a point in the generic sense is
    /// [`Self::reached`], which is recorded separately and is never what the
    /// bijection reads.
    pub fn hook(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection {
        if let Some(open) = self.open_fast {
            if let Some(sequence) = self.fast.get_mut(open) {
                if !sequence.touched.contains(&site) {
                    sequence.touched.push(site);
                }
            }
        }
        let injection = match phase {
            HookPhase::Before | HookPhase::After => Injection::Proceed,
            HookPhase::Point { point, mode } => {
                if self.armed.contains(&(site, point, mode)) {
                    match mode {
                        InjectionMode::Kill => Injection::Kill,
                        InjectionMode::ErrorReturn => Injection::Error,
                    }
                } else {
                    Injection::Proceed
                }
            }
        };
        if let HookPhase::Point { point, mode } = phase {
            Self::record(&mut self.reached, site, HookPhase::Point { point, mode });
            if injection == Injection::Proceed {
                // Reached, and nothing was injected. Recorded as reachability
                // and as nothing else.
                return injection;
            }
        }
        Self::record(&mut self.observed, site, phase);
        injection
    }

    fn record(into: &mut Vec<Observation>, site: EffectSiteId, phase: HookPhase) {
        match into
            .iter_mut()
            .find(|seen| seen.site == site && seen.phase == phase)
        {
            Some(seen) => seen.count = seen.count.saturating_add(1),
            None => into.push(Observation {
                site,
                phase,
                count: 1,
            }),
        }
    }

    /// Begin recording an exact-base fast integration sequence under `name`.
    ///
    /// Everything a funnel hooks until [`Self::end_fast_sequence`] is recorded
    /// as having run inside this sequence, which is what a no-execution entry
    /// is measured against. A second `begin` closes the first.
    pub fn begin_fast_sequence(&mut self, name: &str) {
        self.end_fast_sequence();
        self.fast.push(FastSequence {
            name: name.to_owned(),
            touched: Vec::new(),
        });
        self.open_fast = Some(self.fast.len() - 1);
    }

    /// Stop recording the open fast sequence, keeping what it saw.
    pub fn end_fast_sequence(&mut self) {
        self.open_fast = None;
    }

    /// Every fast sequence the suite exercised.
    pub fn fast_sequences(&self) -> &[FastSequence] {
        &self.fast
    }

    /// The fast sequence of this name, if the suite exercised one.
    pub fn fast_sequence(&self, name: &str) -> Option<&FastSequence> {
        self.fast.iter().find(|sequence| sequence.name == name)
    }

    /// Every `(site, point-phase)` a funnel *reached*, armed or not.
    ///
    /// Kept apart from [`Self::coverage`] on purpose: reaching a point proves
    /// the hook is wired into the funnel, and injecting at it proves the mode
    /// does what the fault matrix says. Only the second is evidence of
    /// coverage, and only the first tells a suite author that an arming was
    /// mistargeted rather than the site unreached.
    pub fn reached(&self) -> &[Observation] {
        &self.reached
    }

    /// Whether a funnel reached this point at all, whatever was armed.
    pub fn reached_point(
        &self,
        site: EffectSiteId,
        point: SubEffectPoint,
        mode: InjectionMode,
    ) -> bool {
        self.reached
            .iter()
            .any(|seen| seen.site == site && seen.phase == HookPhase::Point { point, mode })
    }

    /// Every `(site, phase)` observed, in first-observation order.
    pub fn coverage(&self) -> &[Observation] {
        &self.observed
    }

    /// Whether this exact `(site, phase)` was executed at least once.
    pub fn observed(&self, site: EffectSiteId, phase: HookPhase) -> bool {
        self.count(site, phase) > 0
    }

    /// How many times this exact `(site, phase)` was executed.
    pub fn count(&self, site: EffectSiteId, phase: HookPhase) -> u32 {
        self.observed
            .iter()
            .find(|seen| seen.site == site && seen.phase == phase)
            .map_or(0, |seen| seen.count)
    }

    /// Whether the harness saw this site execute at all, in any phase.
    ///
    /// Deliberately *not* what a no-execution record is measured against. That
    /// claim is scoped to a trace — "no staging, cherry-pick, or prepared-pin
    /// site executed **for any fast sequence**" — and its negation is
    /// [`FastSequence::ran`], per sequence. A suite that exercises a stale
    /// integration and a fast one touches all three sites and is exactly the
    /// suite ST-07 asks for; reading this answer as the no-execution test
    /// would reject it.
    pub fn touched(&self, site: EffectSiteId) -> bool {
        self.observed.iter().any(|seen| seen.site == site)
            || self.reached.iter().any(|seen| seen.site == site)
    }

    /// How many executions in total. Zero for a harness nothing has run
    /// through, whatever it has armed.
    pub fn executions(&self) -> u32 {
        self.observed.iter().map(|seen| seen.count).sum()
    }
}

// ---------------------------------------------------------------------------
// The registry format
// ---------------------------------------------------------------------------

/// What a registry entry is about.
///
/// The four kinds are different in kind, and keeping them apart at the type
/// level is what stops a residue class from being counted as a hook: a
/// [`Self::Residue`] entry cannot carry a [`HookPhase`], and a hook entry
/// cannot carry a [`ResidueClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EntryPhase {
    /// The hook before the primitive.
    Before,
    /// The hook after the primitive.
    After,
    /// A parent-side sub-effect point in one injection mode.
    Point {
        /// Which point.
        point: SubEffectPoint,
        /// Which mode.
        mode: InjectionMode,
    },
    /// A command-internal residue class. Never an executed hook.
    Residue {
        /// Which class.
        class: ResidueClass,
    },
    /// The record that this site did *not* execute — the fast integration
    /// path's assertion about staging, cherry-pick and prepared-pin sites.
    NoExecution,
}

impl EntryPhase {
    /// The hook phase this entry is about, where it is about one.
    pub const fn hook_phase(self) -> Option<HookPhase> {
        match self {
            Self::Before => Some(HookPhase::Before),
            Self::After => Some(HookPhase::After),
            Self::Point { point, mode } => Some(HookPhase::Point { point, mode }),
            Self::Residue { .. } | Self::NoExecution => None,
        }
    }

    /// The residue class this entry is about, where it is about one.
    pub const fn residue_class(self) -> Option<ResidueClass> {
        match self {
            Self::Residue { class } => Some(class),
            Self::Before | Self::After | Self::Point { .. } | Self::NoExecution => None,
        }
    }

    /// Whether `structure` gives this phase the site's *before-phase* resume
    /// action rather than an action of its own.
    ///
    /// Two phases, and the packet says so of both in the same words:
    /// `IdUnread` ("R27 object without a recorded id; resume action = the
    /// before-phase action") and the `Internal` residue class ("objects
    /// present and unreferenced, R27, with administrative residue ...; resume
    /// action equal to the before-phase action"). Both are prefixes in which
    /// nothing was published, so recovery is what recovery from *nothing*
    /// would have been — and an entry free to name a different action could
    /// table a resume that adopts a prefix no reader can authenticate.
    pub const fn resumes_as_before(self) -> bool {
        matches!(
            self,
            Self::Point {
                point: SubEffectPoint::IdUnread,
                ..
            } | Self::Residue { .. }
        )
    }

    /// The evidence label an entry in this phase must carry.
    pub const fn required_label(self) -> EvidenceLabel {
        match self {
            Self::Before | Self::After | Self::Point { .. } | Self::NoExecution => {
                EvidenceLabel::ExecutionObserved
            }
            Self::Residue { .. } => EvidenceLabel::RecoveryProven,
        }
    }
}

impl fmt::Display for EntryPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Before => f.write_str("before"),
            Self::After => f.write_str("after"),
            Self::Point { point, mode } => write!(
                f,
                "{point}/{}",
                match mode {
                    InjectionMode::Kill => "kill",
                    InjectionMode::ErrorReturn => "error-return",
                }
            ),
            Self::Residue { class } => f.write_str(class.name()),
            Self::NoExecution => f.write_str("no-execution"),
        }
    }
}

/// What is left durable after a fault at this entry's point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedResidue {
    /// The ledger rows still holding something. Empty is a real answer — the
    /// before phase of a creation, and a Windows containment point, each leave
    /// no row holding anything — but it is not the *only* answer a before phase
    /// has: see [`BeforeState`].
    pub rows: Vec<ResourceRow>,
    /// The concrete artifacts, in the fault matrix's own words.
    pub detail: String,
}

/// One residue element's synthetic-construction record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticRecord {
    /// Which element.
    pub element: ResidueElement,
    /// Whether it was constructed in a real temporary repository.
    pub constructed: bool,
    /// What the classifier answered for it.
    pub classified: ObjectResidue,
    /// Whether the tabled recovery converged.
    pub recovered: bool,
}

/// How many of each class a site's kill sampling observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassHistogram {
    /// Samples that classified `None`.
    pub none: u32,
    /// Samples that classified `Internal`. Zero is legal: hitting the internal
    /// window is recorded, never required.
    pub internal: u32,
    /// Samples that classified `After`.
    pub after: u32,
}

impl ClassHistogram {
    /// How many samples the histogram accounts for.
    pub const fn total(self) -> u32 {
        self.none
            .saturating_add(self.internal)
            .saturating_add(self.after)
    }
}

/// The real-command kill-sampling record for one site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingRecord {
    /// The frozen sample count for this site.
    pub n: u32,
    /// What the classifier answered, by class.
    pub histogram: ClassHistogram,
    /// Samples that classified into no class at all. Any is a failure: the run
    /// would have durable state no tabled action recovers.
    pub unclassified: u32,
    /// Whether every sampled residue recovered by its classified action.
    pub recovered: bool,
}

/// An entry's evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Evidence {
    /// A hook phase or point ran, and this test recorded it.
    Executed {
        /// The test that executed it.
        test: String,
        /// Its pass record.
        passed: bool,
    },
    /// Nothing executed: every listed residue element was constructed and
    /// recovered, and the site was kill-sampled.
    RecoveryProven {
        /// One record per element the site's class lists.
        synthetic: Vec<SyntheticRecord>,
        /// The sampling record.
        sampling: SamplingRecord,
    },
    /// This site was asserted *not* to have executed.
    NotExecuted {
        /// The test that asserted it.
        test: String,
        /// Its pass record.
        passed: bool,
        /// The exercised fast sequences the absence was proved within.
        ///
        /// "The fast-path no-execution record shows that no staging,
        /// cherry-pick, or prepared-pin site executed **for any fast
        /// sequence**": the claim is about traces, so the evidence names the
        /// traces. An entry naming none is a claim about a process that may
        /// never have run an integration at all.
        sequences: Vec<String>,
    },
}

impl Evidence {
    /// The label this evidence's shape implies.
    pub const fn label(&self) -> EvidenceLabel {
        match self {
            Self::Executed { .. } | Self::NotExecuted { .. } => EvidenceLabel::ExecutionObserved,
            Self::RecoveryProven { .. } => EvidenceLabel::RecoveryProven,
        }
    }

    /// Whether this evidence claims a hook was executed.
    pub const fn claims_execution(&self) -> bool {
        matches!(self, Self::Executed { .. })
    }
}

/// One entry of the fault-injection registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    /// The site.
    pub site: EffectSiteId,
    /// What the entry is about.
    pub phase: EntryPhase,
    /// Which durable order, where the site has one.
    pub order: Option<ObservableOrder>,
    /// The fault-matrix row. Must equal the site's own.
    pub fault_row: FaultRow,
    /// What is left durable.
    pub expected_residue: ExpectedResidue,
    /// What a resume does about it, in the matrix's words.
    pub resume_action: String,
    /// How the claim was obtained.
    pub label: EvidenceLabel,
    /// The evidence itself.
    pub evidence: Evidence,
}

impl RegistryEntry {
    /// This entry's key: site, phase, order.
    pub fn key(&self) -> (EffectSiteId, EntryPhase, Option<ObservableOrder>) {
        (self.site, self.phase, self.order)
    }
}

/// Why the registry format refused an entry.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    #[error(
        "`{site}`'s entry for the residue class `{class}` carries executed-hook evidence. A \
         residue class is a prefix inside an external command that no parent hook can observe; \
         its evidence is recovery-proven, and an entry claiming otherwise would report coverage \
         the suite does not have."
    )]
    ResidueClaimsExecution {
        /// The site.
        site: String,
        /// The class.
        class: &'static str,
    },

    #[error(
        "`{site}`'s `{phase}` entry carries recovery-proven evidence, but a hook phase is \
         observed by execution; recovery-proven is the label for what no hook can reach"
    )]
    HookClaimsRecoveryProof {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
    },

    #[error("`{site}`'s `{phase}` entry is labelled {found:?} but its phase requires {required:?}")]
    MislabelledEntry {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// The label the entry carried.
        found: EvidenceLabel,
        /// The label its phase requires.
        required: EvidenceLabel,
    },

    #[error("`{site}` records fault row {found} but the site's row is {expected}")]
    WrongFaultRow {
        /// The site.
        site: String,
        /// What the entry said.
        found: FaultRow,
        /// What the site says.
        expected: FaultRow,
    },

    #[error(
        "`{site}`'s `{phase}` entry records order {found:?}, which is not an order a fault at \
         this site can leave observable"
    )]
    WrongOrder {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// What the entry said.
        found: Option<ObservableOrder>,
    },

    #[error("`{site}` exposes no `{point}` point in {mode:?} mode")]
    NoSuchPoint {
        /// The site.
        site: String,
        /// The point.
        point: SubEffectPoint,
        /// The mode.
        mode: InjectionMode,
    },

    #[error("`{site}` registers no residue class `{class}`")]
    NoSuchResidueClass {
        /// The site.
        site: String,
        /// The class.
        class: &'static str,
    },

    #[error(
        "`{site}`'s recovery-proven entry has no synthetic-construction record for the `{element:?}` \
         residue element its class lists"
    )]
    MissingSyntheticElement {
        /// The site.
        site: String,
        /// The element with no record.
        element: ResidueElement,
    },

    #[error(
        "`{site}`'s recovery-proven entry records a synthetic construction of `{element:?}`, which its class does not list"
    )]
    UnlistedSyntheticElement {
        /// The site.
        site: String,
        /// The element that does not belong.
        element: ResidueElement,
    },

    #[error("`{site}`'s `{phase}` entry names no test")]
    UnnamedTest {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
    },

    #[error(
        "`{site}` carries a no-execution record, but only the three sites a fast integration \
         sequence skips — Worktree.AddStaging, Object.ProposalCherryPick, Ref.PinPrepared — may \
         record that they did not run"
    )]
    NoExecutionNotSkipped {
        /// The site.
        site: String,
    },

    #[error(
        "`{site}`'s `{phase}` entry expects {found:?} to hold residue and this site's `{phase}` \
         leaves {expected:?}"
    )]
    WrongResidueRows {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// What the entry claimed.
        found: Vec<ResourceRow>,
        /// What the site's own semantics leave.
        expected: Vec<ResourceRow>,
    },

    #[error(
        "`{site}`'s no-execution record names no fast sequence it holds within. Absence is proved \
         inside an exercised trace or it is a claim about a process that ran no integration at all."
    )]
    UnwitnessedNoExecution {
        /// The site.
        site: String,
    },

    #[error("`{site}`'s `{phase}` entry names no resume action")]
    UnnamedResumeAction {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
    },

    #[error(
        "`{site}`'s `{phase}` entry describes its residue as `{found}` and this site's `{phase}` \
         leaves `{expected}`"
    )]
    WrongResidueDetail {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// What the entry claimed.
        found: String,
        /// What the site's own semantics leave.
        expected: &'static str,
    },

    #[error(
        "`{site}`'s `{phase}` entry tables the resume action `{found}` and the matrix tables \
         `{expected}` for this phase of this site"
    )]
    WrongResumeAction {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// What the entry claimed.
        found: String,
        /// What the site's own semantics table.
        expected: &'static str,
    },

    #[error("`{site}` already has an entry for `{phase}` in order {order:?}")]
    DuplicateEntry {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// The order.
        order: Option<ObservableOrder>,
    },
}

/// The fault-injection registry: entries, and the format that refuses a bad
/// one.
///
/// `insert` is the format. Everything it refuses is refused *before* the
/// bijection check runs, so a registry that exists at all is one whose entries
/// are internally consistent with the enums; the bijection is then only about
/// whether the entries and the executions cover the inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultRegistry {
    entries: Vec<RegistryEntry>,
}

impl FaultRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry, or say why it is not one.
    pub fn insert(&mut self, entry: RegistryEntry) -> Result<(), RegistryError> {
        validate_entry(&entry)?;
        if self.entries.iter().any(|held| held.key() == entry.key()) {
            return Err(RegistryError::DuplicateEntry {
                site: entry.site.name(),
                phase: entry.phase.to_string(),
                order: entry.order,
            });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Every entry, in insertion order.
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// The entry for one key, if there is one.
    pub fn get(
        &self,
        site: EffectSiteId,
        phase: EntryPhase,
        order: Option<ObservableOrder>,
    ) -> Option<&RegistryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.key() == (site, phase, order))
    }

    /// How many entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The whole of the format's validity rule, as one function.
///
/// Separate from [`FaultRegistry::insert`] so the bijection check can apply it
/// again to entries handed to it as a bare slice — a registry.json that was
/// hand-edited between a gate and a review never went through `insert`, and
/// "the bijection check fails on a residue-class entry claiming executed-hook
/// evidence" has to be true of that document too.
pub fn validate_entry(entry: &RegistryEntry) -> Result<(), RegistryError> {
    let site = entry.site;
    let name = site.name();

    if entry.fault_row != site.fault_row() {
        return Err(RegistryError::WrongFaultRow {
            site: name,
            found: entry.fault_row,
            expected: site.fault_row(),
        });
    }

    // A no-execution record is not about an order: nothing was performed, so
    // there is no effect to be durable before or after the append. Every other
    // phase carries the site's one order, or `None` where the site has none.
    let orders = site.observable_orders();
    let order_ok = match (entry.phase, entry.order) {
        (EntryPhase::NoExecution, order) => order.is_none(),
        (_, Some(order)) => orders.contains(&order),
        (_, None) => orders.is_empty(),
    };
    if !order_ok {
        return Err(RegistryError::WrongOrder {
            site: name,
            phase: entry.phase.to_string(),
            found: entry.order,
        });
    }

    if entry.phase == EntryPhase::NoExecution && !site.skipped_on_fast_path() {
        return Err(RegistryError::NoExecutionNotSkipped { site: name });
    }

    // The expected residue and the tabled recovery are the site's own
    // semantics, not the entry's opinion of them. Without this an otherwise
    // complete entry can name an unrelated row — or none — describe residue
    // the site does not leave, and table a resume the matrix does not give it,
    // and the registry reads as evidence that a fault there was accounted for
    // when nothing checked any of the three.
    //
    // All three come from one call, so they cannot be checked against two
    // tables that disagree.
    let semantics = site.semantics(entry.phase);
    if entry.expected_residue.rows != semantics.rows {
        return Err(RegistryError::WrongResidueRows {
            site: name,
            phase: entry.phase.to_string(),
            found: entry.expected_residue.rows.clone(),
            expected: semantics.rows,
        });
    }
    if entry.resume_action.trim().is_empty() {
        return Err(RegistryError::UnnamedResumeAction {
            site: name,
            phase: entry.phase.to_string(),
        });
    }
    if entry.expected_residue.detail != semantics.artifact.detail() {
        return Err(RegistryError::WrongResidueDetail {
            site: name,
            phase: entry.phase.to_string(),
            found: entry.expected_residue.detail.clone(),
            expected: semantics.artifact.detail(),
        });
    }
    if entry.resume_action != semantics.action.text() {
        return Err(RegistryError::WrongResumeAction {
            site: name,
            phase: entry.phase.to_string(),
            found: entry.resume_action.clone(),
            expected: semantics.action.text(),
        });
    }

    match entry.phase {
        EntryPhase::Point { point, mode } => {
            if !site.exposes(point, mode) {
                return Err(RegistryError::NoSuchPoint {
                    site: name,
                    point,
                    mode,
                });
            }
        }
        EntryPhase::Residue { class } => {
            if !site.registers(class) {
                return Err(RegistryError::NoSuchResidueClass {
                    site: name,
                    class: class.name(),
                });
            }
        }
        EntryPhase::Before | EntryPhase::After | EntryPhase::NoExecution => {}
    }

    // The load-bearing refusal, stated first and stated by itself: a residue
    // class is not a hook, and an entry that claims one executed is refused
    // whatever else about it is well-formed.
    if let Some(class) = entry.phase.residue_class() {
        if entry.evidence.claims_execution() || entry.label == EvidenceLabel::ExecutionObserved {
            return Err(RegistryError::ResidueClaimsExecution {
                site: name,
                class: class.name(),
            });
        }
    }
    if entry.phase.residue_class().is_none()
        && matches!(entry.evidence, Evidence::RecoveryProven { .. })
    {
        return Err(RegistryError::HookClaimsRecoveryProof {
            site: name,
            phase: entry.phase.to_string(),
        });
    }
    if entry.label != entry.phase.required_label() {
        return Err(RegistryError::MislabelledEntry {
            site: name,
            phase: entry.phase.to_string(),
            found: entry.label,
            required: entry.phase.required_label(),
        });
    }
    if entry.label != entry.evidence.label() {
        return Err(RegistryError::MislabelledEntry {
            site: name,
            phase: entry.phase.to_string(),
            found: entry.label,
            required: entry.evidence.label(),
        });
    }

    // The two evidence shapes that are legal for a hook entry are legal only
    // for the phase kind that matches them: `NoExecution` records that nothing
    // ran, and a before/after/point entry records that something did.
    match (&entry.phase, &entry.evidence) {
        (EntryPhase::NoExecution, Evidence::Executed { .. }) => {
            return Err(RegistryError::MislabelledEntry {
                site: name,
                phase: entry.phase.to_string(),
                found: EvidenceLabel::ExecutionObserved,
                required: EvidenceLabel::ExecutionObserved,
            });
        }
        (
            EntryPhase::Before | EntryPhase::After | EntryPhase::Point { .. },
            Evidence::NotExecuted { .. },
        ) => {
            return Err(RegistryError::MislabelledEntry {
                site: name,
                phase: entry.phase.to_string(),
                found: EvidenceLabel::ExecutionObserved,
                required: EvidenceLabel::ExecutionObserved,
            });
        }
        _ => {}
    }

    match &entry.evidence {
        Evidence::Executed { test, .. } => {
            if test.trim().is_empty() {
                return Err(RegistryError::UnnamedTest {
                    site: name,
                    phase: entry.phase.to_string(),
                });
            }
        }
        Evidence::NotExecuted {
            test, sequences, ..
        } => {
            if test.trim().is_empty() {
                return Err(RegistryError::UnnamedTest {
                    site: name,
                    phase: entry.phase.to_string(),
                });
            }
            if sequences.is_empty() || sequences.iter().any(|name| name.trim().is_empty()) {
                return Err(RegistryError::UnwitnessedNoExecution { site: name });
            }
        }
        Evidence::RecoveryProven { synthetic, .. } => {
            for element in site.residue_elements() {
                if !synthetic.iter().any(|record| record.element == *element) {
                    return Err(RegistryError::MissingSyntheticElement {
                        site: name,
                        element: *element,
                    });
                }
            }
            for record in synthetic {
                if !site.residue_elements().contains(&record.element) {
                    return Err(RegistryError::UnlistedSyntheticElement {
                        site: name,
                        element: record.element,
                    });
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// The bijection check
// ---------------------------------------------------------------------------

/// One way the bijection is not a bijection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BijectionFailure {
    #[error("`{site}` was never observed executing its `{phase}` hook")]
    Unobserved {
        /// The site.
        site: String,
        /// The phase or point that never ran.
        phase: String,
    },

    #[error("`{site}` has no registry entry for `{phase}` in order {order:?}")]
    MissingEntry {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// The order.
        order: Option<ObservableOrder>,
    },

    #[error("`{site}`'s `{phase}` entry has no passing evidence")]
    MissingEvidence {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
    },

    #[error("`{site}`'s sampling record classified {count} residues into no class at all")]
    UnclassifiableResidue {
        /// The site.
        site: String,
        /// How many.
        count: u32,
    },

    #[error(
        "`{site}`'s sampling record covers {n} samples but its histogram accounts for {counted}"
    )]
    SamplingUnaccounted {
        /// The site.
        site: String,
        /// The frozen sample count.
        n: u32,
        /// What the histogram and the unclassified count add up to.
        counted: u32,
    },

    #[error("`{site}` has a residue class but no sampling record: its frozen N is zero")]
    MissingSampling {
        /// The site.
        site: String,
    },

    #[error("`{site}`'s sampled residues did not all recover by their classified action")]
    UnrecoveredSampling {
        /// The site.
        site: String,
    },

    #[error("`{site}`'s residue-class entry claims executed-hook evidence")]
    ResidueClaimsExecution {
        /// The site.
        site: String,
    },

    #[error(
        "`{site}` carries a no-execution record and the suite exercised no fast sequence; an \
         empty harness is not evidence that a site a fast sequence skips was skipped"
    )]
    NoFastSequenceExercised {
        /// The site.
        site: String,
    },

    #[error(
        "`{site}`'s no-execution record does not hold within the exercised fast sequence \
         `{sequence}`"
    )]
    UnwitnessedFastSequence {
        /// The site.
        site: String,
        /// The sequence it says nothing about.
        sequence: String,
    },

    #[error("`{site}`'s no-execution record names `{sequence}`, which the harness never exercised")]
    UnknownFastSequence {
        /// The site.
        site: String,
        /// The sequence it named.
        sequence: String,
    },

    #[error("`{site}` executed during the fast sequence `{sequence}` its record says it skipped")]
    ExecutedInFastSequence {
        /// The site.
        site: String,
        /// The sequence it ran in.
        sequence: String,
    },

    #[error("the registry holds an entry for `{site}`, which the inventory under check does not")]
    EntryOutsideInventory {
        /// The site.
        site: String,
    },

    #[error(
        "`{site}` has {count} entries for `{phase}` in order {order:?}; a registry key is one \
         entry, and a checker that kept the first or the last would report whichever of two \
         disagreeing claims it happened to reach"
    )]
    DuplicateEntry {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// The order.
        order: Option<ObservableOrder>,
        /// How many entries carried the key.
        count: usize,
    },

    #[error(
        "`{site}`'s `{phase}` entry resumes by `{found}` and its before-phase entry resumes by \
         `{expected}`; this phase's resume action is the before-phase action"
    )]
    ResumeActionNotBeforeAction {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// What the entry said.
        found: String,
        /// The site's before-phase action.
        expected: String,
    },

    #[error("`{site}`'s `{phase}` entry is not a valid entry: {reason}")]
    InvalidEntry {
        /// The site.
        site: String,
        /// The phase.
        phase: String,
        /// Why.
        reason: String,
    },
}

/// The checked bijection over an inventory
/// (`fault_injection_registry.completeness_rule`).
///
/// Returns every way the claim fails; an empty answer is the claim holding.
/// `inventory` is a parameter rather than [`EffectSiteId::all`] because the
/// framework has to be checkable long before every site exists: PR3 runs it
/// over the handful of sites its self-test drives, and PR10 runs it over
/// everything. A slice that narrows the inventory narrows its own claim, which
/// is why the self-test also runs the check over the *full* claimed inventory
/// and asserts that it fails.
///
/// Legacy-scoped sites are skipped: `scope` says they are inventoried and
/// row-mapped and carry no fault-registry requirement.
pub fn check_bijection(
    inventory: &[EffectSiteId],
    harness: &HookHarness,
    entries: &[RegistryEntry],
    host: Host,
) -> Vec<BijectionFailure> {
    let mut failures = Vec::new();

    // `FaultRegistry::insert` refuses a duplicate key, but this function is
    // documented to take a bare slice precisely because a registry.json that
    // was hand-edited between a gate and a review never went through `insert`.
    // `structure` keys entries by site x phase x order, so two entries at one
    // key are two answers to one question — and `check_evidence` would silently
    // read the first of them. Restated here so the bare-slice path carries the
    // same invariant the constructor does.
    for (index, entry) in entries.iter().enumerate() {
        let key = entry.key();
        if entries[..index].iter().any(|held| held.key() == key) {
            // Already reported at its first occurrence.
            continue;
        }
        let count = entries.iter().filter(|held| held.key() == key).count();
        if count > 1 {
            failures.push(BijectionFailure::DuplicateEntry {
                site: entry.site.name(),
                phase: entry.phase.to_string(),
                order: entry.order,
                count,
            });
        }
    }

    for entry in entries {
        if let Err(error) = validate_entry(entry) {
            // Restated rather than folded into `InvalidEntry`, because ST-07
            // names this one direction explicitly and a reviewer looking for it
            // should find it under its own name.
            if matches!(error, RegistryError::ResidueClaimsExecution { .. }) {
                failures.push(BijectionFailure::ResidueClaimsExecution {
                    site: entry.site.name(),
                });
            } else {
                failures.push(BijectionFailure::InvalidEntry {
                    site: entry.site.name(),
                    phase: entry.phase.to_string(),
                    reason: error.to_string(),
                });
            }
        }
        if !inventory.contains(&entry.site) {
            failures.push(BijectionFailure::EntryOutsideInventory {
                site: entry.site.name(),
            });
        }
        // The relation `validate_entry` cannot make, because it sees one entry:
        // the phases `structure` gives "the before-phase action" have to name
        // the action this site's own before-phase entry names.
        if entry.phase.resumes_as_before() {
            let before = entries
                .iter()
                .find(|held| held.site == entry.site && held.phase == EntryPhase::Before);
            match before {
                Some(before) if before.resume_action == entry.resume_action => {}
                Some(before) => failures.push(BijectionFailure::ResumeActionNotBeforeAction {
                    site: entry.site.name(),
                    phase: entry.phase.to_string(),
                    found: entry.resume_action.clone(),
                    expected: before.resume_action.clone(),
                }),
                None => failures.push(BijectionFailure::MissingEntry {
                    site: entry.site.name(),
                    phase: EntryPhase::Before.to_string(),
                    order: entry.order,
                }),
            }
        }
    }

    for site in inventory {
        let site = *site;
        if !site.scope().is_claimed() {
            continue;
        }
        let name = site.name();

        // A no-execution record is *additional* evidence about the fast
        // traces, not an alternative to ordinary coverage. The three sites it
        // may be written for are Topology-scoped sites on the stale-candidate
        // path: a staging worktree is added, a proposal is cherry-picked and a
        // prepared pin is taken whenever the base is not exact, and
        // `completeness_rule` requires "every site x hook phase ... observed
        // executed at least once by the suite" of them like any other. What
        // `structure` says is narrower and is a statement about traces: "for a
        // fast sequence Worktree.AddStaging, Object.ProposalCherryPick, and
        // Ref.PinPrepared are asserted not executed".
        //
        // So this block adds requirements and removes none. It does not ask
        // whether the harness ever touched the site — a global `touched` test
        // rejects the valid evidence of a suite that exercised both paths, and
        // accepts nothing extra: execution inside a named fast sequence is
        // caught by `ExecutedInFastSequence` below, where the claim actually
        // lives. And it does not `continue`, because skipping the phase and
        // point bijection is how a site excuses itself from coverage by
        // declaring that it did not run.
        //
        // The condition is `skipped_on_fast_path()` — a property of the site —
        // and emphatically not "does a no-execution entry exist for it". The
        // predecessor asked the second question, so deleting all three records
        // made the entire branch unreachable and `check_bijection` reported
        // nothing: a completeness oracle that derives *whether* a requirement
        // exists from the very entries it is checking cannot report a missing
        // one. `completeness_rule` is explicit that "any missing link fails",
        // and ST-07 requires the record itself — "the fast-path no-execution
        // record shows that no staging, cherry-pick, or prepared-pin site
        // executed for any fast sequence". The `check_evidence` call at the end
        // of the block is what reports the record's absence, and it is now
        // reached whether or not the record is there.
        //
        // Exactly one record, not at least one: `check_evidence` finds the
        // entry at the key `(site, NoExecution, None)` and the duplicate sweep
        // above refuses a second at the same key, so the two together admit one
        // and only one.
        if site.skipped_on_fast_path() {
            // "The fast-path no-execution record shows that no staging,
            // cherry-pick, or prepared-pin site executed for any fast
            // sequence" — so there has to *be* a fast sequence, the record has
            // to hold within every one the suite exercised, and it may not
            // name one that never happened. Without all three an empty harness
            // substantiates the claim, which is the same false report as an
            // empty coverage table.
            if harness.fast_sequences().is_empty() {
                failures.push(BijectionFailure::NoFastSequenceExercised { site: name.clone() });
            }
            let claimed: Vec<&str> = entries
                .iter()
                .filter(|entry| entry.site == site && entry.phase == EntryPhase::NoExecution)
                .filter_map(|entry| match &entry.evidence {
                    Evidence::NotExecuted { sequences, .. } => Some(sequences),
                    _ => None,
                })
                .flatten()
                .map(String::as_str)
                .collect();
            for sequence in harness.fast_sequences() {
                if !claimed.contains(&sequence.name()) {
                    failures.push(BijectionFailure::UnwitnessedFastSequence {
                        site: name.clone(),
                        sequence: sequence.name().to_owned(),
                    });
                } else if sequence.ran(site) {
                    failures.push(BijectionFailure::ExecutedInFastSequence {
                        site: name.clone(),
                        sequence: sequence.name().to_owned(),
                    });
                }
            }
            for sequence in &claimed {
                if harness.fast_sequence(sequence).is_none() {
                    failures.push(BijectionFailure::UnknownFastSequence {
                        site: name.clone(),
                        sequence: (*sequence).to_owned(),
                    });
                }
            }
            check_evidence(&mut failures, entries, site, EntryPhase::NoExecution, None);
        }

        let mut required = vec![EntryPhase::Before, EntryPhase::After];
        for point in site.sub_effects() {
            if !point.platform().required_on(host) {
                continue;
            }
            for mode in point.modes() {
                required.push(EntryPhase::Point {
                    point: *point,
                    mode: *mode,
                });
            }
        }

        for phase in required {
            let hook = phase
                .hook_phase()
                .expect("before, after and point phases all have a hook phase");
            if !harness.observed(site, hook) {
                failures.push(BijectionFailure::Unobserved {
                    site: name.clone(),
                    phase: phase.to_string(),
                });
            }
            let orders = site.observable_orders();
            if orders.is_empty() {
                check_evidence(&mut failures, entries, site, phase, None);
            } else {
                for order in orders {
                    check_evidence(&mut failures, entries, site, phase, Some(*order));
                }
            }
        }

        for class in site.residue_classes() {
            let phase = EntryPhase::Residue { class: *class };
            let orders = site.observable_orders();
            let order = if orders.is_empty() {
                None
            } else {
                Some(orders[0])
            };
            check_evidence(&mut failures, entries, site, phase, order);
        }
    }

    failures
}

/// Whether one required key has an entry, and whether that entry's evidence
/// says anything.
fn check_evidence(
    failures: &mut Vec<BijectionFailure>,
    entries: &[RegistryEntry],
    site: EffectSiteId,
    phase: EntryPhase,
    order: Option<ObservableOrder>,
) {
    let Some(entry) = entries
        .iter()
        .find(|entry| entry.key() == (site, phase, order))
    else {
        failures.push(BijectionFailure::MissingEntry {
            site: site.name(),
            phase: phase.to_string(),
            order,
        });
        return;
    };

    match &entry.evidence {
        Evidence::Executed { passed, .. } | Evidence::NotExecuted { passed, .. } => {
            if !passed {
                failures.push(BijectionFailure::MissingEvidence {
                    site: site.name(),
                    phase: phase.to_string(),
                });
            }
        }
        Evidence::RecoveryProven {
            synthetic,
            sampling,
        } => {
            for record in synthetic {
                if !record.constructed
                    || !record.recovered
                    || record.classified != ObjectResidue::Internal
                {
                    failures.push(BijectionFailure::MissingEvidence {
                        site: site.name(),
                        phase: phase.to_string(),
                    });
                    break;
                }
            }
            if sampling.n == 0 {
                failures.push(BijectionFailure::MissingSampling { site: site.name() });
            }
            if sampling.unclassified > 0 {
                failures.push(BijectionFailure::UnclassifiableResidue {
                    site: site.name(),
                    count: sampling.unclassified,
                });
            }
            let counted = sampling
                .histogram
                .total()
                .saturating_add(sampling.unclassified);
            if counted != sampling.n {
                failures.push(BijectionFailure::SamplingUnaccounted {
                    site: site.name(),
                    n: sampling.n,
                    counted,
                });
            }
            if !sampling.recovered {
                failures.push(BijectionFailure::UnrecoveredSampling { site: site.name() });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// effect_sites.json
// ---------------------------------------------------------------------------

/// One point of a site, as the generated inventory records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointExport {
    /// Which point.
    pub point: SubEffectPoint,
    /// The host it exists on.
    pub platform: Platform,
    /// Every mode it supports.
    pub modes: Vec<InjectionMode>,
}

/// One residue class of a site, as the generated inventory records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidueClassExport {
    /// Which class.
    pub class: ResidueClass,
    /// The label it must carry. Always recovery-proven.
    pub label: EvidenceLabel,
    /// The classifier outcome it is the class of.
    pub classified_as: ObjectResidue,
    /// Every element its synthetic construction must build.
    pub elements: Vec<ResidueElement>,
}

/// One site of `effect_sites.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectSiteExport {
    /// The dotted name.
    pub site: EffectSiteId,
    /// Its group.
    pub group: FunnelGroup,
    /// Its row.
    pub row: ResourceRow,
    /// The row's enforcement domain.
    pub domain: EnforcementDomain,
    /// Its adjacency.
    pub adjacent: Adjacent,
    /// The orders a fault here can leave observable.
    pub observable_orders: Vec<ObservableOrder>,
    /// Its fault-matrix row.
    pub fault_row: FaultRow,
    /// Its scope.
    pub scope: SiteScope,
    /// The module its funnel lives in.
    pub module: String,
    /// Whether it performs no effect.
    pub read_only: bool,
    /// Its parent-side sub-effect points.
    pub sub_effect_points: Vec<PointExport>,
    /// Its residue classes.
    pub residue_classes: Vec<ResidueClassExport>,
}

/// The generated inventory, in group and declaration order.
///
/// Generated *from* the enums, so it cannot describe a site that does not
/// exist and cannot omit one that does.
pub fn effect_sites() -> Vec<EffectSiteExport> {
    EffectSiteId::all()
        .into_iter()
        .map(|site| EffectSiteExport {
            site,
            group: site.group(),
            row: site.row(),
            domain: site.row().domain(),
            adjacent: site.adjacent(),
            observable_orders: site.observable_orders().to_vec(),
            fault_row: site.fault_row(),
            scope: site.scope(),
            module: site.module().to_owned(),
            read_only: site.is_read_only(),
            sub_effect_points: site
                .sub_effects()
                .iter()
                .map(|point| PointExport {
                    point: *point,
                    platform: point.platform(),
                    modes: point.modes().to_vec(),
                })
                .collect(),
            residue_classes: site
                .residue_classes()
                .iter()
                .map(|class| ResidueClassExport {
                    class: *class,
                    label: class.label(),
                    classified_as: class.classified_as(),
                    elements: site.residue_elements().to_vec(),
                })
                .collect(),
        })
        .collect()
}

/// `effect_sites.json`, pretty-printed for a gate report to attach.
pub fn effect_sites_json() -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&effect_sites())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::topology::events::TOPOLOGY_EVENT_KINDS;

    // -----------------------------------------------------------------------
    // The independent tables
    //
    // Every expected value below is read off `decisions.effect_site_inventory`,
    // `decisions.resource_accounting.rows` and `transaction_fault_matrix` and
    // written here as a literal. Nothing in this module computes an expected
    // value by calling the function under test: `row()` is never its own
    // oracle, and neither is `fault_row()`, `scope()` or `adjacent()`.
    //
    // The tables are keyed by dotted name and asserted *total* over
    // `EffectSiteId::all()`, so a site added without a table row fails rather
    // than passing unchecked.
    // -----------------------------------------------------------------------

    /// `(site, row, fault row, scope, adjacency)` for every site in the
    /// inventory.
    ///
    /// One table rather than four, so that a site can only be missing from all
    /// four at once — four separate lists would let one of them quietly lose a
    /// row while the totality assertion on the others still passed.
    #[allow(clippy::type_complexity)]
    fn expected_attributes() -> Vec<(&'static str, ResourceRow, FaultRow, SiteScope, Adjacent)> {
        use Adjacent::{After, Before, None as NoAdjacent};
        use DurableEvent as E;
        use FaultRow as F;
        use ResourceRow as R;
        use SiteScope::{Legacy, Shared, Topology};
        vec![
            // Worktree: R9 task, R10 staging, R18 execution root.
            (
                "Worktree.CreateExecutionRoot",
                R::R18,
                F::TRunstart,
                Topology,
                Before(E::RunStarted),
            ),
            (
                "Worktree.RemoveExecutionRoot",
                R::R18,
                F::TFinalize,
                Topology,
                After(E::RunFinished),
            ),
            (
                "Worktree.WriteIntent",
                R::R9,
                F::TDispatch,
                Topology,
                After(E::TaskDispatched),
            ),
            (
                "Worktree.Add",
                R::R9,
                F::TDispatch,
                Topology,
                After(E::TaskDispatched),
            ),
            (
                "Worktree.Verify",
                R::R9,
                F::TRetry,
                Topology,
                Before(E::AttemptStarted),
            ),
            (
                "Worktree.Remove",
                R::R9,
                F::TScrub,
                Topology,
                After(E::TaskCandidateCreated),
            ),
            (
                "Worktree.RemoveIntent",
                R::R9,
                F::TScrub,
                Topology,
                After(E::TaskCandidateCreated),
            ),
            (
                "Worktree.WriteStagingIntent",
                R::R10,
                F::TProposal,
                Topology,
                Before(E::MergeVerificationStarted),
            ),
            (
                "Worktree.AddStaging",
                R::R10,
                F::TProposal,
                Topology,
                Before(E::MergeVerificationStarted),
            ),
            (
                "Worktree.RemoveStaging",
                R::R10,
                F::TProposal,
                Topology,
                After(E::TaskMerged),
            ),
            (
                "Worktree.RemoveStagingIntent",
                R::R10,
                F::TProposal,
                Topology,
                After(E::TaskMerged),
            ),
            // Snapshot: R24 throughout.
            (
                "Snapshot.WriteIntent",
                R::R24,
                F::TAttempt,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Snapshot.Add",
                R::R24,
                F::TAttempt,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Snapshot.Remove",
                R::R24,
                F::TScrub,
                Topology,
                Before(E::AttemptFinished),
            ),
            (
                "Snapshot.RemoveIntent",
                R::R24,
                F::TScrub,
                Topology,
                Before(E::AttemptFinished),
            ),
            // Ref: R11 candidates, R12 prepared pin, R23 candidate pin, R21 integration.
            (
                "Ref.CreateIntegration",
                R::R21,
                F::TRunstart,
                Topology,
                Before(E::RunStarted),
            ),
            (
                "Ref.CompareAndSwapIntegration",
                R::R21,
                F::TFast,
                Topology,
                Before(E::TaskMerged),
            ),
            (
                "Ref.CreateCandidates",
                R::R11,
                F::TCandRef,
                Topology,
                Before(E::TaskCandidateCreated),
            ),
            (
                "Ref.DeleteCandidatesRef",
                R::R11,
                F::TFinalize,
                Topology,
                After(E::RunFinished),
            ),
            (
                "Ref.PinCandidatePrepared",
                R::R23,
                F::TCandObj,
                Topology,
                Before(E::CandidatePrepared),
            ),
            (
                "Ref.DeleteCandidatePin",
                R::R23,
                F::TCandRef,
                Topology,
                After(E::TaskCandidateCreated),
            ),
            (
                "Ref.PinPrepared",
                R::R12,
                F::TProposal,
                Topology,
                Before(E::MergeVerificationStarted),
            ),
            (
                "Ref.DeletePreparedPin",
                R::R12,
                F::TFinalize,
                Topology,
                After(E::TaskMerged),
            ),
            // Object: the row that references the object immediately after the effect.
            (
                "Object.CandidateStage",
                R::R9,
                F::TAttempt,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Object.CandidateWriteTree",
                R::R9,
                F::TAttempt,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Object.SnapshotCommitTree",
                R::R27,
                F::TAttempt,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Object.CandidateCommitTree",
                R::R27,
                F::TCandObj,
                Topology,
                Before(E::CandidatePrepared),
            ),
            (
                "Object.ProposalCherryPick",
                R::R10,
                F::TProposal,
                Topology,
                Before(E::MergeVerificationStarted),
            ),
            (
                "Object.RepairMaterialize",
                R::R9,
                F::TRepairDispatch,
                Topology,
                After(E::TaskDispatched),
            ),
            // RunDir: all R21, the packet says so in as many words.
            (
                "RunDir.CreatePublicDir",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.StageMarker",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.PublishMarker",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.RemoveMarker",
                R::R21,
                F::TRunstart,
                Shared,
                After(E::RunStarted),
            ),
            (
                "RunDir.CreatePrivateDir",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.StageOwnerRecord",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.PublishOwnerRecord",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.StageCommitRecord",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.PublishCommitRecord",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.WritePlan",
                R::R21,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "RunDir.WriteReport",
                R::R21,
                F::TFinalize,
                Shared,
                After(E::RunFinished),
            ),
            (
                "RunDir.WriteQuestionPayload",
                R::R21,
                F::TFailed,
                Shared,
                Before(E::QuestionRaised),
            ),
            (
                "RunDir.RemovePrivateHusk",
                R::R21,
                F::TRunstart,
                Shared,
                NoAdjacent,
            ),
            (
                "RunDir.RemovePublicHusk",
                R::R21,
                F::TRunstart,
                Shared,
                NoAdjacent,
            ),
            // Event: R21, T-APPEND, Shared but for the two legacy sites.
            ("Event.OpenLog", R::R21, F::TAppend, Shared, NoAdjacent),
            (
                "Event.ProvePrefixStable",
                R::R21,
                F::TAppend,
                Shared,
                NoAdjacent,
            ),
            ("Event.AppendFirst", R::R21, F::TAppend, Shared, NoAdjacent),
            ("Event.Append", R::R21, F::TAppend, Shared, NoAdjacent),
            (
                "Event.AppendInformational",
                R::R21,
                F::TAppend,
                Shared,
                NoAdjacent,
            ),
            (
                "Event.LegacyOpenLog",
                R::R21,
                F::TAppend,
                Legacy,
                NoAdjacent,
            ),
            ("Event.LegacyAppend", R::R21, F::TAppend, Legacy, NoAdjacent),
            // Answer: R21, T-ANSWER.
            (
                "Answer.StageWrite",
                R::R21,
                F::TAnswer,
                Shared,
                Before(E::QuestionAnswered),
            ),
            (
                "Answer.PublishRename",
                R::R21,
                F::TAnswer,
                Shared,
                Before(E::QuestionAnswered),
            ),
            (
                "Answer.Ingest",
                R::R21,
                F::TAnswer,
                Shared,
                Before(E::QuestionAnswered),
            ),
            // Lock: R17 holds, R25 the file, R28 the observed reaper hold.
            (
                "Lock.AcquireRun",
                R::R17,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "Lock.AcquireWorktree",
                R::R17,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "Lock.ProbeCleanupExclusive",
                R::R17,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "Lock.Release",
                R::R17,
                F::TFinalize,
                Shared,
                After(E::RunFinished),
            ),
            (
                "Lock.CreateWorktreeLockFile",
                R::R25,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            (
                "Lock.ObserveCleanupHold",
                R::R28,
                F::TRunstart,
                Shared,
                Before(E::RunStarted),
            ),
            // Report.
            (
                "Report.Write",
                R::R21,
                F::TFinalize,
                Shared,
                After(E::RunFinished),
            ),
            // Process: R22.
            (
                "Process.Spawn",
                R::R22,
                F::TAttempt,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Process.Terminate",
                R::R22,
                F::TAttempt,
                Topology,
                Before(E::AttemptFinished),
            ),
            // Container: R19 the view, R26 the container.
            (
                "Container.WriteIntent",
                R::R26,
                F::TContainer,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Container.Create",
                R::R26,
                F::TContainer,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Container.Start",
                R::R26,
                F::TContainer,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Container.MountGitView",
                R::R19,
                F::TContainer,
                Topology,
                After(E::AttemptStarted),
            ),
            (
                "Container.Stop",
                R::R26,
                F::TContainer,
                Topology,
                Before(E::AttemptFinished),
            ),
            (
                "Container.Remove",
                R::R26,
                F::TContainer,
                Topology,
                Before(E::AttemptFinished),
            ),
            (
                "Container.UnmountGitView",
                R::R19,
                F::TContainer,
                Topology,
                Before(E::AttemptFinished),
            ),
            (
                "Container.RemoveIntent",
                R::R26,
                F::TContainer,
                Topology,
                Before(E::AttemptFinished),
            ),
        ]
    }

    /// Every site the packet names in prose, by dotted name.
    ///
    /// Kept separate from [`expected_attributes`] on purpose: that table is
    /// this module's own inventory, and this list is the packet's. A site that
    /// exists in the enums and is missing from the design would pass the first
    /// and fail nothing; this list is what makes the second direction — the
    /// design names it and the enums must have it — an assertion.
    const NAMED_IN_THE_DESIGN: &[&str] = &[
        "RunDir.CreatePublicDir",
        "RunDir.StageMarker",
        "RunDir.PublishMarker",
        "RunDir.RemoveMarker",
        "RunDir.CreatePrivateDir",
        "RunDir.StageOwnerRecord",
        "RunDir.PublishOwnerRecord",
        "RunDir.StageCommitRecord",
        "RunDir.PublishCommitRecord",
        "RunDir.WritePlan",
        "RunDir.WriteReport",
        "RunDir.WriteQuestionPayload",
        "RunDir.RemovePrivateHusk",
        "RunDir.RemovePublicHusk",
        "Event.OpenLog",
        "Event.ProvePrefixStable",
        "Event.AppendFirst",
        "Event.Append",
        "Event.AppendInformational",
        "Answer.StageWrite",
        "Answer.PublishRename",
        "Answer.Ingest",
        "Lock.AcquireRun",
        "Lock.AcquireWorktree",
        "Lock.ProbeCleanupExclusive",
        "Lock.Release",
        "Lock.ObserveCleanupHold",
        "Object.CandidateStage",
        "Object.CandidateWriteTree",
        "Object.SnapshotCommitTree",
        "Object.CandidateCommitTree",
        "Object.ProposalCherryPick",
        "Object.RepairMaterialize",
        "Worktree.Verify",
        "Worktree.Remove",
        "Worktree.Add",
        "Worktree.AddStaging",
        "Snapshot.Add",
        "Snapshot.Remove",
        "Ref.PinCandidatePrepared",
        "Ref.PinPrepared",
        "Ref.DeleteCandidatesRef",
        "Ref.DeleteCandidatePin",
        "Ref.DeletePreparedPin",
        "Container.Create",
        "Container.Start",
        "Process.Spawn",
    ];

    fn attribute_map() -> BTreeMap<&'static str, (ResourceRow, FaultRow, SiteScope, Adjacent)> {
        expected_attributes()
            .into_iter()
            .map(|(name, row, fault, scope, adjacent)| (name, (row, fault, scope, adjacent)))
            .collect()
    }

    // -----------------------------------------------------------------------
    // The enums
    // -----------------------------------------------------------------------

    #[test]
    fn every_group_enums_all_slice_lists_every_one_of_its_variants() {
        // Each block's match is exhaustive over its enum, so a new variant
        // fails to compile until it is listed here; the assertion then ties it
        // to a distinct slot of `ALL`, so a variant that compiles is one `ALL`
        // also lists. The length pins the count against a duplicate.
        macro_rules! tie {
            ($enum:ty, $count:expr, $slot:expr) => {{
                let all = <$enum>::ALL;
                assert_eq!(
                    all.len(),
                    $count,
                    concat!(stringify!($enum), "::ALL length")
                );
                let mut seen = BTreeSet::new();
                for site in all {
                    let position: usize = $slot(*site);
                    assert_eq!(
                        all[position], *site,
                        concat!(stringify!($enum), " is not at the slot it claims")
                    );
                    assert!(seen.insert(position), "two variants claim one slot");
                }
                assert_eq!(seen.len(), $count);
            }};
        }

        tie!(WorktreeSite, 11, |site| match site {
            WorktreeSite::CreateExecutionRoot => 0,
            WorktreeSite::RemoveExecutionRoot => 1,
            WorktreeSite::WriteIntent => 2,
            WorktreeSite::Add => 3,
            WorktreeSite::Verify => 4,
            WorktreeSite::Remove => 5,
            WorktreeSite::RemoveIntent => 6,
            WorktreeSite::WriteStagingIntent => 7,
            WorktreeSite::AddStaging => 8,
            WorktreeSite::RemoveStaging => 9,
            WorktreeSite::RemoveStagingIntent => 10,
        });
        tie!(SnapshotSite, 4, |site| match site {
            SnapshotSite::WriteIntent => 0,
            SnapshotSite::Add => 1,
            SnapshotSite::Remove => 2,
            SnapshotSite::RemoveIntent => 3,
        });
        tie!(RefSite, 8, |site| match site {
            RefSite::CreateIntegration => 0,
            RefSite::CompareAndSwapIntegration => 1,
            RefSite::CreateCandidates => 2,
            RefSite::DeleteCandidatesRef => 3,
            RefSite::PinCandidatePrepared => 4,
            RefSite::DeleteCandidatePin => 5,
            RefSite::PinPrepared => 6,
            RefSite::DeletePreparedPin => 7,
        });
        tie!(ObjectSite, 6, |site| match site {
            ObjectSite::CandidateStage => 0,
            ObjectSite::CandidateWriteTree => 1,
            ObjectSite::SnapshotCommitTree => 2,
            ObjectSite::CandidateCommitTree => 3,
            ObjectSite::ProposalCherryPick => 4,
            ObjectSite::RepairMaterialize => 5,
        });
        tie!(RunDirSite, 14, |site| match site {
            RunDirSite::CreatePublicDir => 0,
            RunDirSite::StageMarker => 1,
            RunDirSite::PublishMarker => 2,
            RunDirSite::RemoveMarker => 3,
            RunDirSite::CreatePrivateDir => 4,
            RunDirSite::StageOwnerRecord => 5,
            RunDirSite::PublishOwnerRecord => 6,
            RunDirSite::StageCommitRecord => 7,
            RunDirSite::PublishCommitRecord => 8,
            RunDirSite::WritePlan => 9,
            RunDirSite::WriteReport => 10,
            RunDirSite::WriteQuestionPayload => 11,
            RunDirSite::RemovePrivateHusk => 12,
            RunDirSite::RemovePublicHusk => 13,
        });
        tie!(EventSite, 7, |site| match site {
            EventSite::OpenLog => 0,
            EventSite::ProvePrefixStable => 1,
            EventSite::AppendFirst => 2,
            EventSite::Append => 3,
            EventSite::AppendInformational => 4,
            EventSite::LegacyOpenLog => 5,
            EventSite::LegacyAppend => 6,
        });
        tie!(AnswerSite, 3, |site| match site {
            AnswerSite::StageWrite => 0,
            AnswerSite::PublishRename => 1,
            AnswerSite::Ingest => 2,
        });
        tie!(LockSite, 6, |site| match site {
            LockSite::AcquireRun => 0,
            LockSite::AcquireWorktree => 1,
            LockSite::ProbeCleanupExclusive => 2,
            LockSite::Release => 3,
            LockSite::CreateWorktreeLockFile => 4,
            LockSite::ObserveCleanupHold => 5,
        });
        tie!(ReportSite, 1, |site| match site {
            ReportSite::Write => 0,
        });
        tie!(ProcessSite, 2, |site| match site {
            ProcessSite::Spawn => 0,
            ProcessSite::Terminate => 1,
        });
        tie!(ContainerSite, 8, |site| match site {
            ContainerSite::WriteIntent => 0,
            ContainerSite::Create => 1,
            ContainerSite::Start => 2,
            ContainerSite::MountGitView => 3,
            ContainerSite::Stop => 4,
            ContainerSite::Remove => 5,
            ContainerSite::UnmountGitView => 6,
            ContainerSite::RemoveIntent => 7,
        });
    }

    #[test]
    fn the_inventory_is_the_eleven_groups_and_every_one_of_them_has_sites() {
        assert_eq!(FunnelGroup::ALL.len(), 11);
        let sites = EffectSiteId::all();
        let mut by_group: BTreeMap<FunnelGroup, usize> = BTreeMap::new();
        for site in &sites {
            *by_group.entry(site.group()).or_default() += 1;
        }
        for group in FunnelGroup::ALL {
            assert!(
                by_group.get(group).copied().unwrap_or_default() > 0,
                "{group} declares no sites"
            );
        }
        assert_eq!(by_group.len(), 11, "a group with no sites at all");
        // Every dotted name is unique: two sites sharing one would make the
        // wire form ambiguous and `from_name` arbitrary.
        let names: BTreeSet<String> = sites.iter().map(|site| site.name()).collect();
        assert_eq!(names.len(), sites.len(), "two sites share a dotted name");
        // The site's group prefix is its group's own name, not a second copy.
        for site in &sites {
            assert!(
                site.name()
                    .starts_with(&format!("{}.", site.group().name())),
                "{} is not named for its group",
                site.name()
            );
        }
    }

    #[test]
    fn every_group_names_the_funnel_module_the_design_confines_it_to() {
        // From `mechanism`'s funnel-module list, written out here rather than
        // read back from `module()`.
        let expected = [
            (FunnelGroup::Worktree, "src/workspace_manager.rs"),
            (FunnelGroup::Snapshot, "src/workspace_manager.rs"),
            (FunnelGroup::Ref, "src/workspace_manager.rs"),
            (FunnelGroup::Object, "src/workspace_manager.rs"),
            (FunnelGroup::RunDir, "src/rundir.rs"),
            (FunnelGroup::Event, "src/events/log.rs"),
            (FunnelGroup::Answer, "src/interaction.rs"),
            (FunnelGroup::Lock, "src/rundir.rs"),
            (FunnelGroup::Report, "src/util.rs"),
            (FunnelGroup::Process, "src/runner/host.rs"),
            (FunnelGroup::Container, "src/runner/container.rs"),
        ];
        assert_eq!(expected.len(), FunnelGroup::ALL.len());
        for (group, module) in expected {
            assert_eq!(group.module(), module, "{group}");
        }
        // A site's module is its group's; nothing invents a per-site one.
        for site in EffectSiteId::all() {
            assert_eq!(site.module(), site.group().module(), "{site}");
        }
        // The legacy allowlist may never contain a topology module, so no
        // Topology-scoped site may name one of the modules PR5 freezes.
        for site in EffectSiteId::all() {
            if site.scope() == SiteScope::Topology {
                assert!(
                    site.module().starts_with("src/topology/")
                        || site.module().starts_with("src/runner/")
                        || site.module() == "src/workspace_manager.rs",
                    "{site} is Topology-scoped but lives in {}",
                    site.module()
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rows, fault rows, scope, adjacency
    // -----------------------------------------------------------------------

    #[test]
    fn every_site_carries_the_row_fault_row_scope_and_adjacency_the_design_gives_it() {
        let table = attribute_map();
        let sites = EffectSiteId::all();
        assert_eq!(
            table.len(),
            sites.len(),
            "the expected-attribute table and the inventory are different sizes"
        );
        for site in &sites {
            let name = site.name();
            let (row, fault, scope, adjacent) = *table
                .get(name.as_str())
                .unwrap_or_else(|| panic!("{name} has no expected-attribute row"));
            assert_eq!(site.row(), row, "{name} row");
            assert_eq!(site.fault_row(), fault, "{name} fault row");
            assert_eq!(site.scope(), scope, "{name} scope");
            assert_eq!(site.adjacent(), adjacent, "{name} adjacency");
        }
        // Total in the other direction too: a table row naming a site that
        // does not exist is a table that stopped describing the enums.
        for name in table.keys() {
            EffectSiteId::from_name(name)
                .unwrap_or_else(|error| panic!("expected-attribute table: {error}"));
        }
    }

    #[test]
    fn every_site_the_design_names_in_prose_exists_in_the_enums() {
        for name in NAMED_IN_THE_DESIGN {
            let site = EffectSiteId::from_name(name)
                .unwrap_or_else(|error| panic!("the design names {name}: {error}"));
            assert_eq!(&site.name(), name);
        }
        // The fourteen R21 run-directory sites the packet lists with "(all
        // R21)" after them, as one statement rather than fourteen.
        let rundir: Vec<EffectSiteId> = RunDirSite::ALL
            .iter()
            .copied()
            .map(EffectSiteId::RunDir)
            .collect();
        assert_eq!(rundir.len(), 14);
        for site in rundir {
            assert_eq!(site.row(), ResourceRow::R21, "{site}");
        }
    }

    #[test]
    fn the_packets_group_level_row_statements_hold_over_whole_groups() {
        // Each of these is a sentence of `identity`, asserted over the whole
        // group rather than site by site — a per-site table can agree with a
        // mistake, a group-wide invariant cannot.
        let rows = |sites: Vec<EffectSiteId>| -> BTreeSet<ResourceRow> {
            sites.into_iter().map(EffectSiteId::row).collect()
        };
        let group = |wanted: FunnelGroup| -> Vec<EffectSiteId> {
            EffectSiteId::all()
                .into_iter()
                .filter(|site| site.group() == wanted)
                .collect()
        };

        // "Ref.* (R11/R12/R23/R21)"
        assert_eq!(
            rows(group(FunnelGroup::Ref)),
            BTreeSet::from([
                ResourceRow::R11,
                ResourceRow::R12,
                ResourceRow::R21,
                ResourceRow::R23
            ])
        );
        // "Worktree.*/Snapshot.* (R9/R10/R24/R18)"
        let mut worktree_and_snapshot = group(FunnelGroup::Worktree);
        worktree_and_snapshot.extend(group(FunnelGroup::Snapshot));
        assert_eq!(
            rows(worktree_and_snapshot),
            BTreeSet::from([
                ResourceRow::R9,
                ResourceRow::R10,
                ResourceRow::R18,
                ResourceRow::R24
            ])
        );
        // "Process.* (R22)"
        assert_eq!(
            rows(group(FunnelGroup::Process)),
            BTreeSet::from([ResourceRow::R22])
        );
        // "Container.* (R19/R26)"
        assert_eq!(
            rows(group(FunnelGroup::Container)),
            BTreeSet::from([ResourceRow::R19, ResourceRow::R26])
        );
        // "Lock.AcquireRun, ..., Lock.Release (R17; the worktree lock file
        // creation maps to R25; the reaper hold is observed through
        // Lock.ObserveCleanupHold, R28)"
        assert_eq!(
            rows(group(FunnelGroup::Lock)),
            BTreeSet::from([ResourceRow::R17, ResourceRow::R25, ResourceRow::R28])
        );
        assert_eq!(
            EffectSiteId::Lock(LockSite::CreateWorktreeLockFile).row(),
            ResourceRow::R25
        );
        assert_eq!(
            EffectSiteId::Lock(LockSite::ObserveCleanupHold).row(),
            ResourceRow::R28
        );
        // "Answer.StageWrite and Answer.PublishRename (... R21), Answer.Ingest"
        // and the whole Event and Report groups.
        for wanted in [FunnelGroup::Answer, FunnelGroup::Event, FunnelGroup::Report] {
            assert_eq!(
                rows(group(wanted)),
                BTreeSet::from([ResourceRow::R21]),
                "{wanted}"
            );
        }
        // "unreferenced, R27, until ..." for exactly the two commit-tree sites,
        // and no other Object site.
        let r27: BTreeSet<String> = group(FunnelGroup::Object)
            .into_iter()
            .filter(|site| site.row() == ResourceRow::R27)
            .map(|site| site.name())
            .collect();
        assert_eq!(
            r27,
            BTreeSet::from([
                "Object.SnapshotCommitTree".to_owned(),
                "Object.CandidateCommitTree".to_owned()
            ])
        );
    }

    #[test]
    fn every_external_and_process_local_row_has_at_least_one_claimed_site() {
        // `outputs`: "every such row has at least one Topology/Shared site".
        let claimed: BTreeSet<ResourceRow> = EffectSiteId::claimed()
            .into_iter()
            .map(|s| s.row())
            .collect();
        assert_eq!(ResourceRow::ALL.len(), 15);
        for row in ResourceRow::ALL {
            assert!(claimed.contains(row), "{row} has no Topology/Shared site");
        }
        // And nothing outside the fifteen: the logical fold/broker rows take no
        // effect-site mapping, which is why they are not in the enum at all.
        for site in EffectSiteId::all() {
            assert!(ResourceRow::ALL.contains(&site.row()), "{site}");
        }
        // The domains, from `enforcement_domains`, written out independently.
        for (row, domain) in [
            (ResourceRow::R9, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R10, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R11, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R12, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R17, EnforcementDomain::ProcessLocalOs),
            (ResourceRow::R18, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R19, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R21, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R22, EnforcementDomain::ProcessLocalOs),
            (ResourceRow::R23, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R24, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R25, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R26, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R27, EnforcementDomain::ExternalPhysical),
            (ResourceRow::R28, EnforcementDomain::ProcessLocalOs),
        ] {
            assert_eq!(row.domain(), domain, "{row}");
        }
    }

    #[test]
    fn every_fault_matrix_row_exists_and_the_ones_sites_use_are_used() {
        assert_eq!(FaultRow::ALL.len(), 21, "the matrix has twenty-one rows");
        let ids: BTreeSet<&str> = FaultRow::ALL.iter().map(|row| row.id()).collect();
        assert_eq!(ids.len(), 21, "two rows share an id");
        for id in [
            "T-RUNSTART",
            "T-DISPATCH",
            "T-ATTEMPT",
            "T-RETRY",
            "T-CAND-OBJ",
            "T-CAND-REF",
            "T-SCRUB",
            "T-FAILED",
            "T-RETAINED",
            "T-FAST",
            "T-PROPOSAL",
            "T-VERIFY",
            "T-PREPARED",
            "T-REJECT",
            "T-REPAIR-DISPATCH",
            "T-CONTAINER",
            "T-APPEND",
            "T-ANSWER",
            "T-FINISH",
            "T-FINALIZE",
            "T-RESUME",
        ] {
            assert!(ids.contains(id), "the matrix row {id} has no variant");
        }
        // The Object sites map to exactly the rows `structure` says they map
        // to: "T-ATTEMPT (b')/(b)/(c), T-CAND-OBJ (a), T-PROPOSAL (a')/(a),
        // T-REPAIR-DISPATCH, and T-DISPATCH" — the last of which is the
        // worktree the objects land behind, not an Object site itself.
        let object_rows: BTreeSet<FaultRow> = ObjectSite::ALL
            .iter()
            .map(|site| EffectSiteId::Object(*site).fault_row())
            .collect();
        assert_eq!(
            object_rows,
            BTreeSet::from([
                FaultRow::TAttempt,
                FaultRow::TCandObj,
                FaultRow::TProposal,
                FaultRow::TRepairDispatch
            ])
        );
        assert_eq!(
            EffectSiteId::Worktree(WorktreeSite::Add).fault_row(),
            FaultRow::TDispatch
        );
        // Every Event site is T-APPEND, as `structure` says in as many words.
        for site in EventSite::ALL {
            assert_eq!(
                EffectSiteId::Event(*site).fault_row(),
                FaultRow::TAppend,
                "{site:?}"
            );
        }
    }

    #[test]
    fn the_adjacency_vocabulary_is_the_logs_vocabulary() {
        // A1 froze the twenty-four tags; this module mirrors them, and the
        // mirror is checked rather than assumed. A tag renamed in `events.rs`
        // has to break here.
        assert_eq!(DurableEvent::ALL.len(), TOPOLOGY_EVENT_KINDS.len());
        for (mine, theirs) in DurableEvent::ALL.iter().zip(TOPOLOGY_EVENT_KINDS.iter()) {
            assert_eq!(&mine.kind(), theirs, "the vocabularies diverged");
        }
        // Every adjacency names one of them.
        for site in EffectSiteId::all() {
            if let Some(kind) = site.adjacent().event() {
                assert!(
                    TOPOLOGY_EVENT_KINDS.contains(&kind.kind()),
                    "{site} is ordered against `{kind}`, which the log never writes"
                );
            }
        }
        // Exactly the Event group and the two husk-removal sites have no
        // adjacency: an append site *is* the event, and a census runs outside
        // any run's log.
        let unordered: BTreeSet<String> = EffectSiteId::all()
            .into_iter()
            .filter(|site| site.adjacent() == Adjacent::None)
            .map(|site| site.name())
            .collect();
        let mut expected: BTreeSet<String> = EventSite::ALL
            .iter()
            .map(|site| EffectSiteId::Event(*site).name())
            .collect();
        expected.insert("RunDir.RemovePrivateHusk".to_owned());
        expected.insert("RunDir.RemovePublicHusk".to_owned());
        assert_eq!(unordered, expected);
    }

    #[test]
    fn an_adjacency_before_a_kind_is_not_the_adjacency_after_it() {
        // `effect_site_inventory.identity` requires adjacency to be "exactly
        // Before(kind), After(kind), or None" — so the direction is half the
        // value, and every test that compares adjacencies is trusting that
        // `PartialEq` reads it. Nothing said so: replace the derive with
        // equality over `event()` alone and `Before(run_finished)` becomes
        // equal to `After(run_finished)`, after which an opposite-direction
        // site satisfies every equality-based check in the module, including
        // the attribute table's.
        //
        // Written against the vocabulary rather than against a site, so it
        // holds independently of what any site's `adjacent()` happens to say.
        for kind in DurableEvent::ALL {
            let before = Adjacent::Before(*kind);
            let after = Adjacent::After(*kind);

            assert_ne!(before, after, "{kind}");
            assert!(!before.eq(&after), "{kind}");
            // They agree about the event and differ anyway: the event is the
            // part a direction-blind equality keeps, so a test that compared
            // only `event()` would pass under the mutation.
            assert_eq!(before.event(), after.event());
            assert_eq!(before.event(), Some(*kind));
            assert_ne!(before, Adjacent::None, "{kind}");
            assert_ne!(after, Adjacent::None, "{kind}");
            assert_eq!(before, Adjacent::Before(*kind));
            assert_eq!(after, Adjacent::After(*kind));

            // And the wire forms differ, so the direction survives a round
            // trip through the artifacts a gate reads rather than only through
            // the Rust value.
            let before_json = serde_json::to_string(&before).expect("adjacency serializes");
            let after_json = serde_json::to_string(&after).expect("adjacency serializes");
            assert_ne!(before_json, after_json, "{kind}");
            assert!(before_json.contains("before"), "{before_json}");
            assert!(after_json.contains("after"), "{after_json}");
            assert_eq!(
                serde_json::from_str::<Adjacent>(&before_json).expect("round trip"),
                before
            );
            assert_eq!(
                serde_json::from_str::<Adjacent>(&after_json).expect("round trip"),
                after
            );
            // The forged direction: the other form's JSON does not read back
            // as this one.
            assert_ne!(
                serde_json::from_str::<Adjacent>(&after_json).expect("round trip"),
                before
            );
        }

        // Two different kinds in the same direction are unequal too, so the
        // above is not passing on a `PartialEq` that reads only the direction.
        assert_ne!(
            Adjacent::Before(DurableEvent::RunStarted),
            Adjacent::Before(DurableEvent::RunFinished)
        );
        assert_ne!(
            Adjacent::After(DurableEvent::RunStarted),
            Adjacent::After(DurableEvent::RunFinished)
        );
        assert_eq!(Adjacent::None, Adjacent::None);
        assert_eq!(Adjacent::None.event(), None);

        // The consequence the framework actually depends on: the two
        // directions are the two observable orders, and they are different
        // orders.
        for kind in DurableEvent::ALL {
            assert_ne!(
                observable_orders_of(Adjacent::Before(*kind)),
                observable_orders_of(Adjacent::After(*kind)),
                "{kind}"
            );
        }
    }

    /// The orders an adjacency admits, read off the adjacency alone.
    ///
    /// `EffectSiteId::observable_orders` is a method on a site; this is the
    /// same rule applied to the adjacency by itself, so the test above does
    /// not need a site that happens to carry the direction it is testing.
    fn observable_orders_of(adjacent: Adjacent) -> &'static [ObservableOrder] {
        match adjacent {
            Adjacent::Before(_) => &[ObservableOrder::EffectBeforeEvent],
            Adjacent::After(_) => &[ObservableOrder::EventBeforeEffect],
            Adjacent::None => &[],
        }
    }

    #[test]
    fn the_observable_orders_are_the_ones_the_adjacency_admits() {
        // Crossed over every site rather than sampled: the relation is
        // "`Before` admits effect-before-event, `After` admits
        // event-before-effect, no adjacency admits neither", and a site that
        // broke it would be one whose registry entry could carry an order the
        // design never produced.
        let mut before = 0;
        let mut after = 0;
        let mut neither = 0;
        for site in EffectSiteId::all() {
            match site.adjacent() {
                Adjacent::Before(_) => {
                    assert_eq!(
                        site.observable_orders(),
                        &[ObservableOrder::EffectBeforeEvent],
                        "{site}"
                    );
                    before += 1;
                }
                Adjacent::After(_) => {
                    assert_eq!(
                        site.observable_orders(),
                        &[ObservableOrder::EventBeforeEffect],
                        "{site}"
                    );
                    after += 1;
                }
                Adjacent::None => {
                    assert!(site.observable_orders().is_empty(), "{site}");
                    neither += 1;
                }
            }
        }
        // All three arms are populated, so the crossing is a crossing.
        assert!(
            before > 0 && after > 0 && neither > 0,
            "{before}/{after}/{neither}"
        );
    }

    #[test]
    fn only_the_legacy_event_sites_are_outside_the_claim() {
        let unclaimed: BTreeSet<String> = EffectSiteId::all()
            .into_iter()
            .filter(|site| !site.scope().is_claimed())
            .map(|site| site.name())
            .collect();
        assert_eq!(
            unclaimed,
            BTreeSet::from([
                "Event.LegacyOpenLog".to_owned(),
                "Event.LegacyAppend".to_owned()
            ]),
            "`scope` puts only schema-1..3 callers of a shared funnel outside the claim"
        );
        assert!(SiteScope::Topology.is_claimed());
        assert!(SiteScope::Shared.is_claimed());
        assert!(!SiteScope::Legacy.is_claimed());
        // Both claimed scopes are populated, and each by more than one group.
        let topology: BTreeSet<FunnelGroup> = EffectSiteId::all()
            .into_iter()
            .filter(|site| site.scope() == SiteScope::Topology)
            .map(|site| site.group())
            .collect();
        let shared: BTreeSet<FunnelGroup> = EffectSiteId::all()
            .into_iter()
            .filter(|site| site.scope() == SiteScope::Shared)
            .map(|site| site.group())
            .collect();
        assert_eq!(
            topology,
            BTreeSet::from([
                FunnelGroup::Worktree,
                FunnelGroup::Snapshot,
                FunnelGroup::Ref,
                FunnelGroup::Object,
                FunnelGroup::Process,
                FunnelGroup::Container
            ])
        );
        assert_eq!(
            shared,
            BTreeSet::from([
                FunnelGroup::RunDir,
                FunnelGroup::Event,
                FunnelGroup::Answer,
                FunnelGroup::Lock,
                FunnelGroup::Report
            ])
        );
    }

    #[test]
    fn the_read_only_sites_are_the_four_the_design_says_perform_no_effect() {
        let read_only: BTreeSet<String> = EffectSiteId::all()
            .into_iter()
            .filter(|site| site.is_read_only())
            .map(|site| site.name())
            .collect();
        assert_eq!(
            read_only,
            BTreeSet::from([
                "Worktree.Verify".to_owned(),
                "Event.ProvePrefixStable".to_owned(),
                "Answer.Ingest".to_owned(),
                "Lock.ObserveCleanupHold".to_owned(),
            ]),
            "a read-only observation performs no effect and an effect site is not one"
        );
        // A read-only site still has both hook phases — it is a funnel API and
        // the funnel calls the hooks — but it registers no residue class,
        // because there is nothing for a fault to leave behind.
        for name in &read_only {
            let site = EffectSiteId::from_name(name).expect("named above");
            assert!(site.residue_classes().is_empty(), "{name}");
        }
    }

    // -----------------------------------------------------------------------
    // Sub-effect points
    // -----------------------------------------------------------------------

    #[test]
    fn every_sub_effect_point_supports_the_modes_and_platform_the_design_gives_it() {
        use InjectionMode::{ErrorReturn, Kill};
        use Platform::{Any, Unix, Windows};
        // Written from `command_internal_sub_effects` and
        // `containment_sub_effects`, not read back from `modes()`.
        let expected: &[(SubEffectPoint, &[InjectionMode], Platform)] = &[
            (SubEffectPoint::IdUnread, &[Kill], Any),
            (SubEffectPoint::Written, &[Kill, ErrorReturn], Any),
            (SubEffectPoint::WrittenFull, &[ErrorReturn], Any),
            (SubEffectPoint::Synced, &[Kill, ErrorReturn], Any),
            (SubEffectPoint::Create, &[Kill, ErrorReturn], Any),
            (SubEffectPoint::TruncateTornTail, &[Kill, ErrorReturn], Any),
            (SubEffectPoint::SyncPrefix, &[Kill, ErrorReturn], Any),
            (
                SubEffectPoint::AmbientJobJoined,
                &[Kill, ErrorReturn],
                Windows,
            ),
            (SubEffectPoint::CreatedSuspended, &[Kill], Windows),
            (SubEffectPoint::PrivateJobAssigned, &[Kill], Windows),
            (SubEffectPoint::Resumed, &[Kill], Windows),
            (SubEffectPoint::ReaperStarted, &[Kill], Unix),
            (SubEffectPoint::PreExecPgidAndRegister, &[Kill], Unix),
            (SubEffectPoint::Exec, &[Kill], Unix),
            (SubEffectPoint::Registered, &[Kill], Unix),
        ];
        assert_eq!(expected.len(), SubEffectPoint::ALL.len());
        for (point, modes, platform) in expected {
            assert_eq!(point.modes(), *modes, "{point} modes");
            assert_eq!(point.platform(), *platform, "{point} platform");
            for mode in InjectionMode::ALL {
                assert_eq!(
                    point.supports(*mode),
                    modes.contains(mode),
                    "{point} {mode:?}"
                );
            }
        }
        // Kill is all but universal: a coordinator can die anywhere, so a
        // point that did not support it would generally be one the framework
        // could not model a crash at. `WrittenFull` is the single exception,
        // and it is one because a kill there is already a required coordinate
        // under another point rather than because it cannot happen.
        // `structure` tables "kill entries for Written (torn ...;
        // complete-unsynced ...) and Synced" — two kill entries for an append
        // site — and "error-return entries for Written-partial-then-Err,
        // Written-full-then-flush-Err, and Synced-Err" — three. A kill at
        // `WrittenFull` leaves the complete-unsynced prefix `Written`'s kill
        // entry covers, so declaring the mode would require a third kill entry
        // the design does not table.
        for point in SubEffectPoint::ALL {
            if *point == SubEffectPoint::WrittenFull {
                assert_eq!(point.modes(), &[ErrorReturn]);
                continue;
            }
            assert!(point.supports(Kill), "{point}");
        }
        // Both modes and all three platforms are represented, so the two
        // tables above are crossings rather than constants.
        let modes: BTreeSet<InjectionMode> = SubEffectPoint::ALL
            .iter()
            .flat_map(|point| point.modes().iter().copied())
            .collect();
        assert_eq!(modes.len(), 2);
        let platforms: BTreeSet<Platform> =
            SubEffectPoint::ALL.iter().map(|p| p.platform()).collect();
        assert_eq!(platforms.len(), 3);
    }

    #[test]
    fn the_sites_that_expose_points_are_the_ones_the_design_names() {
        let expected: &[(&str, &[SubEffectPoint])] = &[
            (
                "Event.OpenLog",
                &[
                    SubEffectPoint::Create,
                    SubEffectPoint::TruncateTornTail,
                    SubEffectPoint::SyncPrefix,
                ],
            ),
            (
                "Event.AppendFirst",
                &[
                    SubEffectPoint::Written,
                    SubEffectPoint::WrittenFull,
                    SubEffectPoint::Synced,
                ],
            ),
            (
                "Event.Append",
                &[
                    SubEffectPoint::Written,
                    SubEffectPoint::WrittenFull,
                    SubEffectPoint::Synced,
                ],
            ),
            (
                "Event.AppendInformational",
                &[
                    SubEffectPoint::Written,
                    SubEffectPoint::WrittenFull,
                    SubEffectPoint::Synced,
                ],
            ),
            ("Object.SnapshotCommitTree", &[SubEffectPoint::IdUnread]),
            ("Object.CandidateCommitTree", &[SubEffectPoint::IdUnread]),
            (
                "Process.Spawn",
                &[
                    SubEffectPoint::AmbientJobJoined,
                    SubEffectPoint::CreatedSuspended,
                    SubEffectPoint::PrivateJobAssigned,
                    SubEffectPoint::Resumed,
                    SubEffectPoint::ReaperStarted,
                    SubEffectPoint::PreExecPgidAndRegister,
                    SubEffectPoint::Exec,
                    SubEffectPoint::Registered,
                ],
            ),
        ];
        let named: BTreeSet<&str> = expected.iter().map(|(name, _)| *name).collect();
        for (name, points) in expected {
            let site = EffectSiteId::from_name(name).expect("a site the design names");
            assert_eq!(site.sub_effects(), *points, "{name}");
        }
        // Nothing else exposes one. `IdUnread` is "the two commit-tree sites"
        // and no other Object site, because the rest have no post-child prefix
        // the parent can stand in.
        for site in EffectSiteId::all() {
            if !named.contains(site.name().as_str()) {
                assert!(
                    site.sub_effects().is_empty(),
                    "{site} exposes points the design does not give it"
                );
            }
        }
        // The Legacy sites expose none: they carry no fault-registry
        // requirement, and a point would manufacture one.
        for site in [EventSite::LegacyOpenLog, EventSite::LegacyAppend] {
            assert!(EffectSiteId::Event(site).sub_effects().is_empty());
        }
        // Both injection modes are reachable through a real site, and so is a
        // kill-only point — the crossing the harness and registry range over.
        let append = EffectSiteId::Event(EventSite::AppendFirst);
        assert!(append.exposes(SubEffectPoint::Written, InjectionMode::Kill));
        assert!(append.exposes(SubEffectPoint::Written, InjectionMode::ErrorReturn));

        // `structure` names exactly two kill entries and three error-return
        // entries for an append site, and the three error-return cases are
        // distinct durable shapes: a partial line the next open truncates, a
        // complete unsynced line the barrier makes durable, and a synced line
        // whose sync reported failure. They are three *keys*, so a suite
        // cannot execute one and have the coordinate read as complete, and the
        // format cannot be handed both under one key without refusing the
        // second as a duplicate.
        for site in [
            EventSite::AppendFirst,
            EventSite::Append,
            EventSite::AppendInformational,
        ] {
            let site = EffectSiteId::Event(site);
            let kills: Vec<SubEffectPoint> = site
                .sub_effects()
                .iter()
                .copied()
                .filter(|point| point.supports(InjectionMode::Kill))
                .collect();
            let errors: Vec<SubEffectPoint> = site
                .sub_effects()
                .iter()
                .copied()
                .filter(|point| point.supports(InjectionMode::ErrorReturn))
                .collect();
            assert_eq!(
                kills,
                vec![SubEffectPoint::Written, SubEffectPoint::Synced],
                "{site} kill entries"
            );
            assert_eq!(
                errors,
                vec![
                    SubEffectPoint::Written,
                    SubEffectPoint::WrittenFull,
                    SubEffectPoint::Synced,
                ],
                "{site} error-return entries"
            );
            // And the two written cases are different keys, so a registry
            // holding both is a registry rather than a duplicate.
            assert_ne!(
                EntryPhase::Point {
                    point: SubEffectPoint::Written,
                    mode: InjectionMode::ErrorReturn,
                },
                EntryPhase::Point {
                    point: SubEffectPoint::WrittenFull,
                    mode: InjectionMode::ErrorReturn,
                }
            );
        }
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        assert!(commit_tree.exposes(SubEffectPoint::IdUnread, InjectionMode::Kill));
        assert!(!commit_tree.exposes(SubEffectPoint::IdUnread, InjectionMode::ErrorReturn));
        assert!(!commit_tree.exposes(SubEffectPoint::Written, InjectionMode::Kill));
    }

    // -----------------------------------------------------------------------
    // Residue classes
    // -----------------------------------------------------------------------

    #[test]
    fn the_residue_class_is_registered_exactly_where_the_design_registers_it() {
        // "every Object site carries a registered residue class
        // ObjectResidue::Internal", and "the classifier is total over {None,
        // Internal, After} for every Object site and for
        // Worktree.Add/Snapshot.Add".
        let expected: BTreeSet<String> = ObjectSite::ALL
            .iter()
            .map(|site| EffectSiteId::Object(*site).name())
            .chain([
                EffectSiteId::Worktree(WorktreeSite::Add).name(),
                EffectSiteId::Worktree(WorktreeSite::AddStaging).name(),
                EffectSiteId::Snapshot(SnapshotSite::Add).name(),
            ])
            .collect();
        let actual: BTreeSet<String> = EffectSiteId::all()
            .into_iter()
            .filter(|site| !site.residue_classes().is_empty())
            .map(|site| site.name())
            .collect();
        assert_eq!(actual, expected);
        for name in &actual {
            let site = EffectSiteId::from_name(name).expect("listed above");
            assert_eq!(site.residue_classes(), &[ResidueClass::ObjectInternal]);
            assert!(site.registers(ResidueClass::ObjectInternal), "{name}");
            assert!(
                !site.residue_elements().is_empty(),
                "{name} registers a class with nothing to construct"
            );
        }
        // A class is never an executed hook: its label is fixed, and the
        // classifier outcome it stands for is `Internal` and not the two the
        // classifier can also answer.
        assert_eq!(ResidueClass::ALL.len(), 1);
        assert_eq!(
            ResidueClass::ObjectInternal.label(),
            EvidenceLabel::RecoveryProven
        );
        assert_eq!(
            ResidueClass::ObjectInternal.classified_as(),
            ObjectResidue::Internal
        );
        assert_eq!(
            ObjectResidue::ALL.len(),
            3,
            "the classifier is total over three"
        );
    }

    #[test]
    fn each_site_lists_the_residue_elements_its_own_command_can_leave() {
        use ResidueElement as X;
        // From each transaction's own residue description in the fault matrix.
        // The lists differ by command on purpose: a killed `commit-tree`
        // touches no index, so an `index.lock` in its list would be a residue
        // element nothing could ever construct there.
        let expected: &[(&str, &[ResidueElement])] = &[
            (
                "Object.CandidateStage",
                &[X::UnreferencedObject, X::TemporaryObjectFile, X::IndexLock],
            ),
            (
                "Object.CandidateWriteTree",
                &[X::UnreferencedObject, X::TemporaryObjectFile, X::IndexLock],
            ),
            (
                "Object.SnapshotCommitTree",
                &[X::UnreferencedObject, X::TemporaryObjectFile],
            ),
            (
                "Object.CandidateCommitTree",
                &[X::UnreferencedObject, X::TemporaryObjectFile],
            ),
            (
                "Object.ProposalCherryPick",
                &[
                    X::UnreferencedObject,
                    X::TemporaryObjectFile,
                    X::IndexLock,
                    X::CherryPickHead,
                    X::MergeHead,
                    X::MergeMsg,
                    X::SequencerState,
                ],
            ),
            (
                "Object.RepairMaterialize",
                &[
                    X::UnreferencedObject,
                    X::TemporaryObjectFile,
                    X::IndexLock,
                    X::CherryPickHead,
                ],
            ),
            ("Worktree.Add", &[X::RegisteredUnpopulatedWorktree]),
            ("Worktree.AddStaging", &[X::RegisteredUnpopulatedWorktree]),
            ("Snapshot.Add", &[X::RegisteredUnpopulatedWorktree]),
        ];
        for (name, elements) in expected {
            let site = EffectSiteId::from_name(name).expect("a site with a residue class");
            assert_eq!(site.residue_elements(), *elements, "{name}");
        }
        // The lists are genuinely different: five distinct list lengths across
        // nine sites, so a `residue_elements` that answered one constant would
        // fail rather than pass.
        let lengths: BTreeSet<usize> = expected
            .iter()
            .map(|(_, elements)| elements.len())
            .collect();
        assert_eq!(lengths, BTreeSet::from([1, 2, 3, 4, 7]), "{lengths:?}");
        // Every element classifies `Internal`; that is what makes the answer a
        // class rather than a list of files.
        assert_eq!(ResidueElement::ALL.len(), 9);
        for element in ResidueElement::ALL {
            assert_eq!(
                element.classifies_as(),
                ObjectResidue::Internal,
                "{element:?}"
            );
        }
        // `ORIG_HEAD` is classifiable and is on no site's construction list:
        // the classifier's definition names it, the synthetic-construction list
        // does not, and this framework does not invent an element for a site to
        // have to build.
        let constructed: BTreeSet<ResidueElement> = EffectSiteId::all()
            .into_iter()
            .flat_map(|site| site.residue_elements().iter().copied())
            .collect();
        assert!(!constructed.contains(&ResidueElement::OrigHead));
        assert_eq!(constructed.len(), 8);
    }

    #[test]
    fn a_residue_class_is_not_a_hook_phase() {
        // The type says so: an `EntryPhase::Residue` has no hook phase, and a
        // hook phase has no residue class. This is the first of the two places
        // the framework refuses to count a class as an execution — the second
        // is the format, below, which refuses the claim even when it is made.
        let class = EntryPhase::Residue {
            class: ResidueClass::ObjectInternal,
        };
        assert_eq!(class.hook_phase(), None);
        assert_eq!(class.residue_class(), Some(ResidueClass::ObjectInternal));
        assert_eq!(class.required_label(), EvidenceLabel::RecoveryProven);
        for phase in [
            EntryPhase::Before,
            EntryPhase::After,
            EntryPhase::Point {
                point: SubEffectPoint::Synced,
                mode: InjectionMode::ErrorReturn,
            },
        ] {
            assert!(phase.hook_phase().is_some(), "{phase}");
            assert_eq!(phase.residue_class(), None, "{phase}");
            assert_eq!(phase.required_label(), EvidenceLabel::ExecutionObserved);
        }
        // A no-execution record is neither: nothing ran, and nothing was left.
        assert_eq!(EntryPhase::NoExecution.hook_phase(), None);
        assert_eq!(EntryPhase::NoExecution.residue_class(), None);
        assert_eq!(
            EntryPhase::NoExecution.required_label(),
            EvidenceLabel::ExecutionObserved
        );
    }

    #[test]
    fn only_the_three_sites_a_fast_sequence_skips_may_record_that_they_did_not_run() {
        let skipped: BTreeSet<String> = EffectSiteId::all()
            .into_iter()
            .filter(|site| site.skipped_on_fast_path())
            .map(|site| site.name())
            .collect();
        assert_eq!(
            skipped,
            BTreeSet::from([
                "Worktree.AddStaging".to_owned(),
                "Object.ProposalCherryPick".to_owned(),
                "Ref.PinPrepared".to_owned(),
            ]),
            "`structure` names exactly these three as asserted-not-executed"
        );
    }

    #[test]
    fn a_site_name_no_group_declares_is_refused() {
        for name in [
            "RunDir.NoSuchSite",
            "NoSuchGroup.CreatePublicDir",
            "CreatePublicDir",
            "RunDir.createpublicdir",
            "RunDir.CreatePublicDir ",
            "",
        ] {
            let error = EffectSiteId::from_name(name).expect_err("must be refused");
            assert_eq!(error.name, name);
            assert!(error.to_string().contains(name), "{error}");
        }
        // And the round trip holds for every real one.
        for site in EffectSiteId::all() {
            assert_eq!(EffectSiteId::from_name(&site.name()), Ok(site));
        }
    }

    // -----------------------------------------------------------------------
    // ST-07: the framework self-test
    //
    // A synthetic exercise — nothing here performs an effect — of the whole
    // loop: sites out of the enums, executions into the harness, entries into
    // the registry format, and the bijection over the three.
    //
    // Fixture hostility, stated as counts rather than as a claim (§8.2 of this
    // slice's contract). Across the thirty entries of `self_test_registry`:
    //
    //   order              3 distinct  (None, EffectBeforeEvent, EventBeforeEffect)
    //   fault_row          5 distinct  (T-APPEND, T-CAND-OBJ, T-ATTEMPT,
    //                                 T-REPAIR-DISPATCH, T-PROPOSAL)
    //   expected_residue.rows  6 distinct row sets, incl. the empty one
    //   expected_residue.detail  30 distinct (one per entry)
    //   resume_action      30 distinct (one per entry)
    //   label               2 distinct
    //   evidence kind       3 distinct (Executed, RecoveryProven, NotExecuted)
    //   evidence test name 28 distinct (the two residue entries name none)
    //   sampling.n          2 distinct (61 and 23)
    //   sampling histogram  2 distinct, one with internal == 0 and one > 0
    //   synthetic element   4 distinct across the two residue entries
    //
    // The counts are asserted by `the_self_test_fixture_varies_every_field_it_reads`,
    // so they cannot drift away from this comment silently.
    // -----------------------------------------------------------------------

    /// The sites the self-test drives.
    ///
    /// Chosen to cover every shape the framework has: a site with three points
    /// in two modes each (`Event.OpenLog`), one with two points in two modes
    /// (`Event.AppendFirst`), one with a kill-only point *and* a residue class
    /// (`Object.CandidateCommitTree`), one with a residue class and no points
    /// (`Object.RepairMaterialize`), one whose points are platform-scoped
    /// (`Process.Spawn`), one whose before phase finds its target already
    /// durable (`Worktree.Remove`), the three a fast sequence skips, and a
    /// Legacy site that must be exempt.
    ///
    /// `Worktree.Remove` is here because a fixture in which a classification
    /// never occurs cannot show that the format reads it: the entry a
    /// packet-correct registry writes for `Worktree.Remove`'s before phase
    /// carries `[R9]`, and the authority that predated PR3-ST07-011 refused
    /// exactly that entry. All three [`BeforeState`] answers now occur here —
    /// `Worktree.Remove` is [`BeforeState::Present`], `Worktree.AddStaging`
    /// (already present as one of the three sites a fast sequence skips) is
    /// [`BeforeState::PrecursorDurable`], and the rest are
    /// [`BeforeState::Absent`] — and
    /// `the_self_test_fixture_varies_every_field_it_reads` asserts that,
    /// because the two non-empty answers name the same row and differ only in
    /// the words the format checks.
    fn self_test_inventory() -> Vec<EffectSiteId> {
        vec![
            EffectSiteId::Event(EventSite::OpenLog),
            EffectSiteId::Event(EventSite::AppendFirst),
            EffectSiteId::Event(EventSite::LegacyAppend),
            EffectSiteId::Object(ObjectSite::CandidateCommitTree),
            EffectSiteId::Object(ObjectSite::RepairMaterialize),
            EffectSiteId::Process(ProcessSite::Spawn),
            EffectSiteId::Worktree(WorktreeSite::Remove),
            EffectSiteId::Worktree(WorktreeSite::AddStaging),
            EffectSiteId::Object(ObjectSite::ProposalCherryPick),
            EffectSiteId::Ref(RefSite::PinPrepared),
        ]
    }

    /// The sites the self-test asserts did *not* run.
    fn fast_path_skipped() -> Vec<EffectSiteId> {
        vec![
            EffectSiteId::Worktree(WorktreeSite::AddStaging),
            EffectSiteId::Object(ObjectSite::ProposalCherryPick),
            EffectSiteId::Ref(RefSite::PinPrepared),
        ]
    }

    /// The one order an entry for this site must carry, or `None`.
    fn only_order(site: EffectSiteId) -> Option<ObservableOrder> {
        site.observable_orders().first().copied()
    }

    /// Run one site through both hook phases and every point required on
    /// `host`, exactly as a funnel would.
    fn drive(harness: &mut HookHarness, site: EffectSiteId, host: Host) {
        harness.hook(site, HookPhase::Before);
        for point in site.sub_effects() {
            if !point.platform().required_on(host) {
                continue;
            }
            for mode in point.modes() {
                harness
                    .arm(site, *point, *mode)
                    .expect("the site exposes this point in this mode");
                harness.hook(
                    site,
                    HookPhase::Point {
                        point: *point,
                        mode: *mode,
                    },
                );
            }
        }
        harness.disarm();
        harness.hook(site, HookPhase::After);
    }

    /// A harness that has driven every site of the inventory that is supposed
    /// to run, and none of the three a fast sequence skips.
    fn self_test_harness(host: Host) -> HookHarness {
        let mut harness = HookHarness::new();
        // Every fast sequence the suite runs is recorded by name, and the
        // sites a fast publication skips run in none of them. A harness that
        // exercised no sequence would substantiate the no-execution record by
        // having done nothing, which is what this shape exists to prevent.
        for sequence in FAST_SEQUENCES {
            harness.begin_fast_sequence(sequence);
            for site in self_test_inventory() {
                if site.skipped_on_fast_path() || !site.scope().is_claimed() {
                    continue;
                }
                drive(&mut harness, site, host);
            }
            harness.end_fast_sequence();
        }
        // And the stale-candidate path, outside every fast sequence: a staging
        // worktree is added, the proposal is cherry-picked and a prepared pin
        // is taken. These are ordinary claimed sites and ST-07 requires their
        // hook phases observed; the no-execution record says only that they do
        // not run *inside* a fast sequence. A suite that never drove them
        // would have no coverage of them at all, which is the report the
        // no-execution entry used to stand in for.
        harness.end_fast_sequence();
        for site in self_test_inventory() {
            if !site.skipped_on_fast_path() || !site.scope().is_claimed() {
                continue;
            }
            drive(&mut harness, site, host);
        }
        harness
    }

    /// The rows the fixture writes, which are the site's own semantics.
    ///
    /// Deliberately the production authority rather than a second copy of it:
    /// the fixture's job is to be a registry the format accepts, and a fixture
    /// carrying its own table would only prove the two tables agree. What the
    /// *values* are is asserted separately, against the packet's words, in
    /// `the_expected_residue_of_a_phase_is_the_sites_own_semantics`.
    fn residue_rows(site: EffectSiteId, phase: EntryPhase) -> Vec<ResourceRow> {
        site.expected_rows(phase)
    }

    /// The resume action an entry in this phase must name.
    ///
    /// The production authority, for the same reason [`residue_rows`] is: the
    /// fixture's job is to be a registry the format accepts. What the values
    /// *are* is asserted against the packet's words by the independent oracle
    /// in `the_residue_and_recovery_authority_is_exhaustive_and_says_what_the_packet_says`.
    fn resume_action(site: EffectSiteId, phase: EntryPhase) -> String {
        site.semantics(phase).action.text().to_owned()
    }

    /// The residue detail an entry in this phase must carry.
    fn residue_detail(site: EffectSiteId, phase: EntryPhase) -> String {
        site.semantics(phase).artifact.detail().to_owned()
    }

    fn hook_entry(site: EffectSiteId, phase: EntryPhase) -> RegistryEntry {
        let name = format!("{site}/{phase}");
        RegistryEntry {
            site,
            phase,
            order: only_order(site),
            fault_row: site.fault_row(),
            expected_residue: ExpectedResidue {
                rows: residue_rows(site, phase),
                detail: residue_detail(site, phase),
            },
            resume_action: resume_action(site, phase),
            label: EvidenceLabel::ExecutionObserved,
            evidence: Evidence::Executed {
                test: format!("st07::{name}"),
                passed: true,
            },
        }
    }

    /// A residue-class entry. `internal` is how many of the `n` samples landed
    /// in the internal window — zero is legal and is one of the two cases the
    /// self-test carries.
    fn residue_entry(site: EffectSiteId, n: u32, internal: u32) -> RegistryEntry {
        let phase = EntryPhase::Residue {
            class: ResidueClass::ObjectInternal,
        };
        let none = (n - internal) / 2;
        let after = n - internal - none;
        RegistryEntry {
            site,
            phase,
            order: only_order(site),
            fault_row: site.fault_row(),
            expected_residue: ExpectedResidue {
                rows: residue_rows(site, phase),
                detail: residue_detail(site, phase),
            },
            resume_action: resume_action(site, phase),
            label: EvidenceLabel::RecoveryProven,
            evidence: Evidence::RecoveryProven {
                synthetic: site
                    .residue_elements()
                    .iter()
                    .map(|element| SyntheticRecord {
                        element: *element,
                        constructed: true,
                        classified: ObjectResidue::Internal,
                        recovered: true,
                    })
                    .collect(),
                sampling: SamplingRecord {
                    n,
                    histogram: ClassHistogram {
                        none,
                        internal,
                        after,
                    },
                    unclassified: 0,
                    recovered: true,
                },
            },
        }
    }

    /// The fast integration sequences the self-test drives.
    ///
    /// Two, and named, because a no-execution record is measured against every
    /// one the suite exercised: one sequence cannot show that the second did
    /// not reach a site the first skipped.
    const FAST_SEQUENCES: [&str; 2] = ["fast/seq-0", "fast/seq-1"];

    fn no_execution_entry(site: EffectSiteId) -> RegistryEntry {
        RegistryEntry {
            site,
            phase: EntryPhase::NoExecution,
            order: None,
            fault_row: site.fault_row(),
            expected_residue: ExpectedResidue {
                rows: residue_rows(site, EntryPhase::NoExecution),
                detail: residue_detail(site, EntryPhase::NoExecution),
            },
            resume_action: resume_action(site, EntryPhase::NoExecution),
            label: EvidenceLabel::ExecutionObserved,
            evidence: Evidence::NotExecuted {
                test: format!("st07::fast-path::{site}"),
                passed: true,
                sequences: FAST_SEQUENCES
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
            },
        }
    }

    /// The frozen sample count and internal-window hit count for one site.
    ///
    /// Distinct per site, because `N` is frozen per site and a fixture that
    /// wrote one number for four sites could not show that anything reads it.
    /// One of the four is deliberately zero: "hitting Internal is recorded but
    /// never required".
    fn sampling_for(site: EffectSiteId) -> (u32, u32) {
        match site {
            EffectSiteId::Object(ObjectSite::CandidateCommitTree) => (61, 0),
            EffectSiteId::Object(ObjectSite::RepairMaterialize) => (23, 4),
            EffectSiteId::Object(ObjectSite::ProposalCherryPick) => (37, 9),
            EffectSiteId::Worktree(WorktreeSite::AddStaging) => (19, 2),
            other => unreachable!("the fixture drives no other residue-class site: {other}"),
        }
    }

    /// Every entry the inventory needs, built through the format so that a
    /// fixture the format would refuse cannot be the thing the bijection
    /// passes on.
    fn self_test_registry(host: Host) -> Vec<RegistryEntry> {
        let mut registry = FaultRegistry::new();
        for site in self_test_inventory() {
            if !site.scope().is_claimed() {
                continue;
            }
            if site.skipped_on_fast_path() {
                // Additive, not instead of: the no-execution record goes in
                // *and* the site carries the ordinary entries every claimed
                // site carries.
                registry
                    .insert(no_execution_entry(site))
                    .expect("a no-execution record for a site a fast sequence skips");
            }
            for phase in [EntryPhase::Before, EntryPhase::After] {
                registry
                    .insert(hook_entry(site, phase))
                    .expect("hook entry");
            }
            for point in site.sub_effects() {
                if !point.platform().required_on(host) {
                    continue;
                }
                for mode in point.modes() {
                    registry
                        .insert(hook_entry(
                            site,
                            EntryPhase::Point {
                                point: *point,
                                mode: *mode,
                            },
                        ))
                        .expect("point entry");
                }
            }
            // A frozen sample count per site — "N frozen per site in the
            // registry" — and one class deliberately never hit.
            for class in site.residue_classes() {
                assert_eq!(*class, ResidueClass::ObjectInternal);
                let (n, internal) = sampling_for(site);
                registry
                    .insert(residue_entry(site, n, internal))
                    .expect("residue entry");
            }
        }
        registry.entries().to_vec()
    }

    #[test]
    fn the_framework_self_test_round_trips_through_enums_harness_and_registry() {
        // ST-07's proof test for this slice, in one place: a site set out of
        // the enums, driven through the harness in both injection modes, with
        // a residue-class entry, checked by the bijection.
        //
        // Run for both hosts and not only for [`Host::current`]. The fixture,
        // the harness and the check all take the host as a parameter, so a
        // Linux box can build and check the Windows shape; leaving that to the
        // Windows CI cell is how a self-test acquires a platform it has never
        // been run against.
        for host in Host::ALL.iter().copied() {
            let inventory = self_test_inventory();
            let harness = self_test_harness(host);
            let entries = self_test_registry(host);
            let failures = check_bijection(&inventory, &harness, &entries, host);
            assert!(failures.is_empty(), "{host}: {failures:#?}");
        }

        let host = Host::current();
        let inventory = self_test_inventory();
        let harness = self_test_harness(host);
        let entries = self_test_registry(host);

        let failures = check_bijection(&inventory, &harness, &entries, host);
        assert!(failures.is_empty(), "{failures:#?}");

        // The exercise was real: both injection modes were executed, the
        // kill-only point was executed in kill mode, and the sites a fast
        // sequence skips executed in neither.
        let append = EffectSiteId::Event(EventSite::AppendFirst);
        for mode in InjectionMode::ALL {
            for point in [SubEffectPoint::Written, SubEffectPoint::Synced] {
                assert!(
                    harness.observed(append, HookPhase::Point { point, mode: *mode }),
                    "{append} {point} {mode:?}"
                );
            }
        }
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        assert!(harness.observed(
            commit_tree,
            HookPhase::Point {
                point: SubEffectPoint::IdUnread,
                mode: InjectionMode::Kill,
            }
        ));
        assert!(!harness.observed(
            commit_tree,
            HookPhase::Point {
                point: SubEffectPoint::IdUnread,
                mode: InjectionMode::ErrorReturn,
            }
        ));
        // The three sites a fast publication skips ran on the stale-candidate
        // path and in none of the fast sequences: both halves, because the
        // no-execution record is a claim about the traces and not a claim that
        // the site never runs. A suite that had never driven them would
        // satisfy the second half by having no coverage at all.
        for site in fast_path_skipped() {
            assert!(
                harness.touched(site),
                "{site} was never driven, so its hook phases have no coverage"
            );
            for sequence in harness.fast_sequences() {
                assert!(
                    !sequence.ran(site),
                    "{site} ran inside the fast sequence {}",
                    sequence.name()
                );
            }
            for phase in HookPhase::PHASES {
                assert!(harness.observed(site, *phase), "{site}/{phase}");
            }
        }
        // The Legacy site was never driven and never entered, and the check
        // passed anyway — `scope` says it carries no requirement.
        let legacy = EffectSiteId::Event(EventSite::LegacyAppend);
        assert!(!harness.touched(legacy));
        assert!(!entries.iter().any(|entry| entry.site == legacy));
    }

    /// The shape of the self-test fixture on one host: how many entries it
    /// holds and how many distinct values each field the format reads takes
    /// across them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FixtureShape {
        entries: usize,
        order: usize,
        fault_row: usize,
        rows: usize,
        detail: usize,
        resume_action: usize,
        label: usize,
        evidence_kind: usize,
        test_name: usize,
        bound_to_before: usize,
        sampling: usize,
    }

    /// Measure one host's fixture. Takes the host as a parameter rather than
    /// reading [`Host::current`], so the numbers below are checked for both
    /// platforms wherever the suite runs.
    fn fixture_shape(host: Host) -> FixtureShape {
        let entries = self_test_registry(host);
        let distinct = |mut values: Vec<String>| -> usize {
            values.sort();
            values.dedup();
            values.len()
        };
        FixtureShape {
            entries: entries.len(),
            order: distinct(entries.iter().map(|e| format!("{:?}", e.order)).collect()),
            fault_row: distinct(entries.iter().map(|e| e.fault_row.to_string()).collect()),
            rows: distinct(
                entries
                    .iter()
                    .map(|e| format!("{:?}", e.expected_residue.rows))
                    .collect(),
            ),
            detail: distinct(
                entries
                    .iter()
                    .map(|e| e.expected_residue.detail.clone())
                    .collect(),
            ),
            resume_action: distinct(entries.iter().map(|e| e.resume_action.clone()).collect()),
            label: distinct(entries.iter().map(|e| format!("{:?}", e.label)).collect()),
            evidence_kind: distinct(
                entries
                    .iter()
                    .map(|e| match &e.evidence {
                        Evidence::Executed { .. } => "executed".to_owned(),
                        Evidence::RecoveryProven { .. } => "recovery".to_owned(),
                        Evidence::NotExecuted { .. } => "not-executed".to_owned(),
                    })
                    .collect(),
            ),
            test_name: distinct(
                entries
                    .iter()
                    .filter_map(|e| match &e.evidence {
                        Evidence::Executed { test, .. } | Evidence::NotExecuted { test, .. } => {
                            Some(test.clone())
                        }
                        Evidence::RecoveryProven { .. } => None,
                    })
                    .collect(),
            ),
            bound_to_before: entries
                .iter()
                .filter(|e| e.phase.resumes_as_before())
                .count(),
            sampling: entries
                .iter()
                .filter(|e| matches!(e.evidence, Evidence::RecoveryProven { .. }))
                .count(),
        }
    }

    /// What each host's fixture has to look like.
    ///
    /// Two literals, and both asserted on every host. PR3-ST07-013's second
    /// half: the predecessor of this test read `Platform::host()` and asserted
    /// a single hard-coded total of 39. That total is the *Unix* shape.
    /// `Spawn.AmbientJobJoined` supports kill and error-return while the other
    /// three Windows containment points and all four Unix ones are kill-only,
    /// so a Windows fixture holds one entry more — and CLAUDE.md makes Windows
    /// a first-class target whose CI cell runs this very suite. A number
    /// measured on one platform and asserted on both is a red matrix cell that
    /// the platform which produced it can never see.
    ///
    /// So the shapes are computed for both hosts here, on whichever host is
    /// running. A Linux box proves the Windows numbers and a Windows box proves
    /// the Unix ones.
    const FIXTURE_SHAPES: &[(Host, FixtureShape)] = &[
        (
            Host::Unix,
            FixtureShape {
                entries: 41,
                order: 3,
                fault_row: 6,
                rows: 10,
                detail: 17,
                resume_action: 8,
                label: 2,
                evidence_kind: 3,
                test_name: 37,
                bound_to_before: 5,
                sampling: 4,
            },
        ),
        (
            Host::Windows,
            FixtureShape {
                entries: 42,
                order: 3,
                fault_row: 6,
                rows: 9,
                detail: 17,
                resume_action: 8,
                label: 2,
                evidence_kind: 3,
                test_name: 38,
                bound_to_before: 5,
                sampling: 4,
            },
        ),
    ];

    #[test]
    fn the_self_test_fixture_varies_every_field_it_reads() {
        // Counts, not prose. A field with one distinct value across the
        // fixture cannot prove that anything reads that field, so each of
        // these is asserted to take more than one — and the ones that are
        // deliberately constant say so.
        assert_eq!(FIXTURE_SHAPES.len(), Host::ALL.len());
        for (host, expected) in FIXTURE_SHAPES.iter().copied() {
            assert_eq!(fixture_shape(host), expected, "the {host} fixture");
        }
        // Every count above is at least two except the ones named here, so a
        // table edited to a pile of ones would not pass by being a table.
        for (host, shape) in FIXTURE_SHAPES.iter().copied() {
            for (name, count) in [
                ("order", shape.order),
                ("fault_row", shape.fault_row),
                ("expected_residue.rows", shape.rows),
                ("expected_residue.detail", shape.detail),
                ("resume_action", shape.resume_action),
                ("label", shape.label),
                ("evidence kind", shape.evidence_kind),
            ] {
                assert!(count >= 2, "{host}: {name} takes {count} distinct values");
            }
        }
        // The two hosts differ in exactly the containment points: one more
        // entry on Windows, one more evidence test name with it, and the same
        // number of everything the platform does not touch.
        let unix = fixture_shape(Host::Unix);
        let windows = fixture_shape(Host::Windows);
        assert_eq!(windows.entries, unix.entries + 1);
        assert_eq!(windows.test_name, unix.test_name + 1);
        assert_eq!(windows.sampling, unix.sampling);
        assert_eq!(windows.bound_to_before, unix.bound_to_before);
        assert_eq!(windows.order, unix.order);
        assert_eq!(windows.fault_row, unix.fault_row);
        // One fewer distinct row-list on Windows, and it is the interesting
        // one: the Unix containment points leave `[R28]`, the Windows ones
        // leave `[]`, and `[]` is already the before phase of every creation.
        // Under the shipped authority both platforms answered `[R22]` and this
        // difference did not exist.
        assert_eq!(windows.rows, unix.rows - 1);

        // Every `BeforeState` answer occurs in the fixture, so each one is
        // carried through the format — `hook_entry`, `validate_entry`,
        // `check_bijection` — rather than only through the table. The two
        // non-empty answers name the *same* row and differ only in the words
        // the format compares, so a fixture holding one of them and not the
        // other could not show that the format tells them apart.
        let classified: BTreeSet<BeforeState> = self_test_inventory()
            .into_iter()
            .map(EffectSiteId::before_state)
            .collect();
        assert_eq!(
            classified,
            BTreeSet::from([
                BeforeState::Absent,
                BeforeState::PrecursorDurable,
                BeforeState::Present,
            ]),
            "the self-test fixture no longer exercises every before-phase answer"
        );
        assert_eq!(
            EffectSiteId::Worktree(WorktreeSite::Remove).before_state(),
            BeforeState::Present
        );
        assert_eq!(
            EffectSiteId::Worktree(WorktreeSite::AddStaging).before_state(),
            BeforeState::PrecursorDurable
        );

        // The rest is host-independent and is asserted on both fixtures.
        for host in Host::ALL.iter().copied() {
            let entries = self_test_registry(host);

            // The entries whose phase `structure` gives "the before-phase
            // action" carry their site's own before-phase action and are not
            // free to vary.
            for entry in entries.iter().filter(|e| e.phase.resumes_as_before()) {
                assert_eq!(
                    entry.resume_action,
                    entry.site.semantics(EntryPhase::Before).action.text(),
                    "{host}: {}/{}",
                    entry.site,
                    entry.phase
                );
            }

            // Both before-phase classifications occur in the fixture, so the
            // registry the bijection passes on is one that exercises each. The
            // `[R9]` entry is the one the shipped authority refused.
            let before: Vec<&RegistryEntry> = entries
                .iter()
                .filter(|e| e.phase == EntryPhase::Before)
                .collect();
            assert!(
                before
                    .iter()
                    .any(|e| e.expected_residue.rows == vec![ResourceRow::R9]
                        && e.site == EffectSiteId::Worktree(WorktreeSite::Remove)),
                "{host}: no before-phase entry carries a target that is already durable"
            );
            assert!(
                before.iter().any(|e| e.expected_residue.rows.is_empty()),
                "{host}: no before-phase entry carries an absent target"
            );

            // The residue entries differ in every field a checker reads: the
            // frozen N, the histogram, and whether the internal window was hit.
            let sampling: Vec<SamplingRecord> = entries
                .iter()
                .filter_map(|e| match &e.evidence {
                    Evidence::RecoveryProven { sampling, .. } => Some(*sampling),
                    _ => None,
                })
                .collect();
            let distinct = |mut values: Vec<String>| -> usize {
                values.sort();
                values.dedup();
                values.len()
            };
            assert_eq!(sampling.len(), 4);
            assert_eq!(
                distinct(sampling.iter().map(|s| s.n.to_string()).collect()),
                sampling.len(),
                "{host}: frozen N is per site"
            );
            assert_eq!(
                distinct(
                    sampling
                        .iter()
                        .map(|s| format!("{:?}", s.histogram))
                        .collect()
                ),
                sampling.len(),
                "{host}: the histogram is per site"
            );
            let hit: Vec<u32> = sampling.iter().map(|s| s.histogram.internal).collect();
            assert!(
                hit.contains(&0) && hit.iter().any(|count| *count > 0),
                "{host}: one class never hit and the rest hit: {hit:?}"
            );
            // Every residue element the inventory can construct is constructed
            // across the four.
            let elements: BTreeSet<ResidueElement> = entries
                .iter()
                .filter_map(|e| match &e.evidence {
                    Evidence::RecoveryProven { synthetic, .. } => Some(synthetic.clone()),
                    _ => None,
                })
                .flatten()
                .map(|record| record.element)
                .collect();
            assert_eq!(elements.len(), 8, "{host}: {elements:?}");
        }
    }

    #[test]
    fn the_fixture_shape_table_is_measured_and_not_asserted_into_being() {
        // The table above is a literal, so this prints what the fixture
        // actually is when it disagrees — a bare `assert_eq!` on a struct of
        // eleven numbers is otherwise a puzzle to re-derive by hand.
        for (host, expected) in FIXTURE_SHAPES.iter().copied() {
            let measured = fixture_shape(host);
            assert_eq!(
                measured, expected,
                "{host} fixture measured {measured:?}, table says {expected:?}"
            );
        }
    }

    #[test]
    fn the_harness_reports_no_execution_that_did_not_happen() {
        // The §7 empty-coverage proof, and the whole reason the harness exists
        // as a type rather than as a boolean per site.
        let mut harness = HookHarness::new();
        assert!(harness.coverage().is_empty());
        assert_eq!(harness.executions(), 0);

        // Arm every injection the whole inventory admits, and fire none.
        let mut armed = 0;
        for site in EffectSiteId::all() {
            for point in site.sub_effects() {
                for mode in point.modes() {
                    harness.arm(site, *point, *mode).expect("a legal arming");
                    armed += 1;
                }
            }
        }
        assert!(armed > 20, "the arming was not vacuous: {armed}");
        assert!(
            harness.coverage().is_empty(),
            "arming an injection recorded an execution: {:?}",
            harness.coverage()
        );
        assert_eq!(harness.executions(), 0);
        for site in EffectSiteId::all() {
            assert!(!harness.touched(site), "{site}");
            for phase in HookPhase::PHASES {
                assert!(!harness.observed(site, *phase), "{site}");
            }
        }
        // And a bijection over a site nothing ran through fails, rather than
        // passing because the coverage report was empty.
        let site = EffectSiteId::Event(EventSite::AppendFirst);
        let failures = check_bijection(&[site], &harness, &[], Host::current());
        assert!(
            failures
                .iter()
                .any(|failure| matches!(failure, BijectionFailure::Unobserved { .. })),
            "{failures:#?}"
        );
    }

    #[test]
    fn no_execution_evidence_holds_inside_an_exercised_fast_sequence_or_it_holds_nothing() {
        // ST-07: "the fast-path no-execution record shows that no staging,
        // cherry-pick, or prepared-pin site executed **for any fast
        // sequence**". A fresh harness has touched nothing, so `!touched(site)`
        // is true of it — and of a process that never ran an integration, or
        // ran one and forgot to hook it. The record has to hold *within* a
        // sequence that demonstrably happened, so every direction below is a
        // way it can fail to.
        let host = Host::current();
        let inventory = self_test_inventory();
        let entries = self_test_registry(host);
        let skipped = fast_path_skipped();
        assert_eq!(skipped.len(), 3, "the three sites a fast sequence skips");

        // The shape that passes, for contrast.
        assert!(check_bijection(&inventory, &self_test_harness(host), &entries, host).is_empty());

        // (a) An empty harness. This is the withheld mutation exactly: "treat
        // an empty harness as sufficient no-execution evidence without an
        // explicit entry bound to an exercised trace."
        let empty = HookHarness::new();
        assert!(empty.fast_sequences().is_empty());
        let failures = check_bijection(&inventory, &empty, &entries, host);
        for site in &skipped {
            assert!(
                failures.iter().any(|failure| matches!(
                    failure,
                    BijectionFailure::NoFastSequenceExercised { site: named } if *named == site.name()
                )),
                "{site}'s absence was substantiated by a harness that ran nothing: {failures:#?}"
            );
        }

        // (b) A harness that ran the fast sites but recorded no sequence: the
        // executions happened and nothing says they were a fast integration,
        // so there is still no trace the absence is measured inside.
        let mut unrecorded = HookHarness::new();
        for site in self_test_inventory() {
            if site.skipped_on_fast_path() || !site.scope().is_claimed() {
                continue;
            }
            drive(&mut unrecorded, site, host);
        }
        assert!(unrecorded.executions() > 0);
        assert!(unrecorded.fast_sequences().is_empty());
        assert!(
            check_bijection(&inventory, &unrecorded, &entries, host)
                .iter()
                .any(|failure| matches!(failure, BijectionFailure::NoFastSequenceExercised { .. }))
        );

        // (c) A second fast sequence the record says nothing about. One
        // sequence cannot witness another, so a record naming only the first
        // is silent about whether the second cherry-picked anything.
        let mut extra = self_test_harness(host);
        extra.begin_fast_sequence("fast/seq-2");
        drive(
            &mut extra,
            EffectSiteId::Event(EventSite::AppendFirst),
            host,
        );
        extra.end_fast_sequence();
        let failures = check_bijection(&inventory, &extra, &entries, host);
        for site in &skipped {
            assert!(
                failures.iter().any(|failure| matches!(
                    failure,
                    BijectionFailure::UnwitnessedFastSequence { site: named, sequence }
                        if *named == site.name() && sequence == "fast/seq-2"
                )),
                "{site} said nothing about a fast sequence the suite ran: {failures:#?}"
            );
        }

        // (d) A record naming a sequence the harness never exercised — the
        // forgery direction, where the evidence is invented rather than
        // missing.
        let mut invented = entries.clone();
        for entry in &mut invented {
            if let Evidence::NotExecuted { sequences, .. } = &mut entry.evidence {
                sequences.push("fast/seq-that-never-ran".to_owned());
            }
        }
        let failures = check_bijection(&inventory, &self_test_harness(host), &invented, host);
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                BijectionFailure::UnknownFastSequence { sequence, .. }
                    if sequence == "fast/seq-that-never-ran"
            )),
            "{failures:#?}"
        );

        // (e) A site that actually ran inside a recorded fast sequence. The
        // exact-base decision is made before any staging effect, so a
        // cherry-pick inside a fast sequence is INV-09 broken, and the record
        // that says it did not happen is the thing that must fail.
        let mut cherry_picked = HookHarness::new();
        for sequence in FAST_SEQUENCES {
            cherry_picked.begin_fast_sequence(sequence);
            for site in self_test_inventory() {
                if !site.scope().is_claimed() {
                    continue;
                }
                if site.skipped_on_fast_path()
                    && site != EffectSiteId::Object(ObjectSite::ProposalCherryPick)
                {
                    continue;
                }
                drive(&mut cherry_picked, site, host);
            }
            cherry_picked.end_fast_sequence();
        }
        let failures = check_bijection(&inventory, &cherry_picked, &entries, host);
        let cherry = EffectSiteId::Object(ObjectSite::ProposalCherryPick);
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                BijectionFailure::ExecutedInFastSequence { site: named, .. }
                    if *named == cherry.name()
            )),
            "a cherry-pick inside a fast sequence passed its own no-execution record: \
             {failures:#?}"
        );
        // And the other two, which did not run, are still clean of that
        // particular failure — so the report names what happened rather than
        // failing everything at once.
        for site in &skipped {
            if *site == cherry {
                continue;
            }
            assert!(
                !failures.iter().any(|failure| matches!(
                    failure,
                    BijectionFailure::ExecutedInFastSequence { site: named, .. }
                        if *named == site.name()
                )),
                "{site} was reported as executing and it did not"
            );
        }

        // (f) The format refuses a record that names no sequence at all,
        // before the bijection is reached.
        let mut unwitnessed = no_execution_entry(skipped[0]);
        if let Evidence::NotExecuted { sequences, .. } = &mut unwitnessed.evidence {
            sequences.clear();
        }
        assert!(matches!(
            validate_entry(&unwitnessed),
            Err(RegistryError::UnwitnessedNoExecution { .. })
        ));
        if let Evidence::NotExecuted { sequences, .. } = &mut unwitnessed.evidence {
            *sequences = vec!["   ".to_owned()];
        }
        assert!(matches!(
            validate_entry(&unwitnessed),
            Err(RegistryError::UnwitnessedNoExecution { .. })
        ));
    }

    #[test]
    fn a_fast_path_record_that_is_simply_absent_fails_like_any_other_missing_entry() {
        // PR3-ST07-012, the omission direction — the one the malformed-record
        // cases above cannot reach.
        //
        // The predecessor of this branch opened with
        //
        //     let no_execution = entries.iter().any(|e| e.site == site
        //         && e.phase == EntryPhase::NoExecution);
        //     if no_execution { ... }
        //
        // so *whether* the fast-path requirement existed was read off the
        // entries being checked. Delete all three records and every check of
        // them is skipped: `check_bijection` returns no failure for a registry
        // that contains no fast-path absence proof at all. A completeness
        // oracle that asks the artifact whether it is required is not a
        // completeness oracle. `completeness_rule` — "any missing link fails";
        // ST-07 — "the fast-path no-execution record shows that no staging,
        // cherry-pick, or prepared-pin site executed for any fast sequence".
        //
        // The requirement now comes from `skipped_on_fast_path()`, a property
        // of the site, and this test is that mutation.
        for host in Host::ALL.iter().copied() {
            let inventory = self_test_inventory();
            let harness = self_test_harness(host);
            let entries = self_test_registry(host);
            let skipped = fast_path_skipped();
            assert!(check_bijection(&inventory, &harness, &entries, host).is_empty());

            // Delete all three, leaving every ordinary entry and every
            // observation exactly as it was.
            let stripped: Vec<RegistryEntry> = entries
                .iter()
                .filter(|entry| entry.phase != EntryPhase::NoExecution)
                .cloned()
                .collect();
            assert_eq!(
                entries.len() - stripped.len(),
                3,
                "the fixture did not carry three records to delete"
            );
            let failures = check_bijection(&inventory, &harness, &stripped, host);
            for site in &skipped {
                assert!(
                    failures.iter().any(|failure| matches!(
                        failure,
                        BijectionFailure::MissingEntry { site: named, phase, .. }
                            if *named == site.name() && phase == "no-execution"
                    )),
                    "{host}: {site} has no fast-path record and the bijection did not say so: \
                     {failures:#?}"
                );
            }
            // Every ordinary requirement still holds, so the report is about
            // the three missing records and not about a fixture that fell
            // apart around them.
            assert!(
                !failures
                    .iter()
                    .any(|failure| matches!(failure, BijectionFailure::Unobserved { .. })),
                "{host}: {failures:#?}"
            );

            // And deleting one of the three is caught too, so the check is per
            // site rather than "at least one record exists somewhere".
            for site in &skipped {
                let one_gone: Vec<RegistryEntry> = entries
                    .iter()
                    .filter(|entry| {
                        !(entry.site == *site && entry.phase == EntryPhase::NoExecution)
                    })
                    .cloned()
                    .collect();
                assert_eq!(one_gone.len(), entries.len() - 1);
                let failures = check_bijection(&inventory, &harness, &one_gone, host);
                assert!(
                    failures.iter().any(|failure| matches!(
                        failure,
                        BijectionFailure::MissingEntry { site: named, phase, .. }
                            if *named == site.name() && phase == "no-execution"
                    )),
                    "{host}: {site}'s record could be dropped alone: {failures:#?}"
                );
                // Precisely that site, and precisely that claim. A record that
                // is absent also says nothing about each sequence the harness
                // ran, which is a true report and the only other one: one
                // `MissingEntry` plus one `UnwitnessedFastSequence` per
                // exercised sequence, and nothing about the other two sites or
                // about any ordinary coverage.
                assert_eq!(
                    failures.len(),
                    1 + harness.fast_sequences().len(),
                    "{host}: dropping {site}'s record reported more than its absence: \
                     {failures:#?}"
                );
                for failure in &failures {
                    let named = match failure {
                        BijectionFailure::MissingEntry { site, .. }
                        | BijectionFailure::UnwitnessedFastSequence { site, .. } => site.clone(),
                        other => panic!("{host}: unexpected failure {other:?}"),
                    };
                    assert_eq!(named, site.name(), "{host}: {failures:#?}");
                }
            }
        }
    }

    #[test]
    fn exactly_one_fast_path_record_is_required_and_a_second_is_refused() {
        // "Exactly one valid record", from both sides. The missing direction is
        // above; this is the duplicate direction, which matters because a
        // checker that accepted two would read whichever it reached first and
        // report one of two disagreeing claims.
        let host = Host::current();
        let inventory = self_test_inventory();
        let harness = self_test_harness(host);
        let entries = self_test_registry(host);
        let site = EffectSiteId::Worktree(WorktreeSite::AddStaging);

        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.site == site && entry.phase == EntryPhase::NoExecution)
                .count(),
            1
        );
        // The constructor refuses the second at the same key...
        let mut registry = FaultRegistry::new();
        for entry in &entries {
            registry
                .insert(entry.clone())
                .expect("the fixture is sound");
        }
        assert!(registry.insert(no_execution_entry(site)).is_err());
        // ...and so does the bare-slice path a hand-edited registry.json takes.
        let mut doubled = entries.clone();
        doubled.push(no_execution_entry(site));
        let failures = check_bijection(&inventory, &harness, &doubled, host);
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                BijectionFailure::DuplicateEntry { site: named, phase, .. }
                    if *named == site.name() && phase == "no-execution"
            )),
            "{failures:#?}"
        );
    }

    #[test]
    fn a_destructive_sites_before_entry_names_the_target_it_is_about_to_destroy() {
        // PR3-ST07-011, as the inversion it actually was rather than as a table
        // difference.
        //
        // `transaction_fault_matrix[T-SCRUB]` is live and binding, and its
        // boundary is "task_candidate_created appended; worktree, its intent,
        // or snapshots not yet removed". So the packet-correct registry entry
        // for `Worktree.Remove`'s before hook carries `[R9]`. Under the shipped
        // authority — `EntryPhase::Before => rows: Vec::new()` for every site —
        // `validate_entry` *refused* that entry with `WrongResidueRows` and
        // *accepted* an entry claiming the worktree was already gone. Both
        // directions are asserted here, because either one alone is satisfied
        // by a table that simply says something different.
        let scrub = EffectSiteId::Worktree(WorktreeSite::Remove);
        let sound = hook_entry(scrub, EntryPhase::Before);
        assert_eq!(
            sound.expected_residue.rows,
            vec![ResourceRow::R9],
            "the fixture writes the site's own semantics, which is what the packet says"
        );
        validate_entry(&sound).expect("a packet-correct before entry must be accepted");

        let mut empty = sound.clone();
        empty.expected_residue.rows = Vec::new();
        assert!(
            matches!(
                validate_entry(&empty),
                Err(RegistryError::WrongResidueRows { .. })
            ),
            "an entry claiming the worktree is already gone before its removal was accepted"
        );
        // The detail moves with the rows, so a mutation that changed only one
        // of the two cannot pass by leaving the other alone.
        let mut wrong_detail = sound.clone();
        wrong_detail.expected_residue.detail = ResidueArtifact::Nothing.detail().to_owned();
        assert!(matches!(
            validate_entry(&wrong_detail),
            Err(RegistryError::WrongResidueDetail { .. })
        ));

        // The mirror: a one-step creation's before entry is empty, and naming
        // its row is refused. Without this, an authority that answered
        // `[row()]` for every before phase would pass the assertions above.
        // `Worktree.WriteIntent` is the mirror rather than `Worktree.Add`,
        // which is not a one-step creation — see the third case below.
        let intent = EffectSiteId::Worktree(WorktreeSite::WriteIntent);
        let sound_intent = hook_entry(intent, EntryPhase::Before);
        assert!(sound_intent.expected_residue.rows.is_empty());
        validate_entry(&sound_intent).expect("a creation's before phase names no row");
        let mut invented = sound_intent.clone();
        invented.expected_residue.rows = vec![ResourceRow::R9];
        assert!(matches!(
            validate_entry(&invented),
            Err(RegistryError::WrongResidueRows { .. })
        ));
        // The two sites share a row and a group and differ only in the
        // authority, which is what makes this a per-site claim.
        assert_eq!(scrub.row(), intent.row());
        assert_eq!(scrub.group(), intent.group());

        // PR3-ST07-014, and the third answer the row alone cannot give.
        // `transaction_fault_matrix[T-DISPATCH]`'s boundary is "worktree
        // **intent** or worktree not yet created", its resume is "recreate it
        // (**intent then add**)", and R9 is "Task worktree **+ its durable
        // synced intent**". So a kill at `Worktree.Add`'s before hook leaves
        // R9 holding that intent — and the predecessor answered `[]` here,
        // refusing the packet-correct entry and accepting one that said a
        // durable synced intent was not there.
        //
        // All three directions, because any two of them are satisfied by a
        // table that merely says something different: the rows accepted, the
        // empty rows refused, and the *other* non-empty answer's words —
        // `Worktree.Remove`'s, over the identical row — refused too. That last
        // one is what stops `PrecursorDurable` from being `Present` under
        // another name: an add whose entry claimed the worktree was present
        // and unchanged would be as false as one claiming nothing was there.
        let add = EffectSiteId::Worktree(WorktreeSite::Add);
        assert_eq!(add.row(), scrub.row());
        assert_eq!(add.group(), scrub.group());
        let sound_add = hook_entry(add, EntryPhase::Before);
        assert_eq!(sound_add.expected_residue.rows, vec![ResourceRow::R9]);
        assert_eq!(
            sound_add.expected_residue.detail,
            ResidueArtifact::PrecursorDurable.detail()
        );
        validate_entry(&sound_add).expect("the intent an add follows is durable and R9 holds it");

        let mut denied = sound_add.clone();
        denied.expected_residue.rows = Vec::new();
        denied.expected_residue.detail = ResidueArtifact::Nothing.detail().to_owned();
        assert!(
            matches!(
                validate_entry(&denied),
                Err(RegistryError::WrongResidueRows { .. })
            ),
            "an entry claiming the synced intent is not there before the add was accepted"
        );

        let mut as_if_intact = sound_add.clone();
        as_if_intact.expected_residue.detail = ResidueArtifact::TargetIntact.detail().to_owned();
        assert!(
            matches!(
                validate_entry(&as_if_intact),
                Err(RegistryError::WrongResidueDetail { .. })
            ),
            "an add's before entry claimed the worktree it is about to create is already intact"
        );
        // ...and the same words in the other direction, over the same row: the
        // removal may not borrow the add's.
        let mut as_if_precursor = sound.clone();
        as_if_precursor.expected_residue.detail =
            ResidueArtifact::PrecursorDurable.detail().to_owned();
        assert!(matches!(
            validate_entry(&as_if_precursor),
            Err(RegistryError::WrongResidueDetail { .. })
        ));

        // And the containment half, through the format rather than through the
        // table: a `Process.Spawn` kill at a Unix point that claimed the R22
        // handle — the shipped answer — is refused, and the R28 hold its own
        // detail names is accepted.
        let spawn = EffectSiteId::Process(ProcessSite::Spawn);
        for (point, packet_rows) in [
            (SubEffectPoint::ReaperStarted, vec![ResourceRow::R28]),
            (SubEffectPoint::Registered, vec![ResourceRow::R28]),
            (SubEffectPoint::CreatedSuspended, Vec::new()),
            (SubEffectPoint::Resumed, Vec::new()),
        ] {
            let phase = EntryPhase::Point {
                point,
                mode: InjectionMode::Kill,
            };
            let sound = hook_entry(spawn, phase);
            assert_eq!(sound.expected_residue.rows, packet_rows, "{point}");
            validate_entry(&sound).unwrap_or_else(|e| panic!("{point}: {e}"));
            let mut r22 = sound.clone();
            r22.expected_residue.rows = vec![ResourceRow::R22];
            assert!(
                matches!(
                    validate_entry(&r22),
                    Err(RegistryError::WrongResidueRows { .. })
                ),
                "{point} still accepts the host-process handle its own detail denies"
            );
        }
    }

    #[test]
    fn the_harness_counts_what_the_funnel_told_it_and_answers_what_is_armed() {
        let site = EffectSiteId::Event(EventSite::AppendFirst);
        let written = |mode| HookPhase::Point {
            point: SubEffectPoint::Written,
            mode,
        };
        let mut harness = HookHarness::new();

        // Unarmed: every phase proceeds. The two hook phases are reachability
        // and are counted; a point that fired nothing is *reached* and is not
        // coverage. `completeness_rule` asks for each mode "observed executed",
        // and a funnel walking past an unarmed point executed no mode.
        assert_eq!(harness.hook(site, HookPhase::Before), Injection::Proceed);
        assert_eq!(harness.hook(site, HookPhase::Before), Injection::Proceed);
        assert_eq!(
            harness.hook(site, written(InjectionMode::Kill)),
            Injection::Proceed
        );
        assert_eq!(harness.count(site, HookPhase::Before), 2);
        assert_eq!(harness.count(site, HookPhase::After), 0);
        assert_eq!(
            harness.count(site, written(InjectionMode::Kill)),
            0,
            "an unarmed point recorded a mode as executed"
        );
        assert!(
            !harness.observed(site, written(InjectionMode::Kill)),
            "an unarmed point reported coverage of its mode"
        );
        assert!(
            harness.reached_point(site, SubEffectPoint::Written, InjectionMode::Kill),
            "the funnel reached the point and the harness did not record that it had"
        );
        assert_eq!(harness.executions(), 2);

        // Armed: the injection is the mode that was armed, and only for the
        // exact (site, point, mode) triple — and *that* is the execution the
        // bijection reads.
        harness
            .arm(site, SubEffectPoint::Written, InjectionMode::Kill)
            .expect("armable");
        assert_eq!(
            harness.hook(site, written(InjectionMode::Kill)),
            Injection::Kill
        );
        assert_eq!(harness.count(site, written(InjectionMode::Kill)), 1);
        assert_eq!(
            harness.hook(site, written(InjectionMode::ErrorReturn)),
            Injection::Proceed,
            "arming kill must not arm error-return"
        );
        assert_eq!(
            harness.count(site, written(InjectionMode::ErrorReturn)),
            0,
            "arming one mode reported coverage of the other"
        );
        harness
            .arm(site, SubEffectPoint::Synced, InjectionMode::ErrorReturn)
            .expect("armable");
        assert_eq!(
            harness.hook(
                site,
                HookPhase::Point {
                    point: SubEffectPoint::Synced,
                    mode: InjectionMode::ErrorReturn
                }
            ),
            Injection::Error
        );
        assert_eq!(
            harness.count(
                site,
                HookPhase::Point {
                    point: SubEffectPoint::Synced,
                    mode: InjectionMode::ErrorReturn
                }
            ),
            1
        );
        // A different site's identical point is not armed, and not covered.
        let other = EffectSiteId::Event(EventSite::Append);
        assert_eq!(
            harness.hook(other, written(InjectionMode::Kill)),
            Injection::Proceed,
            "arming one site must not arm another"
        );
        assert_eq!(harness.count(other, written(InjectionMode::Kill)), 0);
        assert!(harness.reached_point(other, SubEffectPoint::Written, InjectionMode::Kill));
        // A hook phase never injects, whatever is armed.
        assert_eq!(harness.hook(site, HookPhase::After), Injection::Proceed);
        // Disarming keeps what was seen and stops what would be injected —
        // and a call after disarming adds reachability, not coverage.
        harness.disarm();
        assert_eq!(
            harness.hook(site, written(InjectionMode::Kill)),
            Injection::Proceed
        );
        assert!(harness.observed(site, HookPhase::After));
        assert_eq!(
            harness.count(site, written(InjectionMode::Kill)),
            1,
            "a disarmed point went on counting the mode it no longer injects"
        );
    }

    #[test]
    fn a_point_and_a_mode_are_one_coverage_coordinate_and_not_two_axes() {
        // `completeness_rule` requires "every parent-side sub-effect point (in
        // every injection mode it supports) ... observed executed at least
        // once". The unit of coverage is the pair, and the suite only ever
        // recorded matrices in which the pair happened to be recoverable from
        // its halves: drive both points in both modes and a harness that
        // reports the Cartesian product of the points it saw and the modes it
        // saw is indistinguishable from one that keeps them together, and a
        // harness whose `Synced` queries silently answer for `Written` is
        // indistinguishable too.
        //
        // Both mutations die on an *asymmetric* matrix: one where the set of
        // observed points and the set of observed modes have a product
        // strictly larger than what was observed.
        let site = EffectSiteId::Event(EventSite::AppendFirst);
        let written = SubEffectPoint::Written;
        let synced = SubEffectPoint::Synced;
        let kill = InjectionMode::Kill;
        let err = InjectionMode::ErrorReturn;
        let at = |point, mode| HookPhase::Point { point, mode };
        let fire = |harness: &mut HookHarness, point, mode| {
            harness.arm(site, point, mode).expect("a legal arming");
            harness.hook(site, at(point, mode));
            harness.disarm();
        };

        // (a) One cell. Its own row and its own column stay empty, which is
        //     what a per-point or per-mode record cannot say.
        let mut one = HookHarness::new();
        fire(&mut one, written, kill);
        assert!(one.observed(site, at(written, kill)));
        assert_eq!(one.count(site, at(written, kill)), 1);
        for (point, mode) in [(written, err), (synced, kill), (synced, err)] {
            assert!(
                !one.observed(site, at(point, mode)),
                "{point}/{mode:?} was reported present after only Written/Kill ran"
            );
            assert_eq!(one.count(site, at(point, mode)), 0, "{point}/{mode:?}");
        }
        assert_eq!(one.coverage().len(), 1, "{:?}", one.coverage());
        assert_eq!(one.executions(), 1);

        // (b) The anti-diagonal. Points {Written, Synced} and modes {Kill,
        //     ErrorReturn} were each observed, and the two cells that were not
        //     observed are exactly the ones their product invents.
        let mut diagonal = HookHarness::new();
        fire(&mut diagonal, written, kill);
        fire(&mut diagonal, synced, err);
        assert!(diagonal.observed(site, at(written, kill)));
        assert!(
            diagonal.observed(site, at(synced, err)),
            "a Synced query answered about Written"
        );
        assert!(
            !diagonal.observed(site, at(written, err)),
            "an unobserved cell was reported present by the product of its axes"
        );
        assert!(
            !diagonal.observed(site, at(synced, kill)),
            "an unobserved cell was reported present by the product of its axes"
        );
        assert_eq!(diagonal.coverage().len(), 2, "{:?}", diagonal.coverage());
        let recorded: BTreeSet<String> = diagonal
            .coverage()
            .iter()
            .map(|seen| seen.phase.to_string())
            .collect();
        assert_eq!(
            recorded,
            BTreeSet::from(["Written/kill".to_owned(), "Synced/error-return".to_owned()])
        );

        // (c) The other anti-diagonal, so neither cell of the pair is the one
        //     that happens to be reachable by a mutation's fallback.
        let mut mirrored = HookHarness::new();
        fire(&mut mirrored, written, err);
        fire(&mut mirrored, synced, kill);
        assert!(mirrored.observed(site, at(written, err)));
        assert!(mirrored.observed(site, at(synced, kill)));
        assert!(!mirrored.observed(site, at(written, kill)));
        assert!(!mirrored.observed(site, at(synced, err)));

        // (d) Reachability is the same coordinate and the same claim: walking
        //     past Synced in one mode does not report the other mode reached.
        let mut reached = HookHarness::new();
        reached.hook(site, at(synced, kill));
        assert!(reached.reached_point(site, synced, kill));
        assert!(!reached.reached_point(site, synced, err));
        assert!(!reached.reached_point(site, written, kill));

        // (e) And the bijection reads the coordinate, not the axes: with a
        //     complete registry and the anti-diagonal harness, the two absent
        //     cells are the two reported unobserved — by name, so a checker
        //     that reported the wrong pair fails here too.
        let host = Host::current();
        let inventory = vec![site];
        let entries: Vec<RegistryEntry> = [
            EntryPhase::Before,
            EntryPhase::After,
            EntryPhase::Point {
                point: written,
                mode: kill,
            },
            EntryPhase::Point {
                point: written,
                mode: err,
            },
            EntryPhase::Point {
                point: SubEffectPoint::WrittenFull,
                mode: err,
            },
            EntryPhase::Point {
                point: synced,
                mode: kill,
            },
            EntryPhase::Point {
                point: synced,
                mode: err,
            },
        ]
        .into_iter()
        .map(|phase| hook_entry(site, phase))
        .collect();

        let mut harness = HookHarness::new();
        harness.hook(site, HookPhase::Before);
        harness.hook(site, HookPhase::After);
        fire(&mut harness, written, kill);
        fire(&mut harness, synced, err);
        fire(&mut harness, SubEffectPoint::WrittenFull, err);
        let unobserved: BTreeSet<String> = check_bijection(&inventory, &harness, &entries, host)
            .into_iter()
            .filter_map(|failure| match failure {
                BijectionFailure::Unobserved { phase, .. } => Some(phase),
                _ => None,
            })
            .collect();
        assert_eq!(
            unobserved,
            BTreeSet::from(["Written/error-return".to_owned(), "Synced/kill".to_owned()]),
            "the bijection did not report exactly the two coordinates that did not run"
        );
    }

    #[test]
    fn an_unarmed_harness_substantiates_no_mode_however_far_the_funnels_run() {
        // The withheld mutation this is against, stated: "increment coverage
        // before checking whether the injector is enabled or matches the
        // reached coordinate, then inject nothing". A suite whose funnels all
        // run but whose injector is never armed — a mistargeted arming, a
        // harness reset, a feature flag off — would report every mode of every
        // point covered, which is the empty-coverage failure one level up from
        // the one §7 already guards.
        let host = Host::current();
        let mut harness = HookHarness::new();
        let mut points = 0;
        for site in self_test_inventory() {
            if !site.scope().is_claimed() {
                continue;
            }
            harness.hook(site, HookPhase::Before);
            for point in site.sub_effects() {
                if !point.platform().required_on(host) {
                    continue;
                }
                for mode in point.modes() {
                    // Reached, deliberately unarmed.
                    assert_eq!(
                        harness.hook(
                            site,
                            HookPhase::Point {
                                point: *point,
                                mode: *mode
                            }
                        ),
                        Injection::Proceed
                    );
                    points += 1;
                }
            }
            harness.hook(site, HookPhase::After);
        }
        assert!(points > 5, "the sweep was not vacuous: {points}");

        // Every point was reached and no mode was executed.
        for observation in harness.reached() {
            assert!(matches!(observation.phase, HookPhase::Point { .. }));
        }
        assert_eq!(harness.reached().len(), points);
        assert!(
            harness
                .coverage()
                .iter()
                .all(|seen| matches!(seen.phase, HookPhase::Before | HookPhase::After)),
            "an unarmed run reported an injected mode: {:?}",
            harness.coverage()
        );

        // And the bijection says so, rather than passing on the strength of a
        // full-looking coverage report.
        let failures = check_bijection(
            &self_test_inventory(),
            &harness,
            &self_test_registry(host),
            host,
        );
        let unobserved: Vec<&BijectionFailure> = failures
            .iter()
            .filter(|failure| matches!(failure, BijectionFailure::Unobserved { .. }))
            .collect();
        assert_eq!(
            unobserved.len(),
            points,
            "an unarmed harness substantiated {} of {points} mode(s): {failures:#?}",
            points - unobserved.len()
        );
    }

    #[test]
    fn the_harness_refuses_to_arm_a_point_or_mode_the_site_does_not_have() {
        let mut harness = HookHarness::new();
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let append = EffectSiteId::Event(EventSite::AppendFirst);

        // A point the site does not expose.
        let error = harness
            .arm(commit_tree, SubEffectPoint::Written, InjectionMode::Kill)
            .expect_err("CandidateCommitTree exposes only IdUnread");
        assert!(
            matches!(error, HarnessError::NoSuchPoint { ref point, .. } if *point == SubEffectPoint::Written),
            "{error}"
        );
        // A mode the point does not support.
        let error = harness
            .arm(
                commit_tree,
                SubEffectPoint::IdUnread,
                InjectionMode::ErrorReturn,
            )
            .expect_err("IdUnread is kill-only");
        assert!(
            matches!(error, HarnessError::UnsupportedMode { mode, .. } if mode == InjectionMode::ErrorReturn),
            "{error}"
        );
        // A site with no points at all.
        let lock = EffectSiteId::Lock(LockSite::AcquireRun);
        assert!(
            harness
                .arm(lock, SubEffectPoint::Synced, InjectionMode::Kill)
                .is_err()
        );
        // And the legal ones are legal.
        harness
            .arm(commit_tree, SubEffectPoint::IdUnread, InjectionMode::Kill)
            .expect("the one point it has, in the one mode it supports");
        for mode in InjectionMode::ALL {
            harness
                .arm(append, SubEffectPoint::Written, *mode)
                .expect("an append point supports both modes");
        }
        // A refused arming armed nothing and recorded nothing.
        assert!(harness.coverage().is_empty());
    }

    // -----------------------------------------------------------------------
    // The registry format
    // -----------------------------------------------------------------------

    #[test]
    fn a_residue_class_entry_with_an_executed_hook_claim_is_refused() {
        // ST-07's load-bearing clause, on its own, in both the ways the claim
        // can be made: through the evidence and through the label.
        let site = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let sound = residue_entry(site, 61, 0);
        FaultRegistry::new()
            .insert(sound.clone())
            .expect("a well-formed recovery-proven entry");

        let mut claims_by_evidence = sound.clone();
        claims_by_evidence.evidence = Evidence::Executed {
            test: "st07::pretending_the_internal_point_ran".to_owned(),
            passed: true,
        };
        let error = FaultRegistry::new()
            .insert(claims_by_evidence.clone())
            .expect_err("executed-hook evidence for a residue class");
        assert!(
            matches!(error, RegistryError::ResidueClaimsExecution { .. }),
            "{error}"
        );

        let mut claims_by_label = sound.clone();
        claims_by_label.label = EvidenceLabel::ExecutionObserved;
        let error = FaultRegistry::new()
            .insert(claims_by_label.clone())
            .expect_err("an execution-observed label on a residue class");
        assert!(
            matches!(error, RegistryError::ResidueClaimsExecution { .. }),
            "{error}"
        );

        // And the bijection refuses the same document, because a registry.json
        // handed to a reviewer never went through `insert`.
        let host = Host::current();
        for bad in [claims_by_evidence, claims_by_label] {
            let mut entries = self_test_registry(host);
            let slot = entries
                .iter()
                .position(|entry| entry.key() == bad.key())
                .expect("the self-test registry holds this key");
            entries[slot] = bad;
            let failures = check_bijection(
                &self_test_inventory(),
                &self_test_harness(host),
                &entries,
                host,
            );
            assert!(
                failures
                    .iter()
                    .any(|f| matches!(f, BijectionFailure::ResidueClaimsExecution { .. })),
                "{failures:#?}"
            );
        }

        // The converse is refused too: a hook entry cannot borrow the label
        // that exists for what no hook can reach.
        let mut hook = hook_entry(site, EntryPhase::Before);
        hook.label = EvidenceLabel::RecoveryProven;
        hook.evidence = match sound.evidence.clone() {
            evidence @ Evidence::RecoveryProven { .. } => evidence,
            _ => unreachable!("the sound entry is recovery-proven"),
        };
        let error = FaultRegistry::new()
            .insert(hook)
            .expect_err("a before-phase claiming recovery-proven evidence");
        assert!(
            matches!(error, RegistryError::HookClaimsRecoveryProof { .. }),
            "{error}"
        );
    }

    #[test]
    fn the_format_admits_exactly_one_evidence_shape_and_label_per_phase_kind() {
        // The crossed grid: five phase kinds x three evidence shapes x two
        // labels. Five cells are legal and twenty-five are refused; the whole
        // thirty are enumerated rather than sampled, because any smaller set
        // is satisfiable by a rule that happens to agree on the cases tried.
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let skipped = EffectSiteId::Object(ObjectSite::ProposalCherryPick);
        let phases = [
            (commit_tree, EntryPhase::Before),
            (commit_tree, EntryPhase::After),
            (
                commit_tree,
                EntryPhase::Point {
                    point: SubEffectPoint::IdUnread,
                    mode: InjectionMode::Kill,
                },
            ),
            (
                commit_tree,
                EntryPhase::Residue {
                    class: ResidueClass::ObjectInternal,
                },
            ),
            (skipped, EntryPhase::NoExecution),
        ];
        let executed = Evidence::Executed {
            test: "grid::executed".to_owned(),
            passed: true,
        };
        let not_executed = Evidence::NotExecuted {
            test: "grid::not-executed".to_owned(),
            passed: true,
            sequences: FAST_SEQUENCES
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        };
        let recovery = match residue_entry(commit_tree, 61, 0).evidence {
            evidence @ Evidence::RecoveryProven { .. } => evidence,
            _ => unreachable!(),
        };
        let recovery_for_skipped = match residue_entry(skipped, 23, 4).evidence {
            evidence @ Evidence::RecoveryProven { .. } => evidence,
            _ => unreachable!(),
        };

        let mut legal = 0;
        let mut refused = 0;
        for (site, phase) in phases {
            for evidence_kind in 0..3 {
                for label in [
                    EvidenceLabel::ExecutionObserved,
                    EvidenceLabel::RecoveryProven,
                ] {
                    let evidence = match evidence_kind {
                        0 => executed.clone(),
                        1 => not_executed.clone(),
                        _ if site == skipped => recovery_for_skipped.clone(),
                        _ => recovery.clone(),
                    };
                    let mut entry = hook_entry(site, phase);
                    if phase == EntryPhase::NoExecution {
                        entry.order = None;
                    }
                    entry.evidence = evidence;
                    entry.label = label;

                    let expected_legal = matches!(
                        (phase, evidence_kind, label),
                        (
                            EntryPhase::Before | EntryPhase::After | EntryPhase::Point { .. },
                            0,
                            EvidenceLabel::ExecutionObserved
                        ) | (EntryPhase::NoExecution, 1, EvidenceLabel::ExecutionObserved)
                            | (EntryPhase::Residue { .. }, 2, EvidenceLabel::RecoveryProven)
                    );
                    let result = FaultRegistry::new().insert(entry);
                    assert_eq!(
                        result.is_ok(),
                        expected_legal,
                        "phase {phase}, evidence {evidence_kind}, label {label:?}: {result:?}"
                    );
                    if expected_legal {
                        legal += 1;
                    } else {
                        refused += 1;
                    }
                }
            }
        }
        assert_eq!((legal, refused), (5, 25));
    }

    #[test]
    fn the_format_refuses_an_entry_that_disagrees_with_the_site_it_names() {
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let append = EffectSiteId::Event(EventSite::AppendFirst);

        // A fault row that is not the site's.
        let mut entry = hook_entry(commit_tree, EntryPhase::Before);
        entry.fault_row = FaultRow::TFinish;
        assert!(matches!(
            FaultRegistry::new().insert(entry).expect_err("wrong row"),
            RegistryError::WrongFaultRow { .. }
        ));

        // An order the site cannot leave observable, in both directions: a
        // site with one order carrying the other or none, and a site with no
        // order carrying one.
        let mut entry = hook_entry(commit_tree, EntryPhase::Before);
        entry.order = Some(ObservableOrder::EventBeforeEffect);
        assert!(matches!(
            FaultRegistry::new().insert(entry).expect_err("wrong order"),
            RegistryError::WrongOrder { .. }
        ));
        let mut entry = hook_entry(commit_tree, EntryPhase::Before);
        entry.order = None;
        assert!(matches!(
            FaultRegistry::new()
                .insert(entry)
                .expect_err("missing order"),
            RegistryError::WrongOrder { .. }
        ));
        let mut entry = hook_entry(append, EntryPhase::Before);
        entry.order = Some(ObservableOrder::EffectBeforeEvent);
        assert!(matches!(
            FaultRegistry::new()
                .insert(entry)
                .expect_err("an append has no order"),
            RegistryError::WrongOrder { .. }
        ));

        // A point the site does not expose, and a mode it does not support.
        let entry = hook_entry(
            commit_tree,
            EntryPhase::Point {
                point: SubEffectPoint::Written,
                mode: InjectionMode::Kill,
            },
        );
        assert!(matches!(
            FaultRegistry::new()
                .insert(entry)
                .expect_err("no such point"),
            RegistryError::NoSuchPoint { .. }
        ));
        let entry = hook_entry(
            commit_tree,
            EntryPhase::Point {
                point: SubEffectPoint::IdUnread,
                mode: InjectionMode::ErrorReturn,
            },
        );
        assert!(matches!(
            FaultRegistry::new()
                .insert(entry)
                .expect_err("no such mode"),
            RegistryError::NoSuchPoint { .. }
        ));

        // A residue class the site does not register.
        let entry = hook_entry(
            append,
            EntryPhase::Residue {
                class: ResidueClass::ObjectInternal,
            },
        );
        assert!(matches!(
            FaultRegistry::new()
                .insert(entry)
                .expect_err("no such class"),
            RegistryError::NoSuchResidueClass { .. }
        ));

        // A no-execution record for a site a fast sequence does not skip.
        let entry = no_execution_entry(append);
        assert!(matches!(
            FaultRegistry::new()
                .insert(entry)
                .expect_err("only three sites may claim they did not run"),
            RegistryError::NoExecutionNotSkipped { .. }
        ));
        for site in fast_path_skipped() {
            FaultRegistry::new()
                .insert(no_execution_entry(site))
                .expect("the three the design names");
        }
    }

    #[test]
    fn the_format_refuses_an_incomplete_or_invented_synthetic_record() {
        let site = EffectSiteId::Object(ObjectSite::ProposalCherryPick);
        assert_eq!(site.residue_elements().len(), 7);

        // Every element removed in turn: a class whose evidence skipped one is
        // a class whose recovery was never shown for that element.
        for absent in site.residue_elements() {
            let mut entry = residue_entry(site, 23, 4);
            if let Evidence::RecoveryProven { synthetic, .. } = &mut entry.evidence {
                synthetic.retain(|record| record.element != *absent);
            }
            let error = FaultRegistry::new()
                .insert(entry)
                .expect_err("a missing element");
            assert!(
                matches!(error, RegistryError::MissingSyntheticElement { element, .. } if element == *absent),
                "{error}"
            );
        }

        // And an element the site's command cannot leave: a `MERGE_HEAD` in a
        // repair worktree that only ever cherry-picks one commit is evidence
        // about something that never happens there.
        let repair = EffectSiteId::Object(ObjectSite::RepairMaterialize);
        let mut entry = residue_entry(repair, 23, 4);
        if let Evidence::RecoveryProven { synthetic, .. } = &mut entry.evidence {
            synthetic.push(SyntheticRecord {
                element: ResidueElement::MergeHead,
                constructed: true,
                classified: ObjectResidue::Internal,
                recovered: true,
            });
        }
        let error = FaultRegistry::new()
            .insert(entry)
            .expect_err("an unlisted element");
        assert!(
            matches!(error, RegistryError::UnlistedSyntheticElement { element, .. } if element == ResidueElement::MergeHead),
            "{error}"
        );
    }

    #[test]
    fn the_expected_residue_of_a_phase_is_the_sites_own_semantics() {
        // The values, written from `fault_injection_registry.structure` rather
        // than read back from `expected_rows`, so this pins the table and not
        // merely today's output of it.
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let repair = EffectSiteId::Object(ObjectSite::RepairMaterialize);
        let append = EffectSiteId::Event(EventSite::AppendFirst);
        let staging = EffectSiteId::Worktree(WorktreeSite::AddStaging);
        let internal = EntryPhase::Residue {
            class: ResidueClass::ObjectInternal,
        };
        let id_unread = EntryPhase::Point {
            point: SubEffectPoint::IdUnread,
            mode: InjectionMode::Kill,
        };

        // The before phase, from the packet and not from the code.
        //
        // "Object sites carry entries — before: no object (hook)" — the whole
        // group, by name.
        for site in EffectSiteId::all() {
            if site.group() == FunnelGroup::Object {
                assert!(site.expected_rows(EntryPhase::Before).is_empty(), "{site}");
            }
            assert!(
                site.expected_rows(EntryPhase::NoExecution).is_empty(),
                "{site}"
            );
        }
        // `transaction_fault_matrix[T-SCRUB]` — live and binding — boundary:
        // "task_candidate_created appended; worktree, its intent, or snapshots
        // not yet removed". The worktree is still there, and R9 is the row that
        // holds "task worktree + its durable synced intent, and the objects its
        // index or HEAD references".
        //
        // This is PR3-ST07-011's witness. Under the shipped authority the
        // literal `[R9]` below was the value `validate_entry` *refused*, and an
        // entry claiming an empty before phase was the one it accepted.
        let scrub = EffectSiteId::Worktree(WorktreeSite::Remove);
        assert_eq!(scrub.fault_row(), FaultRow::TScrub);
        assert_eq!(scrub.row(), ResourceRow::R9);
        assert_eq!(
            scrub.expected_rows(EntryPhase::Before),
            vec![ResourceRow::R9]
        );
        assert_eq!(
            scrub.semantics(EntryPhase::Before).artifact,
            ResidueArtifact::TargetIntact
        );
        // The same matrix row covers the intent and the snapshots it names.
        for site in [
            EffectSiteId::Worktree(WorktreeSite::RemoveIntent),
            EffectSiteId::Snapshot(SnapshotSite::Remove),
            EffectSiteId::Snapshot(SnapshotSite::RemoveIntent),
        ] {
            assert_eq!(site.fault_row(), FaultRow::TScrub, "{site}");
            assert_eq!(site.expected_rows(EntryPhase::Before), vec![site.row()]);
        }
        // T-FAST: "assert_publishable read the integration ref head H ==
        // candidate.base_sha" — the CAS replaces a head that is there.
        let cas = EffectSiteId::Ref(RefSite::CompareAndSwapIntegration);
        assert_eq!(cas.fault_row(), FaultRow::TFast);
        assert_eq!(
            cas.expected_rows(EntryPhase::Before),
            vec![ResourceRow::R21]
        );
        // T-RUNSTART: "no ref until P8" — the creation of the same ref, in the
        // same row, finds nothing. The two differ in the authority and not in
        // anything a generic rule over R21 could see.
        let create_ref = EffectSiteId::Ref(RefSite::CreateIntegration);
        assert_eq!(create_ref.row(), cas.row());
        assert!(create_ref.expected_rows(EntryPhase::Before).is_empty());
        // T-CAND-OBJ (b): "the object and the candidate-prepared pin (R23)
        // exist" — so the deletion of that pin finds it, and the pinning does
        // not: "(a) ... and no pin exists".
        assert_eq!(
            EffectSiteId::Ref(RefSite::DeleteCandidatePin).expected_rows(EntryPhase::Before),
            vec![ResourceRow::R23]
        );
        assert!(
            EffectSiteId::Ref(RefSite::PinCandidatePrepared)
                .expected_rows(EntryPhase::Before)
                .is_empty()
        );
        // T-RUNSTART again: "P6 run_started durable ..., marker still present;
        // P7 marker removed".
        assert_eq!(
            EffectSiteId::RunDir(RunDirSite::RemoveMarker).expected_rows(EntryPhase::Before),
            vec![ResourceRow::R21]
        );
        // ...and "P1 marker **staged (.creating.tmp)** or published
        // (.creating ...)": the publication renames a temporary its own
        // staging site made durable, so R21 holds something at its before hook
        // — and what it holds is not the marker, so the words differ from
        // `RemoveMarker`'s even though the row does not.
        assert_eq!(
            EffectSiteId::RunDir(RunDirSite::PublishMarker).expected_rows(EntryPhase::Before),
            vec![ResourceRow::R21]
        );
        assert_eq!(
            EffectSiteId::RunDir(RunDirSite::PublishMarker)
                .semantics(EntryPhase::Before)
                .artifact,
            ResidueArtifact::PrecursorDurable
        );
        assert!(
            EffectSiteId::RunDir(RunDirSite::StageMarker)
                .expected_rows(EntryPhase::Before)
                .is_empty(),
            "the staging is the first half of the pair and finds nothing"
        );
        // PR3-ST07-014. `transaction_fault_matrix[T-DISPATCH]` — live and
        // binding — puts the boundary at "worktree **intent** or worktree not
        // yet created" and tables the resume as "recreate it (**intent then
        // add**)"; R9 is "Task worktree **+ its durable synced intent**". So a
        // kill at `Worktree.Add`'s before hook leaves R9 holding that intent.
        // The predecessor answered `[]` here and refused exactly the literal
        // below.
        let add = EffectSiteId::Worktree(WorktreeSite::Add);
        assert_eq!(add.row(), ResourceRow::R9);
        assert_eq!(add.fault_row(), FaultRow::TDispatch);
        assert_eq!(add.expected_rows(EntryPhase::Before), vec![ResourceRow::R9]);
        assert_eq!(
            add.semantics(EntryPhase::Before).artifact,
            ResidueArtifact::PrecursorDurable
        );
        // And the row is the same one `Worktree.Remove` names while the words
        // are not: R9 holds the intent here and the worktree there, and an
        // entry that said "the artifact this site acts on is present and
        // unchanged" of an add would be false.
        let scrub_words = EffectSiteId::Worktree(WorktreeSite::Remove)
            .semantics(EntryPhase::Before)
            .artifact;
        assert_eq!(scrub_words, ResidueArtifact::TargetIntact);
        assert_ne!(
            add.semantics(EntryPhase::Before).artifact.detail(),
            scrub_words.detail()
        );
        // The intent that add follows is itself a creation, and finds nothing.
        assert!(
            EffectSiteId::Worktree(WorktreeSite::WriteIntent)
                .expected_rows(EntryPhase::Before)
                .is_empty(),
            "the first half of the pair creates the intent it is about to write"
        );
        // WHERE THIS CLASSIFICATION STOPS, as an assertion rather than a
        // paragraph. `RunDir.CreatePrivateDir` runs at T-RUNSTART's P3a, after
        // "P0 public directory created" and "P1 marker ... published" — both
        // durable, both accounted for by R21, the same row this site names —
        // and its before phase still names nothing, because neither is an
        // earlier state of the private directory. A before phase names this
        // site's own artifact, not the durable prefix of its transaction.
        assert_eq!(
            EffectSiteId::RunDir(RunDirSite::CreatePrivateDir).row(),
            ResourceRow::R21
        );
        assert!(
            EffectSiteId::RunDir(RunDirSite::CreatePrivateDir)
                .expected_rows(EntryPhase::Before)
                .is_empty(),
            "the public half is durable at P3a and this entry does not claim it"
        );
        assert!(
            EffectSiteId::Event(EventSite::Append)
                .expected_rows(EntryPhase::Before)
                .is_empty(),
            "an append names the line it appends, not the log the open created"
        );
        // The containment rows, from `containment_sub_effects`: Windows kills
        // leave "no host process", Unix kills leave a group "the reaper settles
        // while holding R28". Both were R22 — the host-process handle row — and
        // both contradicted their own entry's detail.
        let spawn = EffectSiteId::Process(ProcessSite::Spawn);
        assert_eq!(spawn.row(), ResourceRow::R22);
        for point in [
            SubEffectPoint::AmbientJobJoined,
            SubEffectPoint::CreatedSuspended,
            SubEffectPoint::PrivateJobAssigned,
            SubEffectPoint::Resumed,
        ] {
            let phase = EntryPhase::Point {
                point,
                mode: InjectionMode::Kill,
            };
            assert!(spawn.expected_rows(phase).is_empty(), "{point}");
            assert_eq!(
                spawn.semantics(phase).artifact,
                ResidueArtifact::NoHostProcess
            );
        }
        for point in [
            SubEffectPoint::ReaperStarted,
            SubEffectPoint::PreExecPgidAndRegister,
            SubEffectPoint::Exec,
            SubEffectPoint::Registered,
        ] {
            let phase = EntryPhase::Point {
                point,
                mode: InjectionMode::Kill,
            };
            assert_eq!(
                spawn.expected_rows(phase),
                vec![ResourceRow::R28],
                "{point}"
            );
            assert_eq!(
                spawn.semantics(phase).artifact,
                ResidueArtifact::ReaperHeldGroup
            );
        }
        // And R22 is not left unused by the repair: the site's own after phase
        // is still the handle row, which is what makes the point rows a
        // statement about the points rather than a blanket change.
        assert_eq!(
            spawn.expected_rows(EntryPhase::After),
            vec![ResourceRow::R22]
        );
        // "after: the object present and referenced by the row named by row(),
        // or unreferenced R27 for the commit-tree sites"
        assert_eq!(
            commit_tree.expected_rows(EntryPhase::After),
            vec![ResourceRow::R27]
        );
        assert_eq!(commit_tree.row(), ResourceRow::R27);
        assert_eq!(
            append.expected_rows(EntryPhase::After),
            vec![ResourceRow::R21]
        );
        assert_eq!(
            staging.expected_rows(EntryPhase::After),
            vec![staging.row()]
        );
        // "IdUnread ... R27 object without a recorded id"
        assert_eq!(commit_tree.expected_rows(id_unread), vec![ResourceRow::R27]);
        // "Internal residue class ... objects present and unreferenced, R27,
        // with administrative residue in the owning worktree"
        assert_eq!(commit_tree.expected_rows(internal), vec![ResourceRow::R27]);
        assert_eq!(
            repair.expected_rows(internal),
            vec![ResourceRow::R27, repair.row()]
        );
        assert_ne!(
            repair.row(),
            ResourceRow::R27,
            "the two-row case has to be a site whose own row is not R27, or it is the one-row case"
        );

        // And the two phases `structure` binds to the before-phase action, and
        // no others.
        assert!(id_unread.resumes_as_before());
        assert!(internal.resumes_as_before());
        for phase in [
            EntryPhase::Before,
            EntryPhase::After,
            EntryPhase::NoExecution,
            EntryPhase::Point {
                point: SubEffectPoint::Written,
                mode: InjectionMode::Kill,
            },
        ] {
            assert!(!phase.resumes_as_before(), "{phase}");
        }
    }

    #[test]
    fn the_format_refuses_residue_and_resume_semantics_the_site_does_not_have() {
        // A2's and A3's shared blind spot: an entry can be complete, correctly
        // keyed, correctly labelled and carry passing evidence while claiming
        // that a fault at its point leaves an unrelated ledger row and that a
        // resume does something the fault matrix does not say. Neither field
        // was consulted, so a unique garbage string in either satisfied the
        // fixture's own diversity counts as well as a right answer would.
        let host = Host::current();
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let internal = EntryPhase::Residue {
            class: ResidueClass::ObjectInternal,
        };

        // Wrong rows, one wrong way at a time, for a residue class whose
        // authority is R27 alone.
        for (label, rows) in [
            ("an unrelated row", vec![ResourceRow::R9]),
            ("no rows at all", Vec::new()),
            (
                "R27 plus a row this site does not hold",
                vec![ResourceRow::R27, ResourceRow::R24],
            ),
            (
                "the right row twice",
                vec![ResourceRow::R27, ResourceRow::R27],
            ),
        ] {
            let mut entry = residue_entry(commit_tree, 61, 0);
            entry.expected_residue.rows = rows.clone();
            let error = validate_entry(&entry)
                .expect_err("an entry claiming residue the site does not leave");
            assert!(
                matches!(error, RegistryError::WrongResidueRows { .. }),
                "{label} was accepted: {error}"
            );
            assert_eq!(
                FaultRegistry::new().insert(entry.clone()),
                Err(match validate_entry(&entry) {
                    Err(error) => error,
                    Ok(()) => unreachable!("just refused"),
                }),
                "{label} was accepted by the constructor"
            );
        }

        // An after-phase entry that claims the before-phase's empty residue,
        // and a before-phase entry that claims the after-phase's row: the two
        // directions of the same relation.
        let mut empty_after = hook_entry(commit_tree, EntryPhase::After);
        empty_after.expected_residue.rows = Vec::new();
        assert!(matches!(
            validate_entry(&empty_after),
            Err(RegistryError::WrongResidueRows { .. })
        ));
        let mut full_before = hook_entry(commit_tree, EntryPhase::Before);
        full_before.expected_residue.rows = vec![ResourceRow::R27];
        assert!(matches!(
            validate_entry(&full_before),
            Err(RegistryError::WrongResidueRows { .. })
        ));

        // A resume action that is not a resume action at all.
        let mut unnamed = hook_entry(commit_tree, EntryPhase::Before);
        unnamed.resume_action = "   ".to_owned();
        assert!(matches!(
            validate_entry(&unnamed),
            Err(RegistryError::UnnamedResumeAction { .. })
        ));

        // A resume action that is a resume action and is not this one. The
        // blank check above was the whole of what the format asked of the
        // field for every phase but two, so a unique, plausible, false claim
        // passed — and passed the fixture's own diversity counts while it did.
        for phase in [
            EntryPhase::Before,
            EntryPhase::After,
            EntryPhase::Point {
                point: SubEffectPoint::IdUnread,
                mode: InjectionMode::Kill,
            },
            internal,
        ] {
            let mut entry = if phase == internal {
                residue_entry(commit_tree, 61, 0)
            } else {
                hook_entry(commit_tree, phase)
            };
            entry.resume_action = "retry the command from the start".to_owned();
            let error = validate_entry(&entry).expect_err("a resume the matrix does not table");
            assert!(
                matches!(error, RegistryError::WrongResumeAction { .. }),
                "{phase}: {error}"
            );

            let mut entry = if phase == internal {
                residue_entry(commit_tree, 61, 0)
            } else {
                hook_entry(commit_tree, phase)
            };
            entry.expected_residue.detail = "some durable state or other".to_owned();
            let error = validate_entry(&entry).expect_err("residue the site does not leave");
            assert!(
                matches!(error, RegistryError::WrongResidueDetail { .. }),
                "{phase}: {error}"
            );
        }

        // Swapping two real answers is the sharper direction: both strings are
        // the matrix's own words, and neither belongs to this coordinate.
        let mut swapped = hook_entry(commit_tree, EntryPhase::After);
        swapped.expected_residue.detail = commit_tree
            .semantics(EntryPhase::Before)
            .artifact
            .detail()
            .to_owned();
        assert!(matches!(
            validate_entry(&swapped),
            Err(RegistryError::WrongResidueDetail { .. })
        ));
        let mut swapped = hook_entry(commit_tree, EntryPhase::After);
        swapped.resume_action = commit_tree
            .semantics(EntryPhase::Before)
            .action
            .text()
            .to_owned();
        assert!(matches!(
            validate_entry(&swapped),
            Err(RegistryError::WrongResumeAction { .. })
        ));

        // And the relation that needs the whole slice: `IdUnread` and the
        // `Internal` class resume by the site's *before-phase* action. The
        // format now refuses the entry on its own — the authority tables one
        // action for the coordinate — and `check_bijection`, which collects
        // failures rather than stopping at the first, still names the relation
        // it breaks as well as the entry it invalidates.
        for phase in [
            internal,
            EntryPhase::Point {
                point: SubEffectPoint::IdUnread,
                mode: InjectionMode::Kill,
            },
        ] {
            let mut entries = self_test_registry(host);
            let position = entries
                .iter()
                .position(|entry| entry.site == commit_tree && entry.phase == phase)
                .expect("the fixture carries this entry");
            entries[position].resume_action = "do nothing".to_owned();
            let failures = check_bijection(
                &self_test_inventory(),
                &self_test_harness(host),
                &entries,
                host,
            );
            assert!(
                failures.iter().any(|failure| matches!(
                    failure,
                    BijectionFailure::ResumeActionNotBeforeAction { .. }
                )),
                "a {phase} entry resuming by something other than the before-phase action passed: \
                 {failures:#?}"
            );
            assert!(
                failures
                    .iter()
                    .any(|failure| matches!(failure, BijectionFailure::InvalidEntry { .. })),
                "{failures:#?}"
            );
        }
    }

    #[test]
    fn a_pruning_sites_after_phase_records_the_objects_it_released() {
        // `structure`: "the pruning sites' after-phase entries record the
        // released objects as R27 residue". The framework shipped with one
        // `After | Point => vec![self.row()]` arm, so the packet-required entry
        // was *refused* and the wrong one — a removed worktree still held by
        // R9 — was the only one the format would take.
        let removed = EffectSiteId::Worktree(WorktreeSite::Remove);
        assert_eq!(removed.row(), ResourceRow::R9, "the row it accounted for");
        assert_eq!(
            removed.expected_rows(EntryPhase::After),
            vec![ResourceRow::R27],
            "a forced removal releases its index-referenced objects and keeps nothing"
        );

        let mut entry = hook_entry(removed, EntryPhase::After);
        validate_entry(&entry).expect("the packet-required released-object entry");
        entry.expected_residue.rows = vec![removed.row()];
        assert!(
            matches!(
                validate_entry(&entry),
                Err(RegistryError::WrongResidueRows { .. })
            ),
            "a removed worktree is still accounted for by the row it no longer occupies"
        );

        // Every pruning site the packet names, and only those: `Worktree.Remove`
        // and `Worktree.RemoveStaging`, `Snapshot.Remove`, and `Ref.Delete*`.
        let released: BTreeSet<String> = EffectSiteId::all()
            .into_iter()
            .filter(|site| site.after_effect() == AfterEffect::Released)
            .map(|site| site.name())
            .collect();
        assert_eq!(
            released,
            BTreeSet::from([
                "Worktree.Remove".to_owned(),
                "Worktree.RemoveStaging".to_owned(),
                "Snapshot.Remove".to_owned(),
                "Ref.DeleteCandidatesRef".to_owned(),
                "Ref.DeleteCandidatePin".to_owned(),
                "Ref.DeletePreparedPin".to_owned(),
            ])
        );
        for site in EffectSiteId::all() {
            if site.after_effect() != AfterEffect::Released {
                continue;
            }
            assert_eq!(
                site.expected_rows(EntryPhase::After),
                vec![ResourceRow::R27],
                "{site}"
            );
            assert_eq!(
                site.semantics(EntryPhase::After).artifact,
                ResidueArtifact::Released,
                "{site}"
            );
        }
    }

    #[test]
    fn both_commit_tree_sites_leave_an_unrecorded_id_at_r27() {
        // "IdUnread for the two commit-tree sites (hook; R27 object without a
        // recorded id)". Both, and stated rather than inherited from `row()`:
        // `row()` is R27 for both today, which is exactly why moving one of
        // them to R24 survived the suite.
        let id_unread = EntryPhase::Point {
            point: SubEffectPoint::IdUnread,
            mode: InjectionMode::Kill,
        };
        let sites: Vec<EffectSiteId> = EffectSiteId::all()
            .into_iter()
            .filter(|site| site.sub_effects().contains(&SubEffectPoint::IdUnread))
            .collect();
        assert_eq!(
            sites,
            vec![
                EffectSiteId::Object(ObjectSite::SnapshotCommitTree),
                EffectSiteId::Object(ObjectSite::CandidateCommitTree),
            ],
            "the two the packet names, in inventory order"
        );
        for site in sites {
            assert_eq!(
                site.expected_rows(id_unread),
                vec![ResourceRow::R27],
                "{site}"
            );
            let semantics = site.semantics(id_unread);
            assert_eq!(semantics.artifact, ResidueArtifact::IdNotRecorded, "{site}");
            assert_eq!(
                semantics.action,
                site.semantics(EntryPhase::Before).action,
                "{site}: \"resume action = the before-phase action\""
            );
            let mut entry = hook_entry(site, id_unread);
            validate_entry(&entry).expect("the packet's own entry");
            entry.expected_residue.rows = vec![ResourceRow::R24];
            assert!(matches!(
                validate_entry(&entry),
                Err(RegistryError::WrongResidueRows { .. })
            ));
        }
    }

    /// Every site of the inventory and what its *after* phase leaves, written
    /// out by dotted name from the packet's own words rather than derived from
    /// the enums.
    ///
    /// Independent of the production table in the way that matters: production
    /// classifies by variant pattern, in eleven grouped matches, and this is a
    /// flat list keyed by the name the wire format uses. A production arm that
    /// merges two variants, moves one between buckets, or acquires a default
    /// disagrees with a row here; a site added to a group and forgotten here
    /// fails the totality assertion below rather than passing unclassified.
    ///
    /// Reading:
    ///
    /// * `Referenced` — the site publishes something and its own `row()`
    ///   references it afterwards.
    /// * `Unreferenced` — "unreferenced R27 for the commit-tree sites".
    /// * `Released` — a pruning site: "the release of objects to R27 is never
    ///   a separate effect but the after-phase residue of the pruning sites
    ///   (Worktree.Remove, Snapshot.Remove, Ref.Delete*), whose entries record
    ///   it", and `effect_phases_covered`'s "worktree/staging/snapshot ...
    ///   removals (forced; with the objects they referenced released to R27
    ///   and administrative residue removed)".
    /// * `Removed` — a removal with no objects to release: the row that
    ///   accounted for what it removed holds nothing afterwards.
    /// * `NoEffect` — the four sites the design says perform no effect.
    const AFTER_EFFECT_ORACLE: &[(&str, AfterEffect)] = &[
        ("Worktree.CreateExecutionRoot", AfterEffect::Referenced),
        ("Worktree.RemoveExecutionRoot", AfterEffect::Removed),
        ("Worktree.WriteIntent", AfterEffect::Referenced),
        ("Worktree.Add", AfterEffect::Referenced),
        ("Worktree.Verify", AfterEffect::NoEffect),
        ("Worktree.Remove", AfterEffect::Released),
        ("Worktree.RemoveIntent", AfterEffect::Removed),
        ("Worktree.WriteStagingIntent", AfterEffect::Referenced),
        ("Worktree.AddStaging", AfterEffect::Referenced),
        ("Worktree.RemoveStaging", AfterEffect::Released),
        ("Worktree.RemoveStagingIntent", AfterEffect::Removed),
        ("Snapshot.WriteIntent", AfterEffect::Referenced),
        ("Snapshot.Add", AfterEffect::Referenced),
        ("Snapshot.Remove", AfterEffect::Released),
        ("Snapshot.RemoveIntent", AfterEffect::Removed),
        ("Ref.CreateIntegration", AfterEffect::Referenced),
        ("Ref.CompareAndSwapIntegration", AfterEffect::Referenced),
        ("Ref.CreateCandidates", AfterEffect::Referenced),
        ("Ref.DeleteCandidatesRef", AfterEffect::Released),
        ("Ref.PinCandidatePrepared", AfterEffect::Referenced),
        ("Ref.DeleteCandidatePin", AfterEffect::Released),
        ("Ref.PinPrepared", AfterEffect::Referenced),
        ("Ref.DeletePreparedPin", AfterEffect::Released),
        ("Object.CandidateStage", AfterEffect::Referenced),
        ("Object.CandidateWriteTree", AfterEffect::Referenced),
        ("Object.SnapshotCommitTree", AfterEffect::Unreferenced),
        ("Object.CandidateCommitTree", AfterEffect::Unreferenced),
        ("Object.ProposalCherryPick", AfterEffect::Referenced),
        ("Object.RepairMaterialize", AfterEffect::Referenced),
        ("RunDir.CreatePublicDir", AfterEffect::Referenced),
        ("RunDir.StageMarker", AfterEffect::Referenced),
        ("RunDir.PublishMarker", AfterEffect::Referenced),
        ("RunDir.RemoveMarker", AfterEffect::Removed),
        ("RunDir.CreatePrivateDir", AfterEffect::Referenced),
        ("RunDir.StageOwnerRecord", AfterEffect::Referenced),
        ("RunDir.PublishOwnerRecord", AfterEffect::Referenced),
        ("RunDir.StageCommitRecord", AfterEffect::Referenced),
        ("RunDir.PublishCommitRecord", AfterEffect::Referenced),
        ("RunDir.WritePlan", AfterEffect::Referenced),
        ("RunDir.WriteReport", AfterEffect::Referenced),
        ("RunDir.WriteQuestionPayload", AfterEffect::Referenced),
        ("RunDir.RemovePrivateHusk", AfterEffect::Removed),
        ("RunDir.RemovePublicHusk", AfterEffect::Removed),
        ("Event.OpenLog", AfterEffect::Referenced),
        ("Event.ProvePrefixStable", AfterEffect::NoEffect),
        ("Event.AppendFirst", AfterEffect::Referenced),
        ("Event.Append", AfterEffect::Referenced),
        ("Event.AppendInformational", AfterEffect::Referenced),
        ("Event.LegacyOpenLog", AfterEffect::Referenced),
        ("Event.LegacyAppend", AfterEffect::Referenced),
        ("Answer.StageWrite", AfterEffect::Referenced),
        ("Answer.PublishRename", AfterEffect::Referenced),
        ("Answer.Ingest", AfterEffect::NoEffect),
        ("Lock.AcquireRun", AfterEffect::Referenced),
        ("Lock.AcquireWorktree", AfterEffect::Referenced),
        ("Lock.ProbeCleanupExclusive", AfterEffect::Referenced),
        ("Lock.Release", AfterEffect::Removed),
        ("Lock.CreateWorktreeLockFile", AfterEffect::Referenced),
        ("Lock.ObserveCleanupHold", AfterEffect::NoEffect),
        ("Report.Write", AfterEffect::Referenced),
        ("Process.Spawn", AfterEffect::Referenced),
        ("Process.Terminate", AfterEffect::Removed),
        ("Container.WriteIntent", AfterEffect::Referenced),
        ("Container.Create", AfterEffect::Referenced),
        ("Container.Start", AfterEffect::Referenced),
        ("Container.MountGitView", AfterEffect::Referenced),
        ("Container.Stop", AfterEffect::Referenced),
        ("Container.Remove", AfterEffect::Removed),
        ("Container.UnmountGitView", AfterEffect::Removed),
        ("Container.RemoveIntent", AfterEffect::Removed),
    ];

    /// Every site and the before-phase state the packet gives it, written by
    /// name.
    ///
    /// PR3-ST07-011's witness table. A second, independent statement of
    /// `before_state()` — not a derivation from it and not a derivation from
    /// `after_effect()` either, which is why it is a literal list of seventy
    /// names rather than a rule. The shipped authority answered "nothing is
    /// durable" for all seventy, which is a rule that is right for forty-nine
    /// of them and inverts the registry's verdict on the other twenty-one.
    ///
    /// The twenty-one are every removal and release, plus the two in-place
    /// replacements the fault matrix puts after an artifact that exists:
    /// `Ref.CompareAndSwapIntegration` (T-FAST reads the head H before the CAS)
    /// and `Container.Start`/`Container.Stop` (T-CONTAINER: "container created
    /// ... and verified; docker start issued; ... the invocation running").
    const BEFORE_STATE_ORACLE: &[(&str, BeforeState)] = &[
        ("Worktree.CreateExecutionRoot", BeforeState::Absent),
        ("Worktree.RemoveExecutionRoot", BeforeState::Present),
        ("Worktree.WriteIntent", BeforeState::Absent),
        ("Worktree.Add", BeforeState::PrecursorDurable),
        ("Worktree.Verify", BeforeState::Absent),
        ("Worktree.Remove", BeforeState::Present),
        ("Worktree.RemoveIntent", BeforeState::Present),
        ("Worktree.WriteStagingIntent", BeforeState::Absent),
        ("Worktree.AddStaging", BeforeState::PrecursorDurable),
        ("Worktree.RemoveStaging", BeforeState::Present),
        ("Worktree.RemoveStagingIntent", BeforeState::Present),
        ("Snapshot.WriteIntent", BeforeState::Absent),
        ("Snapshot.Add", BeforeState::PrecursorDurable),
        ("Snapshot.Remove", BeforeState::Present),
        ("Snapshot.RemoveIntent", BeforeState::Present),
        ("Ref.CreateIntegration", BeforeState::Absent),
        ("Ref.CompareAndSwapIntegration", BeforeState::Present),
        ("Ref.CreateCandidates", BeforeState::Absent),
        ("Ref.DeleteCandidatesRef", BeforeState::Present),
        ("Ref.PinCandidatePrepared", BeforeState::Absent),
        ("Ref.DeleteCandidatePin", BeforeState::Present),
        ("Ref.PinPrepared", BeforeState::Absent),
        ("Ref.DeletePreparedPin", BeforeState::Present),
        ("Object.CandidateStage", BeforeState::Absent),
        ("Object.CandidateWriteTree", BeforeState::Absent),
        ("Object.SnapshotCommitTree", BeforeState::Absent),
        ("Object.CandidateCommitTree", BeforeState::Absent),
        ("Object.ProposalCherryPick", BeforeState::Absent),
        ("Object.RepairMaterialize", BeforeState::Absent),
        ("RunDir.CreatePublicDir", BeforeState::Absent),
        ("RunDir.StageMarker", BeforeState::Absent),
        ("RunDir.PublishMarker", BeforeState::PrecursorDurable),
        ("RunDir.RemoveMarker", BeforeState::Present),
        ("RunDir.CreatePrivateDir", BeforeState::Absent),
        ("RunDir.StageOwnerRecord", BeforeState::Absent),
        ("RunDir.PublishOwnerRecord", BeforeState::PrecursorDurable),
        ("RunDir.StageCommitRecord", BeforeState::Absent),
        ("RunDir.PublishCommitRecord", BeforeState::PrecursorDurable),
        ("RunDir.WritePlan", BeforeState::Absent),
        ("RunDir.WriteReport", BeforeState::Absent),
        ("RunDir.WriteQuestionPayload", BeforeState::Absent),
        ("RunDir.RemovePrivateHusk", BeforeState::Present),
        ("RunDir.RemovePublicHusk", BeforeState::Present),
        ("Event.OpenLog", BeforeState::Absent),
        ("Event.ProvePrefixStable", BeforeState::Absent),
        ("Event.AppendFirst", BeforeState::Absent),
        ("Event.Append", BeforeState::Absent),
        ("Event.AppendInformational", BeforeState::Absent),
        ("Event.LegacyOpenLog", BeforeState::Absent),
        ("Event.LegacyAppend", BeforeState::Absent),
        ("Answer.StageWrite", BeforeState::Absent),
        ("Answer.PublishRename", BeforeState::PrecursorDurable),
        ("Answer.Ingest", BeforeState::Absent),
        ("Lock.AcquireRun", BeforeState::Absent),
        ("Lock.AcquireWorktree", BeforeState::Absent),
        ("Lock.ProbeCleanupExclusive", BeforeState::Absent),
        ("Lock.Release", BeforeState::Present),
        ("Lock.CreateWorktreeLockFile", BeforeState::Absent),
        ("Lock.ObserveCleanupHold", BeforeState::Absent),
        ("Report.Write", BeforeState::Absent),
        ("Process.Spawn", BeforeState::Absent),
        ("Process.Terminate", BeforeState::Present),
        ("Container.WriteIntent", BeforeState::Absent),
        ("Container.Create", BeforeState::PrecursorDurable),
        ("Container.Start", BeforeState::Present),
        ("Container.MountGitView", BeforeState::Absent),
        ("Container.Stop", BeforeState::Present),
        ("Container.Remove", BeforeState::Present),
        ("Container.UnmountGitView", BeforeState::Present),
        ("Container.RemoveIntent", BeforeState::Present),
    ];

    /// The rows a fault at a point leaves holding something, as the packet
    /// states them and not as `residue_rows` computes them.
    ///
    /// Four answers, which is the point: the predecessor of `residue_rows`
    /// returned the site's own row for thirteen of the fifteen points, and the
    /// oracle that checked it recorded only a `bool` for "R27 or the site row"
    /// — so it could not have expressed, let alone caught, a containment point
    /// claiming R22 while its own artifact said the coordinator left no host
    /// process at all.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OracleRows {
        /// The row the site's own `row()` names.
        SiteRow,
        /// R27 and nothing else.
        R27,
        /// R28 and nothing else — a surviving Unix reaper's cleanup hold.
        R28,
        /// No row at all.
        NoRow,
    }

    impl OracleRows {
        /// The rows this answer names at a site whose own row is `site_row`.
        fn rows(self, site_row: ResourceRow) -> Vec<ResourceRow> {
            match self {
                Self::SiteRow => vec![site_row],
                Self::R27 => vec![ResourceRow::R27],
                Self::R28 => vec![ResourceRow::R28],
                Self::NoRow => Vec::new(),
            }
        }
    }

    /// Every `(point, mode)` and the semantics the packet gives it: the rows
    /// the residue sits at, the artifact, and the tabled recovery.
    ///
    /// Total over the whole product, not only the pairs
    /// [`SubEffectPoint::modes`] admits, because
    /// [`SubEffectPoint::resume_action`] is.
    const POINT_ORACLE: &[(
        SubEffectPoint,
        InjectionMode,
        OracleRows,
        ResidueArtifact,
        ResumeAction,
    )] = &[
        (
            SubEffectPoint::IdUnread,
            InjectionMode::Kill,
            OracleRows::R27,
            ResidueArtifact::IdNotRecorded,
            ResumeAction::ResumeUnperformed,
        ),
        (
            SubEffectPoint::IdUnread,
            InjectionMode::ErrorReturn,
            OracleRows::R27,
            ResidueArtifact::IdNotRecorded,
            ResumeAction::ResumeUnperformed,
        ),
        (
            SubEffectPoint::Written,
            InjectionMode::Kill,
            OracleRows::SiteRow,
            ResidueArtifact::UnsyncedBytes,
            ResumeAction::NextOpenConverges,
        ),
        (
            SubEffectPoint::Written,
            InjectionMode::ErrorReturn,
            OracleRows::SiteRow,
            ResidueArtifact::UnsyncedBytes,
            ResumeAction::AppendErrorProtocol,
        ),
        (
            SubEffectPoint::WrittenFull,
            InjectionMode::Kill,
            OracleRows::SiteRow,
            ResidueArtifact::UnsyncedLine,
            ResumeAction::NextOpenConverges,
        ),
        (
            SubEffectPoint::WrittenFull,
            InjectionMode::ErrorReturn,
            OracleRows::SiteRow,
            ResidueArtifact::UnsyncedLine,
            ResumeAction::AppendErrorProtocol,
        ),
        (
            SubEffectPoint::Synced,
            InjectionMode::Kill,
            OracleRows::SiteRow,
            ResidueArtifact::SyncedLine,
            ResumeAction::NextOpenConverges,
        ),
        (
            SubEffectPoint::Synced,
            InjectionMode::ErrorReturn,
            OracleRows::SiteRow,
            ResidueArtifact::SyncedLine,
            ResumeAction::AppendErrorProtocol,
        ),
        (
            SubEffectPoint::Create,
            InjectionMode::Kill,
            OracleRows::SiteRow,
            ResidueArtifact::LogCreated,
            ResumeAction::NextOpenConverges,
        ),
        (
            SubEffectPoint::Create,
            InjectionMode::ErrorReturn,
            OracleRows::SiteRow,
            ResidueArtifact::LogCreated,
            ResumeAction::RefuseResumably,
        ),
        (
            SubEffectPoint::TruncateTornTail,
            InjectionMode::Kill,
            OracleRows::SiteRow,
            ResidueArtifact::TornTailTruncated,
            ResumeAction::NextOpenConverges,
        ),
        (
            SubEffectPoint::TruncateTornTail,
            InjectionMode::ErrorReturn,
            OracleRows::SiteRow,
            ResidueArtifact::TornTailTruncated,
            ResumeAction::RefuseResumably,
        ),
        (
            SubEffectPoint::SyncPrefix,
            InjectionMode::Kill,
            OracleRows::SiteRow,
            ResidueArtifact::PrefixPossiblyNonDurable,
            ResumeAction::RefuseResumably,
        ),
        (
            SubEffectPoint::SyncPrefix,
            InjectionMode::ErrorReturn,
            OracleRows::SiteRow,
            ResidueArtifact::PrefixPossiblyNonDurable,
            ResumeAction::RefuseResumably,
        ),
        (
            SubEffectPoint::AmbientJobJoined,
            InjectionMode::Kill,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::AmbientHandleTerminates,
        ),
        (
            SubEffectPoint::AmbientJobJoined,
            InjectionMode::ErrorReturn,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::RefuseResumably,
        ),
        (
            SubEffectPoint::CreatedSuspended,
            InjectionMode::Kill,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::AmbientHandleTerminates,
        ),
        (
            SubEffectPoint::CreatedSuspended,
            InjectionMode::ErrorReturn,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::AmbientHandleTerminates,
        ),
        (
            SubEffectPoint::PrivateJobAssigned,
            InjectionMode::Kill,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::AmbientHandleTerminates,
        ),
        (
            SubEffectPoint::PrivateJobAssigned,
            InjectionMode::ErrorReturn,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::AmbientHandleTerminates,
        ),
        (
            SubEffectPoint::Resumed,
            InjectionMode::Kill,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::AmbientHandleTerminates,
        ),
        (
            SubEffectPoint::Resumed,
            InjectionMode::ErrorReturn,
            OracleRows::NoRow,
            ResidueArtifact::NoHostProcess,
            ResumeAction::AmbientHandleTerminates,
        ),
        (
            SubEffectPoint::ReaperStarted,
            InjectionMode::Kill,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
        (
            SubEffectPoint::ReaperStarted,
            InjectionMode::ErrorReturn,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
        (
            SubEffectPoint::PreExecPgidAndRegister,
            InjectionMode::Kill,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
        (
            SubEffectPoint::PreExecPgidAndRegister,
            InjectionMode::ErrorReturn,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
        (
            SubEffectPoint::Exec,
            InjectionMode::Kill,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
        (
            SubEffectPoint::Exec,
            InjectionMode::ErrorReturn,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
        (
            SubEffectPoint::Registered,
            InjectionMode::Kill,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
        (
            SubEffectPoint::Registered,
            InjectionMode::ErrorReturn,
            OracleRows::R28,
            ResidueArtifact::ReaperHeldGroup,
            ResumeAction::ReaperSettlesGroup,
        ),
    ];

    #[test]
    fn the_residue_and_recovery_authority_is_exhaustive_and_says_what_the_packet_says() {
        // The class this test is against, not the three symptoms of it: before
        // the typed authority, `expected_rows` answered `vec![self.row()]` for
        // the after phase and every point of every site, `expected_residue.detail`
        // was read by nothing at all, and `resume_action` had to be non-blank
        // and, for two phases out of five, equal to another entry's string.
        // Three fields, one of them partly wrong and two of them unchecked, and
        // no per-site statement anywhere the compiler could see.
        //
        // So: every site, every phase, against a table written by name.

        // (1) The after-phase oracle is total over the inventory and agrees
        //     with the enums. Totality first: an oracle that silently omitted
        //     a site would let production answer for it unchallenged.
        let inventory: BTreeSet<String> = EffectSiteId::all()
            .into_iter()
            .map(|site| site.name())
            .collect();
        let oracle: BTreeMap<&str, AfterEffect> = AFTER_EFFECT_ORACLE.iter().copied().collect();
        assert_eq!(
            oracle.len(),
            AFTER_EFFECT_ORACLE.len(),
            "the oracle names a site twice"
        );
        assert_eq!(
            oracle
                .keys()
                .map(|name| (*name).to_owned())
                .collect::<BTreeSet<String>>(),
            inventory,
            "the oracle and the enums disagree about what the inventory is"
        );
        assert_eq!(oracle.len(), INVENTORY_SIZE);
        for site in EffectSiteId::all() {
            assert_eq!(
                site.after_effect(),
                oracle[site.name().as_str()],
                "{site}'s after phase"
            );
        }

        // (1b) The before-phase oracle, the same way and to the same standard.
        let before_oracle: BTreeMap<&str, BeforeState> =
            BEFORE_STATE_ORACLE.iter().copied().collect();
        assert_eq!(
            before_oracle.len(),
            BEFORE_STATE_ORACLE.len(),
            "the before-state oracle names a site twice"
        );
        assert_eq!(
            before_oracle
                .keys()
                .map(|name| (*name).to_owned())
                .collect::<BTreeSet<String>>(),
            inventory,
            "the before-state oracle and the enums disagree about what the inventory is"
        );
        assert_eq!(before_oracle.len(), INVENTORY_SIZE);
        for site in EffectSiteId::all() {
            assert_eq!(
                site.before_state(),
                before_oracle[site.name().as_str()],
                "{site}'s before phase"
            );
        }
        // All three classifications occur, and none is a rounding error: an
        // oracle that said `Absent` for sixty-nine sites would restate the
        // defect and pass, and one that collapsed the two non-empty answers
        // would restate PR3-ST07-014's.
        let count = |state: BeforeState| {
            EffectSiteId::all()
                .into_iter()
                .filter(|site| site.before_state() == state)
                .count()
        };
        let (absent, precursor, present) = (
            count(BeforeState::Absent),
            count(BeforeState::PrecursorDurable),
            count(BeforeState::Present),
        );
        assert_eq!(
            present, 21,
            "the sites whose primitive acts on something already durable"
        );
        assert_eq!(
            precursor, 8,
            "the second halves of the two-step pairs the packet names as pairs"
        );
        assert_eq!(absent, 41);
        assert_eq!(absent + precursor + present, EffectSiteId::all().len());
        // The two non-empty classifications name the same row and must not
        // carry the same words, or the third classification is decoration.
        assert_ne!(
            ResidueArtifact::PrecursorDurable.detail(),
            ResidueArtifact::TargetIntact.detail()
        );
        assert_ne!(
            ResidueArtifact::PrecursorDurable.detail(),
            ResidueArtifact::Nothing.detail()
        );
        // And every site classified `PrecursorDurable` is the second half of a
        // pair whose first half is a site of the same group and the same row,
        // classified `Absent`. A site with no such partner is not a two-step
        // protocol and does not belong here.
        for site in EffectSiteId::all() {
            if site.before_state() != BeforeState::PrecursorDurable {
                continue;
            }
            assert!(
                EffectSiteId::all().into_iter().any(|other| {
                    other != site
                        && other.group() == site.group()
                        && other.row() == site.row()
                        && other.before_state() == BeforeState::Absent
                        && other.after_effect() == AfterEffect::Referenced
                }),
                "{site} claims a durable precursor and no site of its group and row makes one"
            );
        }
        // And it is *not* `after_effect` wearing a second name. If it were, a
        // mutation of one table would move the other and no test between them
        // could see it. Two sites separate them in each direction.
        let cas = EffectSiteId::Ref(RefSite::CompareAndSwapIntegration);
        assert_eq!(cas.after_effect(), AfterEffect::Referenced);
        assert_eq!(cas.before_state(), BeforeState::Present);
        let add = EffectSiteId::Worktree(WorktreeSite::Add);
        assert_eq!(add.after_effect(), AfterEffect::Referenced);
        assert_eq!(add.before_state(), BeforeState::PrecursorDurable);
        let intent = EffectSiteId::Worktree(WorktreeSite::WriteIntent);
        assert_eq!(intent.after_effect(), AfterEffect::Referenced);
        assert_eq!(intent.before_state(), BeforeState::Absent);
        let verify = EffectSiteId::Worktree(WorktreeSite::Verify);
        assert_eq!(verify.after_effect(), AfterEffect::NoEffect);
        assert_eq!(
            verify.before_state(),
            BeforeState::Absent,
            "a read-only observation performs nothing at either phase"
        );
        for state in [
            BeforeState::Absent,
            BeforeState::PrecursorDurable,
            BeforeState::Present,
        ] {
            assert!(
                EffectSiteId::all().into_iter().any(|site| {
                    site.after_effect() == AfterEffect::Referenced && site.before_state() == state
                }),
                "the `Referenced` after-effect class does not reach {state:?}, so one table could \
                 be determining the other"
            );
        }
        // Every class is exercised by some site, so no arm of the enum is
        // asserted only against itself.
        for effect in [
            AfterEffect::NoEffect,
            AfterEffect::Referenced,
            AfterEffect::Unreferenced,
            AfterEffect::Released,
            AfterEffect::Removed,
        ] {
            assert!(
                EffectSiteId::all()
                    .into_iter()
                    .any(|site| site.after_effect() == effect),
                "{effect:?} classifies no site"
            );
        }
        // `NoEffect` is exactly the read-only claim, from the other direction.
        for site in EffectSiteId::all() {
            assert_eq!(
                site.after_effect() == AfterEffect::NoEffect,
                site.is_read_only(),
                "{site}"
            );
        }

        // (2) The point oracle, over the whole (point, mode) product. Two
        //     probe rows, not one: a table that answered `vec![site_row]`
        //     everywhere would satisfy a single-probe check for every point
        //     whose oracle answer happens to be `SiteRow`, and the containment
        //     answers are exactly the ones that must *not* move with the site.
        assert_eq!(
            POINT_ORACLE.len(),
            SubEffectPoint::ALL.len() * InjectionMode::ALL.len(),
            "the point oracle is not total over the product"
        );
        for (point, mode, rows, artifact, action) in POINT_ORACLE.iter().copied() {
            for probe_row in [ResourceRow::R21, ResourceRow::R22] {
                assert_eq!(
                    point.residue_rows(probe_row),
                    rows.rows(probe_row),
                    "{point}'s residue rows at a site whose row is {probe_row}"
                );
            }
            assert_eq!(point.residue_artifact(), artifact, "{point}'s artifact");
            assert_eq!(
                point.resume_action(mode),
                action,
                "{point}/{mode:?}'s resume action"
            );
        }
        // The four answers all occur, so no arm of the oracle is asserted only
        // against itself, and each occurs where the packet puts it.
        let probe_row = ResourceRow::R21;
        let answering = |rows: Vec<ResourceRow>| -> Vec<SubEffectPoint> {
            SubEffectPoint::ALL
                .iter()
                .copied()
                .filter(|point| point.residue_rows(probe_row) == rows)
                .collect()
        };
        assert_eq!(
            answering(vec![ResourceRow::R27]),
            vec![SubEffectPoint::IdUnread],
            "\"IdUnread ... R27 object without a recorded id\""
        );
        // `containment_sub_effects`, Windows: "a coordinator kill after any of
        // these leaves no host process".
        assert_eq!(
            answering(Vec::new()),
            vec![
                SubEffectPoint::AmbientJobJoined,
                SubEffectPoint::CreatedSuspended,
                SubEffectPoint::PrivateJobAssigned,
                SubEffectPoint::Resumed,
            ],
            "the Windows containment points"
        );
        // Unix: "leaves a group the reaper settles while holding R28".
        assert_eq!(
            answering(vec![ResourceRow::R28]),
            vec![
                SubEffectPoint::ReaperStarted,
                SubEffectPoint::PreExecPgidAndRegister,
                SubEffectPoint::Exec,
                SubEffectPoint::Registered,
            ],
            "the Unix containment points"
        );
        assert_eq!(
            answering(vec![probe_row]).len(),
            SubEffectPoint::ALL.len() - 9,
            "the append and open points"
        );
        // The platform half is not an accident of which points were listed:
        // every point that leaves no row is a Windows point and every point
        // that leaves R28 is a Unix one, stated from `platform()`.
        for point in SubEffectPoint::ALL.iter().copied() {
            match point.platform() {
                Platform::Windows => assert!(
                    point.residue_rows(probe_row).is_empty(),
                    "{point} is a Windows containment point and must leave no row"
                ),
                Platform::Unix => assert_eq!(
                    point.residue_rows(probe_row),
                    vec![ResourceRow::R28],
                    "{point} is a Unix containment point and must leave the reaper's hold"
                ),
                Platform::Any => assert!(
                    !point.residue_rows(probe_row).is_empty()
                        && point.residue_rows(probe_row) != vec![ResourceRow::R28],
                    "{point}"
                ),
            }
        }
        // R22 is the row for a host-process handle, and no containment point
        // leaves one: that was the shipped answer for all eight of them.
        for point in SubEffectPoint::ALL.iter().copied() {
            if point.platform() == Platform::Any {
                continue;
            }
            assert!(
                !point
                    .residue_rows(ResourceRow::R22)
                    .contains(&ResourceRow::R22),
                "{point} still claims the R22 handle the dying coordinator does not have"
            );
        }
        assert!(
            SubEffectPoint::ALL
                .iter()
                .any(|point| point.resume_action(InjectionMode::Kill)
                    != point.resume_action(InjectionMode::ErrorReturn)),
            "no point's recovery reads the mode, so the mode is not part of the coordinate"
        );

        // (3) The phase-uniform half, over every site — stated once here
        //     because `structure` states it once.
        for site in EffectSiteId::all() {
            let before = site.semantics(EntryPhase::Before);
            match site.before_state() {
                BeforeState::Absent => {
                    assert!(before.rows.is_empty(), "{site}");
                    assert_eq!(before.artifact, ResidueArtifact::Nothing, "{site}");
                }
                // The two classifications that name the same row and must not
                // carry the same words: the row holds the intent, or it holds
                // the target — and only one of the two is the thing this
                // site's primitive is about to act on.
                BeforeState::PrecursorDurable => {
                    assert_eq!(before.rows, vec![site.row()], "{site}");
                    assert_eq!(before.artifact, ResidueArtifact::PrecursorDurable, "{site}");
                }
                BeforeState::Present => {
                    assert_eq!(before.rows, vec![site.row()], "{site}");
                    assert_eq!(before.artifact, ResidueArtifact::TargetIntact, "{site}");
                }
            }
            // The action is the one thing the before phase *is* uniform in,
            // and it has to stay that way: `resumes_as_before` binds two other
            // phases to it.
            assert_eq!(before.action, ResumeAction::ResumeUnperformed, "{site}");

            let none = site.semantics(EntryPhase::NoExecution);
            assert!(none.rows.is_empty(), "{site}");
            assert_eq!(none.artifact, ResidueArtifact::NotReached, "{site}");
            assert_eq!(none.action, ResumeAction::NotExecuted, "{site}");

            let after = site.semantics(EntryPhase::After);
            match site.after_effect() {
                AfterEffect::NoEffect => {
                    assert!(after.rows.is_empty(), "{site}");
                    assert_eq!(after.artifact, ResidueArtifact::NoEffectPerformed, "{site}");
                    assert_eq!(after.action, ResumeAction::RepeatObservation, "{site}");
                }
                AfterEffect::Referenced => {
                    assert_eq!(after.rows, vec![site.row()], "{site}");
                    assert_eq!(after.artifact, ResidueArtifact::Referenced, "{site}");
                    assert_eq!(after.action, ResumeAction::AdoptPerformed, "{site}");
                }
                AfterEffect::Unreferenced => {
                    assert_eq!(after.rows, vec![ResourceRow::R27], "{site}");
                    assert_eq!(after.artifact, ResidueArtifact::Unreferenced, "{site}");
                    assert_eq!(after.action, ResumeAction::AdoptPerformed, "{site}");
                }
                AfterEffect::Released => {
                    assert_eq!(after.rows, vec![ResourceRow::R27], "{site}");
                    assert_eq!(after.artifact, ResidueArtifact::Released, "{site}");
                    assert_eq!(after.action, ResumeAction::ReclaimReleased, "{site}");
                }
                AfterEffect::Removed => {
                    assert!(after.rows.is_empty(), "{site}");
                    assert_eq!(after.artifact, ResidueArtifact::Removed, "{site}");
                    assert_eq!(after.action, ResumeAction::AdoptPerformed, "{site}");
                }
            }

            for class in site.residue_classes() {
                let phase = EntryPhase::Residue { class: *class };
                let semantics = site.semantics(phase);
                if site.row() == ResourceRow::R27 {
                    assert_eq!(semantics.rows, vec![ResourceRow::R27], "{site}");
                    assert_eq!(
                        semantics.artifact,
                        ResidueArtifact::ObjectsUnreferenced,
                        "{site}"
                    );
                } else {
                    assert_eq!(semantics.rows, vec![ResourceRow::R27, site.row()], "{site}");
                    assert_eq!(
                        semantics.artifact,
                        ResidueArtifact::ObjectsAndAdministrativeResidue,
                        "{site}"
                    );
                }
                assert_eq!(semantics.action, ResumeAction::ResumeUnperformed, "{site}");
            }

            for point in site.sub_effects() {
                for mode in InjectionMode::ALL {
                    let phase = EntryPhase::Point {
                        point: *point,
                        mode: *mode,
                    };
                    let semantics = site.semantics(phase);
                    assert_eq!(
                        semantics.rows,
                        point.residue_rows(site.row()),
                        "{site}/{phase}"
                    );
                    assert_eq!(
                        semantics.artifact,
                        point.residue_artifact(),
                        "{site}/{phase}"
                    );
                    assert_eq!(
                        semantics.action,
                        point.resume_action(*mode),
                        "{site}/{phase}"
                    );
                }
            }
        }

        // (4) `resumes_as_before` is the authority's own answer and not a
        //     second opinion beside it: for every phase but the before phase
        //     itself, the phase is bound to the before-phase action exactly
        //     when the authority tables that action for it.
        for site in EffectSiteId::all() {
            let before = site.semantics(EntryPhase::Before).action;
            let mut phases = vec![EntryPhase::After, EntryPhase::NoExecution];
            for class in site.residue_classes() {
                phases.push(EntryPhase::Residue { class: *class });
            }
            for point in site.sub_effects() {
                for mode in InjectionMode::ALL {
                    phases.push(EntryPhase::Point {
                        point: *point,
                        mode: *mode,
                    });
                }
            }
            for phase in phases {
                assert_eq!(
                    phase.resumes_as_before(),
                    site.semantics(phase).action == before,
                    "{site}/{phase}"
                );
            }
        }

        // (5) The words are distinguishable. Validation is by string equality,
        //     so two artifacts or two actions sharing a phrase would be one
        //     claim wearing two names, and a blank one would be no claim.
        let details: BTreeSet<&str> = ResidueArtifact::ALL
            .iter()
            .map(|artifact| artifact.detail())
            .collect();
        assert_eq!(details.len(), ResidueArtifact::ALL.len());
        assert!(details.iter().all(|detail| !detail.trim().is_empty()));
        let actions: BTreeSet<&str> = ResumeAction::ALL
            .iter()
            .map(|action| action.text())
            .collect();
        assert_eq!(actions.len(), ResumeAction::ALL.len());
        assert!(actions.iter().all(|action| !action.trim().is_empty()));
        // And `ALL` is every variant of each, checked by a match rather than a
        // count that a new variant would leave behind.
        for artifact in ResidueArtifact::ALL {
            match artifact {
                ResidueArtifact::Nothing
                | ResidueArtifact::TargetIntact
                | ResidueArtifact::PrecursorDurable
                | ResidueArtifact::NotReached
                | ResidueArtifact::NoEffectPerformed
                | ResidueArtifact::Referenced
                | ResidueArtifact::Unreferenced
                | ResidueArtifact::Released
                | ResidueArtifact::Removed
                | ResidueArtifact::IdNotRecorded
                | ResidueArtifact::ObjectsUnreferenced
                | ResidueArtifact::ObjectsAndAdministrativeResidue
                | ResidueArtifact::UnsyncedBytes
                | ResidueArtifact::UnsyncedLine
                | ResidueArtifact::SyncedLine
                | ResidueArtifact::LogCreated
                | ResidueArtifact::TornTailTruncated
                | ResidueArtifact::PrefixPossiblyNonDurable
                | ResidueArtifact::NoHostProcess
                | ResidueArtifact::ReaperHeldGroup => {}
            }
        }
        assert_eq!(
            ResidueArtifact::ALL
                .iter()
                .copied()
                .collect::<BTreeSet<ResidueArtifact>>()
                .len(),
            ResidueArtifact::ALL.len()
        );
        for action in ResumeAction::ALL {
            match action {
                ResumeAction::ResumeUnperformed
                | ResumeAction::NotExecuted
                | ResumeAction::AdoptPerformed
                | ResumeAction::ReclaimReleased
                | ResumeAction::RepeatObservation
                | ResumeAction::AppendErrorProtocol
                | ResumeAction::NextOpenConverges
                | ResumeAction::RefuseResumably
                | ResumeAction::AmbientHandleTerminates
                | ResumeAction::ReaperSettlesGroup => {}
            }
        }
        assert_eq!(
            ResumeAction::ALL
                .iter()
                .copied()
                .collect::<BTreeSet<ResumeAction>>()
                .len(),
            ResumeAction::ALL.len()
        );
    }

    #[test]
    fn the_format_reads_the_detail_and_the_action_of_every_claimed_coordinate() {
        // Exhaustiveness of the *check*, not only of the table: for every
        // claimed site and every phase that site admits, a wrong detail and a
        // wrong action are each refused. A typed authority nothing consults at
        // some coordinate is the same gap in a nicer shape.
        let mut coordinates = 0;
        for site in EffectSiteId::claimed() {
            let mut phases = vec![EntryPhase::Before, EntryPhase::After];
            if site.skipped_on_fast_path() {
                phases.push(EntryPhase::NoExecution);
            }
            for class in site.residue_classes() {
                phases.push(EntryPhase::Residue { class: *class });
            }
            for point in site.sub_effects() {
                for mode in point.modes() {
                    phases.push(EntryPhase::Point {
                        point: *point,
                        mode: *mode,
                    });
                }
            }
            for phase in phases {
                let semantics = site.semantics(phase);
                let sound = RegistryEntry {
                    site,
                    phase,
                    order: if phase == EntryPhase::NoExecution {
                        None
                    } else {
                        only_order(site)
                    },
                    fault_row: site.fault_row(),
                    expected_residue: ExpectedResidue {
                        rows: semantics.rows.clone(),
                        detail: semantics.artifact.detail().to_owned(),
                    },
                    resume_action: semantics.action.text().to_owned(),
                    label: phase.required_label(),
                    evidence: match phase {
                        EntryPhase::NoExecution => Evidence::NotExecuted {
                            test: "st07::oracle".to_owned(),
                            passed: true,
                            sequences: vec!["fast/seq-0".to_owned()],
                        },
                        EntryPhase::Residue { .. } => Evidence::RecoveryProven {
                            synthetic: site
                                .residue_elements()
                                .iter()
                                .map(|element| SyntheticRecord {
                                    element: *element,
                                    constructed: true,
                                    classified: ObjectResidue::Internal,
                                    recovered: true,
                                })
                                .collect(),
                            sampling: SamplingRecord {
                                n: 7,
                                histogram: ClassHistogram {
                                    none: 7,
                                    internal: 0,
                                    after: 0,
                                },
                                unclassified: 0,
                                recovered: true,
                            },
                        },
                        EntryPhase::Before | EntryPhase::After | EntryPhase::Point { .. } => {
                            Evidence::Executed {
                                test: "st07::oracle".to_owned(),
                                passed: true,
                            }
                        }
                    },
                };
                validate_entry(&sound).unwrap_or_else(|error| {
                    panic!("{site}/{phase} is not a well-formed coordinate: {error}")
                });

                // The rows, at every coordinate and not only at the handful
                // the witness tests name. `structure`'s three fields are
                // checked by the same sweep or the weakest of them is checked
                // by nobody: before the per-site before-phase authority
                // existed, `rows` was the only one of the three that was read
                // at all, and it still answered one value for seventy sites.
                let mut wrong_rows = sound.clone();
                wrong_rows.expected_residue.rows = if semantics.rows.is_empty() {
                    vec![ResourceRow::R27]
                } else {
                    Vec::new()
                };
                assert!(
                    matches!(
                        validate_entry(&wrong_rows),
                        Err(RegistryError::WrongResidueRows { .. })
                    ),
                    "{site}/{phase} accepted ledger rows it does not leave"
                );

                let mut wrong_detail = sound.clone();
                wrong_detail.expected_residue.detail = "durable state of some kind".to_owned();
                assert!(
                    matches!(
                        validate_entry(&wrong_detail),
                        Err(RegistryError::WrongResidueDetail { .. })
                    ),
                    "{site}/{phase} accepted a residue description it does not have"
                );

                let mut wrong_action = sound.clone();
                wrong_action.resume_action = "resume somehow".to_owned();
                assert!(
                    matches!(
                        validate_entry(&wrong_action),
                        Err(RegistryError::WrongResumeAction { .. })
                    ),
                    "{site}/{phase} accepted a resume action the matrix does not table"
                );

                coordinates += 1;
            }
        }
        assert!(
            coordinates > 150,
            "the sweep covered {coordinates} coordinates, which is not the inventory"
        );
    }

    #[test]
    fn the_bijection_refuses_a_hand_edited_slice_that_keys_one_coordinate_twice() {
        // `check_bijection` is documented to revalidate a bare slice because a
        // registry.json hand-edited between a gate and a review never went
        // through `insert`. `structure` keys entries by site x phase x order,
        // so two entries at one key are two answers to one question — and
        // `check_evidence` reads whichever it reaches first. Both entries below
        // are individually valid and they disagree about the evidence, which is
        // the case a first-or-last policy decides silently.
        let host = Host::current();
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let mut entries = self_test_registry(host);
        let position = entries
            .iter()
            .position(|entry| entry.site == commit_tree && entry.phase == EntryPhase::After)
            .expect("the fixture carries an after-phase entry");
        let mut second = entries[position].clone();
        second.evidence = Evidence::Executed {
            test: "st07::a-different-test".to_owned(),
            passed: false,
        };
        assert_eq!(second.key(), entries[position].key(), "the same key");
        assert_ne!(second, entries[position], "and a different claim");
        validate_entry(&second).expect("individually valid");
        entries.insert(position + 1, second.clone());

        let failures = check_bijection(
            &self_test_inventory(),
            &self_test_harness(host),
            &entries,
            host,
        );
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                BijectionFailure::DuplicateEntry { count: 2, .. }
            )),
            "a slice keying one coordinate twice passed: {failures:#?}"
        );

        // The order the two are written in must not decide the verdict: with
        // the failing entry first, the same duplicate is reported.
        let mut reversed = self_test_registry(host);
        reversed.insert(position, second);
        let failures = check_bijection(
            &self_test_inventory(),
            &self_test_harness(host),
            &reversed,
            host,
        );
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                BijectionFailure::DuplicateEntry { count: 2, .. }
            )),
            "the duplicate was reported only in one written order: {failures:#?}"
        );

        // The constructor refuses it too, so the two paths agree.
        let mut registry = FaultRegistry::new();
        for entry in self_test_registry(host) {
            registry.insert(entry).expect("the fixture inserts");
        }
        let held = registry
            .get(commit_tree, EntryPhase::After, only_order(commit_tree))
            .expect("the after-phase entry")
            .clone();
        assert!(matches!(
            registry.insert(held),
            Err(RegistryError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn the_format_refuses_an_unnamed_test_and_a_duplicate_key() {
        let site = EffectSiteId::Event(EventSite::AppendFirst);
        for blank in ["", "   ", "\t\n"] {
            let mut entry = hook_entry(site, EntryPhase::Before);
            entry.evidence = Evidence::Executed {
                test: blank.to_owned(),
                passed: true,
            };
            assert!(matches!(
                FaultRegistry::new().insert(entry).expect_err("unnamed"),
                RegistryError::UnnamedTest { .. }
            ));
        }
        let mut registry = FaultRegistry::new();
        registry
            .insert(hook_entry(site, EntryPhase::Before))
            .expect("the first");
        let error = registry
            .insert(hook_entry(site, EntryPhase::Before))
            .expect_err("the second");
        assert!(
            matches!(error, RegistryError::DuplicateEntry { .. }),
            "{error}"
        );
        assert_eq!(registry.len(), 1, "a refused entry is not stored");

        // A different phase of the same site, and the same phase of a
        // different site, are different keys.
        registry
            .insert(hook_entry(site, EntryPhase::After))
            .expect("a different phase");
        registry
            .insert(hook_entry(
                EffectSiteId::Event(EventSite::Append),
                EntryPhase::Before,
            ))
            .expect("a different site");
        assert_eq!(registry.len(), 3);
        assert!(registry.get(site, EntryPhase::Before, None).is_some());
        assert!(registry.get(site, EntryPhase::NoExecution, None).is_none());
        assert!(!registry.is_empty());
    }

    // -----------------------------------------------------------------------
    // The bijection's failure directions
    // -----------------------------------------------------------------------

    /// A mutilation of the passing self-test state, and the failure it must
    /// produce.
    struct Direction {
        name: &'static str,
        break_it: fn(&mut HookHarness, &mut Vec<RegistryEntry>),
        expect: fn(&BijectionFailure) -> bool,
    }

    #[test]
    fn the_bijection_fails_on_every_missing_link() {
        // Each direction asserted positively — the checker must *reject*, and
        // reject with the failure that names what went wrong. A test that only
        // showed the checker accepting valid input would pass for a checker
        // that accepted everything.
        let host = Host::current();
        let commit_tree = EffectSiteId::Object(ObjectSite::CandidateCommitTree);
        let append = EffectSiteId::Event(EventSite::AppendFirst);

        let directions: &[Direction] = &[
            Direction {
                name: "an unobserved before-phase",
                break_it: |harness, _| {
                    *harness = HookHarness::new();
                    for site in self_test_inventory() {
                        if site.skipped_on_fast_path() || !site.scope().is_claimed() {
                            continue;
                        }
                        if site == EffectSiteId::Event(EventSite::AppendFirst) {
                            // Drive everything but the before phase.
                            for point in site.sub_effects() {
                                for mode in point.modes() {
                                    harness.hook(
                                        site,
                                        HookPhase::Point {
                                            point: *point,
                                            mode: *mode,
                                        },
                                    );
                                }
                            }
                            harness.hook(site, HookPhase::After);
                        } else {
                            drive(harness, site, Host::current());
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::Unobserved { phase, .. } if phase == "before"),
            },
            Direction {
                name: "an unobserved injection mode",
                break_it: |harness, _| {
                    *harness = HookHarness::new();
                    for site in self_test_inventory() {
                        if site.skipped_on_fast_path() || !site.scope().is_claimed() {
                            continue;
                        }
                        harness.hook(site, HookPhase::Before);
                        for point in site.sub_effects() {
                            if !point.platform().required_on(Host::current()) {
                                continue;
                            }
                            for mode in point.modes() {
                                // Every point in every mode but one: the
                                // error-return half of a sync.
                                if *point == SubEffectPoint::Synced
                                    && *mode == InjectionMode::ErrorReturn
                                {
                                    continue;
                                }
                                harness.hook(
                                    site,
                                    HookPhase::Point {
                                        point: *point,
                                        mode: *mode,
                                    },
                                );
                            }
                        }
                        harness.hook(site, HookPhase::After);
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::Unobserved { phase, .. } if phase.contains("Synced") && phase.contains("error-return")),
            },
            Direction {
                name: "a missing entry",
                break_it: |_, entries| {
                    entries.retain(|entry| {
                        entry.key()
                            != (
                                EffectSiteId::Event(EventSite::AppendFirst),
                                EntryPhase::After,
                                None,
                            )
                    });
                },
                expect: |failure| matches!(failure, BijectionFailure::MissingEntry { .. }),
            },
            Direction {
                name: "evidence that did not pass",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::Executed { passed, .. } = &mut entry.evidence {
                            *passed = false;
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::MissingEvidence { .. }),
            },
            Direction {
                name: "a residue element that was never constructed",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::RecoveryProven { synthetic, .. } = &mut entry.evidence {
                            synthetic[0].constructed = false;
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::MissingEvidence { .. }),
            },
            Direction {
                name: "a residue element that did not recover",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::RecoveryProven { synthetic, .. } = &mut entry.evidence {
                            synthetic[0].recovered = false;
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::MissingEvidence { .. }),
            },
            Direction {
                name: "a residue element that classified as something else",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::RecoveryProven { synthetic, .. } = &mut entry.evidence {
                            synthetic[0].classified = ObjectResidue::After;
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::MissingEvidence { .. }),
            },
            Direction {
                name: "an unclassifiable sampled residue",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::RecoveryProven { sampling, .. } = &mut entry.evidence {
                            // Kept summing to N, so this is the unclassifiable
                            // failure and not the accounting one.
                            sampling.histogram.after -= 2;
                            sampling.unclassified = 2;
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::UnclassifiableResidue { .. }),
            },
            Direction {
                name: "a sampling record with no samples",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::RecoveryProven { sampling, .. } = &mut entry.evidence {
                            sampling.n = 0;
                            sampling.histogram = ClassHistogram::default();
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::MissingSampling { .. }),
            },
            Direction {
                name: "a histogram that does not account for the samples",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::RecoveryProven { sampling, .. } = &mut entry.evidence {
                            sampling.histogram.none += 1;
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::SamplingUnaccounted { .. }),
            },
            Direction {
                name: "a sampled residue that did not recover",
                break_it: |_, entries| {
                    for entry in entries.iter_mut() {
                        if let Evidence::RecoveryProven { sampling, .. } = &mut entry.evidence {
                            sampling.recovered = false;
                            break;
                        }
                    }
                },
                expect: |failure| matches!(failure, BijectionFailure::UnrecoveredSampling { .. }),
            },
            Direction {
                // A no-execution record is additional evidence, not a
                // substitute for the ordinary bijection. Drop one of the
                // skipped sites' ordinary entries and the check has to notice,
                // or "it did not run on the fast path" is a way to be excused
                // from coverage entirely.
                name: "a no-execution site missing its ordinary after entry",
                break_it: |_, entries| {
                    let cherry = EffectSiteId::Object(ObjectSite::ProposalCherryPick);
                    entries.retain(|entry| {
                        !(entry.site == cherry && entry.phase == EntryPhase::After)
                    });
                },
                expect: |failure| {
                    matches!(
                        failure,
                        BijectionFailure::MissingEntry { site, phase, .. }
                            if site == "Object.ProposalCherryPick" && phase == "after"
                    )
                },
            },
            Direction {
                // The same claim from the harness side: the record says
                // nothing about what happens off the fast path, so an
                // unobserved hook there is still an unobserved hook.
                name: "a no-execution site whose hooks were never observed",
                break_it: |harness, _| {
                    let mut replacement = HookHarness::new();
                    for sequence in FAST_SEQUENCES {
                        replacement.begin_fast_sequence(sequence);
                        replacement.end_fast_sequence();
                    }
                    *harness = replacement;
                },
                expect: |failure| {
                    matches!(
                        failure,
                        BijectionFailure::Unobserved { site, .. }
                            if site == "Ref.PinPrepared"
                    )
                },
            },
            Direction {
                name: "an entry for a site outside the inventory",
                break_it: |_, entries| {
                    entries.push(hook_entry(
                        EffectSiteId::Lock(LockSite::AcquireRun),
                        EntryPhase::Before,
                    ));
                },
                expect: |failure| matches!(failure, BijectionFailure::EntryOutsideInventory { .. }),
            },
            Direction {
                name: "an entry the format would have refused",
                break_it: |_, entries| {
                    entries[0].fault_row = FaultRow::TResume;
                },
                expect: |failure| matches!(failure, BijectionFailure::InvalidEntry { .. }),
            },
        ];

        for direction in directions {
            let mut harness = self_test_harness(host);
            let mut entries = self_test_registry(host);
            (direction.break_it)(&mut harness, &mut entries);
            let failures = check_bijection(&self_test_inventory(), &harness, &entries, host);
            assert!(
                failures.iter().any(direction.expect),
                "`{}` did not produce its failure: {failures:#?}",
                direction.name
            );
        }
        assert_eq!(directions.len(), 15, "every direction above is exercised");

        // The unbroken state passes, so each direction above is the *only*
        // difference between passing and failing.
        assert!(
            check_bijection(
                &self_test_inventory(),
                &self_test_harness(host),
                &self_test_registry(host),
                host
            )
            .is_empty()
        );
        let _ = (commit_tree, append);
    }

    #[test]
    fn a_never_hit_internal_class_passes_and_an_unclassifiable_one_does_not() {
        // Both directions of `completeness_rule`'s one explicit exemption:
        // "an unclassifiable residue fails; a never-hit Internal class does
        // not fail".
        let host = Host::current();
        let site = EffectSiteId::Object(ObjectSite::CandidateStage);
        let inventory = vec![site];
        let mut harness = HookHarness::new();
        drive(&mut harness, site, host);

        let entries = |n: u32, internal: u32, unclassified: u32| -> Vec<RegistryEntry> {
            let mut registry = FaultRegistry::new();
            for phase in [EntryPhase::Before, EntryPhase::After] {
                registry.insert(hook_entry(site, phase)).expect("hook");
            }
            let mut residue = residue_entry(site, n, internal);
            if unclassified > 0 {
                if let Evidence::RecoveryProven { sampling, .. } = &mut residue.evidence {
                    sampling.histogram.after -= unclassified;
                    sampling.unclassified = unclassified;
                }
            }
            registry.insert(residue).expect("residue");
            registry.entries().to_vec()
        };

        // Never hit: the histogram's internal count is zero and the check
        // passes. Hitting the internal window is recorded, never required.
        let never_hit = entries(40, 0, 0);
        assert!(never_hit.iter().any(|entry| matches!(
            &entry.evidence,
            Evidence::RecoveryProven { sampling, .. } if sampling.histogram.internal == 0
        )));
        assert!(
            check_bijection(&inventory, &harness, &never_hit, host).is_empty(),
            "a never-hit internal class must not fail"
        );
        // Hit: also passes.
        assert!(check_bijection(&inventory, &harness, &entries(40, 9, 0), host).is_empty());
        // Unclassifiable: fails, and fails by name.
        let failures = check_bijection(&inventory, &harness, &entries(40, 9, 3), host);
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                BijectionFailure::UnclassifiableResidue { count, .. } if *count == 3
            )),
            "{failures:#?}"
        );
    }

    #[test]
    fn a_legacy_site_carries_no_bijection_requirement_and_a_claimed_one_does() {
        let host = Host::current();
        let legacy = EffectSiteId::Event(EventSite::LegacyAppend);
        let shared = EffectSiteId::Event(EventSite::Append);
        let harness = HookHarness::new();

        // Nothing observed, nothing entered, and the Legacy site is silent.
        assert!(check_bijection(&[legacy], &harness, &[], host).is_empty());
        // The same emptiness for its Shared neighbour is a pile of failures.
        let failures = check_bijection(&[shared], &harness, &[], host);
        assert!(!failures.is_empty(), "a Shared site must carry the claim");
        assert!(
            failures
                .iter()
                .any(|f| matches!(f, BijectionFailure::Unobserved { .. }))
        );
        assert!(
            failures
                .iter()
                .any(|f| matches!(f, BijectionFailure::MissingEntry { .. }))
        );
        // The exemption is by scope, not by group: the two sites differ in
        // nothing else that the checker reads.
        assert_eq!(legacy.group(), shared.group());
        assert_eq!(legacy.row(), shared.row());
        assert_eq!(legacy.fault_row(), shared.fault_row());
        assert_ne!(legacy.scope(), shared.scope());
    }

    #[test]
    fn a_point_is_required_on_its_own_platform_and_not_on_the_other() {
        // ST-07's evidence "executes each point on its platform", both ways: a
        // Unix suite is not asked for the Windows containment steps, and a
        // Windows suite is not asked for the Unix ones — but each is asked for
        // its own.
        let spawn = EffectSiteId::Process(ProcessSite::Spawn);
        for host in Host::ALL.iter().copied() {
            let mut harness = HookHarness::new();
            drive(&mut harness, spawn, host);
            let mut registry = FaultRegistry::new();
            for phase in [EntryPhase::Before, EntryPhase::After] {
                registry.insert(hook_entry(spawn, phase)).expect("hook");
            }
            for point in spawn.sub_effects() {
                if !point.platform().required_on(host) {
                    continue;
                }
                for mode in point.modes() {
                    registry
                        .insert(hook_entry(
                            spawn,
                            EntryPhase::Point {
                                point: *point,
                                mode: *mode,
                            },
                        ))
                        .expect("point");
                }
            }
            let entries = registry.entries().to_vec();
            assert!(
                check_bijection(&[spawn], &harness, &entries, host).is_empty(),
                "{host}"
            );
            // The other platform's check over the same evidence fails, which is
            // what makes the scoping a scoping rather than a hole.
            let other = host.other();
            let failures = check_bijection(&[spawn], &harness, &entries, other);
            assert!(
                failures
                    .iter()
                    .any(|f| matches!(f, BijectionFailure::Unobserved { .. })),
                "{host} evidence must not satisfy {other}: {failures:#?}"
            );
        }
        // Four Windows points and four Unix ones, and `Any` points are
        // required on both.
        let windows = spawn
            .sub_effects()
            .iter()
            .filter(|point| point.platform() == Platform::Windows)
            .count();
        let unix = spawn
            .sub_effects()
            .iter()
            .filter(|point| point.platform() == Platform::Unix)
            .count();
        assert_eq!((windows, unix), (4, 4));
        for host in Host::ALL.iter().copied() {
            assert!(SubEffectPoint::Written.platform().required_on(host));
        }
    }

    #[test]
    fn there_is_no_host_on_which_a_containment_point_is_unrequired() {
        // PR3-ST07-013. `required_on` used to take a `Platform` as its host, and
        // its last arm was `(Self::Windows, _) | (Self::Unix, _) => false` — so
        // `Platform::Any`, which means "a point that exists everywhere", read as
        // "a host that is neither platform". `check_bijection(&[spawn], &empty
        // harness, &two entries, Platform::Any)` then returned success with all
        // eight containment points unobserved, unentered and unentried: the
        // strongest claim ST-07 makes about the process funnel, erased by
        // passing an enum variant that is not a machine.
        //
        // The repair is the type: `Host` has two values and no third to pass.
        // This test is the property that fix buys, stated over the whole
        // product so that it cannot be true of one host and vacuous on the
        // other, and so that a later `Host` variant has to break it.
        assert_eq!(Host::ALL.len(), 2, "a host is Windows or it is Unix");
        assert_eq!(
            Host::current(),
            if cfg!(windows) {
                Host::Windows
            } else {
                Host::Unix
            },
            "the default host is the one this build actually runs on"
        );
        assert_eq!(Host::current().other(), Host::current().other());
        assert_ne!(Host::current().other(), Host::current());
        assert_eq!(
            Host::current().platform(),
            if cfg!(windows) {
                Platform::Windows
            } else {
                Platform::Unix
            }
        );
        let spawn = EffectSiteId::Process(ProcessSite::Spawn);

        // (1) Over every host, every point of every site is required on at
        //     least one of them, and every containment point on exactly one.
        for point in SubEffectPoint::ALL {
            let required: Vec<Host> = Host::ALL
                .iter()
                .copied()
                .filter(|host| point.platform().required_on(*host))
                .collect();
            assert!(
                !required.is_empty(),
                "{point} is required on no host at all, so no suite has to execute it"
            );
            match point.platform() {
                Platform::Any => assert_eq!(required.len(), 2, "{point}"),
                Platform::Windows => assert_eq!(required, vec![Host::Windows], "{point}"),
                Platform::Unix => assert_eq!(required, vec![Host::Unix], "{point}"),
            }
        }

        // (2) The failing call, now for both hosts: an empty harness and a
        //     registry carrying only the two hook phases is refused on every
        //     host, and refused *for the containment points* rather than only
        //     for the hooks. Under the old wildcard the `Platform::Any` call
        //     returned an empty vector.
        for host in Host::ALL.iter().copied() {
            let mut harness = HookHarness::new();
            harness.hook(spawn, HookPhase::Before);
            harness.hook(spawn, HookPhase::After);
            let entries = vec![
                hook_entry(spawn, EntryPhase::Before),
                hook_entry(spawn, EntryPhase::After),
            ];
            let failures = check_bijection(&[spawn], &harness, &entries, host);
            let unobserved: Vec<&String> = failures
                .iter()
                .filter_map(|failure| match failure {
                    BijectionFailure::Unobserved { phase, .. } => Some(phase),
                    _ => None,
                })
                .collect();
            assert_eq!(
                unobserved.len(),
                match host {
                    // AmbientJobJoined supports both modes; the other three
                    // Windows points and all four Unix points are kill-only.
                    Host::Windows => 5,
                    Host::Unix => 4,
                },
                "{host}: {failures:#?}"
            );
            for point in spawn.sub_effects() {
                if !point.platform().required_on(host) {
                    continue;
                }
                assert!(
                    unobserved
                        .iter()
                        .any(|phase| phase.starts_with(point.name())),
                    "{host} accepted a check in which {point} never executed"
                );
            }
        }
    }

    #[test]
    fn the_bijection_over_the_whole_claimed_inventory_fails_for_this_slice() {
        // Non-vacuity. The check is only as strong as the inventory it is
        // handed, so this slice states plainly what it has *not* covered: run
        // the same check over every Topology and Shared site and it fails,
        // because PR3 builds the frame and PR7-PR10 fill it.
        let host = Host::current();
        let claimed = EffectSiteId::claimed();
        assert!(claimed.len() >= 60, "{}", claimed.len());
        let failures = check_bijection(
            &claimed,
            &self_test_harness(host),
            &self_test_registry(host),
            host,
        );
        assert!(
            failures.len() > 100,
            "a framework whose full inventory nearly passes in PR3 is a framework \
             that is not checking anything: {}",
            failures.len()
        );
        // And it fails for the right reason: sites no funnel exists for yet.
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                BijectionFailure::Unobserved { site, .. } if site == "RunDir.PublishCommitRecord"
            )),
            "{failures:#?}"
        );
    }

    // -----------------------------------------------------------------------
    // effect_sites.json and the wire forms
    // -----------------------------------------------------------------------

    #[test]
    fn the_generated_inventory_describes_every_site_and_invents_none() {
        let export = effect_sites();
        let sites = EffectSiteId::all();
        assert_eq!(export.len(), sites.len());
        assert_eq!(export.len(), 70, "the inventory this slice ships");
        for (entry, site) in export.iter().zip(&sites) {
            // Generated *from* the enums, so every field is the enum's answer
            // and not a second copy that could disagree with it.
            assert_eq!(entry.site, *site);
            assert_eq!(entry.group, site.group());
            assert_eq!(entry.row, site.row());
            assert_eq!(entry.domain, site.row().domain());
            assert_eq!(entry.adjacent, site.adjacent());
            assert_eq!(entry.observable_orders, site.observable_orders());
            assert_eq!(entry.fault_row, site.fault_row());
            assert_eq!(entry.scope, site.scope());
            assert_eq!(entry.module, site.module());
            assert_eq!(entry.read_only, site.is_read_only());
            assert_eq!(entry.sub_effect_points.len(), site.sub_effects().len());
            for (point, expected) in entry.sub_effect_points.iter().zip(site.sub_effects()) {
                assert_eq!(point.point, *expected);
                assert_eq!(point.platform, expected.platform());
                assert_eq!(point.modes, expected.modes());
            }
            assert_eq!(entry.residue_classes.len(), site.residue_classes().len());
            for class in &entry.residue_classes {
                assert_eq!(class.label, EvidenceLabel::RecoveryProven);
                assert_eq!(class.classified_as, ObjectResidue::Internal);
                assert_eq!(class.elements, site.residue_elements());
            }
        }

        // The document itself: a real JSON array of objects that names the
        // sites by their dotted names and round-trips.
        let json = effect_sites_json().expect("the inventory serializes");
        assert!(
            json.contains(r#""site": "RunDir.PublishCommitRecord""#),
            "{json:.400}"
        );
        assert!(json.contains(r#""row": "r21""#));
        assert!(json.contains(r#""point": "sync_prefix""#));
        assert!(json.contains(r#""class": "object_internal""#));
        assert!(json.contains(r#""label": "recovery_proven""#));
        let back: Vec<EffectSiteExport> =
            serde_json::from_str(&json).expect("the inventory round-trips");
        assert_eq!(back, export);

        // Every group, every row, both claimed scopes and the legacy one, and
        // both adjacency directions appear, so the document is a description
        // of the whole inventory rather than of one corner of it.
        let groups: BTreeSet<FunnelGroup> = export.iter().map(|entry| entry.group).collect();
        assert_eq!(groups.len(), 11);
        let rows: BTreeSet<ResourceRow> = export.iter().map(|entry| entry.row).collect();
        assert_eq!(rows.len(), 15);
        let scopes: BTreeSet<SiteScope> = export.iter().map(|entry| entry.scope).collect();
        assert_eq!(scopes.len(), 3);
        let modules: BTreeSet<&str> = export.iter().map(|entry| entry.module.as_str()).collect();
        assert_eq!(modules.len(), 7, "{modules:?}");
    }

    /// Every JSON pointer in `value` that addresses an object.
    fn object_pointers(value: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                out.push(prefix.to_owned());
                for (key, child) in map {
                    let escaped = key.replace('~', "~0").replace('/', "~1");
                    object_pointers(child, &format!("{prefix}/{escaped}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    object_pointers(child, &format!("{prefix}/{index}"), out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn every_reachable_object_of_both_wire_forms_refuses_an_unknown_field() {
        // Strictness applied recursively and *proved* recursively: rather than
        // naming the types that carry `deny_unknown_fields`, this walks the
        // serialized documents and injects a key at every object node there
        // is. A type reachable only through a payload — the shape A1's review
        // found unprotected — is a node here like any other.
        let mut checked = 0;

        let inventory = serde_json::to_value(effect_sites()).expect("serialize");
        let mut pointers = Vec::new();
        object_pointers(&inventory, "", &mut pointers);
        assert!(pointers.len() > 100, "{}", pointers.len());
        for pointer in &pointers {
            let mut document = inventory.clone();
            document
                .pointer_mut(pointer)
                .and_then(serde_json::Value::as_object_mut)
                .expect("an object pointer addresses an object")
                .insert("tactus_unknown_probe".to_owned(), serde_json::json!(1));
            assert!(
                serde_json::from_value::<Vec<EffectSiteExport>>(document).is_err(),
                "effect_sites.json accepted an unknown field at `{pointer}`"
            );
            checked += 1;
        }

        // The registry's own document, built to contain every variant that has
        // an object form: all five phases, all three evidence shapes, both
        // orders, and a residue entry with its synthetic and sampling records.
        let mut entries = self_test_registry(Host::current());
        entries.push(hook_entry(
            EffectSiteId::Object(ObjectSite::CandidateCommitTree),
            EntryPhase::Point {
                point: SubEffectPoint::IdUnread,
                mode: InjectionMode::Kill,
            },
        ));
        let shapes: BTreeSet<String> = entries
            .iter()
            .map(|entry| format!("{}", entry.phase))
            .collect();
        assert!(shapes.len() >= 5, "{shapes:?}");
        let registry = serde_json::to_value(&entries).expect("serialize");
        let mut pointers = Vec::new();
        object_pointers(&registry, "", &mut pointers);
        assert!(pointers.len() > 60, "{}", pointers.len());
        for pointer in &pointers {
            let mut document = registry.clone();
            document
                .pointer_mut(pointer)
                .and_then(serde_json::Value::as_object_mut)
                .expect("an object pointer addresses an object")
                .insert("tactus_unknown_probe".to_owned(), serde_json::json!(1));
            assert!(
                serde_json::from_value::<Vec<RegistryEntry>>(document).is_err(),
                "registry.json accepted an unknown field at `{pointer}`"
            );
            checked += 1;
        }

        // The coverage record the harness produces is the third document a
        // gate attaches, and it is walked too.
        let mut harness = HookHarness::new();
        for site in self_test_inventory() {
            if site.skipped_on_fast_path() || !site.scope().is_claimed() {
                continue;
            }
            drive(&mut harness, site, Host::current());
        }
        let coverage = serde_json::to_value(harness.coverage()).expect("serialize");
        let mut pointers = Vec::new();
        object_pointers(&coverage, "", &mut pointers);
        assert!(pointers.len() > 20, "{}", pointers.len());
        for pointer in &pointers {
            let mut document = coverage.clone();
            document
                .pointer_mut(pointer)
                .and_then(serde_json::Value::as_object_mut)
                .expect("an object pointer addresses an object")
                .insert("tactus_unknown_probe".to_owned(), serde_json::json!(1));
            assert!(
                serde_json::from_value::<Vec<Observation>>(document).is_err(),
                "the coverage record accepted an unknown field at `{pointer}`"
            );
            checked += 1;
        }

        assert!(checked > 200, "only {checked} object paths were probed");
    }

    #[test]
    fn the_wire_form_refuses_an_entry_naming_a_site_the_enums_do_not_declare() {
        // `completeness_rule`: "entries for sites absent from the enums are
        // refused". In Rust the type says so; on the wire, this does.
        let entries = vec![hook_entry(
            EffectSiteId::Event(EventSite::AppendFirst),
            EntryPhase::Before,
        )];
        let json = serde_json::to_string(&entries).expect("serialize");
        assert!(json.contains(r#""site":"Event.AppendFirst""#), "{json}");
        let back: Vec<RegistryEntry> = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, entries);

        for invented in [
            "Event.AppendSecond",
            "Ledger.Append",
            "Event.appendfirst",
            "Event.AppendFirst.Written",
        ] {
            let forged = json.replace("Event.AppendFirst", invented);
            assert_ne!(forged, json);
            let error = serde_json::from_str::<Vec<RegistryEntry>>(&forged)
                .expect_err("a site no enum declares");
            assert!(error.to_string().contains(invented), "{error}");
        }
        // The same for the generated inventory.
        let inventory = effect_sites_json().expect("serialize");
        let forged = inventory.replace("Lock.ObserveCleanupHold", "Lock.ObserveCleanupLease");
        assert!(serde_json::from_str::<Vec<EffectSiteExport>>(&forged).is_err());
    }

    #[test]
    fn the_coverage_record_round_trips_and_names_its_phases() {
        let host = Host::current();
        let harness = self_test_harness(host);
        let json = serde_json::to_string(harness.coverage()).expect("serialize");
        let back: Vec<Observation> = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, harness.coverage());
        assert!(json.contains(r#""phase":"before""#), "{json:.300}");
        assert!(json.contains(r#""phase":"after""#));
        assert!(
            json.contains(r#""point":{"point":"sync_prefix","mode":"error_return"}"#),
            "{json}"
        );
        // Nothing in the record can name a residue class: the type has no
        // variant for one, which is the first half of "a residue class is
        // never counted as an executed hook".
        assert!(!json.contains("residue"), "{json}");
        assert!(!json.contains("object_internal"), "{json}");
    }
}
