//! The task registry: what a schema-4 run stores a task *as*.
//!
//! **INV-04 — [`TaskKey`] is the only storage identity, and display ids are
//! validated projections.** A key is a dense index assigned at registration;
//! the id a person types, a plan writes, and a report prints is a field on the
//! entry that key names. Every later slice — the checked fold, the candidate
//! queue, the merge queue, repair lineage — addresses tasks by key, so the one
//! place a display id is interpreted is here, where it is checked.
//!
//! That inversion is what the merge queue needs. A run that spawns repair tasks
//! has ids nobody wrote down in the plan, and a design keyed on the display
//! string has to answer awkward questions about what happens when two of them
//! collide, or when a plan happens to contain the id the queue was about to
//! generate. Keyed on a dense index, both answers are structural: a display id
//! names exactly one entry or the registry refuses to exist, and the id space
//! the queue generates into is reserved against originals up front.
//!
//! # What an original entry is derived from
//!
//! Originals come from two frozen inputs and nothing else: the run's
//! `plan.normalized.json` and its [`RunStarted`] record — the resolved chains
//! with their exact rung bindings, the review plan, and the effort policy.
//! Both are already immutable for the life of the run, which is what lets a
//! resume, a replay, and a fresh reader rebuild the identical registry rather
//! than three that agree by inspection.
//!
//! [`TaskRegistry::digest`] is the authentication value over that derivation.
//! A reader rebuilds the originals and compares; a mismatch means the frozen
//! plan or the run record moved underneath the log and is refused rather than
//! folded on a guess. The digest is consumed from the schema-4 fold onwards —
//! this slice establishes it and proves it deterministic.
//!
//! Dynamic (merge-repair) entries are the merge queue's, and it does not exist
//! yet: this module reserves their id namespace and carries their shape, and
//! nothing in production registers one.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::events::{ChainSummary, RunStarted};
use crate::ir::{ArtifactId, Plan, ResolvedEffortPolicy, Task, TaskId, TaskKind, Tier};
use crate::review::PassBinding;

/// Storage identity for one task in one run: dense from 0, assigned in plan
/// order for originals and equal to the registry's length at the event that
/// registers a dynamic task.
///
/// Deliberately not the display id. See the module documentation for why.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct TaskKey(pub u32);

impl TaskKey {
    /// Position of this key's entry in the dense registry.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for TaskKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Where an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Written in the plan the run froze.
    Original,
    /// Registered by a merge rejection. No production producer yet — the merge
    /// queue lands in a later slice; the variant is here because it is part of
    /// what an entry *is*, and therefore part of what the digest covers.
    MergeRepair,
}

impl Origin {
    /// The token this origin contributes to the canonical serialization.
    fn tag(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::MergeRepair => "merge-repair",
        }
    }
}

/// A repair's place in the lineage it belongs to. `None` on an original.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lineage {
    /// The original task this lineage descends from.
    pub root: TaskKey,
    /// The entry whose rejection produced this one.
    pub parent: TaskKey,
    /// Run-local monotonic index within the lineage, and the number that
    /// appears in the repair's display id.
    pub index: u32,
}

/// One rung's frozen execution identity, exactly as the run resolved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenRung {
    pub tier: Tier,
    pub agent: String,
    pub model: String,
    pub pinned: bool,
}

/// Whether an entry may be dispatched, or is waiting for a human to name a
/// binding for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Admission {
    /// The frozen ladder has rungs; the scheduler may dispatch it.
    Runnable,
    /// The ladder clipped to nothing, so there is no binding to run and the
    /// entry cannot move until an answer records an explicit one-off binding.
    ///
    /// Reachable only for a repair whose floor and its root's ceiling do not
    /// intersect, which is the merge queue's business and has no producer here.
    /// An original's ladder is whatever its run resolved, and a run that
    /// resolved nothing is refused at construction instead.
    HumanBinding { options: Vec<String> },
}

impl Admission {
    /// The token this admission contributes to the canonical serialization.
    fn tag(&self) -> &'static str {
        match self {
            Self::Runnable => "runnable",
            Self::HumanBinding { .. } => "human-binding",
        }
    }
}

/// The escalation ladder frozen for one entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenLadder {
    /// The resolved tiers, in escalation order.
    pub tiers: Vec<Tier>,
    /// Attempts allowed on each rung before escalating (§10.1).
    pub attempts_per: u32,
    /// Each rung's exact binding, aligned with `tiers`. Empty only for an
    /// entry admitted as [`Admission::HumanBinding`].
    pub rungs: Vec<FrozenRung>,
    /// The task's binding `min=` clip, or `None` where it set no floor. This is
    /// what a repair spawned from this entry intersects its own floor with.
    #[serde(deserialize_with = "crate::topology::events::strict::required")]
    pub floor: Option<Tier>,
    /// The highest tier this ladder reaches — the policy ceiling a repair
    /// descended from this entry may not exceed. `None` on an empty ladder.
    #[serde(deserialize_with = "crate::topology::events::strict::required")]
    pub ceiling: Option<Tier>,
    /// The run's resolved effort standard. Carried per entry rather than
    /// referenced, because a dynamic entry is embedded whole in the event that
    /// registers it and has to be readable without the run header beside it.
    #[serde(deserialize_with = "crate::topology::events::strict::field")]
    pub effort: ResolvedEffortPolicy,
    pub admission: Admission,
}

/// Everything about a task that is not its identity, its dependencies, or how
/// it is run — frozen at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenTaskSpec {
    pub kind: TaskKind,
    pub title: String,
    pub body: String,
    pub acceptance: Vec<String>,
    pub path_hints: Vec<String>,
    #[serde(deserialize_with = "crate::topology::events::strict::required")]
    pub suggested_tier: Option<Tier>,
    #[serde(deserialize_with = "crate::topology::events::strict::required")]
    pub min_tier: Option<Tier>,
    pub artifacts_in: Vec<ArtifactId>,
    pub artifacts_out: Vec<ArtifactId>,
}

/// The review identity frozen for one entry.
///
/// The run-level record ([`crate::review::ReviewPlan`]) resolved these; they
/// are copied onto the entry for the same reason the effort policy is, and
/// they are the inputs [`crate::review::ReviewPlan::passes_for`] consumes at
/// attempt time. Which of them actually runs still depends on the rung the
/// implementer bound to, so that choice stays where it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenReviews {
    /// Whether verification was deliberately enabled when the run froze.
    pub enabled: bool,
    /// Whether the run deliberately retained an anti-self-review alternative.
    pub alternative_available: bool,
    /// The independent per-pass wall-clock allowance.
    pub pass_timeout_secs: u64,
    #[serde(deserialize_with = "crate::topology::events::strict::optional")]
    pub primary: Option<PassBinding>,
    #[serde(deserialize_with = "crate::topology::events::strict::optional")]
    pub alternative: Option<PassBinding>,
    /// This task's §11.3 second opinion, where its paths asked for one.
    #[serde(deserialize_with = "crate::topology::events::strict::optional")]
    pub second_opinion: Option<PassBinding>,
}

/// One registered task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEntry {
    pub key: TaskKey,
    /// The id a plan wrote or the merge queue generated. Display only: it is
    /// validated on the way in and projected on the way out, and nothing
    /// stores a relationship by it.
    pub display_id: TaskId,
    pub origin: Origin,
    pub spec: FrozenTaskSpec,
    /// Dependencies as keys — what readiness is actually computed over.
    pub deps: Vec<TaskKey>,
    /// The same dependencies as the plan wrote them, kept so the legacy
    /// projection is a copy rather than a reconstruction.
    pub display_deps: Vec<TaskId>,
    pub ladder: FrozenLadder,
    pub reviews: FrozenReviews,
    /// The agents this run's pre-flight actually probed — the allow-list every
    /// binding on this entry is drawn from, including one a human names for a
    /// repair whose ladder clipped to nothing.
    ///
    /// Recorded per entry rather than referenced from the run header for the
    /// same reason the effort policy is: a dynamic entry is embedded whole in
    /// the event that registers it and has to be readable without the header
    /// beside it. Kept in the order `run_started` recorded, because that record
    /// is frozen and this value is part of what the digest authenticates.
    pub allowed_agents: Vec<String>,
    #[serde(deserialize_with = "crate::topology::events::strict::required")]
    pub lineage: Option<Lineage>,
}

impl TaskEntry {
    /// This entry projected back to the [`Task`] shape schemas 1–3 read.
    ///
    /// Lossless by construction: everything a `Task` holds is either the
    /// display id, the display dependencies, or a field of the spec. That is
    /// what makes the registry a re-encoding of the frozen plan rather than a
    /// summary of it, and it is the property the projection-parity tests check
    /// by comparing serialized bytes.
    pub fn legacy_task(&self) -> Task {
        Task {
            id: self.display_id.clone(),
            kind: self.spec.kind,
            title: self.spec.title.clone(),
            body: self.spec.body.clone(),
            depends_on: self.display_deps.clone(),
            acceptance: self.spec.acceptance.clone(),
            path_hints: self.spec.path_hints.clone(),
            suggested_tier: self.spec.suggested_tier,
            min_tier: self.spec.min_tier,
            artifacts_in: self.spec.artifacts_in.clone(),
            artifacts_out: self.spec.artifacts_out.clone(),
        }
    }
}

/// Every task in one run, addressed by [`TaskKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRegistry {
    entries: Vec<TaskEntry>,
    by_display: BTreeMap<String, TaskKey>,
    /// How many leading entries came from the frozen plan.
    ///
    /// The boundary [`Self::digest`] is defined over. Everything after it was
    /// registered by an event, which carries it complete and is its own
    /// authority.
    originals: usize,
}

/// Why a registry could not be derived, or could not be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    #[error("duplicate task id `{id}` in the frozen plan; a display id names exactly one task")]
    DuplicateDisplayId { id: String },

    #[error(
        "task `{id}` sits in the id namespace reserved for merge repairs \
         (`merge-fix-<index>-<task>`); a plan may not name a task the merge queue could generate"
    )]
    ReservedDisplayId { id: String },

    #[error("task `{task}` depends on unknown id `{dep}`")]
    UnknownDependency { task: String, dep: String },

    #[error("run-start chain task `{task}` is absent from the frozen plan")]
    ChainWithoutTask { task: String },

    #[error("duplicate run-start chain for task `{task}`")]
    DuplicateChain { task: String },

    #[error("frozen-plan task `{task}` has no run-start chain")]
    TaskWithoutChain { task: String },

    #[error(
        "the recorded chain for task `{task}` has no rungs; an original's ladder is the one its \
         run resolved, and a run that resolved nothing recorded no way to admit the task either"
    )]
    EmptyLadder { task: String },

    #[error("the recorded chain for task `{task}` allows 0 attempts per rung")]
    ZeroAttempts { task: String },

    #[error(
        "the recorded chain for task `{task}` has {bindings} binding(s) for {tiers} rung(s); the \
         event log cannot say which model belongs to which rung"
    )]
    BindingCount {
        task: String,
        bindings: usize,
        tiers: usize,
    },

    #[error("the recorded chain for task `{task}` assigns tier `{binding}` to a `{tier}` rung")]
    BindingTier {
        task: String,
        tier: Tier,
        binding: Tier,
    },

    #[error(
        "this run's record has no {field}; a registry is derived from what the run itself froze, \
         and a record that never froze it cannot authenticate one"
    )]
    IncompleteRunRecord { field: &'static str },

    #[error(
        "this run records {recorded} second-opinion slot(s) for {tasks} task(s); a misaligned \
         review identity would give some task another task's reviewer"
    )]
    ReviewAlignment { recorded: usize, tasks: usize },

    #[error("a plan with {tasks} tasks exceeds what a dense TaskKey can address")]
    TooManyTasks { tasks: usize },

    #[error("registry digest `{actual}` does not match the recorded digest `{expected}`")]
    DigestMismatch { expected: String, actual: String },
}

/// The id namespace merge repairs are generated into.
const REPAIR_PREFIX: &str = "merge-fix-";

/// Zero-padded width of a repair's lineage index
/// (`decisions/2026-08-12-merge-queue-execution-topology.md`: `merge-fix-0001-<task>`).
const REPAIR_INDEX_WIDTH: usize = 4;

/// The display id a merge repair takes.
///
/// The one place the pattern is written. [`is_reserved_display_id`] refuses
/// everything this can produce, so the generator and the refusal cannot drift
/// into disagreeing about what the reserved namespace is.
pub fn repair_display_id(lineage_index: u32, root: &TaskId) -> String {
    format!(
        "{REPAIR_PREFIX}{lineage_index:0width$}-{root}",
        width = REPAIR_INDEX_WIDTH
    )
}

/// Whether a display id falls inside the reserved repair namespace.
///
/// Deliberately a superset of what [`repair_display_id`] emits: the index is
/// matched at four digits *or more* so a run that ever exceeds 9999 repairs
/// cannot generate an id a plan was allowed to take, and the prefix is matched
/// without regard to ASCII case so `MERGE-FIX-0001-x` cannot be smuggled past
/// it. Reserving more than is generated costs a plan author a hyphenated id
/// nobody writes; reserving less costs a collision between a plan's task and a
/// repair, which is the thing a storage identity exists to make impossible.
pub fn is_reserved_display_id(id: &str) -> bool {
    let Some((head, rest)) = id.split_at_checked(REPAIR_PREFIX.len()) else {
        return false;
    };
    if !head.eq_ignore_ascii_case(REPAIR_PREFIX) {
        return false;
    }
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    digits >= REPAIR_INDEX_WIDTH && rest.as_bytes().get(digits) == Some(&b'-')
}

impl TaskRegistry {
    /// Derive the original entries: the frozen plan's tasks, in plan order,
    /// against the chains, review plan, and effort policy the run recorded.
    ///
    /// Derive the original entries from a run record that names no probed
    /// agents, giving every entry an empty allow-list.
    ///
    /// A legacy [`RunStarted`] has no probed-agent record — the field is
    /// schema 4's — so this is the whole of what such a record supports. **A
    /// schema-4 derivation must use [`Self::originals_with_agents`]**: the
    /// allow-list is a digest input, so originals rebuilt through this
    /// constructor authenticate against a schema-4 log only if that log probed
    /// nothing, which no run does.
    ///
    /// # Errors
    ///
    /// Every [`RegistryError`] [`Self::originals_with_agents`] produces.
    pub fn originals(plan: &Plan, started: &RunStarted) -> Result<Self, RegistryError> {
        Self::originals_with_agents(plan, started, &[])
    }

    /// Derive the original entries: the frozen plan's tasks, in plan order,
    /// against the chains, review plan, and effort policy the run recorded,
    /// with the agents its pre-flight probed.
    ///
    /// Every refusal here is a statement that the two inputs do not describe
    /// the same run. That matters more than it looks: this is the construction
    /// a reader repeats to check [`Self::digest`], so an input pair it accepted
    /// loosely would authenticate a registry nothing else agrees with.
    ///
    /// # Errors
    ///
    /// A [`RegistryError`] naming the first way the plan and the run record
    /// disagree about the run they describe.
    pub fn originals_with_agents(
        plan: &Plan,
        started: &RunStarted,
        probed_agents: &[String],
    ) -> Result<Self, RegistryError> {
        let effort = started
            .effort_policy
            .ok_or(RegistryError::IncompleteRunRecord {
                field: "effort policy",
            })?;
        let reviews = started
            .reviews
            .as_ref()
            .ok_or(RegistryError::IncompleteRunRecord {
                field: "review plan",
            })?;
        let enabled = reviews.enabled.ok_or(RegistryError::IncompleteRunRecord {
            field: "reviews.enabled marker",
        })?;
        let alternative_available =
            reviews
                .alternative_available
                .ok_or(RegistryError::IncompleteRunRecord {
                    field: "reviews.alternative_available marker",
                })?;
        let pass_timeout_secs =
            reviews
                .pass_timeout_secs
                .ok_or(RegistryError::IncompleteRunRecord {
                    field: "per-pass review timeout",
                })?;
        // Aligned by index, exactly as the review plan is (its own record
        // refuses a misalignment when it is written). Checked again rather than
        // assumed: a registry rebuilt on replay is rebuilt from the file, and
        // the file is the only thing it may take as given.
        if enabled && reviews.second_opinion.len() != plan.tasks.len() {
            return Err(RegistryError::ReviewAlignment {
                recorded: reviews.second_opinion.len(),
                tasks: plan.tasks.len(),
            });
        }

        let by_display = keys_by_display_id(plan)?;
        let chains = chains_by_task(&started.chains, &by_display)?;

        let mut entries = Vec::with_capacity(plan.tasks.len());
        for (index, task) in plan.tasks.iter().enumerate() {
            let key = TaskKey(index_key(index, plan.tasks.len())?);
            let chain =
                *chains
                    .get(task.id.as_str())
                    .ok_or_else(|| RegistryError::TaskWithoutChain {
                        task: task.id.to_string(),
                    })?;
            let mut deps = Vec::with_capacity(task.depends_on.len());
            for dep in &task.depends_on {
                deps.push(*by_display.get(dep.as_str()).ok_or_else(|| {
                    RegistryError::UnknownDependency {
                        task: task.id.to_string(),
                        dep: dep.to_string(),
                    }
                })?);
            }
            entries.push(TaskEntry {
                key,
                display_id: task.id.clone(),
                origin: Origin::Original,
                spec: FrozenTaskSpec {
                    kind: task.kind,
                    title: task.title.clone(),
                    body: task.body.clone(),
                    acceptance: task.acceptance.clone(),
                    path_hints: task.path_hints.clone(),
                    suggested_tier: task.suggested_tier,
                    min_tier: task.min_tier,
                    artifacts_in: task.artifacts_in.clone(),
                    artifacts_out: task.artifacts_out.clone(),
                },
                deps,
                display_deps: task.depends_on.clone(),
                ladder: frozen_ladder(task, chain, effort)?,
                reviews: FrozenReviews {
                    enabled,
                    alternative_available,
                    pass_timeout_secs,
                    primary: reviews.primary.clone(),
                    alternative: reviews.alternative.clone(),
                    second_opinion: reviews.second_opinion.get(index).cloned().flatten(),
                },
                allowed_agents: probed_agents.to_vec(),
                lineage: None,
            });
        }

        Ok(Self {
            originals: entries.len(),
            entries,
            by_display,
        })
    }

    /// Add an entry a schema-4 event registered.
    ///
    /// Infallible on purpose: whether this key is the next dense index, whether
    /// its display id is free, and whether its ladder is one an attempt could
    /// climb are all decided by the checked fold *before* it applies the event
    /// that registers the entry. Repeating those checks here would put a second
    /// authority on the same question, and the one place a dynamic entry can be
    /// refused is the transition that introduces it.
    ///
    /// Does not move [`Self::digest`]: see that method for why.
    pub fn register(&mut self, entry: TaskEntry) {
        self.by_display
            .insert(entry.display_id.to_string(), entry.key);
        self.entries.push(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[TaskEntry] {
        &self.entries
    }

    pub fn get(&self, key: TaskKey) -> Option<&TaskEntry> {
        self.entries.get(key.index())
    }

    /// The key a display id names, or `None` if this run has no such task.
    pub fn key_of(&self, display_id: &str) -> Option<TaskKey> {
        self.by_display.get(display_id).copied()
    }

    /// Every entry projected back to the [`Task`] shape schemas 1–3 read, in
    /// key order — which for originals is plan order.
    ///
    /// This is the legacy projection: a `Plan` rebuilt around it serializes to
    /// the same bytes as the one the registry was derived from, so a status, a
    /// report, and an export taken through the registry are the same bytes as
    /// one taken through the plan.
    pub fn legacy_tasks(&self) -> Vec<Task> {
        self.entries.iter().map(TaskEntry::legacy_task).collect()
    }

    /// How many entries came from the frozen plan.
    pub fn originals_len(&self) -> usize {
        self.originals
    }

    /// The authentication value over this registry's **original** entries.
    ///
    /// `sha256:<hex>` of the canonical encoding over the originals alone, in
    /// the `sha256:<hex>` shape the normalized plan's digest uses so a log
    /// carries one shape of digest rather than two.
    ///
    /// Deliberately not a digest of everything registered. A reader
    /// authenticates a registry by rebuilding the originals from
    /// `plan.normalized.json` and `run_started` and comparing; a dynamic entry
    /// has no frozen input behind it to rebuild *from*, and is authenticated
    /// instead by arriving complete inside the event that registers it. A
    /// digest that widened as repairs were registered would be a value no
    /// reader could ever recompute, and it would do so silently.
    ///
    /// This is the half of the pair that is *narrow* on purpose.
    /// [`Self::canonical_bytes`] is the whole registry; the two are the same
    /// bytes exactly when nothing dynamic has been registered.
    pub fn digest(&self) -> String {
        format!(
            "sha256:{:x}",
            Sha256::digest(self.encode(self.originals.min(self.entries.len())))
        )
    }

    /// Refuse a registry that does not match a recorded digest.
    pub fn verify_digest(&self, recorded: &str) -> Result<(), RegistryError> {
        let actual = self.digest();
        if actual == recorded {
            return Ok(());
        }
        Err(RegistryError::DigestMismatch {
            expected: recorded.to_owned(),
            actual,
        })
    }

    /// The exact bytes [`Self::digest`] hashes.
    ///
    /// **Frozen.** The field order below, and the set of fields in it, are part
    /// of what a recorded digest means; changing either re-dates every digest
    /// ever recorded. A new field goes in at the end behind a new version tag,
    /// never in the middle.
    ///
    /// `allowed_agents` is the one field that arrived after the encoding was
    /// written and did *not* take a new tag. It is not an extension: it is part
    /// of what an entry has always been (`decisions.task_registry.task_entry`),
    /// deferred by one slice on the explicit ruling that no digest is recorded
    /// in between. Nothing has ever written a `tactus.registry.v1` value
    /// without it, so there is no reader for which the two versions differ, and
    /// a second tag would claim a compatibility history this format does not
    /// have. The next field to arrive will be a real extension and takes v2.
    ///
    /// Every value is written length-prefixed as `<byte length>:<bytes>;`, so
    /// the encoding is injective — two registries that differ anywhere produce
    /// different bytes, and no arrangement of one entry's text can imitate
    /// another's. Nothing here is a float, a hash-map iteration, or a
    /// locale-dependent rendering, which is what makes the value identical in
    /// another process on another platform.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.encode(self.entries.len())
    }

    /// The canonical encoding of this registry's first `entries` entries.
    ///
    /// One encoder, two readers: [`Self::digest`] takes the originals and
    /// [`Self::canonical_bytes`] takes everything. Writing it once is what
    /// makes "the digest is the whole-registry encoding when nothing dynamic
    /// exists" a fact about the code rather than a coincidence between two
    /// copies of a format — and a dynamic entry that no encoder ever visited
    /// would be a value nothing downstream could compare.
    ///
    /// The count is part of the encoding, so a prefix of a longer registry is
    /// never the encoding of a shorter one.
    fn encode(&self, entries: usize) -> Vec<u8> {
        let entries = &self.entries[..entries.min(self.entries.len())];
        let mut out = Vec::new();
        field(&mut out, "tactus.registry.v1");
        count(&mut out, entries.len());
        for entry in entries {
            encode_entry(&mut out, entry);
        }
        out
    }
}

/// Dense keys by display id, refusing a duplicate or a reserved id on the way.
fn keys_by_display_id(plan: &Plan) -> Result<BTreeMap<String, TaskKey>, RegistryError> {
    let mut out = BTreeMap::new();
    for (index, task) in plan.tasks.iter().enumerate() {
        if is_reserved_display_id(task.id.as_str()) {
            return Err(RegistryError::ReservedDisplayId {
                id: task.id.to_string(),
            });
        }
        let key = TaskKey(index_key(index, plan.tasks.len())?);
        if out.insert(task.id.to_string(), key).is_some() {
            return Err(RegistryError::DuplicateDisplayId {
                id: task.id.to_string(),
            });
        }
    }
    Ok(out)
}

fn index_key(index: usize, tasks: usize) -> Result<u32, RegistryError> {
    u32::try_from(index).map_err(|_| RegistryError::TooManyTasks { tasks })
}

/// The recorded chains, indexed by the task each names.
///
/// Matched by display id rather than by position: the run writes them in plan
/// order, but a registry rebuilt from a file has no standing to assume the file
/// still says so. The coverage has to be exact in both directions — a chain for
/// a task the plan does not have, or a task with no chain, means the plan and
/// the record are not describing one run.
fn chains_by_task<'a>(
    chains: &'a [ChainSummary],
    by_display: &BTreeMap<String, TaskKey>,
) -> Result<BTreeMap<&'a str, &'a ChainSummary>, RegistryError> {
    let mut out: BTreeMap<&str, &ChainSummary> = BTreeMap::new();
    for chain in chains {
        if !by_display.contains_key(chain.task.as_str()) {
            return Err(RegistryError::ChainWithoutTask {
                task: chain.task.clone(),
            });
        }
        if out.insert(chain.task.as_str(), chain).is_some() {
            return Err(RegistryError::DuplicateChain {
                task: chain.task.clone(),
            });
        }
    }
    for task in by_display.keys() {
        if !out.contains_key(task.as_str()) {
            return Err(RegistryError::TaskWithoutChain { task: task.clone() });
        }
    }
    Ok(out)
}

/// One task's ladder, frozen from the chain its run recorded.
fn frozen_ladder(
    task: &Task,
    chain: &ChainSummary,
    effort: ResolvedEffortPolicy,
) -> Result<FrozenLadder, RegistryError> {
    if chain.tiers.is_empty() {
        return Err(RegistryError::EmptyLadder {
            task: task.id.to_string(),
        });
    }
    if chain.attempts_per == 0 {
        return Err(RegistryError::ZeroAttempts {
            task: task.id.to_string(),
        });
    }
    let bindings = chain
        .bindings
        .as_ref()
        .ok_or(RegistryError::IncompleteRunRecord {
            field: "resolved rung bindings",
        })?;
    if bindings.len() != chain.tiers.len() {
        return Err(RegistryError::BindingCount {
            task: task.id.to_string(),
            bindings: bindings.len(),
            tiers: chain.tiers.len(),
        });
    }
    let mut rungs = Vec::with_capacity(bindings.len());
    for (tier, binding) in chain.tiers.iter().copied().zip(bindings) {
        if binding.tier != tier {
            return Err(RegistryError::BindingTier {
                task: task.id.to_string(),
                tier,
                binding: binding.tier,
            });
        }
        rungs.push(FrozenRung {
            tier,
            agent: binding.agent.clone(),
            model: binding.model.clone(),
            pinned: binding.pinned,
        });
    }
    Ok(FrozenLadder {
        tiers: chain.tiers.clone(),
        attempts_per: chain.attempts_per,
        rungs,
        floor: task.min_tier,
        ceiling: chain.tiers.iter().copied().max(),
        effort,
        // An original is admitted by the ladder its run resolved, and an empty
        // one was refused above. The human-gated admission belongs to a repair
        // whose clip emptied its ladder, which nothing here produces.
        admission: Admission::Runnable,
    })
}

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/// One length-prefixed value: `<byte length>:<bytes>;`.
fn field(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value.as_bytes());
    out.push(b';');
}

fn count(out: &mut Vec<u8>, value: usize) {
    field(out, &value.to_string());
}

fn flag(out: &mut Vec<u8>, value: bool) {
    field(out, if value { "1" } else { "0" });
}

fn key(out: &mut Vec<u8>, value: TaskKey) {
    field(out, &value.0.to_string());
}

fn strings(out: &mut Vec<u8>, values: impl ExactSizeIterator<Item = impl AsRef<str>>) {
    count(out, values.len());
    for value in values {
        field(out, value.as_ref());
    }
}

fn optional_tier(out: &mut Vec<u8>, value: Option<Tier>) {
    match value {
        Some(tier) => {
            flag(out, true);
            field(out, &tier.to_string());
        }
        None => flag(out, false),
    }
}

fn optional_binding(out: &mut Vec<u8>, value: Option<&PassBinding>) {
    match value {
        Some(binding) => {
            flag(out, true);
            field(out, &binding.agent);
            field(out, &binding.model);
        }
        None => flag(out, false),
    }
}

fn encode_entry(out: &mut Vec<u8>, entry: &TaskEntry) {
    key(out, entry.key);
    field(out, entry.display_id.as_str());
    field(out, entry.origin.tag());
    match &entry.lineage {
        Some(lineage) => {
            flag(out, true);
            key(out, lineage.root);
            key(out, lineage.parent);
            field(out, &lineage.index.to_string());
        }
        None => flag(out, false),
    }

    let spec = &entry.spec;
    field(out, &spec.kind.to_string());
    field(out, &spec.title);
    field(out, &spec.body);
    strings(out, spec.acceptance.iter());
    strings(out, spec.path_hints.iter());
    optional_tier(out, spec.suggested_tier);
    optional_tier(out, spec.min_tier);
    strings(out, spec.artifacts_in.iter().map(ArtifactId::as_str));
    strings(out, spec.artifacts_out.iter().map(ArtifactId::as_str));

    count(out, entry.deps.len());
    for dep in &entry.deps {
        key(out, *dep);
    }
    strings(out, entry.display_deps.iter().map(TaskId::as_str));

    let ladder = &entry.ladder;
    strings(out, ladder.tiers.iter().map(Tier::to_string));
    field(out, &ladder.attempts_per.to_string());
    count(out, ladder.rungs.len());
    for rung in &ladder.rungs {
        field(out, &rung.tier.to_string());
        field(out, &rung.agent);
        field(out, &rung.model);
        flag(out, rung.pinned);
    }
    optional_tier(out, ladder.floor);
    optional_tier(out, ladder.ceiling);
    field(out, &ladder.effort.small.to_string());
    field(out, &ladder.effort.mid.to_string());
    field(out, &ladder.effort.frontier.to_string());
    field(out, &ladder.effort.review.to_string());
    field(out, ladder.admission.tag());
    match &ladder.admission {
        Admission::Runnable => {}
        Admission::HumanBinding { options } => strings(out, options.iter()),
    }

    let reviews = &entry.reviews;
    flag(out, reviews.enabled);
    flag(out, reviews.alternative_available);
    field(out, &reviews.pass_timeout_secs.to_string());
    optional_binding(out, reviews.primary.as_ref());
    optional_binding(out, reviews.alternative.as_ref());
    optional_binding(out, reviews.second_opinion.as_ref());

    // In the order `run_started` recorded, not sorted: the record is frozen,
    // and two runs that probed the same agents in different orders resolved
    // their bindings against different lists.
    strings(out, entry.allowed_agents.iter());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{
        AttemptRecord, AttemptStarted, AttemptTransition, BindingSummary, Event, EventBody,
        FailureRecord, LadderEscalated, RunFinished, RunOutcome, TaskCommitted,
    };
    use crate::ir::{Artifact, Effort, PlanSource};
    use crate::ladder::{FailureKind, FailureOrigin};
    use crate::review::ReviewPlan;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const RUN_ID: &str = "01REGISTRY0000000000000000";

    /// One way to damage a run record, for the refusal tables.
    type BreakRecord = fn(&mut RunStarted);

    /// One way to move a single digest input, for the coverage table.
    ///
    /// The probed agents are a third input rather than a field of the run
    /// record: a legacy [`RunStarted`] has no place to record them, and they
    /// are a digest input all the same.
    type MoveInput = fn(&mut Plan, &mut RunStarted, &mut Vec<String>);

    /// One way to move a single field of one already-built entry.
    type MoveField = fn(&mut TaskEntry);

    /// One way to permute a list one task wrote in a deliberate order.
    type PermuteTask = fn(&mut Task);

    fn task(id: &str, deps: &[&str]) -> Task {
        Task {
            id: TaskId::from(id),
            kind: TaskKind::Fix,
            title: format!("{id} title"),
            body: format!("{id} body"),
            depends_on: deps.iter().copied().map(TaskId::from).collect(),
            acceptance: vec![format!("{id} passes"), "and keeps passing".to_owned()],
            path_hints: vec![format!("src/{id}.rs"), "src/shared.rs".to_owned()],
            suggested_tier: Some(Tier::Mid),
            min_tier: Some(Tier::Small),
            artifacts_in: vec![ArtifactId::from("contract")],
            artifacts_out: vec![ArtifactId::from(format!("{id}-out").as_str())],
        }
    }

    fn plan_of(tasks: Vec<Task>) -> Plan {
        Plan {
            source: PlanSource {
                adapter: "markdown".to_owned(),
                hash: "frozen-hash".to_owned(),
            },
            tasks,
            artifacts: vec![Artifact {
                id: ArtifactId::from("contract"),
                produced_by: Some(TaskId::from("alpha")),
            }],
        }
    }

    /// Plan order, display-id order, and topological order all disagree here,
    /// so a projection that quietly used one where it meant another shows up
    /// rather than passing by coincidence.
    fn sample_plan() -> Plan {
        plan_of(vec![
            task("zeta", &["alpha"]),
            task("alpha", &[]),
            task("mid", &["alpha", "zeta"]),
        ])
    }

    fn chain(task: &str) -> ChainSummary {
        ChainSummary {
            task: task.to_owned(),
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
                    agent: "codex".to_owned(),
                    model: "gpt-5.6-sol".to_owned(),
                    pinned: true,
                },
            ]),
        }
    }

    /// The effort standard the sample record freezes. Written once, so a
    /// fixture that expects it cannot drift from the record that carries it.
    fn sample_effort() -> ResolvedEffortPolicy {
        ResolvedEffortPolicy {
            small: Effort::Low,
            mid: Effort::Medium,
            frontier: Effort::High,
            review: Effort::High,
        }
    }

    fn review_plan(tasks: usize) -> ReviewPlan {
        ReviewPlan {
            enabled: Some(true),
            alternative_available: Some(true),
            pass_timeout_secs: Some(900),
            primary: Some(PassBinding::new("claude-code", "claude-opus-5")),
            alternative: Some(PassBinding::new("copilot", "gpt-5.6")),
            // Only some tasks ask for one, so a slot read at the wrong index
            // lands on a different answer.
            second_opinion: (0..tasks)
                .map(|index| (index % 2 == 1).then(|| PassBinding::new("copilot", "gpt-5.6")))
                .collect(),
        }
    }

    fn started_for(plan: &Plan) -> RunStarted {
        RunStarted {
            schema: 2,
            tactus_version: "0.1.0".to_owned(),
            run_id: RUN_ID.to_owned(),
            branch: format!("tactus/run-{RUN_ID}"),
            base_sha: "a".repeat(40),
            plan_path: "plan.md".to_owned(),
            config_path: Some("tactus.toml".to_owned()),
            plan_hash: plan.source.hash.clone(),
            normalized_plan_digest: None,
            private_dir: "/private/runs".to_owned(),
            gates: vec!["check".to_owned()],
            gates_from_config: true,
            interaction_mode: "never".to_owned(),
            chains: plan.tasks.iter().map(|t| chain(t.id.as_str())).collect(),
            effort_policy: Some(sample_effort()),
            gate_cmds: None,
            reviews: Some(review_plan(plan.tasks.len())),
        }
    }

    /// A ladder that belongs to one task and to no other.
    ///
    /// Every component the registry freezes — the tier list, the attempts
    /// allowance, and each rung's agent, model and pin — is derived from the
    /// task's own id. Reading the wrong task's chain therefore yields a wrong
    /// *value*, where [`chain`] yields the same value for every task and so
    /// cannot tell a keyed lookup from a positional one.
    fn varied_chain(task: &str) -> ChainSummary {
        let tiers = match task {
            "zeta" => vec![Tier::Small, Tier::Mid, Tier::Frontier],
            "alpha" => vec![Tier::Mid],
            _ => vec![Tier::Small, Tier::Frontier],
        };
        let attempts_per = match task {
            "zeta" => 1,
            "alpha" => 3,
            _ => 5,
        };
        ChainSummary {
            task: task.to_owned(),
            attempts_per,
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

    /// A chain that records its rungs in an order that is neither ascending nor
    /// descending, so the derived `ceiling` is neither end of the list.
    ///
    /// Every other fixture records an ascending ladder, because that is what an
    /// escalation ladder is — and while the tiers ascend, the ceiling is the
    /// list's maximum *and* its last element at once. A ceiling read off the end
    /// of the list rather than taken over the whole of it is invisible
    /// everywhere else, and so is one read off the front of a descending list.
    /// Nothing validates the recorded order, so a record can put the top rung in
    /// the middle, and there all three derivations disagree: the maximum is
    /// `frontier`, the first is `mid`, and the last is `small`.
    fn unordered_chain(task: &str) -> ChainSummary {
        let tiers = vec![Tier::Mid, Tier::Frontier, Tier::Small];
        ChainSummary {
            task: task.to_owned(),
            attempts_per: 2,
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

    /// The sample plan with a different binding floor on each task, so the
    /// derived `floor` distinguishes an entry as well as its chain does.
    fn varied_plan() -> Plan {
        let mut plan = sample_plan();
        plan.tasks[0].min_tier = Some(Tier::Small);
        plan.tasks[1].min_tier = None;
        plan.tasks[2].min_tier = Some(Tier::Mid);
        plan
    }

    /// The varied plan's run record — chains and review slots that name the
    /// task they belong to, written in an order the plan does not share.
    ///
    /// Plan order is `zeta, alpha, mid`; the record writes `alpha, mid, zeta`.
    /// That is a derangement, so no task's chain sits at its own index and the
    /// chain at index 0 is not the first task's: a positional read and a
    /// first-chain read each land on a ladder that says whose it really is.
    fn varied_started_for(plan: &Plan) -> RunStarted {
        let mut started = started_for(plan);
        started.chains = ["alpha", "mid", "zeta"]
            .into_iter()
            .map(varied_chain)
            .collect();
        started.reviews = Some(ReviewPlan {
            // Distinct models rather than the sample's palindromic
            // `[None, Some, None]`, which a reversed read reproduces exactly —
            // and a distinct *agent* on each occupied slot for the same reason
            // one level down. The sample's occupied slot holds `copilot`, which
            // is also `alternative`'s agent, so while every occupied slot said
            // `copilot` the model's source was discriminated and the agent's
            // was not: an agent copied from the alternative reviewer, or
            // hard-coded to that literal, produced the fixture's own answer.
            // Each component of each slot now names the task it belongs to, and
            // [`the_fixtures_give_every_binding_component_its_own_literal`]
            // holds the whole set apart.
            second_opinion: vec![
                Some(PassBinding::new("zeta-second-agent", "second-for-zeta")),
                None,
                Some(PassBinding::new("mid-second-agent", "second-for-mid")),
            ],
            ..review_plan(plan.tasks.len())
        });
        started
    }

    /// The ladder the varied fixture declares for one task, restated from the
    /// fixture's own inputs rather than read back off the registry under test.
    fn expected_ladder(plan: &Plan, task: &str) -> FrozenLadder {
        let chain = varied_chain(task);
        FrozenLadder {
            rungs: chain
                .bindings
                .expect("the varied fixture records bindings")
                .into_iter()
                .map(|binding| FrozenRung {
                    tier: binding.tier,
                    agent: binding.agent,
                    model: binding.model,
                    pinned: binding.pinned,
                })
                .collect(),
            floor: plan
                .tasks
                .iter()
                .find(|candidate| candidate.id.as_str() == task)
                .expect("the varied fixture's task")
                .min_tier,
            ceiling: chain.tiers.iter().copied().max(),
            attempts_per: chain.attempts_per,
            tiers: chain.tiers,
            effort: sample_effort(),
            admission: Admission::Runnable,
        }
    }

    /// The sample plan plus two tasks the fixture log never reaches.
    ///
    /// A report lists the tasks that ran in the order they ran and appends the
    /// rest in **plan order**, so the untouched tail has to be longer than one
    /// task for a reordered projection to be visible at all. With a single
    /// untouched task the comparison passes under a registry that sorts its
    /// entries by display id, which is exactly the defect it is here to catch.
    fn projection_plan() -> Plan {
        let mut plan = sample_plan();
        plan.tasks.push(task("beta", &[]));
        plan.tasks.push(task("gamma", &["beta"]));
        plan
    }

    /// A plan whose one wide dependency list is written in an order that is
    /// neither its sorted order nor the reverse of it.
    ///
    /// [`sample_plan`]'s widest list is `alpha, zeta`: two entries, already in
    /// lexicographic order. A registry that sorted `display_deps` on the way
    /// in reproduces it exactly, and one that reversed them is indistinguishable
    /// from one that sorted them descending — two entries cannot tell those
    /// apart. Four entries in a scrambled order can, and plan order is chosen
    /// so the resolved keys `0, 2, 1, 3` are equally unordered: a sort of
    /// *either* representation is a list this fixture does not contain.
    fn dependency_order_plan() -> Plan {
        plan_of(vec![
            task("zeta", &[]),
            task("echo", &[]),
            task("alpha", &[]),
            task("beta", &[]),
            task("omega", &["zeta", "alpha", "echo", "beta"]),
        ])
    }

    /// The wide-dependency plan, with artifact lists wide enough to have an
    /// order and written in one that is neither sorted nor reversed.
    ///
    /// [`task`] gives every task exactly one artifact on each side, and the
    /// parsed fixture plans carry no task with two of either. A one-entry list
    /// cannot tell a registry that kept its order from one that sorted it, so
    /// without this fixture both artifact lists are named by tests that no
    /// ordering defect could fail.
    fn artifact_order_plan() -> Plan {
        let mut plan = dependency_order_plan();
        let omega = plan.tasks.last_mut().expect("omega is the last task");
        omega.artifacts_in = ["contract", "api", "schema"]
            .into_iter()
            .map(ArtifactId::from)
            .collect();
        omega.artifacts_out = ["omega-out", "audit", "notes"]
            .into_iter()
            .map(ArtifactId::from)
            .collect();
        plan
    }

    /// The agents the sample run's pre-flight probed.
    ///
    /// Not the agents the chains bind, and not a sorted list. A real run's
    /// probe finds every configured CLI, of which the ladder binds some; a
    /// fixture whose allow-list happened to be the set of bound agents would be
    /// reproduced exactly by an encoder that derived the allow-list from the
    /// rungs instead of reading the record. `copilot` is here and is bound by
    /// nothing; `claude-code` is bound and is here; the padded, multi-byte and
    /// over-length entries are here and are bound by nothing.
    ///
    /// The order is the record's: neither ascending nor descending by bytes
    /// (`"  Codex-CLI  "` sorts first, the `a`-run second, `claude-code` third,
    /// `copilot` fourth, `ÜBER…` last), so an encoder that sorted or reversed
    /// the list writes bytes this fixture does not contain.
    fn sample_agents() -> Vec<String> {
        vec![
            "ÜBER-agent-Ωmega".to_owned(),
            "claude-code".to_owned(),
            "  Codex-CLI  ".to_owned(),
            "a".repeat(300),
            "copilot".to_owned(),
        ]
    }

    /// The derivation every fixture here goes through, with the sample run's
    /// probed agents.
    fn originals_of(plan: &Plan, started: &RunStarted) -> Result<TaskRegistry, RegistryError> {
        TaskRegistry::originals_with_agents(plan, started, &sample_agents())
    }

    fn registry_of(plan: &Plan) -> TaskRegistry {
        originals_of(plan, &started_for(plan)).expect("the sample record is complete")
    }

    // -----------------------------------------------------------------------
    // INV-04: the key is the identity, the display id is a projection
    // -----------------------------------------------------------------------

    #[test]
    fn keys_are_dense_and_assigned_in_plan_order() {
        let plan = sample_plan();
        let registry = registry_of(&plan);

        let keyed: Vec<(u32, &str)> = registry
            .entries()
            .iter()
            .map(|entry| (entry.key.0, entry.display_id.as_str()))
            .collect();
        assert_eq!(
            keyed,
            vec![(0, "zeta"), (1, "alpha"), (2, "mid")],
            "keys are dense from 0 in plan order — not in display-id order, and not in \
             topological order"
        );

        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());
        for (index, entry) in registry.entries().iter().enumerate() {
            assert_eq!(entry.key.index(), index);
            assert_eq!(registry.key_of(entry.display_id.as_str()), Some(entry.key));
            assert_eq!(
                registry.get(entry.key).map(|found| &found.display_id),
                Some(&entry.display_id)
            );
            assert_eq!(entry.origin, Origin::Original);
            assert_eq!(entry.lineage, None);
        }
        assert_eq!(registry.key_of("no-such-task"), None);
        assert_eq!(registry.get(TaskKey(3)), None);
    }

    #[test]
    fn dependencies_are_stored_as_keys_and_projected_as_written() {
        let plan = sample_plan();
        let registry = registry_of(&plan);

        let deps: Vec<(&str, Vec<u32>, Vec<&str>)> = registry
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.display_id.as_str(),
                    entry.deps.iter().map(|key| key.0).collect(),
                    entry.display_deps.iter().map(TaskId::as_str).collect(),
                )
            })
            .collect();

        assert_eq!(
            deps,
            vec![
                ("zeta", vec![1], vec!["alpha"]),
                ("alpha", vec![], vec![]),
                // Written `alpha, zeta`, which is keys 1 then 0: resolved by id
                // and kept in the order the plan wrote them, never sorted and
                // never taken from the dependent's own position.
                ("mid", vec![1, 0], vec!["alpha", "zeta"]),
            ]
        );

        // The keys above are `1, 0` and so cannot be a sorted list, but the
        // display side of the same task is `alpha, zeta` — already sorted, and
        // therefore silent about whether the plan's order was kept or merely
        // reproduced by accident. The wide fixture says which, and says it of
        // each representation on its own rather than of the pair moving
        // together.
        let plan = dependency_order_plan();
        let registry = originals_of(&plan, &started_for(&plan))
            .expect("the dependency-order record is complete");
        let omega = registry
            .get(registry.key_of("omega").expect("omega is registered"))
            .expect("omega's entry");

        let written: Vec<&str> = omega.display_deps.iter().map(TaskId::as_str).collect();
        assert_eq!(
            written,
            vec!["zeta", "alpha", "echo", "beta"],
            "display dependencies are the plan's own order, not a sorted one"
        );
        assert_eq!(
            omega.deps,
            vec![TaskKey(0), TaskKey(2), TaskKey(1), TaskKey(3)],
            "and the keys are those ids resolved in place, not a sorted or a positional list"
        );

        // The fixture has to be able to see a sort before either assertion
        // above means anything: a list that was already ordered would satisfy
        // both a registry that kept it and one that ordered it.
        for (what, ordered) in [
            ("sorted", {
                let mut sorted = written.clone();
                sorted.sort_unstable();
                sorted
            }),
            ("reverse-sorted", {
                let mut reversed = written.clone();
                reversed.sort_unstable_by(|left, right| right.cmp(left));
                reversed
            }),
        ] {
            assert_ne!(
                written, ordered,
                "the fixture's dependency list must not already be in {what} order"
            );
        }
        let keys: Vec<u32> = omega.deps.iter().map(|key| key.0).collect();
        assert_ne!(keys, vec![0, 1, 2, 3], "nor may the keys already be sorted");
        assert_ne!(keys, vec![3, 2, 1, 0], "nor reverse-sorted");

        // Each representation names the same dependency at the same position:
        // that is the pairing the two lists claim, and it is what makes a sort
        // of one alone a contradiction rather than a difference of opinion.
        for (position, (key, display)) in omega.deps.iter().zip(&omega.display_deps).enumerate() {
            assert_eq!(
                registry.get(*key).map(|entry| &entry.display_id),
                Some(display),
                "the key and the display id at position {position} name different tasks"
            );
        }

        // And the projection is the written order too — the whole point of
        // keeping a second copy is that a legacy reader sees what the plan
        // said.
        assert_eq!(
            omega
                .legacy_task()
                .depends_on
                .iter()
                .map(TaskId::as_str)
                .collect::<Vec<_>>(),
            written
        );
    }

    #[test]
    fn artifact_lists_keep_the_order_the_plan_wrote_them_in() {
        // The same defect as the dependency lists, in the two remaining fields
        // whose order the encoder writes: every other fixture holds exactly one
        // artifact on each side, so a registry that sorted either list is
        // indistinguishable from one that copied it.
        let plan = artifact_order_plan();
        let registry = originals_of(&plan, &started_for(&plan))
            .expect("the artifact-order record is complete");
        let omega = registry
            .get(registry.key_of("omega").expect("omega is registered"))
            .expect("omega's entry");

        assert_eq!(
            omega
                .spec
                .artifacts_in
                .iter()
                .map(ArtifactId::as_str)
                .collect::<Vec<_>>(),
            vec!["contract", "api", "schema"]
        );
        assert_eq!(
            omega
                .spec
                .artifacts_out
                .iter()
                .map(ArtifactId::as_str)
                .collect::<Vec<_>>(),
            vec!["omega-out", "audit", "notes"]
        );

        // Neither list may already be in an order a sort would produce, or the
        // assertions above hold just as well for a registry that sorted it.
        for (what, list) in [
            ("artifacts in", &omega.spec.artifacts_in),
            ("artifacts out", &omega.spec.artifacts_out),
        ] {
            let written: Vec<&str> = list.iter().map(ArtifactId::as_str).collect();
            let mut sorted = written.clone();
            sorted.sort_unstable();
            assert_ne!(
                written, sorted,
                "the fixture's {what} list must not already be sorted"
            );
            sorted.reverse();
            assert_ne!(written, sorted, "nor reverse-sorted, for the same reason");
        }

        // The projection carries the written order back out to a legacy reader,
        assert_eq!(
            normalized_bytes(&round_tripped(&plan)),
            normalized_bytes(&plan),
            "an artifact list came back in an order the frozen plan did not write"
        );

        // and the digest authenticates it: were a permutation to encode alike,
        // one recorded digest would accept both records.
        let baseline = registry.canonical_bytes();
        let permutations: [(&str, PermuteTask); 2] = [
            ("artifacts in", |task| task.artifacts_in.swap(0, 1)),
            ("artifacts out", |task| task.artifacts_out.swap(0, 1)),
        ];
        for (what, permute) in permutations {
            let mut moved = artifact_order_plan();
            permute(moved.tasks.last_mut().expect("omega is the last task"));
            let rebuilt = originals_of(&moved, &started_for(&moved))
                .expect("a permuted artifact list still builds");
            assert_ne!(
                rebuilt.canonical_bytes(),
                baseline,
                "permuting {what} left the canonical bytes where they were"
            );
        }
    }

    #[test]
    fn the_frozen_ladder_is_the_chain_the_run_recorded() {
        let plan = sample_plan();
        let registry = registry_of(&plan);

        // Every entry rather than the first. The sample records one chain shape
        // for all three tasks, so a check of entry 0 alone says nothing about
        // whether the other two were given a ladder at all — which is why the
        // association itself is proved on the varied fixture below rather than
        // here.
        for entry in registry.entries() {
            let id = &entry.display_id;
            assert_eq!(entry.ladder.tiers, vec![Tier::Small, Tier::Mid], "{id}");
            assert_eq!(entry.ladder.attempts_per, 2, "{id}");
            assert_eq!(
                entry.ladder.rungs,
                vec![
                    FrozenRung {
                        tier: Tier::Small,
                        agent: "claude-code".to_owned(),
                        model: "claude-haiku-4-5".to_owned(),
                        pinned: false,
                    },
                    FrozenRung {
                        tier: Tier::Mid,
                        agent: "codex".to_owned(),
                        model: "gpt-5.6-sol".to_owned(),
                        pinned: true,
                    },
                ],
                "{id}"
            );
            assert_eq!(
                entry.ladder.floor,
                Some(Tier::Small),
                "{id}: the task's min="
            );
            assert_eq!(
                entry.ladder.ceiling,
                Some(Tier::Mid),
                "{id}: the top of the frozen chain, which a repair may not exceed"
            );
            assert_eq!(entry.ladder.admission, Admission::Runnable, "{id}");
            assert_eq!(
                entry.ladder.effort,
                sample_effort(),
                "{id}: the whole resolved standard, not one member of it"
            );
        }
    }

    #[test]
    fn each_entry_takes_the_chain_recorded_for_its_own_display_id() {
        // The scope requirement: an original's attempts, agent, model and pin
        // come from *its own* `run_started` chain. The sample fixture cannot
        // witness that — one chain shape repeated makes a keyed lookup, a
        // positional lookup and a first-chain lookup indistinguishable. Here
        // the three ladders differ in every component and the record writes
        // them in a derangement of plan order, so each wrong lookup produces a
        // wrong ladder for at least one task.
        let plan = varied_plan();
        let started = varied_started_for(&plan);
        let registry = originals_of(&plan, &started).expect("the varied record is complete");

        // The fixture has to discriminate before anything below means
        // something: two equal ladders would satisfy any lookup at all.
        let ladders: Vec<&FrozenLadder> = registry
            .entries()
            .iter()
            .map(|entry| &entry.ladder)
            .collect();
        assert_eq!(ladders.len(), 3);
        for (index, left) in ladders.iter().enumerate() {
            for right in &ladders[index + 1..] {
                assert_ne!(
                    left, right,
                    "the varied fixture must give no two tasks the same ladder"
                );
            }
        }

        // Every entry's complete ladder, addressed by the display id whose
        // chain it had to have taken — and reachable by its key, which is the
        // identity everything after this slice addresses it by.
        for entry in registry.entries() {
            assert_eq!(registry.get(entry.key), Some(entry));
            assert_eq!(registry.key_of(entry.display_id.as_str()), Some(entry.key));
            assert_eq!(
                entry.ladder,
                expected_ladder(&plan, entry.display_id.as_str()),
                "`{}` (key {}) was given a ladder that is not its own",
                entry.display_id,
                entry.key
            );
        }

        // And the two substitutions named explicitly, so a regression to either
        // fails here instead of passing on a fixture that cannot see it.
        let first_chain = started.chains[0].task.as_str();
        for (index, entry) in registry.entries().iter().enumerate() {
            let positional = started.chains[index].task.as_str();
            assert_ne!(
                positional,
                entry.display_id.as_str(),
                "the record's chain order must stay a derangement of plan order"
            );
            assert_ne!(
                entry.ladder,
                expected_ladder(&plan, positional),
                "`{}` must not be satisfiable by the chain at its own index",
                entry.display_id
            );
            if entry.display_id.as_str() != first_chain {
                assert_ne!(
                    entry.ladder,
                    expected_ladder(&plan, first_chain),
                    "`{}` must not be satisfiable by the first recorded chain",
                    entry.display_id
                );
            }
        }
    }

    #[test]
    fn the_ladder_ceiling_is_the_highest_tier_recorded_not_an_end_of_the_list() {
        // `ceiling` is the maximum of the recorded tiers, and every other
        // fixture records them ascending — which is what an escalation ladder
        // is, and which makes the maximum, the last element and (for the
        // one-rung chain) the first element the same value. A ceiling taken
        // from an end of the list rather than over the whole of it therefore
        // produces the expected answer everywhere else in this module.
        let plan = plan_of(vec![task("alpha", &[])]);
        let mut started = started_for(&plan);
        started.chains = vec![unordered_chain("alpha")];
        let registry = originals_of(&plan, &started).expect("the unordered record is complete");
        let entry = &registry.entries()[0];

        // The fixture has to be able to see the difference before the assertion
        // below means anything.
        assert_eq!(
            entry.ladder.tiers,
            vec![Tier::Mid, Tier::Frontier, Tier::Small],
            "the fixture records the top rung in the middle"
        );
        assert_ne!(
            entry.ladder.tiers.first().copied(),
            Some(Tier::Frontier),
            "the first recorded tier must not be the highest, or a ceiling read off the front of \
             the list is indistinguishable from one taken over all of it"
        );
        assert_ne!(
            entry.ladder.tiers.last().copied(),
            Some(Tier::Frontier),
            "nor the last, for the same reason"
        );

        assert_eq!(
            entry.ladder.ceiling,
            Some(Tier::Frontier),
            "the ceiling is the highest tier the ladder reaches — the policy ceiling a repair \
             descended from this entry may not exceed — not whichever tier the record happened \
             to write first or last"
        );
        // And the floor is the task's own `min=`, which does not follow the
        // recorded order at all: here it is the tier the list ends on.
        assert_eq!(
            entry.ladder.floor,
            Some(Tier::Small),
            "the task's min=, not a position in the recorded chain"
        );
    }

    #[test]
    fn frozen_reviews_take_each_task_s_own_second_opinion_slot() {
        let plan = sample_plan();
        let registry = registry_of(&plan);
        let slots: Vec<Option<&str>> = registry
            .entries()
            .iter()
            .map(|entry| {
                entry
                    .reviews
                    .second_opinion
                    .as_ref()
                    .map(|binding| binding.model.as_str())
            })
            .collect();
        assert_eq!(
            slots,
            vec![None, Some("gpt-5.6"), None],
            "slots are read at the task's own index, so a shifted read is visible"
        );
        for entry in registry.entries() {
            assert!(entry.reviews.enabled);
            assert!(entry.reviews.alternative_available);
            assert_eq!(entry.reviews.pass_timeout_secs, 900);
            assert_eq!(
                entry.reviews.primary,
                Some(PassBinding::new("claude-code", "claude-opus-5"))
            );
            assert_eq!(
                entry.reviews.alternative,
                Some(PassBinding::new("copilot", "gpt-5.6"))
            );
        }

        // The sample's slot pattern is a palindrome, and its one occupied slot
        // holds the same binding as `alternative`. A read that walked the slots
        // backwards therefore reproduces it exactly, and so does one that
        // copied the alternative reviewer into every entry. The varied fixture
        // gives each occupied slot an agent *and* a model naming the task it
        // belongs to, which neither substitution can imitate.
        //
        // Both components are read. While only the model was, the agent's
        // source was free: every occupied fixture slot said `copilot`, so an
        // agent taken from `alternative` — which says `copilot` too — or
        // hard-coded to that literal produced the expected answer, and the
        // slot's own recorded agent was never consulted by anything.
        let plan = varied_plan();
        let registry =
            originals_of(&plan, &varied_started_for(&plan)).expect("the varied record is complete");
        let named: Vec<(&str, Option<(&str, &str)>)> = registry
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.display_id.as_str(),
                    entry
                        .reviews
                        .second_opinion
                        .as_ref()
                        .map(|binding| (binding.agent.as_str(), binding.model.as_str())),
                )
            })
            .collect();
        assert_eq!(
            named,
            vec![
                ("zeta", Some(("zeta-second-agent", "second-for-zeta"))),
                ("alpha", None),
                ("mid", Some(("mid-second-agent", "second-for-mid"))),
            ],
            "each entry holds both components of the slot recorded at its own plan index"
        );

        // And the run-level bindings the occupied slots could have been taken
        // from are still beside them, holding literals none of the slots share.
        for entry in registry.entries() {
            assert_eq!(
                entry.reviews.primary,
                Some(PassBinding::new("claude-code", "claude-opus-5"))
            );
            assert_eq!(
                entry.reviews.alternative,
                Some(PassBinding::new("copilot", "gpt-5.6"))
            );
        }
    }

    /// One value in the run record, and the entry field it is supposed to feed.
    ///
    /// `mutate` moves exactly one recorded value; `restore` copies back the one
    /// field the case claims that value lands in. Both halves are load-bearing.
    /// Without the first, a constructor that ignored the record and wrote a
    /// literal passes, because the field it wrote never depended on the record
    /// at all. Without the second, a constructor that read the record at the
    /// wrong field passes, because *something* moved.
    struct SourceCase {
        label: &'static str,
        mutate: fn(&mut RunStarted),
        restore: fn(&mut TaskEntry, &TaskEntry),
    }

    #[test]
    fn moving_one_recorded_value_moves_exactly_the_entry_field_it_feeds() {
        // The distinction this draws is derivation against encoding. The
        // canonical-bytes table takes an entry that is already built and moves
        // one field of it, which proves the serializer writes that field — and
        // says nothing about where the builder got it. A constructor that
        // wrote the literal `Effort::Low` into `effort.small`, or `true` into
        // `reviews.enabled`, encodes just as faithfully and satisfies every
        // fixture that never moves the source underneath it.
        //
        // So each case here moves one value of the `RunStarted` the registry is
        // derived *from*, and the built entry has to follow it — in that field
        // and in no other. `effort.review` is the worked example for the second
        // half: the sample record resolves it to `high`, which is also what it
        // resolves `effort.frontier` to, so a constructor that read the
        // frontier standard where it meant the review standard stays invisible
        // until exactly one of the two moves.
        let cases: [SourceCase; 13] = [
            SourceCase {
                label: "small-tier effort standard",
                mutate: |started| {
                    started.effort_policy.as_mut().expect("effort policy").small = Effort::Max;
                },
                restore: |entry, base| entry.ladder.effort.small = base.ladder.effort.small,
            },
            SourceCase {
                label: "mid-tier effort standard",
                mutate: |started| {
                    started.effort_policy.as_mut().expect("effort policy").mid = Effort::Max;
                },
                restore: |entry, base| entry.ladder.effort.mid = base.ladder.effort.mid,
            },
            SourceCase {
                label: "frontier-tier effort standard",
                mutate: |started| {
                    started
                        .effort_policy
                        .as_mut()
                        .expect("effort policy")
                        .frontier = Effort::Low;
                },
                restore: |entry, base| entry.ladder.effort.frontier = base.ladder.effort.frontier,
            },
            SourceCase {
                label: "review effort standard",
                mutate: |started| {
                    started
                        .effort_policy
                        .as_mut()
                        .expect("effort policy")
                        .review = Effort::Low;
                },
                restore: |entry, base| entry.ladder.effort.review = base.ladder.effort.review,
            },
            SourceCase {
                label: "reviews.enabled marker",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").enabled = Some(false);
                },
                restore: |entry, base| entry.reviews.enabled = base.reviews.enabled,
            },
            SourceCase {
                label: "reviews.alternative_available marker",
                mutate: |started| {
                    started
                        .reviews
                        .as_mut()
                        .expect("reviews")
                        .alternative_available = Some(false);
                },
                restore: |entry, base| {
                    entry.reviews.alternative_available = base.reviews.alternative_available;
                },
            },
            SourceCase {
                label: "per-pass review timeout",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").pass_timeout_secs = Some(60);
                },
                restore: |entry, base| {
                    entry.reviews.pass_timeout_secs = base.reviews.pass_timeout_secs;
                },
            },
            // The reviewer bindings are restored one component at a time rather
            // than whole, so a constructor that put the recorded agent in the
            // model field fails here as well: restoring the agent alone leaves
            // the misplaced value behind for the comparison to find.
            SourceCase {
                label: "primary reviewer agent",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").primary =
                        Some(PassBinding::new("copilot", "claude-opus-5"));
                },
                restore: |entry, base| {
                    restore_agent(&mut entry.reviews.primary, &base.reviews.primary)
                },
            },
            SourceCase {
                label: "primary reviewer model",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").primary =
                        Some(PassBinding::new("claude-code", "gpt-5.6"));
                },
                restore: |entry, base| {
                    restore_model(&mut entry.reviews.primary, &base.reviews.primary)
                },
            },
            SourceCase {
                label: "primary reviewer absence",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").primary = None;
                },
                restore: |entry, base| entry.reviews.primary = base.reviews.primary.clone(),
            },
            SourceCase {
                label: "alternative reviewer agent",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").alternative =
                        Some(PassBinding::new("claude-code", "gpt-5.6"));
                },
                restore: |entry, base| {
                    restore_agent(&mut entry.reviews.alternative, &base.reviews.alternative);
                },
            },
            SourceCase {
                label: "alternative reviewer model",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").alternative =
                        Some(PassBinding::new("copilot", "gpt-5.6-sol"));
                },
                restore: |entry, base| {
                    restore_model(&mut entry.reviews.alternative, &base.reviews.alternative);
                },
            },
            SourceCase {
                label: "alternative reviewer absence",
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").alternative = None;
                },
                restore: |entry, base| entry.reviews.alternative = base.reviews.alternative.clone(),
            },
        ];

        let plan = sample_plan();
        let baseline = registry_of(&plan);
        for SourceCase {
            label,
            mutate,
            restore,
        } in cases
        {
            let mut started = started_for(&plan);
            mutate(&mut started);
            let moved = originals_of(&plan, &started)
                .unwrap_or_else(|error| panic!("the {label} case must still build: {error}"));
            assert_eq!(moved.len(), baseline.len(), "{label}");

            // Every entry rather than the first. These are run-level standards
            // and belong on all three, so an entry that stayed where it was
            // names one the constructor filled in from something other than the
            // record it was handed.
            for (index, (entry, base)) in moved.entries().iter().zip(baseline.entries()).enumerate()
            {
                assert_ne!(
                    entry, base,
                    "moving the {label} left entry {index} exactly as it was, so that field is \
                     not read from the run record"
                );
                let mut restored = entry.clone();
                restore(&mut restored, base);
                assert_eq!(
                    &restored, base,
                    "moving the {label} moved something else in entry {index} too, so the \
                     recorded value reaches a field it does not belong to"
                );
            }
        }
    }

    /// Copy one binding's agent back, leaving its model where it was found.
    fn restore_agent(entry: &mut Option<PassBinding>, base: &Option<PassBinding>) {
        if let (Some(moved), Some(original)) = (entry.as_mut(), base.as_ref()) {
            moved.agent.clone_from(&original.agent);
        }
    }

    /// Copy one binding's model back, leaving its agent where it was found.
    fn restore_model(entry: &mut Option<PassBinding>, base: &Option<PassBinding>) {
        if let (Some(moved), Some(original)) = (entry.as_mut(), base.as_ref()) {
            moved.model.clone_from(&original.model);
        }
    }

    /// One recorded second-opinion slot, and the entry component it feeds.
    ///
    /// The table above moves run-level standards, where the claim is that
    /// *every* entry follows the value. A second-opinion slot is the opposite
    /// claim: it belongs to one task, so the entry at that index has to follow
    /// it and the others have to stay exactly where they were.
    struct SlotCase {
        label: &'static str,
        /// The plan index whose entry is the only one allowed to move.
        slot: usize,
        mutate: fn(&mut RunStarted),
        restore: fn(&mut TaskEntry, &TaskEntry),
    }

    #[test]
    fn moving_one_second_opinion_slot_moves_exactly_that_entry_s_component() {
        // The run-level table has a case for each component of the primary and
        // the alternative reviewer, and none for the second opinion — the one
        // reviewer binding that is *per task*. Every test that named it read
        // the slot back off a fixture instead, and while both occupied fixture
        // slots said `copilot`, so did `alternative`: an agent copied from the
        // alternative reviewer, or hard-coded to that literal, was the fixture's
        // own answer and no test could see the difference.
        //
        // So each case here moves one component of one recorded slot and
        // requires the entry at that index to follow it — in that component,
        // in no other component of that entry, and in no other entry. The
        // varied record is the fixture because the sample's occupied slot holds
        // `alternative`'s exact binding and cannot discriminate the two.
        let cases: [SlotCase; 7] = [
            SlotCase {
                label: "zeta's second-opinion agent",
                slot: 0,
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").second_opinion[0] =
                        Some(PassBinding::new("moved-agent-for-zeta", "second-for-zeta"));
                },
                restore: |entry, base| {
                    restore_agent(
                        &mut entry.reviews.second_opinion,
                        &base.reviews.second_opinion,
                    );
                },
            },
            SlotCase {
                label: "zeta's second-opinion model",
                slot: 0,
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").second_opinion[0] = Some(
                        PassBinding::new("zeta-second-agent", "moved-model-for-zeta"),
                    );
                },
                restore: |entry, base| {
                    restore_model(
                        &mut entry.reviews.second_opinion,
                        &base.reviews.second_opinion,
                    );
                },
            },
            SlotCase {
                label: "zeta's second-opinion absence",
                slot: 0,
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").second_opinion[0] = None;
                },
                restore: |entry, base| {
                    entry.reviews.second_opinion = base.reviews.second_opinion.clone();
                },
            },
            SlotCase {
                label: "mid's second-opinion agent",
                slot: 2,
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").second_opinion[2] =
                        Some(PassBinding::new("moved-agent-for-mid", "second-for-mid"));
                },
                restore: |entry, base| {
                    restore_agent(
                        &mut entry.reviews.second_opinion,
                        &base.reviews.second_opinion,
                    );
                },
            },
            SlotCase {
                label: "mid's second-opinion model",
                slot: 2,
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").second_opinion[2] =
                        Some(PassBinding::new("mid-second-agent", "moved-model-for-mid"));
                },
                restore: |entry, base| {
                    restore_model(
                        &mut entry.reviews.second_opinion,
                        &base.reviews.second_opinion,
                    );
                },
            },
            SlotCase {
                label: "mid's second-opinion absence",
                slot: 2,
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").second_opinion[2] = None;
                },
                restore: |entry, base| {
                    entry.reviews.second_opinion = base.reviews.second_opinion.clone();
                },
            },
            // The empty slot filled, rather than an occupied one emptied: a
            // constructor that decided which entries get a second opinion from
            // anything but the record — the sample's alternating pattern, say —
            // leaves `alpha` empty here.
            SlotCase {
                label: "alpha's second-opinion presence",
                slot: 1,
                mutate: |started| {
                    started.reviews.as_mut().expect("reviews").second_opinion[1] =
                        Some(PassBinding::new("alpha-second-agent", "second-for-alpha"));
                },
                restore: |entry, base| {
                    entry.reviews.second_opinion = base.reviews.second_opinion.clone();
                },
            },
        ];

        let plan = varied_plan();
        let baseline =
            originals_of(&plan, &varied_started_for(&plan)).expect("the varied record is complete");
        for SlotCase {
            label,
            slot,
            mutate,
            restore,
        } in cases
        {
            let mut started = varied_started_for(&plan);
            mutate(&mut started);
            let moved = originals_of(&plan, &started)
                .unwrap_or_else(|error| panic!("the {label} case must still build: {error}"));
            assert_eq!(moved.len(), baseline.len(), "{label}");

            let entry = &moved.entries()[slot];
            let base = &baseline.entries()[slot];
            assert_ne!(
                entry, base,
                "moving {label} left entry {slot} exactly as it was, so that component is not \
                 read from the run record"
            );
            let mut restored = entry.clone();
            restore(&mut restored, base);
            assert_eq!(
                &restored, base,
                "moving {label} moved something else in entry {slot} too, so the recorded value \
                 reaches a component it does not belong to"
            );

            // A slot belongs to one task. Any other entry that followed it is a
            // slot being broadcast rather than read at the task's own index.
            for (index, (other, base_other)) in
                moved.entries().iter().zip(baseline.entries()).enumerate()
            {
                if index == slot {
                    continue;
                }
                assert_eq!(
                    other, base_other,
                    "moving {label} moved entry {index} as well"
                );
            }
        }
    }

    #[test]
    fn the_fixtures_give_every_binding_component_its_own_literal() {
        // The systematic defect this slice kept producing, stated as a fixture
        // property rather than patched one case at a time: where two
        // independently meaningful components share a literal, the one a test
        // names can be read from the other — or hard-coded to the value both
        // happen to hold — and still produce the expected answer. Enumerating
        // every identity literal the discriminating record carries and refusing
        // a repeat closes that for components no test names yet as well as for
        // the ones it does.
        //
        // The sample record is deliberately not enumerated: it feeds the frozen
        // digest vector and cannot move, and its occupied second-opinion slot
        // holds `alternative`'s exact binding. That is precisely why the varied
        // record exists and why it is the one that has to stay discriminating.
        let plan = varied_plan();
        let started = varied_started_for(&plan);
        let reviews = started
            .reviews
            .as_ref()
            .expect("the varied record's review plan");

        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut record = |label: String, value: &str| {
            if let Some(first) = seen.insert(value.to_owned(), label.clone()) {
                panic!(
                    "the varied fixture gives `{value}` to both {first} and {label}; a component \
                     read from either where it meant the other would still look right"
                );
            }
        };

        for chain in &started.chains {
            let task = &chain.task;
            for binding in chain
                .bindings
                .as_ref()
                .expect("the varied fixture records bindings")
            {
                let tier = binding.tier;
                record(
                    format!("chain `{task}`'s {tier} rung agent"),
                    &binding.agent,
                );
                record(
                    format!("chain `{task}`'s {tier} rung model"),
                    &binding.model,
                );
            }
        }
        for (what, binding) in [
            ("the primary reviewer", reviews.primary.as_ref()),
            ("the alternative reviewer", reviews.alternative.as_ref()),
        ] {
            let binding = binding.expect("the varied fixture records the run-level reviewers");
            record(format!("{what}'s agent"), &binding.agent);
            record(format!("{what}'s model"), &binding.model);
        }
        for (index, slot) in reviews.second_opinion.iter().enumerate() {
            let Some(binding) = slot.as_ref() else {
                continue;
            };
            let task = plan.tasks[index].id.as_str();
            record(format!("`{task}`'s second-opinion agent"), &binding.agent);
            record(format!("`{task}`'s second-opinion model"), &binding.model);
        }

        // The count is this guard's own guard: a collection loop that stopped
        // recording would otherwise pass by finding nothing to collide.
        assert_eq!(
            seen.len(),
            20,
            "six recorded rungs, two run-level reviewers and two occupied second-opinion slots, \
             each contributing an agent and a model"
        );
    }

    // -----------------------------------------------------------------------
    // Reserved display ids
    // -----------------------------------------------------------------------

    #[test]
    fn the_reserved_namespace_covers_every_id_the_repair_generator_can_emit() {
        // The generator and the refusal are checked against each other rather
        // than each against a literal, so a change to one that the other does
        // not follow fails here instead of colliding at run time.
        for index in [0u32, 1, 9, 99, 999, 1000, 9999, 10_000, u32::MAX] {
            for root in ["a", "alpha", "0001", "x-1", "merge-fix-0001-alpha"] {
                let id = repair_display_id(index, &TaskId::from(root));
                assert!(
                    is_reserved_display_id(&id),
                    "the generator emitted `{id}`, which the refusal does not reserve"
                );
            }
        }
        // Two literal ids, anchoring the shape the decision wrote down. They
        // are samples and cannot be more than that: any pair of inputs can be
        // answered from a table keyed on exactly those inputs. What makes the
        // suffix *the root* rather than a string that matched twice is the
        // relation asserted in
        // `a_repair_id_is_its_prefix_its_index_and_the_root_display_id_itself`.
        assert_eq!(
            repair_display_id(1, &TaskId::from("zeta")),
            "merge-fix-0001-zeta",
            "the shape the merge-queue decision records"
        );
        assert_eq!(
            repair_display_id(12_345, &TaskId::from("omega")),
            "merge-fix-12345-omega",
            "an index past the pad width widens rather than truncating"
        );

        // And the namespace stops where it should: reserving everything would
        // refuse ordinary plans, and reserving only the literal prefix would
        // let a plan take an id a five-digit lineage would later generate.
        for outside in [
            "alpha",
            "merge",
            "merge-fix",
            "merge-fix-",
            "merge-fix-001-a",
            "merge-fix-abcd-a",
            "merge-fix-0001a",
            "merge-fixed-0001-a",
            "x-merge-fix-0001-a",
            "mérge-fix-0001-a",
        ] {
            assert!(
                !is_reserved_display_id(outside),
                "`{outside}` is not an id the merge queue can generate"
            );
        }
        assert!(
            is_reserved_display_id("MERGE-FIX-0001-a"),
            "a reserved namespace is not escaped by shouting"
        );
    }

    #[test]
    fn a_repair_id_is_its_prefix_its_index_and_the_root_display_id_itself() {
        // The frozen framing, written out rather than read from `REPAIR_PREFIX`
        // and `REPAIR_INDEX_WIDTH`: an expectation composed from the production
        // constants would follow them wherever they moved, and holding them
        // still is half of what this test is for.
        const PREFIX: &str = "merge-fix-";
        const SEPARATOR: &str = "-";
        const PAD_WIDTH: usize = 4;

        // Roots that no table can be keyed on: none is a fixture task id or
        // appears anywhere else in this module, `0042` and `-` are not task ids
        // at all, and `merge-fix-0042-kestrel` is itself shaped like a repair
        // id. Every root is crossed against every index, so a suffix chosen by
        // index and a suffix chosen by root are each wrong somewhere in this
        // grid; only reading the argument satisfies all of it.
        //
        // The last four are hostile to *transformations* of the root rather
        // than to substitutions of it. A generator that reads the argument but
        // lowercases, trims, truncates or re-encodes it would satisfy every
        // root above and disagree here: `Kestrel` is not case-stable, the
        // padded root is not trim-stable, the long root exceeds any plausible
        // truncation bound, and `café-kestrel` has more bytes than characters.
        // `TaskId` is a transparent string that preserves what it is given, so
        // each of these is a legal root and the suffix must come back
        // byte-for-byte.
        for root in [
            "kestrel",
            "quartz",
            "0042",
            "-",
            "merge-fix-0042-kestrel",
            "Kestrel",
            "  quartz  ",
            "a-root-identifier-that-is-longer-than-thirty-two-bytes",
            "café-kestrel",
        ] {
            for index in [0u32, 1, 4_242, 9_999, 10_000, u32::MAX] {
                let id = repair_display_id(index, &TaskId::from(root));

                let framed = id
                    .strip_prefix(PREFIX)
                    .unwrap_or_else(|| panic!("`{id}` does not open with `{PREFIX}`"));
                let digits = framed.bytes().take_while(u8::is_ascii_digit).count();
                let (rendered, tail) = framed.split_at(digits);
                assert_eq!(
                    rendered.parse::<u32>().ok(),
                    Some(index),
                    "`{id}` does not carry lineage index {index}"
                );
                assert_eq!(
                    rendered.len(),
                    index.to_string().len().max(PAD_WIDTH),
                    "`{id}` renders its index at neither {PAD_WIDTH} padded digits nor its own width"
                );
                let suffix = tail.strip_prefix(SEPARATOR).unwrap_or_else(|| {
                    panic!("`{id}` does not part its index from its root with `{SEPARATOR}`")
                });

                // The relation, which is the whole point: the suffix is not a
                // string this pair happens to produce, it *is* the root display
                // id. A generator that chose the suffix any other way — from the
                // index, from a list of known roots, from nothing — disagrees
                // here for at least one cell of the grid above.
                assert_eq!(
                    suffix, root,
                    "`{id}` was generated for root `{root}` and does not end in it"
                );
            }
        }
    }

    #[test]
    fn an_original_may_not_take_a_reserved_repair_id() {
        // Written out rather than asked of `repair_display_id`: a refusal test
        // that derives the id it expects to be refused from the generator
        // agrees with that generator however wrong it is, and would keep
        // passing while the namespace it defends moved out from under it.
        const RESERVED: &str = "merge-fix-0001-alpha";

        let plan = plan_of(vec![task("alpha", &[]), task(RESERVED, &[])]);
        let refusal = originals_of(&plan, &started_for(&plan))
            .expect_err("the reserved namespace belongs to the merge queue");
        assert_eq!(
            refusal,
            RegistryError::ReservedDisplayId {
                id: RESERVED.to_owned()
            }
        );
        assert!(refusal.to_string().contains(RESERVED));
    }

    #[test]
    fn a_duplicate_display_id_is_refused() {
        let plan = plan_of(vec![task("alpha", &[]), task("alpha", &[])]);
        assert_eq!(
            originals_of(&plan, &started_for(&plan)),
            Err(RegistryError::DuplicateDisplayId {
                id: "alpha".to_owned()
            })
        );
    }

    #[test]
    fn an_unknown_dependency_is_refused() {
        let plan = plan_of(vec![task("alpha", &["ghost"])]);
        assert_eq!(
            originals_of(&plan, &started_for(&plan)),
            Err(RegistryError::UnknownDependency {
                task: "alpha".to_owned(),
                dep: "ghost".to_owned(),
            })
        );
    }

    // -----------------------------------------------------------------------
    // Refusals: the plan and the run record must describe one run
    // -----------------------------------------------------------------------

    #[test]
    fn an_incomplete_run_record_cannot_authenticate_a_registry() {
        let cases: [(&str, BreakRecord); 6] = [
            ("effort policy", |started| started.effort_policy = None),
            ("review plan", |started| started.reviews = None),
            ("reviews.enabled marker", |started| {
                started.reviews.as_mut().expect("reviews").enabled = None;
            }),
            ("reviews.alternative_available marker", |started| {
                started
                    .reviews
                    .as_mut()
                    .expect("reviews")
                    .alternative_available = None;
            }),
            ("per-pass review timeout", |started| {
                started.reviews.as_mut().expect("reviews").pass_timeout_secs = None;
            }),
            ("resolved rung bindings", |started| {
                started.chains[0].bindings = None;
            }),
        ];
        for (field, break_it) in cases {
            let plan = sample_plan();
            let mut started = started_for(&plan);
            break_it(&mut started);
            assert_eq!(
                originals_of(&plan, &started),
                Err(RegistryError::IncompleteRunRecord { field }),
                "a record missing its {field} must refuse rather than default"
            );
        }
    }

    #[test]
    fn a_record_that_does_not_describe_the_frozen_plan_is_refused() {
        let cases: [(BreakRecord, RegistryError); 6] = [
            (
                |started| started.chains[0].task = "ghost".to_owned(),
                RegistryError::ChainWithoutTask {
                    task: "ghost".to_owned(),
                },
            ),
            (
                |started| started.chains[1].task = "zeta".to_owned(),
                RegistryError::DuplicateChain {
                    task: "zeta".to_owned(),
                },
            ),
            (
                |started| {
                    started.chains.pop();
                },
                RegistryError::TaskWithoutChain {
                    task: "mid".to_owned(),
                },
            ),
            (
                |started| {
                    started.chains[0].tiers.clear();
                    started.chains[0].bindings = Some(Vec::new());
                },
                RegistryError::EmptyLadder {
                    task: "zeta".to_owned(),
                },
            ),
            (
                |started| started.chains[0].attempts_per = 0,
                RegistryError::ZeroAttempts {
                    task: "zeta".to_owned(),
                },
            ),
            (
                |started| {
                    started.chains[0].bindings.as_mut().expect("bindings").pop();
                },
                RegistryError::BindingCount {
                    task: "zeta".to_owned(),
                    bindings: 1,
                    tiers: 2,
                },
            ),
        ];
        for (break_it, expected) in cases {
            let plan = sample_plan();
            let mut started = started_for(&plan);
            break_it(&mut started);
            assert_eq!(originals_of(&plan, &started), Err(expected));
        }

        // A binding recorded against the wrong tier: same count, wrong meaning.
        let plan = sample_plan();
        let mut started = started_for(&plan);
        started.chains[0].bindings.as_mut().expect("bindings")[0].tier = Tier::Frontier;
        assert_eq!(
            originals_of(&plan, &started),
            Err(RegistryError::BindingTier {
                task: "zeta".to_owned(),
                tier: Tier::Small,
                binding: Tier::Frontier,
            })
        );

        // A review identity that does not line up with the task list would give
        // one task another task's reviewer.
        let plan = sample_plan();
        let mut started = started_for(&plan);
        started
            .reviews
            .as_mut()
            .expect("reviews")
            .second_opinion
            .pop();
        assert_eq!(
            originals_of(&plan, &started),
            Err(RegistryError::ReviewAlignment {
                recorded: 2,
                tasks: 3
            })
        );
    }

    // -----------------------------------------------------------------------
    // registry_digest
    // -----------------------------------------------------------------------

    /// The value another process on another platform has to reach from the same
    /// inputs. Written down rather than derived beside the code, which would
    /// agree with any bug in it — and reproduced once from a separate
    /// implementation of the documented encoding rather than copied out of this
    /// one, so it pins the format and not merely today's output.
    const SAMPLE_DIGEST: &str =
        "sha256:02b5b9f120fb1b0499698e98849d5da3f7cadc35ba69da6f11e3f89464d3845d";

    /// The length of the exact bytes [`SAMPLE_DIGEST`] is taken over.
    ///
    /// Pinned beside the digest because the two fail differently: a hash
    /// mismatch says something moved, and the byte count says whether the
    /// encoding grew, shrank, or merely rearranged. Re-derived from the
    /// documented framing at the same time as the digest.
    const SAMPLE_CANONICAL_BYTES: usize = 2520;

    #[test]
    fn the_registry_digest_is_its_frozen_vector() {
        let plan = sample_plan();
        let registry = registry_of(&plan);
        assert_eq!(
            registry.digest(),
            SAMPLE_DIGEST,
            "the canonical serialization is frozen; a recorded digest outlives this binary"
        );
        assert_eq!(
            registry.canonical_bytes().len(),
            SAMPLE_CANONICAL_BYTES,
            "the digest is taken over a different number of bytes than the frozen encoding"
        );
        // Built again from scratch: no interior iteration order, no address,
        // no clock.
        assert_eq!(registry_of(&sample_plan()).digest(), SAMPLE_DIGEST);
        assert_eq!(registry.digest().len(), "sha256:".len() + 64);
    }

    #[test]
    fn a_record_that_names_no_probed_agents_derives_an_empty_allow_list() {
        // The two-argument derivation is the legacy one: a schema-1..3
        // `RunStarted` has nowhere to record what pre-flight probed, so every
        // entry's allow-list is empty — and that is a different registry, with
        // a different digest, from the one the same plan derives under a run
        // that probed anything at all. Asserted rather than assumed because the
        // difference is exactly what stops a schema-4 log from authenticating
        // against originals rebuilt through the wrong constructor.
        let plan = sample_plan();
        let started = started_for(&plan);
        let legacy =
            TaskRegistry::originals(&plan, &started).expect("the sample record is complete");

        for entry in legacy.entries() {
            assert!(
                entry.allowed_agents.is_empty(),
                "`{}` took an allow-list from a record that has no place to record one",
                entry.display_id
            );
        }
        assert_eq!(
            legacy,
            TaskRegistry::originals_with_agents(&plan, &started, &[])
                .expect("the sample record is complete"),
            "the two-argument derivation must be the no-agents case of the three-argument one, \
             not a second derivation that could drift from it"
        );
        assert_ne!(legacy.digest(), SAMPLE_DIGEST);
    }

    #[test]
    fn a_digest_mismatch_is_refused_and_a_match_is_not() {
        let registry = registry_of(&sample_plan());
        let recorded = registry.digest();
        assert_eq!(registry.verify_digest(&recorded), Ok(()));

        // What the refusal is actually for: the frozen plan moved by one field
        // under a log that recorded the digest of the plan it started with.
        let mut moved = sample_plan();
        moved.tasks[0].body.push('!');
        let rebuilt = registry_of(&moved);
        assert_eq!(
            rebuilt.verify_digest(&recorded),
            Err(RegistryError::DigestMismatch {
                expected: recorded,
                actual: rebuilt.digest(),
            })
        );
    }

    #[test]
    fn the_digest_covers_every_field_it_authenticates() {
        // One mutation per digest input. Each must move the digest, and no two
        // may move it to the same place: a field left out of the canonical
        // serialization shows up as a digest that did not move, and a field
        // written without its own length prefix shows up as a collision.
        let cases: [(&str, MoveInput); 30] = [
            ("display id", |plan, started, _| {
                plan.tasks[0].id = TaskId::from("zeta-renamed");
                plan.tasks[2].depends_on[1] = TaskId::from("zeta-renamed");
                started.chains[0].task = "zeta-renamed".to_owned();
            }),
            ("kind", |plan, _, _| plan.tasks[0].kind = TaskKind::Docs),
            ("title", |plan, _, _| plan.tasks[0].title.push('!')),
            ("body", |plan, _, _| plan.tasks[0].body.push('!')),
            ("acceptance", |plan, _, _| {
                plan.tasks[0].acceptance.push("more".to_owned());
            }),
            ("path hints", |plan, _, _| {
                plan.tasks[0].path_hints.push("src/extra.rs".to_owned());
            }),
            ("suggested tier", |plan, _, _| {
                plan.tasks[0].suggested_tier = Some(Tier::Frontier);
            }),
            ("suggested tier absent", |plan, _, _| {
                plan.tasks[0].suggested_tier = None;
            }),
            ("min tier", |plan, _, _| {
                plan.tasks[0].min_tier = Some(Tier::Mid);
            }),
            ("artifacts in", |plan, _, _| {
                plan.tasks[0].artifacts_in.push(ArtifactId::from("extra"));
            }),
            ("artifacts out", |plan, _, _| {
                plan.tasks[0].artifacts_out.push(ArtifactId::from("extra"));
            }),
            ("dependencies", |plan, _, _| {
                plan.tasks[0].depends_on.clear();
            }),
            ("dependency order", |plan, _, _| {
                plan.tasks[2].depends_on.swap(0, 1);
            }),
            ("plan order", |plan, started, _| {
                plan.tasks.swap(0, 1);
                started.chains.swap(0, 1);
            }),
            ("chain tiers", |_, started, _| {
                started.chains[0].tiers[1] = Tier::Frontier;
                started.chains[0].bindings.as_mut().expect("bindings")[1].tier = Tier::Frontier;
            }),
            ("attempts per rung", |_, started, _| {
                started.chains[0].attempts_per = 3;
            }),
            ("rung agent", |_, started, _| {
                started.chains[0].bindings.as_mut().expect("bindings")[0].agent =
                    "copilot".to_owned();
            }),
            ("rung model", |_, started, _| {
                started.chains[0].bindings.as_mut().expect("bindings")[0].model =
                    "claude-sonnet-5".to_owned();
            }),
            ("rung pin", |_, started, _| {
                started.chains[0].bindings.as_mut().expect("bindings")[0].pinned = true;
            }),
            ("effort policy", |_, started, _| {
                started
                    .effort_policy
                    .as_mut()
                    .expect("effort policy")
                    .frontier = Effort::Max;
            }),
            ("review pass timeout", |_, started, _| {
                started.reviews.as_mut().expect("reviews").pass_timeout_secs = Some(60);
            }),
            ("primary reviewer", |_, started, _| {
                started.reviews.as_mut().expect("reviews").primary =
                    Some(PassBinding::new("copilot", "gpt-5.6"));
            }),
            // The alternative reviewer and the marker that says one was
            // retained move separately, though a real run moves them together.
            // Moved as a pair they are one case, and a serialization that wrote
            // only one of them is authenticated by the other; apart, each has
            // to reach the digest on its own.
            ("alternative reviewer", |_, started, _| {
                started.reviews.as_mut().expect("reviews").alternative = None;
            }),
            ("alternative available marker", |_, started, _| {
                started
                    .reviews
                    .as_mut()
                    .expect("reviews")
                    .alternative_available = Some(false);
            }),
            // The sample record enables verification, and nothing else here
            // moves that marker off its default, so an encoding that dropped it
            // would be authenticated by every other case in this table.
            ("reviews enabled marker", |_, started, _| {
                started.reviews.as_mut().expect("reviews").enabled = Some(false);
            }),
            ("second opinion slot", |_, started, _| {
                started.reviews.as_mut().expect("reviews").second_opinion[1] = None;
            }),
            // The allow-list, moved four ways. It is the same value on every
            // entry, which is exactly why a single "the agents changed" case
            // would be weak evidence: an encoder that wrote it once for the
            // whole registry rather than once per entry, or that wrote only
            // its length, or that sorted it, passes that case and fails these.
            ("probed agent value", |_, _, agents| agents[1].push('!')),
            ("probed agent count", |_, _, agents| {
                agents.push("gemini".to_owned());
            }),
            ("probed agent order", |_, _, agents| agents.swap(0, 1)),
            ("probed agents absent", |_, _, agents| agents.clear()),
        ];

        // Against the baseline computed here, not against the frozen vector: a
        // field dropped from the canonical serialization moves the baseline
        // too, and comparing to a stale constant would let every case pass
        // while proving nothing about coverage.
        let baseline = registry_of(&sample_plan()).digest();
        let mut digests: BTreeSet<String> = BTreeSet::new();
        digests.insert(baseline.clone());
        for (label, mutate) in cases {
            let mut plan = sample_plan();
            let mut started = started_for(&plan);
            let mut agents = sample_agents();
            mutate(&mut plan, &mut started, &mut agents);
            let digest = TaskRegistry::originals_with_agents(&plan, &started, &agents)
                .unwrap_or_else(|error| panic!("the {label} case must still build: {error}"))
                .digest();
            assert_ne!(
                digest, baseline,
                "changing the {label} left the digest where it was, so the digest does not \
                 authenticate it"
            );
            assert!(
                digests.insert(digest),
                "the {label} case collided with another mutation's digest"
            );
        }
        assert_eq!(digests.len(), cases.len() + 1);
    }

    #[test]
    fn changing_one_entry_field_alone_changes_the_canonical_bytes() {
        // What the table above cannot reach. Its mutations move a `Plan` or a
        // `RunStarted`, and one such edit moves every entry field derived from
        // it at once — so a field the encoder wrote as a constant would hide
        // behind a correlated field that really did move. `effort.small` is the
        // worked example: the sample resolves it to `low`, so an encoder that
        // wrote the literal `low` there leaves the frozen vector and every
        // plan-level case exactly where they are.
        //
        // Here the registry is built normally and then exactly one field of one
        // already-built entry is written, so nothing else can move with it. A
        // case that leaves the bytes alone names a field the digest does not
        // authenticate; two cases that reach the same bytes name a pair of
        // records a single recorded digest would accept both of.
        //
        // The entry moved is `mid`, the sample's third and last. It is the only
        // one with more than one dependency, which is what lets the order of a
        // dependency list be moved without its contents — and each list moved
        // apart from the other, rather than the pair of them together, since an
        // encoder that sorted one is invisible while the other supplies the
        // difference.
        const MOVED: usize = 2;
        let cases: [(&str, MoveField); 64] = [
            ("key", |entry| entry.key = TaskKey(7)),
            ("display id", |entry| {
                entry.display_id = TaskId::from("zeta-renamed");
            }),
            ("origin", |entry| entry.origin = Origin::MergeRepair),
            ("lineage present", |entry| {
                entry.lineage = Some(Lineage {
                    root: TaskKey(1),
                    parent: TaskKey(2),
                    index: 4,
                });
            }),
            ("lineage root", |entry| {
                entry.lineage = Some(Lineage {
                    root: TaskKey(2),
                    parent: TaskKey(2),
                    index: 4,
                });
            }),
            ("lineage parent", |entry| {
                entry.lineage = Some(Lineage {
                    root: TaskKey(1),
                    parent: TaskKey(0),
                    index: 4,
                });
            }),
            ("lineage index", |entry| {
                entry.lineage = Some(Lineage {
                    root: TaskKey(1),
                    parent: TaskKey(2),
                    index: 5,
                });
            }),
            ("kind", |entry| entry.spec.kind = TaskKind::Docs),
            ("title", |entry| entry.spec.title.push('!')),
            ("body", |entry| entry.spec.body.push('!')),
            ("acceptance value", |entry| {
                entry.spec.acceptance[0].push('!')
            }),
            ("acceptance count", |entry| {
                entry.spec.acceptance.push("more".to_owned());
            }),
            ("acceptance order", |entry| entry.spec.acceptance.swap(0, 1)),
            ("path hint value", |entry| {
                entry.spec.path_hints[0].push('!')
            }),
            ("path hint count", |entry| {
                entry.spec.path_hints.push("src/extra.rs".to_owned());
            }),
            ("path hint order", |entry| entry.spec.path_hints.swap(0, 1)),
            ("suggested tier", |entry| {
                entry.spec.suggested_tier = Some(Tier::Frontier);
            }),
            ("suggested tier absent", |entry| {
                entry.spec.suggested_tier = None;
            }),
            ("min tier", |entry| entry.spec.min_tier = Some(Tier::Mid)),
            ("min tier absent", |entry| entry.spec.min_tier = None),
            ("artifacts in", |entry| {
                entry.spec.artifacts_in.push(ArtifactId::from("extra"));
            }),
            ("artifacts out", |entry| {
                entry.spec.artifacts_out.push(ArtifactId::from("extra"));
            }),
            ("dependency key", |entry| entry.deps[0] = TaskKey(2)),
            ("dependency count", |entry| entry.deps.push(TaskKey(2))),
            // The two order cases are the pair that matters. Each moves one
            // dependency representation and leaves the other exactly as it
            // was, so an encoder that sorted `deps`, or one that sorted
            // `display_deps`, changes bytes here that the untouched
            // representation cannot account for.
            ("dependency key order", |entry| entry.deps.swap(0, 1)),
            ("display dependency", |entry| {
                entry.display_deps[0] = TaskId::from("mid");
            }),
            ("display dependency count", |entry| {
                entry.display_deps.push(TaskId::from("mid"));
            }),
            ("display dependency order", |entry| {
                entry.display_deps.swap(0, 1);
            }),
            ("ladder tier", |entry| {
                entry.ladder.tiers[1] = Tier::Frontier;
            }),
            ("ladder tier count", |entry| {
                entry.ladder.tiers.push(Tier::Frontier);
            }),
            // Escalation order is ascending in every fixture here, because that
            // is what an escalation ladder is. Sorting it is therefore a
            // no-op on real input and undetectable from values alone.
            ("ladder tier order", |entry| entry.ladder.tiers.swap(0, 1)),
            ("attempts per rung", |entry| entry.ladder.attempts_per = 3),
            ("rung tier", |entry| {
                entry.ladder.rungs[0].tier = Tier::Frontier;
            }),
            ("rung agent", |entry| {
                entry.ladder.rungs[0].agent = "copilot".to_owned();
            }),
            ("rung model", |entry| {
                entry.ladder.rungs[0].model = "claude-sonnet-5".to_owned();
            }),
            ("rung pin", |entry| entry.ladder.rungs[0].pinned = true),
            ("rung count", |entry| {
                entry.ladder.rungs.push(FrozenRung {
                    tier: Tier::Frontier,
                    agent: "codex".to_owned(),
                    model: "gpt-5.6-sol".to_owned(),
                    pinned: true,
                });
            }),
            // Rung order runs in lockstep with tier order in every fixture, so
            // it needs moving on its own for the same reason the tiers do.
            ("rung order", |entry| entry.ladder.rungs.swap(0, 1)),
            ("ladder floor", |entry| entry.ladder.floor = Some(Tier::Mid)),
            ("ladder floor absent", |entry| entry.ladder.floor = None),
            ("ladder ceiling", |entry| {
                entry.ladder.ceiling = Some(Tier::Frontier);
            }),
            ("ladder ceiling absent", |entry| entry.ladder.ceiling = None),
            ("effort small", |entry| {
                entry.ladder.effort.small = Effort::High;
            }),
            ("effort mid", |entry| entry.ladder.effort.mid = Effort::Max),
            ("effort frontier", |entry| {
                entry.ladder.effort.frontier = Effort::Low;
            }),
            ("effort review", |entry| {
                entry.ladder.effort.review = Effort::Max;
            }),
            ("admission", |entry| {
                entry.ladder.admission = Admission::HumanBinding {
                    options: Vec::new(),
                };
            }),
            ("admission options", |entry| {
                entry.ladder.admission = Admission::HumanBinding {
                    options: vec!["small/claude-haiku-4-5".to_owned()],
                };
            }),
            ("reviews enabled", |entry| entry.reviews.enabled = false),
            ("reviews alternative available", |entry| {
                entry.reviews.alternative_available = false;
            }),
            ("review pass timeout", |entry| {
                entry.reviews.pass_timeout_secs = 60;
            }),
            ("primary reviewer agent", |entry| {
                entry.reviews.primary = Some(PassBinding::new("copilot", "claude-opus-5"));
            }),
            ("primary reviewer model", |entry| {
                entry.reviews.primary = Some(PassBinding::new("claude-code", "gpt-5.6"));
            }),
            ("primary reviewer absent", |entry| {
                entry.reviews.primary = None;
            }),
            ("alternative reviewer agent", |entry| {
                entry.reviews.alternative = Some(PassBinding::new("claude-code", "gpt-5.6"));
            }),
            ("alternative reviewer model", |entry| {
                entry.reviews.alternative = Some(PassBinding::new("copilot", "gpt-5.6-sol"));
            }),
            ("alternative reviewer absent", |entry| {
                entry.reviews.alternative = None;
            }),
            ("second opinion present", |entry| {
                entry.reviews.second_opinion = Some(PassBinding::new("copilot", "gpt-5.6"));
            }),
            ("second opinion agent", |entry| {
                entry.reviews.second_opinion = Some(PassBinding::new("claude-code", "gpt-5.6"));
            }),
            ("second opinion model", |entry| {
                entry.reviews.second_opinion = Some(PassBinding::new("copilot", "claude-opus-5"));
            }),
            // The allow-list is the one entry field every entry holds the same
            // value of, so it is the field an encoder is most likely to write
            // once for the whole registry — or to leave out, since no
            // plan-level mutation moves it alone. Moved here on one entry only,
            // with the entries either side of it asserted unchanged, all four
            // shortcuts are visible: a registry-level write leaves these bytes
            // where they were, and so does no write at all.
            ("allowed agent value", |entry| {
                entry.allowed_agents[1].push('!');
            }),
            ("allowed agent count", |entry| {
                entry.allowed_agents.push("gemini".to_owned());
            }),
            ("allowed agent order", |entry| {
                entry.allowed_agents.swap(0, 1);
            }),
            ("allowed agents absent", |entry| {
                entry.allowed_agents.clear();
            }),
        ];

        let baseline = registry_of(&sample_plan());
        let baseline_bytes = baseline.canonical_bytes();
        let mut encodings: BTreeSet<Vec<u8>> = BTreeSet::new();
        encodings.insert(baseline_bytes.clone());
        for (label, mutate) in cases {
            let mut registry = registry_of(&sample_plan());
            mutate(&mut registry.entries[MOVED]);

            assert_ne!(
                registry.entries[MOVED], baseline.entries[MOVED],
                "the {label} case left the entry as it found it, so it tests nothing"
            );
            // The isolation the case claims: one field of one entry moved, and
            // the entries either side of it are byte-for-byte what they were.
            assert_eq!(
                registry.entries[..MOVED],
                baseline.entries[..MOVED],
                "{label}"
            );
            assert_eq!(
                registry.entries[MOVED + 1..],
                baseline.entries[MOVED + 1..],
                "{label}"
            );

            let bytes = registry.canonical_bytes();
            assert_ne!(
                bytes, baseline_bytes,
                "changing the {label} alone left the canonical bytes where they were, so the \
                 digest does not authenticate it"
            );
            assert_ne!(registry.digest(), baseline.digest(), "{label}");
            assert!(
                encodings.insert(bytes),
                "the {label} case encodes to bytes another case already reached"
            );
        }
        assert_eq!(encodings.len(), cases.len() + 1);
    }

    #[test]
    fn the_canonical_encoding_cannot_shift_text_between_adjacent_fields() {
        /// The sample plan with one task's adjacent title and body replaced.
        fn adjacent(title: &str, body: &str) -> Plan {
            let mut plan = sample_plan();
            plan.tasks[0].title = title.to_owned();
            plan.tasks[0].body = body.to_owned();
            plan
        }

        // Each row is one run of text split two ways across an adjacent pair.
        // The first is benign — `ab`/`c` against `a`/`bc` produces different
        // bytes under *delimiter-only* framing (`value;`) as well, so on its own
        // it witnesses nothing about the length prefix and would keep passing if
        // the prefix were dropped. The rest are hostile: the text they shift
        // across the boundary is the framing punctuation itself, so under
        // `value;` framing the two sides of each pair are the same bytes and
        // one recorded digest would authenticate both records.
        for [left_title, left_body, right_title, right_body] in [
            // Benign, kept for the plain case.
            ["ab", "c", "a", "bc"],
            // The value terminator moved across the boundary.
            ["a;", "b", "a", ";b"],
            // The same, in text where a byte length and a character count
            // disagree: `é` is one character and two bytes.
            ["é;", "b", "é", ";b"],
            // The length/value separator, for a framing that kept `:` instead.
            ["a:", "b", "a", ":b"],
            // Punctuation-dense: both delimiters and a digit run that reads
            // like a prefix of its own.
            ["x2:;", "y", "x", "2:;y"],
        ] {
            assert_eq!(
                format!("{left_title}{left_body}"),
                format!("{right_title}{right_body}"),
                "the pair must be one run of text split two ways, or it proves nothing"
            );
            let left = registry_of(&adjacent(left_title, left_body));
            let right = registry_of(&adjacent(right_title, right_body));
            assert_ne!(
                left.canonical_bytes(),
                right.canonical_bytes(),
                "`{left_title}`/`{left_body}` and `{right_title}`/`{right_body}` encode alike, so \
                 text can be shifted between adjacent fields"
            );
            assert_ne!(left.digest(), right.digest());
        }

        // And the prefix is the value's length in bytes, not in characters: a
        // character count would frame the two-byte `é` as `1:`.
        let bytes = registry_of(&adjacent("é", "b")).canonical_bytes();
        assert!(
            bytes.windows(5).any(|window| window == "2:é;".as_bytes()),
            "the length prefix counts bytes"
        );
    }

    // -----------------------------------------------------------------------
    // Legacy projection parity
    // -----------------------------------------------------------------------

    /// The plan a registry projects back to, in the frozen plan's own envelope.
    fn round_tripped(plan: &Plan) -> Plan {
        Plan {
            source: plan.source.clone(),
            tasks: registry_of(plan).legacy_tasks(),
            artifacts: plan.artifacts.clone(),
        }
    }

    /// Exactly what `plan.normalized.json` holds
    /// (`engine::preflight::normalized_plan_bytes`).
    fn normalized_bytes(plan: &Plan) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(plan).expect("serialize plan");
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn the_registry_round_trips_the_frozen_plan_byte_for_byte() {
        // Real plans first: whatever the parser produces, including fields no
        // hand-written fixture would think to set.
        for fixture in [
            "fixtures/sample-plan.md",
            "fixtures/bare-plan.md",
            "fixtures/steps-plan.md",
        ] {
            let raw = std::fs::read_to_string(fixture).expect("fixture plan");
            let plan = crate::plan::detect(&raw)
                .expect("a markdown plan")
                .parse(&raw)
                .expect("parses");
            assert!(!plan.tasks.is_empty(), "{fixture} has tasks");
            assert_eq!(
                normalized_bytes(&round_tripped(&plan)),
                normalized_bytes(&plan),
                "{fixture} did not survive the registry byte-for-byte"
            );
        }

        // Then the shapes a fixture plan does not reach: no dependencies, no
        // annotations, empty strings, every list empty.
        let bare = plan_of(vec![Task {
            id: TaskId::from("solo"),
            kind: TaskKind::Chore,
            title: String::new(),
            body: String::new(),
            depends_on: Vec::new(),
            acceptance: Vec::new(),
            path_hints: Vec::new(),
            suggested_tier: None,
            min_tier: None,
            artifacts_in: Vec::new(),
            artifacts_out: Vec::new(),
        }]);
        // The last of these is the wide dependency list: `depends_on` survives
        // as written, so a registry that ordered it on the way in writes a
        // `plan.normalized.json` the frozen one does not match.
        for plan in [sample_plan(), bare, dependency_order_plan()] {
            assert_eq!(
                normalized_bytes(&round_tripped(&plan)),
                normalized_bytes(&plan)
            );
        }
    }

    /// A log with a committed task, an escalation, and an interrupted attempt,
    /// so the projections under test have something to project.
    fn event_log(started: &RunStarted) -> Vec<Event> {
        fn at(seconds: u32) -> String {
            format!("2026-08-01T00:00:{seconds:02}.000Z")
        }
        fn model_for(tier: &str) -> String {
            if tier == "small" {
                "claude-haiku-4-5".to_owned()
            } else {
                "gpt-5.6-sol".to_owned()
            }
        }
        fn record(attempt: u32, tier: &str, failure: Option<FailureRecord>) -> Box<AttemptRecord> {
            Box::new(AttemptRecord {
                attempt,
                tier: tier.to_owned(),
                model: model_for(tier),
                pool: Some("claude-max".to_owned()),
                resumed: false,
                duration: Duration::from_secs(7),
                cost_usd: Some(0.25),
                reviews: Vec::new(),
                session_id: None,
                usage: None,
                failure,
            })
        }
        fn start(tier: &str) -> AttemptStarted {
            AttemptStarted {
                tier: tier.to_owned(),
                agent: "claude-code".to_owned(),
                model: model_for(tier),
                adapter: Some("claude-code".to_owned()),
                preflight_cli_version: Some("1.2.3".to_owned()),
                effort: Some(Effort::Low),
                selection_origin: None,
                pool: Some("claude-max".to_owned()),
                resume_session: None,
            }
        }
        fn event(ts: String, body: EventBody) -> Event {
            Event { ts, body }
        }

        vec![
            event(
                at(0),
                EventBody::RunStarted {
                    data: Box::new(started.clone()),
                },
            ),
            event(
                at(1),
                EventBody::AttemptStarted {
                    task: "alpha".to_owned(),
                    attempt: 1,
                    rung: 0,
                    profile: "small-worker".to_owned(),
                    data: start("small"),
                },
            ),
            event(
                at(2),
                EventBody::AttemptFinished {
                    task: "alpha".to_owned(),
                    attempt: 1,
                    rung: 0,
                    profile: "small-worker".to_owned(),
                    data: record(1, "small", None),
                    parking: None,
                    transition: None,
                    prepared_commit: None,
                },
            ),
            event(
                at(3),
                EventBody::TaskCommitted {
                    task: "alpha".to_owned(),
                    data: TaskCommitted {
                        sha: "b".repeat(40),
                        message: "[tactus] alpha: alpha title".to_owned(),
                    },
                },
            ),
            event(
                at(4),
                EventBody::AttemptStarted {
                    task: "zeta".to_owned(),
                    attempt: 1,
                    rung: 0,
                    profile: "small-worker".to_owned(),
                    data: start("small"),
                },
            ),
            event(
                at(5),
                EventBody::AttemptFinished {
                    task: "zeta".to_owned(),
                    attempt: 1,
                    rung: 0,
                    profile: "small-worker".to_owned(),
                    data: record(
                        1,
                        "small",
                        Some(FailureRecord {
                            kind: FailureKind::GateFailed,
                            origin: FailureOrigin::Worker,
                            reason: "gate `check` failed".to_owned(),
                        }),
                    ),
                    parking: None,
                    transition: Some(Box::new(AttemptTransition::Escalate(LadderEscalated {
                        to_rung: 1,
                        tier: "small".to_owned(),
                        summary: "escalate".to_owned(),
                        detail: None,
                    }))),
                    prepared_commit: None,
                },
            ),
            event(
                at(6),
                EventBody::AttemptStarted {
                    task: "zeta".to_owned(),
                    attempt: 2,
                    rung: 1,
                    profile: "mid-worker".to_owned(),
                    data: start("mid"),
                },
            ),
            event(
                at(7),
                EventBody::AttemptInterrupted {
                    task: "zeta".to_owned(),
                    attempt: 2,
                    rung: 1,
                    profile: "mid-worker".to_owned(),
                    data: record(
                        2,
                        "mid",
                        Some(FailureRecord {
                            kind: FailureKind::Interrupted,
                            origin: FailureOrigin::Worker,
                            reason: "the engine died mid-attempt".to_owned(),
                        }),
                    ),
                },
            ),
            event(
                at(8),
                EventBody::RunFinished {
                    data: RunFinished {
                        outcome: RunOutcome::Parked,
                        halted_at: None,
                        committed: 1,
                        parked: 0,
                    },
                },
            ),
        ]
    }

    fn replayed(plan: &Plan, log: &[Event]) -> crate::events::RunState {
        crate::events::replay(
            log.to_vec(),
            plan.tasks.iter().map(|t| t.id.to_string()).collect(),
            Path::new("events.jsonl"),
        )
        .expect("the fixture log replays")
        .state
    }

    #[test]
    fn the_report_and_status_projections_are_byte_identical_through_the_registry() {
        let plan = projection_plan();
        let rebuilt = round_tripped(&plan);
        let started = started_for(&plan);
        let log = event_log(&started);

        let build = |plan: &Plan| {
            crate::engine::RunReport::from_state(
                &started,
                plan,
                &replayed(plan, &log),
                vec!["a warning".to_owned()],
                false,
                true,
            )
        };
        let from_plan = build(&plan);
        let from_registry = build(&rebuilt);

        assert_eq!(
            serde_json::to_vec_pretty(&from_registry).expect("serialize report"),
            serde_json::to_vec_pretty(&from_plan).expect("serialize report"),
            "report.json is written from exactly these bytes"
        );
        let rendered = |report: &crate::engine::RunReport| {
            let mut out = report.render();
            out.push_str(&report.render_ledger());
            out
        };
        assert_eq!(rendered(&from_registry), rendered(&from_plan));
        // The projection has to be worth comparing: an empty report, or one
        // whose task order carried no information, would satisfy any of the
        // above. Tasks that ran come first in the order they ran, and the three
        // that never ran follow in plan order — which is not display-id order.
        assert_eq!(
            from_plan
                .tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta", "mid", "beta", "gamma"]
        );
        assert!(from_plan.total_cost_usd > 0.0);
        assert!(
            rendered(&from_plan).contains("alpha title"),
            "a committed task's title reaches the rendered view"
        );
        let json =
            String::from_utf8(serde_json::to_vec_pretty(&from_plan).expect("serialize report"))
                .expect("utf-8 report");
        for title in [
            "zeta title",
            "alpha title",
            "mid title",
            "beta title",
            "gamma title",
        ] {
            assert!(
                json.contains(title),
                "`{title}` is part of what the byte comparison covers"
            );
        }
    }

    /// A run directory holding one frozen plan and one log, removed on drop.
    ///
    /// Every effect here goes through a funnel that takes a site — the run
    /// directory through `RunDir.CreatePublicDir`, the frozen plan through
    /// `RunDir.WritePlan`, the log through `Event.LegacyOpenLog` and
    /// `Event.LegacyAppend`, the teardown through `RunDir.RemovePublicHusk`.
    /// It has to: `decisions.effect_site_inventory.mechanism` (2) puts a raw
    /// `fs` call in a **topology** module beyond reach of every allow the
    /// allowlist can grant, because the legacy section "never contains a
    /// topology module (src/topology/**, …)" and the funnel section's clause is
    /// about performing effects inside site-taking APIs. PR5 lane D turned the
    /// denial on; this is what it demanded, and nothing about what the test
    /// below proves has changed.
    struct RunFixture {
        root: PathBuf,
        public: PathBuf,
    }

    impl RunFixture {
        /// One run directory: the plan, and a log written once.
        ///
        /// The plan is rewritten in place by [`Self::reproject`] rather than a
        /// second fixture being built beside this one, because the log would
        /// then be appended twice and `EventLog::append` stamps the wall clock —
        /// two logs, two sets of timestamps, and `Row::run_started_at` carries
        /// them into the export. One log, one set of timestamps, and the only
        /// thing that differs between the two projections is the plan, which is
        /// exactly the claim.
        fn new(tag: &str, plan: &Plan, log: &[Event]) -> Self {
            let root =
                std::env::temp_dir().join(format!("tactus-registry-{tag}-{}", std::process::id()));
            let public = crate::rundir::public_dir(&root, RUN_ID);
            let hooks = &mut crate::rundir::NoHooks;
            crate::rundir::create_public_dir(&public, hooks).expect("run directory");
            crate::rundir::write_plan(&public, &normalized_bytes(plan), hooks)
                .expect("frozen plan");
            let mut warnings = Vec::new();
            let mut writer = crate::events::EventLog::open(
                crate::topology::effects::EventSite::LegacyOpenLog,
                &public.join("events.jsonl"),
                &mut warnings,
            )
            .expect("event log");
            assert!(warnings.is_empty(), "{warnings:?}");
            for event in log {
                writer
                    .append(
                        crate::topology::effects::EventSite::LegacyAppend,
                        event.body.clone(),
                    )
                    .expect("append");
            }
            Self { root, public }
        }

        /// Replace the frozen plan, leaving the log alone.
        fn reproject(&self, plan: &Plan) {
            crate::rundir::write_plan(
                &self.public,
                &normalized_bytes(plan),
                &mut crate::rundir::NoHooks,
            )
            .expect("frozen plan");
        }

        fn exported(&self, format: crate::export::Format) -> Vec<u8> {
            let loaded = crate::export::load(&self.root, RUN_ID).expect("export loads");
            let mut out = Vec::new();
            crate::export::write(&loaded.rows, format, &mut out).expect("export writes");
            out
        }
    }

    impl Drop for RunFixture {
        fn drop(&mut self) {
            let _ = crate::rundir::remove_public_husk(&self.public, &mut crate::rundir::NoHooks);
        }
    }

    #[test]
    fn the_export_projection_is_byte_identical_through_the_registry() {
        let plan = projection_plan();
        let rebuilt = round_tripped(&plan);
        let log = event_log(&started_for(&plan));

        let run = RunFixture::new("projection", &plan, &log);

        for format in [crate::export::Format::Jsonl, crate::export::Format::Csv] {
            run.reproject(&plan);
            let expected = run.exported(format);
            run.reproject(&rebuilt);
            assert_eq!(
                run.exported(format),
                expected,
                "the export projection moved"
            );
            // The comparison has to be over real rows.
            let text = String::from_utf8(expected).expect("utf-8 export");
            assert!(text.contains("zeta") && text.contains("alpha"), "{text}");
            assert!(text.len() > 512, "{text}");
        }
    }
}
