//! What a schema-4 run records: the complete parallel-topology vocabulary.
//!
//! This module is the *shape* of the topology log and nothing else. Which
//! transitions are legal, and what state each one produces, is the checked
//! fold's — it shares this vocabulary and arrives beside it. Keeping the two
//! apart is not tidiness: the fold is the thing a live run and a replay must
//! reach identically (INV-02), and it can only be one function over one set of
//! types if those types exist without it.
//!
//! # What changed from schemas 1–3
//!
//! **Identity is stored once.** Legacy events hoist `task`, `attempt`, `rung`
//! and `profile` beside the tag so the raw file is greppable, and pay for it
//! with a class of refusal that exists purely to catch an envelope disagreeing
//! with its own payload. Schema 4 records identity in the payload only, and
//! restores the routing question as a total function over the vocabulary
//! ([`TopologyEventBody::key`], [`TopologyEventBody::sequence`]). A hoisted
//! field that contradicts the record it sits on is not refused here; it is
//! unrepresentable.
//!
//! **Tasks are addressed by [`TaskKey`], not by display id.** A run that
//! spawns repair tasks has ids nobody wrote in the plan, so every relation —
//! dependencies, leases, queue positions, questions, overrides — is keyed on
//! the dense index the registry assigned.
//!
//! **The run has an execution identity beyond its plan.** [`RunnerPolicy`] is
//! resolved once, before the worktree lock, and recorded in `run_started`;
//! every later incarnation rebuilds it and records in `run_resumed` what it
//! established, which must equal the original exactly (INV-23). That is why
//! [`RunnerPolicy::difference`] names *which* field moved rather than
//! returning a bool: an operator whose container reference now points at a
//! rebuilt image needs to be told that, not told "runner mismatch".
//!
//! **Nothing here is optional-for-legacy.** Schemas 1–3 carry `Option` fields
//! whose `None` means "a log written before this record existed", because they
//! grew. Schema 4 has no ancestors — there is no upgrade into it
//! ([`crate::topology::schema::check_upgrade_transition`]) — so every `Option`
//! in this module is a real choice a writer made, and every absent field is a
//! refusal rather than a default.
//!
//! # Unknown fields
//!
//! Every payload defined here denies unknown fields, **recursively**: a
//! transaction carrying something this binary does not understand is a
//! transaction it cannot claim to have applied, and a refusal that stopped at
//! the top of `data` would only be skin deep. So the rule holds at the
//! envelope (`ts`, `event`, `data` and nothing else), at each payload, at every
//! nested struct, and at every data-carrying variant of every nested enum.
//!
//! Informational events ([`TopologyEventBody::CapacitySnapshot`] and its
//! neighbours) stay lenient *inside their payload*, because ignoring an extra
//! column in a record nothing folds on costs nothing.
//!
//! Records reused from schemas 1–3 ([`AttemptRecord`], the review plan, the
//! frozen registry entry) keep the leniency they have always had **when a
//! schema-1..3 log is read**: tightening their own types would change how a
//! legacy log reads, which this slice must not do. Inside a schema-4
//! transaction they are decoded through the `strict` door instead — the same
//! type, reached through a stricter decoder — because `refusals[24]` names the
//! payload, not the type, and grants no legacy-nested exception.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::events::{
    AttemptRecord, BudgetKind, CapacitySnapshot, ChainSummary, DesignDefect, GateSummary,
    PoolExhausted, ReviewRecord, RunOutcome, RunStarted,
};
use crate::ir::{Effort, QuestionId, QuestionKind, ResolvedEffortPolicy, Tier};
use crate::review::ReviewPlan;
use crate::topology::paths::{PathPolicy, PathSet};
use crate::topology::registry::{FrozenRung, TaskEntry, TaskKey};
use crate::topology::schema::TOPOLOGY_SCHEMA;

pub(crate) mod strict {
    //! Schema-4 strictness for records schemas 1–3 also read.
    //!
    //! `refusals[24]` refuses an unknown field in a topology transaction
    //! payload, and a payload embeds records the legacy schemas defined. Those
    //! types cannot gain `deny_unknown_fields` of their own — that would change
    //! how a schema-1..3 log reads, and the legacy-unchanged invariant is about
    //! the *decoder a legacy log gets*, not about which fields schema 4 accepts.
    //! So the strictness is attached to the schema-4 field with
    //! `#[serde(deserialize_with = ...)]`, leaving both the embedded type and
    //! every legacy call site untouched.
    //!
    //! The check is a *witness comparison*: decode the record, encode it again,
    //! and report any key the input carried that the record did not claim back.
    //! That is exact whenever the embedded type serializes every field it
    //! deserializes — true of every record schema 4 embeds, none of which uses
    //! `skip_serializing_if` (pinned by
    //! `a_known_null_survives_the_strict_door_and_an_unknown_null_does_not`).
    //! It is deliberately not a hand-copied field list: a list would be a second
    //! declaration of the same shape, and the two would drift.

    use serde::de::{DeserializeOwned, Deserializer};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    /// Collect every path in `input` that `echo` did not claim back.
    fn unclaimed(input: &Value, echo: &Value, at: &str, found: &mut Vec<String>) {
        match (input, echo) {
            (Value::Object(supplied), Value::Object(claimed)) => {
                for (key, value) in supplied {
                    let path = if at.is_empty() {
                        key.clone()
                    } else {
                        format!("{at}.{key}")
                    };
                    match claimed.get(key) {
                        Some(mirror) => unclaimed(value, mirror, &path, found),
                        None => found.push(path),
                    }
                }
            }
            (Value::Array(supplied), Value::Array(claimed)) => {
                for (index, (value, mirror)) in supplied.iter().zip(claimed).enumerate() {
                    unclaimed(value, mirror, &format!("{at}[{index}]"), found);
                }
            }
            _ => {}
        }
    }

    /// Decode `T`, refusing any field it does not claim.
    fn checked<E, T>(input: Value) -> Result<T, E>
    where
        E: serde::de::Error,
        T: DeserializeOwned + Serialize,
    {
        let record: T = serde_json::from_value(input.clone()).map_err(E::custom)?;
        let echo = serde_json::to_value(&record).map_err(E::custom)?;
        let mut found = Vec::new();
        unclaimed(&input, &echo, "", &mut found);
        match found.first() {
            Some(path) => Err(E::custom(format!(
                "unknown field `{path}` in a record embedded in a schema-4 transaction payload"
            ))),
            None => Ok(record),
        }
    }

    /// A single embedded record.
    ///
    /// # Errors
    ///
    /// Whatever `T` refuses, plus any field of the input `T` does not claim.
    pub(crate) fn field<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned + Serialize,
    {
        checked(Value::deserialize(deserializer)?)
    }

    /// An embedded record behind a `Box`.
    ///
    /// # Errors
    ///
    /// As [`field`].
    pub(crate) fn boxed<'de, D, T>(deserializer: D) -> Result<Box<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned + Serialize,
    {
        checked(Value::deserialize(deserializer)?).map(Box::new)
    }

    /// A list of embedded records.
    ///
    /// # Errors
    ///
    /// As [`field`], for any element.
    pub(crate) fn list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned + Serialize,
    {
        checked(Value::deserialize(deserializer)?)
    }

    /// An embedded record a writer may have recorded as absent.
    ///
    /// # Errors
    ///
    /// As [`field`], when one is present.
    pub(crate) fn optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned + Serialize,
    {
        checked(Value::deserialize(deserializer)?)
    }

    /// An optional field whose *key* is still required.
    ///
    /// Serde reads a missing `Option` field as `None`, which is the right
    /// default for schemas that grew — an absent key there means "written
    /// before this field existed". Schema 4 has no ancestors, so an absent key
    /// means only that the record is incomplete, and `None` is a choice a
    /// writer made and wrote down as `null`. Naming a `deserialize_with` is
    /// what makes serde treat the missing case as `missing_field` instead.
    ///
    /// # Errors
    ///
    /// Whatever `T` refuses. The absent-key refusal is serde's, not this
    /// function's: it is never called for a key that is not there.
    pub(crate) fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::deserialize(deserializer)
    }
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// Which attempt-carrying generation of a task this is: a worktree, a base
/// commit, and a lease. Dense from 0 per task.
///
/// A task gets a new generation when it is dispatched again from a fresh
/// worktree, and keeps the one it has across a same-session retry — which is
/// exactly the distinction the retry rule turns on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct GenerationId(pub u32);

/// Which attempt within a generation. Dense from 1, as the ladder counts them.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct AttemptNumber(pub u32);

/// Which integration transaction. Dense from 0 across the whole run, so a
/// re-verification after an interruption is a new sequence rather than a
/// second use of an old one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct SequenceId(pub u32);

/// Which coordinator process is driving the run: a ULID minted per process.
///
/// Not the resume count. Two incarnations can share an epoch only if the run
/// lock failed, which it cannot, but a container name, an intent path, and a
/// retained session all have to be attributable to the exact process that
/// created them, and "the third resume" does not identify a process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IncarnationId(pub String);

impl fmt::Display for IncarnationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How many times the run has been picked up again. The scope a budget stop
/// lives in: `budget_exceeded` sets it, `run_resumed` clears it by starting a
/// new one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct Epoch(pub u32);

/// An agent CLI conversation an attempt may resume (§11.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A full commit sha. Full, never abbreviated: `--short` length varies with
/// `core.abbrev`, and every relation in the merge queue is an equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitSha(pub String);

impl CommitSha {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for CommitSha {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A full ref name (`refs/...`). Distinct from [`CommitSha`] so that a
/// relation between a ref and a sha cannot be written by accident.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GitRef(pub String);

impl GitRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for GitRef {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for GitRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One candidate commit, named by the task and generation that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRef {
    pub key: TaskKey,
    pub generation: GenerationId,
    /// The immutable commit the gates and reviewers judged.
    pub commit_sha: CommitSha,
    /// `refs/tactus/runs/<id>/candidates/<key>/<gen>` — the authoritative ref
    /// that keeps it reachable and is the protected source a repair is
    /// materialized from.
    pub candidate_ref: GitRef,
}

// ---------------------------------------------------------------------------
// Runner identity (INV-23)
// ---------------------------------------------------------------------------

/// Where a run's processes execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerKind {
    Host,
    Container,
}

/// The mount, environment, Git-view and supervision contract the binary
/// implements for a [`RunnerKind`].
///
/// Versioned separately from the kind because the contract can change while
/// the kind does not, and a run resumed by a binary implementing a different
/// contract is a run whose second half executes somewhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerContract {
    HostV1,
    ContainerV1,
}

impl RunnerContract {
    /// The kind this contract is the contract *for*.
    pub fn kind(self) -> RunnerKind {
        match self {
            Self::HostV1 => RunnerKind::Host,
            Self::ContainerV1 => RunnerKind::Container,
        }
    }
}

/// The image a container runner executes from.
///
/// Three values rather than one, because they answer three different
/// questions. The `reference` is what an operator wrote and what a registry
/// may re-point at any time; the `id` is what the runtime actually holds and
/// is what every container of the run is created from, so a moved reference
/// cannot change what executes; the `digest` is what the registry called that
/// content, when it said so at all.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageIdentity {
    pub reference: String,
    /// The runtime's immutable image id.
    pub id: String,
    /// The manifest digest, when the runtime reported one.
    #[serde(deserialize_with = "strict::required")]
    pub digest: Option<String>,
}

/// The execution identity of a schema-4 run.
///
/// Resolved once by read-only inspection before the worktree lock, digested
/// into the marker, recorded in the private owner record before the first
/// probe, and recorded here in `run_started`. Every later incarnation rebuilds
/// it from this record and records what it established in `run_resumed`, which
/// must equal this exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerPolicy {
    pub kind: RunnerKind,
    pub policy: RunnerContract,
    /// `None` for a host runner: there is no image, and recording an empty one
    /// would make "no image" and "an image nobody identified" the same record.
    #[serde(deserialize_with = "strict::required")]
    pub image: Option<ImageIdentity>,
    /// Per-agent credential volume names, for a container runner.
    ///
    /// A map rather than a list so that the *set* is what equality compares:
    /// two incarnations that enumerated the same volumes in different orders
    /// established the same runner, and refusing that would make a resume
    /// depend on iteration order.
    #[serde(deserialize_with = "strict::required")]
    pub credential_volumes: Option<BTreeMap<String, String>>,
}

/// Which part of a runner record two incarnations disagree about.
///
/// Ordered as the record is read, so the first difference reported is the
/// most structural one: a run that changed kind has not merely moved its
/// image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunnerField {
    Kind,
    Policy,
    ImagePresence,
    ImageReference,
    ImageId,
    ImageDigest,
    CredentialVolumes,
}

impl fmt::Display for RunnerField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kind => "runner kind",
            Self::Policy => "runner policy",
            Self::ImagePresence => "presence of an image record",
            Self::ImageReference => "image reference",
            Self::ImageId => "image id",
            Self::ImageDigest => "image digest",
            Self::CredentialVolumes => "credential volume set",
        })
    }
}

/// What a runner record is missing, or says inconsistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunnerRecordDefect {
    /// The contract version does not belong to the recorded kind.
    ContractDoesNotMatchKind,
    /// A container runner without an image record: nothing names what executes.
    ContainerWithoutImage,
    /// An image record whose reference or id is empty.
    ImageNotIdentified,
    /// A container runner without a credential-volume record. An empty map is
    /// a real answer — no agent needs credentials — and is not this.
    ContainerWithoutCredentialVolumes,
    /// A host runner carrying an image or volumes it cannot have used.
    HostWithContainerFields,
}

impl fmt::Display for RunnerRecordDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContractDoesNotMatchKind => {
                "the recorded policy version does not belong to the recorded runner kind"
            }
            Self::ContainerWithoutImage => {
                "a container runner without an image record: nothing names what executed"
            }
            Self::ImageNotIdentified => {
                "the image record has no reference or no runtime id, so it cannot be re-established"
            }
            Self::ContainerWithoutCredentialVolumes => {
                "a container runner without a credential-volume record (an empty set is a record)"
            }
            Self::HostWithContainerFields => {
                "a host runner carrying an image or credential volumes it could not have used"
            }
        })
    }
}

impl RunnerPolicy {
    /// Whether this record names everything needed to re-establish the runner.
    ///
    /// A shape check over the record alone — whether the runtime still *has*
    /// that image is an observation, made by the incarnation that rebuilds it.
    /// The digest is deliberately not required: it is the manifest digest when
    /// the runtime reported one, and runtimes that report none are not thereby
    /// unusable. It is still compared by [`Self::difference`], because a
    /// record that gained or lost one changed.
    ///
    /// # Errors
    ///
    /// The first [`RunnerRecordDefect`] the record exhibits.
    pub fn completeness(&self) -> Result<(), RunnerRecordDefect> {
        if self.policy.kind() != self.kind {
            return Err(RunnerRecordDefect::ContractDoesNotMatchKind);
        }
        match self.kind {
            RunnerKind::Host => {
                if self.image.is_some() || self.credential_volumes.is_some() {
                    return Err(RunnerRecordDefect::HostWithContainerFields);
                }
            }
            RunnerKind::Container => {
                let image = self
                    .image
                    .as_ref()
                    .ok_or(RunnerRecordDefect::ContainerWithoutImage)?;
                if image.reference.is_empty() || image.id.is_empty() {
                    return Err(RunnerRecordDefect::ImageNotIdentified);
                }
                if self.credential_volumes.is_none() {
                    return Err(RunnerRecordDefect::ContainerWithoutCredentialVolumes);
                }
            }
        }
        Ok(())
    }

    /// The first field in which `self` and `other` are not the same runner, or
    /// `None` when they are identical.
    ///
    /// This is the whole of the resume check: a run's boundary and image are
    /// fixed for its life, so any difference at all refuses. It names the
    /// field because the three ways this happens in practice — a config edit,
    /// a moved tag, a rebuilt image behind an unchanged tag — are indistinguishable
    /// from "runner mismatch" and have completely different fixes.
    pub fn difference(&self, other: &Self) -> Option<RunnerField> {
        if self.kind != other.kind {
            return Some(RunnerField::Kind);
        }
        if self.policy != other.policy {
            return Some(RunnerField::Policy);
        }
        match (&self.image, &other.image) {
            (Some(mine), Some(theirs)) => {
                if mine.reference != theirs.reference {
                    return Some(RunnerField::ImageReference);
                }
                if mine.id != theirs.id {
                    return Some(RunnerField::ImageId);
                }
                if mine.digest != theirs.digest {
                    return Some(RunnerField::ImageDigest);
                }
            }
            (None, None) => {}
            _ => return Some(RunnerField::ImagePresence),
        }
        if self.credential_volumes != other.credential_volumes {
            return Some(RunnerField::CredentialVolumes);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Run-level records
// ---------------------------------------------------------------------------

/// The ceilings a run froze, and every later fold reads rather than re-derives.
///
/// Budgets are not here on purpose: a ceiling on one's own spending is checked
/// against today's configuration by the loop, and a resume is allowed to raise
/// it. These three shape what the fold *permits*, which is identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyLimits {
    /// The global pipeline entitlement.
    pub max_parallel: u32,
    /// How many times one integration may be deferred by an outage before the
    /// next outage parks it for a human instead.
    pub max_defers: u32,
    /// How many automatic repairs one lineage root may consume.
    pub max_merge_repairs: u32,
}

/// `run_started` for a parallel-topology run.
///
/// Everything schemas 1–3 made optional for the sake of logs written before a
/// field existed is required here, because no schema-4 log predates any of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunStarted4 {
    /// Always [`TOPOLOGY_SCHEMA`]. First field of the first line, and the only
    /// thing a reader is entitled to look at before choosing a fold.
    pub schema: u32,
    pub tactus_version: String,
    pub run_id: String,
    /// The coordinator process that created the run.
    pub incarnation: IncarnationId,
    /// What every process of this run executes through, for its whole life.
    pub runner: RunnerPolicy,
    /// The agents pre-flight actually probed. The allow-list every task's
    /// bindings — including one a human names for a repair — is drawn from.
    pub probed_agents: Vec<String>,
    pub branch: String,
    /// The ref this run publishes onto, named rather than re-derived.
    ///
    /// Authoritative because a resume has to move the same ref the first half
    /// of the run moved: deriving it again from today's configuration would let
    /// a config edit between two incarnations publish the second half of a run
    /// somewhere else, and the CAS would succeed while doing it.
    pub integration_ref: GitRef,
    pub base_sha: CommitSha,
    /// The contained root every worktree, snapshot and staging directory of
    /// this run is created under.
    ///
    /// Recorded for the same reason `integration_ref` is, and for one more: it
    /// is the containment boundary every create, reclaim and delete is checked
    /// against, so a recovery that re-derived it from ambient configuration
    /// would be checking containment against a boundary the run never used.
    ///
    /// A string rather than a [`std::path::PathBuf`], exactly as `private_dir`
    /// and `worktree_path` are: a recorded root has to mean the same thing on
    /// the Windows machine that resumes the run as on the Linux one that wrote
    /// it, and a platform path type would make that a question about separators.
    pub execution_root: String,
    pub private_dir: String,
    pub plan_path: String,
    #[serde(deserialize_with = "strict::required")]
    pub config_path: Option<String>,
    pub plan_hash: String,
    /// Digest of the exact `plan.normalized.json` bytes.
    pub normalized_plan_digest: String,
    /// Digest of the original registry entries derived from those bytes and
    /// this record. A reader rebuilds and compares.
    pub registry_digest: String,
    pub path_policy: PathPolicy,
    pub limits: TopologyLimits,
    pub gates: Vec<String>,
    pub gates_from_config: bool,
    #[serde(deserialize_with = "strict::list")]
    pub gate_cmds: Vec<GateSummary>,
    pub interaction_mode: String,
    #[serde(deserialize_with = "strict::list")]
    pub chains: Vec<ChainSummary>,
    #[serde(deserialize_with = "strict::field")]
    pub effort_policy: ResolvedEffortPolicy,
    #[serde(deserialize_with = "strict::field")]
    pub reviews: ReviewPlan,
}

impl RunStarted4 {
    /// This record in the shape the registry derivation reads.
    ///
    /// A projection, not a second copy: the registry is derived from the
    /// frozen plan and the run record, and that derivation is the same one for
    /// both execution models. Every field here is read straight off `self`, so
    /// the two cannot drift — which matters because the digest this feeds is
    /// what authenticates a rebuilt registry against the log.
    pub fn registry_record(&self) -> RunStarted {
        RunStarted {
            schema: self.schema,
            tactus_version: self.tactus_version.clone(),
            run_id: self.run_id.clone(),
            branch: self.branch.clone(),
            base_sha: self.base_sha.0.clone(),
            plan_path: self.plan_path.clone(),
            config_path: self.config_path.clone(),
            plan_hash: self.plan_hash.clone(),
            normalized_plan_digest: Some(self.normalized_plan_digest.clone()),
            private_dir: self.private_dir.clone(),
            gates: self.gates.clone(),
            gates_from_config: self.gates_from_config,
            interaction_mode: self.interaction_mode.clone(),
            chains: self.chains.clone(),
            effort_policy: Some(self.effort_policy),
            gate_cmds: Some(self.gate_cmds.clone()),
            reviews: Some(self.reviews.clone()),
        }
    }

    /// Whether this record claims to be a topology run at all.
    pub fn is_topology_schema(&self) -> bool {
        self.schema == TOPOLOGY_SCHEMA
    }
}

/// `run_resumed` for a parallel-topology run.
///
/// Carries no re-derived configuration, unlike its legacy counterpart: there
/// is nothing for a resume to establish, because a schema-4 log never predates
/// a field. What it does carry is what this incarnation *is* and what it
/// re-established, so that a forged resume is refused on replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunResumed4 {
    pub incarnation: IncarnationId,
    /// What this incarnation rebuilt and verified. Must equal `run_started`'s
    /// exactly, field for field.
    pub runner: RunnerPolicy,
    /// What this incarnation's pre-flight probes found.
    pub probed_agents: Vec<String>,
    pub tactus_version: String,
}

/// `run_finished` for a parallel-topology run.
///
/// The outcome is not a decision this event records; it is a value derived
/// from durable state, and the event is accepted only when it equals it. What
/// the event adds is the attribution a report needs and a fold would otherwise
/// have to recompute to print.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunFinished4 {
    pub outcome: RunOutcome,
    /// The task whose settlement halted the run, when one did.
    #[serde(deserialize_with = "strict::required")]
    pub halted_at: Option<TaskKey>,
    pub merged: u32,
    pub parked: u32,
}

/// The total outcome function's result.
///
/// [`Self::NotEnding`] is not an error: it is the ordinary answer while work
/// remains, and the reason the guard is a comparison rather than a validity
/// check. [`Self::FoldError`] is the arm the design argues is unreachable, kept
/// as a value so that "unreachable" is something a census can assert rather
/// than something a `panic!` asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedOutcome {
    NotEnding,
    Ending(RunOutcome),
    FoldError,
}

/// The epoch-scoped budget stop.
///
/// Scoped to an epoch because raising the ceiling and resuming is the intended
/// response to it: the stop belongs to the epoch that hit the old ceiling, and
/// the next epoch starts without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetStop {
    pub epoch: Epoch,
    pub budget: BudgetKind,
}

/// `budget_exceeded`: the ceiling refused the next spawn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetExceeded4 {
    /// The epoch this stop belongs to. Recorded so a replay can tell that a
    /// stop was cleared by a resume rather than inferring it from position.
    pub epoch: Epoch,
    pub budget: BudgetKind,
    pub limit_usd: f64,
    /// Reported spend to date — a floor wherever a route reports no spend.
    pub spent_usd: f64,
    /// The task whose next attempt was refused. Not a failed task: nothing
    /// judged it and nothing was spent on it.
    #[serde(deserialize_with = "strict::required")]
    pub key: Option<TaskKey>,
}

impl BudgetExceeded4 {
    /// The stop this event establishes.
    pub fn stop(&self) -> BudgetStop {
        BudgetStop {
            epoch: self.epoch,
            budget: self.budget,
        }
    }
}

// ---------------------------------------------------------------------------
// Questions
// ---------------------------------------------------------------------------

/// A question keyed by the task it blocks.
///
/// Keyed rather than addressed by display id, and embedded complete in the
/// event that raises it: a question raised about a repair names a task that
/// exists only in the log, and an answer arriving three processes later has to
/// be validated against the options as they were frozen, not as they would be
/// re-derived today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenQuestion {
    pub id: QuestionId,
    pub key: TaskKey,
    pub kind: QuestionKind,
    /// Human-facing framing. Any agent-authored text inside it is quoted and
    /// labelled as such by whoever built the question.
    pub context: String,
    pub options: Vec<String>,
}

impl FrozenQuestion {
    /// Whether this question can actually be answered.
    ///
    /// An option-less question parks a task nothing can un-park, and an
    /// unidentified or context-free one cannot be presented to the human it
    /// exists for. All three are the same failure — a question that stops the
    /// run without offering a way to continue it.
    pub fn is_complete(&self) -> bool {
        !self.id.as_str().trim().is_empty()
            && !self.context.trim().is_empty()
            && !self.options.is_empty()
    }
}

/// `question_raised`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionRaised4 {
    pub question: FrozenQuestion,
}

/// A one-off binding a human named for a task whose ladder clipped to nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingOverride {
    pub key: TaskKey,
    pub question: QuestionId,
    pub option_index: u32,
    pub agent: String,
    pub model: String,
    pub effort: Effort,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case", deny_unknown_fields)]
pub enum Answer4 {
    Answered {
        option_index: u32,
        /// Present exactly when the question was asking for a binding.
        #[serde(deserialize_with = "strict::required")]
        binding_override: Option<BindingOverride>,
    },
    /// The human said no. Whether that halts the run is the run's policy as it
    /// stood when the decline became durable — recorded, not re-derived, so a
    /// config edit between a run and its resume cannot rewrite what the answer
    /// meant.
    Declined { decline_halts_run: bool },
}

/// `question_answered`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionAnswered4 {
    pub key: TaskKey,
    pub question: QuestionId,
    pub answer: Answer4,
    /// Which channel produced it — a terminal, an out-of-band `tactus answer`,
    /// or a resume picking up an answer written while the run was dead.
    pub via: String,
}

/// How an answer disagrees with itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnswerDefect {
    /// The override names a different question from the one being answered.
    OverrideNamesAnotherQuestion,
    /// The override names a different task from the one being answered.
    OverrideNamesAnotherTask,
    /// The override records a different option from the one chosen.
    OverrideNamesAnotherOption,
    /// A decline carrying a binding.
    DeclineWithOverride,
}

impl fmt::Display for AnswerDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OverrideNamesAnotherQuestion => {
                "the binding override names a different question from the one being answered"
            }
            Self::OverrideNamesAnotherTask => {
                "the binding override names a different task from the one being answered"
            }
            Self::OverrideNamesAnotherOption => {
                "the binding override records a different option from the one chosen"
            }
            Self::DeclineWithOverride => "a declined answer carries a binding override",
        })
    }
}

impl QuestionAnswered4 {
    /// Whether the answer agrees with itself.
    ///
    /// Only the relations inside one event: whether the option exists, and
    /// whether the question was open, are facts about the question this event
    /// answers and belong to the fold that holds it.
    ///
    /// # Errors
    ///
    /// The first [`AnswerDefect`] the event exhibits.
    pub fn self_consistency(&self) -> Result<(), AnswerDefect> {
        let Answer4::Answered {
            option_index,
            binding_override: Some(binding),
        } = &self.answer
        else {
            return Ok(());
        };
        if binding.question != self.question {
            return Err(AnswerDefect::OverrideNamesAnotherQuestion);
        }
        if binding.key != self.key {
            return Err(AnswerDefect::OverrideNamesAnotherTask);
        }
        if binding.option_index != *option_index {
            return Err(AnswerDefect::OverrideNamesAnotherOption);
        }
        Ok(())
    }

    /// Whether this answer is the carrier that halts the run.
    pub fn halts_run(&self) -> bool {
        matches!(
            self.answer,
            Answer4::Declined {
                decline_halts_run: true
            }
        )
    }
}

// ---------------------------------------------------------------------------
// Task registration and dispatch
// ---------------------------------------------------------------------------

/// Whether a freshly registered task may be dispatched, and what it is waiting
/// for if not.
///
/// The registry entry carries its own admission; this carries the question
/// that admission implies, which the entry has no place for. The two are
/// checked against each other by the fold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpawnAdmission {
    /// A resolved ladder with rungs; the scheduler may dispatch it.
    Runnable,
    /// The lineage has consumed its automatic repairs. Only a human admits
    /// another.
    HumanRequired {
        limit: u32,
        question: FrozenQuestion,
    },
    /// The clipped ladder is empty: there is no binding to run, and only a
    /// validated override creates one.
    HumanBinding {
        options: Vec<String>,
        question: FrozenQuestion,
    },
}

impl SpawnAdmission {
    /// The question this admission raises, where it raises one.
    pub fn question(&self) -> Option<&FrozenQuestion> {
        match self {
            Self::Runnable => None,
            Self::HumanRequired { question, .. } | Self::HumanBinding { question, .. } => {
                Some(question)
            }
        }
    }
}

/// A dynamic task, complete, in the event that registers it.
///
/// Embedded whole rather than referenced, because a dynamic entry has no
/// frozen plan behind it: the event *is* its authority, and a reader that had
/// to reconstruct it would be reconstructing it from nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenSpawn {
    /// Equal to the registry's length at this event.
    pub key: TaskKey,
    pub entry: TaskEntry,
    #[serde(deserialize_with = "strict::field")]
    pub admission: SpawnAdmission,
}

/// `task_spawned`: a task that was not in the plan joins the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpawned {
    pub spawn: FrozenSpawn,
}

/// What a dispatch does to the run's leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lease", rename_all = "snake_case", deny_unknown_fields)]
pub enum LeaseGrant {
    /// An ordinary dispatch takes a predicted lease over the region the plan's
    /// hints imply.
    Predicted {
        #[serde(deserialize_with = "strict::field")]
        paths: PathSet,
    },
    /// A repair executes inside the lineage lease its root already holds, and
    /// takes nothing of its own.
    InheritedLineage { root: TaskKey },
}

/// `task_dispatched`: a generation is opened, before its worktree exists.
///
/// Written first on purpose. A worktree created before the event that records
/// it is a directory nothing in the log accounts for; an event written before
/// a worktree that then fails to appear is a generation the next process
/// closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDispatched {
    pub key: TaskKey,
    pub generation: GenerationId,
    /// The commit the worktree is created at.
    pub base_sha: CommitSha,
    /// Recorded as the string a later process compares and re-derives, exactly
    /// as `private_dir` is. A platform path type here would make a log written
    /// on one operating system a question on another.
    pub worktree_path: String,
    pub lease: LeaseGrant,
    /// The candidate a repair is materialized from.
    #[serde(deserialize_with = "strict::required")]
    pub source_candidate: Option<CandidateRef>,
}

// ---------------------------------------------------------------------------
// Attempts
// ---------------------------------------------------------------------------

/// One rung's binding as an attempt actually used it.
///
/// Comparable against both authorities: the frozen rung the registry holds,
/// and an override a human named. The override records no tier — the option
/// list it chose from is agents, not tiers — which is why the two comparisons
/// are two methods rather than one equality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RungBinding {
    pub tier: Tier,
    pub agent: String,
    pub model: String,
    /// Whether the frozen rung this binding came from was pinned by the plan
    /// rather than resolved by the run.
    ///
    /// Part of the recorded binding because it is part of the frozen rung
    /// ([`FrozenRung`]), and INV-19 makes the frozen rung binding execution
    /// identity that `attempt_started` records. Two rungs identical in tier,
    /// agent and model but differing in provenance are two different
    /// authorities, and a recorded binding that dropped this would match both.
    pub pinned: bool,
    pub effort: Effort,
}

impl RungBinding {
    /// This binding as the frozen ladder would produce it.
    pub fn from_frozen(rung: &FrozenRung, effort: Effort) -> Self {
        Self {
            tier: rung.tier,
            agent: rung.agent.clone(),
            model: rung.model.clone(),
            pinned: rung.pinned,
            effort,
        }
    }

    /// Whether this binding is the one the frozen rung names.
    pub fn matches_frozen(&self, rung: &FrozenRung, effort: Effort) -> bool {
        *self == Self::from_frozen(rung, effort)
    }

    /// Whether this binding is the one an override names.
    ///
    /// Tier and pin are not compared: an override chooses an agent from a
    /// frozen option list, so the tier it lands on is whatever that agent is
    /// bound at, and a human-named binding has no plan pin behind it at all.
    /// [`BindingOverride`] records neither, and comparing a field the authority
    /// does not carry would refuse every valid override.
    pub fn matches_override(&self, binding: &BindingOverride) -> bool {
        self.agent == binding.agent && self.model == binding.model && self.effort == binding.effort
    }
}

/// What a repair's worktree looked like when its attempt started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Materialization {
    /// The rejected candidate applied cleanly onto the new base.
    Clean,
    /// It did not, and the conflict is the repair's subject.
    Conflict,
    /// It applied to nothing: the change is already present.
    Empty,
    /// The worktree was kept from the previous attempt and not re-materialized.
    Retained,
}

/// `attempt_started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptStarted4 {
    pub key: TaskKey,
    pub generation: GenerationId,
    pub attempt: AttemptNumber,
    /// Index into the frozen ladder.
    pub rung: u32,
    pub binding: RungBinding,
    /// The capacity pool this attempt draws on, where its agent names one.
    #[serde(deserialize_with = "strict::required")]
    pub pool: Option<String>,
    /// The session this attempt resumed. Only a generation that settled
    /// Retained, in the incarnation that retained it, has one to resume.
    #[serde(deserialize_with = "strict::required")]
    pub resume_session: Option<SessionId>,
    /// What the repair's worktree looked like when this attempt started.
    /// Present on a repair, absent otherwise.
    #[serde(deserialize_with = "strict::required")]
    pub materialization_observed: Option<Materialization>,
}

/// The non-parking state transition a settled attempt records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transition", rename_all = "snake_case", deny_unknown_fields)]
pub enum SettlementTransition {
    /// The attempt produced a tree the gates and reviewers accepted; a
    /// candidate follows.
    Succeeded,
    /// Another attempt on the same rung.
    Retry,
    /// The next rung of the ladder.
    Escalated { rung: u32 },
    /// Backoff: the task waits for `defer_wait_elapsed` or a resume.
    Deferred { defers: u32, reason: String },
    /// A human is asked.
    Parked { question: FrozenQuestion },
    /// Terminal for the task, and — where the run's policy says so — for the
    /// run.
    Failed { halts_run: bool, reason: String },
}

/// What a settlement does to the generation's lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseDisposition {
    /// The generation's own predicted lease ends with it.
    PredictedReleased,
    /// The generation keeps its predicted lease, because it keeps its worktree.
    PredictedRetained,
    /// A lineage lease, held across the settlement. The disposition a repair
    /// generation records: a lineage lease belongs to the lineage root and no
    /// attempt-level settlement releases it.
    LineageHeld,
}

/// How an attempt ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "settlement", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttemptSettlement {
    /// The generation stays alive holding a session for a same-session retry.
    ///
    /// The incarnation is recorded with the session because a session belongs
    /// to a process: after a crash the working tree is rolled back, so the
    /// conversation's belief about what it left behind is false, and only the
    /// process that retained it may resume it.
    Retained {
        retained_session: SessionId,
        retained_incarnation: Epoch,
    },
    /// The generation closes.
    Closed {
        #[serde(deserialize_with = "strict::field")]
        transition: SettlementTransition,
        lease: LeaseDisposition,
    },
}

/// `attempt_finished`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptFinished4 {
    pub key: TaskKey,
    pub generation: GenerationId,
    pub attempt: AttemptNumber,
    /// The ledger line: what it cost, what ran, what went wrong.
    #[serde(deserialize_with = "strict::boxed")]
    pub record: Box<AttemptRecord>,
    pub settlement: AttemptSettlement,
}

impl AttemptFinished4 {
    /// Whether this settlement is the carrier that halts the run.
    ///
    /// Only a terminal task failure whose recorded policy says so. A deferral,
    /// a park, a retry, an escalation, and a retained settlement all leave the
    /// run running by construction.
    pub fn halts_run(&self) -> bool {
        matches!(
            &self.settlement,
            AttemptSettlement::Closed {
                transition: SettlementTransition::Failed {
                    halts_run: true,
                    ..
                },
                ..
            }
        )
    }

    /// The session and incarnation this settlement retained, if any.
    pub fn retained(&self) -> Option<(&SessionId, Epoch)> {
        match &self.settlement {
            AttemptSettlement::Retained {
                retained_session,
                retained_incarnation,
            } => Some((retained_session, *retained_incarnation)),
            AttemptSettlement::Closed { .. } => None,
        }
    }
}

/// `attempt_interrupted`: a process died holding this attempt.
///
/// Never halting. An interruption is a statement about a coordinator, not a
/// judgement of the work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptInterrupted4 {
    pub key: TaskKey,
    pub generation: GenerationId,
    pub attempt: AttemptNumber,
    pub lease: LeaseDisposition,
    pub detail: String,
}

/// Why a generation was closed without a settlement of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum GenerationCloseReason {
    /// A retained session belongs to the incarnation that retained it, and
    /// this is not that incarnation.
    ResumeDiscardsRetainedSession,
    /// The recorded worktree is gone, or failed its quiescence check and
    /// cannot be rebuilt into what a retained generation claims to hold.
    WorktreeMissing,
    /// Run-end closure, with the outcome it is closing for.
    RunEnding { outcome: RunOutcome },
}

/// `generation_closed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationClosed {
    pub key: TaskKey,
    pub generation: GenerationId,
    #[serde(deserialize_with = "strict::field")]
    pub reason: GenerationCloseReason,
    pub lease: LeaseDisposition,
}

/// `defer_wait_elapsed`: the backoff the run was sleeping through is over.
///
/// One event for the whole run rather than one per waiter: it wakes every
/// deferred task and every verification-deferred candidate at once, so the
/// order they were deferred in cannot become an order they are retried in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferWaitElapsed4 {
    pub waited_ms: u64,
    /// Which sleep this was, counted across the run.
    pub round: u32,
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

/// What preparing a candidate does to the run's leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lease_effect", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateLeaseEffect {
    /// The predicted region is replaced by the region the diff actually
    /// touched.
    ReplacesPredicted {
        #[serde(deserialize_with = "strict::field")]
        paths: PathSet,
    },
    /// A lineage member adds its region to the lineage's.
    WidensLineage {
        root: TaskKey,
        #[serde(deserialize_with = "strict::field")]
        paths: PathSet,
    },
}

/// `candidate_prepared`: an immutable commit of exactly the tree that was
/// judged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePrepared {
    pub key: TaskKey,
    pub generation: GenerationId,
    /// The attempt whose gates and reviewers judged this tree. Embedded whole
    /// because a fast integration publishes this commit with no verification
    /// of its own, and this record is then the entire evidence for it.
    #[serde(deserialize_with = "strict::boxed")]
    pub attempt: Box<AttemptRecord>,
    /// The commit the worktree was created at, and the commit the candidate is
    /// parented on. Recorded twice because they are two claims — where the work
    /// started, and what the object says — and the merge queue's exact-base
    /// decision depends on them being the same claim.
    pub base_sha: CommitSha,
    pub parent_sha: CommitSha,
    pub tree_sha: CommitSha,
    pub commit_sha: CommitSha,
    pub message: String,
    /// `refs/tactus/runs/<id>/candidate-prepared/<key>/<gen>` — the pin that
    /// keeps the commit reachable until the authoritative ref exists.
    pub prepared_ref: GitRef,
    /// `refs/tactus/runs/<id>/candidates/<key>/<gen>` — created next.
    pub candidate_ref: GitRef,
    /// The region the diff actually touched.
    #[serde(deserialize_with = "strict::field")]
    pub actual_paths: PathSet,
    pub lease_effect: CandidateLeaseEffect,
}

impl CandidatePrepared {
    /// Whether the object's parent is the base the work started from.
    ///
    /// An intra-event relation, and the one that makes `base_sha` usable by
    /// the merge queue at all: the exact-base decision compares the
    /// integration head against `base_sha` and then publishes `commit_sha`, so
    /// a commit parented somewhere else would fast-forward the integration ref
    /// onto history nobody judged.
    pub fn parent_is_base(&self) -> bool {
        self.parent_sha == self.base_sha
    }

    /// This candidate as the merge queue names it.
    pub fn candidate(&self) -> CandidateRef {
        CandidateRef {
            key: self.key,
            generation: self.generation,
            commit_sha: self.commit_sha.clone(),
            candidate_ref: self.candidate_ref.clone(),
        }
    }
}

/// `task_candidate_created`: the authoritative ref exists and the candidate
/// takes its queue position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCandidateCreated {
    pub candidate: CandidateRef,
}

// ---------------------------------------------------------------------------
// Integration
// ---------------------------------------------------------------------------

/// Why a verification is running at all.
///
/// There is no `fast` variant: an exact-base candidate is published without a
/// verification of its own, so no `merge_verification_started` exists for it.
/// That absence is the design — the commit the integration ref fast-forwards
/// onto is the very commit its gates and reviewers judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationBasis {
    /// A stale candidate was cherry-picked onto the current head and the
    /// resulting proposal is under judgement.
    StaleClean {
        /// `refs/tactus/runs/<id>/prepared/<seq>` — the proposal pin.
        prepared_ref: GitRef,
    },
    /// The cherry-pick was empty: the change is already in the head, and the
    /// head itself is what gets verified.
    AlreadyPresent,
}

/// `merge_verification_started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeVerificationStarted {
    pub sequence: SequenceId,
    pub candidate: CandidateRef,
    #[serde(deserialize_with = "strict::field")]
    pub basis: VerificationBasis,
    /// The integration ref head this transaction read, and the head the CAS
    /// will expect.
    pub expected_head: CommitSha,
    /// What is under judgement: the proposal commit, or the head itself.
    pub proposed_sha: CommitSha,
}

/// How a verification ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    Passed,
    GatesFailed,
    Rejected,
}

/// A completed verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRecord {
    pub verdict: VerificationVerdict,
    pub gates_passed: bool,
    /// The review passes that actually ran, in order. Empty when the gates
    /// failed first and nothing was reviewed.
    #[serde(deserialize_with = "strict::list")]
    pub reviews: Vec<ReviewRecord>,
    pub detail: String,
}

impl VerificationRecord {
    /// Whether this is a passing terminal record.
    pub fn passed(&self) -> bool {
        self.verdict == VerificationVerdict::Passed
    }
}

/// Why an integration could not be judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnavailableCause {
    /// A reviewer found something only a person may decide. Always parks.
    HumanRequired { verdict: String },
    /// Something outside the run was unavailable. Defers until it has deferred
    /// enough times, then parks.
    Infrastructure {
        #[serde(deserialize_with = "strict::field")]
        kind: InfrastructureKind,
    },
}

/// Which outage. Open-ended: the list is what has been seen, not what can
/// happen, and an unrecognized outage must still be recordable as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InfrastructureKind {
    RateLimited,
    ReviewUnavailable,
    ReviewerTimeout,
    RunnerSpawnFailure,
    Other { detail: String },
}

/// What the run does about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnavailableOutcome {
    /// Back off and try again. The candidate keeps its queue position and its
    /// lease, the sequence is consumed, and no attempt is burned — an outage
    /// never fails a task on its own.
    Deferred { defers: u32 },
    /// Ask a person. The task moves to awaiting input and the candidate stays
    /// queued but ineligible.
    Parked { question: FrozenQuestion },
}

/// `merge_verification_unavailable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeVerificationUnavailable {
    pub sequence: SequenceId,
    pub cause: UnavailableCause,
    pub outcome: UnavailableOutcome,
}

/// How an unavailability record disagrees with itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnavailableDefect {
    /// A human finding cannot be waited out.
    HumanRequiredWithoutPark,
    /// A park whose question cannot be answered.
    ParkedWithoutCompleteQuestion,
}

impl fmt::Display for UnavailableDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HumanRequiredWithoutPark => {
                "a human-required verdict deferred rather than parked; waiting cannot resolve a \
                 finding only a person can decide"
            }
            Self::ParkedWithoutCompleteQuestion => {
                "a park whose question is incomplete: the task would stop with no way to \
                 continue it"
            }
        })
    }
}

impl MergeVerificationUnavailable {
    /// Whether the record agrees with itself.
    ///
    /// The defer *count* is checked against the run's frozen ceiling and the
    /// candidate's own history, which are the fold's; what is checkable here
    /// is that a human finding parked, and that the park it produced is
    /// answerable.
    ///
    /// # Errors
    ///
    /// The first [`UnavailableDefect`] the event exhibits.
    pub fn self_consistency(&self) -> Result<(), UnavailableDefect> {
        if matches!(self.cause, UnavailableCause::HumanRequired { .. })
            && !matches!(self.outcome, UnavailableOutcome::Parked { .. })
        {
            return Err(UnavailableDefect::HumanRequiredWithoutPark);
        }
        if let UnavailableOutcome::Parked { question } = &self.outcome {
            if !question.is_complete() {
                return Err(UnavailableDefect::ParkedWithoutCompleteQuestion);
            }
        }
        Ok(())
    }
}

/// `merge_verification_interrupted`: a process died holding this transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeVerificationInterrupted {
    pub sequence: SequenceId,
    pub detail: String,
}

/// How the integration ref is being moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedDisposition {
    /// The head is exactly the candidate's base, so the candidate commit
    /// itself is published: no staging worktree, no cherry-pick, no proposal
    /// object, no pin. The integration ref fast-forwards onto the very commit
    /// that was judged.
    Fast,
    /// The candidate was stale, was cherry-picked onto the head, and the
    /// resulting proposal was verified.
    StaleClean,
    /// The cherry-pick was empty and the head itself was verified.
    AlreadyPresent,
}

/// What judged the thing being published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationSource {
    /// The candidate's own attempt record. Only a fast publication may cite
    /// it, because only a fast publication publishes the object that record
    /// judged.
    CandidatePrepared {
        key: TaskKey,
        generation: GenerationId,
    },
    /// A verification run in this transaction.
    Verification { sequence: SequenceId },
}

/// `merge_prepared`: the run is authorized to move the integration ref.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergePrepared {
    pub sequence: SequenceId,
    pub disposition: PreparedDisposition,
    /// The head the CAS expects. Read before any staging effect.
    pub expected_head: CommitSha,
    /// What the ref will point at afterwards.
    pub proposed_sha: CommitSha,
    /// The completion identity INV-20 binds this transaction to: which task and
    /// which generation produced the candidate being published. Recorded beside
    /// the candidate's commit and ref rather than inside them, because
    /// `candidate_sha` and `candidate_ref` are payload fields of `merge_prepared`
    /// itself.
    pub key: TaskKey,
    pub generation: GenerationId,
    /// The immutable commit the gates and reviewers judged. On a fast
    /// publication this is also `proposed_sha`; on a stale one it is the object
    /// the proposal was cherry-picked from.
    pub candidate_sha: CommitSha,
    /// The authoritative candidate ref that keeps `candidate_sha` reachable.
    pub candidate_ref: GitRef,
    /// The proposal pin, on a stale publication only.
    #[serde(deserialize_with = "strict::required")]
    pub prepared_ref: Option<GitRef>,
    pub verification_source: VerificationSource,
    /// The verification's terminal record, where one ran.
    #[serde(deserialize_with = "strict::required")]
    pub verification: Option<VerificationRecord>,
    /// Every task this publication settles, as the fold derived the closure.
    pub satisfies: Vec<TaskKey>,
}

/// How a publication record disagrees with itself.
///
/// Only the relations that live inside one event. The rest of INV-09's
/// relations — `expected_head` against the candidate's recorded base, the
/// proposal against the pin, the head against the verification's — compare
/// this event against records elsewhere in the log and belong to the fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreparedDefect {
    /// A fast publication carrying a proposal pin. There is no proposal: the
    /// candidate commit is what is published, and a pin would name an object
    /// this disposition never creates.
    FastWithPreparedRef,
    /// A fast publication proposing something other than the candidate commit.
    FastProposesAnotherCommit,
    /// A fast publication citing a verification rather than the candidate's
    /// own record.
    FastWithoutCandidateSource,
    /// A stale publication without the pin that keeps its proposal reachable.
    StaleWithoutPreparedRef,
    /// An already-present publication proposing something other than the head
    /// it claims is already present.
    AlreadyPresentMovesTheHead,
    /// A verified disposition citing the candidate's record rather than the
    /// verification that actually judged what is being published.
    VerifiedWithoutVerificationSource,
    /// A verified disposition without a terminal verification record.
    VerifiedWithoutRecord,
    /// A verified disposition whose verification did not pass.
    VerificationDidNotPass,
}

impl fmt::Display for PreparedDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FastWithPreparedRef => {
                "a fast publication carrying a proposal pin: an exact-base publication creates no \
                 proposal object to pin"
            }
            Self::FastProposesAnotherCommit => {
                "a fast publication proposing something other than the candidate commit"
            }
            Self::FastWithoutCandidateSource => {
                "a fast publication citing a verification rather than the candidate record that \
                 judged the commit being published"
            }
            Self::StaleWithoutPreparedRef => {
                "a stale publication without the pin keeping its proposal reachable"
            }
            Self::AlreadyPresentMovesTheHead => {
                "an already-present publication proposing a commit other than the head it claims \
                 already contains the change"
            }
            Self::VerifiedWithoutVerificationSource => {
                "a verified publication citing the candidate record rather than the verification \
                 that judged what is being published"
            }
            Self::VerifiedWithoutRecord => {
                "a verified publication without a terminal verification record"
            }
            Self::VerificationDidNotPass => "a publication whose verification did not pass",
        })
    }
}

impl MergePrepared {
    /// The candidate this publication names, in the shape the queue holds it.
    ///
    /// A projection of the four payload fields, so the two cannot disagree:
    /// `merge_prepared` records the candidate's identity flat, and every
    /// comparison against a queue entry wants it whole.
    pub fn candidate(&self) -> CandidateRef {
        CandidateRef {
            key: self.key,
            generation: self.generation,
            commit_sha: self.candidate_sha.clone(),
            candidate_ref: self.candidate_ref.clone(),
        }
    }

    /// Whether the record agrees with itself.
    ///
    /// # Errors
    ///
    /// The first [`PreparedDefect`] the event exhibits.
    pub fn self_consistency(&self) -> Result<(), PreparedDefect> {
        match self.disposition {
            PreparedDisposition::Fast => {
                if self.prepared_ref.is_some() {
                    return Err(PreparedDefect::FastWithPreparedRef);
                }
                if self.proposed_sha != self.candidate_sha {
                    return Err(PreparedDefect::FastProposesAnotherCommit);
                }
                if !matches!(
                    self.verification_source,
                    VerificationSource::CandidatePrepared { .. }
                ) {
                    return Err(PreparedDefect::FastWithoutCandidateSource);
                }
            }
            PreparedDisposition::StaleClean | PreparedDisposition::AlreadyPresent => {
                if self.disposition == PreparedDisposition::StaleClean
                    && self.prepared_ref.is_none()
                {
                    return Err(PreparedDefect::StaleWithoutPreparedRef);
                }
                if self.disposition == PreparedDisposition::AlreadyPresent
                    && self.proposed_sha != self.expected_head
                {
                    return Err(PreparedDefect::AlreadyPresentMovesTheHead);
                }
                if !matches!(
                    self.verification_source,
                    VerificationSource::Verification { .. }
                ) {
                    return Err(PreparedDefect::VerifiedWithoutVerificationSource);
                }
                let record = self
                    .verification
                    .as_ref()
                    .ok_or(PreparedDefect::VerifiedWithoutRecord)?;
                if !record.passed() {
                    return Err(PreparedDefect::VerificationDidNotPass);
                }
            }
        }
        Ok(())
    }
}

/// Why a candidate was not published.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum RejectionDisposition {
    /// The cherry-pick conflicted. The conflicting region is what the repair
    /// inherits and what widens the lineage lease.
    Conflict {
        #[serde(deserialize_with = "strict::field")]
        paths: PathSet,
    },
    /// The proposal was verified and judged unacceptable.
    CodeRejected { verification: VerificationRecord },
}

/// What a rejection does to the run's leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lease_effect", rename_all = "snake_case", deny_unknown_fields)]
pub enum RejectionLeaseEffect {
    /// A non-lineage candidate's lease becomes the new lineage's.
    CreatesLineage {
        root: TaskKey,
        #[serde(deserialize_with = "strict::field")]
        paths: PathSet,
    },
    /// A lineage member's rejection widens the lineage it already belongs to.
    WidensLineage {
        root: TaskKey,
        #[serde(deserialize_with = "strict::field")]
        paths: PathSet,
    },
}

/// `merge_rejected`: one append that rejects a candidate and registers the
/// repair for it.
///
/// One append because the two are one decision. A rejection recorded without
/// its repair is a lineage that a crash could leave holding a lease with
/// nothing scheduled to release it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeRejected {
    pub sequence: SequenceId,
    pub candidate: CandidateRef,
    /// The integration head the candidate was judged against.
    pub rejecting_head: CommitSha,
    pub disposition: RejectionDisposition,
    /// The repair this rejection registers, complete.
    pub repair: FrozenSpawn,
    pub lease_effect: RejectionLeaseEffect,
}

/// Which lease a publication releases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "release", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeLeaseRelease {
    /// An ordinary candidate's actual lease.
    Candidate {
        key: TaskKey,
        generation: GenerationId,
    },
    /// The lineage lease, released when the publication settles its root.
    Lineage { root: TaskKey },
}

/// `task_merged`: the integration ref moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMerged {
    pub sequence: SequenceId,
    /// What the ref now points at — the `proposed_sha` of the authorization.
    pub merged_sha: CommitSha,
    /// Every task this settles, copied exactly from the authorization.
    pub satisfies: Vec<TaskKey>,
    pub lease_release: MergeLeaseRelease,
}

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

/// What made the run halt, and where.
///
/// Two carriers and no others. In particular an outage is not one: a
/// verification that could not run defers or parks, and only a decline of the
/// question it parked behind halts anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltCarrier {
    /// A terminal task failure whose recorded policy halts the run.
    TaskFailure {
        key: TaskKey,
        generation: GenerationId,
        attempt: AttemptNumber,
    },
    /// A declined question whose recorded policy halts the run.
    DeclinedQuestion { key: TaskKey, question: QuestionId },
}

impl HaltCarrier {
    /// The task the halt is attributed to.
    pub fn key(&self) -> TaskKey {
        match self {
            Self::TaskFailure { key, .. } | Self::DeclinedQuestion { key, .. } => *key,
        }
    }
}

/// Every transition a schema-4 run records.
///
/// Internally tagged on `event` with the payload under `data`, exactly as
/// schemas 1–3 are, so the file stays one JSON object per line and stays
/// greppable by tag. What it does not carry is the legacy envelope's hoisted
/// routing fields — see the module documentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TopologyEventBody {
    RunStarted {
        data: Box<RunStarted4>,
    },
    RunResumed {
        data: Box<RunResumed4>,
    },
    TaskSpawned {
        data: Box<TaskSpawned>,
    },
    TaskDispatched {
        data: TaskDispatched,
    },
    AttemptStarted {
        data: AttemptStarted4,
    },
    AttemptFinished {
        data: Box<AttemptFinished4>,
    },
    AttemptInterrupted {
        data: AttemptInterrupted4,
    },
    GenerationClosed {
        data: GenerationClosed,
    },
    DeferWaitElapsed {
        data: DeferWaitElapsed4,
    },
    CandidatePrepared {
        data: Box<CandidatePrepared>,
    },
    TaskCandidateCreated {
        data: TaskCandidateCreated,
    },
    MergeVerificationStarted {
        data: MergeVerificationStarted,
    },
    MergeVerificationUnavailable {
        data: MergeVerificationUnavailable,
    },
    MergeVerificationInterrupted {
        data: MergeVerificationInterrupted,
    },
    MergePrepared {
        data: Box<MergePrepared>,
    },
    MergeRejected {
        data: Box<MergeRejected>,
    },
    TaskMerged {
        data: TaskMerged,
    },
    QuestionRaised {
        data: QuestionRaised4,
    },
    QuestionAnswered {
        data: QuestionAnswered4,
    },
    BudgetExceeded {
        data: BudgetExceeded4,
    },
    RunFinished {
        data: RunFinished4,
    },
    /// Informational: §14's pre-flight capacity snapshot. Nothing folds on it.
    CapacitySnapshot {
        data: CapacitySnapshot,
    },
    /// Informational: a pool reported itself empty.
    PoolExhausted {
        data: PoolExhausted,
    },
    /// Informational: a question routed to the designer rather than execution.
    DesignDefect {
        data: DesignDefect,
    },
}

/// Every tag the vocabulary can write, in declaration order.
///
/// The first twenty-one are transactions — a fold applies them and refuses
/// what it cannot apply. The last three are informational.
pub const TOPOLOGY_EVENT_KINDS: [&str; 24] = [
    "run_started",
    "run_resumed",
    "task_spawned",
    "task_dispatched",
    "attempt_started",
    "attempt_finished",
    "attempt_interrupted",
    "generation_closed",
    "defer_wait_elapsed",
    "candidate_prepared",
    "task_candidate_created",
    "merge_verification_started",
    "merge_verification_unavailable",
    "merge_verification_interrupted",
    "merge_prepared",
    "merge_rejected",
    "task_merged",
    "question_raised",
    "question_answered",
    "budget_exceeded",
    "run_finished",
    "capacity_snapshot",
    "pool_exhausted",
    "design_defect",
];

/// How many of [`TOPOLOGY_EVENT_KINDS`] are transactions rather than
/// informational records.
pub const TOPOLOGY_TRANSACTION_KINDS: usize = 21;

impl TopologyEventBody {
    /// This event's tag, as it appears on the wire.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::RunStarted { .. } => "run_started",
            Self::RunResumed { .. } => "run_resumed",
            Self::TaskSpawned { .. } => "task_spawned",
            Self::TaskDispatched { .. } => "task_dispatched",
            Self::AttemptStarted { .. } => "attempt_started",
            Self::AttemptFinished { .. } => "attempt_finished",
            Self::AttemptInterrupted { .. } => "attempt_interrupted",
            Self::GenerationClosed { .. } => "generation_closed",
            Self::DeferWaitElapsed { .. } => "defer_wait_elapsed",
            Self::CandidatePrepared { .. } => "candidate_prepared",
            Self::TaskCandidateCreated { .. } => "task_candidate_created",
            Self::MergeVerificationStarted { .. } => "merge_verification_started",
            Self::MergeVerificationUnavailable { .. } => "merge_verification_unavailable",
            Self::MergeVerificationInterrupted { .. } => "merge_verification_interrupted",
            Self::MergePrepared { .. } => "merge_prepared",
            Self::MergeRejected { .. } => "merge_rejected",
            Self::TaskMerged { .. } => "task_merged",
            Self::QuestionRaised { .. } => "question_raised",
            Self::QuestionAnswered { .. } => "question_answered",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::RunFinished { .. } => "run_finished",
            Self::CapacitySnapshot { .. } => "capacity_snapshot",
            Self::PoolExhausted { .. } => "pool_exhausted",
            Self::DesignDefect { .. } => "design_defect",
        }
    }

    /// Whether a fold applies this event, as opposed to merely recording it.
    ///
    /// The distinction the unknown-field rule turns on: a transaction carrying
    /// a field this binary does not understand is one it cannot claim to have
    /// applied, while an informational record with an extra column costs
    /// nothing to ignore.
    pub fn is_transaction(&self) -> bool {
        !matches!(
            self,
            Self::CapacitySnapshot { .. } | Self::PoolExhausted { .. } | Self::DesignDefect { .. }
        )
    }

    /// The task this event concerns, where it concerns exactly one.
    ///
    /// Replaces the legacy envelope's hoisted `task` field. Total over the
    /// vocabulary, so a new event kind has to answer the question rather than
    /// silently answering `None`.
    pub fn key(&self) -> Option<TaskKey> {
        match self {
            Self::TaskSpawned { data } => Some(data.spawn.key),
            Self::TaskDispatched { data } => Some(data.key),
            Self::AttemptStarted { data } => Some(data.key),
            Self::AttemptFinished { data } => Some(data.key),
            Self::AttemptInterrupted { data } => Some(data.key),
            Self::GenerationClosed { data } => Some(data.key),
            Self::CandidatePrepared { data } => Some(data.key),
            Self::TaskCandidateCreated { data } => Some(data.candidate.key),
            Self::MergeVerificationStarted { data } => Some(data.candidate.key),
            Self::MergePrepared { data } => Some(data.key),
            Self::MergeRejected { data } => Some(data.candidate.key),
            Self::QuestionRaised { data } => Some(data.question.key),
            Self::QuestionAnswered { data } => Some(data.key),
            Self::BudgetExceeded { data } => data.key,
            // Deliberately keyless: a verification outage and an interruption
            // are facts about a transaction, and the fold resolves the
            // candidate from the sequence rather than trusting a second copy.
            Self::MergeVerificationUnavailable { .. }
            | Self::MergeVerificationInterrupted { .. }
            | Self::TaskMerged { .. }
            | Self::RunStarted { .. }
            | Self::RunResumed { .. }
            | Self::DeferWaitElapsed { .. }
            | Self::RunFinished { .. }
            | Self::CapacitySnapshot { .. }
            | Self::PoolExhausted { .. }
            | Self::DesignDefect { .. } => None,
        }
    }

    /// The integration transaction this event belongs to, where it belongs to
    /// one.
    pub fn sequence(&self) -> Option<SequenceId> {
        match self {
            Self::MergeVerificationStarted { data } => Some(data.sequence),
            Self::MergeVerificationUnavailable { data } => Some(data.sequence),
            Self::MergeVerificationInterrupted { data } => Some(data.sequence),
            Self::MergePrepared { data } => Some(data.sequence),
            Self::MergeRejected { data } => Some(data.sequence),
            Self::TaskMerged { data } => Some(data.sequence),
            Self::RunStarted { .. }
            | Self::RunResumed { .. }
            | Self::TaskSpawned { .. }
            | Self::TaskDispatched { .. }
            | Self::AttemptStarted { .. }
            | Self::AttemptFinished { .. }
            | Self::AttemptInterrupted { .. }
            | Self::GenerationClosed { .. }
            | Self::DeferWaitElapsed { .. }
            | Self::CandidatePrepared { .. }
            | Self::TaskCandidateCreated { .. }
            | Self::QuestionRaised { .. }
            | Self::QuestionAnswered { .. }
            | Self::BudgetExceeded { .. }
            | Self::RunFinished { .. }
            | Self::CapacitySnapshot { .. }
            | Self::PoolExhausted { .. }
            | Self::DesignDefect { .. } => None,
        }
    }

    /// The halt this event carries, if it carries one.
    ///
    /// Total over the vocabulary and deliberately narrow. `halted_at` is first
    /// in wins, and what may set it at all is a closed list: a terminal task
    /// failure the run's policy halts on, and a decline the run's policy halts
    /// on. An interruption, a generation closure, a deferral, and a
    /// verification outage are each a reason the run is *not* progressing, and
    /// none of them is a reason it is over.
    pub fn halt_carrier(&self) -> Option<HaltCarrier> {
        match self {
            Self::AttemptFinished { data } if data.halts_run() => Some(HaltCarrier::TaskFailure {
                key: data.key,
                generation: data.generation,
                attempt: data.attempt,
            }),
            Self::QuestionAnswered { data } if data.halts_run() => {
                Some(HaltCarrier::DeclinedQuestion {
                    key: data.key,
                    question: data.question.clone(),
                })
            }
            _ => None,
        }
    }
}

/// One line of a schema-4 `events.jsonl`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyEvent {
    pub ts: String,
    #[serde(flatten)]
    pub body: TopologyEventBody,
}

impl TopologyEvent {
    /// Stamp a body with the current time.
    pub fn now(body: TopologyEventBody) -> Self {
        Self {
            ts: crate::util::rfc3339_utc_now(),
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::events::{FailureRecord, PoolSnapshot, ReviewPassOutcome};
    use crate::gates::ShellKind;
    use crate::ir::{Artifact, ArtifactId, Plan, PlanSource, Task, TaskId, TaskKind, Usage};
    use crate::ladder::{FailureKind, FailureOrigin};
    use crate::review::PassBinding;
    use crate::topology::registry::{
        Admission, FrozenLadder, FrozenReviews, FrozenTaskSpec, Lineage, Origin, TaskRegistry,
    };

    // ------------------------------------------------------------------
    // Fixtures
    //
    // Every independently meaningful field carries a different value from
    // every other, nothing sits at its type's default, orderings are
    // deranged against the order a reader would guess, and the strings are
    // padded, mixed-case, multi-byte and over-length by turns. That is not
    // decoration: a fixture whose fields correlate lets a test observe a
    // difference that the field it names did not produce.
    // ------------------------------------------------------------------

    const RUN_ID: &str = "01J8ZQK9WQ4RXN7VYB3TMEF6GD";

    /// Three commit shas that are distinguishable at every position: no shared
    /// prefix, no shared suffix, and different lengths of run so a comparison
    /// that truncated or abbreviated would land somewhere visible.
    const SHA_CANDIDATE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c";
    const SHA_HEAD: &str = "9a8b7c6d5e4f30211302f4e5d6c7b8a99a8b7c6d";
    const SHA_THIRD: &str = "cafebabe0123456789abcdefdeadbeefcafebabe";
    const SHA_BASE: &str = "5150413f2b1c0d9e8f7a6b5c4d3e2f105150413f";
    const SHA_TREE: &str = "7e6d5c4b3a29180fe1d2c3b4a59687787e6d5c4b";
    /// Two further candidate commits, so a relation stated about "the
    /// candidate's commit" can be crossed over more than one of them.
    const SHA_FOURTH: &str = "3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e";
    const SHA_FIFTH: &str = "d1d3d5d7e2e4e6e8f1f3f5f7a2a4a6a8b1b3b5b7";
    /// A sha that differs from [`SHA_CANDIDATE`] in exactly one interior byte,
    /// sharing its first 20 and last 19 characters. A comparison that
    /// abbreviated, hashed a prefix, or compared a suffix accepts this as equal.
    const SHA_CANDIDATE_ONE_BYTE_OFF: &str = "0f1e2d3c4b5a6978879fa5b4c3d2e1f00f1e2d3c";

    fn task_key(index: u32) -> TaskKey {
        TaskKey(index)
    }

    fn hostile_paths() -> PathSet {
        PathSet::Prefixes {
            paths: vec![
                crate::topology::paths::GitPath::from("src/Zebra/ÜBER.rs"),
                crate::topology::paths::GitPath::from("  padded/entry  "),
                crate::topology::paths::GitPath::from("Docs/adr/0001.md"),
            ],
        }
    }

    fn other_paths() -> PathSet {
        PathSet::Prefixes {
            paths: vec![crate::topology::paths::GitPath::from("build.rs")],
        }
    }

    fn path_policy() -> PathPolicy {
        PathPolicy {
            version: crate::topology::paths::PathPolicyVersion::V1,
            case_fold: true,
            grammar: crate::topology::paths::PathGrammar::Globset,
        }
    }

    fn volumes(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(agent, volume)| ((*agent).to_owned(), (*volume).to_owned()))
            .collect()
    }

    /// A container runner with every identity field distinct from every other,
    /// including a digest that shares no substring with the id it accompanies.
    fn container_runner() -> RunnerPolicy {
        RunnerPolicy {
            kind: RunnerKind::Container,
            policy: RunnerContract::ContainerV1,
            image: Some(ImageIdentity {
                reference: "ghcr.io/Example-Org/tactus-Runner:v2.1-Ünicode".to_owned(),
                id: "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
                    .to_owned(),
                digest: Some(
                    "sha256:ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211"
                        .to_owned(),
                ),
            }),
            credential_volumes: Some(volumes(&[
                ("zeta-agent", "tactus-creds-Zeta"),
                ("alpha-agent", "tactus-creds-ALPHA  "),
            ])),
        }
    }

    fn host_runner() -> RunnerPolicy {
        RunnerPolicy {
            kind: RunnerKind::Host,
            policy: RunnerContract::HostV1,
            image: None,
            credential_volumes: None,
        }
    }

    fn chain(task: &str) -> ChainSummary {
        ChainSummary {
            task: task.to_owned(),
            tiers: vec![Tier::Small, Tier::Mid],
            attempts_per: 3,
            bindings: Some(vec![
                crate::events::BindingSummary {
                    tier: Tier::Small,
                    agent: "claude-code".to_owned(),
                    model: "claude-haiku-4-5".to_owned(),
                    pinned: false,
                },
                crate::events::BindingSummary {
                    tier: Tier::Mid,
                    agent: "codex".to_owned(),
                    model: "gpt-5.6-sol".to_owned(),
                    pinned: true,
                },
            ]),
        }
    }

    fn effort_policy() -> ResolvedEffortPolicy {
        ResolvedEffortPolicy {
            small: Effort::Low,
            mid: Effort::High,
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
                .map(|index| (index % 2 == 1).then(|| PassBinding::new("copilot", "gpt-5.6")))
                .collect(),
        }
    }

    fn gate_summaries() -> Vec<GateSummary> {
        vec![
            GateSummary {
                name: "  Fmt Check  ".to_owned(),
                cmd: "cargo fmt --check".to_owned(),
                timeout: Duration::from_millis(91_000),
                shell: ShellKind::Pwsh,
            },
            GateSummary {
                name: "clippy".to_owned(),
                cmd: "cargo clippy --all-targets -- -D warnings".to_owned(),
                timeout: Duration::from_millis(7_000),
                shell: ShellKind::Bash,
            },
        ]
    }

    /// Plan order, display-id order and topological order all disagree, so a
    /// projection that used one where it meant another shows up.
    fn task_of(id: &str, deps: &[&str]) -> Task {
        Task {
            id: TaskId::from(id),
            kind: TaskKind::Fix,
            title: format!("{id} title"),
            body: format!("{id} body"),
            depends_on: deps.iter().copied().map(TaskId::from).collect(),
            acceptance: vec![format!("{id} passes")],
            path_hints: vec![format!("src/{id}.rs")],
            suggested_tier: Some(Tier::Mid),
            min_tier: Some(Tier::Small),
            artifacts_in: vec![ArtifactId::from("contract")],
            artifacts_out: vec![ArtifactId::from(format!("{id}-out").as_str())],
        }
    }

    fn sample_plan() -> Plan {
        Plan {
            source: PlanSource {
                adapter: "markdown".to_owned(),
                hash: "frozen-Ünicode-hash".to_owned(),
            },
            tasks: vec![
                task_of("zeta", &["alpha"]),
                task_of("alpha", &[]),
                task_of("mid", &["alpha", "zeta"]),
            ],
            artifacts: vec![Artifact {
                id: ArtifactId::from("contract"),
                produced_by: Some(TaskId::from("alpha")),
            }],
        }
    }

    fn run_started(plan: &Plan) -> RunStarted4 {
        RunStarted4 {
            schema: TOPOLOGY_SCHEMA,
            tactus_version: "0.2.0-Ünicode".to_owned(),
            run_id: RUN_ID.to_owned(),
            incarnation: IncarnationId("01J8ZQKB2M7NC5PQR0TVWXYZ12".to_owned()),
            runner: container_runner(),
            probed_agents: vec![
                "codex".to_owned(),
                "claude-code".to_owned(),
                "copilot".to_owned(),
            ],
            branch: format!("tactus/run-{RUN_ID}"),
            // Deliberately not derived from `branch`, `private_dir` or the run
            // id: a projection that reached for the wrong one of the four
            // resource identities would still agree with itself if they shared
            // text.
            integration_ref: GitRef::from("refs/heads/Ünïcode/Integration Target"),
            base_sha: CommitSha::from(SHA_BASE),
            execution_root: "  D:\\Tactus Roots\\exec ünïcode  ".to_owned(),
            private_dir: "/var/lib/Tactus/private runs".to_owned(),
            plan_path: "docs/Plan Ünicode.md".to_owned(),
            config_path: Some("tactus.toml".to_owned()),
            plan_hash: plan.source.hash.clone(),
            normalized_plan_digest:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            registry_digest:
                "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned(),
            path_policy: path_policy(),
            limits: TopologyLimits {
                max_parallel: 7,
                max_defers: 3,
                max_merge_repairs: 5,
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

    fn attempt_record() -> AttemptRecord {
        AttemptRecord {
            attempt: 2,
            tier: "mid".to_owned(),
            model: "gpt-5.6-sol".to_owned(),
            pool: Some("codex-plus".to_owned()),
            resumed: true,
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
            failure: Some(FailureRecord {
                kind: FailureKind::GateFailed,
                origin: FailureOrigin::Reviewer,
                reason: "  clippy: 3 warnings, one of them Ünicode  ".to_owned(),
            }),
        }
    }

    fn frozen_question(id: &str, key: TaskKey) -> FrozenQuestion {
        FrozenQuestion {
            id: QuestionId::from(id),
            key,
            kind: QuestionKind::Unblock,
            context: "  The reviewer found a licence question only a person may settle.  "
                .to_owned(),
            options: vec![
                "escalate to frontier".to_owned(),
                "accept as-is".to_owned(),
                "  rescope  ".to_owned(),
            ],
        }
    }

    fn frozen_ladder() -> FrozenLadder {
        FrozenLadder {
            tiers: vec![Tier::Mid, Tier::Frontier],
            attempts_per: 3,
            rungs: vec![
                FrozenRung {
                    tier: Tier::Mid,
                    agent: "codex".to_owned(),
                    model: "gpt-5.6-sol".to_owned(),
                    pinned: true,
                },
                FrozenRung {
                    tier: Tier::Frontier,
                    agent: "claude-code".to_owned(),
                    model: "claude-opus-5".to_owned(),
                    pinned: false,
                },
            ],
            floor: Some(Tier::Mid),
            ceiling: Some(Tier::Frontier),
            effort: effort_policy(),
            admission: Admission::Runnable,
        }
    }

    fn spawned_entry() -> TaskEntry {
        TaskEntry {
            key: task_key(9),
            display_id: TaskId::from("merge-fix-0003-zeta"),
            origin: Origin::MergeRepair,
            spec: FrozenTaskSpec {
                kind: TaskKind::Fix,
                title: "  Repair the Zeta rejection  ".to_owned(),
                body: "Conflict against `src/Zebra/ÜBER.rs`; preserve merged behaviour.".to_owned(),
                acceptance: vec!["the conflict is resolved".to_owned()],
                path_hints: vec!["src/Zebra/ÜBER.rs".to_owned(), "build.rs".to_owned()],
                suggested_tier: Some(Tier::Frontier),
                min_tier: Some(Tier::Mid),
                artifacts_in: vec![ArtifactId::from("contract")],
                artifacts_out: vec![ArtifactId::from("zeta-out")],
            },
            deps: vec![task_key(1)],
            display_deps: vec![TaskId::from("alpha")],
            ladder: frozen_ladder(),
            reviews: FrozenReviews {
                enabled: true,
                alternative_available: true,
                pass_timeout_secs: 1_337,
                primary: Some(PassBinding::new("claude-code", "claude-opus-5")),
                alternative: Some(PassBinding::new("copilot", "gpt-5.6")),
                second_opinion: None,
            },
            allowed_agents: vec![
                "  Codex-CLI  ".to_owned(),
                "ÜBER-agent-Ωmega".to_owned(),
                "claude-code".to_owned(),
            ],
            lineage: Some(Lineage {
                root: task_key(0),
                parent: task_key(4),
                index: 3,
            }),
        }
    }

    fn frozen_spawn() -> FrozenSpawn {
        FrozenSpawn {
            key: task_key(9),
            entry: spawned_entry(),
            admission: SpawnAdmission::HumanBinding {
                options: vec!["codex".to_owned(), "claude-code".to_owned()],
                question: frozen_question("q-binding-Ünicode", task_key(9)),
            },
        }
    }

    fn candidate_ref() -> CandidateRef {
        CandidateRef {
            key: task_key(2),
            generation: GenerationId(4),
            commit_sha: CommitSha::from(SHA_CANDIDATE),
            candidate_ref: GitRef::from(&format!("refs/tactus/runs/{RUN_ID}/candidates/2/4")[..]),
        }
    }

    fn verification(verdict: VerificationVerdict) -> VerificationRecord {
        VerificationRecord {
            verdict,
            gates_passed: verdict != VerificationVerdict::GatesFailed,
            reviews: vec![ReviewRecord {
                pass: "review".to_owned(),
                agent: "claude-code".to_owned(),
                model: "claude-opus-5".to_owned(),
                adapter: Some("claude-code".to_owned()),
                preflight_cli_version: Some("2.4.1".to_owned()),
                effort: Some(Effort::Max),
                pool: Some("claude-max".to_owned()),
                cost_usd: Some(0.75),
                outcome: if verdict == VerificationVerdict::Passed {
                    ReviewPassOutcome::Passed
                } else {
                    ReviewPassOutcome::Failed
                },
            }],
            detail: "  integration verification, run 7  ".to_owned(),
        }
    }

    fn merge_prepared_fast() -> MergePrepared {
        let candidate = candidate_ref();
        MergePrepared {
            sequence: SequenceId(6),
            disposition: PreparedDisposition::Fast,
            expected_head: CommitSha::from(SHA_BASE),
            proposed_sha: CommitSha::from(SHA_CANDIDATE),
            key: candidate.key,
            generation: candidate.generation,
            candidate_sha: candidate.commit_sha,
            candidate_ref: candidate.candidate_ref,
            prepared_ref: None,
            verification_source: VerificationSource::CandidatePrepared {
                key: task_key(2),
                generation: GenerationId(4),
            },
            verification: None,
            satisfies: vec![task_key(2), task_key(0)],
        }
    }

    fn candidate_prepared() -> CandidatePrepared {
        CandidatePrepared {
            key: task_key(2),
            generation: GenerationId(4),
            attempt: Box::new(attempt_record()),
            base_sha: CommitSha::from(SHA_BASE),
            parent_sha: CommitSha::from(SHA_BASE),
            tree_sha: CommitSha::from(SHA_TREE),
            commit_sha: CommitSha::from(SHA_CANDIDATE),
            message: "  zeta: repair the Ünicode path  ".to_owned(),
            prepared_ref: GitRef::from(
                &format!("refs/tactus/runs/{RUN_ID}/candidate-prepared/2/4")[..],
            ),
            candidate_ref: GitRef::from(&format!("refs/tactus/runs/{RUN_ID}/candidates/2/4")[..]),
            actual_paths: hostile_paths(),
            lease_effect: CandidateLeaseEffect::WidensLineage {
                root: task_key(0),
                paths: other_paths(),
            },
        }
    }

    /// One instance of every kind in [`TOPOLOGY_EVENT_KINDS`], in declaration
    /// order. None of them halts: the halt carriers are built separately, so
    /// the totality assertions cannot be satisfied by a fixture that happens
    /// to be a halt.
    fn every_kind() -> Vec<TopologyEventBody> {
        let plan = sample_plan();
        vec![
            TopologyEventBody::RunStarted {
                data: Box::new(run_started(&plan)),
            },
            TopologyEventBody::RunResumed {
                data: Box::new(RunResumed4 {
                    incarnation: IncarnationId("01J8ZQKC3N8PD6QRS1UVWXYZ34".to_owned()),
                    runner: container_runner(),
                    probed_agents: vec!["codex".to_owned(), "claude-code".to_owned()],
                    tactus_version: "0.2.1-Ünicode".to_owned(),
                }),
            },
            TopologyEventBody::TaskSpawned {
                data: Box::new(TaskSpawned {
                    spawn: frozen_spawn(),
                }),
            },
            TopologyEventBody::TaskDispatched {
                data: TaskDispatched {
                    key: task_key(5),
                    generation: GenerationId(2),
                    base_sha: CommitSha::from(SHA_HEAD),
                    worktree_path: "/var/lib/Tactus/work trees/zeta-2".to_owned(),
                    lease: LeaseGrant::Predicted {
                        paths: hostile_paths(),
                    },
                    source_candidate: Some(candidate_ref()),
                },
            },
            TopologyEventBody::AttemptStarted {
                data: AttemptStarted4 {
                    key: task_key(5),
                    generation: GenerationId(2),
                    attempt: AttemptNumber(3),
                    rung: 1,
                    binding: RungBinding {
                        tier: Tier::Frontier,
                        agent: "claude-code".to_owned(),
                        model: "claude-opus-5".to_owned(),
                        pinned: false,
                        effort: Effort::Max,
                    },
                    pool: Some("claude-max".to_owned()),
                    resume_session: Some(SessionId("sess-ÜNI-0042".to_owned())),
                    materialization_observed: Some(Materialization::Conflict),
                },
            },
            TopologyEventBody::AttemptFinished {
                data: Box::new(AttemptFinished4 {
                    key: task_key(5),
                    generation: GenerationId(2),
                    attempt: AttemptNumber(3),
                    record: Box::new(attempt_record()),
                    settlement: AttemptSettlement::Retained {
                        retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                        retained_incarnation: Epoch(5),
                    },
                }),
            },
            TopologyEventBody::AttemptInterrupted {
                data: AttemptInterrupted4 {
                    key: task_key(7),
                    generation: GenerationId(1),
                    attempt: AttemptNumber(2),
                    lease: LeaseDisposition::LineageHeld,
                    detail: "  coordinator died holding the attempt  ".to_owned(),
                },
            },
            TopologyEventBody::GenerationClosed {
                data: GenerationClosed {
                    key: task_key(6),
                    generation: GenerationId(3),
                    reason: GenerationCloseReason::WorktreeMissing,
                    lease: LeaseDisposition::PredictedReleased,
                },
            },
            TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 61_000,
                    round: 4,
                },
            },
            TopologyEventBody::CandidatePrepared {
                data: Box::new(candidate_prepared()),
            },
            TopologyEventBody::TaskCandidateCreated {
                data: TaskCandidateCreated {
                    candidate: candidate_ref(),
                },
            },
            TopologyEventBody::MergeVerificationStarted {
                data: MergeVerificationStarted {
                    sequence: SequenceId(6),
                    candidate: candidate_ref(),
                    basis: VerificationBasis::StaleClean {
                        prepared_ref: GitRef::from(
                            &format!("refs/tactus/runs/{RUN_ID}/prepared/6")[..],
                        ),
                    },
                    expected_head: CommitSha::from(SHA_HEAD),
                    proposed_sha: CommitSha::from(SHA_THIRD),
                },
            },
            TopologyEventBody::MergeVerificationUnavailable {
                data: MergeVerificationUnavailable {
                    sequence: SequenceId(6),
                    cause: UnavailableCause::Infrastructure {
                        kind: InfrastructureKind::ReviewerTimeout,
                    },
                    outcome: UnavailableOutcome::Deferred { defers: 2 },
                },
            },
            TopologyEventBody::MergeVerificationInterrupted {
                data: MergeVerificationInterrupted {
                    sequence: SequenceId(6),
                    detail: "  process died mid-verification  ".to_owned(),
                },
            },
            TopologyEventBody::MergePrepared {
                data: Box::new(merge_prepared_fast()),
            },
            TopologyEventBody::MergeRejected {
                data: Box::new(MergeRejected {
                    sequence: SequenceId(8),
                    candidate: candidate_ref(),
                    rejecting_head: CommitSha::from(SHA_HEAD),
                    disposition: RejectionDisposition::Conflict {
                        paths: hostile_paths(),
                    },
                    repair: frozen_spawn(),
                    lease_effect: RejectionLeaseEffect::CreatesLineage {
                        root: task_key(2),
                        paths: other_paths(),
                    },
                }),
            },
            TopologyEventBody::TaskMerged {
                data: TaskMerged {
                    sequence: SequenceId(6),
                    merged_sha: CommitSha::from(SHA_CANDIDATE),
                    satisfies: vec![task_key(2), task_key(0)],
                    lease_release: MergeLeaseRelease::Lineage { root: task_key(0) },
                },
            },
            TopologyEventBody::QuestionRaised {
                data: QuestionRaised4 {
                    question: frozen_question("q-park-0007", task_key(3)),
                },
            },
            TopologyEventBody::QuestionAnswered {
                data: QuestionAnswered4 {
                    key: task_key(3),
                    question: QuestionId::from("q-park-0007"),
                    answer: Answer4::Answered {
                        option_index: 2,
                        binding_override: Some(BindingOverride {
                            key: task_key(3),
                            question: QuestionId::from("q-park-0007"),
                            option_index: 2,
                            agent: "codex".to_owned(),
                            model: "gpt-5.6-sol".to_owned(),
                            effort: Effort::XHigh,
                        }),
                    },
                    via: "  tactus answer  ".to_owned(),
                },
            },
            TopologyEventBody::BudgetExceeded {
                data: BudgetExceeded4 {
                    epoch: Epoch(2),
                    budget: BudgetKind::Task,
                    limit_usd: 12.5,
                    spent_usd: 13.75,
                    key: Some(task_key(4)),
                },
            },
            TopologyEventBody::RunFinished {
                data: RunFinished4 {
                    outcome: RunOutcome::Parked,
                    halted_at: None,
                    merged: 3,
                    parked: 2,
                },
            },
            TopologyEventBody::CapacitySnapshot {
                data: CapacitySnapshot {
                    strategy: "  Conservative  ".to_owned(),
                    pools: vec![PoolSnapshot {
                        pool: "codex-plus".to_owned(),
                        agent: "codex".to_owned(),
                        kind: "subscription".to_owned(),
                        remaining: "42%".to_owned(),
                        confidence: "reported".to_owned(),
                        reset_at: Some("2026-08-17T21:00:00Z".to_owned()),
                    }],
                },
            },
            TopologyEventBody::PoolExhausted {
                data: PoolExhausted {
                    pool: "claude-max".to_owned(),
                    agent: "claude-code".to_owned(),
                    reset_at: Some("2026-08-18T04:00:00Z".to_owned()),
                    detail: "  5-hour limit reached  ".to_owned(),
                },
            },
            TopologyEventBody::DesignDefect {
                data: DesignDefect {
                    question: QuestionId::from("q-design-0001"),
                    context: "  the plan contradicts itself about Ünicode paths  ".to_owned(),
                    answer: "rescope".to_owned(),
                },
            },
        ]
    }

    fn payload_of(body: &TopologyEventBody) -> serde_json::Value {
        let event = TopologyEvent {
            ts: "2026-08-17T03:04:05.678Z".to_owned(),
            body: body.clone(),
        };
        serde_json::to_value(&event).expect("serialize")
    }

    // ------------------------------------------------------------------
    // The vocabulary itself
    // ------------------------------------------------------------------

    #[test]
    fn every_kind_is_represented_exactly_once_and_the_list_agrees() {
        let events = every_kind();
        let kinds: Vec<&str> = events.iter().map(TopologyEventBody::kind).collect();
        assert_eq!(kinds, TOPOLOGY_EVENT_KINDS.to_vec());
        assert_eq!(events.len(), TOPOLOGY_EVENT_KINDS.len());

        let mut sorted = kinds.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), kinds.len(), "a tag is used by two variants");

        let transactions = events.iter().filter(|body| body.is_transaction()).count();
        assert_eq!(transactions, TOPOLOGY_TRANSACTION_KINDS);
        assert_eq!(
            events.len() - transactions,
            3,
            "the informational class is capacity_snapshot, pool_exhausted, design_defect"
        );
    }

    #[test]
    fn the_wire_tag_of_every_event_is_the_kind_it_reports() {
        // Asserting the serialized tag, not merely that serialize and
        // deserialize agree: a renamed variant round-trips perfectly and
        // silently stops matching every log already written.
        for body in every_kind() {
            let value = payload_of(&body);
            let tag = value
                .get("event")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("{} has no tag", body.kind()));
            assert_eq!(tag, body.kind());
            assert!(
                TOPOLOGY_EVENT_KINDS.contains(&tag),
                "{tag} is not in the declared vocabulary"
            );
        }
    }

    #[test]
    fn every_event_round_trips_through_json_unchanged() {
        for body in every_kind() {
            let event = TopologyEvent {
                ts: "2026-08-17T03:04:05.678Z".to_owned(),
                body,
            };
            let json = serde_json::to_string(&event).expect("serialize");
            let back: TopologyEvent = serde_json::from_str(&json)
                .unwrap_or_else(|error| panic!("{}: {error}", event.body.kind()));
            assert_eq!(back, event, "{}", event.body.kind());
        }
    }

    #[test]
    fn the_envelope_is_a_timestamp_a_tag_and_a_payload_and_nothing_else() {
        // Schema 4 hoists no routing field beside the tag. Identity lives in
        // the payload once, so an envelope that contradicts its own record is
        // not a refusal — it cannot be written.
        for body in every_kind() {
            let value = payload_of(&body);
            let object = value.as_object().expect("object");
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, vec!["data", "event", "ts"], "{}", body.kind());
        }
    }

    // ------------------------------------------------------------------
    // Unknown fields (deny_unknown_fields on transactions only)
    // ------------------------------------------------------------------

    #[test]
    fn a_transaction_refuses_an_unknown_field_and_an_informational_record_ignores_it() {
        for body in every_kind() {
            let mut value = payload_of(&body);
            value
                .get_mut("data")
                .and_then(serde_json::Value::as_object_mut)
                .unwrap_or_else(|| panic!("{} has no payload object", body.kind()))
                .insert(
                    "Ünknown Field  ".to_owned(),
                    serde_json::Value::from("injected"),
                );
            let parsed = serde_json::from_value::<TopologyEvent>(value);
            assert_eq!(
                parsed.is_err(),
                body.is_transaction(),
                "{} accepted/refused an unknown field against its class",
                body.kind()
            );
        }
    }

    /// Every object path in `value`, deepest last, as a list of steps.
    ///
    /// Enumerated from the payload itself rather than listed by hand: a list is
    /// a second declaration of the shape, and the shape is what moves.
    fn object_paths(value: &serde_json::Value, at: Vec<String>, found: &mut Vec<Vec<String>>) {
        match value {
            serde_json::Value::Object(map) => {
                found.push(at.clone());
                for (key, child) in map {
                    let mut deeper = at.clone();
                    deeper.push(key.clone());
                    object_paths(child, deeper, found);
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    let mut deeper = at.clone();
                    deeper.push(format!("[{index}]"));
                    object_paths(child, deeper, found);
                }
            }
            _ => {}
        }
    }

    /// Walk `value` to `path`, where a step of the form `[n]` indexes an array.
    fn walk<'a>(
        value: &'a mut serde_json::Value,
        path: &[String],
    ) -> Option<&'a mut serde_json::Value> {
        let mut cursor = value;
        for step in path {
            cursor = match step.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                Some(index) => cursor.get_mut(index.parse::<usize>().ok()?)?,
                None => cursor.get_mut(step)?,
            };
        }
        Some(cursor)
    }

    /// Whether `path` is the payload of an event `refusals[24]` calls lenient.
    ///
    /// The `data` object of an informational event and everything under it.
    /// The envelope is not in this set for any class: it is `{ts, event, data}`
    /// whatever the event, and an unknown key beside them is one of the hoisted
    /// routing fields schema 4 made unrepresentable.
    fn is_informational_payload(kind: &str, path: &[String]) -> bool {
        matches!(
            kind,
            "capacity_snapshot" | "pool_exhausted" | "design_defect"
        ) && path.first().is_some_and(|step| step == "data")
    }

    /// The one object in the vocabulary whose keys are *values*.
    ///
    /// `credential_volumes` maps an agent name to its volume name, so a key
    /// nobody enumerated is another agent rather than a field this binary does
    /// not understand — and removing one changes which volumes the run used
    /// rather than truncating the record. Every other object in a schema-4
    /// payload is a declared shape. Kept as a named exception rather than a
    /// silently skipped path, because "this object is open" is a design claim.
    fn is_open_map(path: &[String]) -> bool {
        path.last().is_some_and(|step| step == "credential_volumes")
    }

    /// Where a schema-4 payload stops declaring a shape and starts embedding
    /// one schemas 1–3 declared.
    ///
    /// Which fields those records require is schemas 1–3's rule and this slice
    /// does not restate it: `ChainSummary.bindings` is absent in a log written
    /// before bindings were recorded, and demanding it here would refuse a
    /// legacy record schema 4 legitimately carries. What schema 4 *does* impose
    /// on them — that they carry no field this binary cannot read — is the
    /// strict door, which is exercised by the injection sweep at these very
    /// paths.
    fn embeds_a_legacy_record(path: &[String]) -> bool {
        const ROOTS: [&[&str]; 11] = [
            &["data", "gate_cmds"],
            &["data", "chains"],
            &["data", "effort_policy"],
            &["data", "reviews"],
            &["data", "record"],
            &["data", "attempt"],
            &["data", "verification", "reviews"],
            &["data", "spawn", "entry", "ladder", "effort"],
            &["data", "spawn", "entry", "reviews", "primary"],
            &["data", "spawn", "entry", "reviews", "alternative"],
            &["data", "spawn", "entry", "reviews", "second_opinion"],
        ];
        ROOTS.iter().any(|root| {
            // `merge_rejected` embeds the same registry entry under `repair`.
            let under_repair = path.first().is_some_and(|step| step == "data")
                && path.get(1).is_some_and(|step| step == "repair")
                && root.get(1).is_some_and(|step| *step == "spawn");
            let rooted: Vec<&str> = if under_repair {
                let mut rewritten = vec!["data", "spawn"];
                rewritten.extend(path.iter().skip(2).map(String::as_str));
                rewritten
            } else {
                path.iter().map(String::as_str).collect()
            };
            rooted.len() >= root.len() && &rooted[..root.len()] == *root
        })
    }

    #[test]
    fn an_unknown_field_is_refused_at_every_object_boundary_of_every_transaction() {
        // `refusals[24]`: unknown fields in topology transaction payloads are
        // refused, and only informational events are lenient. Recursively —
        // a payload that denied at its top and ignored a stray key three levels
        // down would be a transaction carrying meaning this binary does not
        // understand, which is the whole thing the rule forbids.
        //
        // The paths are enumerated from the canonical payloads rather than
        // sampled, so a nested structure nobody remembered is covered by
        // construction and a new one is covered the day it is added.
        let mut visited = 0_usize;
        let mut lenient = 0_usize;
        for (body, canonical) in every_kind().iter().zip(canonical_events()) {
            let kind = body.kind();
            let mut paths = Vec::new();
            object_paths(&canonical, Vec::new(), &mut paths);
            assert!(
                paths.len() > 1,
                "{kind} has no nested object to inject into"
            );
            for path in paths {
                if is_open_map(&path) {
                    continue;
                }
                let mut value = canonical.clone();
                walk(&mut value, &path)
                    .and_then(serde_json::Value::as_object_mut)
                    .unwrap_or_else(|| panic!("{kind} {path:?} is not an object"))
                    .insert(
                        "Ünknown Field  ".to_owned(),
                        serde_json::Value::from("injected"),
                    );
                let refused = serde_json::from_value::<TopologyEvent>(value).is_err();
                let expected = !is_informational_payload(kind, &path);
                assert_eq!(
                    refused, expected,
                    "{kind} at {path:?}: refused={refused}, required={expected}"
                );
                visited += 1;
                if !expected {
                    lenient += 1;
                }
            }
        }
        // Pinned rather than bounded: the failure this whole test exists to
        // prevent is a sweep that quietly stops covering something, and a
        // shrinking corpus is exactly as invisible as a shrinking grid. A
        // legitimate new nested object raises this number and says so.
        assert_eq!(
            visited, 130,
            "the corpus covers a different number of object boundaries than it did"
        );
        // Both classes are non-empty, so neither assertion above is vacuously
        // satisfied by a decoder that refuses or accepts everything.
        assert_eq!(
            lenient, 4,
            "the lenient boundaries are the three informational payloads plus \
             capacity_snapshot's one pool object"
        );
    }

    #[test]
    fn a_record_reused_from_the_legacy_schemas_is_read_strictly_inside_a_transaction() {
        // The reconciliation the design forces. `refusals[24]` refuses an
        // unknown field in a *topology transaction payload* and grants no
        // legacy-nested exception; the legacy-unchanged invariant is about the
        // decoder a schema-1..3 log gets, not about which fields schema 4
        // accepts. Both hold at once because the strictness is attached to the
        // schema-4 field, not to `AttemptRecord`.
        //
        // This replaces the assertion A1 shipped, which required the opposite.
        let finished = AttemptFinished4 {
            key: task_key(5),
            generation: GenerationId(2),
            attempt: AttemptNumber(3),
            record: Box::new(attempt_record()),
            settlement: AttemptSettlement::Closed {
                transition: SettlementTransition::Retry,
                lease: LeaseDisposition::PredictedRetained,
            },
        };
        let mut value = payload_of(&TopologyEventBody::AttemptFinished {
            data: Box::new(finished),
        });
        value["data"]["record"]
            .as_object_mut()
            .expect("legacy record")
            .insert("future_column".to_owned(), serde_json::Value::from(1));
        assert!(
            serde_json::from_value::<TopologyEvent>(value).is_err(),
            "a schema-4 transaction accepted an unknown field in an embedded legacy record"
        );

        // And the same bytes still read exactly as they always did through the
        // legacy type itself: the schema-1..3 decoder is untouched.
        let mut legacy = serde_json::to_value(attempt_record()).expect("serialize");
        legacy
            .as_object_mut()
            .expect("object")
            .insert("future_column".to_owned(), serde_json::Value::from(1));
        assert!(
            serde_json::from_value::<AttemptRecord>(legacy).is_ok(),
            "tightening reached the legacy decoder"
        );
    }

    #[test]
    fn a_known_null_survives_the_strict_door_and_an_unknown_null_does_not() {
        // The strict door decides "unknown" by asking the record which keys it
        // claims back. That is exact only while every embedded record
        // serializes each field it deserializes — no `skip_serializing_if` —
        // and this is where that precondition is checked rather than assumed.
        // `cost_usd` and `session_id` are the optional fields of the attempt
        // record; supplied as an explicit null they are known, absent-valued
        // fields and must pass.
        let mut record = serde_json::to_value(attempt_record()).expect("serialize");
        let object = record.as_object_mut().expect("object");
        object.insert("cost_usd".to_owned(), serde_json::Value::Null);
        object.insert("session_id".to_owned(), serde_json::Value::Null);
        let mut value = payload_of(&TopologyEventBody::AttemptFinished {
            data: Box::new(AttemptFinished4 {
                key: task_key(5),
                generation: GenerationId(2),
                attempt: AttemptNumber(3),
                record: Box::new(attempt_record()),
                settlement: AttemptSettlement::Closed {
                    transition: SettlementTransition::Succeeded,
                    lease: LeaseDisposition::PredictedReleased,
                },
            }),
        });
        value["data"]["record"] = record.clone();
        let parsed: TopologyEvent =
            serde_json::from_value(value.clone()).expect("an explicit null is a known value");
        let TopologyEventBody::AttemptFinished { data } = parsed.body else {
            unreachable!("built as an attempt_finished")
        };
        assert_eq!(data.record.cost_usd, None);
        assert_eq!(data.record.session_id, None);

        // A null under a key the record does not claim is still unknown.
        value["data"]["record"]
            .as_object_mut()
            .expect("object")
            .insert("future_column".to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<TopologyEvent>(value).is_err());
    }

    #[test]
    fn every_required_payload_field_is_refused_when_it_is_absent() {
        // A field made `#[serde(default)]` on input accepts a truncated durable
        // record and round-trips unchanged, so no round trip can see it.
        // Schema 4 has no ancestors — there is no upgrade into it — so every
        // absent field is a refusal rather than a default, and the way to prove
        // that is to take each one away.
        //
        // A key whose value is `null` is excluded: for an `Option` field the
        // absent key and the null key are the same durable answer, and the
        // distinction the design draws is between a value and no record at all.
        let mut deletions = 0_usize;
        for (body, canonical) in every_kind().iter().zip(canonical_events()) {
            let kind = body.kind();
            if !body.is_transaction() {
                continue;
            }
            let mut paths = Vec::new();
            object_paths(&canonical, Vec::new(), &mut paths);
            for path in paths {
                if is_open_map(&path) || embeds_a_legacy_record(&path) {
                    continue;
                }
                let keys: Vec<String> = {
                    let mut probe = canonical.clone();
                    walk(&mut probe, &path)
                        .and_then(|node| node.as_object().cloned())
                        .unwrap_or_else(|| panic!("{kind} {path:?}"))
                        .into_iter()
                        .filter(|(_, value)| !value.is_null())
                        .map(|(key, _)| key)
                        .collect()
                };
                for key in keys {
                    let mut value = canonical.clone();
                    walk(&mut value, &path)
                        .and_then(serde_json::Value::as_object_mut)
                        .expect("object")
                        .remove(&key)
                        .expect("present");
                    assert!(
                        serde_json::from_value::<TopologyEvent>(value).is_err(),
                        "{kind} was accepted without {path:?}.{key}"
                    );
                    deletions += 1;
                }
            }
        }
        // Pinned rather than bounded, for the same reason the injection sweep
        // is: a sweep that quietly stops covering a field is exactly as
        // invisible as a grid that quietly stops at 6.
        assert_eq!(
            deletions, 376,
            "the corpus requires a different number of fields than it did"
        );
    }

    // ------------------------------------------------------------------
    // Runner identity (INV-23)
    // ------------------------------------------------------------------

    /// One way to move exactly one identity field of a runner record.
    type MoveRunner = fn(&mut RunnerPolicy);

    /// One way to move exactly one field of a rung binding, and its name.
    type NamedBindingMove = (&'static str, fn(&mut RungBinding));

    #[test]
    fn a_runner_record_differs_in_the_field_that_moved_and_no_other() {
        // Crossed over every field the design names, each moved on its own
        // against a base whose fields are already distinct from one another.
        // A comparison that read one field and reported the rest would satisfy
        // any single example.
        let cases: Vec<(RunnerField, MoveRunner)> = vec![
            (RunnerField::Kind, |policy| {
                policy.kind = RunnerKind::Host;
            }),
            (RunnerField::Policy, |policy| {
                policy.policy = RunnerContract::HostV1;
            }),
            (RunnerField::ImageReference, |policy| {
                if let Some(image) = policy.image.as_mut() {
                    image.reference = "ghcr.io/Example-Org/tactus-Runner:v2.2".to_owned();
                }
            }),
            (RunnerField::ImageId, |policy| {
                if let Some(image) = policy.image.as_mut() {
                    image.id =
                        "sha256:00000000000000000000000000000000000000000000000000000000deadbeef"
                            .to_owned();
                }
            }),
            (RunnerField::ImageDigest, |policy| {
                if let Some(image) = policy.image.as_mut() {
                    image.digest = None;
                }
            }),
            (RunnerField::ImagePresence, |policy| {
                policy.image = None;
            }),
            (RunnerField::CredentialVolumes, |policy| {
                policy.credential_volumes = Some(volumes(&[
                    ("zeta-agent", "tactus-creds-Zeta"),
                    ("alpha-agent", "tactus-creds-ALPHA  "),
                    ("mid-agent", "tactus-creds-Mid"),
                ]));
            }),
        ];

        let base = container_runner();
        assert_eq!(base.difference(&base.clone()), None);
        assert_eq!(base, base.clone());

        for (field, moved) in cases {
            let mut other = base.clone();
            moved(&mut other);
            assert_ne!(other, base, "moving {field} left the record equal");
            assert_eq!(
                base.difference(&other),
                Some(field),
                "moving {field} was reported as something else"
            );
            // Symmetric: which side is the record and which the incarnation
            // does not change what moved.
            assert_eq!(other.difference(&base), Some(field));
        }
    }

    #[test]
    fn the_first_difference_reported_is_the_most_structural_one() {
        // A record that changed kind has not merely moved its image, and
        // telling an operator to check their tag when the run changed
        // confinement boundary sends them to the wrong place.
        let base = container_runner();
        let mut wholly_different = host_runner();
        wholly_different.image = base.image.clone();
        assert_eq!(base.difference(&wholly_different), Some(RunnerField::Kind));

        let mut policy_only = base.clone();
        policy_only.policy = RunnerContract::HostV1;
        if let Some(image) = policy_only.image.as_mut() {
            image.id = "sha256:different".to_owned();
        }
        assert_eq!(base.difference(&policy_only), Some(RunnerField::Policy));
    }

    #[test]
    fn a_credential_volume_set_is_a_set_and_not_an_ordered_list() {
        // Two incarnations that enumerated the same volumes in different
        // orders established the same runner. A list here would refuse a
        // resume for the order a directory listing came back in.
        let forwards = container_runner();
        let mut backwards = container_runner();
        backwards.credential_volumes = Some(volumes(&[
            ("alpha-agent", "tactus-creds-ALPHA  "),
            ("zeta-agent", "tactus-creds-Zeta"),
        ]));
        assert_eq!(forwards.difference(&backwards), None);
        assert_eq!(forwards, backwards);

        // But the contents are compared exactly: an added agent, a removed
        // one, and a renamed volume for the same agent are all differences.
        for changed in [
            volumes(&[
                ("zeta-agent", "tactus-creds-Zeta"),
                ("alpha-agent", "tactus-creds-ALPHA  "),
                ("mid-agent", "tactus-creds-Mid"),
            ]),
            volumes(&[("zeta-agent", "tactus-creds-Zeta")]),
            volumes(&[
                ("zeta-agent", "tactus-creds-Zeta"),
                ("alpha-agent", "tactus-creds-alpha"),
            ]),
            BTreeMap::new(),
        ] {
            let mut other = container_runner();
            other.credential_volumes = Some(changed);
            assert_eq!(
                forwards.difference(&other),
                Some(RunnerField::CredentialVolumes)
            );
        }

        // An empty record and no record at all are different answers.
        let mut empty = container_runner();
        empty.credential_volumes = Some(BTreeMap::new());
        let mut absent = container_runner();
        absent.credential_volumes = None;
        assert_eq!(
            empty.difference(&absent),
            Some(RunnerField::CredentialVolumes)
        );
    }

    /// The contract-to-kind mapping the packet fixes, as a literal table.
    ///
    /// Not `RunnerContract::kind()`: the completeness grid below is about
    /// whether a record's contract belongs to its kind, and an oracle that
    /// asked the mapping under test what it thought would move with it. A
    /// mapping that sent `host-v1` to `Container` would then refuse every host
    /// run while the grid derived the same wrong expectation and passed.
    fn frozen_kind_of(contract: RunnerContract) -> RunnerKind {
        match contract {
            RunnerContract::HostV1 => RunnerKind::Host,
            RunnerContract::ContainerV1 => RunnerKind::Container,
        }
    }

    #[test]
    fn each_runner_contract_belongs_to_the_kind_the_packet_gives_it() {
        // `decisions.sequential_substrate.runner`: `host-v1` is the host
        // contract and `container-v1` is the container one. Pinned against
        // literals so the grid below has an oracle that cannot move with the
        // implementation.
        assert_eq!(RunnerContract::HostV1.kind(), RunnerKind::Host);
        assert_eq!(RunnerContract::ContainerV1.kind(), RunnerKind::Container);
        assert_ne!(
            RunnerContract::HostV1.kind(),
            RunnerContract::ContainerV1.kind()
        );
        for contract in [RunnerContract::HostV1, RunnerContract::ContainerV1] {
            assert_eq!(contract.kind(), frozen_kind_of(contract));
        }
    }

    /// Every image record the completeness rule distinguishes.
    ///
    /// The digest is crossed *independently* of the reference and the id: a
    /// grid whose only valid image has no digest never asks what a complete
    /// record with one does, so a rule that rejected every reported digest
    /// would pass it.
    fn image_grid() -> Vec<Option<ImageIdentity>> {
        let mut images = vec![None];
        for reference in ["ghcr.io/Example-Org/tactus-Runner:v2.1", ""] {
            for id in ["sha256:1122", ""] {
                for digest in [None, Some("sha256:ffee".to_owned())] {
                    images.push(Some(ImageIdentity {
                        reference: reference.to_owned(),
                        id: id.to_owned(),
                        digest,
                    }));
                }
            }
        }
        images
    }

    #[test]
    fn runner_completeness_is_decided_over_every_kind_and_field_combination() {
        let mut cells = 0_u32;
        let mut complete = 0_u32;
        for kind in [RunnerKind::Host, RunnerKind::Container] {
            for contract in [RunnerContract::HostV1, RunnerContract::ContainerV1] {
                for image in image_grid() {
                    for creds in [None, Some(BTreeMap::new()), Some(volumes(&[("a", "v")]))] {
                        let policy = RunnerPolicy {
                            kind,
                            policy: contract,
                            image: image.clone(),
                            credential_volumes: creds.clone(),
                        };
                        // The rule, restated from the design rather than read
                        // off the implementation.
                        let expected = if frozen_kind_of(contract) != kind {
                            Err(RunnerRecordDefect::ContractDoesNotMatchKind)
                        } else {
                            match kind {
                                RunnerKind::Host => {
                                    if image.is_some() || creds.is_some() {
                                        Err(RunnerRecordDefect::HostWithContainerFields)
                                    } else {
                                        Ok(())
                                    }
                                }
                                RunnerKind::Container => match &image {
                                    None => Err(RunnerRecordDefect::ContainerWithoutImage),
                                    Some(image)
                                        if image.reference.is_empty() || image.id.is_empty() =>
                                    {
                                        Err(RunnerRecordDefect::ImageNotIdentified)
                                    }
                                    Some(_) if creds.is_none() => {
                                        Err(RunnerRecordDefect::ContainerWithoutCredentialVolumes)
                                    }
                                    Some(_) => Ok(()),
                                },
                            }
                        };
                        assert_eq!(
                            policy.completeness(),
                            expected,
                            "kind {kind:?}, contract {contract:?}, image {image:?}, creds {creds:?}"
                        );
                        cells += 1;
                        if expected.is_ok() {
                            complete += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cells, 2 * 2 * 9 * 3, "the grid was not crossed in full");
        // Non-vacuous in both directions, and specifically: a valid container
        // record *with* a reported digest is among the accepted cells.
        assert!(complete > 0 && complete < cells);
        assert_eq!(
            RunnerPolicy {
                kind: RunnerKind::Container,
                policy: RunnerContract::ContainerV1,
                image: Some(ImageIdentity {
                    reference: "ghcr.io/Example-Org/tactus-Runner:v2.1".to_owned(),
                    id: "sha256:1122".to_owned(),
                    digest: Some("sha256:ffee".to_owned()),
                }),
                credential_volumes: Some(volumes(&[("a", "v")])),
            }
            .completeness(),
            Ok(()),
            "an ordinary complete container record with a reported digest was refused"
        );
    }

    #[test]
    fn a_missing_digest_is_a_complete_record_but_not_an_equal_one() {
        // The digest is the manifest digest *when reported*, so a runtime that
        // reports none still produces a re-establishable record. It is
        // compared all the same: a record that gained or lost one changed.
        let mut without = container_runner();
        if let Some(image) = without.image.as_mut() {
            image.digest = None;
        }
        assert_eq!(without.completeness(), Ok(()));
        assert_eq!(
            container_runner().difference(&without),
            Some(RunnerField::ImageDigest)
        );
    }

    #[test]
    fn two_independently_built_identical_runners_are_the_same_runner() {
        // A2 refuses a resume on any `Some(field)`, so a comparator that
        // reported a difference between a record and its own twin would refuse
        // every resume of the shape it got wrong. Each pair below is built
        // twice from scratch rather than cloned, and each is a shape the
        // existing equal-runner coverage never had: a complete host record
        // (no image, no volumes), a container whose runtime reported no digest,
        // and a container whose agents need no credentials at all.
        let pairs: Vec<(&str, RunnerPolicy, RunnerPolicy)> = vec![
            ("a complete host runner", host_runner(), host_runner()),
            (
                "a container whose runtime reported no digest",
                no_digest_runner(),
                no_digest_runner(),
            ),
            (
                "a container needing no credentials",
                empty_credentials_runner(),
                empty_credentials_runner(),
            ),
            (
                "an ordinary container",
                container_runner(),
                container_runner(),
            ),
        ];
        for (name, mine, theirs) in pairs {
            assert_eq!(
                mine.completeness(),
                Ok(()),
                "{name} is not a complete record"
            );
            assert_eq!(mine, theirs, "{name} is not equal to itself");
            assert_eq!(mine.difference(&theirs), None, "{name} differs from itself");
            assert_eq!(
                theirs.difference(&mine),
                None,
                "{name} differs from itself the other way round"
            );
        }
    }

    /// A container whose runtime reported no manifest digest. Complete by the
    /// packet's when-reported rule, and a shape a resume must accept twice.
    fn no_digest_runner() -> RunnerPolicy {
        let mut policy = container_runner();
        if let Some(image) = policy.image.as_mut() {
            image.digest = None;
        }
        policy
    }

    /// A container whose agents need no credentials. An empty map is a record;
    /// `None` is the absence of one, and the two are different answers.
    fn empty_credentials_runner() -> RunnerPolicy {
        let mut policy = container_runner();
        policy.credential_volumes = Some(BTreeMap::new());
        policy
    }

    #[test]
    fn an_image_id_is_compared_byte_for_byte_in_both_directions() {
        // INV-23 requires the re-established image id to equal the recorded one
        // exactly. A mover that swaps the whole value proves only that the
        // field is read at all; these change one thing each, and the ASCII-case
        // pair is the one a normalizing comparison survives.
        let base_id = "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        let movers: [(&str, String); 6] = [
            ("one interior byte", base_id.replacen("55", "45", 1)),
            ("ASCII case only", base_id.to_ascii_uppercase()),
            ("the first byte", format!("Sha256{}", &base_id[6..])),
            (
                "the last byte",
                format!("{}0", &base_id[..base_id.len() - 1]),
            ),
            ("a longer id with the same prefix", format!("{base_id}00")),
            (
                "a shorter id with the same prefix",
                base_id[..base_id.len() - 2].to_owned(),
            ),
        ];
        for (name, moved) in movers {
            assert_ne!(moved, base_id, "the {name} mover did not move anything");
            let mut other = container_runner();
            other
                .image
                .as_mut()
                .expect("a container image")
                .id
                .clone_from(&moved);
            assert_eq!(
                container_runner().difference(&other),
                Some(RunnerField::ImageId),
                "an id differing by {name} was accepted"
            );
            assert_eq!(
                other.difference(&container_runner()),
                Some(RunnerField::ImageId)
            );
        }
    }

    #[test]
    fn a_credential_volume_name_is_compared_byte_for_byte_at_a_fixed_key() {
        // INV-23 again, on the other side of the map. Every mover below keeps
        // the keys, the cardinality and the pairing identical and changes one
        // property of one value, so a comparison that lower-cased, trimmed, or
        // compared lengths fails on exactly the mover that isolates it.
        let base = "tactus-creds-Zeta";
        let movers: [(&str, String); 6] = [
            ("ASCII case only", base.to_ascii_lowercase()),
            ("trailing whitespace only", format!("{base}  ")),
            ("leading whitespace only", format!("  {base}")),
            ("one interior byte", base.replacen("creds", "cred5", 1)),
            ("a multi-byte character", base.replacen('Z', "Ü", 1)),
            ("length alone", format!("{base}{base}")),
        ];
        for (name, moved) in movers {
            assert_ne!(moved, base, "the {name} mover did not move anything");
            let mut other = container_runner();
            other.credential_volumes = Some(volumes(&[
                ("zeta-agent", moved.as_str()),
                ("alpha-agent", "tactus-creds-ALPHA  "),
            ]));
            assert_eq!(
                container_runner().difference(&other),
                Some(RunnerField::CredentialVolumes),
                "a volume name differing by {name} was accepted"
            );
            assert_eq!(
                other.difference(&container_runner()),
                Some(RunnerField::CredentialVolumes)
            );
        }
    }

    // ------------------------------------------------------------------
    // Test-owned oracles for the vocabulary itself
    // ------------------------------------------------------------------

    /// The twenty-four tags a schema-4 log can carry, and whether a fold
    /// applies each one.
    ///
    /// Written down here, in this test module, from the frozen contract.
    /// `TOPOLOGY_EVENT_KINDS`, `kind()` and `is_transaction()` are three
    /// declarations of the same facts in production, and a mutation that moves
    /// all three together is invisible to any test that compares them with each
    /// other. This is the fourth copy, and the only one that is not production.
    const FROZEN_VOCABULARY: [(&str, bool); 24] = [
        ("run_started", true),
        ("run_resumed", true),
        ("task_spawned", true),
        ("task_dispatched", true),
        ("attempt_started", true),
        ("attempt_finished", true),
        ("attempt_interrupted", true),
        ("generation_closed", true),
        ("defer_wait_elapsed", true),
        ("candidate_prepared", true),
        ("task_candidate_created", true),
        ("merge_verification_started", true),
        ("merge_verification_unavailable", true),
        ("merge_verification_interrupted", true),
        ("merge_prepared", true),
        ("merge_rejected", true),
        ("task_merged", true),
        ("question_raised", true),
        ("question_answered", true),
        ("budget_exceeded", true),
        ("run_finished", true),
        ("capacity_snapshot", false),
        ("pool_exhausted", false),
        ("design_defect", false),
    ];

    #[test]
    fn the_vocabulary_and_its_transaction_class_match_a_test_owned_frozen_table() {
        // Counting 21 and 3 is satisfied by swapping one member of each class,
        // which is exactly the mutation that would make `run_finished` lenient
        // about a payload field the fold reads. So the classes are named, not
        // counted.
        assert_eq!(
            TOPOLOGY_EVENT_KINDS.len(),
            FROZEN_VOCABULARY.len(),
            "the vocabulary changed size"
        );
        for (index, (tag, transactional)) in FROZEN_VOCABULARY.iter().enumerate() {
            assert_eq!(
                &TOPOLOGY_EVENT_KINDS[index], tag,
                "position {index} of the declared vocabulary"
            );
            let body = &every_kind()[index];
            assert_eq!(&body.kind(), tag, "position {index} reports another tag");
            assert_eq!(
                body.is_transaction(),
                *transactional,
                "{tag} is on the wrong side of the transaction boundary"
            );
        }
        let informational: Vec<&str> = FROZEN_VOCABULARY
            .iter()
            .filter(|(_, transactional)| !transactional)
            .map(|(tag, _)| *tag)
            .collect();
        assert_eq!(
            informational,
            vec!["capacity_snapshot", "pool_exhausted", "design_defect"],
            "the lenient class is exactly these three by name"
        );
        assert_eq!(
            FROZEN_VOCABULARY
                .iter()
                .filter(|(_, transactional)| *transactional)
                .count(),
            TOPOLOGY_TRANSACTION_KINDS
        );
    }

    // ------------------------------------------------------------------
    // The writer and the reader, composed
    // ------------------------------------------------------------------

    #[test]
    fn the_run_started_this_module_writes_is_the_header_the_probe_reads() {
        // The two halves of the seam, in one test, over bytes. Separate
        // fixtures for the producer and the decoder let this module's writer
        // vocabulary and `schema::probe_header` drift apart while both stay
        // green — and the first line of the log is exactly where that costs a
        // reader the ability to choose a fold at all.
        use crate::topology::schema::{
            LogHeader, ReaderSelection, TopologyActivation, max_readable_schema, probe_header,
            select_reader_with,
        };

        let plan = sample_plan();
        let event = TopologyEvent {
            ts: "2026-08-17T03:04:05.678Z".to_owned(),
            body: TopologyEventBody::RunStarted {
                data: Box::new(run_started(&plan)),
            },
        };
        let mut bytes = serde_json::to_vec(&event).expect("serialize");
        bytes.push(b'\n');

        assert_eq!(
            probe_header(&bytes),
            Ok(LogHeader {
                event: "run_started".to_owned(),
                schema: TOPOLOGY_SCHEMA,
            }),
            "the header this module writes is not the header the probe reads"
        );
        assert_eq!(
            select_reader_with(&bytes, max_readable_schema(TopologyActivation::Active)),
            Ok(ReaderSelection::Topology)
        );
        assert!(
            select_reader_with(&bytes, max_readable_schema(TopologyActivation::Inactive)).is_err()
        );

        // Without the commit marker the very same bytes are not a header, so
        // the composition is not accidentally reading past the line.
        let torn = &bytes[..bytes.len() - 1];
        assert!(probe_header(torn).is_err());
    }

    #[test]
    fn the_run_header_records_each_resource_identity_in_its_own_slot() {
        // `transaction_fault_matrix[0].durable_state` for a committed run:
        // `run_started` records the integration ref, the base sha, the
        // execution root, the limits, the registry digest, the incarnation and
        // the runner. Recovery compares each against the resource it is about
        // to mutate, so two of them sharing a slot is two resources it can no
        // longer tell apart.
        let plan = sample_plan();
        let started = run_started(&plan);
        let identities = [
            started.integration_ref.as_str(),
            started.base_sha.as_str(),
            started.execution_root.as_str(),
            started.private_dir.as_str(),
            started.branch.as_str(),
            started.run_id.as_str(),
        ];
        let mut distinct: Vec<&str> = identities.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            identities.len(),
            "two resource identities share a value, so a projection that read \
             the wrong one would still agree with itself"
        );
        // And the four the design does not derive from one another share no
        // text at all: a fixture whose execution root contained its private
        // directory would hide a projection that reached for the wrong one.
        // The branch and the run id are excluded deliberately — the branch *is*
        // `tactus/run-<id>` by construction, which is why
        // `canonical_trace_projection` drops ref names containing the run id.
        let independent = [
            started.integration_ref.as_str(),
            started.base_sha.as_str(),
            started.execution_root.as_str(),
            started.private_dir.as_str(),
        ];
        for (outer, first) in independent.iter().enumerate() {
            for (inner, second) in independent.iter().enumerate() {
                assert!(
                    outer == inner || !first.contains(second),
                    "identity {inner} is contained in identity {outer}"
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Accessors that must follow their value rather than their variant
    // ------------------------------------------------------------------

    #[test]
    fn a_halt_is_attributed_to_the_key_its_carrier_names() {
        // Checked once per variant with one key each, a variant-keyed constant
        // satisfies the accessor: `halted_at` would then name a task that
        // failed nothing.
        for key in [0, 1, 5, 19, 4_294_967_295] {
            let failure = HaltCarrier::TaskFailure {
                key: TaskKey(key),
                generation: GenerationId(2),
                attempt: AttemptNumber(3),
            };
            assert_eq!(failure.key(), TaskKey(key));
            let declined = HaltCarrier::DeclinedQuestion {
                key: TaskKey(key),
                question: QuestionId::from("q-park-0007"),
            };
            assert_eq!(declined.key(), TaskKey(key));
        }
        // And through the event, so the carrier the vocabulary builds carries
        // the key the payload names rather than the fixture's usual one.
        for key in [0, 11, 4_294_967_295] {
            let body = TopologyEventBody::AttemptFinished {
                data: Box::new(AttemptFinished4 {
                    key: TaskKey(key),
                    generation: GenerationId(2),
                    attempt: AttemptNumber(3),
                    record: Box::new(attempt_record()),
                    settlement: AttemptSettlement::Closed {
                        transition: SettlementTransition::Failed {
                            halts_run: true,
                            reason: "  ladder exhausted  ".to_owned(),
                        },
                        lease: LeaseDisposition::PredictedReleased,
                    },
                }),
            };
            assert_eq!(
                body.halt_carrier().map(|carrier| carrier.key()),
                Some(TaskKey(key))
            );
        }
    }

    #[test]
    fn a_budget_stop_is_scoped_to_the_exact_epoch_that_hit_the_ceiling() {
        // Checking one epoch exactly and one other for inequality is satisfied
        // by any projection that is injective on the pair tested — masking the
        // low bits keeps `Epoch(2)` exact and `Epoch(3)` different. So every
        // epoch is asserted exactly, across the bits a mask would drop.
        for epoch in [0, 1, 2, 3, 4, 7, 8, 15, 16, 255, 256, u32::MAX] {
            for budget in [BudgetKind::Run, BudgetKind::Task] {
                let event = BudgetExceeded4 {
                    epoch: Epoch(epoch),
                    budget,
                    limit_usd: 50.0,
                    spent_usd: 51.25,
                    key: Some(task_key(4)),
                };
                assert_eq!(
                    event.stop(),
                    BudgetStop {
                        epoch: Epoch(epoch),
                        budget,
                    },
                    "the stop for epoch {epoch} is not that epoch's"
                );
            }
        }
        // The high-bit case said plainly: a mask to the low two bits sends
        // epoch 4 to 0, and a stop attributed to epoch 0 is a stop a resume
        // never clears.
        let event = BudgetExceeded4 {
            epoch: Epoch(4),
            budget: BudgetKind::Run,
            limit_usd: 50.0,
            spent_usd: 51.25,
            key: None,
        };
        assert_eq!(event.stop().epoch, Epoch(4));
        assert_ne!(event.stop().epoch, Epoch(0));
    }

    #[test]
    fn a_topology_schema_is_exactly_four_and_nothing_near_it() {
        // A2's fold gates schema-4 admission on this predicate, and INV-03 says
        // schema 4 is the topology *only*. Testing the adjacent pair 3/4 leaves
        // `>= TOPOLOGY_SCHEMA` indistinguishable from `==`, which admits every
        // future vocabulary as this one.
        let plan = sample_plan();
        let mut topology = 0_u32;
        for schema in [0, 1, 2, 3, 4, 5, 6, 7, 99, 255, 256, u32::MAX] {
            let mut started = run_started(&plan);
            started.schema = schema;
            let is_topology = started.is_topology_schema();
            assert_eq!(
                is_topology,
                schema == TOPOLOGY_SCHEMA,
                "schema {schema} was classified as topology = {is_topology}"
            );
            if is_topology {
                topology += 1;
            }
        }
        assert_eq!(
            topology, 1,
            "exactly one schema in the domain is the topology"
        );
    }

    // ------------------------------------------------------------------
    // merge_prepared relations that live inside one event (INV-09)
    // ------------------------------------------------------------------

    #[test]
    fn the_commit_corpus_shares_no_run_a_comparison_could_key_on() {
        // Every relation in the merge queue is an equality over a full sha,
        // and the fixtures are what decide whether a *partial* comparison
        // could pass. So the property the grids rely on is checked rather than
        // asserted in a comment: the six commits are pairwise distinct, all
        // forty characters, and share no run of eight — long enough that an
        // abbreviation, a prefix hash, or a suffix comparison lands on a
        // difference.
        //
        // SHA_CANDIDATE_ONE_BYTE_OFF is excluded: it exists precisely to share
        // everything but one interior byte with SHA_CANDIDATE, and is checked
        // against it directly in `a_fast_publication_publishes_the_commit_that
        // _was_judged`.
        let corpus = [
            ("candidate", SHA_CANDIDATE),
            ("head", SHA_HEAD),
            ("third", SHA_THIRD),
            ("base", SHA_BASE),
            ("tree", SHA_TREE),
            ("fourth", SHA_FOURTH),
            ("fifth", SHA_FIFTH),
        ];
        for (name, sha) in corpus {
            assert_eq!(sha.len(), 40, "{name} is not a full sha");
            assert!(
                sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{name} is not hex"
            );
        }
        for (outer, (left_name, left)) in corpus.iter().enumerate() {
            for (inner, (right_name, right)) in corpus.iter().enumerate() {
                if outer >= inner {
                    continue;
                }
                assert_ne!(left, right, "{left_name} and {right_name} are the same sha");
                for window in 0..=left.len() - 8 {
                    let run = &left[window..window + 8];
                    assert!(
                        !right.contains(run),
                        "{left_name} and {right_name} share the run `{run}`, so a comparison \
                         keyed on part of a sha could pass"
                    );
                }
            }
        }
    }

    #[test]
    fn merge_prepared_self_consistency_over_the_crossed_disposition_grid() {
        let dispositions = [
            PreparedDisposition::Fast,
            PreparedDisposition::StaleClean,
            PreparedDisposition::AlreadyPresent,
        ];
        let pins = [
            None,
            Some(GitRef::from(
                &format!("refs/tactus/runs/{RUN_ID}/prepared/6")[..],
            )),
        ];
        // Three proposals: the candidate's commit, the expected head, and a
        // third sha belonging to neither. Sampling two of them would let a
        // check compare against the wrong one and still pass.
        let proposals = [
            CommitSha::from(SHA_CANDIDATE),
            CommitSha::from(SHA_HEAD),
            CommitSha::from(SHA_THIRD),
        ];
        // And three candidate commits, crossed independently of the proposal.
        // INV-09's relation is `proposed_sha == the candidate's recorded
        // commit` *whatever that commit is*; a grid built around one candidate
        // sha is satisfied by an implementation keyed on that literal value.
        // How distinct the three are is asserted in
        // `the_commit_corpus_shares_no_run_a_comparison_could_key_on`, not
        // claimed here.
        let candidates = [
            CommitSha::from(SHA_CANDIDATE),
            CommitSha::from(SHA_FOURTH),
            CommitSha::from(SHA_FIFTH),
        ];
        let sources = [
            VerificationSource::CandidatePrepared {
                key: task_key(2),
                generation: GenerationId(4),
            },
            VerificationSource::Verification {
                sequence: SequenceId(6),
            },
        ];
        let records = [
            None,
            Some(verification(VerificationVerdict::Rejected)),
            Some(verification(VerificationVerdict::Passed)),
        ];

        let head = CommitSha::from(SHA_HEAD);
        let mut cells = 0_u32;
        for disposition in dispositions {
            for pin in &pins {
                for proposed in &proposals {
                    for candidate_sha in &candidates {
                        for source in &sources {
                            for record in &records {
                                let event = MergePrepared {
                                    sequence: SequenceId(6),
                                    disposition,
                                    expected_head: head.clone(),
                                    proposed_sha: proposed.clone(),
                                    key: task_key(2),
                                    generation: GenerationId(4),
                                    candidate_sha: candidate_sha.clone(),
                                    candidate_ref: GitRef::from(
                                        &format!("refs/tactus/runs/{RUN_ID}/candidates/2/4")[..],
                                    ),
                                    prepared_ref: pin.clone(),
                                    verification_source: source.clone(),
                                    verification: record.clone(),
                                    satisfies: vec![task_key(2)],
                                };
                                // The rule as the design states it, restated here.
                                let cited_candidate =
                                    matches!(source, VerificationSource::CandidatePrepared { .. });
                                let expected = match disposition {
                                    PreparedDisposition::Fast => {
                                        if pin.is_some() {
                                            Err(PreparedDefect::FastWithPreparedRef)
                                        } else if proposed != candidate_sha {
                                            Err(PreparedDefect::FastProposesAnotherCommit)
                                        } else if !cited_candidate {
                                            Err(PreparedDefect::FastWithoutCandidateSource)
                                        } else {
                                            Ok(())
                                        }
                                    }
                                    PreparedDisposition::StaleClean => {
                                        if pin.is_none() {
                                            Err(PreparedDefect::StaleWithoutPreparedRef)
                                        } else if cited_candidate {
                                            Err(PreparedDefect::VerifiedWithoutVerificationSource)
                                        } else if record.is_none() {
                                            Err(PreparedDefect::VerifiedWithoutRecord)
                                        } else if !record
                                            .as_ref()
                                            .is_some_and(VerificationRecord::passed)
                                        {
                                            Err(PreparedDefect::VerificationDidNotPass)
                                        } else {
                                            Ok(())
                                        }
                                    }
                                    PreparedDisposition::AlreadyPresent => {
                                        if *proposed != head {
                                            Err(PreparedDefect::AlreadyPresentMovesTheHead)
                                        } else if cited_candidate {
                                            Err(PreparedDefect::VerifiedWithoutVerificationSource)
                                        } else if record.is_none() {
                                            Err(PreparedDefect::VerifiedWithoutRecord)
                                        } else if !record
                                            .as_ref()
                                            .is_some_and(VerificationRecord::passed)
                                        {
                                            Err(PreparedDefect::VerificationDidNotPass)
                                        } else {
                                            Ok(())
                                        }
                                    }
                                };
                                assert_eq!(
                                    event.self_consistency(),
                                    expected,
                                    "{disposition:?}, pin {}, proposed {proposed}, candidate \
                                 {candidate_sha}, source {source:?}, record {:?}",
                                    pin.is_some(),
                                    record.as_ref().map(|r| r.verdict)
                                );
                                cells += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(
            cells,
            3 * 2 * 3 * 3 * 2 * 3,
            "the grid was not crossed in full"
        );
    }

    #[test]
    fn a_fast_publication_publishes_the_commit_that_was_judged() {
        // The shape that must be accepted, stated once so the grid above
        // cannot be satisfied by refusing everything.
        assert_eq!(merge_prepared_fast().self_consistency(), Ok(()));
        assert_eq!(
            merge_prepared_fast().proposed_sha,
            merge_prepared_fast().candidate_sha
        );
        assert!(merge_prepared_fast().prepared_ref.is_none());
        assert!(merge_prepared_fast().verification.is_none());

        // And the relation is byte-exact. A proposal one interior byte away
        // from the candidate's recorded commit shares its first twenty and
        // last nineteen characters and its length, so a comparison that
        // abbreviated — which is what `core.abbrev` does to every sha an
        // operator ever sees — would publish an object nobody judged.
        let mut near = merge_prepared_fast();
        near.proposed_sha = CommitSha::from(SHA_CANDIDATE_ONE_BYTE_OFF);
        assert_ne!(near.proposed_sha.as_str(), SHA_CANDIDATE);
        assert_eq!(near.proposed_sha.as_str().len(), SHA_CANDIDATE.len());
        assert_eq!(
            near.self_consistency(),
            Err(PreparedDefect::FastProposesAnotherCommit)
        );
        // Symmetrically, with the candidate moved instead of the proposal.
        let mut other = merge_prepared_fast();
        other.candidate_sha = CommitSha::from(SHA_CANDIDATE_ONE_BYTE_OFF);
        assert_eq!(
            other.self_consistency(),
            Err(PreparedDefect::FastProposesAnotherCommit)
        );
    }

    #[test]
    fn a_candidate_commit_is_parented_on_the_base_its_worktree_used() {
        let candidate = candidate_prepared();
        assert!(candidate.parent_is_base());
        assert_eq!(candidate.candidate().commit_sha, candidate.commit_sha);
        assert_eq!(candidate.candidate().key, candidate.key);

        let mut moved = candidate_prepared();
        moved.parent_sha = CommitSha::from(SHA_THIRD);
        assert!(!moved.parent_is_base());

        // And the other direction: moving the base, not the parent.
        let mut rebased = candidate_prepared();
        rebased.base_sha = CommitSha::from(SHA_HEAD);
        assert!(!rebased.parent_is_base());

        // Full equality, not a prefix, a suffix or a length. Every pair below
        // is unequal while agreeing everywhere a partial comparison would
        // look — and a commit parented somewhere other than its worktree base
        // fast-forwards the integration ref onto history nobody judged, so the
        // cheap comparison is the expensive bug.
        let base = SHA_BASE;
        let near: [(&str, String); 4] = [
            ("one interior byte", base.replacen("2b1c", "2b1d", 1)),
            ("the same first character", format!("5{}", &SHA_THIRD[1..])),
            (
                "the same last character",
                format!("{}f", &SHA_THIRD[..SHA_THIRD.len() - 1]),
            ),
            (
                "the same first and last characters",
                format!("5{}f", &SHA_THIRD[1..SHA_THIRD.len() - 1]),
            ),
        ];
        for (name, parent) in near {
            assert_ne!(parent, base, "the {name} case did not move anything");
            assert_eq!(parent.len(), base.len(), "{name} changed the length");
            let mut candidate = candidate_prepared();
            candidate.parent_sha = CommitSha::from(&parent[..]);
            assert!(
                !candidate.parent_is_base(),
                "a parent differing by {name} was accepted as the base"
            );
            // And symmetrically, with the base moved instead of the parent.
            let mut other = candidate_prepared();
            other.base_sha = CommitSha::from(&parent[..]);
            assert!(!other.parent_is_base(), "{name}, moved on the base");
        }
    }

    // ------------------------------------------------------------------
    // Halting
    // ------------------------------------------------------------------

    fn finished_with(settlement: AttemptSettlement) -> TopologyEventBody {
        TopologyEventBody::AttemptFinished {
            data: Box::new(AttemptFinished4 {
                key: task_key(5),
                generation: GenerationId(2),
                attempt: AttemptNumber(3),
                record: Box::new(attempt_record()),
                settlement,
            }),
        }
    }

    fn answered_with(answer: Answer4) -> TopologyEventBody {
        TopologyEventBody::QuestionAnswered {
            data: QuestionAnswered4 {
                key: task_key(3),
                question: QuestionId::from("q-park-0007"),
                answer,
                via: "terminal".to_owned(),
            },
        }
    }

    #[test]
    fn exactly_two_carriers_can_halt_a_run_and_only_when_their_policy_says_so() {
        // Every settlement and every answer, crossed against the carriers the
        // design names. The near-misses are the point: an outage that parked,
        // a deferral, an interruption, a run-ending closure, and a terminal
        // failure the run's policy does not halt on all look like the end of
        // something and none of them ends the run.
        let halting = [
            (
                finished_with(AttemptSettlement::Closed {
                    transition: SettlementTransition::Failed {
                        halts_run: true,
                        reason: "  ladder exhausted  ".to_owned(),
                    },
                    lease: LeaseDisposition::PredictedReleased,
                }),
                HaltCarrier::TaskFailure {
                    key: task_key(5),
                    generation: GenerationId(2),
                    attempt: AttemptNumber(3),
                },
            ),
            (
                answered_with(Answer4::Declined {
                    decline_halts_run: true,
                }),
                HaltCarrier::DeclinedQuestion {
                    key: task_key(3),
                    question: QuestionId::from("q-park-0007"),
                },
            ),
        ];
        for (body, carrier) in halting {
            assert_eq!(
                body.halt_carrier(),
                Some(carrier.clone()),
                "{}",
                body.kind()
            );
            assert_eq!(carrier.key(), body.key().expect("a halt is attributed"));
        }

        let non_halting = vec![
            finished_with(AttemptSettlement::Closed {
                transition: SettlementTransition::Failed {
                    halts_run: false,
                    reason: "  ladder exhausted, run continues  ".to_owned(),
                },
                lease: LeaseDisposition::PredictedReleased,
            }),
            finished_with(AttemptSettlement::Closed {
                transition: SettlementTransition::Deferred {
                    defers: 2,
                    reason: "rate limited".to_owned(),
                },
                lease: LeaseDisposition::PredictedReleased,
            }),
            finished_with(AttemptSettlement::Closed {
                transition: SettlementTransition::Parked {
                    question: frozen_question("q-park-0008", task_key(5)),
                },
                lease: LeaseDisposition::PredictedReleased,
            }),
            finished_with(AttemptSettlement::Closed {
                transition: SettlementTransition::Retry,
                lease: LeaseDisposition::PredictedRetained,
            }),
            finished_with(AttemptSettlement::Closed {
                transition: SettlementTransition::Escalated { rung: 1 },
                lease: LeaseDisposition::PredictedReleased,
            }),
            finished_with(AttemptSettlement::Closed {
                transition: SettlementTransition::Succeeded,
                lease: LeaseDisposition::LineageHeld,
            }),
            finished_with(AttemptSettlement::Retained {
                retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                retained_incarnation: Epoch(5),
            }),
            answered_with(Answer4::Declined {
                decline_halts_run: false,
            }),
            answered_with(Answer4::Answered {
                option_index: 0,
                binding_override: None,
            }),
            TopologyEventBody::MergeVerificationUnavailable {
                data: MergeVerificationUnavailable {
                    sequence: SequenceId(6),
                    cause: UnavailableCause::HumanRequired {
                        verdict: "  a licence question  ".to_owned(),
                    },
                    outcome: UnavailableOutcome::Parked {
                        question: frozen_question("q-verify-0001", task_key(2)),
                    },
                },
            },
            TopologyEventBody::GenerationClosed {
                data: GenerationClosed {
                    key: task_key(6),
                    generation: GenerationId(3),
                    reason: GenerationCloseReason::RunEnding {
                        outcome: RunOutcome::Halted,
                    },
                    lease: LeaseDisposition::PredictedReleased,
                },
            },
        ];
        for body in non_halting {
            assert_eq!(body.halt_carrier(), None, "{} halted the run", body.kind());
        }

        // And none of the ordinary vocabulary carries a halt either.
        for body in every_kind() {
            assert_eq!(body.halt_carrier(), None, "{}", body.kind());
        }
    }

    #[test]
    fn a_settlement_retains_a_session_only_when_it_retained_the_generation() {
        let retained = AttemptFinished4 {
            key: task_key(5),
            generation: GenerationId(2),
            attempt: AttemptNumber(3),
            record: Box::new(attempt_record()),
            settlement: AttemptSettlement::Retained {
                retained_session: SessionId("sess-ÜNI-0042".to_owned()),
                retained_incarnation: Epoch(5),
            },
        };
        assert_eq!(
            retained.retained(),
            Some((&SessionId("sess-ÜNI-0042".to_owned()), Epoch(5)))
        );
        assert!(!retained.halts_run());

        for transition in [
            SettlementTransition::Succeeded,
            SettlementTransition::Retry,
            SettlementTransition::Escalated { rung: 1 },
            SettlementTransition::Deferred {
                defers: 1,
                reason: "rate limited".to_owned(),
            },
            SettlementTransition::Parked {
                question: frozen_question("q", task_key(5)),
            },
            SettlementTransition::Failed {
                halts_run: true,
                reason: "gone".to_owned(),
            },
        ] {
            let halting = matches!(transition, SettlementTransition::Failed { .. });
            let closed = AttemptFinished4 {
                settlement: AttemptSettlement::Closed {
                    transition,
                    lease: LeaseDisposition::PredictedReleased,
                },
                ..retained.clone()
            };
            assert_eq!(closed.retained(), None);
            assert_eq!(closed.halts_run(), halting);
        }
    }

    // ------------------------------------------------------------------
    // Answers and binding overrides
    // ------------------------------------------------------------------

    #[test]
    fn an_answer_and_its_override_must_name_the_same_question_task_and_option() {
        // 2^3 over the three identity fields, crossed against values chosen so
        // that no cheaper relation than equality satisfies the grid: the
        // unequal task keys include a same-parity pair (3/5) and a pair
        // differing only above the low bits (4/12), the unequal questions share
        // a prefix and a length, and the unequal options are 2/10 rather than
        // 2/1. A check that compared parity, a low bit, or a first character
        // would otherwise pass every cell.
        let outer_keys = [3_u32, 4, 12];
        let other_keys = [5_u32, 12, 4];
        let options = [(2_u32, 10_u32), (0, 8), (7, 15)];
        let questions = [
            ("q-park-0007", "q-park-0005"),
            ("q-park-0007", "q-park-0017"),
            ("q-park-0000", "q-park-0000-b"),
        ];
        let mut cells = 0_u32;
        for index in 0..outer_keys.len() {
            let (chosen_option, other_option) = options[index];
            let (asked, other_question) = questions[index];
            for same_question in [true, false] {
                for same_key in [true, false] {
                    for same_option in [true, false] {
                        let answered = QuestionAnswered4 {
                            key: task_key(outer_keys[index]),
                            question: QuestionId::from(asked),
                            answer: Answer4::Answered {
                                option_index: chosen_option,
                                binding_override: Some(BindingOverride {
                                    key: if same_key {
                                        task_key(outer_keys[index])
                                    } else {
                                        task_key(other_keys[index])
                                    },
                                    question: QuestionId::from(if same_question {
                                        asked
                                    } else {
                                        other_question
                                    }),
                                    option_index: if same_option {
                                        chosen_option
                                    } else {
                                        other_option
                                    },
                                    agent: "codex".to_owned(),
                                    model: "gpt-5.6-sol".to_owned(),
                                    effort: Effort::XHigh,
                                }),
                            },
                            via: "terminal".to_owned(),
                        };
                        cells += 1;
                        let expected = if !same_question {
                            Err(AnswerDefect::OverrideNamesAnotherQuestion)
                        } else if !same_key {
                            Err(AnswerDefect::OverrideNamesAnotherTask)
                        } else if !same_option {
                            Err(AnswerDefect::OverrideNamesAnotherOption)
                        } else {
                            Ok(())
                        };
                        assert_eq!(
                            answered.self_consistency(),
                            expected,
                            "question {same_question}, key {same_key}, option {same_option}, \
                         values {index}"
                        );
                    }
                }
            }
        }
        assert_eq!(cells, 3 * 2 * 2 * 2, "the grid was not crossed in full");

        // An answer without an override, and a decline, have nothing to
        // disagree with.
        for answer in [
            Answer4::Answered {
                option_index: 0,
                binding_override: None,
            },
            Answer4::Declined {
                decline_halts_run: true,
            },
            Answer4::Declined {
                decline_halts_run: false,
            },
        ] {
            let TopologyEventBody::QuestionAnswered { data } = answered_with(answer) else {
                unreachable!("built as a question_answered")
            };
            assert_eq!(data.self_consistency(), Ok(()));
        }
    }

    #[test]
    fn a_question_is_complete_only_when_it_can_actually_be_answered() {
        let complete = frozen_question("q-park-0007", task_key(3));
        assert!(complete.is_complete());

        let mut no_options = complete.clone();
        no_options.options.clear();
        assert!(!no_options.is_complete());

        let mut no_context = complete.clone();
        no_context.context = "   ".to_owned();
        assert!(!no_context.is_complete());

        let mut no_id = complete.clone();
        no_id.id = QuestionId::from("  ");
        assert!(!no_id.is_complete());

        // A single option is enough; the bar is answerable, not plural.
        let mut one_option = complete;
        one_option.options = vec!["proceed".to_owned()];
        assert!(one_option.is_complete());
    }

    // ------------------------------------------------------------------
    // Verification outages
    // ------------------------------------------------------------------

    #[test]
    fn a_human_finding_always_parks_and_a_park_always_carries_an_answerable_question() {
        let causes = [
            UnavailableCause::HumanRequired {
                verdict: "  a licence question  ".to_owned(),
            },
            UnavailableCause::Infrastructure {
                kind: InfrastructureKind::RateLimited,
            },
            UnavailableCause::Infrastructure {
                kind: InfrastructureKind::ReviewUnavailable,
            },
            UnavailableCause::Infrastructure {
                kind: InfrastructureKind::ReviewerTimeout,
            },
            UnavailableCause::Infrastructure {
                kind: InfrastructureKind::RunnerSpawnFailure,
            },
            UnavailableCause::Infrastructure {
                kind: InfrastructureKind::Other {
                    detail: "  the registry returned 503  ".to_owned(),
                },
            },
        ];
        let mut incomplete = frozen_question("q-verify-0001", task_key(2));
        incomplete.options.clear();
        let outcomes = [
            UnavailableOutcome::Deferred { defers: 0 },
            UnavailableOutcome::Deferred { defers: 3 },
            UnavailableOutcome::Parked {
                question: frozen_question("q-verify-0001", task_key(2)),
            },
            UnavailableOutcome::Parked {
                question: incomplete,
            },
        ];

        for cause in &causes {
            for outcome in &outcomes {
                let event = MergeVerificationUnavailable {
                    sequence: SequenceId(6),
                    cause: cause.clone(),
                    outcome: outcome.clone(),
                };
                let human = matches!(cause, UnavailableCause::HumanRequired { .. });
                let parked = matches!(outcome, UnavailableOutcome::Parked { .. });
                let answerable = match outcome {
                    UnavailableOutcome::Parked { question } => question.is_complete(),
                    UnavailableOutcome::Deferred { .. } => true,
                };
                let expected = if human && !parked {
                    Err(UnavailableDefect::HumanRequiredWithoutPark)
                } else if parked && !answerable {
                    Err(UnavailableDefect::ParkedWithoutCompleteQuestion)
                } else {
                    Ok(())
                };
                assert_eq!(
                    event.self_consistency(),
                    expected,
                    "cause {cause:?}, outcome {outcome:?}"
                );
            }
        }
    }

    #[test]
    fn every_infrastructure_kind_is_distinguishable_on_the_wire() {
        // Including the open-ended one: an outage nobody enumerated must still
        // be recordable as itself rather than collapsing into a neighbour.
        let kinds = [
            InfrastructureKind::RateLimited,
            InfrastructureKind::ReviewUnavailable,
            InfrastructureKind::ReviewerTimeout,
            InfrastructureKind::RunnerSpawnFailure,
            InfrastructureKind::Other {
                detail: "  the registry returned 503  ".to_owned(),
            },
            InfrastructureKind::Other {
                detail: "a different outage".to_owned(),
            },
        ];
        let mut rendered: Vec<String> = kinds
            .iter()
            .map(|kind| serde_json::to_string(kind).expect("serialize"))
            .collect();
        for (kind, json) in kinds.iter().zip(&rendered) {
            assert_eq!(
                &serde_json::from_str::<InfrastructureKind>(json).expect("deserialize"),
                kind
            );
        }
        let before = rendered.len();
        rendered.sort();
        rendered.dedup();
        assert_eq!(rendered.len(), before, "two outages serialize identically");
    }

    // ------------------------------------------------------------------
    // Generation closure
    // ------------------------------------------------------------------

    #[test]
    fn every_close_reason_is_distinguishable_including_each_run_ending_outcome() {
        let reasons = [
            GenerationCloseReason::ResumeDiscardsRetainedSession,
            GenerationCloseReason::WorktreeMissing,
            GenerationCloseReason::RunEnding {
                outcome: RunOutcome::Complete,
            },
            GenerationCloseReason::RunEnding {
                outcome: RunOutcome::Parked,
            },
            GenerationCloseReason::RunEnding {
                outcome: RunOutcome::Halted,
            },
            GenerationCloseReason::RunEnding {
                outcome: RunOutcome::BudgetExceeded,
            },
        ];
        // The exact tags, not merely six distinct strings: a renamed reason
        // round-trips and stays distinct while no longer matching a log
        // already written, and the run-ending reason must name its outcome.
        let tags = [
            r#""reason":"resume_discards_retained_session""#,
            r#""reason":"worktree_missing""#,
            r#""reason":"run_ending","outcome":"complete""#,
            r#""reason":"run_ending","outcome":"parked""#,
            r#""reason":"run_ending","outcome":"halted""#,
            r#""reason":"run_ending","outcome":"budget_exceeded""#,
        ];
        let mut rendered = Vec::new();
        for (reason, tag) in reasons.iter().zip(tags) {
            let json = serde_json::to_string(reason).expect("serialize");
            assert_eq!(
                &serde_json::from_str::<GenerationCloseReason>(&json).expect("deserialize"),
                reason
            );
            assert!(json.contains(tag), "{json} does not carry {tag}");
            rendered.push(json);
        }
        let before = rendered.len();
        rendered.sort();
        rendered.dedup();
        assert_eq!(
            rendered.len(),
            before,
            "two close reasons serialize identically — a run-end closure would be \
             indistinguishable from another outcome's"
        );
        assert!(rendered.iter().any(|json| json.contains("budget_exceeded")));
    }

    // ------------------------------------------------------------------
    // Routing, restored as a function
    // ------------------------------------------------------------------

    #[test]
    fn the_task_and_sequence_are_recoverable_from_every_event_that_has_one() {
        // The legacy envelope hoisted these; schema 4 derives them. Stated as
        // a table over the whole vocabulary so a kind that quietly answers
        // `None` is visible rather than convenient.
        let expected_keys: Vec<Option<u32>> = vec![
            None,    // run_started
            None,    // run_resumed
            Some(9), // task_spawned
            Some(5), // task_dispatched
            Some(5), // attempt_started
            Some(5), // attempt_finished
            Some(7), // attempt_interrupted
            Some(6), // generation_closed
            None,    // defer_wait_elapsed
            Some(2), // candidate_prepared
            Some(2), // task_candidate_created
            Some(2), // merge_verification_started
            None,    // merge_verification_unavailable
            None,    // merge_verification_interrupted
            Some(2), // merge_prepared
            Some(2), // merge_rejected
            None,    // task_merged
            Some(3), // question_raised
            Some(3), // question_answered
            Some(4), // budget_exceeded
            None,    // run_finished
            None,    // capacity_snapshot
            None,    // pool_exhausted
            None,    // design_defect
        ];
        let expected_sequences: Vec<Option<u32>> = vec![
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(6), // merge_verification_started
            Some(6), // merge_verification_unavailable
            Some(6), // merge_verification_interrupted
            Some(6), // merge_prepared
            Some(8), // merge_rejected
            Some(6), // task_merged
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        assert_eq!(expected_keys.len(), TOPOLOGY_EVENT_KINDS.len());
        assert_eq!(expected_sequences.len(), TOPOLOGY_EVENT_KINDS.len());

        for ((body, key), sequence) in every_kind()
            .iter()
            .zip(&expected_keys)
            .zip(&expected_sequences)
        {
            assert_eq!(body.key(), key.map(TaskKey), "{} key", body.kind());
            assert_eq!(
                body.sequence(),
                sequence.map(SequenceId),
                "{} sequence",
                body.kind()
            );
        }

        // A key that differs from the one the surrounding fixture uses, so an
        // accessor reading the wrong field of the right event is caught.
        assert_ne!(expected_keys[2], expected_keys[3]);
        assert_ne!(expected_sequences[14], expected_sequences[15]);
    }

    // ------------------------------------------------------------------
    // Bindings
    // ------------------------------------------------------------------

    #[test]
    fn a_binding_is_compared_against_both_authorities_field_by_field() {
        let rung = FrozenRung {
            tier: Tier::Mid,
            agent: "codex".to_owned(),
            model: "gpt-5.6-sol".to_owned(),
            pinned: true,
        };
        let effort = Effort::XHigh;
        let frozen = RungBinding::from_frozen(&rung, effort);
        assert!(frozen.matches_frozen(&rung, effort));

        // Each field moved on its own.
        let movers: Vec<NamedBindingMove> = vec![
            ("tier", |b| b.tier = Tier::Frontier),
            ("agent", |b| b.agent = "claude-code".to_owned()),
            ("model", |b| b.model = "gpt-5.6".to_owned()),
            ("pinned", |b| b.pinned = false),
            ("effort", |b| b.effort = Effort::Low),
        ];
        for (name, move_field) in movers {
            let mut moved = frozen.clone();
            move_field(&mut moved);
            assert!(
                !moved.matches_frozen(&rung, effort),
                "moving {name} still matched the frozen rung"
            );
        }
        // And the effort argument itself is part of the comparison.
        assert!(!frozen.matches_frozen(&rung, Effort::Low));

        // The pin is crossed rather than sampled. A frozen rung the plan
        // pinned and one the run resolved are two different authorities even
        // when tier, agent and model agree, so a binding recorded against one
        // must not match the other — in *both* directions, which one fixture at
        // `pinned: true` cannot show.
        for pinned in [true, false] {
            let authority = FrozenRung {
                tier: Tier::Mid,
                agent: "codex".to_owned(),
                model: "gpt-5.6-sol".to_owned(),
                pinned,
            };
            let recorded = RungBinding::from_frozen(&authority, effort);
            assert_eq!(recorded.pinned, pinned, "the pin was not carried");
            assert!(recorded.matches_frozen(&authority, effort));

            let other = FrozenRung {
                pinned: !pinned,
                ..authority.clone()
            };
            assert!(
                !recorded.matches_frozen(&other, effort),
                "a binding recorded against pinned={pinned} matched pinned={}",
                !pinned
            );
            assert_ne!(
                RungBinding::from_frozen(&authority, effort),
                RungBinding::from_frozen(&other, effort),
                "two packet-distinct frozen rungs produced the same binding"
            );
        }

        // The override comparison ignores tier and nothing else: the option
        // list an override chooses from is agents, not tiers.
        let binding = BindingOverride {
            key: task_key(3),
            question: QuestionId::from("q"),
            option_index: 1,
            agent: "codex".to_owned(),
            model: "gpt-5.6-sol".to_owned(),
            effort: Effort::XHigh,
        };
        assert!(frozen.matches_override(&binding));
        let mut other_tier = frozen.clone();
        other_tier.tier = Tier::Frontier;
        assert!(other_tier.matches_override(&binding));
        // The pin is ignored for the same reason the tier is, and for both of
        // its values: `BindingOverride` records neither, so comparing either
        // would refuse a validated one-off binding rather than check it.
        for pinned in [true, false] {
            let mut either = frozen.clone();
            either.pinned = pinned;
            assert!(
                either.matches_override(&binding),
                "an override was refused for a pin it does not record ({pinned})"
            );
        }
        for (name, move_field) in [
            (
                "agent",
                (|b: &mut RungBinding| b.agent = "aider".to_owned()) as fn(&mut RungBinding),
            ),
            ("model", |b: &mut RungBinding| b.model = "gpt-4".to_owned()),
            ("effort", |b: &mut RungBinding| b.effort = Effort::Medium),
        ] {
            let mut moved = frozen.clone();
            move_field(&mut moved);
            assert!(
                !moved.matches_override(&binding),
                "moving {name} still matched the override"
            );
        }
    }

    // ------------------------------------------------------------------
    // The run record
    // ------------------------------------------------------------------

    #[test]
    fn a_topology_run_record_projects_to_the_registry_derivation_intact() {
        // The registry is the oracle: it refuses a run record that does not
        // describe the same run as the plan, and it refuses one that is
        // incomplete. A projection that dropped or defaulted a field it needs
        // is therefore not a field comparison away from being caught — it
        // fails to build a registry at all, or builds a different one.
        let plan = sample_plan();
        let started = run_started(&plan);
        let projected = started.registry_record();

        assert_eq!(projected.schema, TOPOLOGY_SCHEMA);
        assert_eq!(projected.run_id, started.run_id);
        assert_eq!(projected.base_sha, started.base_sha.0);
        assert_eq!(projected.plan_hash, started.plan_hash);
        assert_eq!(projected.chains, started.chains);
        assert_eq!(projected.effort_policy, Some(started.effort_policy));
        assert_eq!(projected.reviews.as_ref(), Some(&started.reviews));
        assert_eq!(projected.gate_cmds.as_ref(), Some(&started.gate_cmds));
        assert_eq!(
            projected.normalized_plan_digest.as_deref(),
            Some(started.normalized_plan_digest.as_str())
        );
        assert_eq!(projected.private_dir, started.private_dir);
        assert_eq!(projected.plan_path, started.plan_path);
        assert_eq!(projected.config_path, started.config_path);
        assert_eq!(projected.branch, started.branch);
        assert_eq!(projected.gates, started.gates);
        assert_eq!(projected.gates_from_config, started.gates_from_config);
        assert_eq!(projected.interaction_mode, started.interaction_mode);
        assert_eq!(projected.tactus_version, started.tactus_version);

        let registry = TaskRegistry::originals(&plan, &projected).expect("registry derives");
        assert_eq!(registry.len(), plan.tasks.len());
        // And the derivation actually read the projected values: the digest
        // moves when the record does.
        let mut elsewhere = run_started(&plan);
        elsewhere.effort_policy = ResolvedEffortPolicy {
            small: Effort::Max,
            mid: Effort::Max,
            frontier: Effort::Max,
            review: Effort::Max,
        };
        let other =
            TaskRegistry::originals(&plan, &elsewhere.registry_record()).expect("registry derives");
        assert_ne!(registry.digest(), other.digest());
    }

    #[test]
    fn a_topology_run_record_leaves_nothing_the_registry_would_call_incomplete() {
        // Schema 4 has no ancestors, so the fields schemas 1–3 made optional
        // for the sake of older logs are required here — and the projection
        // must therefore never hand the derivation a `None` it would refuse.
        let plan = sample_plan();
        let projected = run_started(&plan).registry_record();
        assert!(projected.effort_policy.is_some());
        assert!(projected.reviews.is_some());
        assert!(projected.gate_cmds.is_some());
        assert!(projected.normalized_plan_digest.is_some());
        assert!(TaskRegistry::originals(&plan, &projected).is_ok());
    }

    #[test]
    fn a_topology_run_started_says_it_is_one() {
        let plan = sample_plan();
        let started = run_started(&plan);
        assert!(started.is_topology_schema());
        assert_eq!(started.schema, 4);

        let mut legacy = run_started(&plan);
        legacy.schema = 3;
        assert!(!legacy.is_topology_schema());
    }

    // ------------------------------------------------------------------
    // The frozen wire, pinned against independently written payloads
    //
    // A round trip compares an encoder against its own decoder, so it agrees
    // with any symmetric rename: `#[serde(rename = "repeat")]` on
    // `SettlementTransition::Retry` round-trips perfectly and stops matching
    // every log already written. Everything below is the independent side of
    // that comparison — payloads written out here from the declared shape, so
    // no schema-4 wire name can move without a test failing.
    // ------------------------------------------------------------------

    /// Pin one value to its exact canonical JSON, in both directions.
    fn pinned<T>(value: &T, canonical: serde_json::Value)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + fmt::Debug,
    {
        assert_eq!(
            serde_json::to_value(value).expect("serialize"),
            canonical,
            "{value:?} does not serialize to its frozen payload"
        );
        assert_eq!(
            &serde_json::from_value::<T>(canonical.clone()).expect("deserialize"),
            value,
            "the frozen payload {canonical} does not decode to {value:?}"
        );
    }

    /// The frozen wire for the run's execution identity (INV-23).
    fn canonical_runner() -> serde_json::Value {
        serde_json::json!({
            "kind": "container",
            "policy": "container-v1",
            "image": {
                "reference": "ghcr.io/Example-Org/tactus-Runner:v2.1-Ünicode",
                "id": "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                "digest":
                    "sha256:ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211",
            },
            "credential_volumes": {
                "alpha-agent": "tactus-creds-ALPHA  ",
                "zeta-agent": "tactus-creds-Zeta",
            },
        })
    }

    fn canonical_candidate() -> serde_json::Value {
        serde_json::json!({
            "key": 2,
            "generation": 4,
            "commit_sha": SHA_CANDIDATE,
            "candidate_ref": format!("refs/tactus/runs/{RUN_ID}/candidates/2/4"),
        })
    }

    fn canonical_question(id: &str, key: u32) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "key": key,
            "kind": "unblock",
            "context": "  The reviewer found a licence question only a person may settle.  ",
            "options": ["escalate to frontier", "accept as-is", "  rescope  "],
        })
    }

    fn canonical_hostile_paths() -> serde_json::Value {
        serde_json::json!({
            "region": "prefixes",
            "paths": ["src/Zebra/ÜBER.rs", "  padded/entry  ", "Docs/adr/0001.md"],
        })
    }

    fn canonical_other_paths() -> serde_json::Value {
        serde_json::json!({"region": "prefixes", "paths": ["build.rs"]})
    }

    /// The frozen wire for the registry entry a `task_spawned` embeds whole.
    fn canonical_entry() -> serde_json::Value {
        serde_json::json!({
            "key": 9,
            "display_id": "merge-fix-0003-zeta",
            "origin": "merge_repair",
            "spec": {
                "kind": "fix",
                "title": "  Repair the Zeta rejection  ",
                "body": "Conflict against `src/Zebra/ÜBER.rs`; preserve merged behaviour.",
                "acceptance": ["the conflict is resolved"],
                "path_hints": ["src/Zebra/ÜBER.rs", "build.rs"],
                "suggested_tier": "frontier",
                "min_tier": "mid",
                "artifacts_in": ["contract"],
                "artifacts_out": ["zeta-out"],
            },
            "deps": [1],
            "display_deps": ["alpha"],
            "ladder": {
                "tiers": ["mid", "frontier"],
                "attempts_per": 3,
                "rungs": [
                    {"tier": "mid", "agent": "codex", "model": "gpt-5.6-sol", "pinned": true},
                    {
                        "tier": "frontier",
                        "agent": "claude-code",
                        "model": "claude-opus-5",
                        "pinned": false,
                    },
                ],
                "floor": "mid",
                "ceiling": "frontier",
                "effort": {
                    "small": "low",
                    "mid": "high",
                    "frontier": "max",
                    "review": "medium",
                },
                "admission": "runnable",
            },
            "reviews": {
                "enabled": true,
                "alternative_available": true,
                "pass_timeout_secs": 1_337,
                "primary": {"agent": "claude-code", "model": "claude-opus-5"},
                "alternative": {"agent": "copilot", "model": "gpt-5.6"},
                "second_opinion": null,
            },
            "allowed_agents": ["  Codex-CLI  ", "ÜBER-agent-Ωmega", "claude-code"],
            "lineage": {"root": 0, "parent": 4, "index": 3},
        })
    }

    fn canonical_spawn() -> serde_json::Value {
        serde_json::json!({
            "key": 9,
            "entry": canonical_entry(),
            "admission": {
                "admission": "human_binding",
                "options": ["codex", "claude-code"],
                "question": canonical_question("q-binding-Ünicode", 9),
            },
        })
    }

    /// Every event of [`every_kind`], in the same order, as the exact line a
    /// conforming writer commits.
    ///
    /// Written here from the frozen design — the declared field list, the
    /// declared tag — never read back from the serializer.
    ///
    /// Records schemas 1–3 also define (the attempt record, the gate and chain
    /// summaries, the effort policy, the review plan, and the three
    /// informational payloads) are spliced from their own values rather than
    /// respelled. A1 embeds those types; it does not declare or freeze their
    /// shape, and their keys are already pinned by the schema-1..3 suite that
    /// reads them. What is written out by hand here is exactly what schema 4
    /// froze, which is exactly what this slice owns.
    fn canonical_events() -> Vec<serde_json::Value> {
        let plan = sample_plan();
        let started = run_started(&plan);
        let legacy = |value: serde_json::Value| value;
        let ts = "2026-08-17T03:04:05.678Z";
        let record = serde_json::to_value(attempt_record()).expect("legacy attempt record");
        let envelope = |event: &str, data: serde_json::Value| serde_json::json!({"ts": ts, "event": event, "data": data});
        vec![
            envelope(
                "run_started",
                serde_json::json!({
                    "schema": 4,
                    "tactus_version": "0.2.0-Ünicode",
                    "run_id": RUN_ID,
                    "incarnation": "01J8ZQKB2M7NC5PQR0TVWXYZ12",
                    "runner": canonical_runner(),
                    "probed_agents": ["codex", "claude-code", "copilot"],
                    "branch": format!("tactus/run-{RUN_ID}"),
                    "integration_ref": "refs/heads/Ünïcode/Integration Target",
                    "base_sha": SHA_BASE,
                    "execution_root": "  D:\\Tactus Roots\\exec ünïcode  ",
                    "private_dir": "/var/lib/Tactus/private runs",
                    "plan_path": "docs/Plan Ünicode.md",
                    "config_path": "tactus.toml",
                    "plan_hash": "frozen-Ünicode-hash",
                    "normalized_plan_digest":
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "registry_digest":
                        "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    "path_policy": {"version": "v1", "case_fold": true, "grammar": "globset"},
                    "limits": {"max_parallel": 7, "max_defers": 3, "max_merge_repairs": 5},
                    "gates": ["fmt", "clippy"],
                    "gates_from_config": true,
                    "gate_cmds": legacy(
                        serde_json::to_value(&started.gate_cmds).expect("legacy gate summaries"),
                    ),
                    "interaction_mode": "never",
                    "chains": legacy(
                        serde_json::to_value(&started.chains).expect("legacy chain summaries"),
                    ),
                    "effort_policy": legacy(
                        serde_json::to_value(started.effort_policy).expect("legacy effort policy"),
                    ),
                    "reviews": legacy(
                        serde_json::to_value(&started.reviews).expect("legacy review plan"),
                    ),
                }),
            ),
            envelope(
                "run_resumed",
                serde_json::json!({
                    "incarnation": "01J8ZQKC3N8PD6QRS1UVWXYZ34",
                    "runner": canonical_runner(),
                    "probed_agents": ["codex", "claude-code"],
                    "tactus_version": "0.2.1-Ünicode",
                }),
            ),
            envelope(
                "task_spawned",
                serde_json::json!({"spawn": canonical_spawn()}),
            ),
            envelope(
                "task_dispatched",
                serde_json::json!({
                    "key": 5,
                    "generation": 2,
                    "base_sha": SHA_HEAD,
                    "worktree_path": "/var/lib/Tactus/work trees/zeta-2",
                    "lease": {"lease": "predicted", "paths": canonical_hostile_paths()},
                    "source_candidate": canonical_candidate(),
                }),
            ),
            envelope(
                "attempt_started",
                serde_json::json!({
                    "key": 5,
                    "generation": 2,
                    "attempt": 3,
                    "rung": 1,
                    "binding": {
                        "tier": "frontier",
                        "agent": "claude-code",
                        "model": "claude-opus-5",
                        "pinned": false,
                        "effort": "max",
                    },
                    "pool": "claude-max",
                    "resume_session": "sess-ÜNI-0042",
                    "materialization_observed": "conflict",
                }),
            ),
            envelope(
                "attempt_finished",
                serde_json::json!({
                    "key": 5,
                    "generation": 2,
                    "attempt": 3,
                    "record": record.clone(),
                    "settlement": {
                        "settlement": "retained",
                        "retained_session": "sess-ÜNI-0042",
                        "retained_incarnation": 5,
                    },
                }),
            ),
            envelope(
                "attempt_interrupted",
                serde_json::json!({
                    "key": 7,
                    "generation": 1,
                    "attempt": 2,
                    "lease": "lineage_held",
                    "detail": "  coordinator died holding the attempt  ",
                }),
            ),
            envelope(
                "generation_closed",
                serde_json::json!({
                    "key": 6,
                    "generation": 3,
                    "reason": {"reason": "worktree_missing"},
                    "lease": "predicted_released",
                }),
            ),
            envelope(
                "defer_wait_elapsed",
                serde_json::json!({"waited_ms": 61_000, "round": 4}),
            ),
            envelope(
                "candidate_prepared",
                serde_json::json!({
                    "key": 2,
                    "generation": 4,
                    "attempt": record.clone(),
                    "base_sha": SHA_BASE,
                    "parent_sha": SHA_BASE,
                    "tree_sha": SHA_TREE,
                    "commit_sha": SHA_CANDIDATE,
                    "message": "  zeta: repair the Ünicode path  ",
                    "prepared_ref": format!("refs/tactus/runs/{RUN_ID}/candidate-prepared/2/4"),
                    "candidate_ref": format!("refs/tactus/runs/{RUN_ID}/candidates/2/4"),
                    "actual_paths": canonical_hostile_paths(),
                    "lease_effect": {
                        "lease_effect": "widens_lineage",
                        "root": 0,
                        "paths": canonical_other_paths(),
                    },
                }),
            ),
            envelope(
                "task_candidate_created",
                serde_json::json!({"candidate": canonical_candidate()}),
            ),
            envelope(
                "merge_verification_started",
                serde_json::json!({
                    "sequence": 6,
                    "candidate": canonical_candidate(),
                    "basis": {
                        "basis": "stale_clean",
                        "prepared_ref": format!("refs/tactus/runs/{RUN_ID}/prepared/6"),
                    },
                    "expected_head": SHA_HEAD,
                    "proposed_sha": SHA_THIRD,
                }),
            ),
            envelope(
                "merge_verification_unavailable",
                serde_json::json!({
                    "sequence": 6,
                    "cause": {"cause": "infrastructure", "kind": {"kind": "reviewer_timeout"}},
                    "outcome": {"outcome": "deferred", "defers": 2},
                }),
            ),
            envelope(
                "merge_verification_interrupted",
                serde_json::json!({
                    "sequence": 6,
                    "detail": "  process died mid-verification  ",
                }),
            ),
            envelope(
                "merge_prepared",
                serde_json::json!({
                    "sequence": 6,
                    "disposition": "fast",
                    "expected_head": SHA_BASE,
                    "proposed_sha": SHA_CANDIDATE,
                    "key": 2,
                    "generation": 4,
                    "candidate_sha": SHA_CANDIDATE,
                    "candidate_ref": format!("refs/tactus/runs/{RUN_ID}/candidates/2/4"),
                    "prepared_ref": null,
                    "verification_source": {
                        "source": "candidate_prepared",
                        "key": 2,
                        "generation": 4,
                    },
                    "verification": null,
                    "satisfies": [2, 0],
                }),
            ),
            envelope(
                "merge_rejected",
                serde_json::json!({
                    "sequence": 8,
                    "candidate": canonical_candidate(),
                    "rejecting_head": SHA_HEAD,
                    "disposition": {"disposition": "conflict", "paths": canonical_hostile_paths()},
                    "repair": canonical_spawn(),
                    "lease_effect": {
                        "lease_effect": "creates_lineage",
                        "root": 2,
                        "paths": canonical_other_paths(),
                    },
                }),
            ),
            envelope(
                "task_merged",
                serde_json::json!({
                    "sequence": 6,
                    "merged_sha": SHA_CANDIDATE,
                    "satisfies": [2, 0],
                    "lease_release": {"release": "lineage", "root": 0},
                }),
            ),
            envelope(
                "question_raised",
                serde_json::json!({"question": canonical_question("q-park-0007", 3)}),
            ),
            envelope(
                "question_answered",
                serde_json::json!({
                    "key": 3,
                    "question": "q-park-0007",
                    "answer": {
                        "answer": "answered",
                        "option_index": 2,
                        "binding_override": {
                            "key": 3,
                            "question": "q-park-0007",
                            "option_index": 2,
                            "agent": "codex",
                            "model": "gpt-5.6-sol",
                            "effort": "xhigh",
                        },
                    },
                    "via": "  tactus answer  ",
                }),
            ),
            envelope(
                "budget_exceeded",
                serde_json::json!({
                    "epoch": 2,
                    "budget": "task",
                    "limit_usd": 12.5,
                    "spent_usd": 13.75,
                    "key": 4,
                }),
            ),
            envelope(
                "run_finished",
                serde_json::json!({
                    "outcome": "parked",
                    "halted_at": null,
                    "merged": 3,
                    "parked": 2,
                }),
            ),
            envelope(
                "capacity_snapshot",
                legacy(
                    serde_json::to_value(CapacitySnapshot {
                        strategy: "  Conservative  ".to_owned(),
                        pools: vec![PoolSnapshot {
                            pool: "codex-plus".to_owned(),
                            agent: "codex".to_owned(),
                            kind: "subscription".to_owned(),
                            remaining: "42%".to_owned(),
                            confidence: "reported".to_owned(),
                            reset_at: Some("2026-08-17T21:00:00Z".to_owned()),
                        }],
                    })
                    .expect("legacy capacity snapshot"),
                ),
            ),
            envelope(
                "pool_exhausted",
                legacy(
                    serde_json::to_value(PoolExhausted {
                        pool: "claude-max".to_owned(),
                        agent: "claude-code".to_owned(),
                        reset_at: Some("2026-08-18T04:00:00Z".to_owned()),
                        detail: "  5-hour limit reached  ".to_owned(),
                    })
                    .expect("legacy pool exhausted"),
                ),
            ),
            envelope(
                "design_defect",
                legacy(
                    serde_json::to_value(DesignDefect {
                        question: QuestionId::from("q-design-0001"),
                        context: "  the plan contradicts itself about Ünicode paths  ".to_owned(),
                        answer: "rescope".to_owned(),
                    })
                    .expect("legacy design defect"),
                ),
            ),
        ]
    }

    #[test]
    fn every_event_serializes_to_exactly_its_independently_written_payload() {
        let events = every_kind();
        let canonical = canonical_events();
        assert_eq!(
            canonical.len(),
            TOPOLOGY_EVENT_KINDS.len(),
            "the canonical corpus does not cover the whole vocabulary"
        );
        for (body, expected) in events.iter().zip(&canonical) {
            assert_eq!(
                &payload_of(body),
                expected,
                "{} does not serialize to its frozen payload",
                body.kind()
            );
        }
    }

    #[test]
    fn every_event_decodes_from_its_independently_written_payload() {
        // The other direction, and the one a replay actually performs: bytes a
        // conforming writer produced, read by this decoder. A rename that
        // moved encoder and decoder together passes the round trip and fails
        // here.
        for (body, canonical) in every_kind().iter().zip(canonical_events()) {
            let decoded: TopologyEvent = serde_json::from_value(canonical.clone())
                .unwrap_or_else(|error| panic!("{}: {error} in {canonical}", body.kind()));
            assert_eq!(&decoded.body, body, "{}", body.kind());
            assert_eq!(decoded.ts, "2026-08-17T03:04:05.678Z");
        }
    }

    #[test]
    fn every_nested_variant_is_pinned_to_its_frozen_tag_and_fields() {
        // `bounded_census.event_payload_classes`: every nested payload class,
        // including the variants no fixture in `every_kind` instantiates.
        // Sampling one arm of an enum leaves the other free to be renamed.
        let paths = PathSet::Prefixes {
            paths: vec![crate::topology::paths::GitPath::from("src/a.rs")],
        };
        let paths_json = serde_json::json!({"region": "prefixes", "paths": ["src/a.rs"]});
        let question = frozen_question("q-1", task_key(3));
        let question_json = canonical_question("q-1", 3);

        // Runner identity (INV-23): the kebab-case contract spellings are
        // durable identity, and `host-v1` is the arm no event fixture uses.
        pinned(&RunnerKind::Host, serde_json::json!("host"));
        pinned(&RunnerKind::Container, serde_json::json!("container"));
        pinned(&RunnerContract::HostV1, serde_json::json!("host-v1"));
        pinned(
            &RunnerContract::ContainerV1,
            serde_json::json!("container-v1"),
        );
        pinned(
            &host_runner(),
            serde_json::json!({
                "kind": "host",
                "policy": "host-v1",
                "image": null,
                "credential_volumes": null,
            }),
        );

        // Spawn admission: all three arms.
        pinned(
            &SpawnAdmission::Runnable,
            serde_json::json!({"admission": "runnable"}),
        );
        pinned(
            &SpawnAdmission::HumanRequired {
                limit: 2,
                question: question.clone(),
            },
            serde_json::json!({
                "admission": "human_required",
                "limit": 2,
                "question": question_json.clone(),
            }),
        );
        pinned(
            &SpawnAdmission::HumanBinding {
                options: vec!["codex".to_owned()],
                question: question.clone(),
            },
            serde_json::json!({
                "admission": "human_binding",
                "options": ["codex"],
                "question": question_json.clone(),
            }),
        );

        // Lease grants: both, including the repair arm nothing else builds.
        pinned(
            &LeaseGrant::Predicted {
                paths: paths.clone(),
            },
            serde_json::json!({"lease": "predicted", "paths": paths_json.clone()}),
        );
        pinned(
            &LeaseGrant::InheritedLineage { root: task_key(7) },
            serde_json::json!({"lease": "inherited_lineage", "root": 7}),
        );

        // Settlement transitions: every arm, including `retry`, whose tag no
        // other test reads off the wire.
        pinned(
            &SettlementTransition::Succeeded,
            serde_json::json!({"transition": "succeeded"}),
        );
        pinned(
            &SettlementTransition::Retry,
            serde_json::json!({"transition": "retry"}),
        );
        pinned(
            &SettlementTransition::Escalated { rung: 2 },
            serde_json::json!({"transition": "escalated", "rung": 2}),
        );
        pinned(
            &SettlementTransition::Deferred {
                defers: 1,
                reason: "  rate limited  ".to_owned(),
            },
            serde_json::json!({
                "transition": "deferred",
                "defers": 1,
                "reason": "  rate limited  ",
            }),
        );
        pinned(
            &SettlementTransition::Parked {
                question: question.clone(),
            },
            serde_json::json!({"transition": "parked", "question": question_json.clone()}),
        );
        pinned(
            &SettlementTransition::Failed {
                halts_run: true,
                reason: "  ladder exhausted  ".to_owned(),
            },
            serde_json::json!({
                "transition": "failed",
                "halts_run": true,
                "reason": "  ladder exhausted  ",
            }),
        );

        // Attempt settlement and lease disposition: the frozen vocabulary.
        pinned(
            &AttemptSettlement::Retained {
                retained_session: SessionId("s-1".to_owned()),
                retained_incarnation: Epoch(5),
            },
            serde_json::json!({
                "settlement": "retained",
                "retained_session": "s-1",
                "retained_incarnation": 5,
            }),
        );
        pinned(
            &AttemptSettlement::Closed {
                transition: SettlementTransition::Retry,
                lease: LeaseDisposition::PredictedRetained,
            },
            serde_json::json!({
                "settlement": "closed",
                "transition": {"transition": "retry"},
                "lease": "predicted_retained",
            }),
        );
        pinned(
            &LeaseDisposition::PredictedReleased,
            serde_json::json!("predicted_released"),
        );
        pinned(
            &LeaseDisposition::PredictedRetained,
            serde_json::json!("predicted_retained"),
        );
        pinned(
            &LeaseDisposition::LineageHeld,
            serde_json::json!("lineage_held"),
        );

        // Every repair materialization, including the three no fixture uses.
        pinned(&Materialization::Clean, serde_json::json!("clean"));
        pinned(&Materialization::Conflict, serde_json::json!("conflict"));
        pinned(&Materialization::Empty, serde_json::json!("empty"));
        pinned(&Materialization::Retained, serde_json::json!("retained"));

        // Generation closure.
        pinned(
            &GenerationCloseReason::ResumeDiscardsRetainedSession,
            serde_json::json!({"reason": "resume_discards_retained_session"}),
        );
        pinned(
            &GenerationCloseReason::WorktreeMissing,
            serde_json::json!({"reason": "worktree_missing"}),
        );
        pinned(
            &GenerationCloseReason::RunEnding {
                outcome: RunOutcome::BudgetExceeded,
            },
            serde_json::json!({"reason": "run_ending", "outcome": "budget_exceeded"}),
        );

        // Candidate and rejection lease effects: both arms of each.
        pinned(
            &CandidateLeaseEffect::ReplacesPredicted {
                paths: paths.clone(),
            },
            serde_json::json!({"lease_effect": "replaces_predicted", "paths": paths_json.clone()}),
        );
        pinned(
            &CandidateLeaseEffect::WidensLineage {
                root: task_key(1),
                paths: paths.clone(),
            },
            serde_json::json!({
                "lease_effect": "widens_lineage",
                "root": 1,
                "paths": paths_json.clone(),
            }),
        );
        pinned(
            &RejectionLeaseEffect::CreatesLineage {
                root: task_key(1),
                paths: paths.clone(),
            },
            serde_json::json!({
                "lease_effect": "creates_lineage",
                "root": 1,
                "paths": paths_json.clone(),
            }),
        );
        pinned(
            &RejectionLeaseEffect::WidensLineage {
                root: task_key(1),
                paths: paths.clone(),
            },
            serde_json::json!({
                "lease_effect": "widens_lineage",
                "root": 1,
                "paths": paths_json.clone(),
            }),
        );

        // Verification bases, sources, verdicts, and both rejection forms.
        pinned(
            &VerificationBasis::StaleClean {
                prepared_ref: GitRef::from("refs/prepared/1"),
            },
            serde_json::json!({"basis": "stale_clean", "prepared_ref": "refs/prepared/1"}),
        );
        pinned(
            &VerificationBasis::AlreadyPresent,
            serde_json::json!({"basis": "already_present"}),
        );
        pinned(
            &VerificationSource::CandidatePrepared {
                key: task_key(2),
                generation: GenerationId(4),
            },
            serde_json::json!({"source": "candidate_prepared", "key": 2, "generation": 4}),
        );
        pinned(
            &VerificationSource::Verification {
                sequence: SequenceId(6),
            },
            serde_json::json!({"source": "verification", "sequence": 6}),
        );
        pinned(&VerificationVerdict::Passed, serde_json::json!("passed"));
        pinned(
            &VerificationVerdict::GatesFailed,
            serde_json::json!("gates_failed"),
        );
        pinned(
            &VerificationVerdict::Rejected,
            serde_json::json!("rejected"),
        );
        pinned(
            &RejectionDisposition::Conflict {
                paths: paths.clone(),
            },
            serde_json::json!({"disposition": "conflict", "paths": paths_json.clone()}),
        );
        pinned(&PreparedDisposition::Fast, serde_json::json!("fast"));
        pinned(
            &PreparedDisposition::StaleClean,
            serde_json::json!("stale_clean"),
        );
        pinned(
            &PreparedDisposition::AlreadyPresent,
            serde_json::json!("already_present"),
        );

        // Outages: every enumerated kind and the open-ended one.
        pinned(
            &UnavailableCause::HumanRequired {
                verdict: "  a licence question  ".to_owned(),
            },
            serde_json::json!({"cause": "human_required", "verdict": "  a licence question  "}),
        );
        for (kind, tag) in [
            (InfrastructureKind::RateLimited, "rate_limited"),
            (InfrastructureKind::ReviewUnavailable, "review_unavailable"),
            (InfrastructureKind::ReviewerTimeout, "reviewer_timeout"),
            (
                InfrastructureKind::RunnerSpawnFailure,
                "runner_spawn_failure",
            ),
        ] {
            pinned(&kind, serde_json::json!({"kind": tag}));
        }
        pinned(
            &InfrastructureKind::Other {
                detail: "  503  ".to_owned(),
            },
            serde_json::json!({"kind": "other", "detail": "  503  "}),
        );
        pinned(
            &UnavailableOutcome::Deferred { defers: 3 },
            serde_json::json!({"outcome": "deferred", "defers": 3}),
        );
        pinned(
            &UnavailableOutcome::Parked {
                question: question.clone(),
            },
            serde_json::json!({"outcome": "parked", "question": question_json.clone()}),
        );

        // Merge lease release: both arms.
        pinned(
            &MergeLeaseRelease::Candidate {
                key: task_key(2),
                generation: GenerationId(4),
            },
            serde_json::json!({"release": "candidate", "key": 2, "generation": 4}),
        );
        pinned(
            &MergeLeaseRelease::Lineage { root: task_key(0) },
            serde_json::json!({"release": "lineage", "root": 0}),
        );

        // Answers: both arms, and the override whose authoritative slot is a
        // key rather than a task label.
        pinned(
            &Answer4::Answered {
                option_index: 1,
                binding_override: None,
            },
            serde_json::json!({
                "answer": "answered",
                "option_index": 1,
                "binding_override": null,
            }),
        );
        pinned(
            &Answer4::Declined {
                decline_halts_run: true,
            },
            serde_json::json!({"answer": "declined", "decline_halts_run": true}),
        );
        pinned(
            &BindingOverride {
                key: task_key(8),
                question: QuestionId::from("q-1"),
                option_index: 0,
                agent: "codex".to_owned(),
                model: "gpt-5.6-sol".to_owned(),
                effort: Effort::Low,
            },
            serde_json::json!({
                "key": 8,
                "question": "q-1",
                "option_index": 0,
                "agent": "codex",
                "model": "gpt-5.6-sol",
                "effort": "low",
            }),
        );

        // The run's frozen ceilings, and the region vocabulary.
        pinned(
            &TopologyLimits {
                max_parallel: 7,
                max_defers: 3,
                max_merge_repairs: 5,
            },
            serde_json::json!({"max_parallel": 7, "max_defers": 3, "max_merge_repairs": 5}),
        );
        pinned(
            &PathSet::RepoWide,
            serde_json::json!({"region": "repo_wide"}),
        );
        pinned(&paths, paths_json);
    }

    #[test]
    fn budget_exceeded_carries_the_epoch_its_stop_belongs_to() {
        // Epoch-scoped, because raising the ceiling and resuming is the
        // intended response: the stop belongs to the epoch that hit the old
        // ceiling and must not outlive it.
        let event = BudgetExceeded4 {
            epoch: Epoch(2),
            budget: BudgetKind::Run,
            limit_usd: 50.0,
            spent_usd: 51.25,
            key: Some(task_key(4)),
        };
        assert_eq!(
            event.stop(),
            BudgetStop {
                epoch: Epoch(2),
                budget: BudgetKind::Run,
            }
        );
        let mut later = event.clone();
        later.epoch = Epoch(3);
        assert_ne!(later.stop(), event.stop());
        let mut other_ceiling = event;
        other_ceiling.budget = BudgetKind::Task;
        assert_ne!(other_ceiling.stop().budget, BudgetKind::Run);
    }
}
