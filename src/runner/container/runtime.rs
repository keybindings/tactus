//! The container-runtime seam, and the ordered trace every obligation in this
//! slice is asserted against.
//!
//! ## Why a seam at all
//!
//! `decisions.tests_acceptance.determinism` requires "a fake container runtime
//! with owner labels, incarnations, liveness simulation, an image table keyed
//! by immutable id with references and digests, a mutable tag table …, an
//! availability toggle for ST-16 and ST-20 **plus Docker-gated real runs**".
//! Two implementations of one contract is what that sentence asks for, so the
//! contract is a trait and neither implementation is the definition.
//!
//! ## The operation list is derived from obligations, not from Docker
//!
//! Every method here exists because some live passage cannot be held without
//! it. The mapping is written out in [`RuntimeOp`], one arm per method, so a
//! method added later has to say which obligation it serves.
//!
//! ## Reachability is not one boolean, and that is a decision
//!
//! `crash_reconstruction`: "the container runtime is required only when an
//! intent exists or a labeled container is discoverable: if any intent exists
//! and the runtime cannot be reached the write command refuses (it cannot
//! prove those containers terminated), and with no intent and no reachable
//! runtime it proceeds".
//!
//! A runtime that answers `docker ps` and fails `docker inspect` is a real
//! state — a daemon under load, a partially broken socket, a `ps` served from
//! cache. If reachability were one boolean taken once, such a runtime would
//! classify as *reachable*, the write command would proceed past the refusal
//! point, and the failure would arrive later — after "before any recovery
//! event", which is precisely the predicate the refusal exists to hold.
//!
//! So reachability is **per operation**: every fallible method returns
//! [`RuntimeError`], which distinguishes [`RuntimeError::Unreachable`] from
//! [`RuntimeError::Failed`] and names the [`RuntimeOp`] that could not be
//! reached. [`ContainerRuntime::probe`] exists as the cheap up-front question,
//! but no caller may treat its answer as a promise about a later operation —
//! and the fake can make `ListByLabel` reachable while `InspectImageById` is
//! not, so the mixed state is constructible rather than merely conceded.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::topology::effects::ContainerSite;

// ---------------------------------------------------------------------------
// The operations, and why each exists
// ---------------------------------------------------------------------------

/// One operation of the runtime seam.
///
/// The discriminant is not decorative: [`RuntimeError`] names it, so
/// "unreachable" is always a statement about a specific question, and the fake
/// arms unreachability per operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeOp {
    /// The cheap up-front reachability question. `crash_reconstruction`: "the
    /// container runtime is required only when an intent exists or a labeled
    /// container is discoverable".
    Probe,
    /// Resolve a **reference** to its immutable id and its manifest digest.
    /// `pr_sequence[7].scope`: "image reference already present in the runtime
    /// — no implicit pull — its immutable image id and manifest digest when
    /// reported".
    InspectImageByReference,
    /// Resolve an **id**. A different question from the reference, and the
    /// rebuild path asks only this one: "refuse … when … the **recorded image
    /// id** is absent from the runtime". A seam that could only ask about the
    /// reference could not express that refusal.
    InspectImageById,
    /// `pr_sequence[7].scope`: "per-agent credential volume names present by
    /// **volume inspection**".
    InspectVolume,
    /// `crash_reconstruction`: "docker ps by `tactus.private_root`". Discovery
    /// returns names **and labels**, because a labeled container without an
    /// intent is classified from its labels alone.
    ListByLabel,
    /// The reclaim sequence's middle step: "wait until observed
    /// exited/removed".
    Observe,
    /// The invocation's result — exit status, stdout, stderr — for a
    /// [`crate::agent::ProcessOutput`].
    Collect,
    /// `INV-23`: "every container of every epoch is **created from the
    /// recorded image id**". The result reports the id the runtime actually
    /// used; see [`CreatedContainer::reported_image_id`].
    Create,
    /// `docker start`, after the reported id has been verified.
    Start,
    /// Completion's `docker stop` and reclaim's `docker kill`, distinguished
    /// by [`StopMode`] and accounted to the one site the frozen inventory has
    /// for both, `ContainerSite::Stop`.
    Stop,
    /// `docker rm`. Idempotent and tolerant of already-gone.
    Remove,
}

impl RuntimeOp {
    /// Every operation, in the order the seam declares them.
    ///
    /// Written out rather than derived so an operation added later has to be
    /// added here, and so a grid over operations is a grid over all of them.
    pub const ALL: &'static [Self] = &[
        Self::Probe,
        Self::InspectImageByReference,
        Self::InspectImageById,
        Self::InspectVolume,
        Self::ListByLabel,
        Self::Observe,
        Self::Collect,
        Self::Create,
        Self::Start,
        Self::Stop,
        Self::Remove,
    ];

    /// Whether the operation changes runtime state.
    ///
    /// The four effectful ones are the four the Container funnel wraps; the
    /// seven read-only ones are inspections and carry no site, because
    /// `ContainerSite` has no inspection variant and this slice may not add
    /// one.
    #[must_use]
    pub const fn is_effect(self) -> bool {
        match self {
            Self::Create | Self::Start | Self::Stop | Self::Remove => true,
            Self::Probe
            | Self::InspectImageByReference
            | Self::InspectImageById
            | Self::InspectVolume
            | Self::ListByLabel
            | Self::Observe
            | Self::Collect => false,
        }
    }

    /// The operation as it is written in a trace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::InspectImageByReference => "inspect-image-by-reference",
            Self::InspectImageById => "inspect-image-by-id",
            Self::InspectVolume => "inspect-volume",
            Self::ListByLabel => "list-by-label",
            Self::Observe => "observe",
            Self::Collect => "collect",
            Self::Create => "create",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "remove",
        }
    }
}

impl fmt::Display for RuntimeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What went wrong, and whether the runtime could be reached at all.
///
/// The distinction is the whole point: `crash_reconstruction` refuses a write
/// command when "any intent exists and the runtime **cannot be reached**",
/// which is not the same as an operation that reached the runtime and failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// The runtime could not be reached for this operation.
    Unreachable {
        operation: RuntimeOp,
        detail: String,
    },
    /// The runtime answered, and the answer was a failure.
    Failed {
        operation: RuntimeOp,
        detail: String,
    },
}

impl RuntimeError {
    /// The operation that produced this error.
    #[must_use]
    pub const fn operation(&self) -> RuntimeOp {
        match self {
            Self::Unreachable { operation, .. } | Self::Failed { operation, .. } => *operation,
        }
    }

    /// Whether the runtime could not be reached.
    #[must_use]
    pub const fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable { .. })
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable { operation, detail } => write!(
                f,
                "the container runtime cannot be reached for `{operation}`: {detail}"
            ),
            Self::Failed { operation, detail } => {
                write!(f, "the container runtime refused `{operation}`: {detail}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

// ---------------------------------------------------------------------------
// Values the seam exchanges
// ---------------------------------------------------------------------------

/// What an image inspection reports.
///
/// **Not** [`crate::topology::events::ImageIdentity`], deliberately. The
/// recorded identity pairs the reference the *operator wrote* with the id the
/// runtime resolved; an inspection reports what the runtime holds, and its
/// `references` may be empty (an id with no tag), may be several, or may name
/// a tag the operator never wrote. Returning the recorded shape here would let
/// a resolver take its `reference` field from the runtime's answer instead of
/// from the config — which is the record's own oracle, and would make "the
/// recorded reference now names another image" unconstructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInspection {
    /// The runtime's immutable image id.
    pub id: String,
    /// The manifest digest, `None` when the runtime reports none. INV-23:
    /// "digest (the manifest digest **when reported**)".
    pub digest: Option<String>,
    /// Every reference the runtime says resolves to this id.
    pub references: Vec<String>,
}

/// One mount the container receives.
///
/// DESIGN.md:400: "A container receives only its role's one worktree mount; it
/// never receives the public log, sibling worktrees, or private artifacts", and
/// DESIGN.md:612 adds the read-only reviewer mount and the per-agent credential
/// volume ("persistent volumes, not ephemeral copies").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mount {
    /// A host path, bound at `target`.
    Path {
        source: PathBuf,
        target: String,
        read_only: bool,
    },
    /// A named volume — R20, operator-owned, "never created or pruned by a
    /// run".
    Volume {
        name: String,
        target: String,
        read_only: bool,
    },
}

impl Mount {
    /// Where the container sees it.
    #[must_use]
    pub fn target(&self) -> &str {
        match self {
            Self::Path { target, .. } | Self::Volume { target, .. } => target,
        }
    }

    /// Whether the mount is read-only.
    #[must_use]
    pub const fn read_only(&self) -> bool {
        match self {
            Self::Path { read_only, .. } | Self::Volume { read_only, .. } => *read_only,
        }
    }
}

/// Everything `docker create` is given.
///
/// `image_id` and not a reference: INV-23's "every container of every epoch is
/// created from the recorded image id … so a moved reference cannot change what
/// executes". The type carries no reference at all, so a caller cannot create
/// from one by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSpec {
    /// The container's name. `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>`.
    pub name: String,
    /// The **recorded immutable image id**.
    pub image_id: String,
    /// The five `tactus.*` labels.
    pub labels: BTreeMap<String, String>,
    pub mounts: Vec<Mount>,
    /// The runner-owned base environment plus the adapter's overlay
    /// (DESIGN.md:258). Composed by lane A; carried verbatim here.
    pub env: Vec<(String, String)>,
    /// The command line, from the `CommandSpec`.
    pub command: Vec<String>,
    /// The child's working directory inside the container.
    pub workdir: Option<String>,
}

/// What `docker create` gives back.
///
/// [`Self::reported_image_id`] is the runtime's answer and **must never be
/// filled in from the request**. INV-23: "its reported image id is verified
/// equal to the record before it starts". A `create` that echoed its argument
/// would make `substituted_image_id_refused_before_start` unconstructible and
/// the suite green because the test could not be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedContainer {
    pub name: String,
    /// The image id the **runtime** says the container was created from.
    pub reported_image_id: String,
}

/// A container discovered by label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredContainer {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

impl DiscoveredContainer {
    /// One label's value.
    #[must_use]
    pub fn label(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(String::as_str)
    }
}

/// Whether a container is still running.
///
/// Three answers and not two: reclaim must "wait until observed
/// exited/**removed**", and a container that is gone is as terminated as one
/// that exited. Collapsing them would make a reclaimer that raced another
/// reclaimer report "cannot be observed terminated" and block admission, which
/// is the opposite of "two concurrent reclaimers converge".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Running,
    Exited,
    Gone,
}

impl Liveness {
    /// Whether this answer proves the container is no longer running.
    #[must_use]
    pub const fn is_terminated(self) -> bool {
        match self {
            Self::Exited | Self::Gone => true,
            Self::Running => false,
        }
    }
}

/// How a container is stopped.
///
/// Two dispositions, one site. `ContainerSite` is frozen with eight variants
/// and has exactly one for stopping, so both the completion path's `docker
/// stop` (`at_run_end`: "released on complete (**stop**/rm, …)") and reclaim's
/// `docker kill` ("reclaim = docker **kill** -> observe …") are accounted to
/// `ContainerSite::Stop`. The disposition travels as a value so a trace still
/// distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    /// Completion or cancellation: ask it to stop.
    Graceful,
    /// Reclaim: kill it.
    Kill,
}

impl StopMode {
    /// The disposition as it is written in a trace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Kill => "kill",
        }
    }
}

/// What a finished container did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerExecution {
    /// `None` when the process was signalled rather than exiting.
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/// The container runtime, as this slice needs it.
///
/// `Send + Sync` for the same reason [`crate::runner::Runner`] is: PR11 holds
/// one of these across await points behind a `&dyn`.
///
/// **The four effectful methods are denied in `clippy.toml`.** Only
/// `src/runner/container.rs` — the module the frozen inventory names as the
/// Container funnel — is allowed to call them, so a lane cannot perform a
/// container effect without going through a funnel API that takes its site by
/// value. `runner::container::tests::every_container_effect_in_the_tree_goes_through_the_funnel`
/// is the source census that says so in the tree's own idiom.
pub trait ContainerRuntime: Send + Sync {
    /// Can the runtime be reached at all?
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Unreachable`] when it cannot. A caller may **not** treat
    /// `Ok(())` as a promise about any later operation; see the module docs.
    fn probe(&self) -> Result<(), RuntimeError>;

    /// Resolve a reference. `Ok(None)` means the reference is not present —
    /// which is a refusal, not a pull. `non_goals[1]` is "implicit image pull".
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or the inspection
    /// fails.
    fn image_by_reference(&self, reference: &str) -> Result<Option<ImageInspection>, RuntimeError>;

    /// Resolve an immutable id. `Ok(None)` means "the recorded image id is
    /// absent from the runtime", which refuses a rebuild before any spawn.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or the inspection
    /// fails.
    fn image_by_id(&self, id: &str) -> Result<Option<ImageInspection>, RuntimeError>;

    /// Whether a named volume exists. R20 volumes are operator-owned and are
    /// never created here.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or the inspection
    /// fails.
    fn volume_present(&self, name: &str) -> Result<bool, RuntimeError>;

    /// Every container carrying `key=value`, with its labels.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or the listing
    /// fails.
    fn containers_with_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Vec<DiscoveredContainer>, RuntimeError>;

    /// Whether a container is running, exited, or gone.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or the inspection
    /// fails.
    fn observe(&self, name: &str) -> Result<Liveness, RuntimeError>;

    /// The container's exit status and captured output.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or the collection
    /// fails.
    fn collect(&self, name: &str) -> Result<ContainerExecution, RuntimeError>;

    /// Create a container **from an image id**, and report the id the runtime
    /// used.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or creation fails.
    fn create(&self, spec: &CreateSpec) -> Result<CreatedContainer, RuntimeError>;

    /// Start it.
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached or the start fails.
    fn start(&self, name: &str) -> Result<(), RuntimeError>;

    /// Stop or kill it. **Idempotent and tolerant of already-gone.**
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached, or the stop fails
    /// for a reason other than the container being absent.
    fn stop(&self, name: &str, mode: StopMode) -> Result<(), RuntimeError>;

    /// Remove it. **Idempotent and tolerant of already-gone**, because "two
    /// concurrent reclaimers converge".
    ///
    /// # Errors
    ///
    /// [`RuntimeError`] when the runtime cannot be reached, or the removal
    /// fails for a reason other than the container being absent.
    fn remove(&self, name: &str) -> Result<(), RuntimeError>;
}

// ---------------------------------------------------------------------------
// Owner liveness — a separate seam, and that is the point
// ---------------------------------------------------------------------------

/// Is another run's coordinator alive?
///
/// `crash_reconstruction`: "owner run != this run: **probe that run's run.lock
/// non-blocking** (is_running semantics: src/rundir.rs:619-652)".
///
/// **This trait returns a `bool` and takes a public run directory, and both
/// halves of that signature are load-bearing.** The same passage says "the
/// coordinator incarnation id is a per-process ULID recorded in
/// run_started(4)/run_resumed(4) and is **never read from lock-file contents**
/// (run.lock content is never read: src/rundir.rs:886; a Windows exclusive lock
/// makes it unreadable to non-holders)". Deriving an incarnation from the lock
/// is a plausible implementation and a real defect; a seam whose answer is one
/// bit makes it **structurally impossible** — there is no incarnation in the
/// return type to read.
///
/// Kept out of [`ContainerRuntime`] for the same reason: liveness is a question
/// about a lock file on this host, not about the container runtime, and a
/// runtime that could answer it would be a runtime that had opened a run lock.
pub trait OwnerLiveness: Send + Sync {
    /// Whether a coordinator holds the run lock of the run whose **public**
    /// directory this is.
    fn is_running(&self, public_run_dir: &Path) -> bool;
}

/// The production answer: `rundir::is_running`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LockProbe;

impl OwnerLiveness for LockProbe {
    fn is_running(&self, public_run_dir: &Path) -> bool {
        crate::rundir::is_running(public_run_dir)
    }
}

// ---------------------------------------------------------------------------
// The trace
// ---------------------------------------------------------------------------

/// Which half of a funnel call a trace entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracePhase {
    Before,
    After,
}

impl TracePhase {
    /// As it is written in a trace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// A durable step of a record write, recorded where it happens.
///
/// The sibling of [`crate::util::DurableStep`], and a separate enum for one
/// reason: this trace interleaves durability with runtime calls and funnel
/// phases in **one order**, and `util`'s ledger is a separate list. "Intent
/// **synced** before docker create" is a statement about one sequence
/// containing both, so both have to be in the same sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableStep {
    /// The staged file's bytes are written and fsynced.
    Synced,
    /// The atomic rename onto the published name.
    Renamed,
    /// The containing directory is fsynced, which is what makes the rename
    /// durable.
    DirSynced,
    /// A file was removed.
    Removed,
}

impl DurableStep {
    /// As it is written in a trace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Renamed => "renamed",
            Self::DirSynced => "dir-synced",
            Self::Removed => "removed",
        }
    }
}

/// One thing that happened, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEntry {
    /// A funnel reached a hook phase of a site.
    Site {
        site: ContainerSite,
        phase: TracePhase,
    },
    /// A runtime operation was issued.
    Runtime { op: RuntimeOp, target: String },
    /// A durability step of a record write.
    Durable { step: DurableStep, path: PathBuf },
    /// A Git view was materialised or discarded (R19).
    View { action: ViewAction, path: PathBuf },
}

/// What happened to a Git view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewAction {
    Materialized,
    Discarded,
}

impl ViewAction {
    /// As it is written in a trace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Materialized => "materialized",
            Self::Discarded => "discarded",
        }
    }
}

impl TraceEntry {
    /// A short, stable rendering, so a test can assert on a `Vec<&str>`.
    ///
    /// Orderings are most of this slice's contract and "a suite that proves the
    /// set of operations happened without pinning their order holds none of
    /// them". A sequence of strings is the cheapest thing to write an ordering
    /// assertion against, which is the point: an assertion nobody writes holds
    /// nothing either.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Site { site, phase } => format!("site:{}:{}", site.name(), phase.name()),
            Self::Runtime { op, target } => format!("rt:{}:{target}", op.name()),
            Self::Durable { step, path } => format!(
                "durable:{}:{}",
                step.name(),
                path.file_name().map_or_else(
                    || path.to_string_lossy().into_owned(),
                    |name| name.to_string_lossy().into_owned()
                )
            ),
            Self::View { action, path } => format!(
                "view:{}:{}",
                action.name(),
                path.file_name().map_or_else(
                    || path.to_string_lossy().into_owned(),
                    |name| name.to_string_lossy().into_owned()
                )
            ),
        }
    }
}

/// An ordered record of everything the funnel and the runtime did.
///
/// A cloneable handle over a shared log, like [`crate::util::DurabilityLedger`]
/// and for the same reason: the funnel holds `&mut dyn ContainerHooks` across
/// its body, so the body cannot borrow the observer again. Both the funnel and
/// the runtime take a clone of one handle, which is what puts their entries in
/// one order.
#[derive(Debug, Clone, Default)]
pub struct ContainerTrace(Option<Arc<Mutex<Vec<TraceEntry>>>>);

impl ContainerTrace {
    /// A trace that records nothing. What production passes.
    #[must_use]
    pub fn off() -> Self {
        Self(None)
    }

    /// A trace that records. What a test passes.
    #[must_use]
    pub fn recording() -> Self {
        Self(Some(Arc::new(Mutex::new(Vec::new()))))
    }

    /// Whether this trace records at all.
    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.0.is_some()
    }

    /// Append one entry.
    pub fn push(&self, entry: TraceEntry) {
        if let Some(log) = &self.0 {
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(entry);
        }
    }

    /// Record a funnel phase.
    pub fn site(&self, site: ContainerSite, phase: TracePhase) {
        self.push(TraceEntry::Site { site, phase });
    }

    /// Record a runtime operation.
    pub fn runtime(&self, op: RuntimeOp, target: &str) {
        self.push(TraceEntry::Runtime {
            op,
            target: target.to_owned(),
        });
    }

    /// Record a durability step.
    pub fn durable(&self, step: DurableStep, path: &Path) {
        self.push(TraceEntry::Durable {
            step,
            path: path.to_path_buf(),
        });
    }

    /// Record a Git view action.
    pub fn view(&self, action: ViewAction, path: &Path) {
        self.push(TraceEntry::View {
            action,
            path: path.to_path_buf(),
        });
    }

    /// Everything recorded so far, in order.
    #[must_use]
    pub fn entries(&self) -> Vec<TraceEntry> {
        self.0.as_ref().map_or_else(Vec::new, |log| {
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
    }

    /// Everything recorded so far, rendered, in order.
    #[must_use]
    pub fn rendered(&self) -> Vec<String> {
        self.entries().iter().map(TraceEntry::render).collect()
    }

    /// Only the site phases, in order — the sequence the eight-site contract is
    /// written in.
    #[must_use]
    pub fn sites(&self) -> Vec<(ContainerSite, TracePhase)> {
        self.entries()
            .into_iter()
            .filter_map(|entry| match entry {
                TraceEntry::Site { site, phase } => Some((site, phase)),
                _ => None,
            })
            .collect()
    }

    /// Only the runtime operations, in order.
    #[must_use]
    pub fn ops(&self) -> Vec<RuntimeOp> {
        self.entries()
            .into_iter()
            .filter_map(|entry| match entry {
                TraceEntry::Runtime { op, .. } => Some(op),
                _ => None,
            })
            .collect()
    }

    /// The index of the first entry whose rendering is exactly `needle`.
    ///
    /// The ordering assertions in this slice are all of the form "x happened
    /// before y", and comparing two positions is how that is said.
    #[must_use]
    pub fn position(&self, needle: &str) -> Option<usize> {
        self.rendered().iter().position(|entry| entry == needle)
    }

    /// The index of the first entry whose rendering starts with `prefix`.
    #[must_use]
    pub fn position_starting(&self, prefix: &str) -> Option<usize> {
        self.rendered()
            .iter()
            .position(|entry| entry.starts_with(prefix))
    }

    /// Forget everything recorded so far, keeping the handle.
    pub fn clear(&self) {
        if let Some(log) = &self.0 {
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }
}
