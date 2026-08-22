//! The **Container funnel** — `FunnelGroup::Container.module()` is this file.
//!
//! `decisions.effect_site_inventory.identity`: "every effectful funnel API
//! takes its group's site by value, and the funnel itself calls `hook(Before,
//! site)` -> primitive -> `hook(After, site)`, so hooks exist for every site by
//! construction". `ContainerSite` in the frozen `src/topology/effects.rs` has
//! **eight** variants and all eight are taken by value by an API here.
//!
//! ## Why this is a file and not `container/mod.rs`
//!
//! `FunnelGroup::Container.module()` returns the literal
//! `"src/runner/container.rs"` and
//! `effects::tests::every_site_the_inventory_declares_has_a_funnel_that_names_it_or_is_recorded_absent`
//! reads exactly that path. `container/mod.rs` would make the inventory's
//! `module` column false of this tree — `PR5-CONF-018` is the standing entry
//! for what that costs. Rust 2018 path style makes this file plus
//! `src/runner/container/*.rs` the ordinary layout, so both hold at once.
//!
//! ## What "impossible to bypass" can and cannot mean here
//!
//! Rust module privacy cannot isolate siblings under a shared ancestor: an item
//! private to `runner::container` is visible to `runner::container::census` and
//! to every other module a lane adds beside it, so no token, sealed trait or
//! private constructor makes a bypass a **compile** error from inside this
//! subtree. The project's own mechanism for exactly this is
//! `decisions.effect_site_inventory.mechanism` (1)-(2), and it is a **build**
//! error rather than a compile one:
//!
//! * every effectful method of [`runtime::ContainerRuntime`] and of [`GitView`]
//!   is on `clippy.toml`'s disallowed list — "docker invocation helpers" is the
//!   packet's own phrase for them — so a module that calls one fails
//!   `cargo clippy -- -D warnings` unless it is in `effects/allowlist.toml`,
//!   which is a reviewed artifact at every gate;
//! * [`tests::every_container_effect_in_the_tree_goes_through_the_funnel`] is
//!   the source census beside it, in the idiom of
//!   `runner::tests::every_production_process_start_is_classified`: it names
//!   every file that may issue a container effect and fails when a new one
//!   appears.
//!
//! `PR5D-PROCESS-FUNNEL-TAKES-NO-SITE` records what happens when a group has no
//! funnel that names its sites, and `PR5D-FUNNEL-RETURNS-A-COMMAND` what
//! happens when one hands a writable handle back. Neither is repeated here: the
//! site travels with every call, and no API returns a runtime handle, a
//! `Command`, or a `File`.
//!
//! ## The orderings
//!
//! `slice_contract.side_effect_vs_event_ordering` is the whole of this module's
//! contract: "no events; intent synced before docker create; container created
//! from the recorded id and verified before start; view mounted before start;
//! stop/rm, view removal, intent removal after completion". Each clause is an
//! independently droppable predicate, so [`launch`] and [`release`] perform
//! them in one place and [`runtime::ContainerTrace`] records the sequence,
//! which is what the tests assert on.
// Allowlist placement: the **funnel section** of `effects/allowlist.toml`, which
// carries this module's review clause -- effects only inside site-taking APIs,
// no writable handle returned. `decisions.effect_site_inventory.mechanism` (2).
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

// -- module declarations -------------------------------------------------
// APPEND ONLY. Lane A adds `exec`, `view` and `env`; lane C adds `census`.
// Keep every `#[cfg(test)]` declaration at the BOTTOM of this file:
// `effects::production_region` cuts a source at its FIRST `#[cfg(test)]`, so a
// test-only `mod` here would remove every funnel below it from the census that
// proves this group has a funnel at all (`PR5-R1-CFG-TEST-SHRINKS-THE-DOMAIN`).
pub mod census;
pub mod env;
pub mod exec;
pub mod intent;
pub mod runtime;
pub mod view;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::TactusError;
use crate::topology::effects::{ContainerSite, EffectSiteId, HookPhase, Injection};
use crate::util;

use intent::{ContainerIntent, ContainerName, INTENT_STAGED_SUFFIX, containers_dir};
use runtime::{
    ContainerExecution, ContainerRuntime, ContainerTrace, CreateSpec, CreatedContainer,
    DiscoveredContainer, DurableStep, Liveness, RuntimeError, RuntimeOp, StopMode, TracePhase,
    ViewAction,
};

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/// What the funnel consults at each phase of each site.
///
/// The sibling of [`crate::rundir::RunDirHooks`] and
/// [`crate::workspace_manager::EffectHooks`]. The site travels with the call
/// because this funnel serves eight sites, which is the shape
/// `effect_site_inventory.identity` describes in as many words.
pub trait ContainerHooks {
    /// The funnel reached `phase` of `site`. The answer says what to do there.
    fn phase(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection;

    /// Where this observer wants the funnel's ordered record kept.
    ///
    /// A *handle*, taken before the funnel body runs, because `funnel` holds
    /// `&mut dyn ContainerHooks` across the body — the same reason
    /// `EffectHooks::durability_ledger` is a handle. The default records
    /// nothing, which is what production passes.
    fn trace(&self) -> ContainerTrace {
        ContainerTrace::off()
    }
}

/// What production passes: nothing is armed and nothing is recorded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl ContainerHooks for NoHooks {
    fn phase(&mut self, _site: EffectSiteId, _phase: HookPhase) -> Injection {
        Injection::Proceed
    }
}

/// Turn a hook's answer into what the funnel must do at that point.
fn apply(injection: Injection, site: EffectSiteId, phase: HookPhase) -> Result<(), TactusError> {
    match injection {
        Injection::Proceed => Ok(()),
        Injection::Kill => std::process::abort(),
        Injection::Error => Err(TactusError::Refused {
            message: format!("the container funnel was made to fail at `{site}` ({phase})"),
        }),
    }
}

/// One effect, between its two hook phases, with its site recorded in the
/// trace on both sides.
///
/// An `Err` from the `After` phase is returned *after* the primitive ran, which
/// is the whole point of the error-return mode.
fn funnel<T>(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    primitive: impl FnOnce() -> Result<T, TactusError>,
) -> Result<T, TactusError> {
    let id = EffectSiteId::Container(site);
    let trace = hooks.trace();
    trace.site(site, TracePhase::Before);
    apply(hooks.phase(id, HookPhase::Before), id, HookPhase::Before)?;
    let produced = primitive()?;
    apply(hooks.phase(id, HookPhase::After), id, HookPhase::After)?;
    trace.site(site, TracePhase::After);
    Ok(produced)
}

// ---------------------------------------------------------------------------
// The site each API takes, and the guard that keeps the parameter honest
// ---------------------------------------------------------------------------

/// What a site names.
///
/// Every funnel API below takes `site: ContainerSite` **by value**, which is
/// what `identity` requires. A free parameter can be passed a wrong value, so
/// each API checks it against this map: passing `ContainerSite::Start` to
/// [`write_intent`] refuses, before any effect, rather than writing a record
/// under a label that lies about what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    WriteIntent,
    Create,
    Start,
    MountGitView,
    Stop,
    Remove,
    UnmountGitView,
    RemoveIntent,
}

/// The site-to-operation map, exhaustive over the frozen eight.
const fn operation_of(site: ContainerSite) -> Operation {
    match site {
        ContainerSite::WriteIntent => Operation::WriteIntent,
        ContainerSite::Create => Operation::Create,
        ContainerSite::Start => Operation::Start,
        ContainerSite::MountGitView => Operation::MountGitView,
        ContainerSite::Stop => Operation::Stop,
        ContainerSite::Remove => Operation::Remove,
        ContainerSite::UnmountGitView => Operation::UnmountGitView,
        ContainerSite::RemoveIntent => Operation::RemoveIntent,
    }
}

/// Refuse a site that does not name this operation.
fn expect_site(site: ContainerSite, wanted: Operation) -> Result<(), TactusError> {
    if operation_of(site) == wanted {
        return Ok(());
    }
    Err(TactusError::Refused {
        message: format!(
            "the container funnel was asked to perform {wanted:?} under site \
             `Container.{}`; every effectful funnel API takes its group's site by value \
             (decisions.effect_site_inventory.identity) and the site must name the \
             operation it accounts for",
            site.name()
        ),
    })
}

// ---------------------------------------------------------------------------
// The Git view (R19)
// ---------------------------------------------------------------------------

/// What a Git view needs to exist.
///
/// DESIGN.md:612: "the container overlays a disposable role-scoped Git view —
/// exact detached HEAD/index, no engine refs, read-only objects — so
/// Git-dependent tools work without exposing or mutating the coordinator's
/// refs."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitViewRequest {
    /// Where the view directory is materialised, on the host.
    pub path: PathBuf,
    /// The worktree the role is executing in.
    pub workspace: PathBuf,
    /// The commit the view is pinned to, when the projection needs one.
    pub head: Option<String>,
}

/// The R19 disposable Git view.
///
/// Its two methods are the primitives of `Container.MountGitView` and
/// `Container.UnmountGitView` and are on `clippy.toml`'s disallowed list, so
/// only this module calls them — [`mount_git_view`] and [`unmount_git_view`]
/// are the funnels, and they are what a caller uses.
///
/// **Lane A implements the projection.** [`DisposableDirView`] below is the
/// directory half — the R19 artifact whose lifecycle the resource row accounts
/// for ("mounted": "pruned on complete or cancel; orphan views reclaimed during
/// dead-owner or dead-incarnation container reclaim") — and it is what the
/// substrate's own tests and the reclaim path need. What it does **not** do is
/// the detached HEAD/index projection or the read-only object mount; those are
/// `src/runner/container/view.rs`.
pub trait GitView: Send + Sync {
    /// Bring the view into existence, returning where it is.
    ///
    /// # Errors
    ///
    /// [`TactusError::Io`] when the view cannot be materialised.
    fn materialize(&self, request: &GitViewRequest) -> Result<PathBuf, TactusError>;

    /// Remove it. **Idempotent**: an orphan view is reclaimed by whichever
    /// process gets there first, and reclaim converges.
    ///
    /// # Errors
    ///
    /// [`TactusError::Io`] when the view exists and cannot be removed.
    fn discard(&self, path: &Path) -> Result<(), TactusError>;
}

/// The directory half of the view: create it, remove it.
///
/// Not a stub — this is R19's whole physical artifact, and the row's lifecycle
/// is about the directory. Lane A's projection fills it.
#[derive(Debug, Clone, Default)]
pub struct DisposableDirView {
    trace: ContainerTrace,
}

impl DisposableDirView {
    /// A view whose actions are recorded in `trace`.
    #[must_use]
    pub fn new(trace: ContainerTrace) -> Self {
        Self { trace }
    }
}

impl GitView for DisposableDirView {
    fn materialize(&self, request: &GitViewRequest) -> Result<PathBuf, TactusError> {
        fs::create_dir_all(&request.path).map_err(|source| TactusError::Io {
            path: request.path.clone(),
            source,
        })?;
        self.trace.view(ViewAction::Materialized, &request.path);
        Ok(request.path.clone())
    }

    fn discard(&self, path: &Path) -> Result<(), TactusError> {
        // R19's half of "every step idempotent and tolerant of already-gone so
        // two concurrent reclaimers converge". The errno is not the question —
        // see [`RACING_ACCESS_ATTEMPTS`], and the Windows guest measurement that
        // put it there.
        racing_removal(path, || fs::remove_dir_all(path))?;
        self.trace.view(ViewAction::Discarded, path);
        Ok(())
    }
}

/// How many times a path that another reclaimer may be removing is asked about
/// before a failure is believed.
///
/// **The whole reason this exists is a platform difference, measured on the
/// Windows guest and invisible on Linux.** "every step idempotent and tolerant
/// of already-gone so two concurrent reclaimers converge" is usually written as
/// `if error.kind() == NotFound`, and on Windows the losing reclaimer does not
/// get `NotFound`: a file or directory another process is deleting is
/// **delete-pending**, and opening it answers `ERROR_ACCESS_DENIED` — `kind() ==
/// PermissionDenied` — until the winner's handle closes. An errno test
/// therefore cannot tell "somebody else is removing it" from "I may not touch
/// it", and tolerating `PermissionDenied` outright would silently treat a
/// genuinely protected path as reclaimed.
///
/// So the question asked is the **outcome**, not the errno: retry, and believe
/// the failure only once the path has stopped changing under it. Delete-pending
/// clears when the winner's own call returns, so this is a handoff rather than a
/// wait, and [`std::thread::yield_now`] is what it costs.
///
/// Bounded rather than timed, for the reason [`TERMINATION_OBSERVATIONS`] is: a
/// wait with no bound turns "this path cannot be removed" into "this write
/// command never returns".
pub const RACING_ACCESS_ATTEMPTS: usize = 64;

// ---------------------------------------------------------------------------
// The eight site-taking APIs
// ---------------------------------------------------------------------------

/// `Container.WriteIntent` (R26) — the synced global intent record.
///
/// "every container invocation writes a **synced** intent in the global
/// namespace `<R>/containers/<container-name>.intent`". Written the way every
/// other durable record in this engine is written: staged, fsynced, renamed,
/// and the directory fsynced — `run_creation`'s own four steps — each recorded
/// in the trace beside the primitive that performs it, so a deleted step is a
/// missing trace entry rather than an invisible loss of durability.
///
/// Returns the path of the published record, which is data and not a handle.
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation,
/// [`TactusError::Io`] on any filesystem failure, [`TactusError::Git`] when the
/// record will not serialize.
pub fn write_intent(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    private_root: &Path,
    name: &ContainerName,
    record: &ContainerIntent,
) -> Result<PathBuf, TactusError> {
    expect_site(site, Operation::WriteIntent)?;
    let path = name.intent_path(private_root);
    let trace = hooks.trace();
    funnel(hooks, site, || {
        let bytes = serde_json::to_vec(record).map_err(|error| TactusError::Git {
            message: format!("serializing the container intent for `{name}`: {error}"),
        })?;
        write_synced(&path, &bytes, &trace)?;
        Ok(path.clone())
    })
}

/// `Container.Create` (R26) — create the container **from an image id**.
///
/// INV-23: "every container of every epoch is created from the recorded image
/// id". [`CreateSpec`] carries no reference at all, so creating from one is not
/// expressible. The returned [`CreatedContainer::reported_image_id`] is the
/// runtime's own answer; [`launch`] verifies it against the record **before
/// start**.
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation or the
/// runtime refuses.
pub fn create_container(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    runtime: &dyn ContainerRuntime,
    spec: &CreateSpec,
) -> Result<CreatedContainer, TactusError> {
    expect_site(site, Operation::Create)?;
    funnel(hooks, site, || runtime.create(spec).map_err(refused))
}

/// `Container.Start` (R26).
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation or the
/// runtime refuses.
pub fn start_container(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    runtime: &dyn ContainerRuntime,
    name: &ContainerName,
) -> Result<(), TactusError> {
    expect_site(site, Operation::Start)?;
    funnel(hooks, site, || {
        runtime.start(name.as_str()).map_err(refused)
    })
}

/// `Container.MountGitView` (**R19**, not R26 — the view is its own row).
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation, or
/// whatever the projection returns.
pub fn mount_git_view(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    view: &dyn GitView,
    request: &GitViewRequest,
) -> Result<PathBuf, TactusError> {
    expect_site(site, Operation::MountGitView)?;
    funnel(hooks, site, || view.materialize(request))
}

/// `Container.Stop` (R26) — completion's `docker stop` and reclaim's `docker
/// kill`, which the frozen inventory accounts to one site.
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation or the
/// runtime refuses.
pub fn stop_container(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    runtime: &dyn ContainerRuntime,
    name: &ContainerName,
    mode: StopMode,
) -> Result<(), TactusError> {
    expect_site(site, Operation::Stop)?;
    funnel(hooks, site, || {
        runtime.stop(name.as_str(), mode).map_err(refused)
    })
}

/// `Container.Remove` (R26) — `docker rm`, idempotent.
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation or the
/// runtime refuses.
pub fn remove_container(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    runtime: &dyn ContainerRuntime,
    name: &ContainerName,
) -> Result<(), TactusError> {
    expect_site(site, Operation::Remove)?;
    funnel(hooks, site, || {
        runtime.remove(name.as_str()).map_err(refused)
    })
}

/// `Container.UnmountGitView` (R19), idempotent.
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation, or
/// whatever the projection returns.
pub fn unmount_git_view(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    view: &dyn GitView,
    path: &Path,
) -> Result<(), TactusError> {
    expect_site(site, Operation::UnmountGitView)?;
    funnel(hooks, site, || view.discard(path))
}

/// `Container.RemoveIntent` (R26), idempotent.
///
/// # Errors
///
/// [`TactusError::Refused`] when `site` does not name this operation,
/// [`TactusError::Io`] when the record exists and cannot be removed.
pub fn remove_intent(
    hooks: &mut dyn ContainerHooks,
    site: ContainerSite,
    private_root: &Path,
    name: &ContainerName,
) -> Result<(), TactusError> {
    expect_site(site, Operation::RemoveIntent)?;
    let path = name.intent_path(private_root);
    let trace = hooks.trace();
    funnel(hooks, site, || {
        // The staged half too: a crash between the stage and the rename leaves
        // `<name>.intent.tmp`, and a reclaim that removed only the published
        // name would leave writer-owned residue in a directory the census
        // enumerates.
        let staged = staged_path(&path);
        remove_if_present(&staged, &trace)?;
        remove_if_present(&path, &trace)
    })
}

// ---------------------------------------------------------------------------
// The sequences the contract states
// ---------------------------------------------------------------------------

/// Everything one container invocation needs.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    /// `<R>` — the run's **recorded** private root.
    pub private_root: PathBuf,
    pub name: ContainerName,
    pub intent: ContainerIntent,
    /// The create arguments. `spec.image_id` is the record's image id, and it
    /// is what the reported id is verified against.
    pub spec: CreateSpec,
    pub view: GitViewRequest,
}

/// A container that is running, and what it took to get there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launched {
    pub name: ContainerName,
    pub intent_path: PathBuf,
    pub view_path: PathBuf,
    /// The id the runtime reported, already verified equal to the record.
    pub reported_image_id: String,
}

/// The ordering `side_effect_vs_event_ordering` states, in one place.
///
/// > intent synced before docker create; container created from the recorded id
/// > and verified before start; view mounted before start
///
/// Four sites in that order, and the verification between `Create` and
/// everything after it. **This is also what makes "container start without an
/// intent is impossible by construction"** (`expected_failures_refusals[6]`)
/// true of the shape a caller uses: the only sequence that reaches
/// `Container.Start` begins by writing the intent.
///
/// On a reported image id that differs from the record the invocation is
/// **refused before start** and the container it created is released — R26's
/// "released on complete …, **cancel**, or shutdown" — so the ledger balances
/// and no unstarted container is left for a census to find.
///
/// # Errors
///
/// [`TactusError::Refused`] when the reported image id differs from the record,
/// or whatever a step returns.
pub fn launch(
    hooks: &mut dyn ContainerHooks,
    runtime: &dyn ContainerRuntime,
    view: &dyn GitView,
    plan: &LaunchPlan,
) -> Result<Launched, TactusError> {
    let intent_path = write_intent(
        hooks,
        ContainerSite::WriteIntent,
        &plan.private_root,
        &plan.name,
        &plan.intent,
    )?;
    let created = create_container(hooks, ContainerSite::Create, runtime, &plan.spec)?;
    if created.reported_image_id != plan.spec.image_id {
        let refusal = TactusError::Refused {
            message: format!(
                "the container runtime created `{}` and reports image id `{}`, and the run's \
                 recorded image id is `{}`; a created container whose reported image id \
                 differs from the record is refused before start (INV-23)",
                plan.name, created.reported_image_id, plan.spec.image_id
            ),
        };
        // Cancel: stop/rm and remove the intent. No view was mounted, so there
        // is no R19 residue to prune.
        stop_container(
            hooks,
            ContainerSite::Stop,
            runtime,
            &plan.name,
            StopMode::Graceful,
        )?;
        remove_container(hooks, ContainerSite::Remove, runtime, &plan.name)?;
        remove_intent(
            hooks,
            ContainerSite::RemoveIntent,
            &plan.private_root,
            &plan.name,
        )?;
        return Err(refusal);
    }
    let view_path = mount_git_view(hooks, ContainerSite::MountGitView, view, &plan.view)?;
    start_container(hooks, ContainerSite::Start, runtime, &plan.name)?;
    Ok(Launched {
        name: plan.name.clone(),
        intent_path,
        view_path,
        reported_image_id: created.reported_image_id,
    })
}

/// The completion half: "stop/rm, view removal, intent removal after
/// completion".
///
/// # Errors
///
/// Whatever a step returns.
pub fn release(
    hooks: &mut dyn ContainerHooks,
    runtime: &dyn ContainerRuntime,
    view: &dyn GitView,
    private_root: &Path,
    launched: &Launched,
) -> Result<(), TactusError> {
    stop_container(
        hooks,
        ContainerSite::Stop,
        runtime,
        &launched.name,
        StopMode::Graceful,
    )?;
    remove_container(hooks, ContainerSite::Remove, runtime, &launched.name)?;
    unmount_git_view(
        hooks,
        ContainerSite::UnmountGitView,
        view,
        &launched.view_path,
    )?;
    remove_intent(
        hooks,
        ContainerSite::RemoveIntent,
        private_root,
        &launched.name,
    )
}

/// How many times reclaim asks whether a container has terminated.
///
/// `determinism` forbids sleeps, so this is a bounded number of round trips and
/// not a timed wait: `docker kill` returns after the signal has been delivered,
/// and each observation is a fresh inspection. A container still running after
/// all of them "cannot be observed terminated", which
/// `crash_reconstruction` says "blocks admission".
pub const TERMINATION_OBSERVATIONS: usize = 8;

/// One container reclaimed, in the packet's own order.
///
/// > reclaim = docker kill -> wait until observed exited/removed -> docker rm
/// > -> remove Git view -> remove intent, every step idempotent and tolerant of
/// > already-gone so two concurrent reclaimers converge
///
/// The Git view path is the caller's, because a census reads it from the
/// intent's run directory rather than from a live [`Launched`].
///
/// # Errors
///
/// [`TactusError::Refused`] when the container cannot be observed terminated
/// within [`TERMINATION_OBSERVATIONS`] observations, or whatever a step
/// returns.
pub fn reclaim(
    hooks: &mut dyn ContainerHooks,
    runtime: &dyn ContainerRuntime,
    view: &dyn GitView,
    private_root: &Path,
    name: &ContainerName,
    view_path: Option<&Path>,
) -> Result<(), TactusError> {
    stop_container(hooks, ContainerSite::Stop, runtime, name, StopMode::Kill)?;
    observe_terminated(runtime, name)?;
    remove_container(hooks, ContainerSite::Remove, runtime, name)?;
    if let Some(path) = view_path {
        unmount_git_view(hooks, ContainerSite::UnmountGitView, view, path)?;
    }
    remove_intent(hooks, ContainerSite::RemoveIntent, private_root, name)
}

/// "wait until observed exited/removed" — a read-only observation, and so not
/// a site.
///
/// # Errors
///
/// [`TactusError::Refused`] when the container is still running after
/// [`TERMINATION_OBSERVATIONS`] observations, or when the runtime refuses.
pub fn observe_terminated(
    runtime: &dyn ContainerRuntime,
    name: &ContainerName,
) -> Result<Liveness, TactusError> {
    for _ in 0..TERMINATION_OBSERVATIONS {
        let state = runtime.observe(name.as_str()).map_err(refused)?;
        if state.is_terminated() {
            return Ok(state);
        }
    }
    Err(TactusError::Refused {
        message: format!(
            "`{name}` is still running after {TERMINATION_OBSERVATIONS} observations and \
             cannot be observed terminated; a dead owner's or dead incarnation's labeled \
             container that cannot be observed terminated blocks admission \
             (transaction_fault_matrix[T-CONTAINER].refusal_condition)"
        ),
    })
}

// ---------------------------------------------------------------------------
// The orphan window
// ---------------------------------------------------------------------------

/// Who closes the window between a coordinator's death and its containers being
/// reclaimed.
///
/// `decisions.admission_and_leases.permits.os_matrix`, in full:
///
/// > Linux and macOS (cfg(unix)): the cleanup reaper survives coordinator
/// > death, settles the dead coordinator's process groups while holding R28,
/// > and additionally kills the dead coordinator's labeled containers, closing
/// > the **orphan window**; Windows: **no reaper**; the ambient
/// > coordinator-joined Job Object ends every ordinary host descendant incl.
/// > suspended stubs at any spawn sub-step, private per-invocation jobs scope
/// > timeouts, and containers are reclaimed at the **next write-command start**
/// > (orphan window until then; documented; **a portable watchdog is
/// > deferred**).
///
/// A value rather than a comment, so the Windows guest — which has no container
/// runtime at all — still asserts something about containers, and so lane C's
/// census can report the window it is closing rather than infer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrphanWindow {
    /// `cfg(unix)`: the per-invocation cleanup reaper outlives the coordinator
    /// and kills its labeled containers.
    ClosedByTheUnixReaper,
    /// Windows: nothing runs between the death and the next `tactus` write
    /// command, so the containers survive until its startup census.
    UntilNextWriteCommandStart,
}

impl OrphanWindow {
    /// Both answers. Written out so the platform is an axis and not a constant.
    pub const ALL: &'static [Self] = &[
        Self::ClosedByTheUnixReaper,
        Self::UntilNextWriteCommandStart,
    ];

    /// Whether a reaper closes it.
    #[must_use]
    pub const fn closed_by_a_reaper(self) -> bool {
        match self {
            Self::ClosedByTheUnixReaper => true,
            Self::UntilNextWriteCommandStart => false,
        }
    }
}

/// This platform's orphan window.
#[must_use]
pub const fn orphan_window() -> OrphanWindow {
    #[cfg(unix)]
    {
        OrphanWindow::ClosedByTheUnixReaper
    }
    #[cfg(not(unix))]
    {
        OrphanWindow::UntilNextWriteCommandStart
    }
}

// ---------------------------------------------------------------------------
// Read-only observations of the global namespace
// ---------------------------------------------------------------------------

/// One intent record found in `<R>/containers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundIntent {
    pub name: ContainerName,
    pub path: PathBuf,
    pub record: ContainerIntent,
}

/// Read one record back.
///
/// # Errors
///
/// [`TactusError::Io`] when the file cannot be read, [`TactusError::Refused`]
/// when it is not a `ContainerIntent`.
pub fn read_intent(path: &Path) -> Result<ContainerIntent, TactusError> {
    let bytes = fs::read(path).map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|error| TactusError::Refused {
        message: format!("`{}` is not a container intent: {error}", path.display()),
    })
}

/// Read one record back, answering `None` when it went away under the read.
///
/// The read half of [`RACING_ACCESS_ATTEMPTS`]: on Windows a file another
/// process is deleting answers `PermissionDenied` until that delete completes,
/// so "is it gone?" is a question about the outcome and not about the first
/// errno. A record that is present and unreadable is still an error, after the
/// bound — silently skipping one would let a census admit over a container whose
/// ownership evidence it could not read.
///
/// # Errors
///
/// [`TactusError::Refused`] when the file is not a `ContainerIntent`,
/// [`TactusError::Io`] when it is still there and still unreadable after
/// [`RACING_ACCESS_ATTEMPTS`] attempts.
fn read_racing(path: &Path) -> Result<Option<ContainerIntent>, TactusError> {
    let mut last = None;
    for _ in 0..RACING_ACCESS_ATTEMPTS {
        match read_intent(path) {
            Ok(record) => return Ok(Some(record)),
            Err(TactusError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(TactusError::Io { source, .. }) => {
                last = Some(source);
                std::thread::yield_now();
            }
            // Not an IO answer at all: the bytes were read and are not a
            // record. Retrying cannot change that.
            Err(other) => return Err(other),
        }
    }
    Err(TactusError::Io {
        path: path.to_path_buf(),
        source: last.unwrap_or_else(|| {
            std::io::Error::other("the record could not be read and reported no reason")
        }),
    })
}

/// Every intent record under `<R>/containers`, sorted by name.
///
/// "discovery at every write-command start **scans the whole namespace
/// `<R>/containers`** of the command's authorized private root **and** docker
/// ps by `tactus.private_root`" — this is the first half; the second is
/// [`runtime::ContainerRuntime::containers_with_label`]. A missing directory is
/// an empty namespace, not an error: a run that has never launched a container
/// has none.
///
/// The staged `<name>.intent.tmp` half is skipped: it is writer-owned residue
/// that no reader may adopt, exactly as `Answer.StageWrite`'s `.partial` is.
///
/// # Errors
///
/// [`TactusError::Io`] when the directory cannot be read, or whatever
/// [`read_intent`] returns.
pub fn list_intents(private_root: &Path) -> Result<Vec<FoundIntent>, TactusError> {
    let dir = containers_dir(private_root);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(TactusError::Io { path: dir, source }),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| TactusError::Io {
            path: dir.clone(),
            source,
        })?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if file_name.ends_with(INTENT_STAGED_SUFFIX) {
            continue;
        }
        let Some(name) = ContainerName::from_intent_file_name(&file_name)? else {
            continue;
        };
        let path = entry.path();
        // A record that vanished between the directory read and this one is a
        // record another reclaimer removed, and that is not an error: "every
        // step idempotent and tolerant of already-gone so **two concurrent
        // reclaimers converge**".
        //
        // Measured by lane C, not reasoned. With a bare `?` here,
        // `census::tests::concurrent_reclaimers_converge` refused with
        // `Io { NotFound }` on Linux in 2 of 20 runs, and with
        // `Io { PermissionDenied }` on the Windows guest — a whole write
        // command failing because another write command was tidying at the same
        // moment. A **malformed** record is still an error: "the record could
        // not be parsed" and "the record is gone" are different answers, and
        // only one of them licenses proceeding.
        let Some(record) = read_racing(&path)? else {
            continue;
        };
        found.push(FoundIntent { name, path, record });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(found)
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// A runtime failure, as the engine's error type.
fn refused(error: RuntimeError) -> TactusError {
    TactusError::Refused {
        message: error.to_string(),
    }
}

/// `<name>.intent` -> `<name>.intent.tmp`.
fn staged_path(path: &Path) -> PathBuf {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".tmp");
    PathBuf::from(staged)
}

/// Write `bytes` durably: stage, fsync, rename, fsync the directory.
///
/// `run_creation`'s own four steps, each recorded in `trace` beside the
/// primitive that performs it. The file and directory barriers are
/// [`util::fsync_file`] and [`util::fsync_dir`] — the one call each that
/// `effects::tests::every_file_durability_barrier_in_a_funnel_module_goes_through_one_call`
/// censuses — rather than a `sync_all` of this module's own.
fn write_synced(path: &Path, bytes: &[u8], trace: &ContainerTrace) -> Result<(), TactusError> {
    let parent = path.parent().ok_or_else(|| TactusError::Git {
        message: format!("{} has no parent directory", path.display()),
    })?;
    fs::create_dir_all(parent).map_err(|source| TactusError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let staged = staged_path(path);
    {
        let mut file = fs::File::create(&staged).map_err(|source| TactusError::Io {
            path: staged.clone(),
            source,
        })?;
        file.write_all(bytes).map_err(|source| TactusError::Io {
            path: staged.clone(),
            source,
        })?;
        util::fsync_file(&file).map_err(|source| TactusError::Io {
            path: staged.clone(),
            source,
        })?;
    }
    trace.durable(DurableStep::Synced, &staged);
    fs::rename(&staged, path).map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    trace.durable(DurableStep::Renamed, path);
    util::fsync_dir(parent).map_err(|source| TactusError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    trace.durable(DurableStep::DirSynced, parent);
    Ok(())
}

/// Remove a file that may not be there, or may be going away under another
/// reclaimer.
fn remove_if_present(path: &Path, trace: &ContainerTrace) -> Result<(), TactusError> {
    if racing_removal(path, || fs::remove_file(path))? {
        trace.durable(DurableStep::Removed, path);
    }
    Ok(())
}

/// Perform `remove` until the path is gone, however it went.
///
/// Answers whether **this** caller was the one that removed it, so a trace
/// records the removal once rather than once per reclaimer.
///
/// See [`RACING_ACCESS_ATTEMPTS`] for why this is not `if kind() == NotFound`.
///
/// # Errors
///
/// [`TactusError::Io`] when the path is still there, and still refusing, after
/// [`RACING_ACCESS_ATTEMPTS`] attempts.
fn racing_removal(
    path: &Path,
    mut remove: impl FnMut() -> Result<(), std::io::Error>,
) -> Result<bool, TactusError> {
    let mut last = None;
    for _ in 0..RACING_ACCESS_ATTEMPTS {
        match remove() {
            Ok(()) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                last = Some(error);
                std::thread::yield_now();
            }
        }
    }
    Err(TactusError::Io {
        path: path.to_path_buf(),
        source: last.unwrap_or_else(|| {
            std::io::Error::other("the path could not be removed and reported no reason")
        }),
    })
}

// ---------------------------------------------------------------------------
// The real runtime: the `docker` CLI
// ---------------------------------------------------------------------------

/// The program name. `non_goals[3]` is "remote runners", so this is the local
/// CLI and nothing configures a socket.
pub const DOCKER_PROGRAM: &str = "docker";

/// The `docker` CLI.
///
/// Every process it starts is a **coordinator-side control-plane** call, and
/// deliberately does **not** go through the Runner: DESIGN.md:612 is "Workers,
/// repository-controlled gates, and reviewers all cross the boundary;
/// authoritative Git and the event log never do", and asking the container
/// runtime what it holds is the same kind of thing as authoritative Git — it is
/// how the boundary is *built*, so it cannot execute inside it.
/// `runner::tests::every_production_process_start_is_classified` carries the
/// row that says so.
#[derive(Debug, Clone, Default)]
pub struct DockerCli {
    trace: ContainerTrace,
}

impl DockerCli {
    /// A CLI whose operations are recorded in `trace`.
    #[must_use]
    pub fn new(trace: ContainerTrace) -> Self {
        Self { trace }
    }

    /// Whether `docker` is on this machine and its daemon answers.
    ///
    /// Two questions and not one, because `docker` exits **non-zero** with a
    /// daemon-unreachable message when the binary is present and the daemon is
    /// not — the same shape as `codex login status`, whose exit code and output
    /// disagree.
    #[must_use]
    pub fn available() -> bool {
        util::find_program(DOCKER_PROGRAM).is_some()
            && Self::default()
                .exec(
                    RuntimeOp::Probe,
                    "daemon",
                    &["version", "--format", "{{.Server.Version}}"],
                )
                .is_ok()
    }

    /// Run one `docker` subcommand and capture it.
    ///
    /// `target` is what the call log names — the container, image or volume the
    /// operation is about, rather than the subcommand, so the trace of a real
    /// run and the trace of a fake one are the same shape.
    fn exec(&self, op: RuntimeOp, target: &str, args: &[&str]) -> Result<String, RuntimeError> {
        self.trace.runtime(op, target);
        let output = Command::new(DOCKER_PROGRAM)
            .args(args)
            .output()
            .map_err(|error| RuntimeError::Unreachable {
                operation: op,
                detail: format!("{DOCKER_PROGRAM} could not be started: {error}"),
            })?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        // The daemon-unreachable shape. `docker` reports it on stderr with a
        // zero-or-nonzero status depending on subcommand, so the classification
        // is by message rather than by code.
        if detail.contains("Cannot connect to the Docker daemon")
            || detail.contains("error during connect")
            || detail.contains("Is the docker daemon running")
        {
            return Err(RuntimeError::Unreachable {
                operation: op,
                detail,
            });
        }
        Err(RuntimeError::Failed {
            operation: op,
            detail,
        })
    }

    /// `docker inspect` a thing, tolerating "no such object" as absence.
    fn inspect(
        &self,
        op: RuntimeOp,
        target: &str,
        args: &[&str],
    ) -> Result<Option<String>, RuntimeError> {
        match self.exec(op, target, args) {
            Ok(text) => Ok(Some(text)),
            Err(RuntimeError::Failed { detail, .. }) if is_absent(&detail) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// An image inspection from `docker image inspect`'s Go-template output.
    fn image(
        &self,
        op: RuntimeOp,
        reference: &str,
    ) -> Result<Option<ImageInspectionRaw>, RuntimeError> {
        let Some(text) = self.inspect(
            op,
            reference,
            &[
                "image",
                "inspect",
                reference,
                "--format",
                "{{.Id}}\u{1f}{{join .RepoDigests \",\"}}\u{1f}{{join .RepoTags \",\"}}",
            ],
        )?
        else {
            return Ok(None);
        };
        let line = text.lines().next().unwrap_or_default();
        let fields: Vec<&str> = line.split('\u{1f}').collect();
        let id = fields
            .first()
            .copied()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if id.is_empty() {
            return Err(RuntimeError::Failed {
                operation: op,
                detail: format!("`docker image inspect {reference}` reported no image id"),
            });
        }
        Ok(Some(ImageInspectionRaw {
            id,
            digests: split_list(fields.get(1).copied().unwrap_or_default()),
            tags: split_list(fields.get(2).copied().unwrap_or_default()),
        }))
    }
}

/// What `docker image inspect` reported, before it becomes an
/// [`runtime::ImageInspection`].
struct ImageInspectionRaw {
    id: String,
    digests: Vec<String>,
    tags: Vec<String>,
}

impl ImageInspectionRaw {
    fn into_inspection(self) -> runtime::ImageInspection {
        runtime::ImageInspection {
            id: self.id,
            // "the manifest digest **when reported**". An image built locally
            // and never pushed has no repo digest, and `None` is the record
            // INV-23 asks for in that case.
            digest: self
                .digests
                .into_iter()
                .next()
                .and_then(|entry| entry.rsplit('@').next().map(str::to_owned)),
            references: self.tags,
        }
    }
}

/// A comma-separated Go-template list, with the empty case as an empty vector.
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether a `docker` failure means "the object is not there".
fn is_absent(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("no such object")
        || lower.contains("no such container")
        || lower.contains("no such image")
        || lower.contains("no such volume")
        || lower.contains("is already in progress")
}

impl ContainerRuntime for DockerCli {
    fn probe(&self) -> Result<(), RuntimeError> {
        self.exec(
            RuntimeOp::Probe,
            "daemon",
            &["version", "--format", "{{.Server.Version}}"],
        )
        .map(|_| ())
    }

    fn image_by_reference(
        &self,
        reference: &str,
    ) -> Result<Option<runtime::ImageInspection>, RuntimeError> {
        Ok(self
            .image(RuntimeOp::InspectImageByReference, reference)?
            .map(ImageInspectionRaw::into_inspection))
    }

    fn image_by_id(&self, id: &str) -> Result<Option<runtime::ImageInspection>, RuntimeError> {
        let Some(found) = self.image(RuntimeOp::InspectImageById, id)? else {
            return Ok(None);
        };
        // `docker image inspect` resolves a *prefix* of an id and a tag alike,
        // so an answer whose id is not the value asked for is not an answer to
        // this question. The rebuild path's refusal is "the recorded image id
        // is absent from the runtime", and a different id present is exactly
        // that.
        if found.id != id {
            return Ok(None);
        }
        Ok(Some(found.into_inspection()))
    }

    fn volume_present(&self, name: &str) -> Result<bool, RuntimeError> {
        Ok(self
            .inspect(
                RuntimeOp::InspectVolume,
                name,
                &["volume", "inspect", name, "--format", "{{.Name}}"],
            )?
            .is_some())
    }

    fn containers_with_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Vec<DiscoveredContainer>, RuntimeError> {
        let filter = format!("label={key}={value}");
        let text = self.exec(
            RuntimeOp::ListByLabel,
            value,
            &[
                "ps",
                "--all",
                "--filter",
                &filter,
                "--format",
                "{{.Names}}\u{1f}{{.Labels}}",
            ],
        )?;
        let mut found = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let mut fields = line.split('\u{1f}');
            let name = fields.next().unwrap_or_default().trim().to_owned();
            if name.is_empty() {
                continue;
            }
            let mut labels = BTreeMap::new();
            for pair in fields.next().unwrap_or_default().split(',') {
                if let Some((key, value)) = pair.split_once('=') {
                    labels.insert(key.trim().to_owned(), value.trim().to_owned());
                }
            }
            found.push(DiscoveredContainer { name, labels });
        }
        Ok(found)
    }

    fn observe(&self, name: &str) -> Result<Liveness, RuntimeError> {
        let Some(text) = self.inspect(
            RuntimeOp::Observe,
            name,
            &[
                "container",
                "inspect",
                name,
                "--format",
                "{{.State.Status}}",
            ],
        )?
        else {
            return Ok(Liveness::Gone);
        };
        match text.trim() {
            "running" | "restarting" | "paused" | "removing" => Ok(Liveness::Running),
            _ => Ok(Liveness::Exited),
        }
    }

    fn collect(&self, name: &str) -> Result<ContainerExecution, RuntimeError> {
        let status = self
            .inspect(
                RuntimeOp::Collect,
                name,
                &[
                    "container",
                    "inspect",
                    name,
                    "--format",
                    "{{.State.ExitCode}}",
                ],
            )?
            .ok_or_else(|| RuntimeError::Failed {
                operation: RuntimeOp::Collect,
                detail: format!("`{name}` is gone, so its exit status cannot be collected"),
            })?;
        let exit_code = status.trim().parse::<i32>().ok();
        let stdout = self.exec(RuntimeOp::Collect, name, &["logs", name])?;
        Ok(ContainerExecution {
            exit_code,
            // `docker logs` interleaves both streams on a container without a
            // TTY unless asked otherwise; lane A separates them when it wires
            // the ContainerRunner. Recorded here rather than silently merged.
            stdout: stdout.into_bytes(),
            stderr: Vec::new(),
        })
    }

    fn create(&self, spec: &CreateSpec) -> Result<CreatedContainer, RuntimeError> {
        let mut args: Vec<String> =
            vec!["create".to_owned(), "--name".to_owned(), spec.name.clone()];
        for (key, value) in &spec.labels {
            args.push("--label".to_owned());
            args.push(format!("{key}={value}"));
        }
        for mount in &spec.mounts {
            args.push("--mount".to_owned());
            args.push(mount_argument(mount));
        }
        for (key, value) in &spec.env {
            args.push("--env".to_owned());
            args.push(format!("{key}={value}"));
        }
        if let Some(workdir) = &spec.workdir {
            args.push("--workdir".to_owned());
            args.push(workdir.clone());
        }
        // The **image id**, never a reference (INV-23).
        args.push(spec.image_id.clone());
        args.extend(spec.command.iter().cloned());
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        self.exec(RuntimeOp::Create, &spec.name, &borrowed)?;
        // The id the runtime says it used, read back from the created
        // container. Never `spec.image_id`: the whole point of the check the
        // caller then performs is that these two can differ.
        let reported = self
            .inspect(
                RuntimeOp::Create,
                &spec.name,
                &["container", "inspect", &spec.name, "--format", "{{.Image}}"],
            )?
            .ok_or_else(|| RuntimeError::Failed {
                operation: RuntimeOp::Create,
                detail: format!("`{}` was created and cannot be inspected", spec.name),
            })?;
        Ok(CreatedContainer {
            name: spec.name.clone(),
            reported_image_id: reported.trim().to_owned(),
        })
    }

    fn start(&self, name: &str) -> Result<(), RuntimeError> {
        self.exec(RuntimeOp::Start, name, &["start", name])
            .map(|_| ())
    }

    fn stop(&self, name: &str, mode: StopMode) -> Result<(), RuntimeError> {
        let verb = match mode {
            StopMode::Graceful => "stop",
            StopMode::Kill => "kill",
        };
        match self.exec(RuntimeOp::Stop, name, &[verb, name]) {
            Ok(_) => Ok(()),
            // Tolerant of already-gone and of already-stopped: two concurrent
            // reclaimers converge.
            Err(RuntimeError::Failed { detail, .. })
                if is_absent(&detail) || detail.contains("is not running") =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn remove(&self, name: &str) -> Result<(), RuntimeError> {
        match self.exec(RuntimeOp::Remove, name, &["rm", "--force", name]) {
            Ok(_) => Ok(()),
            Err(RuntimeError::Failed { detail, .. }) if is_absent(&detail) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// One `--mount` argument.
fn mount_argument(mount: &runtime::Mount) -> String {
    let mut parts = Vec::new();
    match mount {
        runtime::Mount::Path { source, target, .. } => {
            parts.push("type=bind".to_owned());
            parts.push(format!(
                "source={}",
                source.to_string_lossy().replace('\\', "/")
            ));
            parts.push(format!("target={target}"));
        }
        runtime::Mount::Volume { name, target, .. } => {
            parts.push("type=volume".to_owned());
            parts.push(format!("source={name}"));
            parts.push(format!("target={target}"));
        }
    }
    if mount.read_only() {
        parts.push("readonly".to_owned());
    }
    parts.join(",")
}

// -- test-only declarations ----------------------------------------------
// At the BOTTOM, deliberately: `effects::production_region` cuts a source at
// its first `#[cfg(test)]`, so a test module declared above would remove every
// funnel in this file from the census that proves the Container group has one
// (`PR5-R1-CFG-TEST-SHRINKS-THE-DOMAIN`).
#[cfg(test)]
mod fake;

#[cfg(test)]
pub(crate) use fake::{
    DOCKER_GATED_TESTS, FakeOwnerLiveness, FakeRuntime, RecordingHooks, docker_gate,
};

#[cfg(test)]
mod tests;
