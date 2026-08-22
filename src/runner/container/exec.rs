//! The container [`Runner`]: mounts, environment, supervision, and the one
//! path every container invocation of a run takes.
//!
//! DESIGN.md:118 gives a runner "cwd, mounts, environment, supervision, and
//! timeout, never agent semantics or Git", and DESIGN.md:612 narrows what this
//! one may know: "the runner learns nothing about agent semantics beyond
//! **which per-agent credential volume to mount**". That sentence is the whole
//! design of this module — the only agent-shaped thing in it is a volume name
//! taken from the run's recorded `RunnerPolicy`.
//!
//! ## Everything goes through one function, and that is load-bearing
//!
//! DESIGN.md:263: "**Probe and execution compose the same base, mounts,
//! reserved values, and overlay**, so pre-flight certifies the environment that
//! will actually spend." The natural implementation is two call sites that
//! happen to agree today, and it satisfies the sentence by accident until
//! somebody edits one of them. Here there is one: [`ContainerRunner::run`], and
//! the `RunnerPreflight` shell probe reaches it through
//! [`crate::runner::host::run_shell_probe`] — a free function over `&dyn
//! Runner`, written by PR4 for exactly this and not re-implemented here.
//! `tests::probe_and_execution_compose_through_one_code_path` counts the
//! composition sites in this module's production region and asserts there is
//! one.
//!
//! ## Ordering, and why this module does not call [`super::launch`]
//!
//! `slice_contract.side_effect_vs_event_ordering`: "no events; **intent synced
//! before docker create**; container created from the recorded id and
//! **verified before start**; **view mounted before start**; stop/rm, view
//! removal, intent removal after completion". Four independently droppable
//! predicates, and [`ContainerRunner::launch`] performs them in one place with
//! [`super::runtime::ContainerTrace`] recording the sequence.
//!
//! [`super::launch`] performs the same four sites in the order
//! `WriteIntent -> Create -> MountGitView -> Start`, which satisfies every
//! clause above and **cannot produce a working container**: the Git view is a
//! **bind-mount source** of the `docker create` call, and a bind source must
//! exist when the container is created. Measured against `docker` 29.7.2 —
//! `invalid mount config for type "bind": bind source path does not exist` —
//! which is what `real_docker_a_git_dependent_gate_sees_only_the_role_view`
//! reported the first time it ran. So the order here is
//! `WriteIntent -> MountGitView -> Create(+verify) -> Start`, which holds all
//! four clauses *and* works, and the eight site-taking APIs are called
//! directly rather than through a convenience whose order this caller cannot
//! use. The one-line repair to `super::launch` is
//! `PR6A-LAUNCH-MOUNTS-THE-VIEW-AFTER-CREATE` in the report; it is a lane F
//! file and is not changed from here.
//!
//! **`T-CONTAINER.boundary` reads "docker start issued; Git view mounted" and
//! the contract clause reads the opposite.** `RECONCILIATION-OBLIGATION.md` §C1
//! rules that `side_effect_vs_event_ordering` governs, and the measurement
//! above is a third, independent reason: a bind mount is declared at `create`
//! and cannot be added to a running container, so `T-CONTAINER`'s prose order
//! is not merely non-conforming — it does not run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::agent::ProcessOutput;
use crate::error::TactusError;
use crate::rundir::RunPaths;
use crate::runner::policy::runner_policy_sha256;
use crate::runner::{AgentId, ExecutionRole, Runner, RunnerRequest};
use crate::topology::events::{RunnerContract, RunnerKind, RunnerPolicy};

use super::env::{BoundaryLayout, ContainerEnvironment, RoleScope, supplies_credential_location};
use super::intent::{ContainerIntent, ContainerName};
use super::runtime::{ContainerRuntime, ContainerTrace, CreateSpec, Mount, RuntimeError};
use super::view::{self, RoleGitView};
use super::{
    ContainerHooks, GitView, GitViewRequest, LaunchPlan, Launched, NoHooks, create_container,
    mount_git_view, remove_container, remove_intent, start_container, stop_container,
    unmount_git_view, write_intent,
};
use crate::topology::effects::ContainerSite;

/// How much of a container's output is captured.
///
/// The host funnel bounds capture at 16 MiB per stream and terminates the tree
/// that exceeds it (`agent::proc`). A container runtime hands back whatever the
/// container wrote, so the bound is applied here — and the container is stopped
/// and removed either way, which is the same disposition the host's supervisor
/// reaches. Without it `ProcessOutput::output_limited` would be `false` for
/// every container invocation and
/// [`crate::runner::host::run_shell_probe`]'s bounded-output refusal would be
/// unreachable at this boundary while remaining reachable at the other — a
/// pre-flight that certifies less than the one it is paired with.
pub const OUTPUT_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// How often the supervisor asks whether the container has finished.
///
/// `decisions.tests_acceptance.determinism` forbids sleeps in the suite, so
/// this is a value and every test sets it to zero. A container that finishes
/// between two observations is observed at the second; a container that does
/// not finish by the request's deadline is stopped and removed.
pub const SUPERVISION_POLL: Duration = Duration::from_millis(25);

// ---------------------------------------------------------------------------
// Who owns the containers
// ---------------------------------------------------------------------------

/// The run whose containers these are.
///
/// The five fields the intent record carries that are properties of the *run*
/// rather than of the invocation — `crash_reconstruction`'s "owner run id, run
/// directory (public path), coordinator incarnation id, repo key" plus the
/// private root the namespace lives under. The sixth and seventh, the
/// invocation and the runner digest, come from the request and the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunIdentity {
    /// `<R>` — the run's **recorded** private root.
    pub private_root: PathBuf,
    /// The owner run id.
    pub run_id: String,
    /// The owner's **public** run directory.
    pub run_dir: PathBuf,
    /// The coordinator incarnation id: a per-process ULID, never read from a
    /// lock file.
    pub incarnation: String,
    /// The repo key.
    pub repo_key: String,
}

/// Whether this role receives its role's worktree.
///
/// DESIGN.md:400: "A container receives only **its role's one worktree** mount".
/// A probe has no worktree. [`crate::agent::probe_workspace`]'s own words are
/// "a probe asks a CLI about itself and **has no workspace of its own**", and
/// the value it returns is the **coordinator's current working directory** —
/// which at the host boundary is harmless and at this one is the repository
/// itself: the public log and authoritative Git in a single mount. So a probe's
/// container receives no worktree, no Git projection and no working directory,
/// and certifies exactly what a probe is for: that the recorded shell, or the
/// recorded agent CLI, runs inside the recorded image.
///
/// This is a **boundary** decision, which is what DESIGN.md:118 gives a runner
/// ("owns cwd, mounts, environment"), not a change to what a probe *is*: the
/// request, its role, its slot accounting and its `InvocationId` are untouched,
/// and the same request executes on the host exactly as it did before.
/// `PR6A-PROBE-WORKSPACE-IS-THE-COORDINATORS-CWD` in the report records the
/// other half — that a caller which wants a probe to have a workspace has no
/// way to say so.
///
/// Exhaustive with no wildcard: a role added later has to be classified here.
#[must_use]
pub const fn receives_a_worktree(role: &ExecutionRole) -> bool {
    match role {
        ExecutionRole::Implement | ExecutionRole::Gate | ExecutionRole::Review => true,
        ExecutionRole::Probe(_) => false,
    }
}

// ---------------------------------------------------------------------------
// The negative space
// ---------------------------------------------------------------------------

/// What a container must never receive.
///
/// DESIGN.md:400 names three — "A container receives only its role's one
/// worktree mount; it never receives **the public log**, **sibling worktrees**,
/// or **private artifacts**" — and DESIGN.md:612 names the fourth: "Workers,
/// repository-controlled gates, and reviewers all cross the boundary;
/// **authoritative Git** and the event log never do."
///
/// An enumeration rather than a list of paths, because the paths are derived
/// per run and the *categories* are what the passages fix. A category added
/// later has to name its passage here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Withheld {
    /// `<repo>/.tactus/runs/<run-id>` — `events.jsonl`, the frozen plan,
    /// questions, answers, artifacts.
    PublicLog,
    /// Every other role's worktree of this run, and the integration staging
    /// worktree.
    SiblingWorktree,
    /// `<R>/runs/<run-id>` — transcripts, reviews, per-attempt settings, gate
    /// logs — and `<R>/containers`, which is every container's ownership
    /// evidence.
    PrivateArtifacts,
    /// The repository's shared Git directory: every engine ref, and the
    /// coordinator's own `HEAD`.
    AuthoritativeGit,
}

impl Withheld {
    /// All four. Written out so a grid over categories is a grid over all of
    /// them.
    pub const ALL: &'static [Self] = &[
        Self::PublicLog,
        Self::SiblingWorktree,
        Self::PrivateArtifacts,
        Self::AuthoritativeGit,
    ];

    /// The passage that withholds it.
    #[must_use]
    pub const fn passage(self) -> &'static str {
        match self {
            Self::PublicLog => "DESIGN.md:400 — it never receives the public log",
            Self::SiblingWorktree => "DESIGN.md:400 — it never receives sibling worktrees",
            Self::PrivateArtifacts => "DESIGN.md:400 — it never receives private artifacts",
            Self::AuthoritativeGit => {
                "DESIGN.md:612 — authoritative Git and the event log never cross the boundary"
            }
        }
    }
}

/// The host paths one run withholds from every container of that run.
///
/// Built from [`RunPaths`] and [`crate::workspace_manager::execution_root_of`]
/// rather than from a list written here, so a layout change moves this set with
/// it. That is the point: "a test that checks *the worktree is mounted* passes
/// on a container that also mounts `/`", and a hand-written forbidden list
/// passes on a layout that has moved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confinement {
    entries: Vec<(Withheld, PathBuf)>,
}

impl Confinement {
    /// Everything `identity`'s run withholds.
    ///
    /// Derived from [`RunPaths`], which is the type that owns the layout, so
    /// this set moves when the layout moves. `run` adds one more per
    /// invocation: the workspace's **resolved** common Git directory, which is
    /// where a linked worktree's refs really are rather than where an assumed
    /// `<repo>/.git` would be.
    #[must_use]
    pub fn of_run(identity: &RunIdentity, repo_root: &Path) -> Self {
        let paths =
            RunPaths::with_private_root(repo_root, &identity.run_id, &identity.private_root);
        Self {
            entries: vec![
                (Withheld::PublicLog, paths.public),
                (Withheld::PrivateArtifacts, paths.private),
                (
                    Withheld::PrivateArtifacts,
                    super::intent::containers_dir(&identity.private_root),
                ),
                (Withheld::AuthoritativeGit, repo_root.join(".git")),
            ],
        }
    }

    /// An empty set, for a caller with no run — a probe before P0, and every
    /// fixture that is not about confinement.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Withhold one more path under `category`.
    #[must_use]
    pub fn withholding(mut self, category: Withheld, path: impl Into<PathBuf>) -> Self {
        self.entries.push((category, path.into()));
        self
    }

    /// Every withheld path, with its category.
    #[must_use]
    pub fn entries(&self) -> &[(Withheld, PathBuf)] {
        &self.entries
    }

    /// Which of `mounts` would hand a withheld path to the container.
    ///
    /// A mount **is** a withheld path, or is an **ancestor** of one. The
    /// ancestor half is the whole check: a container that mounts the repository
    /// root has mounted the public log, and a container that mounts `/` has
    /// mounted everything. A membership test — "is the public log in the mount
    /// list" — passes on both.
    #[must_use]
    pub fn violations(&self, mounts: &[Mount]) -> Vec<String> {
        let mut found = Vec::new();
        for mount in mounts {
            // A named volume has no host path, so it can carry none of these.
            let Mount::Path { source, target, .. } = mount else {
                continue;
            };
            for (category, withheld) in &self.entries {
                if withheld.starts_with(source) {
                    found.push(format!(
                        "the mount `{}` -> `{target}` would hand the container `{}` ({})",
                        source.display(),
                        withheld.display(),
                        category.passage()
                    ));
                }
            }
        }
        found
    }
}

// ---------------------------------------------------------------------------
// The recorded policy, read for what this runner needs
// ---------------------------------------------------------------------------

/// The recorded immutable image id.
///
/// INV-23: "every container of every epoch is created from **the recorded image
/// id** … so a moved reference cannot change what executes". The reference is
/// deliberately not read here and is not carried into [`CreateSpec`], which has
/// no field for one.
///
/// # Errors
///
/// [`TactusError::Refused`] when the policy is not a container policy or
/// records no image.
pub fn recorded_image_id(policy: &RunnerPolicy) -> Result<&str, TactusError> {
    if policy.kind != RunnerKind::Container || policy.policy != RunnerContract::ContainerV1 {
        return Err(TactusError::Refused {
            message: format!(
                "the container runner was given a `{:?}`/`{:?}` RunnerPolicy; \
                 `container-v1` is the mount, environment, Git-view and supervision \
                 contract this runner implements (INV-23)",
                policy.kind, policy.policy
            ),
        });
    }
    let Some(image) = &policy.image else {
        return Err(TactusError::Refused {
            message: "the recorded RunnerPolicy is a container policy with no image; INV-23 \
                      records `image: {reference, id, digest}` and every container is created \
                      from the recorded id"
                .to_owned(),
        });
    };
    if image.id.trim().is_empty() {
        return Err(TactusError::Refused {
            message: "the recorded RunnerPolicy carries an empty image id".to_owned(),
        });
    }
    Ok(&image.id)
}

/// The recorded per-agent credential volume names, or an empty map.
#[must_use]
pub fn recorded_volumes(policy: &RunnerPolicy) -> BTreeMap<String, String> {
    policy.credential_volumes.clone().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// What one request becomes before anything is created.
///
/// Returned by [`ContainerRunner::plan`] so a test can inspect the mounts, the
/// environment and the create spec **without** a runtime — which is what makes
/// the mount and environment obligations assertable on a machine with no
/// container runtime at all, including the Windows guest.
#[derive(Debug, Clone)]
pub struct InvocationPlan {
    /// The launch sequence's own plan: name, intent, create spec, view request.
    pub launch: LaunchPlan,
    /// The Git layout the view projects, when the workspace is a worktree.
    pub git: Option<view::GitLayout>,
}

impl InvocationPlan {
    /// The mounts this container receives.
    #[must_use]
    pub fn mounts(&self) -> &[Mount] {
        &self.launch.spec.mounts
    }

    /// The environment this container receives.
    #[must_use]
    pub fn env(&self) -> &[(String, String)] {
        &self.launch.spec.env
    }
}

/// The `Container` / `container-v1` [`Runner`].
///
/// Holds the **recorded** `RunnerPolicy` rather than resolving one: resolution
/// by read-only inspection is a separate obligation (INV-23, "resolved once by
/// read-only inspection before the worktree lock"), and a runner that resolved
/// its own policy could not be rebuilt from a record — which is what every
/// later incarnation does.
pub struct ContainerRunner {
    policy: RunnerPolicy,
    image_id: String,
    digest: String,
    volumes: BTreeMap<String, String>,
    identity: RunIdentity,
    environment: ContainerEnvironment,
    layout: BoundaryLayout,
    confinement: Confinement,
    runtime: Box<dyn ContainerRuntime>,
    view: Box<dyn GitView>,
    /// Whether [`ContainerRunner::with_view`] replaced the default projection.
    ///
    /// The default view has to be rebuilt whenever the layout or the observer
    /// moves — its alternate names the object store's in-container target and
    /// its trace is the observer's — and a builder whose result depended on the
    /// order its setters were called in is a builder that is wrong half the
    /// time. So the default is rebuilt by every setter and an explicit one
    /// never is.
    view_is_explicit: bool,
    hooks: Mutex<Box<dyn ContainerHooks + Send>>,
    poll: Duration,
    output_limit: usize,
}

impl std::fmt::Debug for ContainerRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerRunner")
            .field("policy", &self.policy)
            .field("digest", &self.digest)
            .field("identity", &self.identity)
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl ContainerRunner {
    /// A runner for `identity`'s run, executing in `policy`'s recorded image.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when `policy` is not a usable container policy
    /// — see [`recorded_image_id`].
    pub fn new(
        policy: RunnerPolicy,
        identity: RunIdentity,
        runtime: Box<dyn ContainerRuntime>,
    ) -> Result<Self, TactusError> {
        let image_id = recorded_image_id(&policy)?.to_owned();
        let digest = runner_policy_sha256(&policy);
        let volumes = recorded_volumes(&policy);
        let layout = BoundaryLayout::new();
        let view = RoleGitView::new(ContainerTrace::off())
            .for_reader(layout.git_view(), layout.git_objects());
        Ok(Self {
            policy,
            image_id,
            digest,
            volumes,
            identity,
            environment: ContainerEnvironment::inherited(),
            layout,
            confinement: Confinement::none(),
            runtime,
            view: Box::new(view),
            view_is_explicit: false,
            hooks: Mutex::new(Box::new(NoHooks)),
            poll: SUPERVISION_POLL,
            output_limit: OUTPUT_LIMIT_BYTES,
        })
    }

    /// Compose from an explicit image environment.
    #[must_use]
    pub fn with_environment(mut self, environment: ContainerEnvironment) -> Self {
        self.environment = environment;
        self
    }

    /// Use an explicit boundary layout, and point the Git view's alternate at
    /// its object mount.
    #[must_use]
    pub fn with_layout(mut self, layout: BoundaryLayout) -> Self {
        self.layout = layout;
        self.rebuild_view();
        self
    }

    /// Withhold this run's own paths from every container it starts.
    #[must_use]
    pub fn with_confinement(mut self, confinement: Confinement) -> Self {
        self.confinement = confinement;
        self
    }

    /// Observe (and, for the fault subset, inject at) every container site this
    /// runner reaches.
    #[must_use]
    pub fn with_hooks(mut self, hooks: Box<dyn ContainerHooks + Send>) -> Self {
        self.hooks = Mutex::new(hooks);
        self.rebuild_view();
        self
    }

    /// Use an explicit Git view implementation.
    #[must_use]
    pub fn with_view(mut self, view: Box<dyn GitView>) -> Self {
        self.view = view;
        self.view_is_explicit = true;
        self
    }

    /// Put the default projection back in step with the layout and the
    /// observer. A no-op once [`Self::with_view`] has replaced it.
    fn rebuild_view(&mut self) {
        if self.view_is_explicit {
            return;
        }
        self.view = Box::new(
            RoleGitView::new(self.trace())
                .for_reader(self.layout.git_view(), self.layout.git_objects()),
        );
    }

    /// How often the supervisor asks whether the container has finished.
    /// `Duration::ZERO` is what the suite sets: no sleeps.
    #[must_use]
    pub const fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// Bound the captured output at `bytes`.
    #[must_use]
    pub const fn with_output_limit(mut self, bytes: usize) -> Self {
        self.output_limit = bytes;
        self
    }

    /// The record this runner executes under.
    #[must_use]
    pub const fn policy(&self) -> &RunnerPolicy {
        &self.policy
    }

    /// `runner_policy_sha256` of [`Self::policy`] — every container intent
    /// carries it.
    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.digest
    }

    /// The boundary layout.
    #[must_use]
    pub const fn layout(&self) -> &BoundaryLayout {
        &self.layout
    }

    /// The environment contract this runner composes under.
    #[must_use]
    pub const fn environment(&self) -> &ContainerEnvironment {
        &self.environment
    }

    /// What this run withholds from every container.
    #[must_use]
    pub const fn confinement(&self) -> &Confinement {
        &self.confinement
    }

    fn trace(&self) -> ContainerTrace {
        self.hooks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .trace()
    }

    /// Everything one request becomes, without performing any effect.
    ///
    /// **This is the composition site**, and there is one: `Runner::run` calls
    /// it and so does every test that inspects a mount set, so a mount or an
    /// environment key that pre-flight sees and the spending invocation does
    /// not is not expressible.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when the overlay names a reserved key, when the
    /// container name cannot be built from the request's identity, or when the
    /// mount plan would hand the container a withheld path.
    pub fn plan(&self, request: &RunnerRequest) -> Result<InvocationPlan, TactusError> {
        let name = ContainerName::new(
            &self.identity.repo_key,
            &self.identity.run_id,
            &self.identity.incarnation,
            &request.invocation,
        )?;
        let intent = ContainerIntent {
            run_id: self.identity.run_id.clone(),
            run_dir: self.identity.run_dir.to_string_lossy().replace('\\', "/"),
            incarnation: self.identity.incarnation.clone(),
            repo_key: self.identity.repo_key.clone(),
            invocation: request.invocation.render(),
            runner_policy_sha256: self.digest.clone(),
        };

        let git = if receives_a_worktree(&request.role) {
            view::resolve(&request.workspace)?
        } else {
            None
        };
        let mounts = self.mounts(request, git.as_ref(), &name);
        let mut confinement = self.confinement.clone();
        if let Some(layout) = &git {
            // The worktree's *resolved* common directory, which is where a
            // linked worktree's refs really are — rather than an assumed
            // `<repo>/.git`.
            confinement =
                confinement.withholding(Withheld::AuthoritativeGit, layout.common_dir.clone());
        }
        let violations = confinement.violations(&mounts);
        if !violations.is_empty() {
            return Err(TactusError::Refused {
                message: format!(
                    "the container for `{}` would receive a path this run withholds: {}",
                    request.invocation.render(),
                    violations.join("; ")
                ),
            });
        }

        let scope = RoleScope {
            role: &request.role,
            agent: request.agent.as_ref(),
            volumes: &self.volumes,
            layout: &self.layout,
        };
        let env = self.environment.compose(&scope, &request.command.env)?;

        let mut command = vec![request.command.program.clone()];
        command.extend(request.command.args.iter().cloned());
        let view_path = view_dir(&self.identity.private_root, &name);

        Ok(InvocationPlan {
            launch: LaunchPlan {
                private_root: self.identity.private_root.clone(),
                spec: CreateSpec {
                    name: name.as_str().to_owned(),
                    // INV-23: the recorded **id**, never the reference.
                    image_id: self.image_id.clone(),
                    labels: intent.labels(&self.identity.private_root),
                    mounts,
                    env,
                    command,
                    workdir: receives_a_worktree(&request.role)
                        .then(|| self.layout.workspace().to_owned()),
                },
                view: GitViewRequest {
                    path: view_path.clone(),
                    // R19 is "per container invocation (**incl. shell and agent
                    // probes**)", so a probe gets its view directory too — and
                    // it has nothing to project. `GitViewRequest` has no
                    // "project nothing" state, so the request names a directory
                    // that is not a worktree, which is what the projection
                    // already treats as "no repository here". Recorded as a
                    // seam note rather than worked around silently.
                    workspace: if receives_a_worktree(&request.role) {
                        request.workspace.clone()
                    } else {
                        view_path
                    },
                    head: None,
                },
                name,
                intent,
            },
            git,
        })
    }

    /// The mounts this request's role receives, and no others.
    ///
    /// DESIGN.md:400: "A container receives **only its role's one worktree
    /// mount**". Four kinds, and each is here because a live passage puts it
    /// here:
    ///
    /// 1. the role's **one** worktree, `:ro` for a reviewer — DESIGN.md:610's
    ///    "a `:ro` mount makes the reviewer's read-only *mechanically* perfect
    ///    instead of flag-deep";
    /// 2. the disposable Git view, over the worktree's own `.git` —
    ///    DESIGN.md:612;
    /// 3. the object store the view borrows, **read-only** — the same sentence;
    /// 4. this agent's credential volume, for the roles that execute an agent
    ///    CLI — DESIGN.md:612's "which per-agent credential volume to mount",
    ///    and R20's "persistent volumes, not ephemeral copies", so it is
    ///    writable: "some CLIs rotate refresh tokens on use, and a discarded
    ///    rotation forces re-login".
    ///
    /// (2) and (3) are absent when the workspace is not a worktree — a probe's
    /// scratch directory — and (4) is absent for a role
    /// [`supplies_credential_location`] refuses. Nothing else is ever added,
    /// which is the positive half of the confinement claim; the negative half
    /// is [`Confinement::violations`].
    fn mounts(
        &self,
        request: &RunnerRequest,
        git: Option<&view::GitLayout>,
        name: &ContainerName,
    ) -> Vec<Mount> {
        let mut mounts = Vec::new();
        if receives_a_worktree(&request.role) {
            mounts.push(Mount::Path {
                source: request.workspace.clone(),
                target: self.layout.workspace().to_owned(),
                read_only: request.role == ExecutionRole::Review,
            });
        }
        if let Some(layout) = git {
            let view = view_dir(&self.identity.private_root, name);
            mounts.push(Mount::Path {
                source: view.clone(),
                target: self.layout.git_view().to_owned(),
                read_only: false,
            });
            mounts.push(Mount::Path {
                source: layout.objects.clone(),
                target: self.layout.git_objects().to_owned(),
                read_only: true,
            });
            // The overlay at `<workspace>/.git`. A bind mount's source and its
            // target must be the same kind — measured against `docker` 29.7.2,
            // which fails `runc create` with "Are you trying to mount a
            // directory onto a file" — so a linked worktree (a `.git` file)
            // receives the one-line pointer file and a main worktree (a `.git`
            // directory) receives the view directory itself. Either way what a
            // tool finds at `<workspace>/.git` is the disposable view.
            let source = if layout.dot_git_is_file {
                view.join(view::WORKTREE_GITFILE)
            } else {
                view
            };
            mounts.push(Mount::Path {
                source,
                target: self.layout.git_pointer(),
                read_only: false,
            });
        }
        if supplies_credential_location(&request.role) {
            if let Some(agent) = request.agent.as_ref() {
                if let Some(volume) = self.volumes.get(agent.as_str()) {
                    mounts.push(Mount::Volume {
                        name: volume.clone(),
                        target: self.layout.credentials(agent),
                        read_only: false,
                    });
                }
            }
        }
        mounts
    }

    /// The credential volume this request's role would be given, if any.
    ///
    /// Exposed so the mount rule and [`supplies_credential_location`] can be
    /// asserted to be **the same predicate** rather than two rules that agree
    /// today.
    #[must_use]
    pub fn credential_volume_for(
        &self,
        role: &ExecutionRole,
        agent: Option<&AgentId>,
    ) -> Option<&str> {
        if !supplies_credential_location(role) {
            return None;
        }
        agent
            .and_then(|agent| self.volumes.get(agent.as_str()))
            .map(String::as_str)
    }

    /// The four sites `side_effect_vs_event_ordering` puts before the
    /// invocation, in the order it states and in the order a container runtime
    /// can execute.
    ///
    /// > intent synced before docker create; container created from the
    /// > recorded id and verified before start; view mounted before start
    ///
    /// The Git view is materialised **before** `Container.Create` because it is
    /// a bind-mount source of that call and a bind source must exist when the
    /// container is created — see the module docs. Every clause the contract
    /// states still holds: the intent is synced before the create, the reported
    /// image id is verified before the start, and the view is mounted before
    /// the start.
    ///
    /// **This is also what makes "container start without an intent is
    /// impossible by construction"** (`expected_failures_refusals[6]`) true of
    /// the shape a caller uses: the only sequence in this module that reaches
    /// `Container.Start` begins by writing the intent.
    ///
    /// On a reported image id that differs from the record the invocation is
    /// **refused before start** and everything it created is released — R26's
    /// "released on complete …, **cancel**, or shutdown" and R19's "pruned on
    /// complete or **cancel**" — so both ledgers balance and no census finds
    /// residue of a refusal.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when the reported image id differs from the
    /// record, or whatever a step returns.
    fn launch(
        &self,
        hooks: &mut dyn ContainerHooks,
        plan: &LaunchPlan,
    ) -> Result<Launched, TactusError> {
        let intent_path = write_intent(
            hooks,
            ContainerSite::WriteIntent,
            &plan.private_root,
            &plan.name,
            &plan.intent,
        )?;
        let view_path = mount_git_view(
            hooks,
            ContainerSite::MountGitView,
            self.view.as_ref(),
            &plan.view,
        )?;
        let created = create_container(
            hooks,
            ContainerSite::Create,
            self.runtime.as_ref(),
            &plan.spec,
        )?;
        if created.reported_image_id != plan.spec.image_id {
            let refusal = TactusError::Refused {
                message: format!(
                    "the container runtime created `{}` and reports image id `{}`, and the \
                     run's recorded image id is `{}`; a created container whose reported image \
                     id differs from the record is refused before start (INV-23)",
                    plan.name, created.reported_image_id, plan.spec.image_id
                ),
            };
            self.release(
                hooks,
                &plan.private_root,
                &Launched {
                    name: plan.name.clone(),
                    intent_path,
                    view_path,
                    reported_image_id: created.reported_image_id,
                },
            )?;
            return Err(refusal);
        }
        start_container(
            hooks,
            ContainerSite::Start,
            self.runtime.as_ref(),
            &plan.name,
        )?;
        Ok(Launched {
            name: plan.name.clone(),
            intent_path,
            view_path,
            reported_image_id: created.reported_image_id,
        })
    }

    /// "stop/rm, view removal, intent removal **after completion**".
    ///
    /// The same four sites [`super::release`] performs and in the same order;
    /// written here because [`Self::launch`] is, and one sequence that a reader
    /// can check against the contract clause beats two halves in two files.
    ///
    /// # Errors
    ///
    /// Whatever a step returns.
    fn release(
        &self,
        hooks: &mut dyn ContainerHooks,
        private_root: &Path,
        launched: &Launched,
    ) -> Result<(), TactusError> {
        stop_container(
            hooks,
            ContainerSite::Stop,
            self.runtime.as_ref(),
            &launched.name,
            super::runtime::StopMode::Graceful,
        )?;
        remove_container(
            hooks,
            ContainerSite::Remove,
            self.runtime.as_ref(),
            &launched.name,
        )?;
        unmount_git_view(
            hooks,
            ContainerSite::UnmountGitView,
            self.view.as_ref(),
            &launched.view_path,
        )?;
        remove_intent(
            hooks,
            ContainerSite::RemoveIntent,
            private_root,
            &launched.name,
        )
    }

    /// Wait for the container, bounded by the request's own timeout.
    ///
    /// "timeout or shutdown stops and removes the container"
    /// (`slice_contract.cancellation`). The stop and the removal are the
    /// caller's [`super::release`]; this decides *which* disposition.
    fn supervise(&self, name: &ContainerName, deadline: Instant) -> Result<bool, TactusError> {
        loop {
            let state = self
                .runtime
                .observe(name.as_str())
                .map_err(refused_by_runtime)?;
            if state.is_terminated() {
                return Ok(false);
            }
            if Instant::now() >= deadline {
                return Ok(true);
            }
            if !self.poll.is_zero() {
                std::thread::sleep(self.poll);
            }
        }
    }
}

/// `<R>/views/<container-name>`.
///
/// Under the run's recorded private root, beside `<R>/containers`, so a census
/// that reclaims an orphan container has the view path without a live
/// [`Launched`] — which is exactly how [`super::reclaim`] takes it.
#[must_use]
pub fn view_dir(private_root: &Path, name: &ContainerName) -> PathBuf {
    private_root.join("views").join(name.as_str())
}

impl Runner for ContainerRunner {
    fn run(&self, request: &RunnerRequest) -> Result<ProcessOutput, TactusError> {
        let plan = self.plan(request)?;
        let started = Instant::now();
        let deadline = started + request.timeout;
        let mut hooks = self.hooks.lock().unwrap_or_else(PoisonError::into_inner);

        // WriteIntent -> MountGitView -> Create (+ verify the reported image
        // id) -> Start, in that order and in one place.
        let launched: Launched = self.launch(&mut **hooks, &plan.launch)?;

        let outcome = self.finish(&launched, started, deadline);
        // Release whatever the invocation reached, whether or not it succeeded:
        // R26 is "released on complete (stop/rm, view removed, intent removed),
        // **cancel**, or shutdown", and R19's "pruned on complete or cancel".
        // So the release runs on both paths and its own failure is reported
        // only when there is no earlier one to report — a release that could
        // not finish leaves residue the census reclaims, and hiding the reason
        // the invocation failed behind it would trade a diagnosis for a
        // symptom.
        let released = self.release(&mut **hooks, &self.identity.private_root, &launched);
        let output = outcome?;
        released?;
        Ok(output)
    }
}

impl ContainerRunner {
    /// Supervise, then collect. Split out so `run` can release on either path.
    fn finish(
        &self,
        launched: &Launched,
        started: Instant,
        deadline: Instant,
    ) -> Result<ProcessOutput, TactusError> {
        let timed_out = self.supervise(&launched.name, deadline)?;
        // Collected **before** the release: `docker logs` answers for a running
        // container and not for a removed one, so a timed-out invocation still
        // reports what it printed.
        let execution = self
            .runtime
            .collect(launched.name.as_str())
            .map_err(refused_by_runtime)?;
        let (stdout, stdout_limited) = bounded(&execution.stdout, self.output_limit);
        let (stderr, stderr_limited) = bounded(&execution.stderr, self.output_limit);
        Ok(ProcessOutput {
            // A container the supervisor stopped did not exit on its own,
            // whatever status the runtime reports afterwards — the same
            // disposition `agent::proc` gives a killed tree.
            code: if timed_out { None } else { execution.exit_code },
            stdout,
            stderr,
            duration: started.elapsed(),
            timed_out,
            output_limited: stdout_limited || stderr_limited,
        })
    }
}

/// A runtime failure, as the engine's error type.
fn refused_by_runtime(error: RuntimeError) -> TactusError {
    TactusError::Refused {
        message: error.to_string(),
    }
}

/// `bytes` as text, truncated at `limit`, and whether it was.
fn bounded(bytes: &[u8], limit: usize) -> (String, bool) {
    if bytes.len() <= limit {
        return (String::from_utf8_lossy(bytes).into_owned(), false);
    }
    let mut end = limit;
    // Do not split a UTF-8 sequence: back up to a character boundary.
    while end > 0 && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    (String::from_utf8_lossy(&bytes[..end]).into_owned(), true)
}

// -- test-only declarations ----------------------------------------------
// At the BOTTOM: `effects::production_region` cuts a source at its first
// `#[cfg(test)]` (`PR5-R1-CFG-TEST-SHRINKS-THE-DOMAIN`).
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::*;
    use crate::gates::ShellKind;
    use crate::rundir::RunPaths;
    use crate::runner::container::intent::LABEL_PRIVATE_ROOT;
    use crate::runner::container::runtime::{
        ContainerExecution, ContainerTrace, CreatedContainer, DiscoveredContainer, ImageInspection,
        Liveness, RuntimeOp, StopMode,
    };
    use crate::runner::container::view::fixtures as repo;
    use crate::runner::container::{
        DOCKER_GATED_TESTS, FakeRuntime, GitView, RecordingHooks, docker_gate, list_intents,
    };
    use crate::runner::host::{self, HostEnvironment};
    use crate::runner::invocation::AttemptRole;
    use crate::runner::{
        AgentId, InvocationId, ProbeTarget, RunnerRequest, gate_request, review_request,
        worker_request,
    };
    use crate::topology::events::{AttemptNumber, GenerationId, ImageIdentity};
    use crate::topology::registry::TaskKey;

    const RUN_ID: &str = "01KZRN48A4ZK3AEDST3RJ8HMA4";
    const REPO_KEY: &str = "0123456789abcdef";
    const INCARNATION_1: &str = "01KZTAAAAAAAAAAAAAAAAAAAAA";
    const INCARNATION_2: &str = "01KZTBBBBBBBBBBBBBBBBBBBBB";
    const IMAGE_ID: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_IMAGE_ID: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const IMAGE_REFERENCE: &str = "ghcr.io/example/tactus-runner:v1";
    const MANIFEST_DIGEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const VOLUMES: &[(&str, &str)] = &[
        ("claude-code", "tactus-creds-claude"),
        ("copilot", "tactus-creds-copilot"),
        ("codex", "tactus-creds-codex"),
    ];
    /// Written into the run's public log, so a container that could read it
    /// would be caught by content rather than by the absence of a file.
    const EVENT_LOG_MARKER: &str = "COORDINATOR-EVENT-LOG-a5f2";

    fn container_policy() -> RunnerPolicy {
        RunnerPolicy {
            kind: RunnerKind::Container,
            policy: RunnerContract::ContainerV1,
            image: Some(ImageIdentity {
                reference: IMAGE_REFERENCE.to_owned(),
                id: IMAGE_ID.to_owned(),
                digest: Some(MANIFEST_DIGEST.to_owned()),
            }),
            credential_volumes: Some(
                VOLUMES
                    .iter()
                    .map(|(agent, volume)| ((*agent).to_owned(), (*volume).to_owned()))
                    .collect(),
            ),
        }
    }

    // -----------------------------------------------------------------------
    // A runtime that can finish, and that a test keeps a handle on
    // -----------------------------------------------------------------------

    /// The fake, wrapped so a test can hold it while the runner owns it, and so
    /// a container can be made to **finish**.
    ///
    /// `FakeRuntime::start` leaves a container `Running` and nothing in a
    /// synchronous `Runner::run` could move it afterwards, so the success path
    /// would be unreachable and only the timeout path would ever be measured. A
    /// decorator that exits the container at `start` — and, when asked, gives
    /// it an exit status and output — is what makes both paths constructible;
    /// the plain fake still drives the timeout.
    #[derive(Debug)]
    struct Scripted {
        fake: FakeRuntime,
        exit_on_start: bool,
        execution: Mutex<Option<ContainerExecution>>,
    }

    #[derive(Debug, Clone)]
    struct Runtime(Arc<Scripted>);

    impl Runtime {
        fn new(trace: ContainerTrace, exit_on_start: bool) -> Self {
            let fake = FakeRuntime::new(trace);
            fake.add_image(IMAGE_ID, Some(MANIFEST_DIGEST));
            fake.add_image(OTHER_IMAGE_ID, None);
            fake.tag(IMAGE_REFERENCE, IMAGE_ID);
            for (_, volume) in VOLUMES {
                fake.add_volume(volume);
            }
            Self(Arc::new(Scripted {
                fake,
                exit_on_start,
                execution: Mutex::new(None),
            }))
        }

        fn fake(&self) -> &FakeRuntime {
            &self.0.fake
        }

        /// What every container of this runtime reports when it finishes.
        fn scripts(&self, execution: ContainerExecution) -> Self {
            *self
                .0
                .execution
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(execution);
            self.clone()
        }
    }

    impl ContainerRuntime for Runtime {
        fn probe(&self) -> Result<(), RuntimeError> {
            self.0.fake.probe()
        }
        fn image_by_reference(
            &self,
            reference: &str,
        ) -> Result<Option<ImageInspection>, RuntimeError> {
            self.0.fake.image_by_reference(reference)
        }
        fn image_by_id(&self, id: &str) -> Result<Option<ImageInspection>, RuntimeError> {
            self.0.fake.image_by_id(id)
        }
        fn volume_present(&self, name: &str) -> Result<bool, RuntimeError> {
            self.0.fake.volume_present(name)
        }
        fn containers_with_label(
            &self,
            key: &str,
            value: &str,
        ) -> Result<Vec<DiscoveredContainer>, RuntimeError> {
            self.0.fake.containers_with_label(key, value)
        }
        fn observe(&self, name: &str) -> Result<Liveness, RuntimeError> {
            self.0.fake.observe(name)
        }
        fn collect(&self, name: &str) -> Result<ContainerExecution, RuntimeError> {
            self.0.fake.collect(name)
        }
        fn create(&self, spec: &CreateSpec) -> Result<CreatedContainer, RuntimeError> {
            self.0.fake.create(spec)
        }
        fn start(&self, name: &str) -> Result<(), RuntimeError> {
            self.0.fake.start(name)?;
            if self.0.exit_on_start {
                self.0.fake.set_container_state(name, Liveness::Exited);
                if let Some(execution) = self
                    .0
                    .execution
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
                {
                    self.0.fake.set_execution(name, execution);
                }
            }
            Ok(())
        }
        fn stop(&self, name: &str, mode: StopMode) -> Result<(), RuntimeError> {
            self.0.fake.stop(name, mode)
        }
        fn remove(&self, name: &str) -> Result<(), RuntimeError> {
            self.0.fake.remove(name)
        }
    }

    // -----------------------------------------------------------------------
    // A realistic run layout
    // -----------------------------------------------------------------------

    /// One run, laid out where the engine really puts things.
    ///
    /// Every path here comes from the type that owns it — [`RunPaths`] for the
    /// two halves of a run directory, `workspace_manager::execution_root_of`
    /// for the worktrees — rather than from string literals, so a layout change
    /// moves the fixture with it. A hand-built layout is a fixture that keeps
    /// passing after the thing it describes has moved.
    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
        private_root: PathBuf,
        paths: RunPaths,
        identity: RunIdentity,
        task_a: PathBuf,
        task_b: PathBuf,
        merge: PathBuf,
        trace: ContainerTrace,
        runtime: Runtime,
    }

    impl Fixture {
        fn new(tag: &str, exit_on_start: bool) -> Self {
            let root = repo::scratch(tag);
            let repo_dir = root.join("repo");
            let (head, _) = repo::repository(&repo_dir);
            let private_root = root.join("private");
            let paths = RunPaths::with_private_root(&repo_dir, RUN_ID, &private_root);
            paths.create().expect("the run's two halves");
            std::fs::write(paths.events(), format!("{EVENT_LOG_MARKER}\n"))
                .expect("the public log");
            std::fs::write(
                paths.transcripts().join("k0-a1.md"),
                "PRIVATE-TRANSCRIPT-a5f2\n",
            )
            .expect("a private artifact");
            std::fs::create_dir_all(crate::runner::container::intent::containers_dir(
                &private_root,
            ))
            .expect("the container namespace");

            let execution_root =
                crate::workspace_manager::execution_root_of(&private_root, REPO_KEY, RUN_ID);
            let task_a = execution_root.join("tasks").join("kalpha-g0");
            let task_b = execution_root.join("tasks").join("kbeta-g0");
            let merge = execution_root.join("merge").join("s0");
            for at in [&task_a, &task_b, &merge] {
                repo::worktree(&repo_dir, at, &head);
            }
            std::fs::write(task_b.join("sibling.txt"), "SIBLING-WORKTREE-a5f2\n")
                .expect("a sibling file");

            let trace = ContainerTrace::recording();
            Self {
                identity: RunIdentity {
                    private_root: private_root.clone(),
                    run_id: RUN_ID.to_owned(),
                    run_dir: paths.public.clone(),
                    incarnation: INCARNATION_1.to_owned(),
                    repo_key: REPO_KEY.to_owned(),
                },
                runtime: Runtime::new(trace.clone(), exit_on_start),
                trace,
                root,
                repo: repo_dir,
                private_root,
                paths,
                task_a,
                task_b,
                merge,
            }
        }

        /// Everything this run withholds, including its two sibling worktrees.
        fn confinement(&self) -> Confinement {
            Confinement::of_run(&self.identity, &self.repo)
                .withholding(Withheld::SiblingWorktree, self.task_b.clone())
                .withholding(Withheld::SiblingWorktree, self.merge.clone())
        }

        fn runner(&self) -> ContainerRunner {
            self.runner_with(self.identity.clone())
        }

        fn runner_with(&self, identity: RunIdentity) -> ContainerRunner {
            ContainerRunner::new(container_policy(), identity, Box::new(self.runtime.clone()))
                .expect("a container policy")
                .with_hooks(Box::new(RecordingHooks::new(self.trace.clone())))
                .with_confinement(self.confinement())
                .with_poll(Duration::ZERO)
        }

        /// The concrete host paths this run withholds, as a table a test can
        /// iterate — derived from the same accessors the layout is built from.
        fn withheld(&self) -> Vec<(Withheld, PathBuf)> {
            vec![
                (Withheld::PublicLog, self.paths.public.clone()),
                (Withheld::PublicLog, self.paths.events()),
                (Withheld::PrivateArtifacts, self.paths.private.clone()),
                (Withheld::PrivateArtifacts, self.paths.transcripts()),
                (
                    Withheld::PrivateArtifacts,
                    crate::runner::container::intent::containers_dir(&self.private_root),
                ),
                (Withheld::SiblingWorktree, self.task_b.clone()),
                (Withheld::SiblingWorktree, self.merge.clone()),
                (Withheld::AuthoritativeGit, self.repo.join(".git")),
            ]
        }
    }

    fn worker_id(ordinal: u32) -> InvocationId {
        InvocationId::attempt(
            TaskKey(0),
            GenerationId(0),
            AttemptNumber(1),
            AttemptRole::Worker,
            ordinal,
        )
    }

    fn gate_id(ordinal: u32) -> InvocationId {
        InvocationId::attempt(
            TaskKey(0),
            GenerationId(0),
            AttemptNumber(1),
            AttemptRole::Gate(ordinal),
            0,
        )
    }

    fn shell_probe_id() -> InvocationId {
        InvocationId::probe(ProbeTarget::Shell, 0).expect("the shell probe identity")
    }

    fn agent_probe_id(agent: &str) -> InvocationId {
        InvocationId::probe(ProbeTarget::Agent(AgentId::new(agent)), 0)
            .expect("an agent probe identity")
    }

    /// A request in every role, over one workspace, with the binding each role
    /// takes in production.
    fn requests(workspace: &Path) -> Vec<RunnerRequest> {
        let claude = AgentId::new("claude-code");
        let spec = ShellKind::Sh.spec("exit 0");
        vec![
            crate::agent::probe_request("claude-code", spec.clone(), 0, Duration::from_secs(10))
                .expect("an agent probe request"),
            host::shell_probe_request(ShellKind::Sh, workspace.to_path_buf(), shell_probe_id()),
            worker_request(
                spec.clone(),
                workspace.to_path_buf(),
                claude.clone(),
                Duration::from_secs(10),
                worker_id(0),
            ),
            gate_request(
                spec.clone(),
                workspace.to_path_buf(),
                Duration::from_secs(10),
                gate_id(0),
            ),
            review_request(
                spec,
                workspace.to_path_buf(),
                claude,
                Duration::from_secs(10),
                InvocationId::attempt(
                    TaskKey(0),
                    GenerationId(0),
                    AttemptNumber(1),
                    AttemptRole::ReviewPass(0),
                    0,
                ),
            ),
        ]
    }

    /// Requests whose **role and agent binding are varied independently**.
    ///
    /// `runner::gate_request` and `host::shell_probe_request` bind no agent, so
    /// a grid built only from the production builders never asks the question
    /// the role rule exists to answer: what happens to a role that takes no
    /// credentials and names an agent anyway. `host-v1`'s own
    /// `reserved_values` says it in as many words — "neither is told where an
    /// agent's credentials live, **whatever agent the request happens to
    /// name**" — and until this grid existed, deleting the role check from the
    /// container's mount plan changed nothing any test could see (measured:
    /// mutation `M8-credential-volume-for-every-role` survived the whole
    /// suite). That is `PR4-CONF-002`'s class exactly: a predicate keyed on a
    /// field no fixture varies on its own.
    fn hostile_bindings(workspace: &Path) -> Vec<RunnerRequest> {
        let claude = AgentId::new("claude-code");
        vec![
            RunnerRequest {
                command: ShellKind::Sh.spec("cargo test"),
                workspace: workspace.to_path_buf(),
                role: ExecutionRole::Gate,
                timeout: Duration::from_secs(10),
                agent: Some(claude.clone()),
                invocation: gate_id(7),
            },
            RunnerRequest {
                command: ShellKind::Sh.spec("exit 0"),
                workspace: workspace.to_path_buf(),
                role: ExecutionRole::Probe(ProbeTarget::Shell),
                timeout: Duration::from_secs(10),
                agent: Some(claude),
                invocation: shell_probe_id(),
            },
        ]
    }

    /// Every host path a mount hands over.
    fn sources(mounts: &[Mount]) -> Vec<PathBuf> {
        mounts
            .iter()
            .filter_map(|mount| match mount {
                Mount::Path { source, .. } => Some(source.clone()),
                Mount::Volume { .. } => None,
            })
            .collect()
    }

    fn target_of<'a>(mounts: &'a [Mount], target: &str) -> Option<&'a Mount> {
        mounts.iter().find(|mount| mount.target() == target)
    }

    // -----------------------------------------------------------------------
    // 1. Mounts, and the negative space
    // -----------------------------------------------------------------------

    /// The mount set is the role's one worktree, its view, its borrowed object
    /// store and its credential volume — and **nothing that reaches the
    /// coordinator**.
    ///
    /// Both halves, because either alone passes on a wrong implementation:
    /// a positive check ("the worktree is mounted") passes on a container that
    /// also mounts `/`, and a negative check alone passes on a container that
    /// mounts nothing at all. The withheld set is derived from [`RunPaths`] and
    /// `workspace_manager::execution_root_of`, so it moves when the layout does.
    ///
    /// Second field held constant: the role (`Implement`) and the agent
    /// binding; what varies is which withheld path is offered.
    #[test]
    fn the_mount_set_is_the_roles_own_and_reaches_nothing_of_the_coordinators() {
        let fixture = Fixture::new("mounts", true);
        let runner = fixture.runner();
        let request = worker_request(
            ShellKind::Sh.spec("exit 0"),
            fixture.task_a.clone(),
            AgentId::new("claude-code"),
            Duration::from_secs(10),
            worker_id(0),
        );
        let plan = runner.plan(&request).expect("plans");

        // Positive: four mounts, each with its target and its disposition.
        let mounts = plan.mounts();
        let targets: Vec<&str> = mounts.iter().map(Mount::target).collect();
        assert_eq!(
            targets,
            vec![
                "/tactus/workspace",
                "/tactus/gitview",
                "/tactus/gitobjects",
                "/tactus/workspace/.git",
                "/tactus/credentials/claude-code",
            ],
            "the mount set moved"
        );
        assert_eq!(
            target_of(mounts, "/tactus/gitobjects").map(Mount::read_only),
            Some(true),
            "the borrowed object store is read-only (DESIGN.md:612)"
        );
        assert_eq!(
            target_of(mounts, "/tactus/workspace").map(Mount::read_only),
            Some(false),
            "an implementer writes to its worktree"
        );

        // Negative: no mount source is a withheld path or an ancestor of one.
        let withheld = fixture.withheld();
        assert!(withheld.len() >= 8, "the fixture withholds {withheld:?}");
        for (category, path) in &withheld {
            assert!(
                path.exists(),
                "{path:?} does not exist, so withholding it proves nothing"
            );
            for source in sources(mounts) {
                assert!(
                    !path.starts_with(&source),
                    "the mount `{}` hands the container `{}` ({})",
                    source.display(),
                    path.display(),
                    category.passage()
                );
            }
        }
        assert!(
            fixture.confinement().violations(mounts).is_empty(),
            "{:?}",
            fixture.confinement().violations(mounts)
        );

        // The control: the same check over a mount set that *does* reach the
        // coordinator finds every category. Without it a `violations` that
        // always returned an empty vector would pass the assertion above.
        let hostile = vec![Mount::Path {
            source: fixture.root.clone(),
            target: "/everything".to_owned(),
            read_only: false,
        }];
        let found = fixture.confinement().violations(&hostile);
        let categories: BTreeSet<&str> = Withheld::ALL
            .iter()
            .filter(|category| found.iter().any(|entry| entry.contains(category.passage())))
            .map(|category| category.passage())
            .collect();
        assert_eq!(
            categories.len(),
            Withheld::ALL.len(),
            "a mount of the whole tree did not name every withheld category: {found:#?}"
        );
        assert_eq!(Withheld::ALL.len(), 4);
    }

    /// A workspace that contains a withheld path is refused, by name, before
    /// anything is created.
    ///
    /// This is the assertion a membership test cannot make. The repository root
    /// contains the public log and authoritative Git; `/` contains everything.
    /// Both are plausible values for `RunnerRequest.workspace` — the second is
    /// what a path-joining mistake produces — and both are refused with the
    /// paths named.
    ///
    /// Second field held constant: the role, the agent and the image; what
    /// varies is the workspace.
    #[test]
    fn a_workspace_that_contains_a_withheld_path_is_refused_before_any_effect() {
        let fixture = Fixture::new("hostile-ws", true);
        let runner = fixture.runner();
        for (tag, workspace, expected) in [
            (
                "the repository root",
                fixture.repo.clone(),
                vec![Withheld::PublicLog, Withheld::AuthoritativeGit],
            ),
            (
                "the private root",
                fixture.private_root.clone(),
                vec![Withheld::PrivateArtifacts, Withheld::SiblingWorktree],
            ),
            (
                // The **volume** root of the fixture's own tree, not a bare
                // `Component::RootDir`. `Path::starts_with` is component-wise,
                // and on Windows `C:\\x` begins with a `Prefix` component that
                // a bare `\\` does not have — so a bare root contains nothing
                // there and the refusal would not fire. Measured on the
                // Windows guest, where the first spelling of this row was the
                // slice's only guest failure.
                "the filesystem root",
                fixture
                    .repo
                    .ancestors()
                    .last()
                    .expect("every path has a root")
                    .to_path_buf(),
                Withheld::ALL.to_vec(),
            ),
        ] {
            let request = worker_request(
                ShellKind::Sh.spec("exit 0"),
                workspace,
                AgentId::new("claude-code"),
                Duration::from_secs(10),
                worker_id(0),
            );
            let refusal = runner
                .plan(&request)
                .expect_err("a workspace containing a withheld path is refused");
            let message = refusal.to_string();
            for category in expected {
                assert!(
                    message.contains(category.passage()),
                    "{tag}: the refusal does not name {category:?}: {message}"
                );
            }
        }
        // And nothing was created on the way to any of those refusals: the
        // refusal is in `plan`, which performs no effect at all.
        assert!(
            list_intents(&fixture.private_root)
                .expect("scan")
                .is_empty()
        );
        assert!(fixture.runtime.fake().container_names().is_empty());
    }

    /// Only the reviewer's worktree is read-only.
    ///
    /// DESIGN.md:610: "a `:ro` mount makes the reviewer's read-only
    /// **mechanically** perfect instead of flag-deep." A count, not a spot
    /// check: exactly one of the five roles gets `:ro`, and the other four do
    /// not — a runner that made every mount read-only would pass a test that
    /// only looked at the reviewer.
    ///
    /// Second field held constant: the workspace, the image and the agent
    /// binding each role takes in production; what varies is the role.
    #[test]
    fn only_the_reviewer_receives_a_read_only_worktree() {
        let fixture = Fixture::new("ro-review", true);
        let runner = fixture.runner();
        let mut read_only = Vec::new();
        let mut writable = Vec::new();
        let mut without = Vec::new();
        for request in requests(&fixture.task_a) {
            let plan = runner.plan(&request).expect("plans");
            match target_of(plan.mounts(), "/tactus/workspace") {
                Some(mount) if mount.read_only() => read_only.push(request.role.label()),
                Some(_) => writable.push(request.role.label()),
                None => without.push(request.role.label()),
            }
        }
        assert_eq!(read_only, vec!["review".to_owned()], "{read_only:?}");
        assert_eq!(
            writable,
            vec!["implement".to_owned(), "gate".to_owned()],
            "{writable:?}"
        );
        // The two probe roles receive no worktree at all — a probe has none.
        assert_eq!(
            without,
            vec!["probe(claude-code)".to_owned(), "probe(shell)".to_owned()],
            "{without:?}"
        );
        assert_eq!(read_only.len() + writable.len() + without.len(), 5);
    }

    /// The credential volume is mounted **exactly** when its location is
    /// supplied, and both follow one predicate.
    ///
    /// The intersection that makes this worth writing: {role} × {volume
    /// recorded}. A rule keyed only on the role mounts a volume the record does
    /// not name; a rule keyed only on the record hands a gate an agent's
    /// credentials. And the mount and the environment variable are asserted to
    /// agree cell by cell — two rules that happen to agree today is the shape
    /// this project keeps paying for.
    #[test]
    fn the_credential_volume_is_mounted_exactly_when_its_location_is_supplied() {
        let fixture = Fixture::new("creds", true);
        let with_volumes = fixture.runner();
        let without_volumes = ContainerRunner::new(
            RunnerPolicy {
                credential_volumes: None,
                ..container_policy()
            },
            fixture.identity.clone(),
            Box::new(fixture.runtime.clone()),
        )
        .expect("a container policy with no volumes")
        .with_confinement(fixture.confinement())
        .with_poll(Duration::ZERO);

        let mut mounted = 0_usize;
        let mut cells = 0_usize;
        let mut volume_names: BTreeSet<String> = BTreeSet::new();
        for (recorded, runner) in [(true, &with_volumes), (false, &without_volumes)] {
            for request in requests(&fixture.task_a) {
                let plan = runner.plan(&request).expect("plans");
                let volume = plan.mounts().iter().find_map(|mount| match mount {
                    Mount::Volume { name, target, .. } => Some((name.clone(), target.clone())),
                    Mount::Path { .. } => None,
                });
                let key = request.agent.as_ref().and_then(host::credential_location);
                let in_env = key.and_then(|key| {
                    plan.env()
                        .iter()
                        .find(|(name, _)| name == key)
                        .map(|(_, value)| value.clone())
                });
                let expected = recorded
                    && supplies_credential_location(&request.role)
                    && request.agent.is_some();
                assert_eq!(
                    volume.is_some(),
                    expected,
                    "{} (recorded: {recorded}) mounted {volume:?}",
                    request.role
                );
                assert_eq!(
                    in_env.is_some(),
                    volume.is_some(),
                    "{}: the mount and the location disagree — {volume:?} vs {in_env:?}",
                    request.role
                );
                if let (Some((name, target)), Some(value)) = (volume, in_env) {
                    assert_eq!(
                        target, value,
                        "{}: the variable points elsewhere",
                        request.role
                    );
                    volume_names.insert(name);
                    mounted += 1;
                }
                // The one predicate, asserted rather than assumed.
                assert_eq!(
                    runner
                        .credential_volume_for(&request.role, request.agent.as_ref())
                        .is_some(),
                    expected,
                    "{}",
                    request.role
                );
                cells += 1;
            }
        }
        assert_eq!(cells, 10, "five roles crossed with recorded/absent");
        assert_eq!(mounted, 3, "implement, review and the agent probe, once");

        // The cell the production builders cannot reach: a role that takes no
        // credentials, carrying an agent whose volume the record **does** name.
        // Without it the role check in the mount plan is unmeasured, because
        // `agent.is_some()` already excludes every such role in production.
        let mut hostile_cells = 0_usize;
        for request in hostile_bindings(&fixture.task_a) {
            assert!(request.agent.is_some(), "the fixture bound no agent");
            assert!(
                !supplies_credential_location(&request.role),
                "{}: this role does take credentials, so the cell is not hostile",
                request.role
            );
            assert!(
                fixture
                    .runtime
                    .volume_present("tactus-creds-claude")
                    .expect("reachable"),
                "the volume this role must not receive does not exist"
            );
            let plan = with_volumes.plan(&request).expect("plans");
            assert!(
                !plan
                    .mounts()
                    .iter()
                    .any(|mount| matches!(mount, Mount::Volume { .. })),
                "{}: a role that takes no credentials was handed a credential volume — \
                 `host-v1` refuses this shape whatever agent the request names",
                request.role
            );
            assert!(
                !plan.env().iter().any(|(key, _)| key == "CLAUDE_CONFIG_DIR"),
                "{}: and it was told where they live",
                request.role
            );
            assert_eq!(
                with_volumes.credential_volume_for(&request.role, request.agent.as_ref()),
                None,
                "{}",
                request.role
            );
            hostile_cells += 1;
        }
        assert_eq!(
            hostile_cells, 2,
            "a gate and a shell probe, each bound anyway"
        );
        assert_eq!(
            volume_names,
            BTreeSet::from(["tactus-creds-claude".to_owned()]),
            "the volume is the one the record names for that agent"
        );
    }

    // -----------------------------------------------------------------------
    // 2. Creation from the recorded image id
    // -----------------------------------------------------------------------

    /// Every container is created from the **recorded id**, and a moved
    /// reference does not change what executes.
    ///
    /// The intersection: {image id recorded} × {reference moved}. A runner that
    /// resolved the reference at each invocation passes every test that never
    /// moves the tag, which is every test that does not build this cell.
    #[test]
    fn every_container_is_created_from_the_recorded_id_even_after_the_reference_moves() {
        let fixture = Fixture::new("recorded-id", true);
        let runner = fixture.runner();
        let request = gate_request(
            ShellKind::Sh.spec("exit 0"),
            fixture.task_a.clone(),
            Duration::from_secs(10),
            gate_id(0),
        );

        let before = runner.plan(&request).expect("plans");
        assert_eq!(before.launch.spec.image_id, IMAGE_ID);

        // The reference now names another image, and the old id stays.
        fixture
            .runtime
            .fake()
            .move_tag(IMAGE_REFERENCE, OTHER_IMAGE_ID);
        assert_eq!(
            fixture
                .runtime
                .image_by_reference(IMAGE_REFERENCE)
                .expect("reachable")
                .expect("present")
                .id,
            OTHER_IMAGE_ID,
            "the fixture did not move the reference"
        );
        let after = runner.plan(&request).expect("plans");
        assert_eq!(
            after.launch.spec.image_id, IMAGE_ID,
            "a moved reference changed what executes (INV-23, DESIGN.md:610)"
        );

        // And it really runs from the recorded id. The trace is cleared first
        // so the fixture's own `image_by_reference` — which is how the moved
        // tag was verified above — cannot be mistaken for one the runner made.
        fixture.trace.clear();
        runner.run(&request).expect("runs");
        assert_eq!(
            fixture
                .trace
                .ops()
                .iter()
                .filter(|op| **op == RuntimeOp::Create)
                .count(),
            1
        );
        assert_eq!(
            fixture
                .trace
                .ops()
                .iter()
                .filter(|op| **op == RuntimeOp::InspectImageByReference)
                .count(),
            0,
            "the runner resolved a reference on the way to creating a container"
        );
    }

    /// A reported image id that differs from the record refuses **before
    /// start**, in both phases, through the one code path.
    ///
    /// INV-23 gives the mismatch two outcomes that differ by phase — a refusal
    /// during pre-flight or rebuild, and a `RunnerSpawnFailure` outage
    /// settlement mid-run. The **settlement** is an event and belongs to PR7
    /// (`invariants_introduced`: the container transition is "test-only until
    /// PR7 wires TopologyRun"); what this slice owns is that the refusal is the
    /// same at both phases and that `Container.Start` is never reached at
    /// either. So the grid is {pre-flight probe, in-run worker} × {mismatch},
    /// and the second field held constant is the runtime, which is reachable
    /// throughout.
    #[test]
    fn a_substituted_reported_image_id_refuses_before_start_in_both_phases() {
        for (phase, build) in [
            (
                "pre-flight",
                (|fixture: &Fixture| {
                    host::shell_probe_request(
                        ShellKind::Sh,
                        fixture.task_a.clone(),
                        shell_probe_id(),
                    )
                }) as fn(&Fixture) -> RunnerRequest,
            ),
            ("mid-run", |fixture: &Fixture| {
                worker_request(
                    ShellKind::Sh.spec("exit 0"),
                    fixture.task_a.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(10),
                    worker_id(0),
                )
            }),
        ] {
            let fixture = Fixture::new(&format!("mismatch-{phase}"), true);
            let runner = fixture.runner();
            let request = build(&fixture);
            let name = ContainerName::new(REPO_KEY, RUN_ID, INCARNATION_1, &request.invocation)
                .expect("a name");
            fixture
                .runtime
                .fake()
                .substitute_reported_image_id(name.as_str(), OTHER_IMAGE_ID);

            let refusal = runner.run(&request).expect_err("{phase}: refused");
            let message = refusal.to_string();
            assert!(message.contains(IMAGE_ID), "{phase}: {message}");
            assert!(message.contains(OTHER_IMAGE_ID), "{phase}: {message}");
            assert!(message.contains("INV-23"), "{phase}: {message}");

            // Before start, and that is asserted as an absence rather than as
            // an error having come back.
            assert!(
                fixture.trace.position_starting("site:Start").is_none(),
                "{phase}: the container was started: {:#?}",
                fixture.trace.rendered()
            );
            assert!(!fixture.trace.ops().contains(&RuntimeOp::Start), "{phase}");

            // R26 and R19 balance: no container, no intent, no view.
            assert!(
                fixture.runtime.fake().container_names().is_empty(),
                "{phase}"
            );
            assert!(
                list_intents(&fixture.private_root)
                    .expect("scan")
                    .is_empty(),
                "{phase}"
            );
            assert!(
                !fixture
                    .private_root
                    .join("views")
                    .join(name.as_str())
                    .exists()
            );
        }
    }

    /// A policy that is not a usable container policy is refused at
    /// construction, before a runner exists to execute anything.
    #[test]
    fn a_policy_that_is_not_a_container_policy_is_refused_at_construction() {
        let fixture = Fixture::new("policy", true);
        let cases: Vec<(&str, RunnerPolicy)> = vec![
            ("a host policy", crate::runner::policy::host_policy()),
            (
                "a container policy with no image",
                RunnerPolicy {
                    image: None,
                    ..container_policy()
                },
            ),
            (
                "a container policy with an empty image id",
                RunnerPolicy {
                    image: Some(ImageIdentity {
                        reference: IMAGE_REFERENCE.to_owned(),
                        id: String::new(),
                        digest: None,
                    }),
                    ..container_policy()
                },
            ),
            (
                "a container kind under the host contract",
                RunnerPolicy {
                    policy: RunnerContract::HostV1,
                    ..container_policy()
                },
            ),
        ];
        for (tag, policy) in cases {
            ContainerRunner::new(
                policy,
                fixture.identity.clone(),
                Box::new(fixture.runtime.clone()),
            )
            .err()
            .unwrap_or_else(|| panic!("{tag} was accepted"));
        }
        // The control: the good one is accepted, and its digest is the record's.
        let runner = ContainerRunner::new(
            container_policy(),
            fixture.identity.clone(),
            Box::new(fixture.runtime.clone()),
        )
        .expect("accepted");
        assert_eq!(
            runner.policy_digest(),
            crate::runner::policy::runner_policy_sha256(&container_policy())
        );
        assert!(runner.policy_digest().starts_with("sha256:"));
    }

    // -----------------------------------------------------------------------
    // 3. Probes through the runner
    // -----------------------------------------------------------------------

    /// The `RunnerPreflight` shell probe executes through **this** runner, as a
    /// registered container invocation created from the recorded image id.
    ///
    /// `decisions.sequential_substrate.runner`: "both implement the
    /// RunnerPreflight shell probe (the recorded shell executing `exit 0`
    /// through the Runner: on the host as an ordinary supervised process, **in
    /// a container from the recorded image id**)". The probe is not
    /// re-implemented here — `host::run_shell_probe` is a free function over
    /// `&dyn Runner`, and this is the same call the host makes, with the runner
    /// varied and everything else held fixed.
    #[test]
    fn the_shell_probe_runs_through_this_runner_as_a_registered_container_invocation() {
        let fixture = Fixture::new("shell-probe", true);
        let runner = fixture.runner();
        let invocation = shell_probe_id();
        let name =
            ContainerName::new(REPO_KEY, RUN_ID, INCARNATION_1, &invocation).expect("a name");

        host::run_shell_probe(
            &runner,
            ShellKind::Sh,
            fixture.task_a.clone(),
            invocation.clone(),
        )
        .expect("the recorded shell runs inside the recorded image");

        // It was a container invocation, in the contract's order, from the
        // recorded id — and the intent that owns it was written first.
        let rendered = fixture.trace.rendered();
        let at = |needle: &str| {
            fixture
                .trace
                .position_starting(needle)
                .unwrap_or_else(|| panic!("`{needle}` is not in {rendered:#?}"))
        };
        assert!(at("durable:synced") < at("rt:create"), "{rendered:#?}");
        assert!(at("site:MountGitView") < at("rt:create"), "{rendered:#?}");
        assert!(at("site:MountGitView") < at("site:Start"), "{rendered:#?}");
        assert!(at("rt:create") < at("site:Start"), "{rendered:#?}");
        assert!(at("site:Start") < at("site:Stop"), "{rendered:#?}");

        // The command really was the recorded shell executing `exit 0`, and the
        // probe carries a probe-role identity.
        assert!(invocation.probe_target().is_some());
        assert_eq!(invocation.render(), "p.shell.o0");

        // A registered invocation: the intent named it, and the record carried
        // the runner digest. The intent is gone now, so the evidence is the
        // container the runtime saw.
        assert!(
            list_intents(&fixture.private_root)
                .expect("scan")
                .is_empty()
        );
        assert!(fixture.runtime.fake().container_names().is_empty());
        assert!(
            !fixture
                .private_root
                .join("views")
                .join(name.as_str())
                .exists()
        );
    }

    /// T-CONTAINER (17), PR6 half: a failing pre-flight probe refuses and its
    /// probe containers are reclaimed.
    ///
    /// **What PR7 completes**, and this test does not claim: the *ordering*
    /// against a recovery event ("refuses before any recovery event") and the
    /// resume that produces one. `decisions.pr_sequence[8].scope` puts "rebuild
    /// of the recorded Runner … with **RunnerPreflight before any recovery
    /// event**" in PR7, and this slice's `permitted_transitions` says the
    /// container transition is "test-only until PR7 wires TopologyRun". What is
    /// held here is the half the mechanism owns: the probe spawn is the only
    /// thing that observes the failure, the refusal names the shell, and the
    /// probe's container, view and intent are all gone afterwards so the run
    /// stays resumable.
    ///
    /// Both probe kinds, because `expected_failures_refusals` names both — "a
    /// recorded **shell or agent CLI** that fails inside the recorded image".
    /// Second field held constant: the image id, which matches the record in
    /// every cell, so what varies is only what the process did.
    #[test]
    fn failing_preflight_probe_on_resume_refuses_before_recovery_event_and_reclaims_probe_containers()
     {
        for (tag, invocation, exit, stderr) in [
            (
                "shell",
                shell_probe_id(),
                Some(127),
                "sh: exec: not found".to_owned(),
            ),
            (
                "agent",
                agent_probe_id("claude-code"),
                Some(1),
                "claude: command not found".to_owned(),
            ),
        ] {
            let fixture = Fixture::new(&format!("failing-{tag}"), true);
            fixture.runtime.scripts(ContainerExecution {
                exit_code: exit,
                stdout: Vec::new(),
                stderr: stderr.clone().into_bytes(),
            });
            let runner = fixture.runner();
            let name =
                ContainerName::new(REPO_KEY, RUN_ID, INCARNATION_1, &invocation).expect("a name");

            // The observation is a spawn, not an inspection: `non_goals[2]` is
            // "non-spawn shell/CLI presence inspection", and the container was
            // created and started before anything knew the answer.
            if tag == "shell" {
                let refusal = host::run_shell_probe(
                    &runner,
                    ShellKind::Sh,
                    fixture.task_a.clone(),
                    invocation.clone(),
                )
                .expect_err("a shell that fails inside the image refuses");
                assert!(refusal.to_string().contains("sh"), "{refusal}");
                assert!(refusal.to_string().contains("127"), "{refusal}");
            } else {
                let request = crate::agent::probe_request(
                    "claude-code",
                    ShellKind::Sh.spec("claude --version"),
                    0,
                    Duration::from_secs(10),
                )
                .expect("an agent probe request");
                let output = runner.run(&request).expect("the spawn itself succeeds");
                assert_eq!(output.code, exit, "the CLI failed inside the image");
                assert!(output.stderr.contains("command not found"));
            }
            assert!(
                fixture.trace.ops().contains(&RuntimeOp::Start),
                "{tag}: nothing was spawned, so nothing observed the failure"
            );

            // The probe containers are reclaimed, and the run stays resumable:
            // no container, no intent, no view.
            assert!(
                fixture.runtime.fake().container_names().is_empty(),
                "{tag}: a probe container survived"
            );
            assert!(
                list_intents(&fixture.private_root)
                    .expect("scan")
                    .is_empty(),
                "{tag}: a probe intent survived"
            );
            assert!(
                !fixture
                    .private_root
                    .join("views")
                    .join(name.as_str())
                    .exists()
            );
            // And the run's own record is untouched by any of it.
            assert!(fixture.paths.events().exists());
        }
    }

    /// One probe identity, two incarnations, two container invocations.
    ///
    /// The intersection {probe kind} × {epoch}. `InvocationId::probe` is
    /// deterministic **by construction**, so the same probe of a resumed run
    /// carries the same identity; without the incarnation in the name the
    /// second epoch's intent would overwrite the first's and the census would
    /// lose the evidence it needs. This is that property at the *runner* level:
    /// two runners differing in nothing but the incarnation.
    #[test]
    fn two_incarnations_of_one_probe_are_two_container_invocations() {
        let fixture = Fixture::new("epochs", true);
        let mut names = BTreeSet::new();
        let mut intents = BTreeSet::new();
        for incarnation in [INCARNATION_1, INCARNATION_2] {
            for invocation in [shell_probe_id(), agent_probe_id("claude-code")] {
                let identity = RunIdentity {
                    incarnation: incarnation.to_owned(),
                    ..fixture.identity.clone()
                };
                let runner = fixture.runner_with(identity);
                let request = if invocation.render().starts_with("p.shell") {
                    host::shell_probe_request(
                        ShellKind::Sh,
                        fixture.task_a.clone(),
                        invocation.clone(),
                    )
                } else {
                    crate::agent::probe_request(
                        "claude-code",
                        ShellKind::Sh.spec("claude --version"),
                        0,
                        Duration::from_secs(10),
                    )
                    .expect("an agent probe request")
                };
                let plan = runner.plan(&request).expect("plans");
                names.insert(plan.launch.name.as_str().to_owned());
                intents.insert(plan.launch.name.intent_path(&fixture.private_root));
                assert_eq!(
                    plan.launch.intent.incarnation, incarnation,
                    "the record does not carry the incarnation it was built for"
                );
            }
        }
        // The identity repeats across incarnations — which is why the name may
        // not — and the fixture proves that rather than assuming it.
        assert_eq!(shell_probe_id().render(), shell_probe_id().render());
        assert_eq!(names.len(), 4, "{names:?}");
        assert_eq!(intents.len(), 4, "{intents:?}");
    }

    // -----------------------------------------------------------------------
    // 4. Environment composition, and parity with the host
    // -----------------------------------------------------------------------

    /// Probe and execution compose through **one** code path, and produce the
    /// same environment.
    ///
    /// DESIGN.md:263. "Two call sites that happen to agree today" is the shape
    /// this sentence is most often satisfied by, so both halves are asserted:
    /// a source census that there is one composition site and one plan site in
    /// this module's production region, and a runtime comparison of the pair
    /// the sentence names.
    ///
    /// The one difference is stated rather than hidden: a probe receives no
    /// worktree ([`receives_a_worktree`]), so its mount set is the execution's
    /// minus the worktree, the view and the borrowed object store. Everything
    /// that decides what the process *is* — the image id, the credential
    /// volume, the reserved values, the overlay — is identical.
    #[test]
    fn probe_and_execution_compose_through_one_code_path() {
        // (a) the source census.
        let source = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("runner")
                .join("container")
                .join("exec.rs"),
        )
        .expect("read this module");
        let production =
            crate::effects::blank_comments(&crate::effects::production_region(&source));
        assert_eq!(
            production.matches("self.environment.compose(").count(),
            1,
            "the environment is composed in more than one place"
        );
        assert_eq!(
            production.matches("self.plan(").count(),
            1,
            "a request becomes a plan in more than one place"
        );
        assert_eq!(
            production.matches("self.mounts(").count(),
            1,
            "the mount set is built in more than one place"
        );

        // (b) the pair the sentence names, composed.
        let fixture = Fixture::new("parity-probe", true);
        let runner = fixture.runner();
        let overlay = (
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS".to_owned(),
            "8000".to_owned(),
        );
        let pairs: Vec<(&str, RunnerRequest, RunnerRequest)> = vec![
            (
                "the agent probe and the worker it certifies",
                crate::agent::probe_request(
                    "claude-code",
                    ShellKind::Sh
                        .spec("claude --version")
                        .env(&overlay.0, &overlay.1),
                    0,
                    Duration::from_secs(10),
                )
                .expect("an agent probe request"),
                worker_request(
                    ShellKind::Sh.spec("claude -p").env(&overlay.0, &overlay.1),
                    fixture.task_a.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(10),
                    worker_id(0),
                ),
            ),
            (
                "the shell probe and the gate it certifies",
                host::shell_probe_request(ShellKind::Sh, fixture.task_a.clone(), shell_probe_id()),
                gate_request(
                    ShellKind::Sh.spec("cargo test"),
                    fixture.task_a.clone(),
                    Duration::from_secs(10),
                    gate_id(0),
                ),
            ),
        ];
        for (tag, probe, execution) in pairs {
            let probed = runner.plan(&probe).expect("plans");
            let executed = runner.plan(&execution).expect("plans");
            assert_eq!(
                probed.launch.spec.image_id, executed.launch.spec.image_id,
                "{tag}: two boundaries"
            );
            // The overlay differs only where the *request* differs, so the
            // composed environments are compared as sets of (key, value).
            let composed = |plan: &InvocationPlan| -> BTreeMap<String, String> {
                plan.env().iter().cloned().collect()
            };
            assert_eq!(
                composed(&probed),
                composed(&executed),
                "{tag}: pre-flight certifies an environment the attempt does not run in"
            );
            // Mounts: the probe's set is the execution's minus the worktree.
            let probe_targets: BTreeSet<&str> = probed.mounts().iter().map(Mount::target).collect();
            let execution_targets: BTreeSet<&str> =
                executed.mounts().iter().map(Mount::target).collect();
            assert!(
                probe_targets.is_subset(&execution_targets),
                "{tag}: {probe_targets:?} vs {execution_targets:?}"
            );
            let difference: BTreeSet<&&str> =
                execution_targets.difference(&probe_targets).collect();
            assert_eq!(
                difference,
                BTreeSet::from([
                    &"/tactus/workspace",
                    &"/tactus/gitview",
                    &"/tactus/gitobjects",
                    &"/tactus/workspace/.git",
                ]),
                "{tag}: the probe and the execution differ by something other than the worktree"
            );
        }
    }

    /// `decisions.tests_acceptance.parity`: "host and container runners produce
    /// identical … **environment composition**".
    ///
    /// The runner is varied and **everything else is held fixed**: one explicit
    /// base, one name rule, one overlay, and all five `ExecutionRole` values
    /// including both probe targets — `ExecutionRole::all()` returns five for
    /// exactly this reason. The base is explicit rather than each runner's own,
    /// because the two bases are *supposed* to differ (the Tactus environment
    /// and the image environment) and a comparison of those would be a
    /// comparison of two fixtures rather than of two composition rules.
    ///
    /// The one place they legitimately differ is stated as an assertion rather
    /// than skipped: a credential *location* is a path at the boundary that
    /// executes, so the host names a host directory and the container names its
    /// mount target. Both are supplied for exactly the same three roles.
    #[test]
    fn host_and_container_compose_the_same_environment_for_every_role() {
        let base: Vec<(String, String)> = [
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("HOME", "/root"),
            ("LANG", "C.UTF-8"),
            ("CLAUDE_CONFIG_DIR", "/host/claude"),
            ("TACTUS_SHARED", "shared"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        let host_base: Vec<(std::ffi::OsString, std::ffi::OsString)> = base
            .iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        let host_env = HostEnvironment::with_base(host_base, super::super::env::CONTAINER_KEY_CASE);
        let container_env =
            ContainerEnvironment::with_base(base.clone(), super::super::env::CONTAINER_KEY_CASE);
        let volumes: BTreeMap<String, String> = VOLUMES
            .iter()
            .map(|(agent, volume)| ((*agent).to_owned(), (*volume).to_owned()))
            .collect();
        let layout = BoundaryLayout::new();
        let overlay = vec![
            ("TACTUS_OVERLAY".to_owned(), "1".to_owned()),
            ("LANG".to_owned(), "en_GB.UTF-8".to_owned()),
        ];

        let mut supplied_locations = 0_usize;
        let mut rows = 0_usize;
        for role in ExecutionRole::all() {
            let agent = match &role {
                ExecutionRole::Probe(ProbeTarget::Agent(agent)) => Some(agent.clone()),
                ExecutionRole::Implement | ExecutionRole::Review => {
                    Some(AgentId::new("claude-code"))
                }
                ExecutionRole::Gate | ExecutionRole::Probe(ProbeTarget::Shell) => None,
            };
            let scope = RoleScope {
                role: &role,
                agent: agent.as_ref(),
                volumes: &volumes,
                layout: &layout,
            };
            let host_composed: BTreeMap<String, String> = host_env
                .compose(&role, agent.as_ref(), &overlay)
                .expect("the host composes")
                .into_iter()
                .map(|(key, value)| {
                    (
                        key.to_string_lossy().into_owned(),
                        value.to_string_lossy().into_owned(),
                    )
                })
                .collect();
            let container_composed: BTreeMap<String, String> = container_env
                .compose(&scope, &overlay)
                .expect("the container composes")
                .into_iter()
                .collect();

            // Same keys, for every role.
            assert_eq!(
                host_composed.keys().collect::<Vec<_>>(),
                container_composed.keys().collect::<Vec<_>>(),
                "{role}: the two runners composed different key sets"
            );
            // Same values everywhere except the credential location.
            let location = agent.as_ref().and_then(host::credential_location);
            for (key, host_value) in &host_composed {
                let container_value = &container_composed[key];
                if Some(key.as_str()) == location {
                    assert_eq!(host_value, "/host/claude");
                    assert_eq!(
                        container_value,
                        &layout.credentials(agent.as_ref().expect("an agent")),
                        "{role}: the container named a location that is not its own"
                    );
                    supplied_locations += 1;
                } else {
                    assert_eq!(
                        host_value, container_value,
                        "{role}: `{key}` composed differently"
                    );
                }
            }
            // And both refuse the same overlay keys.
            for reserved in host::reserved_keys() {
                let bad = vec![(reserved.to_owned(), "x".to_owned())];
                host_env
                    .compose(&role, agent.as_ref(), &bad)
                    .expect_err("the host refuses");
                container_env
                    .compose(&scope, &bad)
                    .expect_err("and so does the container");
            }
            rows += 1;
        }
        assert_eq!(rows, 5, "all five roles, both probe targets");
        assert_eq!(
            supplied_locations, 3,
            "implement, review and the agent probe get a location at both boundaries"
        );
        // The base really did carry a credential location, so "the reserved
        // copies are dropped" is a statement about this fixture.
        assert!(base.iter().any(|(key, _)| key == "CLAUDE_CONFIG_DIR"));
    }

    // -----------------------------------------------------------------------
    // 5. Supervision, release, and the resource ledgers
    // -----------------------------------------------------------------------

    /// A completed invocation stops, removes, unmounts the view and removes the
    /// intent — in that order — and reports what the container did.
    ///
    /// `side_effect_vs_event_ordering`: "stop/rm, view removal, intent removal
    /// **after completion**". Asserted as a sequence of positions in one
    /// ordered trace, not as membership: a release that performed the same four
    /// operations in any other order would satisfy a set.
    ///
    /// Second field held constant: the image id, which matches the record; what
    /// varies is only that the container finished.
    #[test]
    fn a_completed_invocation_releases_in_the_contracts_order_and_reports_the_result() {
        let fixture = Fixture::new("complete", true);
        fixture.runtime.scripts(ContainerExecution {
            exit_code: Some(3),
            stdout: b"the work is done\n".to_vec(),
            stderr: b"a warning\n".to_vec(),
        });
        let runner = fixture.runner();
        let request = worker_request(
            ShellKind::Sh.spec("exit 3"),
            fixture.task_a.clone(),
            AgentId::new("claude-code"),
            Duration::from_secs(10),
            worker_id(0),
        );
        let name = ContainerName::new(REPO_KEY, RUN_ID, INCARNATION_1, &request.invocation)
            .expect("a name");

        let output = runner
            .run(&request)
            .expect("a non-zero exit is not an error");
        assert_eq!(output.code, Some(3), "a non-zero exit is a ProcessOutput");
        assert_eq!(output.stdout, "the work is done\n");
        assert_eq!(
            output.stderr, "a warning\n",
            "the seam carries two streams and `ProcessOutput` keeps them apart"
        );
        assert!(!output.timed_out);
        assert!(!output.output_limited);

        let rendered = fixture.trace.rendered();
        let at = |needle: &str| {
            fixture
                .trace
                .position_starting(needle)
                .unwrap_or_else(|| panic!("`{needle}` is not in {rendered:#?}"))
        };
        // The whole sequence, in one chain.
        let order = [
            "site:WriteIntent:before",
            "durable:synced",
            "durable:renamed",
            "durable:dir-synced",
            "site:MountGitView:before",
            "site:Create:before",
            "site:Start:before",
            "rt:collect",
            "site:Stop:before",
            "site:Remove:before",
            "site:UnmountGitView:before",
            "site:RemoveIntent:before",
        ];
        for pair in order.windows(2) {
            assert!(
                at(pair[0]) < at(pair[1]),
                "`{}` is not before `{}` in {rendered:#?}",
                pair[0],
                pair[1]
            );
        }
        // The three clauses of `side_effect_vs_event_ordering`, each stated on
        // its own rather than only as a link in the chain above — a chain is
        // one assertion and the contract is three predicates.
        assert!(
            at("durable:synced") < at("rt:create"),
            "intent synced before docker create"
        );
        assert!(
            at("rt:create") < at("site:Start:before"),
            "created and verified before start"
        );
        assert!(
            at("view:materialized") < at("site:Start:before"),
            "view mounted before start"
        );
        // And the view really is materialised before the create, which is the
        // physical constraint the module docs record.
        assert!(at("view:materialized") < at("rt:create"), "{rendered:#?}");
        // Collected **before** the release, because `docker logs` answers for a
        // running container and not for a removed one.
        assert!(at("rt:collect") < at("rt:remove"), "{rendered:#?}");

        // R26 and R19 balance.
        assert!(fixture.runtime.fake().container_names().is_empty());
        assert!(
            list_intents(&fixture.private_root)
                .expect("scan")
                .is_empty()
        );
        assert!(
            !fixture
                .private_root
                .join("views")
                .join(name.as_str())
                .exists()
        );
    }

    /// A container that outlives its timeout is stopped and removed, and the
    /// output says so.
    ///
    /// `slice_contract.cancellation`: "timeout or shutdown **stops and
    /// removes** the container". The fixture's timeout is `Duration::ZERO`, so
    /// the deadline has passed by the first observation and the supervisor
    /// makes exactly one round trip — `determinism` forbids sleeps and a poll
    /// loop with a real timeout would be one.
    ///
    /// Second field held constant: everything except whether the container
    /// terminates — the same image, the same role, the same workspace as the
    /// completing case above.
    #[test]
    fn a_container_that_outlives_its_timeout_is_stopped_and_removed() {
        let fixture = Fixture::new("timeout", false);
        let runner = fixture.runner();
        let mut request = worker_request(
            ShellKind::Sh.spec("sleep 600"),
            fixture.task_a.clone(),
            AgentId::new("claude-code"),
            Duration::from_secs(10),
            worker_id(0),
        );
        request.timeout = Duration::ZERO;
        let name = ContainerName::new(REPO_KEY, RUN_ID, INCARNATION_1, &request.invocation)
            .expect("a name");

        let output = runner
            .run(&request)
            .expect("a timeout is an output, not an error");
        assert!(output.timed_out);
        assert_eq!(
            output.code, None,
            "a container the supervisor stopped did not exit on its own"
        );

        // Stopped and removed, in that order, and the ledgers balance.
        let rendered = fixture.trace.rendered();
        let at = |needle: &str| {
            fixture
                .trace
                .position_starting(needle)
                .unwrap_or_else(|| panic!("`{needle}` is not in {rendered:#?}"))
        };
        assert!(
            at("site:Start:before") < at("site:Stop:before"),
            "{rendered:#?}"
        );
        assert!(
            at("site:Stop:before") < at("site:Remove:before"),
            "{rendered:#?}"
        );
        assert!(
            at("site:Remove:before") < at("site:UnmountGitView:before"),
            "{rendered:#?}"
        );
        assert!(
            at("site:UnmountGitView:before") < at("site:RemoveIntent:before"),
            "{rendered:#?}"
        );
        assert!(fixture.runtime.fake().container_names().is_empty());
        assert!(
            list_intents(&fixture.private_root)
                .expect("scan")
                .is_empty()
        );
        assert!(
            !fixture
                .private_root
                .join("views")
                .join(name.as_str())
                .exists()
        );

        // Exactly one observation: no sleeps, and the loop is bounded by the
        // deadline rather than by a count.
        assert_eq!(
            fixture
                .trace
                .ops()
                .iter()
                .filter(|op| **op == RuntimeOp::Observe)
                .count(),
            1,
            "{rendered:#?}"
        );
    }

    /// Output beyond the bound is truncated and reported as limited.
    ///
    /// Without it `ProcessOutput::output_limited` would be `false` for every
    /// container invocation, and `host::run_shell_probe`'s bounded-output
    /// refusal — a real arm of that function — would be reachable at the host
    /// boundary and unreachable at this one. A pre-flight that certifies less
    /// than the one it is paired with is not the parity the packet asks for.
    ///
    /// Second field held constant: the exit status, which is 0 in both cells,
    /// so what varies is only how much the container printed.
    #[test]
    fn output_beyond_the_bound_is_truncated_and_reported_as_limited() {
        for (tag, bytes, limited) in [("under", 8_usize, false), ("over", 40_usize, true)] {
            let fixture = Fixture::new(&format!("bound-{tag}"), true);
            fixture.runtime.scripts(ContainerExecution {
                exit_code: Some(0),
                stdout: vec![b'x'; bytes],
                stderr: Vec::new(),
            });
            let runner = fixture.runner().with_output_limit(16);
            let request = gate_request(
                ShellKind::Sh.spec("yes"),
                fixture.task_a.clone(),
                Duration::from_secs(10),
                gate_id(0),
            );
            let output = runner.run(&request).expect("runs");
            assert_eq!(output.output_limited, limited, "{tag}");
            assert_eq!(output.stdout.len(), bytes.min(16), "{tag}");
            assert_eq!(output.code, Some(0), "{tag}: the exit status is held fixed");

            // And the probe refusal really is reachable at this boundary.
            let probe = host::run_shell_probe(
                &fixture.runner().with_output_limit(16),
                ShellKind::Sh,
                fixture.task_a.clone(),
                shell_probe_id(),
            );
            if limited {
                let refusal = probe.expect_err("a shell that printed too much is refused");
                assert!(
                    refusal.to_string().contains("bounded output allowance"),
                    "{refusal}"
                );
            } else {
                probe.expect("and an ordinary one is not");
            }
        }
    }

    /// R20: a credential volume is **never created or pruned by a run**, in
    /// every disposition this runner can reach.
    ///
    /// `resource_accounting.rows[R20]` is `operator_owned` and
    /// `persistent_output` in **all five** `at_run_end` outcomes — `Complete`,
    /// `Parked`, `Halted`, `BudgetExceeded`, `NoRunFinished`. A run-end outcome
    /// is a fold over the event log and PR6 has no events at all
    /// (`durable_events`: "none"), so what this slice can measure is the set of
    /// dispositions the runner itself reaches, and the five outcomes differ
    /// only in *which* of them ends the last invocation. Each is driven here
    /// and the volume is asserted present afterwards.
    ///
    /// The failure this prevents is one no ordinary test looks at: a runner
    /// that tidied up a volume it mounted would destroy operator credentials,
    /// and CLIs "rotate refresh tokens on use, and a discarded rotation forces
    /// re-login" (DESIGN.md:612).
    #[test]
    fn a_credential_volume_is_never_created_or_pruned_by_any_disposition() {
        let volume = "tactus-creds-claude";
        /// One way an invocation of this runner can end.
        type Disposition = (&'static str, fn(&Fixture));
        let dispositions: Vec<Disposition> = vec![
            ("complete", |fixture| {
                let request = worker_request(
                    ShellKind::Sh.spec("exit 0"),
                    fixture.task_a.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(10),
                    worker_id(0),
                );
                fixture.runner().run(&request).expect("completes");
            }),
            ("cancelled by timeout", |fixture| {
                let mut request = worker_request(
                    ShellKind::Sh.spec("sleep 600"),
                    fixture.task_a.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(10),
                    worker_id(1),
                );
                request.timeout = Duration::ZERO;
                fixture.runner().run(&request).expect("times out");
            }),
            ("refused for a substituted image id", |fixture| {
                let request = worker_request(
                    ShellKind::Sh.spec("exit 0"),
                    fixture.task_a.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(10),
                    worker_id(2),
                );
                let name = ContainerName::new(REPO_KEY, RUN_ID, INCARNATION_1, &request.invocation)
                    .expect("a name");
                fixture
                    .runtime
                    .fake()
                    .substitute_reported_image_id(name.as_str(), OTHER_IMAGE_ID);
                fixture.runner().run(&request).expect_err("refuses");
            }),
            ("refused at a funnel phase", |fixture| {
                let mut hooks = RecordingHooks::new(fixture.trace.clone());
                hooks.fail_at(
                    crate::topology::effects::EffectSiteId::Container(
                        crate::topology::effects::ContainerSite::Create,
                    ),
                    crate::topology::effects::HookPhase::Before,
                );
                let runner = ContainerRunner::new(
                    container_policy(),
                    fixture.identity.clone(),
                    Box::new(fixture.runtime.clone()),
                )
                .expect("a container policy")
                .with_hooks(Box::new(hooks))
                .with_confinement(fixture.confinement())
                .with_poll(Duration::ZERO);
                let request = worker_request(
                    ShellKind::Sh.spec("exit 0"),
                    fixture.task_a.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(10),
                    worker_id(3),
                );
                runner
                    .run(&request)
                    .expect_err("the funnel was made to fail");
            }),
            ("reclaimed as an orphan", |fixture| {
                let request = worker_request(
                    ShellKind::Sh.spec("exit 0"),
                    fixture.task_a.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(10),
                    worker_id(4),
                );
                let name = ContainerName::new(REPO_KEY, RUN_ID, INCARNATION_1, &request.invocation)
                    .expect("a name");
                let mut hooks = RecordingHooks::new(fixture.trace.clone());
                crate::runner::container::reclaim(
                    &mut hooks,
                    &fixture.runtime,
                    &crate::runner::container::DisposableDirView::new(fixture.trace.clone()),
                    &fixture.private_root,
                    &name,
                    Some(&view_dir(&fixture.private_root, &name)),
                )
                .expect("reclaim converges on a container that never existed");
            }),
        ];
        assert_eq!(
            dispositions.len(),
            5,
            "one per `at_run_end` outcome: Complete, Parked, Halted, BudgetExceeded, NoRunFinished"
        );
        for (tag, drive) in dispositions {
            let fixture = Fixture::new(&format!("r20-{}", tag.replace(' ', "-")), true);
            assert!(
                fixture.runtime.volume_present(volume).expect("reachable"),
                "{tag}: the operator's volume was not there to begin with"
            );
            drive(&fixture);
            assert!(
                fixture.runtime.volume_present(volume).expect("reachable"),
                "{tag}: the run pruned an operator-owned credential volume"
            );
            for (_, other) in VOLUMES {
                assert!(
                    fixture.runtime.volume_present(other).expect("reachable"),
                    "{tag}: `{other}` is gone"
                );
            }
        }
    }

    /// Nothing in the container subtree can create or prune a volume.
    ///
    /// The runtime assertion above measures the dispositions a test drove; this
    /// measures the *domain* — `enforcement_domains.operator_owned`: "R20
    /// credential volumes: **never created or pruned by a run**". The seam has
    /// one volume method and it returns a `bool`, and the `docker` CLI issues
    /// exactly one volume subcommand, which is `inspect`.
    #[test]
    fn the_container_subtree_can_only_inspect_a_volume() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("runner");
        let mut sources = std::fs::read_to_string(dir.join("container.rs")).expect("the funnel");
        for name in ["runtime.rs", "intent.rs", "exec.rs", "env.rs", "view.rs"] {
            sources.push_str(
                &std::fs::read_to_string(dir.join("container").join(name)).expect("a module"),
            );
        }
        let production =
            crate::effects::blank_comments(&crate::effects::production_region(&sources));
        // The control: the read-only inspection really is there, so a census
        // that had stopped finding anything fails here rather than reporting
        // silence.
        assert_eq!(
            production.matches("\"volume\",").count(),
            1,
            "the `docker volume` census is measuring nothing"
        );
        assert!(production.contains("\"inspect\""));
        for mutating in ["\"create\", ", "volume rm", "volume prune", "\"prune\""] {
            assert_eq!(
                production.matches(mutating).count(),
                0,
                "the container subtree names `{mutating}`, so a run could create or prune a volume"
            );
        }
        // And the seam has one volume method.
        let seam =
            std::fs::read_to_string(dir.join("container").join("runtime.rs")).expect("the seam");
        let seam = crate::effects::blank_comments(&crate::effects::production_region(&seam));
        assert_eq!(seam.matches("fn volume").count(), 1, "one volume method");
        assert!(
            seam.contains("fn volume_present(&self, name: &str) -> Result<bool, RuntimeError>")
        );
    }

    /// The container runner is a `Runner` like any other: object-safe, `Send`
    /// and `Sync`.
    ///
    /// PR11 turns `run` into a boxed `Send` future behind the same `&dyn
    /// Runner` its callers hold, so a container runner that stopped being
    /// object-safe would fail to compile here rather than at the migration —
    /// the same guard `runner::tests::the_runner_trait_is_object_safe` gives
    /// the host.
    #[test]
    fn the_container_runner_is_object_safe_and_send_and_sync() {
        fn takes_dyn(_: &dyn Runner) {}
        fn is_send_sync<T: Send + Sync>() {}
        is_send_sync::<ContainerRunner>();

        let fixture = Fixture::new("object-safe", true);
        let runner = fixture.runner();
        takes_dyn(&runner);
        let boxed: Box<dyn Runner> = Box::new(fixture.runner());
        takes_dyn(boxed.as_ref());
        // And a `GitView` is object-safe too, which is what lets the funnel
        // take `&dyn GitView` and this module hand it a projection.
        let view: Box<dyn GitView> = Box::new(RoleGitView::new(ContainerTrace::off()));
        fn takes_view(_: &dyn GitView) {}
        takes_view(view.as_ref());
    }

    // -----------------------------------------------------------------------
    // 6. Docker-gated: what the fake cannot prove
    // -----------------------------------------------------------------------

    /// The references the gated tests prefer, in order.
    ///
    /// **These tests never pull.** `non_goals[1]` is "implicit image pull", and
    /// a fixture that pulled would exercise the behaviour the slice forbids on
    /// the very runtime the refusal is meant to be proven against. So the image
    /// is *discovered* among what the machine already holds. `tactus-test/git:v1`
    /// is first because it is the only local image carrying both a shell and
    /// `git`, and because its `TACTUS_IMAGE_MARKER` is how "the container runner
    /// starts from the **image** environment" is measured rather than asserted.
    const PREFERRED_IMAGES: &[&str] = &[
        "tactus-test/git:v1",
        "alpine:3.20",
        "busybox:latest",
        "debian:stable-slim",
    ];

    /// Images that carry `git`. A subset, named separately because the
    /// Git-view proof needs one and the others do not.
    ///
    /// **One entry, and `alpine/git` is deliberately not the second.** That
    /// image declares `VOLUME /git`, so every container created from it leaves
    /// an anonymous volume behind that `docker rm --force` does not remove —
    /// measured here, 29 of them from one run of this suite, which is
    /// `PR6A-ANONYMOUS-VOLUMES-LEAK`. A fallback that breaks
    /// `DOCKER-SUBSTRATE.md`'s "leave the daemon as you found it" on somebody
    /// else's machine is worse than a loud, counted absence.
    const GIT_IMAGES: &[&str] = &["tactus-test/git:v1"];

    /// The image whose environment carries a marker this suite can recognise.
    const MARKER_IMAGE: &str = "tactus-test/git:v1";
    const IMAGE_MARKER_VALUE: &str = "image-environment-v1";

    /// What a Docker-gated test does when there is no runtime.
    ///
    /// It **reads** the reason rather than returning silently, so a skip that
    /// stopped saying why would not compile.
    fn skipped(reason: &str) {
        assert_eq!(
            reason,
            crate::runner::container::fake::absent_reason(),
            "a Docker-gated test skipped for a reason the gate does not know about"
        );
    }

    /// What a Docker-gated test does when the runtime holds no usable image.
    ///
    /// Loud under the same variable as a missing runtime: a machine with Docker
    /// and no image would otherwise pass these tests without touching it.
    fn no_image(reason: &str) {
        assert!(reason.contains("never pull"), "{reason}");
        assert!(
            std::env::var_os(crate::runner::container::fake::REQUIRE_DOCKER).is_none(),
            "{} is set and a gated test found no usable image: {reason}",
            crate::runner::container::fake::REQUIRE_DOCKER
        );
    }

    /// A reference the runtime holds, with its id, or the reason there is none.
    fn discover(
        docker: &dyn ContainerRuntime,
        preferred: &[&str],
    ) -> Result<(String, String), String> {
        for reference in preferred {
            if let Ok(Some(found)) = docker.image_by_reference(reference) {
                return Ok(((*reference).to_owned(), found.id));
            }
        }
        Err(format!(
            "the container runtime holds none of {preferred:?} and these tests never pull \
             (non_goals[1])"
        ))
    }

    /// A container policy naming a real image id, and no credential volumes.
    ///
    /// R20 volumes are **operator-owned** and `persistent_output`; a test that
    /// created one would be creating operator state on the machine it runs on,
    /// which is the very thing the row forbids a run from doing. So the gated
    /// suite records none, and `a_credential_volume_is_never_created_or_pruned_by_any_disposition`
    /// carries the volume obligation against the fake.
    fn real_policy(image_id: &str) -> RunnerPolicy {
        RunnerPolicy {
            kind: RunnerKind::Container,
            policy: RunnerContract::ContainerV1,
            image: Some(ImageIdentity {
                reference: "discovered-locally".to_owned(),
                id: image_id.to_owned(),
                digest: None,
            }),
            credential_volumes: None,
        }
    }

    /// A `RunIdentity` for a gated test, under a scratch private root.
    ///
    /// `run_id` is a **parameter** because the container name is
    /// `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>` and carries
    /// no private root: two gated tests sharing a run id and an invocation
    /// ordinal produce the same container name, and `cargo test` runs them
    /// concurrently. Measured: the first version of this suite failed with
    /// `Conflict. The container name ... is already in use`. In production the
    /// run id is a ULID and the collision cannot arise; in a fixture it is
    /// whatever the fixture writes, which is why it is written per test.
    fn real_identity(root: &Path, repo: &Path, run_id: &str) -> RunIdentity {
        let private_root = root.join("private");
        let paths = RunPaths::with_private_root(repo, run_id, &private_root);
        paths.create().expect("the run's two halves");
        std::fs::write(paths.events(), format!("{EVENT_LOG_MARKER}\n")).expect("the public log");
        std::fs::write(
            paths.transcripts().join("k0-a1.md"),
            "PRIVATE-TRANSCRIPT-a5f2\n",
        )
        .expect("a private artifact");
        RunIdentity {
            private_root,
            run_id: run_id.to_owned(),
            run_dir: paths.public,
            incarnation: INCARNATION_1.to_owned(),
            repo_key: REPO_KEY.to_owned(),
        }
    }

    /// One run id per gated test. Distinct by construction, and asserted so.
    const GATED_RUNS: &[(&str, &str)] = &[
        ("env", "01KZGATEDA000000000000000A"),
        ("readonly", "01KZGATEDB000000000000000B"),
        ("confine", "01KZGATEDC000000000000000C"),
        ("gitview", "01KZGATEDD000000000000000D"),
        ("parity", "01KZGATEDE000000000000000E"),
    ];

    fn gated_run(tag: &str) -> &'static str {
        GATED_RUNS
            .iter()
            .find(|(name, _)| *name == tag)
            .map(|(_, run)| *run)
            .unwrap_or_else(|| panic!("`{tag}` has no gated run id"))
    }

    /// Leave the daemon as we found it, even if an assertion panics.
    ///
    /// `DOCKER-SUBSTRATE.md`'s first rule. `Drop` rather than a line at the end
    /// of each test, because the line at the end of a test does not run when
    /// the test fails — which is exactly when a container is most likely to be
    /// left behind.
    struct LeaveNoResidue {
        docker: crate::runner::container::DockerCli,
        private_root: PathBuf,
    }

    impl Drop for LeaveNoResidue {
        fn drop(&mut self) {
            let label = self.private_root.to_string_lossy().replace('\\', "/");
            let Ok(found) = self
                .docker
                .containers_with_label(LABEL_PRIVATE_ROOT, &label)
            else {
                return;
            };
            for container in found {
                let Ok(name) = ContainerName::rebuild(&container.name) else {
                    continue;
                };
                let mut hooks = crate::runner::container::NoHooks;
                let view = crate::runner::container::DisposableDirView::default();
                let _ = crate::runner::container::reclaim(
                    &mut hooks,
                    &self.docker,
                    &view,
                    &self.private_root,
                    &name,
                    Some(&view_dir(&self.private_root, &name)),
                );
            }
        }
    }

    /// The container runner executes the recorded image id, composes **over**
    /// the image environment, and runs in the role's worktree.
    ///
    /// Three separately droppable claims against the real runtime:
    ///
    /// * the composed `CreateSpec.env` does **not** name `PATH`, and `$PATH` is
    ///   nevertheless set inside the container — so the base really is the
    ///   image's and the runner overlaid it rather than replacing it. That is
    ///   image-independent, which is why it is the primary measurement.
    /// * the adapter's overlay key lands.
    /// * the working directory is the role's worktree mount.
    ///
    /// Second field held constant: the role and the workspace; what varies
    /// across the three claims is which part of the environment is read.
    #[test]
    fn real_docker_runs_from_the_recorded_image_id_and_composes_over_the_image_environment() {
        let trace = ContainerTrace::recording();
        let docker = match docker_gate(
            "real_docker_runs_from_the_recorded_image_id_and_composes_over_the_image_environment",
            trace.clone(),
        ) {
            Ok(docker) => docker,
            Err(reason) => return skipped(&reason),
        };
        let (reference, image_id) = match discover(docker.as_ref(), PREFERRED_IMAGES) {
            Ok(found) => found,
            Err(reason) => return no_image(&reason),
        };

        let root = repo::scratch("real-env");
        let run_id = gated_run("env");
        let repo_dir = root.join("repo");
        repo::repository(&repo_dir);
        let identity = real_identity(&root, &repo_dir, run_id);
        let workspace = root.join("plain-workspace");
        std::fs::create_dir_all(&workspace).expect("a workspace");
        let _residue = LeaveNoResidue {
            docker: (*docker).clone(),
            private_root: identity.private_root.clone(),
        };

        let runner = ContainerRunner::new(
            real_policy(&image_id),
            identity.clone(),
            Box::new((*docker).clone()),
        )
        .expect("a container policy")
        .with_hooks(Box::new(RecordingHooks::new(trace.clone())))
        .with_confinement(Confinement::of_run(&identity, &repo_dir))
        .with_poll(Duration::from_millis(10));

        let request = gate_request(
            ShellKind::Sh
                .spec(
                    "printf 'PATH=%s\\n' \"$PATH\"; \
                 printf 'OVERLAY=%s\\n' \"$TACTUS_OVERLAY\"; \
                 printf 'MARKER=%s\\n' \"$TACTUS_IMAGE_MARKER\"; \
                 printf 'PWD=%s\\n' \"$(pwd)\"",
                )
                .env("TACTUS_OVERLAY", "landed"),
            workspace.clone(),
            Duration::from_secs(60),
            gate_id(0),
        );

        // The composed environment names no `PATH`: the runner's base is empty
        // and the runtime supplies the image's.
        let plan = runner.plan(&request).expect("plans");
        assert!(
            !plan.env().iter().any(|(key, _)| key == "PATH"),
            "the runner named PATH, so the assertion below would prove nothing: {:?}",
            plan.env()
        );
        assert_eq!(plan.launch.spec.image_id, image_id);

        let output = runner.run(&request).expect("runs");
        assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
        let line = |key: &str| -> String {
            output
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap_or_else(|| panic!("`{key}` is not in {:?}", output.stdout))
                .to_owned()
        };
        assert!(
            line("PATH=").contains("/bin"),
            "the image environment did not reach the child: {:?}",
            output.stdout
        );
        assert_eq!(line("OVERLAY="), "landed", "the overlay did not land");
        assert_eq!(line("PWD="), "/tactus/workspace");
        if reference == MARKER_IMAGE {
            assert_eq!(
                line("MARKER="),
                IMAGE_MARKER_VALUE,
                "the marker image's own environment did not survive composition"
            );
        }

        // R26 and R19 balance against the real daemon.
        assert_eq!(
            docker
                .containers_with_label(
                    LABEL_PRIVATE_ROOT,
                    &identity.private_root.to_string_lossy().replace('\\', "/")
                )
                .expect("reachable")
                .len(),
            0
        );
        assert!(
            list_intents(&identity.private_root)
                .expect("scan")
                .is_empty()
        );
    }

    /// `expected_failures_refusals`: "**reviewer write attempt fails**".
    ///
    /// DESIGN.md:610: "a `:ro` mount makes the reviewer's read-only
    /// *mechanically* perfect instead of flag-deep". The control is the same
    /// command in the `Implement` role over the same workspace: it writes, and
    /// the file appears on the host. Without it, a test in which nothing could
    /// write would pass.
    ///
    /// Second field held constant: the command, the image and the workspace;
    /// what varies is the role.
    #[test]
    fn real_docker_refuses_a_reviewer_write_to_its_read_only_mount() {
        let trace = ContainerTrace::recording();
        let docker = match docker_gate(
            "real_docker_refuses_a_reviewer_write_to_its_read_only_mount",
            trace.clone(),
        ) {
            Ok(docker) => docker,
            Err(reason) => return skipped(&reason),
        };
        let (_, image_id) = match discover(docker.as_ref(), PREFERRED_IMAGES) {
            Ok(found) => found,
            Err(reason) => return no_image(&reason),
        };

        let root = repo::scratch("real-ro");
        let run_id = gated_run("readonly");
        let repo_dir = root.join("repo");
        repo::repository(&repo_dir);
        let identity = real_identity(&root, &repo_dir, run_id);
        let _residue = LeaveNoResidue {
            docker: (*docker).clone(),
            private_root: identity.private_root.clone(),
        };
        let runner = ContainerRunner::new(
            real_policy(&image_id),
            identity.clone(),
            Box::new((*docker).clone()),
        )
        .expect("a container policy")
        .with_confinement(Confinement::of_run(&identity, &repo_dir))
        .with_poll(Duration::from_millis(10));

        let mut outcomes = Vec::new();
        for (tag, role_is_review, ordinal) in [("review", true, 0_u32), ("implement", false, 1)] {
            let workspace = root.join(format!("ws-{tag}"));
            std::fs::create_dir_all(&workspace).expect("a workspace");
            // The redirection is captured **inside** the container, because
            // `DockerCli::collect` returns only what `docker logs` wrote to its
            // own stdout and discards the container's stderr entirely
            // (`PR6A-DOCKERCLI-MERGES-STDERR-INTO-STDOUT`). Measured on docker
            // 29.7.2: `docker logs` really does separate the two streams, so
            // that is a repairable defect in the CLI adapter rather than a
            // property of the runtime — and this test does not depend on
            // either way.
            let spec =
                ShellKind::Sh.spec("( echo tactus-wrote-this > /tactus/workspace/probe.txt ) 2>&1");
            let request = if role_is_review {
                review_request(
                    spec,
                    workspace.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(60),
                    InvocationId::attempt(
                        TaskKey(0),
                        GenerationId(0),
                        AttemptNumber(1),
                        AttemptRole::ReviewPass(0),
                        ordinal,
                    ),
                )
            } else {
                worker_request(
                    spec,
                    workspace.clone(),
                    AgentId::new("claude-code"),
                    Duration::from_secs(60),
                    worker_id(ordinal),
                )
            };
            let plan = runner.plan(&request).expect("plans");
            assert_eq!(
                target_of(plan.mounts(), "/tactus/workspace").map(Mount::read_only),
                Some(role_is_review),
                "{tag}: the mount disposition"
            );
            let output = runner.run(&request).expect("runs");
            let wrote = workspace.join("probe.txt").exists();
            // Both streams, because `DockerCli::collect` merges the container's
            // stderr into its stdout — `docker logs` interleaves them on a
            // container without a TTY. Recorded as
            // `PR6A-DOCKERCLI-MERGES-STDERR-INTO-STDOUT`; the assertion is
            // written so it holds either way rather than pinning the residual.
            outcomes.push((
                tag,
                output.code,
                wrote,
                format!("{}{}", output.stdout, output.stderr),
            ));
        }

        let (_, review_code, review_wrote, review_output) = &outcomes[0];
        assert_ne!(*review_code, Some(0), "the reviewer's write succeeded");
        assert!(
            review_output.to_ascii_lowercase().contains("read-only"),
            "the failure is not the read-only mount: {review_output}"
        );
        assert!(!review_wrote, "the reviewer wrote into the workspace");

        let (_, implement_code, implement_wrote, _) = &outcomes[1];
        assert_eq!(
            *implement_code,
            Some(0),
            "the control could not write either, so the test above proves nothing"
        );
        assert!(*implement_wrote);
        assert_eq!(
            std::fs::read_to_string(root.join("ws-implement").join("probe.txt"))
                .expect("the control's file")
                .trim(),
            "tactus-wrote-this"
        );
    }

    /// `expected_failures_refusals`: "**gate write outside mount fails**", and
    /// DESIGN.md:400's whole sentence.
    ///
    /// Repository-controlled gate code — "which no agent permission surface can
    /// ever bound" (DESIGN.md:610) — is given every withheld path by absolute
    /// name and asked to read it and to write it. The assertions are on the
    /// **host**, because that is what the claim is about: a container is free
    /// to create whatever it likes inside its own writable layer, and none of
    /// it may reach the coordinator.
    ///
    /// The control is in the same command: the gate reads its own workspace,
    /// which it *can* see. A test in which the container could read nothing at
    /// all would pass without the confinement doing anything.
    #[test]
    fn real_docker_confines_a_gate_to_its_mount() {
        let trace = ContainerTrace::recording();
        let docker = match docker_gate("real_docker_confines_a_gate_to_its_mount", trace.clone()) {
            Ok(docker) => docker,
            Err(reason) => return skipped(&reason),
        };
        let (_, image_id) = match discover(docker.as_ref(), PREFERRED_IMAGES) {
            Ok(found) => found,
            Err(reason) => return no_image(&reason),
        };

        let root = repo::scratch("real-confine");
        let run_id = gated_run("confine");
        let repo_dir = root.join("repo");
        let (head, _) = repo::repository(&repo_dir);
        let identity = real_identity(&root, &repo_dir, run_id);
        let paths = RunPaths::with_private_root(&repo_dir, run_id, &identity.private_root);
        let execution_root =
            crate::workspace_manager::execution_root_of(&identity.private_root, REPO_KEY, run_id);
        let mine = execution_root.join("tasks").join("kalpha-g0");
        let sibling = execution_root.join("tasks").join("kbeta-g0");
        repo::worktree(&repo_dir, &mine, &head);
        repo::worktree(&repo_dir, &sibling, &head);
        std::fs::write(sibling.join("sibling.txt"), "SIBLING-WORKTREE-a5f2\n")
            .expect("a sibling file");
        std::fs::write(mine.join("mine.txt"), "MY-OWN-WORKTREE-a5f2\n").expect("my file");

        let withheld: Vec<(Withheld, PathBuf)> = vec![
            (Withheld::PublicLog, paths.events()),
            (
                Withheld::PrivateArtifacts,
                paths.transcripts().join("k0-a1.md"),
            ),
            (Withheld::SiblingWorktree, sibling.join("sibling.txt")),
            (
                Withheld::AuthoritativeGit,
                repo_dir.join(".git").join("HEAD"),
            ),
        ];
        let before: Vec<Vec<u8>> = withheld
            .iter()
            .map(|(_, path)| std::fs::read(path).expect("a withheld file"))
            .collect();

        let _residue = LeaveNoResidue {
            docker: (*docker).clone(),
            private_root: identity.private_root.clone(),
        };
        let runner = ContainerRunner::new(
            real_policy(&image_id),
            identity.clone(),
            Box::new((*docker).clone()),
        )
        .expect("a container policy")
        .with_confinement(
            Confinement::of_run(&identity, &repo_dir)
                .withholding(Withheld::SiblingWorktree, sibling.clone()),
        )
        .with_poll(Duration::from_millis(10));

        let mut script = String::from("cat /tactus/workspace/mine.txt;");
        for (_, path) in &withheld {
            let path = path.to_string_lossy().replace('\\', "/");
            script.push_str(&format!(
                " printf 'READ {path}: '; cat '{path}' 2>&1 | head -1; \
                 printf 'WRITE {path}: '; \
                 ( mkdir -p \"$(dirname '{path}')\" && \
                   echo tactus-container-wrote-this > '{path}' ) 2>&1 && echo WROTE || echo FAILED;"
            ));
        }
        let request = gate_request(
            ShellKind::Sh.spec(&script),
            mine.clone(),
            Duration::from_secs(60),
            gate_id(0),
        );
        let output = runner.run(&request).expect("runs");

        // The control: the gate can read its own worktree.
        assert!(
            output.stdout.contains("MY-OWN-WORKTREE-a5f2"),
            "the gate could not read its own workspace, so nothing here is measured: {:?}",
            output.stdout
        );
        // And it saw none of the withheld content.
        for marker in [
            EVENT_LOG_MARKER,
            "PRIVATE-TRANSCRIPT-a5f2",
            "SIBLING-WORKTREE-a5f2",
        ] {
            assert!(
                !output.stdout.contains(marker),
                "the gate read `{marker}`: {:?}",
                output.stdout
            );
        }
        // The host is byte-identical: whatever the container wrote stayed in
        // the container.
        for ((category, path), original) in withheld.iter().zip(&before) {
            assert_eq!(
                &std::fs::read(path).expect("still there"),
                original,
                "a gate changed `{}` ({})",
                path.display(),
                category.passage()
            );
        }
        // And the coordinator's Git is unmoved.
        assert_eq!(repo::git_ok(&repo_dir, &["rev-parse", "HEAD"]), head);
    }

    /// `proof_tests[1]`: "**Git-dependent gate sees only the role view**",
    /// against a real container.
    ///
    /// The four properties of DESIGN.md:612, each read out of a real `git`
    /// running inside the boundary: the exact detached HEAD, the exact index
    /// (`status --porcelain` is empty on a clean worktree), no engine refs, and
    /// objects that resolve. The coordinator's refs are re-read afterwards, so
    /// "without exposing **or mutating**" is both halves.
    #[test]
    fn real_docker_a_git_dependent_gate_sees_only_the_role_view() {
        let trace = ContainerTrace::recording();
        let docker = match docker_gate(
            "real_docker_a_git_dependent_gate_sees_only_the_role_view",
            trace.clone(),
        ) {
            Ok(docker) => docker,
            Err(reason) => return skipped(&reason),
        };
        let (_, image_id) = match discover(docker.as_ref(), GIT_IMAGES) {
            Ok(found) => found,
            Err(reason) => return no_image(&reason),
        };

        let root = repo::scratch("real-gitview");
        let run_id = gated_run("gitview");
        let repo_dir = root.join("repo");
        let (head, _) = repo::repository(&repo_dir);
        let planted = repo::engine_refs(&repo_dir, &head);
        let identity = real_identity(&root, &repo_dir, run_id);
        let execution_root =
            crate::workspace_manager::execution_root_of(&identity.private_root, REPO_KEY, run_id);
        let workspace = execution_root.join("tasks").join("kalpha-g0");
        repo::worktree(&repo_dir, &workspace, &head);
        repo::git_ok(&repo_dir, &["pack-refs", "--all"]);

        let _residue = LeaveNoResidue {
            docker: (*docker).clone(),
            private_root: identity.private_root.clone(),
        };
        let runner = ContainerRunner::new(
            real_policy(&image_id),
            identity.clone(),
            Box::new((*docker).clone()),
        )
        .expect("a container policy")
        .with_confinement(Confinement::of_run(&identity, &repo_dir))
        .with_poll(Duration::from_millis(10));

        // `safe.directory` because the host paths are owned by the coordinator's
        // user and the container's process is not it — an ownership check, not a
        // confinement one.
        let git = "git -c safe.directory='*' -C /tactus/workspace";
        let leak = &planted[0];
        let script = format!(
            "{git} rev-parse HEAD | sed 's/^/HEAD=/'; \
             {git} rev-parse --absolute-git-dir | sed 's/^/GITDIR=/'; \
             {git} for-each-ref --format='%(refname)' | wc -l | tr -d ' ' | sed 's/^/REFS=/'; \
             {git} log -1 --format=%s | sed 's/^/SUBJECT=/'; \
             {git} status --porcelain | wc -l | tr -d ' ' | sed 's/^/DIRTY=/'; \
             {git} rev-parse --verify --quiet '{leak}' >/dev/null 2>&1 && echo LEAK=yes || echo LEAK=no"
        );
        let request = gate_request(
            ShellKind::Sh.spec(&script),
            workspace.clone(),
            Duration::from_secs(60),
            gate_id(0),
        );
        let output = runner.run(&request).expect("runs");
        assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
        let line = |key: &str| -> String {
            output
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap_or_else(|| {
                    panic!(
                        "`{key}` is not in stdout {:?} / stderr {:?}",
                        output.stdout, output.stderr
                    )
                })
                .trim()
                .to_owned()
        };
        assert_eq!(line("HEAD="), head, "the exact detached HEAD");
        assert_eq!(
            line("GITDIR="),
            BoundaryLayout::DEFAULT_GIT_VIEW,
            "the tool found the coordinator's Git directory, not the role view"
        );
        assert_eq!(line("REFS="), "0", "the view carries refs");
        assert_eq!(line("SUBJECT="), "second", "the objects do not resolve");
        assert_eq!(
            line("DIRTY="),
            "0",
            "the index the view carries is not exact"
        );
        assert_eq!(
            line("LEAK="),
            "no",
            "an engine ref resolved inside the view"
        );

        // Nothing was exposed and nothing was mutated: the coordinator's refs
        // are all still there and still where they were.
        for name in &planted {
            assert_eq!(
                repo::git_ok(&repo_dir, &["rev-parse", "--verify", name]),
                head
            );
        }
        assert_eq!(repo::git_ok(&repo_dir, &["rev-parse", "HEAD"]), head);
        assert!(
            list_intents(&identity.private_root)
                .expect("scan")
                .is_empty()
        );
    }

    /// `decisions.tests_acceptance.parity`: "host and container runners produce
    /// identical **adapter parsing**".
    ///
    /// The table, the fixtures and the expectations are PR4's — `runner::tests::
    /// adapter_parse_parity` was written for exactly this and its doc comment
    /// says so — and the **only** thing this test varies is the `&dyn Runner`.
    /// It is a real chain, spec -> runner -> `ProcessOutput` -> `AgentAdapter::
    /// parse`, because the claim is about the seam: an adapter never learns
    /// which runner produced the output it reads, and nothing but a runner
    /// actually producing it proves that.
    #[test]
    fn real_docker_adapter_parsing_matches_the_host_table() {
        let trace = ContainerTrace::recording();
        let docker = match docker_gate(
            "real_docker_adapter_parsing_matches_the_host_table",
            trace.clone(),
        ) {
            Ok(docker) => docker,
            Err(reason) => return skipped(&reason),
        };
        let (_, image_id) = match discover(docker.as_ref(), PREFERRED_IMAGES) {
            Ok(found) => found,
            Err(reason) => return no_image(&reason),
        };

        let root = repo::scratch("real-parity");
        let run_id = gated_run("parity");
        let repo_dir = root.join("repo");
        repo::repository(&repo_dir);
        let identity = real_identity(&root, &repo_dir, run_id);
        let workspace = root.join("parity-workspace");
        std::fs::create_dir_all(&workspace).expect("a workspace");
        let _residue = LeaveNoResidue {
            docker: (*docker).clone(),
            private_root: identity.private_root.clone(),
        };
        let runner = ContainerRunner::new(
            real_policy(&image_id),
            identity.clone(),
            Box::new((*docker).clone()),
        )
        .expect("a container policy")
        .with_confinement(Confinement::of_run(&identity, &repo_dir))
        .with_poll(Duration::from_millis(10));

        let container_rows = crate::runner::tests::adapter_parse_parity(&runner, &workspace);
        let host_rows = crate::runner::tests::adapter_parse_parity(
            &crate::runner::host::HostRunner::new(),
            &workspace,
        );
        assert_eq!(
            container_rows, host_rows,
            "the container runner's adapter parsing differs from the host's"
        );
        // The table is not empty and really did vary, so equality is a claim.
        assert_eq!(container_rows.len(), 3);
        let statuses: BTreeSet<String> = container_rows
            .iter()
            .map(|row| format!("{:?}", row.status))
            .collect();
        assert_eq!(statuses.len(), 2, "{statuses:?}");
        assert!(
            list_intents(&identity.private_root)
                .expect("scan")
                .is_empty()
        );
    }

    /// Every Docker-gated test this lane adds is on the list that counts them.
    ///
    /// `every_docker_gated_test_is_named_and_present` in the substrate's own
    /// suite closes both directions across `src/runner/**`; this is the lane's
    /// half, so a name added here without being listed fails in this file
    /// rather than in another lane's.
    #[test]
    fn every_gated_test_of_this_lane_is_counted() {
        const MINE: &[&str] = &[
            "real_docker_runs_from_the_recorded_image_id_and_composes_over_the_image_environment",
            "real_docker_refuses_a_reviewer_write_to_its_read_only_mount",
            "real_docker_confines_a_gate_to_its_mount",
            "real_docker_a_git_dependent_gate_sees_only_the_role_view",
            "real_docker_adapter_parsing_matches_the_host_table",
        ];
        assert_eq!(MINE.len(), 5);
        assert_eq!(GATED_RUNS.len(), MINE.len(), "one run id per gated test");
        let ids: BTreeSet<&str> = GATED_RUNS.iter().map(|(_, run)| *run).collect();
        assert_eq!(
            ids.len(),
            GATED_RUNS.len(),
            "two gated tests share a run id, so they would fight over a container name"
        );
        let source = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("runner")
                .join("container")
                .join("exec.rs"),
        )
        .expect("read this module");
        for name in MINE {
            assert!(
                DOCKER_GATED_TESTS.contains(name),
                "`{name}` is gated and nothing counts it"
            );
            assert!(
                source.contains(&format!("fn {name}(")),
                "`{name}` is counted and is not a test here"
            );
        }
    }
}
