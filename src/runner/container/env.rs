//! `container-v1`'s environment contract, and the boundary layout the
//! environment names.
//!
//! DESIGN.md:258-264, quoted in full because every clause is separately
//! droppable:
//!
//! > `CommandSpec.env` **overlays a runner-owned base rather than replacing
//! > it**. The host runner starts from the Tactus environment and **the
//! > container runner from the image environment**; each supplies role-scoped
//! > `HOME`, `PATH`, and credential locations. Adapter overrides may select
//! > profiles or CLI behavior but **may not conflict with runner-reserved
//! > keys**. **Probe and execution compose the same base, mounts, reserved
//! > values, and overlay**, so pre-flight certifies the environment that will
//! > actually spend.
//!
//! ## Why this is a second implementation and not a call into `host-v1`
//!
//! `decisions.tests_acceptance.parity` is "host and container runners produce
//! identical adapter parsing and **environment composition**". A container
//! runner that delegated composition to [`crate::runner::host::HostEnvironment`]
//! would make that clause true by construction and therefore unmeasurable — the
//! parity test would compare a function with itself, which is the project's own
//! "a function may not be its own oracle" applied to a whole seam. So the
//! contract is implemented twice and
//! `exec::tests::host_and_container_compose_the_same_environment_for_every_role`
//! is the cross-check, over an **explicit shared base** so the two really do
//! differ in nothing but the runner.
//!
//! What is *not* re-derived is the **reserved-key enumeration**:
//! [`crate::runner::host::reserved_keys`] is a `pub fn` and is the one list, so
//! "which keys are reserved" is a thing another module reads rather than a
//! literal buried in a match arm here. Two runners disagreeing about the
//! reserved set would be a difference no parity test could interpret.
//!
//! ## What role-scoping means at a boundary with its own filesystem
//!
//! The host supplies a credential *location* from its own base and relies on
//! the agent's permission surface for everything else. A container supplies the
//! location **and** either mounts that agent's credential volume there or does
//! not — so for a role that takes no credentials the directory the variable
//! names is simply not there. That is the mechanically-perfect half
//! DESIGN.md:610 claims a container buys, and it is why
//! [`supplies_credential_location`] and the mount plan in
//! [`super::exec::ContainerRunner`] are asserted to be **the same predicate**
//! rather than two rules that happen to agree.

use std::collections::BTreeMap;

use crate::error::TactusError;
use crate::runner::host::{KeyCase, credential_location, reserved_keys};
use crate::runner::{AgentId, ExecutionRole, ProbeTarget};

// ---------------------------------------------------------------------------
// The boundary's own layout
// ---------------------------------------------------------------------------

/// Where a container sees the things it is given.
///
/// A value rather than a set of constants, because both the environment
/// (`HOME`, credential locations) and the mount plan
/// ([`super::exec::ContainerRunner`]) have to name the same paths, and two
/// literals that must agree are two literals that drift. The mount target and
/// the variable that points at it come from one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryLayout {
    workspace: String,
    credentials: String,
    git_view: String,
    git_objects: String,
}

impl Default for BoundaryLayout {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundaryLayout {
    /// Where the role's one worktree is mounted.
    ///
    /// DESIGN.md:400: "A container receives **only its role's one worktree
    /// mount**". One path, so a second worktree would need a second target and
    /// there is nowhere to put it.
    pub const DEFAULT_WORKSPACE: &'static str = "/tactus/workspace";

    /// Under which each agent's credential volume is mounted.
    pub const DEFAULT_CREDENTIALS: &'static str = "/tactus/credentials";

    /// Where the disposable Git view is mounted.
    ///
    /// A root of its own rather than `<workspace>/.git`, and that is forced by
    /// the runtime rather than chosen. Measured against `docker` 29.7.2: a bind
    /// mount whose source is a **directory** and whose target is an existing
    /// **file** fails the container's `runc create` outright —
    /// `not a directory: Are you trying to mount a directory onto a file` — and
    /// a linked worktree's `.git` is exactly such a file. So the view is
    /// mounted here and `<workspace>/.git` receives a one-line **file** mount
    /// pointing at it, which is the shape a linked worktree already has and is
    /// therefore an overlay rather than a redirection: a tool that opens
    /// `<workspace>/.git` finds the disposable view, not the real repository,
    /// with no environment variable involved.
    pub const DEFAULT_GIT_VIEW: &'static str = "/tactus/gitview";

    /// Where the repository's object store is mounted, **read-only**.
    ///
    /// Beside the view rather than inside it, so the view's own `objects/`
    /// stays writable: every object a gate creates lands in the disposable half
    /// and the borrowed store is one the kernel will not let the container
    /// write. Mounting the borrowed store *over* `<view>/objects` would make
    /// `git add`, `git stash` and `git write-tree` fail hard inside every
    /// container.
    pub const DEFAULT_GIT_OBJECTS: &'static str = "/tactus/gitobjects";

    /// The default layout.
    #[must_use]
    pub fn new() -> Self {
        Self {
            workspace: Self::DEFAULT_WORKSPACE.to_owned(),
            credentials: Self::DEFAULT_CREDENTIALS.to_owned(),
            git_view: Self::DEFAULT_GIT_VIEW.to_owned(),
            git_objects: Self::DEFAULT_GIT_OBJECTS.to_owned(),
        }
    }

    /// A layout with explicit roots, so a grid can vary them.
    #[must_use]
    pub fn with_roots(
        workspace: impl Into<String>,
        credentials: impl Into<String>,
        git_view: impl Into<String>,
        git_objects: impl Into<String>,
    ) -> Self {
        Self {
            workspace: workspace.into(),
            credentials: credentials.into(),
            git_view: git_view.into(),
            git_objects: git_objects.into(),
        }
    }

    /// The role's worktree.
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    /// The disposable Git view.
    #[must_use]
    pub fn git_view(&self) -> &str {
        &self.git_view
    }

    /// The borrowed, read-only object store.
    #[must_use]
    pub fn git_objects(&self) -> &str {
        &self.git_objects
    }

    /// `<workspace>/.git` — where a Git-dependent tool looks, and what the
    /// view overlays.
    ///
    /// DESIGN.md:612: "Because a linked worktree's `.git` points back into the
    /// real repository, the container **overlays** a disposable role-scoped Git
    /// view". *Overlays* — at the place the tools look.
    #[must_use]
    pub fn git_pointer(&self) -> String {
        format!("{}/.git", self.workspace)
    }

    /// Where this agent's credential volume is mounted.
    #[must_use]
    pub fn credentials(&self, agent: &AgentId) -> String {
        format!("{}/{}", self.credentials, agent.as_str())
    }

    /// The credential root itself.
    #[must_use]
    pub fn credential_root(&self) -> &str {
        &self.credentials
    }
}

// ---------------------------------------------------------------------------
// Role scoping
// ---------------------------------------------------------------------------

/// Whether `container-v1` tells this role where an agent's credentials live —
/// and, equivalently, whether it mounts that agent's credential volume.
///
/// Transcribed from the same two sentences `host-v1` reads, not from
/// `host-v1`:
///
/// * INV-18: "every agent CLI invocation **incl. agent probes** acquires its
///   atomic {agent, pool?} pair while gates **and the shell probe** register
///   without slots" — the split between the processes that execute an agent CLI
///   and the ones that do not.
/// * DESIGN.md:260: "each supplies **role-scoped** … credential locations".
///
/// A gate is repository-controlled code — the thing DESIGN.md:610 says a
/// container exists to confine — and the shell probe is a shell running
/// `exit 0`. Neither runs an agent CLI, so neither is handed an agent's
/// credentials, whatever agent the request happens to name.
///
/// Exhaustive with no wildcard: a role added later has to be classified here
/// rather than defaulting into the side that hands out credentials.
#[must_use]
pub const fn supplies_credential_location(role: &ExecutionRole) -> bool {
    match role {
        ExecutionRole::Implement
        | ExecutionRole::Review
        | ExecutionRole::Probe(ProbeTarget::Agent(_)) => true,
        ExecutionRole::Gate | ExecutionRole::Probe(ProbeTarget::Shell) => false,
    }
}

// ---------------------------------------------------------------------------
// The environment
// ---------------------------------------------------------------------------

/// The name rule the **container** boundary obeys.
///
/// `KeyCase::Sensitive` unconditionally, and that is a decision rather than an
/// oversight: `host-v1` takes [`KeyCase::current`], the *coordinator's* rule,
/// because its boundary is the coordinator's own process environment. A
/// container's boundary is the image, and DESIGN.md:610's Windows paragraph
/// puts the repository "WSL-side" — the boundary is Linux even when the
/// coordinator is not. A container runner that took `KeyCase::current()` would,
/// on a Windows coordinator, treat `Path` and `PATH` as one variable inside a
/// boundary where they are two, and would refuse an overlay key the boundary
/// does not reserve.
pub const CONTAINER_KEY_CASE: KeyCase = KeyCase::Sensitive;

/// What one request's environment is composed for.
///
/// A struct rather than four parameters because the four travel together and a
/// call site that got one of them wrong — a gate carrying a bound agent, say —
/// is the shape `runner::worker_request` and its siblings exist to prevent.
#[derive(Debug, Clone, Copy)]
pub struct RoleScope<'a> {
    /// Which seat this process occupies.
    pub role: &'a ExecutionRole,
    /// The agent whose credential volume this process uses, if any.
    pub agent: Option<&'a AgentId>,
    /// The run's recorded per-agent credential volume names
    /// (`RunnerPolicy.credential_volumes`). A volume this map does not name
    /// cannot be mounted, so its location is not supplied either.
    pub volumes: &'a BTreeMap<String, String>,
    /// Where the boundary puts things.
    pub layout: &'a BoundaryLayout,
}

/// `container-v1`'s environment contract.
///
/// Holds its base explicitly, exactly as [`crate::runner::host::HostEnvironment`]
/// does and for the same reason: a test composes against a base it wrote rather
/// than against whatever the machine happens to carry.
#[derive(Debug, Clone)]
pub struct ContainerEnvironment {
    base: Vec<(String, String)>,
    case: KeyCase,
}

impl Default for ContainerEnvironment {
    fn default() -> Self {
        Self::inherited()
    }
}

impl ContainerEnvironment {
    /// The image environment, as the base.
    ///
    /// "the container runner [starts] from the image environment"
    /// (DESIGN.md:259).
    #[must_use]
    pub fn from_image(base: Vec<(String, String)>) -> Self {
        Self {
            base,
            case: CONTAINER_KEY_CASE,
        }
    }

    /// An empty base: the runtime applies the image environment itself.
    ///
    /// `docker create --env K=V` **overlays** the image's own environment
    /// rather than replacing it, so a runner that names no key still executes
    /// against the image environment — which is precisely the base
    /// DESIGN.md:259 gives this runner. This constructor is the honest spelling
    /// of "the base is the image's, and this runner did not read it": the
    /// composed vector then names only the keys the runner owns.
    ///
    /// **The residual is stated rather than hidden.** A container runtime
    /// cannot *unset* a variable the image sets, so an image whose environment
    /// carries an agent's credential-location variable hands it to every role,
    /// including the ones [`supplies_credential_location`] refuses. What that
    /// cannot do is hand over the credentials themselves: the volume is either
    /// mounted at that path or it is not, and for a gate it is not. The mount
    /// is the boundary; the variable is a pointer.
    #[must_use]
    pub fn inherited() -> Self {
        Self::from_image(Vec::new())
    }

    /// An explicit base and an explicit name rule, for grids that must cover
    /// both rules.
    #[must_use]
    pub fn with_base(base: Vec<(String, String)>, case: KeyCase) -> Self {
        Self { base, case }
    }

    /// The base this runner composes from.
    #[must_use]
    pub fn base(&self) -> &[(String, String)] {
        &self.base
    }

    /// The name rule in force.
    #[must_use]
    pub const fn case(&self) -> KeyCase {
        self.case
    }

    /// The reserved values the runner supplies for this request.
    ///
    /// The same two rules `host-v1` applies, resolved for a boundary that has
    /// its own filesystem:
    ///
    /// * `PATH`, `HOME` and `USERPROFILE` are supplied to **every** role at the
    ///   boundary's own value — from the base, which for this runner is the
    ///   image environment. Not per-role: DESIGN.md:263's "probe and execution
    ///   compose the same base … so pre-flight certifies the environment that
    ///   will actually spend" forbids a `HOME` that differs between
    ///   `probe(<agent>)` and `implement`, and a `PATH` that differed between
    ///   `probe(shell)` and `gate` would certify a different program from the
    ///   one that runs. A reserved key the base does not carry is **not**
    ///   supplied — setting an absent variable to the empty string is a
    ///   different environment from not setting it.
    /// * The **credential location is role-scoped**, and its value is the
    ///   boundary's own: the mount target of that agent's credential volume,
    ///   never a coordinator-host path. A host path here would name nothing
    ///   inside the image, which is the container half of
    ///   `PR4-ADAPTER-RESOLVES-ON-THE-HOST` applied to the environment.
    #[must_use]
    pub fn reserved_values(&self, scope: &RoleScope<'_>) -> Vec<(String, String)> {
        let mut supplied = Vec::new();
        for key in crate::runner::host::RESERVED_ALWAYS {
            if let Some(value) = self.lookup(key) {
                supplied.push(((*key).to_owned(), value));
            }
        }
        if supplies_credential_location(scope.role) {
            if let Some(agent) = scope.agent {
                // A location is supplied only when a volume is recorded for
                // that agent: the run's `RunnerPolicy.credential_volumes` is
                // what says which volumes exist, and pointing a CLI at a
                // directory nothing mounts is worse than saying nothing.
                if scope.volumes.contains_key(agent.as_str()) {
                    if let Some(key) = credential_location(agent) {
                        supplied.push((key.to_owned(), scope.layout.credentials(agent)));
                    }
                }
            }
        }
        supplied
    }

    /// Base, then reserved values, then overlay — DESIGN.md:263's own order
    /// ("the same base, mounts, reserved values, and overlay").
    ///
    /// The base's own copies of the **reserved** keys are dropped before the
    /// runner supplies them, for the reason `host-v1` states: cloning the base
    /// and upserting would leave every credential location the image happens to
    /// carry in a gate's environment, and would make this step
    /// output-equivalent to deleting it, because [`Self::reserved_values`]
    /// reads its values back out of the same base.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] naming the key when the overlay names a
    /// reserved one — refused by **key**, not by value, exactly as `host-v1`
    /// refuses it: an overlay permitted to restate `PATH` today because the
    /// value happens to match is an overlay that breaks silently the day the
    /// runner's value changes.
    pub fn compose(
        &self,
        scope: &RoleScope<'_>,
        overlay: &[(String, String)],
    ) -> Result<Vec<(String, String)>, TactusError> {
        self.preflight(overlay)?;
        let mut composed = self.base.clone();
        for reserved in reserved_keys() {
            composed.retain(|(name, _)| !self.case.same_key(name.as_ref(), reserved.as_ref()));
        }
        for (key, value) in self.reserved_values(scope) {
            upsert(&mut composed, self.case, key, value);
        }
        for (key, value) in overlay {
            upsert(&mut composed, self.case, key.clone(), value.clone());
        }
        Ok(composed)
    }

    /// The reserved-key refusal on its own, so a caller can certify an overlay
    /// without building an environment.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] naming the offending key and the reserved key
    /// it collides with.
    pub fn preflight(&self, overlay: &[(String, String)]) -> Result<(), TactusError> {
        for (key, _) in overlay {
            if let Some(reserved) = reserved_keys()
                .into_iter()
                .find(|reserved| self.case.same_key(key.as_ref(), reserved.as_ref()))
            {
                return Err(TactusError::Refused {
                    message: format!(
                        "the command overlay sets `{key}`, which is reserved by the container \
                         runner (`{reserved}`). An adapter may select a profile or change CLI \
                         behaviour, but the runner owns the environment the process executes in \
                         (DESIGN.md:258-264)"
                    ),
                });
            }
        }
        Ok(())
    }

    fn lookup(&self, key: &str) -> Option<String> {
        self.base
            .iter()
            .find(|(name, _)| self.case.same_key(name.as_ref(), key.as_ref()))
            .map(|(_, value)| value.clone())
    }
}

fn upsert(into: &mut Vec<(String, String)>, case: KeyCase, key: String, value: String) {
    if let Some(slot) = into
        .iter_mut()
        .find(|(name, _)| case.same_key(name.as_ref(), key.as_ref()))
    {
        slot.1 = value;
        return;
    }
    into.push((key, value));
}

// -- test-only declarations ----------------------------------------------
// At the BOTTOM: `effects::production_region` cuts a source at its first
// `#[cfg(test)]`, so a test module above would remove everything below it from
// every source census (`PR5-R1-CFG-TEST-SHRINKS-THE-DOMAIN`).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::host::{CREDENTIAL_LOCATIONS, HostEnvironment, RESERVED_ALWAYS};

    /// The three shipped adapters, and a volume name per adapter. Every value
    /// distinct, so a swap between two of them is visible.
    const VOLUMES: &[(&str, &str)] = &[
        ("claude-code", "tactus-creds-claude"),
        ("copilot", "tactus-creds-copilot"),
        ("codex", "tactus-creds-codex"),
    ];

    fn volumes() -> BTreeMap<String, String> {
        VOLUMES
            .iter()
            .map(|(agent, volume)| ((*agent).to_owned(), (*volume).to_owned()))
            .collect()
    }

    /// An image environment with a value for every key any test reads, each
    /// distinct.
    fn image_base() -> Vec<(String, String)> {
        [
            ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"),
            ("HOME", "/root"),
            ("LANG", "C.UTF-8"),
            ("TACTUS_IMAGE_MARKER", "image-environment-v1"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    fn scope<'a>(
        role: &'a ExecutionRole,
        agent: Option<&'a AgentId>,
        volumes: &'a BTreeMap<String, String>,
        layout: &'a BoundaryLayout,
    ) -> RoleScope<'a> {
        RoleScope {
            role,
            agent,
            volumes,
            layout,
        }
    }

    /// The agent a role binds in production: `runner::worker_request` and its
    /// siblings decide this, and a grid that let the binding ride along with
    /// the role would be varying two fields and calling it one.
    fn binding(role: &ExecutionRole) -> Option<AgentId> {
        match role {
            ExecutionRole::Gate | ExecutionRole::Probe(ProbeTarget::Shell) => None,
            ExecutionRole::Probe(ProbeTarget::Agent(agent)) => Some(agent.clone()),
            ExecutionRole::Implement | ExecutionRole::Review => Some(AgentId::new("claude-code")),
        }
    }

    fn value<'a>(composed: &'a [(String, String)], key: &str) -> Option<&'a str> {
        composed
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// The reserved set is **one** enumeration, and it is `host-v1`'s.
    ///
    /// Second field held constant: the role is `Implement` throughout, so what
    /// varies is only which key is offered. The expected list is written from
    /// DESIGN.md:260 ("role-scoped `HOME`, `PATH`, and credential locations")
    /// and `src/capacity.rs:36-37`'s naming of the three vendor variables — not
    /// read back from `reserved_keys()`, which is the function this pins.
    #[test]
    fn the_reserved_key_enumeration_is_the_hosts_and_not_a_second_list() {
        const EXPECTED: &[&str] = &[
            "PATH",
            "HOME",
            "USERPROFILE",
            "CLAUDE_CONFIG_DIR",
            "COPILOT_HOME",
            "CODEX_HOME",
        ];
        let keys = reserved_keys();
        assert_eq!(keys, EXPECTED, "the reserved enumeration moved");
        assert_eq!(RESERVED_ALWAYS.len() + CREDENTIAL_LOCATIONS.len(), 6);

        // And the container runner refuses every one of them, by key, so the
        // two boundaries cannot disagree about what "reserved" means. A second
        // list here would be a difference no parity test could interpret.
        let environment = ContainerEnvironment::from_image(image_base());
        let host = HostEnvironment::with_base(Vec::new(), CONTAINER_KEY_CASE);
        for key in EXPECTED {
            let overlay = vec![((*key).to_owned(), "anything".to_owned())];
            let refusal = environment
                .preflight(&overlay)
                .expect_err("a reserved key in the overlay is refused");
            assert!(
                refusal.to_string().contains(key),
                "the refusal does not name `{key}`: {refusal}"
            );
            host.preflight(&overlay)
                .expect_err("and the host refuses the same key");
        }
        // The control: a key neither runner reserves composes.
        environment
            .preflight(&[(
                "CLAUDE_CODE_MAX_OUTPUT_TOKENS".to_owned(),
                "8000".to_owned(),
            )])
            .expect("an ordinary adapter override is not a reserved key");
    }

    /// Every role refuses every reserved key, and refuses it **by key** rather
    /// than by value.
    ///
    /// Second field held constant: the base and the volume set, so what varies
    /// is the (role, key) pair. Thirty refusals plus five controls, counted.
    #[test]
    fn an_overlay_naming_a_reserved_key_is_refused_by_key_across_every_role() {
        let environment = ContainerEnvironment::from_image(image_base());
        let volumes = volumes();
        let layout = BoundaryLayout::new();
        let mut refused = 0_usize;
        let mut allowed = 0_usize;
        for role in ExecutionRole::all() {
            let agent = binding(&role);
            let scope = scope(&role, agent.as_ref(), &volumes, &layout);
            for key in reserved_keys() {
                // The value is exactly what the runner itself would supply for
                // `PATH`, so a refusal that compared values would let this one
                // through.
                let value = if key == "PATH" {
                    "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin".to_owned()
                } else {
                    layout.credentials(&AgentId::new("claude-code"))
                };
                environment
                    .compose(&scope, &[(key.to_owned(), value)])
                    .expect_err("a reserved key is refused whatever its value");
                refused += 1;
            }
            environment
                .compose(&scope, &[("TACTUS_OVERLAY".to_owned(), "1".to_owned())])
                .expect("a non-reserved overlay key composes");
            allowed += 1;
        }
        assert_eq!(refused, 5 * 6, "five roles crossed with six reserved keys");
        assert_eq!(allowed, 5);
        assert_eq!(ExecutionRole::all().len(), 5);
    }

    /// "overlays a runner-owned base rather than replacing it" — three
    /// fixtures, because the sentence has three separately droppable halves.
    #[test]
    fn the_overlay_overlays_the_base_rather_than_replacing_it() {
        let environment = ContainerEnvironment::from_image(image_base());
        let volumes = volumes();
        let layout = BoundaryLayout::new();
        let role = ExecutionRole::Gate;
        let scope = scope(&role, None, &volumes, &layout);

        let composed = environment
            .compose(
                &scope,
                &[
                    // (b) an overlay key the base does not carry lands
                    ("TACTUS_NEW".to_owned(), "landed".to_owned()),
                    // (c) a collision between base and overlay resolves to the
                    // overlay
                    ("LANG".to_owned(), "en_GB.UTF-8".to_owned()),
                ],
            )
            .expect("composes");

        // (a) a base key with no overlay survives
        assert_eq!(
            value(&composed, "TACTUS_IMAGE_MARKER"),
            Some("image-environment-v1"),
            "the image environment is the base, and a key nobody touched survives it"
        );
        assert_eq!(value(&composed, "TACTUS_NEW"), Some("landed"));
        assert_eq!(value(&composed, "LANG"), Some("en_GB.UTF-8"));

        // One entry per key: an overlay that appended rather than upserted
        // would leave the child with whichever the runtime read last.
        let mut keys: Vec<&str> = composed.iter().map(|(key, _)| key.as_str()).collect();
        let total = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), total, "a key appears twice in the composed set");

        // And the base really did carry a different value for the collided key,
        // so (c) is a statement about resolution rather than about equality.
        assert_eq!(
            environment
                .base()
                .iter()
                .find(|(key, _)| key == "LANG")
                .map(|(_, v)| v.as_str()),
            Some("C.UTF-8")
        );
    }

    /// The credential location is role-scoped, and its value is the
    /// **boundary's** path.
    ///
    /// The grid is {5 roles} × {volume recorded, volume absent}, and the second
    /// field is the one that matters: a rule keyed only on the role would
    /// supply a location for a volume the record does not name, and a rule
    /// keyed only on the record would hand a gate an agent's credentials.
    #[test]
    fn the_credential_location_is_role_scoped_and_names_the_boundarys_own_path() {
        let environment = ContainerEnvironment::from_image(image_base());
        let layout = BoundaryLayout::new();
        let recorded = volumes();
        let empty = BTreeMap::new();

        let mut supplied = 0_usize;
        let mut withheld = 0_usize;
        let mut targets: Vec<String> = Vec::new();
        for role in ExecutionRole::all() {
            let agent = binding(&role);
            for (recorded_volumes, is_recorded) in [(&recorded, true), (&empty, false)] {
                let scope = scope(&role, agent.as_ref(), recorded_volumes, &layout);
                let composed = environment.compose(&scope, &[]).expect("composes");
                let key = agent.as_ref().and_then(credential_location);
                let found = key.and_then(|key| value(&composed, key));
                let expected =
                    supplies_credential_location(&role) && agent.is_some() && is_recorded;
                assert_eq!(
                    found.is_some(),
                    expected,
                    "{role} (volume recorded: {is_recorded}) got {found:?}"
                );
                if let Some(found) = found {
                    let agent = agent.as_ref().expect("a location implies an agent");
                    assert_eq!(found, layout.credentials(agent));
                    assert!(
                        found.starts_with(layout.credential_root()),
                        "the location is the boundary's own path, not a host one: {found}"
                    );
                    targets.push(found.to_owned());
                    supplied += 1;
                } else {
                    withheld += 1;
                }
            }
        }
        // Implement, Review and probe(claude-code) with a recorded volume.
        assert_eq!(supplied, 3, "three of the ten cells supply a location");
        assert_eq!(withheld, 7);

        // The cell the production request builders cannot reach: a role that
        // takes no credentials, carrying an agent anyway. `host-v1`'s own
        // `reserved_values` names this shape — "neither is told where an
        // agent's credentials live, **whatever agent the request happens to
        // name**" — and a grid built from `binding(role)` alone never asks it,
        // because that function gives a gate and a shell probe `None`.
        let claude = AgentId::new("claude-code");
        let mut hostile = 0_usize;
        for role in [
            ExecutionRole::Gate,
            ExecutionRole::Probe(ProbeTarget::Shell),
        ] {
            let scope = scope(&role, Some(&claude), &recorded, &layout);
            let composed = environment.compose(&scope, &[]).expect("composes");
            assert_eq!(
                value(&composed, "CLAUDE_CONFIG_DIR"),
                None,
                "{role} named an agent and was handed its credential location"
            );
            hostile += 1;
        }
        assert_eq!(hostile, 2);

        // Distinct-value count over the agents, so a layout that returned one
        // path for every agent is visible.
        let per_agent: std::collections::BTreeSet<String> = VOLUMES
            .iter()
            .map(|(agent, _)| layout.credentials(&AgentId::new(*agent)))
            .collect();
        assert_eq!(per_agent.len(), VOLUMES.len(), "{per_agent:?}");
        assert!(!targets.is_empty());
    }

    /// The container boundary is case-sensitive whatever the coordinator is.
    ///
    /// Second field held constant: the role and the base; what varies is the
    /// name rule, and it is varied over `KeyCase::ALL` rather than through
    /// `cfg!(windows)` — a rule written as a `cfg!` is a rule whose other arm
    /// no test on this machine can reach.
    #[test]
    fn the_container_boundary_is_case_sensitive_whatever_the_coordinator_is() {
        assert_eq!(
            CONTAINER_KEY_CASE,
            KeyCase::Sensitive,
            "a Linux image has two variables where Windows has one"
        );
        assert_eq!(KeyCase::ALL.len(), 2);

        let volumes = volumes();
        let layout = BoundaryLayout::new();
        let role = ExecutionRole::Gate;
        let scope = scope(&role, None, &volumes, &layout);
        let overlay = vec![("Path".to_owned(), "/opt/tools".to_owned())];

        let sensitive = ContainerEnvironment::with_base(image_base(), KeyCase::Sensitive);
        let composed = sensitive
            .compose(&scope, &overlay)
            .expect("`Path` is not `PATH` at a boundary that tells them apart");
        assert_eq!(value(&composed, "Path"), Some("/opt/tools"));
        assert_eq!(
            value(&composed, "PATH"),
            Some("/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"),
            "both variables survive, which is what case-sensitive means"
        );

        let insensitive = ContainerEnvironment::with_base(image_base(), KeyCase::Insensitive);
        insensitive
            .compose(&scope, &overlay)
            .expect_err("under the other rule `Path` collides with the reserved `PATH`");

        // And the production constructor picks the sensitive rule, on every
        // platform this crate builds for.
        assert_eq!(
            ContainerEnvironment::inherited().case(),
            KeyCase::Sensitive,
            "the coordinator's platform decided the container's name rule"
        );
    }

    /// The base's own copies of the reserved keys are dropped before the runner
    /// supplies them.
    ///
    /// This is the assertion `host-v1`'s own doc comment says the step exists
    /// for, transcribed to the other boundary: an implementation that cloned
    /// the base and upserted would leave every credential location the *image*
    /// happens to carry in a gate's environment, and would be output-equivalent
    /// to deleting the step, because `reserved_values` reads its values back
    /// out of the same base.
    ///
    /// Second field held constant: the image, which carries `CODEX_HOME` in
    /// both cells; what varies is the role.
    #[test]
    fn an_image_credential_variable_does_not_survive_into_a_role_that_takes_none() {
        let mut base = image_base();
        base.push(("CODEX_HOME".to_owned(), "/image/codex".to_owned()));
        let environment = ContainerEnvironment::from_image(base);
        let volumes = volumes();
        let layout = BoundaryLayout::new();
        let codex = AgentId::new("codex");

        let gate = ExecutionRole::Gate;
        let composed = environment
            .compose(&scope(&gate, Some(&codex), &volumes, &layout), &[])
            .expect("composes");
        assert_eq!(
            value(&composed, "CODEX_HOME"),
            None,
            "a gate is repository-controlled code and was handed an agent's credential location"
        );

        let implement = ExecutionRole::Implement;
        let composed = environment
            .compose(&scope(&implement, Some(&codex), &volumes, &layout), &[])
            .expect("composes");
        assert_eq!(
            value(&composed, "CODEX_HOME"),
            Some(layout.credentials(&codex).as_str()),
            "the value is the boundary's mount target, not the image's own path"
        );
        assert_ne!(
            value(&composed, "CODEX_HOME"),
            Some("/image/codex"),
            "the image's value survived the supply step"
        );
    }

    /// Four in-container roots, and every derived path follows its own.
    ///
    /// Two literals that must agree are two literals that drift, so the mount
    /// target and the variable that points at it come from one value. Varying
    /// every root moves every derived path, which is what says they are
    /// derived; the five roots are asserted **pairwise distinct** so a layout
    /// that collapsed two of them onto one path is visible.
    #[test]
    fn the_boundary_layout_derives_every_path_from_its_own_root() {
        let layout = BoundaryLayout::new();
        assert_eq!(layout.workspace(), "/tactus/workspace");
        assert_eq!(layout.git_view(), "/tactus/gitview");
        assert_eq!(layout.git_objects(), "/tactus/gitobjects");
        assert_eq!(layout.git_pointer(), "/tactus/workspace/.git");
        assert_eq!(
            layout.credentials(&AgentId::new("codex")),
            "/tactus/credentials/codex"
        );
        // `git_pointer` is where a tool looks, so it is inside the workspace;
        // the view and the borrowed store are not, because a directory cannot
        // be bind-mounted onto a file and a read-only object mount over the
        // view's own `objects/` would make every write-side Git call fail.
        assert!(layout.git_pointer().starts_with(layout.workspace()));
        assert!(!layout.git_view().starts_with(layout.workspace()));
        assert!(!layout.git_objects().starts_with(layout.git_view()));

        let moved = BoundaryLayout::with_roots(
            "/elsewhere/ws",
            "/elsewhere/creds",
            "/elsewhere/view",
            "/elsewhere/objects",
        );
        assert_eq!(moved.git_pointer(), "/elsewhere/ws/.git");
        assert_eq!(moved.git_view(), "/elsewhere/view");
        assert_eq!(moved.git_objects(), "/elsewhere/objects");
        assert_eq!(
            moved.credentials(&AgentId::new("codex")),
            "/elsewhere/creds/codex"
        );

        let before = [
            layout.workspace().to_owned(),
            layout.git_view().to_owned(),
            layout.git_objects().to_owned(),
            layout.git_pointer(),
            layout.credentials(&AgentId::new("codex")),
        ];
        let after = [
            moved.workspace().to_owned(),
            moved.git_view().to_owned(),
            moved.git_objects().to_owned(),
            moved.git_pointer(),
            moved.credentials(&AgentId::new("codex")),
        ];
        assert_eq!(
            before.iter().zip(&after).filter(|(a, b)| a == b).count(),
            0,
            "a path did not move with its root: {before:?} vs {after:?}"
        );
        // Five distinct targets: a layout that mounted two things at one path
        // would hide one of them.
        let distinct: std::collections::BTreeSet<&String> = before.iter().collect();
        assert_eq!(distinct.len(), before.len(), "{before:?}");
    }

    /// The role rule is exhaustive over the five roles, and it is the packet's
    /// split rather than a predicate that happens to agree with one.
    ///
    /// The expected pairs are transcribed from INV-18 ("every agent CLI
    /// invocation **incl. agent probes** … while gates **and the shell probe**
    /// register without slots"), not computed from the function under test.
    #[test]
    fn credential_scoping_follows_inv18s_split_not_the_predicate() {
        let expected: Vec<(ExecutionRole, bool)> = vec![
            (ExecutionRole::Probe(ProbeTarget::Shell), false),
            (
                ExecutionRole::Probe(ProbeTarget::Agent(AgentId::new("claude-code"))),
                true,
            ),
            (ExecutionRole::Implement, true),
            (ExecutionRole::Gate, false),
            (ExecutionRole::Review, true),
        ];
        assert_eq!(expected.len(), ExecutionRole::all().len());
        for (role, supplies) in &expected {
            assert_eq!(supplies_credential_location(role), *supplies, "{role}");
            // And it is the same split as the slot rule, which is the sentence
            // both come from.
            assert_eq!(
                supplies_credential_location(role),
                role.is_slotted(),
                "{role}: INV-18 splits slots and credentials the same way"
            );
        }
        assert_eq!(expected.iter().filter(|(_, supplies)| *supplies).count(), 3);
    }
}
