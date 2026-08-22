//! The Runner seam (DESIGN.md §8, §20; INV-18, INV-20, INV-22, INV-23).
//!
//! > **Runner** — Execute probes, workers, gates, and reviewers on the host or
//! > in a role-scoped container; owns cwd, mounts, environment, supervision,
//! > and timeout, never agent semantics or Git. (DESIGN.md:118)
//!
//! An adapter builds a data-only [`CommandSpec`]; a [`Runner`] decides where
//! it executes. That split is the whole point of the layer: "adapters never
//! learn about containers, and the runner learns nothing about agent semantics
//! beyond which per-agent credential volume to mount" (DESIGN.md:612).
//!
//! PR4 ships the host half. [`host::HostRunner`] implements the trait, resolves
//! the `host-v1` [`policy`] for the marker, the owner record and
//! `run_started(4).runner`, composes the base-plus-overlay environment, and
//! executes the `RunnerPreflight` shell probe. The container runner is PR6 and
//! an explicit non-goal here, as are the async surface and the slot broker.
//!
//! ## Why `run` is synchronous and still shaped like the async one
//!
//! `decisions.sequential_substrate.runner`: "Runner::run(&RunnerRequest) ->
//! ProcessOutput synchronous until PR11 (then a boxed Send future)".
//! DESIGN.md:250-256 says why the shape has to survive that change: every
//! async trait used behind `dyn` returns a boxed `Send` future, so the trait
//! must already be object-safe and its request must already be a single
//! borrowed value. It is, and [`Runner`] is `Send + Sync` so a `&dyn Runner`
//! can be held across the await points PR11 introduces.

pub mod host;
pub mod invocation;
pub mod policy;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::agent::ProcessOutput;
use crate::agent::proc::SpawnHooks;
use crate::error::TactusError;
use crate::topology::effects::{
    EffectSiteId, HookHarness, HookPhase, Injection, InjectionMode, ProcessSite, SubEffectPoint,
};

pub use invocation::InvocationId;

/// What an adapter hands the runner (DESIGN.md:222).
///
/// ```text
/// struct CommandSpec { program: String, args: Vec<String>, env: Vec<(String, String)>, stdin: Vec<u8> } // env is an overlay
/// ```
///
/// Data only, and that is load-bearing rather than stylistic: it knows nothing
/// about where it will run, so the same value is executed by the host runner
/// and (PR6) by the container runner without an adapter ever learning which.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandSpec {
    /// The program to execute, as the **adapter** resolved it.
    ///
    /// Today that resolution happens on the coordinator host: an adapter's
    /// `build` and `probe` locate their CLI on this machine's `PATH` and put
    /// the absolute path here. For PR4 the machine that resolved it is also the
    /// boundary that executes it, because the host runner is the only one. A
    /// boundary with a filesystem of its own ends that, and the program has to
    /// stop being a coordinator-host path — `PR4-ADAPTER-RESOLVES-ON-THE-HOST`
    /// in `reviews/FINDINGS.md` says what breaks and owns it to PR6.
    pub program: String,
    pub args: Vec<String>,
    /// **An overlay**, not the environment. DESIGN.md:258: "`CommandSpec.env`
    /// overlays a runner-owned base rather than replacing it."
    pub env: Vec<(String, String)>,
    /// Bytes for the child's stdin. `Vec<u8>` rather than `String` because a
    /// prompt is text but a spec is a command, and the funnel writes bytes.
    pub stdin: Vec<u8>,
}

impl CommandSpec {
    /// A spec for `program` with no arguments, no overlay and no stdin.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            ..Self::default()
        }
    }

    /// Append arguments.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add one overlay entry.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set the stdin payload.
    #[must_use]
    pub fn stdin(mut self, stdin: impl Into<Vec<u8>>) -> Self {
        self.stdin = stdin.into();
        self
    }
}

/// The agent a request is bound to.
///
/// Matches [`crate::agent::AgentAdapter::id`] — `claude-code`, `copilot`,
/// `codex` — because that is the identity the credential location, the slot
/// pair and the catalog are all keyed by.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentId(String);

impl AgentId {
    /// The adapter id as its own type.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id as recorded.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a probe certifies.
///
/// The contract's `invariants_introduced[1]`: "the probe role carries target
/// `Agent(name) | Shell`". Two targets rather than one flag, because the two
/// are accounted differently and the difference is an invariant, not a
/// detail: INV-18 has "every agent CLI invocation **incl. agent probes**
/// acquires its atomic {agent, pool?} pair while gates **and the shell probe**
/// register without slots".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeTarget {
    /// One recorded agent's CLI. Slotted.
    Agent(AgentId),
    /// The recorded shell executing `exit 0`. Non-slotted.
    Shell,
}

/// Which seat a process occupies (DESIGN.md:224), with the probe target the
/// contract adds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionRole {
    Probe(ProbeTarget),
    Implement,
    Gate,
    Review,
}

impl ExecutionRole {
    /// Every role, with both probe targets.
    ///
    /// Written out rather than derived so a role added later has to be added
    /// here too, and so every grid over roles covers both probe targets — the
    /// pair whose accounting differs.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::Probe(ProbeTarget::Shell),
            Self::Probe(ProbeTarget::Agent(AgentId::new(
                crate::agent::claude::ADAPTER_ID,
            ))),
            Self::Implement,
            Self::Gate,
            Self::Review,
        ]
    }

    /// Whether this role's process takes an atomic `{agent, pool?}` slot pair.
    ///
    /// R3: "agent slot + pool slot pair (worker, review, re-ask, agent probe)
    /// … the shell probe and gates are non-slotted". PR4 records the property;
    /// the broker that acts on it is PR11.
    #[must_use]
    pub fn is_slotted(&self) -> bool {
        match self {
            Self::Probe(ProbeTarget::Agent(_)) | Self::Implement | Self::Review => true,
            Self::Probe(ProbeTarget::Shell) | Self::Gate => false,
        }
    }

    /// The role as it is written in a record: `probe(shell)`, `probe(<agent>)`,
    /// `implement`, `gate`, `review`.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Probe(ProbeTarget::Shell) => "probe(shell)".to_owned(),
            Self::Probe(ProbeTarget::Agent(agent)) => format!("probe({agent})"),
            Self::Implement => "implement".to_owned(),
            Self::Gate => "gate".to_owned(),
            Self::Review => "review".to_owned(),
        }
    }
}

impl std::fmt::Display for ExecutionRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label())
    }
}

/// One process the runner is asked to execute (DESIGN.md:223 plus the
/// contract's `invocation` field).
#[derive(Debug, Clone)]
pub struct RunnerRequest {
    pub command: CommandSpec,
    /// The child's working directory.
    pub workspace: PathBuf,
    pub role: ExecutionRole,
    pub timeout: Duration,
    /// The agent whose slot pair and credential location this process uses.
    /// `None` for a gate and for the shell probe.
    pub agent: Option<AgentId>,
    /// R4: "invocation registration (all Runner processes incl. gates, agent
    /// probes, and the shell probe)". Not optional — that is the invariant.
    pub invocation: InvocationId,
}

/// The worker process of one attempt: `ExecutionRole::Implement`, bound to the
/// agent whose CLI it is, carrying that attempt's worker identity.
///
/// One construction point per role, for the same reason
/// [`crate::agent::probe_request`] and [`host::shell_probe_request`] are one
/// each. The three fields below do not vary independently in production — the
/// role decides the slot pair (R3, [`ExecutionRole::is_slotted`]), the agent
/// binding decides which credential location `host-v1` supplies
/// ([`host::HostEnvironment::compose`]), and the identity form is the one
/// `decisions.admission_and_leases.permits.invocation_identity` gives a worker
/// — so a request that carried one without the others would be a request this
/// crate never sends. Before these existed, `HostRunner`'s own role grid
/// hand-built the worker and reviewer requests with `agent: None` and a *gate*
/// identity, which left a `HostRunner::run` that suppressed the containment
/// hooks for exactly the production shape (`role in {Implement, Review}` **and**
/// `agent.is_some()`) passing every test in the suite.
#[must_use]
pub fn worker_request(
    command: CommandSpec,
    workspace: PathBuf,
    agent: AgentId,
    timeout: Duration,
    invocation: InvocationId,
) -> RunnerRequest {
    RunnerRequest {
        command,
        workspace,
        // "`ExecutionRole::Implement` with the bound agent is what makes this
        // process slotted (R3) and what tells `host-v1` to supply that agent's
        // credential location — both properties of the role, not of the call
        // site."
        role: ExecutionRole::Implement,
        timeout,
        agent: Some(agent),
        invocation,
    }
}

/// One reviewer process: `ExecutionRole::Review`, bound to the reviewing
/// agent, carrying that pass's or re-ask's identity. See [`worker_request`].
///
/// A reviewer is an agent CLI, so it is slotted and `host-v1` gives it its
/// agent's credential location — the same rule as the worker, and the reason
/// the two share a shape rather than each being spelled out where it is sent.
#[must_use]
pub fn review_request(
    command: CommandSpec,
    workspace: PathBuf,
    agent: AgentId,
    timeout: Duration,
    invocation: InvocationId,
) -> RunnerRequest {
    RunnerRequest {
        command,
        workspace,
        role: ExecutionRole::Review,
        timeout,
        agent: Some(agent),
        invocation,
    }
}

/// One gate process: `ExecutionRole::Gate`, and **no** agent. See
/// [`worker_request`].
///
/// "A gate is repository-controlled code and runs no agent CLI, so it takes no
/// `{agent, pool}` pair (R3) and `host-v1` hands it no agent's credential
/// directory." `agent: None` is therefore part of what a gate *is*, not an
/// omission at the call site — which is why it is written once, here.
#[must_use]
pub fn gate_request(
    command: CommandSpec,
    workspace: PathBuf,
    timeout: Duration,
    invocation: InvocationId,
) -> RunnerRequest {
    RunnerRequest {
        command,
        workspace,
        role: ExecutionRole::Gate,
        timeout,
        agent: None,
        invocation,
    }
}

/// DESIGN.md:227.
///
/// Object-safe, and `Send + Sync` so PR11 can turn `run` into a boxed `Send`
/// future behind the same `&dyn Runner` its callers already hold.
pub trait Runner: Send + Sync {
    /// Execute `request` and return what the process did.
    ///
    /// # Errors
    ///
    /// A pre-flight refusal (a reserved environment key in the overlay, a
    /// failing shell probe) or a spawn/supervision failure. A non-zero exit is
    /// not an error: it is a [`ProcessOutput`].
    fn run(&self, request: &RunnerRequest) -> Result<ProcessOutput, TactusError>;
}

// ---------------------------------------------------------------------------
// ST-07 evidence: the containment sub-effect points
// ---------------------------------------------------------------------------

/// The site every containment sub-effect point belongs to.
pub const SPAWN_SITE: EffectSiteId = EffectSiteId::Process(ProcessSite::Spawn);

/// Wires the process funnel's [`SpawnHooks`] onto PR3's [`HookHarness`].
///
/// The funnel names a point; the harness is keyed by `(site, point, mode)`,
/// because a mode is executed when its fault *fired* rather than when a funnel
/// walked past the place it would have fired. So one funnel call consults the
/// harness once per mode the point declares, and the first non-`Proceed`
/// answer wins. A point with one mode is consulted once; `AmbientJobJoined`,
/// the only containment point the packet gives an error contract
/// (`containment_sub_effects`: "failure refuses the write command"), is
/// consulted for both.
#[derive(Debug, Clone, Default)]
pub struct HarnessHooks {
    harness: Arc<Mutex<HookHarness>>,
}

impl HarnessHooks {
    /// Observe through `harness`.
    #[must_use]
    pub fn new(harness: Arc<Mutex<HookHarness>>) -> Self {
        Self { harness }
    }

    /// The harness this observer records into.
    #[must_use]
    pub fn harness(&self) -> &Arc<Mutex<HookHarness>> {
        &self.harness
    }
}

impl SpawnHooks for HarnessHooks {
    fn point(&mut self, point: SubEffectPoint) -> Injection {
        let mut decision = Injection::Proceed;
        for mode in point.modes() {
            let answer = self.point_mode(point, *mode);
            if decision == Injection::Proceed {
                decision = answer;
            }
        }
        decision
    }

    /// One mode, at the coordinate that mode belongs at. A funnel that fires a
    /// point's two modes at two coordinates calls this twice, once each; the
    /// harness is keyed by `(site, point, mode)`, so each lands on its own key.
    fn point_mode(&mut self, point: SubEffectPoint, mode: InjectionMode) -> Injection {
        let mut harness = self
            .harness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        harness.hook(SPAWN_SITE, HookPhase::Point { point, mode })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::invocation::{AttemptRole, SequenceRole};
    use crate::topology::events::{AttemptNumber, GenerationId, SequenceId};
    use crate::topology::registry::TaskKey;

    #[test]
    fn command_spec_carries_exactly_the_four_frozen_fields() {
        let spec = CommandSpec::new("claude")
            .arg("-p")
            .env("CLAUDE_CODE_MAX_OUTPUT_TOKENS", "8000")
            .stdin(b"prompt".to_vec());
        assert_eq!(spec.program, "claude");
        assert_eq!(spec.args, vec!["-p".to_owned()]);
        assert_eq!(
            spec.env,
            vec![(
                "CLAUDE_CODE_MAX_OUTPUT_TOKENS".to_owned(),
                "8000".to_owned()
            )]
        );
        assert_eq!(spec.stdin, b"prompt".to_vec());
    }

    /// The slotting split is R3's sentence, transcribed here rather than
    /// computed from the function under test.
    #[test]
    fn slotting_follows_r3_not_the_predicate() {
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
        assert_eq!(
            expected.len(),
            ExecutionRole::all().len(),
            "every role in the grid, and no more"
        );
        for (role, slotted) in expected {
            assert_eq!(role.is_slotted(), slotted, "R3 for {role}");
        }
    }

    /// Each role builder produces its role, its binding and nothing else's,
    /// and carries the spec and the identity through untouched.
    ///
    /// The builders are what every fixture and every call site now asks for, so
    /// a builder that named the wrong role — or bound an agent to a gate —
    /// would be wrong everywhere at once and invisible in a grid keyed on the
    /// same builders. The expected values here are written from R3 and from
    /// each role's own sentence, not read back out of the builder.
    #[test]
    fn each_role_builder_binds_what_its_role_binds() {
        let spec = CommandSpec::new("prog")
            .arg("--go")
            .env("TACTUS_OVERLAY", "1")
            .stdin(b"payload".to_vec());
        let workspace = PathBuf::from("/tmp/ws");
        let agent = AgentId::new("claude-code");
        let timeout = Duration::from_secs(11);
        let worker_id = InvocationId::attempt(
            TaskKey(1),
            GenerationId(0),
            AttemptNumber(2),
            AttemptRole::Worker,
            0,
        );
        let review_id = InvocationId::attempt(
            TaskKey(1),
            GenerationId(0),
            AttemptNumber(2),
            AttemptRole::ReviewPass(0),
            0,
        );
        let gate_id = InvocationId::attempt(
            TaskKey(1),
            GenerationId(0),
            AttemptNumber(2),
            AttemptRole::Gate(3),
            0,
        );

        let built = vec![
            (
                worker_request(
                    spec.clone(),
                    workspace.clone(),
                    agent.clone(),
                    timeout,
                    worker_id.clone(),
                ),
                ExecutionRole::Implement,
                Some(agent.clone()),
                worker_id,
            ),
            (
                review_request(
                    spec.clone(),
                    workspace.clone(),
                    agent.clone(),
                    timeout,
                    review_id.clone(),
                ),
                ExecutionRole::Review,
                Some(agent),
                review_id,
            ),
            (
                gate_request(spec.clone(), workspace.clone(), timeout, gate_id.clone()),
                ExecutionRole::Gate,
                None,
                gate_id,
            ),
        ];
        assert_eq!(built.len(), 3, "the three in-attempt roles");

        for (request, role, agent, invocation) in &built {
            assert_eq!(&request.role, role);
            assert_eq!(&request.agent, agent, "{role}: the binding R3 gives it");
            assert_eq!(
                request.agent.is_some(),
                request.role.is_slotted(),
                "{role}: the binding and the slot pair are the same fact"
            );
            assert_eq!(&request.invocation, invocation, "{role}: the identity");
            // The spec is carried, not rebuilt: an overlay or a stdin payload
            // dropped here would be dropped for every caller at once.
            assert_eq!(request.command, spec, "{role}: the command spec");
            assert_eq!(request.workspace, workspace, "{role}");
            assert_eq!(request.timeout, timeout, "{role}");
        }
        // Three builders, three distinct roles, and two of the three bind.
        let roles: std::collections::BTreeSet<String> = built
            .iter()
            .map(|(request, _, _, _)| request.role.label())
            .collect();
        assert_eq!(roles.len(), 3);
        assert_eq!(
            built
                .iter()
                .filter(|(request, _, _, _)| request.agent.is_some())
                .count(),
            2
        );
    }

    #[test]
    fn role_labels_name_the_probe_target() {
        assert_eq!(
            ExecutionRole::Probe(ProbeTarget::Shell).label(),
            "probe(shell)"
        );
        assert_eq!(
            ExecutionRole::Probe(ProbeTarget::Agent(AgentId::new("codex"))).label(),
            "probe(codex)"
        );
        assert_eq!(ExecutionRole::Implement.label(), "implement");
        assert_eq!(ExecutionRole::Gate.label(), "gate");
        assert_eq!(ExecutionRole::Review.label(), "review");
        // Two probe targets never render the same, or a record could not tell
        // a slotted probe from a non-slotted one.
        let labels: std::collections::BTreeSet<String> = ExecutionRole::all()
            .iter()
            .map(ExecutionRole::label)
            .collect();
        assert_eq!(labels.len(), ExecutionRole::all().len());
    }

    #[test]
    fn the_runner_trait_is_object_safe() {
        // PR11 turns `run` into a boxed Send future behind this same `dyn`.
        // A trait that stopped being object-safe would fail to compile here
        // rather than at the migration.
        fn takes_dyn(_: &dyn Runner) {}
        let runner = host::HostRunner::new();
        takes_dyn(&runner);
        let boxed: Box<dyn Runner> = Box::new(host::HostRunner::new());
        takes_dyn(boxed.as_ref());
    }

    /// Proof test: "InvocationId uniqueness within a run incl. agent and
    /// shell probes".
    ///
    /// Uniqueness is **structural**, not statistical. The identities of a run
    /// are the tuples the packet enumerates, and distinct tuples render
    /// distinctly (`invocation::tests::distinct_tuples_render_distinctly`
    /// crosses every field). So what this proves is the other half: that the
    /// set of identities a whole run's worth of Runner processes carries —
    /// INV-20's "worker, gate, review, re-ask, agent probe, shell probe" — is
    /// exactly one per process, with no expected value taken from a generator.
    #[test]
    fn invocation_ids_are_unique_within_a_run_incl_agent_and_shell_probes() {
        const TASKS: u32 = 7;
        const ATTEMPTS: u32 = 3;
        const GATES: u32 = 4;
        const SEQUENCES: u32 = 2;
        const AGENTS: [&str; 3] = ["claude-code", "copilot", "codex"];

        /// One run's Runner processes, in the order the run would produce
        /// them. A function rather than a literal because it is called twice:
        /// a run whose identities are not a function of the run is a run whose
        /// identities are not deterministic.
        fn run_requests() -> Vec<RunnerRequest> {
            let mut requests: Vec<RunnerRequest> = Vec::new();
            let mut push = |role: ExecutionRole, agent: Option<AgentId>, invocation| {
                requests.push(RunnerRequest {
                    command: CommandSpec::new("prog"),
                    workspace: PathBuf::from("/tmp"),
                    role,
                    timeout: Duration::from_secs(1),
                    agent,
                    invocation,
                });
            };

            // Pre-flight (INV-23's RunnerPreflight): one non-slotted shell
            // probe and one slotted probe per recorded agent. The packet's
            // third form, "(probe, target: Agent(name) | Shell, ordinal)".
            push(
                ExecutionRole::Probe(ProbeTarget::Shell),
                None,
                InvocationId::probe(ProbeTarget::Shell, 0).expect("shell probe identity"),
            );
            for agent in AGENTS {
                let id = AgentId::new(agent);
                push(
                    ExecutionRole::Probe(ProbeTarget::Agent(id.clone())),
                    Some(id.clone()),
                    InvocationId::probe(ProbeTarget::Agent(id), 0).expect("agent probe identity"),
                );
            }
            // The run: every attempt of every task, its gates, and its review
            // pass — the packet's first form, "(key, generation, attempt,
            // role, ordinal)".
            for task in 0..TASKS {
                for attempt in 1..=ATTEMPTS {
                    let agent = AgentId::new(AGENTS[((task + attempt) % 3) as usize]);
                    let key = TaskKey(task);
                    let generation = GenerationId(0);
                    let attempt_no = AttemptNumber(attempt);
                    push(
                        ExecutionRole::Implement,
                        Some(agent.clone()),
                        InvocationId::attempt(key, generation, attempt_no, AttemptRole::Worker, 0),
                    );
                    for gate in 0..GATES {
                        push(
                            ExecutionRole::Gate,
                            None,
                            InvocationId::attempt(
                                key,
                                generation,
                                attempt_no,
                                AttemptRole::Gate(gate),
                                0,
                            ),
                        );
                    }
                    push(
                        ExecutionRole::Review,
                        Some(agent),
                        InvocationId::attempt(
                            key,
                            generation,
                            attempt_no,
                            AttemptRole::ReviewPass(0),
                            0,
                        ),
                    );
                }
            }
            // Integration transactions — the packet's second form,
            // "(sequence, role, ordinal)", whose roles exclude worker.
            for sequence in 0..SEQUENCES {
                push(
                    ExecutionRole::Gate,
                    None,
                    InvocationId::sequence(SequenceId(sequence), SequenceRole::Gate(0), 0),
                );
                push(
                    ExecutionRole::Review,
                    // A reviewer is an agent CLI in this form too, so it
                    // carries its agent. A grid whose sequence reviews bound
                    // no agent would be varying the role and the binding
                    // together and calling it one field.
                    Some(AgentId::new(AGENTS[(sequence % 3) as usize])),
                    InvocationId::sequence(SequenceId(sequence), SequenceRole::ReviewPass(0), 0),
                );
            }
            requests
        }

        let requests = run_requests();
        // The size comes from the run's shape, written here, not from the
        // vector under test.
        let expected = 1
            + AGENTS.len()
            + (TASKS * ATTEMPTS * (1 + GATES + 1)) as usize
            + (SEQUENCES * 2) as usize;
        assert_eq!(requests.len(), expected, "the grid is the size it claims");
        assert_eq!(expected, 134, "a run's worth of processes, not a handful");

        let ids: std::collections::BTreeSet<String> = requests
            .iter()
            .map(|request| request.invocation.render())
            .collect();
        assert_eq!(
            ids.len(),
            requests.len(),
            "two Runner processes of one run share an InvocationId"
        );
        // All three forms are in the set, and each is in it the number of times
        // the run's shape says.
        let counted = |prefix: &str| ids.iter().filter(|id| id.starts_with(prefix)).count();
        assert_eq!(counted("p."), 1 + AGENTS.len(), "the pre-flight probes");
        assert_eq!(
            counted("k"),
            (TASKS * ATTEMPTS * (1 + GATES + 1)) as usize,
            "the attempt form"
        );
        assert_eq!(counted("s"), (SEQUENCES * 2) as usize, "the sequence form");

        // The binding is R3's rule in every form, and it is a count rather
        // than a claim: a grid that let the agent binding ride along with the
        // role would prove the identities of a run this crate never executes.
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.agent.is_some() != request.role.is_slotted())
                .count(),
            0,
            "a request bound an agent to a non-slotted role, or left a slotted one unbound"
        );
        let bound = requests
            .iter()
            .filter(|request| request.agent.is_some())
            .count();
        assert_eq!(
            bound,
            AGENTS.len() + (TASKS * ATTEMPTS * 2) as usize + SEQUENCES as usize,
            "the agent probes, every worker and reviewer of every attempt, and the sequence \
             reviews — counted"
        );
        assert_eq!(
            requests.len() - bound,
            1 + (TASKS * ATTEMPTS * GATES) as usize + SEQUENCES as usize,
            "the shell probe and every gate — counted"
        );

        // Deterministic in the sequential substrate: the same run yields the
        // same identities. A generator that mints a fresh value per call — a
        // ULID, a counter, a clock — fails here, and this is the assertion
        // `crash_reconstruction` rests on when it builds a container name
        // "so deterministic InvocationIds never collide across incarnations
        // and no earlier ownership evidence is overwritten".
        let again: Vec<String> = run_requests()
            .iter()
            .map(|request| request.invocation.render())
            .collect();
        let first: Vec<String> = requests
            .iter()
            .map(|request| request.invocation.render())
            .collect();
        assert_eq!(
            first, again,
            "the run's identities are not a function of the run"
        );

        // The probes are in the set, and they are accounted the way INV-18
        // accounts them: agent probes slotted, the shell probe not.
        let probes: Vec<&RunnerRequest> = requests
            .iter()
            .filter(|request| matches!(request.role, ExecutionRole::Probe(_)))
            .collect();
        assert_eq!(probes.len(), 1 + AGENTS.len());
        assert_eq!(
            probes.iter().filter(|p| p.role.is_slotted()).count(),
            AGENTS.len(),
            "agent probes are slotted"
        );
        assert_eq!(
            probes.iter().filter(|p| !p.role.is_slotted()).count(),
            1,
            "the shell probe is not"
        );
        assert_eq!(
            probes
                .iter()
                .filter(|p| p.invocation.probe_target().is_some())
                .count(),
            probes.len(),
            "every probe request carries a probe identity"
        );

        // "changes with every attempt": the same task, agent and role at two
        // attempts are two invocations, and they differ in the attempt field
        // rather than by chance.
        let workers: Vec<&InvocationId> = requests
            .iter()
            .filter(|request| request.role == ExecutionRole::Implement)
            .map(|request| &request.invocation)
            .collect();
        assert_eq!(workers.len(), (TASKS * ATTEMPTS) as usize);
        assert_eq!(
            workers
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            workers.len()
        );
        let first_task: Vec<String> = workers
            .iter()
            .filter(|id| matches!(id, InvocationId::Attempt { key, .. } if *key == TaskKey(0)))
            .map(|id| id.render())
            .collect();
        assert_eq!(
            first_task,
            vec![
                "k0.g0.a1.worker.o0".to_owned(),
                "k0.g0.a2.worker.o0".to_owned(),
                "k0.g0.a3.worker.o0".to_owned(),
            ],
            "a retry attempt has a new attempt number"
        );
    }

    /// Every place production code starts a process, named and counted.
    ///
    /// `decisions.pr_sequence[5].slice_contract.invariants_introduced[0]`:
    /// "**every** CLI and gate process executes through Runner", and
    /// `gating`: "process funnel sites recorded". Recorded as a table with
    /// counts rather than as prose, because the failure mode is a *new* spawn
    /// appearing somewhere with nobody deciding whether it should have been
    /// routed. A file that grows one fails here until it is classified.
    ///
    /// What is scanned: `Command::new`, `.spawn()` and `run_with_timeout` in
    /// the production region of every `src/**/*.rs`. The production region is
    /// the file with every `#[cfg(test)] mod … { … }` block removed by brace
    /// matching at the module's own indentation — sound because
    /// `cargo fmt --check` is a gate, so a module's closing brace is the first
    /// line at exactly that indentation. `src/engine/tests.rs` is a whole test
    /// module (`engine/mod.rs`: `#[cfg(test)] mod tests;`) and is excluded as
    /// one.
    ///
    /// The three rows are the only production process starts in the tree, and
    /// each is classified against the passage that puts it there.
    /// One row of the parity obligation: what a runner was asked to run, and
    /// what the adapter made of what came back.
    #[derive(Debug, Clone, PartialEq)]
    pub(crate) struct ParsedRow {
        pub(crate) name: &'static str,
        pub(crate) adapter: &'static str,
        pub(crate) status: crate::ir::OutcomeStatus,
        pub(crate) detail: Option<String>,
        pub(crate) session: Option<String>,
        pub(crate) cost_usd: Option<f64>,
    }

    /// The adapter-parsing half of `decisions.tests_acceptance.parity`, as a
    /// function of the boundary.
    ///
    /// > host and container runners produce identical **adapter parsing** and
    /// > environment composition
    ///
    /// PR6 calls this with its container runner and compares the returned
    /// table against the host's, which is what "dropped in beside it" means:
    /// the fixtures, the specs and the expectations live here once, and the
    /// only thing that varies between the two runs is the `&dyn Runner`.
    ///
    /// It is a real chain rather than a stub — spec → runner → `ProcessOutput`
    /// → `AgentAdapter::parse` — because the claim is about the *seam*: an
    /// adapter never learns which runner produced the output it reads, and
    /// nothing but a runner actually producing it proves that.
    ///
    /// The child is the recorded shell echoing an environment variable, so the
    /// fixtures need no agent CLI and no writable scratch file, and no payload
    /// byte ever reaches a command line. The payload and the exit code ride in
    /// on `CommandSpec.env` — the overlay, which is therefore load-bearing
    /// here rather than decorative, and which is itself half of what the
    /// parity clause is about.
    pub(crate) fn adapter_parse_parity(
        runner: &dyn Runner,
        workspace: &std::path::Path,
    ) -> Vec<ParsedRow> {
        struct Fixture {
            name: &'static str,
            adapter: &'static str,
            payload: &'static str,
            code: i32,
        }

        // Two adapters with two different answer shapes (a JSON envelope and
        // plain text) and both exit dispositions: a parity table whose rows
        // all parse the same way would prove two runners agree about nothing.
        const FIXTURES: &[Fixture] = &[
            Fixture {
                name: "json envelope, exit 0",
                adapter: crate::agent::claude::ADAPTER_ID,
                payload: r#"{"session_id":"s-parity","total_cost_usd":0.5,"result":"the work is done","subtype":"success"}"#,
                code: 0,
            },
            Fixture {
                name: "json envelope, non-zero exit",
                adapter: crate::agent::claude::ADAPTER_ID,
                payload: r#"{"session_id":"s-parity","total_cost_usd":0.5,"result":"the work is done","subtype":"success"}"#,
                code: 3,
            },
            Fixture {
                name: "plain text, exit 0",
                adapter: crate::agent::copilot::ADAPTER_ID,
                payload: "wrote the encoder",
                code: 0,
            },
        ];

        /// Echo `$TACTUS_PARITY_PAYLOAD` and exit `code`, in the recorded
        /// shell's own dialect. The payload is never in the command line, so
        /// nothing here depends on either shell's quoting.
        fn script(code: i32) -> String {
            if cfg!(windows) {
                format!("echo %TACTUS_PARITY_PAYLOAD%& exit {code}")
            } else {
                format!("printf '%s\\n' \"$TACTUS_PARITY_PAYLOAD\"; exit {code}")
            }
        }

        FIXTURES
            .iter()
            .enumerate()
            .map(|(index, fixture)| {
                let adapter = crate::agent::by_id(fixture.adapter).expect("a shipped adapter");
                let command = crate::gates::ShellKind::native()
                    .spec(&script(fixture.code))
                    .env("TACTUS_PARITY_PAYLOAD", fixture.payload);
                let output = runner
                    .run(&RunnerRequest {
                        command,
                        workspace: workspace.to_path_buf(),
                        role: ExecutionRole::Implement,
                        timeout: Duration::from_secs(60),
                        agent: Some(AgentId::new(fixture.adapter)),
                        invocation: InvocationId::attempt(
                            TaskKey(0),
                            GenerationId(0),
                            AttemptNumber(1),
                            AttemptRole::Worker,
                            u32::try_from(index).unwrap_or(u32::MAX),
                        ),
                    })
                    .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
                let outcome = adapter
                    .parse(&output)
                    .unwrap_or_else(|error| panic!("{}: parse: {error}", fixture.name));
                ParsedRow {
                    name: fixture.name,
                    adapter: fixture.adapter,
                    status: outcome.status,
                    detail: outcome.detail,
                    session: outcome.session_id,
                    cost_usd: outcome.cost_usd,
                }
            })
            .collect()
    }

    /// The host side of the parity table, pinned.
    ///
    /// The expected rows are written from what each adapter's `parse`
    /// documents — a JSON envelope with `is_error` absent and exit 0 is
    /// `Completed` carrying `result`, its session and its cost; the same
    /// envelope after a non-zero exit is an `AgentError`; and Copilot has no
    /// envelope at all, so it reports no session and no cost even on success.
    /// None of them is read back from `parse`.
    #[test]
    fn the_host_runners_adapter_parsing_table_is_the_one_pr6_must_match() {
        let workspace = std::env::temp_dir();
        let rows = adapter_parse_parity(&host::HostRunner::new(), &workspace);
        use crate::ir::OutcomeStatus;
        assert_eq!(
            rows,
            vec![
                ParsedRow {
                    name: "json envelope, exit 0",
                    adapter: "claude-code",
                    status: OutcomeStatus::Completed,
                    detail: Some("the work is done".to_owned()),
                    session: Some("s-parity".to_owned()),
                    cost_usd: Some(0.5),
                },
                ParsedRow {
                    name: "json envelope, non-zero exit",
                    adapter: "claude-code",
                    status: OutcomeStatus::AgentError,
                    // The failure path reports the agent's own text, and the
                    // envelope's session and cost survive it: spend already
                    // happened.
                    detail: Some("the work is done".to_owned()),
                    session: Some("s-parity".to_owned()),
                    cost_usd: Some(0.5),
                },
                ParsedRow {
                    name: "plain text, exit 0",
                    adapter: "copilot",
                    status: OutcomeStatus::Completed,
                    detail: Some("wrote the encoder".to_owned()),
                    session: None,
                    cost_usd: None,
                },
            ],
            "the host runner's adapter parsing moved"
        );
        // Hostility as counts: two adapters, two statuses, three distinct
        // details, and both "reports a session" dispositions.
        let mut statuses: Vec<String> =
            rows.iter().map(|row| format!("{:?}", row.status)).collect();
        statuses.sort();
        statuses.dedup();
        assert_eq!(statuses.len(), 2);
        let adapters: std::collections::BTreeSet<_> = rows.iter().map(|row| row.adapter).collect();
        assert_eq!(adapters.len(), 2);
        assert_eq!(rows.iter().filter(|row| row.session.is_some()).count(), 2);
        assert_eq!(rows.iter().filter(|row| row.cost_usd.is_some()).count(), 2);
    }

    /// Every spawn this slice performs is filed under **one** site, and that
    /// site declares one adjacent event, one fault row and one observable
    /// order.
    ///
    /// `decisions.effect_site_inventory.identity` says each group's "variants
    /// are its semantic contexts", and every variant carries "its adjacent
    /// durable event … [and] its fault-matrix row id". PR3's `Process` group
    /// has two variants — `Spawn` and `Terminate` — and `Spawn` is
    /// `After(AttemptStarted)` / `T-ATTEMPT`. PR4 routes five roles through
    /// it, and two of them do not run inside an attempt at all: the shell
    /// probe and the agent probes are `RunnerPreflight`, which
    /// `workspace_candidates.run_creation` orders at **P4**, before P6's
    /// `run_started`. A crash prefix at a probe spawn is therefore
    /// effect-before-`run_started` (T-RUNSTART on a fresh run, T-RESUME on a
    /// resume) while the site it is recorded under says event-before-effect in
    /// T-ATTEMPT.
    ///
    /// **The site's own variants are not this slice's to add.** The site enum,
    /// its adjacency and its fault row are `src/topology/effects.rs` — PR3's,
    /// frozen here — and a probe context would be a *new variant* of an
    /// inventory the packet enumerates. That half is deferred, with an owner,
    /// in `reviews/FINDINGS.md`. What this test contributes is that the
    /// mismatch is counted rather than silent: the two roles are named here,
    /// so ST-07 evidence over `Process.Spawn` cannot be read as covering the
    /// probe prefixes.
    ///
    /// **This count discharges nothing about the hooks themselves, and must
    /// not be read as if it did.** Counting that two roles fall outside the
    /// site's declared context proves the mismatch exists; it does not prove
    /// the containment hooks execute on those roles, and a `HostRunner::run`
    /// that passed `NoHooks` for `Probe(_)` would leave this test green. That
    /// obligation is PR4's — `scope`'s "**probes**, workers, gates, reviews go
    /// through the Runner" and `proof_tests[3]`'s "containment sub-effect hook
    /// tests (ST-07 subset)" — and it is discharged at runtime, for all five
    /// roles, by `host::tests::every_role_reaches_the_containment_points_of_this_platform`
    /// and `host::tests::a_fault_armed_at_any_containment_point_stops_any_role`.
    #[test]
    fn the_spawn_site_files_every_role_under_one_context_and_the_count_says_which() {
        use crate::topology::effects::{Adjacent, DurableEvent, FaultRow, ObservableOrder};

        // Transcribed from PR3's inventory, not read back from PR4.
        assert_eq!(SPAWN_SITE, EffectSiteId::Process(ProcessSite::Spawn));
        assert_eq!(
            SPAWN_SITE.adjacent(),
            Adjacent::After(DurableEvent::AttemptStarted)
        );
        assert_eq!(SPAWN_SITE.fault_row(), FaultRow::TAttempt);
        assert_eq!(
            SPAWN_SITE.observable_orders(),
            &[ObservableOrder::EventBeforeEffect],
            "one order, which is why `A3-REG-001`'s order-free key stays \
             equivalent for this site rather than becoming live debt here"
        );

        // Which roles this slice spawns, and whether each runs inside an
        // attempt — i.e. after the durable event the site is adjacent to.
        // Written from the packet's own ordering of a run's phases.
        let roles: Vec<(ExecutionRole, bool)> = vec![
            (ExecutionRole::Implement, true),
            (ExecutionRole::Gate, true),
            (ExecutionRole::Review, true),
            (ExecutionRole::Probe(ProbeTarget::Shell), false),
            (
                ExecutionRole::Probe(ProbeTarget::Agent(AgentId::new("claude-code"))),
                false,
            ),
        ];
        assert_eq!(
            roles.len(),
            ExecutionRole::all().len(),
            "every role this slice routes is classified here"
        );
        let outside: Vec<String> = roles
            .iter()
            .filter(|(_, inside)| !*inside)
            .map(|(role, _)| role.label())
            .collect();
        assert_eq!(
            outside,
            vec!["probe(shell)".to_owned(), "probe(claude-code)".to_owned()],
            "the pre-flight roles, whose spawns precede `run_started` and are \
             nevertheless recorded under a site adjacent to `attempt_started`"
        );
        assert_eq!(
            outside.len(),
            2,
            "two of the five roles spawn outside the context this site names — \
             counted so the boundary cannot grow in silence"
        );
    }

    /// The eight containment coordinates, pinned as literals.
    ///
    /// `containment_sub_effects` writes them out — "Spawn.AmbientJobJoined …,
    /// Spawn.CreatedSuspended …, Spawn.PrivateJobAssigned, Spawn.Resumed …;
    /// Unix: Spawn.ReaperStarted …, Spawn.PreExecPgidAndRegister, Spawn.Exec,
    /// Spawn.Registered" — and every check the suite made on that vocabulary
    /// was derived from the enum it is meant to pin: the generated registry,
    /// the `Display` impl and the serde round trip all read `SubEffectPoint`,
    /// so renaming a variant *and* its `name()` arm together left all of them
    /// agreeing on the new spelling and the suite green. The literal
    /// `Spawn.CreatedSuspended` existed in this tree only inside doc comments.
    ///
    /// This is the project's own upheld line — a suite that "compares its own
    /// serialization only against itself" has not pinned anything — applied
    /// where the packet freezes the spelling in prose. The enum is PR3's and
    /// frozen; the assertion is PR4's, because PR4 is the slice that made these
    /// eight coordinates load-bearing.
    ///
    /// Two spellings, because there are two: the coordinate the packet writes
    /// (from `name()`) and the wire form the enum serialises to (from
    /// `rename_all = "snake_case"`). Naming the Rust variant in the same row is
    /// deliberate — a rename of the variant itself stops this table compiling,
    /// which is the same failure by a shorter route.
    #[test]
    fn the_containment_coordinates_are_pinned_against_written_literals() {
        use crate::topology::effects::ProcessSite;

        // (variant, the coordinate `containment_sub_effects` writes, wire form)
        const PINNED: &[(SubEffectPoint, &str, &str)] = &[
            (
                SubEffectPoint::AmbientJobJoined,
                "Spawn.AmbientJobJoined",
                "\"ambient_job_joined\"",
            ),
            (
                SubEffectPoint::CreatedSuspended,
                "Spawn.CreatedSuspended",
                "\"created_suspended\"",
            ),
            (
                SubEffectPoint::PrivateJobAssigned,
                "Spawn.PrivateJobAssigned",
                "\"private_job_assigned\"",
            ),
            (SubEffectPoint::Resumed, "Spawn.Resumed", "\"resumed\""),
            (
                SubEffectPoint::ReaperStarted,
                "Spawn.ReaperStarted",
                "\"reaper_started\"",
            ),
            (
                SubEffectPoint::PreExecPgidAndRegister,
                "Spawn.PreExecPgidAndRegister",
                "\"pre_exec_pgid_and_register\"",
            ),
            (SubEffectPoint::Exec, "Spawn.Exec", "\"exec\""),
            (
                SubEffectPoint::Registered,
                "Spawn.Registered",
                "\"registered\"",
            ),
        ];

        let declared: std::collections::BTreeSet<SubEffectPoint> =
            SPAWN_SITE.sub_effects().iter().copied().collect();
        let pinned: std::collections::BTreeSet<SubEffectPoint> =
            PINNED.iter().map(|(point, _, _)| *point).collect();
        assert_eq!(
            pinned, declared,
            "the site declares a containment point this table does not pin"
        );
        assert_eq!(PINNED.len(), 8);

        for (point, coordinate, wire) in PINNED {
            assert_eq!(
                format!("{}.{}", ProcessSite::Spawn.name(), point.name()),
                *coordinate,
                "the coordinate the packet writes moved"
            );
            assert_eq!(
                serde_json::to_string(point).expect("encode a containment point"),
                *wire,
                "the wire form of {coordinate} moved"
            );
            // And the written literal decodes back to this point: a rename that
            // kept the encoder and the decoder agreeing would otherwise be
            // invisible from this direction too.
            let decoded: SubEffectPoint =
                serde_json::from_str(wire).expect("decode the written literal");
            assert_eq!(decoded, *point, "{coordinate} no longer accepts {wire}");
        }
    }

    /// The file minus every `#[cfg(test)] mod … { … }` block.
    ///
    /// Sound because `cargo fmt --check` is a gate, so a module's closing brace
    /// is the first line at exactly the module's own indentation.
    /// `src/engine/tests.rs` is a whole test module (`engine/mod.rs`:
    /// `#[cfg(test)] mod tests;`) and is excluded as one by every caller.
    fn production_region(source: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        let mut kept = String::new();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            let is_test_mod = line.trim() == "#[cfg(test)]"
                && lines
                    .get(index + 1)
                    .is_some_and(|next| next.trim_start().starts_with("mod "));
            if !is_test_mod {
                kept.push_str(line);
                kept.push('\n');
                index += 1;
                continue;
            }
            let header = lines[index + 1];
            let indent = &header[..header.len() - header.trim_start().len()];
            let closing = format!("{indent}}}");
            index += 2;
            while index < lines.len() && lines[index] != closing {
                index += 1;
            }
            index += 1;
        }
        kept
    }

    /// Every source file the crate declares as `#[cfg(test)] mod <name>;`.
    ///
    /// Such a file is test code end to end, and [`production_region`] — which
    /// cuts a file at its first *inline* `#[cfg(test)]` — has nothing to cut in
    /// one, so it would count the whole of it as production. The set is read
    /// out of the declarations rather than listed by hand: it was
    /// `src/engine/tests.rs` alone until PR5 moved the Event funnel into
    /// `src/events/log.rs` with two test modules of its own, and the census
    /// failed on the first file the hand-maintained list did not know about.
    fn whole_file_test_modules(files: &[PathBuf]) -> std::collections::BTreeSet<PathBuf> {
        files
            .iter()
            .flat_map(|path| {
                let source = std::fs::read_to_string(path).expect("read source");
                let parent = path.parent().expect("a source file has a directory");
                let stem = path.file_stem().expect("a source file has a name");
                let dir = if stem == "mod" || stem == "lib" || stem == "main" {
                    parent.to_path_buf()
                } else {
                    parent.join(stem)
                };
                source
                    .split("#[cfg(test)]")
                    .skip(1)
                    .filter_map(|rest| {
                        let name = rest.trim_start().strip_prefix("mod ")?;
                        let name = name.split(';').next()?.trim();
                        (!name.is_empty() && !name.contains('{')).then(|| {
                            [
                                dir.join(format!("{name}.rs")),
                                dir.join(name).join("mod.rs"),
                            ]
                        })
                    })
                    .flatten()
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Every `src/**/*.rs`, as `(repo-relative path, production region)`, with
    /// whole-file test modules left out.
    fn production_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, into: &mut Vec<PathBuf>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .expect("read src")
                .map(|entry| entry.expect("entry").path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    walk(&path, into);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    into.push(path);
                }
            }
        }

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        walk(&root.join("src"), &mut files);
        assert!(files.len() > 20, "the walk found the tree: {}", files.len());
        let test_modules = whole_file_test_modules(&files);
        // The control: a derivation that found nothing would silently count
        // every test file as production, which is the failure this replaces.
        assert!(
            test_modules.contains(&root.join("src").join("engine").join("tests.rs")),
            "the `#[cfg(test)] mod tests;` derivation found no engine test module: {test_modules:?}"
        );
        files
            .into_iter()
            .filter_map(|path| {
                if test_modules.contains(&path) {
                    return None;
                }
                let relative = path
                    .strip_prefix(&root)
                    .expect("under the manifest")
                    .to_string_lossy()
                    .replace('\\', "/");
                let source = std::fs::read_to_string(&path).expect("read source");
                Some((relative, production_region(&source)))
            })
            .collect()
    }

    /// Every `RunnerRequest` production builds is built by the builder for its
    /// role, and there are five roles and five builders.
    ///
    /// `scope`: "probes, workers, gates, reviews go through the Runner", and
    /// each of those four words is a role whose request carries three fields
    /// that travel together — the role, the agent binding (R3's slot pair,
    /// `host-v1`'s credential location) and the identity form. A request
    /// assembled at a call site can get one of them wrong; a request assembled
    /// by the role's builder cannot, and a *test* that assembles its own is
    /// how PR4 came to prove containment for a shape production never sends.
    ///
    /// So the census is on the construction, not on the shape: one
    /// `role: ExecutionRole::` per builder in the production region of the
    /// tree, and no others anywhere. A new hand-built request — in production
    /// or in a fixture that copied one — shows up here as a row that has to be
    /// classified.
    ///
    /// **Two needles, because one of them can be dodged.** A literal written
    /// with field shorthand (`RunnerRequest { command, workspace, role, … }`)
    /// names no variant and would slip past the first needle entirely — the
    /// grid in this very file writes one that way. So the type's own name is
    /// counted beside it, and that count includes the declaration and the
    /// builders' return types, which is why the numbers are what they are.
    #[test]
    fn every_production_runner_request_is_built_by_its_roles_builder() {
        use std::collections::BTreeMap;

        /// (file, `role: ExecutionRole::`, `RunnerRequest {`, and what they are).
        const EXPECTED: &[(&str, usize, usize, &str)] = &[
            (
                "src/agent/mod.rs",
                1,
                1,
                "probe_request: the agent probe, slotted and bound to the \
                 adapter it certifies",
            ),
            (
                "src/runner/host.rs",
                1,
                2,
                "shell_probe_request: the RunnerPreflight shell probe, \
                 non-slotted and bound to no agent — its literal, and the \
                 return type above it",
            ),
            (
                "src/runner/mod.rs",
                3,
                7,
                "worker_request, review_request, gate_request: the three \
                 in-attempt roles, where the binding is R3's rule rather than \
                 the call site's — three literals, three return types, and the \
                 declaration of the type itself",
            ),
        ];

        let mut found: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (relative, production) in production_sources() {
            let counts = (
                production.matches("role: ExecutionRole::").count(),
                production.matches("RunnerRequest {").count(),
            );
            if counts != (0, 0) {
                found.insert(relative, counts);
            }
        }

        let expected: BTreeMap<String, (usize, usize)> = EXPECTED
            .iter()
            .map(|(file, roles, mentions, _)| ((*file).to_owned(), (*roles, *mentions)))
            .collect();
        assert_eq!(
            found, expected,
            "a RunnerRequest is built somewhere that is not its role's builder"
        );
        assert_eq!(
            expected.values().map(|(roles, _)| roles).sum::<usize>(),
            ExecutionRole::all().len(),
            "five roles, five construction points, and this is the count"
        );
        // The four words of `scope`, and the file that would hold a fifth.
        for absent in [
            "src/gates.rs",
            "src/review.rs",
            "src/engine/attempt.rs",
            "src/engine/coordinator.rs",
        ] {
            assert!(
                !expected.contains_key(absent),
                "{absent} assembles a request instead of asking for one"
            );
        }
    }

    #[test]
    fn every_production_process_start_is_classified() {
        use std::collections::BTreeMap;

        /// (file, `Command::new`, `.spawn()`, `run_with_timeout`) and why.
        const EXPECTED: &[(&str, usize, usize, usize, &str)] = &[
            (
                "src/agent/proc.rs",
                1,
                2,
                8,
                "the process funnel itself: two `command.spawn()` (Unix and \
                 Windows), the `run_with_timeout*` entry points — the plain \
                 one now *delegates* to the hooked one rather than calling \
                 the private limit-taking entry beside it, which is the eighth \
                 mention and the reason there is one bounded-capture value \
                 rather than two — and one `/bin/ps` on macOS that asks the \
                 kernel whether a process group has settled: a kernel query \
                 inside the reaper, not a CLI or a gate",
            ),
            (
                "src/runner/host.rs",
                1,
                0,
                1,
                "the host runner: `build_command` turns one CommandSpec into \
                 one Command, and `run` hands it to the funnel. This is where \
                 every routed process converges",
            ),
            (
                "src/workspace.rs",
                14,
                1,
                0,
                "authoritative Git, deliberately NOT routed. DESIGN.md:612 — \
                 \"Workers, repository-controlled gates, and reviewers all \
                 cross the boundary; authoritative Git and the event log \
                 never do.\" A git call that started going through the Runner \
                 would be a defect in the other direction",
            ),
            (
                "src/workspace_manager.rs",
                2,
                0,
                0,
                "the same decision as src/workspace.rs, for the schema-4 \
                 primitives: authoritative Git, deliberately NOT routed \
                 (DESIGN.md:612). Two `Command::new(` — one hook-free builder \
                 every effectful funnel goes through, and one read-only \
                 inspection helper the residue classifier uses — and no \
                 `.spawn()`, because every one of them is a `.output()` the \
                 funnel waits on. `decisions.workspace_candidates.manager` puts \
                 worktrees, snapshots, refs and Git objects behind these \
                 funnels; nothing here is a CLI, a gate, or a reviewer",
            ),
            (
                "src/effects.rs",
                1,
                0,
                0,
                "NOT a process start at all: the one `Command::new(` is inside \
                 `DENIAL_FIXTURES`, a string constant whose whole purpose is to \
                 be REFUSED. `effects::tests::every_declared_effect_denial_\
                 refuses_for_the_reason_it_declares` compiles it against \
                 `clippy.toml` and asserts it emits `clippy::disallowed_types` \
                 naming `std::process::Command` — so this row is the denylist's \
                 own evidence, and if it ever started compiling clean that test \
                 fails first. This census counts literal occurrences and does \
                 not strip string literals (`PR4-CENSUS-COMMENT-ORACLE`), which \
                 is why the row exists rather than the count being zero",
            ),
        ];

        fn count(haystack: &str, needle: &str) -> usize {
            haystack.matches(needle).count()
        }

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut found: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
        for (relative, production) in production_sources() {
            let counts = (
                count(&production, "Command::new("),
                count(&production, ".spawn()"),
                count(&production, "run_with_timeout"),
            );
            if counts != (0, 0, 0) {
                found.insert(relative, counts);
            }
        }

        let expected: BTreeMap<String, (usize, usize, usize)> = EXPECTED
            .iter()
            .map(|(file, new, spawn, timeout, _)| ((*file).to_owned(), (*new, *spawn, *timeout)))
            .collect();
        assert_eq!(
            found, expected,
            "production process starts moved. Every row is a decision \
             (DESIGN.md:612): route it through the Runner, or say here why it \
             is one of the things that never crosses the boundary"
        );
        // The table names five files, and it is the *set* that is the claim:
        // adapters, gates, review and the engine appear nowhere in it, which
        // is what "every CLI and gate process executes through Runner" means
        // once the migration has happened. Four of the five really do start a
        // process; the fifth, `src/effects.rs`, is a fixture that exists to be
        // refused, and its row says so.
        assert_eq!(expected.len(), 5);
        for name in [
            "src/gates.rs",
            "src/review.rs",
            "src/engine/attempt.rs",
            "src/agent/claude.rs",
            "src/agent/copilot.rs",
            "src/agent/codex.rs",
            "src/agent/bin.rs",
            "src/capacity.rs",
            "src/connect.rs",
        ] {
            assert!(
                !expected.contains_key(name),
                "{name} starts no process of its own"
            );
        }

        // The other half of DESIGN.md:612's sentence. "Authoritative Git and
        // the event log never [cross the boundary]" names two things, and the
        // table above only sees one of them: `src/workspace.rs` is caught by a
        // declared `Command::new(` count it would have to lose, but `events.rs`
        // legitimately starts no process at all, so a Runner call *appearing*
        // there subtracts from nothing. An event append implemented by
        // spawning an append helper through the Runner — on every event,
        // replay included — passed the census above unchanged.
        //
        // So the event log is asserted by name and by the tokens that would
        // mean it had acquired a boundary: not just a spawn, but a runner, a
        // request, or a command spec, any of which is the log deciding where
        // its writes execute.
        for (file, why) in [
            (
                "src/events/mod.rs",
                "the event vocabulary and fold: DESIGN.md:612 puts the event log, \
                 with authoritative Git, among the things that never cross the \
                 boundary",
            ),
            (
                // PR5 moved the writer here. The claim follows the code: this
                // file is now the only one that writes the log, so it is the
                // one an append-by-subprocess would have to appear in.
                "src/events/log.rs",
                "the event log writer: DESIGN.md:612 puts it, with authoritative \
                 Git, among the things that never cross the boundary",
            ),
            (
                "src/topology/events.rs",
                "the event vocabulary: data, and it stays data",
            ),
        ] {
            let source = std::fs::read_to_string(root.join(file)).expect("read the event log");
            let code: String = production_region(&source)
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for token in [
                "Command::new(",
                ".spawn()",
                "run_with_timeout",
                "HostRunner",
                "dyn Runner",
                "RunnerRequest",
                "CommandSpec",
            ] {
                assert_eq!(
                    count(&code, token),
                    0,
                    "{file} names `{token}`, so it can start a process. {why}"
                );
            }
        }

        // And an adapter does not *choose* a boundary either. DESIGN.md:117:
        // an adapter turns a TaskRun into a data-only CommandSpec and "does
        // not decide where the process runs". Naming a concrete runner in
        // production is that decision, whether or not it also spawns — which
        // is the half a spawn-site count cannot see. `capacity` and `connect`
        // are the two commands that legitimately make their own host runner
        // because they drive no run and have none to borrow, so they are
        // named here rather than covered by silence.
        for adapter in [
            "src/agent/mod.rs",
            "src/agent/bin.rs",
            "src/agent/claude.rs",
            "src/agent/copilot.rs",
            "src/agent/codex.rs",
        ] {
            let source = std::fs::read_to_string(root.join(adapter)).expect("read adapter");
            // Code, not prose: a doc comment may name the host runner to
            // explain why something is the way it is, and several do.
            let code: String = production_region(&source)
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                count(&code, "HostRunner"),
                0,
                "{adapter} names a concrete boundary; an adapter receives one"
            );
        }
    }

    /// Write-command containment is joined in **one** place and proved in
    /// **one** place, and this is the count.
    ///
    /// `Contained`'s constructor is private to `runner::host`, so the only
    /// mutation that can mint a proof out of a failed join — `let _ =
    /// proc::join_ambient_job(hooks); Ok(Contained::new())` — is one that can
    /// be *written* inside that module, and nowhere else in the crate. That
    /// makes the class closable by counting: one call to
    /// `proc::join_ambient_job`, one call to `Contained::new`, both inside the
    /// function
    /// `host::tests::the_production_containment_mint_propagates_a_join_refusal_and_mints_nothing`
    /// drives on its failure branch.
    ///
    /// A second mint appearing anywhere — a new entry point that "also"
    /// establishes containment, a facade that inlines the step — fails here
    /// until it is classified, which is the half a single failure-path test
    /// cannot cover on its own. Code only: several doc comments name both
    /// symbols, and two of them do it to explain this very rule.
    ///
    /// **Three needles, because the named constructor can be walked around.**
    /// `Contained`'s field is private to `runner::host`, and inside that module
    /// `Contained(())` builds one without going anywhere near `Contained::new`
    /// — and without touching the establishment counter the failure-path test
    /// reads. So the tuple-struct call is counted too, which is why
    /// `src/runner/host.rs` shows one (the declaration) and `src/main.rs` shows
    /// two.
    #[test]
    fn write_command_containment_has_one_join_site_and_one_mint() {
        use std::collections::BTreeMap;

        /// (file, `proc::join_ambient_job(`, `Contained::new()`, `Contained(`,
        /// and why).
        const EXPECTED: &[(&str, usize, usize, usize, &str)] = &[
            (
                "src/main.rs",
                0,
                0,
                2,
                "a different type with the same name and shape: the CLI's own \
                 `containment::Contained`, which proves *classification* — a \
                 write command joined, a read-only one was not asked to. Its \
                 two are the declaration and `establish`'s own construction, \
                 and it joins through `runner::host::start_write_command` \
                 rather than calling `proc` itself",
            ),
            (
                "src/runner/host.rs",
                1,
                1,
                1,
                "contain_write_command: the step every public facade and \
                 `src/main.rs`'s dispatch reaches — one join, one mint. \
                 `HostRunner::start_write_command` calls it rather than \
                 repeating it, so a runner's own observer and production's \
                 `NoHooks` go through one body. The third count is the type \
                 declaration; a second `Contained(` here would be a mint that \
                 bypassed the counter",
            ),
        ];

        let mut found: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
        for (relative, production) in production_sources() {
            let code: String = production
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let counts = (
                code.matches("proc::join_ambient_job(").count(),
                code.matches("Contained::new()").count(),
                code.matches("Contained(").count(),
            );
            if counts != (0, 0, 0) {
                found.insert(relative, counts);
            }
        }

        let expected: BTreeMap<String, (usize, usize, usize)> = EXPECTED
            .iter()
            .map(|(file, join, mint, built, _)| ((*file).to_owned(), (*join, *mint, *built)))
            .collect();
        assert_eq!(
            found, expected,
            "write-command containment is established somewhere new. Every row is a decision: \
             either it is the one step with the failure-path test behind it, or it is a second \
             one with none"
        );
    }

    /// Every production call site that **populates** a [`CommandSpec`] payload
    /// field, named and counted.
    ///
    /// This is the tripwire for `PR4-CONF-006`'s whole class. That finding was
    /// not "the fixtures forgot stdin"; it was that a production call site
    /// started filling a spec field and no fixture grid learned of it, so an
    /// observer suppression keyed on that field passed every test in the suite.
    /// The same thing is true of the overlay the moment anything sets one: as
    /// of this slice **nothing does**, and `runner::host::tests::
    /// the_role_grid_sends_the_shapes_production_sends` carries an empty
    /// overlay for all five roles *because* that is production's only value.
    ///
    /// So the count is on the population, not on the shape. `.stdin(` and
    /// `.env(` are counted across the production region of the tree — both
    /// `CommandSpec`'s builders and `std::process::Command`'s methods spell
    /// them the same way, and each row says which it is. A file that grows one
    /// fails here until somebody decides whether the grids have to carry it.
    ///
    /// **A method call is not the only way to populate a field.**
    /// `PR5-FIDELITY-001`: the two spec *constructors* build a `CommandSpec`
    /// with a struct literal, so `env: Vec::new()` at `src/agent/bin.rs`
    /// becoming an argument-dependent overlay is a production site this census
    /// could not see at all — pre-flight would then launch the probe with an
    /// overlay the spending command does not carry, against DESIGN.md:262-264.
    /// So the third column counts struct-literal `env:`/`stdin:` initializers
    /// too, and the constructors are enumerated rows like everything else.
    #[test]
    fn every_production_command_spec_payload_is_classified() {
        use std::collections::BTreeMap;

        /// (file, `.stdin(`, `.env(`, struct-literal `env:`/`stdin:`, and what
        /// they are).
        const EXPECTED: &[(&str, usize, usize, usize, &str)] = &[
            (
                "src/agent/bin.rs",
                0,
                0,
                2,
                "`Invocation::spec` — one of the crate's two CommandSpec \
                 constructors. Both payload fields are `Vec::new()`, and \
                 `a_command_specs_payload_does_not_depend_on_its_arguments` is \
                 what says they stay constant over production's own argument \
                 vectors. Invisible to the method-call columns, which is why \
                 this column exists (PR5-FIDELITY-001)",
            ),
            (
                "src/agent/proc.rs",
                1,
                1,
                0,
                "the process funnel's own `Command`: `.stdin(Stdio::piped())` \
                 is the pipe it writes the payload into, and the `.env` is the \
                 reaper's `/bin/ps` query on macOS. Neither is a CommandSpec",
            ),
            (
                "src/engine/attempt.rs",
                1,
                0,
                0,
                "the worker's prompt: `CommandSpec::stdin` from \
                 `AgentAdapter::stdin_payload`. The role grid carries it",
            ),
            (
                "src/gates.rs",
                0,
                0,
                2,
                "`ShellKind::spec` — the crate's other CommandSpec \
                 constructor, and the same answer: two `Vec::new()` payload \
                 fields, held constant by the same test",
            ),
            (
                "src/review.rs",
                1,
                0,
                0,
                "the reviewer's prompt, from the same seam. The role grid \
                 carries it",
            ),
            (
                "src/workspace.rs",
                1,
                4,
                0,
                "authoritative Git, which DESIGN.md:612 keeps off the boundary \
                 entirely: `std::process::Command` methods on git invocations, \
                 not a CommandSpec",
            ),
            (
                "src/workspace_manager.rs",
                2,
                6,
                0,
                "authoritative Git again, and the same answer: \
                 `std::process::Command` methods on git invocations, never a \
                 CommandSpec. The two `.stdin(` are `Stdio::null()` on the two \
                 builders — these funnels feed no payload to a child — and the \
                 six `.env(` are the fixed author/committer identity and dates \
                 that make a commit-tree a function of its inputs rather than \
                 of the machine",
            ),
        ];

        let mut found: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
        let mut stripped = 0_usize;
        for (relative, production) in production_sources() {
            let kept: Vec<&str> = production
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect();
            stripped += production.lines().count() - kept.len();
            let code: String = kept.join("\n");
            let counts = (
                code.matches(".stdin(").count(),
                code.matches(".env(").count(),
                // Struct-literal initializers of the same two fields. Anchored
                // at the start of a line so `.env(` chains and doc prose cannot
                // contribute, and counted separately so a row says which kind
                // of population it is.
                code.lines()
                    .filter(|line| {
                        let line = line.trim_start();
                        line.starts_with("env:") || line.starts_with("stdin:")
                    })
                    .count(),
            );
            if counts != (0, 0, 0) {
                found.insert(relative, counts);
            }
        }
        // The comment strip is a census over a file format that has comments,
        // which is `PR4-CENSUS-COMMENT-ORACLE`'s class. Assert it removed
        // something: a strip that silently stopped working would put every doc
        // comment mentioning `.env(` back into the counts.
        assert!(
            stripped > 100,
            "the comment strip removed {stripped} lines, so it is not working"
        );

        let expected: BTreeMap<String, (usize, usize, usize)> = EXPECTED
            .iter()
            .map(|(file, stdin, env, literal, _)| ((*file).to_owned(), (*stdin, *env, *literal)))
            .collect();
        assert_eq!(
            found, expected,
            "a production call site populates a CommandSpec payload field. Classify it, and if \
             it is a spec field, make the fixture grids carry that shape — an observer \
             suppression keyed on a field no grid varies is invisible (PR4-CONF-006), and one \
             keyed on a field no census counts is invisible twice (PR5-FIDELITY-001)"
        );
    }

    /// The two spec constructors' payload is a function of nothing.
    ///
    /// DESIGN.md:262-264: "Probe and execution compose the **same** base,
    /// mounts, reserved values, and overlay, so pre-flight certifies the
    /// environment that will actually spend." A probe and a work command differ
    /// in exactly one thing — their **arguments** — so an overlay that varies
    /// with the arguments is an overlay that differs between pre-flight and
    /// spend, and `PR5-FIDELITY-001` is that edit at `bin::Invocation::spec`.
    ///
    /// The census above says a site *exists*; this says what it produces. Both
    /// are needed and neither implies the other: a census cannot tell
    /// `Vec::new()` from a conditional, and a fixture that built one spec
    /// cannot tell a constant from a function of its input.
    ///
    /// The argument vectors are production's own — every adapter's `--version`
    /// probe, every adapter's `build_args` fresh and resumed, Codex's six
    /// strict-config parser probes' shape, and the gate/shell dialects — so
    /// this is a statement about the values production actually passes and not
    /// about invented ones.
    #[test]
    fn a_command_specs_payload_does_not_depend_on_its_arguments() {
        use crate::agent::bin::Invocation;

        fn run(agent: &str, resume: Option<&str>) -> crate::agent::TaskRun {
            crate::agent::TaskRun {
                prompt: "Do the thing.".to_owned(),
                profile: crate::ir::WorkerProfile {
                    name: "impl-mid".to_owned(),
                    agent: agent.to_owned(),
                    model: "a-model".to_owned(),
                    pool: "a-pool".to_owned(),
                    permissions: crate::ir::PermissionMode::ReadOnly,
                    effort: Some(crate::ir::Effort::Medium),
                    max_turns: Some(30),
                    extra_args: Vec::new(),
                },
                workspace: PathBuf::from("."),
                gate_cmds: Vec::new(),
                resume_session: resume.map(str::to_owned),
                settings_path: None,
            }
        }

        let mut argument_vectors: Vec<Vec<String>> = vec![
            vec!["--version".to_owned()],
            vec!["--help".to_owned()],
            vec!["exec".to_owned(), "--help".to_owned()],
            vec![
                "exec".to_owned(),
                "--ignore-user-config".to_owned(),
                "--strict-config".to_owned(),
                "-c".to_owned(),
                "model_reasoning_effort=xhigh".to_owned(),
            ],
            vec!["login".to_owned(), "status".to_owned()],
            vec!["debug".to_owned(), "models".to_owned()],
            Vec::new(),
        ];
        for id in ["claude-code", "codex", "copilot"] {
            for resume in [None, Some("session-1")] {
                argument_vectors.push(match id {
                    "claude-code" => crate::agent::claude::build_args(&run(id, resume)),
                    "codex" => crate::agent::codex::build_args(&run(id, resume)),
                    _ => crate::agent::copilot::build_args(&run(id, resume)),
                });
            }
        }
        assert!(
            argument_vectors.len() >= 13,
            "the argument vectors are production's own: {}",
            argument_vectors.len()
        );
        assert!(
            argument_vectors
                .iter()
                .any(|args| args.first().is_some_and(|arg| arg == "--version")),
            "a probe's argument vector must be among them, or the claim is untested"
        );
        assert!(
            argument_vectors
                .iter()
                .any(|args| args.first().is_some_and(|arg| arg == "exec")),
            "and a work command's"
        );

        // (a) `bin::Invocation::spec`, the agent-CLI constructor.
        let invocation = Invocation::at(if cfg!(windows) {
            r"C:\nowhere\claude.cmd"
        } else {
            "/nowhere/claude"
        });
        /// One spec's payload: its overlay and its stdin.
        type Payload = (Vec<(String, String)>, Vec<u8>);
        let mut payloads: Vec<Payload> = Vec::new();
        for args in &argument_vectors {
            let spec = invocation.spec(args).expect("a Unicode path");
            assert_eq!(&spec.args, args, "the arguments are carried verbatim");
            payloads.push((spec.env, spec.stdin));
        }
        let first = payloads.first().expect("at least one vector").clone();
        for (index, payload) in payloads.iter().enumerate() {
            assert_eq!(
                payload, &first,
                "`Invocation::spec` gave argument vector {index} ({:?}) a different \
                 payload than it gave {:?} — pre-flight would then certify an \
                 environment other than the one that spends",
                argument_vectors[index], argument_vectors[0]
            );
        }
        assert_eq!(
            first,
            (Vec::new(), Vec::new()),
            "and the payload production's constructor writes is empty"
        );

        // (b) `gates::ShellKind::spec`, the other one. Every dialect, because
        // the shell is a field of the record and not a constant.
        let mut shell_payloads: Vec<Payload> = Vec::new();
        use crate::gates::ShellKind;
        for shell in [
            ShellKind::Cmd,
            ShellKind::Sh,
            ShellKind::Bash,
            ShellKind::PowerShell,
            ShellKind::Pwsh,
        ] {
            for line in ["exit 0", "cargo test --all", "echo \"quoted arg\""] {
                let spec = shell.spec(line);
                shell_payloads.push((spec.env, spec.stdin));
            }
        }
        assert_eq!(
            shell_payloads.len(),
            15,
            "five dialects, three command lines"
        );
        for payload in &shell_payloads {
            assert_eq!(
                payload,
                &(Vec::new(), Vec::new()),
                "`ShellKind::spec` populated a payload field"
            );
        }
    }

    #[test]
    fn harness_hooks_consult_every_mode_a_point_declares() {
        let harness = Arc::new(Mutex::new(HookHarness::new()));
        let mut hooks = HarnessHooks::new(Arc::clone(&harness));
        for point in [
            SubEffectPoint::AmbientJobJoined,
            SubEffectPoint::CreatedSuspended,
        ] {
            assert_eq!(hooks.point(point), Injection::Proceed);
        }
        let harness = harness.lock().expect("harness");
        // AmbientJobJoined declares both modes; CreatedSuspended declares kill
        // only. The expected pairs come from `containment_sub_effects` ("failure
        // refuses the write command" for the ambient join alone), not from
        // `SubEffectPoint::modes`.
        assert!(harness.reached_point(
            SPAWN_SITE,
            SubEffectPoint::AmbientJobJoined,
            InjectionMode::Kill
        ));
        assert!(harness.reached_point(
            SPAWN_SITE,
            SubEffectPoint::AmbientJobJoined,
            InjectionMode::ErrorReturn
        ));
        assert!(harness.reached_point(
            SPAWN_SITE,
            SubEffectPoint::CreatedSuspended,
            InjectionMode::Kill
        ));
        assert!(!harness.reached_point(
            SPAWN_SITE,
            SubEffectPoint::CreatedSuspended,
            InjectionMode::ErrorReturn
        ));
    }
}
