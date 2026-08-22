//! The bounded reachability census (ST-14), as a skeleton.
//!
//! `decisions.bounded_census` asks for an executable breadth-first exploration
//! of abstract fold states: at every state, every event class is offered to the
//! real [`TopologyFold::plan_transition`], and each offer is either refused or
//! yields a next state. Nothing is simulated — the transition function under
//! test is the one a live run and a replay both use.
//!
//! # What a census is evidence for, and what it is not
//!
//! Bounded evidence for the stated bounds. It is not closure of the unbounded
//! system, and it proves nothing at all about effect phases — those are the
//! typed site registry's business ([`crate::topology::effects`]). What it *can*
//! settle is the shape of the transition table: that no `(state, event class)`
//! pair is unmapped, that a replay of every explored trace reaches the state
//! the exploration reached, and that [`TopologyFold::derived_outcome`] is total
//! — `NotEnding` or exactly one outcome at every state, with the
//! [`DerivedOutcome::FoldError`] arm never reached.
//!
//! That last one is why the arm is a value rather than a `panic!`: "this is
//! unreachable" is a claim, and a claim wants a census rather than an
//! assertion.
//!
//! # Skeleton
//!
//! This slice ships the explorer, the bounds, the recording, and the totality
//! assertions over fixtures. PR10 raises the fixtures to the packet's full
//! bounds and adds the per-arm coverage assertion. What is deliberately *not*
//! claimed here is stated by [`Census::truncated`] and by this module's tests:
//! a census that stopped early says so rather than reporting the states it did
//! reach as if they were all of them.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::topology::events::{DerivedOutcome, TopologyEvent};
use crate::topology::fold::TopologyFold;

/// The exploration bounds (`decisions.bounded_census.bounds`).
///
/// Recorded as data rather than as constants so a census can say which bounds
/// it ran under, and so the two numbers that actually stop the search —
/// [`Self::max_trace`] and [`Self::max_states`] — are visible beside the
/// design's own bounds instead of buried in the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CensusBounds {
    /// Original tasks in the plan.
    pub originals: u32,
    /// Repairs, and therefore lineages.
    pub repairs: u32,
    /// Generations per task.
    pub generations_per_task: u32,
    /// Attempts per generation.
    pub attempts_per_generation: u32,
    /// Integration sequences.
    pub sequences: u32,
    /// Verification defers per candidate — the fixture's `max_defers`.
    pub defers: u32,
    /// Open questions.
    pub questions: u32,
    /// Resumes.
    pub resumes: u32,
    /// The longest trace the search will extend.
    pub max_trace: usize,
    /// The most states the search will record before stopping.
    pub max_states: usize,
}

impl CensusBounds {
    /// Every dimension of the *explored space* this census declares, as
    /// `(name, bound)`.
    ///
    /// The two search limits are deliberately absent: [`Self::max_trace`] and
    /// [`Self::max_states`] bound the search, not the space, and a census that
    /// reached neither of them has still only generated whatever its fixture
    /// generates. This list exists so "every declared dimension" is something
    /// a test can quantify over rather than a list someone retypes — a bound
    /// that is declared here and never generated is a boundary the skeleton
    /// would otherwise report without evidence.
    pub const fn dimensions(&self) -> [(&'static str, u32); 8] {
        [
            ("originals", self.originals),
            ("repairs", self.repairs),
            ("generations_per_task", self.generations_per_task),
            ("attempts_per_generation", self.attempts_per_generation),
            ("sequences", self.sequences),
            ("defers", self.defers),
            ("questions", self.questions),
            ("resumes", self.resumes),
        ]
    }
}

impl Default for CensusBounds {
    /// The packet's bounds, with the two search limits set wide enough that
    /// the fixtures below reach their terminals and narrow enough that the
    /// search finishes in a unit test.
    fn default() -> Self {
        Self {
            originals: 3,
            repairs: 2,
            generations_per_task: 2,
            attempts_per_generation: 2,
            sequences: 4,
            defers: 2,
            questions: 2,
            resumes: 2,
            max_trace: 12,
            max_states: 20_000,
        }
    }
}

/// One event class offered at a state.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The class's name, used as its identity in the coverage record.
    pub label: String,
    /// The event the class produces at this state.
    pub event: TopologyEvent,
}

impl Candidate {
    /// A candidate with a label.
    pub fn new(label: impl Into<String>, event: TopologyEvent) -> Self {
        Self {
            label: label.into(),
            event,
        }
    }
}

/// What happened when a class was offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionOutcome {
    /// The fold accepted it; this is the state it reached.
    Accepted {
        /// The state's id.
        to: usize,
    },
    /// The fold refused it, and said why.
    Refused {
        /// The refusal, rendered.
        reason: String,
    },
    /// The fold accepted it and the state it reached was new, but the search
    /// had already recorded [`CensusBounds::max_states`] states.
    ///
    /// Recorded rather than dropped: an offer that vanished because the search
    /// was full is exactly the kind of silent cap that makes a coverage report
    /// read as complete when it is not.
    Truncated,
}

/// One `(state, event class)` pair and its answer.
///
/// Every offer is recorded, accepted or refused. "No `(state, event class)`
/// pair is unmapped" is then a property of this list rather than of the
/// explorer's control flow: an offer that produced neither would be an offer
/// that is not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CensusTransition {
    /// The state the class was offered at.
    pub from: usize,
    /// The class.
    pub label: String,
    /// The answer.
    pub outcome: TransitionOutcome,
}

/// One explored abstract state.
#[derive(Debug, Clone)]
pub struct CensusState {
    /// The state's id, in discovery order.
    pub id: usize,
    /// A shortest trace that reaches it.
    pub trace: Vec<TopologyEvent>,
    /// The fold at that state.
    pub fold: TopologyFold,
    /// What the total outcome function says here.
    pub outcome: DerivedOutcome,
}

/// A completed exploration.
#[derive(Debug, Clone)]
pub struct Census {
    bounds: CensusBounds,
    states: Vec<CensusState>,
    transitions: Vec<CensusTransition>,
    truncated: bool,
}

impl Census {
    /// Explore breadth-first from `start`, offering every class `classes`
    /// produces at every state.
    ///
    /// States are identified by the fold state they hold, not by the trace that
    /// reached it: two different histories that leave the run in the same state
    /// are one state, which is what makes the search finite and what makes
    /// "reachable" mean something.
    pub fn explore<F>(
        start: TopologyFold,
        seed: Vec<TopologyEvent>,
        bounds: CensusBounds,
        classes: F,
    ) -> Self
    where
        F: Fn(&TopologyFold) -> Vec<Candidate>,
    {
        let mut states: Vec<CensusState> = Vec::new();
        let mut transitions: Vec<CensusTransition> = Vec::new();
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut frontier: VecDeque<usize> = VecDeque::new();
        let mut truncated = false;

        seen.insert(fingerprint(&start), 0);
        states.push(CensusState {
            id: 0,
            outcome: start.derived_outcome(),
            trace: seed,
            fold: start,
        });
        frontier.push_back(0);

        while let Some(id) = frontier.pop_front() {
            if states[id].trace.len() >= bounds.max_trace {
                continue;
            }
            for candidate in classes(&states[id].fold) {
                let outcome = match states[id].fold.plan_transition(&candidate.event) {
                    Err(error) => TransitionOutcome::Refused {
                        reason: error.to_string(),
                    },
                    Ok(delta) => {
                        let mut next = states[id].fold.clone();
                        next.apply_delta(delta);
                        let key = fingerprint(&next);
                        match seen.get(&key) {
                            Some(existing) => TransitionOutcome::Accepted { to: *existing },
                            None => {
                                if states.len() >= bounds.max_states {
                                    truncated = true;
                                    transitions.push(CensusTransition {
                                        from: id,
                                        label: candidate.label,
                                        outcome: TransitionOutcome::Truncated,
                                    });
                                    continue;
                                }
                                let to = states.len();
                                let mut trace = states[id].trace.clone();
                                trace.push(candidate.event.clone());
                                seen.insert(key, to);
                                states.push(CensusState {
                                    id: to,
                                    trace,
                                    outcome: next.derived_outcome(),
                                    fold: next,
                                });
                                frontier.push_back(to);
                                TransitionOutcome::Accepted { to }
                            }
                        }
                    }
                };
                transitions.push(CensusTransition {
                    from: id,
                    label: candidate.label,
                    outcome,
                });
            }
        }

        Self {
            bounds,
            states,
            transitions,
            truncated,
        }
    }

    /// The bounds this census ran under.
    pub fn bounds(&self) -> CensusBounds {
        self.bounds
    }

    /// Every state reached.
    pub fn states(&self) -> &[CensusState] {
        &self.states
    }

    /// Every `(state, class)` offer and its answer.
    pub fn transitions(&self) -> &[CensusTransition] {
        &self.transitions
    }

    /// Whether the search stopped at [`CensusBounds::max_states`] rather than
    /// because it ran out of new states.
    ///
    /// A truncated census has explored a *subset*, and every assertion over it
    /// is an assertion about that subset. Reported rather than inferred,
    /// because a coverage claim over a silently truncated search reads exactly
    /// like a coverage claim over a complete one.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// The offers made at one state.
    pub fn outgoing(&self, id: usize) -> impl Iterator<Item = &CensusTransition> {
        self.transitions
            .iter()
            .filter(move |transition| transition.from == id)
    }

    /// Whether any class is accepted **at this state**.
    ///
    /// Two halves, and both are promises rather than incidental properties of
    /// the expression below, so both are asserted by
    /// `has_legal_transition_is_local_to_the_state_and_excludes_refusals`
    /// against censuses built to make each fail on its own:
    ///
    /// * *local* — a state with no accepted offer of its own answers `false`
    ///   even when some other state has one. A global existential would read
    ///   as an answer about a dead end and be an answer about the census.
    /// * *accepted only* — a refusal is not a transition. `plan_transition`
    ///   returning `Err` normally is the fold working, not the run moving, and
    ///   an out-of-range id has no offers and so answers `false`.
    pub fn has_legal_transition(&self, id: usize) -> bool {
        self.outgoing(id)
            .any(|transition| matches!(transition.outcome, TransitionOutcome::Accepted { .. }))
    }

    /// Every class that was accepted somewhere.
    pub fn accepted_labels(&self) -> BTreeSet<&str> {
        self.labels(true)
    }

    /// Every class that was refused somewhere.
    pub fn refused_labels(&self) -> BTreeSet<&str> {
        self.labels(false)
    }

    fn labels(&self, accepted: bool) -> BTreeSet<&str> {
        self.transitions
            .iter()
            .filter(|transition| {
                matches!(transition.outcome, TransitionOutcome::Accepted { .. }) == accepted
            })
            .map(|transition| transition.label.as_str())
            .collect()
    }

    /// Every state whose outcome is this one.
    pub fn states_with(&self, outcome: &DerivedOutcome) -> Vec<&CensusState> {
        self.states
            .iter()
            .filter(|state| &state.outcome == outcome)
            .collect()
    }

    /// Re-evaluate [`TopologyFold::derived_outcome`] once at every explored
    /// state and report what it found, raw.
    ///
    /// See [`TotalityAudit`] for why the totality assertion runs over this
    /// rather than over [`CensusState::outcome`].
    pub fn totality_audit(&self) -> TotalityAudit {
        TotalityAudit::over(&self.states)
    }
}

/// One raw [`TopologyFold::derived_outcome`] evaluation per state, and what it
/// disagreed with.
///
/// # Why this exists rather than a loop over `state.outcome`
///
/// [`CensusState::outcome`] is written by [`Census::explore`], which is also
/// the thing the totality assertion is evidence about. A checker whose input
/// is chosen by what it checks establishes nothing: an explorer that dropped a
/// [`DerivedOutcome::FoldError`] successor before recording it, recorded it as
/// a refusal, or wrote `NotEnding` in its place would leave every such loop
/// green. This audit closes three of those four doors and names the fourth:
///
/// * *normalising* — every state's recorded outcome is compared with a fresh
///   evaluation of the very same fold, and a disagreement is reported by id
///   rather than silently preferred one way or the other.
/// * *filtering* — [`Self::fold_errors`] counts an id when **either** side is
///   `FoldError`, so a checker cannot arrive at zero by discarding one side.
/// * *skipping* — [`Self::evaluated`] holds one entry per state in the order
///   they were given, so a caller can require it to equal the explored id set
///   computed from somewhere else (the accepted transitions, say) instead of
///   from the same list it is auditing.
/// * *dropping the successor entirely* — outside this type's reach, because a
///   state that was never recorded is not in `states`. That is what
///   `the_census_transition_table_is_reproducible_from_the_folds_alone`
///   settles, by re-deriving every offer from the folds and requiring each
///   accepted one to land on a recorded state with the same fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotalityAudit {
    /// The ids evaluated, one entry per state, in the order given.
    pub evaluated: Vec<usize>,
    /// The ids where the recorded outcome or the fresh evaluation — either —
    /// is [`DerivedOutcome::FoldError`].
    pub fold_errors: Vec<usize>,
    /// The ids where the recorded outcome and the fresh evaluation disagree.
    pub disagreements: Vec<usize>,
    /// How many fresh evaluations answered [`DerivedOutcome::NotEnding`].
    pub not_ending: usize,
    /// How many fresh evaluations answered [`DerivedOutcome::Ending`].
    pub ending: usize,
}

impl TotalityAudit {
    /// Audit an arbitrary list of states.
    ///
    /// Takes the slice rather than the [`Census`] so that the checker itself
    /// can be given a list containing a `FoldError` and shown to report it. A
    /// negative control that cannot be constructed is not a control.
    pub fn over(states: &[CensusState]) -> Self {
        let mut audit = Self {
            evaluated: Vec::with_capacity(states.len()),
            fold_errors: Vec::new(),
            disagreements: Vec::new(),
            not_ending: 0,
            ending: 0,
        };
        for state in states {
            audit.evaluated.push(state.id);
            let raw = state.fold.derived_outcome();
            if raw == DerivedOutcome::FoldError || state.outcome == DerivedOutcome::FoldError {
                audit.fold_errors.push(state.id);
            }
            if raw != state.outcome {
                audit.disagreements.push(state.id);
            }
            match raw {
                DerivedOutcome::NotEnding => audit.not_ending += 1,
                DerivedOutcome::Ending(_) => audit.ending += 1,
                DerivedOutcome::FoldError => {}
            }
        }
        audit
    }
}

/// The abstraction: the fold state, rendered.
///
/// `decisions.bounded_census.abstraction` asks for concrete state with commit
/// SHAs replaced by symbolic labels, paths replaced by regions, and timestamps
/// dropped. Timestamps are dropped by construction — they live on the event
/// envelope and never enter the fold — and the fixtures are written in symbolic
/// SHAs and named regions already, so the abstraction of a fixture state is the
/// state. Rendering it is then a faithful key: two states with the same
/// rendering agree on every relation `plan_transition` reads, because every one
/// of those relations is a field of what is rendered.
///
/// # The obligation this key carries, and why a paragraph is not it
///
/// The argument above is an argument about *this* body. Any projection of the
/// state — dropping the lease regions, collapsing `verification_deferred` to a
/// count, rendering the transaction without its `expected_head` — keeps the
/// function compiling, keeps it deterministic, and keeps every existing
/// assertion green, because two states that alias here are *one* state
/// everywhere downstream: the second is never recorded, so nothing later can
/// notice it is missing. A weakened key cannot be caught by looking at what
/// the census explored.
///
/// It is caught by looking at what the census *distinguishes*. Every relation
/// `decisions.bounded_census.abstraction` names as retained has a witness pair
/// in `the_abstraction_key_separates_states_that_differ_in_one_retained_relation`:
/// two reachable folds whose traces are identical but for one event, differing
/// in one field of that event — or, where the fold refuses a log that records
/// one symbolic label in one place and a different one elsewhere, differing in
/// that one label throughout — required to have different fingerprints. Path
/// regions get a second witness in
/// `an_overlapping_region_is_explored_and_changes_a_transition_answer`, where
/// A and AB are separate explored states whose answers to the same offer
/// differ — an overlap the key forgot would make that pair one state and the
/// differing answer unreachable.
fn fingerprint(fold: &TopologyFold) -> String {
    format!("{:?}|{:?}", fold.state(), fold.is_poisoned())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::OnceLock;
    use std::time::Duration;

    use super::*;
    use crate::events::{
        AttemptRecord, BindingSummary, BudgetKind, ChainSummary, GateSummary, RunOutcome,
    };
    use crate::gates::ShellKind;
    use crate::ir::{
        Artifact, ArtifactId, Effort, Plan, PlanSource, QuestionId, QuestionKind,
        ResolvedEffortPolicy, Task, TaskId, TaskKind, Tier,
    };
    use crate::review::{PassBinding, ReviewPlan};
    use crate::topology::events::{
        AttemptFinished4, AttemptNumber, AttemptSettlement, AttemptStarted4, BudgetExceeded4,
        CandidateLeaseEffect, CandidatePrepared, CandidateRef, CommitSha, DeferWaitElapsed4,
        GenerationCloseReason, GenerationClosed, GenerationId, GitRef, ImageIdentity,
        IncarnationId, InfrastructureKind, LeaseDisposition, LeaseGrant, MergeLeaseRelease,
        MergePrepared, MergeVerificationStarted, MergeVerificationUnavailable, PreparedDisposition,
        RunStarted4, RungBinding, RunnerContract, RunnerKind, RunnerPolicy, SequenceId,
        SettlementTransition, TaskCandidateCreated, TaskDispatched, TaskMerged, TopologyEvent,
        TopologyEventBody, TopologyLimits, UnavailableCause, UnavailableOutcome, VerificationBasis,
        VerificationRecord, VerificationSource, VerificationVerdict,
    };
    use crate::topology::fold::{
        FrozenInputs, GenerationClass, PreparedCandidate, TaskState, TopologyFold, TransactionClass,
    };
    use crate::topology::paths::{GitPath, PathGrammar, PathPolicy, PathPolicyVersion, PathSet};
    use crate::topology::registry::{TaskKey, TaskRegistry};
    use crate::topology::schema::TOPOLOGY_SCHEMA;

    const RUN_ID: &str = "01CENSUS000000000000000009";
    const ALEPH: TaskKey = TaskKey(0);
    const BET: TaskKey = TaskKey(1);

    // -----------------------------------------------------------------------
    // Fixtures
    //
    // Written for this module rather than shared with the fold's own tests: a
    // census that explored the same fixture the transition table was built
    // against would agree with it about a shape neither had questioned.
    //
    // Symbolic SHAs and two disjoint regions, so the state rendering that
    // identifies a census state is already the abstraction the design asks
    // for. Every independently meaningful field takes a value of its own —
    // `the_fixture_varies_every_field_a_relation_reads` counts them.
    // -----------------------------------------------------------------------

    /// A 40-character symbolic sha, one per role.
    fn sha(label: &str) -> CommitSha {
        let mut value = format!("{label:-<40}");
        value.truncate(40);
        CommitSha(value)
    }

    fn git_ref(name: &str) -> GitRef {
        GitRef(format!("refs/tactus/census/{RUN_ID}/{name}"))
    }

    fn task_of(id: &str, deps: &[&str], hint: &str) -> Task {
        Task {
            id: TaskId::from(id),
            kind: if id == "aleph" {
                TaskKind::Refactor
            } else {
                TaskKind::Test
            },
            title: format!("  {id} — Ünicode title  "),
            body: format!("{id} body"),
            depends_on: deps.iter().copied().map(TaskId::from).collect(),
            acceptance: vec![format!("{id} holds")],
            path_hints: vec![hint.to_owned()],
            suggested_tier: if id == "aleph" {
                Some(Tier::Mid)
            } else {
                Some(Tier::Small)
            },
            min_tier: None,
            artifacts_in: Vec::new(),
            artifacts_out: vec![ArtifactId::from(format!("{id}-out").as_str())],
        }
    }

    /// Two independent tasks over two disjoint regions, so the queue can hold
    /// two candidates at once and a lease has something to be wrong about.
    fn plan() -> Plan {
        Plan {
            source: PlanSource {
                adapter: "markdown".to_owned(),
                hash: "census-frozen-hash".to_owned(),
            },
            tasks: vec![
                task_of("aleph", &[], "src/aleph/"),
                task_of("bet", &[], "src/bet/"),
            ],
            artifacts: vec![Artifact {
                id: ArtifactId::from("aleph-out"),
                produced_by: Some(TaskId::from("aleph")),
            }],
        }
    }

    fn chain(task: &str) -> ChainSummary {
        let tiers = if task == "aleph" {
            vec![Tier::Mid, Tier::Frontier]
        } else {
            vec![Tier::Small]
        };
        ChainSummary {
            task: task.to_owned(),
            attempts_per: if task == "aleph" { 2 } else { 1 },
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

    const NORMALIZED_DIGEST: &str =
        "sha256:5555555555555555555555555555555555555555555555555555555555555555";

    fn path_policy() -> PathPolicy {
        PathPolicy {
            version: PathPolicyVersion::V1,
            case_fold: true,
            grammar: PathGrammar::Globset,
        }
    }

    fn inputs() -> FrozenInputs {
        FrozenInputs {
            plan: plan(),
            normalized_plan_digest: NORMALIZED_DIGEST.to_owned(),
        }
    }

    fn probed_agents() -> Vec<String> {
        vec![
            "  Codex-CLI  ".to_owned(),
            "aleph-Mid-agent".to_owned(),
            "bet-Small-agent".to_owned(),
            "aleph-Frontier-agent".to_owned(),
        ]
    }

    fn run_started_unauthenticated() -> RunStarted4 {
        RunStarted4 {
            schema: TOPOLOGY_SCHEMA,
            tactus_version: "0.2.0-census".to_owned(),
            run_id: RUN_ID.to_owned(),
            incarnation: IncarnationId("01J8ZQKB2M7NC5PQR0TVWXYZ77".to_owned()),
            runner: RunnerPolicy {
                kind: RunnerKind::Container,
                policy: RunnerContract::ContainerV1,
                image: Some(ImageIdentity {
                    reference: "ghcr.io/example/census-runner:3.4".to_owned(),
                    id: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                        .to_owned(),
                    digest: Some(
                        "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                            .to_owned(),
                    ),
                }),
                credential_volumes: Some(
                    [
                        (
                            "aleph-Mid-agent".to_owned(),
                            "tactus-creds-Ünicode".to_owned(),
                        ),
                        ("  Codex-CLI  ".to_owned(), "tactus-creds-codex".to_owned()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
            probed_agents: probed_agents(),
            branch: format!("tactus/run-{RUN_ID}"),
            integration_ref: git_ref("integration"),
            base_sha: sha("base"),
            execution_root: "/var/lib/Tactus/census execution roots".to_owned(),
            private_dir: "/var/lib/Tactus/census private".to_owned(),
            plan_path: "docs/Census Plan.md".to_owned(),
            config_path: None,
            plan_hash: "census-frozen-hash".to_owned(),
            normalized_plan_digest: NORMALIZED_DIGEST.to_owned(),
            registry_digest: String::new(),
            path_policy: path_policy(),
            // Three different numbers, so a fold that read one limit where it
            // meant another lands on a value this fixture does not hold.
            limits: TopologyLimits {
                max_parallel: 3,
                max_defers: 2,
                max_merge_repairs: 1,
            },
            gates: vec!["fmt".to_owned()],
            gates_from_config: false,
            gate_cmds: vec![GateSummary {
                name: "fmt".to_owned(),
                cmd: "cargo fmt --check".to_owned(),
                timeout: Duration::from_secs(451),
                shell: ShellKind::Bash,
            }],
            interaction_mode: "never".to_owned(),
            chains: vec![chain("aleph"), chain("bet")],
            effort_policy: ResolvedEffortPolicy {
                small: Effort::Low,
                mid: Effort::High,
                frontier: Effort::Max,
                review: Effort::Medium,
            },
            reviews: ReviewPlan {
                enabled: Some(false),
                alternative_available: Some(false),
                pass_timeout_secs: Some(97),
                primary: Some(PassBinding::new("aleph-Mid-agent", "aleph-Mid-model")),
                alternative: None,
                second_opinion: vec![None, None],
            },
        }
    }

    fn run_started() -> RunStarted4 {
        let started = run_started_unauthenticated();
        let digest = TaskRegistry::originals_with_agents(
            &plan(),
            &started.registry_record(),
            &started.probed_agents,
        )
        .expect("the fixture derives a registry")
        .digest();
        RunStarted4 {
            registry_digest: digest,
            ..started
        }
    }

    fn ev(body: TopologyEventBody) -> TopologyEvent {
        TopologyEvent {
            ts: "2026-08-17T19:04:11Z".to_owned(),
            body,
        }
    }

    /// A fold that has recorded its `run_started` and nothing else.
    fn started() -> TopologyFold {
        let mut fold = TopologyFold::new(inputs());
        let event = ev(TopologyEventBody::RunStarted {
            data: Box::new(run_started()),
        });
        let delta = fold
            .plan_transition(&event)
            .expect("the fixture's run_started applies");
        fold.apply_delta(delta);
        fold
    }

    fn region(key: TaskKey) -> PathSet {
        PathSet::Prefixes {
            paths: vec![GitPath::from(if key == ALEPH {
                "src/aleph/"
            } else {
                "src/bet/"
            })],
        }
    }

    /// Region AB: the union of the two disjoint regions, so it overlaps each
    /// of them and neither of them contains it.
    ///
    /// `decisions.bounded_census.abstraction` names "paths replaced by regions
    /// A, B, AB" — three labels, not two — and AB is the only one of the three
    /// under which the overlap relation answers differently from the others.
    fn overlap_region() -> PathSet {
        PathSet::Prefixes {
            paths: vec![GitPath::from("src/aleph/"), GitPath::from("src/bet/")],
        }
    }

    fn label(key: TaskKey) -> &'static str {
        if key == ALEPH { "aleph" } else { "bet" }
    }

    fn binding(fold: &TopologyFold, key: TaskKey, rung: usize) -> RungBinding {
        let registry = fold.registry().expect("started");
        let entry = registry.get(key).expect("a registered task");
        let frozen = &entry.ladder.rungs[rung];
        RungBinding::from_frozen(frozen, entry.ladder.effort.implementation_for(frozen.tier))
    }

    fn attempt_record(attempt: u32) -> AttemptRecord {
        AttemptRecord {
            attempt,
            tier: "mid".to_owned(),
            model: "aleph-Mid-model".to_owned(),
            pool: None,
            resumed: false,
            duration: Duration::from_millis(4_321),
            cost_usd: Some(0.75),
            reviews: Vec::new(),
            session_id: None,
            usage: None,
            failure: None,
        }
    }

    fn dispatch(key: TaskKey, generation: u32) -> TopologyEvent {
        dispatch_over(key, generation, region(key))
    }

    /// The same dispatch with its predicted region named, so a fixture can
    /// vary the one field the overlap relation reads and vary nothing else.
    fn dispatch_over(key: TaskKey, generation: u32, paths: PathSet) -> TopologyEvent {
        dispatch_at(key, generation, paths, sha("base"))
    }

    /// The same dispatch cut from a named base.
    ///
    /// The base a generation is dispatched at is the base its candidate must
    /// record — `check_candidate_prepared` refuses a record that disagrees
    /// with it — and it is the left operand of the fast publication's head
    /// relation. So a witness that varies the candidate's base varies this
    /// event and the prepared record together, and can vary nothing less.
    fn dispatch_at(
        key: TaskKey,
        generation: u32,
        paths: PathSet,
        base: CommitSha,
    ) -> TopologyEvent {
        ev(TopologyEventBody::TaskDispatched {
            data: TaskDispatched {
                key,
                generation: GenerationId(generation),
                base_sha: base,
                worktree_path: format!("/tmp/census/{}", label(key)),
                lease: LeaseGrant::Predicted { paths },
                source_candidate: None,
            },
        })
    }

    fn attempt_started(
        fold: &TopologyFold,
        key: TaskKey,
        generation: u32,
        attempt: u32,
    ) -> TopologyEvent {
        ev(TopologyEventBody::AttemptStarted {
            data: AttemptStarted4 {
                key,
                generation: GenerationId(generation),
                attempt: AttemptNumber(attempt),
                rung: 0,
                binding: binding(fold, key, 0),
                pool: None,
                resume_session: None,
                materialization_observed: None,
            },
        })
    }

    fn settle(
        key: TaskKey,
        generation: u32,
        attempt: u32,
        transition: SettlementTransition,
        lease: LeaseDisposition,
    ) -> TopologyEvent {
        ev(TopologyEventBody::AttemptFinished {
            data: Box::new(AttemptFinished4 {
                key,
                generation: GenerationId(generation),
                attempt: AttemptNumber(attempt),
                record: Box::new(attempt_record(attempt)),
                settlement: AttemptSettlement::Closed { transition, lease },
            }),
        })
    }

    fn candidate_of(key: TaskKey, generation: u32) -> CandidateRef {
        CandidateRef {
            key,
            generation: GenerationId(generation),
            commit_sha: sha(&format!("commit-{}-{generation}", label(key))),
            candidate_ref: git_ref(&format!("candidates/{}/{generation}", label(key))),
        }
    }

    fn candidate_prepared(key: TaskKey, generation: u32, attempt: u32) -> TopologyEvent {
        candidate_prepared_over(key, generation, attempt, region(key))
    }

    /// The same record with the region its diff touched named. `actual_paths`
    /// and the lease it replaces the prediction with are one region by
    /// `check_candidate_prepared`'s own rule — "the region it takes is not the
    /// region its diff touched" — so one parameter is the honest shape.
    fn candidate_prepared_over(
        key: TaskKey,
        generation: u32,
        attempt: u32,
        paths: PathSet,
    ) -> TopologyEvent {
        candidate_prepared_at(
            key,
            generation,
            attempt,
            paths,
            sha("base"),
            candidate_of(key, generation).commit_sha,
        )
    }

    /// The same record at a named base and a named commit.
    ///
    /// The two labels the fast publication relations compare a candidate
    /// against, as parameters. `parent_sha` moves with `base_sha` because
    /// `parent_is_base` requires it, which is why the base is one parameter
    /// and not two.
    fn candidate_prepared_at(
        key: TaskKey,
        generation: u32,
        attempt: u32,
        paths: PathSet,
        base: CommitSha,
        commit: CommitSha,
    ) -> TopologyEvent {
        ev(TopologyEventBody::CandidatePrepared {
            data: Box::new(CandidatePrepared {
                key,
                generation: GenerationId(generation),
                attempt: Box::new(attempt_record(attempt)),
                base_sha: base.clone(),
                parent_sha: base,
                tree_sha: sha(&format!("tree-{}", label(key))),
                commit_sha: commit,
                message: format!("{}: census candidate", label(key)),
                prepared_ref: git_ref(&format!("prepared-candidate/{}", label(key))),
                candidate_ref: candidate_of(key, generation).candidate_ref,
                actual_paths: paths.clone(),
                lease_effect: CandidateLeaseEffect::ReplacesPredicted { paths },
            }),
        })
    }

    /// The same candidate at a named commit. Its commit is part of its
    /// identity, so every later record that names it carries the same label or
    /// the fold refuses the log.
    fn candidate_at(key: TaskKey, generation: u32, commit: CommitSha) -> CandidateRef {
        CandidateRef {
            commit_sha: commit,
            ..candidate_of(key, generation)
        }
    }

    fn candidate_created(key: TaskKey, generation: u32) -> TopologyEvent {
        candidate_created_of(candidate_of(key, generation))
    }

    fn candidate_created_of(candidate: CandidateRef) -> TopologyEvent {
        ev(TopologyEventBody::TaskCandidateCreated {
            data: TaskCandidateCreated { candidate },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn merge_prepared(
        sequence: u32,
        key: TaskKey,
        generation: u32,
        disposition: PreparedDisposition,
        expected_head: CommitSha,
        proposed_sha: CommitSha,
        prepared_ref: Option<GitRef>,
        source: VerificationSource,
    ) -> TopologyEvent {
        merge_prepared_for(
            sequence,
            candidate_of(key, generation),
            disposition,
            expected_head,
            proposed_sha,
            prepared_ref,
            source,
        )
    }

    /// The same publication naming its candidate outright, so a witness whose
    /// whole point is a candidate at a label the fixture does not otherwise
    /// derive can still be published.
    fn merge_prepared_for(
        sequence: u32,
        candidate: CandidateRef,
        disposition: PreparedDisposition,
        expected_head: CommitSha,
        proposed_sha: CommitSha,
        prepared_ref: Option<GitRef>,
        source: VerificationSource,
    ) -> TopologyEvent {
        let CandidateRef {
            key,
            generation,
            commit_sha,
            candidate_ref,
        } = candidate;
        ev(TopologyEventBody::MergePrepared {
            data: Box::new(MergePrepared {
                sequence: SequenceId(sequence),
                disposition,
                expected_head,
                proposed_sha,
                key,
                generation,
                candidate_sha: commit_sha,
                candidate_ref,
                prepared_ref,
                verification_source: source.clone(),
                verification: match &source {
                    VerificationSource::CandidatePrepared { .. } => None,
                    VerificationSource::Verification { .. } => Some(VerificationRecord {
                        verdict: VerificationVerdict::Passed,
                        gates_passed: true,
                        reviews: Vec::new(),
                        detail: "census verification".to_owned(),
                    }),
                },
                satisfies: vec![key],
            }),
        })
    }

    /// The merge that resolves an open publication.
    ///
    /// `merged_sha` and `satisfies` are read off the transaction the fold is
    /// holding, because a merge is the ref move a publication already
    /// authorized: a class that invented either would only ever be refused,
    /// and the census would then never resolve a transaction.
    fn task_merged(
        fold: &TopologyFold,
        sequence: u32,
        key: TaskKey,
        generation: u32,
    ) -> TopologyEvent {
        let (merged_sha, satisfies) = match fold.transaction().map(|open| &open.class) {
            Some(TransactionClass::Prepared {
                proposed_sha,
                satisfies,
            }) => (proposed_sha.clone(), satisfies.clone()),
            _ => (candidate_of(key, generation).commit_sha, vec![key]),
        };
        ev(TopologyEventBody::TaskMerged {
            data: TaskMerged {
                sequence: SequenceId(sequence),
                merged_sha,
                satisfies,
                lease_release: MergeLeaseRelease::Candidate {
                    key,
                    generation: GenerationId(generation),
                },
            },
        })
    }

    fn run_finished(fold: &TopologyFold, outcome: RunOutcome) -> TopologyEvent {
        ev(TopologyEventBody::RunFinished {
            data: crate::topology::events::RunFinished4 {
                outcome,
                halted_at: fold.halted_at(),
                merged: 0,
                parked: 0,
            },
        })
    }

    // -----------------------------------------------------------------------
    // The event classes
    // -----------------------------------------------------------------------

    /// Every event class the census offers, at every state.
    ///
    /// Parameters range over the bounded identities exactly as
    /// `event_payload_classes` asks: both tasks, both generations, both
    /// attempts, the settlement transitions, the three publication
    /// dispositions each in a matching and a mismatching shape, the budget
    /// stop, the backoff wake, and `run_finished` for each of the four
    /// outcomes.
    fn classes(fold: &TopologyFold) -> Vec<Candidate> {
        let mut out = Vec::new();
        let sequence = fold.transaction().map_or(0, |t| t.sequence.0);

        for key in [ALEPH, BET] {
            let name = label(key);
            for generation in 0..2 {
                out.push(Candidate::new(
                    format!("task_dispatched/{name}/g{generation}"),
                    dispatch(key, generation),
                ));
                for attempt in 1..=2 {
                    out.push(Candidate::new(
                        format!("attempt_started/{name}/g{generation}/a{attempt}"),
                        attempt_started(fold, key, generation, attempt),
                    ));
                    for (tag, transition, lease) in [
                        (
                            "succeeded",
                            SettlementTransition::Succeeded,
                            LeaseDisposition::PredictedRetained,
                        ),
                        (
                            "retry",
                            SettlementTransition::Retry,
                            LeaseDisposition::PredictedReleased,
                        ),
                        (
                            "failed",
                            SettlementTransition::Failed {
                                halts_run: false,
                                reason: "census failure".to_owned(),
                            },
                            LeaseDisposition::PredictedReleased,
                        ),
                        (
                            "halting",
                            SettlementTransition::Failed {
                                halts_run: true,
                                reason: "census halting failure".to_owned(),
                            },
                            LeaseDisposition::PredictedReleased,
                        ),
                        (
                            "deferred",
                            SettlementTransition::Deferred {
                                defers: 1,
                                reason: "census outage".to_owned(),
                            },
                            LeaseDisposition::PredictedReleased,
                        ),
                        (
                            "parked",
                            SettlementTransition::Parked {
                                question: crate::topology::events::FrozenQuestion {
                                    id: QuestionId::from(format!("q-{name}-{generation}").as_str()),
                                    key,
                                    kind: QuestionKind::Unblock,
                                    context: "  a question only a person settles  ".to_owned(),
                                    options: vec!["yes".to_owned(), "no".to_owned()],
                                },
                            },
                            LeaseDisposition::PredictedReleased,
                        ),
                    ] {
                        out.push(Candidate::new(
                            format!("attempt_finished/{tag}/{name}/g{generation}/a{attempt}"),
                            settle(key, generation, attempt, transition, lease),
                        ));
                    }
                    out.push(Candidate::new(
                        format!("candidate_prepared/{name}/g{generation}/a{attempt}"),
                        candidate_prepared(key, generation, attempt),
                    ));
                }
                out.push(Candidate::new(
                    format!("task_candidate_created/{name}/g{generation}"),
                    candidate_created(key, generation),
                ));
                out.push(Candidate::new(
                    format!("generation_closed/{name}/g{generation}"),
                    ev(TopologyEventBody::GenerationClosed {
                        data: GenerationClosed {
                            key,
                            generation: GenerationId(generation),
                            reason: GenerationCloseReason::RunEnding {
                                outcome: RunOutcome::Complete,
                            },
                            lease: LeaseDisposition::PredictedReleased,
                        },
                    }),
                ));

                let candidate = candidate_of(key, generation);
                let source = VerificationSource::CandidatePrepared {
                    key,
                    generation: GenerationId(generation),
                };
                // The fast relation, matching and each way of missing it.
                out.push(Candidate::new(
                    format!("merge_prepared/fast/match/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::Fast,
                        sha("base"),
                        candidate.commit_sha.clone(),
                        None,
                        source.clone(),
                    ),
                ));
                out.push(Candidate::new(
                    format!("merge_prepared/fast/moved-head/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::Fast,
                        sha("moved-head"),
                        candidate.commit_sha.clone(),
                        None,
                        source.clone(),
                    ),
                ));
                out.push(Candidate::new(
                    format!("merge_prepared/fast/other-proposed/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::Fast,
                        sha("base"),
                        sha("not-the-candidate"),
                        None,
                        source.clone(),
                    ),
                ));
                out.push(Candidate::new(
                    format!("merge_prepared/fast/with-pin/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::Fast,
                        sha("base"),
                        candidate.commit_sha.clone(),
                        Some(git_ref(&format!("prepared/{sequence}"))),
                        source.clone(),
                    ),
                ));
                // A stale verification, then the stale_clean relation both
                // ways, and already_present both ways.
                out.push(Candidate::new(
                    format!("merge_verification_started/stale/{name}/g{generation}"),
                    ev(TopologyEventBody::MergeVerificationStarted {
                        data: MergeVerificationStarted {
                            sequence: SequenceId(sequence),
                            candidate: candidate.clone(),
                            basis: VerificationBasis::StaleClean {
                                prepared_ref: git_ref(&format!("prepared/{sequence}")),
                            },
                            expected_head: sha("moved-head"),
                            proposed_sha: sha(&format!("proposal-{name}")),
                        },
                    }),
                ));
                out.push(Candidate::new(
                    format!("merge_verification_started/present/{name}/g{generation}"),
                    ev(TopologyEventBody::MergeVerificationStarted {
                        data: MergeVerificationStarted {
                            sequence: SequenceId(sequence),
                            candidate: candidate.clone(),
                            basis: VerificationBasis::AlreadyPresent,
                            expected_head: candidate.commit_sha.clone(),
                            proposed_sha: candidate.commit_sha.clone(),
                        },
                    }),
                ));
                let verified = VerificationSource::Verification {
                    sequence: SequenceId(sequence),
                };
                out.push(Candidate::new(
                    format!("merge_prepared/stale_clean/match/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::StaleClean,
                        sha("moved-head"),
                        sha(&format!("proposal-{name}")),
                        Some(git_ref(&format!("prepared/{sequence}"))),
                        verified.clone(),
                    ),
                ));
                out.push(Candidate::new(
                    format!("merge_prepared/stale_clean/mismatch/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::StaleClean,
                        sha("moved-head"),
                        sha("not-the-pinned-proposal"),
                        Some(git_ref(&format!("prepared/{sequence}"))),
                        verified.clone(),
                    ),
                ));
                out.push(Candidate::new(
                    format!("merge_prepared/already_present/match/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::AlreadyPresent,
                        candidate.commit_sha.clone(),
                        candidate.commit_sha.clone(),
                        None,
                        verified.clone(),
                    ),
                ));
                out.push(Candidate::new(
                    format!("merge_prepared/already_present/mismatch/{name}/g{generation}"),
                    merge_prepared(
                        sequence,
                        key,
                        generation,
                        PreparedDisposition::AlreadyPresent,
                        candidate.commit_sha.clone(),
                        sha("not-the-head"),
                        None,
                        verified.clone(),
                    ),
                ));
                out.push(Candidate::new(
                    format!("task_merged/{name}/g{generation}"),
                    task_merged(fold, sequence, key, generation),
                ));
            }
        }

        out.push(Candidate::new(
            "defer_wait_elapsed",
            ev(TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 30_000,
                    round: 1,
                },
            }),
        ));
        out.push(Candidate::new(
            "budget_exceeded",
            ev(TopologyEventBody::BudgetExceeded {
                data: BudgetExceeded4 {
                    epoch: fold.epoch().unwrap_or(crate::topology::events::Epoch(0)),
                    budget: BudgetKind::Run,
                    limit_usd: 12.5,
                    spent_usd: 12.75,
                    key: Some(ALEPH),
                },
            }),
        ));
        for outcome in [
            RunOutcome::Complete,
            RunOutcome::Parked,
            RunOutcome::Halted,
            RunOutcome::BudgetExceeded,
        ] {
            out.push(Candidate::new(
                format!("run_finished/{outcome:?}"),
                run_finished(fold, outcome),
            ));
        }
        out
    }

    fn run_started_event() -> TopologyEvent {
        ev(TopologyEventBody::RunStarted {
            data: Box::new(run_started()),
        })
    }

    /// The one exploration every assertion below runs over.
    ///
    /// Memoised rather than re-explored per test: the search is deterministic
    /// and the value is shared behind `&`, so a second run would be the same
    /// bytes at the price of another quarter of a million `plan_transition`
    /// calls. Sharing it is what makes the independent re-derivation in
    /// `the_census_transition_table_is_reproducible_from_the_folds_alone`
    /// affordable.
    fn census() -> &'static Census {
        static CENSUS: OnceLock<Census> = OnceLock::new();
        CENSUS.get_or_init(|| {
            Census::explore(
                started(),
                vec![run_started_event()],
                CensusBounds::default(),
                classes,
            )
        })
    }

    // -----------------------------------------------------------------------
    // The independent oracle
    //
    // Every expectation below is computed from the *dimension tuple* by
    // `run_end_policy.derived_outcome`'s own chain — not by calling
    // `derived_outcome`, and not from a constant the fold also reads.
    // -----------------------------------------------------------------------

    /// `common`: no generation in {OpenNoAttempt, InFlight, Promoting,
    /// RetainedIdle} and no unresolved integration transaction.
    fn common(fold: &TopologyFold) -> bool {
        let no_open_generation = [ALEPH, BET].iter().all(|key| {
            fold.task(*key).is_none_or(|task| {
                task.generations
                    .iter()
                    .all(|generation| generation.class == GenerationClass::Closed)
            })
        });
        no_open_generation && fold.transaction().is_none()
    }

    /// `backoff_pending`: any task Deferred or any candidate
    /// verification-deferred.
    fn backoff_pending(fold: &TopologyFold) -> bool {
        let deferred_task = [ALEPH, BET]
            .iter()
            .any(|key| fold.task_state(*key) == Some(TaskState::Deferred));
        let deferred_candidate = fold.queue().is_some_and(|queue| {
            queue
                .entries()
                .iter()
                .any(|entry| entry.verification_deferred)
        });
        deferred_task || deferred_candidate
    }

    /// `questions_open`: any open question.
    fn questions_open(fold: &TopologyFold) -> bool {
        fold.open_questions()
            .is_some_and(|questions| !questions.is_empty())
    }

    /// The Complete arm's own condition, read off the durable state.
    fn complete_shape(fold: &TopologyFold) -> bool {
        // "every task is Merged, Failed, or Pending with a Failed task in its
        // transitive dependency closure". The fixture plan has no dependencies,
        // so no Pending task is ever derived-Blocked and the arm reduces to
        // Merged-or-Failed here. PR10's fixtures carry the dependency shapes.
        let every_task_terminal = [ALEPH, BET].iter().all(|key| {
            matches!(
                fold.task_state(*key),
                Some(TaskState::Merged | TaskState::Failed)
            )
        });
        let queue_empty = fold.queue().is_none_or(|queue| queue.is_empty());
        let no_lease = fold
            .leases()
            .is_none_or(|leases| !leases.any_candidate_or_lineage());
        every_task_terminal && queue_empty && no_lease && !questions_open(fold)
    }

    #[test]
    fn the_derived_outcome_is_total_over_every_explored_state() {
        // ST-14's headline: `NotEnding` or exactly one outcome at every
        // explored state, and the `FoldError` arm never reached.
        //
        // Run through `TotalityAudit` rather than over `state.outcome`,
        // because `state.outcome` is written by the explorer this assertion is
        // evidence about: see that type's own documentation, and
        // `the_totality_audit_reports_a_fold_error_a_normalisation_and_a_short_domain`
        // for the three failures it is shown reporting.
        let census = census();
        assert!(!census.states().is_empty());
        let audit = census.totality_audit();

        // The domain first, and named from somewhere other than the list being
        // audited: the seed, plus every state some accepted offer landed on.
        let reached: BTreeSet<usize> =
            std::iter::once(0)
                .chain(census.transitions().iter().filter_map(
                    |transition| match transition.outcome {
                        TransitionOutcome::Accepted { to } => Some(to),
                        TransitionOutcome::Refused { .. } | TransitionOutcome::Truncated => None,
                    },
                ))
                .collect();
        assert_eq!(
            audit.evaluated,
            (0..census.states().len()).collect::<Vec<_>>(),
            "one evaluation per explored state, in order, and no more"
        );
        assert_eq!(
            audit.evaluated.iter().copied().collect::<BTreeSet<_>>(),
            reached,
            "the states that were evaluated and the states the transitions reach are not the \
             same set"
        );

        // The arm the design argues is unreachable, counted from the recorded
        // value and from a fresh evaluation of the same fold alike.
        assert!(
            audit.fold_errors.is_empty(),
            "the arm the design argues is unreachable was reached at states {:?}, the first after \
             {:?}",
            audit.fold_errors,
            audit.fold_errors.first().map(|id| census.states()[*id]
                .trace
                .iter()
                .map(|event| event.body.kind())
                .collect::<Vec<_>>())
        );
        assert!(
            audit.disagreements.is_empty(),
            "the recorded outcome and a fresh evaluation of the same fold disagree at {:?}",
            audit.disagreements
        );
        assert_eq!(
            audit.not_ending + audit.ending,
            census.states().len(),
            "every explored state answered exactly one of the two"
        );
        let (not_ending, ending) = (audit.not_ending, audit.ending);
        // Both answers occur, so totality is a statement about a range rather
        // than about a constant.
        assert!(not_ending > 0 && ending > 0, "{not_ending}/{ending}");

        // And each answer is the one the dimension tuple implies, by the
        // packet's precedence chain rather than by the function under test.
        for state in census.states() {
            let fold = &state.fold;
            let common = common(fold);
            let halting = fold.halted_at().is_some();
            let budget = fold
                .budget_stop()
                .is_some_and(|stop| Some(stop.epoch) == fold.epoch());
            if !common {
                assert_eq!(
                    state.outcome,
                    DerivedOutcome::NotEnding,
                    "state {}: a run with open work is not ending",
                    state.id
                );
            } else if halting {
                assert_eq!(
                    state.outcome,
                    DerivedOutcome::Ending(RunOutcome::Halted),
                    "state {}: halt outranks everything",
                    state.id
                );
            } else if budget {
                assert_eq!(
                    state.outcome,
                    DerivedOutcome::Ending(RunOutcome::BudgetExceeded),
                    "state {}: budget outranks parked and complete",
                    state.id
                );
            } else if backoff_pending(fold) {
                assert_eq!(
                    state.outcome,
                    DerivedOutcome::NotEnding,
                    "state {}: pending backoff blocks Parked and Complete",
                    state.id
                );
            } else if complete_shape(fold) {
                assert_eq!(
                    state.outcome,
                    DerivedOutcome::Ending(RunOutcome::Complete),
                    "state {}: nothing is open and nothing is asked",
                    state.id
                );
            }
            // The necessary conditions of the two arms the oracle above does
            // not compute forwards, asserted backwards.
            match &state.outcome {
                DerivedOutcome::Ending(RunOutcome::Parked) => {
                    assert!(questions_open(fold), "state {}", state.id);
                    assert!(!backoff_pending(fold), "state {}", state.id);
                    assert!(common, "state {}", state.id);
                }
                DerivedOutcome::Ending(RunOutcome::Complete) => {
                    assert!(!questions_open(fold), "state {}", state.id);
                    assert!(complete_shape(fold), "state {}", state.id);
                }
                DerivedOutcome::Ending(RunOutcome::Halted) => {
                    assert!(halting, "state {}", state.id);
                }
                DerivedOutcome::Ending(RunOutcome::BudgetExceeded) => {
                    assert!(budget && !halting, "state {}", state.id);
                }
                DerivedOutcome::NotEnding | DerivedOutcome::FoldError => {}
            }
        }
    }

    #[test]
    fn a_state_with_admissible_work_and_no_budget_exceeded_classifies_not_ending() {
        // The pre-`budget_exceeded` counterexample the packet names: a run
        // with structurally admissible work and no budget record is NotEnding
        // *whatever the unmodeled spend*, and BudgetExceeded only after the
        // record exists.
        let census = census();
        let mut before = 0;
        let mut after = 0;
        for state in census.states() {
            let fold = &state.fold;
            let has_record = fold.budget_stop().is_some();
            if !has_record && fold.halted_at().is_none() {
                assert_ne!(
                    state.outcome,
                    DerivedOutcome::Ending(RunOutcome::BudgetExceeded),
                    "state {}: a run that recorded no budget_exceeded cannot end for budget",
                    state.id
                );
            }
            // The prefix itself: a dispatched, un-attempted generation is
            // admissible work, and there is no budget record.
            let admissible_work = [ALEPH, BET].iter().any(|key| {
                fold.task(*key).is_some_and(|task| {
                    task.generations
                        .iter()
                        .any(|generation| generation.class != GenerationClass::Closed)
                })
            });
            if admissible_work && !has_record {
                assert_eq!(
                    state.outcome,
                    DerivedOutcome::NotEnding,
                    "state {}",
                    state.id
                );
                before += 1;
            }
            if has_record && fold.halted_at().is_none() && common(fold) {
                assert_eq!(
                    state.outcome,
                    DerivedOutcome::Ending(RunOutcome::BudgetExceeded),
                    "state {}: once common holds, the record decides",
                    state.id
                );
                after += 1;
            }
        }
        // Both halves of the counterexample are populated, so neither branch
        // above is vacuous.
        assert!(before > 0, "no pre-budget_exceeded prefix was explored");
        assert!(after > 0, "no post-budget_exceeded state was explored");
    }

    #[test]
    fn every_deferred_state_has_a_legal_next_transition() {
        // `coverage_assertions`: "every state with a Deferred task or
        // verification-deferred candidate has at least one legal next
        // transition (defer_wait_elapsed when neither halting nor
        // budget-stopped; otherwise a closure transition or
        // run_finished(Halted | BudgetExceeded))".
        //
        // *Every* state, and a state the search recorded and declined to
        // extend is a state it recorded — unexpanded is not unreached. So the
        // condition is evaluated where the packet states it, against the fold,
        // rather than read off the offers the explorer happened to write down.
        //
        // The recorded table is evidence for a different claim: that the
        // answers the explorer wrote are the answers the fold gives. That is
        // asserted too, below the ceiling where there are any, and asserted as
        // agreement with the evaluation rather than in place of it.
        let census = census();
        let mut deferred_states = 0;
        let mut at_ceiling = 0;
        let mut below_ceiling = 0;
        let mut ceiling_wakes = 0;
        let mut ceiling_closes = 0;
        for state in census.states() {
            // A run that has appended its `run_finished` has ended; its
            // deferred items are void with it (Halted) or resumably open
            // (BudgetExceeded), and neither is a transition this log can still
            // make. The assertion is about live states.
            if !backoff_pending(&state.fold) || state.fold.finished().is_some() {
                continue;
            }
            deferred_states += 1;
            let at_the_ceiling = state.trace.len() >= census.bounds().max_trace;
            // The semantic answer, evaluated against the fold: every class the
            // census was explored with, offered to the real `plan_transition`
            // at this state. No successor is built, nothing is recorded, and
            // the search's ceiling is untouched — so a state the search
            // declined to extend is still a state this condition can be asked
            // of.
            let accepted: BTreeSet<String> = classes(&state.fold)
                .into_iter()
                .filter(|candidate| state.fold.plan_transition(&candidate.event).is_ok())
                .map(|candidate| candidate.label)
                .collect();
            if at_the_ceiling {
                at_ceiling += 1;
                // Nothing is recorded here, which is what makes the evaluation
                // above the only evidence rather than a second reading of the
                // explorer's own record. Pinned rather than assumed: were a
                // ceiling state extended after all, this branch would be
                // asserting about a state the other branch already covers.
                assert_eq!(
                    census.outgoing(state.id).count(),
                    0,
                    "state {} sits at the trace ceiling and was extended anyway",
                    state.id
                );
            } else {
                below_ceiling += 1;
                // Below the ceiling the explorer did record answers, and they
                // are the fold's — label for label. Asserted so the evaluation
                // above cannot be a weaker oracle quietly standing in for the
                // recorded one.
                let recorded: BTreeSet<String> = census
                    .outgoing(state.id)
                    .filter(|transition| {
                        matches!(transition.outcome, TransitionOutcome::Accepted { .. })
                    })
                    .map(|transition| transition.label.clone())
                    .collect();
                assert_eq!(
                    recorded, accepted,
                    "state {}: the recorded offers and the fold disagree about what is accepted \
                     here",
                    state.id
                );
                // And the accessor over that record. Both halves of what
                // `has_legal_transition` promises — that it is about *this*
                // state and about acceptance rather than about
                // `plan_transition` returning at all — are pinned by
                // `has_legal_transition_is_local_to_the_state_and_excludes_refusals`,
                // which is what makes this line depend on a tested predicate
                // rather than on a second reading of the same record.
                assert_eq!(
                    census.has_legal_transition(state.id),
                    !accepted.is_empty(),
                    "state {}: the accessor and the fold disagree about whether anything is \
                     accepted here",
                    state.id
                );
            }
            assert!(
                !accepted.is_empty(),
                "state {} has a deferred item and no way out: {:?}",
                state.id,
                state
                    .trace
                    .iter()
                    .map(|event| event.body.kind())
                    .collect::<Vec<_>>()
            );
            let halting = state.fold.halted_at().is_some();
            let stopped = state.fold.budget_stop().is_some();
            if !halting && !stopped {
                assert!(
                    accepted.contains("defer_wait_elapsed"),
                    "state {}: an unhalted, unstopped backoff wakes: {accepted:?}",
                    state.id
                );
                ceiling_wakes += usize::from(at_the_ceiling);
            } else {
                // `precedence_consequences`: after a halting settlement or
                // budget_exceeded, no defer_wait_elapsed is appended — halt and
                // budget outrank backoff. What remains is the closure
                // procedure: drain the in-flight settlements, complete the
                // owed promotions and publications, close the open
                // generations, and end.
                assert!(
                    !accepted.contains("defer_wait_elapsed"),
                    "state {}: halt and budget outrank backoff: {accepted:?}",
                    state.id
                );
                assert!(
                    accepted.iter().any(|label| {
                        [
                            "attempt_finished/",
                            "attempt_interrupted",
                            "candidate_prepared/",
                            "generation_closed/",
                            "task_candidate_created/",
                            "merge_prepared/",
                            "task_merged/",
                            "run_finished/",
                        ]
                        .iter()
                        .any(|closure| label.starts_with(closure))
                    }),
                    "state {}: a halted or stopped backoff closes: {accepted:?}\n  \
                     outcome={:?} halted={:?} stop={:?}\n  trace={:?}",
                    state.id,
                    state.outcome,
                    state.fold.halted_at(),
                    state.fold.budget_stop(),
                    state
                        .trace
                        .iter()
                        .map(|e| e.body.kind())
                        .collect::<Vec<_>>(),
                );
                ceiling_closes += usize::from(at_the_ceiling);
            }
        }
        assert!(deferred_states > 0, "no deferred state was explored");
        assert!(
            below_ceiling > 0,
            "every deferred state sat at the trace ceiling, so the recorded table was never \
             cross-checked against the fold"
        );
        // PR3-ST14-006: the ceiling branch is the one this assertion used to
        // skip, and a branch that runs over nothing asserts nothing. Both arms
        // of the packet's condition are required to reach it, so neither is
        // carried by the states below the ceiling alone.
        assert!(
            at_ceiling > 0,
            "no deferred state sat at the trace ceiling, so the unextended states this assertion \
             now covers are hypothetical"
        );
        assert!(
            ceiling_wakes > 0 && ceiling_closes > 0,
            "the ceiling holds {ceiling_wakes} waking and {ceiling_closes} closing deferred \
             states; both arms of the condition are owed one"
        );

        // The packet's condition names two classes — "a Deferred task **or**
        // verification-deferred candidate" — and this fixture's class set
        // offers no `merge_verification_unavailable`, so the only one it can
        // reach is the first. Stated as an assertion rather than left to be
        // discovered, and answered beside it: the second class is reached by
        // `a_verification_deferred_candidate_is_a_deferred_state_with_a_way_out`.
        assert!(
            census
                .states()
                .iter()
                .all(|state| state.fold.queue().is_none_or(|queue| queue
                    .entries()
                    .iter()
                    .all(|entry| { !entry.verification_deferred }))),
            "this fixture reached a verification-deferred candidate after all, and the assertion \
             above no longer needs its companion"
        );
    }

    /// The classes the verification-deferral census offers.
    fn deferral_classes(fold: &TopologyFold) -> Vec<Candidate> {
        let mut out = overlap_classes(fold);
        out.retain(|candidate| !candidate.label.starts_with("candidate_prepared/region-ab"));
        out.push(Candidate::new(
            "merge_verification_unavailable/deferred",
            verification_deferred_by_outage(0, 1),
        ));
        out.push(Candidate::new(
            "defer_wait_elapsed",
            ev(TopologyEventBody::DeferWaitElapsed {
                data: DeferWaitElapsed4 {
                    waited_ms: 30_000,
                    round: 1,
                },
            }),
        ));
        out
    }

    #[test]
    fn a_verification_deferred_candidate_is_a_deferred_state_with_a_way_out() {
        // The other half of `coverage_assertions`' deferred-state condition.
        // `every_deferred_state_has_a_legal_next_transition` runs over a
        // fixture whose only deferred item is a Deferred *task*, so the
        // verification-deferred candidate — a different field, on a different
        // record, cleared by a different rule — gets its own census rather
        // than a claim that the first one covered it.
        let census = Census::explore(
            started(),
            vec![run_started_event()],
            CensusBounds::default(),
            deferral_classes,
        );
        assert!(!census.truncated());
        let deferred: Vec<&CensusState> = census
            .states()
            .iter()
            .filter(|state| {
                state.fold.queue().is_some_and(|queue| {
                    queue
                        .entries()
                        .iter()
                        .any(|entry| entry.verification_deferred)
                })
            })
            .collect();
        assert!(
            !deferred.is_empty(),
            "no candidate was verification-deferred"
        );
        for state in &deferred {
            assert!(state.trace.len() < census.bounds().max_trace);
            // Neither halting nor budget-stopped, so the packet's first arm
            // applies verbatim: `defer_wait_elapsed` is the way out.
            assert!(state.fold.halted_at().is_none());
            assert!(state.fold.budget_stop().is_none());
            assert!(
                census.has_legal_transition(state.id),
                "state {} defers a verification and has no way out",
                state.id
            );
            let accepted: BTreeSet<&str> = census
                .outgoing(state.id)
                .filter(|transition| {
                    matches!(transition.outcome, TransitionOutcome::Accepted { .. })
                })
                .map(|transition| transition.label.as_str())
                .collect();
            assert!(
                accepted.contains("defer_wait_elapsed"),
                "state {}: {accepted:?}",
                state.id
            );
            // And the deferral is what makes the candidate ineligible: the
            // verification it just refused cannot be restarted from here.
            assert!(
                !accepted.contains("merge_verification_started/aleph/g0"),
                "state {}: a deferred candidate was re-offered for verification",
                state.id
            );
            // A deferred candidate holds the run open whatever else is true.
            assert_eq!(
                state.outcome,
                DerivedOutcome::NotEnding,
                "state {}",
                state.id
            );
        }
    }

    #[test]
    fn the_publication_relations_are_exercised_in_both_directions() {
        // `coverage_assertions`: every `merge_prepared(fast)` matching the
        // relation is accepted and every mismatch refused, and the stale_clean
        // and already_present relations exercised both ways. Both directions
        // of each, over the states the census actually reached.
        let census = census();
        let accepted = census.accepted_labels();
        let refused = census.refused_labels();

        for matching in [
            "merge_prepared/fast/match/aleph/g0",
            "merge_prepared/stale_clean/match/aleph/g0",
            "merge_prepared/already_present/match/aleph/g0",
        ] {
            assert!(
                accepted.contains(matching),
                "`{matching}` was never accepted: {:?}",
                accepted
                    .iter()
                    .filter(|label| label.starts_with("merge_prepared/"))
                    .collect::<Vec<_>>()
            );
        }
        for mismatching in [
            "merge_prepared/fast/moved-head/aleph/g0",
            "merge_prepared/fast/other-proposed/aleph/g0",
            "merge_prepared/fast/with-pin/aleph/g0",
            "merge_prepared/stale_clean/mismatch/aleph/g0",
            "merge_prepared/already_present/mismatch/aleph/g0",
        ] {
            assert!(
                refused.contains(mismatching),
                "`{mismatching}` was never refused"
            );
            assert!(
                !accepted.contains(mismatching),
                "`{mismatching}` was accepted somewhere, and it names a relation the fold must refuse"
            );
        }
        // A fast publication with a prepared pin is refused everywhere, which
        // is the one of the three fast clauses that is about a field's
        // presence rather than about two SHAs agreeing.
        assert!(census.transitions().iter().any(|transition| {
            transition.label == "merge_prepared/fast/with-pin/aleph/g0"
                && matches!(transition.outcome, TransitionOutcome::Refused { .. })
        }));
    }

    #[test]
    fn no_offer_is_unmapped_and_every_class_is_offered_everywhere() {
        // "no (state, event class) pair is unmapped": every offer produced an
        // acceptance or a refusal, and the count is the product rather than
        // whatever survived.
        let census = census();
        let per_state = classes(&started()).len();
        assert!(per_state > 60, "{per_state} classes is a thin census");
        let extendable = census
            .states()
            .iter()
            .filter(|state| state.trace.len() < census.bounds().max_trace)
            .count();
        assert_eq!(
            census.transitions().len(),
            extendable * per_state,
            "an offer produced neither an acceptance nor a refusal"
        );
        for transition in census.transitions() {
            match &transition.outcome {
                TransitionOutcome::Accepted { to } => assert!(*to < census.states().len()),
                TransitionOutcome::Refused { reason } => {
                    assert!(!reason.is_empty(), "{}", transition.label);
                }
                TransitionOutcome::Truncated => {
                    panic!("the census truncated at {}", transition.label)
                }
            }
        }
        // Both directions occur for the census as a whole, and the search ran
        // to exhaustion rather than stopping at its state ceiling.
        assert!(!census.accepted_labels().is_empty());
        assert!(!census.refused_labels().is_empty());
        assert!(
            !census.truncated(),
            "the census hit its state ceiling; every assertion over it is about a subset"
        );
    }

    #[test]
    fn replaying_every_explored_trace_reaches_the_state_it_was_explored_at() {
        // INV-02 over the whole explored set: the live path and the replay
        // path are one transition function, so a trace folded event by event
        // during exploration and the same trace replayed from nothing must be
        // the same state.
        let census = census();
        for state in census.states() {
            let replayed = TopologyFold::replay(inputs(), &state.trace)
                .unwrap_or_else(|error| panic!("state {} does not replay: {error}", state.id));
            assert!(
                replayed.state() == state.fold.state(),
                "state {} replays to a different state",
                state.id
            );
            assert_eq!(
                replayed.derived_outcome(),
                state.outcome,
                "state {} classifies differently live and on replay",
                state.id
            );
            // Replaying twice is equal, which is the property a resume needs
            // and a fold with hidden state would not have.
            let again = TopologyFold::replay(inputs(), &state.trace).expect("replays again");
            assert!(again.state() == replayed.state(), "state {}", state.id);
        }
    }

    #[test]
    fn the_census_reaches_every_outcome_and_says_what_it_did_not_reach() {
        let census = census();
        let reached: BTreeSet<String> = census
            .states()
            .iter()
            .filter_map(|state| match &state.outcome {
                DerivedOutcome::Ending(outcome) => Some(format!("{outcome:?}")),
                _ => None,
            })
            .collect();
        for outcome in ["Complete", "Halted", "BudgetExceeded", "Parked"] {
            assert!(
                reached.contains(outcome),
                "{outcome} unreached: {reached:?}"
            );
        }
        // And each is accepted as a `run_finished` exactly where it is derived
        // and refused everywhere else: the guard is a comparison, not a
        // validity check.
        let mut compared = 0;
        for state in census.states() {
            // A second `run_finished` is refused whatever the derived outcome,
            // so the comparison the guard makes is only visible before the
            // first one. Both halves are asserted.
            if state.fold.finished().is_some() {
                for outcome in [
                    RunOutcome::Complete,
                    RunOutcome::Parked,
                    RunOutcome::Halted,
                    RunOutcome::BudgetExceeded,
                ] {
                    let event = run_finished(&state.fold, outcome.clone());
                    assert!(
                        state.fold.plan_transition(&event).is_err(),
                        "state {}: a run ends once",
                        state.id
                    );
                }
                continue;
            }
            for outcome in [
                RunOutcome::Complete,
                RunOutcome::Parked,
                RunOutcome::Halted,
                RunOutcome::BudgetExceeded,
            ] {
                let event = run_finished(&state.fold, outcome.clone());
                let accepted = state.fold.plan_transition(&event).is_ok();
                assert_eq!(
                    accepted,
                    state.outcome == DerivedOutcome::Ending(outcome.clone()),
                    "state {}: run_finished({outcome:?}) against {:?}",
                    state.id,
                    state.outcome
                );
                compared += 1;
            }
        }
        assert!(compared > 100, "only {compared} guards were compared");
    }

    #[test]
    fn the_skeleton_states_the_bounds_it_ran_under_and_the_ones_it_did_not() {
        // What this slice does *not* establish, as an assertion rather than as
        // a paragraph: the fixture is two originals with no repairs, and the
        // packet's bounds are three originals with two repairs and two
        // lineages. PR10 raises them; nothing here should read as if it
        // already had.
        let bounds = CensusBounds::default();
        assert_eq!(bounds.originals, 3);
        assert_eq!(bounds.repairs, 2);
        assert_eq!(bounds.generations_per_task, 2);
        assert_eq!(bounds.attempts_per_generation, 2);
        assert_eq!(bounds.sequences, 4);
        assert_eq!(bounds.defers, 2);

        let census = census();
        let registry = started().registry().expect("started").len();
        assert_eq!(registry, 2, "the fixture plan is two originals");
        assert!(
            u32::try_from(registry).unwrap_or(u32::MAX) < bounds.originals,
            "the skeleton runs below the design's bound and says so"
        );
        // No repair is spawned by any class this skeleton offers, so no
        // lineage lease is ever taken: the lineage half of the census is
        // PR10's.
        assert!(
            !census
                .transitions()
                .iter()
                .any(|transition| transition.label.starts_with("task_spawned/")),
            "the skeleton offers no repair spawn"
        );
        for state in census.states() {
            assert!(
                state
                    .fold
                    .leases()
                    .is_none_or(|leases| leases.lineages().is_empty()),
                "state {} holds a lineage lease the skeleton cannot have made",
                state.id
            );
        }
    }

    #[test]
    fn the_fixture_varies_every_field_a_relation_reads() {
        // Distinct-value counts, so "hostile" is checkable.
        let started = run_started();
        // Three limits, three numbers.
        let limits = BTreeSet::from([
            started.limits.max_parallel,
            started.limits.max_defers,
            started.limits.max_merge_repairs,
        ]);
        assert_eq!(limits.len(), 3, "a fold reading one limit for another");
        // Four efforts, four values.
        let efforts = BTreeSet::from([
            format!("{:?}", started.effort_policy.small),
            format!("{:?}", started.effort_policy.mid),
            format!("{:?}", started.effort_policy.frontier),
            format!("{:?}", started.effort_policy.review),
        ]);
        assert_eq!(efforts.len(), 4);
        // The two tasks differ in ladder length, attempts allowance, kind and
        // region, so no relation over them can pass by symmetry.
        assert_ne!(started.chains[0].tiers.len(), started.chains[1].tiers.len());
        assert_ne!(
            started.chains[0].attempts_per,
            started.chains[1].attempts_per
        );
        assert_ne!(region(ALEPH), region(BET));
        // Every symbolic sha a relation compares is a different literal: base,
        // the two candidate commits, the moved head, the proposal, and the
        // three deliberate non-matches.
        let shas = BTreeSet::from([
            sha("base"),
            candidate_of(ALEPH, 0).commit_sha,
            candidate_of(BET, 0).commit_sha,
            sha("moved-head"),
            sha("proposal-aleph"),
            sha("proposal-bet"),
            sha("not-the-candidate"),
            sha("not-the-pinned-proposal"),
            sha("not-the-head"),
            sha("tree-aleph"),
        ]);
        assert_eq!(shas.len(), 10, "two roles share a literal");
        // The digest is derived from the record rather than pinned, so a
        // fixture whose plan moved fails to start rather than folding on a
        // guess.
        assert_ne!(started.registry_digest, String::new());
        assert_ne!(started.registry_digest, started.normalized_plan_digest);
    }

    #[test]
    fn a_census_that_hits_its_ceiling_says_so() {
        // The truncation flag is the one thing standing between "explored
        // everything" and "explored the first six hundred", so it is asserted
        // in both directions rather than trusted.
        let tight = CensusBounds {
            max_states: 3,
            ..CensusBounds::default()
        };
        let stopped = Census::explore(started(), vec![run_started_event()], tight, classes);
        assert!(stopped.truncated());
        assert!(stopped.states().len() <= 3);
        assert!(!census().truncated());

        // And the trace ceiling bounds the search without silently dropping
        // offers: a state at the ceiling is recorded and simply not extended.
        let shallow = CensusBounds {
            // The seed trace already holds `run_started`, so a ceiling of two
            // extends the root and nothing beyond it.
            max_trace: 2,
            ..CensusBounds::default()
        };
        let shallow = Census::explore(started(), vec![run_started_event()], shallow, classes);
        assert!(!shallow.truncated());
        assert!(shallow.states().len() > 1);
        assert_eq!(
            shallow.transitions().len(),
            classes(&started()).len(),
            "only the root was extended"
        );
    }

    #[test]
    fn a_transaction_class_is_reachable_and_blocks_the_run_from_ending() {
        // The one relation the totality oracle above leans on hardest — that
        // an unresolved integration transaction makes `common` false — needs
        // a state that actually has one, or the oracle is asserting over an
        // empty set.
        let census = census();
        let with_transaction: Vec<&CensusState> = census
            .states()
            .iter()
            .filter(|state| state.fold.transaction().is_some())
            .collect();
        assert!(
            !with_transaction.is_empty(),
            "no state held an unresolved transaction"
        );
        for state in &with_transaction {
            assert_eq!(
                state.outcome,
                DerivedOutcome::NotEnding,
                "state {}",
                state.id
            );
        }
        // Both transaction classes are reached, so `common` is false for the
        // verification-running case and for the publication-owed case alike.
        let classes_seen: BTreeSet<&'static str> = with_transaction
            .iter()
            .map(|state| {
                match state
                    .fold
                    .transaction()
                    .map(|transaction| &transaction.class)
                {
                    Some(TransactionClass::VerificationStarted { .. }) => "verification",
                    Some(TransactionClass::Prepared { .. }) => "prepared",
                    None => "none",
                }
            })
            .collect();
        assert_eq!(
            classes_seen,
            BTreeSet::from(["verification", "prepared"]),
            "{classes_seen:?}"
        );
    }
    // -----------------------------------------------------------------------
    // PR3-ST14-001 — the totality assertion's own independence
    // -----------------------------------------------------------------------

    /// A hand-built state, for feeding the checker something the explorer
    /// would never produce.
    fn state_at(id: usize, fold: TopologyFold, outcome: DerivedOutcome) -> CensusState {
        CensusState {
            id,
            trace: Vec::new(),
            fold,
            outcome,
        }
    }

    /// A fold the census actually reached whose outcome is this one.
    fn fold_with(outcome: &DerivedOutcome) -> TopologyFold {
        census()
            .states_with(outcome)
            .first()
            .unwrap_or_else(|| panic!("no census state is {outcome:?}"))
            .fold
            .clone()
    }

    #[test]
    fn the_totality_audit_reports_a_fold_error_a_normalisation_and_a_short_domain() {
        // `the_derived_outcome_is_total_over_every_explored_state` asserts
        // through `TotalityAudit`, and on the real census every list it
        // returns is empty — which is also what a checker that does nothing
        // returns. So the checker is shown three failures it must report,
        // built by hand because a census cannot be asked to produce them.
        let ending = fold_with(&DerivedOutcome::Ending(RunOutcome::Complete));
        let not_ending = started();

        // (1) Filtering. A `FoldError` is reported even when it is only the
        // *recorded* value and a fresh evaluation of the fold beside it
        // disagrees: a checker that quietly preferred one side could reach
        // zero by discarding the other.
        let sentinel = vec![
            state_at(0, not_ending.clone(), DerivedOutcome::NotEnding),
            state_at(1, ending.clone(), DerivedOutcome::FoldError),
        ];
        let audit = TotalityAudit::over(&sentinel);
        assert_eq!(audit.fold_errors, vec![1]);
        assert_eq!(audit.evaluated, vec![0, 1]);

        // (2) Normalising. A state recorded `NotEnding` over a fold that ends
        // is a disagreement, named by id rather than resolved.
        let normalised = vec![state_at(0, ending.clone(), DerivedOutcome::NotEnding)];
        let audit = TotalityAudit::over(&normalised);
        assert_eq!(audit.disagreements, vec![0]);
        assert!(audit.fold_errors.is_empty());
        assert_eq!((audit.not_ending, audit.ending), (0, 1));

        // (3) Skipping. The domain is what it was handed, in order, so a
        // caller comparing it with the ids something else computed sees a gap
        // rather than a shorter list that still looks total.
        let short = vec![
            state_at(0, not_ending.clone(), DerivedOutcome::NotEnding),
            state_at(2, not_ending.clone(), DerivedOutcome::NotEnding),
        ];
        let audit = TotalityAudit::over(&short);
        assert_eq!(audit.evaluated, vec![0, 2]);
        assert_ne!(audit.evaluated, vec![0, 1]);

        // And the honest list, so the three above are differences rather than
        // the only thing this checker ever says.
        let clean = vec![
            state_at(0, not_ending, DerivedOutcome::NotEnding),
            state_at(1, ending, DerivedOutcome::Ending(RunOutcome::Complete)),
        ];
        let audit = TotalityAudit::over(&clean);
        assert!(audit.fold_errors.is_empty() && audit.disagreements.is_empty());
        assert_eq!((audit.not_ending, audit.ending), (1, 1));
    }

    #[test]
    fn the_census_transition_table_is_reproducible_from_the_folds_alone() {
        // PR3-ST14-001, the half no loop over `states()` can reach: a
        // successor that was dropped before it was recorded is not in
        // `states()`, so nothing that reads `states()` can miss it.
        //
        // This does not read the record and check it for consistency with
        // itself. It re-derives the whole table from the folds and the class
        // function — the real `plan_transition`, the real `apply_delta` — and
        // requires the record to be what that derivation produced. Every way
        // the explorer could edit its own evidence lands here: an accepted
        // offer filed as a refusal, a refusal filed as an acceptance, an edge
        // pointing at a state that is not the one applying the delta reaches,
        // an outcome rewritten on the way in, or a row no offer produced.
        let census = census();
        let mut rows = 0usize;
        for state in census.states() {
            let recorded: Vec<&CensusTransition> = census.outgoing(state.id).collect();
            if state.trace.len() >= census.bounds().max_trace {
                assert!(
                    recorded.is_empty(),
                    "state {} sits at the trace ceiling and was extended anyway",
                    state.id
                );
                assert!(
                    !census.has_legal_transition(state.id),
                    "state {} was never extended and reports a transition",
                    state.id
                );
                continue;
            }
            let offers = classes(&state.fold);
            assert_eq!(
                recorded.len(),
                offers.len(),
                "state {} recorded {} answers for {} offers",
                state.id,
                recorded.len(),
                offers.len()
            );
            let mut any_accepted = false;
            for (offer, row) in offers.iter().zip(&recorded) {
                assert_eq!(row.from, state.id);
                assert_eq!(row.label, offer.label, "state {}", state.id);
                match (state.fold.plan_transition(&offer.event), &row.outcome) {
                    (Err(error), TransitionOutcome::Refused { reason }) => {
                        assert_eq!(*reason, error.to_string(), "state {}", state.id);
                    }
                    (Ok(delta), TransitionOutcome::Accepted { to }) => {
                        any_accepted = true;
                        let mut next = state.fold.clone();
                        next.apply_delta(delta);
                        let landed = &census.states()[*to];
                        assert_eq!(
                            fingerprint(&next),
                            fingerprint(&landed.fold),
                            "state {} --{}--> {to} is not the state applying it reaches",
                            state.id,
                            offer.label
                        );
                        assert_eq!(
                            landed.outcome,
                            next.derived_outcome(),
                            "state {to} was recorded with an outcome its own fold does not give"
                        );
                    }
                    (Ok(_), answer) => panic!(
                        "state {}: the fold accepts `{}` and the census recorded {answer:?}",
                        state.id, offer.label
                    ),
                    (Err(error), answer) => panic!(
                        "state {}: the fold refuses `{}` with `{error}` and the census recorded \
                         {answer:?}",
                        state.id, offer.label
                    ),
                }
                rows += 1;
            }
            // And the public accessor, re-derived without reading the
            // transition list at all: an accepted delta exists *at this state*
            // or it does not.
            assert_eq!(
                census.has_legal_transition(state.id),
                any_accepted,
                "state {}",
                state.id
            );
        }
        assert_eq!(
            rows,
            census.transitions().len(),
            "the census holds a row no offer produced"
        );
    }

    #[test]
    fn the_seed_state_is_evaluated_rather_than_assumed_not_ending() {
        // A3-ST14-021: an explorer that writes `NotEnding` for its seed — the
        // one state no transition produced — and evaluates only the
        // successors. Every assertion over a census seeded from `started()`
        // survives it, because that seed *is* NotEnding.
        //
        // So the seed is one the answer cannot be guessed at: a state the
        // census itself reached with the run already over, re-explored under a
        // trace ceiling that extends nothing.
        let ended = census()
            .states()
            .iter()
            .find(|state| {
                state.fold.finished().is_some()
                    && state.outcome == DerivedOutcome::Ending(RunOutcome::Complete)
            })
            .expect("the census reaches a completed run");
        let bounds = CensusBounds {
            max_trace: 0,
            ..CensusBounds::default()
        };
        let seeded = Census::explore(ended.fold.clone(), ended.trace.clone(), bounds, classes);
        assert_eq!(seeded.states().len(), 1, "nothing was extended");
        assert!(seeded.transitions().is_empty());
        assert!(!seeded.truncated());
        assert_eq!(
            seeded.states()[0].outcome,
            DerivedOutcome::Ending(RunOutcome::Complete),
            "the seed was assumed rather than evaluated"
        );
        let audit = seeded.totality_audit();
        assert_eq!(audit.evaluated, vec![0]);
        assert!(audit.disagreements.is_empty() && audit.fold_errors.is_empty());
        assert_eq!((audit.not_ending, audit.ending), (0, 1));
    }

    // -----------------------------------------------------------------------
    // PR3-ST14-003 — what `has_legal_transition` promises
    // -----------------------------------------------------------------------

    /// A merge no state of this fixture accepts: there is no open transaction
    /// for it to resolve.
    fn unresolvable_merge() -> TopologyEvent {
        ev(TopologyEventBody::TaskMerged {
            data: TaskMerged {
                sequence: SequenceId(0),
                merged_sha: sha("base"),
                satisfies: vec![ALEPH],
                lease_release: MergeLeaseRelease::Candidate {
                    key: ALEPH,
                    generation: GenerationId(0),
                },
            },
        })
    }

    fn only_refused(_: &TopologyFold) -> Vec<Candidate> {
        vec![Candidate::new(
            "task_merged/no-transaction",
            unresolvable_merge(),
        )]
    }

    fn dispatch_once_then_dead(fold: &TopologyFold) -> Vec<Candidate> {
        let mut out = only_refused(fold);
        if fold
            .task(ALEPH)
            .is_none_or(|task| task.generations.is_empty())
        {
            out.push(Candidate::new(
                "task_dispatched/aleph/g0",
                dispatch(ALEPH, 0),
            ));
        }
        out
    }

    #[test]
    fn has_legal_transition_is_local_to_the_state_and_excludes_refusals() {
        // PR3-ST14-003. `every_deferred_state_has_a_legal_next_transition`
        // only ever asserts this accessor *true*, so a predicate that answers
        // true too often passes it: a global existential over the whole
        // census, or one that counts a refusal as progress. Both are answered
        // here by censuses in which the honest answer is `false`.

        // Refusals only. `plan_transition` returning `Err` is the fold
        // working, not the run moving.
        let refusals = Census::explore(
            started(),
            vec![run_started_event()],
            CensusBounds::default(),
            only_refused,
        );
        assert_eq!(refusals.states().len(), 1);
        assert_eq!(refusals.transitions().len(), 1);
        assert!(matches!(
            refusals.transitions()[0].outcome,
            TransitionOutcome::Refused { .. }
        ));
        assert!(
            !refusals.has_legal_transition(0),
            "every offer at this state was refused"
        );

        // Locality: one state that can move beside one that cannot. A global
        // existential answers `true` at both.
        let mixed = Census::explore(
            started(),
            vec![run_started_event()],
            CensusBounds::default(),
            dispatch_once_then_dead,
        );
        assert_eq!(mixed.states().len(), 2, "one live state and one dead one");
        assert!(mixed.has_legal_transition(0), "the root dispatches");
        assert!(
            !mixed.has_legal_transition(1),
            "the dispatched state has no accepted offer of its own"
        );
        // The dead state's offers were made and answered; it is not a state
        // the search declined to extend.
        assert_eq!(mixed.outgoing(1).count(), 1);
        // An id no state carries has no offers, and so no legal transition —
        // the answer a whole-census existential cannot give.
        assert!(!mixed.has_legal_transition(2));
        assert!(!mixed.has_legal_transition(usize::MAX));
    }

    // -----------------------------------------------------------------------
    // PR3-ST14-002 — what the abstraction key must keep
    // -----------------------------------------------------------------------

    /// A stale-clean verification of a candidate, with the three fields the
    /// `merge_prepared` relations are about named.
    fn verification_started(
        sequence: u32,
        key: TaskKey,
        generation: u32,
        pin: &str,
        expected_head: CommitSha,
        proposed_sha: CommitSha,
    ) -> TopologyEvent {
        ev(TopologyEventBody::MergeVerificationStarted {
            data: MergeVerificationStarted {
                sequence: SequenceId(sequence),
                candidate: candidate_of(key, generation),
                basis: VerificationBasis::StaleClean {
                    prepared_ref: git_ref(pin),
                },
                expected_head,
                proposed_sha,
            },
        })
    }

    fn verification_parked(sequence: u32, key: TaskKey, id: &str) -> TopologyEvent {
        ev(TopologyEventBody::MergeVerificationUnavailable {
            data: MergeVerificationUnavailable {
                sequence: SequenceId(sequence),
                cause: UnavailableCause::HumanRequired {
                    verdict: "  a reviewer found something only a person decides  ".to_owned(),
                },
                outcome: UnavailableOutcome::Parked {
                    question: crate::topology::events::FrozenQuestion {
                        id: QuestionId::from(id),
                        key,
                        kind: QuestionKind::Unblock,
                        context: "  the verification could not run  ".to_owned(),
                        options: vec!["retry".to_owned(), "abandon".to_owned()],
                    },
                },
            },
        })
    }

    fn verification_deferred_by_outage(sequence: u32, defers: u32) -> TopologyEvent {
        ev(TopologyEventBody::MergeVerificationUnavailable {
            data: MergeVerificationUnavailable {
                sequence: SequenceId(sequence),
                cause: UnavailableCause::Infrastructure {
                    kind: InfrastructureKind::RateLimited,
                },
                outcome: UnavailableOutcome::Deferred { defers },
            },
        })
    }

    /// The prefix every abstraction witness below shares: one task's
    /// generation carried as far as a queued candidate over `paths`.
    fn queued_candidate_trace(paths: PathSet) -> Vec<TopologyEvent> {
        let mut fold = started();
        let mut trace = vec![run_started_event()];
        for event in [
            dispatch(ALEPH, 0),
            attempt_started(&fold, ALEPH, 0, 1),
            settle(
                ALEPH,
                0,
                1,
                SettlementTransition::Succeeded,
                LeaseDisposition::PredictedRetained,
            ),
            candidate_prepared_over(ALEPH, 0, 1, paths.clone()),
            candidate_created(ALEPH, 0),
        ] {
            let delta = fold
                .plan_transition(&event)
                .unwrap_or_else(|error| panic!("the shared prefix applies: {error}"));
            fold.apply_delta(delta);
            trace.push(event);
        }
        trace
    }

    /// The two candidate-side witnesses' shared prefix: `aleph`'s first
    /// generation carried to a queued candidate, with the two labels the fast
    /// publication relations compare a candidate against as parameters.
    ///
    /// Each label is carried by more than one event, and the fold is why: it
    /// refuses a `candidate_prepared` whose base disagrees with its
    /// generation's dispatch, one whose parent is not its own base, and a
    /// `task_candidate_created` promoting a commit the prepared record does not
    /// hold. So the reachable unit of variation is one *label* across a trace
    /// rather than one field of one event — checked on the trace by
    /// [`WitnessShape::OneLabel`] and on the state the fold kept by
    /// [`RecordedOperand`].
    fn queued_candidate_at(base: CommitSha, commit: CommitSha) -> Vec<TopologyEvent> {
        let mut fold = started();
        let mut trace = vec![run_started_event()];
        for event in [
            dispatch_at(ALEPH, 0, region(ALEPH), base.clone()),
            attempt_started(&fold, ALEPH, 0, 1),
            settle(
                ALEPH,
                0,
                1,
                SettlementTransition::Succeeded,
                LeaseDisposition::PredictedRetained,
            ),
            candidate_prepared_at(ALEPH, 0, 1, region(ALEPH), base, commit.clone()),
            candidate_created_of(candidate_at(ALEPH, 0, commit)),
        ] {
            let delta = fold
                .plan_transition(&event)
                .unwrap_or_else(|error| panic!("a candidate-side prefix applies: {error}"));
            fold.apply_delta(delta);
            trace.push(event);
        }
        trace
    }

    /// The fast publication of `aleph`'s first candidate at one head.
    ///
    /// The two labels are the offer side of the two relations
    /// `decisions.bounded_census.abstraction` retains, so an offer built from
    /// one witness leg's own labels is exactly the question the other leg has
    /// to answer differently. How each is compared differs, and the refusals
    /// the witnesses draw say which:
    ///
    /// * *the base* — `check_merge_prepared`'s own line, refusals[9]: the head
    ///   a fast publication expects is the candidate's recorded base.
    /// * *the commit* — through the identity the publication cites, because
    ///   `self_consistency` refuses a fast publication whose `proposed_sha` is
    ///   not the commit it names and `prepared_candidate` refuses a citation of
    ///   a commit the log never recorded. The two compose into "proposed_sha
    ///   versus the candidate's commit label", and the fold's own later
    ///   comparison of the two is unreachable for a well-formed fast event.
    fn fast_publication(base: CommitSha, commit: CommitSha) -> TopologyEvent {
        merge_prepared_for(
            0,
            candidate_at(ALEPH, 0, commit.clone()),
            PreparedDisposition::Fast,
            base,
            commit,
            None,
            VerificationSource::CandidatePrepared {
                key: ALEPH,
                generation: GenerationId(0),
            },
        )
    }

    /// The `candidate_prepared` record `aleph`'s first generation kept.
    fn prepared_record(fold: &TopologyFold) -> PreparedCandidate {
        fold.task(ALEPH)
            .and_then(|task| task.generations.first())
            .and_then(|generation| generation.candidate.clone())
            .expect("a candidate-side witness leg prepares a candidate")
    }

    fn replayed(trace: &[TopologyEvent]) -> TopologyFold {
        TopologyFold::replay(inputs(), trace)
            .unwrap_or_else(|error| panic!("a witness trace does not replay: {error}"))
    }

    /// How a witness pair's two traces are known to differ by one thing.
    enum WitnessShape {
        /// One event replaced, and one string-valued field of it changed:
        /// substituting the old value for the new in the replaced event's own
        /// rendering reproduces it exactly, which no two-field change does.
        OneField { from: String, to: String },
        /// One symbolic label replaced throughout, in however many events
        /// carry it: substituting the old label for the new across the whole
        /// trace's rendering reproduces it exactly, so nothing else moved.
        ///
        /// Distinct from [`Self::OneField`] rather than a laxer version of it
        /// — a pair that moves one event is required to declare itself
        /// `OneField`, so this variant cannot become the place a two-field
        /// change hides.
        OneLabel { from: String, to: String },
        /// One event replaced through a helper that takes the region as its
        /// only parameter.
        OneRegion,
        /// One event appended whose whole documented effect is the relation.
        OneAppend,
        /// The same events in a different order.
        Reordered,
    }

    /// The one field of the recorded [`PreparedCandidate`] a candidate-side
    /// witness moves.
    ///
    /// [`WitnessShape`] is a claim about the two traces; this is the same claim
    /// about the state the fold kept, and they are not the same claim. A trace
    /// that varies one label could still leave the fold recording two
    /// differences, or none, and it is the record that the relations read.
    /// Checked the way `OneField` checks an event: copy the named field across
    /// and require the two records to become equal.
    enum RecordedOperand {
        Base,
        Commit,
    }

    impl RecordedOperand {
        fn copied(
            &self,
            from: &PreparedCandidate,
            mut into: PreparedCandidate,
        ) -> PreparedCandidate {
            match self {
                Self::Base => into.base_sha = from.base_sha.clone(),
                Self::Commit => into.candidate.commit_sha = from.candidate.commit_sha.clone(),
            }
            into
        }
    }

    struct RelationWitness {
        relation: &'static str,
        left: Vec<TopologyEvent>,
        right: Vec<TopologyEvent>,
        shape: WitnessShape,
        /// A pair of offers, the first accepted at `left` and refused at
        /// `right` and the second the mirror. A fingerprint difference says
        /// the key kept the relation; this says the relation was worth
        /// keeping.
        opposed: Option<(TopologyEvent, TopologyEvent)>,
        /// What the two legs' recorded candidates differ in, when the witness
        /// varies the candidate side.
        recorded: Option<RecordedOperand>,
    }

    fn abstraction_witnesses() -> Vec<RelationWitness> {
        let base = queued_candidate_trace(region(ALEPH));
        let verification = |pin: &str, head: CommitSha, proposed: CommitSha| {
            let mut trace = base.clone();
            trace.push(verification_started(0, ALEPH, 0, pin, head, proposed));
            trace
        };
        let deferred = {
            let mut trace = verification("prepared/0", sha("moved-head"), sha("proposal-aleph"));
            trace.push(verification_deferred_by_outage(0, 1));
            trace
        };
        let mut woken = deferred.clone();
        woken.push(ev(TopologyEventBody::DeferWaitElapsed {
            data: DeferWaitElapsed4 {
                waited_ms: 30_000,
                round: 1,
            },
        }));

        // Two candidates, queued in each order. The same events, so nothing
        // but the queue's order can tell the two states apart.
        let mut aleph_first = vec![run_started_event()];
        let mut bet_first = vec![run_started_event()];
        for key in [ALEPH, BET] {
            let mut fold = started();
            let mut leg = Vec::new();
            for event in [
                dispatch(key, 0),
                attempt_started(&fold, key, 0, 1),
                settle(
                    key,
                    0,
                    1,
                    SettlementTransition::Succeeded,
                    LeaseDisposition::PredictedRetained,
                ),
                candidate_prepared(key, 0, 1),
                candidate_created(key, 0),
            ] {
                if let Ok(delta) = fold.plan_transition(&event) {
                    fold.apply_delta(delta);
                }
                leg.push(event);
            }
            if key == ALEPH {
                aleph_first.splice(1..1, leg.clone());
                bet_first.extend(leg);
            } else {
                aleph_first.extend(leg.clone());
                bet_first.splice(1..1, leg);
            }
        }

        // The candidate side of the two fast relations. `expected_head` and
        // `proposed_sha` above vary the *offer*; these vary what an offer is
        // compared against — the candidate's own base and its own commit —
        // which no offer-side witness reaches, because the fixture hardcodes
        // one base and derives one commit per key and generation. So a key
        // that dropped either operand would confuse two states the fast
        // relation answers oppositely, and every witness above would stay
        // green. See `fast_publication` for which comparison each draws.
        let shared_commit = candidate_of(ALEPH, 0).commit_sha;
        let base_a = sha("candidate-base-a");
        let base_b = sha("candidate-base-b");
        let commit_one = sha("candidate-commit-one");
        let commit_two = sha("candidate-commit-two");

        vec![
            RelationWitness {
                relation: "the region a candidate's lease holds (A versus AB)",
                left: base.clone(),
                right: queued_candidate_trace(overlap_region()),
                shape: WitnessShape::OneRegion,
                opposed: None,
                recorded: None,
            },
            RelationWitness {
                relation: "merge_prepared: expected_head",
                left: verification("prepared/0", sha("moved-head"), sha("proposal-aleph")),
                right: verification("prepared/0", sha("other-head"), sha("proposal-aleph")),
                shape: WitnessShape::OneField {
                    from: sha("moved-head").0,
                    to: sha("other-head").0,
                },
                opposed: None,
                recorded: None,
            },
            RelationWitness {
                relation: "merge_prepared: proposed_sha",
                left: verification("prepared/0", sha("moved-head"), sha("proposal-aleph")),
                right: verification("prepared/0", sha("moved-head"), sha("other-proposal")),
                shape: WitnessShape::OneField {
                    from: sha("proposal-aleph").0,
                    to: sha("other-proposal").0,
                },
                opposed: None,
                recorded: None,
            },
            RelationWitness {
                relation: "merge_prepared: the pinned proposal ref",
                left: verification("prepared/0", sha("moved-head"), sha("proposal-aleph")),
                right: verification("prepared/9", sha("moved-head"), sha("proposal-aleph")),
                shape: WitnessShape::OneField {
                    from: git_ref("prepared/0").0,
                    to: git_ref("prepared/9").0,
                },
                opposed: None,
                recorded: None,
            },
            RelationWitness {
                relation: "verification_deferred on a queued candidate",
                left: deferred,
                right: woken,
                shape: WitnessShape::OneAppend,
                opposed: None,
                recorded: None,
            },
            RelationWitness {
                relation: "the queue's order",
                left: aleph_first,
                right: bet_first,
                shape: WitnessShape::Reordered,
                opposed: None,
                recorded: None,
            },
            RelationWitness {
                relation: "merge_prepared: the candidate's own base label",
                left: queued_candidate_at(base_a.clone(), shared_commit.clone()),
                right: queued_candidate_at(base_b.clone(), shared_commit.clone()),
                shape: WitnessShape::OneLabel {
                    from: base_a.0.clone(),
                    to: base_b.0.clone(),
                },
                opposed: Some((
                    fast_publication(base_a, shared_commit.clone()),
                    fast_publication(base_b, shared_commit),
                )),
                recorded: Some(RecordedOperand::Base),
            },
            RelationWitness {
                relation: "merge_prepared: the candidate's own commit label",
                left: queued_candidate_at(sha("base"), commit_one.clone()),
                right: queued_candidate_at(sha("base"), commit_two.clone()),
                shape: WitnessShape::OneLabel {
                    from: commit_one.0.clone(),
                    to: commit_two.0.clone(),
                },
                opposed: Some((
                    fast_publication(sha("base"), commit_one),
                    fast_publication(sha("base"), commit_two),
                )),
                recorded: Some(RecordedOperand::Commit),
            },
        ]
    }

    #[test]
    fn the_abstraction_key_separates_states_that_differ_in_one_retained_relation() {
        // PR3-ST14-002. A key that forgets a relation cannot be caught by
        // looking at what the census explored: the two states it confuses
        // become one, and the second is never recorded, so nothing downstream
        // has anything to miss. It is caught by handing it two states that
        // differ in exactly one retained relation and requiring two answers.
        //
        // `decisions.bounded_census.abstraction`: "all relational predicates
        // used by plan_transition retained (... overlap ... verification_deferred
        // and defers per candidate ... queue order ... and the merge_prepared
        // relations — expected_head versus the candidate's base label,
        // proposed_sha versus the candidate's commit label or the pinned
        // proposal label, prepared_ref presence)".
        //
        // PR3-ST14-005: two of those relations have an operand on each side.
        // `expected_head` and `proposed_sha` are the offer's; the candidate's
        // base and the candidate's commit are the state's, and a key that
        // dropped either would leave every offer-side witness green. They get
        // witnesses of their own below, and a second obligation with them:
        // distinct fingerprints, *and* one fast publication that the two legs
        // answer in opposite directions.
        let witnesses = abstraction_witnesses();
        assert!(witnesses.len() >= 8);
        for witness in &witnesses {
            let left = replayed(&witness.left);
            let right = replayed(&witness.right);
            let name = witness.relation;

            // The witness is one difference, checked rather than asserted into
            // being by the way it was written.
            match &witness.shape {
                WitnessShape::OneField { from, to } => {
                    assert_eq!(witness.left.len(), witness.right.len(), "{name}");
                    let differing: Vec<usize> = (0..witness.left.len())
                        .filter(|index| witness.left[*index] != witness.right[*index])
                        .collect();
                    assert_eq!(differing.len(), 1, "{name}: not one event");
                    let index = differing[0];
                    let before = format!("{:?}", witness.left[index].body);
                    let after = format!("{:?}", witness.right[index].body);
                    assert_ne!(before, after, "{name}");
                    assert_eq!(
                        before.replace(from.as_str(), to.as_str()),
                        after,
                        "{name}: more than one field moved"
                    );
                }
                WitnessShape::OneLabel { from, to } => {
                    assert_eq!(witness.left.len(), witness.right.len(), "{name}");
                    let differing = (0..witness.left.len())
                        .filter(|index| witness.left[*index] != witness.right[*index])
                        .count();
                    assert!(
                        differing > 1,
                        "{name}: one event moved, so `OneField` is the honest shape and the \
                         stricter check"
                    );
                    let rendered = |trace: &[TopologyEvent]| {
                        trace
                            .iter()
                            .map(|event| format!("{:?}", event.body))
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    assert_eq!(
                        rendered(&witness.left).replace(from.as_str(), to.as_str()),
                        rendered(&witness.right),
                        "{name}: more than one label moved"
                    );
                }
                WitnessShape::OneRegion => {
                    assert_eq!(witness.left.len(), witness.right.len(), "{name}");
                    let differing = (0..witness.left.len())
                        .filter(|index| witness.left[*index] != witness.right[*index])
                        .count();
                    assert_eq!(differing, 1, "{name}: not one event");
                }
                WitnessShape::OneAppend => {
                    assert_eq!(witness.right.len(), witness.left.len() + 1, "{name}");
                    assert_eq!(
                        witness.right[..witness.left.len()],
                        witness.left[..],
                        "{name}"
                    );
                }
                WitnessShape::Reordered => {
                    assert_ne!(witness.left, witness.right, "{name}");
                    let sorted = |trace: &[TopologyEvent]| {
                        let mut rendered: Vec<String> = trace
                            .iter()
                            .map(|event| format!("{:?}", event.body))
                            .collect();
                        rendered.sort();
                        rendered
                    };
                    assert_eq!(sorted(&witness.left), sorted(&witness.right), "{name}");
                }
            }

            // The trace's one difference, again as one difference in the
            // record the relations actually read.
            if let Some(operand) = &witness.recorded {
                let (kept_left, kept_right) = (prepared_record(&left), prepared_record(&right));
                assert_ne!(
                    kept_left, kept_right,
                    "{name}: the two legs record the same candidate"
                );
                assert_eq!(
                    operand.copied(&kept_left, kept_right),
                    kept_left,
                    "{name}: more than one recorded field moved"
                );
            }

            // And the two answers the key owes.
            assert!(
                left.state() != right.state(),
                "{name}: the witness pair is one state, so it witnesses nothing"
            );
            assert_ne!(
                fingerprint(&left),
                fingerprint(&right),
                "the key does not read {name}"
            );

            // For the candidate-side pairs, what the difference is *for*: one
            // publication, accepted at one leg and refused at the other. Both
            // directions, so a leg that refuses everything — an unreachable
            // trace, a candidate that never queued — cannot pass for a witness
            // by refusing the one offer aimed at it.
            if let Some((for_left, for_right)) = &witness.opposed {
                assert!(
                    left.plan_transition(for_left).is_ok(),
                    "{name}: the publication built from the left leg's own labels is refused \
                     there: {:?}",
                    left.plan_transition(for_left).err()
                );
                assert!(
                    right.plan_transition(for_left).is_err(),
                    "{name}: the left leg's publication is accepted at the right leg too, so the \
                     two states answer it alike"
                );
                assert!(
                    right.plan_transition(for_right).is_ok(),
                    "{name}: the publication built from the right leg's own labels is refused \
                     there: {:?}",
                    right.plan_transition(for_right).err()
                );
                assert!(
                    left.plan_transition(for_right).is_err(),
                    "{name}: the right leg's publication is accepted at the left leg too, so the \
                     two states answer it alike"
                );
            }
        }
        // Every relation named once, so a witness cannot be counted twice.
        let named: BTreeSet<&str> = witnesses.iter().map(|witness| witness.relation).collect();
        assert_eq!(named.len(), witnesses.len());
        // And the second obligation is carried by both candidate-side operands
        // rather than by whichever one was written first.
        assert_eq!(
            witnesses
                .iter()
                .filter(|witness| witness.opposed.is_some() && witness.recorded.is_some())
                .count(),
            2,
            "the candidate's base and the candidate's commit each owe an opposed publication"
        );
    }

    /// The overlap census: one route, branching only where a region is chosen.
    fn overlap_classes(fold: &TopologyFold) -> Vec<Candidate> {
        vec![
            Candidate::new("task_dispatched/aleph/g0", dispatch(ALEPH, 0)),
            Candidate::new(
                "attempt_started/aleph/g0/a1",
                attempt_started(fold, ALEPH, 0, 1),
            ),
            Candidate::new(
                "attempt_finished/succeeded/aleph/g0/a1",
                settle(
                    ALEPH,
                    0,
                    1,
                    SettlementTransition::Succeeded,
                    LeaseDisposition::PredictedRetained,
                ),
            ),
            Candidate::new(
                "candidate_prepared/region-a/aleph/g0/a1",
                candidate_prepared_over(ALEPH, 0, 1, region(ALEPH)),
            ),
            Candidate::new(
                "candidate_prepared/region-ab/aleph/g0/a1",
                candidate_prepared_over(ALEPH, 0, 1, overlap_region()),
            ),
            Candidate::new(
                "task_candidate_created/aleph/g0",
                candidate_created(ALEPH, 0),
            ),
            Candidate::new(
                "merge_verification_started/aleph/g0",
                verification_started(
                    0,
                    ALEPH,
                    0,
                    "prepared/0",
                    sha("moved-head"),
                    sha("proposal-aleph"),
                ),
            ),
            Candidate::new(
                "merge_verification_unavailable/parked",
                verification_parked(0, ALEPH, "q-overlap-park"),
            ),
            Candidate::new(
                "run_finished/Parked",
                run_finished(fold, RunOutcome::Parked),
            ),
        ]
    }

    #[test]
    fn an_overlapping_region_is_explored_and_changes_a_transition_answer() {
        // PR3-ST14-002's other half: A3-ST14-014 normalises AB to A or drops
        // path regions from the key. `decisions.bounded_census.abstraction`
        // names three regions, and AB is the only one under which the overlap
        // relation answers differently.
        //
        // The two states here differ in one thing: whether `aleph`'s candidate
        // lease covers `bet`'s region as well as its own. Under A, `bet` is
        // still dispatchable, so the run has structurally admissible work and
        // does not end. Under AB it is lease-blocked, `aleph`'s own queued
        // candidate is ineligible behind its open question, and the run is
        // Parked — so `run_finished(Parked)` is refused at one and accepted at
        // the other. Alias the two and one of those two answers is not in the
        // census at all.
        let census = Census::explore(
            started(),
            vec![run_started_event()],
            CensusBounds::default(),
            overlap_classes,
        );
        assert!(!census.truncated());

        let parked: Vec<&CensusState> = census
            .states()
            .iter()
            .filter(|state| {
                state
                    .fold
                    .open_questions()
                    .is_some_and(|open| !open.is_empty())
                    && state.fold.transaction().is_none()
                    && state.fold.finished().is_none()
            })
            .collect();
        assert_eq!(
            parked.len(),
            2,
            "A and AB reached {} parked state(s), not two",
            parked.len()
        );

        let holds_bet = |state: &CensusState| {
            state.trace.iter().any(|event| match &event.body {
                TopologyEventBody::CandidatePrepared { data } => {
                    data.actual_paths == overlap_region()
                }
                _ => false,
            })
        };
        let wide = parked
            .iter()
            .find(|state| holds_bet(state))
            .expect("one parked state took region AB");
        let narrow = parked
            .iter()
            .find(|state| !holds_bet(state))
            .expect("one parked state took region A");

        // The traces differ in exactly one event, and in that event only the
        // region.
        assert_eq!(wide.trace.len(), narrow.trace.len());
        let differing: Vec<usize> = (0..wide.trace.len())
            .filter(|index| wide.trace[*index] != narrow.trace[*index])
            .collect();
        assert_eq!(differing, vec![4], "more than the region moved");

        // Two states, and two different answers to the same offer.
        assert_ne!(wide.id, narrow.id);
        assert_eq!(narrow.outcome, DerivedOutcome::NotEnding);
        assert_eq!(wide.outcome, DerivedOutcome::Ending(RunOutcome::Parked));
        let answer = |state: &CensusState| {
            census
                .outgoing(state.id)
                .find(|transition| transition.label == "run_finished/Parked")
                .map(|transition| matches!(transition.outcome, TransitionOutcome::Accepted { .. }))
                .unwrap_or_else(|| panic!("state {} never offered run_finished", state.id))
        };
        assert!(!answer(narrow), "region A leaves bet dispatchable");
        assert!(answer(wide), "region AB blocks bet and the run parks");
        // Both regions really are in play, and AB is neither of the other two.
        assert_ne!(region(ALEPH), overlap_region());
        assert_ne!(region(BET), overlap_region());
    }

    // -----------------------------------------------------------------------
    // PR3-ST14-004 — the bounds it generated, and one-field negatives
    // -----------------------------------------------------------------------

    /// Every generation id, attempt number and question id the fixture's
    /// classes construct, read off the events rather than off their labels: a
    /// label is a string a change to the payload it names can leave alone.
    fn generated_by_the_classes() -> (BTreeSet<u32>, BTreeSet<u32>, BTreeSet<String>) {
        let mut generations = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        let mut questions = BTreeSet::new();
        for candidate in classes(&started()) {
            match &candidate.event.body {
                TopologyEventBody::TaskDispatched { data } => {
                    generations.insert(data.generation.0);
                }
                TopologyEventBody::AttemptStarted { data } => {
                    generations.insert(data.generation.0);
                    attempts.insert(data.attempt.0);
                }
                TopologyEventBody::AttemptFinished { data } => {
                    generations.insert(data.generation.0);
                    attempts.insert(data.attempt.0);
                    if let AttemptSettlement::Closed {
                        transition: SettlementTransition::Parked { question },
                        ..
                    } = &data.settlement
                    {
                        questions.insert(question.id.to_string());
                    }
                }
                TopologyEventBody::CandidatePrepared { data } => {
                    generations.insert(data.generation.0);
                    attempts.insert(data.attempt.attempt);
                }
                TopologyEventBody::GenerationClosed { data } => {
                    generations.insert(data.generation.0);
                }
                _ => {}
            }
        }
        (generations, attempts, questions)
    }

    #[test]
    fn every_declared_dimension_reports_what_the_fixture_generated() {
        // PR3-ST14-004. A3-ST14-011 turns the attempt generator's `1..=2` into
        // `1..2`. Attempt 2 stops being offered anywhere, an attempt-2-only
        // transition defect becomes invisible, and `CensusBounds` goes on
        // reporting `attempts_per_generation: 2` — a boundary the skeleton did
        // not generate. So each declared dimension is measured against what
        // the fixture actually built, and the shortfalls are named rather than
        // left to read as coverage.
        let bounds = CensusBounds::default();
        let census = census();
        let (generations, attempts, question_ids) = generated_by_the_classes();

        // The most questions any explored state holds open at once, which is
        // what the bound is about.
        let open_questions = census
            .states()
            .iter()
            .filter_map(|state| state.fold.open_questions().map(BTreeMap::len))
            .max()
            .unwrap_or(0);
        // Integration sequences the census ran, and verification deferrals any
        // candidate took.
        let mut sequences = BTreeSet::new();
        let mut defers = 0;
        for state in census.states() {
            if let Some(transaction) = state.fold.transaction() {
                sequences.insert(transaction.sequence.0);
            }
            if let Some(queue) = state.fold.queue() {
                for entry in queue.entries() {
                    defers = defers.max(entry.defers);
                }
            }
        }
        let originals = u32::try_from(started().registry().expect("started").len()).unwrap_or(0);
        let repairs = u32::try_from(
            census
                .transitions()
                .iter()
                .filter(|transition| transition.label.starts_with("task_spawned/"))
                .count(),
        )
        .unwrap_or(0);
        let resumes = u32::try_from(
            census
                .transitions()
                .iter()
                .filter(|transition| transition.label.starts_with("run_resumed"))
                .count(),
        )
        .unwrap_or(0);

        // What the fixture generated, per declared dimension.
        let generated: BTreeMap<&str, u32> = [
            ("originals", originals),
            ("repairs", repairs),
            (
                "generations_per_task",
                u32::try_from(generations.len()).unwrap_or(0),
            ),
            (
                "attempts_per_generation",
                attempts.iter().copied().max().unwrap_or(0),
            ),
            ("sequences", u32::try_from(sequences.len()).unwrap_or(0)),
            ("defers", defers),
            ("questions", u32::try_from(open_questions).unwrap_or(0)),
            ("resumes", resumes),
        ]
        .into_iter()
        .collect();

        // The declared list and the measured list are the same list, so a
        // ninth dimension cannot be declared without being measured.
        assert_eq!(
            bounds
                .dimensions()
                .iter()
                .map(|(name, _)| *name)
                .collect::<BTreeSet<_>>(),
            generated.keys().copied().collect::<BTreeSet<_>>()
        );
        // ...and `dimensions()` is every dimension `CensusBounds` declares,
        // read off its own rendering rather than off a list beside it. A field
        // added to the struct and forgotten here fails.
        let rendered = format!("{bounds:#?}");
        let fields: BTreeSet<&str> = rendered
            .lines()
            .filter_map(|line| line.trim().split_once(':'))
            .map(|(name, _)| name)
            .filter(|name| *name != "max_trace" && *name != "max_states")
            .collect();
        assert_eq!(
            fields,
            bounds
                .dimensions()
                .iter()
                .map(|(name, _)| *name)
                .collect::<BTreeSet<_>>(),
            "a bound the struct declares and `dimensions()` does not"
        );

        // Which dimensions this fixture takes to their declared maximum, and
        // which it does not. Both lists are asserted, so a shortfall cannot
        // become coverage and coverage cannot quietly become a shortfall.
        let at_maximum = [
            "attempts_per_generation",
            "generations_per_task",
            "questions",
        ];
        let below_maximum = ["originals", "repairs", "sequences", "defers", "resumes"];
        assert_eq!(
            at_maximum.len() + below_maximum.len(),
            bounds.dimensions().len(),
            "a declared dimension is in neither list"
        );
        for (name, declared) in bounds.dimensions() {
            let made = generated[name];
            assert!(
                made <= declared,
                "{name}: the fixture generated {made} and the census declares {declared}"
            );
            if at_maximum.contains(&name) {
                assert_eq!(
                    made, declared,
                    "{name}: declared {declared} and generated {made}; a boundary this skeleton \
                     did not generate is not evidence it explored"
                );
            } else {
                assert!(
                    below_maximum.contains(&name),
                    "{name} is classified twice or not at all"
                );
                assert!(
                    made < declared,
                    "{name}: generated {made} of {declared}, so it belongs in the other list"
                );
            }
        }

        // And maximum-plus-one is excluded rather than merely unobserved: the
        // identities the fixture generates are exactly `1..=max`, densely,
        // with nothing above.
        assert_eq!(attempts, BTreeSet::from([1, 2]));
        assert!(!attempts.contains(&(bounds.attempts_per_generation + 1)));
        assert_eq!(generations, BTreeSet::from([0, 1]));
        assert!(!generations.contains(&bounds.generations_per_task));
        assert!(
            open_questions <= usize::try_from(bounds.questions).unwrap_or(usize::MAX),
            "{open_questions} questions were open at once"
        );
        // Four question identities are constructed and at most two are ever
        // open together, so the bound is about simultaneity and is measured as
        // such.
        assert_eq!(question_ids.len(), 4);
    }

    fn merge_prepared_of(label: &str) -> MergePrepared {
        let candidate = classes(&started())
            .into_iter()
            .find(|candidate| candidate.label == label)
            .unwrap_or_else(|| panic!("the classes offer no `{label}`"));
        match candidate.event.body {
            TopologyEventBody::MergePrepared { data } => *data,
            other => panic!("`{label}` is a {:?}", other.kind()),
        }
    }

    /// Which fields of two publication records differ, by name.
    fn merge_prepared_diff(left: &MergePrepared, right: &MergePrepared) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, differs) in [
            ("sequence", left.sequence != right.sequence),
            ("disposition", left.disposition != right.disposition),
            ("expected_head", left.expected_head != right.expected_head),
            ("proposed_sha", left.proposed_sha != right.proposed_sha),
            ("key", left.key != right.key),
            ("generation", left.generation != right.generation),
            ("candidate_sha", left.candidate_sha != right.candidate_sha),
            ("candidate_ref", left.candidate_ref != right.candidate_ref),
            ("prepared_ref", left.prepared_ref != right.prepared_ref),
            (
                "verification_source",
                left.verification_source != right.verification_source,
            ),
            ("verification", left.verification != right.verification),
            ("satisfies", left.satisfies != right.satisfies),
        ] {
            if differs {
                out.push(name);
            }
        }
        out
    }

    #[test]
    fn every_publication_negative_differs_from_its_positive_in_exactly_one_field() {
        // PR3-ST14-004's other half. A3-ST14-044 changes `proposed_sha` in the
        // moved-head payload as well as `expected_head`. The class named
        // `moved-head` stays refused — because the proposal is wrong — so a
        // fold that stopped comparing heads altogether passes a test that
        // reads as evidence the head relation is checked.
        //
        // So each negative is required to be its positive with exactly one
        // field moved, before anything is asserted about the answer.
        let fast = merge_prepared_of("merge_prepared/fast/match/aleph/g0");
        let stale = merge_prepared_of("merge_prepared/stale_clean/match/aleph/g0");
        let present = merge_prepared_of("merge_prepared/already_present/match/aleph/g0");

        // The diff names every field of the record, checked against the
        // record's own rendering: a field added to `MergePrepared` and
        // forgotten here would make "exactly one" a claim about a subset.
        let rendered = format!("{fast:#?}");
        let fields: BTreeSet<&str> = rendered
            .lines()
            .filter_map(|line| line.trim().split_once(':'))
            .map(|(name, _)| name)
            .filter(|name| {
                !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            })
            .collect();
        let mut every = fast.clone();
        every.sequence = SequenceId(97);
        every.disposition = PreparedDisposition::AlreadyPresent;
        every.expected_head = sha("nothing-alike");
        every.proposed_sha = sha("nothing-alike-either");
        every.key = BET;
        every.generation = GenerationId(9);
        every.candidate_sha = sha("nor-this");
        every.candidate_ref = git_ref("nor/this");
        every.prepared_ref = Some(git_ref("nor/that"));
        every.verification_source = VerificationSource::Verification {
            sequence: SequenceId(97),
        };
        every.verification = Some(VerificationRecord {
            verdict: VerificationVerdict::Passed,
            gates_passed: false,
            reviews: Vec::new(),
            detail: "different".to_owned(),
        });
        every.satisfies = vec![BET, ALEPH];
        assert_eq!(
            merge_prepared_diff(&fast, &every)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            fields,
            "the field-by-field diff and the record's own fields are not the same list"
        );

        let census = census();
        let accepted = census.accepted_labels();
        let refused = census.refused_labels();
        for (positive, label, field) in [
            (
                &fast,
                "merge_prepared/fast/moved-head/aleph/g0",
                "expected_head",
            ),
            (
                &fast,
                "merge_prepared/fast/other-proposed/aleph/g0",
                "proposed_sha",
            ),
            (
                &fast,
                "merge_prepared/fast/with-pin/aleph/g0",
                "prepared_ref",
            ),
            (
                &stale,
                "merge_prepared/stale_clean/mismatch/aleph/g0",
                "proposed_sha",
            ),
            (
                &present,
                "merge_prepared/already_present/mismatch/aleph/g0",
                "proposed_sha",
            ),
        ] {
            let negative = merge_prepared_of(label);
            assert_eq!(
                merge_prepared_diff(positive, &negative),
                vec![field],
                "`{label}` is not its positive with one field moved"
            );
            // And only then the answers: the positive accepted somewhere, this
            // negative refused everywhere.
            assert!(refused.contains(label), "`{label}` was never refused");
            assert!(
                !accepted.contains(label),
                "`{label}` was accepted somewhere"
            );
        }
        for positive in [
            "merge_prepared/fast/match/aleph/g0",
            "merge_prepared/stale_clean/match/aleph/g0",
            "merge_prepared/already_present/match/aleph/g0",
        ] {
            assert!(
                accepted.contains(positive),
                "`{positive}` was never accepted"
            );
        }
    }
}
