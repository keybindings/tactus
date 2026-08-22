//! The census suite.
//!
//! **Every test here names the second field it holds constant.** The dominant
//! defect shape on this project is two axes covered separately with their
//! intersection never built, and this module is unusually exposed to it: the
//! liveness rule is `{owner run} × {incarnation}`, discovery is `{intent
//! present} × {container present}`, and the write-command axis is `{run} ×
//! {resume}`. A suite that varies one at a time passes while an implementation
//! that reclaims a **live** run's dead earlier incarnation ships.

// `effects::production_region` cuts a source at its FIRST `#[cfg(test)]`, and
// several source censuses in this tree scan every `src/**/*.rs` — including
// this one, which is reached only through `#[cfg(test)] mod tests;` and so has
// no attribute of its own for them to cut on. The marker below is redundant to
// the compiler and load-bearing to those censuses: it makes this file's
// production region empty, so a fixture that names a primitive is not reported
// as a production offender (`PR5-R1-CFG-TEST-SHRINKS-THE-DOMAIN`, used here in
// the direction it is wanted).
#[cfg(test)]
mod this_file_is_test_only {}

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex, PoisonError};

use super::{
    Boundary, Census, CensusComplete, CensusStart, DiscoveredBy, Ownership, PrefixBytes,
    PrefixReplay, PrefixReread, PrefixSync, StablePrefixBarrier, WriteCommand, private_root_label,
    run_startup_census, view_path,
};
use crate::error::TactusError;
use crate::runner::container::intent::{
    ContainerIntent, ContainerName, LABEL_INCARNATION, LABEL_PRIVATE_ROOT, LABEL_RUN,
    LABEL_RUN_DIR, containers_dir,
};
use crate::runner::container::runtime::{
    ContainerRuntime, ContainerTrace, Liveness, OwnerLiveness, RuntimeOp,
};
use crate::runner::container::{
    ContainerHooks, DisposableDirView, FakeRuntime, RecordingHooks, TERMINATION_OBSERVATIONS,
    write_intent,
};
use crate::runner::{AgentId, InvocationId, ProbeTarget};
use crate::topology::effects::ContainerSite;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A scratch private root. Thread id is in the name because
/// [`concurrent_reclaimers_converge`] runs two of these at once.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tactus-census-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a scratch private root");
    dir
}

/// Distinct values for every independently meaningful field, so a swap between
/// any two is visible rather than accidentally equal.
const REPO_KEY_A: &str = "0123456789abcdef";
const REPO_KEY_B: &str = "fedcba9876543210";
const RUN_A: &str = "01KZRN48A4ZK3AEDST3RJ8HMA4";
const RUN_B: &str = "01KZS7R0V1ZD6MC290MG350QXF";
const RUN_C: &str = "01KZSCCCCCCCCCCCCCCCCCCCCC";
const INC_1: &str = "01KZTAAAAAAAAAAAAAAAAAAAAA";
const INC_2: &str = "01KZTBBBBBBBBBBBBBBBBBBBBB";
const INC_3: &str = "01KZTCCCCCCCCCCCCCCCCCCCCC";
const POLICY_A: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const POLICY_B: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
const IMAGE_ID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn shell_probe() -> InvocationId {
    InvocationId::probe(ProbeTarget::Shell, 0).expect("the shell probe identity")
}

fn agent_probe() -> InvocationId {
    InvocationId::probe(ProbeTarget::Agent(AgentId::new("claude-code")), 0).expect("an agent probe")
}

/// One owner, fully specified. Every field varies independently in the grids
/// below, which is why they are arguments and not defaults.
#[derive(Debug, Clone)]
struct Owner {
    run_id: &'static str,
    incarnation: &'static str,
    repo_key: &'static str,
    run_dir: PathBuf,
    policy: &'static str,
}

impl Owner {
    fn new(run_id: &'static str, incarnation: &'static str, repo_key: &'static str) -> Self {
        Self {
            run_id,
            incarnation,
            repo_key,
            run_dir: PathBuf::from(format!("/repo/.tactus/runs/{run_id}")),
            policy: POLICY_A,
        }
    }

    fn with_policy(mut self, policy: &'static str) -> Self {
        self.policy = policy;
        self
    }

    fn name(&self, invocation: &InvocationId) -> ContainerName {
        ContainerName::new(self.repo_key, self.run_id, self.incarnation, invocation)
            .expect("a container name")
    }

    fn record(&self, invocation: &InvocationId) -> ContainerIntent {
        ContainerIntent {
            run_id: self.run_id.to_owned(),
            run_dir: self.run_dir.to_string_lossy().into_owned(),
            incarnation: self.incarnation.to_owned(),
            repo_key: self.repo_key.to_owned(),
            invocation: invocation.render(),
            runner_policy_sha256: self.policy.to_owned(),
        }
    }
}

/// What a fixture puts on the machine for one container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Present {
    /// A record and a container: the ordinary running state.
    Both,
    /// A record and no container: a crash between the intent write and
    /// `docker create`, or a Unix reaper that already killed and removed it.
    IntentOnly,
    /// A container and no record: "a labeled container without an intent".
    LabelOnly,
}

/// Put one container's evidence on the machine and return its name.
fn seed(
    root: &Path,
    runtime: &FakeRuntime,
    owner: &Owner,
    invocation: &InvocationId,
    present: Present,
    state: Liveness,
) -> ContainerName {
    let name = owner.name(invocation);
    let record = owner.record(invocation);
    if present != Present::LabelOnly {
        let mut hooks = RecordingHooks::new(ContainerTrace::off());
        write_intent(&mut hooks, ContainerSite::WriteIntent, root, &name, &record)
            .expect("write the intent");
    }
    if present != Present::IntentOnly {
        runtime.seed_container(
            name.as_str(),
            record.labels(root),
            IMAGE_ID,
            IMAGE_ID,
            state,
        );
        // R19: the view a live invocation would have mounted.
        fs::create_dir_all(view_path(root, &name)).expect("an orphan view directory");
    }
    name
}

/// An owner-liveness probe that records what it was asked.
///
/// Not [`crate::runner::container::FakeOwnerLiveness`], which answers but keeps
/// no log: "arm (i) does not probe the lock at all" and "arm (ii) does not read
/// the incarnation" are both claims about **what was asked**, and only a log can
/// hold them.
#[derive(Debug, Default)]
struct RecordingLiveness {
    live: Mutex<BTreeSet<PathBuf>>,
    asked: Mutex<Vec<PathBuf>>,
}

impl RecordingLiveness {
    fn new() -> Self {
        Self::default()
    }

    fn set_live(&self, run_dir: &Path) {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(run_dir.to_path_buf());
    }

    fn asked(&self) -> Vec<PathBuf> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl OwnerLiveness for RecordingLiveness {
    fn is_running(&self, public_run_dir: &Path) -> bool {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(public_run_dir.to_path_buf());
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(public_run_dir)
    }
}

/// A runtime whose `stop` **succeeds and does not stop anything**.
///
/// The container is still running after every observation, which is the state
/// `refusal_condition`'s "cannot be observed terminated" is about: a wedged
/// supervisor, a container in `removing` that never leaves it, a daemon that
/// accepts a signal and delivers nothing. [`FakeRuntime`] cannot reach it —
/// its `stop` always moves the container to `Exited` — so a suite built only on
/// the fake would find that branch unconstructible and green.
///
/// It delegates only the **read-only** operations. The four effectful ones are
/// the funnel's primitives, and this wrapper implements rather than forwards
/// them, so it never becomes a second caller of one.
struct WedgedRuntime {
    inner: Arc<FakeRuntime>,
}

impl ContainerRuntime for WedgedRuntime {
    fn probe(&self) -> Result<(), crate::runner::container::runtime::RuntimeError> {
        self.inner.probe()
    }
    fn image_by_reference(
        &self,
        reference: &str,
    ) -> Result<
        Option<crate::runner::container::runtime::ImageInspection>,
        crate::runner::container::runtime::RuntimeError,
    > {
        self.inner.image_by_reference(reference)
    }
    fn image_by_id(
        &self,
        id: &str,
    ) -> Result<
        Option<crate::runner::container::runtime::ImageInspection>,
        crate::runner::container::runtime::RuntimeError,
    > {
        self.inner.image_by_id(id)
    }
    fn volume_present(
        &self,
        name: &str,
    ) -> Result<bool, crate::runner::container::runtime::RuntimeError> {
        self.inner.volume_present(name)
    }
    fn containers_with_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<
        Vec<crate::runner::container::runtime::DiscoveredContainer>,
        crate::runner::container::runtime::RuntimeError,
    > {
        self.inner.containers_with_label(key, value)
    }
    fn observe(
        &self,
        name: &str,
    ) -> Result<Liveness, crate::runner::container::runtime::RuntimeError> {
        self.inner.observe(name)
    }
    fn collect(
        &self,
        name: &str,
    ) -> Result<
        crate::runner::container::runtime::ContainerExecution,
        crate::runner::container::runtime::RuntimeError,
    > {
        self.inner.collect(name)
    }
    fn create(
        &self,
        _spec: &crate::runner::container::runtime::CreateSpec,
    ) -> Result<
        crate::runner::container::runtime::CreatedContainer,
        crate::runner::container::runtime::RuntimeError,
    > {
        unreachable!("a census creates nothing")
    }
    fn start(&self, _name: &str) -> Result<(), crate::runner::container::runtime::RuntimeError> {
        unreachable!("a census starts nothing")
    }
    fn stop(
        &self,
        _name: &str,
        _mode: crate::runner::container::runtime::StopMode,
    ) -> Result<(), crate::runner::container::runtime::RuntimeError> {
        // Accepted, delivered nowhere. This is the whole fixture.
        Ok(())
    }
    fn remove(&self, _name: &str) -> Result<(), crate::runner::container::runtime::RuntimeError> {
        unreachable!("reclaim refuses before `rm` when termination cannot be observed")
    }
}

/// A resume's recovery step (a1), established from bytes this fixture owns.
fn barrier() -> StablePrefixBarrier {
    let bytes = b"{\"event\":\"run_started\"}\n";
    let measured = PrefixBytes::of(bytes);
    StablePrefixBarrier::establish(
        PrefixSync {
            synced_len: measured.len,
        },
        &PrefixReread {
            first: measured.clone(),
            second: measured.clone(),
        },
        &PrefixReplay { replayed: measured },
    )
    .expect("a barrier over a stable prefix")
}

fn fresh(incarnation: &str) -> CensusStart {
    CensusStart::FreshRun {
        incarnation: incarnation.to_owned(),
    }
}

fn resume(run_id: &str, incarnation: &str) -> CensusStart {
    CensusStart::Resume {
        run_id: run_id.to_owned(),
        incarnation: incarnation.to_owned(),
        barrier: barrier(),
    }
}

/// Everything a census run needs, held together so a test varies one field.
struct Harness {
    root: PathBuf,
    trace: ContainerTrace,
    runtime: Arc<FakeRuntime>,
    liveness: RecordingLiveness,
    view: DisposableDirView,
}

impl Harness {
    fn new(tag: &str) -> Self {
        let root = scratch(tag);
        let trace = ContainerTrace::recording();
        Self {
            root,
            runtime: Arc::new(FakeRuntime::new(trace.clone())),
            liveness: RecordingLiveness::new(),
            view: DisposableDirView::new(trace.clone()),
            trace,
        }
    }

    fn census(&self, start: &CensusStart) -> Result<CensusComplete, TactusError> {
        let mut hooks = RecordingHooks::new(self.trace.clone());
        self.run_with(&mut hooks, start)
    }

    fn run_with(
        &self,
        hooks: &mut dyn ContainerHooks,
        start: &CensusStart,
    ) -> Result<CensusComplete, TactusError> {
        run_startup_census(
            hooks,
            &Census {
                private_root: &self.root,
                start,
                runtime: self.runtime.as_ref(),
                liveness: &self.liveness,
                view: &self.view,
            },
        )
    }

    fn holds(&self, name: &ContainerName) -> bool {
        self.runtime.container(name.as_str()).is_some()
    }

    fn intent_exists(&self, name: &ContainerName) -> bool {
        name.intent_path(&self.root).exists()
    }

    fn view_exists(&self, name: &ContainerName) -> bool {
        view_path(&self.root, name).exists()
    }
}

/// Where `needle` first appears in the trace, or a failure naming the sequence.
fn at(trace: &ContainerTrace, needle: &str) -> usize {
    trace.position(needle).unwrap_or_else(|| {
        panic!(
            "`{needle}` is not in the trace, which is {:#?}",
            trace.rendered()
        )
    })
}

fn refusal(error: &TactusError) -> String {
    match error {
        TactusError::Refused { message } => message.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 1. The liveness rule — two arms, and the intersection nobody builds
// ---------------------------------------------------------------------------

/// Every cell of `{owner run} × {incarnation} × {owner lock}`.
///
/// The rule has two arms and each arm has two outcomes, so the grid is the
/// product and not a list of the cases that came to mind. Arm (i) has no lock
/// axis (this process holds the lock) and arm (ii) has no incarnation axis, so
/// the eight tuples collapse to **four** classifications — and that collapse is
/// asserted as a distinct-value count rather than described.
///
/// Second field held constant: the container name, the repo key and the run
/// directory are the same shape in every cell, so nothing but the ownership
/// triple moves.
#[test]
fn the_liveness_rule_classifies_every_cell_of_owner_run_by_incarnation_by_lock() {
    let liveness = RecordingLiveness::new();
    let live_dir = PathBuf::from("/repo/.tactus/runs/live");
    let dead_dir = PathBuf::from("/repo/.tactus/runs/dead");
    liveness.set_live(&live_dir);

    let mine = resume(RUN_A, INC_1);
    let cells: Vec<(&str, &str, &str, &Path, Ownership)> = vec![
        // Arm (i): the run this process drives. The lock is not probed.
        (
            "own run, this incarnation",
            RUN_A,
            INC_1,
            dead_dir.as_path(),
            Ownership::OwnRunThisIncarnation,
        ),
        (
            "own run, earlier incarnation",
            RUN_A,
            INC_2,
            dead_dir.as_path(),
            Ownership::OwnRunEarlierIncarnation,
        ),
        (
            "own run, another earlier incarnation",
            RUN_A,
            INC_3,
            live_dir.as_path(),
            Ownership::OwnRunEarlierIncarnation,
        ),
        // Arm (ii): another run. The incarnation is not read.
        (
            "foreign run, lock held, my incarnation's value",
            RUN_B,
            INC_1,
            live_dir.as_path(),
            Ownership::ForeignRunLiveOwner,
        ),
        (
            "foreign run, lock held, another incarnation",
            RUN_B,
            INC_2,
            live_dir.as_path(),
            Ownership::ForeignRunLiveOwner,
        ),
        (
            "foreign run, lock free, my incarnation's value",
            RUN_B,
            INC_1,
            dead_dir.as_path(),
            Ownership::ForeignRunDeadOwner,
        ),
        (
            "foreign run, lock free, another incarnation",
            RUN_B,
            INC_3,
            dead_dir.as_path(),
            Ownership::ForeignRunDeadOwner,
        ),
    ];

    let mut seen = BTreeSet::new();
    for (what, run_id, incarnation, run_dir, expected) in &cells {
        let got = super::classify_ownership(&mine, run_id, incarnation, run_dir, &liveness);
        assert_eq!(got, *expected, "{what}");
        seen.insert(got);
    }
    assert_eq!(
        seen.len(),
        4,
        "the grid must reach all four classifications, not the three a one-axis fixture reaches"
    );
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        Ownership::ALL.to_vec(),
        "the classifications the grid reaches are exactly the ones the enum declares"
    );

    // Arm (i) probes nothing: three own-run cells produced no question at all,
    // and the four foreign cells produced one each.
    assert_eq!(
        liveness.asked().len(),
        4,
        "arm (i) asked whether this process's own run is running: {:?}",
        liveness.asked()
    );
}

/// **The crossed fixture.** A *live* run's *dead earlier incarnation*, seen by a
/// *foreign* census, is never touched.
///
/// `crash_reconstruction`: "held -> live owner -> **never touched** (that owner
/// reclaims its own earlier incarnations at its own startup census, which
/// precedes its admission)"; and the residual it names — "a container of a dead
/// incarnation of a live run may run until that run's own census reclaims it …
/// **out of scope**".
///
/// This is the cell an implementation that reclaims dead incarnations gets
/// wrong, and it passes every test that varies only `{owner run}` or only
/// `{incarnation}`. The same fixture is then run again with the owner's lock
/// **free** and the same two incarnations are both reclaimed, so the test cannot
/// pass by never reclaiming anything.
///
/// Second field held constant: the two containers, their names, their records
/// and their private root are byte-identical between the two halves; the **only**
/// thing that moves is whether the owner's lock is held.
#[test]
fn a_live_runs_dead_earlier_incarnation_is_untouched_by_a_foreign_census() {
    for owner_is_live in [true, false] {
        let harness = Harness::new(if owner_is_live {
            "crossed-live"
        } else {
            "crossed-dead"
        });
        let earlier = Owner::new(RUN_B, INC_1, REPO_KEY_A);
        let current = Owner::new(RUN_B, INC_2, REPO_KEY_A);
        assert_eq!(
            earlier.run_dir, current.run_dir,
            "two incarnations of one run share one public run directory, which is what makes \
             this the crossed cell rather than two unrelated runs"
        );
        if owner_is_live {
            harness.liveness.set_live(&current.run_dir);
        }
        let old = seed(
            &harness.root,
            &harness.runtime,
            &earlier,
            &shell_probe(),
            Present::Both,
            Liveness::Running,
        );
        let new = seed(
            &harness.root,
            &harness.runtime,
            &current,
            &agent_probe(),
            Present::Both,
            Liveness::Running,
        );
        assert_ne!(old, new, "the incarnation component separates the names");

        let complete = harness
            .census(&fresh(INC_3))
            .expect("a foreign census of another run's containers");
        let report = complete.report();

        if owner_is_live {
            assert!(report.reclaimed.is_empty(), "{:#?}", report.reclaimed);
            assert_eq!(report.untouched.len(), 2);
            assert!(report.was_untouched(&old) && report.was_untouched(&new));
            assert!(
                harness.holds(&old) && harness.holds(&new),
                "a live owner's containers were killed, including the dead incarnation's"
            );
            assert!(harness.intent_exists(&old) && harness.intent_exists(&new));
            for entry in &report.untouched {
                assert_eq!(entry.ownership, Ownership::ForeignRunLiveOwner);
            }
        } else {
            assert_eq!(report.reclaimed.len(), 2, "{:#?}", report.reclaimed);
            assert!(report.untouched.is_empty());
            assert!(!harness.holds(&old) && !harness.holds(&new));
            assert!(!harness.intent_exists(&old) && !harness.intent_exists(&new));
            for entry in &report.reclaimed {
                assert_eq!(entry.ownership, Ownership::ForeignRunDeadOwner);
            }
            // "reclaim EVERY container of that run WHATEVER its incarnation".
            let incarnations: BTreeSet<&str> = report
                .reclaimed
                .iter()
                .map(|entry| entry.incarnation.as_str())
                .collect();
            assert_eq!(
                incarnations.len(),
                2,
                "a dead owner's containers span both its incarnations"
            );
        }
    }
}

/// Arm (ii) does not read the incarnation, over a domain of them.
///
/// Second field held constant: the owner run and its lock state; only the
/// incarnation moves, across four distinct values including this process's own.
#[test]
fn arm_two_gives_one_answer_whatever_the_incarnation() {
    let liveness = RecordingLiveness::new();
    let held = PathBuf::from("/repo/.tactus/runs/held");
    let free = PathBuf::from("/repo/.tactus/runs/free");
    liveness.set_live(&held);
    let me = resume(RUN_A, INC_1);
    let incarnations = [INC_1, INC_2, INC_3, "01KZTDDDDDDDDDDDDDDDDDDDDD"];
    assert_eq!(
        incarnations.iter().collect::<BTreeSet<_>>().len(),
        4,
        "four distinct incarnations, one of them this process's own"
    );

    let mut held_answers = BTreeSet::new();
    let mut free_answers = BTreeSet::new();
    for incarnation in incarnations {
        held_answers.insert(super::classify_ownership(
            &me,
            RUN_B,
            incarnation,
            &held,
            &liveness,
        ));
        free_answers.insert(super::classify_ownership(
            &me,
            RUN_B,
            incarnation,
            &free,
            &liveness,
        ));
    }
    assert_eq!(
        held_answers.into_iter().collect::<Vec<_>>(),
        vec![Ownership::ForeignRunLiveOwner],
        "four incarnations of a live foreign owner, one answer"
    );
    assert_eq!(
        free_answers.into_iter().collect::<Vec<_>>(),
        vec![Ownership::ForeignRunDeadOwner],
        "four incarnations of a dead foreign owner, one answer"
    );
}

/// The incarnation is never read from the lock: the seam has no incarnation in
/// it, and this module never names a lock file.
///
/// `crash_reconstruction`: "the coordinator incarnation id is a per-process ULID
/// recorded in `run_started(4)`/`run_resumed(4)` and is **never read from
/// lock-file contents** (`run.lock` content is never read: `src/rundir.rs:886`;
/// a Windows exclusive lock makes it unreadable to non-holders)". Deriving it
/// from the lock is a plausible implementation and a real defect.
///
/// Second field held constant: the runtime and the namespace; only what the
/// liveness seam is handed and returns is under test.
#[test]
fn the_census_learns_no_incarnation_from_the_owner_liveness_seam() {
    let harness = Harness::new("no-incarnation-from-lock");
    let dead = Owner::new(RUN_B, INC_2, REPO_KEY_A);
    seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    harness
        .census(&resume(RUN_A, INC_1))
        .expect("a census of a dead foreign owner");

    // What the seam was handed is the PUBLIC run directory and nothing else,
    // and what it gave back is one bit — there is no incarnation in the return
    // type to read.
    assert_eq!(harness.liveness.asked(), vec![dead.run_dir.clone()]);
    let one_bit: bool = harness.liveness.is_running(&dead.run_dir);
    assert!(!one_bit);

    // And the module does not reach around the seam: its production region
    // names no lock file at all.
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runner/container/census.rs"),
    )
    .expect("the census module");
    let production =
        crate::effects::blank_comments_and_strings(&crate::effects::production_region(&source));
    for needle in ["run.lock", "lock_file", "acquire", "holder"] {
        assert!(
            !production.contains(needle),
            "the census names `{needle}`; the incarnation comes from run_started(4)/\
             run_resumed(4) and is never read from lock-file contents"
        );
    }
    assert!(
        production.contains("is_running("),
        "the census asks the one-bit seam, so this scan is looking at the right file"
    );
}

// ---------------------------------------------------------------------------
// 2. The T-CONTAINER names
// ---------------------------------------------------------------------------

/// (4) An orphan is reclaimed **before slot reset, credential reuse, or
/// admission** — expressed as the token those consumers cannot be reached
/// without.
///
/// ST-16 (a): "single owner dies -> next write-command start reclaims
/// (inspect/kill/observe/rm/view/intent) **before slot reset, credential reuse,
/// or admission**". Slots and admission are PR11's and the credential-volume
/// turn is PR7's, so what this slice can hold is that (i) the whole five-step
/// reclaim is complete when the census returns, in the packet's order, and (ii)
/// a census that could not complete it returns **no token**, so nothing that
/// takes one can run. `census_returns_the_only_token_that_reaches_a_consumer`
/// is the structural half.
///
/// Second field held constant: the owner is dead in both halves and the fixture
/// is byte-identical; only whether the container can be observed terminated
/// moves.
#[test]
fn orphan_reclaimed_before_slot_reset() {
    let harness = Harness::new("before-slot-reset");
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let name = seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );

    let complete = harness.census(&fresh(INC_2)).expect("the census completes");

    // The five steps, in the packet's order, all before the token existed.
    let sites: Vec<ContainerSite> = harness
        .trace
        .sites()
        .into_iter()
        .map(|(site, _)| site)
        .collect();
    let ordered: Vec<ContainerSite> = {
        let mut seen = Vec::new();
        for site in sites {
            if seen.last() != Some(&site) {
                seen.push(site);
            }
        }
        seen
    };
    assert_eq!(
        ordered,
        vec![
            ContainerSite::Stop,
            ContainerSite::Remove,
            ContainerSite::UnmountGitView,
            ContainerSite::RemoveIntent,
        ],
        "reclaim is kill -> observe -> rm -> remove view -> remove intent"
    );
    assert!(
        at(&harness.trace, &format!("rt:observe:{name}"))
            < at(&harness.trace, &format!("rt:remove:{name}")),
        "the observation wait was dropped: `rm` before termination was proven"
    );
    assert!(!harness.holds(&name) && !harness.intent_exists(&name) && !harness.view_exists(&name));
    assert_eq!(complete.report().reclaimed.len(), 1);
    assert_eq!(complete.private_root(), harness.root.as_path());

    // The other half: a container that cannot be observed terminated blocks
    // admission, so there is no token at all.
    let root = scratch("blocks-admission");
    let inner = Arc::new(FakeRuntime::new(ContainerTrace::off()));
    let stuck = seed(
        &root,
        &inner,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    let wedged = WedgedRuntime {
        inner: Arc::clone(&inner),
    };
    let liveness = RecordingLiveness::new();
    let view = DisposableDirView::new(ContainerTrace::off());
    let mut hooks = RecordingHooks::new(ContainerTrace::off());
    let start = fresh(INC_2);
    let error = run_startup_census(
        &mut hooks,
        &Census {
            private_root: &root,
            start: &start,
            runtime: &wedged,
            liveness: &liveness,
            view: &view,
        },
    )
    .expect_err("a container that cannot be observed terminated blocks admission");
    let message = refusal(&error);
    assert!(
        message.contains("cannot be observed terminated"),
        "{message}"
    );
    assert!(message.contains("blocks admission"), "{message}");
    assert!(
        inner.container(stuck.as_str()).is_some(),
        "the container is still there, and nothing admitted over it"
    );
    let _ = fs::remove_dir_all(&root);
}

/// (5) A live owner's containers are untouched while a dead owner's orphan in
/// the **same private root** is reclaimed.
///
/// ST-16 (b): "live coordinator A running while dead coordinator B's orphan
/// exists in the same private root (**same or different repository**) -> reclaim
/// kills only B's container, A's continues, and **no invocation uses the shared
/// credential volume before B's is observed terminated**".
///
/// The repositories differ — two repo keys under one private root, which is the
/// "different repository" half of that clause — and the run directories differ,
/// which is what the lock probe distinguishes them by. The credential-volume
/// clause is the token: B's observation is complete before `run_startup_census`
/// returns, and nothing that takes a `&CensusComplete` exists until then.
///
/// Second field held constant: both containers are `Running`, both have records,
/// both are under the same private root; only the owner run and its lock state
/// move.
#[test]
fn live_owner_untouched_while_dead_orphan_reclaimed() {
    let harness = Harness::new("live-and-dead");
    let live = Owner::new(RUN_A, INC_1, REPO_KEY_A);
    let dead = Owner::new(RUN_B, INC_2, REPO_KEY_B);
    assert_ne!(live.repo_key, dead.repo_key, "different repositories");
    assert_ne!(live.run_dir, dead.run_dir);
    harness.liveness.set_live(&live.run_dir);

    let a = seed(
        &harness.root,
        &harness.runtime,
        &live,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    let b = seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );

    let complete = harness.census(&fresh(INC_3)).expect("the census completes");
    let report = complete.report();

    assert_eq!(report.reclaimed.len(), 1);
    assert_eq!(report.reclaimed[0].name, b);
    assert_eq!(report.untouched.len(), 1);
    assert_eq!(report.untouched[0].name, a);
    assert!(
        harness.holds(&a),
        "the live coordinator's container continues"
    );
    assert!(harness.intent_exists(&a));
    assert!(!harness.holds(&b));

    // Only B was touched: no runtime operation names A's container at all.
    let named_a: Vec<String> = harness
        .trace
        .rendered()
        .into_iter()
        .filter(|entry| entry.starts_with("rt:") && entry.ends_with(a.as_str()))
        .collect();
    assert!(
        named_a.is_empty(),
        "the census issued operations against a live owner's container: {named_a:?}"
    );

    // The credential-volume clause: B's termination is observed before the
    // token exists, and no volume operation happens in a census at all.
    assert!(
        at(&harness.trace, &format!("rt:observe:{b}"))
            < at(&harness.trace, &format!("rt:remove:{b}"))
    );
    assert!(
        !harness.trace.ops().contains(&RuntimeOp::InspectVolume),
        "a census inspects no volume; the turn is taken by a consumer of the token"
    );
}

/// (6) A labeled container with no intent is reclaimed under the same rule.
///
/// `crash_reconstruction`: "a labeled container **without an intent** is treated
/// as an orphan of its **labeled** run and incarnation under the same rule".
/// Its ownership therefore comes from `tactus.run` and `tactus.incarnation`, and
/// the census must reach the same verdict it would have reached from a record.
///
/// Second field held constant: the same owner, the same name and the same
/// liveness answer are used for a record-backed container in the same fixture,
/// so the two differ **only** in which half of discovery found them.
#[test]
fn labeled_orphan_without_intent_reclaimed() {
    let harness = Harness::new("labeled-orphan");
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let recorded = seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    let unrecorded = seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &agent_probe(),
        Present::LabelOnly,
        Liveness::Running,
    );
    assert!(!harness.intent_exists(&unrecorded));

    let complete = harness.census(&fresh(INC_2)).expect("the census completes");
    let report = complete.report();
    assert_eq!(report.reclaimed.len(), 2);
    assert!(!harness.holds(&recorded) && !harness.holds(&unrecorded));

    let by_discovery: Vec<(ContainerName, DiscoveredBy, Boundary)> = report
        .reclaimed
        .iter()
        .map(|entry| {
            (
                entry.name.clone(),
                entry.discovered_by,
                entry.boundary.clone(),
            )
        })
        .collect();
    let recorded_entry = by_discovery
        .iter()
        .find(|(name, ..)| name == &recorded)
        .expect("the recorded one");
    let unrecorded_entry = by_discovery
        .iter()
        .find(|(name, ..)| name == &unrecorded)
        .expect("the unrecorded one");
    assert_eq!(recorded_entry.1, DiscoveredBy::IntentAndLabel);
    assert_eq!(unrecorded_entry.1, DiscoveredBy::LabelOnly);
    assert_eq!(
        recorded_entry.2,
        Boundary::FromIntent(POLICY_A.to_owned()),
        "a record-backed container's boundary is its runner_policy_sha256"
    );
    assert_eq!(
        unrecorded_entry.2,
        Boundary::NoIntentRecord,
        "a labeled orphan with no record has no boundary from this side; PR7's owner \
         record is the other half, and saying so beats inventing a digest"
    );

    // Both reached the same ownership verdict, which is what "under the same
    // rule" means.
    let verdicts: BTreeSet<Ownership> = report
        .reclaimed
        .iter()
        .map(|entry| entry.ownership)
        .collect();
    assert_eq!(
        verdicts.into_iter().collect::<Vec<_>>(),
        vec![Ownership::ForeignRunDeadOwner]
    );
}

/// (7) A resume reclaims its own earlier incarnation's orphan — including a
/// probe invocation with the **same deterministic `InvocationId`**.
///
/// ST-16 (f): "the resuming incarnation holds the run lock … and still reclaims
/// its own earlier incarnation's orphan (incl. a probe invocation with the same
/// deterministic `InvocationId`, whose new container name and intent path
/// differ) before slot init, admission, credential use, or its own probes, while
/// containers it starts afterwards are untouched".
///
/// Second field held constant: the invocation identity is **literally the same
/// value** for the dead incarnation and for this one, so the only thing that can
/// separate their names and intent paths is the incarnation component.
#[test]
fn same_run_resume_reclaims_earlier_incarnation_orphan() {
    let harness = Harness::new("resume-earlier-incarnation");
    let earlier = Owner::new(RUN_A, INC_1, REPO_KEY_A);
    let probe = shell_probe();
    let orphan = seed(
        &harness.root,
        &harness.runtime,
        &earlier,
        &probe,
        Present::Both,
        Liveness::Running,
    );

    // The same deterministic identity, this incarnation.
    let mine = Owner::new(RUN_A, INC_2, REPO_KEY_A);
    let would_be = mine.name(&probe);
    assert_eq!(
        probe.render(),
        shell_probe().render(),
        "the probe identity repeats across incarnations by construction, which is why the \
         name carries the incarnation"
    );
    assert_ne!(orphan, would_be, "the container names differ");
    assert_ne!(
        orphan.intent_path(&harness.root),
        would_be.intent_path(&harness.root),
        "the intent paths differ, so no earlier ownership evidence is overwritten"
    );

    let complete = harness
        .census(&resume(RUN_A, INC_2))
        .expect("the resume's census completes");
    let report = complete.report();
    assert_eq!(report.command, WriteCommand::Resume);
    assert_eq!(report.reclaimed.len(), 1);
    assert_eq!(report.reclaimed[0].name, orphan);
    assert_eq!(
        report.reclaimed[0].ownership,
        Ownership::OwnRunEarlierIncarnation,
        "dead by construction: the run lock is exclusive and this process holds it"
    );
    assert!(
        harness.liveness.asked().is_empty(),
        "arm (i) probed the lock of the run this process is itself driving: {:?}",
        harness.liveness.asked()
    );
    assert!(!harness.holds(&orphan) && !harness.intent_exists(&orphan));

    // "while containers it starts afterwards are untouched": this incarnation's
    // own container appears only after the census, and a second census of the
    // same root would refuse it rather than reclaim it — which is the next test.
    assert!(
        !harness.holds(&would_be),
        "this incarnation has started nothing yet; the census precedes every invocation"
    );
}

/// (8) The census scans **exactly the root it is given**, after the default
/// moved.
///
/// ST-16 (f): "censuses the recorded private root **even when the default root
/// or `HOME` changed**". PR7 owns deriving that root from
/// `run_started.private_dir` (recovery step (a0)); what this slice owns is that
/// the census takes it as a parameter and reads no default — so a second root
/// holding a reclaimable orphan is left completely alone, and "different private
/// roots are disjoint worlds".
///
/// Second field held constant: the two roots hold **the same owner, the same
/// invocation and therefore the same container name**; the only thing that
/// differs is which root the census was handed.
#[test]
fn same_run_resume_censuses_recorded_root_after_default_changed() {
    let recorded = Harness::new("recorded-root");
    let other_root = scratch("default-root-that-moved");
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);

    let in_recorded = seed(
        &recorded.root,
        &recorded.runtime,
        &dead,
        &shell_probe(),
        Present::IntentOnly,
        Liveness::Gone,
    );
    // The same container name and record, under the other root. If the census
    // read a default it would find this one instead, or as well.
    let mut hooks = RecordingHooks::new(ContainerTrace::off());
    write_intent(
        &mut hooks,
        ContainerSite::WriteIntent,
        &other_root,
        &in_recorded,
        &dead.record(&shell_probe()),
    )
    .expect("an intent under the other root");

    let complete = recorded
        .census(&resume(RUN_A, INC_2))
        .expect("the census completes");
    assert_eq!(complete.private_root(), recorded.root.as_path());
    assert_eq!(complete.report().reclaimed.len(), 1);
    assert!(!recorded.intent_exists(&in_recorded));
    assert!(
        in_recorded.intent_path(&other_root).exists(),
        "the census reached into a root it was not given: different private roots are \
         disjoint worlds"
    );

    // And the label filter is the root it was given, not any other.
    let filtered: Vec<String> = recorded
        .trace
        .rendered()
        .into_iter()
        .filter(|entry| entry.starts_with("rt:list-by-label:"))
        .collect();
    assert_eq!(
        filtered,
        vec![format!(
            "rt:list-by-label:{}",
            private_root_label(&recorded.root)
        )]
    );
    let _ = fs::remove_dir_all(&other_root);
}

/// (10) Three incarnations, two crashes, every dead incarnation reclaimed with
/// no name or intent collision.
///
/// ST-16 (g): "repeated crashes across **three** incarnations leave orphans from
/// **two** dead incarnations that are all reclaimed with no name or intent
/// collision".
///
/// Second field held constant: every orphan is the **same deterministic probe
/// identity** under the **same run** and the **same repo key**, so the only
/// thing separating three names and three intent paths is the incarnation
/// component — which is exactly the thing the packet says it is for.
#[test]
fn repeated_crashes_reclaim_every_dead_incarnation() {
    let harness = Harness::new("three-incarnations");
    let probe = shell_probe();
    let mut names = Vec::new();
    for incarnation in [INC_1, INC_2] {
        let owner = Owner::new(RUN_A, incarnation, REPO_KEY_A);
        names.push(seed(
            &harness.root,
            &harness.runtime,
            &owner,
            &probe,
            Present::Both,
            Liveness::Running,
        ));
    }
    // A third incarnation of the same run, from a different invocation, so the
    // fixture is not three copies of one shape.
    let third = Owner::new(RUN_A, INC_3, REPO_KEY_A);
    names.push(seed(
        &harness.root,
        &harness.runtime,
        &third,
        &agent_probe(),
        Present::Both,
        Liveness::Running,
    ));

    assert_eq!(
        names.iter().collect::<BTreeSet<_>>().len(),
        3,
        "three distinct container names"
    );
    assert_eq!(
        names
            .iter()
            .map(|name| name.intent_path(&harness.root))
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "three distinct intent paths: no earlier ownership evidence was overwritten"
    );
    assert_eq!(
        fs::read_dir(containers_dir(&harness.root))
            .expect("the namespace")
            .count(),
        3
    );

    // The fourth incarnation resumes and censuses.
    let complete = harness
        .census(&resume(RUN_A, "01KZTDDDDDDDDDDDDDDDDDDDDD"))
        .expect("the census completes");
    let report = complete.report();
    assert_eq!(report.reclaimed.len(), 3);
    let reclaimed_incarnations: BTreeSet<&str> = report
        .reclaimed
        .iter()
        .map(|entry| entry.incarnation.as_str())
        .collect();
    assert_eq!(
        reclaimed_incarnations,
        [INC_1, INC_2, INC_3].into_iter().collect::<BTreeSet<_>>()
    );
    for name in &names {
        assert!(!harness.holds(name) && !harness.intent_exists(name));
    }
    assert_eq!(
        fs::read_dir(containers_dir(&harness.root))
            .expect("the namespace")
            .count(),
        0,
        "the namespace is empty: every record was removed, not merely the last one"
    );
}

/// (11) Two reclaimers **actually racing** on one container converge.
///
/// "every step idempotent and tolerant of already-gone so **two concurrent
/// reclaimers converge**". A fixture that ran two censuses one after the other
/// would prove idempotence, which is a different claim: idempotence is about
/// repeating a completed operation, convergence is about two interleaved ones.
/// So the two run on two threads, released together by a
/// [`Barrier`], over many rounds so the interleaving actually varies.
///
/// Second field held constant: both reclaimers are handed the **same** runtime,
/// the same root and the same container; the only thing that differs between
/// them is which thread gets there first.
#[test]
fn concurrent_reclaimers_converge() {
    const ROUNDS: usize = 24;
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let probe = shell_probe();

    for round in 0..ROUNDS {
        let root = scratch(&format!("converge-{round}"));
        let trace = ContainerTrace::off();
        let runtime = Arc::new(FakeRuntime::new(trace.clone()));
        // FOUR containers, not one. The dangerous window is between the
        // namespace directory read and the per-record reads inside it, and one
        // record closes that window almost immediately: with a single orphan,
        // this fixture detected the `list_intents` intolerance measured below
        // in only 2 of 20 runs. Four records widen the scan enough for the
        // detection to be reliable, which is the difference between a test that
        // holds a claim and one that occasionally notices it.
        let names: Vec<ContainerName> = (0..4)
            .map(|ordinal| {
                let invocation =
                    InvocationId::probe(ProbeTarget::Shell, ordinal).expect("a probe identity");
                seed(
                    &root,
                    &runtime,
                    &dead,
                    &invocation,
                    Present::Both,
                    Liveness::Running,
                )
            })
            .collect();
        let _ = &probe;
        assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), 4);
        let gate = Arc::new(Barrier::new(2));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let root = root.clone();
            let runtime = Arc::clone(&runtime);
            let gate = Arc::clone(&gate);
            handles.push(std::thread::spawn(move || {
                let liveness = RecordingLiveness::new();
                let view = DisposableDirView::new(ContainerTrace::off());
                let mut hooks = RecordingHooks::new(ContainerTrace::off());
                let start = CensusStart::FreshRun {
                    incarnation: INC_2.to_owned(),
                };
                gate.wait();
                run_startup_census(
                    &mut hooks,
                    &Census {
                        private_root: &root,
                        start: &start,
                        runtime: runtime.as_ref(),
                        liveness: &liveness,
                        view: &view,
                    },
                )
                .map(|complete| complete.report().reclaimed.len())
            }));
        }
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("a reclaimer panicked"))
            .collect();
        for outcome in &outcomes {
            assert!(
                outcome.is_ok(),
                "a concurrent reclaimer refused instead of converging: {outcome:?}"
            );
        }
        // Whichever order they interleaved in, the machine converged.
        for name in &names {
            assert!(runtime.container(name.as_str()).is_none());
            assert!(!name.intent_path(&root).exists());
            assert!(!view_path(&root, name).exists());
        }
        // Somebody did the work. The loser may legitimately find a container
        // already gone and report fewer; between them they must account for all
        // four. What must never happen is a refusal, asserted above.
        let total: usize = outcomes
            .iter()
            .map(|outcome| *outcome.as_ref().unwrap_or(&0))
            .sum();
        assert!(
            total >= names.len(),
            "round {round}: two reclaimers between them reported {total} of {} orphans they \
             removed",
            names.len()
        );
        let _ = fs::remove_dir_all(&root);
    }
}

/// The sharpest interleaving, made deterministic.
///
/// A racing fixture visits the dangerous window by luck. This one puts a
/// reclaimer to sleep at `Container.Remove`'s `Before` phase, lets a second
/// reclaimer run the whole sequence to completion underneath it, and then
/// releases the first — so the first issues `docker rm`, view removal and
/// intent removal against a machine where all three are already gone. Every one
/// must be tolerant of already-gone or the census refuses and blocks admission
/// forever.
///
/// Second field held constant: both reclaimers see the same root, the same
/// runtime and the same container; only the suspension point moves, and it is
/// the same point every run.
#[test]
fn a_reclaimer_suspended_mid_sequence_converges_with_one_that_finished() {
    /// Hooks that block once, at one phase of one site.
    struct BlockAt {
        trace: ContainerTrace,
        site: crate::topology::effects::EffectSiteId,
        phase: crate::topology::effects::HookPhase,
        release: Option<std::sync::mpsc::Receiver<()>>,
        arrived: Option<std::sync::mpsc::Sender<()>>,
    }
    impl ContainerHooks for BlockAt {
        fn phase(
            &mut self,
            site: crate::topology::effects::EffectSiteId,
            phase: crate::topology::effects::HookPhase,
        ) -> crate::topology::effects::Injection {
            if site == self.site && phase == self.phase {
                if let Some(arrived) = self.arrived.take() {
                    let _ = arrived.send(());
                }
                if let Some(release) = self.release.take() {
                    let _ = release.recv();
                }
            }
            crate::topology::effects::Injection::Proceed
        }
        fn trace(&self) -> ContainerTrace {
            self.trace.clone()
        }
    }

    let root = scratch("suspended-reclaimer");
    let runtime = Arc::new(FakeRuntime::new(ContainerTrace::off()));
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let name = seed(
        &root,
        &runtime,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );

    let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let slow_root = root.clone();
    let slow_runtime = Arc::clone(&runtime);
    let slow = std::thread::spawn(move || {
        let liveness = RecordingLiveness::new();
        let view = DisposableDirView::new(ContainerTrace::off());
        let mut hooks = BlockAt {
            trace: ContainerTrace::off(),
            site: crate::topology::effects::EffectSiteId::Container(ContainerSite::Remove),
            phase: crate::topology::effects::HookPhase::Before,
            release: Some(release_rx),
            arrived: Some(arrived_tx),
        };
        let start = CensusStart::FreshRun {
            incarnation: INC_2.to_owned(),
        };
        run_startup_census(
            &mut hooks,
            &Census {
                private_root: &slow_root,
                start: &start,
                runtime: slow_runtime.as_ref(),
                liveness: &liveness,
                view: &view,
            },
        )
        .map(|complete| complete.report().reclaimed.len())
    });

    arrived_rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("the slow reclaimer reached Container.Remove");

    // The second reclaimer finishes the whole sequence underneath it.
    let fast = {
        let liveness = RecordingLiveness::new();
        let view = DisposableDirView::new(ContainerTrace::off());
        let mut hooks = RecordingHooks::new(ContainerTrace::off());
        let start = CensusStart::FreshRun {
            incarnation: INC_3.to_owned(),
        };
        run_startup_census(
            &mut hooks,
            &Census {
                private_root: &root,
                start: &start,
                runtime: runtime.as_ref(),
                liveness: &liveness,
                view: &view,
            },
        )
    };
    assert!(fast.is_ok(), "the second reclaimer refused: {fast:?}");
    assert!(!name.intent_path(&root).exists());

    release_tx.send(()).expect("release the slow reclaimer");
    let slow = slow.join().expect("the slow reclaimer panicked");
    assert!(
        slow.is_ok(),
        "a reclaimer resumed into an already-converged machine and refused: {slow:?}"
    );
    assert!(runtime.container(name.as_str()).is_none());
    assert!(!view_path(&root, &name).exists());
    let _ = fs::remove_dir_all(&root);
}

/// (12) A foreign census leaves a schema-4 run's probe containers alone while
/// its `run.lock` is held during preflight.
///
/// ST-16 (i): "a schema-4 run's probe containers (shell and agent probes) carry
/// an owner whose `run.lock` is **held** during preflight (T-RUNSTART P4) and
/// whose owner record already names the `RunnerPolicy`, and a concurrent foreign
/// census leaves them untouched".
///
/// **PR7 completes this.** The owner record at P3b and the P0-P8 sequence that
/// makes the lock held at P4 are `decisions.pr_sequence[8]`'s. What PR6 holds is
/// the half the census owns: a foreign census leaves untouched **every**
/// container of a run whose lock is held, including probe containers, and
/// including a probe container whose owner has not yet appended `run_started`.
///
/// Second field held constant: an identical dead-owner probe container is in the
/// same fixture, so the test cannot pass by leaving everything alone.
#[test]
fn schema4_probe_container_owned_during_preflight_untouched_by_foreign_census() {
    let harness = Harness::new("preflight-probes");
    let preflighting = Owner::new(RUN_A, INC_1, REPO_KEY_A).with_policy(POLICY_A);
    let dead = Owner::new(RUN_B, INC_2, REPO_KEY_B).with_policy(POLICY_B);
    harness.liveness.set_live(&preflighting.run_dir);

    let mut held = Vec::new();
    for invocation in [shell_probe(), agent_probe()] {
        held.push(seed(
            &harness.root,
            &harness.runtime,
            &preflighting,
            &invocation,
            Present::Both,
            Liveness::Running,
        ));
    }
    let orphan = seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );

    let complete = harness
        .census(&fresh(INC_3))
        .expect("a concurrent foreign census");
    let report = complete.report();
    assert_eq!(report.untouched.len(), 2);
    for name in &held {
        assert!(report.was_untouched(name));
        assert!(harness.holds(name), "a preflighting run's probe was killed");
        assert!(harness.intent_exists(name));
    }
    assert_eq!(report.reclaimed.len(), 1);
    assert_eq!(report.reclaimed[0].name, orphan);
    assert!(!harness.holds(&orphan));

    // Both probe kinds were present, so the claim is about probe containers and
    // not about one of them.
    assert_eq!(
        held.iter().collect::<BTreeSet<_>>().len(),
        2,
        "a shell probe and an agent probe, two distinct names"
    );
}

/// (14) Intents present + the runtime unreachable = the write command refuses,
/// before any effect.
///
/// ST-16 (j) and `expected_failures_refusals[8]`: "intents present without a
/// reachable runtime refuse the write command". It "cannot prove those
/// containers terminated".
///
/// The reachability question is asked of the operation the census actually needs
/// — `ListByLabel` — and **not** of `probe`, whose `Ok` binds nothing: the
/// fixture arms `ListByLabel` unreachable while leaving `Probe` reachable, so an
/// implementation that gated on `probe` proceeds and fails this test.
///
/// Second field held constant: the same single intent is on disk in both halves;
/// only the runtime's answer moves.
#[test]
fn census_refuses_when_intents_exist_without_reachable_runtime() {
    let harness = Harness::new("intents-without-runtime");
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let name = seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &shell_probe(),
        Present::IntentOnly,
        Liveness::Gone,
    );
    harness.runtime.set_unreachable(RuntimeOp::ListByLabel);
    assert!(
        harness.runtime.probe().is_ok(),
        "`probe` still answers: an implementation that gated on it would proceed here"
    );

    let error = harness
        .census(&fresh(INC_2))
        .expect_err("intents exist and the runtime cannot be reached");
    let message = refusal(&error);
    assert!(message.contains("cannot be reached"), "{message}");
    assert!(
        message.contains("prove those containers terminated"),
        "{message}"
    );
    assert!(
        harness.intent_exists(&name),
        "the refusal happened before any effect: the record is untouched"
    );
    assert!(
        harness.trace.sites().is_empty(),
        "the refusal reached a funnel site: {:#?}",
        harness.trace.rendered()
    );

    // And the same runtime, reachable again, reclaims it — so the refusal is
    // about reachability and not about the fixture being unreclaimable.
    harness.runtime.set_reachable(RuntimeOp::ListByLabel);
    let complete = harness.census(&fresh(INC_2)).expect("now it proceeds");
    assert_eq!(complete.report().reclaimed.len(), 1);
    assert!(!harness.intent_exists(&name));
}

/// (15) No intent + no reachable runtime = the census **proceeds**.
///
/// This is the half a plausible suite forgets, and getting it wrong makes the
/// engine unusable on every machine without a container runtime — which today
/// is every machine, because `production_effect` is "none". The whole daemon is
/// armed unreachable, not one operation.
///
/// Second field held constant: the private root and the write command are the
/// same as in the refusing half above; only the presence of an intent moves.
#[test]
fn census_proceeds_without_runtime_when_no_intent_exists() {
    for (tag, command) in [("run", WriteCommand::Run), ("resume", WriteCommand::Resume)] {
        let harness = Harness::new(&format!("no-intent-no-runtime-{tag}"));
        harness.runtime.set_all_unreachable();
        assert!(
            harness.runtime.probe().is_err(),
            "the whole daemon is unreachable"
        );
        assert!(
            !containers_dir(&harness.root).exists(),
            "an empty namespace"
        );

        let start = match command {
            WriteCommand::Run => fresh(INC_1),
            WriteCommand::Resume => resume(RUN_A, INC_1),
        };
        let complete = harness
            .census(&start)
            .expect("with no intent and no reachable runtime it proceeds");
        let report = complete.report();
        assert_eq!(report.runtime_use, super::RuntimeUse::NotRequired);
        assert_eq!(report.command, command);
        assert!(report.reclaimed.is_empty() && report.untouched.is_empty());
        assert!(
            harness.trace.sites().is_empty(),
            "a census with nothing to do performed an effect"
        );
    }
}

/// A runtime that is **reached** and refuses to list is not the same answer.
///
/// `RuntimeError` distinguishes `Unreachable` from `Failed` for exactly this:
/// "with no intent and no **reachable** runtime it proceeds" licenses proceeding
/// when the runtime is not there, and says nothing about one that is there and
/// will not answer. A daemon that answers and fails a `ps` cannot prove there is
/// no labeled orphan, so the census refuses rather than admitting over one.
///
/// Recorded as a judgement, not as a packet clause: it is the conservative
/// reading of a case the sentence does not enumerate, and the refusal names it.
///
/// Second field held constant: the namespace is empty in both halves — the one
/// state that *would* license proceeding — so the only thing under test is which
/// kind of runtime error it is.
#[test]
fn a_reachable_runtime_that_refuses_to_list_refuses_the_write_command() {
    let unreachable = Harness::new("list-unreachable");
    unreachable.runtime.set_unreachable(RuntimeOp::ListByLabel);
    assert!(
        unreachable.census(&fresh(INC_1)).is_ok(),
        "no intent, unreachable runtime: proceeds"
    );

    let failing = Harness::new("list-failing");
    failing.runtime.set_failing(RuntimeOp::ListByLabel);
    let error = failing
        .census(&fresh(INC_1))
        .expect_err("no intent, and a runtime that answered and would not list");
    let message = refusal(&error);
    assert!(message.contains("reached and refused"), "{message}");
    assert!(message.contains("cannot prove"), "{message}");
}

/// (16) The census report names each reclaimed container's boundary from its
/// `runner_policy_sha256`.
///
/// ST-16 (k): "a probe container killed with its coordinator **before
/// `run_started`** is reclaimed by the next census, whose report names its
/// boundary from the intent's `runner_policy_sha256` **and the owner record**".
///
/// **PR7 completes this**: the owner-record half is `decisions.pr_sequence[8]`'s
/// "atomic owner record with the RunnerPolicy". PR6 holds the intent half, and
/// [`Boundary::NoIntentRecord`] is the honest name for the case where this side
/// has nothing.
///
/// Second field held constant: the two reclaimed containers are the same probe
/// kind under the same private root and are both dead-owner orphans; the only
/// thing that differs is which `RunnerPolicy` their record names, so a report
/// that carried one digest for both fails.
#[test]
fn census_report_names_reclaimed_probe_boundary() {
    let harness = Harness::new("boundary-from-digest");
    let one = Owner::new(RUN_B, INC_1, REPO_KEY_A).with_policy(POLICY_A);
    let two = Owner::new(RUN_C, INC_2, REPO_KEY_B).with_policy(POLICY_B);
    assert_ne!(one.policy, two.policy, "two distinct runner policies");

    let first = seed(
        &harness.root,
        &harness.runtime,
        &one,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    let second = seed(
        &harness.root,
        &harness.runtime,
        &two,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );

    let complete = harness.census(&fresh(INC_3)).expect("the census completes");
    let report = complete.report();
    assert_eq!(report.reclaimed.len(), 2);
    assert_eq!(
        report.boundary_of(&first),
        Some(&Boundary::FromIntent(POLICY_A.to_owned()))
    );
    assert_eq!(
        report.boundary_of(&second),
        Some(&Boundary::FromIntent(POLICY_B.to_owned()))
    );
    let digests: BTreeSet<Option<&str>> = report
        .reclaimed
        .iter()
        .map(|entry| entry.boundary.digest())
        .collect();
    assert_eq!(
        digests.len(),
        2,
        "the report carried one boundary for two containers with different policies"
    );

    // The values are the records' own — read back off disk rather than taken
    // from the fixture's variables, so the report cannot be its own oracle.
    let recorded: BTreeSet<String> = [POLICY_A, POLICY_B]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let reported: BTreeSet<String> = report
        .reclaimed
        .iter()
        .filter_map(|entry| entry.boundary.digest().map(str::to_owned))
        .collect();
    assert_eq!(reported, recorded);

    // The probe was killed before `run_started`: nothing in this fixture wrote
    // an event log at all, and the boundary still has a name.
    assert!(!harness.root.join("events.jsonl").exists());
}

// ---------------------------------------------------------------------------
// 3. Refusals, each with the ordering predicate it carries
// ---------------------------------------------------------------------------

/// An intent naming this process's own incarnation refuses — **before any
/// effect**, including before a reclaim it would otherwise have performed.
///
/// `expected_failures_refusals[7]`, and "the one most likely to be written as a
/// `continue`". The fixture puts a perfectly reclaimable orphan beside it, so an
/// implementation that skipped the offending record and got on with its work
/// fails here rather than passing quietly.
///
/// Second field held constant: the reclaimable orphan is identical in both
/// halves; the only thing that moves is whether the second record names this
/// process's own incarnation or an earlier one.
#[test]
fn an_intent_naming_this_processs_own_incarnation_is_refused_before_any_effect() {
    for (tag, incarnation, refuses) in [("own", INC_1, true), ("earlier", INC_2, false)] {
        let harness = Harness::new(&format!("own-incarnation-{tag}"));
        let orphan_owner = Owner::new(RUN_B, INC_3, REPO_KEY_B);
        let orphan = seed(
            &harness.root,
            &harness.runtime,
            &orphan_owner,
            &shell_probe(),
            Present::Both,
            Liveness::Running,
        );
        let mine = Owner::new(RUN_A, incarnation, REPO_KEY_A);
        let suspect = seed(
            &harness.root,
            &harness.runtime,
            &mine,
            &agent_probe(),
            Present::Both,
            Liveness::Running,
        );

        let outcome = harness.census(&resume(RUN_A, INC_1));
        if refuses {
            let message = refusal(&outcome.expect_err("refused"));
            assert!(message.contains("own incarnation"), "{message}");
            assert!(message.contains("cannot exist at census time"), "{message}");
            assert!(
                harness.trace.sites().is_empty(),
                "the census reclaimed something and then refused: {:#?}",
                harness.trace.rendered()
            );
            assert!(
                harness.holds(&orphan) && harness.intent_exists(&orphan),
                "the other orphan was reclaimed on behalf of a write command that refused"
            );
            assert!(harness.holds(&suspect));
        } else {
            let complete = outcome.expect("an earlier incarnation is dead by construction");
            assert_eq!(complete.report().reclaimed.len(), 2);
            assert!(!harness.holds(&orphan) && !harness.holds(&suspect));
        }
    }
}

/// A labeled container whose name no funnel could have written blocks
/// admission, and one whose labels do not say who owns it blocks admission.
///
/// `refusal_condition`: "a dead owner's or dead incarnation's labeled container
/// that **cannot be observed terminated** blocks admission". A container
/// claiming this private root that the funnel cannot name, or whose ownership
/// cannot be established, is one this census cannot take through
/// kill/observe/rm — so it refuses rather than proceeding past it.
///
/// Second field held constant: every case carries a valid `tactus.private_root`
/// label under the censused root, so what is under test is only what is missing
/// beside it.
#[test]
fn a_labeled_container_this_census_cannot_own_blocks_admission() {
    use crate::runner::container::runtime::DiscoveredContainer;
    use std::collections::BTreeMap;

    let owner = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let good = owner.name(&shell_probe());

    // `(what, the name the runtime reports, the label to withhold, the needle)`.
    // Data rather than closures, so every case builds the same complete label
    // set and then breaks exactly one thing about it.
    let cases: [(&str, &str, Option<&str>, &str); 4] = [
        (
            "a name no funnel could have written",
            "someone-elses-container",
            None,
            "not a tactus container name",
        ),
        (
            LABEL_RUN,
            good.as_str(),
            Some(LABEL_RUN),
            "blocks admission",
        ),
        (
            LABEL_INCARNATION,
            good.as_str(),
            Some(LABEL_INCARNATION),
            "blocks admission",
        ),
        (
            LABEL_RUN_DIR,
            good.as_str(),
            Some(LABEL_RUN_DIR),
            "blocks admission",
        ),
    ];

    let mut messages = BTreeSet::new();
    for (what, name, withheld, needle) in cases {
        let harness = Harness::new(&format!("unownable-{}", what.replace('.', "-")));
        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_PRIVATE_ROOT.to_owned(),
            private_root_label(&harness.root),
        );
        labels.insert(LABEL_RUN.to_owned(), RUN_B.to_owned());
        labels.insert(LABEL_INCARNATION.to_owned(), INC_1.to_owned());
        labels.insert(LABEL_RUN_DIR.to_owned(), "/repo/.tactus/runs/x".to_owned());
        if let Some(key) = withheld {
            labels.remove(key);
        }
        let container = DiscoveredContainer {
            name: name.to_owned(),
            labels,
        };
        harness.runtime.seed_container(
            &container.name,
            container.labels.clone(),
            IMAGE_ID,
            IMAGE_ID,
            Liveness::Running,
        );
        let error = harness
            .census(&fresh(INC_2))
            .expect_err("an unownable labeled container blocks admission");
        let message = refusal(&error);
        assert!(message.contains(needle), "{what}: {message}");
        assert!(
            harness.trace.sites().is_empty(),
            "{what}: the refusal came after an effect"
        );
        messages.insert(message);
    }
    assert_eq!(
        messages.len(),
        4,
        "four distinct causes must give four distinct diagnostics, or the operator cannot \
         tell which label is missing"
    );
}

/// A name and its ownership evidence that disagree refuse.
///
/// The name is `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>`, so
/// its components **are** ownership evidence. A record that says one incarnation
/// while its own file name says another would mean classifying on one value and
/// reclaiming a container named for the other.
///
/// Second field held constant: the container exists and is running in every
/// case; only which of the three components disagrees moves.
#[test]
fn a_name_that_disagrees_with_its_own_record_refuses() {
    let owner = Owner::new(RUN_A, INC_1, REPO_KEY_A);
    let name = owner.name(&shell_probe());
    let cases: [(&str, ContainerIntent, &str); 3] = [
        (
            "run id",
            {
                let mut record = owner.record(&shell_probe());
                record.run_id = RUN_B.to_owned();
                record
            },
            "named for run",
        ),
        (
            "incarnation",
            {
                let mut record = owner.record(&shell_probe());
                record.incarnation = INC_2.to_owned();
                record
            },
            "named for incarnation",
        ),
        (
            "repo key",
            {
                let mut record = owner.record(&shell_probe());
                record.repo_key = REPO_KEY_B.to_owned();
                record
            },
            "named for repo key",
        ),
    ];

    let mut seen = BTreeSet::new();
    for (what, record, needle) in cases {
        let harness = Harness::new(&format!("name-disagrees-{}", what.replace(' ', "-")));
        let mut hooks = RecordingHooks::new(ContainerTrace::off());
        write_intent(
            &mut hooks,
            ContainerSite::WriteIntent,
            &harness.root,
            &name,
            &record,
        )
        .expect("a record that disagrees with the name it is filed under");
        let error = harness
            .census(&fresh(INC_3))
            .expect_err("a record disagreeing with its own name is not ownership evidence");
        let message = refusal(&error);
        assert!(message.contains(needle), "{what}: {message}");
        seen.insert(needle);
    }
    assert_eq!(seen.len(), 3, "three components, three diagnostics");
}

/// A container whose labels and whose record disagree about its owner refuses.
///
/// The labels are derived from the record when a container is created
/// (`ContainerIntent::labels`), so a disagreement is not a state this engine
/// wrote — and picking a winner would mean deciding, from corrupted evidence,
/// whether to kill a container.
///
/// Second field held constant: the container name, the private root and the
/// record are the same in both cases; only which label was tampered with moves.
#[test]
fn labels_and_a_record_that_disagree_about_the_owner_refuse() {
    let owner = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    for (key, forged) in [(LABEL_RUN, RUN_C), (LABEL_INCARNATION, INC_2)] {
        let harness = Harness::new(&format!("label-disagrees-{}", key.replace('.', "-")));
        let name = owner.name(&shell_probe());
        let record = owner.record(&shell_probe());
        let mut hooks = RecordingHooks::new(ContainerTrace::off());
        write_intent(
            &mut hooks,
            ContainerSite::WriteIntent,
            &harness.root,
            &name,
            &record,
        )
        .expect("write the intent");
        let mut labels = record.labels(&harness.root);
        labels.insert(key.to_owned(), forged.to_owned());
        harness.runtime.seed_container(
            name.as_str(),
            labels,
            IMAGE_ID,
            IMAGE_ID,
            Liveness::Running,
        );

        let error = harness
            .census(&fresh(INC_3))
            .expect_err("labels and record disagree");
        let message = refusal(&error);
        assert!(message.contains(key), "{message}");
        assert!(message.contains("will not choose"), "{message}");
        assert!(
            harness.trace.sites().is_empty(),
            "refused before any effect"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Recovery step (a1) — the stable-prefix barrier
// ---------------------------------------------------------------------------

/// The four predicates of the barrier are separately droppable, and each has its
/// own refusal.
///
/// `crash_reconstruction`: the census happens "after the stable-prefix barrier
/// of step (a1) has **synced** the surviving event-log prefix, **proven it
/// stable**, and **checked-replayed it**, so that no fold-derived reclaim
/// decision precedes durability". Reclaim decided from a prefix that was synced
/// but not proven stable, or proven stable but not replayed, is reclaim on
/// unproven authority.
///
/// The digests are computed **out of band** (`python3 -c 'hashlib.sha256(...)'`)
/// and written here as literals, so the barrier is not compared against the
/// function that produced it.
///
/// Second field held constant: every case starts from the same healthy triple
/// and breaks exactly one predicate.
#[test]
fn the_stable_prefix_barrier_refuses_each_of_its_four_predicates_independently() {
    const PREFIX: &[u8] = b"{\"event\":\"run_started\"}\n";
    const PREFIX_SHA: &str = "2f9864f5b2e0acc40bf4a8b9fb5ae52b142cdcd0870db42ddcac489991b5206d";
    const LONGER: &[u8] = b"{\"event\":\"run_started\"}\n{\"event\":\"attempt_started\"}\n";
    const LONGER_SHA: &str = "9f6a5ec6a50778f18bc1fc9b3ff2286a43c4130479cf391cf321743450e5acc8";
    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // The measurement agrees with the out-of-band digests, so neither side is
    // the other's oracle.
    let measured = PrefixBytes::of(PREFIX);
    assert_eq!(measured.len, 24);
    assert_eq!(measured.sha256, PREFIX_SHA);
    assert_eq!(PrefixBytes::of(LONGER).sha256, LONGER_SHA);
    assert_eq!(PrefixBytes::of(b"").sha256, EMPTY_SHA);

    let healthy = || PrefixReread {
        first: measured.clone(),
        second: measured.clone(),
    };
    let synced = PrefixSync {
        synced_len: measured.len,
    };
    let replayed = || PrefixReplay {
        replayed: measured.clone(),
    };

    let established =
        StablePrefixBarrier::establish(synced, &healthy(), &replayed()).expect("a healthy barrier");
    assert_eq!(established.boundary(), 24);
    assert_eq!(established.digest(), PREFIX_SHA);

    let mut reasons = BTreeSet::new();

    // 1. The boundary moved between the two reads.
    let mut moved = healthy();
    moved.second = PrefixBytes::of(LONGER);
    let message = refusal(
        &StablePrefixBarrier::establish(synced, &moved, &replayed()).expect_err("boundary moved"),
    );
    assert!(
        message.contains("bytes AND boundary unchanged"),
        "{message}"
    );
    reasons.insert("boundary");

    // 2. The bytes changed while the boundary stayed put.
    let mut rewritten = healthy();
    rewritten.second = PrefixBytes {
        len: measured.len,
        sha256: LONGER_SHA.to_owned(),
    };
    let message = refusal(
        &StablePrefixBarrier::establish(synced, &rewritten, &replayed())
            .expect_err("bytes changed under a stable boundary"),
    );
    assert!(message.contains("proves the prefix stable"), "{message}");
    reasons.insert("bytes");

    // 3. Proven stable, and not durable to its boundary.
    let message = refusal(
        &StablePrefixBarrier::establish(
            PrefixSync {
                synced_len: measured.len - 1,
            },
            &healthy(),
            &replayed(),
        )
        .expect_err("the prefix is not synced to its boundary"),
    );
    assert!(message.contains("is not durable"), "{message}");
    reasons.insert("synced");

    // 4. Synced and proven stable, and the replay consumed other bytes.
    let message = refusal(
        &StablePrefixBarrier::establish(
            synced,
            &healthy(),
            &PrefixReplay {
                replayed: PrefixBytes::of(LONGER),
            },
        )
        .expect_err("the replay was of other bytes"),
    );
    assert!(message.contains("exactly the reread bytes"), "{message}");
    reasons.insert("replayed");

    assert_eq!(
        reasons.len(),
        4,
        "four predicates, four distinct refusals; a barrier that checked three would pass a \
         suite that only counted that it refused"
    );

    // A replay of the same length but different content is refused too: length
    // alone is not identity.
    assert!(
        StablePrefixBarrier::establish(
            synced,
            &healthy(),
            &PrefixReplay {
                replayed: PrefixBytes {
                    len: measured.len,
                    sha256: EMPTY_SHA.to_owned(),
                },
            },
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// 5. Discovery, both halves, every cell
// ---------------------------------------------------------------------------

/// Both halves of discovery are scanned, and every cell of `{intent present} ×
/// {container present}` is classified.
///
/// "discovery at every write-command start scans the whole namespace
/// `<R>/containers` … **and** docker ps by `tactus.private_root`". A census that
/// read only the namespace misses a labeled orphan whose record was already
/// removed; one that read only `docker ps` misses an intent whose container the
/// Unix reaper already killed and removed — which is the *ordinary* state after
/// a Unix coordinator death, because the reaper does kill/rm and leaves the
/// record for the next census.
///
/// Second field held constant: one owner, one liveness answer, one private root;
/// only which halves hold evidence moves.
#[test]
fn both_halves_of_discovery_are_scanned_and_every_cell_is_classified() {
    let harness = Harness::new("both-halves");
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let invocations = [
        InvocationId::probe(ProbeTarget::Shell, 0).expect("shell probe 0"),
        InvocationId::probe(ProbeTarget::Shell, 1).expect("shell probe 1"),
        agent_probe(),
    ];
    let cells = [Present::Both, Present::IntentOnly, Present::LabelOnly];
    let mut expected = Vec::new();
    for (invocation, present) in invocations.iter().zip(cells) {
        let name = seed(
            &harness.root,
            &harness.runtime,
            &dead,
            invocation,
            present,
            Liveness::Running,
        );
        expected.push((
            name,
            match present {
                Present::Both => DiscoveredBy::IntentAndLabel,
                Present::IntentOnly => DiscoveredBy::IntentOnly,
                Present::LabelOnly => DiscoveredBy::LabelOnly,
            },
        ));
    }

    let complete = harness.census(&fresh(INC_2)).expect("the census completes");
    let report = complete.report();
    assert_eq!(report.reclaimed.len(), 3);
    for (name, discovered_by) in &expected {
        let entry = report
            .reclaimed
            .iter()
            .find(|entry| &entry.name == name)
            .unwrap_or_else(|| panic!("`{name}` was not reclaimed: {:#?}", report.reclaimed));
        assert_eq!(entry.discovered_by, *discovered_by);
        assert!(!harness.holds(name) && !harness.intent_exists(name));
    }
    let cells: BTreeSet<DiscoveredBy> = report
        .reclaimed
        .iter()
        .map(|entry| entry.discovered_by)
        .collect();
    assert_eq!(
        cells.into_iter().collect::<Vec<_>>(),
        DiscoveredBy::ALL.to_vec(),
        "the fixture reached every cell the enum declares"
    );

    // The fourth cell — neither half — is the empty machine, and it is what the
    // census reports when nothing is there.
    let empty = Harness::new("neither-half");
    let complete = empty.census(&fresh(INC_2)).expect("an empty namespace");
    assert!(complete.report().reclaimed.is_empty());
}

/// The label this census filters on is the label the funnel writes.
///
/// A census that filtered on a different spelling would discover nothing and
/// report a clean machine — the "green because the test could not run" shape,
/// with the runtime standing in for the test. The two renderings are produced by
/// **different functions in different modules**, which is the only way this
/// comparison means anything.
///
/// Second field held constant: one record, one root; only which side computes
/// the string moves.
#[test]
fn the_private_root_label_this_census_filters_on_is_the_one_the_intent_writes() {
    for root in [
        PathBuf::from("/srv/tactus/private"),
        PathBuf::from("/tmp/a b/c"),
        PathBuf::from(r"C:\Users\dev\.tactus"),
    ] {
        let record = Owner::new(RUN_A, INC_1, REPO_KEY_A).record(&shell_probe());
        let written = record.labels(&root);
        assert_eq!(
            written.get(LABEL_PRIVATE_ROOT).map(String::as_str),
            Some(private_root_label(&root).as_str()),
            "the census's filter value and the funnel's label disagree for {}",
            root.display()
        );
    }
}

/// Every topology write command performs the census — `run` **and** `resume`.
///
/// `startup_census`: "performed by **every topology write command (run,
/// resume)**". Guarding it behind resume-only logic lets dead containers survive
/// into a fresh run's admission.
///
/// Second field held constant: the orphan, its owner, its liveness and the
/// private root are identical between the two halves; only the write command
/// moves.
#[test]
fn every_topology_write_command_performs_the_census() {
    let mut reclaimed_by = Vec::new();
    for command in WriteCommand::ALL {
        let harness = Harness::new(&format!("write-command-{}", command.name()));
        let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
        let name = seed(
            &harness.root,
            &harness.runtime,
            &dead,
            &shell_probe(),
            Present::Both,
            Liveness::Running,
        );
        let start = match command {
            WriteCommand::Run => fresh(INC_2),
            WriteCommand::Resume => resume(RUN_A, INC_2),
        };
        let complete = harness.census(&start).expect("the census completes");
        assert_eq!(complete.report().command, *command);
        assert_eq!(complete.report().reclaimed.len(), 1);
        assert!(!harness.holds(&name));
        reclaimed_by.push(*command);
    }
    assert_eq!(reclaimed_by, WriteCommand::ALL.to_vec());
    assert_eq!(WriteCommand::ALL.len(), 2);
}

// ---------------------------------------------------------------------------
// 6. The token, and what it precedes
// ---------------------------------------------------------------------------

/// [`CensusComplete`] is constructed in exactly one place.
///
/// `crash_reconstruction`'s four "before"s — slot/reservation initialization,
/// admission, credential-volume use, and this incarnation's probes — are
/// consumers PR7 and PR11 build. This slice cannot test against a consumer that
/// does not exist, so what it holds instead is that the token those consumers
/// will take can be made in exactly one way: by a census that completed.
///
/// The source census is the tree's own idiom
/// (`runner::container::tests::every_container_effect_in_the_tree_goes_through_the_funnel`),
/// and it has a positive control so a scan that stopped finding anything fails
/// rather than reporting silence.
///
/// Second field held constant: **none, and that is the answer rather than an
/// omission.** This is a census over the whole tree, so the axis it varies is
/// *which file* and there is no other field to pin. What replaces a second axis
/// here is the positive control — a scan whose needle stopped matching would
/// otherwise report an empty offender set and pass.
#[test]
fn census_returns_the_only_token_that_reaches_a_consumer() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let census_module = root.join("src/runner/container/census.rs");
    let mut offenders = Vec::new();
    let mut scanned = 0;
    for path in walk(&root.join("src")) {
        let source = fs::read_to_string(&path).expect("read source");
        let production =
            crate::effects::blank_comments_and_strings(&crate::effects::production_region(&source));
        scanned += 1;
        if path == census_module {
            continue;
        }
        if production.contains("CensusComplete {") {
            offenders.push(path.display().to_string());
        }
    }
    assert!(scanned > 20, "the walk found the tree: {scanned}");
    assert!(
        offenders.is_empty(),
        "`CensusComplete` is constructed outside the census: {offenders:#?}"
    );

    let production =
        crate::effects::blank_comments_and_strings(&crate::effects::production_region(
            &fs::read_to_string(&census_module).expect("the census module"),
        ));
    // The positive control. `CensusComplete {` appears three times here — the
    // declaration, the `impl` header and the one construction — so the control
    // needle is the construction shape alone, and the scan above would find it
    // if it moved into another file.
    assert_eq!(
        production.matches("Ok(CensusComplete {").count(),
        1,
        "the census constructs its token exactly once, so the scan above is measuring \
         something"
    );
    assert_eq!(production.matches("CensusComplete {").count(), 3);

    // And the type really is closed: its field is private, so no other module
    // can build one even with a struct literal.
    let harness = Harness::new("token-shape");
    let complete = harness.census(&fresh(INC_1)).expect("an empty census");
    assert_eq!(complete.report().incarnation, INC_1);
    assert_eq!(complete.report().orphan_window, super::orphan_window());
}

/// Every `src/**/*.rs`, sorted.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read src")
        .map(|entry| entry.expect("entry").path())
        .collect();
    entries.sort();
    let mut found = Vec::new();
    for path in entries {
        if path.is_dir() {
            found.extend(walk(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

// ---------------------------------------------------------------------------
// 7. The resource rows this census is accountable for
// ---------------------------------------------------------------------------

/// R20 is `operator_owned` and `persistent_output` in **all five**
/// `at_run_end` outcomes, and no census path touches it.
///
/// `resource_accounting[R20]`: "per-agent credential volume … `persistent_output`
/// (**never created or pruned by a run**)" for `Complete`, `Parked`, `Halted`,
/// `BudgetExceeded` and `NoRunFinished`. A run that tidied a volume it mounted
/// would destroy operator credentials, and the CLIs **rotate refresh tokens on
/// use**, so a discarded rotation forces a re-login.
///
/// Two halves, because either alone is weak: the five outcomes are transcribed
/// from the packet as an independent table, and the census is measured to issue
/// no volume operation at all on a fixture that reclaims two containers.
///
/// Second field held constant: a volume **is present** throughout, and two
/// containers really are reclaimed around it. Varying only the outcome column
/// would leave a table nothing executes; varying only the census would leave a
/// run that never had a volume to spare. The pair is what makes "never created
/// or pruned by a run" a measurement.
#[test]
fn r20_is_persistent_output_in_every_at_run_end_outcome_and_no_census_path_touches_it() {
    /// Transcribed from `decisions.resource_accounting.rows[R20].at_run_end`,
    /// not read back from any code.
    const AT_RUN_END: &[(&str, &str)] = &[
        ("Complete", "persistent_output"),
        ("Parked", "persistent_output"),
        ("Halted", "persistent_output"),
        ("BudgetExceeded", "persistent_output"),
        ("NoRunFinished", "persistent_output"),
    ];
    assert_eq!(AT_RUN_END.len(), 5);
    let dispositions: BTreeSet<&str> = AT_RUN_END.iter().map(|(_, value)| *value).collect();
    assert_eq!(
        dispositions.into_iter().collect::<Vec<_>>(),
        vec!["persistent_output"],
        "R20 is operator-owned in every outcome; a row with a `pruned` cell is a row a run \
         may clean up"
    );

    let harness = Harness::new("r20-untouched");
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    harness.runtime.add_volume("tactus-claude-code");
    for invocation in [shell_probe(), agent_probe()] {
        seed(
            &harness.root,
            &harness.runtime,
            &dead,
            &invocation,
            Present::Both,
            Liveness::Running,
        );
    }
    let complete = harness.census(&fresh(INC_2)).expect("the census completes");
    assert_eq!(complete.report().reclaimed.len(), 2);
    assert!(
        !harness.trace.ops().contains(&RuntimeOp::InspectVolume),
        "a census inspected a volume: {:?}",
        harness.trace.ops()
    );
    assert!(
        harness
            .runtime
            .volume_present("tactus-claude-code")
            .expect("ask the runtime"),
        "the volume this census reclaimed containers around is still there"
    );

    // And the module names no volume operation at all.
    let production =
        crate::effects::blank_comments_and_strings(&crate::effects::production_region(
            &fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runner/container/census.rs"),
            )
            .expect("the census module"),
        ));
    for needle in ["volume_present", "add_volume", "remove_volume"] {
        assert!(!production.contains(needle), "the census names `{needle}`");
    }
}

/// R26 is `released` in `Complete`, `Parked`, `Halted` and `BudgetExceeded`, and
/// the census is the mechanism for the fifth cell.
///
/// `resource_accounting[R26].at_run_end`: four outcomes release the container
/// (`release`, which is the funnel's completion sequence), and `NoRunFinished`
/// is reclaimed at the next write-command start — which is this module. A
/// container surviving a **budget stop** or a **park** would keep spending while
/// the run is supposed to be quiescent, which is why the first four are
/// `released` rather than "left for the census".
///
/// The four `released` cells belong to `release` and are held by
/// `runner::container::tests`; what is executed here is the fifth, and that a
/// container left by a run that never finished is gone, record and view with it.
///
/// Second field held constant: the owner is dead and the container is running
/// in the executed half, so the only thing distinguishing `NoRunFinished` from
/// the four `released` outcomes is **which mechanism disposes of it** — the
/// census here, `release` there. All three of R26's container, R19's view and
/// R26's record are asserted gone, because a fifth cell that pruned two of
/// three would leave the ledgers unbalanced in a way a single assertion misses.
#[test]
fn r26_is_released_in_four_outcomes_and_the_census_is_the_mechanism_for_no_run_finished() {
    /// Transcribed from `decisions.resource_accounting.rows[R26].at_run_end`.
    const AT_RUN_END: &[(&str, &str)] = &[
        ("Complete", "released"),
        ("Parked", "released"),
        ("Halted", "released"),
        ("BudgetExceeded", "released"),
        ("NoRunFinished", "reclaimed at the next write-command start"),
    ];
    assert_eq!(AT_RUN_END.len(), 5);
    assert_eq!(
        AT_RUN_END
            .iter()
            .filter(|(_, value)| *value == "released")
            .count(),
        4,
        "a container surviving a park or a budget stop keeps spending while the run is \
         supposed to be quiescent"
    );

    let harness = Harness::new("r26-no-run-finished");
    let never_finished = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let name = seed(
        &harness.root,
        &harness.runtime,
        &never_finished,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    assert!(
        harness.view_exists(&name),
        "R19's directory is there to prune"
    );
    harness.census(&fresh(INC_2)).expect("the census completes");
    assert!(!harness.holds(&name), "R26: the container");
    assert!(!harness.view_exists(&name), "R19: the view");
    assert!(!harness.intent_exists(&name), "R26: the intent record");
    assert!(
        fs::read_dir(containers_dir(&harness.root))
            .expect("the namespace")
            .next()
            .is_none(),
        "the ledgers balance: nothing is left in the namespace"
    );
}

/// The observation wait is a step, not an implementation detail, and it is
/// **bounded**.
///
/// "reclaim = docker kill -> **wait until observed exited/removed** -> docker rm
/// …". Dropping the wait is the classic mutation: `kill` then `rm` still leaves
/// the container gone at the end, so a test that only checks the final state
/// passes. Here the container never terminates, the bound is exhausted, and the
/// refusal names the clause — and `docker rm` is never issued, which is what
/// says the wait sits **between** kill and rm rather than after both.
///
/// Second field held constant: the same container, owner and dead-owner verdict
/// as [`orphan_reclaimed_before_slot_reset`]; only whether `stop` actually stops
/// it moves.
#[test]
fn a_container_that_never_terminates_exhausts_the_bounded_observation_and_refuses() {
    let root = scratch("never-terminates");
    let trace = ContainerTrace::recording();
    let inner = Arc::new(FakeRuntime::new(trace.clone()));
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let name = seed(
        &root,
        &inner,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    let wedged = WedgedRuntime {
        inner: Arc::clone(&inner),
    };
    let liveness = RecordingLiveness::new();
    let view = DisposableDirView::new(trace.clone());
    let mut hooks = RecordingHooks::new(trace.clone());
    let start = fresh(INC_2);
    let error = run_startup_census(
        &mut hooks,
        &Census {
            private_root: &root,
            start: &start,
            runtime: &wedged,
            liveness: &liveness,
            view: &view,
        },
    )
    .expect_err("a container that never terminates cannot be reclaimed");
    let message = refusal(&error);
    assert!(
        message.contains(&format!("after {TERMINATION_OBSERVATIONS} observations")),
        "{message}"
    );
    assert!(message.contains("blocks admission"), "{message}");
    assert_eq!(
        trace
            .ops()
            .into_iter()
            .filter(|op| *op == RuntimeOp::Observe)
            .count(),
        TERMINATION_OBSERVATIONS,
        "the wait is bounded: exactly the declared number of observations, not a spin"
    );
    assert!(
        trace.position_starting("rt:remove:").is_none(),
        "`docker rm` was issued before termination was proven: {:#?}",
        trace.rendered()
    );
    assert!(inner.container(name.as_str()).is_some());
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 8. The Unix reaper's selector — ST-16 (d)'s half that is pure
// ---------------------------------------------------------------------------

/// The reaper's selector names **both** labels, and every component varies the
/// rendering independently.
///
/// `os_matrix`: the reaper "kills the **dead coordinator's** labeled
/// containers". `tactus.private_root` alone names every container of every run
/// under `<R>`, including a **live** coordinator's — which
/// `T-CONTAINER.authoritative_state` forbids in as many words ("a live
/// incarnation's containers must not be touched"). The incarnation is a
/// per-process ULID and is what makes the selector name one coordinator.
///
/// Second field held constant: the program is the same in every cell, so the
/// only thing that moves is the pair of label values.
#[test]
fn the_reapers_container_selector_names_the_incarnation_and_not_the_root_alone() {
    let roots = [Path::new("/srv/a"), Path::new("/srv/b")];
    let incarnations = [INC_1, INC_2];
    let mut rendered = BTreeSet::new();
    for root in roots {
        for incarnation in incarnations {
            let scope = super::ReaperContainerScope::new("/usr/bin/docker", root, incarnation)
                .expect("a scope");
            let argv = scope.list_argv();
            assert_eq!(argv[0], "/usr/bin/docker");
            assert_eq!(argv[1], "ps");
            assert!(
                argv.contains(&"--all".to_owned()),
                "an exited container still holds its name, its labels and its layer: {argv:?}"
            );
            let filters: Vec<&String> = argv
                .iter()
                .filter(|argument| argument.starts_with("label="))
                .collect();
            assert_eq!(filters.len(), 2, "{argv:?}");
            assert!(filters.contains(&&format!(
                "label={LABEL_PRIVATE_ROOT}={}",
                private_root_label(root)
            )));
            assert!(filters.contains(&&format!("label={LABEL_INCARNATION}={incarnation}")));
            assert_eq!(
                filters.iter().collect::<BTreeSet<_>>().len(),
                2,
                "two filters carrying one value is one filter"
            );
            rendered.insert(argv.join(" "));
        }
    }
    assert_eq!(
        rendered.len(),
        4,
        "two roots and two incarnations, varied independently, must give four distinct \
         selectors; a selector that dropped either component gives two"
    );

    // kill and rm carry the id and nothing else, and the reaper does only those
    // two: the view and the record are the next census's.
    let scope = super::ReaperContainerScope::new("docker", roots[0], INC_1).expect("a scope");
    assert_eq!(scope.kill_argv("abc"), vec!["docker", "kill", "abc"]);
    assert_eq!(
        scope.remove_argv("abc"),
        vec!["docker", "rm", "--force", "abc"]
    );
    assert_eq!(scope.program(), Path::new("docker"));
}

/// A label value that could change what the filter selects is refused.
///
/// The reaper has no error channel and no allocator: it cannot report a
/// malformed selector, and a filter that matched more than it should would kill
/// a live coordinator's containers. So the check is on the parent side, and it
/// is a refusal.
///
/// Second field held constant: the private root is well-formed in the
/// incarnation cases and vice versa, so each case names one hostile value.
#[test]
fn a_reaper_scope_whose_label_value_could_widen_the_filter_is_refused() {
    let good_root = Path::new("/srv/private");
    let hostile = ["", "01KZ\nlabel=tactus.run", "a,b", "a=b"];
    assert_eq!(
        hostile.iter().collect::<BTreeSet<_>>().len(),
        4,
        "four distinct hostile values"
    );
    for value in hostile {
        assert!(
            super::ReaperContainerScope::new("docker", good_root, value).is_err(),
            "`{value}` was accepted as an incarnation"
        );
        assert!(
            super::ReaperContainerScope::new("docker", Path::new(value), INC_1).is_err(),
            "`{value}` was accepted as a private root"
        );
    }
    // And the well-formed pair is accepted, so this is not a function that
    // refuses everything.
    assert!(super::ReaperContainerScope::new("docker", good_root, INC_1).is_ok());
}

// ---------------------------------------------------------------------------
// 9. Docker-gated: a census against the real runtime
// ---------------------------------------------------------------------------

/// A census over **real Docker** reclaims a dead owner's labeled orphan and
/// leaves a live owner's container alone.
///
/// The fake proves the decision; this proves the decision survives contact with
/// the runtime the decision is about — `docker ps --filter label=…` really does
/// return the containers this census expects, `docker kill`/`rm` really are
/// idempotent, and `observe` really does report a removed container as gone.
///
/// **Never pulls** (`non_goals[1]`): the image is discovered among what the
/// machine already holds, and a machine holding none reports absence through the
/// same loud, counted gate.
///
/// Second field held constant: both containers are created from the same image
/// with the same command under the same private root; the only thing that
/// differs is whether their owner's run directory is reported live.
#[test]
fn real_docker_census_reclaims_a_dead_owner_and_spares_a_live_one() {
    let trace = ContainerTrace::recording();
    let docker = match crate::runner::container::docker_gate(
        "real_docker_census_reclaims_a_dead_owner_and_spares_a_live_one",
        trace.clone(),
    ) {
        Ok(docker) => docker,
        Err(reason) => {
            assert_eq!(
                reason,
                crate::runner::container::fake::absent_reason(),
                "a Docker-gated test skipped for a reason the gate does not know about"
            );
            return;
        }
    };
    let image = ["alpine:3.20", "busybox:latest", "debian:stable-slim"]
        .into_iter()
        .find_map(|reference| docker.image_by_reference(reference).ok().flatten());
    let Some(image) = image else {
        assert!(
            std::env::var_os(crate::runner::container::fake::REQUIRE_DOCKER).is_none(),
            "TACTUS_REQUIRE_DOCKER is set and the runtime holds none of the images these \
             tests may use; they never pull (non_goals[1])"
        );
        return;
    };

    // Owner constants THIS TEST ALONE uses. Container names are deterministic
    // and the daemon is one namespace shared with every other Docker-gated test
    // in this tree, which run concurrently: reusing the fixture constants above
    // made `docker create` fail with a name conflict against
    // `runner::container::tests`'s own gated test. Measured, and the reason
    // these four constants exist.
    const REAL_REPO_KEY: &str = "cccccccccccccccc";
    const REAL_RUN_LIVE: &str = "01KZTREALLIVE00000000000AA";
    const REAL_RUN_DEAD: &str = "01KZTREALDEAD00000000000BB";
    let root = scratch("real-docker-census");
    let live = Owner::new(REAL_RUN_LIVE, INC_1, REAL_REPO_KEY);
    let dead = Owner::new(REAL_RUN_DEAD, INC_2, REAL_REPO_KEY);
    let liveness = RecordingLiveness::new();
    liveness.set_live(&live.run_dir);

    let mut names = Vec::new();
    for owner in [&live, &dead] {
        let name = owner.name(&shell_probe());
        let record = owner.record(&shell_probe());
        let mut hooks = RecordingHooks::new(ContainerTrace::off());
        write_intent(
            &mut hooks,
            ContainerSite::WriteIntent,
            &root,
            &name,
            &record,
        )
        .expect("write the intent");
        let plan = crate::runner::container::LaunchPlan {
            private_root: root.clone(),
            name: name.clone(),
            intent: record.clone(),
            spec: crate::runner::container::runtime::CreateSpec {
                name: name.as_str().to_owned(),
                image_id: image.id.clone(),
                labels: record.labels(&root),
                mounts: Vec::new(),
                env: Vec::new(),
                command: vec!["sleep".to_owned(), "120".to_owned()],
                workdir: None,
            },
            view: crate::runner::container::GitViewRequest {
                path: view_path(&root, &name),
                workspace: root.clone(),
                head: None,
            },
        };
        let view = DisposableDirView::new(ContainerTrace::off());
        let mut hooks = RecordingHooks::new(ContainerTrace::off());
        crate::runner::container::launch(&mut hooks, docker.as_ref(), &view, &plan)
            .expect("launch a real container from the recorded image id");
        names.push(name);
    }

    let view = DisposableDirView::new(trace.clone());
    let mut hooks = RecordingHooks::new(trace.clone());
    let start = fresh(INC_3);
    let outcome = run_startup_census(
        &mut hooks,
        &Census {
            private_root: &root,
            start: &start,
            runtime: docker.as_ref(),
            liveness: &liveness,
            view: &view,
        },
    );

    // Whatever happened, do not leave real containers behind.
    let cleanup = |name: &ContainerName| {
        let view = DisposableDirView::new(ContainerTrace::off());
        let mut hooks = RecordingHooks::new(ContainerTrace::off());
        let _ = crate::runner::container::reclaim(
            &mut hooks,
            docker.as_ref(),
            &view,
            &root,
            name,
            Some(&view_path(&root, name)),
        );
    };
    let report = match &outcome {
        Ok(complete) => complete.report().clone(),
        Err(error) => {
            for name in &names {
                cleanup(name);
            }
            let _ = fs::remove_dir_all(&root);
            panic!("the census refused against real Docker: {error}");
        }
    };
    let live_name = names[0].clone();
    let dead_name = names[1].clone();
    let live_still_there = docker
        .observe(live_name.as_str())
        .expect("observe the live owner's container");
    let dead_gone = docker
        .observe(dead_name.as_str())
        .expect("observe the dead owner's container");
    for name in &names {
        cleanup(name);
    }
    let _ = fs::remove_dir_all(&root);

    assert_eq!(report.reclaimed.len(), 1, "{report:#?}");
    assert_eq!(report.reclaimed[0].name, dead_name);
    assert_eq!(
        report.reclaimed[0].boundary,
        Boundary::FromIntent(POLICY_A.to_owned())
    );
    assert_eq!(report.untouched.len(), 1);
    assert_eq!(report.untouched[0].name, live_name);
    assert_eq!(
        dead_gone,
        Liveness::Gone,
        "the real runtime still holds the dead owner's container"
    );
    assert_eq!(
        live_still_there,
        Liveness::Running,
        "a live owner's real container was stopped by a foreign census"
    );
}

/// A record that disappears between the namespace scan and the read of it is
/// **skipped**, deterministically.
///
/// This is the discovery half of "every step idempotent and tolerant of
/// already-gone so **two concurrent reclaimers converge**", and the racing
/// fixture above reaches it only by luck. The state it reaches — a directory
/// entry whose file is not there — is constructible on demand as a **dangling
/// symlink**: `read_dir` lists it and `fs::read` answers `NotFound`, which is
/// byte-for-byte the answer the losing reclaimer gets.
///
/// Measured, not assumed: before the repair in `list_intents`, a whole write
/// command refused with `Io { NotFound }` because another write command was
/// tidying at the same moment.
///
/// Second field held constant: a real, readable record sits beside the vanished
/// one in the same namespace, so the test cannot pass by skipping everything.
///
/// Unix-only because a dangling symlink needs a privilege the Windows guest's
/// test user does not have; the racing fixture above covers the same property
/// on every platform, less sharply, and this comment is the record of which
/// half runs where.
#[cfg(unix)]
#[test]
fn a_record_that_vanishes_between_the_scan_and_the_read_is_skipped() {
    let harness = Harness::new("vanishing-record");
    let dead = Owner::new(RUN_B, INC_1, REPO_KEY_A);
    let real = seed(
        &harness.root,
        &harness.runtime,
        &dead,
        &shell_probe(),
        Present::Both,
        Liveness::Running,
    );
    let vanished = dead.name(&agent_probe());
    let path = vanished.intent_path(&harness.root);
    std::os::unix::fs::symlink(harness.root.join("this-record-is-gone"), &path)
        .expect("a dangling entry in the namespace");
    assert!(fs::symlink_metadata(&path).is_ok(), "read_dir will list it");
    assert_eq!(
        fs::read(&path)
            .expect_err("and reading it answers NotFound")
            .kind(),
        std::io::ErrorKind::NotFound,
        "the fixture must produce the losing reclaimer's exact answer"
    );

    let complete = harness
        .census(&fresh(INC_2))
        .expect("a record another reclaimer removed is not a reason to refuse a write command");
    let report = complete.report();
    assert_eq!(report.reclaimed.len(), 1, "{:#?}", report.reclaimed);
    assert_eq!(report.reclaimed[0].name, real);
    assert!(!harness.holds(&real));

    // And a record that is present but unreadable is still an error: "the
    // record could not be read" and "the record is gone" are different answers,
    // and only one of them licenses proceeding. Two shapes, because the
    // tolerance has two ways to be too wide.
    let malformed = Harness::new("malformed-record");
    let torn = dead.name(&shell_probe());
    let torn_path = torn.intent_path(&malformed.root);
    fs::create_dir_all(torn_path.parent().expect("the namespace")).expect("namespace");
    fs::write(&torn_path, b"{ this is not a container intent").expect("a damaged record");
    assert!(
        malformed.census(&fresh(INC_2)).is_err(),
        "a damaged record was treated as an absent one"
    );

    // The one that matters for the Windows repair: a record whose read fails
    // with **`PermissionDenied`** and keeps failing. The repair tolerates that
    // errno while a delete is pending, and a repair that tolerated it outright
    // would let a census admit over a container whose ownership evidence it
    // could not read. The bound is what separates the two, and this is the
    // fixture that holds the separation.
    let protected = Harness::new("unreadable-record");
    let locked = dead.name(&agent_probe());
    let locked_path = locked.intent_path(&protected.root);
    fs::create_dir_all(locked_path.parent().expect("the namespace")).expect("namespace");
    fs::write(&locked_path, b"{}").expect("a record");
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&locked_path, fs::Permissions::from_mode(0o000))
            .expect("make the record unreadable");
    }
    let outcome = protected.census(&fresh(INC_2));
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&locked_path, fs::Permissions::from_mode(0o600));
    }
    assert!(
        outcome.is_err(),
        "a record that is THERE and cannot be read was treated as one that is gone; the \
         already-gone tolerance is about a delete in flight, not about every PermissionDenied"
    );
}
