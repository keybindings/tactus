//! The container substrate's own suite.
//!
//! Four things this file is organised around, each learned expensively on this
//! project:
//!
//! * **Orderings are most of the contract.** "intent synced before docker
//!   create", "verified before start", "view mounted before start", "stop/rm,
//!   view removal, intent removal after completion", and reclaim's own five
//!   steps are each an independently droppable predicate. Every one is asserted
//!   as a **sequence** taken from [`ContainerTrace`], never as membership.
//! * **A function may not be its own oracle.** Every expected digest and every
//!   expected name in this file is a literal, computed out of band with
//!   `python3 -c 'hashlib.sha256(...)'` against the packet's own template, and
//!   the tuple that produces it is written beside it.
//! * **Fixtures vary every independently meaningful field independently**, and
//!   hostility is asserted as **distinct-value counts**.
//! * **The dominant defect is two axes covered separately with the intersection
//!   never built.** Each test below names the second field it holds constant.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::fake::absent_reason;
use super::intent::{
    self, CONTAINERS_DIR, ContainerIntent, ContainerName, INTENT_SUFFIX, LABEL_INCARNATION,
    LABEL_INVOCATION, LABEL_PRIVATE_ROOT, LABEL_RUN, LABEL_RUN_DIR, LABELS, containers_dir,
    invocation_hash,
};
use super::runtime::{
    ContainerExecution, ContainerRuntime, ContainerTrace, CreateSpec, ImageInspection, Liveness,
    Mount, OwnerLiveness, RuntimeError, RuntimeOp, StopMode, TracePhase,
};
use super::{
    DOCKER_GATED_TESTS, DisposableDirView, FakeOwnerLiveness, FakeRuntime, FoundIntent,
    GitViewRequest, LaunchPlan, Launched, NoHooks, OrphanWindow, RecordingHooks,
    TERMINATION_OBSERVATIONS, create_container, docker_gate, launch, list_intents, mount_git_view,
    observe_terminated, read_intent, reclaim, release, remove_container, remove_intent,
    start_container, stop_container, unmount_git_view, write_intent,
};
use crate::error::TactusError;
use crate::runner::{AgentId, InvocationId, ProbeTarget};
use crate::topology::effects::{
    Adjacent, ContainerSite, DurableEvent, EffectSiteId, FaultRow, ResourceRow, SiteScope,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A scratch private root, in the idiom of `effects::tests::scratch_dir`.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tactus-container-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a scratch private root");
    dir
}

/// The four name components used across this file, each a distinct value so a
/// swap between two of them is visible.
const REPO_KEY: &str = "0123456789abcdef";
const RUN_A: &str = "01KZRN48A4ZK3AEDST3RJ8HMA4";
const RUN_B: &str = "01KZS7R0V1ZD6MC290MG350QXF";
const INCARNATION_1: &str = "01KZTAAAAAAAAAAAAAAAAAAAAA";
const INCARNATION_2: &str = "01KZTBBBBBBBBBBBBBBBBBBBBB";

/// The recorded image id, and a different one, and a third.
const IMAGE_ID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_IMAGE_ID: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const IMAGE_REFERENCE: &str = "ghcr.io/example/tactus-runner:v1";
const MANIFEST_DIGEST: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const POLICY_DIGEST: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";

/// A shell probe identity. Deterministic across incarnations **by
/// construction** — `InvocationId::Probe`'s own doc says so — which is why the
/// container name carries the incarnation.
fn shell_probe() -> InvocationId {
    InvocationId::probe(ProbeTarget::Shell, 0).expect("the shell probe identity")
}

/// An agent probe identity.
fn agent_probe() -> InvocationId {
    InvocationId::probe(ProbeTarget::Agent(AgentId::new("claude-code")), 0)
        .expect("the agent probe identity")
}

/// The intent record for `run`/`incarnation`, with every field a distinct
/// value.
fn intent_for(run: &str, incarnation: &str, invocation: &InvocationId) -> ContainerIntent {
    ContainerIntent {
        run_id: run.to_owned(),
        run_dir: format!("/srv/public/{run}"),
        incarnation: incarnation.to_owned(),
        repo_key: REPO_KEY.to_owned(),
        invocation: invocation.render(),
        runner_policy_sha256: POLICY_DIGEST.to_owned(),
    }
}

/// The name for `run`/`incarnation`.
fn name_for(run: &str, incarnation: &str, invocation: &InvocationId) -> ContainerName {
    ContainerName::new(REPO_KEY, run, incarnation, invocation).expect("a container name")
}

/// The five labels a container of this run carries.
fn labels_for(root: &Path, record: &ContainerIntent) -> BTreeMap<String, String> {
    record.labels(root)
}

/// A create spec that asks for `image_id`.
fn spec_for(
    name: &ContainerName,
    record: &ContainerIntent,
    root: &Path,
    image_id: &str,
) -> CreateSpec {
    CreateSpec {
        name: name.as_str().to_owned(),
        image_id: image_id.to_owned(),
        labels: labels_for(root, record),
        mounts: vec![Mount::Path {
            source: PathBuf::from("/srv/work/task"),
            target: "/work".to_owned(),
            read_only: false,
        }],
        env: vec![("HOME".to_owned(), "/home/tactus".to_owned())],
        command: vec!["/bin/sh".to_owned(), "-c".to_owned(), "exit 0".to_owned()],
        workdir: Some("/work".to_owned()),
    }
}

/// A whole plan, plus a fake runtime already holding the recorded image.
struct Fixture {
    root: PathBuf,
    trace: ContainerTrace,
    runtime: FakeRuntime,
    view: DisposableDirView,
    plan: LaunchPlan,
}

impl Fixture {
    fn new(tag: &str, run: &str, incarnation: &str, invocation: &InvocationId) -> Self {
        let root = scratch(tag);
        let trace = ContainerTrace::recording();
        let runtime = FakeRuntime::new(trace.clone());
        runtime.add_image(IMAGE_ID, Some(MANIFEST_DIGEST));
        runtime.add_image(OTHER_IMAGE_ID, None);
        runtime.tag(IMAGE_REFERENCE, IMAGE_ID);
        let record = intent_for(run, incarnation, invocation);
        let name = name_for(run, incarnation, invocation);
        let spec = spec_for(&name, &record, &root, IMAGE_ID);
        let view = GitViewRequest {
            path: root.join("views").join(name.as_str()),
            workspace: PathBuf::from("/srv/work/task"),
            head: Some("0".repeat(40)),
        };
        Self {
            plan: LaunchPlan {
                private_root: root.clone(),
                name,
                intent: record,
                spec,
                view,
            },
            view: DisposableDirView::new(trace.clone()),
            runtime,
            trace,
            root,
        }
    }

    fn hooks(&self) -> RecordingHooks {
        RecordingHooks::new(self.trace.clone())
    }
}

/// What a Docker-gated test does when there is no runtime.
///
/// It **reads** the reason rather than returning silently, so a skip that had
/// stopped saying why would not compile. Combined with
/// [`super::fake::REQUIRE_DOCKER`] — which turns a skip into a failure on a
/// machine that has Docker — and with
/// [`every_docker_gated_test_is_named_and_present`], which counts the gated
/// tests by name, this is the whole of "loud and counted, never silent".
fn skipped(reason: &str) {
    assert_eq!(
        reason,
        absent_reason(),
        "a Docker-gated test skipped for a reason the gate does not know about"
    );
}

/// What a Docker-gated test does when the runtime holds no usable image.
///
/// The second absence, and it is a different one: Docker answers, and there is
/// nothing to inspect. It is loud under the same variable, because a machine
/// that has a runtime and no image would otherwise pass three tests that never
/// touched it.
fn no_image(reason: &str) {
    assert!(reason.contains("never pull"), "{reason}");
    assert!(
        std::env::var_os(super::fake::REQUIRE_DOCKER).is_none(),
        "{} is set and a gated test found no usable image: {reason}",
        super::fake::REQUIRE_DOCKER
    );
}

/// Where `needle` first appears in the trace, or a failure naming the whole
/// sequence — because "x before y" is unreadable when the report is `None`.
fn at(trace: &ContainerTrace, needle: &str) -> usize {
    trace.position(needle).unwrap_or_else(|| {
        panic!(
            "`{needle}` is not in the trace, which is {:#?}",
            trace.rendered()
        )
    })
}

// ---------------------------------------------------------------------------
// 1. The fake's six required capabilities
// ---------------------------------------------------------------------------

/// (1) an image table keyed by **immutable id**, with references and digests.
///
/// Second field held constant: the runtime is reachable throughout, so what
/// varies is only which key the table is read by. Without an id-keyed table,
/// `image_by_id` could not answer at all and the rebuild path's refusal — "the
/// **recorded image id** is absent from the runtime" — would be unwritable.
#[test]
fn the_image_table_is_keyed_by_id_and_references_resolve_through_it() {
    let runtime = FakeRuntime::new(ContainerTrace::recording());
    runtime.add_image(IMAGE_ID, Some(MANIFEST_DIGEST));
    runtime.add_image(OTHER_IMAGE_ID, None);
    runtime.tag(IMAGE_REFERENCE, IMAGE_ID);

    let by_id = runtime
        .image_by_id(IMAGE_ID)
        .expect("reachable")
        .expect("present");
    assert_eq!(by_id.id, IMAGE_ID);
    assert_eq!(by_id.digest.as_deref(), Some(MANIFEST_DIGEST));

    let by_reference = runtime
        .image_by_reference(IMAGE_REFERENCE)
        .expect("reachable")
        .expect("present");
    assert_eq!(
        by_reference.id, IMAGE_ID,
        "the reference resolves to the id"
    );
    assert_eq!(by_reference.references, vec![IMAGE_REFERENCE.to_owned()]);

    // "the manifest digest **when reported**" — absent is a real state and a
    // separately encodable one, not a missing fixture.
    let without = runtime
        .image_by_id(OTHER_IMAGE_ID)
        .expect("reachable")
        .expect("present");
    assert_eq!(without.digest, None);

    // The two questions are independent: an id present under no reference is
    // findable by id and by no reference.
    assert_eq!(runtime.image_by_reference("ghcr.io/nobody:v9"), Ok(None));
    assert_eq!(runtime.image_by_id("sha256:absent"), Ok(None));
}

/// (2) a **mutable tag table** — a reference can be moved to another id while
/// the id stays.
///
/// ST-20: "a resume after the recorded reference was moved to another image
/// warns and creates every container from the recorded id". Without a mutable
/// tag table that sentence has no fixture at all.
///
/// Second field held constant: the image table itself. Both ids are present
/// before and after; only the tag moves — which is the whole point, because a
/// fixture that also deleted the old id would prove the wrong thing.
#[test]
fn a_reference_can_be_moved_to_another_id_and_the_old_id_stays() {
    let runtime = FakeRuntime::new(ContainerTrace::recording());
    runtime.add_image(IMAGE_ID, Some(MANIFEST_DIGEST));
    runtime.add_image(OTHER_IMAGE_ID, None);
    runtime.tag(IMAGE_REFERENCE, IMAGE_ID);

    runtime.move_tag(IMAGE_REFERENCE, OTHER_IMAGE_ID);

    assert_eq!(
        runtime
            .image_by_reference(IMAGE_REFERENCE)
            .expect("reachable")
            .expect("present")
            .id,
        OTHER_IMAGE_ID,
        "the reference now names another image"
    );
    assert!(
        runtime.image_by_id(IMAGE_ID).expect("reachable").is_some(),
        "the recorded id is still resolvable, which is what lets the rebuild \
         create from it while the reference has moved"
    );
    // Two distinct answers to two distinct questions about one reference: the
    // intersection {image id recorded} x {reference moved} rather than either
    // alone.
    let answers: BTreeSet<String> = [
        runtime
            .image_by_reference(IMAGE_REFERENCE)
            .expect("reachable")
            .expect("present")
            .id,
        runtime
            .image_by_id(IMAGE_ID)
            .expect("reachable")
            .expect("present")
            .id,
    ]
    .into_iter()
    .collect();
    assert_eq!(answers.len(), 2);
}

/// (3) per-container **reported image ids with substitution injection**.
///
/// The correlated-fixture trap this slice was warned about: if the reported id
/// were set from the requested id there would be no way to build a
/// substitution, and `substituted_image_id_refused_before_start` would be green
/// because it could not be written. This is the test that proves the two are
/// separate inputs.
#[test]
fn the_fake_can_report_an_image_id_that_differs_from_the_one_create_asked_for() {
    let trace = ContainerTrace::recording();
    let runtime = FakeRuntime::new(trace);
    runtime.add_image(IMAGE_ID, None);
    let spec = CreateSpec {
        name: "tactus-a-b-c-d".to_owned(),
        image_id: IMAGE_ID.to_owned(),
        labels: BTreeMap::new(),
        mounts: Vec::new(),
        env: Vec::new(),
        command: Vec::new(),
        workdir: None,
    };

    // Healthy: the runtime reports what it was asked for.
    let honest = runtime.create(&spec).expect("created");
    assert_eq!(honest.reported_image_id, IMAGE_ID);
    runtime.remove(&spec.name).expect("removed");

    // Injected: it does not.
    runtime.substitute_reported_image_id(&spec.name, OTHER_IMAGE_ID);
    let substituted = runtime.create(&spec).expect("created");
    assert_eq!(substituted.reported_image_id, OTHER_IMAGE_ID);
    assert_ne!(
        substituted.reported_image_id, spec.image_id,
        "the reported id and the requested id are separate inputs; if this ever \
         becomes impossible, every image-verification test in this slice is vacuous"
    );

    // And the container the fake holds records both, separately.
    let held = runtime.container(&spec.name).expect("held");
    assert_eq!(held.requested_image_id, IMAGE_ID);
    assert_eq!(held.reported_image_id, OTHER_IMAGE_ID);
}

/// (4) **volume presence toggles**.
///
/// R20 is operator-owned and `persistent_output` in all five `at_run_end`
/// outcomes — "never created or pruned by a run" — so the only thing a run does
/// with a volume is *observe* it, and absence is a refusal. Second field held
/// constant: the image table, so a refusal here cannot be an image problem
/// wearing a volume's name.
#[test]
fn volume_presence_is_a_toggle_and_absence_refuses_a_create() {
    let trace = ContainerTrace::recording();
    let runtime = FakeRuntime::new(trace);
    runtime.add_image(IMAGE_ID, None);
    assert!(!runtime.volume_present("tactus-claude").expect("reachable"));
    runtime.add_volume("tactus-claude");
    assert!(runtime.volume_present("tactus-claude").expect("reachable"));
    runtime.remove_volume("tactus-claude");
    assert!(!runtime.volume_present("tactus-claude").expect("reachable"));

    let spec = CreateSpec {
        name: "tactus-a-b-c-d".to_owned(),
        image_id: IMAGE_ID.to_owned(),
        labels: BTreeMap::new(),
        mounts: vec![Mount::Volume {
            name: "tactus-claude".to_owned(),
            target: "/home/tactus/.claude".to_owned(),
            read_only: false,
        }],
        env: Vec::new(),
        command: Vec::new(),
        workdir: None,
    };
    let refused = runtime.create(&spec).expect_err("an absent volume refuses");
    assert!(!refused.is_unreachable(), "the runtime answered; it failed");
    runtime.add_volume("tactus-claude");
    assert!(runtime.create(&spec).is_ok(), "and present, it creates");
}

/// (5) an **availability toggle**, and it is per operation.
///
/// The reachability decision this lane made, stated as a test: a runtime that
/// answers `docker ps` and fails `docker inspect` is a real state, and a seam
/// with one global boolean could not express it. The intersection here is
/// {operation} x {reachable?}, which one boolean collapses.
#[test]
fn the_availability_toggle_is_per_operation_so_ps_can_answer_while_inspect_cannot() {
    let runtime = FakeRuntime::new(ContainerTrace::recording());
    runtime.add_image(IMAGE_ID, None);
    runtime.set_unreachable(RuntimeOp::InspectImageById);

    // `ps` answers.
    assert_eq!(
        runtime
            .containers_with_label(LABEL_PRIVATE_ROOT, "/srv/private")
            .expect("ps is reachable"),
        Vec::new()
    );
    // `inspect` does not, and says which operation could not be reached.
    let error = runtime
        .image_by_id(IMAGE_ID)
        .expect_err("inspect is unreachable");
    assert!(error.is_unreachable());
    assert_eq!(error.operation(), RuntimeOp::InspectImageById);

    // The whole daemon down is the other end of the same toggle, and every
    // operation reports it.
    runtime.set_all_unreachable();
    let unreachable: BTreeSet<RuntimeOp> = RuntimeOp::ALL
        .iter()
        .filter(|op| match op {
            RuntimeOp::Probe => runtime.probe().is_err(),
            RuntimeOp::InspectImageByReference => runtime.image_by_reference("x").is_err(),
            RuntimeOp::InspectImageById => runtime.image_by_id("x").is_err(),
            RuntimeOp::InspectVolume => runtime.volume_present("x").is_err(),
            RuntimeOp::ListByLabel => runtime.containers_with_label("k", "v").is_err(),
            RuntimeOp::Observe => runtime.observe("x").is_err(),
            RuntimeOp::Collect => runtime.collect("x").is_err(),
            RuntimeOp::Create => runtime
                .create(&CreateSpec {
                    name: "x".to_owned(),
                    image_id: IMAGE_ID.to_owned(),
                    labels: BTreeMap::new(),
                    mounts: Vec::new(),
                    env: Vec::new(),
                    command: Vec::new(),
                    workdir: None,
                })
                .is_err(),
            RuntimeOp::Start => runtime.start("x").is_err(),
            RuntimeOp::Stop => runtime.stop("x", StopMode::Kill).is_err(),
            RuntimeOp::Remove => runtime.remove("x").is_err(),
        })
        .copied()
        .collect();
    assert_eq!(
        unreachable.len(),
        RuntimeOp::ALL.len(),
        "every operation of the seam has to be able to report unreachability, \
         or a refusal that depends on one of them cannot be written"
    );
    assert_eq!(RuntimeOp::ALL.len(), 11);
}

/// (6) owner **labels**, **incarnations**, and the two image ids as separate
/// inputs.
///
/// Second field held constant: the label *keys* are the packet's five for both
/// containers; what varies is the run and the incarnation, which is the axis
/// the census classifies on.
#[test]
fn a_seeded_container_carries_owner_labels_and_an_incarnation() {
    let runtime = FakeRuntime::new(ContainerTrace::recording());
    let root = PathBuf::from("/srv/private");
    let mine = intent_for(RUN_A, INCARNATION_1, &shell_probe());
    let earlier = intent_for(RUN_A, INCARNATION_2, &shell_probe());
    let foreign = intent_for(RUN_B, INCARNATION_1, &agent_probe());

    for (tag, record) in [
        ("mine", &mine),
        ("earlier", &earlier),
        ("foreign", &foreign),
    ] {
        runtime.seed_container(
            tag,
            record.labels(&root),
            IMAGE_ID,
            // Separate argument, always.
            IMAGE_ID,
            Liveness::Running,
        );
    }

    let found = runtime
        .containers_with_label(LABEL_PRIVATE_ROOT, "/srv/private")
        .expect("reachable");
    assert_eq!(found.len(), 3, "all three share one private root");

    let runs: BTreeSet<&str> = found.iter().filter_map(|c| c.label(LABEL_RUN)).collect();
    let incarnations: BTreeSet<&str> = found
        .iter()
        .filter_map(|c| c.label(LABEL_INCARNATION))
        .collect();
    let invocations: BTreeSet<&str> = found
        .iter()
        .filter_map(|c| c.label(LABEL_INVOCATION))
        .collect();
    // Distinct-value counts, not prose: two runs, two incarnations, two
    // invocations, and the pairs are not the same partition — which is what
    // makes {owner run} x {incarnation} a real grid rather than one axis twice.
    assert_eq!(runs.len(), 2, "{runs:?}");
    assert_eq!(incarnations.len(), 2, "{incarnations:?}");
    assert_eq!(invocations.len(), 2, "{invocations:?}");
    let pairs: BTreeSet<(&str, &str)> = found
        .iter()
        .filter_map(|c| Some((c.label(LABEL_RUN)?, c.label(LABEL_INCARNATION)?)))
        .collect();
    assert_eq!(pairs.len(), 3, "three distinct (run, incarnation) pairs");
}

/// (6b) **liveness simulation**, and the shape that makes an incarnation
/// unreadable from a lock.
///
/// `crash_reconstruction`: the incarnation id "is **never read from lock-file
/// contents**". [`OwnerLiveness`] answers one bit about a public run directory,
/// so there is no incarnation in the return type to read — the defect is not
/// refused, it is unexpressible.
#[test]
fn owner_liveness_answers_one_bit_and_carries_no_incarnation() {
    let liveness = FakeOwnerLiveness::new();
    let live = PathBuf::from("/srv/public/live");
    let dead = PathBuf::from("/srv/public/dead");
    liveness.set_live(&live);

    assert!(liveness.is_running(&live));
    assert!(!liveness.is_running(&dead));
    liveness.set_dead(&live);
    assert!(!liveness.is_running(&live));

    // The production probe is `rundir::is_running`, and it answers the same
    // shape for a directory that never held a run.
    let probe = super::runtime::LockProbe;
    assert!(
        !probe.is_running(&scratch("liveness")),
        "a directory with no run.lock has no live owner"
    );
}

/// The call log is ordered and holds every operation.
///
/// The instrument the rest of this file rests on. Second field held constant:
/// one runtime, one trace; what varies is only how many operations have run.
#[test]
fn the_call_log_is_ordered_and_holds_every_operation() {
    let trace = ContainerTrace::recording();
    let runtime = FakeRuntime::new(trace.clone());
    runtime.add_image(IMAGE_ID, None);
    let spec = CreateSpec {
        name: "tactus-a-b-c-d".to_owned(),
        image_id: IMAGE_ID.to_owned(),
        labels: BTreeMap::new(),
        mounts: Vec::new(),
        env: Vec::new(),
        command: Vec::new(),
        workdir: None,
    };
    runtime.probe().expect("reachable");
    runtime.create(&spec).expect("created");
    runtime.start(&spec.name).expect("started");
    runtime.stop(&spec.name, StopMode::Kill).expect("stopped");
    runtime.observe(&spec.name).expect("observed");
    runtime.remove(&spec.name).expect("removed");

    assert_eq!(
        runtime.calls(),
        vec![
            RuntimeOp::Probe,
            RuntimeOp::Create,
            RuntimeOp::Start,
            RuntimeOp::Stop,
            RuntimeOp::Observe,
            RuntimeOp::Remove,
        ],
        "the call log is a sequence; a set would hold none of this slice's orderings"
    );
    assert_eq!(
        trace.rendered().first().map(String::as_str),
        Some("rt:probe:daemon")
    );
}

// ---------------------------------------------------------------------------
// 2. The eight sites and the funnel's shape
// ---------------------------------------------------------------------------

/// The row, adjacency, fault row and scope of each of the eight sites,
/// transcribed from the packet rather than read back from the enum that
/// produces them.
///
/// `effect_site_inventory.identity`: "Container.* (R19/R26; Container.Create
/// verifies the created container's image id against the record before
/// Container.Start)", and `slice_contract.owned_resources` splits them:
/// "R26 container + labels + global intent incl. runner digest", "R19
/// disposable Git view per request".
#[test]
fn every_container_sites_row_adjacency_fault_row_and_scope_is_the_packets() {
    const EXPECTED: &[(ContainerSite, ResourceRow, Adjacent, FaultRow, SiteScope)] = &[
        (
            ContainerSite::WriteIntent,
            ResourceRow::R26,
            Adjacent::After(DurableEvent::AttemptStarted),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
        (
            ContainerSite::Create,
            ResourceRow::R26,
            Adjacent::After(DurableEvent::AttemptStarted),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
        (
            ContainerSite::Start,
            ResourceRow::R26,
            Adjacent::After(DurableEvent::AttemptStarted),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
        (
            ContainerSite::MountGitView,
            ResourceRow::R19,
            Adjacent::After(DurableEvent::AttemptStarted),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
        (
            ContainerSite::Stop,
            ResourceRow::R26,
            Adjacent::Before(DurableEvent::AttemptFinished),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
        (
            ContainerSite::Remove,
            ResourceRow::R26,
            Adjacent::Before(DurableEvent::AttemptFinished),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
        (
            ContainerSite::UnmountGitView,
            ResourceRow::R19,
            Adjacent::Before(DurableEvent::AttemptFinished),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
        (
            ContainerSite::RemoveIntent,
            ResourceRow::R26,
            Adjacent::Before(DurableEvent::AttemptFinished),
            FaultRow::TContainer,
            SiteScope::Topology,
        ),
    ];
    assert_eq!(EXPECTED.len(), ContainerSite::ALL.len());
    assert_eq!(
        ContainerSite::ALL.len(),
        8,
        "the frozen inventory has eight"
    );
    for (site, row, adjacent, fault, scope) in EXPECTED {
        assert_eq!(site.row(), *row, "{}", site.name());
        assert_eq!(site.adjacent(), *adjacent, "{}", site.name());
        assert_eq!(site.fault_row(), *fault, "{}", site.name());
        assert_eq!(site.scope(), *scope, "{}", site.name());
    }
    // Two of the eight are R19 and six are R26, which is the split
    // `owned_resources` states. A count, so a site moved between rows fails
    // here as well as in its own row above.
    let r19 = EXPECTED.iter().filter(|e| e.1 == ResourceRow::R19).count();
    assert_eq!(r19, 2);
    assert_eq!(EXPECTED.len() - r19, 6);

    // No Container site exposes a parent-side sub-effect point or registers a
    // command-internal residue class, and both absences are **stated** rather
    // than left unmentioned. `command_internal_sub_effects` registers
    // `ObjectResidue::Internal` for the Object sites because a Git child writes
    // objects before publishing their reference; a `docker create` publishes
    // nothing the parent can observe halfway, and the intent record is a
    // stage/rename whose torn half is writer-owned residue the scan skips.
    // `effect_site_inventory.scope` makes every Topology site owe evidence for
    // "every parent-side sub-effect point"; an empty list is that debt being
    // zero, and this is where a variant that grew one would be noticed.
    for site in ContainerSite::ALL {
        assert_eq!(site.sub_effects(), &[], "{}", site.name());
        assert_eq!(site.residue_classes(), &[], "{}", site.name());
        assert_eq!(site.residue_elements(), &[], "{}", site.name());
        assert!(!site.is_read_only(), "{}", site.name());
    }
}

/// **T-CONTAINER (19)** `windows_orphan_window_documented`.
///
/// `decisions.admission_and_leases.permits.os_matrix`:
///
/// > Linux and macOS (cfg(unix)): the cleanup reaper survives coordinator
/// > death, settles the dead coordinator's process groups while holding R28,
/// > and **additionally kills the dead coordinator's labeled containers,
/// > closing the orphan window**; Windows: no reaper; … and **containers are
/// > reclaimed at the next tactus write-command start (orphan window until
/// > then; documented; a portable watchdog is deferred)**.
///
/// The window is a **value** and not only a sentence, so the two platforms give
/// different answers and the Windows guest — which has no container runtime at
/// all — still asserts something about containers. The intersection here is
/// {platform} x {who closes the window}, and a constant would collapse it.
#[test]
fn windows_orphan_window_documented() {
    let window = super::orphan_window();
    if cfg!(windows) {
        assert_eq!(window, OrphanWindow::UntilNextWriteCommandStart);
        assert!(!window.closed_by_a_reaper());
    } else {
        assert_eq!(window, OrphanWindow::ClosedByTheUnixReaper);
        assert!(window.closed_by_a_reaper());
    }

    // Both answers exist and differ, so the value is a platform axis rather
    // than a constant this platform happens to agree with.
    let answers: BTreeSet<OrphanWindow> = OrphanWindow::ALL.iter().copied().collect();
    assert_eq!(answers.len(), 2);
    assert_eq!(
        OrphanWindow::ALL
            .iter()
            .filter(|w| w.closed_by_a_reaper())
            .count(),
        1,
        "exactly one platform has a reaper; `os_matrix` says Windows has none"
    );

    // And the sentence is in the tree, next to the reclaim path it governs, so
    // "documented" is a fact about this file rather than about the packet.
    let raw = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runner/container.rs"),
    )
    .expect("the funnel");
    // Doc-comment markers, block quoting and emphasis removed and whitespace
    // collapsed, because a quoted sentence is wrapped by `rustfmt` at whatever
    // column it lands on and a phrase search over the raw bytes would be
    // asserting the wrap rather than the sentence.
    let source: String = raw
        .replace("//!", " ")
        .replace("///", " ")
        .replace(['>', '*', '`'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for phrase in [
        "orphan window",
        "next write-command start",
        "no reaper",
        "a portable watchdog is deferred",
    ] {
        assert!(
            source.contains(phrase),
            "the orphan window's documentation no longer says `{phrase}`"
        );
    }
}

/// Every one of the eight sites is taken **by value** by a funnel API, and the
/// funnel records both hook phases around the primitive.
///
/// `identity`: "every effectful funnel API takes its group's site by value, and
/// the funnel itself calls hook(Before, site) -> primitive -> hook(After,
/// site), so hooks exist for every site by construction". This is the runtime
/// evidence for that sentence — `effects::tests::every_site_the_inventory_declares_has_a_funnel_that_names_it_or_is_recorded_absent`
/// is the source-level half.
#[test]
fn every_container_site_is_taken_by_value_by_a_funnel_that_hooks_both_phases() {
    let fixture = Fixture::new("all-sites", RUN_A, INCARNATION_1, &shell_probe());
    let mut hooks = fixture.hooks();
    let name = fixture.plan.name.clone();

    write_intent(
        &mut hooks,
        ContainerSite::WriteIntent,
        &fixture.root,
        &name,
        &fixture.plan.intent,
    )
    .expect("intent");
    create_container(
        &mut hooks,
        ContainerSite::Create,
        &fixture.runtime,
        &fixture.plan.spec,
    )
    .expect("created");
    let view_path = mount_git_view(
        &mut hooks,
        ContainerSite::MountGitView,
        &fixture.view,
        &fixture.plan.view,
    )
    .expect("view");
    start_container(&mut hooks, ContainerSite::Start, &fixture.runtime, &name).expect("started");
    stop_container(
        &mut hooks,
        ContainerSite::Stop,
        &fixture.runtime,
        &name,
        StopMode::Graceful,
    )
    .expect("stopped");
    remove_container(&mut hooks, ContainerSite::Remove, &fixture.runtime, &name).expect("removed");
    unmount_git_view(
        &mut hooks,
        ContainerSite::UnmountGitView,
        &fixture.view,
        &view_path,
    )
    .expect("unmounted");
    remove_intent(
        &mut hooks,
        ContainerSite::RemoveIntent,
        &fixture.root,
        &name,
    )
    .expect("intent removed");

    let sites = fixture.trace.sites();
    // Both phases, once each, for all eight, in the order they were called.
    let expected: Vec<(ContainerSite, TracePhase)> = [
        ContainerSite::WriteIntent,
        ContainerSite::Create,
        ContainerSite::MountGitView,
        ContainerSite::Start,
        ContainerSite::Stop,
        ContainerSite::Remove,
        ContainerSite::UnmountGitView,
        ContainerSite::RemoveIntent,
    ]
    .into_iter()
    .flat_map(|site| [(site, TracePhase::Before), (site, TracePhase::After)])
    .collect();
    assert_eq!(sites, expected);
    let covered: BTreeSet<&str> = sites.iter().map(|(site, _)| site.name()).collect();
    assert_eq!(
        covered.len(),
        ContainerSite::ALL.len(),
        "a site with no funnel is the `PR5D-PROCESS-FUNNEL-TAKES-NO-SITE` shape; \
         the Container group must not become the third"
    );
}

/// A funnel API refuses a site that does not name its operation, **before any
/// effect**.
///
/// The site is a by-value parameter, which is what `identity` asks for; a free
/// parameter can be passed a wrong value, so the guard is what keeps the
/// parameter load-bearing rather than decorative. The grid is all eight sites
/// against all eight APIs: eight accept and fifty-six refuse.
#[test]
fn a_funnel_api_refuses_a_site_that_does_not_name_its_operation() {
    let fixture = Fixture::new("site-guard", RUN_A, INCARNATION_1, &shell_probe());
    let name = fixture.plan.name.clone();
    let mut accepted = 0;
    let mut refused = 0;
    for site in ContainerSite::ALL.iter().copied() {
        let mut hooks = NoHooks;
        // One API, driven over every site. `write_intent` is the one whose
        // effect is observable without a runtime, so a refusal that still wrote
        // is visible on disk.
        let outcome = write_intent(&mut hooks, site, &fixture.root, &name, &fixture.plan.intent);
        if site == ContainerSite::WriteIntent {
            outcome.expect("the site that names the operation is accepted");
            accepted += 1;
            fs::remove_file(name.intent_path(&fixture.root)).expect("clean up");
        } else {
            let error = outcome.expect_err("a site that names another operation refuses");
            assert!(matches!(error, TactusError::Refused { .. }));
            assert!(
                !name.intent_path(&fixture.root).exists(),
                "a refused call performed its effect anyway, under site {}",
                site.name()
            );
            refused += 1;
        }
    }
    assert_eq!((accepted, refused), (1, 7));

    // And the same over the seven other APIs, counted rather than described.
    let mut wrong_site_refusals = 0;
    for site in ContainerSite::ALL.iter().copied() {
        let mut hooks = NoHooks;
        if site != ContainerSite::Create
            && create_container(&mut hooks, site, &fixture.runtime, &fixture.plan.spec).is_err()
        {
            wrong_site_refusals += 1;
        }
        if site != ContainerSite::Start
            && start_container(&mut hooks, site, &fixture.runtime, &name).is_err()
        {
            wrong_site_refusals += 1;
        }
        if site != ContainerSite::Stop
            && stop_container(
                &mut hooks,
                site,
                &fixture.runtime,
                &name,
                StopMode::Graceful,
            )
            .is_err()
        {
            wrong_site_refusals += 1;
        }
        if site != ContainerSite::Remove
            && remove_container(&mut hooks, site, &fixture.runtime, &name).is_err()
        {
            wrong_site_refusals += 1;
        }
        if site != ContainerSite::MountGitView
            && mount_git_view(&mut hooks, site, &fixture.view, &fixture.plan.view).is_err()
        {
            wrong_site_refusals += 1;
        }
        if site != ContainerSite::UnmountGitView
            && unmount_git_view(&mut hooks, site, &fixture.view, &fixture.plan.view.path).is_err()
        {
            wrong_site_refusals += 1;
        }
        if site != ContainerSite::RemoveIntent
            && remove_intent(&mut hooks, site, &fixture.root, &name).is_err()
        {
            wrong_site_refusals += 1;
        }
    }
    assert_eq!(
        wrong_site_refusals,
        7 * 7,
        "seven APIs, seven wrong sites each"
    );
}

/// A hook armed at a phase makes the funnel return `Err` there, and an `After`
/// error arrives **after** the primitive ran.
#[test]
fn a_hook_armed_at_a_phase_fails_the_funnel_at_that_phase() {
    let fixture = Fixture::new("hook-arm", RUN_A, INCARNATION_1, &shell_probe());
    let name = fixture.plan.name.clone();

    // Before: nothing is written.
    let mut hooks = fixture.hooks();
    hooks.fail_at(
        EffectSiteId::Container(ContainerSite::WriteIntent),
        crate::topology::effects::HookPhase::Before,
    );
    write_intent(
        &mut hooks,
        ContainerSite::WriteIntent,
        &fixture.root,
        &name,
        &fixture.plan.intent,
    )
    .expect_err("armed before");
    assert!(!name.intent_path(&fixture.root).exists());

    // After: the record is on disk and the call still fails.
    let mut hooks = fixture.hooks();
    hooks.fail_at(
        EffectSiteId::Container(ContainerSite::WriteIntent),
        crate::topology::effects::HookPhase::After,
    );
    write_intent(
        &mut hooks,
        ContainerSite::WriteIntent,
        &fixture.root,
        &name,
        &fixture.plan.intent,
    )
    .expect_err("armed after");
    assert!(
        name.intent_path(&fixture.root).exists(),
        "an Err from the After phase is returned after the primitive ran"
    );
}

// ---------------------------------------------------------------------------
// 3. The intent record — six fields, each read back
// ---------------------------------------------------------------------------

/// The six fields `crash_reconstruction` and R26 enumerate, each written and
/// each read back.
///
/// "A field written and never read is invisible to mutation witnessing", so
/// every field is given a value distinct from every other field's and the
/// round trip is asserted field by field. The distinct-value count is the
/// hostility assertion: six fields, six distinct values, so a record that
/// copied one field into another fails.
#[test]
fn the_intent_record_carries_the_six_fields_and_each_is_read_back() {
    let fixture = Fixture::new("six-fields", RUN_A, INCARNATION_1, &shell_probe());
    let mut hooks = fixture.hooks();
    let path = write_intent(
        &mut hooks,
        ContainerSite::WriteIntent,
        &fixture.root,
        &fixture.plan.name,
        &fixture.plan.intent,
    )
    .expect("written");

    let read = read_intent(&path).expect("read back");
    assert_eq!(read.run_id, RUN_A);
    assert_eq!(read.run_dir, format!("/srv/public/{RUN_A}"));
    assert_eq!(read.incarnation, INCARNATION_1);
    assert_eq!(read.repo_key, REPO_KEY);
    assert_eq!(read.invocation, "p.shell.o0");
    assert_eq!(read.runner_policy_sha256, POLICY_DIGEST);
    assert_eq!(read, fixture.plan.intent);

    let values: BTreeSet<&str> = [
        read.run_id.as_str(),
        read.run_dir.as_str(),
        read.incarnation.as_str(),
        read.repo_key.as_str(),
        read.invocation.as_str(),
        read.runner_policy_sha256.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        values.len(),
        6,
        "six independently meaningful fields, six distinct values"
    );

    // The serialized document has exactly six keys, in the packet's order, and
    // the key names are pinned as literals rather than taken from the struct.
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("bytes")).expect("json");
    let object = document.as_object().expect("an object");
    assert_eq!(object.len(), 6);
    for key in [
        "run_id",
        "run_dir",
        "incarnation",
        "repo_key",
        "invocation",
        "runner_policy_sha256",
    ] {
        assert!(object.contains_key(key), "the record has no `{key}`");
    }
}

/// A record with a seventh field is not this engine's record.
#[test]
fn an_intent_record_with_an_unknown_field_is_refused() {
    let root = scratch("unknown-field");
    let path = root.join("bad.intent");
    fs::write(
        &path,
        br#"{"run_id":"r","run_dir":"d","incarnation":"i","repo_key":"k","invocation":"p.shell.o0","runner_policy_sha256":"s","extra":1}"#,
    )
    .expect("write");
    let error = read_intent(&path).expect_err("an unknown field is refused");
    assert!(matches!(error, TactusError::Refused { .. }));
}

/// The five labels, each carrying its own field.
///
/// `crash_reconstruction`: "labels tactus.private_root, tactus.run,
/// tactus.run_dir, tactus.incarnation, tactus.invocation". Written out as
/// literals, and each value asserted against the field it comes from — a label
/// map with five keys and one value repeated would pass a count and fails here.
#[test]
fn the_five_labels_are_the_packets_five_and_each_carries_its_own_field() {
    assert_eq!(
        LABELS,
        [
            "tactus.private_root",
            "tactus.run",
            "tactus.run_dir",
            "tactus.incarnation",
            "tactus.invocation",
        ]
    );
    let root = PathBuf::from("/srv/private");
    let record = intent_for(RUN_A, INCARNATION_1, &shell_probe());
    let labels = record.labels(&root);
    assert_eq!(labels.len(), 5);
    assert_eq!(labels[LABEL_PRIVATE_ROOT], "/srv/private");
    assert_eq!(labels[LABEL_RUN], RUN_A);
    assert_eq!(labels[LABEL_RUN_DIR], format!("/srv/public/{RUN_A}"));
    assert_eq!(labels[LABEL_INCARNATION], INCARNATION_1);
    assert_eq!(labels[LABEL_INVOCATION], "p.shell.o0");
    let distinct: BTreeSet<&String> = labels.values().collect();
    assert_eq!(distinct.len(), 5, "five labels, five distinct values");

    // Discovery is by `tactus.private_root` and the record's own location is
    // inside that root, so the one label with no field of its own is the one
    // the census already knows.
    assert!(
        !record.run_dir.starts_with("/srv/private"),
        "the public run directory and the private root are different values, so \
         a label that took one for the other is visible"
    );
}

// ---------------------------------------------------------------------------
// 4. The name
// ---------------------------------------------------------------------------

/// The name is the packet's template, and the expected value is a literal.
///
/// > the container name is `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>`
///
/// The invocation hash is pinned against a value computed **out of band**:
///
/// ```text
/// python3 -c 'import hashlib; print(hashlib.sha256(
///     b"tactus.container-invocation.v1" + b"\x00" + b"p.shell.o0").hexdigest()[:16])'
/// c8e75afe1649f987
/// ```
///
/// A digest compared only against the code that produced it proves nothing.
#[test]
fn the_container_name_is_the_packets_template_and_its_hash_is_pinned() {
    assert_eq!(invocation_hash(&shell_probe()), "c8e75afe1649f987");
    assert_eq!(
        invocation_hash(&InvocationId::probe(ProbeTarget::Shell, 1).expect("o1")),
        "0ba209deb7340f44"
    );
    assert_eq!(invocation_hash(&agent_probe()), "dcd71fb456045de6");

    let name = name_for(RUN_A, INCARNATION_1, &shell_probe());
    assert_eq!(
        name.as_str(),
        "tactus-0123456789abcdef-01KZRN48A4ZK3AEDST3RJ8HMA4-\
         01KZTAAAAAAAAAAAAAAAAAAAAA-c8e75afe1649f987"
    );
    assert_eq!(
        name.intent_file_name(),
        format!("{}{INTENT_SUFFIX}", name.as_str())
    );
    assert_eq!(
        name.intent_path(Path::new("/srv/private")),
        Path::new("/srv/private")
            .join(CONTAINERS_DIR)
            .join(name.intent_file_name())
    );

    let parts = ContainerName::parse(name.as_str()).expect("parses");
    assert_eq!(parts.repo_key, REPO_KEY);
    assert_eq!(parts.run_id, RUN_A);
    assert_eq!(parts.incarnation, INCARNATION_1);
    assert_eq!(parts.invocation_hash, "c8e75afe1649f987");
}

/// The parse is injective over a hostile component grid.
///
/// Every component is varied independently and the counts are asserted:
/// 2 repo keys x 2 run ids x 2 incarnations x 2 hashes = 16 tuples, 16 distinct
/// names, and 16 distinct parses that each round-trip. A name produced two ways
/// by two different tuples is an ownership record that lies.
#[test]
fn the_name_is_injective_over_every_component_varied_independently() {
    let repo_keys = ["0123456789abcdef", "fedcba9876543210"];
    let runs = [RUN_A, RUN_B];
    let incarnations = [INCARNATION_1, INCARNATION_2];
    let hashes = ["c8e75afe1649f987", "0ba209deb7340f44"];

    let mut names = BTreeSet::new();
    let mut parsed = BTreeSet::new();
    let mut tuples = BTreeSet::new();
    for repo_key in repo_keys {
        for run in runs {
            for incarnation in incarnations {
                for hash in hashes {
                    let name = ContainerName::from_parts(repo_key, run, incarnation, hash)
                        .expect("a name");
                    let parts = ContainerName::parse(name.as_str()).expect("parses");
                    assert_eq!(parts.repo_key, repo_key);
                    assert_eq!(parts.run_id, run);
                    assert_eq!(parts.incarnation, incarnation);
                    assert_eq!(parts.invocation_hash, hash);
                    names.insert(name.as_str().to_owned());
                    parsed.insert((
                        parts.repo_key,
                        parts.run_id,
                        parts.incarnation,
                        parts.invocation_hash,
                    ));
                    tuples.insert((repo_key, run, incarnation, hash));
                }
            }
        }
    }
    assert_eq!(tuples.len(), 16);
    assert_eq!(names.len(), 16, "two tuples rendered to one name");
    assert_eq!(parsed.len(), 16, "two names parsed to one tuple");

    // The adversarial pair: components chosen so that a template joining them
    // without a refusal on the separator would collide. `a-b` + `c` and `a` +
    // `b-c` render the same string under a naive join; here both are refused.
    assert!(ContainerName::from_parts("a-b", "c", INCARNATION_1, "d").is_err());
    assert!(ContainerName::from_parts("a", "b-c", INCARNATION_1, "d").is_err());
}

/// A component carrying a separator, a `.`, or a path separator is refused.
///
/// The name goes into a **file name** — `<name>.intent` — so a component with a
/// path separator names a different file than the record says, which is the
/// same class `workspace_manager::remove_intent` validates its slot names
/// against.
#[test]
fn a_hostile_name_component_is_refused_and_the_refusal_says_why() {
    let hostile = [
        "with-separator",
        "with.dot",
        "with/slash",
        "with\\backslash",
        "with space",
        "with\u{0}nul",
        "",
    ];
    let mut refusals = BTreeSet::new();
    for bad in hostile {
        for position in 0..4 {
            let mut parts = [REPO_KEY, RUN_A, INCARNATION_1, "c8e75afe1649f987"];
            parts[position] = bad;
            let error = ContainerName::from_parts(parts[0], parts[1], parts[2], parts[3])
                .expect_err("a hostile component is refused");
            assert!(matches!(error, TactusError::Refused { .. }));
            refusals.insert(error.to_string());
        }
    }
    // Seven hostile values in four positions, and the message names the
    // position, so the refusals are not one message repeated.
    assert!(
        refusals.len() >= hostile.len(),
        "the refusals collapse to {} distinct messages for {} hostile values",
        refusals.len(),
        hostile.len()
    );

    // Over-long is refused too, and the boundary is exact.
    let at_limit = "a".repeat(intent::MAX_COMPONENT_LEN);
    let over = "a".repeat(intent::MAX_COMPONENT_LEN + 1);
    assert!(ContainerName::from_parts(&at_limit, RUN_A, INCARNATION_1, "d").is_ok());
    assert!(ContainerName::from_parts(&over, RUN_A, INCARNATION_1, "d").is_err());
}

/// **T-CONTAINER (9)** `probe_name_reuse_across_incarnations_never_collides`.
///
/// `crash_reconstruction`: "the container name is
/// `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>`, so
/// **deterministic InvocationIds never collide across incarnations and no
/// earlier ownership evidence is overwritten**". ST-16 (f) is the same claim
/// from the other side: "a probe invocation with the same deterministic
/// InvocationId, whose **new container name and intent path differ**".
///
/// The intersection: {probe kind} x {incarnation}. Both probe targets, both
/// incarnations, one run — so a name that dropped the incarnation collides in
/// **two** places, and one that dropped the invocation collides in two others.
#[test]
fn probe_name_reuse_across_incarnations_never_collides() {
    let root = scratch("probe-reuse");
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for incarnation in [INCARNATION_1, INCARNATION_2] {
        for invocation in [shell_probe(), agent_probe()] {
            // The identity really is the same across incarnations: that is the
            // premise the incarnation component exists for, and asserting it
            // here stops the test passing because the ids happened to differ.
            assert_eq!(
                invocation.render(),
                match invocation.probe_target() {
                    Some(ProbeTarget::Shell) => "p.shell.o0".to_owned(),
                    _ => "p.agent-claude-code.o0".to_owned(),
                }
            );
            let name = name_for(RUN_A, incarnation, &invocation);
            names.insert(name.as_str().to_owned());
            paths.insert(name.intent_path(&root));
        }
    }
    assert_eq!(
        names.len(),
        4,
        "2 incarnations x 2 probe targets: {names:?}"
    );
    assert_eq!(paths.len(), 4, "and four distinct intent paths");

    // And no earlier ownership evidence is overwritten: writing all four leaves
    // four records on disk.
    let mut hooks = RecordingHooks::new(ContainerTrace::recording());
    for incarnation in [INCARNATION_1, INCARNATION_2] {
        for invocation in [shell_probe(), agent_probe()] {
            let name = name_for(RUN_A, incarnation, &invocation);
            write_intent(
                &mut hooks,
                ContainerSite::WriteIntent,
                &root,
                &name,
                &intent_for(RUN_A, incarnation, &invocation),
            )
            .expect("written");
        }
    }
    let found = list_intents(&root).expect("scanned");
    assert_eq!(found.len(), 4);
    let incarnations: BTreeSet<&str> = found
        .iter()
        .map(|entry| entry.record.incarnation.as_str())
        .collect();
    assert_eq!(incarnations.len(), 2);
    let invocations: BTreeSet<&str> = found
        .iter()
        .map(|entry| entry.record.invocation.as_str())
        .collect();
    assert_eq!(invocations.len(), 2);
}

// ---------------------------------------------------------------------------
// 5. The orderings
// ---------------------------------------------------------------------------

/// **T-CONTAINER (1)** `container_intent_written_before_run`.
///
/// `side_effect_vs_event_ordering`: "**intent synced before docker create**".
/// Both halves: the record's *sync* (not merely its write) precedes the create,
/// and the create precedes the start.
///
/// Second field held constant: the runtime is reachable and reports the
/// recorded id, so nothing here can pass because the launch failed early.
#[test]
fn container_intent_written_before_run() {
    let fixture = Fixture::new("intent-before-run", RUN_A, INCARNATION_1, &shell_probe());
    let mut hooks = fixture.hooks();
    let launched =
        launch(&mut hooks, &fixture.runtime, &fixture.view, &fixture.plan).expect("launched");

    let trace = &fixture.trace;
    let rendered = trace.rendered();
    let file = fixture.plan.name.intent_file_name();

    let synced = at(trace, &format!("durable:synced:{file}.tmp"));
    let renamed = at(trace, &format!("durable:renamed:{file}"));
    let dir_synced = trace
        .position_starting("durable:dir-synced:")
        .unwrap_or_else(|| panic!("no directory barrier in {rendered:#?}"));
    let created = at(trace, &format!("rt:create:{}", fixture.plan.name));
    let started = at(trace, &format!("rt:start:{}", fixture.plan.name));

    assert!(
        synced < renamed && renamed < dir_synced && dir_synced < created,
        "the intent must be SYNCED before docker create, not merely written: {rendered:#?}"
    );
    assert!(
        created < started,
        "and created before started: {rendered:#?}"
    );

    // The record really is on disk, with the run that owns it.
    assert!(launched.intent_path.exists());
    assert_eq!(
        read_intent(&launched.intent_path).expect("read").run_id,
        RUN_A
    );
}

/// **T-CONTAINER (2)** `container_created_from_recorded_image_id_and_verified`.
///
/// INV-23: "every container of every epoch is created from the **recorded image
/// id** and its reported image id is verified equal to the record **before it
/// starts**".
///
/// The intersection: {image id recorded} x {reference moved}. The reference is
/// moved to another image *before* the launch, and the container is still
/// created from the recorded id — which is the sentence "so a moved reference
/// cannot change what executes" and is not provable by a fixture whose
/// reference never moved.
#[test]
fn container_created_from_recorded_image_id_and_verified() {
    let fixture = Fixture::new("created-from-id", RUN_A, INCARNATION_1, &shell_probe());
    // The reference now names another image. The record still names the id.
    fixture.runtime.move_tag(IMAGE_REFERENCE, OTHER_IMAGE_ID);
    assert_eq!(
        fixture
            .runtime
            .image_by_reference(IMAGE_REFERENCE)
            .expect("reachable")
            .expect("present")
            .id,
        OTHER_IMAGE_ID
    );

    let mut hooks = fixture.hooks();
    let launched =
        launch(&mut hooks, &fixture.runtime, &fixture.view, &fixture.plan).expect("launched");

    assert_eq!(launched.reported_image_id, IMAGE_ID);
    let held = fixture
        .runtime
        .container(fixture.plan.name.as_str())
        .expect("held");
    assert_eq!(
        held.requested_image_id, IMAGE_ID,
        "created from the recorded id, not from what the reference now names"
    );
    assert_ne!(held.requested_image_id, OTHER_IMAGE_ID);
    // Verified *before* start: the verification is between create and start in
    // the sequence, and the start happened, so it passed there.
    let created = at(&fixture.trace, &format!("rt:create:{}", fixture.plan.name));
    let started = at(&fixture.trace, &format!("rt:start:{}", fixture.plan.name));
    assert!(created < started);
}

/// **T-CONTAINER (3)** `substituted_image_id_refused_before_start`.
///
/// INV-23: "a mismatch refuses during pre-flight or rebuild". The refusal is
/// **before start**, and the assertion is that `Container.Start` is absent from
/// the sequence — not that an error was returned, which a refusal after the
/// start would also produce.
///
/// The intersection: {reported id} x {start reached}. R26 balances afterwards,
/// because a refusal is a cancel and a cancel releases.
#[test]
fn substituted_image_id_refused_before_start() {
    let fixture = Fixture::new("substituted", RUN_A, INCARNATION_1, &shell_probe());
    fixture
        .runtime
        .substitute_reported_image_id(fixture.plan.name.as_str(), OTHER_IMAGE_ID);

    let mut hooks = fixture.hooks();
    let error = launch(&mut hooks, &fixture.runtime, &fixture.view, &fixture.plan)
        .expect_err("a substituted image id is refused");
    let message = error.to_string();
    assert!(message.contains(OTHER_IMAGE_ID), "{message}");
    assert!(message.contains(IMAGE_ID), "{message}");
    assert!(message.contains("before start"), "{message}");

    let rendered = fixture.trace.rendered();
    assert!(
        fixture.trace.position_starting("rt:start:").is_none(),
        "the container was started despite the mismatch: {rendered:#?}"
    );
    assert!(
        !fixture
            .trace
            .sites()
            .iter()
            .any(|(site, _)| *site == ContainerSite::Start),
        "the Start site executed despite the mismatch: {rendered:#?}"
    );
    assert!(
        !fixture
            .trace
            .sites()
            .iter()
            .any(|(site, _)| *site == ContainerSite::MountGitView),
        "no view is mounted for a container that will not start: {rendered:#?}"
    );

    // R26 balances: the container it created is released and the intent is
    // gone, so no census finds residue of a refusal.
    assert_eq!(fixture.runtime.container_names(), Vec::<String>::new());
    assert!(!fixture.plan.name.intent_path(&fixture.root).exists());
    assert_eq!(list_intents(&fixture.root).expect("scan").len(), 0);
}

/// "view mounted before start", and the view really exists when the container
/// starts.
#[test]
fn the_git_view_is_mounted_before_start() {
    let fixture = Fixture::new("view-before-start", RUN_A, INCARNATION_1, &shell_probe());
    let mut hooks = fixture.hooks();
    let launched =
        launch(&mut hooks, &fixture.runtime, &fixture.view, &fixture.plan).expect("launched");

    let mounted = at(&fixture.trace, "site:MountGitView:after");
    let started = at(&fixture.trace, &format!("rt:start:{}", fixture.plan.name));
    assert!(
        mounted < started,
        "the view is mounted before start: {:#?}",
        fixture.trace.rendered()
    );
    assert!(launched.view_path.is_dir(), "R19's directory exists");
    assert_eq!(launched.view_path, fixture.plan.view.path);
}

/// "stop/rm, view removal, intent removal after completion" — the four sites in
/// the contract's own order.
#[test]
fn release_stops_removes_unmounts_and_removes_the_intent_in_that_order() {
    let fixture = Fixture::new("release-order", RUN_A, INCARNATION_1, &shell_probe());
    let mut hooks = fixture.hooks();
    let launched =
        launch(&mut hooks, &fixture.runtime, &fixture.view, &fixture.plan).expect("launched");
    fixture.trace.clear();

    release(
        &mut hooks,
        &fixture.runtime,
        &fixture.view,
        &fixture.root,
        &launched,
    )
    .expect("released");

    assert_eq!(
        fixture
            .trace
            .sites()
            .into_iter()
            .filter(|(_, phase)| *phase == TracePhase::After)
            .map(|(site, _)| site)
            .collect::<Vec<_>>(),
        vec![
            ContainerSite::Stop,
            ContainerSite::Remove,
            ContainerSite::UnmountGitView,
            ContainerSite::RemoveIntent,
        ]
    );
    // R19 and R26 both balance.
    assert!(!launched.view_path.exists(), "the view is pruned");
    assert!(!launched.intent_path.exists(), "the intent is removed");
    assert_eq!(fixture.runtime.container_names(), Vec::<String>::new());
}

/// Reclaim, in the packet's order:
///
/// > reclaim = docker kill -> wait until observed exited/removed -> docker rm
/// > -> remove Git view -> remove intent
///
/// Five steps, and the **observation between the kill and the rm** is the one a
/// set-membership assertion would lose.
#[test]
fn reclaim_kills_observes_removes_the_view_and_then_the_intent() {
    let fixture = Fixture::new("reclaim-order", RUN_A, INCARNATION_1, &shell_probe());
    let mut hooks = fixture.hooks();
    let launched =
        launch(&mut hooks, &fixture.runtime, &fixture.view, &fixture.plan).expect("launched");
    assert_eq!(
        fixture
            .runtime
            .container(fixture.plan.name.as_str())
            .map(|c| c.state),
        Some(Liveness::Running),
        "the fixture really is reclaiming a RUNNING container"
    );
    fixture.trace.clear();

    reclaim(
        &mut hooks,
        &fixture.runtime,
        &fixture.view,
        &fixture.root,
        &launched.name,
        Some(&launched.view_path),
    )
    .expect("reclaimed");

    let rendered = fixture.trace.rendered();
    let killed = at(&fixture.trace, &format!("rt:stop:{}", launched.name));
    let observed = at(&fixture.trace, &format!("rt:observe:{}", launched.name));
    let removed = at(&fixture.trace, &format!("rt:remove:{}", launched.name));
    let view_gone = at(&fixture.trace, "site:UnmountGitView:after");
    let intent_gone = at(&fixture.trace, "site:RemoveIntent:after");
    assert!(
        killed < observed && observed < removed && removed < view_gone && view_gone < intent_gone,
        "reclaim's five steps are out of order: {rendered:#?}"
    );
    assert!(!launched.view_path.exists());
    assert!(!launched.intent_path.exists());
    assert_eq!(fixture.runtime.container_names(), Vec::<String>::new());
}

/// Reclaim is idempotent and tolerant of already-gone, so two reclaimers
/// converge.
///
/// The intersection: {intent present} x {container present}. All four cells are
/// driven, and each must converge on the same terminal state.
#[test]
fn reclaim_converges_from_every_combination_of_intent_and_container() {
    for (has_intent, has_container) in [(true, true), (true, false), (false, true), (false, false)]
    {
        let fixture = Fixture::new(
            &format!("converge-{has_intent}-{has_container}"),
            RUN_A,
            INCARNATION_1,
            &shell_probe(),
        );
        let mut hooks = fixture.hooks();
        let name = fixture.plan.name.clone();
        let view_path = fixture.plan.view.path.clone();
        if has_intent {
            write_intent(
                &mut hooks,
                ContainerSite::WriteIntent,
                &fixture.root,
                &name,
                &fixture.plan.intent,
            )
            .expect("intent");
        }
        if has_container {
            fixture.runtime.seed_container(
                name.as_str(),
                fixture.plan.intent.labels(&fixture.root),
                IMAGE_ID,
                IMAGE_ID,
                Liveness::Running,
            );
            fs::create_dir_all(&view_path).expect("view");
        }

        for round in 0..2 {
            reclaim(
                &mut hooks,
                &fixture.runtime,
                &fixture.view,
                &fixture.root,
                &name,
                Some(&view_path),
            )
            .unwrap_or_else(|error| {
                panic!("round {round} of ({has_intent}, {has_container}) refused: {error}")
            });
            assert!(!name.intent_path(&fixture.root).exists());
            assert!(!view_path.exists());
            assert_eq!(fixture.runtime.container_names(), Vec::<String>::new());
        }
    }
}

/// A container that cannot be observed terminated refuses.
///
/// `refusal_condition`: "a dead owner's or dead incarnation's labeled container
/// that cannot be observed terminated **blocks admission**". The fake's stop is
/// armed failing so the container stays `Running` and the observation never
/// converges — the second field held constant is that the runtime is
/// *reachable* throughout, so this is not the unreachable refusal wearing
/// another name.
#[test]
fn a_container_that_cannot_be_observed_terminated_refuses() {
    let fixture = Fixture::new("unobservable", RUN_A, INCARNATION_1, &shell_probe());
    let name = fixture.plan.name.clone();
    fixture.runtime.seed_container(
        name.as_str(),
        fixture.plan.intent.labels(&fixture.root),
        IMAGE_ID,
        IMAGE_ID,
        Liveness::Running,
    );
    // Stop succeeds and the container stays running: a kill that was delivered
    // to a process the kernel has not reaped.
    let error = observe_terminated(&NeverTerminates(&fixture.runtime), &name)
        .expect_err("it cannot be observed terminated");
    let message = error.to_string();
    assert!(
        message.contains("cannot be observed terminated"),
        "{message}"
    );
    assert!(message.contains("blocks admission"), "{message}");
    assert_eq!(
        fixture
            .trace
            .ops()
            .iter()
            .filter(|op| **op == RuntimeOp::Observe)
            .count(),
        TERMINATION_OBSERVATIONS,
        "the bound is the bound, not one observation"
    );
}

/// Unreachable and failed are **different answers**, and the refusal split
/// rests on the difference.
///
/// `crash_reconstruction` refuses a write command when "any intent exists and
/// the runtime **cannot be reached**"; an operation that reached the runtime
/// and failed is a different thing, and a seam that reported one error kind
/// would make lane C's refusal unwritable. The intersection here is {operation}
/// x {reachable? failed? fine?} — three states over one operation, not two axes
/// tested apart.
#[test]
fn a_failed_operation_and_an_unreachable_one_are_different_answers() {
    let runtime = FakeRuntime::new(ContainerTrace::recording());
    runtime.add_image(IMAGE_ID, None);

    // Fine.
    assert!(runtime.image_by_id(IMAGE_ID).expect("reachable").is_some());

    // Reached and failed.
    runtime.set_failing(RuntimeOp::InspectImageById);
    let failed = runtime.image_by_id(IMAGE_ID).expect_err("armed failing");
    assert!(!failed.is_unreachable(), "{failed}");
    assert_eq!(failed.operation(), RuntimeOp::InspectImageById);
    assert!(failed.to_string().contains("refused"), "{failed}");

    // Not reached at all.
    runtime.set_unreachable(RuntimeOp::InspectImageById);
    let unreachable = runtime
        .image_by_id(IMAGE_ID)
        .expect_err("armed unreachable");
    assert!(unreachable.is_unreachable(), "{unreachable}");
    assert!(
        unreachable.to_string().contains("cannot be reached"),
        "{unreachable}"
    );

    // And back: the toggle is a toggle, so a fixture can restore a runtime
    // mid-test — which is what a census that refuses and then succeeds needs.
    runtime.set_reachable(RuntimeOp::InspectImageById);
    let still_failing = runtime.image_by_id(IMAGE_ID).expect_err("still failing");
    assert!(
        !still_failing.is_unreachable(),
        "reachability and failure are independent arms, so clearing one must not \
         clear the other: {still_failing}"
    );

    let kinds: BTreeSet<bool> = [failed.is_unreachable(), unreachable.is_unreachable()]
        .into_iter()
        .collect();
    assert_eq!(kinds.len(), 2);
}

/// A container's exit status and output come back through the seam, which is
/// what lane A turns into a `ProcessOutput`.
///
/// Second field held constant: one container, one runtime; what varies is only
/// what it exited with. Three distinct exit values and two distinct streams, so
/// a `collect` that returned a constant fails.
#[test]
fn a_containers_exit_status_and_streams_come_back_through_the_seam() {
    let runtime = FakeRuntime::new(ContainerTrace::recording());
    runtime.seed_container(
        "tactus-a-b-c-d",
        BTreeMap::new(),
        IMAGE_ID,
        IMAGE_ID,
        Liveness::Running,
    );
    let mut seen = BTreeSet::new();
    for code in [Some(0), Some(17), None] {
        runtime.set_execution(
            "tactus-a-b-c-d",
            ContainerExecution {
                exit_code: code,
                stdout: b"out".to_vec(),
                stderr: b"err".to_vec(),
            },
        );
        let collected = runtime.collect("tactus-a-b-c-d").expect("collected");
        assert_eq!(collected.exit_code, code);
        assert_eq!(collected.stdout, b"out");
        assert_eq!(collected.stderr, b"err");
        seen.insert(collected.exit_code);
    }
    assert_eq!(
        seen.len(),
        3,
        "signalled, zero and non-zero are three states"
    );

    // Liveness is a separate axis from the exit status: a container can be
    // observed running while carrying an exit value from its previous state.
    runtime.set_container_state("tactus-a-b-c-d", Liveness::Exited);
    assert_eq!(
        runtime.observe("tactus-a-b-c-d").expect("observed"),
        Liveness::Exited
    );
    assert!(!Liveness::Running.is_terminated());
    assert!(Liveness::Exited.is_terminated());
    assert!(
        Liveness::Gone.is_terminated(),
        "reclaim waits for exited OR removed; collapsing them makes two \
         concurrent reclaimers block each other"
    );
    // A container the runtime does not hold is Gone, not an error: that is what
    // makes reclaim tolerant of already-gone.
    assert_eq!(
        runtime.observe("never-existed").expect("observed"),
        Liveness::Gone
    );
}

/// The Docker gate refuses a test nothing counts, and its absence reason says
/// what is missing.
#[test]
fn the_docker_gate_refuses_an_uncounted_test_and_names_what_is_absent() {
    let reason = absent_reason();
    assert!(reason.contains(super::DOCKER_PROGRAM), "{reason}");
    assert!(reason.contains("daemon"), "{reason}");

    // Built rather than written, so `every_docker_gated_test_is_named_and_present`
    // — which reads gate call sites out of the source — does not see this
    // negative control as a fourth gated test.
    let unlisted = ["a", "test", "nobody", "listed"].join("_");
    let refused = std::panic::catch_unwind(|| docker_gate(&unlisted, ContainerTrace::off()));
    assert!(
        refused.is_err(),
        "the gate accepted a test that is not in DOCKER_GATED_TESTS, so a gated \
         test could exist that nothing counts"
    );
}

/// A runtime that never reports termination, wrapping another.
///
/// A wrapper rather than a flag on the fake, because "still running after the
/// kill" is a property of the *sequence of answers*, and a fake that could only
/// be armed to fail would make the refusal an error rather than a
/// never-converging observation.
struct NeverTerminates<'a>(&'a FakeRuntime);

impl ContainerRuntime for NeverTerminates<'_> {
    fn probe(&self) -> Result<(), RuntimeError> {
        self.0.probe()
    }
    fn image_by_reference(&self, reference: &str) -> Result<Option<ImageInspection>, RuntimeError> {
        self.0.image_by_reference(reference)
    }
    fn image_by_id(&self, id: &str) -> Result<Option<ImageInspection>, RuntimeError> {
        self.0.image_by_id(id)
    }
    fn volume_present(&self, name: &str) -> Result<bool, RuntimeError> {
        self.0.volume_present(name)
    }
    fn containers_with_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Vec<super::runtime::DiscoveredContainer>, RuntimeError> {
        self.0.containers_with_label(key, value)
    }
    fn observe(&self, name: &str) -> Result<Liveness, RuntimeError> {
        self.0.observe(name).map(|_| Liveness::Running)
    }
    fn collect(&self, name: &str) -> Result<ContainerExecution, RuntimeError> {
        self.0.collect(name)
    }
    fn create(&self, spec: &CreateSpec) -> Result<super::runtime::CreatedContainer, RuntimeError> {
        self.0.create(spec)
    }
    fn start(&self, name: &str) -> Result<(), RuntimeError> {
        self.0.start(name)
    }
    fn stop(&self, name: &str, mode: StopMode) -> Result<(), RuntimeError> {
        self.0.stop(name, mode)
    }
    fn remove(&self, name: &str) -> Result<(), RuntimeError> {
        self.0.remove(name)
    }
}

// ---------------------------------------------------------------------------
// 6. The namespace scan
// ---------------------------------------------------------------------------

/// The scan reads every record and skips the writer-owned staged half.
///
/// "discovery at every write-command start scans the whole namespace
/// `<R>/containers`". A `<name>.intent.tmp` is a crash between the stage and
/// the rename; adopting it would be adopting a record that was never
/// published.
#[test]
fn the_namespace_scan_reads_every_record_and_skips_the_staged_half() {
    let fixture = Fixture::new("scan", RUN_A, INCARNATION_1, &shell_probe());
    let mut hooks = fixture.hooks();
    for (run, incarnation, invocation) in [
        (RUN_A, INCARNATION_1, shell_probe()),
        (RUN_A, INCARNATION_2, shell_probe()),
        (RUN_B, INCARNATION_1, agent_probe()),
    ] {
        write_intent(
            &mut hooks,
            ContainerSite::WriteIntent,
            &fixture.root,
            &name_for(run, incarnation, &invocation),
            &intent_for(run, incarnation, &invocation),
        )
        .expect("written");
    }
    // Residue a reader must ignore: a staged half, and a file that is not an
    // intent at all.
    let dir = containers_dir(&fixture.root);
    fs::write(dir.join("tactus-a-b-c-d.intent.tmp"), b"{}").expect("staged");
    fs::write(dir.join("README"), b"not an intent").expect("stray");

    let found: Vec<FoundIntent> = list_intents(&fixture.root).expect("scanned");
    assert_eq!(
        found.len(),
        3,
        "{:?}",
        found.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    let runs: BTreeSet<&str> = found.iter().map(|f| f.record.run_id.as_str()).collect();
    let incarnations: BTreeSet<&str> = found
        .iter()
        .map(|f| f.record.incarnation.as_str())
        .collect();
    assert_eq!(runs.len(), 2);
    assert_eq!(incarnations.len(), 2);
    // Sorted by name, so a census's report is stable across filesystems whose
    // directory order is not.
    let mut sorted = found.iter().map(|f| f.name.clone()).collect::<Vec<_>>();
    sorted.sort();
    assert_eq!(
        found.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
        sorted
    );
}

/// A private root with no `containers` directory is an **empty namespace**, not
/// an error.
///
/// `crash_reconstruction`: "with no intent and no reachable runtime it
/// proceeds". A run that has never launched a container has no directory, and a
/// scan that treated that as a failure would refuse every write command on a
/// host runner.
#[test]
fn an_absent_containers_directory_is_an_empty_namespace() {
    let root = scratch("empty-namespace");
    assert!(!containers_dir(&root).exists());
    assert_eq!(list_intents(&root).expect("scanned"), Vec::new());
}

// ---------------------------------------------------------------------------
// 7. Enforcement: nothing performs a container effect outside this funnel
// ---------------------------------------------------------------------------

/// Every container effect in the tree goes through the funnel.
///
/// The census beside the denylist, in the idiom of
/// `runner::tests::every_production_process_start_is_classified`. Module
/// privacy cannot make a bypass a compile error from inside this subtree — an
/// item private to `runner::container` is visible to every module a lane adds
/// beside this one — so the enforcement is the clippy denylist (a build error)
/// and this census (a red test), and the two fail for different reasons.
///
/// **Lanes A and C: if this test names your file, you are calling the runtime
/// or the view directly. Call the funnel instead.**
#[test]
fn every_container_effect_in_the_tree_goes_through_the_funnel() {
    /// The effectful primitives, and the only file that may name them.
    const PRIMITIVES: &[&str] = &[
        "runtime.create(",
        "runtime.start(",
        "runtime.stop(",
        "runtime.remove(",
        "view.materialize(",
        "view.discard(",
        ".materialize(",
        ".discard(",
    ];
    const FUNNEL: &str = "src/runner/container.rs";

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    let mut scanned = 0;
    for path in walk(&root.join("src")) {
        let relative = path
            .strip_prefix(&root)
            .expect("under the manifest")
            .to_string_lossy()
            .replace('\\', "/");
        if relative == FUNNEL {
            continue;
        }
        // Test modules of this subtree drive the funnel and may construct a
        // fake; they are excluded by name rather than by a pattern, so a new
        // one is a change here.
        if relative == "src/runner/container/fake.rs" || relative == "src/runner/container/tests.rs"
        {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read source");
        let production =
            crate::effects::blank_comments_and_strings(&crate::effects::production_region(&source));
        scanned += 1;
        for primitive in PRIMITIVES {
            if production.contains(primitive) {
                offenders.push(format!("{relative} names `{primitive}`"));
            }
        }
    }
    assert!(scanned > 20, "the walk found the tree: {scanned}");
    assert!(offenders.is_empty(), "{offenders:#?}");

    // The control: the funnel itself names every one of them, so a census that
    // had stopped finding anything fails here rather than reporting silence.
    let funnel = fs::read_to_string(root.join(FUNNEL)).expect("the funnel");
    let production =
        crate::effects::blank_comments_and_strings(&crate::effects::production_region(&funnel));
    for primitive in [
        "runtime.create(",
        "runtime.start(",
        "runtime.stop(",
        "runtime.remove(",
    ] {
        assert!(
            production.contains(primitive),
            "the funnel does not name `{primitive}`; the census above is measuring nothing"
        );
    }
}

/// `source` with every comment blanked and every string literal left intact.
///
/// [`crate::effects::blank_comments_and_strings`] blanks both, which is right
/// for finding *code* and wrong for finding a name that lives inside a string —
/// a gated test's own name, or a `docker` program name. Blanking only the
/// comments is the half this census needs, and it is the half that stops a doc
/// comment about the scan being counted by the scan.
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

/// Every Docker-gated test is named in the list that counts them, and every
/// name in the list is a test in this tree.
///
/// The skip is loud because it is **counted**: `docker_gate` refuses a test
/// that is not on the list, and this test refuses a name on the list that is
/// not a test. A gated test that vanished would otherwise shorten the list and
/// nothing would say so.
#[test]
fn every_docker_gated_test_is_named_and_present() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sources = String::new();
    for path in walk(&root.join("src").join("runner")) {
        sources.push_str(&fs::read_to_string(&path).expect("read source"));
    }
    assert!(!DOCKER_GATED_TESTS.is_empty());
    for name in DOCKER_GATED_TESTS {
        assert!(
            sources.contains(&format!("fn {name}(")),
            "`{name}` is in DOCKER_GATED_TESTS and is not a test in src/runner/**"
        );
    }
    // And every test that calls the gate is on the list: the name is readable
    // from the call site. Comments are blanked first, so this file's own prose
    // about the gate is not mistaken for a call — measured, because the first
    // version of this scan reported the placeholder in a doc comment as a
    // fourth gated test (`PR4-CENSUS-COMMENT-ORACLE`, the fifth occurrence).
    let mut called: BTreeSet<String> = BTreeSet::new();
    let stripped = crate::effects::blank_comments(&sources);
    let opener = "docker_gate(";
    let mut rest = stripped.as_str();
    while let Some(index) = rest.find(opener) {
        rest = &rest[index + opener.len()..];
        // `rustfmt` may put the name on the next line, so the first quote after
        // the call site is what names the test rather than the byte after the
        // paren. Measured: with a contiguous `gate("` needle this census found
        // **zero** call sites and reported the whole list as missing.
        let Some(open) = rest.find('"') else { break };
        let Some(end) = rest[open + 1..].find('"') else {
            break;
        };
        let name = &rest[open + 1..open + 1 + end];
        if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            called.insert(name.to_owned());
        }
        rest = &rest[open + 1 + end..];
    }
    let listed: BTreeSet<String> = DOCKER_GATED_TESTS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        called, listed,
        "the set of tests that call the Docker gate and the set the list counts disagree"
    );
}

// ---------------------------------------------------------------------------
// 8. Docker-gated: the real runtime
// ---------------------------------------------------------------------------

/// The references the gated tests prefer, in order.
///
/// **These tests never pull.** `non_goals[1]` is "implicit image pull", and a
/// fixture that pulled would be exercising the behaviour the slice forbids on
/// the very runtime it is meant to prove the refusal against. So the image is
/// *discovered* among what the machine already holds, and a machine holding
/// none reports absence through the same loud, counted gate as a machine with
/// no Docker at all.
const PREFERRED_IMAGES: &[&str] = &["alpine:3.20", "busybox:latest", "debian:stable-slim"];

/// A reference the runtime holds, with its id and digest, or the reason there
/// is none.
fn gated_image(docker: &dyn ContainerRuntime) -> Result<(String, ImageInspection), String> {
    for reference in PREFERRED_IMAGES {
        if let Ok(Some(found)) = docker.image_by_reference(reference) {
            return Ok(((*reference).to_owned(), found));
        }
    }
    Err(format!(
        "the container runtime holds none of {PREFERRED_IMAGES:?} and these tests          never pull (non_goals[1])"
    ))
}

/// The real runtime resolves a reference it holds to an id and, when it has
/// one, a manifest digest.
#[test]
fn real_docker_reports_an_image_id_and_a_digest_for_a_reference_it_holds() {
    let trace = ContainerTrace::recording();
    let docker = match docker_gate(
        "real_docker_reports_an_image_id_and_a_digest_for_a_reference_it_holds",
        trace.clone(),
    ) {
        Ok(docker) => docker,
        Err(reason) => return skipped(&reason),
    };
    let (reference, found) = match gated_image(docker.as_ref()) {
        Ok(image) => image,
        Err(reason) => return no_image(&reason),
    };
    assert!(found.id.starts_with("sha256:"), "{}", found.id);
    assert!(
        found.references.contains(&reference),
        "{:?}",
        found.references
    );
    // The same image asked for by id gives the same id back, and a prefix of it
    // does not answer this question.
    let by_id = docker
        .image_by_id(&found.id)
        .expect("reachable")
        .expect("present");
    assert_eq!(by_id.id, found.id);
    assert_eq!(by_id.digest, found.digest);
    assert_eq!(
        docker
            .image_by_id(&found.id[..found.id.len() - 8])
            .expect("reachable"),
        None,
        "an id prefix resolves in docker and is not the recorded id"
    );
    assert!(trace.ops().contains(&RuntimeOp::InspectImageByReference));
}

/// A reference the runtime does not hold is **absent**, and nothing pulls it.
#[test]
fn real_docker_refuses_a_reference_it_does_not_hold_without_pulling() {
    let trace = ContainerTrace::recording();
    let docker = match docker_gate(
        "real_docker_refuses_a_reference_it_does_not_hold_without_pulling",
        trace.clone(),
    ) {
        Ok(docker) => docker,
        Err(reason) => return skipped(&reason),
    };
    let absent = "ghcr.io/tactus-does-not-exist/nothing:v0";
    assert_eq!(
        docker.image_by_reference(absent).expect("reachable"),
        None,
        "an absent reference is absence, not a pull"
    );
    assert_eq!(
        docker
            .image_by_id("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .expect("reachable"),
        None
    );
    assert!(
        !docker
            .volume_present("tactus-volume-that-does-not-exist")
            .expect("reachable")
    );
}

/// The whole R26 lifecycle against the real runtime: create from an id, verify
/// what it reports, launch through the funnel, reclaim, and reclaim again.
#[test]
fn real_docker_creates_from_an_id_reports_it_and_reclaims_idempotently() {
    let trace = ContainerTrace::recording();
    let docker = match docker_gate(
        "real_docker_creates_from_an_id_reports_it_and_reclaims_idempotently",
        trace.clone(),
    ) {
        Ok(docker) => docker,
        Err(reason) => return skipped(&reason),
    };
    let (_, image) = match gated_image(docker.as_ref()) {
        Ok(image) => image,
        Err(reason) => return no_image(&reason),
    };

    let root = scratch("real-docker");
    let invocation = shell_probe();
    let record = intent_for(RUN_A, INCARNATION_1, &invocation);
    let name = name_for(RUN_A, INCARNATION_1, &invocation);
    let view = DisposableDirView::new(trace.clone());
    let plan = LaunchPlan {
        private_root: root.clone(),
        name: name.clone(),
        intent: record.clone(),
        spec: CreateSpec {
            name: name.as_str().to_owned(),
            image_id: image.id.clone(),
            labels: record.labels(&root),
            mounts: Vec::new(),
            env: Vec::new(),
            command: vec!["/bin/sh".to_owned(), "-c".to_owned(), "exit 0".to_owned()],
            workdir: None,
        },
        view: GitViewRequest {
            path: root.join("views").join(name.as_str()),
            workspace: root.clone(),
            head: None,
        },
    };

    let mut hooks = RecordingHooks::new(trace.clone());
    let launched: Launched = match launch(&mut hooks, docker.as_ref(), &view, &plan) {
        Ok(launched) => launched,
        Err(error) => {
            // Leave nothing behind even when the launch itself failed.
            let _ = reclaim(
                &mut hooks,
                docker.as_ref(),
                &view,
                &root,
                &name,
                Some(&plan.view.path),
            );
            panic!("the real runtime refused the launch: {error}");
        }
    };
    assert_eq!(launched.reported_image_id, image.id);
    assert!(launched.intent_path.exists());

    // Discovery finds it by `tactus.private_root`, with its five labels.
    let discovered = docker
        .containers_with_label(
            LABEL_PRIVATE_ROOT,
            &root.to_string_lossy().replace('\\', "/"),
        )
        .expect("reachable");
    assert_eq!(discovered.len(), 1, "{discovered:?}");
    for label in LABELS {
        assert!(
            discovered[0].labels.contains_key(*label),
            "the real container is missing `{label}`"
        );
    }

    // Reclaim, twice: idempotent and tolerant of already-gone.
    for round in 0..2 {
        reclaim(
            &mut hooks,
            docker.as_ref(),
            &view,
            &root,
            &name,
            Some(&launched.view_path),
        )
        .unwrap_or_else(|error| panic!("round {round} refused: {error}"));
    }
    assert!(!launched.intent_path.exists());
    assert!(!launched.view_path.exists());
    assert_eq!(
        docker
            .containers_with_label(
                LABEL_PRIVATE_ROOT,
                &root.to_string_lossy().replace('\\', "/")
            )
            .expect("reachable")
            .len(),
        0
    );
}
