//! The Event funnel's tests.
//!
//! Three rules this project pays for when it forgets them are load-bearing
//! here:
//!
//! * **A function may not be its own oracle.** The byte-identity claim is
//!   measured against [`super::premove::PremoveEventLog`] — the writer as it
//!   stood at `ff0490a` — never against the moved writer.
//! * **Enumerations come from the types.** The site grids iterate
//!   `EventSite::ALL`, `SubEffectPoint::modes()` and `BarrierStep::ALL` rather
//!   than a list somebody thought of, so a variant added later is uncovered
//!   loudly instead of silently.
//! * **Hostility is a count.** The differential grid varies the log's shape,
//!   the torn tail's length and its bytes independently and asserts how many
//!   distinct values each axis took.
// Allowlist placement: the **funnel section** of `effects/allowlist.toml`, which
// carries this module's review clause -- effects only inside site-taking APIs,
// no writable handle returned. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::premove::PremoveEventLog;
use super::*;
use crate::events::{
    BudgetExceeded, BudgetKind, DesignDefect, EventBody, GateSummary, PoolExhausted, TaskCommitted,
};
use crate::gates::ShellKind;
use crate::ir::{
    Artifact, ArtifactId, Effort, Plan, PlanSource, QuestionId, ResolvedEffortPolicy, TaskId,
};
use crate::review::ReviewPlan;
use crate::topology::events::{
    CommitSha, DeferWaitElapsed4, GitRef, IncarnationId, RunStarted4, RunnerContract, RunnerKind,
    RunnerPolicy, TopologyEvent, TopologyEventBody, TopologyLimits,
};
use crate::topology::paths::{PathGrammar, PathPolicy, PathPolicyVersion};
use crate::topology::schema::TOPOLOGY_SCHEMA;
use crate::util::{DurabilityLedger, DurableStep};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static SCRATCH: AtomicU32 = AtomicU32::new(0);

/// A directory of this test's own. Numbered as well as named, because several
/// of the grids below want a fresh log per cell.
fn scratch(tag: &str) -> PathBuf {
    let n = SCRATCH.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tactus-event-funnel-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn log_path(tag: &str) -> PathBuf {
    scratch(tag).join("events.jsonl")
}

/// The **message** a `TactusError::EventLog` carries, without its rendering.
///
/// `TactusError::EventLog`'s Display is `event log {path}: {message}`, so
/// `error.to_string().contains(x)` is satisfied by the *path* as readily as by
/// anything the funnel decided to say. Two catalogue mutations lived in that
/// gap, because the fixtures named their scratch directories after the very
/// point they then looked for (`PR5-EVENTS-045`, `PR5-EVENTS-046`). Assertions
/// about what an error *says* go through here.
fn event_log_message(error: &TactusError) -> &str {
    match error {
        TactusError::EventLog { message, .. } => message,
        other => panic!("not an event-log error: {other}"),
    }
}

fn commit(sha: &str, message: &str) -> EventBody {
    EventBody::TaskCommitted {
        task: format!("task-for-{sha}"),
        data: TaskCommitted {
            sha: sha.to_owned(),
            message: message.to_owned(),
        },
    }
}

fn defect(question: &str) -> EventBody {
    EventBody::DesignDefect {
        data: DesignDefect {
            question: QuestionId(question.to_owned()),
            context: "context Ünicode".to_owned(),
            answer: "answer".to_owned(),
        },
    }
}

/// An `attempt_finished` whose duration the wire format **cannot** carry.
///
/// `duration_ms` is an integer, so 1,500,123 µs is written as `1500` and reads
/// back as 1.500 s exactly. That makes this body the one fixture that can tell
/// the constructed event from the round-tripped one — DESIGN.md:406's "it
/// applies the event as it will be read back rather than as constructed. A live
/// run and a replay of its own log are therefore the same computation".
///
/// Every other body in these grids is lossless, which is why
/// `PR5-CORRECTNESS-015` survived: `Ok(written)` -> `Ok(event)` is invisible
/// to a comparison whose inputs round-trip unchanged.
fn lossy_duration_attempt() -> EventBody {
    EventBody::AttemptFinished {
        task: "t1".to_owned(),
        attempt: 1,
        rung: 0,
        profile: "impl-mid".to_owned(),
        data: Box::new(crate::events::AttemptRecord {
            attempt: 1,
            tier: "mid".to_owned(),
            model: "a-model".to_owned(),
            pool: None,
            resumed: false,
            duration: Duration::from_micros(1_500_123),
            cost_usd: None,
            reviews: Vec::new(),
            session_id: None,
            usage: None,
            failure: None,
        }),
        parking: None,
        transition: None,
        prepared_commit: None,
    }
}

/// The duration `lossy_duration_attempt` carries, and the duration a replay of
/// it yields. Written out rather than computed from the codec.
const LOSSY_CONSTRUCTED: Duration = Duration::from_micros(1_500_123);
const LOSSY_AS_READ_BACK: Duration = Duration::from_millis(1_500);

/// The `duration` of an `attempt_finished` body, for the assertions above.
fn duration_of(body: &EventBody) -> Duration {
    match body {
        EventBody::AttemptFinished { data, .. } => data.duration,
        other => panic!("not an attempt_finished: {}", other.kind()),
    }
}

/// An event carrying a value `serde_json` refuses to serialize.
///
/// Not a contrivance: `limit_usd` is an ordinary `f64` on an ordinary event, and
/// `serde_json` refuses non-finite floats. It is the only *reachable* failure
/// this funnel has strictly before the append is entered, which makes it the
/// only way to prove the entered/not-entered boundary is where the code says.
fn unserializable() -> EventBody {
    EventBody::BudgetExceeded {
        data: BudgetExceeded {
            budget: BudgetKind::Run,
            limit_usd: f64::NAN,
            spent_usd: 1.0,
            task: "t1".to_owned(),
        },
    }
}

fn topology_event(round: u32) -> TopologyEvent {
    TopologyEvent {
        ts: "2026-08-20T09:41:02Z".to_owned(),
        body: TopologyEventBody::DeferWaitElapsed {
            data: DeferWaitElapsed4 {
                waited_ms: 1_500,
                round,
            },
        },
    }
}

fn topology_line(round: u32) -> TopologyLine {
    TopologyLine::round_trip(&topology_event(round))
        .expect("a defer_wait_elapsed survives its own wire format")
        .0
}

/// A `run_started`: the one kind that belongs at `Event.AppendFirst`.
///
/// Hand-built rather than borrowed, because the fold's own fixture lives in a
/// private `mod tests` of a frozen file. None of these values is read by the
/// funnel — it takes the round-tripped *bytes* — so what the fixture has to be
/// is a `RunStarted4` that survives its own wire format, and nothing more.
fn run_started_event() -> TopologyEvent {
    TopologyEvent {
        ts: "2026-08-20T09:41:00Z".to_owned(),
        body: TopologyEventBody::RunStarted {
            data: Box::new(RunStarted4 {
                schema: TOPOLOGY_SCHEMA,
                tactus_version: "0.1.0".to_owned(),
                run_id: "01J8ZQKB2M7NC5PQR0TVWXYZ12".to_owned(),
                incarnation: IncarnationId("01J8ZQKB2M7NC5PQR0TVWXYZ13".to_owned()),
                runner: RunnerPolicy {
                    kind: RunnerKind::Host,
                    policy: RunnerContract::HostV1,
                    image: None,
                    credential_volumes: None,
                },
                probed_agents: vec!["claude-code".to_owned()],
                branch: "tactus/run-01J8ZQKB2M7NC5PQR0TVWXYZ12".to_owned(),
                integration_ref: GitRef::from("refs/tactus/integration"),
                base_sha: CommitSha::from("0f5c1c4"),
                execution_root: "/var/lib/tactus/roots".to_owned(),
                private_dir: "/var/lib/tactus/private".to_owned(),
                plan_path: "docs/plan.md".to_owned(),
                config_path: Some("tactus.toml".to_owned()),
                plan_hash: "frozen-hash".to_owned(),
                normalized_plan_digest: inputs().normalized_plan_digest,
                registry_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                path_policy: PathPolicy {
                    version: PathPolicyVersion::V1,
                    case_fold: false,
                    grammar: PathGrammar::Globset,
                },
                limits: TopologyLimits {
                    max_parallel: 3,
                    max_defers: 2,
                    max_merge_repairs: 1,
                },
                gates: vec!["fmt".to_owned()],
                gates_from_config: true,
                gate_cmds: vec![GateSummary {
                    name: "fmt".to_owned(),
                    cmd: "cargo fmt --check".to_owned(),
                    timeout: Duration::from_secs(60),
                    shell: ShellKind::Sh,
                }],
                interaction_mode: "never".to_owned(),
                chains: Vec::new(),
                effort_policy: ResolvedEffortPolicy {
                    small: Effort::Low,
                    mid: Effort::Medium,
                    frontier: Effort::High,
                    review: Effort::XHigh,
                },
                reviews: ReviewPlan::default(),
            }),
        },
    }
}

/// A `pool_exhausted`: one of the three kinds the frozen lenient class names,
/// and therefore an `Event.AppendInformational`.
fn informational_event() -> TopologyEvent {
    TopologyEvent {
        ts: "2026-08-20T09:41:03Z".to_owned(),
        body: TopologyEventBody::PoolExhausted {
            data: PoolExhausted {
                pool: "claude-code".to_owned(),
                agent: "claude-code".to_owned(),
                reset_at: Some("2026-08-20T10:00:00Z".to_owned()),
                detail: "usage limit reached".to_owned(),
            },
        },
    }
}

/// One line per schema-4 append site, keyed by [`TOPOLOGY_APPEND_SITES`] so a
/// site added to the frozen inventory later has no line here and says so.
///
/// This exists because `PR4-CONF-002` is in the standing ledger: a grid that
/// drove one role and reasoned about the others left both contract-named probe
/// paths emitting no evidence, with the whole suite green. Three sites are
/// named by this slice's contract, and a grid that drives one of them proves
/// one of them.
fn append_site_lines() -> Vec<(EventSite, TopologyLine)> {
    let lines = vec![
        (
            EventSite::AppendFirst,
            TopologyLine::round_trip(&run_started_event())
                .expect("a run_started survives its own wire format")
                .0,
        ),
        (EventSite::Append, topology_line(1)),
        (
            EventSite::AppendInformational,
            TopologyLine::round_trip(&informational_event())
                .expect("a pool_exhausted survives its own wire format")
                .0,
        ),
    ];
    assert_eq!(
        lines.iter().map(|(site, _)| *site).collect::<Vec<_>>(),
        TOPOLOGY_APPEND_SITES,
        "every schema-4 append site the funnel accepts needs a line of its own kind"
    );
    assert_eq!(
        lines
            .iter()
            .map(|(_, line)| line.kind())
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "three sites, three distinct event kinds"
    );
    for (site, line) in &lines {
        assert_eq!(
            line.site(),
            *site,
            "`{}` was built from an event the frozen class puts elsewhere",
            site.name()
        );
    }
    lines
}

/// Frozen inputs for the checked replay. The plan never has to match a
/// `run_started` here: every barrier test either replays an empty prefix or
/// asserts a refusal, and the refusals are the fold's, not this plan's.
fn inputs() -> FrozenInputs {
    FrozenInputs {
        plan: Plan {
            source: PlanSource {
                adapter: "markdown".to_owned(),
                hash: "frozen-hash".to_owned(),
            },
            tasks: Vec::new(),
            artifacts: vec![Artifact {
                id: ArtifactId::from("contract"),
                produced_by: Some(TaskId::from("aay")),
            }],
        },
        normalized_plan_digest:
            "sha256:9999999999999999999999999999999999999999999999999999999999999999".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Observers
// ---------------------------------------------------------------------------

/// Records every coordinate the funnel offered, answers `Proceed` to all of
/// them, and keeps the sync ledger.
#[derive(Debug, Default)]
struct Witness {
    phases: Vec<(EventSite, HookPhase)>,
    offered: Vec<(EventSite, SubEffectPoint, InjectionMode)>,
    ledger: Vec<SyncRecord>,
    durability: DurabilityLedger,
    /// What the durability ledger held **at** each `(point, mode)` consult.
    ///
    /// The whole content of `(e-s)` — "sync_data returned an error *after the
    /// data reached the disk*" — is which side of the sync the coordinate is
    /// on, and that is not readable from a trace taken afterwards: by then the
    /// sync has happened either way. So it is read at the moment the funnel
    /// asks.
    at_consult: Vec<(SubEffectPoint, InjectionMode, Vec<DurableStep>)>,
}

impl EventHooks for Witness {
    fn phase(&mut self, site: EventSite, phase: HookPhase) {
        self.phases.push((site, phase));
    }

    fn point(&mut self, site: EventSite, point: SubEffectPoint, mode: InjectionMode) -> Injection {
        self.offered.push((site, point, mode));
        self.at_consult.push((point, mode, self.durability.steps()));
        Injection::Proceed
    }

    fn durability_ledger(&self) -> DurabilityLedger {
        self.durability.clone()
    }

    fn synced(&mut self, record: &SyncRecord) {
        self.ledger.push(record.clone());
    }
}

impl Witness {
    /// Record the funnel's durability primitives too, in order.
    fn recording_durability(mut self) -> Self {
        self.durability = DurabilityLedger::recording();
        self
    }

    /// The durability steps this funnel performed, in order.
    fn steps(&self) -> Vec<DurableStep> {
        self.durability.steps()
    }

    fn offered_at(&self, point: SubEffectPoint, mode: InjectionMode) -> bool {
        self.offered
            .iter()
            .any(|(_, offered, offered_mode)| *offered == point && *offered_mode == mode)
    }

    fn file_syncs(&self) -> Vec<u64> {
        self.ledger
            .iter()
            .filter(|record| record.target == SyncTarget::LogFile)
            .map(|record| record.len)
            .collect()
    }

    fn directory_syncs(&self) -> Vec<SubEffectPoint> {
        self.ledger
            .iter()
            .filter(|record| record.target == SyncTarget::LogDirectory)
            .map(|record| record.point)
            .collect()
    }
}

/// Returns `Err` at exactly one coordinate, and records the ledger so a test can
/// prove the primitive did *not* run when the coordinate is before it.
#[derive(Debug)]
struct FailAt {
    point: SubEffectPoint,
    mode: InjectionMode,
    ledger: Vec<SyncRecord>,
    fired: u32,
}

impl FailAt {
    fn error(point: SubEffectPoint) -> Self {
        Self {
            point,
            mode: InjectionMode::ErrorReturn,
            ledger: Vec::new(),
            fired: 0,
        }
    }
}

impl EventHooks for FailAt {
    fn point(&mut self, _site: EventSite, point: SubEffectPoint, mode: InjectionMode) -> Injection {
        if point == self.point && mode == self.mode {
            self.fired += 1;
            return Injection::Error;
        }
        Injection::Proceed
    }

    fn synced(&mut self, record: &SyncRecord) {
        self.ledger.push(record.clone());
    }
}

/// Rewrites the log between the barrier's steps.
///
/// `synced` fires after `SyncPrefix` and before the reread, so a mutation there
/// is exactly an unstable reread. `phase(ProvePrefixStable, After)` fires after
/// the stability proof and before the checked replay, so a mutation there is
/// what separates "replayed the bytes it proved" from "read the file a third
/// time".
struct Rewrite {
    after_sync: Option<Vec<u8>>,
    after_proof: Option<Vec<u8>>,
    path: PathBuf,
}

impl Rewrite {
    fn after_sync(path: &Path, bytes: &[u8]) -> Self {
        Self {
            after_sync: Some(bytes.to_vec()),
            after_proof: None,
            path: path.to_path_buf(),
        }
    }

    fn after_proof(path: &Path, bytes: &[u8]) -> Self {
        Self {
            after_sync: None,
            after_proof: Some(bytes.to_vec()),
            path: path.to_path_buf(),
        }
    }
}

impl EventHooks for Rewrite {
    fn phase(&mut self, site: EventSite, phase: HookPhase) {
        if site == EventSite::ProvePrefixStable && phase == HookPhase::After {
            if let Some(bytes) = self.after_proof.take() {
                fs::write(&self.path, bytes).expect("rewrite after the proof");
            }
        }
    }

    fn synced(&mut self, _record: &SyncRecord) {
        if let Some(bytes) = self.after_sync.take() {
            fs::write(&self.path, bytes).expect("rewrite after the sync");
        }
    }
}

/// Asks for the torn half of `Written`'s kill entry without arming a kill.
#[derive(Debug, Default)]
struct TornWriter;

impl EventHooks for TornWriter {
    fn written_kill_shape(&mut self, _site: EventSite) -> WrittenShape {
        WrittenShape::Torn
    }
}

// ---------------------------------------------------------------------------
// The site partition
// ---------------------------------------------------------------------------

/// Every site of the group, classified into exactly one role.
///
/// The table is written from the frozen enum's own doc comments and from
/// `effect_site_inventory.identity`, not from `EventLog`'s `match` arms — a
/// classification derived from the code under test cannot disagree with it.
const SITE_ROLES: &[(EventSite, &str)] = &[
    (EventSite::OpenLog, "open"),
    (EventSite::LegacyOpenLog, "open"),
    (EventSite::AppendFirst, "schema-4 append"),
    (EventSite::Append, "schema-4 append"),
    (EventSite::AppendInformational, "schema-4 append"),
    (EventSite::LegacyAppend, "schema-1..3 append"),
    (
        EventSite::ProvePrefixStable,
        "read-only barrier observation",
    ),
];

#[test]
fn every_event_site_is_classified_and_the_funnel_accepts_exactly_its_own() {
    // The list is derived from the type, so a site added later is uncovered
    // loudly rather than silently.
    let classified: BTreeSet<EventSite> = SITE_ROLES.iter().map(|(site, _)| *site).collect();
    let declared: BTreeSet<EventSite> = EventSite::ALL.iter().copied().collect();
    assert_eq!(
        classified, declared,
        "every site the frozen inventory declares needs a role in this table"
    );
    assert_eq!(
        SITE_ROLES
            .iter()
            .map(|(_, role)| *role)
            .collect::<BTreeSet<_>>()
            .len(),
        4,
        "four roles, and a site that acquired a fifth has to be argued about"
    );

    let dir = scratch("partition");
    for (site, role) in SITE_ROLES {
        let path = dir.join(format!("{}.jsonl", site.name()));
        let mut warnings = Vec::new();
        let opened = EventLog::open(*site, &path, &mut warnings);
        assert_eq!(
            opened.is_ok(),
            *role == "open",
            "`Event.{}` opening: role is {role}",
            site.name()
        );
        if let Err(error) = opened {
            assert!(
                error.to_string().contains("is not an open site"),
                "the refusal has to say why: {error}"
            );
            continue;
        }
    }

    // Appending: one handle per scope, every site tried against both. The
    // schema-4 cell hands each site a line of *its own* kind, so an accepting
    // site is exercised rather than refused for the line's sake — the three
    // append sites are three separately droppable behaviours, not one.
    let lines = append_site_lines();
    let legacy_path = dir.join("legacy-appends.jsonl");
    let shared_path = dir.join("shared-appends.jsonl");
    for (site, role) in SITE_ROLES {
        let mut warnings = Vec::new();
        let mut legacy = EventLog::open(EventSite::LegacyOpenLog, &legacy_path, &mut warnings)
            .expect("a legacy handle");
        let mut shared = EventLog::open(EventSite::OpenLog, &shared_path, &mut warnings)
            .expect("a shared handle");
        assert_eq!(
            legacy.append(*site, commit("a", "m")).is_ok(),
            *role == "schema-1..3 append",
            "`Event.{}` through the legacy append",
            site.name()
        );
        // A site with no line of its own is one this funnel must refuse, so any
        // line will do for it; `defer_wait_elapsed` is the one it gets.
        let line = lines
            .iter()
            .find(|(candidate, _)| candidate == site)
            .map_or_else(|| topology_line(1), |(_, line)| line.clone());
        assert_eq!(
            shared.append_topology(*site, &line).is_ok(),
            *role == "schema-4 append",
            "`Event.{}` through the schema-4 append",
            site.name()
        );
    }
}

#[test]
fn a_handle_does_not_mix_the_legacy_and_shared_scopes() {
    let path = log_path("scopes");
    let mut warnings = Vec::new();

    let mut legacy =
        EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("a legacy handle");
    let refused = legacy
        .append_topology(EventSite::Append, &topology_line(1))
        .expect_err("a schema-3 log does not take schema-4 lines");
    assert!(refused.to_string().contains("does not accept"), "{refused}");

    let shared_path = log_path("scopes-shared");
    let mut shared =
        EventLog::open(EventSite::OpenLog, &shared_path, &mut warnings).expect("a shared handle");
    let refused = shared
        .append(EventSite::LegacyAppend, commit("a", "m"))
        .expect_err("a schema-4 log does not take legacy events");
    assert!(refused.to_string().contains("does not accept"), "{refused}");

    // Nothing was written by either refusal: a scope refusal happens before the
    // append is entered.
    assert_eq!(fs::read(&path).expect("legacy log").len(), 0);
    assert_eq!(fs::read(&shared_path).expect("shared log").len(), 0);
    assert_eq!(legacy.poisoned_at(), None, "a refusal is not a poisoning");
    assert_eq!(shared.poisoned_at(), None);
}

/// The lenient class, transcribed from `src/topology/events.rs`'s own frozen
/// statement of it — "the lenient class is exactly these three by name" — and
/// not computed from the predicate the funnel uses.
const INFORMATIONAL_KINDS: &[&str] = &["capacity_snapshot", "pool_exhausted", "design_defect"];

#[test]
fn an_events_append_site_is_decided_by_the_frozen_transaction_class() {
    // `run_started` is `AppendFirst` ("the commitment boundary"); the three
    // lenient kinds are `AppendInformational`; everything else is `Append`.
    let expected: &[(&str, EventSite)] = &[
        ("run_started", EventSite::AppendFirst),
        ("capacity_snapshot", EventSite::AppendInformational),
        ("pool_exhausted", EventSite::AppendInformational),
        ("design_defect", EventSite::AppendInformational),
        ("defer_wait_elapsed", EventSite::Append),
        ("task_merged", EventSite::Append),
        ("run_finished", EventSite::Append),
    ];
    for (kind, site) in expected {
        let derived = if *kind == "run_started" {
            EventSite::AppendFirst
        } else if INFORMATIONAL_KINDS.contains(kind) {
            EventSite::AppendInformational
        } else {
            EventSite::Append
        };
        assert_eq!(
            derived, *site,
            "the table disagrees with itself about {kind}"
        );
    }

    let line = topology_line(4);
    assert_eq!(line.kind(), "defer_wait_elapsed");
    assert_eq!(line.site(), EventSite::Append);

    // And the two sites the table names that a `defer_wait_elapsed` is not: a
    // `run_started` really does classify as the commitment boundary and a
    // `pool_exhausted` really does classify as lenient, so the three arms of
    // `site_for` are each reached by an event rather than by argument.
    let classified: Vec<(&str, EventSite)> = append_site_lines()
        .iter()
        .map(|(_, line)| (line.kind(), line.site()))
        .collect();
    for (kind, site) in &classified {
        let from_table = expected
            .iter()
            .find(|(candidate, _)| candidate == kind)
            .map(|(_, site)| *site)
            .unwrap_or_else(|| panic!("{kind} is not in the transcribed table"));
        assert_eq!(*site, from_table, "{kind} was filed at the wrong site");
    }
    assert_eq!(
        classified
            .iter()
            .map(|(_, site)| *site)
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "three kinds, three distinct sites: {classified:?}"
    );

    let path = log_path("site-for-kind");
    let mut warnings = Vec::new();
    let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");
    let refused = log
        .append_topology(EventSite::AppendInformational, &line)
        .expect_err("a transaction event does not belong at the lenient site");
    assert!(
        refused.to_string().contains("belongs at `Event.Append`"),
        "the refusal names where it does belong: {refused}"
    );
    assert_eq!(fs::read(&path).expect("log").len(), 0);
}

// ---------------------------------------------------------------------------
// Byte identity with the pre-move writer
// ---------------------------------------------------------------------------

/// Every log shape the open path can meet, each varying one axis.
///
/// `None` is "the file does not exist"; the rest are exact byte strings. The
/// torn cases vary the *length* of the tail (1, 5, 12 bytes) and its *content*
/// (ASCII, valid JSON, a split multi-byte character) independently of whether
/// there is a committed prefix in front of it, because a grid that moved those
/// together could be satisfied by a correlated field.
fn open_grid() -> Vec<(&'static str, Option<Vec<u8>>)> {
    let good = b"{\"ts\":\"2026-08-20T00:00:00Z\",\"event\":\"design_defect\"}".to_vec();
    let mut split_utf8 = good.clone();
    split_utf8.push(b'\n');
    // The first two bytes of a three-byte character: invalid UTF-8 on its own,
    // and dropped before the committed bytes are validated.
    split_utf8.extend_from_slice(&[0xE2, 0x82]);
    vec![
        ("absent", None),
        ("empty", Some(Vec::new())),
        (
            "one committed line",
            Some([good.clone(), b"\n".to_vec()].concat()),
        ),
        (
            "three committed lines",
            Some(
                [
                    good.clone(),
                    b"\n".to_vec(),
                    good.clone(),
                    b"\n".to_vec(),
                    good.clone(),
                    b"\n".to_vec(),
                ]
                .concat(),
            ),
        ),
        (
            "torn tail of 1 byte",
            Some([good.clone(), b"\n".to_vec(), b"{".to_vec()].concat()),
        ),
        (
            "torn tail of 5 bytes",
            Some([good.clone(), b"\n".to_vec(), b"{\"ts\"".to_vec()].concat()),
        ),
        (
            "torn tail of 12 bytes",
            Some([good.clone(), b"\n".to_vec(), b"{\"ts\":\"2026".to_vec()].concat()),
        ),
        (
            "torn tail only, no prefix",
            Some(b"{\"ts\":\"2026".to_vec()),
        ),
        (
            "torn tail that is valid JSON",
            Some([good.clone(), b"\n".to_vec(), good.clone()].concat()),
        ),
        ("torn tail of split UTF-8", Some(split_utf8)),
        (
            "blank committed line",
            Some([good.clone(), b"\n\n".to_vec()].concat()),
        ),
        ("a lone newline", Some(b"\n".to_vec())),
        (
            "trailing carriage return",
            Some([good.clone(), b"\n".to_vec(), b"\r".to_vec()].concat()),
        ),
    ]
}

#[test]
fn the_grid_varies_shape_and_tail_length_and_tail_content_independently() {
    // Hostility as counts, not as prose: `PR4-CONF-004`/`-006` are in the
    // ledger because a grid whose axes moved together was satisfied by a
    // correlated field.
    let grid = open_grid();
    assert_eq!(grid.len(), 13, "thirteen shapes");
    let tails: BTreeSet<usize> = grid
        .iter()
        .filter_map(|(_, bytes)| bytes.as_ref())
        .map(|bytes| {
            let keep = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1);
            bytes.len() - keep
        })
        .collect();
    assert_eq!(
        tails.len(),
        6,
        "six distinct torn-tail lengths (0, 1, 5, 11, 12, 53): {tails:?}"
    );
    let committed: BTreeSet<usize> = grid
        .iter()
        .filter_map(|(_, bytes)| bytes.as_ref())
        .map(|bytes| bytes.iter().filter(|byte| **byte == b'\n').count())
        .collect();
    assert!(
        committed.len() >= 4,
        "at least four distinct committed-line counts: {committed:?}"
    );
    assert_eq!(
        grid.iter().filter(|(_, bytes)| bytes.is_none()).count(),
        1,
        "exactly one absent-file cell"
    );
}

#[test]
fn the_legacy_open_is_byte_identical_to_the_pre_move_writer() {
    for (name, seed) in open_grid() {
        let moved_dir = scratch("identity-moved");
        let premove_dir = scratch("identity-premove");
        let moved = moved_dir.join("events.jsonl");
        let premove = premove_dir.join("events.jsonl");
        if let Some(seed) = &seed {
            fs::write(&moved, seed).expect("seed");
            fs::write(&premove, seed).expect("seed");
        }

        let mut moved_warnings = Vec::new();
        let mut premove_warnings = Vec::new();
        let moved_result = EventLog::open(EventSite::LegacyOpenLog, &moved, &mut moved_warnings);
        let premove_result = PremoveEventLog::open(&premove, &mut premove_warnings);
        if let (Ok(moved_log), Ok(premove_log)) = (&moved_result, &premove_result) {
            assert_eq!(
                moved_log.path(),
                moved,
                "{name}: the moved writer kept its path"
            );
            assert_eq!(premove_log.path(), premove, "{name}: and so did the oracle");
        }

        assert_eq!(
            moved_result.is_ok(),
            premove_result.is_ok(),
            "{name}: one opened and the other did not"
        );
        // Warnings are compared with the path's directory removed, because the
        // two writers were pointed at two directories on purpose — a comparison
        // that shared one file could not tell "wrote the same bytes" from "wrote
        // nothing twice".
        assert_eq!(
            moved_warnings
                .iter()
                .map(|w| w.replace(&moved.display().to_string(), "<log>"))
                .collect::<Vec<_>>(),
            premove_warnings
                .iter()
                .map(|w| w.replace(&premove.display().to_string(), "<log>"))
                .collect::<Vec<_>>(),
            "{name}: the warnings differ"
        );
        assert_eq!(
            fs::read(&moved).expect("moved log"),
            fs::read(&premove).expect("premove log"),
            "{name}: the bytes on disk differ"
        );
    }
}

#[test]
fn the_legacy_append_is_byte_identical_to_the_pre_move_writer() {
    // Four bodies, so a comparison cannot pass by writing one constant twice —
    // and one of them is **lossy over the wire**, which is what makes the
    // returned event a claim and not a copy of the input (`PR5-CORRECTNESS-015`).
    let bodies: Vec<EventBody> = vec![
        commit("0f5c1c4", "first"),
        defect("q-1"),
        lossy_duration_attempt(),
        commit("deadbee", "second Ünicode"),
    ];
    assert_ne!(
        LOSSY_CONSTRUCTED, LOSSY_AS_READ_BACK,
        "the lossy fixture must actually be lossy, or it witnesses nothing"
    );
    for (name, seed) in open_grid() {
        let moved_dir = scratch("append-moved");
        let premove_dir = scratch("append-premove");
        let moved = moved_dir.join("events.jsonl");
        let premove = premove_dir.join("events.jsonl");
        if let Some(seed) = &seed {
            fs::write(&moved, seed).expect("seed");
            fs::write(&premove, seed).expect("seed");
        }
        let mut warnings = Vec::new();
        let mut moved_log = EventLog::open(EventSite::LegacyOpenLog, &moved, &mut warnings)
            .expect("the moved writer opens");
        let mut premove_log =
            PremoveEventLog::open(&premove, &mut warnings).expect("the pre-move writer opens");

        // Bracketing clock reads, so the `ts` the writers stamp can be checked
        // for being a *time* rather than merely for being equal to itself. The
        // format is fixed-width RFC 3339 UTC, so lexical order is chronological.
        let before = crate::util::rfc3339_utc_now();
        for body in &bodies {
            let moved_event = moved_log
                .append(EventSite::LegacyAppend, body.clone())
                .expect("moved append");
            let premove_event = premove_log.append(body.clone()).expect("premove append");
            assert_eq!(
                moved_event.body, premove_event.body,
                "{name}: the round-tripped bodies differ"
            );
            // The returned body is the one the wire carries, not the one that
            // was handed in. `PR5-CORRECTNESS-015`: returning the constructed
            // event leaves the coordinator holding a duration a replay of its
            // own log can never restore.
            if matches!(body, EventBody::AttemptFinished { .. }) {
                assert_eq!(
                    duration_of(&moved_event.body),
                    LOSSY_AS_READ_BACK,
                    "{name}: the moved writer returned the constructed duration, \
                     not the one the log will read back"
                );
                assert_eq!(
                    duration_of(&premove_event.body),
                    LOSSY_AS_READ_BACK,
                    "{name}: and the oracle agrees, so this is the shared contract"
                );
            }
        }
        let after = crate::util::rfc3339_utc_now();

        // The timestamps are the two writers' own `Event::now`, so the bytes are
        // compared with the `ts` field of every line normalized and nothing
        // else touched. A mutation to the separator, the ordering, the newline
        // or the payload still shows.
        assert_eq!(
            normalize_timestamps(&fs::read(&moved).expect("moved log")),
            normalize_timestamps(&fs::read(&premove).expect("premove log")),
            "{name}: the appended bytes differ"
        );
        // Normalising `ts` is what lets the bytes be compared at all, and it is
        // also a hole: it says nothing about the value. `PR5-CORRECTNESS-006` /
        // `PR5-SEAMS-003` is a moved writer stamping `1970-01-01T00:00:00Z`,
        // which this grid folded away. So the field is checked separately, on
        // both writers, against clock reads taken either side of the appends.
        for (writer, path) in [("moved", &moved), ("oracle", &premove)] {
            for stamp in appended_timestamps(path, committed_lines(seed.as_ref())) {
                assert!(
                    stamp >= before && stamp <= after,
                    "{name}/{writer}: appended ts `{stamp}` is not a time this \
                     append could have happened at ({before}..={after})"
                );
            }
        }
        // Both files gained exactly one newline-terminated line per body beyond
        // the committed prefix they started with.
        let committed_before = committed_lines(seed.as_ref());
        let contents = fs::read(&moved).expect("moved log");
        assert_eq!(
            contents.iter().filter(|byte| **byte == b'\n').count(),
            committed_before + bodies.len(),
            "{name}: the wrong number of committed lines"
        );
        assert_eq!(contents.last(), Some(&b'\n'), "{name}: no commit marker");
    }
}

/// The **error contract** of the legacy open is the pre-move writer's too.
///
/// `invariants_preserved[0]` is "EventLog semantics unchanged for legacy
/// callers", and an error *variant* is semantics: `TactusError::Io` carries the
/// `std::io::Error` a caller can match `kind()` on, while
/// `TactusError::EventLog` carries a rendered string and loses it.
/// `PR5-SEAMS-004` is exactly that swap inside `open_legacy`, and the
/// differential grid could not see it because every one of its thirteen shapes
/// **opens successfully** — it varies the file's bytes, and a failing open is a
/// property of the path.
///
/// So this grid varies the path, and the expectation comes from the oracle
/// rather than from a variant written down here: whatever the pre-move writer
/// returns, the moved writer returns the same variant, with the same path
/// named. A control asserts the oracle really did fail, because a grid whose
/// cells all succeeded would compare two `Ok`s and pass.
#[test]
fn a_legacy_open_that_fails_fails_the_way_the_pre_move_writer_did() {
    /// (name, how to build a path that cannot be opened for append).
    type Case = (&'static str, fn(&Path) -> PathBuf);
    let cases: &[Case] = &[
        ("a parent directory that does not exist", |dir| {
            dir.join("no-such-directory").join("events.jsonl")
        }),
        ("the path is an existing directory", |dir| {
            let path = dir.join("events.jsonl");
            fs::create_dir_all(&path).expect("a directory where the log goes");
            path
        }),
        ("a read-only file", |dir| {
            let path = dir.join("events.jsonl");
            fs::write(&path, b"{\"ts\":\"2026-08-20T09:41:00Z\"}\n").expect("seed");
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).expect("make it read-only");
            path
        }),
        ("a read-only file with a torn tail", |dir| {
            let path = dir.join("events.jsonl");
            fs::write(&path, b"{\"ts\":\"2026-08-20T09:41:00Z\"}\n{\"ts\"").expect("seed");
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).expect("make it read-only");
            path
        }),
    ];

    let mut failed = 0_usize;
    let mut unexercisable = Vec::new();
    for (name, build) in cases {
        let moved = build(&scratch("open-fail-moved"));
        let premove = build(&scratch("open-fail-premove"));

        let mut moved_warnings = Vec::new();
        let mut premove_warnings = Vec::new();
        let moved_result = EventLog::open(EventSite::LegacyOpenLog, &moved, &mut moved_warnings);
        let premove_result = PremoveEventLog::open(&premove, &mut premove_warnings);

        assert_eq!(
            moved_result.is_err(),
            premove_result.is_err(),
            "{name}: one writer failed and the other did not"
        );
        let (Err(moved_error), Err(premove_error)) = (&moved_result, &premove_result) else {
            // A machine that can open this anyway (a `root` that ignores the
            // read-only bit) cannot host this cell. Recorded, never silent.
            unexercisable.push(*name);
            continue;
        };
        assert_eq!(
            std::mem::discriminant(moved_error),
            std::mem::discriminant(premove_error),
            "{name}: the moved writer returns a different TactusError variant \
             than the pre-move one did ({moved_error:?} vs {premove_error:?})"
        );
        // The variant is `Io`, and it is asserted positively as well as
        // relatively: a mutation applied to *both* sides would keep the
        // discriminants equal.
        assert!(
            matches!(premove_error, TactusError::Io { .. }),
            "{name}: the frozen oracle's legacy open contract is TactusError::Io: \
             {premove_error:?}"
        );
        assert!(
            matches!(moved_error, TactusError::Io { .. }),
            "{name}: the moved writer must keep it: {moved_error:?}"
        );
        // And the same path is named, with the two directories folded away —
        // they are different on purpose, so a comparison cannot pass by naming
        // nothing.
        assert_eq!(
            moved_error
                .to_string()
                .replace(&moved.display().to_string(), "<log>"),
            premove_error
                .to_string()
                .replace(&premove.display().to_string(), "<log>"),
            "{name}: the rendered errors differ"
        );
        assert!(
            moved_error
                .to_string()
                .contains(&moved.display().to_string()),
            "{name}: the error must name the log: {moved_error}"
        );
        assert!(
            moved_warnings.is_empty() && premove_warnings.is_empty(),
            "{name}: a failed open warns about nothing"
        );
        failed += 1;
    }

    assert!(
        failed >= 2,
        "at least two cells must really fail, or this grid compares two `Ok`s: \
         {failed} of {} (unexercisable here: {unexercisable:?})",
        cases.len()
    );
    assert_eq!(cases.len(), 4, "four failing-path shapes");
}

/// How many newline-terminated lines a seed carried.
fn committed_lines(seed: Option<&Vec<u8>>) -> usize {
    seed.map(|bytes| bytes.iter().filter(|byte| **byte == b'\n').count())
        .unwrap_or(0)
}

/// The `ts` value of every line after the first `skip`, as written.
///
/// Read out of the file rather than off the returned event, because the claim
/// is about the bytes a reader will see: `status` renders this field and
/// `export` copies it into attempt timestamps.
fn appended_timestamps(path: &Path, skip: usize) -> Vec<String> {
    let text = String::from_utf8(fs::read(path).expect("log")).expect("utf-8 log");
    text.lines()
        .skip(skip)
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("an appended line must parse: {error}: {line}"));
            value
                .get("ts")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("an appended line carries a ts: {line}"))
                .to_owned()
        })
        .collect()
}

/// The `ts` this writer stamps is the clock's answer, at both append sites.
///
/// The differential above compares two writers with `ts` normalised away, so it
/// is blind to a *shared* wrong answer and to a moved-writer-only one alike;
/// this asks the value directly. `PR5-CORRECTNESS-006` / `PR5-SEAMS-003` is
/// `event.ts = "1970-01-01T00:00:00Z"`, which every existing grid folded out.
///
/// Both legacy entry points, because they are two functions:
/// [`EventLog::append`] and [`EventLog::append_hooked`]. The schema-4 sites take
/// pre-round-tripped bytes and stamp nothing, so they are not in this class —
/// `the_topology_append_carries_the_callers_own_bytes` is what holds them.
#[test]
fn the_legacy_append_stamps_the_clocks_answer_at_every_entry_point() {
    let path = log_path("ts-value");
    let mut warnings = Vec::new();
    let mut log =
        EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("open the log");

    let before = crate::util::rfc3339_utc_now();
    let plain = log
        .append(EventSite::LegacyAppend, commit("0f5c1c4", "plain"))
        .expect("append");
    let hooked = log
        .append_hooked(
            EventSite::LegacyAppend,
            commit("deadbee", "hooked"),
            &mut NoEventHooks,
        )
        .expect("append_hooked");
    let after = crate::util::rfc3339_utc_now();

    // The epoch is not merely "an old time": it is the value a clock that
    // cannot be read yields, and this machine's clock can be read.
    assert_ne!(
        before, "1970-01-01T00:00:00Z",
        "this machine's clock reads as the epoch, so the assertion below proves nothing"
    );
    for (entry, event) in [("append", &plain), ("append_hooked", &hooked)] {
        assert!(
            event.ts >= before && event.ts <= after,
            "{entry}: returned ts `{}` is not a time this append could have \
             happened at ({before}..={after})",
            event.ts
        );
    }
    // And the same value reached the file, which is what `status` renders and
    // `export` copies.
    let written = appended_timestamps(&path, 0);
    assert_eq!(
        written,
        vec![plain.ts.clone(), hooked.ts.clone()],
        "the persisted ts is not the returned one"
    );
    for stamp in &written {
        assert!(
            stamp.as_str() >= before.as_str() && stamp.as_str() <= after.as_str(),
            "persisted ts `{stamp}` is outside ({before}..={after})"
        );
        assert_eq!(stamp.len(), "2026-08-21T00:00:00Z".len(), "the fixed shape");
    }
}

/// The event handed back is the event a replay of this log produces.
///
/// DESIGN.md:406: "it applies the event **as it will be read back** rather than
/// as constructed. A live run and a replay of its own log are therefore the same
/// computation." The oracle is [`crate::events::read_all`] — the reader, not
/// this writer — so `Ok(written)` -> `Ok(event)` cannot be green.
///
/// Both legacy entry points again, and the value is one the wire genuinely
/// cannot carry, so "returned" and "constructed" are different observations.
#[test]
fn the_legacy_append_returns_the_event_a_replay_of_this_log_yields() {
    let path = log_path("readback");
    let mut warnings = Vec::new();
    let mut log =
        EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("open the log");

    let constructed = lossy_duration_attempt();
    assert_eq!(
        duration_of(&constructed),
        LOSSY_CONSTRUCTED,
        "the fixture carries the sub-millisecond duration"
    );
    let returned = log
        .append(EventSite::LegacyAppend, constructed.clone())
        .expect("append");
    let returned_hooked = log
        .append_hooked(
            EventSite::LegacyAppend,
            constructed.clone(),
            &mut NoEventHooks,
        )
        .expect("append_hooked");

    let mut replay_warnings = Vec::new();
    let replayed = crate::events::read_all(&path, &mut replay_warnings).expect("replay this log");
    assert!(
        replay_warnings.is_empty(),
        "a clean log replays without warnings"
    );
    assert_eq!(replayed.len(), 2, "two appends, two events");
    for (entry, event) in [("append", &returned), ("append_hooked", &returned_hooked)] {
        assert_eq!(
            duration_of(&event.body),
            LOSSY_AS_READ_BACK,
            "{entry}: the constructed duration survived the append, so live state \
             holds more than a replay can restore"
        );
        assert_ne!(
            duration_of(&event.body),
            LOSSY_CONSTRUCTED,
            "{entry}: the returned event is the constructed one"
        );
    }
    for (index, event) in replayed.iter().enumerate() {
        let returned = if index == 0 {
            &returned
        } else {
            &returned_hooked
        };
        assert_eq!(
            event.body, returned.body,
            "line {index}: the replayed event differs from the returned one"
        );
        assert_eq!(&event.ts, &returned.ts, "line {index}: and so does its ts");
    }
}

/// Replace every `"ts":"…"` value with a constant. Deliberately narrow: only the
/// one field the two writers cannot agree on.
fn normalize_timestamps(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("\"ts\":\"") {
        let (before, after) = rest.split_at(start + "\"ts\":\"".len());
        out.push_str(before);
        let end = after.find('"').expect("a ts value is a closed string");
        out.push_str("<ts>");
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

#[test]
fn the_legacy_open_performs_none_of_the_syncs_the_pre_move_open_did_not() {
    // `EventSite::LegacyOpenLog.sub_effects()` is `&[]` in the frozen inventory.
    // A legacy open that acquired `SyncPrefix` would be a new way for a
    // schema-3 run to fail at open, which `production_effect` forbids.
    assert!(
        EventSite::LegacyOpenLog.sub_effects().is_empty(),
        "the frozen inventory gives the legacy open no points"
    );
    assert!(EventSite::LegacyAppend.sub_effects().is_empty());

    let path = log_path("legacy-no-sync");
    fs::write(&path, b"{\"a\":1}\ntorn").expect("seed");
    let mut witness = Witness::default();
    let mut warnings = Vec::new();
    let mut log =
        EventLog::open_hooked(EventSite::LegacyOpenLog, &path, &mut warnings, &mut witness)
            .expect("legacy open");
    log.append_hooked(EventSite::LegacyAppend, commit("a", "m"), &mut witness)
        .expect("legacy append");

    assert_eq!(warnings.len(), 1, "the torn tail is still warned about");
    assert!(
        witness.ledger.is_empty(),
        "the legacy path synced through the ledger: {:?}",
        witness.ledger
    );
    assert_eq!(
        witness
            .phases
            .iter()
            .filter(|(site, _)| *site == EventSite::LegacyOpenLog)
            .count(),
        2,
        "both hook phases still exist for the legacy open"
    );
}

// ---------------------------------------------------------------------------
// The append's own durability trace
// ---------------------------------------------------------------------------

/// One `write_all` of the whole line, then a `flush`, then a `sync_data`
/// (`PR5-EVENTS-049`, `PR5-EVENTS-051`).
///
/// `production_effect`: "the event-log writer keeps its **exact**
/// write/flush/sync and torn-tail truncation semantics". Until the ledger
/// covered the append path, none of the three was an observable: splitting the
/// line's `write_all` into the JSON and then its LF commit marker, and deleting
/// the `flush` outright, both left the whole suite green. The only guard that
/// touched either was a *source census* asserting the literal
/// `self.file.write_all(` appears once in the module — which constrains where
/// the call is spelled, not how many times it runs, and the split reused the
/// one call site.
///
/// The byte count is asserted, not just the number of calls: one `write_all`
/// carrying half the line and a second carrying the rest would otherwise read
/// as "one write" on the count alone.
#[test]
fn an_append_writes_the_whole_line_once_then_flushes_then_syncs() {
    let path = log_path("append-trace");
    let mut warnings = Vec::new();
    let mut witness = Witness::default().recording_durability();
    let mut log = EventLog::open_hooked(EventSite::OpenLog, &path, &mut warnings, &mut witness)
        .expect("open");
    let before = witness.durability.records().len();

    log.append_topology_hooked(EventSite::Append, &topology_line(1), &mut witness)
        .expect("append");

    let all = witness.durability.records();
    let appended: Vec<_> = all[before..].to_vec();
    assert_eq!(
        appended
            .iter()
            .map(|record| record.step)
            .collect::<Vec<_>>(),
        vec![
            DurableStep::Wrote,
            DurableStep::Flushed,
            DurableStep::SyncedData
        ],
        "the append's exact primitive sequence: {appended:?}"
    );
    let on_disk = fs::read(&path).expect("log");
    assert_eq!(
        appended[0].len,
        on_disk.len() as u64,
        "the one write carried the whole line, its LF commit marker included"
    );
    assert_eq!(
        on_disk.last(),
        Some(&b'\n'),
        "and the line the count is measured against really is complete"
    );
    assert_eq!(
        appended[2].len,
        on_disk.len() as u64,
        "and the sync made all of it durable"
    );
}

/// Both `Synced` consults happen **after** `sync_data`, which is the whole
/// content of the coordinate (`PR5-EVENTS-032`, `PR5-EVENTS-035`).
///
/// `transaction_fault_matrix[16]` defines `(e-s)` as "sync_data returned an
/// error **after the data reached the disk** (indistinguishable from (e-u) to
/// the process)". An injector that short-circuits and returns the injected
/// `Err` *before* `sync_data` runs produces an `(e-u)` under an `(e-s)` label,
/// and the tabled-shape test could not tell: `leaves_complete_line: true` holds
/// either way, because the line was written and flushed before the sync. The
/// kill coordinate has the same problem in the other direction, and worse — a
/// kill is `abort`, so no in-process test can observe its aftermath at all.
///
/// What separates them is what was already durable *at the moment the funnel
/// asked*, so that is what is read.
#[test]
fn the_synced_consults_are_offered_after_the_data_is_durable() {
    let path = log_path("synced-coordinate");
    let mut warnings = Vec::new();
    let mut witness = Witness::default().recording_durability();
    let mut log = EventLog::open_hooked(EventSite::OpenLog, &path, &mut warnings, &mut witness)
        .expect("open");
    // The open's own barrier is not this append's trace: both are cleared so
    // every step read below was performed by the append.
    witness.at_consult.clear();
    witness.durability.clear();
    log.append_topology_hooked(EventSite::Append, &topology_line(1), &mut witness)
        .expect("append");

    for mode in InjectionMode::ALL {
        let (_, _, at) = witness
            .at_consult
            .iter()
            .find(|(point, offered, _)| *point == SubEffectPoint::Synced && offered == mode)
            .unwrap_or_else(|| panic!("Synced/{mode:?} was never offered at all"));
        assert!(
            at.contains(&DurableStep::SyncedData),
            "Synced/{mode:?} was offered before the append's own sync_data ran, so a fault \
             injected there stands in place of the sync rather than following it: {at:?}"
        );
        assert_eq!(
            at.last(),
            Some(&DurableStep::SyncedData),
            "Synced/{mode:?} is offered immediately after the sync and not later: {at:?}"
        );
    }

    // And the earlier coordinates are on their own side of it, so the assertion
    // above is about this point rather than about the end of the append.
    let written = witness
        .at_consult
        .iter()
        .find(|(point, mode, _)| {
            *point == SubEffectPoint::Written && *mode == InjectionMode::ErrorReturn
        })
        .map(|(_, _, at)| at.clone())
        .expect("Written/ErrorReturn is offered");
    assert!(
        written.is_empty(),
        "the partial-write coordinate is offered before anything is written: {written:?}"
    );
}

/// A **real** primitive failure is attempted once and never retried
/// (`PR5-EVENTS-044`).
///
/// `invariants[1]`: "an append that was entered and returned an error never
/// mutates the live fold, **is never retried**, and is never resolved from
/// memory". Every append failure the suite could previously build was an
/// *injected* one, delivered by the hook harness at a coordinate rather than by
/// the file — so the retry branch was never entered and "exactly one primitive
/// attempt" was true by construction of the injector, saying nothing about a
/// real one.
///
/// `/dev/full` is a real one: it opens, it reads as empty, and every write to it
/// returns `ENOSPC`. Linux only, and named rather than skipped elsewhere — this
/// is the one place in the lane where the primitive itself fails.
#[cfg(target_os = "linux")]
#[test]
fn a_real_write_failure_is_attempted_once_poisons_the_handle_and_is_not_retried() {
    assert!(
        Path::new("/dev/full").exists(),
        "this host has no always-failing device, so nothing here is measured"
    );
    let dir = scratch("real-enospc");
    let path = dir.join("events.jsonl");
    std::os::unix::fs::symlink("/dev/full", &path).expect("symlink");

    let mut warnings = Vec::new();
    let mut witness = Witness::default().recording_durability();
    // The **legacy** open, which takes no barrier: `fsync` on a character
    // device is `EINVAL`, so `Event.OpenLog`'s prefix sync cannot be performed
    // against one. The claim under test is `write_or_poison`'s, which both
    // append paths share, and the legacy site reaches it without needing a
    // device that can be fsynced.
    let mut log =
        EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("the device opens");
    let before = witness.durability.records().len();

    let error = log
        .append_hooked(EventSite::LegacyAppend, commit("a", "first"), &mut witness)
        .expect_err("every write to /dev/full returns ENOSPC");
    assert!(
        matches!(error, TactusError::Io { .. }),
        "a real failure keeps the exact error the pre-move writer returned: {error}"
    );

    let recorded = witness.durability.records();
    let attempts: Vec<_> = recorded[before..]
        .iter()
        .filter(|record| record.step == DurableStep::Wrote)
        .collect();
    assert_eq!(
        attempts.len(),
        1,
        "one primitive attempt and one error, never a retry: {attempts:?}"
    );
    assert!(
        !witness
            .durability
            .steps()
            .contains(&DurableStep::SyncedData),
        "and nothing past the failed write ran"
    );
    assert_eq!(
        log.poisoned_at(),
        Some(SubEffectPoint::Written),
        "the handle is poisoned at the point the real failure reached"
    );
    assert_eq!(
        log.poisoned_site(),
        Some(EventSite::LegacyAppend),
        "and names the site the failing append was made at"
    );
    let later = log
        .append_hooked(EventSite::LegacyAppend, commit("b", "second"), &mut witness)
        .expect_err("a poisoned handle refuses");
    assert!(
        later.to_string().contains(POISONED_PREFIX),
        "the refusal is the poison, not a second attempt: {later}"
    );
    let after_refusal = witness.durability.records();
    assert_eq!(
        after_refusal[before..]
            .iter()
            .filter(|record| record.step == DurableStep::Wrote)
            .count(),
        1,
        "and the refusal reached no primitive"
    );
}

// ---------------------------------------------------------------------------
// Event.OpenLog
// ---------------------------------------------------------------------------

/// The prefix sync **follows** the truncation and records the **shortened**
/// length (`PR5-EVENTS-011`, `PR5-EVENTS-013`).
///
/// The lane had both axes and never crossed them. The test that compares a
/// synced length against the filesystem deliberately seeds a *complete*
/// unsynced line — "and nothing was truncated: the line was complete" is its
/// own closing assertion — and the test that seeds a torn tail reads only
/// points, never a length. So syncing the *pre*-normalized length and
/// truncating afterwards satisfied both: one had no truncation to get wrong,
/// the other never read the number that would have been wrong.
#[test]
fn open_truncates_the_torn_tail_before_it_syncs_and_syncs_the_shortened_length() {
    let path = log_path("truncate-then-sync");
    let complete = b"{\"a\":1}\n".len() as u64;
    fs::write(&path, b"{\"a\":1}\nthis tail was never finished").expect("seed");
    let full = fs::metadata(&path).expect("metadata").len();
    assert!(full > complete, "the fixture really is torn");

    let mut warnings = Vec::new();
    let mut witness = Witness::default().recording_durability();
    let _log = EventLog::open_hooked(EventSite::OpenLog, &path, &mut warnings, &mut witness)
        .expect("reopen");

    let records = witness.durability.records();
    // One expectation for every platform (`PR5-CONF-013`). This used to fork on
    // `cfg!(unix)` because there was no directory fsync on Windows; `scope`'s
    // "file **and directory** after a truncation" carries no platform
    // exception, and `util::fsync_dir` now performs it on both.
    let expected: Vec<DurableStep> = vec![
        DurableStep::Truncated,
        DurableStep::SyncedFile,
        DurableStep::SyncedDirectory,
    ];
    assert_eq!(
        witness.steps(),
        expected,
        "truncate, then sync the surviving prefix, then its directory: {records:?}"
    );
    for record in &records {
        assert_eq!(
            record.len, complete,
            "every step of the barrier is about the SHORTENED length ({complete}), not the \
             pre-normalized {full}: {record:?}"
        );
    }
    assert_eq!(
        fs::metadata(&path).expect("metadata").len(),
        complete,
        "and the file itself agrees with the ledger"
    );
}

#[test]
fn open_syncs_the_surviving_prefix_and_the_ledger_agrees_with_the_filesystem() {
    let path = log_path("sync-prefix");

    // A line written by an earlier handle and never synced — the case
    // `proof_tests[9]` names explicitly. `WrittenFull`'s error-return leaves
    // exactly that shape: the full newline-terminated line, no flush, no sync.
    let mut warnings = Vec::new();
    let mut first = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("create");
    let mut unsynced = FailAt::error(SubEffectPoint::WrittenFull);
    first
        .append_topology_hooked(EventSite::Append, &topology_line(1), &mut unsynced)
        .expect_err("the append returns at WrittenFull");
    drop(first);

    let on_disk = fs::read(&path).expect("log");
    assert!(!on_disk.is_empty(), "the unsynced line is in the file");
    assert_eq!(on_disk.last(), Some(&b'\n'), "and it is complete");

    let mut witness = Witness::default();
    let mut warnings = Vec::new();
    let _log = EventLog::open_hooked(EventSite::OpenLog, &path, &mut warnings, &mut witness)
        .expect("reopen");

    let length = fs::metadata(&path).expect("metadata").len();
    assert_eq!(
        witness.file_syncs(),
        vec![length],
        "one file sync, of the whole surviving prefix; the filesystem says {length}"
    );
    assert_eq!(
        length,
        on_disk.len() as u64,
        "and nothing was truncated: the line was complete"
    );
}

#[test]
fn open_fsyncs_the_directory_when_it_creates_the_log_and_after_a_truncation() {
    // One expectation for every platform (`PR5-CONF-013`). This used to be
    // `if cfg!(unix) { 1 } else { 0 }`, because `File::open` on a directory needs
    // `FILE_FLAG_BACKUP_SEMANTICS` and std does not expose it — true of std, and
    // the reason `util::fsync_dir` calls `CreateFileW` there instead. `scope`'s
    // "directory fsync" and "file **and directory** after a truncation" carry no
    // platform exception, so neither does this.
    let expected_directory_syncs = 1;

    let created = log_path("dir-fsync-create");
    let mut witness = Witness::default();
    let mut warnings = Vec::new();
    EventLog::open_hooked(EventSite::OpenLog, &created, &mut warnings, &mut witness)
        .expect("create");
    assert_eq!(
        witness.directory_syncs().len(),
        expected_directory_syncs,
        "creating the log fsyncs its directory on this platform"
    );
    assert_eq!(witness.directory_syncs(), vec![SubEffectPoint::Create]);

    let torn = log_path("dir-fsync-truncate");
    fs::write(&torn, b"{\"a\":1}\nhalf").expect("seed");
    let mut witness = Witness::default();
    let mut warnings = Vec::new();
    EventLog::open_hooked(EventSite::OpenLog, &torn, &mut warnings, &mut witness).expect("reopen");
    assert_eq!(
        witness.directory_syncs().len(),
        expected_directory_syncs,
        "a truncation changed the length, so the directory is synced too"
    );
    assert_eq!(witness.directory_syncs(), vec![SubEffectPoint::SyncPrefix]);

    // An untouched existing log syncs the file and nothing else: the directory
    // entry did not move.
    let untouched = log_path("dir-fsync-untouched");
    fs::write(&untouched, b"{\"a\":1}\n").expect("seed");
    let mut witness = Witness::default();
    let mut warnings = Vec::new();
    EventLog::open_hooked(EventSite::OpenLog, &untouched, &mut warnings, &mut witness)
        .expect("reopen");
    assert!(
        witness.directory_syncs().is_empty(),
        "nothing changed the directory, so nothing syncs it"
    );
    assert_eq!(witness.file_syncs().len(), 1);
}

#[test]
fn a_torn_tail_is_truncated_on_open_with_a_warning_at_both_open_sites() {
    for site in [EventSite::OpenLog, EventSite::LegacyOpenLog] {
        let path = log_path(&format!("torn-{}", site.name()));
        fs::write(&path, b"{\"a\":1}\n{\"b\":2 unfinished").expect("seed");
        let mut warnings = Vec::new();
        let log = EventLog::open(site, &path, &mut warnings).expect("open");
        assert_eq!(fs::read(&path).expect("log"), b"{\"a\":1}\n");
        assert_eq!(warnings.len(), 1, "one warning at {}", site.name());
        assert!(
            warnings[0].contains("discarded 17 trailing byte(s)"),
            "the warning counts the bytes: {}",
            warnings[0]
        );
        assert_eq!(log.opened_at(), site);
    }
}

#[test]
fn an_injected_sync_failure_at_open_names_syncprefix_and_hands_out_no_handle() {
    let path = log_path("sync-fails");
    fs::write(&path, b"{\"a\":1}\n").expect("seed");
    let mut failing = FailAt::error(SubEffectPoint::SyncPrefix);
    let mut warnings = Vec::new();

    let refused = EventLog::open_hooked(EventSite::OpenLog, &path, &mut warnings, &mut failing)
        .expect_err("a SyncPrefix error refuses the open");
    assert!(
        refused
            .to_string()
            .contains(SubEffectPoint::SyncPrefix.name()),
        "the error names the point: {refused}"
    );
    assert!(
        refused.to_string().contains(INJECTED_PREFIX),
        "and says it was simulated: {refused}"
    );
    assert_eq!(failing.fired, 1, "the coordinate fired exactly once");
    assert!(
        failing.ledger.is_empty(),
        "the coordinate is before the sync, so nothing was made durable"
    );

    // The barrier reports the same failure as its own step.
    let mut failing = FailAt::error(SubEffectPoint::SyncPrefix);
    let error = establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut failing)
        .expect_err("the barrier does not hold");
    assert_eq!(error.step, BarrierStep::SyncPrefix);
    assert!(
        error.to_string().contains("Event.OpenLog.SyncPrefix"),
        "the barrier error names the step: {error}"
    );
}

#[test]
fn every_open_point_is_offered_in_every_mode_the_frozen_inventory_declares() {
    // Derived from the type, not from a list: `sub_effects()` x `modes()`.
    let points = EventSite::OpenLog.sub_effects();
    assert_eq!(
        points,
        &[
            SubEffectPoint::Create,
            SubEffectPoint::TruncateTornTail,
            SubEffectPoint::SyncPrefix
        ],
        "the frozen inventory's three open points, in its order"
    );

    // `Create` needs an absent log; `TruncateTornTail` needs a torn one. One
    // open cannot be both, so both are run and the offers are unioned.
    let mut offered = Vec::new();
    for (tag, seed) in [
        ("create", None),
        ("truncate", Some(b"{\"a\":1}\nhalf".to_vec())),
    ] {
        let path = log_path(&format!("offers-{tag}"));
        if let Some(seed) = seed {
            fs::write(&path, seed).expect("seed");
        }
        let mut witness = Witness::default();
        let mut warnings = Vec::new();
        EventLog::open_hooked(EventSite::OpenLog, &path, &mut warnings, &mut witness)
            .expect("open");
        offered.extend(witness.offered.iter().copied());
    }

    for point in points {
        for mode in point.modes() {
            assert!(
                offered
                    .iter()
                    .any(|(site, offered, offered_mode)| *site == EventSite::OpenLog
                        && offered == point
                        && offered_mode == mode),
                "`Event.OpenLog` never offered `{point}` in {mode:?} mode"
            );
        }
    }
    assert_eq!(
        offered.len(),
        // Create x 2 modes + SyncPrefix x 2 (first open), TruncateTornTail x 2 +
        // SyncPrefix x 2 (second open).
        8,
        "and offered nothing else: {offered:?}"
    );
}

// ---------------------------------------------------------------------------
// The error contract
// ---------------------------------------------------------------------------

/// The three error-return cases `T-APPEND` names, with the durable shape each
/// leaves. Written from the packet's own words, not from the funnel's code.
///
/// * (e-w) `Written` — "write_all failed after a partial write" → a torn tail.
/// * (e-u) `WrittenFull` — "write_all succeeded (full line, newline present)
///   and flush … returned an error" → the complete line.
/// * (e-s) `Synced` — "sync_data returned an error after the data reached the
///   disk" → the complete line.
const ERROR_RETURN_CASES: &[(SubEffectPoint, bool)] = &[
    (SubEffectPoint::Written, false),
    (SubEffectPoint::WrittenFull, true),
    (SubEffectPoint::Synced, true),
];

#[test]
fn every_error_return_case_leaves_its_tabled_shape_names_its_point_and_poisons_the_handle() {
    assert_eq!(
        ERROR_RETURN_CASES.len(),
        3,
        "three cases, and `fault_injection_registry.structure` names three"
    );
    // Two distinct durable shapes across the three cases: a grid that produced
    // one shape three times would be satisfied by the wrong thing.
    assert_eq!(
        ERROR_RETURN_CASES
            .iter()
            .map(|(_, complete)| *complete)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );

    // Every append site of the group, not the one that was looked at: the
    // contract names `AppendFirst`, `Append` and `AppendInformational`
    // separately, and the legacy site is a fourth behaviour again.
    let mut sites: Vec<(EventSite, Option<TopologyLine>)> = append_site_lines()
        .into_iter()
        .map(|(site, line)| (site, Some(line)))
        .collect();
    sites.push((EventSite::LegacyAppend, None));
    assert_eq!(
        sites.len(),
        4,
        "three schema-4 append sites and the legacy one"
    );

    for (case, (point, leaves_complete_line)) in ERROR_RETURN_CASES.iter().enumerate() {
        for (index, (site, line)) in sites.iter().enumerate() {
            let site = *site;
            // **The scratch name carries no point and no site**
            // (`PR5-EVENTS-045`). It used to be `err-<point>-<site>`, and
            // `TactusError::EventLog`'s Display renders its path — so
            // `error.to_string().contains(point.name())` was satisfied by the
            // *directory name* whatever the message said, and a funnel that
            // reported a `Synced` injection as `Written` passed this grid.
            // Verified by running it under exactly that mutation.
            let path = log_path(&format!("err-{case}-{index}"));
            let open_site = if site == EventSite::LegacyAppend {
                EventSite::LegacyOpenLog
            } else {
                EventSite::OpenLog
            };
            let mut warnings = Vec::new();
            let mut log = EventLog::open(open_site, &path, &mut warnings).expect("open");

            let mut failing = FailAt::error(*point);
            let error = match line {
                None => log
                    .append_hooked(site, commit("a", "first"), &mut failing)
                    .expect_err("the append returns Err"),
                Some(line) => log
                    .append_topology_hooked(site, line, &mut failing)
                    .expect_err("the append returns Err"),
            };

            // On the **message**, not on `to_string()`: the rendering adds the
            // path, and a path is not something the funnel decided to say.
            //
            // And on the *quoted* name, because `Written` is a prefix of
            // `WrittenFull`: a bare `contains` cannot tell the two points
            // apart, and they are the two the packet most needs kept apart —
            // one is a torn tail the next open truncates, the other a complete
            // unsynced prefix the barrier makes durable.
            let quoted = |point: &SubEffectPoint| format!("`{}`", point.name());
            assert!(
                event_log_message(&error).contains(&quoted(point)),
                "`{}` must name its point: {error}",
                point.name()
            );
            for other in ERROR_RETURN_CASES.iter().map(|(other, _)| other) {
                assert_eq!(
                    event_log_message(&error).contains(&quoted(other)),
                    other == point,
                    "the message names exactly the injected point and no other: {error}"
                );
            }
            assert_eq!(
                log.poisoned_at(),
                Some(*point),
                "`{}` must poison the handle at its own point",
                point.name()
            );
            assert_eq!(
                log.poisoned_site(),
                Some(site),
                "and at the site the append was made at"
            );

            let durable = fs::read(&path).expect("log");
            assert!(!durable.is_empty(), "something was written");
            assert_eq!(
                durable.last() == Some(&b'\n'),
                *leaves_complete_line,
                "`{}` left the wrong durable shape: {:?}",
                point.name(),
                String::from_utf8_lossy(&durable)
            );

            // **Every** later append through this handle fails, naming the
            // poisoning coordinate — the first, the second and the third
            // (`PR5-EVENTS-042`). `scope` is "every later append fails until
            // the log is reopened through `Event.OpenLog`", and one attempt is
            // all a poison that *clears itself on read* has to produce: with
            // `check_poison` reading through `take()`, the handle silently
            // became usable again from the second attempt on and this grid
            // stayed green.
            for attempt in 1..=3 {
                let later = match line {
                    None => log
                        .append(site, commit("b", "second"))
                        .expect_err("a poisoned handle refuses"),
                    Some(line) => log
                        .append_topology(site, line)
                        .expect_err("a poisoned handle refuses"),
                };
                assert!(
                    event_log_message(&later).contains(POISONED_PREFIX)
                        && event_log_message(&later).contains(&quoted(point)),
                    "attempt {attempt}: the refusal names the poisoning point: {later}"
                );
                assert!(
                    event_log_message(&later).contains(&format!("`Event.{}`", site.name())),
                    "attempt {attempt}: and the site it was poisoned at: {later}"
                );
                assert_eq!(
                    log.poisoned_at(),
                    Some(*point),
                    "attempt {attempt}: the poison is still there afterwards"
                );
                assert_eq!(
                    fs::read(&path).expect("log"),
                    durable,
                    "attempt {attempt}: and appended nothing"
                );
            }
        }
    }
}

/// A handle poisoned at **one** site refuses a later append at **another**, and
/// still names the site it was poisoned at (`SUPP-EVENTS-046-site`).
///
/// The grid above drives 4 sites × 3 points × 3 later attempts, and in every one
/// of those 36 cells the later attempt is made at *the same binding* the
/// poisoning append used. So "the stored site" and "the newly attempted site"
/// are the same string everywhere, and `assert!(message.contains("`Event.<site>`"))`
/// is satisfied identically by a `check_poison` that names either. Repair round
/// 2 widened `EventLog::poisoned` from `SubEffectPoint` to `(EventSite,
/// SubEffectPoint)` precisely so the refusal names both — and the grid catches
/// the **point** half only. Measured: `self.poisoned.map(|(_, point)|
/// (attempted, point))` survived the whole suite at 1128 / 0 / 21, byte for byte
/// the baseline.
///
/// This is the fourth time this slice has met the same shape —
/// `PR5-WORKSPACE-036`, `correlation-never-broken`, the poisoned-handle grid,
/// and this — so it is worth naming plainly: **two axes covered separately,
/// their intersection never built**. Coverage on each axis reads as coverage of
/// the pair, and the mutation that varies only the un-crossed field survives.
///
/// Here the second field is the **site**, and what varies it is that a schema-4
/// handle accepts three append sites onto one `EventLog` — `AppendFirst`,
/// `Append` and `AppendInformational` — which is the whole reason round 2 said
/// "half an identification on a handle that accepts three append sites". Held
/// constant: the point, at `Written`, so the point half cannot be what fails.
/// A legacy handle cannot build this shape at all (`check_scope` admits only
/// `LegacyAppend`), which is why it took a schema-4 fixture.
#[test]
fn a_handle_poisoned_at_one_site_names_that_site_when_refused_at_another() {
    let lines = append_site_lines();
    assert!(
        lines.len() >= 2,
        "this test needs two distinct append sites on one handle"
    );

    // Every ordered pair of distinct sites, so no single pairing can be the one
    // that happens to agree.
    for (poison_at, poison_line) in &lines {
        for (attempt_at, attempt_line) in &lines {
            if poison_at == attempt_at {
                continue;
            }
            let path = log_path(&format!(
                "crossed-{}-{}",
                poison_at.name(),
                attempt_at.name()
            ));
            let mut warnings = Vec::new();
            let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");

            let mut failing = FailAt::error(SubEffectPoint::Written);
            log.append_topology_hooked(*poison_at, poison_line, &mut failing)
                .expect_err("the append returns Err");
            assert_eq!(
                log.poisoned_site(),
                Some(*poison_at),
                "the handle records the site it was poisoned at"
            );

            let refused = log
                .append_topology(*attempt_at, attempt_line)
                .expect_err("a poisoned handle refuses");
            let message = event_log_message(&refused);
            assert!(
                message.contains(&format!("`Event.{}`", poison_at.name())),
                "the refusal must name the site the handle was POISONED at \
                 (`Event.{}`), not the one now being attempted: {refused}",
                poison_at.name()
            );
            assert!(
                !message.contains(&format!("`Event.{}`", attempt_at.name())),
                "…and must not name `Event.{}`, which is where the outcome did NOT \
                 become unknown: {refused}",
                attempt_at.name()
            );
            assert!(
                message.contains("`Written`"),
                "the point half is held constant here and must still be named: {refused}"
            );
        }
    }
}

#[test]
fn a_value_the_wire_cannot_carry_does_not_enter_the_append_and_does_not_poison() {
    // `emit`'s contract is "a FoldError aborts before any write", and the
    // packet's poisoning rule is about an `Err` "after the append **was
    // entered**". A handle poisoned by a value that never reached the file
    // would refuse the next, perfectly good, event.
    let path = log_path("unserializable");
    let mut warnings = Vec::new();
    let mut log = EventLog::open(EventSite::LegacyOpenLog, &path, &mut warnings).expect("open");

    let refused = log
        .append(EventSite::LegacyAppend, unserializable())
        .expect_err("a NaN does not survive JSON");
    // `serde_json` writes a non-finite float as `null` rather than refusing, so
    // the guard that catches it is the round-trip — which is precisely the step
    // `emit` names ("serialize -> round-trip -> plan_transition -> append").
    assert!(
        refused
            .to_string()
            .contains("budget_exceeded does not survive its own wire format"),
        "{refused}"
    );
    assert_eq!(
        fs::read(&path).expect("log").len(),
        0,
        "nothing was written"
    );
    assert_eq!(log.poisoned_at(), None, "and the handle is still usable");

    log.append(EventSite::LegacyAppend, commit("a", "m"))
        .expect("the next append still works");
    assert!(fs::read(&path).expect("log").ends_with(b"\n"));
}

#[test]
fn reopening_through_openlog_is_what_clears_a_poisoning() {
    let path = log_path("reopen-clears");
    let mut warnings = Vec::new();
    let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");
    let mut failing = FailAt::error(SubEffectPoint::Synced);
    log.append_topology_hooked(EventSite::Append, &topology_line(1), &mut failing)
        .expect_err("Err at Synced");
    assert_eq!(log.poisoned_at(), Some(SubEffectPoint::Synced));
    drop(log);

    let mut reopened = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("reopen");
    assert_eq!(reopened.poisoned_at(), None, "the reopen is the clearing");
    reopened
        .append_topology(EventSite::Append, &topology_line(2))
        .expect("and the handle works");
    assert_eq!(
        fs::read(&path)
            .expect("log")
            .iter()
            .filter(|b| **b == b'\n')
            .count(),
        2,
        "the errored line was durable and the new one is beside it"
    );
}

#[test]
fn every_append_point_is_offered_in_every_mode_the_frozen_inventory_declares() {
    let points = EventSite::Append.sub_effects();
    assert_eq!(
        points,
        &[
            SubEffectPoint::Written,
            SubEffectPoint::WrittenFull,
            SubEffectPoint::Synced
        ],
        "the frozen inventory's three append points, in its order"
    );

    // All three sites declare the same points, and all three are driven. A
    // suppression keyed on one site — `if site == EventSite::Append` around the
    // consults — is the `PR4-CONF-002` defect, and it passes a grid that drives
    // only the site somebody happened to look at.
    for (site, line) in append_site_lines() {
        assert_eq!(
            site.sub_effects(),
            points,
            "`{}` declares different points from `Event.Append`",
            site.name()
        );
        let path = log_path(&format!("append-offers-{}", site.name()));
        let mut warnings = Vec::new();
        let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");
        let mut witness = Witness::default();
        log.append_topology_hooked(site, &line, &mut witness)
            .expect("append");

        for point in points {
            for mode in point.modes() {
                assert!(
                    witness.offered_at(*point, *mode),
                    "`Event.{}` never offered `{point}` in {mode:?} mode",
                    site.name()
                );
            }
        }
        assert!(
            witness
                .offered
                .iter()
                .all(|(offered_site, _, _)| *offered_site == site),
            "`Event.{}` offered a coordinate under another site's name: {:?}",
            site.name(),
            witness.offered
        );
        assert_eq!(
            witness.offered.len(),
            // Written x 2, WrittenFull x 1 (error-return only), Synced x 2.
            5,
            "`Event.{}` offered something else: {:?}",
            site.name(),
            witness.offered
        );
        assert!(
            !witness.offered_at(SubEffectPoint::WrittenFull, InjectionMode::Kill),
            "`WrittenFull` declares no kill mode; offering one would manufacture a \
             coverage obligation the design does not make"
        );
        assert_eq!(
            witness
                .phases
                .iter()
                .filter(|(phase_site, _)| *phase_site == site)
                .count(),
            2,
            "`Event.{}`: both hook phases",
            site.name()
        );
        assert!(
            fs::read(&path).expect("log").ends_with(b"\n"),
            "`Event.{}` committed its line",
            site.name()
        );
    }
}

#[test]
fn the_written_kill_shape_moves_where_a_kill_lands_and_not_what_is_durable() {
    // The observer that asks for the torn coordinate must not change the file a
    // successful append leaves, or every ST-07 kill measurement would be taken
    // against a writer production does not have.
    let mut bytes = Vec::new();
    for (tag, shape) in [("complete", false), ("torn", true)] {
        let path = log_path(&format!("kill-shape-{tag}"));
        let mut warnings = Vec::new();
        let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");
        if shape {
            log.append_topology_hooked(EventSite::Append, &topology_line(7), &mut TornWriter)
                .expect("append");
        } else {
            log.append_topology(EventSite::Append, &topology_line(7))
                .expect("append");
        }
        bytes.push(fs::read(&path).expect("log"));
    }
    assert_eq!(bytes[0], bytes[1], "the durable result is the same");
    assert_eq!(bytes[0].last(), Some(&b'\n'));
    assert_eq!(
        NoEventHooks.written_kill_shape(EventSite::Append),
        WrittenShape::Complete,
        "production asks for one write_all, which is what the pre-move writer did"
    );
}

// ---------------------------------------------------------------------------
// Kill injection
// ---------------------------------------------------------------------------

/// Answers `Kill` at exactly one coordinate, and asks for one of the two
/// durable shapes `Written`'s kill entry tables.
#[derive(Debug)]
struct KillAt {
    point: SubEffectPoint,
    shape: WrittenShape,
}

impl EventHooks for KillAt {
    fn point(&mut self, _site: EventSite, point: SubEffectPoint, mode: InjectionMode) -> Injection {
        if point == self.point && mode == InjectionMode::Kill {
            Injection::Kill
        } else {
            Injection::Proceed
        }
    }

    fn written_kill_shape(&mut self, _site: EventSite) -> WrittenShape {
        self.shape
    }
}

/// Every kill coordinate the frozen inventory gives this funnel, by the name
/// the parent passes down.
///
/// Transcribed from `fault_injection_registry.structure`: "Event sites carry
/// kill entries for `Written` (torn …; complete-unsynced …) and `Synced` …, and
/// `Event.OpenLog` carries `Create`, `TruncateTornTail`, and `SyncPrefix`
/// entries (`SyncPrefix` in kill and error-return modes …)". Six cells over five
/// points, because `Written`'s one kill entry tables two durable shapes.
const KILL_CASES: &[(&str, SubEffectPoint, WrittenShape)] = &[
    // "create the log if absent and fsync its directory"
    ("create", SubEffectPoint::Create, WrittenShape::Complete),
    // "an unterminated final line was truncated before the append handle"
    (
        "truncate-torn-tail",
        SubEffectPoint::TruncateTornTail,
        WrittenShape::Complete,
    ),
    // "a kill before it … leaves the prefix possibly non-durable … and the next
    // open repeats the barrier"
    (
        "sync-prefix",
        SubEffectPoint::SyncPrefix,
        WrittenShape::Complete,
    ),
    // "torn: truncated on the next open, previous prefix"
    ("written-torn", SubEffectPoint::Written, WrittenShape::Torn),
    // "complete-unsynced: either prefix"
    (
        "written-complete",
        SubEffectPoint::Written,
        WrittenShape::Complete,
    ),
    // The synced line. Same bytes as the complete-unsynced one, deliberately.
    ("synced", SubEffectPoint::Synced, WrittenShape::Complete),
];

/// The kill coordinates the frozen inventory declares, derived from the types.
///
/// `EventSite::ALL` x `sub_effects()` x `modes()`, keeping the points that
/// declare `Kill`. A point added to the inventory later is uncovered loudly.
fn declared_kill_points() -> BTreeSet<SubEffectPoint> {
    EventSite::ALL
        .iter()
        .flat_map(|site| site.sub_effects())
        .filter(|point| point.modes().contains(&InjectionMode::Kill))
        .copied()
        .collect()
}

/// Run the helper for one case and hand back what the killed process left.
fn kill_at(case: &str, point: SubEffectPoint, path: &Path) -> Vec<u8> {
    // The harness names a test by its module path without the crate, so the
    // filter is derived rather than written out: a module that moves takes
    // this with it instead of silently matching nothing.
    let helper = format!(
        "{}::event_funnel_kill_helper",
        module_path!()
            .split_once("::")
            .expect("this module is not the crate root")
            .1
    );
    let output = std::process::Command::new(std::env::current_exe().expect("the test executable"))
        .args([helper.as_str(), "--ignored", "--exact"])
        .env(KILL_CASE_ENV, case)
        .env(KILL_LOG_ENV, path)
        .output()
        .unwrap_or_else(|error| panic!("{case}: spawning the helper: {error}"));

    assert!(
        !output.status.success(),
        "{case}: the helper exited cleanly, so the kill at `{}` never fired",
        point.name()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked at"),
        "{case}: the helper panicked rather than aborting, so what is on disk is not what a kill \
         leaves:\n{stderr}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGABRT),
            "{case}: a kill is an abort, and this child died some other way"
        );
    }
    #[cfg(not(unix))]
    {
        assert_ne!(
            output.status.code(),
            Some(101),
            "{case}: 101 is the harness's panic status, not an abort"
        );
    }
    fs::read(path).expect("the log the killed process left")
}

const KILL_CASE_ENV: &str = "TACTUS_EVENT_FUNNEL_KILL";
const KILL_LOG_ENV: &str = "TACTUS_EVENT_FUNNEL_KILL_LOG";

/// The child half of the kill tests.
///
/// A kill is `std::process::abort` for the reason [`crate::agent::proc`] gives:
/// the claim under test is what a process that dies **without running any
/// cleanup** leaves durable, and both `panic!` and `exit` run destructors.
#[test]
#[ignore = "subprocess helper"]
fn event_funnel_kill_helper() {
    let Ok(case) = std::env::var(KILL_CASE_ENV) else {
        return;
    };
    let path = PathBuf::from(std::env::var_os(KILL_LOG_ENV).expect("the parent names the log"));
    let (_, point, shape) = KILL_CASES
        .iter()
        .find(|(name, _, _)| *name == case)
        .unwrap_or_else(|| panic!("the parent named a case this helper does not have: {case}"));

    let mut warnings = Vec::new();
    let mut kill = KillAt {
        point: *point,
        shape: *shape,
    };
    if EventSite::OpenLog.sub_effects().contains(point) {
        // The three open points fire inside `Event.OpenLog` itself; there is no
        // append in these cases and no handle to append through.
        let _ = EventLog::open_hooked(EventSite::OpenLog, &path, &mut warnings, &mut kill);
    } else {
        let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");
        let _ = log.append_topology_hooked(EventSite::Append, &topology_line(1), &mut kill);
    }
    // Reached only if the kill did not fire, which the parent detects as a
    // successful exit.
    std::process::exit(0);
}

#[test]
fn every_kill_point_the_inventory_declares_has_a_case_and_no_case_is_invented() {
    // Derived from the types: `EventSite::ALL` x `sub_effects()` x `modes()`.
    let declared = declared_kill_points();
    assert_eq!(
        declared,
        BTreeSet::from([
            SubEffectPoint::Create,
            SubEffectPoint::TruncateTornTail,
            SubEffectPoint::SyncPrefix,
            SubEffectPoint::Written,
            SubEffectPoint::Synced,
        ]),
        "the frozen inventory's kill points moved: {declared:?}"
    );
    let covered: BTreeSet<SubEffectPoint> = KILL_CASES.iter().map(|(_, point, _)| *point).collect();
    assert_eq!(
        covered, declared,
        "every declared kill point needs a case and no case may invent one"
    );
    assert_eq!(
        KILL_CASES.len(),
        6,
        "six cells over five points: `Written`'s one kill entry tables two durable shapes"
    );
    assert_eq!(
        KILL_CASES
            .iter()
            .map(|(case, _, _)| *case)
            .collect::<BTreeSet<_>>()
            .len(),
        6,
        "six distinct case names, or the helper cannot tell them apart"
    );
    assert!(
        !KILL_CASES
            .iter()
            .any(|(_, point, _)| *point == SubEffectPoint::WrittenFull),
        "`WrittenFull` declares no kill mode, and a case for it would manufacture a coverage \
         obligation the design does not make"
    );
}

/// `Event.OpenLog`'s three kill entries, each executed by a real abort.
///
/// The claims are the inventory's own: `Create` is "create the log if absent and
/// fsync its directory"; `TruncateTornTail` is "an unterminated final line was
/// truncated **before the append handle was taken**"; and for `SyncPrefix`,
/// "a kill before it … leaves the prefix possibly non-durable, no fold-derived
/// effect is performed, the command refuses resumably, and **the next open
/// repeats the barrier**".
#[test]
fn a_kill_at_each_open_point_leaves_the_shape_the_packet_tables() {
    let prefix = topology_line(0).committed_bytes().to_vec();
    let torn = [prefix.clone(), b"{\"ts\":\"2026".to_vec()].concat();

    // `Create` — the log was absent, so nothing seeds it.
    let created = log_path("kill-create");
    let after = kill_at("create", SubEffectPoint::Create, &created);
    assert!(
        created.exists(),
        "the log the funnel created did not survive the kill"
    );
    assert!(
        after.is_empty(),
        "a created log holds no events yet: {after:?}"
    );

    // `TruncateTornTail` — the truncation is already durable at the point.
    let truncated = log_path("kill-truncate-torn-tail");
    fs::write(&truncated, &torn).expect("seed a torn tail");
    let after = kill_at(
        "truncate-torn-tail",
        SubEffectPoint::TruncateTornTail,
        &truncated,
    );
    assert_eq!(
        after, prefix,
        "the point's claim is that the unterminated line *was* truncated before the handle"
    );

    // `SyncPrefix` — consulted before the sync, so the bytes are untouched and
    // the next open is what makes them durable.
    let unsynced = log_path("kill-sync-prefix");
    fs::write(&unsynced, &prefix).expect("seed a complete prefix");
    let after = kill_at("sync-prefix", SubEffectPoint::SyncPrefix, &unsynced);
    assert_eq!(
        after, prefix,
        "a kill at SyncPrefix leaves the prefix exactly as it found it"
    );
    let mut warnings = Vec::new();
    let mut witness = Witness::default();
    EventLog::open_hooked(EventSite::OpenLog, &unsynced, &mut warnings, &mut witness)
        .expect("the next open repeats the barrier");
    assert_eq!(
        witness.file_syncs(),
        vec![prefix.len() as u64],
        "\"the next open repeats the barrier\": it syncs the whole surviving prefix"
    );
    assert!(warnings.is_empty(), "nothing was torn: {warnings:?}");
}

/// `Event.Append`'s kill entries: the two durable shapes `Written` tables and
/// the synced line `Synced` tables, each executed by a real abort, and each
/// followed by what the next open makes of it.
#[test]
fn a_kill_at_each_append_point_leaves_the_shape_the_packet_tables() {
    let seed = topology_line(0).committed_bytes().to_vec();
    assert_eq!(
        seed.last(),
        Some(&b'\n'),
        "the previous prefix is committed"
    );
    let line = topology_line(1).committed_bytes().to_vec();

    let append_cases: Vec<&(&str, SubEffectPoint, WrittenShape)> = KILL_CASES
        .iter()
        .filter(|(_, point, _)| !EventSite::OpenLog.sub_effects().contains(point))
        .collect();
    assert_eq!(append_cases.len(), 3, "the three append-point cells");

    let mut durable = Vec::new();
    for (case, point, shape) in append_cases {
        let path = log_path(&format!("kill-{case}"));
        fs::write(&path, &seed).expect("seed the previous prefix");
        let after = kill_at(case, *point, &path);

        assert!(
            after.starts_with(&seed),
            "{case}: the previous prefix did not survive"
        );
        let appended = &after[seed.len()..];
        match shape {
            WrittenShape::Torn => {
                assert!(!appended.is_empty(), "{case}: nothing was written at all");
                assert_ne!(
                    after.last(),
                    Some(&b'\n'),
                    "{case}: `Written`'s torn entry leaves a line with no commit marker"
                );
                assert!(
                    line.starts_with(appended),
                    "{case}: the torn bytes are not a prefix of the line being written"
                );
            }
            WrittenShape::Complete => {
                assert_eq!(
                    appended, line,
                    "{case}: the whole newline-terminated line is what this entry leaves"
                );
            }
        }

        // What the next open makes of it — the other half of the tabled entry.
        let mut warnings = Vec::new();
        let reopened = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("reopen");
        drop(reopened);
        let normalized = fs::read(&path).expect("the log after the next open");
        match shape {
            WrittenShape::Torn => {
                assert_eq!(
                    normalized, seed,
                    "{case}: \"truncated on the next open, previous prefix\""
                );
                assert_eq!(warnings.len(), 1, "{case}: and warned about it");
                assert!(
                    warnings[0].contains("never finished being written"),
                    "{case}: {}",
                    warnings[0]
                );
            }
            WrittenShape::Complete => {
                assert_eq!(
                    normalized, after,
                    "{case}: a committed line is not a torn tail and is not truncated"
                );
                assert!(warnings.is_empty(), "{case}: {warnings:?}");
            }
        }
        durable.push(normalized);
    }

    // Two shapes across three coordinates: the complete-unsynced line a kill at
    // `Written` leaves and the synced line a kill at `Synced` leaves are the
    // same bytes, which is why `WrittenFull` declares no kill mode at all.
    assert_eq!(durable.len(), 3);
    assert_ne!(durable[0], durable[1], "torn and complete are not the same");
    assert_eq!(
        durable[1], durable[2],
        "a complete-unsynced line and a synced one are indistinguishable to the next reader"
    );
}

// ---------------------------------------------------------------------------
// The stable-prefix barrier
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_log_establishes_the_barrier_trivially_and_hands_out_a_handle() {
    // "a fresh run's Event.OpenLog at P5 creates an empty log, so the barrier is
    // trivially established (no prefix)".
    let path = log_path("barrier-fresh");
    let mut warnings = Vec::new();
    let mut witness = Witness::default();
    let mut prefix = establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut witness)
        .expect("a fresh log establishes the barrier");

    assert!(prefix.bytes().is_empty(), "no prefix");
    assert!(prefix.fold().started().is_none(), "and nothing folded");
    assert_eq!(
        witness.file_syncs().len(),
        1,
        "the empty prefix is still synced"
    );
    prefix
        .log()
        .append_topology(EventSite::Append, &topology_line(1))
        .expect("the handle the barrier entitles this command to");
}

#[test]
fn the_barrier_syncs_before_it_rereads_and_proves_before_it_replays() {
    let path = log_path("barrier-order");
    let mut warnings = Vec::new();
    let mut witness = Witness::default();
    establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut witness)
        .expect("barrier holds");

    let phases: Vec<String> = witness
        .phases
        .iter()
        .map(|(site, phase)| format!("{}/{phase}", site.name()))
        .collect();
    assert_eq!(
        phases,
        vec![
            "OpenLog/before",
            "OpenLog/after",
            "ProvePrefixStable/before",
            "ProvePrefixStable/after",
        ],
        "the barrier's steps in the order stable_prefix_barrier states them"
    );
    // The sync happened inside `OpenLog`, i.e. before `ProvePrefixStable` began.
    // The file's barrier and the directory's, on every platform (`PR5-CONF-013`).
    assert_eq!(witness.ledger.len(), 2);
}

#[test]
fn an_unstable_reread_refuses_naming_prove_prefix_stable_and_hands_out_no_handle() {
    // Three independent ways a reread can be unstable: a byte moved, the length
    // moved, and the boundary moved. `stable_prefix_barrier` step (4) names all
    // three, so each is a cell rather than one test that happens to trip.
    let committed = b"{\"ts\":\"2026-08-20T09:41:02Z\",\"event\":\"defer_wait_elapsed\",\"data\":{\"waited_ms\":1500,\"round\":1}}\n";
    let mut a_byte = committed.to_vec();
    let position = a_byte.len() - 4;
    a_byte[position] = b'9';
    let mut longer = committed.to_vec();
    longer.extend_from_slice(committed);
    let mut torn_again = committed.to_vec();
    torn_again.extend_from_slice(b"{\"ts\"");

    // Three cells, three *different clauses* of step (4). The order the proof
    // checks them in is what makes that possible: byte-equality implies the
    // other two, so it is checked last.
    let cases: &[(&str, Vec<u8>, &str)] = &[
        (
            "a torn tail reappeared",
            torn_again,
            "does not end at a commit marker",
        ),
        (
            "the length changed",
            longer,
            "byte(s) where the prefix synced at open was",
        ),
        (
            "a byte changed",
            a_byte,
            "differs from the prefix synced at open at byte",
        ),
    ];
    assert_eq!(
        cases
            .iter()
            .map(|(_, bytes, _)| bytes.len())
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "three cells, three distinct rewritten lengths"
    );

    for (name, rewritten, expected) in cases {
        let path = log_path(&format!("unstable-{}", name.replace(' ', "-")));
        fs::write(&path, committed).expect("seed");
        let mut warnings = Vec::new();
        let mut rewriter = Rewrite::after_sync(&path, rewritten);
        let error = establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut rewriter)
            .expect_err("an unstable reread refuses");
        assert_eq!(
            error.step,
            BarrierStep::ProvePrefixStable,
            "{name}: the wrong step"
        );
        assert!(
            error.detail.contains(expected),
            "{name}: the detail says which clause failed: {}",
            error.detail
        );
        assert!(
            error
                .to_string()
                .contains("No append handle was handed out"),
            "{name}: {error}"
        );
    }

    // Each cell produced a *distinct* detail, so a proof that had collapsed the
    // three clauses into one would fail here rather than pass three times.
    let details: BTreeSet<String> = cases
        .iter()
        .map(|(_, rewritten, _)| {
            let path = log_path("unstable-detail");
            fs::write(&path, committed).expect("seed");
            let mut warnings = Vec::new();
            let mut rewriter = Rewrite::after_sync(&path, rewritten);
            establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut rewriter)
                .expect_err("unstable")
                .detail
        })
        .collect();
    assert_eq!(
        details.len(),
        3,
        "three clauses, three details: {details:?}"
    );
}

#[test]
fn checked_replay_consumes_exactly_the_reread_bytes() {
    // The sharp form: the file is replaced with bytes the replay would refuse,
    // *after* the stability proof. An implementation that read the file a third
    // time refuses; one that replays what it proved does not.
    let path = log_path("replay-exact-bytes");
    let mut warnings = Vec::new();
    let mut rewriter = Rewrite::after_proof(&path, b"not an event at all\n");
    let prefix = establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut rewriter)
        .expect("the barrier replays the bytes it proved, not the file");
    assert!(
        prefix.bytes().is_empty(),
        "and those bytes are the proven ones"
    );
    assert_eq!(
        fs::read(&path).expect("log"),
        b"not an event at all\n",
        "the file really was rewritten under it"
    );
}

/// `T-APPEND`'s `refusal_condition`: "a newline-terminated invalid line
/// (rewritten log)", and its resume action: "a newline-terminated invalid line
/// anywhere is corruption and refuses (**never repaired**)".
///
/// Named as `transaction_fault_matrix` names it. The second half is a claim
/// about the bytes, not about the error, so the bytes are what is asserted.
#[test]
fn invalid_terminated_line_refused_not_repaired() {
    let path = log_path("rewritten");
    let corrupt: &[u8] = b"{\"ts\":\"2026-08-20T09:41:02Z\",\"event\":\"not_an_event\"}\n";
    fs::write(&path, corrupt).expect("seed");
    let mut warnings = Vec::new();
    let error = establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut NoEventHooks)
        .expect_err("a committed line that is not an event is corruption");
    assert_eq!(error.step, BarrierStep::CheckedReplay);
    assert!(
        error.detail.contains("line 1"),
        "the refusal names the line: {}",
        error.detail
    );
    // "never repaired": the barrier syncs the prefix it found and refuses. It
    // does not truncate the invalid line, rewrite it, or move it aside — a
    // repair would turn corruption into a confident wrong answer, which is the
    // whole reason this refuses rather than recovers.
    assert_eq!(
        fs::read(&path).expect("the log after the refusal"),
        corrupt,
        "the refusal changed the log"
    );
    assert!(
        warnings.is_empty(),
        "and warned about nothing: {warnings:?}"
    );
}

#[test]
fn the_parsed_events_really_reach_the_checked_fold() {
    // A valid schema-4 line that the *fold* refuses: it parses, so `parse_log`
    // is not the refuser, and the refusal can only come from `replay` having
    // been handed the events. A barrier that replayed an empty slice would
    // succeed here.
    let path = log_path("replay-reached");
    let mut warnings = Vec::new();
    let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");
    log.append_topology(EventSite::Append, &topology_line(1))
        .expect("a defer_wait_elapsed is a well-formed line");
    drop(log);

    let error = establish_stable_prefix(&path, inputs(), None, &mut warnings, &mut NoEventHooks)
        .expect_err("a topology log that does not start with run_started is refused");
    assert_eq!(error.step, BarrierStep::CheckedReplay);
    assert!(
        error.detail.contains("before this log's `run_started`"),
        "the fold's own refusal, not the parser's: {}",
        error.detail
    );
}

#[test]
fn a_first_line_digest_that_disagrees_with_the_commit_record_refuses() {
    let path = log_path("first-line-digest");
    let mut warnings = Vec::new();
    let mut log = EventLog::open(EventSite::OpenLog, &path, &mut warnings).expect("open");
    log.append_topology(EventSite::Append, &topology_line(1))
        .expect("append");
    drop(log);

    let bytes = fs::read(&path).expect("log");
    let actual = first_line_digest(&bytes).expect("a committed first line");
    // Computed here from the line's own bytes rather than by calling the
    // function again: an oracle that called the function under test would move
    // with it.
    let expected = {
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("newline");
        format!("sha256:{:x}", Sha256::digest(&bytes[..end]))
    };
    assert_eq!(
        actual, expected,
        "the digest is over the line without its newline"
    );

    let disagreeing = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let error = establish_stable_prefix(
        &path,
        inputs(),
        Some(disagreeing),
        &mut warnings,
        &mut NoEventHooks,
    )
    .expect_err("a first line the commit record does not recognise refuses");
    assert_eq!(error.step, BarrierStep::ProvePrefixStable);
    assert!(error.detail.contains(disagreeing), "{}", error.detail);

    // An empty log with a commit record that names a first line is the other
    // half of the same clause.
    let empty = log_path("first-line-digest-empty");
    let error = establish_stable_prefix(
        &empty,
        inputs(),
        Some(disagreeing),
        &mut warnings,
        &mut NoEventHooks,
    )
    .expect_err("a commit record without its committed line refuses");
    assert_eq!(error.step, BarrierStep::ProvePrefixStable);
    assert!(
        error.detail.contains("no committed first line"),
        "{}",
        error.detail
    );
}

#[test]
fn every_barrier_step_is_reachable_and_named() {
    // The enum is the list; a step added later has no test and says so.
    assert_eq!(BarrierStep::ALL.len(), 4);
    let names: BTreeSet<&str> = BarrierStep::ALL.iter().map(|step| step.name()).collect();
    assert_eq!(names.len(), 4, "four distinct names");
    for step in BarrierStep::ALL {
        assert!(
            step.name().starts_with("Event.") || step.name() == "the checked replay",
            "a step's name has to be something the registry can be keyed by: {step}"
        );
    }

    // `OpenLog` is the one step the tests above do not produce, because it is
    // the ordinary I/O failure: a log whose directory does not exist.
    let missing = scratch("barrier-open-fails")
        .join("no-such-directory")
        .join("events.jsonl");
    let mut warnings = Vec::new();
    let error = establish_stable_prefix(&missing, inputs(), None, &mut warnings, &mut NoEventHooks)
        .expect_err("an unopenable log refuses at the open");
    assert_eq!(error.step, BarrierStep::OpenLog);
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/// Every module that may write to an event log, and how many places in it do.
///
/// `mechanism` (3): "the raw writer they wrap is reachable only inside
/// `src/events/log.rs`". This is that sentence as a count. It is a source census
/// and therefore carries `PR4-CENSUS-COMMENT-ORACLE`'s hazard, which is handled
/// rather than tripped over: comments are stripped first, and the strip is
/// asserted to have removed something, because this file's own prose names every
/// primitive it counts.
#[test]
fn the_event_log_is_written_in_exactly_one_module() {
    // `sync_all(` is deliberately absent (`PR5-CONF-012`): the log's *file*
    // barrier is now `util::fsync_file`, the one call in the funnel modules that
    // may name the primitive, so requiring it here would require the funnel to
    // keep a second copy of it. The two halves that replace it are asserted
    // below — one `util::fsync_file(` and one `util::fsync_dir(` — and
    // `effects::tests::every_file_durability_barrier_in_a_funnel_module_goes_
    // through_one_call` is what checks the syscall is still inside them.
    const PRIMITIVES: &[&str] = &["write_all(", "sync_data(", "set_len(", "OpenOptions::new()"];
    let funnel = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/events/log.rs");
    let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/events/mod.rs");

    let funnel_code = strip_comments(&fs::read_to_string(&funnel).expect("the funnel"));
    let module_source = fs::read_to_string(&module).expect("the module");
    let module_code = production_region(&strip_comments(&module_source)).to_owned();
    assert!(
        funnel_code.len() < fs::read_to_string(&funnel).expect("the funnel").len(),
        "the comment strip removed nothing, so the count below is measuring prose"
    );

    let production = production_region(&funnel_code);
    for primitive in PRIMITIVES {
        assert!(
            production.contains(primitive),
            "`{primitive}` left the funnel"
        );
        assert!(
            !module_code.contains(primitive),
            "`{primitive}` is in `src/events/mod.rs`, which is not the funnel module"
        );
    }
    // The one write path is one `write_all` per shape, and the shapes are the
    // torn split's two halves plus the whole line: three, and no more.
    assert_eq!(
        production.matches("self.file.write_all(").count(),
        1,
        "one write path, reached from every append shape; a second needs a reason"
    );
    assert_eq!(production.matches(".sync_data()").count(), 1);
    // Both halves of the durability barrier left this module for
    // `src/util.rs` — the directory's because std cannot make that call on
    // Windows at all (`PR5-CONF-013`), the file's because a syscall written
    // beside the ledger entry that certifies it has no oracle
    // (`PR5-CONF-012`). This census follows them rather than losing sight of
    // them: still exactly one each, and still in this module's production
    // region.
    assert_eq!(
        production.matches("util::fsync_file(").count(),
        1,
        "the file's own barrier, once, and through the shared wrapper"
    );
    assert_eq!(
        production.matches("util::fsync_dir(").count(),
        1,
        "the directory's barrier, once, and through the shared wrapper"
    );
}

/// The barrier is the **only** path by which a topology write command obtains a
/// fold from an existing log.
///
/// `stable_prefix_barrier` says the checked replay of the proven bytes is what
/// entitles a write command to act, and a second path — anything that reads the
/// log and folds it without the sync, the reread and the stability proof — makes
/// that entitlement a convention rather than a mechanism. This is that sentence
/// as a count over the whole crate.
///
/// Two hazards are handled rather than tripped over. `PR4-CENSUS-COMMENT-ORACLE`:
/// comments are stripped, and the strip is asserted to have removed something.
/// And a census whose regions collapse to nothing counts zero and reads as
/// "nobody does this", so the control below asserts the scan really did reach
/// the files that mention the fold at all.
#[test]
fn the_stable_prefix_barrier_is_the_only_way_a_log_becomes_a_topology_fold() {
    const FOLD_ENTRIES: &[&str] = &["TopologyFold::replay(", "TopologyFold::parse_log("];
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let funnel = src.join("events").join("log.rs");

    let mut files = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();

    // Whole files the crate declares under `#[cfg(test)]` are test code with no
    // production half at all, and treating them as production would count a
    // fixture as a second path. The set is read out of the declarations rather
    // than guessed from a filename convention.
    let test_modules: BTreeSet<PathBuf> = files
        .iter()
        .flat_map(|path| {
            let source = fs::read_to_string(path).expect("a source file");
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
                    let declaration = rest.trim_start();
                    let name = declaration.strip_prefix("mod ")?;
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
        .collect();
    assert!(
        test_modules.contains(&src.join("events").join("log").join("tests.rs")),
        "this file is declared `#[cfg(test)] mod tests;` and the scan has to know it: {test_modules:?}"
    );

    let mut scanned = 0_usize;
    let mut mentioning = 0_usize;
    let mut callers: Vec<(PathBuf, &str, usize)> = Vec::new();
    for path in &files {
        if test_modules.contains(path) {
            continue;
        }
        let source = fs::read_to_string(path).expect("a source file");
        let stripped = strip_comments(&source);
        // A file with no inline `#[cfg(test)]` is production in full.
        let production = match stripped.find("#[cfg(test)]") {
            Some(end) => &stripped[..end],
            None => stripped.as_str(),
        };
        scanned += 1;
        if production.contains("TopologyFold") {
            mentioning += 1;
        }
        for entry in FOLD_ENTRIES {
            let count = production.matches(entry).count();
            if count > 0 {
                callers.push((path.clone(), entry, count));
            }
        }
    }

    assert!(scanned > 40, "the walk found only {scanned} source files");
    assert_eq!(
        mentioning, 3,
        "the control: `TopologyFold` is named in the production half of the fold, its census and \
         this funnel. A different number means the regions this census scanned are not the ones \
         it thinks they are, and its zero counts would prove nothing"
    );

    assert_eq!(
        callers,
        FOLD_ENTRIES
            .iter()
            .map(|entry| (funnel.clone(), *entry, 1))
            .collect::<Vec<_>>(),
        "a topology fold is built from a log in exactly one production place, once each"
    );

    // And that one place is inside the barrier, not merely inside this file.
    let barrier = {
        let source = strip_comments(&fs::read_to_string(&funnel).expect("the funnel"));
        let start = source
            .find("pub fn establish_stable_prefix(")
            .expect("the barrier is still here");
        source[start..].to_owned()
    };
    for entry in FOLD_ENTRIES {
        assert_eq!(
            barrier.matches(entry).count(),
            1,
            "`{entry}` is in the funnel but not in `establish_stable_prefix`"
        );
    }
}

/// Everything before the `#[cfg(test)]` submodules.
fn production_region(source: &str) -> &str {
    let end = source
        .find("#[cfg(test)]")
        .expect("the funnel declares its test submodules");
    &source[..end]
}

/// Remove `//` line comments. Enough for this census: the strings the census
/// counts never contain `//`.
fn strip_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// The build refusal
// ---------------------------------------------------------------------------

/// One `compile_fail` fixture lifted out of this module's own doc comments.
#[derive(Debug)]
struct BuildRefusal {
    /// The `EXXXX` the fence declares.
    code: String,
    /// Where in `src/events/log.rs` the fence opens, for a failure message.
    line: usize,
    /// The block's Rust, doc-comment prefixes removed.
    body: String,
}

/// Every ```` ```compile_fail,EXXXX ```` block in `src/events/log.rs`.
///
/// The fixtures are read out of the doc comments rather than copied, so the
/// executed test and the documented one cannot drift: there is one text.
fn declared_build_refusals() -> Vec<BuildRefusal> {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/events/log.rs"))
            .expect("the funnel");
    let mut refusals = Vec::new();
    let mut open: Option<BuildRefusal> = None;
    for (index, raw) in source.lines().enumerate() {
        let Some(doc) = raw.trim_start().strip_prefix("///") else {
            continue;
        };
        let doc = doc.strip_prefix(' ').unwrap_or(doc);
        if let Some(refusal) = open.as_mut() {
            if doc.trim_end() == "```" {
                refusals.push(open.take().expect("a block is open"));
            } else {
                refusal.body.push_str(doc);
                refusal.body.push('\n');
            }
            continue;
        }
        if let Some(info) = doc.trim_end().strip_prefix("```compile_fail") {
            let code = info.trim_start_matches(',').trim().to_owned();
            assert!(
                code.len() == 5 && code.starts_with('E') && code[1..].chars().all(char::is_numeric),
                "a compile_fail fence at src/events/log.rs:{} declares `{code}`, which is not an \
                 error code — a fence with no code is green whether it failed for the intended \
                 reason or a typo",
                index + 1
            );
            open = Some(BuildRefusal {
                code,
                line: index + 1,
                body: String::new(),
            });
        }
    }
    assert!(
        open.is_none(),
        "an unterminated compile_fail block in src/events/log.rs"
    );
    refusals
}

/// The `--extern` this crate's own rlib is reachable by, and the directory its
/// dependencies are in.
///
/// The test binary lives in `<target>/debug/deps` beside the rlib cargo built
/// from the same sources, so both are found from `current_exe` rather than from
/// a guessed target directory — `CARGO_TARGET_DIR` is set by the build wrapper
/// this project uses and is not `target/`.
fn crate_under_test() -> (PathBuf, PathBuf) {
    let exe = std::env::current_exe().expect("the test executable");
    let deps = exe
        .parent()
        .expect("the test executable is in a directory")
        .to_path_buf();
    let mut rlibs: Vec<(std::time::SystemTime, PathBuf)> = fs::read_dir(&deps)
        .expect("the deps directory")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?;
            (name.starts_with("libtactus-") && name.ends_with(".rlib")).then(|| {
                let stamp = path
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                (stamp, path)
            })
        })
        .collect();
    rlibs.sort();
    let rlib = rlibs
        .pop()
        .unwrap_or_else(|| {
            panic!(
                "no libtactus-*.rlib beside the test executable in {}",
                deps.display()
            )
        })
        .1;
    (deps, rlib)
}

/// Type-check `body` against this crate and return rustc's diagnostics.
fn typecheck(dir: &Path, name: &str, body: &str) -> (bool, String) {
    let (deps, rlib) = crate_under_test();
    let source = dir.join(format!("{name}.rs"));
    // Doctests without a `fn main` are wrapped in one, so the fixtures are
    // written that way and this wraps them the same.
    fs::write(&source, format!("fn main() {{\n{body}\n}}\n")).expect("the fixture");
    let out = dir.join(format!("{name}-out"));
    fs::create_dir_all(&out).expect("an output directory");
    let output = std::process::Command::new("rustc")
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "bin",
            "--emit=metadata",
        ])
        .arg("--out-dir")
        .arg(&out)
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("--extern")
        .arg(format!("tactus={}", rlib.display()))
        .arg(&source)
        .output()
        .expect("rustc runs; it is the compiler that built this test");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The distinct `error[EXXXX]` codes in a rustc diagnostic stream.
fn error_codes(stderr: &str) -> BTreeSet<String> {
    stderr
        .match_indices("error[")
        .filter_map(|(at, _)| {
            let rest = &stderr[at + "error[".len()..];
            let end = rest.find(']')?;
            Some(rest[..end].to_owned())
        })
        .collect()
}

/// `expected_failures_refusals`: "a schema-4 append outside the Event funnel
/// does not compile", proven by a test the project's own gate runs.
///
/// The three fixtures that carry this claim are `compile_fail` doctests, and
/// **`cargo test --all-targets` does not run doctests** — `--all-targets` is
/// `--lib --bins --tests --benches --examples`, and the doc target is not in it.
/// CI runs exactly that command, so as documentation-only fixtures they were
/// green because they never executed at all: the strongest form of the failure
/// this slice's contract warns about ("a fixture asserting *this does not build*
/// is green whether it failed for the intended reason or a typo").
///
/// So the blocks are read out of the doc comments and compiled here. Three
/// things are asserted that a bare "it did not build" cannot:
///
/// * the **positive control** compiles, so a mis-wired `--extern` cannot make
///   every fixture "refuse" for want of a crate to refuse against;
/// * each fixture emits **exactly** its declared error code and no other, so a
///   typo — which lands on `E0425`, `E0432`, `E0599` — fails this test;
/// * the **count** is pinned, so a deleted fixture is loud.
///
/// # The one boundary, stated rather than hidden
///
/// The fixtures are compiled against the rlib cargo built beside this test
/// binary, so they see the crate as an external consumer does. Under the gate
/// command that rlib is always current — `--all-targets` builds the `tactus`
/// binary, which links it. Under a bare `cargo test --lib` after a visibility
/// change, cargo has no reason to rebuild the rlib, and a fixture could then
/// refuse against yesterday's API. That is not guarded here on purpose: every
/// guard available for it is a timestamp comparison, and a test binary that is
/// legitimately newer than an unchanged rlib is the *ordinary* case, so the
/// guard would be a flake rather than a check. The gate is unaffected.
#[test]
fn every_declared_build_refusal_fails_for_the_reason_it_declares() {
    // The harness compiles at one edition; a crate that moved would be checked
    // under rules it is not built with.
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the manifest");
    assert!(
        manifest.contains("edition = \"2024\""),
        "this harness compiles its fixtures at edition 2024 and the crate no longer is"
    );

    let dir = scratch("build-refusal");

    // The control, and it earns its keep twice.
    //
    // (1) If it does not compile, nothing below is evidence: every fixture would
    //     "refuse" for want of a reachable crate.
    // (2) It is compiled as an **external consumer**, against the rlib and
    //     nothing else, so it is also this slice's proof of `scope`'s "public
    //     path `crate::events::EventLog` **unchanged**" — together with
    //     `read_all` and `LogTail`, the other two names `src/events/mod.rs`
    //     re-exports. An in-crate `use` could not prove that: the module's own
    //     callers would compile against `crate::events::log::EventLog` just as
    //     happily.
    let (control_ok, control_stderr) = typecheck(
        &dir,
        "control",
        "use std::path::Path;\n\
         use tactus::events::{EventLog, LogTail, read_all};\n\
         use tactus::topology::effects::EventSite;\n\
         let mut warnings = Vec::new();\n\
         let log = EventLog::open(EventSite::OpenLog, Path::new(\"events.jsonl\"), &mut warnings)\n\
         .expect(\"open\");\n\
         let _ = log.path();\n\
         let _ = read_all(Path::new(\"events.jsonl\"), &mut warnings);\n\
         let _ = LogTail::new(Path::new(\"events.jsonl\").to_path_buf());\n",
    );
    assert!(
        control_ok,
        "the control did not compile. Either this harness cannot tell a refusal from a broken \
         invocation, or a public path an external caller names has moved:\n{control_stderr}"
    );

    let refusals = declared_build_refusals();
    assert_eq!(
        refusals.len(),
        3,
        "three build-refusal fixtures: the private handle, the schema-4 event handed to the \
         schema-1..3 append, and the un-round-tripped line. Found {:?}",
        refusals.iter().map(|r| &r.code).collect::<Vec<_>>()
    );
    assert_eq!(
        refusals
            .iter()
            .map(|refusal| refusal.code.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "three fixtures, three distinct reasons; two that fail the same way test one thing twice"
    );

    for refusal in &refusals {
        let name = format!("refusal-{}", refusal.code);
        let (compiled, stderr) = typecheck(&dir, &name, &refusal.body);
        assert!(
            !compiled,
            "src/events/log.rs:{} declares `{}` and the fixture compiled",
            refusal.line, refusal.code
        );
        assert_eq!(
            error_codes(&stderr),
            BTreeSet::from([refusal.code.clone()]),
            "src/events/log.rs:{} must fail with exactly `{}` — anything else means it failed for \
             a reason the fixture is not about:\n{stderr}",
            refusal.line,
            refusal.code
        );
    }
}

/// The legacy engine's handling of a returned append error is unchanged, and
/// the thing that makes that true is that it does not append again.
///
/// This is a census, and it used to be *all there was*. Its own boundary note
/// said "no test can make one of its appends fail without plumbing hooks
/// through `engine::Harness` — which is another lane's file this slice does not
/// touch", and that boundary is what `PR5-CONF-010` and `PR5-CONF-011` were:
/// with no way to fail a live run's append, `Run::emit`'s `?` could be replaced
/// by a warning-and-`Ok`, and `drain_and_report`'s partial report could be
/// deleted, and both survived the whole suite. The hooks are plumbed now —
/// `RunOptions::log_hooks`, `NoEventHooks` in production — and the behaviour is
/// held by `engine::tests::a_returned_legacy_append_error_stops_the_run` and
/// `…_still_leaves_the_partial_report`.
///
/// What is left here is what a behavioural test cannot see: that the branch
/// emits **nothing**, over the whole branch rather than over the paths a
/// fixture happens to drive.
#[test]
fn the_legacy_engine_reports_and_stops_on_a_returned_append_error() {
    let coordinator = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine/coordinator.rs");
    let source = fs::read_to_string(&coordinator).expect("the coordinator");
    let code = strip_comments(&source);
    assert!(
        code.len() < source.len(),
        "the comment strip removed nothing"
    );

    let branch = code
        .split_once("if let Err(error) = settlement {")
        .expect("the settlement append-error branch is still there")
        .1;
    let branch = &branch[..branch
        .find("if let Some(question) = parking_question")
        .expect("the branch ends where the next statement begins")];
    assert!(
        branch.contains("return Err(error)"),
        "the branch must still report the append's own error"
    );
    assert!(
        !branch.contains(".emit("),
        "the branch must not append anything after a returned append error: {branch}"
    );
    // Whitespace out before counting a call, because rustfmt decides where a
    // method chain breaks and a census that a reformat can silently zero is a
    // census that reports "clean" for the wrong reason. (Measured: it did —
    // `chain_width` split this very call across three lines.)
    let squeezed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(
        squeezed.matches("self.log.append_hooked(").count(),
        1,
        "the engine has exactly one place that appends"
    );
    assert_eq!(
        squeezed.matches("self.log.append(").count(),
        0,
        "…and it goes through the observer, or a live run's append cannot be made \
         to fail and both of PR5-CONF-010/-011 come back"
    );
}
