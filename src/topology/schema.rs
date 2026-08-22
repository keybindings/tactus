//! Which reader a log gets, decided before a single event is folded (INV-03).
//!
//! Schemas 1–3 are legacy sequential runs; schema 4 is the parallel execution
//! topology. They are different execution models sharing a file name, and
//! **there is no upgrade between them** — a run is one or the other for its
//! whole life ([`check_upgrade_transition`]).
//!
//! That makes the choice of reader a header decision rather than a fold
//! decision. [`probe_header`] reads exactly the first newline-terminated line
//! of `events.jsonl` and nothing else, because that line is the only one whose
//! meaning is fixed before the schema is known: `run_started` is always first,
//! and it always carries the schema the rest of the file is written in. A
//! reader that instead learned the schema while folding would already have
//! interpreted events under the wrong model by the time it found out.
//!
//! Two boundaries are enforced here and stated plainly to whoever hits them:
//!
//! * **The newline is the commit marker.** An unterminated first line is a
//!   torn write, not a header. Nothing is committed, so nothing is read —
//!   which is the same rule `EventLog::open` and every whole-log reader in
//!   [`crate::events`] already apply to the tail, applied to the head.
//! * **A schema above the ceiling refuses explicitly.** Already-released
//!   schema-3 binaries refuse a schema-4 log too, but generically — they fail
//!   on a record they cannot deserialize, and the operator is told the line is
//!   invalid. From this binary onwards the refusal names the schema, the
//!   ceiling, and the fact that no upgrade path exists, because "your log is
//!   corrupt" is the wrong thing to tell someone whose log is merely newer.
//!
//! # Activation
//!
//! [`MAX_READABLE_SCHEMA`] is *derived* from [`TOPOLOGY_ACTIVATION`], not
//! written down. Production is [`TopologyActivation::Inactive`], so the ceiling
//! is 3 and a schema-4 log is refused by a released binary rather than folded
//! by a reader that does not exist yet. Activation is a one-token change in a
//! later slice; every decision that depends on the ceiling already reads it
//! through [`select_reader_with`], so nothing has to be rewritten when it moves.

use std::fmt;

use serde::Deserialize;
use thiserror::Error;

/// The last schema a legacy sequential run can be written in.
pub const LATEST_LEGACY_SCHEMA: u32 = 3;

/// The schema a parallel-topology run is written in. Adjacent to
/// [`LATEST_LEGACY_SCHEMA`] and reachable only by starting a fresh run.
pub const TOPOLOGY_SCHEMA: u32 = LATEST_LEGACY_SCHEMA + 1;

/// Whether this binary's topology reader is switched on.
///
/// A separate type rather than a `bool` so that the two states are named at
/// every use site: `max_readable_schema(false)` says nothing about which side
/// of the switch is production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopologyActivation {
    /// No topology reader is wired up; schema-4 logs are refused explicitly.
    Inactive,
    /// The topology reader is wired up and schema-4 logs are read.
    Active,
}

impl fmt::Display for TopologyActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Inactive => "inactive",
            Self::Active => "active",
        })
    }
}

/// This binary's activation state. **Production is [`TopologyActivation::Inactive`].**
pub const TOPOLOGY_ACTIVATION: TopologyActivation = TopologyActivation::Inactive;

/// The highest schema a binary at `activation` may interpret.
///
/// The ceiling is the *activation* expressed as a number: an inactive binary
/// stops at the legacy schema, an active one reads the topology too. Nothing
/// in between is meaningful, which is why this is a match and not arithmetic.
#[must_use]
pub const fn max_readable_schema(activation: TopologyActivation) -> u32 {
    match activation {
        TopologyActivation::Inactive => LATEST_LEGACY_SCHEMA,
        TopologyActivation::Active => TOPOLOGY_SCHEMA,
    }
}

/// This binary's ceiling, derived from [`TOPOLOGY_ACTIVATION`].
pub const MAX_READABLE_SCHEMA: u32 = max_readable_schema(TOPOLOGY_ACTIVATION);

// The slice's invariant — production reads to schema 3 and no further — held
// where a test cannot hold it. Every assertion in the `tests` module below
// compiles only under `cfg(test)`, so an activation that is `Inactive` for the
// test build and `Active` for the released one satisfies the entire suite while
// shipping a binary that folds schema-4 logs through a reader this slice does
// not have. These are evaluated in the ordinary build too — the one `src/main.rs`
// links — so that shape fails to compile rather than shipping.
const _: () = assert!(matches!(TOPOLOGY_ACTIVATION, TopologyActivation::Inactive));
const _: () = assert!(MAX_READABLE_SCHEMA == LATEST_LEGACY_SCHEMA);
const _: () = assert!(MAX_READABLE_SCHEMA == 3);
const _: () = assert!(TOPOLOGY_SCHEMA == LATEST_LEGACY_SCHEMA + 1);

/// Which schema a *fresh* run is written in.
///
/// Separate from the read ceiling on purpose. Reading is about what a binary
/// can be handed; writing is about what it chooses to create, and a binary that
/// could read schema 4 still writes schema 3 for every ordinary run until the
/// topology is what `tactus run` means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriterSelector {
    /// What `tactus run` creates.
    Production,
    /// What a deliberate topology preview creates.
    TopologyPreview,
}

impl fmt::Display for WriterSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Production => "production",
            Self::TopologyPreview => "topology-preview",
        })
    }
}

/// The schema `selector` writes into a fresh `run_started`.
#[must_use]
pub const fn fresh_writer_schema(selector: WriterSelector) -> u32 {
    match selector {
        WriterSelector::Production => LATEST_LEGACY_SCHEMA,
        WriterSelector::TopologyPreview => TOPOLOGY_SCHEMA,
    }
}

// ---------------------------------------------------------------------------
// Header probe
// ---------------------------------------------------------------------------

/// What the first committed line of a log says about the rest of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHeader {
    /// The event tag on line 1. Always `run_started` in an accepted header —
    /// carried anyway so a caller can report what it found instead.
    pub event: String,
    /// The schema the rest of the file is written in.
    pub schema: u32,
}

/// Which fold a log's bytes belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderSelection {
    /// A sequential run: [`crate::events::RunState::apply`], unchanged.
    Legacy {
        /// The exact legacy schema, which still decides legacy-side behaviour.
        schema: u32,
    },
    /// A parallel-topology run: the checked topology fold.
    Topology,
}

/// The minimum shape a header must have. Deliberately not the real
/// `run_started` payload of either schema: the probe's whole job is to run
/// *before* either payload type is chosen, so it must not be able to fail for
/// a reason that belongs to one of them.
#[derive(Debug, Deserialize)]
struct ProbeLine {
    event: String,
    #[serde(default)]
    data: Option<ProbeData>,
}

#[derive(Debug, Deserialize)]
struct ProbeData {
    #[serde(default)]
    schema: Option<u32>,
}

/// The tag every log's first committed line must carry.
const RUN_STARTED: &str = "run_started";

/// Read the header off the first newline-terminated line of `bytes`.
///
/// Everything after that line is ignored — including whether it parses at all.
/// A reader that refused here on a damaged line 7 would be refusing for a
/// reason the *fold* is entitled to state precisely, having read the file.
///
/// # Errors
///
/// [`SchemaRefusal::NoCommittedHeader`] when no line is newline-terminated,
/// [`SchemaRefusal::FirstLineUnreadable`] when line 1 is not a JSON event
/// envelope, [`SchemaRefusal::RunStartedNotFirst`] when it is some other
/// event, and [`SchemaRefusal::HeaderWithoutSchema`] when it records no schema.
pub fn probe_header(bytes: &[u8]) -> Result<LogHeader, SchemaRefusal> {
    // The newline is the commit marker (see `crate::events::parse_bytes`): a
    // syntactically complete first line without one was never committed, so
    // there is no header to read even though the bytes look like one.
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(SchemaRefusal::NoCommittedHeader)?;
    let line =
        std::str::from_utf8(&bytes[..end]).map_err(|error| SchemaRefusal::FirstLineUnreadable {
            detail: error.to_string(),
        })?;
    let probe: ProbeLine =
        serde_json::from_str(line).map_err(|error| SchemaRefusal::FirstLineUnreadable {
            detail: error.to_string(),
        })?;
    if probe.event != RUN_STARTED {
        return Err(SchemaRefusal::RunStartedNotFirst { found: probe.event });
    }
    let schema = probe
        .data
        .and_then(|data| data.schema)
        .ok_or(SchemaRefusal::HeaderWithoutSchema)?;
    Ok(LogHeader {
        event: probe.event,
        schema,
    })
}

/// Which reader a log written in `schema` gets from a binary whose ceiling is
/// `ceiling`.
///
/// Pure, and separate from [`probe_header`] so the ceiling is an argument
/// rather than a constant every caller silently inherits. That is what lets
/// the post-activation ceiling be exercised without moving production's.
///
/// # Errors
///
/// [`SchemaRefusal::TopologyLogUnreadable`] for a topology log this binary is
/// not activated for, and [`SchemaRefusal::NewerThanReadable`] for anything
/// above the topology schema.
pub fn select_for_schema(schema: u32, ceiling: u32) -> Result<ReaderSelection, SchemaRefusal> {
    if schema > ceiling {
        // Two refusals, because they are two different situations for the
        // person reading them: one is fixed by upgrading tactus, the other by
        // upgrading tactus *and* knowing that this log will never be a legacy
        // run no matter what reads it.
        if schema == TOPOLOGY_SCHEMA {
            return Err(SchemaRefusal::TopologyLogUnreadable { schema, ceiling });
        }
        return Err(SchemaRefusal::NewerThanReadable { schema, ceiling });
    }
    if schema == TOPOLOGY_SCHEMA {
        return Ok(ReaderSelection::Topology);
    }
    Ok(ReaderSelection::Legacy { schema })
}

/// Probe `bytes` and choose a reader against an explicit `ceiling`.
///
/// # Errors
///
/// Every [`SchemaRefusal`] [`probe_header`] and [`select_for_schema`] produce.
pub fn select_reader_with(bytes: &[u8], ceiling: u32) -> Result<ReaderSelection, SchemaRefusal> {
    select_for_schema(probe_header(bytes)?.schema, ceiling)
}

/// Probe `bytes` and choose a reader against this binary's ceiling.
///
/// # Errors
///
/// Every [`SchemaRefusal`] [`select_reader_with`] produces.
pub fn select_reader(bytes: &[u8]) -> Result<ReaderSelection, SchemaRefusal> {
    select_reader_with(bytes, MAX_READABLE_SCHEMA)
}

/// Whether a legacy `run_schema_upgraded` transition may be applied.
///
/// **No run upgrades into the topology** (INV-03). The schemas are different
/// execution models, not successive versions of one: a schema-3 log records a
/// sequential run whose tasks committed to a branch, and reinterpreting it as
/// a topology run would invent a merge queue, a candidate for every commit,
/// and a runner identity nobody resolved. The way to get a topology run is to
/// start one.
///
/// # Errors
///
/// [`SchemaRefusal::NoUpgradePath`] for any transition into schema 4 or above,
/// and [`SchemaRefusal::NotAnUpgrade`] for one that does not move forwards.
pub fn check_upgrade_transition(from: u32, to: u32) -> Result<(), SchemaRefusal> {
    if to >= TOPOLOGY_SCHEMA {
        return Err(SchemaRefusal::NoUpgradePath { from, to });
    }
    if to <= from {
        return Err(SchemaRefusal::NotAnUpgrade { from, to });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a log was not read.
///
/// Every message names the numbers involved and what to do, because a refusal
/// an operator cannot act on is indistinguishable from a crash.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SchemaRefusal {
    #[error(
        "the event log has no committed first line — every byte present is an unterminated \
         write. The newline is what commits a line, so this log records nothing yet; a run \
         interrupted this early left no state to recover."
    )]
    NoCommittedHeader,

    #[error(
        "the event log's first line is not a readable event ({detail}). This is not a torn \
         tail — the first line is newline-terminated, so it was committed, and a committed \
         line that will not parse means the log was rewritten rather than appended to."
    )]
    FirstLineUnreadable { detail: String },

    #[error(
        "the event log begins with `{found}` rather than `run_started`. The first line records \
         how the run began and which schema everything after it is written in, so a log that \
         starts anywhere else cannot be interpreted at all — not even to say what is wrong \
         with it."
    )]
    RunStartedNotFirst { found: String },

    #[error(
        "the event log's `run_started` records no schema, so there is no way to tell which \
         execution model the rest of the file describes. Every writer records one; a record \
         without it was not written by tactus."
    )]
    HeaderWithoutSchema,

    #[error(
        "this log is a parallel-execution-topology run (event schema {schema}); this binary \
         reads up to schema {ceiling}, which is sequential runs only. Upgrade tactus to read \
         it. It will never become a schema-{ceiling} run: the topology is a different \
         execution model — a merge queue, per-task worktrees, and a recorded runner identity — \
         and no upgrade path into or out of it exists."
    )]
    TopologyLogUnreadable { schema: u32, ceiling: u32 },

    #[error(
        "this log was written by a newer tactus (event schema {schema}); this binary reads up \
         to schema {ceiling}. Upgrade rather than interpret it — deriving state from a log we \
         only half understand would be confidently wrong."
    )]
    NewerThanReadable { schema: u32, ceiling: u32 },

    #[error(
        "refusing a schema upgrade {from} -> {to}: schemas {LATEST_LEGACY_SCHEMA} and below \
         are sequential runs and schema {TOPOLOGY_SCHEMA} is the parallel execution topology. \
         They are different execution models, not successive versions of one, and no run \
         crosses between them — start a new run instead."
    )]
    NoUpgradePath { from: u32, to: u32 },

    #[error(
        "invalid schema transition {from} -> {to}: an upgrade record must move the log \
         forwards, and this one does not."
    )]
    NotAnUpgrade { from: u32, to: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A first line that is genuinely hostile in every field a probe reads:
    /// a run id in mixed case with padding around it, a multi-byte branch
    /// name, and the schema buried after other keys rather than first.
    fn header_line(event: &str, schema: Option<u32>) -> String {
        let schema_field = match schema {
            Some(value) => format!(r#""schema":{value},"#),
            None => String::new(),
        };
        format!(
            r#"{{"ts":"2026-08-17T03:04:05.678Z","event":"{event}","data":{{"branch":" Ünïcode/BrÄnch  ","run_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV",{schema_field}"tactus_version":"0.0.1-Ünicode"}}}}"#
        )
    }

    fn committed(event: &str, schema: Option<u32>) -> Vec<u8> {
        let mut bytes = header_line(event, schema).into_bytes();
        bytes.push(b'\n');
        bytes
    }

    // -- the domain the relations are stated over -------------------------
    //
    // The wire carries a `u32`, so the schema domain is 2^32 values and no
    // grid enumerates it. What a grid can do is cover every *partition* the
    // relation distinguishes and every *representation boundary* a narrowing
    // mutation could hide behind, which is what these two lists are.
    //
    // Partitions of the schema domain against a ceiling: below it, equal to
    // it, above it but below the topology schema, exactly the topology schema,
    // and above the topology schema. Every one of those is populated below.
    //
    // Representation boundaries: 127/128 (i8), 255/256/257/259 (u8),
    // 511/512, 65535/65536 (u16), and the top of the u32 range. A guard
    // narrowed to any smaller integer width, or capped at any recognized
    // version, changes its answer at one of these.

    /// Schema values every relation over the wire domain is crossed against.
    const HOSTILE_SCHEMAS: [u32; 22] = [
        0,
        1,
        2,
        3,
        LATEST_LEGACY_SCHEMA,
        TOPOLOGY_SCHEMA,
        5,
        6,
        7,
        8,
        127,
        128,
        255,
        256,
        257,
        259,
        511,
        512,
        65_535,
        65_536,
        u32::MAX - 1,
        u32::MAX,
    ];

    /// Ceilings the relation is crossed against.
    ///
    /// `max_readable_schema` has image exactly `{3, 4}` — the two production
    /// can hold — and the rest are hostile values that cannot arise and must
    /// not change the relation. Ceilings above the topology schema are
    /// deliberately absent: the design fixes the answer for `<= 3`, for `4`,
    /// and for "above the ceiling", and says nothing about a binary claiming
    /// to read schema 9, so a test asserting one would freeze an answer the
    /// frozen design does not give.
    const HOSTILE_CEILINGS: [u32; 5] = [0, 1, 2, LATEST_LEGACY_SCHEMA, TOPOLOGY_SCHEMA];

    /// The reader-selection rule as the design states it, restated here and
    /// never read off the implementation.
    fn expected_selection(schema: u32, ceiling: u32) -> Result<ReaderSelection, SchemaRefusal> {
        if schema > ceiling {
            if schema == TOPOLOGY_SCHEMA {
                return Err(SchemaRefusal::TopologyLogUnreadable { schema, ceiling });
            }
            return Err(SchemaRefusal::NewerThanReadable { schema, ceiling });
        }
        if schema == TOPOLOGY_SCHEMA {
            return Ok(ReaderSelection::Topology);
        }
        Ok(ReaderSelection::Legacy { schema })
    }

    /// A later line that is a *perfect* header in its own right, and whose
    /// schema is chosen independently of whatever line 1 says. Anything that
    /// looked past line 1 would find this and be believed.
    fn hostile_later_header(schema: u32) -> Vec<u8> {
        let mut bytes = committed(RUN_STARTED, Some(schema));
        bytes.extend_from_slice(&committed("task_merged", Some(schema)));
        bytes
    }

    // -- constants ---------------------------------------------------------

    #[test]
    fn schema_constants_are_the_frozen_values_and_adjacent() {
        assert_eq!(LATEST_LEGACY_SCHEMA, 3);
        assert_eq!(TOPOLOGY_SCHEMA, 4);
        assert_eq!(TOPOLOGY_SCHEMA, LATEST_LEGACY_SCHEMA + 1);
        assert_eq!(LATEST_LEGACY_SCHEMA, crate::events::SCHEMA_VERSION);
    }

    #[test]
    fn max_readable_is_the_activation_switch_and_production_is_inactive() {
        // The ceiling is not a number this crate writes down twice: it is the
        // activation, evaluated. A mutation that hard-codes either side of the
        // switch is what these four assertions exist to catch.
        assert_eq!(
            max_readable_schema(TopologyActivation::Inactive),
            LATEST_LEGACY_SCHEMA
        );
        assert_eq!(
            max_readable_schema(TopologyActivation::Active),
            TOPOLOGY_SCHEMA
        );
        assert_ne!(
            max_readable_schema(TopologyActivation::Inactive),
            max_readable_schema(TopologyActivation::Active)
        );
        assert_eq!(TOPOLOGY_ACTIVATION, TopologyActivation::Inactive);
        assert_eq!(
            MAX_READABLE_SCHEMA,
            max_readable_schema(TOPOLOGY_ACTIVATION)
        );
        // The slice's stated invariant, said in the plainest possible way.
        assert_eq!(MAX_READABLE_SCHEMA, 3);
    }

    #[test]
    fn fresh_writer_schema_maps_each_selector_to_a_different_model() {
        assert_eq!(
            fresh_writer_schema(WriterSelector::Production),
            LATEST_LEGACY_SCHEMA
        );
        assert_eq!(
            fresh_writer_schema(WriterSelector::TopologyPreview),
            TOPOLOGY_SCHEMA
        );
        assert_ne!(
            fresh_writer_schema(WriterSelector::Production),
            fresh_writer_schema(WriterSelector::TopologyPreview)
        );
        // Production never writes something production cannot read back.
        assert!(fresh_writer_schema(WriterSelector::Production) <= MAX_READABLE_SCHEMA);
    }

    // -- reader selection --------------------------------------------------

    #[test]
    fn reader_selection_is_a_relation_over_every_ceiling_and_schema() {
        // Crossed grid, not samples: a lookup table keyed on a handful of
        // pairs satisfies any finite set of examples, so the expectation here
        // is restated from the design rather than read off the implementation
        // — `<= 3` legacy, `4` topology, above the ceiling refuses, and the
        // topology refusal is a different refusal from the generic one.
        for ceiling in [LATEST_LEGACY_SCHEMA, TOPOLOGY_SCHEMA] {
            for schema in 0..=6 {
                let expected = if schema > ceiling {
                    if schema == TOPOLOGY_SCHEMA {
                        Err(SchemaRefusal::TopologyLogUnreadable { schema, ceiling })
                    } else {
                        Err(SchemaRefusal::NewerThanReadable { schema, ceiling })
                    }
                } else if schema == TOPOLOGY_SCHEMA {
                    Ok(ReaderSelection::Topology)
                } else {
                    Ok(ReaderSelection::Legacy { schema })
                };
                assert_eq!(
                    select_for_schema(schema, ceiling),
                    expected,
                    "ceiling {ceiling}, schema {schema}"
                );
            }
        }
    }

    #[test]
    fn production_refuses_a_topology_log_and_reads_every_legacy_one() {
        assert_eq!(
            select_reader(&committed(RUN_STARTED, Some(TOPOLOGY_SCHEMA))),
            Err(SchemaRefusal::TopologyLogUnreadable {
                schema: TOPOLOGY_SCHEMA,
                ceiling: LATEST_LEGACY_SCHEMA,
            })
        );
        for schema in 1..=LATEST_LEGACY_SCHEMA {
            assert_eq!(
                select_reader(&committed(RUN_STARTED, Some(schema))),
                Ok(ReaderSelection::Legacy { schema })
            );
        }
    }

    #[test]
    fn activating_the_ceiling_is_the_only_thing_that_admits_a_topology_log() {
        let log = committed(RUN_STARTED, Some(TOPOLOGY_SCHEMA));
        assert!(
            select_reader_with(&log, max_readable_schema(TopologyActivation::Inactive)).is_err()
        );
        assert_eq!(
            select_reader_with(&log, max_readable_schema(TopologyActivation::Active)),
            Ok(ReaderSelection::Topology)
        );
    }

    // -- header probe ------------------------------------------------------

    #[test]
    fn a_first_line_is_a_header_only_once_its_newline_commits_it() {
        // The two inputs differ in exactly one byte. Anything that reads the
        // header from an uncommitted line passes the first assertion, so the
        // pair is the test: same bytes, opposite answers.
        let line = header_line(RUN_STARTED, Some(2));
        let torn = line.clone().into_bytes();
        let mut commit = torn.clone();
        commit.push(b'\n');

        assert_eq!(probe_header(&torn), Err(SchemaRefusal::NoCommittedHeader));
        assert_eq!(
            probe_header(&commit),
            Ok(LogHeader {
                event: RUN_STARTED.to_owned(),
                schema: 2,
            })
        );
        assert_eq!(commit.len(), torn.len() + 1);
    }

    #[test]
    fn an_empty_or_newline_only_log_has_no_header() {
        assert_eq!(probe_header(b""), Err(SchemaRefusal::NoCommittedHeader));
        assert!(matches!(
            probe_header(b"\n"),
            Err(SchemaRefusal::FirstLineUnreadable { .. })
        ));
        assert!(matches!(
            probe_header(b"   \n"),
            Err(SchemaRefusal::FirstLineUnreadable { .. })
        ));
    }

    #[test]
    fn the_probe_reads_line_one_and_refuses_to_look_further() {
        // A run_started on line 2 is still a log that does not begin with one.
        // Scanning for the first run_started anywhere would accept this, and
        // would accept a log whose real header had been prefixed away.
        let mut log = committed("task_merged", None);
        log.extend_from_slice(&committed(RUN_STARTED, Some(3)));
        assert_eq!(
            probe_header(&log),
            Err(SchemaRefusal::RunStartedNotFirst {
                found: "task_merged".to_owned(),
            })
        );

        // And the converse: damage after line 1 is not the probe's business.
        let mut good = committed(RUN_STARTED, Some(1));
        good.extend_from_slice(b"{ this is not JSON at all\n\x80\x81\n");
        assert_eq!(
            probe_header(&good),
            Ok(LogHeader {
                event: RUN_STARTED.to_owned(),
                schema: 1,
            })
        );
    }

    #[test]
    fn a_committed_first_line_that_is_not_an_event_is_a_rewritten_log() {
        assert!(matches!(
            probe_header(b"{\"event\":\"run_started\",\n"),
            Err(SchemaRefusal::FirstLineUnreadable { .. })
        ));
        // Invalid UTF-8 inside the committed first line, not after it.
        assert!(matches!(
            probe_header(b"{\"event\":\"run_\x80started\"}\n"),
            Err(SchemaRefusal::FirstLineUnreadable { .. })
        ));
    }

    #[test]
    fn a_run_started_without_a_schema_is_not_a_header() {
        assert_eq!(
            probe_header(&committed(RUN_STARTED, None)),
            Err(SchemaRefusal::HeaderWithoutSchema)
        );
    }

    // -- refusal messages --------------------------------------------------

    #[test]
    fn the_topology_refusal_is_a_different_message_from_the_generic_newer_one() {
        // The ceiling here is deliberately not production's, so a message that
        // renders a hard-coded 3 rather than the ceiling it was given fails.
        let topology = SchemaRefusal::TopologyLogUnreadable {
            schema: 4,
            ceiling: 2,
        }
        .to_string();
        let newer = SchemaRefusal::NewerThanReadable {
            schema: 9,
            ceiling: 7,
        }
        .to_string();

        assert_ne!(topology, newer);
        assert!(topology.contains("schema 4"), "{topology}");
        assert!(topology.contains("schema 2"), "{topology}");
        assert!(!topology.contains('3'), "{topology}");
        assert!(topology.contains("topology"), "{topology}");
        assert!(topology.contains("no upgrade path"), "{topology}");

        assert!(newer.contains("schema 9"), "{newer}");
        assert!(newer.contains("schema 7"), "{newer}");
        assert!(!newer.contains("topology"), "{newer}");
    }

    #[test]
    fn every_refusal_names_what_it_refused() {
        let cases: Vec<(SchemaRefusal, &[&str])> = vec![
            (SchemaRefusal::NoCommittedHeader, &["newline", "committed"]),
            (
                SchemaRefusal::FirstLineUnreadable {
                    detail: "expected value at line 1 column 1".to_owned(),
                },
                &["expected value at line 1 column 1", "rewritten"],
            ),
            (
                SchemaRefusal::RunStartedNotFirst {
                    found: "merge_prepared".to_owned(),
                },
                &["merge_prepared", "run_started"],
            ),
            (SchemaRefusal::HeaderWithoutSchema, &["no schema"]),
            (
                SchemaRefusal::TopologyLogUnreadable {
                    schema: 4,
                    ceiling: 3,
                },
                &["4", "3", "topology"],
            ),
            (
                SchemaRefusal::NewerThanReadable {
                    schema: 5,
                    ceiling: 3,
                },
                &["5", "3", "newer"],
            ),
            (
                SchemaRefusal::NoUpgradePath { from: 3, to: 4 },
                &["3 -> 4", "different execution models"],
            ),
            (
                SchemaRefusal::NotAnUpgrade { from: 2, to: 2 },
                &["2 -> 2", "forwards"],
            ),
        ];
        for (refusal, fragments) in cases {
            let rendered = refusal.to_string();
            for fragment in fragments {
                assert!(
                    rendered.contains(fragment),
                    "{refusal:?} does not name `{fragment}`: {rendered}"
                );
            }
        }
    }

    // -- migration ---------------------------------------------------------

    #[test]
    fn no_upgrade_reaches_the_topology_from_any_legacy_schema() {
        // Crossed grid again: the rule is about the destination, and a test
        // that only ever asks about 3 -> 4 cannot tell a `>=` from a `>`, or a
        // destination check from a source check.
        for from in 0..=5 {
            for to in 0..=6 {
                let expected = if to >= TOPOLOGY_SCHEMA {
                    Err(SchemaRefusal::NoUpgradePath { from, to })
                } else if to <= from {
                    Err(SchemaRefusal::NotAnUpgrade { from, to })
                } else {
                    Ok(())
                };
                assert_eq!(
                    check_upgrade_transition(from, to),
                    expected,
                    "upgrade {from} -> {to}"
                );
            }
        }
    }

    #[test]
    fn the_legacy_upgrade_ladder_still_runs_to_its_own_ceiling() {
        // 1 -> 2 -> 3 remains exactly what it was; only the step into the
        // topology is refused, and it is refused from every rung.
        assert_eq!(check_upgrade_transition(1, 2), Ok(()));
        assert_eq!(check_upgrade_transition(2, 3), Ok(()));
        assert_eq!(check_upgrade_transition(1, 3), Ok(()));
        for from in 1..=LATEST_LEGACY_SCHEMA {
            assert_eq!(
                check_upgrade_transition(from, TOPOLOGY_SCHEMA),
                Err(SchemaRefusal::NoUpgradePath {
                    from,
                    to: TOPOLOGY_SCHEMA
                })
            );
        }
    }

    // ==================================================================
    // The relations over the whole wire domain, not a sample of it
    // ==================================================================

    #[test]
    fn reader_selection_holds_across_every_partition_and_integer_boundary() {
        // The grid above stops at 6, which is a range a `schema <= 6` cap
        // satisfies exactly and a `(schema as u8) > (ceiling as u8)`
        // narrowing never contradicts. This one crosses the partitions the
        // relation distinguishes against the boundaries of every integer
        // width the value could be narrowed to, including the top of u32.
        let mut cells = 0_u32;
        for ceiling in HOSTILE_CEILINGS {
            for schema in HOSTILE_SCHEMAS {
                assert_eq!(
                    select_for_schema(schema, ceiling),
                    expected_selection(schema, ceiling),
                    "ceiling {ceiling}, schema {schema}"
                );
                cells += 1;
            }
        }
        assert_eq!(
            cells,
            (HOSTILE_CEILINGS.len() * HOSTILE_SCHEMAS.len()) as u32
        );

        // Named singly as well, so the intent survives a change to the lists.
        assert_eq!(
            select_for_schema(7, LATEST_LEGACY_SCHEMA),
            Err(SchemaRefusal::NewerThanReadable {
                schema: 7,
                ceiling: LATEST_LEGACY_SCHEMA
            })
        );
        assert_eq!(
            select_for_schema(259, LATEST_LEGACY_SCHEMA),
            Err(SchemaRefusal::NewerThanReadable {
                schema: 259,
                ceiling: LATEST_LEGACY_SCHEMA
            })
        );
        assert_eq!(
            select_for_schema(u32::MAX, TOPOLOGY_SCHEMA),
            Err(SchemaRefusal::NewerThanReadable {
                schema: u32::MAX,
                ceiling: TOPOLOGY_SCHEMA
            })
        );
    }

    #[test]
    fn no_upgrade_reaches_any_destination_at_or_above_the_topology_schema() {
        // The destination rule is unbounded above. A grid that stops at 6 is
        // satisfied by `(TOPOLOGY_SCHEMA..=6).contains(&to)` and by an
        // `as u8` narrowing of the same comparison; both are wrong for a log
        // recording an upgrade into a schema nobody has written yet.
        let froms: [u32; 9] = [0, 1, 2, 3, 4, 5, 255, 256, u32::MAX];
        let mut cells = 0_u32;
        for from in froms {
            for to in HOSTILE_SCHEMAS {
                let expected = if to >= TOPOLOGY_SCHEMA {
                    Err(SchemaRefusal::NoUpgradePath { from, to })
                } else if to <= from {
                    Err(SchemaRefusal::NotAnUpgrade { from, to })
                } else {
                    Ok(())
                };
                assert_eq!(
                    check_upgrade_transition(from, to),
                    expected,
                    "upgrade {from} -> {to}"
                );
                cells += 1;
            }
        }
        assert_eq!(cells, (froms.len() * HOSTILE_SCHEMAS.len()) as u32);

        assert_eq!(
            check_upgrade_transition(3, 7),
            Err(SchemaRefusal::NoUpgradePath { from: 3, to: 7 })
        );
        assert_eq!(
            check_upgrade_transition(3, 256),
            Err(SchemaRefusal::NoUpgradePath { from: 3, to: 256 })
        );
        assert_eq!(
            check_upgrade_transition(3, u32::MAX),
            Err(SchemaRefusal::NoUpgradePath {
                from: 3,
                to: u32::MAX
            })
        );
    }

    #[test]
    fn the_production_wrapper_refuses_every_future_schema_its_inner_selector_refuses() {
        // `select_reader` is what production calls, and a wrapper that
        // short-circuits before delegating passes every test of the function
        // it is supposed to be a composition of. Asserted as an identity over
        // committed bytes rather than as a sample of outcomes.
        for schema in HOSTILE_SCHEMAS {
            let log = committed(RUN_STARTED, Some(schema));
            assert_eq!(
                select_reader(&log),
                expected_selection(schema, MAX_READABLE_SCHEMA),
                "select_reader at schema {schema}"
            );
            assert_eq!(
                select_reader(&log),
                select_for_schema(schema, MAX_READABLE_SCHEMA),
                "select_reader is not select_for_schema at MAX_READABLE_SCHEMA, schema {schema}"
            );
            for ceiling in HOSTILE_CEILINGS {
                assert_eq!(
                    select_reader_with(&log, ceiling),
                    expected_selection(schema, ceiling),
                    "select_reader_with ceiling {ceiling}, schema {schema}"
                );
            }
        }

        // The two cases the wrapper is most tempting to special-case.
        assert_eq!(
            select_reader(&committed(RUN_STARTED, Some(5))),
            Err(SchemaRefusal::NewerThanReadable {
                schema: 5,
                ceiling: LATEST_LEGACY_SCHEMA
            })
        );
        assert_eq!(
            select_reader(&committed(RUN_STARTED, Some(u32::MAX))),
            Err(SchemaRefusal::NewerThanReadable {
                schema: u32::MAX,
                ceiling: LATEST_LEGACY_SCHEMA
            })
        );
    }

    #[test]
    fn a_future_schema_survives_the_probe_at_its_recorded_width() {
        // The probe's own integer type is a place the value can be lost: a
        // `u8` field cannot represent 256, and a header that cannot be
        // represented is reported as unreadable rather than as too new, or is
        // silently clamped to the topology schema and reported as a topology
        // log. Driven through committed JSON so the width under test is the
        // decoder's, not the caller's.
        for schema in [5_u32, 6, 7, 9, 255, 256, 257, 259, 65_536, u32::MAX] {
            let log = committed(RUN_STARTED, Some(schema));
            assert_eq!(
                probe_header(&log),
                Ok(LogHeader {
                    event: RUN_STARTED.to_owned(),
                    schema,
                }),
                "the probe did not preserve schema {schema}"
            );
            let refusal = select_reader_with(&log, LATEST_LEGACY_SCHEMA)
                .expect_err("every one of these is above the ceiling");
            match refusal {
                SchemaRefusal::NewerThanReadable {
                    schema: found,
                    ceiling,
                } => {
                    assert_eq!(found, schema);
                    assert_eq!(ceiling, LATEST_LEGACY_SCHEMA);
                    let rendered = SchemaRefusal::NewerThanReadable {
                        schema: found,
                        ceiling,
                    }
                    .to_string();
                    assert!(
                        rendered.contains(&format!("event schema {schema}")),
                        "{rendered}"
                    );
                    assert!(
                        rendered.contains(&format!("reads up to schema {LATEST_LEGACY_SCHEMA}")),
                        "{rendered}"
                    );
                }
                other => panic!("schema {schema} was refused as {other:?}"),
            }
        }
    }

    // ==================================================================
    // The commit marker
    // ==================================================================

    #[test]
    fn the_line_feed_is_the_only_byte_that_commits_a_first_line() {
        // The existing pair proves LF-present against no-suffix, which any
        // "stop at the first line-ending byte" rule also satisfies. Crossing
        // the same header over all 256 one-byte suffixes is what separates
        // "the newline commits" from "some terminator commits": a CR-only
        // suffix is a torn write on Windows and must record nothing.
        let line = header_line(RUN_STARTED, Some(2));
        for byte in 0_u8..=255 {
            let mut bytes = line.clone().into_bytes();
            bytes.push(byte);
            let observed = probe_header(&bytes);
            if byte == b'\n' {
                assert_eq!(
                    observed,
                    Ok(LogHeader {
                        event: RUN_STARTED.to_owned(),
                        schema: 2,
                    }),
                    "0x0A did not commit the line"
                );
            } else {
                assert_eq!(
                    observed,
                    Err(SchemaRefusal::NoCommittedHeader),
                    "0x{byte:02X} committed a line the newline had not"
                );
            }
        }

        // CRLF is committed, because it contains the newline: the CR is
        // trailing whitespace inside the committed line, not a terminator.
        let mut crlf = line.clone().into_bytes();
        crlf.extend_from_slice(b"\r\n");
        assert_eq!(
            probe_header(&crlf),
            Ok(LogHeader {
                event: RUN_STARTED.to_owned(),
                schema: 2,
            })
        );
    }

    #[test]
    fn commitment_depends_on_the_newline_and_on_nothing_the_header_says() {
        // The torn-write rule is exercised at one schema only, which a
        // schema-dependent exception at the 3/4 boundary survives. The same
        // bytes, differing in the commit marker alone, at every schema class.
        for schema in [
            1_u32,
            2,
            LATEST_LEGACY_SCHEMA,
            TOPOLOGY_SCHEMA,
            5,
            259,
            u32::MAX,
        ] {
            let line = header_line(RUN_STARTED, Some(schema));
            let torn = line.clone().into_bytes();
            let mut commit = torn.clone();
            commit.push(b'\n');

            assert_eq!(
                probe_header(&torn),
                Err(SchemaRefusal::NoCommittedHeader),
                "an unterminated schema-{schema} header was committed"
            );
            assert_eq!(
                probe_header(&commit),
                Ok(LogHeader {
                    event: RUN_STARTED.to_owned(),
                    schema,
                }),
                "a terminated schema-{schema} header was not committed"
            );
            assert_eq!(commit.len(), torn.len() + 1);

            // And through the composite entry point, where a torn line must
            // outrank whatever its bytes claim about the schema.
            assert_eq!(
                select_reader_with(&torn, LATEST_LEGACY_SCHEMA),
                Err(SchemaRefusal::NoCommittedHeader),
                "an uncommitted schema-{schema} header reached selection"
            );
        }
    }

    #[test]
    fn a_committed_header_outranks_every_kind_of_damage_after_it() {
        // The converse of the torn-first-line rule, at the composite entry
        // point: line 1 is committed and above the ceiling, so the refusal is
        // fixed before anything later is looked at. A selector that inspected
        // the tail would report "nothing committed" for a log whose first line
        // records exactly what is wrong with it.
        let head = committed(RUN_STARTED, Some(5));
        let tails: [&[u8]; 5] = [
            b"",
            b"{\"event\":",
            b"{\"event\":\"task_merged\"}",
            b"\x80\x81\x82",
            b"{\"event\":\"run_started\",\"data\":{\"schema\":1}}\n{ broken",
        ];
        for tail in tails {
            let mut log = head.clone();
            log.extend_from_slice(tail);
            assert_eq!(
                select_reader_with(&log, LATEST_LEGACY_SCHEMA),
                Err(SchemaRefusal::NewerThanReadable {
                    schema: 5,
                    ceiling: LATEST_LEGACY_SCHEMA
                }),
                "damage after a committed header changed the refusal"
            );
        }

        // And the mirror: an uncommitted first line stays uncommitted however
        // newsworthy its bytes are.
        for schema in [1_u32, 5, 9, u32::MAX] {
            let torn = header_line(RUN_STARTED, Some(schema)).into_bytes();
            assert_eq!(
                select_reader_with(&torn, LATEST_LEGACY_SCHEMA),
                Err(SchemaRefusal::NoCommittedHeader),
                "uncommitted bytes claiming schema {schema} were selected on"
            );
        }
    }

    // ==================================================================
    // Line 1 is the header, and nothing repairs it
    // ==================================================================

    #[test]
    fn no_later_line_repairs_any_first_line_refusal() {
        // Every first-line refusal state, each paired with a perfect later
        // header whose schema is chosen independently of line 1. A probe that
        // fell through on a parse error, on invalid UTF-8, on a blank line, on
        // a wrong tag, or on a missing schema would find that later header and
        // read a rewritten log as a sound one — which refusals[22] says is
        // never repaired.
        let first_lines: Vec<(&str, Vec<u8>, SchemaRefusal)> = vec![
            (
                "malformed JSON",
                b"{broken\n".to_vec(),
                SchemaRefusal::FirstLineUnreadable {
                    detail: String::new(),
                },
            ),
            (
                "truncated object",
                b"{\"event\":\"run_started\",\n".to_vec(),
                SchemaRefusal::FirstLineUnreadable {
                    detail: String::new(),
                },
            ),
            (
                "invalid UTF-8",
                b"{\"event\":\"run_\x80started\"}\n".to_vec(),
                SchemaRefusal::FirstLineUnreadable {
                    detail: String::new(),
                },
            ),
            (
                "blank line",
                b"\n".to_vec(),
                SchemaRefusal::FirstLineUnreadable {
                    detail: String::new(),
                },
            ),
            (
                "whitespace-only line",
                b"   \t \n".to_vec(),
                SchemaRefusal::FirstLineUnreadable {
                    detail: String::new(),
                },
            ),
            (
                "a schema-bearing wrong tag",
                committed("task_merged", Some(3)),
                SchemaRefusal::RunStartedNotFirst {
                    found: "task_merged".to_owned(),
                },
            ),
            (
                "run_started without a schema",
                committed(RUN_STARTED, None),
                SchemaRefusal::HeaderWithoutSchema,
            ),
        ];

        for (label, line_one, expected) in first_lines {
            let alone = probe_header(&line_one);
            for later in [1_u32, 2, LATEST_LEGACY_SCHEMA, TOPOLOGY_SCHEMA, 7] {
                let mut log = line_one.clone();
                log.extend_from_slice(&hostile_later_header(later));
                let observed = probe_header(&log);
                assert_eq!(
                    observed, alone,
                    "{label}: a later schema-{later} header changed the line-1 answer"
                );
                match (&expected, &observed) {
                    (
                        SchemaRefusal::FirstLineUnreadable { .. },
                        Err(SchemaRefusal::FirstLineUnreadable { .. }),
                    ) => {}
                    (want, Err(got)) => assert_eq!(want, got, "{label}"),
                    (_, Ok(header)) => panic!("{label} was accepted as {header:?}"),
                }
                // And through the composite selector, where a repaired header
                // would silently choose a reader for the wrong model.
                assert!(
                    select_reader_with(&log, LATEST_LEGACY_SCHEMA).is_err(),
                    "{label}: selection accepted a log whose first line refuses"
                );
                assert!(select_reader(&log).is_err(), "{label}");
            }
        }

        // The one case a suffix is allowed not to change: an accepted header
        // ignores everything after it. Stated so the assertions above cannot
        // be satisfied by refusing every multi-line log.
        let mut good = committed(RUN_STARTED, Some(1));
        good.extend_from_slice(&hostile_later_header(TOPOLOGY_SCHEMA));
        assert_eq!(
            probe_header(&good),
            Ok(LogHeader {
                event: RUN_STARTED.to_owned(),
                schema: 1,
            })
        );
    }

    #[test]
    fn a_schema_read_out_of_invalid_committed_bytes_is_not_a_header() {
        // A committed first line that will not parse is a rewritten log,
        // whatever recognizable text it contains. Scanning it for a `schema`
        // token would let corruption choose the reader — and would report a
        // newer-schema refusal, sending the operator to upgrade tactus for a
        // file that is damaged.
        let damaged: [&[u8]; 4] = [
            b"{\"event\":\"run_started\",\"data\":{\"schema\":9},BROKEN\n",
            b"{\"event\":\"run_started\",\"data\":{\"schema\":259}\n",
            b"\"schema\":4\n",
            b"{\"event\":\"run_started\",\"data\":{\"schema\":\n",
        ];
        for bytes in damaged {
            assert!(
                matches!(
                    probe_header(bytes),
                    Err(SchemaRefusal::FirstLineUnreadable { .. })
                ),
                "{} was not treated as a rewritten log",
                String::from_utf8_lossy(bytes)
            );
            assert!(
                matches!(
                    select_reader_with(bytes, LATEST_LEGACY_SCHEMA),
                    Err(SchemaRefusal::FirstLineUnreadable { .. })
                ),
                "{} reached schema selection",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn one_physical_line_holds_exactly_one_event() {
        // A decoder that took the first JSON value off the line and stopped
        // would accept a line carrying two records, or a record followed by
        // anything at all. Both are newline-terminated lines that are not a
        // valid event, which refusals[22] classifies as a rewritten log.
        let one = header_line(RUN_STARTED, Some(3));
        let hostile: Vec<Vec<u8>> = vec![
            format!("{one}{one}\n").into_bytes(),
            format!("{one} trailing junk\n").into_bytes(),
            format!("{one},\n").into_bytes(),
            format!("{one}{{\"event\":\"task_merged\"}}\n").into_bytes(),
            format!("[{one}]\n").into_bytes(),
        ];
        for bytes in hostile {
            assert!(
                matches!(
                    probe_header(&bytes),
                    Err(SchemaRefusal::FirstLineUnreadable { .. })
                ),
                "a line holding more than one value was accepted: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        // The single value it is built from is accepted, so the cases above
        // fail for the reason claimed.
        assert_eq!(
            probe_header(format!("{one}\n").as_bytes()),
            Ok(LogHeader {
                event: RUN_STARTED.to_owned(),
                schema: 3,
            })
        );
    }

    // ==================================================================
    // The first event's tag
    // ==================================================================

    #[test]
    fn the_first_tag_is_compared_exactly_and_reported_verbatim() {
        // Near misses, not an unrelated tag: a case-normalizing or trimming
        // comparison accepts a header no writer of this project ever wrote,
        // and `found` is what tells the operator which one they have.
        for found in [
            "RUN_STARTED",
            "Run_Started",
            "run started",
            "run-started",
            " run_started",
            "run_started ",
            "run_started\u{200b}",
            "",
            "task_merged",
        ] {
            let log = committed(found, Some(3));
            assert_eq!(
                probe_header(&log),
                Err(SchemaRefusal::RunStartedNotFirst {
                    found: found.to_owned()
                }),
                "`{found}` was not refused verbatim"
            );
            assert_eq!(
                select_reader_with(&log, LATEST_LEGACY_SCHEMA),
                Err(SchemaRefusal::RunStartedNotFirst {
                    found: found.to_owned()
                }),
                "`{found}` survived composition"
            );
        }
        assert_eq!(
            probe_header(&committed(RUN_STARTED, Some(3))),
            Ok(LogHeader {
                event: RUN_STARTED.to_owned(),
                schema: 3,
            })
        );
    }

    #[test]
    fn a_non_run_started_first_line_refuses_whatever_schema_it_carries() {
        // The existing case correlates the wrong tag with an absent schema, so
        // a guard that refused only schema-less non-headers passes it. The tag
        // is decided before the schema is read, at every schema class.
        for schema in [
            None,
            Some(1),
            Some(LATEST_LEGACY_SCHEMA),
            Some(TOPOLOGY_SCHEMA),
            Some(9),
        ] {
            let log = committed("task_merged", schema);
            assert_eq!(
                probe_header(&log),
                Err(SchemaRefusal::RunStartedNotFirst {
                    found: "task_merged".to_owned()
                }),
                "a task_merged header carrying schema {schema:?} was read"
            );
            assert_eq!(
                select_reader(&log),
                Err(SchemaRefusal::RunStartedNotFirst {
                    found: "task_merged".to_owned()
                })
            );
        }
    }

    #[test]
    fn a_first_line_that_is_not_an_event_envelope_is_unreadable_rather_than_wrong_tagged() {
        // `refusals` distinguishes a log that begins with the wrong event from
        // a committed line that is not a valid event at all, and they carry
        // different consequences: the second is a rewritten log, never
        // repaired. A defaulted `event` field collapses the two and reports a
        // rewritten log as a header with an empty tag.
        let not_envelopes: [&[u8]; 9] = [
            b"{}\n",
            b"{\"data\":{\"schema\":3}}\n",
            b"{\"event\":null}\n",
            b"{\"event\":42}\n",
            b"{\"event\":[\"run_started\"]}\n",
            b"[]\n",
            b"1\n",
            b"\"run_started\"\n",
            b"null\n",
        ];
        for bytes in not_envelopes {
            let observed = probe_header(bytes);
            assert!(
                matches!(observed, Err(SchemaRefusal::FirstLineUnreadable { .. })),
                "{} was classified as {observed:?}",
                String::from_utf8_lossy(bytes)
            );
            let Err(SchemaRefusal::FirstLineUnreadable { detail }) = observed else {
                unreachable!("asserted above")
            };
            assert!(
                !detail.trim().is_empty(),
                "the refusal for {} says nothing about why",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    // ==================================================================
    // Refusal messages: the numbers keep their roles
    // ==================================================================

    #[test]
    fn the_newer_schema_diagnostics_bind_each_number_to_its_role() {
        // Asserting that both numerals appear proves nothing about which is
        // which, and a diagnostic that swaps them tells the operator their
        // binary reads a schema newer than the log — the opposite of why it
        // refused, and an instruction to do nothing.
        for (schema, ceiling) in [(9_u32, 7_u32), (5, 3), (4, 2), (256, 255), (u32::MAX, 0)] {
            let rendered = SchemaRefusal::NewerThanReadable { schema, ceiling }.to_string();
            assert!(
                rendered.contains(&format!("event schema {schema}")),
                "{rendered}"
            );
            assert!(
                rendered.contains(&format!("reads up to schema {ceiling}")),
                "{rendered}"
            );
        }

        for (schema, ceiling) in [
            (TOPOLOGY_SCHEMA, 2_u32),
            (TOPOLOGY_SCHEMA, 0),
            (TOPOLOGY_SCHEMA, LATEST_LEGACY_SCHEMA),
        ] {
            let rendered = SchemaRefusal::TopologyLogUnreadable { schema, ceiling }.to_string();
            assert!(
                rendered.contains(&format!("event schema {schema}")),
                "{rendered}"
            );
            assert!(
                rendered.contains(&format!("reads up to schema {ceiling}")),
                "{rendered}"
            );
            assert!(
                rendered.contains(&format!("schema-{ceiling} run")),
                "the sentence about what the log will never become names the wrong \
                 number: {rendered}"
            );
        }
    }

    #[test]
    fn the_no_upgrade_refusal_never_advises_the_upgrade_it_refuses() {
        // The packet does not freeze this sentence and this test does not
        // pretend it does. What it does fix is the one thing the remediation
        // may not say: a refusal that tells the operator to append the
        // transition and carry on counsels violating INV-03, and the run it
        // produces is a schema-3 log reinterpreted as a topology one.
        for (from, to) in [(3_u32, TOPOLOGY_SCHEMA), (1, 4), (2, 9), (0, u32::MAX)] {
            let rendered = SchemaRefusal::NoUpgradePath { from, to }.to_string();
            assert!(rendered.contains(&format!("{from} -> {to}")), "{rendered}");
            assert!(
                rendered.contains("start a new run"),
                "the refusal does not say what to do instead: {rendered}"
            );
            assert!(
                !rendered.contains("continue"),
                "the refusal advises continuing the existing run: {rendered}"
            );
            assert!(
                !rendered.contains("append"),
                "the refusal advises appending the transition it refuses: {rendered}"
            );
        }

        let not_an_upgrade = SchemaRefusal::NotAnUpgrade { from: 2, to: 2 }.to_string();
        assert!(!not_an_upgrade.contains("continue"), "{not_an_upgrade}");
        assert!(!not_an_upgrade.contains("append"), "{not_an_upgrade}");
    }

    // ==================================================================
    // Activation
    // ==================================================================

    #[test]
    fn the_activation_constant_is_asserted_outside_the_test_configuration() {
        // The four `const _` assertions beside `MAX_READABLE_SCHEMA` are the
        // load-bearing ones: they are evaluated in the ordinary build, so an
        // activation that is `Inactive` under `cfg(test)` and `Active`
        // otherwise fails to compile rather than shipping a binary that folds
        // schema-4 logs. This test records that they exist and agrees with
        // them, and is deliberately not the proof.
        const { assert!(matches!(TOPOLOGY_ACTIVATION, TopologyActivation::Inactive)) };
        const { assert!(MAX_READABLE_SCHEMA == 3) };
        assert_eq!(TOPOLOGY_ACTIVATION, TopologyActivation::Inactive);
        assert_eq!(MAX_READABLE_SCHEMA, LATEST_LEGACY_SCHEMA);
        assert!(select_reader(&committed(RUN_STARTED, Some(TOPOLOGY_SCHEMA))).is_err());
    }
}
