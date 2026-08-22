//! The Event funnel: the one place in this crate that writes `events.jsonl`.
//!
//! `decisions.effect_site_inventory.mechanism` puts this module in the
//! allowlist's *funnel* section and says what that buys: "`EventLog::open` and
//! `EventLog::append` are classified as the Event funnel (site-taking) rather
//! than as wrappers, and the raw writer they wrap is reachable only inside
//! `src/events/log.rs`". `EffectSiteId::module` for [`FunnelGroup::Event`] names
//! this file, so the site inventory already pointed here before the code did.
//!
//! Three things live here that did not live in `src/events.rs`:
//!
//! 1. **Sites.** Every effectful entry takes an [`EventSite`] by value, and the
//!    funnel calls `hook(Before, site)` → primitive → `hook(After, site)` around
//!    it, so hooks exist for every site by construction. The two Legacy-scoped
//!    sites are what schema-1..3 callers pass.
//! 2. **The error contract.** `INV-02`: "an append that was entered and returned
//!    an error never mutates the live fold, is never retried". This funnel makes
//!    "never retried" a property of the handle rather than a rule call sites are
//!    asked to remember — an `Err` after the append was entered poisons the
//!    handle, and every later append through it fails naming the point that
//!    poisoned it, until the log is reopened through `Event.OpenLog`.
//! 3. **The stable-prefix helper.** `coordinator_integration.stable_prefix_barrier`
//!    in one function: open, normalize the torn tail, sync the surviving prefix,
//!    reread it, prove its bytes *and boundary* unchanged, and hand exactly
//!    those bytes to the checked replay. It is the only path by which a topology
//!    write command obtains a fold from an existing log.
//!
//! # What is *not* here, and why
//!
//! The Legacy sites carry the pre-move behaviour byte for byte.
//! `EventSite::LegacyOpenLog.sub_effects()` is `&[]` in the frozen inventory —
//! no `Create`, no `TruncateTornTail`, no `SyncPrefix` — so the legacy open must
//! *not* acquire the barrier's extra fsyncs. That is not a shortcut: PR5's
//! `production_effect` is "the event-log writer keeps its exact write/flush/sync
//! and torn-tail truncation semantics", and a directory fsync that the pre-move
//! open never performed is a new way for a legacy open to fail. The frozen enum
//! and the frozen production-effect sentence agree, and this module follows
//! both.
// Allowlist placement: the **funnel section** of `effects/allowlist.toml`, which
// carries this module's review clause -- effects only inside site-taking APIs,
// no writable handle returned. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use super::{Event, EventBody};
use crate::error::TactusError;
use crate::topology::effects::{
    EffectSiteId, EventSite, HookHarness, HookPhase, Injection, InjectionMode, SubEffectPoint,
};
use crate::topology::events::{TopologyEvent, TopologyEventBody};
use crate::topology::fold::{FrozenInputs, TopologyFold};
use crate::util::{DurabilityLedger, DurableStep};

// ---------------------------------------------------------------------------
// The observer
// ---------------------------------------------------------------------------

/// What the funnel tells whoever is watching, and what it asks them.
///
/// The shape is [`crate::agent::proc::SpawnHooks`]'s, for the same reason: a
/// hook is parent-executed code, production passes an observer that answers
/// [`Injection::Proceed`] to everything, and the ST-07 subset passes one that
/// records into PR3's [`HookHarness`] and returns whatever the suite armed.
///
/// The site is a parameter rather than a constant because this group has seven
/// of them and two are Legacy-scoped: an observer that could not tell
/// `Event.Append` from `Event.LegacyAppend` would let a legacy append report
/// coverage for a Shared site.
pub trait EventHooks {
    /// The funnel is about to run, or has just run, `site`'s primitive.
    ///
    /// No injection: `HookPhase::Before` and `HookPhase::After` are
    /// reachability, and [`HookHarness::hook`] answers `Proceed` to both by
    /// construction. They exist so that "hooks exist for every site by
    /// construction" is true of this group too.
    fn phase(&mut self, _site: EventSite, _phase: HookPhase) {}

    /// The funnel reached `point` at the coordinate `mode`'s fault belongs at.
    ///
    /// Consulted once per (point, mode) the funnel offers — never once per
    /// point — because the harness is keyed by `(site, point, mode)` and the two
    /// modes of a point do not always fire at the same coordinate.
    fn point(
        &mut self,
        _site: EventSite,
        _point: SubEffectPoint,
        _mode: InjectionMode,
    ) -> Injection {
        Injection::Proceed
    }

    /// Which of the two durable shapes T-APPEND tables for a **kill** at
    /// `Written` this observer wants the funnel to leave behind.
    ///
    /// `SubEffectPoint::Written`'s frozen doc says its kill entry is "the whole
    /// of what the packet tables for a written append — torn: truncated on the
    /// next open, previous prefix; complete-unsynced: either prefix", and
    /// `WrittenFull`'s says a kill there "leaves the complete-unsynced prefix
    /// Written's kill entry already covers". One key, two durable shapes: the
    /// funnel cannot choose between them and the harness cannot say, so the
    /// observer does. Production never answers anything but the default, and
    /// with the default the line is written by a single `write_all` exactly as
    /// the pre-move writer wrote it.
    fn written_kill_shape(&mut self, _site: EventSite) -> WrittenShape {
        WrittenShape::Complete
    }

    /// Where this observer wants the funnel's durability primitives recorded,
    /// **in order and including the ones [`Self::synced`] does not see**.
    ///
    /// [`Self::synced`] is keyed by site, point and target — it answers "which
    /// coordinate synced what". It is wired into `sync_log_file` and
    /// `sync_directory`, the two *open-path* helpers, so the append's own
    /// `write_all`, `flush` and `sync_data` emitted no record at all and the
    /// truncation emitted none either. Seven catalogue mutations lived in that
    /// gap: splitting the line's `write_all` in two, deleting the `flush`,
    /// retrying a failed primitive, moving the `Synced` consults to before the
    /// sync, and syncing the *pre*-truncation length at open
    /// (`PR5-EVENTS-011/013/032/035/044/049/051`).
    ///
    /// This is the other question — "what did the funnel do, in what order" —
    /// and it is a *handle* rather than a callback so a funnel body can record
    /// into it without a second mutable borrow of the observer. The default
    /// records nothing, which is what production passes.
    fn durability_ledger(&self) -> DurabilityLedger {
        DurabilityLedger::off()
    }

    /// A sync completed. The record is the funnel's own ledger of what it made
    /// durable and how much of it.
    ///
    /// `proof_tests[9]` asks for exactly this: "open syncs the surviving prefix
    /// (**the sync ledger** shows the synced length equal to the file length
    /// after open, incl. a line written unsynced by an earlier handle)". An
    /// fsync is not observable from user space, so the length it reports is
    /// checked against the filesystem's own answer rather than against itself.
    fn synced(&mut self, _record: &SyncRecord) {}
}

/// Which durable shape a kill at `Written` leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrittenShape {
    /// A partial line with no terminating newline: T-APPEND (w), the torn tail
    /// the next open truncates.
    Torn,
    /// The whole newline-terminated line, unsynced: T-APPEND (u), the prefix
    /// the next open's barrier makes durable.
    Complete,
}

/// What one sync made durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRecord {
    /// The site whose funnel synced.
    pub site: EventSite,
    /// The point it synced at.
    pub point: SubEffectPoint,
    /// What was synced.
    pub target: SyncTarget,
    /// The log's byte length at the moment of the sync.
    pub len: u64,
    /// The log.
    pub path: PathBuf,
}

/// What a sync was applied to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTarget {
    /// The log file itself (`sync_all`: fsync / `FlushFileBuffers`).
    LogFile,
    /// The directory holding it, so the name is durable too.
    LogDirectory,
}

/// What production passes: nothing armed, nothing recorded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEventHooks;

impl EventHooks for NoEventHooks {}

/// The ST-07 observer: records into PR3's harness and returns what was armed.
#[derive(Debug, Clone)]
pub struct HarnessEventHooks {
    harness: Arc<Mutex<HookHarness>>,
}

impl HarnessEventHooks {
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

impl EventHooks for HarnessEventHooks {
    fn phase(&mut self, site: EventSite, phase: HookPhase) {
        let mut harness = self
            .harness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        harness.hook(EffectSiteId::Event(site), phase);
    }

    fn point(&mut self, site: EventSite, point: SubEffectPoint, mode: InjectionMode) -> Injection {
        let mut harness = self
            .harness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        harness.hook(EffectSiteId::Event(site), HookPhase::Point { point, mode })
    }
}

/// Do what an observer answered at `point` of `site`.
///
/// [`Injection::Kill`] aborts, and it is `abort` rather than `panic!` or
/// `exit` for the reason [`crate::agent::proc`] gives: the claim under test is
/// what a process that dies **without running any cleanup** leaves durable, and
/// both of the others run destructors.
fn apply(
    injection: Injection,
    site: EventSite,
    point: SubEffectPoint,
    path: &Path,
) -> Result<(), TactusError> {
    match injection {
        Injection::Proceed => Ok(()),
        Injection::Kill => std::process::abort(),
        Injection::Error => Err(injected(site, point, path)),
    }
}

/// The `Err` an error-return injection produces.
///
/// Deliberately *not* [`TactusError::Io`]: a real write/flush/sync failure keeps
/// the exact error value the pre-move writer returned, which is the whole of
/// "the legacy engine's handling of a returned append error is unchanged", so a
/// simulated one must be distinguishable from it. Same reasoning as
/// [`crate::agent::proc::AMBIENT_REFUSAL_SIMULATED`].
fn injected(site: EventSite, point: SubEffectPoint, path: &Path) -> TactusError {
    TactusError::EventLog {
        path: path.to_path_buf(),
        message: format!(
            "{INJECTED_PREFIX}`{}` was made to return an error at its `{}` point",
            EffectSiteId::Event(site),
            point.name()
        ),
    }
}

/// The opening words of every injected Event-funnel error, so a caller and a
/// test can recognise a simulated failure without matching a whole sentence.
pub const INJECTED_PREFIX: &str = "simulated fault: ";

// ---------------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------------

/// The append-only writer. One per run, held by the engine — `tactus answer`
/// deliberately does not write here (it drops a file the engine ingests), so
/// the log has exactly one writer and interleaved lines are impossible.
///
/// The `File` is private and no method hands one out: the allowlist's funnel
/// section requires each entry to "perform effects only inside site-taking APIs
/// and never to return writable handles", and this type is the reason a
/// schema-4 append outside this module cannot be written at all.
///
/// `expected_failures_refusals`: "a schema-4 append outside the Event funnel
/// does not compile". Two of the three ways to try it are type errors, and the
/// fixtures below pin the *reason* rather than the failure — a `compile_fail`
/// block with an error code fails the test if the code compiles **or if it
/// fails for a different reason**, which is what a bare "this does not build"
/// fixture cannot do. (The third way — writing the bytes with `std::fs` from
/// another module — is not a type error and is denied by the effect denylist;
/// see `effects/allowlist.toml`.)
///
/// Reaching the handle:
///
/// ```compile_fail,E0616
/// use std::path::Path;
/// use tactus::events::EventLog;
/// use tactus::topology::effects::EventSite;
///
/// let mut warnings = Vec::new();
/// let log = EventLog::open(EventSite::OpenLog, Path::new("events.jsonl"), &mut warnings)
///     .expect("open");
/// let mut handle = log.file;
/// ```
///
/// Handing a schema-4 event to the schema-1..3 append:
///
/// ```compile_fail,E0308
/// use std::path::Path;
/// use tactus::events::EventLog;
/// use tactus::topology::effects::EventSite;
/// use tactus::topology::events::{DeferWaitElapsed4, TopologyEvent, TopologyEventBody};
///
/// let event = TopologyEvent {
///     ts: "2026-08-20T09:41:02Z".to_owned(),
///     body: TopologyEventBody::DeferWaitElapsed {
///         data: DeferWaitElapsed4 { waited_ms: 1, round: 1 },
///     },
/// };
/// let mut warnings = Vec::new();
/// let mut log = EventLog::open(EventSite::LegacyOpenLog, Path::new("events.jsonl"), &mut warnings)
///     .expect("open");
/// log.append(EventSite::LegacyAppend, event).expect("append");
/// ```
#[derive(Debug)]
pub struct EventLog {
    path: PathBuf,
    file: File,
    /// Which of the two open sites produced this handle. It decides which
    /// append sites the handle accepts, so a schema-3 log cannot be handed a
    /// schema-4 line and a legacy append cannot emit Shared-scoped evidence.
    opened_at: EventSite,
    /// The point an entered append returned `Err` at, if one did.
    ///
    /// INV-02: "an append that was entered and returned an error never mutates
    /// the live fold, is never retried". The mechanism note is explicit that
    /// this belongs to the funnel — "after an Err from a Written or Synced point
    /// the handle is poisoned (every later append through it fails until the log
    /// is reopened), so no caller can silently retry".
    /// The **site and point** an entered append returned `Err` at.
    ///
    /// The site as well as the point (`PR5-EVENTS-046`):
    /// `expected_failures_refusals[9]` is "an append on a poisoned handle
    /// returns an error naming the poisoning point", and one handle accepts
    /// `Append`, `AppendFirst` and `AppendInformational`, so "the poisoning
    /// point" is only half an identification. With the site absent, an
    /// implementation that named the *newly attempted* coordinate instead of
    /// the stored one could not be told from a correct one by any fixture that
    /// poisons and re-attempts through the same site — which was every fixture.
    poisoned: Option<(EventSite, SubEffectPoint)>,
}

impl EventLog {
    /// Open for appending, discarding an incomplete trailing record first.
    ///
    /// `site` is [`EventSite::LegacyOpenLog`] for a schema-1..3 caller and
    /// [`EventSite::OpenLog`] for the topology funnel; nothing else opens. See
    /// the module docs for why the two are not one code path.
    ///
    /// # Errors
    ///
    /// A site that is not an open site; any I/O error reading, truncating, or
    /// creating the log; and, for `Event.OpenLog` only, an injected or real
    /// failure at `Create`, `TruncateTornTail`, or `SyncPrefix`.
    pub fn open(
        site: EventSite,
        path: &Path,
        warnings: &mut Vec<String>,
    ) -> Result<Self, TactusError> {
        Self::open_hooked(site, path, warnings, &mut NoEventHooks)
    }

    /// [`Self::open`] with an observer attached.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_hooked(
        site: EventSite,
        path: &Path,
        warnings: &mut Vec<String>,
        hooks: &mut dyn EventHooks,
    ) -> Result<Self, TactusError> {
        Self::open_with_prefix(site, path, warnings, hooks).map(|(log, _)| log)
    }

    /// [`Self::open_hooked`], also handing back the normalized surviving prefix.
    ///
    /// Only the stable-prefix barrier needs those bytes — step (4) proves the
    /// reread equal to "the normalized prefix observed at open", and a second
    /// read of the file would be proving the file equal to itself.
    fn open_with_prefix(
        site: EventSite,
        path: &Path,
        warnings: &mut Vec<String>,
        hooks: &mut dyn EventHooks,
    ) -> Result<(Self, Vec<u8>), TactusError> {
        match site {
            EventSite::OpenLog => {
                hooks.phase(site, HookPhase::Before);
                let opened =
                    Self::open_funnel(site, path, warnings, hooks).map_err(|(_, error)| error);
                if opened.is_ok() {
                    hooks.phase(site, HookPhase::After);
                }
                opened
            }
            EventSite::LegacyOpenLog => {
                hooks.phase(site, HookPhase::Before);
                let opened = Self::open_legacy(site, path, warnings);
                if opened.is_ok() {
                    hooks.phase(site, HookPhase::After);
                }
                opened
            }
            other => Err(wrong_site(other, path, "an open site", OPEN_SITES)),
        }
    }

    /// `Event.LegacyOpenLog`. The pre-move `EventLog::open`, unchanged.
    ///
    /// A process killed mid-write can leave a line with no newline. Appending
    /// straight after it would splice the fragment and the next event into one
    /// unparseable line, losing both.
    ///
    /// Terminating the fragment with a newline instead is worse than it looks:
    /// it promotes a torn *tail*, which [`read_all`] recovers from, into an
    /// unparseable line in the *middle*, which [`read_all`] must treat as a
    /// rewritten log and refuse. So the fragment is truncated away. That is
    /// not rewriting history — those bytes are by construction an event that
    /// never finished being written, and no reader could ever have parsed
    /// them — and it keeps "damage anywhere but the end means corruption" a
    /// statement the reader can still trust.
    fn open_legacy(
        site: EventSite,
        path: &Path,
        warnings: &mut Vec<String>,
    ) -> Result<(Self, Vec<u8>), TactusError> {
        let io = |source| TactusError::Io {
            path: path.to_path_buf(),
            source,
        };
        // Truncate before taking the append handle, through a handle of its
        // own. On Windows an append-only handle is opened with
        // FILE_APPEND_DATA and *not* FILE_WRITE_DATA, so `set_len` on it fails
        // outright with access denied.
        let mut prefix = Vec::new();
        match crate::util::read_file_bounded(path) {
            Ok(existing) if !existing.is_empty() && existing.last() != Some(&b'\n') => {
                let keep = existing
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |index| index + 1);
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(io)?
                    .set_len(keep as u64)
                    .map_err(io)?;
                warnings.push(torn_tail_warning(path, existing.len() - keep));
                prefix.extend_from_slice(&existing[..keep]);
            }
            Ok(existing) => prefix = existing,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io(source)),
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io)?;
        Ok((
            Self {
                path: path.to_path_buf(),
                file,
                opened_at: site,
                poisoned: None,
            },
            prefix,
        ))
    }

    /// `Event.OpenLog`: create (and fsync the directory), truncate a torn tail,
    /// then sync the complete surviving prefix — the file, and the directory
    /// after a truncation changed the length.
    ///
    /// The error carries the [`BarrierStep`] it belongs to. The barrier gives
    /// `SyncPrefix` its own resume action ("leaves the prefix possibly
    /// non-durable and refuses the write command resumably"), so which step
    /// failed is a typed fact rather than something a caller reads out of a
    /// message.
    fn open_funnel(
        site: EventSite,
        path: &Path,
        warnings: &mut Vec<String>,
        hooks: &mut dyn EventHooks,
    ) -> Result<(Self, Vec<u8>), (BarrierStep, TactusError)> {
        let io = |source| {
            (
                BarrierStep::OpenLog,
                TactusError::Io {
                    path: path.to_path_buf(),
                    source,
                },
            )
        };
        let existing = match crate::util::read_file_bounded(path) {
            Ok(bytes) => Some(bytes),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(io(source)),
        };
        let created = existing.is_none();
        let mut truncated = false;
        let mut prefix = Vec::new();

        if let Some(existing) = existing {
            if !existing.is_empty() && existing.last() != Some(&b'\n') {
                let keep = existing
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |index| index + 1);
                // Same handle-of-its-own as the legacy path, and for the same
                // Windows reason.
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(io)?
                    .set_len(keep as u64)
                    .map_err(io)?;
                // The truncation is in the ledger so the two claims about it
                // are expressible: that the prefix sync **follows** it, and
                // that the length synced is the **shortened** one
                // (`PR5-EVENTS-011`, `PR5-EVENTS-013`). Neither is a statement
                // a trace holding only syncs can make.
                hooks
                    .durability_ledger()
                    .record(DurableStep::Truncated, path, keep as u64);
                warnings.push(torn_tail_warning(path, existing.len() - keep));
                truncated = true;
                prefix.extend_from_slice(&existing[..keep]);
                // The point's claim is true once the bytes are gone: "an
                // unterminated final line **was** truncated before the append
                // handle was taken".
                for mode in InjectionMode::ALL {
                    apply(
                        hooks.point(site, SubEffectPoint::TruncateTornTail, *mode),
                        site,
                        SubEffectPoint::TruncateTornTail,
                        path,
                    )
                    .map_err(|error| (BarrierStep::OpenLog, error))?;
                }
            } else {
                prefix = existing;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io)?;

        if created {
            // "create the log if absent and **fsync its directory**": the name
            // has to be durable, not just the (empty) contents.
            sync_directory(path, hooks, site, SubEffectPoint::Create)
                .map_err(|error| (BarrierStep::OpenLog, error))?;
            for mode in InjectionMode::ALL {
                apply(
                    hooks.point(site, SubEffectPoint::Create, *mode),
                    site,
                    SubEffectPoint::Create,
                    path,
                )
                .map_err(|error| (BarrierStep::OpenLog, error))?;
            }
        }

        // `SyncPrefix` is consulted **before** the sync, in both modes, because
        // that is where both of its tabled claims are true: "a kill before or at
        // SyncPrefix simply leaves the prefix for the next open to sync", and a
        // returned `Err` stands *in place of* a successful sync — "an Err from
        // SyncPrefix, or a kill before it, leaves the prefix possibly
        // non-durable and refuses the write command resumably".
        for mode in InjectionMode::ALL {
            apply(
                hooks.point(site, SubEffectPoint::SyncPrefix, *mode),
                site,
                SubEffectPoint::SyncPrefix,
                path,
            )
            .map_err(|error| (BarrierStep::SyncPrefix, error))?;
        }
        sync_log_file(&file, path, hooks, site)
            .map_err(|error| (BarrierStep::SyncPrefix, error))?;
        if truncated {
            // "and its directory after a truncation changed the length".
            sync_directory(path, hooks, site, SubEffectPoint::SyncPrefix)
                .map_err(|error| (BarrierStep::SyncPrefix, error))?;
        }

        Ok((
            Self {
                path: path.to_path_buf(),
                file,
                opened_at: site,
                poisoned: None,
            },
            prefix,
        ))
    }

    /// Append one schema-1..3 event and get it back **as it will be read back**.
    ///
    /// Returning the round-tripped event rather than the one just constructed
    /// is what keeps "the log is the source of truth" literally true. Anything
    /// the wire format cannot represent — a sub-millisecond duration, say —
    /// must not survive in the engine's memory either, or live state would
    /// quietly hold more than a replay could ever restore and the two would
    /// disagree in a way no amount of care at the call sites would catch.
    ///
    /// Flushed and synced before returning: §19 promises a crash or power loss
    /// is recoverable by replaying this file, which is only true if the event
    /// reached the disk before the work it describes carried on. A run emits
    /// tens of events, so the cost is noise beside a single attempt.
    ///
    /// # Errors
    ///
    /// A site that is not [`EventSite::LegacyAppend`]; a handle that is not a
    /// legacy handle; a poisoned handle; a value the wire format cannot carry
    /// (before the append is entered, so the handle stays usable); and any
    /// write, flush, or sync failure (after it is entered, so the handle is
    /// poisoned).
    pub fn append(&mut self, site: EventSite, body: EventBody) -> Result<Event, TactusError> {
        self.append_hooked(site, body, &mut NoEventHooks)
    }

    /// [`Self::append`] with an observer attached.
    ///
    /// # Errors
    ///
    /// As [`Self::append`].
    pub fn append_hooked(
        &mut self,
        site: EventSite,
        body: EventBody,
        hooks: &mut dyn EventHooks,
    ) -> Result<Event, TactusError> {
        if site != EventSite::LegacyAppend {
            return Err(wrong_site(
                site,
                &self.path,
                "the schema-1..3 append site",
                &[EventSite::LegacyAppend],
            ));
        }
        self.check_scope(site)?;
        self.check_poison()?;
        hooks.phase(site, HookPhase::Before);
        // Serialize and round-trip *before* the append is entered: a value the
        // wire cannot carry is not an outcome-unknown append, it is an append
        // that never happened, and `emit`'s contract is "a FoldError aborts
        // before any write".
        let event = Event::now(body);
        let mut line = serde_json::to_string(&event).map_err(|e| TactusError::EventLog {
            path: self.path.clone(),
            message: format!("serializing {}: {e}", event.body.kind()),
        })?;
        let written = serde_json::from_str(&line).map_err(|e| TactusError::EventLog {
            path: self.path.clone(),
            message: format!(
                "{} does not survive its own wire format ({e}); the log could not be replayed",
                event.body.kind()
            ),
        })?;
        line.push('\n');
        self.write_committed(site, line.as_bytes(), hooks)?;
        hooks.phase(site, HookPhase::After);
        Ok(written)
    }

    /// Append the exact bytes of one schema-4 event.
    ///
    /// `coordinator_integration.emit` is "build event → serialize → round-trip →
    /// plan_transition → **append the exact bytes** through the Event funnel",
    /// so the funnel takes bytes that were already round-tripped rather than an
    /// event it would serialize a second time. [`TopologyLine`] is the only way
    /// to make some, and making one *is* the round-trip.
    ///
    /// # Errors
    ///
    /// A site that is not an append site or does not match the line's kind; a
    /// legacy handle; a poisoned handle; and any write, flush, or sync failure.
    pub fn append_topology(
        &mut self,
        site: EventSite,
        line: &TopologyLine,
    ) -> Result<(), TactusError> {
        self.append_topology_hooked(site, line, &mut NoEventHooks)
    }

    /// [`Self::append_topology`] with an observer attached.
    ///
    /// # Errors
    ///
    /// As [`Self::append_topology`].
    pub fn append_topology_hooked(
        &mut self,
        site: EventSite,
        line: &TopologyLine,
        hooks: &mut dyn EventHooks,
    ) -> Result<(), TactusError> {
        if !TOPOLOGY_APPEND_SITES.contains(&site) {
            return Err(wrong_site(
                site,
                &self.path,
                "a schema-4 append site",
                TOPOLOGY_APPEND_SITES,
            ));
        }
        self.check_scope(site)?;
        if line.site() != site {
            return Err(TactusError::EventLog {
                path: self.path.clone(),
                message: format!(
                    "`{}` belongs at `Event.{}`, not `Event.{}`; filing it under the wrong site \
                     would file its faults under the wrong registry coordinate",
                    line.kind(),
                    line.site().name(),
                    site.name()
                ),
            });
        }
        self.check_poison()?;
        hooks.phase(site, HookPhase::Before);
        self.write_committed(site, line.committed_bytes(), hooks)?;
        hooks.phase(site, HookPhase::After);
        Ok(())
    }

    /// The one write path: `write_all` → `flush` → `sync_data`, with the three
    /// parent-side points around it.
    ///
    /// `bytes` already ends in its newline. The newline is the commit marker, so
    /// it is part of the same `write_all` and never a second one — splitting it
    /// would make every append pass through the torn state on purpose.
    fn write_committed(
        &mut self,
        site: EventSite,
        bytes: &[u8],
        hooks: &mut dyn EventHooks,
    ) -> Result<(), TactusError> {
        // (e-w): "write_all failed after a partial write". The funnel performs
        // the partial write itself, because an injection mode is defined as
        // returning Err "after performing or partially performing the
        // primitive" and a torn tail nobody wrote is not that shape.
        let ledger = hooks.durability_ledger();
        if hooks.point(site, SubEffectPoint::Written, InjectionMode::ErrorReturn)
            == Injection::Error
        {
            let cut = torn_cut(bytes);
            let partial =
                self.write_or_poison(site, &bytes[..cut], SubEffectPoint::Written, &ledger);
            self.poisoned = Some((site, SubEffectPoint::Written));
            return Err(partial
                .err()
                .unwrap_or_else(|| injected(site, SubEffectPoint::Written, &self.path)));
        }

        match hooks.written_kill_shape(site) {
            WrittenShape::Torn => {
                // Only an observer asks for this, and only to place a kill in
                // the torn half of `Written`'s kill entry. Production never
                // reaches it, so production still writes the line once.
                let cut = torn_cut(bytes);
                self.write_or_poison(site, &bytes[..cut], SubEffectPoint::Written, &ledger)?;
                self.at_point(hooks, site, SubEffectPoint::Written, InjectionMode::Kill)?;
                self.write_or_poison(site, &bytes[cut..], SubEffectPoint::Written, &ledger)?;
            }
            WrittenShape::Complete => {
                self.write_or_poison(site, bytes, SubEffectPoint::Written, &ledger)?;
                self.at_point(hooks, site, SubEffectPoint::Written, InjectionMode::Kill)?;
            }
        }

        // (e-u): "write_all succeeded (full line, newline present) and flush or
        // sync_data returned an error". `WrittenFull` declares error-return
        // only — a kill here leaves the shape `Written`'s kill entry covers.
        self.at_point(
            hooks,
            site,
            SubEffectPoint::WrittenFull,
            InjectionMode::ErrorReturn,
        )?;
        let flushed = self.file.flush();
        ledger.record(DurableStep::Flushed, &self.path, 0);
        if let Err(error) = flushed {
            self.poisoned = Some((site, SubEffectPoint::WrittenFull));
            return Err(self.io(error));
        }

        // Fused with its ledger entry for the reason `sync_log_file` gives, and
        // for a second one here: the `Synced` consults below are the coordinate
        // `(e-s)` names — "sync_data returned an error **after the data reached
        // the disk**" — and an observer can only tell that coordinate from the
        // one before the sync by reading this entry at the moment it is
        // consulted (`PR5-EVENTS-032`, `PR5-EVENTS-035`).
        let synced = self.file.sync_data();
        let durable = self.file.metadata().map(|meta| meta.len()).unwrap_or(0);
        ledger.record(DurableStep::SyncedData, &self.path, durable);
        if let Err(error) = synced {
            self.poisoned = Some((site, SubEffectPoint::Synced));
            return Err(self.io(error));
        }
        // (e-s): "sync_data returned an error **after the data reached the
        // disk**", which is why this coordinate is after the sync rather than
        // instead of it. Indistinguishable from (e-u) to the process, and the
        // durable shape is the same.
        for mode in InjectionMode::ALL {
            self.at_point(hooks, site, SubEffectPoint::Synced, *mode)?;
        }
        Ok(())
    }

    /// Consult one (point, mode) coordinate. Anything but `Proceed` past the
    /// entry of an append poisons the handle, whichever mode produced it: the
    /// contract is about the *outcome* being unknown, not about how it became
    /// unknown.
    fn at_point(
        &mut self,
        hooks: &mut dyn EventHooks,
        site: EventSite,
        point: SubEffectPoint,
        mode: InjectionMode,
    ) -> Result<(), TactusError> {
        let answer = hooks.point(site, point, mode);
        if answer == Injection::Proceed {
            return Ok(());
        }
        self.poisoned = Some((site, point));
        apply(answer, site, point, &self.path)
    }

    /// A real write, flush, or sync failure keeps [`TactusError::Io`] — the
    /// exact value the pre-move writer returned — so a legacy caller's handling
    /// of it is unchanged. The point it reached is recorded on the handle, and
    /// the *next* append through the handle is the error that names it.
    fn io(&self, source: std::io::Error) -> TactusError {
        TactusError::Io {
            path: self.path.clone(),
            source,
        }
    }

    fn write_or_poison(
        &mut self,
        site: EventSite,
        bytes: &[u8],
        point: SubEffectPoint,
        ledger: &DurabilityLedger,
    ) -> Result<(), TactusError> {
        let written = self.file.write_all(bytes);
        // Recorded whatever it returned, so "exactly one primitive attempt and
        // one error" is a countable claim rather than a description
        // (`PR5-EVENTS-044`).
        ledger.record(DurableStep::Wrote, &self.path, bytes.len() as u64);
        if let Err(error) = written {
            self.poisoned = Some((site, point));
            return Err(self.io(error));
        }
        Ok(())
    }

    fn check_scope(&self, site: EventSite) -> Result<(), TactusError> {
        let legacy_handle = self.opened_at == EventSite::LegacyOpenLog;
        let legacy_append = site == EventSite::LegacyAppend;
        if legacy_handle == legacy_append {
            return Ok(());
        }
        Err(TactusError::EventLog {
            path: self.path.clone(),
            message: format!(
                "a handle opened at `Event.{}` does not accept `Event.{}`: mixing the scopes would \
                 put schema-4 lines in a schema-3 log, and would let a legacy append report \
                 coverage for a Shared site",
                self.opened_at.name(),
                site.name()
            ),
        })
    }

    fn check_poison(&self) -> Result<(), TactusError> {
        match self.poisoned {
            None => Ok(()),
            // The **stored** coordinate, never the one now being attempted:
            // the message identifies where the outcome became unknown, and the
            // later attempt is not that place.
            Some((site, point)) => Err(TactusError::EventLog {
                path: self.path.clone(),
                message: format!(
                    "{POISONED_PREFIX}an append returned an error at `Event.{}`'s `{}` point, so \
                     this handle's outcome is unknown and nothing may be appended through it. \
                     Reopen the log through `Event.OpenLog` and establish the stable-prefix \
                     barrier.",
                    site.name(),
                    point.name()
                ),
            }),
        }
    }

    /// The point an entered append returned `Err` at, or `None` while the handle
    /// is usable.
    #[must_use]
    pub fn poisoned_at(&self) -> Option<SubEffectPoint> {
        self.poisoned.map(|(_, point)| point)
    }

    /// The site the poisoning append was made at, or `None` while the handle is
    /// usable.
    #[must_use]
    pub fn poisoned_site(&self) -> Option<EventSite> {
        self.poisoned.map(|(site, _)| site)
    }

    /// Which site this handle was opened at.
    #[must_use]
    pub fn opened_at(&self) -> EventSite {
        self.opened_at
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The opening words of every poisoned-handle refusal.
pub const POISONED_PREFIX: &str = "the event log handle is poisoned: ";

/// The two sites [`EventLog::open`] accepts.
pub const OPEN_SITES: &[EventSite] = &[EventSite::OpenLog, EventSite::LegacyOpenLog];

/// The three sites [`EventLog::append_topology`] accepts.
pub const TOPOLOGY_APPEND_SITES: &[EventSite] = &[
    EventSite::AppendFirst,
    EventSite::Append,
    EventSite::AppendInformational,
];

/// The site an event belongs at.
///
/// `Event.AppendFirst` is "run_started; the commitment boundary",
/// `Event.AppendInformational` is "a lenient informational append", and
/// `Event.Append` is "every later transaction append". The lenient/transactional
/// split is not re-derived here: `TopologyEventBody::is_transaction` is PR3's
/// and frozen, and a second list would be a second thing to keep in step.
///
/// Filing an event under the wrong site puts its faults at the wrong registry
/// coordinate, which is why the funnel checks rather than trusts.
#[must_use]
pub fn site_for(body: &TopologyEventBody) -> EventSite {
    if matches!(body, TopologyEventBody::RunStarted { .. }) {
        EventSite::AppendFirst
    } else if body.is_transaction() {
        EventSite::Append
    } else {
        EventSite::AppendInformational
    }
}

fn wrong_site(site: EventSite, path: &Path, expected: &str, allowed: &[EventSite]) -> TactusError {
    TactusError::EventLog {
        path: path.to_path_buf(),
        message: format!(
            "`Event.{}` is not {expected} ({})",
            site.name(),
            allowed
                .iter()
                .map(|allowed| format!("Event.{}", allowed.name()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Where a partial write stops.
///
/// Half the line, rounded down, and never fewer than one byte: a committed line
/// is at least `{}\n`, so half of it can never include the terminating newline
/// and the result is always a torn tail rather than an accidental commit.
fn torn_cut(bytes: &[u8]) -> usize {
    (bytes.len() / 2).max(1).min(bytes.len().saturating_sub(1))
}

fn torn_tail_warning(path: &Path, discarded: usize) -> String {
    format!(
        "{}: discarded {discarded} trailing byte(s) of an event that was never finished being \
         written — the shape an interrupted run leaves behind",
        path.display()
    )
}

/// fsync the surviving prefix and record what was made durable.
///
/// The sync and the ledger entry are one call on purpose, and the reason is a
/// measured one. An fsync is not observable from user space, so the ledger is
/// the only proxy a test has for it; with the sync and the record written as two
/// statements, moving the `SyncPrefix` consult to *between* them puts the
/// injection after the syscall and before the only thing that can see it, and
/// the mutation survives the suite. It did, when this was measured. Fused, the
/// only place the consult can be moved to is after the record — where
/// `an_injected_sync_failure_at_open_names_syncprefix_and_hands_out_no_handle`
/// kills it.
///
/// The residual that boundary named — "**deleting the `sync_all` call itself is
/// undetectable by any test on this machine**" — is `PR5-CONF-012`, and it is
/// narrower now than "undetectable". The syscall is [`crate::util::fsync_file`],
/// the one place in the funnel modules that may make it, and two things watch
/// it from either side: `effects::tests::every_file_durability_barrier_in_a_
/// funnel_module_goes_through_one_call` fails if the call leaves that function,
/// and `util::barriers_performed` counts entries so a ledger record that no
/// barrier produced is a disagreement. What is still true, and still stated, is
/// that nothing here can see *inside* `fsync`.
fn sync_log_file(
    file: &File,
    path: &Path,
    hooks: &mut dyn EventHooks,
    site: EventSite,
) -> Result<(), TactusError> {
    let io = |source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    };
    crate::util::fsync_file(file).map_err(io)?;
    // The length is the filesystem's answer, not a number this funnel carried
    // along: a ledger that reported its own idea of the length could agree with
    // itself while the file said something else.
    let len = file.metadata().map_err(io)?.len();
    hooks
        .durability_ledger()
        .record(DurableStep::SyncedFile, path, len);
    hooks.synced(&SyncRecord {
        site,
        point: SubEffectPoint::SyncPrefix,
        target: SyncTarget::LogFile,
        len,
        path: path.to_path_buf(),
    });
    Ok(())
}

/// fsync the directory holding `path`, so the log's *name* is durable, on every
/// platform (`PR5-CONF-013`).
///
/// This was Unix-only, and the comment that said so had the recipe in it: "needs
/// `FILE_FLAG_BACKUP_SEMANTICS` on Windows, which std does not expose". True of
/// std, and the reason [`crate::util::fsync_dir`] does not use std there —
/// `scope` requires `Event.OpenLog`'s "directory fsync" and "file **and
/// directory** after a truncation" with no platform exception, and the appeal to
/// NTFS's own metadata ordering was an argument for a guarantee the packet asks
/// this crate to make.
fn sync_directory(
    path: &Path,
    hooks: &mut dyn EventHooks,
    site: EventSite,
    point: SubEffectPoint,
) -> Result<(), TactusError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    crate::util::fsync_dir(parent).map_err(|source| TactusError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let len = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    hooks
        .durability_ledger()
        .record(DurableStep::SyncedDirectory, path, len);
    hooks.synced(&SyncRecord {
        site,
        point,
        target: SyncTarget::LogDirectory,
        len,
        path: path.to_path_buf(),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// A checked schema-4 line
// ---------------------------------------------------------------------------

/// One serialized, round-tripped schema-4 event: the exact bytes a coordinator
/// checked, and the only thing [`EventLog::append_topology`] accepts.
///
/// The field is private and [`Self::round_trip`] is the only constructor, so a
/// caller cannot hand the funnel bytes that never survived their own wire
/// format. That is `emit`'s "serialize → round-trip → … → append the exact
/// bytes" expressed as a type rather than as a rule a call site is asked to
/// remember, in the same spirit as `TopologyDelta`.
///
/// Bytes that never round-tripped cannot be handed to the funnel, and the
/// fixture pins which error says so:
///
/// ```compile_fail,E0451
/// use tactus::events::log::TopologyLine;
/// use tactus::topology::effects::EventSite;
///
/// let line = TopologyLine {
///     committed: "{\"ts\":\"now\"}\n".to_owned(),
///     kind: "run_started",
///     site: EventSite::AppendFirst,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyLine {
    /// The JSON, plus its terminating newline.
    committed: String,
    kind: &'static str,
    site: EventSite,
}

impl TopologyLine {
    /// Serialize `event`, prove it survives its own wire format, and keep the
    /// exact bytes. The returned event is what the wire will give back.
    ///
    /// # Errors
    ///
    /// [`TactusError::EventLog`] if the value cannot be serialized or does not
    /// round-trip.
    pub fn round_trip(event: &TopologyEvent) -> Result<(Self, TopologyEvent), TactusError> {
        let kind = event.body.kind();
        let line = serde_json::to_string(event).map_err(|e| TactusError::EventLog {
            path: PathBuf::new(),
            message: format!("serializing {kind}: {e}"),
        })?;
        let written: TopologyEvent =
            serde_json::from_str(&line).map_err(|e| TactusError::EventLog {
                path: PathBuf::new(),
                message: format!(
                    "{kind} does not survive its own wire format ({e}); the log could not be \
                     replayed"
                ),
            })?;
        Ok((
            Self {
                committed: line + "\n",
                kind,
                site: site_for(&event.body),
            },
            written,
        ))
    }

    /// The event's wire tag.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// The site this line belongs at.
    #[must_use]
    pub fn site(&self) -> EventSite {
        self.site
    }

    /// The exact bytes, newline included.
    #[must_use]
    pub fn committed_bytes(&self) -> &[u8] {
        self.committed.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// The stable-prefix barrier
// ---------------------------------------------------------------------------

/// Which step of the stable-prefix barrier refused.
///
/// The names are the packet's own — `Event.OpenLog`, its `SyncPrefix` point,
/// the `Event.ProvePrefixStable` observation, and the checked replay — so a
/// caller reporting "the failed step" reports something the fault registry can
/// be keyed by rather than a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierStep {
    /// `Event.OpenLog` itself could not open or normalize the log.
    OpenLog,
    /// `Event.OpenLog.SyncPrefix` returned `Err`; the prefix is possibly not
    /// durable.
    SyncPrefix,
    /// `Event.ProvePrefixStable`: the reread differs from the normalized prefix
    /// in a byte, in its length, or at its boundary.
    ProvePrefixStable,
    /// The checked replay refused the proven bytes.
    CheckedReplay,
}

impl BarrierStep {
    /// Every step, in the order the barrier performs them.
    pub const ALL: &'static [Self] = &[
        Self::OpenLog,
        Self::SyncPrefix,
        Self::ProvePrefixStable,
        Self::CheckedReplay,
    ];

    /// The step's name, as the packet writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenLog => "Event.OpenLog",
            Self::SyncPrefix => "Event.OpenLog.SyncPrefix",
            Self::ProvePrefixStable => "Event.ProvePrefixStable",
            Self::CheckedReplay => "the checked replay",
        }
    }
}

impl fmt::Display for BarrierStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A barrier that did not hold, and which step it failed at.
///
/// Typed rather than a formatted string because "returns an error **naming the
/// barrier step**" is a claim a test has to be able to check without matching
/// prose, and because PR7 reports the step to the operator.
#[derive(Debug)]
pub struct BarrierError {
    /// Which step refused.
    pub step: BarrierStep,
    /// The log.
    pub path: PathBuf,
    /// What the step found.
    pub detail: String,
}

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the event log's stable-prefix barrier did not hold at {}: {} ({}). No append handle \
             was handed out and nothing derived from this log was acted on; the run is resumable.",
            self.step,
            self.detail,
            self.path.display()
        )
    }
}

impl std::error::Error for BarrierError {}

impl From<BarrierError> for TactusError {
    fn from(error: BarrierError) -> Self {
        Self::EventLog {
            path: error.path.clone(),
            message: error.to_string(),
        }
    }
}

/// A log prefix that has been synced, reread, proven stable, and replayed.
///
/// Holding one is the evidence `stable_prefix_barrier` requires before "any
/// other fold-derived mutation". The append handle comes with it because a
/// write command needs both and the barrier is what entitles it to either.
#[derive(Debug)]
pub struct StablePrefix {
    log: EventLog,
    bytes: Vec<u8>,
    fold: TopologyFold,
}

impl StablePrefix {
    /// The append handle the barrier entitles this command to.
    #[must_use]
    pub fn log(&mut self) -> &mut EventLog {
        &mut self.log
    }

    /// The exact bytes that were synced, reread, proven, and replayed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The fold built from exactly those bytes.
    #[must_use]
    pub fn fold(&self) -> &TopologyFold {
        &self.fold
    }

    /// Take the two halves apart.
    #[must_use]
    pub fn into_parts(self) -> (EventLog, Vec<u8>, TopologyFold) {
        (self.log, self.bytes, self.fold)
    }
}

/// The digest of a log's committed first line, in the `sha256:<hex>` shape the
/// records use.
///
/// The bytes are the line **without** its terminating newline — the event's own
/// bytes, the thing `run_started_sha256` names. Exposed so the private commit
/// record and this barrier compute the same number from one definition rather
/// than two that agree by inspection.
#[must_use]
pub fn first_line_digest(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|byte| *byte == b'\n')?;
    Some(format!("sha256:{:x}", Sha256::digest(&bytes[..end])))
}

/// `coordinator_integration.stable_prefix_barrier`, in order and in one place.
///
/// 1. `Event.OpenLog` opens the log and normalizes a torn tail.
/// 2. `Event.OpenLog.SyncPrefix` **successfully** syncs the complete surviving
///    prefix.
/// 3. The whole file is reread.
/// 4. The reread bytes and boundary are proven unchanged: byte-equal to the
///    normalized prefix observed at open, the same length, ending in a newline
///    (no torn tail reappeared), and — for a schema-4 run — the committed first
///    line unchanged.
/// 5. Exactly those reread bytes are handed to the checked replay. Never a third
///    read.
///
/// Only then does a caller hold an append handle. A failed sync, an unstable
/// reread, or a replay refusal returns [`BarrierError`] naming the step and
/// hands out nothing.
///
/// # Errors
///
/// [`BarrierError`] naming the step that refused.
pub fn establish_stable_prefix(
    path: &Path,
    inputs: FrozenInputs,
    committed_first_line_sha256: Option<&str>,
    warnings: &mut Vec<String>,
    hooks: &mut dyn EventHooks,
) -> Result<StablePrefix, BarrierError> {
    // (1) and (2). `open_with_prefix` performs the sync and hands back the
    // normalized prefix it observed; a failure at `SyncPrefix` is the only one
    // of its failures the barrier reports separately, because it is the only one
    // the packet gives its own resume action.
    hooks.phase(EventSite::OpenLog, HookPhase::Before);
    let (log, normalized) = EventLog::open_funnel(EventSite::OpenLog, path, warnings, hooks)
        .map_err(|(step, error)| BarrierError {
            step,
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    hooks.phase(EventSite::OpenLog, HookPhase::After);

    // (3). Read-only: `Event.ProvePrefixStable` "performs no effect".
    hooks.phase(EventSite::ProvePrefixStable, HookPhase::Before);
    let reread = crate::util::read_file_bounded(path).map_err(|source| BarrierError {
        step: BarrierStep::ProvePrefixStable,
        path: path.to_path_buf(),
        detail: format!("the log could not be reread ({source})"),
    })?;

    // (4). Every clause of "bytes and boundary" separately, so a failure says
    // which one — and in an order that leaves each clause separately reachable.
    // Byte-equality implies the other two, so a proof that checked it first
    // would make the boundary and length clauses unreachable and untestable:
    // the boundary goes first, then the length, then the bytes.
    if !reread.is_empty() && reread.last() != Some(&b'\n') {
        return Err(BarrierError {
            step: BarrierStep::ProvePrefixStable,
            path: path.to_path_buf(),
            detail: "the reread does not end at a commit marker — a torn tail reappeared after \
                     the truncation"
                .to_owned(),
        });
    }
    if reread.len() != normalized.len() {
        return Err(BarrierError {
            step: BarrierStep::ProvePrefixStable,
            path: path.to_path_buf(),
            detail: format!(
                "the reread is {} byte(s) where the prefix synced at open was {}",
                reread.len(),
                normalized.len()
            ),
        });
    }
    if reread != normalized {
        let first = reread
            .iter()
            .zip(&normalized)
            .position(|(reread, synced)| reread != synced)
            .unwrap_or(0);
        return Err(BarrierError {
            step: BarrierStep::ProvePrefixStable,
            path: path.to_path_buf(),
            detail: format!("the reread differs from the prefix synced at open at byte {first}"),
        });
    }
    if let Some(expected) = committed_first_line_sha256 {
        match first_line_digest(&reread) {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                return Err(BarrierError {
                    step: BarrierStep::ProvePrefixStable,
                    path: path.to_path_buf(),
                    detail: format!(
                        "the committed first line digests {actual}, and the commit record says \
                         {expected}"
                    ),
                });
            }
            None => {
                return Err(BarrierError {
                    step: BarrierStep::ProvePrefixStable,
                    path: path.to_path_buf(),
                    detail: format!(
                        "the commit record says the first line digests {expected}, and the proven \
                         prefix has no committed first line"
                    ),
                });
            }
        }
    }
    hooks.phase(EventSite::ProvePrefixStable, HookPhase::After);

    // (5). Exactly those bytes. `reread` is moved into the result afterwards, so
    // there is no third read to accidentally take.
    let events = TopologyFold::parse_log(&reread).map_err(|error| BarrierError {
        step: BarrierStep::CheckedReplay,
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    let fold = TopologyFold::replay(inputs, &events).map_err(|error| BarrierError {
        step: BarrierStep::CheckedReplay,
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;

    Ok(StablePrefix {
        log,
        bytes: reread,
        fold,
    })
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

/// Read a whole log.
///
/// An unterminated **final** record is a torn tail — the shape a kill leaves —
/// and is dropped with a warning. A newline is the commit marker written after
/// every event, so any invalid newline-terminated record is corruption even
/// when it is last: something rewrote history, and deriving state from the
/// survivors would produce a confident wrong answer. That errors.
///
/// # Errors
///
/// [`TactusError::EventLog`] for a rewritten log; [`TactusError::Io`] otherwise.
pub fn read_all(path: &Path, warnings: &mut Vec<String>) -> Result<Vec<Event>, TactusError> {
    let bytes = read_bytes(path)?;
    let parsed = parse_bytes(path, &bytes)?;
    warnings.extend(parsed.torn_tail_warning);
    Ok(parsed.events)
}

/// Read the exact bytes a whole-log consumer will parse. Kept separate so a
/// consumer that needs a stable snapshot can compare two reads before trusting
/// the first one.
///
/// [`crate::util::read_file_bounded`] rather than `std::fs::read`, here and at
/// every other read of a log in this module, for the reason `PR5-RD-001` gave
/// about the run-directory classifier: `read_to_end` does not terminate on a
/// source that never reaches end of file, and a log path is a path in a run
/// directory rather than a value this crate chose. The bound is the file's own
/// length, so a real log of any size is still read in full.
pub(crate) fn read_bytes(path: &Path) -> Result<Vec<u8>, TactusError> {
    match crate::util::read_file_bounded(path) {
        Ok(bytes) => Ok(bytes),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            Err(TactusError::EventLog {
                path: path.to_path_buf(),
                message: "no event log here — this run never started, or its directory was \
                          removed"
                    .to_owned(),
            })
        }
        Err(source) => Err(TactusError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// A parsed whole-log snapshot. The only recoverable parse condition is typed
/// separately from the events so callers never have to infer its meaning from
/// human-readable warning text.
pub(crate) struct ParsedLines {
    pub events: Vec<Event>,
    pub torn_tail_warning: Option<String>,
}

pub(crate) fn parse_bytes(path: &Path, bytes: &[u8]) -> Result<ParsedLines, TactusError> {
    // EventLog::append writes the newline after the JSON bytes. EventLog::open
    // likewise discards everything after the last newline before resuming, so
    // whole-log readers must use the same boundary: even syntactically complete
    // JSON without its terminating newline was never a committed event.
    let committed_end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| position + 1);
    let (committed_bytes, trailing) = bytes.split_at(committed_end);
    let torn_tail_warning = (!trailing.is_empty()).then(|| {
        format!(
            "{}: dropped an incomplete final line ({} trailing byte(s)) — the shape an \
             interrupted write leaves behind",
            path.display(),
            trailing.len()
        )
    });
    let committed = std::str::from_utf8(committed_bytes).map_err(|error| {
        let line = committed_bytes[..error.valid_up_to()]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1;
        TactusError::EventLog {
            path: path.to_path_buf(),
            message: format!(
                "line {line} contains invalid UTF-8 in a committed event ({error}). This is not a \
                 torn tail — the log has been rewritten, and state derived from what is left \
                 would be confidently wrong."
            ),
        }
    })?;

    let mut events = Vec::with_capacity(committed.lines().count());
    for (position, line) in committed.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<Event>(line).map_err(|error| TactusError::EventLog {
            path: path.to_path_buf(),
            message: format!(
                "line {} is not a valid event ({error}). This is not a torn tail — the log has \
                 been rewritten, and state derived from what is left would be confidently wrong.",
                position + 1
            ),
        })?;
        events.push(event);
    }
    Ok(ParsedLines {
        events,
        torn_tail_warning,
    })
}

/// Incremental reader for `status --follow`.
///
/// Reads only complete lines: a poll that catches the writer mid-line stops at
/// the last newline and picks the rest up next time, so a follower never sees
/// half an event.
#[derive(Debug)]
pub struct LogTail {
    path: PathBuf,
    offset: u64,
}

impl LogTail {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path, offset: 0 }
    }

    /// Start from the end, so a follower attached to a live run reports only
    /// what happens from now on.
    pub fn skip_existing(&mut self) {
        self.offset = std::fs::metadata(&self.path).map_or(0, |meta| meta.len());
    }

    /// Every complete line written since the last poll.
    ///
    /// # Errors
    ///
    /// [`TactusError::Io`] if the log cannot be read; [`TactusError::EventLog`]
    /// for a rewritten log.
    pub fn poll(&mut self, warnings: &mut Vec<String>) -> Result<Vec<Event>, TactusError> {
        let io = |source| TactusError::Io {
            path: self.path.clone(),
            source,
        };
        let Ok(mut file) = File::open(&self.path) else {
            return Ok(Vec::new());
        };
        let length = file.metadata().map_err(io)?.len();
        if length <= self.offset {
            // Truncated or replaced underneath us: start over rather than
            // read from an offset that now means something else.
            if length < self.offset {
                self.offset = 0;
            }
            if length == self.offset {
                return Ok(Vec::new());
            }
        }
        file.seek(SeekFrom::Start(self.offset)).map_err(io)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).map_err(io)?;
        let Some(end) = buffer.iter().rposition(|byte| *byte == b'\n') else {
            return Ok(Vec::new());
        };
        let complete = &buffer[..=end];
        self.offset += complete.len() as u64;
        let parsed = parse_bytes(&self.path, complete)?;
        warnings.extend(parsed.torn_tail_warning);
        Ok(parsed.events)
    }
}

#[cfg(test)]
mod premove;

#[cfg(test)]
mod tests;
