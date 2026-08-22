//! The pre-move `EventLog`, transcribed verbatim, as an oracle.
//!
//! `PR3-SELF-ORACLE` is in the standing ledger because a completeness grid
//! computed its expected values by calling the function under test, so oracle
//! and result moved together. The obligation this slice carries — "byte-
//! identical legacy behaviour … exact write/flush/sync and torn-tail
//! semantics" — has exactly that shape: comparing the moved writer against
//! itself proves nothing about the move.
//!
//! So the oracle is the code as it stood **before** the move. Every line below
//! is a copy of `src/events.rs` at commit `ff0490a`, lines 1478-1585, with two
//! mechanical changes and no others:
//!
//!   * the type is `PremoveEventLog`, so both writers can be linked at once;
//!   * `EventBody`, `Event` and `TactusError` are imported rather than in scope.
//!
//! To check that claim without trusting this comment:
//!
//! ```text
//! git show ff0490a:src/events.rs | sed -n '1478,1585p'
//! ```
//!
//! and compare. If a future change to the funnel is *meant* to change legacy
//! behaviour, the differential tests in `super::tests` fail and this file is
//! the thing that must be argued with.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::TactusError;
use crate::events::{Event, EventBody};

/// The append-only writer. One per run, held by the engine — `tactus answer`
/// deliberately does not write here (it drops a file the engine ingests), so
/// the log has exactly one writer and interleaved lines are impossible.
#[derive(Debug)]
pub struct PremoveEventLog {
    path: PathBuf,
    file: File,
}

impl PremoveEventLog {
    /// Open for appending, discarding an incomplete trailing record first.
    ///
    /// A process killed mid-write can leave a line with no newline. Appending
    /// straight after it would splice the fragment and the next event into one
    /// unparseable line, losing both.
    ///
    /// Terminating the fragment with a newline instead is worse than it looks:
    /// it promotes a torn *tail*, which [`crate::events::read_all`] recovers from, into an
    /// unparseable line in the *middle*, which [`crate::events::read_all`] must treat as a
    /// rewritten log and refuse. So the fragment is truncated away. That is
    /// not rewriting history — those bytes are by construction an event that
    /// never finished being written, and no reader could ever have parsed
    /// them — and it keeps "damage anywhere but the end means corruption" a
    /// statement the reader can still trust.
    pub fn open(path: &Path, warnings: &mut Vec<String>) -> Result<Self, TactusError> {
        let io = |source| TactusError::Io {
            path: path.to_path_buf(),
            source,
        };
        // Truncate before taking the append handle, through a handle of its
        // own. On Windows an append-only handle is opened with
        // FILE_APPEND_DATA and *not* FILE_WRITE_DATA, so `set_len` on it fails
        // outright with access denied.
        match std::fs::read(path) {
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
                warnings.push(format!(
                    "{}: discarded {} trailing byte(s) of an event that was never finished being \
                     written — the shape an interrupted run leaves behind",
                    path.display(),
                    existing.len() - keep
                ));
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io(source)),
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Append one event and get it back **as it will be read back**.
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
    pub fn append(&mut self, body: EventBody) -> Result<Event, TactusError> {
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
        let io = |source| TactusError::Io {
            path: self.path.clone(),
            source,
        };
        self.file.write_all(line.as_bytes()).map_err(io)?;
        self.file.flush().map_err(io)?;
        self.file.sync_data().map_err(io)?;
        Ok(written)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
