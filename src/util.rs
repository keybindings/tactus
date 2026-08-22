//! Small shared helpers used across the engine, gates, adapters, and
//! reporting: text truncation, filename sanitizing, PATH program resolution,
//! run-artifact writes, and event timestamps.
// Allowlist placement: the **funnel section** of `effects/allowlist.toml`, which
// carries this module's review clause -- effects only inside site-taking APIs,
// no writable handle returned. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::TactusError;

/// Last `max` bytes of trimmed text, cut on a char boundary, with an ellipsis
/// marker when truncated.
pub fn tail(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max {
        return trimmed.to_owned();
    }
    let start = trimmed.len() - max;
    // No boundary in range (possible only for a tiny `max` landing inside the
    // final multibyte char) means the whole tail is unusable — keep nothing.
    let start = (start..trimmed.len())
        .find(|i| trimmed.is_char_boundary(*i))
        .unwrap_or(trimmed.len());
    format!("…{}", &trimmed[start..])
}

/// First `max` bytes of trimmed text, cut on a char boundary, with an
/// ellipsis marker when truncated. For ordered lists whose first entry is the
/// most important — a reviewer's reasons, say — where [`tail`] would drop
/// exactly the part that mattered.
pub fn head(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max {
        return trimmed.to_owned();
    }
    let end = (0..=max)
        .rev()
        .find(|i| trimmed.is_char_boundary(*i))
        .unwrap_or(0);
    format!("{}…", &trimmed[..end])
}

/// A fence long enough to quote `payload` without the payload closing it.
///
/// Everything the engine quotes back to a model or a human — a diff, an
/// artifact, an agent's question, an operator's answer — is untrusted text that
/// routinely contains fences of its own (any repo with markdown does). A fence
/// that closes early hands the remainder of the payload to the reader as if it
/// were instructions, so the invariant is load-bearing rather than cosmetic:
/// it lives in one place so it cannot drift between callers.
pub fn fence_for(payload: &str) -> String {
    let mut longest = 0usize;
    let mut current = 0usize;
    for ch in payload.chars() {
        if ch == '`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
}

/// Make an arbitrary string (task id, gate name — both user-authored) safe to
/// use as a single file-name component: no separators, no Windows-reserved
/// characters, no dot-only names, bounded length. Not injective — callers
/// that need uniqueness must add a discriminator of their own.
pub fn filename_component(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    out.truncate(64);
    if out.trim_matches(['.', '-']).is_empty() {
        return "x".to_owned();
    }
    out
}

/// Executable extensions to probe on Windows: PATHEXT when set, else a
/// conservative default. Unix probes the bare name only.
pub fn executable_extensions() -> Vec<String> {
    if !cfg!(windows) {
        return vec![String::new()];
    }
    let mut exts = vec![String::new()];
    match std::env::var("PATHEXT") {
        Ok(pathext) if !pathext.trim().is_empty() => {
            exts.extend(
                pathext
                    .split(';')
                    .map(|e| e.trim().to_ascii_lowercase())
                    .filter(|e| e.starts_with('.')),
            );
        }
        _ => exts.extend([".exe", ".cmd", ".bat", ".com"].map(str::to_owned)),
    }
    exts
}

/// Try `base` plus each executable extension; first hit wins.
pub fn probe_extensions(base: &Path) -> Option<PathBuf> {
    for ext in executable_extensions() {
        let candidate = if ext.is_empty() {
            base.to_path_buf()
        } else {
            let mut with_ext = base.as_os_str().to_owned();
            with_ext.push(&ext);
            PathBuf::from(with_ext)
        };
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The user-level `~/.tactus` directory: pools live here (§17), and so do the
/// agent-authored artifacts a run must keep outside the workspace (§15).
///
/// `USERPROFILE` wins on Windows because shells like Git Bash set `HOME` to an
/// MSYS-style path (`/c/Users/...`) that the Windows file APIs cannot open —
/// trusting it there would write run artifacts somewhere nothing can read them
/// back. Elsewhere `HOME` is authoritative and `USERPROFILE` is the fallback.
pub fn user_tactus_dir() -> Option<PathBuf> {
    let home = if cfg!(windows) {
        std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
    } else {
        std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
    };
    Some(PathBuf::from(home?).join(".tactus"))
}

/// Resolve a bare program name against PATH. Empty PATH segments are skipped:
/// they mean "current directory" to some shells, and resolving a program
/// against the repo under automation would execute repo-controlled code.
pub fn find_program(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        return probe_extensions(candidate);
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        if let Some(found) = probe_extensions(&dir.join(name)) {
            return Some(found);
        }
    }
    None
}

/// Resolve every matching program in shell PATH order: directory first, then
/// the caller's name preference, then executable extension. Returning all
/// candidates lets an adapter skip an unspawnable app alias without promoting
/// a later directory ahead of a usable earlier installation.
pub(crate) fn find_program_candidates(names: &[&str]) -> Vec<PathBuf> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    find_program_candidates_on_path(names, &path_var)
}

pub(crate) fn find_program_candidates_on_path(
    names: &[&str],
    path_var: &std::ffi::OsStr,
) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in std::env::split_paths(path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        for name in names {
            let base = dir.join(name);
            let explicit_extension = Path::new(name).extension().is_some();
            let extensions = if explicit_extension {
                vec![String::new()]
            } else {
                executable_extensions()
            };
            for extension in extensions {
                let candidate = if extension.is_empty() {
                    base.clone()
                } else {
                    let mut with_extension = base.as_os_str().to_owned();
                    with_extension.push(extension);
                    PathBuf::from(with_extension)
                };
                if candidate.is_file() && !found.contains(&candidate) {
                    found.push(candidate);
                }
            }
        }
    }
    found
}

/// One durability primitive, as a funnel actually performed it.
///
/// The Event lane has had a ledger of these since PR5 opened
/// (`events::log::SyncRecord`), and `proof_tests[9]` names it — "**the sync
/// ledger** shows the synced length equal to the file length after open". The
/// workspace and run-directory lanes had nothing of the kind, and a measured
/// consequence: deleting the intent file's `fsync`, deleting the containing
/// directory's `fsync`, and deleting the staged file's `fsync` from every
/// atomic publication in `rundir` were each invisible to the whole suite
/// (`PR5-WORKSPACE-015`, `PR5-WORKSPACE-016`, `PR5-RUNDIR-057`). They have to
/// be: on a machine that does not lose power mid-test, an unsynced file is
/// byte-for-byte a synced one, and outcomes are all those lanes could check.
///
/// The rename is in the ledger beside the two syncs because the claims are
/// *orderings* — `run_creation` says "write `<name>.tmp`, **fsync**, rename,
/// **fsync the directory**" — and an ordering is not expressible over a trace
/// that holds only one of the three things being ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurableStep {
    /// A `write_all` of `len` bytes was performed.
    Wrote,
    /// A `flush` was performed.
    Flushed,
    /// A `sync_data` was performed — the append's own durability barrier, as
    /// distinct from [`Self::SyncedFile`]'s `sync_all`.
    SyncedData,
    /// A file was truncated to `len` bytes.
    Truncated,
    /// A staged file's own bytes were made durable (`fsync` / `FlushFileBuffers`).
    SyncedFile,
    /// A staged file was renamed onto its published name.
    Renamed,
    /// A directory entry was made durable. Unix only: `sync_dir` is a
    /// documented no-op on Windows, so a Windows trace has the file syncs and
    /// the renames and no directory syncs, and a reader of the evidence can
    /// see which platform produced it.
    SyncedDirectory,
}

/// One entry in a [`DurabilityLedger`].
///
/// **One entry per attempt**, in order, whether or not the primitive returned
/// `Ok`. "Exactly one primitive attempt and one error" is a claim the packet
/// makes about an entered append (`invariants[1]`), and a ledger that recorded
/// only successes could not distinguish one attempt from a retry that failed
/// twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableRecord {
    /// What was done.
    pub step: DurableStep,
    /// What it was done to.
    pub path: PathBuf,
    /// How much of it. For a sync or a truncation this is the **filesystem's
    /// own answer** rather than a number the funnel carried along — a ledger
    /// that reported its own idea of the length could agree with itself while
    /// the file said something else. For [`DurableStep::Wrote`] it is the
    /// number of bytes handed to `write_all`, which is the quantity the claim
    /// "one `write_all` containing both the JSON and its LF commit marker" is
    /// about. Zero when the path has no length to report.
    pub len: u64,
}

/// An ordered record of the durability primitives a funnel performed.
///
/// Cloning shares the log, so a caller can hand a clone into a funnel body and
/// still read what the body recorded. Production never constructs a recording
/// one: [`Self::off`] holds no allocation and every `record` call on it is a
/// discriminant test.
#[derive(Debug, Clone, Default)]
pub struct DurabilityLedger(Option<std::sync::Arc<std::sync::Mutex<Vec<DurableRecord>>>>);

impl DurabilityLedger {
    /// A ledger that records nothing. What production passes.
    #[must_use]
    pub fn off() -> Self {
        Self(None)
    }

    /// A ledger that records. What a test passes.
    #[must_use]
    pub fn recording() -> Self {
        Self(Some(std::sync::Arc::new(std::sync::Mutex::new(Vec::new()))))
    }

    /// Whether this ledger records at all.
    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.0.is_some()
    }

    /// Append one entry.
    pub fn record(&self, step: DurableStep, path: &Path, len: u64) {
        if let Some(log) = &self.0 {
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(DurableRecord {
                    step,
                    path: path.to_path_buf(),
                    len,
                });
        }
    }

    /// Everything recorded so far, in order.
    #[must_use]
    pub fn records(&self) -> Vec<DurableRecord> {
        self.0.as_ref().map_or_else(Vec::new, |log| {
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
    }

    /// Everything recorded so far about `path`, in order.
    #[must_use]
    pub fn records_for(&self, path: &Path) -> Vec<DurableRecord> {
        self.records()
            .into_iter()
            .filter(|record| record.path == path)
            .collect()
    }

    /// The steps recorded so far, in order, with their paths discarded.
    #[must_use]
    pub fn steps(&self) -> Vec<DurableStep> {
        self.records()
            .into_iter()
            .map(|record| record.step)
            .collect()
    }

    /// Forget everything recorded so far, so a later sequence can be read on
    /// its own rather than as a suffix of a cumulative log.
    ///
    /// The cumulative-log trap is not hypothetical here: an ordering assertion
    /// over the *first* match in a log that already held an earlier, unrelated
    /// occurrence is exactly how `PR5-WORKSPACE-022` survived.
    pub fn clear(&self) {
        if let Some(log) = &self.0 {
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }
}

/// Every byte of `path`, up to the length the file itself declares.
///
/// This is [`std::fs::read`] with the one property `std::fs::read` does not
/// have: **it terminates**. `read_to_end` loops until a read returns zero, and
/// an endless source — `/dev/zero`, `/dev/full`, a character device someone
/// symlinked a log to — never returns zero, so `std::fs::read` on one never
/// returns and grows memory until it is killed. Every caller here is reading a
/// file *inside a run directory*, which a startup census must classify before a
/// write command may proceed (`decisions.sequential_substrate.startup_census`),
/// so "never returns" is a coordinator that holds the worktree lock for ever.
///
/// The bound is the file's **own** length, from `fstat` on the already-open
/// handle rather than from the path, so it cannot be raced by a swap between
/// the two calls and cannot be talked out of by an argument. It is not a cap:
/// a regular file is read in full however large it is, so nothing a caller
/// might need is hidden — the read is bounded, not the answer. A source with no
/// length (a device, a fifo, a socket) reports zero and contributes nothing,
/// which every caller here already treats as "no content", the safe direction.
///
/// What it does **not** defend: `File::open` on a fifo with no writer blocks in
/// the kernel before this function sees a handle. That is `std::fs::read`'s
/// behaviour too and is unchanged here; a run directory holds regular files.
///
/// # Errors
///
/// [`std::io::Error`] from `open`, `fstat` or `read`, verbatim, so a caller can
/// still distinguish `NotFound` from a real failure.
pub fn read_file_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let bound = file.metadata()?.len();
    let mut bytes = Vec::new();
    file.by_ref().take(bound).read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn write_text(path: &Path, content: &str) -> Result<(), TactusError> {
    std::fs::write(path, content).map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// How many durability barriers this process has performed.
///
/// Test-only, and the reason it exists is `PR5-CONF-012`: the durability ledger
/// is written by the function it certifies. `let outcome = file.sync_all();` →
/// `let outcome: io::Result<()> = Ok(());` survived the whole suite, because the
/// ledger entry is written *beside* the syscall and every trace assertion reads
/// the entry. A counter here cannot see inside `sync_all` either — nothing on a
/// machine that does not lose power can — but it can see whether the barrier was
/// **reached**, which is the half the ledger was standing in for. The other half
/// is a source census: [`crate::effects`]'s
/// `every_file_durability_barrier_in_a_funnel_module_goes_through_one_call`
/// pins that the syscall is inside these two functions and nowhere else, so
/// deleting it is a failure rather than a silent no-op.
///
/// Unconditional rather than `#[cfg(test)]`, for two reasons. A relaxed
/// increment beside an `fsync` is not measurable — the syscall is six orders of
/// magnitude more expensive — and a `#[cfg(test)]` item in the middle of this
/// file would truncate the **production region** every source census in
/// `src/effects/tests.rs` computes, which cuts at the first `#[cfg(test)]`. That
/// is a census reading half a module and reporting clean, which is the exact
/// failure this project has a reconciliation table for.
static BARRIERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many times [`fsync_file`] or [`fsync_dir`] has been entered.
///
/// Only a test reads it — production performs barriers, it does not count them —
/// so the non-test build is told, in the same idiom `src/agent/proc.rs:155`
/// already uses for its per-platform dead code. The *counter* stays
/// unconditional; see [`BARRIERS`] for why a `#[cfg(test)]` item here would
/// truncate every source census's production region.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn barriers_performed() -> u64 {
    BARRIERS.load(std::sync::atomic::Ordering::Relaxed)
}

fn count_barrier() {
    BARRIERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The **file** half of the durability barrier (`PR5-CONF-012`).
///
/// One call, shared by every funnel that stages a file before publishing it, so
/// that "the durability step is still here" is a property a source census can
/// check rather than a line each caller is trusted to keep.
///
/// # Errors
///
/// [`std::io::Error`] from `fsync`, verbatim.
pub(crate) fn fsync_file(file: &std::fs::File) -> std::io::Result<()> {
    count_barrier();
    file.sync_all()
}

/// The **directory** half of the durability barrier, on every platform this
/// ships on (`PR5-CONF-013`).
///
/// A rename is not durable because the renamed file was synced: the durable
/// thing is the *directory entry*, and it needs its own barrier.
/// `run_creation` says "write `<name>.tmp`, fsync, rename, **fsync the
/// directory**"; `scope` requires `Event.OpenLog`'s "directory fsync" and "file
/// **and directory** after a truncation". Neither carries a platform exception
/// and Windows is a first-class target (DESIGN.md §1), so the three call sites
/// used to return `Ok(())` without opening anything on non-unix and the suite
/// pinned that omission in both directions on purpose.
///
/// **Why this is not `File::open(dir)?.sync_all()` everywhere.** Measured on a
/// Windows Server 2025 guest: std's open refuses a directory outright —
/// `Os { code: 5, kind: PermissionDenied, message: "Access is denied." }`, 14
/// tests down — because it does not pass `FILE_FLAG_BACKUP_SEMANTICS`, which is
/// the flag that makes `CreateFileW` return a *directory* handle at all. So the
/// documented boundary was a platform fact rather than a preference, and the
/// way through it is the Win32 call std does not expose.
///
/// # Errors
///
/// [`std::io::Error`] from the open or from the flush, verbatim, so a caller can
/// still tell a missing directory from a refused barrier.
pub(crate) fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    count_barrier();
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(windows)]
    {
        windows_fsync_dir(dir, WINDOWS_DIRECTORY_ACCESS)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Ok(())
    }
}

/// The access mask [`fsync_dir`] opens a directory with on Windows.
///
/// `FlushFileBuffers` documents that the handle must carry **write** access, and
/// a directory grants `GENERIC_WRITE` as "may add a file or a subdirectory" —
/// it is not a request to write the directory's bytes, which no caller can do.
/// Named rather than inlined so that
/// [`the_directory_barrier_needs_exactly_the_access_it_asks_for`] can drive the
/// same code path with a mask that is *not* enough and show which half refuses.
#[cfg(windows)]
const WINDOWS_DIRECTORY_ACCESS: u32 =
    windows_sys::Win32::Foundation::GENERIC_READ | windows_sys::Win32::Foundation::GENERIC_WRITE;

/// [`fsync_dir`]'s Windows body, over any access mask.
#[cfg(windows)]
fn windows_fsync_dir(dir: &Path, access: u32) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FlushFileBuffers, OPEN_EXISTING,
    };

    // `CreateFileW` takes a NUL-terminated UTF-16 string, and an interior NUL
    // would silently truncate the path — so it is refused rather than trimmed.
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a directory path with an interior NUL cannot be opened",
        ));
    }
    wide.push(0);

    // Shared for read, write and delete: this handle exists for one flush and
    // must not be able to stop a concurrent command from using the directory.
    // SAFETY: `wide` is a live NUL-terminated UTF-16 path that outlives the
    // call, and the two pointer arguments are the documented "no security
    // attributes" and "no template" nulls.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `handle` is a live directory handle this function owns.
    let flushed = unsafe { FlushFileBuffers(handle) };
    let outcome = if flushed == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    };
    // SAFETY: same handle, closed exactly once, and not used afterwards.
    let _ = unsafe { CloseHandle(handle) };
    outcome
}

pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), TactusError> {
    let json = serde_json::to_string_pretty(value).map_err(|e| TactusError::Parse {
        message: format!("serializing {}: {e}", path.display()),
    })?;
    write_text(path, &(json + "\n"))
}

/// Serialize a [`Duration`](std::time::Duration) as whole milliseconds.
///
/// Durations ride in both the event log and the report, and serde's default
/// `{"secs":3,"nanos":120000000}` is neither readable in a JSONL ops log nor
/// stable across serde's internally-tagged buffering path. Milliseconds are
/// finer than anything the ledger reports and survive both.
pub mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, out: S) -> Result<S::Ok, S::Error> {
        out.serialize_u64(u64::try_from(value.as_millis()).unwrap_or(u64::MAX))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_millis(u64::deserialize(input)?))
    }
}

/// Now, as an RFC 3339 UTC timestamp — the `ts` on every event (§15).
///
/// Std-only rather than a date dependency: this is one field on one line of
/// JSON, and the conversion below is a closed-form algorithm with no table and
/// no locale. A clock that cannot read (`SystemTime` before the epoch) yields
/// the epoch rather than failing — a timestamp is metadata on the event, and
/// losing the event to a clock problem would be the worse trade.
pub fn rfc3339_utc_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    rfc3339_utc(seconds)
}

fn rfc3339_utc(unix_seconds: u64) -> String {
    let days = i64::try_from(unix_seconds / 86_400).unwrap_or(0);
    let second_of_day = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60
    )
}

/// Civil date from a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`). The era starts on 0000-03-01 so that a leap day always
/// lands at the end of a cycle, which is what lets the month and day fall out
/// of integer arithmetic instead of a lookup table.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    // March is month 0 in the shifted era; roll January and February into the
    // following calendar year.
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    (year + i64::from(month <= 2), month, day)
}

/// Whether `left` and `right` name the same directory or file on disk.
///
/// Test-only, and shared rather than local because the defect it removes is a
/// class rather than a site. `PathBuf == PathBuf` is a comparison of two
/// strings, and a test that asserts one against a path production derived is
/// asserting that two independent spellings of one directory came out
/// identical. Three environment facts break that, and a Linux CI cell has none
/// of them:
///
/// * macOS symlinks `/var` to `/private/var`, so anything canonicalised
///   disagrees textually with the `std::env::temp_dir()` path it came from;
/// * Windows hands back the 8.3 short name of a directory whose real name is
///   long (`C:\Users\RUNNER~1\…` for `runneradmin`), and which spelling you get
///   depends on whose user name is long — the CI runner's is, so CI saw it and
///   a short-named developer box never can;
/// * the same Windows path arrives with `/` from git and `\` from the OS.
///
/// [`std::fs::canonicalize`] is the normalisation because its contract is
/// exactly the property wanted: "the canonical, absolute form of the path with
/// all intermediate components normalized and symbolic links resolved". Two
/// names for one existing directory therefore canonicalise to one string on
/// every platform std supports, which makes this comparison mean "the same
/// directory" on all of them rather than "the same spelling" on one of them.
///
/// A path that does not resolve is not the same object as one that does, so
/// exactly one failure answers `false` — which keeps the negative form
/// (`!same_path(…)`) honest for a workspace the run has already cleaned up.
///
/// # Panics
///
/// When *neither* side resolves. Nothing can be concluded from comparing two
/// absent paths, and answering `false` there would be the same silent pass
/// this helper exists to remove.
#[cfg(test)]
pub(crate) fn same_path(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => false,
        (Err(left_error), Err(right_error)) => panic!(
            "neither `{}` ({left_error}) nor `{}` ({right_error}) resolves, so no comparison \
             of the two says anything",
            left.display(),
            right.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_truncates_on_char_boundaries() {
        assert_eq!(tail("  short  ", 400), "short");
        let long = "a".repeat(500);
        let cut = tail(&long, 400);
        assert!(cut.starts_with('…') && cut.len() < 500);
        let multi = "é".repeat(300);
        let cut = tail(&multi, 401);
        assert!(cut.chars().all(|c| c == 'é' || c == '…'));
    }

    #[test]
    fn tail_never_slices_mid_char_for_tiny_limits() {
        // Cut lands inside the trailing multibyte char: keep nothing rather
        // than panic on a non-boundary index.
        assert_eq!(tail("é", 1), "…");
        assert_eq!(tail("aé", 1), "…");
    }

    #[test]
    fn filename_component_neutralizes_hostile_names() {
        assert_eq!(filename_component("lint:fast"), "lint-fast");
        assert_eq!(filename_component("unit/fast"), "unit-fast");
        assert_eq!(filename_component("a\\b"), "a-b");
        assert_eq!(filename_component(".."), "x");
        assert_eq!(filename_component("check"), "check");
        assert!(filename_component(&"x".repeat(200)).len() <= 64);
    }

    #[test]
    fn find_program_resolves_real_tools_and_misses_fake_ones() {
        assert!(find_program("git").is_some(), "git is on PATH in this repo");
        assert!(find_program("tactus-definitely-not-real-xyz").is_none());
    }

    #[test]
    fn candidate_resolution_preserves_path_directory_precedence() {
        let root =
            std::env::temp_dir().join(format!("tactus-util-path-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).expect("first PATH directory");
        std::fs::create_dir_all(&second).expect("second PATH directory");
        let first_program = first.join("codex.exe");
        let second_program = second.join("codex.cmd");
        std::fs::write(&first_program, "").expect("first candidate");
        std::fs::write(&second_program, "").expect("second candidate");
        let path = std::env::join_paths([&first, &second]).expect("synthetic PATH");

        let found = find_program_candidates_on_path(&["codex.cmd", "codex.exe"], &path);

        assert_eq!(
            found,
            [first_program, second_program],
            "the name preference must not promote a later PATH directory"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn timestamps_are_rfc3339_utc() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        // Both leap rules: 2024 by the /4 rule, 2000 by the /400 exception.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        // A day boundary and the last second before one.
        assert_eq!(rfc3339_utc(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(rfc3339_utc(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn timestamps_sort_chronologically_as_strings() {
        // The log is read back with a plain string compare in places; the
        // zero-padded fixed-width form is what makes that legitimate.
        let mut stamps = [
            rfc3339_utc(1_700_000_000),
            rfc3339_utc(0),
            rfc3339_utc(951_782_400),
        ];
        stamps.sort();
        assert_eq!(
            stamps,
            [
                rfc3339_utc(0),
                rfc3339_utc(951_782_400),
                rfc3339_utc(1_700_000_000)
            ]
        );
        assert_eq!(rfc3339_utc_now().len(), "1970-01-01T00:00:00Z".len());
    }

    #[test]
    fn probe_extensions_never_resolves_a_bare_relative_name() {
        // The empty-PATH-segment guard in find_program rests on this: a bare
        // name must not resolve against the process CWD. Verified by probing
        // a file that exists in a scratch dir under its bare name.
        let dir = std::env::temp_dir().join(format!("tactus-util-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::write(dir.join("bait.txt"), "").expect("bait");
        assert!(
            probe_extensions(&dir.join("bait.txt")).is_some(),
            "probe finds real paths"
        );
        // find_program must not consult any directory-less candidate.
        assert!(find_program("bait.txt").is_none());
    }

    /// Two spellings of one directory are one directory, and two directories
    /// are not.
    ///
    /// The fixture is `.` and `..` rather than a symlink because those are the
    /// one pair of "different string, same directory" that every platform
    /// std supports normalises identically — Windows has no unprivileged
    /// directory symlink, and the macOS `/var` case and the Windows 8.3 case
    /// this helper exists for cannot be built on demand anywhere else. It is
    /// the same mechanism either way: `canonicalize` resolves the path to the
    /// object, and the object is what the assertion means.
    #[test]
    fn same_path_compares_directories_rather_than_spellings() {
        let root = std::env::temp_dir().join(format!("tactus-util-same-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let inner = root.join("inner");
        std::fs::create_dir_all(&inner).expect("scratch directories");

        let detour = inner.join("..").join("inner").join(".");
        assert_ne!(detour, inner, "the fixture must differ as a string");
        assert!(same_path(&detour, &inner), "…and agree as a directory");

        assert!(!same_path(&root, &inner), "a parent is not its child");
        assert!(
            !same_path(&root.join("absent"), &root),
            "a path that does not resolve is not one that does"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[should_panic(expected = "so no comparison of the two says anything")]
    fn same_path_refuses_to_answer_when_neither_side_resolves() {
        let root = std::env::temp_dir().join(format!("tactus-util-absent-{}", std::process::id()));
        let _ = same_path(&root.join("a"), &root.join("b"));
    }

    /// The directory barrier runs, and runs on **this** platform
    /// (`PR5-CONF-013`).
    ///
    /// The two axes this crosses are the *operation* and the *platform*. Every
    /// caller's ledger assertion holds the operation constant — stage, rename,
    /// then a `SyncedDirectory` record — and until this round those assertions
    /// forked on `cfg!(unix)`, so the Windows cell asserted the barrier's
    /// **absence** and the pair "the barrier, on Windows" was never built. What
    /// varies here is the platform, and nothing is `cfg`-gated away: the call
    /// must succeed wherever the suite runs.
    ///
    /// A ledger record is not enough on its own — a caller records beside the
    /// call — so this drives the primitive directly, and drives it against a
    /// directory that has just changed, which is the only state the barrier is
    /// ever asked about.
    #[test]
    fn the_directory_barrier_runs_on_this_platform() {
        let root = std::env::temp_dir().join(format!("tactus-util-fsync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch directory");

        // A directory entry that was just created, then just renamed: the two
        // changes `run_creation` asks to be made durable.
        let staged = root.join("record.tmp");
        std::fs::write(&staged, b"{}\n").expect("stage");
        fsync_dir(&root).expect("the barrier must run on this platform after a create");
        std::fs::rename(&staged, root.join("record")).expect("publish");
        fsync_dir(&root).expect("the barrier must run on this platform after a rename");

        // A directory that is not there is an error rather than a silent
        // success, so a caller cannot be told a name is durable when nothing
        // was opened at all — which is exactly what the non-unix arm used to do.
        let absent = fsync_dir(&root.join("absent"));
        assert!(
            absent.is_err(),
            "the barrier reported success for a directory that does not exist"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The Windows access mask is the one the barrier actually needs, and a
    /// weaker one is refused (`PR5-CONF-013`).
    ///
    /// `FlushFileBuffers` documents that its handle must carry write access, and
    /// a claim like that is worth exactly as much as the run that checks it —
    /// this project has shipped a "documented" platform boundary that was a
    /// missing flag twice now. So the same code path is driven with
    /// `GENERIC_READ` alone: if that succeeded, `WINDOWS_DIRECTORY_ACCESS` would
    /// be asking for a right it does not need, and if it fails the constant is
    /// pinned to a measured requirement rather than to a doc sentence.
    ///
    /// Held constant: the directory, the flags and the share mode. Varying: the
    /// desired access.
    #[cfg(windows)]
    #[test]
    fn the_directory_barrier_needs_exactly_the_access_it_asks_for() {
        let root = std::env::temp_dir().join(format!("tactus-util-mask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch directory");
        std::fs::write(root.join("record"), b"{}\n").expect("a changed directory");

        windows_fsync_dir(&root, WINDOWS_DIRECTORY_ACCESS)
            .expect("the production mask must flush a directory");

        let read_only = windows_fsync_dir(&root, windows_sys::Win32::Foundation::GENERIC_READ);
        let refusal = read_only
            .expect_err("a read-only handle must not be able to flush; the mask is over-asking");
        assert_eq!(
            refusal.raw_os_error(),
            Some(5),
            "the refusal must be ERROR_ACCESS_DENIED, which is what makes the write \
             right load-bearing rather than incidental: {refusal:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
