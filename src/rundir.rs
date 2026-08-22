//! Run directory layout (DESIGN.md §15) and run discovery.
//!
//! §15 draws the whole run directory under `.tactus/runs/<run-id>/`. This
//! module splits it in two, and the reason is enforcement rather than tidiness.
//!
//! A reviewer is a read-only agent pointed at the workspace, so every path
//! inside the workspace is reachable — including, before this split, the
//! implementer's own transcript. Invariant 3 says the diff is ground truth and
//! the transcript is not, so a reviewer reading the transcript is judging the
//! wrong evidence. Permission deny rules cannot close that on their own: gates
//! execute repository code the implementer just wrote, and that code reads any
//! workspace path the deny list never sees.
//!
//! So the split follows what each file is *for*. The ops surface — what
//! `status`, `resume`, `answer`, and any future pane read — stays in the repo
//! where §15 documents it and where CI can collect it. The agent-authored text
//! moves to a user-level directory no sandboxed agent has a path into. The
//! `run_started` event records where that directory is, so the record stays
//! self-describing rather than depending on this function's defaults.
// Allowlist placement: the **funnel section** of `effects/allowlist.toml`, which
// carries this module's review clause -- effects only inside site-taking APIs,
// no writable handle returned. `decisions.effect_site_inventory.mechanism` (2).
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::TactusError;
use crate::runner::policy::runner_policy_sha256;
use crate::topology::effects::{
    AnswerSite, EffectSiteId, HookHarness, HookPhase, Injection, LockSite, RunDirSite,
};
use crate::topology::events::RunnerPolicy;
use crate::util::{self, DurabilityLedger, DurableStep};
use crate::workspace::Workspace;

/// Created beside the repo: the run's own record and the human/UI surface.
const PUBLIC_DIRS: [&str; 3] = ["artifacts", "questions", "answers"];
/// Created outside the workspace: everything an agent wrote or that describes
/// an agent's sandbox.
const PRIVATE_DIRS: [&str; 5] = [
    "transcripts",
    "reviews",
    "settings",
    "gates",
    "gate-worktrees",
];

/// Where one run's files live, split by who is allowed to read them.
#[derive(Debug, Clone)]
pub struct RunPaths {
    /// `<repo>/.tactus/runs/<run-id>` — `events.jsonl`, the frozen plan,
    /// artifacts, questions, answers, the lock. Git-ignored, but present
    /// beside the repository it describes.
    pub public: PathBuf,
    /// `~/.tactus/runs/<run-id>` — transcripts, review verdicts, gate logs,
    /// and the per-attempt permission settings that define each sandbox.
    pub private: PathBuf,
}

impl RunPaths {
    /// Layout for a fresh run, with the private half at its default root.
    pub fn new(repo_root: &Path, run_id: &str) -> Self {
        Self::with_private_root(repo_root, run_id, &default_private_root())
    }

    /// Layout with an explicit private root — how tests stay out of the real
    /// `~/.tactus`, and how a caller pins the location deliberately.
    pub fn with_private_root(repo_root: &Path, run_id: &str, private_root: &Path) -> Self {
        Self {
            public: public_dir(repo_root, run_id),
            private: private_root.join("runs").join(run_id),
        }
    }

    /// Rebuild from a private directory recorded in `run_started`. Resume and
    /// status use this so they read the run that actually happened rather than
    /// wherever today's defaults would have put it.
    pub fn from_parts(public: PathBuf, private: PathBuf) -> Self {
        Self { public, private }
    }

    /// Create both trees. Callers do this once at run start; every accessor
    /// below assumes it has happened.
    ///
    /// Behaviour-neutral relative to the `create_dir_all` loop this replaced —
    /// the same directories, in the same order — but now through the two sites
    /// that own them, so the effect is inventoried rather than ambient.
    pub fn create(&self) -> Result<(), TactusError> {
        self.create_hooked(&mut NoHooks)
    }

    /// The same creation, observed: `RunDir.CreatePublicDir` (P0) then
    /// `RunDir.CreatePrivateDir` (P2/P3), each followed by its skeleton.
    pub fn create_hooked(&self, hooks: &mut dyn RunDirHooks) -> Result<(), TactusError> {
        create_public_dir(&self.public, hooks)?;
        for name in PUBLIC_DIRS {
            create_dir(&self.public.join(name))?;
        }
        create_private_dir(&self.private, hooks)?;
        for name in PRIVATE_DIRS {
            create_dir(&self.private.join(name))?;
        }
        Ok(())
    }

    /// The append-only source of truth (§15).
    pub fn events(&self) -> PathBuf {
        self.public.join("events.jsonl")
    }

    /// The frozen plan this run is executing (§5).
    pub fn plan_json(&self) -> PathBuf {
        self.public.join("plan.normalized.json")
    }

    /// A projection of the log for humans and tooling — derived, never read
    /// back as state.
    pub fn report_json(&self) -> PathBuf {
        self.public.join("report.json")
    }

    /// Held for the lifetime of a run so two engines cannot drive one branch.
    pub fn lock_file(&self) -> PathBuf {
        lock_file(&self.public)
    }

    pub fn questions(&self) -> PathBuf {
        self.public.join("questions")
    }

    /// Where `tactus answer` drops an answer for the engine to ingest.
    pub fn answers(&self) -> PathBuf {
        self.public.join("answers")
    }

    pub fn artifacts(&self) -> PathBuf {
        self.public.join("artifacts")
    }

    pub fn transcripts(&self) -> PathBuf {
        self.private.join("transcripts")
    }

    pub fn reviews(&self) -> PathBuf {
        self.private.join("reviews")
    }

    pub fn settings(&self) -> PathBuf {
        self.private.join("settings")
    }

    pub fn gates(&self) -> PathBuf {
        self.private.join("gates")
    }

    /// Durable intents and disposable directories for exact gate/review
    /// worktrees. This lives outside the candidate workspace, so a hard-killed
    /// engine can reclaim Git registrations before a resumed worker runs.
    pub fn gate_worktrees(&self) -> PathBuf {
        self.private.join("gate-worktrees")
    }
}

/// `~/.tactus`, or a temp-dir equivalent when no home resolves.
///
/// The fallback is deliberately still outside the workspace. Falling back to
/// the repo would keep runs working on a machine with no `HOME` while silently
/// dropping the isolation this module exists for — a security property that
/// degrades quietly is worse than one that was never claimed.
pub fn default_private_root() -> PathBuf {
    util::user_tactus_dir().unwrap_or_else(|| std::env::temp_dir().join("tactus"))
}

/// `<repo>/.tactus/runs/<run-id>` — §15's documented location.
pub fn public_dir(repo_root: &Path, run_id: &str) -> PathBuf {
    runs_root(repo_root).join(run_id)
}

pub fn runs_root(repo_root: &Path) -> PathBuf {
    repo_root.join(".tactus").join("runs")
}

// ===========================================================================
// The funnel
// ===========================================================================

/// What a run-directory or lock funnel tells whoever is watching.
///
/// `decisions.effect_site_inventory.identity`: "every effectful funnel API
/// takes its group's site by value, and the funnel itself calls `hook(Before,
/// site) -> primitive -> hook(After, site)`, so hooks exist for every site by
/// construction".
///
/// Production passes [`NoHooks`], which answers [`Injection::Proceed`] to
/// everything. A suite passes an observer that records what was reached and
/// answers with whatever it armed. [`HarnessHooks`] wires the same calls onto
/// PR3's [`HookHarness`] so the ST-07 bijection can read them.
///
/// The two phases are not decoration. `RunDirSite::sub_effects()` is empty for
/// every site in the frozen inventory, so `Before` and `After` are the only
/// coordinates a fault can be placed at — and for the publication sites they
/// are exactly the two the fault matrix names: `T-RUNSTART`'s "kill between
/// stage and rename" is a kill at `Before`, and its "a `PublishCommitRecord`
/// error after which the record is present" is an error returned at `After`,
/// which is what [`InjectionMode::ErrorReturn`](crate::topology::effects::InjectionMode)
/// means — "the funnel returns `Err` from that point **after** performing or
/// partially performing the primitive".
pub trait RunDirHooks {
    /// The funnel reached `phase` of `site`. The answer says what to do there.
    fn hook(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection;

    /// Where this observer wants the funnel's durability primitives recorded.
    ///
    /// The sibling of [`crate::workspace_manager::EffectHooks::durability_ledger`]
    /// and of `events::log::EventHooks::synced`, and for the reason
    /// `PR5-RUNDIR-057` measured: `run_creation` specifies each of the three
    /// atomic publications here as "write `<name>.tmp`, **fsync**, rename,
    /// **fsync the directory**", and with no ledger the two fsyncs were not
    /// observables at all — the whole suite stayed green with the staged file's
    /// `sync_all` deleted, because an unsynced file parses exactly like a
    /// synced one.
    ///
    /// A *handle*, taken before the funnel body runs, because `funnel` holds
    /// `&mut dyn RunDirHooks` across the body. The default records nothing.
    fn durability_ledger(&self) -> DurabilityLedger {
        DurabilityLedger::off()
    }
}

/// What production passes: nothing is armed and nothing is recorded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl RunDirHooks for NoHooks {
    fn hook(&mut self, _site: EffectSiteId, _phase: HookPhase) -> Injection {
        Injection::Proceed
    }
}

/// Wires these funnels onto PR3's [`HookHarness`], the way
/// [`crate::runner::HarnessHooks`] wires the process funnel onto it.
#[derive(Debug, Clone, Default)]
pub struct HarnessHooks {
    harness: Arc<Mutex<HookHarness>>,
    ledger: DurabilityLedger,
}

impl HarnessHooks {
    /// Observe through `harness`.
    #[must_use]
    pub fn new(harness: Arc<Mutex<HookHarness>>) -> Self {
        Self {
            harness,
            ledger: DurabilityLedger::off(),
        }
    }

    /// The harness this observer records into.
    #[must_use]
    pub fn harness(&self) -> &Arc<Mutex<HookHarness>> {
        &self.harness
    }

    /// Also record every durability primitive the funnels perform.
    #[must_use]
    pub fn recording_durability(mut self) -> Self {
        self.ledger = DurabilityLedger::recording();
        self
    }

    /// The durability ledger this observer records into.
    #[must_use]
    pub fn ledger(&self) -> DurabilityLedger {
        self.ledger.clone()
    }
}

impl RunDirHooks for HarnessHooks {
    fn durability_ledger(&self) -> DurabilityLedger {
        self.ledger.clone()
    }

    fn hook(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection {
        self.harness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .hook(site, phase)
    }
}

/// Do what a hook answered.
///
/// [`Injection::Kill`] aborts rather than panicking or exiting, for the same
/// reason [`crate::agent::proc`] aborts: the claim under test is what a
/// coordinator that runs **no** cleanup leaves behind, and both of the other
/// two run destructors.
fn apply(injection: Injection, site: EffectSiteId, phase: HookPhase) -> Result<(), TactusError> {
    match injection {
        Injection::Proceed => Ok(()),
        Injection::Kill => std::process::abort(),
        Injection::Error => Err(TactusError::Refused {
            message: format!("the run-directory funnel was made to fail at `{site}` ({phase})"),
        }),
    }
}

/// One effect, between its two hook phases.
///
/// An `Err` from the `After` phase is returned *after* the primitive ran, which
/// is the whole point of the error-return mode and the reason the commit
/// record's post-error helper has to stat rather than infer.
fn funnel<T>(
    hooks: &mut dyn RunDirHooks,
    site: EffectSiteId,
    primitive: impl FnOnce() -> Result<T, TactusError>,
) -> Result<T, TactusError> {
    apply(hooks.hook(site, HookPhase::Before), site, HookPhase::Before)?;
    let produced = primitive()?;
    apply(hooks.hook(site, HookPhase::After), site, HookPhase::After)?;
    Ok(produced)
}

// ---------------------------------------------------------------------------
// The names on disk
// ---------------------------------------------------------------------------

/// `<public>/.creating` — the P1 marker.
pub const MARKER: &str = ".creating";
/// `<public>/.creating.tmp` — the P1 staging file.
pub const MARKER_STAGED: &str = ".creating.tmp";
/// `<private>/owner.json` — the P3b reciprocal ownership record.
pub const OWNER_RECORD: &str = "owner.json";
/// `<private>/owner.json.tmp`.
pub const OWNER_RECORD_STAGED: &str = "owner.json.tmp";
/// `<private>/committed.json` — the P5b private commit record.
pub const COMMIT_RECORD: &str = "committed.json";
/// `<private>/committed.json.tmp`.
pub const COMMIT_RECORD_STAGED: &str = "committed.json.tmp";
/// `<public>/events.jsonl`.
pub const EVENT_LOG: &str = "events.jsonl";
/// `<public>/plan.normalized.json`.
pub const PLAN: &str = "plan.normalized.json";

// ---------------------------------------------------------------------------
// The records
// ---------------------------------------------------------------------------

/// `<public>/.creating` — what P1 publishes.
///
/// `workspace_candidates.run_creation`: "write `<public>/.creating.tmp` (JSON:
/// run_id, repo_key, private_dir = `<authorized private root>/runs/<run_id>` as
/// a canonical path, incarnation, pid, runner_policy_sha256)". Six fields, and
/// `deny_unknown_fields` because a marker is read back by a census that decides
/// whether a directory may be deleted: a field this build does not understand
/// is a marker this build must not act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatingMarker {
    pub run_id: String,
    pub repo_key: String,
    /// `<authorized private root>/runs/<run_id>`, canonical.
    pub private_dir: String,
    pub incarnation: String,
    pub pid: u32,
    pub runner_policy_sha256: String,
}

/// `<private>/owner.json` — what P3b publishes.
///
/// `run_creation`: "(JSON: run_id, repo_key, public_dir as the canonical path
/// of the public run directory, incarnation, runner: the full RunnerPolicy)".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecord {
    pub run_id: String,
    pub repo_key: String,
    /// The canonical path of the public run directory.
    pub public_dir: String,
    pub incarnation: String,
    /// The full policy, not its digest: the marker carries the digest and the
    /// proof compares the two, so a record carrying only the digest could not
    /// be checked against anything.
    pub runner: RunnerPolicy,
}

/// `<private>/committed.json` — what P5b publishes.
///
/// `run_creation`: "{run_id, repo_key, public_dir, incarnation,
/// run_started_sha256 = the digest of the exact run_started line bytes about to
/// be appended}". Its presence is the one deletion boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRecord {
    pub run_id: String,
    pub repo_key: String,
    pub public_dir: String,
    pub incarnation: String,
    /// The digest of the exact `run_started` line bytes about to be appended.
    pub run_started_sha256: String,
}

/// This repository's identity, as the marker and both private records carry it.
///
/// `workspace_candidates.execution_root`: "repo_key v1 = hex16(sha256(
/// 'tactus-repo-key-v1' NUL canonical common git dir bytes))". `hex16` is read
/// as sixteen hex characters — the first eight bytes of the digest — because
/// the same passage uses the key as a path component of the execution root and
/// a 64-character component is not what "key" describes there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoKey(String);

impl RepoKey {
    /// The v1 key over a canonical common git dir.
    ///
    /// The path's bytes, not its display form: a path is bytes on Unix and
    /// `to_string_lossy` would map two distinguishable repositories onto one
    /// key exactly where a non-UTF-8 path makes the difference matter.
    #[must_use]
    pub fn v1(canonical_common_git_dir: &Path) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"tactus-repo-key-v1");
        hasher.update([0u8]);
        hasher.update(canonical_common_git_dir.as_os_str().as_encoded_bytes());
        let digest = format!("{:x}", hasher.finalize());
        Self(digest[..16].to_owned())
    }

    /// The v1 key for a repository, from the git dir of one of its worktrees.
    ///
    /// A linked worktree's git dir is `<common>/worktrees/<name>` (Git's own
    /// layout), and every worktree of one repository must produce one key —
    /// otherwise a run created in the main checkout and a census run from a
    /// linked one would each call the other foreign. A main worktree's git dir
    /// is already the common one.
    pub fn for_worktree_git_dir(worktree_git_dir: &Path) -> Result<Self, TactusError> {
        Ok(Self::v1(&canonical(common_git_dir(worktree_git_dir))?))
    }

    /// The v1 key for the repository `repo_root` is a worktree of.
    pub fn for_repo(repo_root: &Path) -> Result<Self, TactusError> {
        let workspace = Workspace::open(repo_root)?;
        Self::for_worktree_git_dir(&workspace.worktree_git_dir()?)
    }

    /// The key as it is written into a marker or a record.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Read a key back off disk. No validation: a marker carrying a key this
    /// repository does not have is a mismatch to report, never a parse error.
    #[must_use]
    pub fn from_recorded(recorded: &str) -> Self {
        Self(recorded.to_owned())
    }
}

impl std::fmt::Display for RepoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The common git dir behind a worktree git dir.
fn common_git_dir(worktree_git_dir: &Path) -> PathBuf {
    let mut parts = worktree_git_dir.iter().rev();
    let last = parts.next();
    let penultimate = parts.next();
    match (last, penultimate) {
        // `<common>/worktrees/<name>` — two levels up is the common dir.
        (Some(_), Some(dir)) if dir == std::ffi::OsStr::new("worktrees") => worktree_git_dir
            .parent()
            .and_then(Path::parent)
            .map_or_else(|| worktree_git_dir.to_path_buf(), Path::to_path_buf),
        _ => worktree_git_dir.to_path_buf(),
    }
}

fn canonical(path: PathBuf) -> Result<PathBuf, TactusError> {
    fs::canonicalize(&path).map_err(|source| TactusError::Io { path, source })
}

// ---------------------------------------------------------------------------
// Atomic publication
// ---------------------------------------------------------------------------

/// Write JSON to `path` and make the bytes durable.
///
/// The staging half of every atomic publication here: `run_creation` says
/// "write `<name>.tmp`, fsync, rename, fsync the directory", and this is the
/// first two steps.
fn stage_json<T: Serialize>(
    path: &Path,
    value: &T,
    ledger: &DurabilityLedger,
) -> Result<(), TactusError> {
    let mut json = serde_json::to_string_pretty(value).map_err(|error| TactusError::Parse {
        message: format!("serializing {}: {error}", path.display()),
    })?;
    json.push('\n');
    let io = |source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = File::create(path).map_err(io)?;
    file.write_all(json.as_bytes()).map_err(io)?;
    sync_file_recorded(&file, path, ledger)
}

/// fsync `file` and record what was made durable, in one call.
///
/// Fused for the reason `events::log::sync_log_file` gives: with the sync and
/// its ledger entry written as two statements, a mutation can be placed between
/// them. It does not close the residual boundary — deleting the `sync_all` line
/// *inside here* leaves the record and is undetectable on a machine that does
/// not lose power — and nothing here claims it does. What it does close is the
/// mutation the catalogue actually names: removing the durability step from a
/// publication sequence, which now removes its evidence too.
fn sync_file_recorded(
    file: &File,
    path: &Path,
    ledger: &DurabilityLedger,
) -> Result<(), TactusError> {
    let io = |source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    };
    let outcome = util::fsync_file(file);
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    ledger.record(DurableStep::SyncedFile, path, len);
    outcome.map_err(io)
}

/// Rename the staged file onto its published name and make the directory entry
/// durable.
fn publish(staged: &Path, published: &Path, ledger: &DurabilityLedger) -> Result<(), TactusError> {
    fs::rename(staged, published).map_err(|source| TactusError::Io {
        path: published.to_path_buf(),
        source,
    })?;
    ledger.record(
        DurableStep::Renamed,
        published,
        fs::metadata(published).map(|meta| meta.len()).unwrap_or(0),
    );
    match published.parent() {
        Some(dir) => sync_dir(dir, ledger),
        None => Ok(()),
    }
}

/// fsync a directory, on every platform (`PR5-CONF-013`).
///
/// This was Unix-only, with a comment saying Windows had no directory handle a
/// program could `FlushFileBuffers` "without `FILE_FLAG_BACKUP_SEMANTICS` and a
/// raw handle". That is the *recipe*, not an obstacle, and `run_creation`'s
/// "fsync the directory" carries no platform exception — so
/// [`crate::util::fsync_dir`] performs it and this function stays what it always
/// was: the site's ledger entry beside the barrier.
fn sync_dir(dir: &Path, ledger: &DurabilityLedger) -> Result<(), TactusError> {
    util::fsync_dir(dir).map_err(|source| TactusError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    ledger.record(DurableStep::SyncedDirectory, dir, 0);
    Ok(())
}

/// Create a directory and everything above it.
fn create_dir(dir: &Path) -> Result<(), TactusError> {
    fs::create_dir_all(dir).map_err(|source| TactusError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

// ---------------------------------------------------------------------------
// The run-directory funnels
// ---------------------------------------------------------------------------

/// P0 — `RunDir.CreatePublicDir`.
pub fn create_public_dir(public: &Path, hooks: &mut dyn RunDirHooks) -> Result<(), TactusError> {
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::CreatePublicDir),
        || create_dir(public),
    )
}

/// P1a — `RunDir.StageMarker`. Writes `<public>/.creating.tmp` and syncs it.
pub fn stage_marker(
    public: &Path,
    marker: &CreatingMarker,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    let ledger = hooks.durability_ledger();
    funnel(hooks, EffectSiteId::RunDir(RunDirSite::StageMarker), || {
        stage_json(&public.join(MARKER_STAGED), marker, &ledger)
    })
}

/// P1b — `RunDir.PublishMarker`. The atomic rename onto `<public>/.creating`.
pub fn publish_marker(public: &Path, hooks: &mut dyn RunDirHooks) -> Result<(), TactusError> {
    let ledger = hooks.durability_ledger();
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::PublishMarker),
        || publish(&public.join(MARKER_STAGED), &public.join(MARKER), &ledger),
    )
}

/// P7 — `RunDir.RemoveMarker`, once `run_started` is durable.
///
/// Idempotent: a census and the owning resume both remove a stale marker, and
/// `resource_accounting` has a stale marker removed "by a census with the lock
/// free **or** by its owner on resume".
pub fn remove_marker(public: &Path, hooks: &mut dyn RunDirHooks) -> Result<(), TactusError> {
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::RemoveMarker),
        || {
            remove_file_if_present(&public.join(MARKER))?;
            remove_file_if_present(&public.join(MARKER_STAGED))
        },
    )
}

/// P2/P3 — `RunDir.CreatePrivateDir`.
pub fn create_private_dir(private: &Path, hooks: &mut dyn RunDirHooks) -> Result<(), TactusError> {
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::CreatePrivateDir),
        || create_dir(private),
    )
}

/// P3a — `RunDir.StageOwnerRecord`.
pub fn stage_owner_record(
    private: &Path,
    owner: &OwnerRecord,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    let ledger = hooks.durability_ledger();
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::StageOwnerRecord),
        || stage_json(&private.join(OWNER_RECORD_STAGED), owner, &ledger),
    )
}

/// P3b — `RunDir.PublishOwnerRecord`, before any other private content.
pub fn publish_owner_record(
    private: &Path,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    let ledger = hooks.durability_ledger();
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::PublishOwnerRecord),
        || {
            publish(
                &private.join(OWNER_RECORD_STAGED),
                &private.join(OWNER_RECORD),
                &ledger,
            )
        },
    )
}

/// P5a — `RunDir.StageCommitRecord`.
pub fn stage_commit_record(
    private: &Path,
    record: &CommitRecord,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    let ledger = hooks.durability_ledger();
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::StageCommitRecord),
        || stage_json(&private.join(COMMIT_RECORD_STAGED), record, &ledger),
    )
}

/// P5b — `RunDir.PublishCommitRecord`, the one deletion boundary.
///
/// `effect_site_inventory.identity`: "after this site returns, or when a
/// read-only stat after its error shows the record present, no path — creator
/// or census — deletes the private half". The stat is
/// [`commit_record_after_error`], and it is a separate call precisely because
/// an error here does not say which side of the boundary the run is on.
pub fn publish_commit_record(
    private: &Path,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    let ledger = hooks.durability_ledger();
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::PublishCommitRecord),
        || {
            publish(
                &private.join(COMMIT_RECORD_STAGED),
                &private.join(COMMIT_RECORD),
                &ledger,
            )
        },
    )
}

/// Which side of the deletion boundary an errored publication left the run on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitRecordPresence {
    /// The record is on disk. Nothing deletes either half from here on.
    Present,
    /// It is not. The creator, which holds both locks and knows the run never
    /// committed, may remove both halves.
    Absent,
    /// The filesystem would not say. Not an answer, and treated as `Present`
    /// by every caller, because the cost of being wrong is asymmetric: a
    /// retained husk is reported until an operator prunes it, and a deleted
    /// committed run is gone.
    Unknown(String),
}

impl CommitRecordPresence {
    /// Whether deletion is still permitted. `Unknown` is not.
    #[must_use]
    pub const fn permits_deletion(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// The read-only stat after a staging or publication error.
///
/// It **stats**. It does not read the error: `run_creation` distinguishes "a
/// P5b error after which the record is absent" from "a P5b error after which
/// the record is present", and the error is the same value in both cases —
/// the funnel's error-return mode returns `Err` *after* performing the rename.
/// Inferring absence from an error would delete a private half that had
/// already crossed the boundary.
#[must_use]
pub fn commit_record_after_error(private: &Path) -> CommitRecordPresence {
    let path = private.join(COMMIT_RECORD);
    match fs::symlink_metadata(&path) {
        Ok(_) => CommitRecordPresence::Present,
        Err(error) if error.kind() == io::ErrorKind::NotFound => CommitRecordPresence::Absent,
        Err(error) => CommitRecordPresence::Unknown(format!("{}: {error}", path.display())),
    }
}

/// P5 — `RunDir.WritePlan`.
pub fn write_plan(
    public: &Path,
    normalized: &[u8],
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    funnel(hooks, EffectSiteId::RunDir(RunDirSite::WritePlan), || {
        let path = public.join(PLAN);
        fs::write(&path, normalized).map_err(|source| TactusError::Io { path, source })
    })
}

/// `RunDir.WriteReport` — the derived projection, never read back as state.
pub fn write_report<T: Serialize>(
    public: &Path,
    report: &T,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    funnel(hooks, EffectSiteId::RunDir(RunDirSite::WriteReport), || {
        util::write_json(&public.join("report.json"), report)
    })
}

/// `RunDir.WriteQuestionPayload` — written before the question is announced.
pub fn write_question_payload<T: Serialize>(
    questions: &Path,
    component: &str,
    payload: &T,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::WriteQuestionPayload),
        || util::write_json(&questions.join(format!("{component}.json")), payload),
    )
}

/// `RunDir.RemovePublicHusk` — the public half, with the marker last.
///
/// `startup_census`: "then the public directory is removed with the marker
/// last … so a kill mid-census leaves a husk the next census completes".
/// Removing the marker first would leave a marker-less husk carrying content,
/// which the next census retains rather than finishes.
pub fn remove_public_husk(public: &Path, hooks: &mut dyn RunDirHooks) -> Result<(), TactusError> {
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::RemovePublicHusk),
        || {
            for entry in read_dir_names(public) {
                if entry == MARKER {
                    continue;
                }
                let path = public.join(&entry);
                let removed = if path.is_dir() {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
                removed.map_err(|source| TactusError::Io { path, source })?;
            }
            remove_file_if_present(&public.join(MARKER))?;
            fs::remove_dir(public).map_err(|source| TactusError::Io {
                path: public.to_path_buf(),
                source,
            })
        },
    )
}

/// `RunDir.RemovePrivateHusk` — and the only way to reach it is a token.
///
/// `resource_accounting.completeness_rule`: "a private-half deletion outside
/// the proof-token funnel fails to compile". The token is taken **by value**,
/// so it is spent here and cannot authorise a second deletion, and
/// [`PrivateHalfProof`] has no other constructor, no `Clone`, no `Copy` and no
/// `Default` — see [`ownership`].
pub fn remove_private_husk(
    proof: PrivateHalfProof,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    funnel(
        hooks,
        EffectSiteId::RunDir(RunDirSite::RemovePrivateHusk),
        || {
            let target = proof.target();
            fs::remove_dir_all(target).map_err(|source| TactusError::Io {
                path: target.to_path_buf(),
                source,
            })
        },
    )
}

fn remove_file_if_present(path: &Path) -> Result<(), TactusError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TactusError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_dir_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// The answer funnels
// ---------------------------------------------------------------------------

/// `Answer.StageWrite` — `answers/<qid>.json.partial`, writer-owned residue
/// that every reader ignores and no coordinator ever prunes (R21).
pub fn stage_answer<T: Serialize>(
    answers: &Path,
    component: &str,
    answer: &T,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    funnel(hooks, EffectSiteId::Answer(AnswerSite::StageWrite), || {
        util::write_json(&answers.join(format!("{component}.json.partial")), answer)
    })
}

/// `Answer.PublishRename` — the answer exists for the engine from here.
pub fn publish_answer(
    answers: &Path,
    component: &str,
    hooks: &mut dyn RunDirHooks,
) -> Result<(), TactusError> {
    funnel(
        hooks,
        EffectSiteId::Answer(AnswerSite::PublishRename),
        || {
            let staged = answers.join(format!("{component}.json.partial"));
            let published = answers.join(format!("{component}.json"));
            fs::rename(&staged, &published).map_err(|source| TactusError::Io {
                path: published,
                source,
            })
        },
    )
}

/// `Answer.Ingest` — read-only observation, no effect.
///
/// Hooked all the same: the site is in the frozen inventory with
/// `is_read_only()`, and a read-only site that never calls its hooks cannot be
/// shown to have executed.
pub fn ingest_answer(
    answers: &Path,
    component: &str,
    hooks: &mut dyn RunDirHooks,
) -> Result<Option<String>, TactusError> {
    funnel(hooks, EffectSiteId::Answer(AnswerSite::Ingest), || {
        let path = answers.join(format!("{component}.json"));
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(TactusError::Io { path, source }),
        }
    })
}

// ===========================================================================
// Classification
// ===========================================================================

/// What a directory under `<repo>/.tactus/runs` is.
///
/// `sequential_substrate.startup_census`: "every entry is classified by
/// `rundir::classify_run_dir` as **Committed** (`events.jsonl` exists and its
/// first newline-terminated line is a valid `run_started`) or **Husk**
/// (anything else)".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDirClass {
    /// A run exists here and is resumable.
    Committed,
    /// No committed `run_started`. Nothing about a marker changes this, in
    /// either direction.
    Husk,
}

/// How much of `events.jsonl` the first-line probe reads in one go.
///
/// **A performance constant, not a classification bound.** A `run_started` line
/// records the plan path, the gate commands and the runner policy — kilobytes,
/// not megabytes — so a megabyte reaches the newline in a single read for every
/// log this project has ever written. A longer first line is still a first
/// line: `startup_census` defines `Committed` as "`events.jsonl` exists and its
/// first newline-terminated line is a valid `run_started`" and states no size
/// exception, so [`first_line`] falls back to a scan rather than answering
/// `Husk`. Changing this value changes how many syscalls the census makes and
/// nothing else — `classification_does_not_depend_on_the_probe_window` is the
/// assertion, and it is why the name no longer says "cap".
///
/// It exists at all because this runs once per directory in a census: reading
/// the whole file to look for a newline that is not there is the one shape that
/// must stay cheap, and [`newline_offset_from`] handles it in a fixed-size
/// buffer that never grows.
///
/// (`PR5-CORRECTNESS-002`: as a *cap* this was a classification bound, and a
/// valid `run_started` past it was hidden from every reader.)
const FIRST_LINE_WINDOW: u64 = 1 << 20;

/// The fixed buffer [`newline_offset_from`] scans through. Never allocated per
/// byte read and never grown, so a log with no newline at all — the shape the
/// window exists for — costs one stack buffer however large the file is.
const SCAN_CHUNK: usize = 64 * 1024;

/// Classify one run directory. Read-only, and total.
#[must_use]
pub fn classify_run_dir(public: &Path) -> RunDirClass {
    match first_committed_line(public) {
        Some(_) => RunDirClass::Committed,
        None => RunDirClass::Husk,
    }
}

/// The header of a committed first line, or `None` if there is not one.
///
/// Deliberately not `events::started_of`: recovery step (a0) probes this
/// header and only *then* "select[s] the engine by schema", so classification
/// cannot be schema-specific — a schema-4 log must classify through the same
/// call as a schema-1 one, and each engine's own event type refuses the other's.
fn first_committed_line(public: &Path) -> Option<RunStartedHeader> {
    let path = public.join(EVENT_LOG);
    // `open(2)` runs *before* the read, and the read's bound cannot defend it
    // (`PR5-CONF-001`). `open` on a fifo with no writer blocks in the kernel and
    // never returns a handle at all, so `first_line`'s fstat bound — which is
    // taken on a handle this function has already been given — is not reached.
    // That is `PR5-RD-001`'s consequence one syscall earlier: `startup_census`
    // requires *every* entry to classify before a write command proceeds, and
    // the command holds the physical worktree lock across the census, so an
    // entry that never classifies is a lock held for ever.
    //
    // The guard is `symlink_metadata`, not `metadata`, and the difference is
    // deliberate. `stat(2)` on a fifo answers immediately, so either would
    // terminate; what following the link would leave open is a **swap of the
    // link's target** between the check and the open. Refusing the link itself
    // narrows the residual race to replacing a directory entry the census owns.
    // A symlinked `events.jsonl` is therefore a `Husk` whatever it points at,
    // which is this module's stance elsewhere (`:764`, `:1595`) and is the safe
    // direction: a husk is never deleted on shape alone — deletion additionally
    // requires the ownership proof, which requires `committed.json` to be
    // absent, and a run that reached `run_started` published one at P5b.
    if !fs::symlink_metadata(&path).is_ok_and(|entry| entry.is_file()) {
        return None;
    }
    let mut file = File::open(&path).ok()?;
    let line = first_line(&mut file)?;
    let line = std::str::from_utf8(&line).ok()?;
    let header: RunStartedHeader = serde_json::from_str(line).ok()?;
    (header.event == "run_started" && header.data.schema >= 1 && !header.data.run_id.is_empty())
        .then_some(header)
}

/// The bytes of the first newline-terminated line, without its newline, or
/// `None` when the file holds no newline at all.
///
/// The read is bounded by the file's **own length**, taken by `fstat` on the
/// handle that is about to be read (`PR5-RD-001`). Two properties have to hold
/// at once here and an earlier repair traded one for the other:
///
/// * **A committed run is never hidden.** `startup_census` defines `Committed`
///   as "`events.jsonl` exists and its first newline-terminated line is a valid
///   `run_started`" and states no size exception, so a first line past the
///   window must still be found. It is: the bound is the whole file, so the
///   scan reaches any newline a regular file actually contains, however far in.
/// * **Classification terminates.** Before this, the scan ran until a read
///   returned zero — which an endless source never does. A public run directory
///   whose `events.jsonl` was a symlink to `/dev/zero` was therefore never
///   classified at all, and since `startup_census` requires *every* entry to be
///   `Committed` or `Husk` before a write command proceeds, the command held
///   the worktree lock for ever. The file's own length is a bound the source
///   cannot argue with: a source that declares no length is read zero bytes.
///
/// The bound is the *read*, never the answer — the distinction the removed
/// `FIRST_LINE_CAP` got wrong.
///
/// It bounds a handle it is **given**, so it says nothing about how that handle
/// was obtained, and the earlier version of this comment overstated itself by
/// concluding "a device or a fifo … is a `Husk`" (`PR5-CONF-001`). That is true
/// of a device, whose `open` returns; it was never true of a writer-less fifo,
/// whose `open` does not. [`first_committed_line`] carries that half now, by
/// refusing to open anything that is not a regular file, and this function
/// still carries the endless-*device* half — both are measured together in
/// [`a_run_directory_whose_log_never_ends_is_still_classified`].
fn first_line(file: &mut File) -> Option<Vec<u8>> {
    let bound = file.metadata().ok()?.len();
    first_line_within(file, bound)
}

/// [`first_line`] over any source, with the byte budget given explicitly.
///
/// Split out so the budget is a *value a test can supply* rather than a
/// property of a file a test would have to construct. The endless source the
/// production bound defends against is `/dev/zero`, which exists on one of the
/// two platforms this ships on and cannot be built at all on the other; over
/// this signature the same source is a twenty-line reader, so the termination
/// claim is measured on every host rather than on Linux only.
fn first_line_within<R: Read + Seek>(source: &mut R, bound: u64) -> Option<Vec<u8>> {
    let mut window = Vec::new();
    source
        .by_ref()
        .take(FIRST_LINE_WINDOW.min(bound))
        .read_to_end(&mut window)
        .ok()?;
    if let Some(newline) = window.iter().position(|byte| *byte == b'\n') {
        window.truncate(newline);
        return Some(window);
    }
    // The cursor is at `window.len()`, so the scan continues from there rather
    // than re-reading what the window already proved newline-free, and spends
    // only what the window did not.
    let scanned = window.len() as u64;
    let length = newline_offset_from(source, scanned, bound.saturating_sub(scanned))?;
    source.seek(SeekFrom::Start(0)).ok()?;
    let mut line = Vec::new();
    source.by_ref().take(length).read_to_end(&mut line).ok()?;
    // A log that shrank between the scan and the re-read has no first line this
    // probe can vouch for; `Husk` is the safe direction.
    (line.len() as u64 == length).then_some(line)
}

/// The absolute offset of the first `\n` at or after `offset`, in constant
/// memory, or `None` when there is none within `budget` further bytes.
///
/// `source`'s cursor must already be at `offset`. The offset of the newline is
/// also the length of the line that precedes it, which is what the caller
/// wants.
///
/// **Termination**: every iteration either returns or spends at least one byte
/// of `budget`, which is finite. The single branch that spends nothing is
/// `Interrupted`, which is `std::io`'s own convention for "this read did not
/// happen" and which a regular file does not produce; treating it as an end
/// instead would classify a committed run as a husk, which is the direction
/// that must never be taken.
fn newline_offset_from<R: Read>(source: &mut R, mut offset: u64, mut budget: u64) -> Option<u64> {
    let mut chunk = [0_u8; SCAN_CHUNK];
    while budget > 0 {
        let want = usize::try_from(budget.min(SCAN_CHUNK as u64)).ok()?;
        // A short read is normal, not an end: only zero means end of file.
        let read = match source.read(&mut chunk[..want]) {
            Ok(0) => return None,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        if let Some(at) = chunk[..read].iter().position(|byte| *byte == b'\n') {
            return Some(offset + at as u64);
        }
        offset += read as u64;
        budget -= read as u64;
    }
    None
}

/// The header of a committed first line: the envelope's tag, and the two
/// identifying fields inside its payload.
///
/// The wire is `{"ts": …, "event": "run_started", "data": {"schema": …,
/// "run_id": …, …}}` for every schema — `Event`/`TopologyEventBody` both tag on
/// `event` and both nest the record under `data`.
///
/// Unknown fields are allowed here and only here: this reads the *header* of a
/// line each schema's own type owns in full, and rejecting a schema-5 field
/// would classify a future run as a husk. What it does insist on is the shape
/// that makes the line a `run_started` at all — recovery step (a0) "probe[s]
/// the header of the committed first line" and then "select[s] the engine by
/// schema", so a line with no schema to select by is not one.
#[derive(Debug, Clone, Deserialize)]
struct RunStartedHeader {
    event: String,
    data: RunStartedIdentity,
}

#[derive(Debug, Clone, Deserialize)]
struct RunStartedIdentity {
    schema: u32,
    run_id: String,
}

/// The digest of a `run_started` line's exact bytes, for the commit record.
///
/// `run_creation`: "run_started_sha256 = the digest of the exact run_started
/// line bytes about to be appended".
#[must_use]
pub fn run_started_sha256(line: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(line))
}

// ===========================================================================
// The private half's ownership
// ===========================================================================

/// Why a husk is retained rather than reclaimed.
///
/// Every variant is a condition `prove_private_half_ownership` refuses on, and
/// the set is closed: `startup_census` (iii) enumerates the shapes, and
/// `expected_failures_refusals` enumerates them again as refusals. Nothing
/// private is ever deleted for any of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainReason {
    /// A marker that is not JSON, or not this marker's shape.
    MarkerUnparseable,
    /// The marker names a run other than the directory it sits in — a forged
    /// marker pointing at another run's private half.
    MarkerRunIdMismatch { recorded: String, directory: String },
    /// The marker's repository key is not this repository's: a directory
    /// copied from another repository.
    MarkerRepoKeyMismatch { recorded: String, expected: String },
    /// The recorded locator does not canonicalize to
    /// `<authorized private root>/runs/<basename>`.
    LocatorOutsideAuthorizedRoot { locator: PathBuf, expected: PathBuf },
    /// A component of the locator below the runs directory is a symlink or,
    /// on Windows, any reparse point — a junction included.
    LocatorThroughReparsePoint { component: PathBuf },
    /// P3a: the private directory exists, its owner record does not.
    OwnerRecordMissing,
    /// The owner record is not readable as one.
    OwnerRecordUnparseable,
    /// The owner record disagrees with the marker or with the directory.
    OwnerRecordDisagrees {
        field: OwnerField,
        recorded: String,
        expected: String,
    },
    /// A husk with no marker at all, carrying run-scoped content.
    MarkerlessWithContent,
    /// `committed.json` is present: the private half may have crossed P5b, so
    /// no census and no creating process ever deletes it.
    PossiblyCommitted,
}

impl RetainReason {
    /// Every kind of retention, as a closed set.
    ///
    /// The list a suite is measured against, so that a variant added later and
    /// tested by nobody fails a count rather than passing quietly. Rust has no
    /// reflection over variants, so [`Self::kind`]'s exhaustive match is what
    /// makes adding one to the enum and not to this list impossible.
    pub const KINDS: &'static [&'static str] = &[
        "marker-unparseable",
        "marker-run-id-mismatch",
        "marker-repo-key-mismatch",
        "locator-outside-authorized-root",
        "locator-through-reparse-point",
        "owner-record-missing",
        "owner-record-unparseable",
        "owner-record-disagrees",
        "markerless-with-content",
        "possibly-committed",
    ];

    /// This reason's kind. Exhaustive by construction.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::MarkerUnparseable => "marker-unparseable",
            Self::MarkerRunIdMismatch { .. } => "marker-run-id-mismatch",
            Self::MarkerRepoKeyMismatch { .. } => "marker-repo-key-mismatch",
            Self::LocatorOutsideAuthorizedRoot { .. } => "locator-outside-authorized-root",
            Self::LocatorThroughReparsePoint { .. } => "locator-through-reparse-point",
            Self::OwnerRecordMissing => "owner-record-missing",
            Self::OwnerRecordUnparseable => "owner-record-unparseable",
            Self::OwnerRecordDisagrees { .. } => "owner-record-disagrees",
            Self::MarkerlessWithContent => "markerless-with-content",
            Self::PossiblyCommitted => "possibly-committed",
        }
    }

    /// Which owner-record field disagreed, when that is what happened.
    #[must_use]
    pub const fn owner_field(&self) -> Option<OwnerField> {
        match self {
            Self::OwnerRecordDisagrees { field, .. } => Some(*field),
            _ => None,
        }
    }
}

/// Which field of the owner record disagreed.
///
/// `startup_census` (iii) names them: "a private target without an owner record
/// or with a disagreeing one" — disagreeing on "run id, repo key, public path,
/// incarnation, or runner digest" (ST-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OwnerField {
    RunId,
    RepoKey,
    PublicDir,
    Incarnation,
    RunnerDigest,
}

impl OwnerField {
    /// Every field the record is checked on.
    pub const ALL: &'static [Self] = &[
        Self::RunId,
        Self::RepoKey,
        Self::PublicDir,
        Self::Incarnation,
        Self::RunnerDigest,
    ];

    /// The field's name in the record.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RunId => "run_id",
            Self::RepoKey => "repo_key",
            Self::PublicDir => "public_dir",
            Self::Incarnation => "incarnation",
            Self::RunnerDigest => "runner digest",
        }
    }
}

impl std::fmt::Display for RetainReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MarkerUnparseable => f.write_str("its .creating marker cannot be read"),
            Self::MarkerRunIdMismatch {
                recorded,
                directory,
            } => write!(f, "its marker names run `{recorded}`, not `{directory}`"),
            Self::MarkerRepoKeyMismatch { recorded, expected } => write!(
                f,
                "its marker carries repository key `{recorded}`, not this repository's `{expected}`"
            ),
            Self::LocatorOutsideAuthorizedRoot { locator, expected } => write!(
                f,
                "its recorded private locator {} is not {}",
                locator.display(),
                expected.display()
            ),
            Self::LocatorThroughReparsePoint { component } => write!(
                f,
                "its private locator passes through the link {}",
                component.display()
            ),
            Self::OwnerRecordMissing => f.write_str("its private half carries no owner record"),
            Self::OwnerRecordUnparseable => {
                f.write_str("its private half's owner record cannot be read")
            }
            Self::OwnerRecordDisagrees {
                field,
                recorded,
                expected,
            } => write!(
                f,
                "its owner record's {} is `{recorded}`, not `{expected}`",
                field.name()
            ),
            Self::MarkerlessWithContent => {
                f.write_str("it carries run-scoped content but no marker to bind it")
            }
            Self::PossiblyCommitted => {
                f.write_str("its private half carries a commit record, so the run may have started")
            }
        }
    }
}

/// The shape of a husk that binds nothing private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnboundShape {
    /// P0: an empty public directory.
    Bare,
    /// P1a: only `.creating.tmp`, so the marker was never published and no
    /// private half exists by ordering.
    StagedMarkerOnly,
    /// P1b/P2: the marker published, its recorded target absent.
    TargetAbsent,
}

impl UnboundShape {
    /// Every shape, so a suite is measured against the closed set.
    pub const ALL: &'static [Self] = &[Self::Bare, Self::StagedMarkerOnly, Self::TargetAbsent];
}

/// What `prove_private_half_ownership` decided.
#[derive(Debug)]
pub enum PrivateHalfOwnership {
    /// The bidirectional proof holds and the private half carries no commit
    /// record. The token is the only key to [`remove_private_husk`].
    Proven(PrivateHalfProof),
    /// Nothing private is bound to this husk. The public half alone is
    /// reclaimed; there is no private half to prove anything about.
    NothingBound(UnboundShape),
    /// No token, ever. The census retains the husk and reports it.
    Retained(RetainReason),
}

pub use ownership::{PrivateHalfProof, prove_private_half_ownership};

/// The proof and the token it mints, alone in a module.
///
/// The token's fields are private to this module and this module contains
/// exactly one function, so [`prove_private_half_ownership`] is the only
/// constructor of [`PrivateHalfProof`] — not by convention but because no other
/// code, inside `rundir` or outside it, can name the fields. The type derives
/// nothing: a `Clone` would let a spent token authorise a second deletion and a
/// `Default` would mint one out of nothing, and both are exactly what
/// `resource_accounting.completeness_rule` means by "a private-half deletion
/// outside the proof-token funnel fails to compile".
mod ownership {
    use super::{
        COMMIT_RECORD, CreatingMarker, MARKER, MARKER_STAGED, OWNER_RECORD, OwnerField,
        OwnerRecord, Path, PathBuf, PrivateHalfOwnership, RepoKey, RetainReason, UnboundShape, fs,
        read_dir_names, runner_policy_sha256,
    };

    /// Proof that one private half belongs to one public husk of this
    /// repository and never committed.
    ///
    /// Not `Clone`, not `Copy`, not `Default`, and constructed nowhere else.
    /// [`super::remove_private_husk`] takes it by value, so it is spent.
    #[derive(Debug)]
    pub struct PrivateHalfProof {
        target: PathBuf,
        public: PathBuf,
        run_id: String,
    }

    impl PrivateHalfProof {
        /// The private half this token authorises deleting, and nothing else.
        #[must_use]
        pub fn target(&self) -> &Path {
            &self.target
        }

        /// The public husk it is bound to.
        #[must_use]
        pub fn public_dir(&self) -> &Path {
            &self.public
        }

        /// The run both halves agree they belong to.
        #[must_use]
        pub fn run_id(&self) -> &str {
            &self.run_id
        }
    }

    /// The bidirectional ownership proof, read-only and total.
    ///
    /// `startup_census` (ii) states the conjunction and this is it, in that
    /// order: a parseable marker, whose `run_id` equals the directory basename
    /// and whose `repo_key` equals this repository's; then, if the recorded
    /// target exists, a locator chain below the runs directory holding no
    /// symlink or reparse point and canonicalizing to exactly
    /// `<R>/runs/<basename>`; then `<target>/owner.json` parsing and recording
    /// `run_id == basename`, `repo_key == this repository's`, `public_dir ==`
    /// the canonical path of this husk, `incarnation ==` the marker's, and
    /// `sha256(owner.runner) ==` the marker's `runner_policy_sha256`; and
    /// finally `<target>/committed.json` absent.
    ///
    /// Every conjunct refuses with its own [`RetainReason`], because each is
    /// separately droppable and a suite that tested the happy path and one
    /// negative would pass with any single one removed.
    pub fn prove_private_half_ownership(
        public: &Path,
        repo_key: &RepoKey,
        authorized_root: &Path,
    ) -> PrivateHalfOwnership {
        let Some(basename) = public
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
        else {
            // A run directory always has a basename; a path that does not is
            // not one this census can bind anything to. Retained, never
            // reclaimed: nothing private is deleted on shape alone.
            return PrivateHalfOwnership::Retained(RetainReason::MarkerUnparseable);
        };

        // Conjunct 1: the marker parses. No marker at all is a shape question
        // rather than a proof one, and `expected_failures_refusals` puts both
        // answers here — "a marker-less husk with content" is a RetainReason.
        let marker = match fs::read_to_string(public.join(MARKER)) {
            Ok(text) => match serde_json::from_str::<CreatingMarker>(&text) {
                Ok(marker) => marker,
                Err(_) => return PrivateHalfOwnership::Retained(RetainReason::MarkerUnparseable),
            },
            Err(_) => return unbound_shape(public),
        };

        // Conjunct 2: the marker names the directory it sits in.
        if marker.run_id != basename {
            return PrivateHalfOwnership::Retained(RetainReason::MarkerRunIdMismatch {
                recorded: marker.run_id,
                directory: basename,
            });
        }

        // Conjunct 3: and this repository.
        if marker.repo_key != repo_key.as_str() {
            return PrivateHalfOwnership::Retained(RetainReason::MarkerRepoKeyMismatch {
                recorded: marker.repo_key,
                expected: repo_key.as_str().to_owned(),
            });
        }

        let locator = PathBuf::from(&marker.private_dir);

        // The census's own step between the marker conjuncts and the locator
        // ones: "if the marker's private target does not exist the public husk
        // alone is reclaimed". Existence is asked of the link itself, so a
        // dangling symlink counts as present and is refused below rather than
        // reclaimed past.
        if fs::symlink_metadata(&locator).is_err() {
            return PrivateHalfOwnership::NothingBound(UnboundShape::TargetAbsent);
        }

        // Conjunct 4: no symlink or reparse point below the runs directory.
        let authorized_runs = authorized_root.join("runs");
        if let Some(component) = first_reparse_point(&authorized_runs, &locator) {
            return PrivateHalfOwnership::Retained(RetainReason::LocatorThroughReparsePoint {
                component,
            });
        }

        // Conjunct 5: and it canonicalizes to exactly <R>/runs/<basename>.
        // Both sides are canonicalized, so a private root reached through a
        // link — /tmp on macOS, a home directory on a mounted volume — is the
        // same root, while anything *below* runs had to be real to get here.
        let expected = match fs::canonicalize(&authorized_runs) {
            Ok(runs) => runs.join(&basename),
            Err(_) => authorized_runs.join(&basename),
        };
        match fs::canonicalize(&locator) {
            Ok(resolved) if resolved == expected => {}
            Ok(resolved) => {
                return PrivateHalfOwnership::Retained(
                    RetainReason::LocatorOutsideAuthorizedRoot {
                        locator: resolved,
                        expected,
                    },
                );
            }
            Err(_) => {
                return PrivateHalfOwnership::Retained(
                    RetainReason::LocatorOutsideAuthorizedRoot { locator, expected },
                );
            }
        }

        // Conjuncts 6-11: the reciprocal record.
        let owner = match fs::read_to_string(locator.join(OWNER_RECORD)) {
            Ok(text) => match serde_json::from_str::<OwnerRecord>(&text) {
                Ok(owner) => owner,
                Err(_) => {
                    return PrivateHalfOwnership::Retained(RetainReason::OwnerRecordUnparseable);
                }
            },
            Err(_) => return PrivateHalfOwnership::Retained(RetainReason::OwnerRecordMissing),
        };
        let canonical_public = fs::canonicalize(public).unwrap_or_else(|_| public.to_path_buf());
        let disagreements = [
            (OwnerField::RunId, owner.run_id.clone(), basename.clone()),
            (
                OwnerField::RepoKey,
                owner.repo_key.clone(),
                repo_key.as_str().to_owned(),
            ),
            (
                OwnerField::PublicDir,
                owner.public_dir.clone(),
                canonical_public.to_string_lossy().into_owned(),
            ),
            (
                OwnerField::Incarnation,
                owner.incarnation.clone(),
                marker.incarnation.clone(),
            ),
            (
                OwnerField::RunnerDigest,
                runner_policy_sha256(&owner.runner),
                marker.runner_policy_sha256.clone(),
            ),
        ];
        for (field, recorded, expected) in disagreements {
            if recorded != expected {
                return PrivateHalfOwnership::Retained(RetainReason::OwnerRecordDisagrees {
                    field,
                    recorded,
                    expected,
                });
            }
        }

        // Conjunct 12: and it never crossed P5b.
        if fs::symlink_metadata(locator.join(COMMIT_RECORD)).is_ok() {
            return PrivateHalfOwnership::Retained(RetainReason::PossiblyCommitted);
        }

        PrivateHalfOwnership::Proven(PrivateHalfProof {
            target: locator,
            public: public.to_path_buf(),
            run_id: basename,
        })
    }

    /// A husk with no marker: `startup_census` (i) reclaims "a bare directory
    /// or one holding only a staged `.creating.tmp` (no marker, **no other
    /// content**)", and (iii) retains "a marker-less husk carrying run-scoped
    /// content". Read literally: anything other than the staging file is other
    /// content, the empty run skeleton included, because retention costs a
    /// report and reclamation cannot be undone.
    fn unbound_shape(public: &Path) -> PrivateHalfOwnership {
        match read_dir_names(public).as_slice() {
            [] => PrivateHalfOwnership::NothingBound(UnboundShape::Bare),
            [only] if only == MARKER_STAGED => {
                PrivateHalfOwnership::NothingBound(UnboundShape::StagedMarkerOnly)
            }
            _ => PrivateHalfOwnership::Retained(RetainReason::MarkerlessWithContent),
        }
    }

    /// The first component of `locator` strictly below `runs` that is a link.
    ///
    /// On Windows this is the reparse-point attribute rather than
    /// `FileType::is_symlink`, because a **junction** is a reparse point that
    /// is not a symbolic link, needs no privilege to create, and is exactly
    /// what `expected_failures_refusals[0]` means by "symlink/junction on the
    /// chain". A check that only fired on POSIX symlinks would pass every
    /// Linux test and refuse nothing on the platform the word "junction" is
    /// about.
    ///
    /// Only *below* `runs`: `startup_census` says "the locator chain below the
    /// runs directory holds no symlink or reparse point", and the private root
    /// itself is legitimately reached through one on plenty of machines.
    fn first_reparse_point(runs: &Path, locator: &Path) -> Option<PathBuf> {
        let below = locator.strip_prefix(runs).ok()?;
        let mut walked = runs.to_path_buf();
        for component in below.components() {
            walked.push(component);
            if is_reparse_point(&walked) {
                return Some(walked);
            }
        }
        None
    }

    fn is_reparse_point(path: &Path) -> bool {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            // FILE_ATTRIBUTE_REPARSE_POINT. Every reparse point, so a junction
            // (IO_REPARSE_TAG_MOUNT_POINT) is refused alongside a symbolic
            // link (IO_REPARSE_TAG_SYMLINK).
            const REPARSE_POINT: u32 = 0x0000_0400;
            metadata.file_attributes() & REPARSE_POINT != 0
        }
        #[cfg(not(windows))]
        {
            metadata.file_type().is_symlink()
        }
    }
}

/// Every run in this repo, oldest first.
///
/// Run ids are ULIDs with the millisecond timestamp in the high bits and
/// Crockford base32's digits-before-letters ordering, so a plain lexicographic
/// sort is chronological — no directory timestamps, which copying a repo would
/// scramble.
///
/// **Committed directories only.** `startup_census`: "every reader
/// (`list_runs`, `latest_run`, `resolve_run_id`, `find_question`, `status`)
/// returns Committed directories only, **whether or not a marker is present**",
/// and `run_creation` says it from the other side: "readers never return a
/// directory without a committed `run_started` and never hide one because of a
/// marker". Both halves are load-bearing and each is a separate test.
///
/// This is the slice's only change in behaviour: a legacy husk that today
/// shadows [`latest_run`] is no longer listed. A run whose log committed is
/// listed exactly as before, marker or no marker.
pub fn list_runs(repo_root: &Path) -> Vec<String> {
    let mut runs: Vec<String> = run_dir_names(repo_root)
        .into_iter()
        .filter(|run_id| classify_run_dir(&public_dir(repo_root, run_id)) == RunDirClass::Committed)
        .collect();
    runs.sort();
    runs
}

/// Every directory under `<repo>/.tactus/runs`, committed or not, oldest first.
///
/// Not a reader in `startup_census`'s sense and deliberately not filtered by
/// commitment: this is the enumeration a census walks and the one the worktree
/// lease's R28 check scans. A crashed run whose log never committed is exactly
/// the run whose reaper is most likely still holding its cleanup lease, so
/// filtering here would hide the hold that check exists to observe.
#[must_use]
pub fn run_dir_names(repo_root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(runs_root(repo_root)) else {
        return Vec::new();
    };
    let mut runs: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    runs.sort();
    runs
}

/// Every husk under `<repo>/.tactus/runs`, oldest first.
#[must_use]
pub fn list_husks(repo_root: &Path) -> Vec<String> {
    run_dir_names(repo_root)
        .into_iter()
        .filter(|run_id| classify_run_dir(&public_dir(repo_root, run_id)) == RunDirClass::Husk)
        .collect()
}

/// What `status` says about a husk id it was asked for by name.
///
/// `startup_census`: "status is read-only: it ignores husks and, asked
/// explicitly for a husk id, reports an unstarted husk that the next write
/// command reclaims, a retained husk with its reason and locator, or a possibly
/// committed run whose public log has no valid committed first line".
#[derive(Debug)]
pub struct HuskReport {
    pub run_id: String,
    pub public: PathBuf,
    /// The private locator the marker records, when a marker parses.
    pub locator: Option<PathBuf>,
    pub disposition: HuskDisposition,
}

/// What the next write command's census would do with a husk it may reclaim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reclaimable {
    /// Nothing private is bound, so the public half alone is reclaimed.
    PublicOnly(UnboundShape),
    /// The ownership proof holds and no commit record exists: the private half
    /// is reclaimed through the proof-token funnel, then the public directory
    /// with the marker last.
    BothHalves,
}

/// The trichotomy `status` reports a husk id by.
#[derive(Debug)]
pub enum HuskDisposition {
    /// Nothing has started here: the next write command reclaims it.
    Unstarted(Reclaimable),
    /// Retained and reported until the deferred prune command removes it.
    /// [`RetainReason::PossiblyCommitted`] is the third of the three sentences.
    Retained(RetainReason),
}

impl HuskDisposition {
    /// The operator-facing sentence, which names which of the three this is.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Unstarted(Reclaimable::BothHalves) => "an unstarted husk, bound to a private \
                 half that never committed, that the next write command reclaims"
                .to_owned(),
            Self::Unstarted(Reclaimable::PublicOnly(shape)) => format!(
                "an unstarted husk ({}) that the next write command reclaims",
                match shape {
                    UnboundShape::Bare => "a bare directory",
                    UnboundShape::StagedMarkerOnly => "only a staged marker",
                    UnboundShape::TargetAbsent => "its recorded private half is gone",
                }
            ),
            Self::Retained(RetainReason::PossiblyCommitted) => {
                "a possibly committed run whose public log has no valid committed first line; \
                 nothing is deleted"
                    .to_owned()
            }
            Self::Retained(reason) => format!("a retained husk: {reason}"),
        }
    }
}

/// Report a husk by id, for `status` and for the census report.
///
/// Read-only from end to end. The authorized private root is the one the
/// command is configured with, which for a read-only `status` is the default.
#[must_use]
pub fn husk_report(
    repo_root: &Path,
    run_id: &str,
    repo_key: &RepoKey,
    authorized_root: &Path,
) -> HuskReport {
    let public = public_dir(repo_root, run_id);
    let locator = fs::read_to_string(public.join(MARKER))
        .ok()
        .and_then(|text| serde_json::from_str::<CreatingMarker>(&text).ok())
        .map(|marker| PathBuf::from(marker.private_dir));
    let disposition = match prove_private_half_ownership(&public, repo_key, authorized_root) {
        // A token means the husk is provably this run's and never committed —
        // reclaimable, both halves, by the next write command. The token is
        // dropped unspent: `status` is read-only.
        PrivateHalfOwnership::Proven(_) => HuskDisposition::Unstarted(Reclaimable::BothHalves),
        PrivateHalfOwnership::NothingBound(shape) => {
            HuskDisposition::Unstarted(Reclaimable::PublicOnly(shape))
        }
        PrivateHalfOwnership::Retained(reason) => HuskDisposition::Retained(reason),
    };
    HuskReport {
        run_id: run_id.to_owned(),
        public,
        locator,
        disposition,
    }
}

/// The most recent run — what `tactus status` reports when given no id.
pub fn latest_run(repo_root: &Path) -> Option<String> {
    list_runs(repo_root).pop()
}

/// Resolve a run id from any unambiguous prefix, so an operator can type the
/// first few characters of a 26-character ULID.
///
/// An exact match wins outright rather than being treated as one candidate
/// among several: a full id is never ambiguous, even if some other run happens
/// to extend it.
pub fn resolve_run_id(repo_root: &Path, wanted: &str) -> Result<String, TactusError> {
    let runs = list_runs(repo_root);
    let wanted_upper = wanted.to_ascii_uppercase();
    // The entry as it exists on disk, not the uppercased input. The comparison
    // is case-insensitive because a run directory can arrive from a
    // case-insensitive filesystem, and on a case-sensitive one only the real
    // name builds a path that opens — everything downstream joins this id.
    if let Some(matched) = runs.iter().find(|id| id.eq_ignore_ascii_case(wanted)) {
        return Ok(matched.clone());
    }
    let matches: Vec<&String> = runs
        .iter()
        .filter(|id| id.to_ascii_uppercase().starts_with(&wanted_upper))
        .collect();
    match matches.as_slice() {
        [only] => Ok((*only).clone()),
        [] => Err(TactusError::Refused {
            message: match husk_matching(repo_root, wanted) {
                // A directory is there, and it holds no committed `run_started`.
                // Saying "no run matches that id" of a directory the operator
                // can see is the answer that sends them looking for a bug.
                Some(husk) => format!(
                    "`{husk}` never recorded a committed run_started, so there is no run to open \
                     there — ask `tactus status {husk}` for what it is and what happens to it"
                ),
                None if runs.is_empty() => {
                    format!("no runs found under {}", runs_root(repo_root).display())
                }
                None => format!("no run matches that id; known runs: {}", runs.join(", ")),
            },
        }),
        several => Err(TactusError::Refused {
            message: format!(
                "that prefix matches {} runs ({}); use more characters",
                several.len(),
                several
                    .iter()
                    .map(|id| id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }),
    }
}

/// The husk a wanted id names, exactly or by unambiguous prefix.
///
/// Only used to explain a refusal, so an ambiguous prefix answers `None`: the
/// operator is told to use more characters by the branch above, not sent to a
/// husk that merely happens to be one of the matches.
fn husk_matching(repo_root: &Path, wanted: &str) -> Option<String> {
    let husks = list_husks(repo_root);
    let wanted_upper = wanted.to_ascii_uppercase();
    if let Some(exact) = husks.iter().find(|id| id.eq_ignore_ascii_case(wanted)) {
        return Some(exact.clone());
    }
    let mut prefixed = husks
        .iter()
        .filter(|id| id.to_ascii_uppercase().starts_with(&wanted_upper));
    let first = prefixed.next()?;
    prefixed.next().is_none().then(|| first.clone())
}

/// A question id resolved to the run that raised it.
#[derive(Debug)]
pub struct FoundQuestion {
    pub run_id: String,
    /// The run's public directory — everything `tactus answer` touches.
    pub public: PathBuf,
    /// The full question id, expanded from whatever prefix was typed.
    pub question_id: String,
}

/// Find the run holding a question, by full id or unambiguous prefix.
///
/// Scans every run rather than requiring the operator to remember which one
/// asked: the notifier hands them a question id, not a run id, so a question
/// id is what the command has to accept.
pub fn find_question(repo_root: &Path, wanted: &str) -> Result<FoundQuestion, TactusError> {
    let wanted_upper = wanted.to_ascii_uppercase();
    let mut exact: Option<FoundQuestion> = None;
    let mut matches: Vec<FoundQuestion> = Vec::new();
    for run_id in list_runs(repo_root) {
        let public = public_dir(repo_root, &run_id);
        let Ok(entries) = fs::read_dir(public.join("questions")) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(question_id) = name.strip_suffix(".json") else {
                continue;
            };
            let found = FoundQuestion {
                run_id: run_id.clone(),
                public: public.clone(),
                question_id: question_id.to_owned(),
            };
            if question_id.eq_ignore_ascii_case(wanted) {
                exact = Some(found);
            } else if question_id.to_ascii_uppercase().starts_with(&wanted_upper) {
                matches.push(found);
            }
        }
    }
    if let Some(found) = exact {
        return Ok(found);
    }
    match matches.len() {
        1 => matches.pop().ok_or_else(|| TactusError::Refused {
            message: "question vanished while resolving it".to_owned(),
        }),
        0 => Err(TactusError::Refused {
            message: format!(
                "no question with that id under {}",
                runs_root(repo_root).display()
            ),
        }),
        several => Err(TactusError::Refused {
            message: format!(
                "that prefix matches {several} questions ({}); use more characters",
                matches
                    .iter()
                    .map(|found| found.question_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }),
    }
}

/// The lock beside one run's ops surface.
///
/// Takes the public directory rather than a whole [`RunPaths`] because the
/// lock lives in the public half by construction. Two callers only ever want
/// to know whether a run is live — `tactus answer`, and the resume that must
/// claim the run *before* it has read where the private half went — and
/// neither has a private path to offer. Asking them for one invited passing
/// the public path twice, which would have quietly become wrong the moment
/// liveness consulted anything but the lock.
pub fn lock_file(public: &Path) -> PathBuf {
    public.join("run.lock")
}

fn worktree_lock_file(worktree_git_dir: &Path) -> PathBuf {
    worktree_git_dir.join("tactus-worktree.lock")
}

/// An exclusive lease on the physical worktree shared by every run directory.
///
/// A per-run lock protects one log, but two distinct runs still share HEAD, the
/// index, and every working-tree byte. The engine therefore holds this outer
/// lease before either a fresh run or a resume can inspect or mutate Git state.
#[derive(Debug)]
pub struct WorktreeLock {
    _file: Option<File>,
    claim: PathBuf,
}

impl Drop for WorktreeLock {
    fn drop(&mut self) {
        release_claim_after_file(self._file.take(), &self.claim, || {});
    }
}

impl WorktreeLock {
    /// Acquire the lease for `repo_root` without placing coordination state in
    /// the working tree. Kept as the public convenience API for existing
    /// callers; the engine already has the resolved [`Workspace`] and uses
    /// [`Self::acquire_in`] to avoid opening it twice.
    pub fn acquire(repo_root: &Path) -> Result<Self, TactusError> {
        let workspace = Workspace::open(repo_root)?;
        let worktree_git_dir = workspace.worktree_git_dir()?;
        Self::acquire_in(workspace.root(), &worktree_git_dir)
    }

    pub(crate) fn acquire_in(
        repo_root: &Path,
        worktree_git_dir: &Path,
    ) -> Result<Self, TactusError> {
        Self::acquire_in_hooked(repo_root, worktree_git_dir, &mut NoHooks)
    }

    /// The same lease, observed.
    ///
    /// Two sites, two rows: `Lock.CreateWorktreeLockFile` is the file itself
    /// (R25, repository-scoped, "created on first acquisition by any write
    /// command through the lock funnel … spans runs; never removed by a run"),
    /// and `Lock.AcquireWorktree` is this process's hold on it (R17, "released
    /// at process exit"). One `open` serves both because `create(true)` is how
    /// the file comes to exist; the funnel names the create even when the file
    /// was already there, since the alternative is a stat that another process
    /// can invalidate between the question and the answer.
    pub(crate) fn acquire_in_hooked(
        repo_root: &Path,
        worktree_git_dir: &Path,
        hooks: &mut dyn RunDirHooks,
    ) -> Result<Self, TactusError> {
        let path = worktree_lock_file(worktree_git_dir);
        let claim = claim_key(worktree_git_dir).join("tactus-worktree.lock");
        if !claims().insert(claim.clone()) {
            return Err(worktree_refused(repo_root, &path, Some(std::process::id())));
        }
        let taken = funnel(
            hooks,
            EffectSiteId::Lock(LockSite::CreateWorktreeLockFile),
            || {
                File::options()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .read(true)
                    .open(&path)
                    .map_err(|source| TactusError::Io {
                        path: path.clone(),
                        source,
                    })
            },
        )
        .and_then(|file| {
            funnel(
                hooks,
                EffectSiteId::Lock(LockSite::AcquireWorktree),
                || match imp::take(&file) {
                    Holder::Nobody => Ok(()),
                    Holder::Someone { pid } => Err(worktree_refused(repo_root, &path, pid)),
                    Holder::Unknown(source) => Err(TactusError::Io {
                        path: path.clone(),
                        source,
                    }),
                },
            )
            .map(|()| file)
        });
        match taken {
            Ok(file) => {
                // A killed conductor releases the primary worktree lease, but
                // its Unix cleanup reaper deliberately retains the old run's
                // cleanup lease until every agent process is gone. Check only
                // after taking the primary lease, closing the race where the
                // conductor dies between a scan and this acquisition.
                //
                // `run_dir_names`, not `list_runs`: the reader returns
                // committed directories only, and the run most likely to have
                // a reaper still settling its groups is precisely the one that
                // died before its log committed. Scanning the readers' view
                // would leave R28 held and unobserved for exactly that run.
                if let Some(cleaning) = run_dir_names(repo_root)
                    .into_iter()
                    .map(|run_id| public_dir(repo_root, &run_id))
                    .find(|public| observe_cleanup_hold(public, hooks))
                {
                    release_claim_after_file(Some(file), &claim, || {});
                    return Err(TactusError::Refused {
                        message: format!(
                            "run `{}` is still cleaning agent processes in worktree {}; refusing overlapping engine ownership",
                            cleaning.file_name().unwrap_or_default().to_string_lossy(),
                            repo_root.display()
                        ),
                    });
                }
                Ok(Self {
                    _file: Some(file),
                    claim,
                })
            }
            Err(error) => {
                claims().remove(&claim);
                Err(error)
            }
        }
    }
}

/// A second, Unix-only lock used as a crash-cleanup lease. Each external agent
/// reaper opens its own shared hold; `resume` needs the exclusive side, so a
/// hard-killed conductor cannot hand over the run before cleanup is complete.
#[cfg(unix)]
fn cleanup_lock_file(public: &Path) -> PathBuf {
    public.join("cleanup.lock")
}

/// An exclusive hold on one run, released when this value drops.
///
/// Two engines on one run directory would interleave events into the log and
/// fight over the same git branch and working tree. An advisory OS lock is the
/// right shape for that because the operating system releases the primary
/// hold when the conductor dies. On Unix, live crash reapers retain only the
/// shared cleanup lease until their agent groups are quiescent. Neither hold
/// leaves a stale marker to clear by hand.
///
/// Which OS lock, though, is not a detail. See [`imp`].
#[derive(Debug)]
pub struct RunLock {
    _file: Option<File>,
    _cleanup: cleanup::CleanupLease,
    /// The run this claimed in [`claims`], given back on drop.
    claim: PathBuf,
}

impl Drop for RunLock {
    fn drop(&mut self) {
        self.release_file_then(|| {});
    }
}

impl RunLock {
    /// Close the process-scoped OS lock before publishing this process's claim
    /// as free. On POSIX, closing the old descriptor after another thread has
    /// acquired the same inode would release *all* of this process's locks on
    /// that inode, silently stripping the new owner's exclusion.
    fn release_file_then(&mut self, after_close: impl FnOnce()) {
        release_claim_after_file(self._file.take(), &self.claim, after_close);
    }

    /// Take the lock on a run's public directory, or explain who has it.
    pub fn acquire(public: &Path) -> Result<Self, TactusError> {
        Self::acquire_hooked(public, &mut NoHooks)
    }

    /// The same lock, observed. `Lock.AcquireRun` (R17) around the hold, and
    /// `Lock.ProbeCleanupExclusive` (R17, Unix) around the momentary exclusive
    /// probe that refuses while a surviving reaper still holds R28.
    pub fn acquire_hooked(public: &Path, hooks: &mut dyn RunDirHooks) -> Result<Self, TactusError> {
        let path = lock_file(public);
        let claim = claim_key(public);
        // This process first, and not only as an optimisation: the OS lock
        // below is per-*process*, so it cannot tell one thread here from
        // another. `claims` is what makes two `acquire`s in one process behave
        // the way two engines do, and it is exact rather than advisory.
        if !claims().insert(claim.clone()) {
            return Err(refused(public, &path, Some(std::process::id())));
        }
        let taken = funnel(hooks, EffectSiteId::Lock(LockSite::AcquireRun), || {
            File::options()
                .create(true)
                .truncate(false)
                .write(true)
                .read(true)
                .open(&path)
                .map_err(|source| TactusError::Io {
                    path: path.clone(),
                    source,
                })
                .and_then(|file| match imp::take(&file) {
                    Holder::Nobody => Ok(file),
                    Holder::Someone { pid } => Err(refused(public, &path, pid)),
                    // A lock that cannot be taken is not a lock that was taken.
                    // Say what actually failed rather than blaming an engine
                    // that may not exist.
                    Holder::Unknown(source) => Err(TactusError::Io {
                        path: path.clone(),
                        source,
                    }),
                })
        });
        match taken {
            Ok(file) => match funnel(
                hooks,
                EffectSiteId::Lock(LockSite::ProbeCleanupExclusive),
                || cleanup::take(public),
            ) {
                Ok(cleanup) => Ok(Self {
                    _file: Some(file),
                    _cleanup: cleanup,
                    claim,
                }),
                Err(error) => {
                    release_claim_after_file(Some(file), &claim, || {});
                    Err(error)
                }
            },
            Err(error) => {
                claims().remove(&claim);
                Err(error)
            }
        }
    }

    /// Give the hold back, naming `Lock.Release`.
    ///
    /// `Drop` does the same thing through [`NoHooks`], so the release happens
    /// whether or not anybody asks for it — including when the process dies and
    /// the OS does it. This exists so the site can be observed executing.
    pub fn release(mut self, hooks: &mut dyn RunDirHooks) {
        let _ = funnel(hooks, EffectSiteId::Lock(LockSite::Release), || {
            self.release_file_then(|| {});
            Ok::<(), TactusError>(())
        });
    }

    /// Bind subprocess cleanup started on this thread to this run.
    ///
    /// The lock itself remains `Send`; callers enter the scope only while
    /// synchronously driving the run, so a future executor can move ownership
    /// first and establish the context on its actual worker thread.
    pub(crate) fn enter_cleanup_scope(&self) -> cleanup::CleanupScope<'_> {
        cleanup::enter(&self._cleanup)
    }
}

/// `Lock.ObserveCleanupHold` — R28, observed and never owned.
///
/// `resource_accounting` R28: "a surviving Unix cleanup reaper's shared
/// `cleanup.lock` hold (one per reaper; a reaper may outlive the coordinator
/// while it settles its process groups) … observed (never owned or reset) by
/// the next coordinator through `cleanup::is_held` at worktree-lease
/// acquisition and through the exclusive cleanup probe at run-lock
/// acquisition, **both of which refuse until the hold is released**".
///
/// Read-only, which is why `LockSite::ObserveCleanupHold::is_read_only()` is
/// the one `true` in its group — and hooked all the same, because a site that
/// never calls its hooks cannot be shown to have executed.
#[must_use]
pub fn observe_cleanup_hold(public: &Path, hooks: &mut dyn RunDirHooks) -> bool {
    funnel(
        hooks,
        EffectSiteId::Lock(LockSite::ObserveCleanupHold),
        || Ok::<bool, TactusError>(cleanup::is_held(public)),
    )
    .unwrap_or(
        // An observation that was made to fail is not an observation that
        // found nothing. R28 held is the fail-closed answer, exactly as
        // `is_running` treats a lock the OS will not report on.
        true,
    )
}

/// Release a process-scoped POSIX lock before another thread can observe the
/// in-process claim as free. This ordering is shared by ordinary `Drop` and by
/// rollback after the primary lock succeeded but the cleanup lease did not.
fn release_claim_after_file(file: Option<File>, claim: &Path, after_close: impl FnOnce()) {
    drop(file);
    after_close();
    claims().remove(claim);
}

fn refused(public: &Path, path: &Path, pid: Option<u32>) -> TactusError {
    let who = match pid {
        Some(pid) => format!(" (pid {pid})"),
        None => String::new(),
    };
    TactusError::Refused {
        message: format!(
            "another tactus process{who} is already driving run `{}` (lock held on {}). Two \
             engines would interleave events and fight over the same branch — wait for it to \
             finish, or stop it first.",
            public.file_name().unwrap_or_default().to_string_lossy(),
            path.display()
        ),
    }
}

fn worktree_refused(repo_root: &Path, path: &Path, pid: Option<u32>) -> TactusError {
    let who = match pid {
        Some(pid) => format!(" (pid {pid})"),
        None => String::new(),
    };
    TactusError::Refused {
        message: format!(
            "another tactus process{who} is already driving worktree {} (lock held on {}). Different run ids still share HEAD, the index, and working-tree bytes; wait for it to finish, or stop it first.",
            repo_root.display(),
            path.display()
        ),
    }
}

/// Who holds a run's lock.
#[derive(Debug)]
enum Holder {
    Nobody,
    /// Somebody does. `pid` where the platform will say.
    Someone {
        pid: Option<u32>,
    },
    /// The call failed without answering the question.
    Unknown(io::Error),
}

/// Run and worktree locks this process holds, so that two `acquire`s here
/// behave like two engines.
///
/// It also keeps [`is_running`] away from a lock file this process already
/// holds — which on Unix is not tidiness but a correctness requirement, because
/// closing *any* descriptor for a file releases every `fcntl` lock this process
/// has on it. A bare `File::open` + drop in the holder would silently hand the
/// run away. Answering from here means that open never happens.
fn claims() -> &'static Claims {
    static CLAIMS: Claims = Claims {
        runs: Mutex::new(BTreeSet::new()),
    };
    &CLAIMS
}

#[derive(Debug)]
struct Claims {
    runs: Mutex<BTreeSet<PathBuf>>,
}

impl Claims {
    /// `true` if this process did not already hold it.
    fn insert(&self, key: PathBuf) -> bool {
        self.held().insert(key)
    }

    fn remove(&self, key: &Path) {
        self.held().remove(key);
    }

    fn contains(&self, key: &Path) -> bool {
        self.held().contains(key)
    }

    /// A panic in a lock holder must not take the run lock's bookkeeping with
    /// it: the set is still exactly as valid as it was before the panic.
    fn held(&self) -> std::sync::MutexGuard<'_, BTreeSet<PathBuf>> {
        self.runs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The run's identity for [`claims`], resolved so that two spellings of one
/// directory cannot look like two runs.
fn claim_key(public: &Path) -> PathBuf {
    fs::canonicalize(public).unwrap_or_else(|_| public.to_path_buf())
}

/// Whether a run is being driven right now, without disturbing the holder.
///
/// Read-only with respect to the run record. On Unix, `F_GETLK` asks who holds
/// the primary lock without taking one. Only when that lock is free does the
/// probe momentarily try the exclusive side of the cleanup lease; it never
/// creates or changes either file. A primary file that does not exist means
/// the run never started.
pub fn is_running(public: &Path) -> bool {
    // Asked and answered without touching the file. On Unix this is the branch
    // that keeps `fcntl`'s release-on-any-close from applying to us at all.
    if claims().contains(&claim_key(public)) {
        return true;
    }
    let file = match File::open(lock_file(public)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        // An existing run whose lock cannot be inspected is not safe to call
        // dead. `acquire` will report the concrete IO error if a resume tries.
        Err(_) => return true,
    };
    match imp::holder(&file) {
        Holder::Nobody => observe_cleanup_hold(public, &mut NoHooks),
        Holder::Someone { .. } => true,
        // The opened-fine-but-cannot-be-locked case, which is not the same as
        // the unopenable file above and does not get the same answer. Locking
        // fails with `ENOLCK` or `EOPNOTSUPP` on filesystems that do not carry
        // locks — NFS, SMB, some container overlays — and it does so whether or
        // not an engine is driving the run.
        //
        // So the question is which way to be wrong when the OS refuses to say.
        // Answering "not running" makes `status` settle a working attempt as
        // cut off and print `state: interrupted … Continue it with: tactus
        // resume <id>`, sending the operator to start a second engine on a
        // live run. Answering "running" costs a `status` that declines to
        // settle and says another process holds the run. One of those invents
        // a fact the operator will act on; the other admits the run may still
        // be going. `acquire` is the real guard against two engines either
        // way, and it reports this case as the IO error it is.
        Holder::Unknown(_) => true,
    }
}

#[cfg(unix)]
mod cleanup {
    use super::{cleanup_lock_file, refused};
    use crate::error::TactusError;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::marker::PhantomData;
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    thread_local! {
        // v0.1 drives a run synchronously inside an explicit scope. Thread-
        // local registration gives concurrent library/test runs the exact
        // cleanup path for their own reapers instead of conservatively leasing
        // every run active in the process.
        static ACTIVE: RefCell<BTreeMap<PathBuf, usize>> = const { RefCell::new(BTreeMap::new()) };
    }

    #[derive(Debug)]
    pub(super) struct CleanupLease {
        path: PathBuf,
    }

    #[derive(Debug)]
    pub(crate) struct CleanupScope<'a> {
        path: PathBuf,
        _lifetime_and_thread: PhantomData<(&'a CleanupLease, Rc<()>)>,
    }

    impl Drop for CleanupScope<'_> {
        fn drop(&mut self) {
            ACTIVE.with(|active| {
                let mut active = active.borrow_mut();
                let remove = if let Some(count) = active.get_mut(&self.path) {
                    *count = count.saturating_sub(1);
                    *count == 0
                } else {
                    false
                };
                if remove {
                    active.remove(&self.path);
                }
            });
        }
    }

    pub(super) fn enter(lease: &CleanupLease) -> CleanupScope<'_> {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            *active.entry(lease.path.clone()).or_default() += 1;
        });
        CleanupScope {
            path: lease.path.clone(),
            _lifetime_and_thread: PhantomData,
        }
    }

    pub(super) fn take(public: &Path) -> Result<CleanupLease, TactusError> {
        let path = cleanup_lock_file(public);
        let file = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|source| TactusError::Io {
                path: path.clone(),
                source,
            })?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let source = std::io::Error::last_os_error();
            if matches!(
                source.raw_os_error(),
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
            ) {
                return Err(refused(public, &path, None));
            }
            return Err(TactusError::Io { path, source });
        }
        // This probe proves no prior crash reaper remains. Do not retain the
        // lock in the conductor: arbitrary forked children would inherit its
        // open file description and recreate the false-liveness window the
        // primary fcntl lock deliberately avoids. Each cleanup reaper instead
        // reopens `path` and owns an independent shared hold.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
            return Err(TactusError::Io {
                path,
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(CleanupLease { path })
    }

    pub(super) fn is_held(public: &Path) -> bool {
        let path = cleanup_lock_file(public);
        let file = match File::options().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
            // An existing lease file that cannot be inspected is not evidence
            // that cleanup finished. Keep liveness fail-closed just as the
            // primary lock does for an unreportable holder.
            Err(_) => return true,
        };
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            false
        } else {
            true
        }
    }

    pub(crate) fn active_paths() -> Vec<PathBuf> {
        ACTIVE.with(|active| active.borrow().keys().cloned().collect())
    }
}

#[cfg(not(unix))]
mod cleanup {
    use crate::error::TactusError;
    use std::marker::PhantomData;
    use std::path::Path;
    use std::rc::Rc;

    #[derive(Debug)]
    pub(super) struct CleanupLease;

    #[derive(Debug)]
    pub(crate) struct CleanupScope<'a> {
        _lifetime_and_thread: PhantomData<(&'a CleanupLease, Rc<()>)>,
    }

    impl Drop for CleanupScope<'_> {
        fn drop(&mut self) {}
    }

    pub(super) fn take(_: &Path) -> Result<CleanupLease, TactusError> {
        Ok(CleanupLease)
    }

    pub(super) fn is_held(_: &Path) -> bool {
        false
    }

    pub(super) fn enter(_lease: &CleanupLease) -> CleanupScope<'_> {
        CleanupScope {
            _lifetime_and_thread: PhantomData,
        }
    }
}

#[cfg(unix)]
pub(crate) fn active_cleanup_lease_paths() -> Vec<PathBuf> {
    cleanup::active_paths()
}

/// The lock primitive, and why it is not `std`'s.
///
/// `File::try_lock` is `flock(2)` on Unix, and `flock` locks are held by the
/// *open file description*. `fork` duplicates every descriptor, so a child
/// inherits this lock and keeps holding it until it execs — which means an
/// engine that has finished and let go stays "locked" for as long as some
/// unrelated subprocess spawn is between `fork` and `exec`. Measured: hold a
/// lock, fork, release it, and a fresh probe still reports it taken.
///
/// That was papered over with a 500ms grace — believe contention only if it
/// persists — which is a timing proxy for a property the platform states
/// outright, and only ever probabilistic: a fork window longer than the grace
/// on a loaded machine still refuses a run that nothing is driving, and every
/// `status` of a live run paid the full half-second to find out.
///
/// `fcntl(F_SETLK)` locks are held by the *process*, and are documented not to
/// be inherited across `fork`. The grace disappears rather than being tuned.
///
/// Two things come with that, both measured rather than assumed:
///
/// - They do not exclude the same process from itself, which is what [`claims`]
///   is for.
/// - Closing **any** descriptor for the file releases every lock this process
///   holds on it, so a holder must never open its own lock file again.
///   [`is_running`] answers from [`claims`] before it would.
///
/// `F_OFD_SETLK` is not an escape from the first two: it is scoped to the open
/// file description, exactly like `flock`, and is inherited across `fork` in
/// exactly the same way.
///
/// Windows has neither hazard — `LockFileEx` is per-handle and there is no
/// `fork` — so it keeps std's implementation and this module is where the two
/// meet.
#[cfg(unix)]
mod imp {
    use super::Holder;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    /// `F_WRLCK` and `F_UNLCK` are `c_int` on Linux and `c_short` on macOS,
    /// while `flock.l_type` is `c_short` on both. `Into<c_int>` accepts either
    /// — the reflexive conversion on Linux, the widening one on macOS — so the
    /// narrowing to `l_type` happens here and nowhere else.
    fn l_type(kind: impl Into<libc::c_int>) -> libc::c_short {
        kind.into() as libc::c_short
    }

    /// Take the exclusive lock, or say who has it.
    pub(super) fn take(file: &File) -> Holder {
        match set_lock(file, l_type(libc::F_WRLCK)) {
            Ok(()) => Holder::Nobody,
            Err(error) if would_block(&error) => Holder::Someone {
                pid: holding_pid(file),
            },
            Err(error) => Holder::Unknown(error),
        }
    }

    /// Ask who holds it, taking nothing. There is no shared lock to give back
    /// here and so no window in which this call is itself the holder.
    pub(super) fn holder(file: &File) -> Holder {
        match query(file) {
            Ok(Some(pid)) => Holder::Someone { pid: Some(pid) },
            Ok(None) => Holder::Nobody,
            Err(error) => Holder::Unknown(error),
        }
    }

    fn describe(kind: libc::c_short) -> libc::flock {
        libc::flock {
            l_type: kind,
            l_whence: libc::SEEK_SET as libc::c_short,
            // A zero length locks the whole file, however long it grows. The
            // file's contents are never read; it exists to be locked.
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        }
    }

    fn set_lock(file: &File, kind: libc::c_short) -> io::Result<()> {
        let request = describe(kind);
        // `F_SETLK` never blocks, so unlike `flock` it has no interruptible
        // wait to be cut short — the `EINTR` retry the old loop carried has
        // nothing left to guard.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &request) } == 0 {
            return Ok(());
        }
        Err(io::Error::last_os_error())
    }

    /// `Some(pid)` if a conflicting lock exists, `None` if the file is free.
    fn query(file: &File) -> io::Result<Option<u32>> {
        let mut request = describe(l_type(libc::F_WRLCK));
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut request) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if request.l_type == l_type(libc::F_UNLCK) {
            return Ok(None);
        }
        Ok(Some(u32::try_from(request.l_pid).unwrap_or_default()))
    }

    /// Best effort: the holder may let go between the refusal and the question,
    /// and a name that might be stale is worth more than no name at all.
    fn holding_pid(file: &File) -> Option<u32> {
        query(file).ok().flatten()
    }

    fn would_block(error: &io::Error) -> bool {
        // POSIX allows either, and says a portable caller must accept both.
        matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EACCES || code == libc::EAGAIN
        )
    }
}

#[cfg(windows)]
mod imp {
    use super::Holder;
    use std::fs::File;
    use std::io;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    pub(super) fn take(file: &File) -> Holder {
        try_lock(file, true)
    }

    pub(super) fn holder(file: &File) -> Holder {
        match try_lock(file, false) {
            Holder::Nobody => match unlock(file) {
                Ok(()) => Holder::Nobody,
                Err(source) => Holder::Unknown(source),
            },
            other => other,
        }
    }

    fn try_lock(file: &File, exclusive: bool) -> Holder {
        let mut overlapped = OVERLAPPED::default();
        let flags = LOCKFILE_FAIL_IMMEDIATELY
            | if exclusive {
                LOCKFILE_EXCLUSIVE_LOCK
            } else {
                0
            };
        // SAFETY: `file` owns a live Windows handle, `overlapped` describes
        // offset zero, and the same whole-file range is used by every holder.
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                flags,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if locked != 0 {
            return Holder::Nobody;
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            // LockFileEx names no owner, and inventing one would be worse than
            // the shorter sentence.
            Holder::Someone { pid: None }
        } else {
            Holder::Unknown(source)
        }
    }

    fn unlock(file: &File) -> io::Result<()> {
        let mut overlapped = OVERLAPPED::default();
        // SAFETY: this releases exactly the range acquired in `try_lock`.
        if unsafe {
            UnlockFileEx(
                file.as_raw_handle() as HANDLE,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } != 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tactus-rundir-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn paths_in(root: &Path, run_id: &str) -> RunPaths {
        RunPaths::with_private_root(&root.join("repo"), run_id, &root.join("home"))
    }

    /// The exact bytes of a committed first line, written by hand.
    ///
    /// Not `serde_json::to_string(&Event::now(…))`: the classifier is judged
    /// against the **wire**, and a fixture that serialized through the same
    /// types the classifier reads would agree with any symmetric change to
    /// both (`PR3-WIRE-PINNING`). Every field here is one the packet names —
    /// the `event` tag, and `schema` and `run_id` inside `data`, which is what
    /// recovery step (a0) means by "probe the header of the committed first
    /// line … select the engine by schema".
    fn committed_line(run_id: &str, schema: u32) -> String {
        format!(
            "{{\"ts\":\"2026-08-20T00:00:00Z\",\"event\":\"run_started\",\
             \"data\":{{\"schema\":{schema},\"run_id\":\"{run_id}\",\
             \"branch\":\"tactus/run-{run_id}\"}}}}"
        )
    }

    /// Make `<repo>/.tactus/runs/<run_id>` a committed run.
    fn commit_run(repo: &Path, run_id: &str) -> PathBuf {
        let public = public_dir(repo, run_id);
        fs::create_dir_all(&public).expect("run dir");
        fs::write(
            public.join(EVENT_LOG),
            format!("{}\n", committed_line(run_id, 3)),
        )
        .expect("committed first line");
        public
    }

    #[test]
    fn agent_authored_files_land_outside_the_workspace() {
        // The whole point of the split: a reviewer with read access to the
        // repo has no path to the implementer's transcript.
        let root = scratch("split");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");

        let repo = root.join("repo");
        for private in [
            paths.transcripts(),
            paths.reviews(),
            paths.settings(),
            paths.gates(),
            paths.gate_worktrees(),
        ] {
            assert!(private.is_dir(), "{} should exist", private.display());
            assert!(
                !private.starts_with(&repo),
                "{} must not be inside the workspace",
                private.display()
            );
        }
        for public in [paths.questions(), paths.answers(), paths.artifacts()] {
            assert!(
                public.starts_with(&repo),
                "ops surface stays beside the repo"
            );
        }
        assert_eq!(paths.events(), repo.join(".tactus/runs/RUN1/events.jsonl"));
    }

    #[test]
    fn the_private_fallback_is_never_the_workspace() {
        // No HOME is a bad day, not a reason to quietly put transcripts back
        // where an agent can read them.
        let root = default_private_root();
        assert!(
            root.ends_with(".tactus") || root.ends_with("tactus"),
            "{root:?}"
        );
        assert!(root.is_absolute(), "{root:?}");
    }

    #[test]
    fn runs_list_chronologically_and_resolve_by_prefix() {
        let root = scratch("discover");
        let repo = root.join("repo");
        for id in ["01AAA", "01BBB", "01BCC"] {
            commit_run(&repo, id);
        }
        assert_eq!(list_runs(&repo), ["01AAA", "01BBB", "01BCC"]);
        assert_eq!(latest_run(&repo).as_deref(), Some("01BCC"));

        assert_eq!(resolve_run_id(&repo, "01AAA").expect("exact"), "01AAA");
        assert_eq!(resolve_run_id(&repo, "01A").expect("prefix"), "01AAA");
        assert_eq!(
            resolve_run_id(&repo, "01bcc").expect("case-insensitive"),
            "01BCC"
        );

        let err = resolve_run_id(&repo, "01B").expect_err("ambiguous");
        assert!(err.to_string().contains("matches 2 runs"), "got: {err}");
        let err = resolve_run_id(&repo, "02").expect_err("no match");
        assert!(err.to_string().contains("known runs"), "got: {err}");
    }

    #[test]
    fn an_empty_repo_names_where_it_looked() {
        let root = scratch("norun");
        let err = resolve_run_id(&root.join("repo"), "01A").expect_err("nothing to resume");
        assert!(err.to_string().contains("no runs found"), "got: {err}");
    }

    #[test]
    fn questions_resolve_to_their_run_by_prefix() {
        let root = scratch("questions");
        let repo = root.join("repo");
        for (run, question) in [
            ("01AAA", "q-ONE"),
            ("01BBB", "q-TWO"),
            ("01BBB", "q-TWENTY"),
        ] {
            let dir = commit_run(&repo, run).join("questions");
            fs::create_dir_all(&dir).expect("questions dir");
            fs::write(dir.join(format!("{question}.json")), "{}").expect("question");
        }

        let found = find_question(&repo, "q-ONE").expect("exact");
        assert_eq!(found.run_id, "01AAA");
        assert_eq!(found.question_id, "q-ONE");
        assert_eq!(found.public, public_dir(&repo, "01AAA"));

        // A full id wins even though `q-TWO` is also a prefix of `q-TWENTY`.
        let found = find_question(&repo, "q-TWO").expect("exact beats prefix");
        assert_eq!(found.question_id, "q-TWO");
        assert_eq!(found.run_id, "01BBB");

        let err = find_question(&repo, "q-TW").expect_err("ambiguous");
        assert!(
            err.to_string().contains("matches 2 questions"),
            "got: {err}"
        );
        let err = find_question(&repo, "q-NONE").expect_err("no match");
        assert!(err.to_string().contains("no question"), "got: {err}");
    }

    #[test]
    fn a_run_can_only_be_held_once_at_a_time() {
        let root = scratch("lock");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");

        assert!(
            !is_running(&paths.public),
            "nothing holds a run that never started"
        );
        let held = RunLock::acquire(&paths.public).expect("first acquire");
        assert!(is_running(&paths.public), "status can see the run is live");

        // This one is `claims`, not the OS: `fcntl` locks belong to the process,
        // so both of these would succeed if the file were the only guard.
        // Cross-process exclusion — the property that actually matters — is
        // `a_second_process_is_refused_the_run_lock` below.
        let err = RunLock::acquire(&paths.public).expect_err("a second engine is refused");
        assert!(
            err.to_string().contains("already driving run"),
            "got: {err}"
        );

        // A refusal that failed still leaves the run exactly as claimed as it
        // was — a bookkeeping slip here would either free a live run or strand
        // a dead one.
        assert!(
            is_running(&paths.public),
            "the failed acquire changed nothing"
        );

        // Dropping releases it — which is also what a crash does, so resume
        // never has to clear a stale marker by hand.
        drop(held);
        assert!(!is_running(&paths.public));
        RunLock::acquire(&paths.public).expect("re-acquire after release");
    }

    #[cfg(unix)]
    #[test]
    fn same_process_handoff_closes_old_descriptor_before_publishing_claim_free() {
        let root = scratch("orderedhandoff");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");
        let mut held = RunLock::acquire(&paths.public).expect("first acquire");

        held.release_file_then(|| {
            let file = File::open(lock_file(&paths.public)).expect("inspect released lock");
            assert!(
                matches!(imp::holder(&file), Holder::Nobody),
                "the old descriptor must already be closed"
            );
            let error = RunLock::acquire(&paths.public)
                .expect_err("the in-process claim stays published until after close");
            assert!(error.to_string().contains("already driving run"), "{error}");
        });

        let replacement = RunLock::acquire(&paths.public).expect("handoff after ordered release");
        drop(replacement);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_lease_failure_closes_primary_before_releasing_claim() {
        let root = scratch("cleanupfailurehandoff");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");
        let mut held = RunLock::acquire(&paths.public).expect("primary acquired");
        let file = held._file.take();
        let claim = held.claim.clone();

        // This is the exact rollback primitive used when cleanup::take fails.
        // The callback is a deterministic observation point between closing
        // the POSIX descriptor and publishing the same-process claim as free.
        release_claim_after_file(file, &claim, || {
            let file = File::open(lock_file(&paths.public)).expect("inspect primary lock");
            assert!(matches!(imp::holder(&file), Holder::Nobody));
            RunLock::acquire(&paths.public)
                .expect_err("claim cannot be reused until the old descriptor is closed");
        });

        let replacement = RunLock::acquire(&paths.public).expect("clean rollback handoff");
        drop(replacement);
        drop(held);
    }

    #[test]
    fn a_run_lock_remains_send_even_though_its_cleanup_scope_is_thread_local() {
        fn assert_send<T: Send>() {}
        assert_send::<RunLock>();
    }

    #[test]
    fn the_lock_answers_at_once_rather_than_waiting_to_be_sure() {
        // There was a 500ms contention grace here, and it was paid in full
        // exactly when the answer was yes: a live engine never lets go, so the
        // retry loop always ran to the deadline. Every `tactus status` and
        // `tactus answer` against a working run paid it, and `--follow` paid it
        // once per idle poll until it was given a cheaper question to ask.
        //
        // The grace existed to disbelieve a `fork` window. The primitive now
        // rules that out outright, so there is nothing left to wait for.
        let root = scratch("prompt");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");
        let _held = RunLock::acquire(&paths.public).expect("acquire");

        let started = Instant::now();
        for _ in 0..20 {
            assert!(is_running(&paths.public));
        }
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_millis(100),
            "twenty probes of a live run took {waited:?} — something is waiting again"
        );
    }

    /// A `fork` that has not reached its `exec` yet, held open on purpose.
    ///
    /// The child does nothing but sleep and `_exit`, both of which are safe in
    /// the child of a threaded process — no allocation, no locks, no
    /// destructors.
    #[cfg(unix)]
    fn fork_a_sleeper(ms: u64) -> libc::pid_t {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            std::thread::sleep(Duration::from_millis(ms));
            unsafe { libc::_exit(0) };
        }
        assert!(pid > 0, "fork failed");
        pid
    }

    #[cfg(unix)]
    #[test]
    fn a_fork_cannot_keep_a_released_run_locked() {
        // The bug the whole design turns on, deterministically.
        //
        // `flock` belongs to the open file description, and `fork` duplicates
        // every descriptor — so a child holds the run's lock until it execs,
        // and an engine that has finished and let go still reads as live for
        // that whole window. It was measured at 50 false positives in 3000
        // probes under a suite that spawns subprocesses, and each one made a
        // run refuse to start against an engine that did not exist, or a
        // finished run report itself as running.
        //
        // Against `flock` this test fails outright: the probe below sees the
        // lock held by the sleeping child. `fcntl` locks are not inherited, so
        // releasing really releases.
        let root = scratch("forkwindow");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");

        let held = RunLock::acquire(&paths.public).expect("acquire");
        let sleeper = fork_a_sleeper(400);
        // The engine finishes while that child is still between fork and exec.
        drop(held);

        assert!(
            !is_running(&paths.public),
            "a forked child was still holding the run's lock"
        );
        RunLock::acquire(&paths.public).expect("and a second engine can start");

        let mut status = 0;
        unsafe { libc::waitpid(sleeper, &mut status, 0) };
    }

    /// The child half of `a_second_process_is_refused_the_run_lock`: takes the
    /// lock, says so, and holds it until it is killed.
    ///
    /// An `#[ignore]`d test re-invoked as a subprocess, which is how
    /// `killing_a_run_mid_attempt_leaves_a_resumable_record` gets a real second
    /// process too.
    #[test]
    #[ignore = "spawned as a subprocess by a_second_process_is_refused_the_run_lock"]
    fn lock_child_holds_the_run() {
        let public = PathBuf::from(std::env::var("TACTUS_TEST_LOCK_DIR").expect("run dir"));
        let _held = RunLock::acquire(&public).expect("the child takes the lock");
        println!("held");
        std::io::Write::flush(&mut std::io::stdout()).expect("flush");
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "spawned as a subprocess by two_run_ids_cannot_drive_one_worktree_concurrently"]
    fn worktree_lock_child_holds_run_a() {
        let repo = PathBuf::from(std::env::var("TACTUS_TEST_WORKTREE_DIR").expect("repo"));
        let git_dir =
            PathBuf::from(std::env::var("TACTUS_TEST_WORKTREE_GIT_DIR").expect("git dir"));
        let public = PathBuf::from(std::env::var("TACTUS_TEST_LOCK_DIR").expect("run dir"));
        let _worktree =
            WorktreeLock::acquire_in(&repo, &git_dir).expect("child takes worktree lease");
        let _run = RunLock::acquire(&public).expect("child takes run A lock");
        println!("held");
        std::io::Write::flush(&mut std::io::stdout()).expect("flush");
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn two_run_ids_cannot_drive_one_worktree_concurrently() {
        let root = scratch("two-runs-one-worktree");
        let repo = root.join("repo");
        let git_dir = root.join("git-dir");
        fs::create_dir_all(&git_dir).expect("worktree git dir");
        let run_a = paths_in(&repo, "RUNA");
        let run_b = paths_in(&repo, "RUNB");
        run_a.create().expect("run A dirs");
        run_b.create().expect("run B dirs");

        let exe = std::env::current_exe().expect("test binary");
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "rundir::tests::worktree_lock_child_holds_run_a",
                "--ignored",
                "--nocapture",
            ])
            .env("TACTUS_TEST_WORKTREE_DIR", &repo)
            .env("TACTUS_TEST_WORKTREE_GIT_DIR", &git_dir)
            .env("TACTUS_TEST_LOCK_DIR", &run_a.public)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn run A engine");

        let mut out = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            line.clear();
            let read = std::io::BufRead::read_line(&mut out, &mut line).expect("read");
            assert!(read > 0, "run A child ended before taking its leases");
            if line.trim() == "held" {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "run A child never took its leases"
            );
        }

        // The per-run lock alone would allow this: the identifiers and files
        // differ. The outer lease is what owns shared HEAD/index/worktree state.
        let run_b_only = RunLock::acquire(&run_b.public).expect("run B lock is independent");
        drop(run_b_only);
        let error = WorktreeLock::acquire_in(&repo, &git_dir)
            .expect_err("run B must lose the worktree lease");
        assert!(
            error.to_string().contains("already driving worktree"),
            "{error}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_second_process_is_refused_the_run_lock() {
        // The property `claims` cannot provide and the file lock exists for.
        // Two engines are two processes, and `fcntl` locks are per-process —
        // which is exactly why this has to be tested across a real process
        // boundary rather than against a second `acquire` here.
        let root = scratch("twoprocs");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");

        let exe = std::env::current_exe().expect("test binary");
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "rundir::tests::lock_child_holds_the_run",
                "--ignored",
                "--nocapture",
            ])
            .env("TACTUS_TEST_LOCK_DIR", &paths.public)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the second engine");

        // Wait for it to say it has the lock, rather than sleeping and hoping.
        let mut out = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            line.clear();
            let read = std::io::BufRead::read_line(&mut out, &mut line).expect("read");
            assert!(read > 0, "the child ended without taking the lock");
            if line.trim() == "held" {
                break;
            }
            assert!(Instant::now() < deadline, "the child never took the lock");
        }

        let err = RunLock::acquire(&paths.public).expect_err("a second engine must be refused");
        assert!(
            err.to_string().contains("already driving run"),
            "got: {err}"
        );
        assert!(is_running(&paths.public), "and status agrees it is live");

        // `F_GETLK` names the holder, so the refusal can say who instead of
        // leaving the operator to find it. Asserted here rather than against a
        // second `acquire` in this process, because that one is refused by
        // `claims`, which knows this pid without asking the OS anything — it
        // would pass whatever the lock did.
        #[cfg(unix)]
        assert!(
            err.to_string().contains(&format!("pid {}", child.id())),
            "the refusal should name the process actually holding it: {err}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn a_holder_never_opens_its_own_lock_file() {
        // `fcntl`'s sharpest edge: closing *any* descriptor for a file releases
        // every lock this process holds on it. So a holder that does what
        // `is_running` does — open the lock file, look, drop it — hands the run
        // away silently, and the next `acquire` anywhere succeeds against a
        // live engine.
        //
        // `is_running` answers from `claims` before it would open anything,
        // which is what makes that unreachable. This test is here because the
        // rule is invisible in the code that depends on it.
        let root = scratch("selfclose");
        let paths = paths_in(&root, "RUN1");
        paths.create().expect("create");
        let _held = RunLock::acquire(&paths.public).expect("acquire");

        // The call a holder is most likely to make.
        assert!(is_running(&paths.public));

        // If that had gone to the file, the lock would be gone by now — ask
        // from a process that has no claim of its own to answer from.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let file = File::open(lock_file(&paths.public)).expect("open");
            let free = matches!(imp::holder(&file), Holder::Nobody);
            unsafe { libc::_exit(i32::from(free)) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the holder released its own lock by looking at it"
        );
    }

    #[test]
    fn a_lock_the_os_will_not_report_on_is_not_a_free_lock() {
        // No filesystem CI runs on returns `ENOLCK`, so the decision is checked
        // where it is made. A lock the OS declines to report on must not come
        // back as "nobody is running", because that is the reading that tells
        // an operator to resume a run that is still in flight.
        let unknown = Holder::Unknown(io::Error::from_raw_os_error(ENOLCK_LIKE));
        assert!(
            !matches!(unknown, Holder::Nobody),
            "an error is not an answer"
        );
    }

    /// Any errno at all; the value is not what is under test.
    const ENOLCK_LIKE: i32 = 37;

    #[test]
    fn an_exact_match_resolves_to_the_name_on_disk() {
        // The comparison is case-insensitive, so the answer has to be the
        // directory that actually exists: on a case-sensitive filesystem the
        // uppercased input names nothing, and every caller joins this id onto
        // a path.
        let root = scratch("ondisk");
        let repo = root.join("repo");
        commit_run(&repo, "01AbCd");

        assert_eq!(resolve_run_id(&repo, "01abcd").expect("exact"), "01AbCd");
        assert_eq!(resolve_run_id(&repo, "01AB").expect("prefix"), "01AbCd");
    }

    // =======================================================================
    // Classification
    // =======================================================================

    /// One directory shape, its construction, and the class the packet gives
    /// it. The expected value is transcribed from the packet's own rule and
    /// never computed by the function under test.
    struct DirShape {
        name: &'static str,
        build: fn(&Path),
        expected: RunDirClass,
    }

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        fs::write(path, bytes).expect("write");
    }

    /// A marker that **names the private half sitting beside it**.
    ///
    /// `any_marker_bytes` records `/nowhere/runs/01SHAPE`, which is what let
    /// `PR5-RUNDIR-005` and `PR5-RUNDIR-006` survive the thirteen-shape grid: a
    /// classifier that *follows the locator* looked in `/nowhere`, found
    /// nothing, fell through to the first-line probe and answered `Husk` for
    /// the wrong reason. The grid proved the classifier ignores a private half
    /// sitting beside it; it never proved the classifier ignores the private
    /// half the marker actually names — and "`Committed` by a valid
    /// newline-terminated first-line `run_started`, else `Husk`" is a claim
    /// about every private half, named or not.
    fn marker_bytes_locating(private: &Path) -> Vec<u8> {
        serde_json::to_vec(&CreatingMarker {
            run_id: "01SHAPE".to_owned(),
            repo_key: "0123456789abcdef".to_owned(),
            private_dir: private.to_string_lossy().into_owned(),
            incarnation: "01INC".to_owned(),
            pid: 4242,
            runner_policy_sha256: "sha256:00".to_owned(),
        })
        .expect("marker json")
    }

    /// An owner record with every field populated, so a classifier that parses
    /// what it finds is caught as surely as one that only stats it.
    fn plausible_owner_bytes() -> Vec<u8> {
        serde_json::to_vec(&OwnerRecord {
            run_id: "01SHAPE".to_owned(),
            repo_key: "0123456789abcdef".to_owned(),
            public_dir: "/nowhere/public".to_owned(),
            incarnation: "01INC".to_owned(),
            runner: crate::runner::policy::host_policy(),
        })
        .expect("owner json")
    }

    /// A marker whose fields do not matter to the classifier, which is the
    /// point: `startup_census` classifies "whether or not a marker is present".
    fn any_marker_bytes() -> Vec<u8> {
        serde_json::to_vec(&CreatingMarker {
            run_id: "01SHAPE".to_owned(),
            repo_key: "0123456789abcdef".to_owned(),
            private_dir: "/nowhere/runs/01SHAPE".to_owned(),
            incarnation: "01INC".to_owned(),
            pid: 4242,
            runner_policy_sha256: "sha256:00".to_owned(),
        })
        .expect("marker json")
    }

    /// The publication prefixes P0–P8, as `classify_run_dir`'s proof test
    /// names them.
    ///
    /// The contract's list — "bare, staged-marker, marker-only, marker+lock,
    /// marker+private (with and without owner record; with and without commit
    /// record), log-without-committed-first-line, torn-first-line,
    /// committed-with-marker, malformed-marker, and committed" — reads as a
    /// crossing on the `marker+private` entry, so the maximal reading is
    /// thirteen shapes and the collapsed one is ten. This table carries the
    /// maximal reading plus the shapes `startup_census` names that the
    /// contract's phrase does not spell out separately, because covering
    /// thirteen covers twelve whichever way the sentence is read.
    fn shapes() -> Vec<DirShape> {
        vec![
            DirShape {
                name: "bare",
                build: |public| fs::create_dir_all(public).expect("bare"),
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "staged-marker",
                build: |public| write(&public.join(MARKER_STAGED), &any_marker_bytes()),
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "marker-only",
                build: |public| write(&public.join(MARKER), &any_marker_bytes()),
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "marker+lock",
                build: |public| {
                    write(&public.join(MARKER), &any_marker_bytes());
                    write(&lock_file(public), b"");
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "marker+private-with-owner-record",
                build: |public| {
                    write(&public.join(MARKER), &any_marker_bytes());
                    write(&public.join("private/owner.json"), b"{}");
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "marker+private-without-owner-record",
                build: |public| {
                    write(&public.join(MARKER), &any_marker_bytes());
                    fs::create_dir_all(public.join("private")).expect("private");
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "marker+private-with-commit-record",
                build: |public| {
                    write(&public.join(MARKER), &any_marker_bytes());
                    write(&public.join("private/owner.json"), b"{}");
                    write(&public.join("private/committed.json"), b"{}");
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "marker+private-without-commit-record",
                build: |public| {
                    write(&public.join(MARKER), &any_marker_bytes());
                    write(&public.join("private/owner.json"), b"{}");
                    write(&public.join(PLAN), b"{}");
                },
                expected: RunDirClass::Husk,
            },
            // The two shapes the grid was missing: the marker names the
            // private half that is really there. A classifier that follows the
            // locator answers `Committed` for both, and only these two shapes
            // can tell it from one that does not.
            DirShape {
                name: "marker-bound-private-with-owner-record",
                build: |public| {
                    let private = public.join("private");
                    write(&private.join(OWNER_RECORD), &plausible_owner_bytes());
                    write(&public.join(MARKER), &marker_bytes_locating(&private));
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "marker-bound-private-with-commit-record",
                build: |public| {
                    let private = public.join("private");
                    write(&private.join(OWNER_RECORD), &plausible_owner_bytes());
                    write(
                        &private.join(COMMIT_RECORD),
                        b"{\"run_started_sha256\":\"sha256:00\"}",
                    );
                    write(&public.join(MARKER), &marker_bytes_locating(&private));
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "log-without-committed-first-line",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        b"{\"ts\":\"t\",\"event\":\"attempt_started\",\"data\":{}}\n",
                    );
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "torn-first-line",
                build: |public| {
                    // The newline is the commit marker, so a first line
                    // without one is not an event and never was.
                    let torn = committed_line("01TORN", 3);
                    write(&public.join(EVENT_LOG), &torn.as_bytes()[..torn.len() - 8]);
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                // The shape above truncates the JSON as well as the newline, so
                // it refuses on the parse and stays green if the *terminator*
                // requirement is dropped — measured: a `first_committed_line`
                // that treats end-of-file as end-of-line survived the whole
                // grid. This shape isolates the terminator: a complete, valid,
                // parseable `run_started` whose only defect is that it was
                // never terminated. `startup_census` says "first
                // **newline-terminated** line", and the newline is the only
                // evidence that the writer finished writing it.
                name: "complete-first-line-with-no-newline",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        committed_line("01SHAPE", 3).as_bytes(),
                    );
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "malformed-marker",
                build: |public| {
                    write(&public.join(MARKER), b"{ not json");
                    write(&public.join(PLAN), b"{}");
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "committed",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        format!("{}\n", committed_line("01SHAPE", 3)).as_bytes(),
                    );
                },
                expected: RunDirClass::Committed,
            },
            DirShape {
                name: "committed-with-marker",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        format!("{}\n", committed_line("01SHAPE", 3)).as_bytes(),
                    );
                    write(&public.join(MARKER), &any_marker_bytes());
                },
                expected: RunDirClass::Committed,
            },
            // Beyond the contract's list, from `startup_census`'s own
            // enumeration and from the rule's own edges.
            DirShape {
                name: "committed-with-staged-marker",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        format!("{}\n", committed_line("01SHAPE", 3)).as_bytes(),
                    );
                    write(&public.join(MARKER_STAGED), &any_marker_bytes());
                },
                expected: RunDirClass::Committed,
            },
            DirShape {
                name: "empty-log",
                build: |public| write(&public.join(EVENT_LOG), b""),
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "blank-first-line-then-run-started",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        format!("\n{}\n", committed_line("01SHAPE", 3)).as_bytes(),
                    );
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "first-line-is-not-json",
                build: |public| write(&public.join(EVENT_LOG), b"not json at all\n"),
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "first-line-has-no-schema-to-select-by",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        b"{\"event\":\"run_started\",\"data\":{\"run_id\":\"01SHAPE\"}}\n",
                    );
                },
                expected: RunDirClass::Husk,
            },
            DirShape {
                name: "committed-first-line-with-a-torn-tail",
                build: |public| {
                    // A torn *tail* is truncated by the next open and was
                    // never an event; it says nothing about the first line.
                    write(
                        &public.join(EVENT_LOG),
                        format!(
                            "{}\n{{\"ts\":\"t\",\"event\":\"attempt_star",
                            committed_line("01SHAPE", 3)
                        )
                        .as_bytes(),
                    );
                },
                expected: RunDirClass::Committed,
            },
            DirShape {
                name: "committed-schema-4",
                build: |public| {
                    write(
                        &public.join(EVENT_LOG),
                        format!("{}\n", committed_line("01SHAPE", 4)).as_bytes(),
                    );
                },
                expected: RunDirClass::Committed,
            },
        ]
    }

    #[test]
    fn every_publication_prefix_classifies_as_the_packet_names_it() {
        let root = scratch("shapes");
        let mut committed = 0usize;
        let mut husks = 0usize;
        for shape in shapes() {
            let public = root.join(shape.name);
            fs::create_dir_all(&public).expect("shape dir");
            (shape.build)(&public);
            let actual = classify_run_dir(&public);
            assert_eq!(
                actual, shape.expected,
                "shape `{}` classified {actual:?}",
                shape.name
            );
            match shape.expected {
                RunDirClass::Committed => committed += 1,
                RunDirClass::Husk => husks += 1,
            }
        }
        // Distinct-value counts rather than prose: a grid that had drifted to
        // one class would still pass every assertion above.
        assert_eq!(committed, 5, "committed shapes");
        assert_eq!(husks, 18, "husk shapes");
        // The two marker-bound shapes are the ones a locator-following
        // classifier gets wrong, so their presence is asserted rather than
        // left to the count above.
        let names: Vec<&str> = shapes().iter().map(|shape| shape.name).collect();
        for bound in [
            "marker-bound-private-with-owner-record",
            "marker-bound-private-with-commit-record",
        ] {
            assert!(names.contains(&bound), "the grid lost `{bound}`");
        }
        assert!(
            committed + husks >= 13,
            "the contract's list reads as thirteen shapes at its widest"
        );
    }

    #[test]
    fn a_missing_directory_and_a_missing_log_are_both_husks() {
        let root = scratch("absent");
        assert_eq!(classify_run_dir(&root.join("nothing")), RunDirClass::Husk);
        let bare = root.join("bare");
        fs::create_dir_all(&bare).expect("bare");
        assert_eq!(classify_run_dir(&bare), RunDirClass::Husk);
    }

    /// A valid `run_started` line, terminated, whose total length is exactly
    /// `total` bytes.
    ///
    /// The padding is a field *inside* the object, so the line stays a valid
    /// `run_started` at every length — a fixture that padded outside the JSON
    /// would refuse on the parse and could never distinguish a length bound
    /// from a parse failure. That confound is the `bounded_grid` shape recorded
    /// four times in `reviews/FINDINGS.md`, and `PR5B-CLASSIFIER-TERMINATOR-
    /// UNTESTED` is the same file's most recent instance.
    fn committed_line_of_exactly(run_id: &str, total: usize) -> Vec<u8> {
        let line = committed_line(run_id, 3);
        let head = &line[..line.len() - 1];
        let overhead = head.len() + ",\"pad\":\"".len() + "\"}".len() + "\n".len();
        assert!(
            total >= overhead,
            "a {total}-byte line cannot hold a run_started at all"
        );
        let padded = format!("{head},\"pad\":\"{}\"}}\n", "x".repeat(total - overhead));
        assert_eq!(padded.len(), total, "the padding arithmetic is off");
        padded.into_bytes()
    }

    /// `FIRST_LINE_WINDOW` decides how many syscalls the probe makes, and
    /// nothing about what a directory *is*.
    ///
    /// `startup_census` defines `Committed` as "`events.jsonl` exists and its
    /// first **newline-terminated** line is a valid `run_started`" and states no
    /// size exception, so every length classifies the same way. Six lengths
    /// straddling the window in both directions, including a line four times
    /// the window — which is `PR5-CORRECTNESS-002`'s failure sequence at
    /// `FIRST_LINE_WINDOW + 1` and three orders of magnitude past it.
    ///
    /// The lengths are written relative to the constant on purpose: the claim
    /// is *independence*, so shrinking the constant must leave this test
    /// passing. What would fail is any re-introduction of a length bound —
    /// which is the mutation that matters here, and it is witnessed in
    /// `reviews/FINDINGS.md`.
    #[test]
    fn classification_does_not_depend_on_the_probe_window() {
        let root = scratch("window");
        let window = usize::try_from(FIRST_LINE_WINDOW).expect("the window fits a usize");
        let mut lengths = std::collections::BTreeSet::new();
        for (label, total) in [
            ("tiny", 512),
            ("just under a chunk", SCAN_CHUNK - 1),
            ("exactly a chunk", SCAN_CHUNK),
            ("just under the window", window - 1),
            ("exactly the window", window),
            ("one past the window", window + 1),
            ("four windows", window * 4),
        ] {
            lengths.insert(total);
            let public = root.join(label.replace(' ', "-"));
            write(
                &public.join(EVENT_LOG),
                &committed_line_of_exactly("01WINDOW", total),
            );
            assert_eq!(
                classify_run_dir(&public),
                RunDirClass::Committed,
                "a {total}-byte valid run_started line ({label}) is committed at every length"
            );
        }
        assert_eq!(lengths.len(), 7, "seven distinct lengths: {lengths:?}");
        assert!(
            lengths.iter().filter(|len| **len > window).count() >= 2,
            "at least two lengths past the window, or the claim is untested: {lengths:?}"
        );
    }

    /// The terminator is still the whole of the difference, at every length.
    ///
    /// `PR5B-CLASSIFIER-TERMINATOR-UNTESTED` added the un-terminated shape at
    /// one small length; the fall-back path this slice added is a *second*
    /// implementation of "is there a newline", so it gets the same question.
    /// The two files differ in exactly one byte's presence.
    #[test]
    fn a_complete_first_line_with_no_terminator_is_a_husk_at_every_length() {
        let root = scratch("unterminated");
        let window = usize::try_from(FIRST_LINE_WINDOW).expect("the window fits a usize");
        for (label, total) in [
            ("inside the window", 4096),
            ("past the window", window + 4096),
        ] {
            let terminated = committed_line_of_exactly("01TERM", total);
            let unterminated = &terminated[..terminated.len() - 1];
            assert_eq!(
                terminated.last(),
                Some(&b'\n'),
                "{label}: the fixture must be terminated"
            );
            assert!(
                !unterminated.contains(&b'\n'),
                "{label}: dropping the terminator must leave no newline at all"
            );

            let committed = root.join(format!("{}-terminated", label.replace(' ', "-")));
            write(&committed.join(EVENT_LOG), &terminated);
            assert_eq!(
                classify_run_dir(&committed),
                RunDirClass::Committed,
                "{label}: the terminated fixture"
            );

            let husk = root.join(format!("{}-torn", label.replace(' ', "-")));
            write(&husk.join(EVENT_LOG), unterminated);
            assert_eq!(
                classify_run_dir(&husk),
                RunDirClass::Husk,
                "{label}: the same bytes without the terminator"
            );
        }
    }

    /// The line the probe hands to the parser is the line, exactly.
    ///
    /// An off-by-one in the fall-back's newline offset is the defect the new
    /// code could carry: one byte short truncates the closing brace and one
    /// byte long splices the newline into the JSON, and *both* refuse on the
    /// parse — so `Husk` would look like a correct answer for the wrong reason.
    /// This asserts the bytes rather than the verdict, on both paths.
    #[test]
    fn the_probe_returns_the_lines_exact_bytes_on_both_paths() {
        let root = scratch("exact");
        let window = usize::try_from(FIRST_LINE_WINDOW).expect("the window fits a usize");
        for (label, total) in [("window path", 4096), ("scan path", window + 7)] {
            let line = committed_line_of_exactly("01EXACT", total);
            let mut bytes = line.clone();
            // A second event after it, so "read to end of file" and "read to
            // the first newline" are different answers.
            bytes.extend_from_slice(b"{\"ts\":\"2026-08-20T00:00:01Z\",\"event\":\"noise\"}\n");
            let path = root.join(label.replace(' ', "-")).join(EVENT_LOG);
            write(&path, &bytes);

            let mut file = File::open(&path).expect("open");
            let read = first_line(&mut file).expect("a newline-terminated first line");
            assert_eq!(
                read,
                line[..line.len() - 1].to_vec(),
                "{label}: the probe returned {} bytes for a {}-byte line",
                read.len(),
                line.len() - 1
            );
        }
    }

    /// A source that never ends: every read hands back non-newline bytes and
    /// it is never at end of file. `/dev/zero`, on a host that has one and on a
    /// host that does not.
    ///
    /// It refuses rather than looping once it is asked for more than the budget
    /// the probe was given, so an unbounded probe **fails this test in
    /// milliseconds** instead of hanging the suite or eating the machine's
    /// memory. That is deliberate: the defect this guards (`PR5-RD-001`) is
    /// non-termination, and a guard against non-termination that itself does
    /// not terminate is no guard.
    #[derive(Default)]
    struct Endless {
        handed: u64,
        ceiling: u64,
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.handed + buf.len() as u64 > self.ceiling {
                return Err(io::Error::other(format!(
                    "the probe read past its budget: {} bytes handed out, ceiling {}",
                    self.handed, self.ceiling
                )));
            }
            buf.fill(b'x');
            self.handed += buf.len() as u64;
            Ok(buf.len())
        }
    }

    impl Seek for Endless {
        fn seek(&mut self, _to: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }

    /// The probe **terminates** on a source with no end, and spends exactly the
    /// budget it was given — not one byte more (`PR5-RD-001`).
    ///
    /// The byte count is the assertion, not the verdict. `Husk` is what a probe
    /// that read the first byte and gave up answers too, so a test that checked
    /// only the class would pass for a probe that had stopped being able to see
    /// a committed run at all. And the previous test of this shape asserted
    /// `Husk` over one finite regular file, which every implementation of this
    /// function — including the one that never returned — satisfies.
    #[test]
    fn the_first_line_probe_spends_its_budget_and_stops() {
        let budget = FIRST_LINE_WINDOW * 4 + 1234;
        let mut endless = Endless {
            handed: 0,
            // Generous, so what fails is the count below rather than the read:
            // an over-reading probe is caught by an assertion that names the
            // number, not by a mysterious io error.
            ceiling: budget + FIRST_LINE_WINDOW,
        };
        assert_eq!(
            first_line_within(&mut endless, budget),
            None,
            "a source with no newline in it has no first line"
        );
        assert_eq!(
            endless.handed, budget,
            "the probe is bounded by the length the file declares, and by nothing else"
        );

        // A device, a fifo or a socket declares no length, so the budget is
        // zero and the probe reads nothing at all. This is the shape a symlink
        // to /dev/zero presents to `first_line`.
        let mut device = Endless {
            handed: 0,
            ceiling: 1,
        };
        assert_eq!(first_line_within(&mut device, 0), None);
        assert_eq!(device.handed, 0, "a source with no length is not read");
    }

    /// The budget really is *the file's own length*, and a line that runs past
    /// the window is still found through it.
    ///
    /// The pair matters: the first half is what makes the probe terminate, the
    /// second is what stops that bound from becoming a classification cap — the
    /// exact trade `FIRST_LINE_CAP` got wrong and a bound-shaped repair could
    /// reintroduce.
    #[test]
    fn the_budget_is_the_files_length_and_a_line_past_the_window_is_still_read() {
        let root = scratch("budget");
        let window = usize::try_from(FIRST_LINE_WINDOW).expect("the window fits a usize");
        let line = committed_line_of_exactly("01BUDGET", window + 4096);
        let path = root.join("long").join(EVENT_LOG);
        write(&path, &line);

        let mut file = File::open(&path).expect("open");
        assert_eq!(
            file.metadata().expect("stat").len(),
            line.len() as u64,
            "the bound the probe takes is this number"
        );
        assert_eq!(
            first_line(&mut file).expect("a line past the window is still a line"),
            line[..line.len() - 1].to_vec()
        );
        assert_eq!(
            classify_run_dir(root.join("long").as_path()),
            RunDirClass::Committed,
            "a committed run over the window is never excluded by a read bound"
        );
    }

    /// A file with no newline anywhere is a husk, and is answered without
    /// materialising it.
    ///
    /// This is what the window was introduced for and the property the repair
    /// had to keep: `newline_offset_from` scans a fixed `SCAN_CHUNK` buffer, so
    /// the cost of "there is no newline" is independent of the file's size.
    /// Sixteen windows of it, which the pre-repair probe would have read one
    /// megabyte of and this one reads all of in 64 KiB at a time.
    ///
    /// It does **not** establish termination and no longer claims to
    /// (`PR5-RD-001`): one finite regular file reaches end of file under every
    /// implementation of this function, including the one that never returned
    /// for a source that has no end. `the_first_line_probe_spends_its_budget_
    /// and_stops` and `a_run_directory_whose_log_never_ends_is_still_classified`
    /// carry that.
    ///
    /// `Husk` is also the safe direction: a husk is never deleted on shape
    /// alone — deletion additionally requires the ownership proof, which
    /// requires `committed.json` to be absent, and a run that reached
    /// `run_started` published one at P5b.
    #[test]
    fn a_log_with_no_newline_at_all_is_a_husk_however_long_it_is() {
        let root = scratch("no-newline");
        let window = usize::try_from(FIRST_LINE_WINDOW).expect("the window fits a usize");
        // Valid JSON, so the answer cannot come from the parse.
        let head = committed_line_of_exactly("01NONL", 4096);
        let mut bytes = head[..head.len() - 1].to_vec();
        bytes.extend(std::iter::repeat_n(b'x', window * 16));
        assert!(!bytes.contains(&b'\n'));
        let public = root.join("long");
        write(&public.join(EVENT_LOG), &bytes);
        assert_eq!(classify_run_dir(&public), RunDirClass::Husk);

        let mut file = File::open(public.join(EVENT_LOG)).expect("open");
        assert_eq!(
            first_line(&mut file),
            None,
            "no newline is no first line, not an empty one"
        );
    }

    /// Where [`endless_log_classification_helper`] is pointed.
    const ENDLESS_LOG_DIR: &str = "TACTUS_ENDLESS_LOG_DIR";

    /// Set when the helper may also *open* the log itself and measure
    /// [`first_line`]'s bound over it — true of a device, false of a fifo.
    const ENDLESS_LOG_PROBE: &str = "TACTUS_ENDLESS_LOG_PROBE";

    /// The child half of
    /// [`a_run_directory_whose_log_never_ends_is_still_classified`].
    ///
    /// A subprocess rather than a thread, and the reason is the failure mode
    /// rather than the success one: a probe that does not terminate cannot be
    /// stopped from inside the process it is running in, and the mutation this
    /// guards against (an unconditional `read_to_end`) also grows memory
    /// without bound while it fails to return. A child can be killed at a
    /// deadline; a thread would take the whole suite, and the machine, with it.
    #[test]
    #[ignore = "subprocess helper"]
    fn endless_log_classification_helper() {
        let Ok(dir) = std::env::var(ENDLESS_LOG_DIR) else {
            return;
        };
        assert_eq!(
            classify_run_dir(Path::new(&dir)),
            RunDirClass::Husk,
            "a log with no end holds no newline-terminated run_started"
        );
        // The second axis, and it is only measurable where the source can be
        // opened at all. `classify_run_dir` answering `Husk` is satisfied by a
        // guard that refuses the *name* and by a bound that reads the *bytes*,
        // so on its own it cannot say which one answered — and once
        // `first_committed_line` refuses to open a non-regular file, the
        // endless-device witness would silently stop reaching the bound it was
        // built for (`PR5-RD-001`). Here the child holds the guard's verdict
        // constant and varies the handle: it opens the device itself and asserts
        // the bounded read *also* terminates on it.
        if std::env::var_os(ENDLESS_LOG_PROBE).is_some() {
            let mut device = File::open(Path::new(&dir).join(EVENT_LOG)).expect("the log opens");
            assert_eq!(
                first_line(&mut device),
                None,
                "the bounded read must terminate on the device too, not only the guard"
            );
        }
        std::process::exit(0);
    }

    /// Run [`endless_log_classification_helper`] against `public` in a child,
    /// and fail with `never_returned` if it has not answered within 20 seconds.
    ///
    /// A subprocess, not a thread, for the reason the helper's own comment
    /// gives: a probe that does not terminate cannot be stopped from inside its
    /// own process, and both shapes this drives — an unbounded `read_to_end`
    /// and a blocked `open(2)` — are exactly that.
    ///
    /// Unix-gated because both callers are: `/dev/zero` and `mkfifo` are the two
    /// ways to get hold of a non-terminating source without privilege and
    /// neither exists on Windows, so on the guest this would be dead code — and
    /// the guest's `-D warnings` says so, which is how this gate was found.
    #[cfg(unix)]
    fn classification_must_answer(public: &Path, probe: bool, never_returned: &str) {
        let helper = format!(
            "{}::endless_log_classification_helper",
            module_path!()
                .split_once("::")
                .expect("this module is not the crate root")
                .1
        );
        let mut command =
            std::process::Command::new(std::env::current_exe().expect("the test executable"));
        command
            .args([helper.as_str(), "--ignored", "--exact"])
            .env(ENDLESS_LOG_DIR, public)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if probe {
            command.env(ENDLESS_LOG_PROBE, "1");
        }
        let mut child = command.spawn().expect("spawn the classification helper");

        let deadline = Instant::now() + Duration::from_secs(20);
        let outcome = loop {
            match child.try_wait().expect("wait on the helper") {
                Some(status) => break Some(status),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let status = outcome.unwrap_or_else(|| panic!("{never_returned}"));
        assert!(
            status.success(),
            "the helper reached a verdict but it was the wrong one, or it died: {status:?}"
        );
    }

    /// A public run directory whose `events.jsonl` is a **fifo with no writer**
    /// is classified, and classified promptly (`PR5-CONF-001`).
    ///
    /// The sibling below plants an endless *device*, whose `open` returns and
    /// whose `read` never ends; this plants a source whose `open` itself never
    /// returns, which no bound on the read can defend against because the bound
    /// is taken by `fstat` on a handle that is never produced. `startup_census`
    /// requires every entry to classify before a write command proceeds and the
    /// command holds the physical worktree lock across the census, so the
    /// consequence is the same one `PR5-RD-001` was repaired for: a lock held
    /// for ever by a process that will never make progress.
    ///
    /// The two axes this crosses are the *file type* and the *syscall that
    /// meets it*. Held constant: the directory shape, which is a perfectly
    /// ordinary public run directory — the only thing that varies from a
    /// `Committed` one is the type of the `events.jsonl` entry.
    ///
    /// Unix only, because a fifo is where a blocking `open` can be got hold of
    /// without privilege; `mkfifo` has no Windows counterpart at all.
    #[cfg(unix)]
    #[test]
    fn a_run_directory_whose_log_blocks_on_open_is_still_classified() {
        use std::os::unix::fs::FileTypeExt as _;

        let root = scratch("fifo");
        let public = root.join("run");
        fs::create_dir_all(&public).expect("public");
        let log = public.join(EVENT_LOG);
        let name = std::ffi::CString::new(log.as_os_str().as_encoded_bytes())
            .expect("a scratch path holds no interior NUL");
        // SAFETY: `name` is a live NUL-terminated path in a directory this test
        // just created; `mkfifo` borrows it for the duration of the call.
        let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        assert_eq!(
            made,
            0,
            "could not plant the fifo: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            fs::symlink_metadata(&log)
                .expect("stat the fifo")
                .file_type()
                .is_fifo(),
            "the planted entry must really be a fifo, or nothing here is measured"
        );
        // The premise, stated rather than assumed: `stat` answers about this
        // entry immediately, so a guard that consults the type before opening
        // can terminate — and that is the only reason one is possible.
        assert_eq!(
            fs::symlink_metadata(&log).expect("stat the fifo").len(),
            0,
            "a fifo declares no length"
        );

        classification_must_answer(
            &public,
            false,
            "classify_run_dir did not return within 20s for an events.jsonl that is a \
             writer-less fifo. `File::open` blocks in the kernel before any bound on the \
             read applies, the startup census would never classify this entry, and the \
             write command would hold the worktree lock for ever (PR5-CONF-001)",
        );
    }

    /// A public run directory whose `events.jsonl` is a real endless device is
    /// classified, and classified *quickly* (`PR5-RD-001`).
    ///
    /// `startup_census` requires **every** run-directory entry to be classified
    /// `Committed` or `Husk` before a write command proceeds, and the write
    /// command holds the physical worktree lock while it does that. An entry
    /// that never classifies is therefore not a slow census: it is a lock held
    /// for ever by a process that will never make progress, and no later
    /// command in that worktree can run.
    ///
    /// Unix only because `/dev/zero` is where a source with no end can be got
    /// hold of without privilege. The platform-free half of the same claim —
    /// that the probe spends a finite budget and stops — is
    /// `the_first_line_probe_spends_its_budget_and_stops`, which runs on the
    /// Windows guest too.
    ///
    /// **The child probes the device as well as the directory**, and that is not
    /// decoration (`PR5-CONF-001`). Once `first_committed_line` refuses to open
    /// anything that is not a regular file, this planted symlink is answered by
    /// the *guard*, so the classification alone would no longer reach the bound
    /// this test exists for — a green `Husk` would mean the name was refused and
    /// say nothing about the read. The child therefore holds the class constant
    /// and varies the handle: it asserts `Husk`, then opens the real device and
    /// asserts the bounded read terminates on it too. Both assertions run inside
    /// the same 20-second deadline, so either one failing to *return* fails
    /// here rather than hanging the suite.
    #[cfg(unix)]
    #[test]
    fn a_run_directory_whose_log_never_ends_is_still_classified() {
        let root = scratch("endless");
        let public = root.join("run");
        fs::create_dir_all(&public).expect("public");
        assert!(
            Path::new("/dev/zero").exists(),
            "this host has no endless device, so nothing here is measured"
        );
        std::os::unix::fs::symlink("/dev/zero", public.join(EVENT_LOG)).expect("symlink");
        // The device is what the probe will actually meet: a handle that opens,
        // declares no length, and never reaches end of file.
        let device = File::open(public.join(EVENT_LOG)).expect("the log opens");
        assert_eq!(
            device.metadata().expect("stat").len(),
            0,
            "a character device declares no length, which is the probe's budget"
        );
        drop(device);

        classification_must_answer(
            &public,
            true,
            "classify_run_dir or first_line did not return within 20s for an events.jsonl \
             that never ends. The startup census would never classify this entry and the \
             write command would hold the worktree lock for ever (PR5-RD-001)",
        );
    }

    // =======================================================================
    // Readers by commitment
    // =======================================================================

    /// A repository holding one committed run, one husk older than it and one
    /// husk newer than it — so a reader that returned husks would be caught
    /// whichever end of the sort it went wrong at.
    fn repo_with_a_committed_run_between_two_husks(tag: &str) -> PathBuf {
        let repo = scratch(tag).join("repo");
        fs::create_dir_all(runs_root(&repo).join("01AAAHUSK")).expect("older husk");
        write(
            &public_dir(&repo, "01AAAHUSK").join(PLAN),
            b"{\"tasks\":[]}",
        );
        commit_run(&repo, "01BBBRUN");
        fs::create_dir_all(runs_root(&repo).join("01ZZZHUSK")).expect("newer husk");
        write(
            &public_dir(&repo, "01ZZZHUSK").join(MARKER),
            &any_marker_bytes(),
        );
        repo
    }

    /// Every reader **in this module**, crossed with every husk **shape** —
    /// the second axis, and the one this fixture used to be too narrow on.
    ///
    /// `startup_census` names five readers — `list_runs`, `latest_run`,
    /// `resolve_run_id`, `find_question`, `status` — and four of them live
    /// here. The fifth is the `status` command, which reaches run directories
    /// through `resolve_run_id` and `husk_report`, and its husk behaviour is
    /// pinned in its own module by
    /// `status_asked_for_a_husk_id_names_which_husk_it_is`.
    ///
    /// Four readers against two shapes caught any reader that simply stopped
    /// filtering: `find_question` scanning `run_dir_names`, and `latest_run`
    /// taking the newest directory, both die here. What it could not see was a
    /// shape it did not build. Its husks are a markerless directory carrying
    /// content and one with a **well-formed** marker, and
    /// `a_committed_run_is_never_excluded_because_of_a_marker` uses well-formed
    /// markers too — so a filter that admitted exactly the *malformed-marker*
    /// husk changed no measured answer, and the readers' behaviour over that
    /// shape was unpinned in both directions. Measured surviving the whole
    /// suite on Linux and on the Windows guest.
    ///
    /// `01ZZZMALFORMED` is therefore built to win every reader it could: it
    /// sorts lexically last, so `latest_run` would take it, and it carries the
    /// question id being searched for, so `find_question` would return it.
    #[test]
    fn every_reader_returns_committed_directories_only() {
        let repo = repo_with_a_committed_run_between_two_husks("readers");
        // The third shape: a marker that is present and unparseable. Not a
        // fifth reader — the four this module owns are all here already, and
        // the fifth, `status`, is pinned in `status.rs` — a third *shape*.
        let malformed = public_dir(&repo, "01ZZZMALFORMED");
        fs::create_dir_all(&malformed).expect("malformed-marker husk");
        write(&malformed.join(MARKER), b"{ not json at all");
        for husk in ["01AAAHUSK", "01ZZZHUSK", "01ZZZMALFORMED"] {
            let questions = public_dir(&repo, husk).join("questions");
            fs::create_dir_all(&questions).expect("questions");
            fs::write(questions.join("q-HUSK.json"), "{}").expect("question");
        }
        let questions = public_dir(&repo, "01BBBRUN").join("questions");
        fs::create_dir_all(&questions).expect("questions");
        fs::write(questions.join("q-REAL.json"), "{}").expect("question");

        assert_eq!(list_runs(&repo), ["01BBBRUN"], "list_runs");
        assert_eq!(latest_run(&repo).as_deref(), Some("01BBBRUN"), "latest_run");
        assert_eq!(
            resolve_run_id(&repo, "01BBBRUN").expect("the committed run resolves"),
            "01BBBRUN"
        );
        for husk in ["01AAAHUSK", "01ZZZHUSK", "01ZZZMALFORMED"] {
            let error = resolve_run_id(&repo, husk).expect_err("a husk is not a run");
            assert!(
                error.to_string().contains("never recorded a committed"),
                "resolve_run_id must say why: {error}"
            );
        }
        assert_eq!(
            find_question(&repo, "q-REAL")
                .expect("the committed run's question")
                .run_id,
            "01BBBRUN"
        );
        let error = find_question(&repo, "q-HUSK").expect_err("a husk's question is not findable");
        assert!(error.to_string().contains("no question"), "{error}");

        // And the husks are still there: a reader observes, it never reclaims.
        assert_eq!(
            list_husks(&repo),
            ["01AAAHUSK", "01ZZZHUSK", "01ZZZMALFORMED"]
        );
        assert_eq!(run_dir_names(&repo).len(), 4);
    }

    #[test]
    fn a_committed_run_is_never_excluded_because_of_a_marker() {
        // The other half of the behaviour change, and the half a plausible
        // suite forgets: `run_creation` says readers "never return a directory
        // without a committed run_started **and never hide one because of a
        // marker**". Both marker shapes, and with a newer husk present so the
        // committed run has to win `latest_run` on its merits.
        let repo = scratch("markedcommitted").join("repo");
        commit_run(&repo, "01AAAMARKED");
        commit_run(&repo, "01BBBSTAGED");
        write(
            &public_dir(&repo, "01AAAMARKED").join(MARKER),
            &any_marker_bytes(),
        );
        write(
            &public_dir(&repo, "01BBBSTAGED").join(MARKER_STAGED),
            &any_marker_bytes(),
        );
        fs::create_dir_all(runs_root(&repo).join("01ZZZHUSK")).expect("newer husk");

        assert_eq!(list_runs(&repo), ["01AAAMARKED", "01BBBSTAGED"]);
        assert_eq!(
            latest_run(&repo).as_deref(),
            Some("01BBBSTAGED"),
            "a committed-but-marked run is the latest run, and a husk newer \
             than it does not become one"
        );
        for id in ["01AAAMARKED", "01BBBSTAGED"] {
            assert_eq!(resolve_run_id(&repo, id).expect("resolves"), id);
            assert_eq!(
                classify_run_dir(&public_dir(&repo, id)),
                RunDirClass::Committed
            );
        }
    }

    #[test]
    fn latest_run_skips_a_husk_that_would_otherwise_shadow_it() {
        // The named change: "legacy husks that today shadow latest_run are no
        // longer listed". Asserted from the shadowing direction, because that
        // is the operator-visible symptom.
        let repo = repo_with_a_committed_run_between_two_husks("shadow");
        assert_eq!(latest_run(&repo).as_deref(), Some("01BBBRUN"));
        assert!(
            run_dir_names(&repo)
                .last()
                .is_some_and(|last| last == "01ZZZHUSK"),
            "the husk really is the newest directory, so the skip is doing work"
        );
    }

    // =======================================================================
    // The private half's ownership
    // =======================================================================

    const BOUND_RUN: &str = "01BOUNDHUSK000000000000000";
    const BOUND_INCARNATION: &str = "01INCARNATION00000000000000";

    /// A husk at P3b–P5: the marker published, the private half created, the
    /// owner record published, and no commit record. The one shape the proof
    /// is supposed to accept.
    struct BoundHusk {
        root: PathBuf,
        repo: PathBuf,
        private_root: PathBuf,
        repo_key: RepoKey,
        /// Where the private half's bytes are written.
        private: PathBuf,
        marker: CreatingMarker,
        owner: OwnerRecord,
    }

    impl BoundHusk {
        fn new(tag: &str) -> Self {
            let root = scratch(tag);
            let repo = root.join("repo");
            let private_root = root.join("private");
            let public = public_dir(&repo, BOUND_RUN);
            fs::create_dir_all(&public).expect("public");
            fs::create_dir_all(private_root.join("runs")).expect("runs root");
            let private = fs::canonicalize(private_root.join("runs"))
                .expect("canonical runs root")
                .join(BOUND_RUN);
            let repo_key = RepoKey::v1(&root.join("git-dir"));
            let policy = crate::runner::policy::host_policy();
            let marker = CreatingMarker {
                run_id: BOUND_RUN.to_owned(),
                repo_key: repo_key.as_str().to_owned(),
                private_dir: private.to_string_lossy().into_owned(),
                incarnation: BOUND_INCARNATION.to_owned(),
                pid: std::process::id(),
                runner_policy_sha256: runner_policy_sha256(&policy),
            };
            let owner = OwnerRecord {
                run_id: BOUND_RUN.to_owned(),
                repo_key: repo_key.as_str().to_owned(),
                public_dir: fs::canonicalize(&public)
                    .expect("canonical public")
                    .to_string_lossy()
                    .into_owned(),
                incarnation: BOUND_INCARNATION.to_owned(),
                runner: policy,
            };
            Self {
                root,
                repo,
                private_root,
                repo_key,
                private,
                marker,
                owner,
            }
        }

        fn public(&self) -> PathBuf {
            public_dir(&self.repo, BOUND_RUN)
        }

        /// Publish both halves through the funnels, in the packet's order.
        fn publish(&self) {
            let hooks = &mut NoHooks;
            let public = self.public();
            create_public_dir(&public, hooks).expect("P0");
            stage_marker(&public, &self.marker, hooks).expect("P1a");
            publish_marker(&public, hooks).expect("P1b");
            create_private_dir(&self.private, hooks).expect("P3");
            stage_owner_record(&self.private, &self.owner, hooks).expect("P3a");
            publish_owner_record(&self.private, hooks).expect("P3b");
        }

        fn prove(&self) -> PrivateHalfOwnership {
            prove_private_half_ownership(&self.public(), &self.repo_key, &self.private_root)
        }
    }

    /// Every file below `root`, by relative path, so "byte-identical
    /// afterwards" is an assertion rather than a hope.
    fn snapshot_tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(bytes) = fs::read(&path) {
                    out.insert(
                        path.strip_prefix(root).unwrap_or(&path).to_path_buf(),
                        bytes,
                    );
                }
            }
        }
        out
    }

    /// A directory link: a POSIX symlink, or on Windows a **junction**.
    ///
    /// `mklink /J` rather than `/D` because a junction needs no privilege and
    /// is exactly the reparse point `expected_failures_refusals[0]` names
    /// beside a symlink. A refusal that only fired on POSIX symlinks would
    /// pass every Linux test and refuse nothing on the platform the word
    /// "junction" is about.
    fn link_dir(link: &Path, target: &Path) {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).expect("symlink");
        }
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .status()
                .expect("mklink runs");
            assert!(
                status.success(),
                "creating a junction must succeed; an unmakeable junction is a \
                 failure of this test, never a skip"
            );
        }
        assert!(
            fs::symlink_metadata(link).is_ok(),
            "the link must exist afterwards"
        );
    }

    /// What a case expects the proof to answer.
    #[derive(Debug, PartialEq, Eq)]
    enum Expect {
        Proven,
        Nothing(UnboundShape),
        /// The kind, and — when the owner record is what disagreed — the field.
        Retained(&'static str, Option<OwnerField>),
    }

    struct ProofCase {
        name: &'static str,
        /// Applied to the records before publication.
        before: fn(&mut BoundHusk),
        /// Applied to the bytes on disk after publication.
        after: fn(&BoundHusk),
        expect: Expect,
    }

    fn nothing(_: &mut BoundHusk) {}
    fn nothing_after(_: &BoundHusk) {}

    /// One case per conjunct, because every conjunct is separately droppable
    /// and a suite testing the happy path plus one negative passes with any
    /// single one removed.
    fn proof_cases() -> Vec<ProofCase> {
        vec![
            ProofCase {
                name: "a bound husk without a commit record yields a token",
                before: nothing,
                after: nothing_after,
                expect: Expect::Proven,
            },
            ProofCase {
                name: "malformed marker",
                before: nothing,
                after: |husk| write(&husk.public().join(MARKER), b"{ not json at all"),
                expect: Expect::Retained("marker-unparseable", None),
            },
            ProofCase {
                name: "forged marker naming a foreign run",
                before: |husk| husk.marker.run_id = "01FOREIGNRUN00000000000000".to_owned(),
                after: nothing_after,
                expect: Expect::Retained("marker-run-id-mismatch", None),
            },
            ProofCase {
                name: "copied husk from another repository",
                before: |husk| {
                    husk.marker.repo_key = RepoKey::v1(&husk.root.join("another-git-dir"))
                        .as_str()
                        .to_owned();
                },
                after: nothing_after,
                expect: Expect::Retained("marker-repo-key-mismatch", None),
            },
            ProofCase {
                name: "locator outside the authorized private root",
                before: |husk| {
                    let foreign = husk.root.join("foreign-root").join("runs");
                    fs::create_dir_all(&foreign).expect("foreign root");
                    husk.private = fs::canonicalize(&foreign)
                        .expect("canonical foreign root")
                        .join(BOUND_RUN);
                    husk.marker.private_dir = husk.private.to_string_lossy().into_owned();
                },
                after: nothing_after,
                expect: Expect::Retained("locator-outside-authorized-root", None),
            },
            ProofCase {
                name: "locator through a reparse point",
                before: |husk| {
                    let real = husk.private_root.join("elsewhere");
                    fs::create_dir_all(&real).expect("real private half");
                    let link = husk.private_root.join("runs").join(BOUND_RUN);
                    link_dir(&link, &real);
                    // The marker records the *link*, which is what a census
                    // has to follow and what the chain check has to refuse.
                    husk.private = link.clone();
                    husk.marker.private_dir = link.to_string_lossy().into_owned();
                },
                after: nothing_after,
                expect: Expect::Retained("locator-through-reparse-point", None),
            },
            ProofCase {
                name: "private target without an owner record",
                before: nothing,
                after: |husk| {
                    fs::remove_file(husk.private.join(OWNER_RECORD)).expect("remove owner record");
                },
                expect: Expect::Retained("owner-record-missing", None),
            },
            ProofCase {
                name: "owner record that cannot be read",
                before: nothing,
                after: |husk| write(&husk.private.join(OWNER_RECORD), b"{ not json"),
                expect: Expect::Retained("owner-record-unparseable", None),
            },
            ProofCase {
                name: "owner record disagreeing on run id",
                before: |husk| husk.owner.run_id = "01OTHERRUN0000000000000000".to_owned(),
                after: nothing_after,
                expect: Expect::Retained("owner-record-disagrees", Some(OwnerField::RunId)),
            },
            ProofCase {
                name: "owner record disagreeing on repo key",
                before: |husk| {
                    husk.owner.repo_key = RepoKey::v1(&husk.root.join("third-git-dir"))
                        .as_str()
                        .to_owned();
                },
                after: nothing_after,
                expect: Expect::Retained("owner-record-disagrees", Some(OwnerField::RepoKey)),
            },
            ProofCase {
                name: "owner record disagreeing on public path",
                before: |husk| {
                    husk.owner.public_dir = husk
                        .root
                        .join("some-other-run-directory")
                        .to_string_lossy()
                        .into_owned();
                },
                after: nothing_after,
                expect: Expect::Retained("owner-record-disagrees", Some(OwnerField::PublicDir)),
            },
            ProofCase {
                name: "owner record disagreeing on incarnation",
                before: |husk| husk.owner.incarnation = "01ANOTHERINCARNATION000000".to_owned(),
                after: nothing_after,
                expect: Expect::Retained("owner-record-disagrees", Some(OwnerField::Incarnation)),
            },
            ProofCase {
                name: "owner record naming another runner boundary",
                before: |husk| husk.owner.runner = another_policy(),
                after: nothing_after,
                expect: Expect::Retained("owner-record-disagrees", Some(OwnerField::RunnerDigest)),
            },
            ProofCase {
                name: "marker-less husk carrying run-scoped content",
                before: nothing,
                after: |husk| {
                    fs::remove_file(husk.public().join(MARKER)).expect("remove marker");
                    write(&lock_file(&husk.public()), b"");
                },
                expect: Expect::Retained("markerless-with-content", None),
            },
            ProofCase {
                name: "private half carrying a commit record",
                before: nothing,
                after: |husk| write(&husk.private.join(COMMIT_RECORD), b"{}"),
                expect: Expect::Retained("possibly-committed", None),
            },
            ProofCase {
                name: "bare public directory",
                before: nothing,
                after: |husk| {
                    fs::remove_file(husk.public().join(MARKER)).expect("remove marker");
                },
                expect: Expect::Nothing(UnboundShape::Bare),
            },
            ProofCase {
                name: "staged marker only",
                before: nothing,
                after: |husk| {
                    fs::rename(
                        husk.public().join(MARKER),
                        husk.public().join(MARKER_STAGED),
                    )
                    .expect("unpublish the marker");
                },
                expect: Expect::Nothing(UnboundShape::StagedMarkerOnly),
            },
            ProofCase {
                name: "marker whose recorded target is gone",
                before: nothing,
                after: |husk| {
                    fs::remove_dir_all(&husk.private).expect("remove the private half");
                },
                expect: Expect::Nothing(UnboundShape::TargetAbsent),
            },
        ]
    }

    /// A second host policy, distinguishable from `host_policy()` by its
    /// canonical bytes and therefore by its digest.
    fn another_policy() -> RunnerPolicy {
        let mut policy = crate::runner::policy::host_policy();
        policy.credential_volumes = Some(std::collections::BTreeMap::from([(
            "claude-code".to_owned(),
            "tactus-creds".to_owned(),
        )]));
        policy
    }

    /// Conjunct 5 binds the locator to **this run's basename**, not merely to
    /// the authorized `runs` directory (`PR5-RUNDIR-022`).
    ///
    /// `scope` is "locator chain without reparse points canonicalizing to
    /// `<authorized private root>/runs/<basename>`" — an equality. The grid's
    /// own conjunct-5 case points the locator at a *foreign root*, which a
    /// `starts_with` prefix test rejects exactly as an equality does, so the
    /// conjunct was proven to reject another root and never asked the question
    /// the sentence is about. These are the two shapes a prefix test admits: a
    /// **sibling** run's private half, and a path **nested** inside this run's
    /// own. The first is the one that matters — under it a proof for run A
    /// authorizes deleting run B's private half, and
    /// `tests_acceptance.seam_tests[3]` says "no census can bind another run's
    /// private half to a husk".
    ///
    /// A separate test rather than two more `proof_cases` entries: that grid
    /// asserts one *distinct* `RetainReason` per case, so two more cases
    /// refusing for the same reason would fail it, and the property it is
    /// asserting — every conjunct separately covered — is worth keeping.
    #[test]
    fn a_locator_beside_or_below_this_runs_private_half_cannot_authorize_deletion() {
        type Build = fn(&mut BoundHusk) -> PathBuf;
        let cases: Vec<(&str, Build)> = vec![
            (
                "a sibling run under the authorized runs directory",
                |husk| {
                    let sibling = husk
                        .private_root
                        .join("runs")
                        .join("01SIBLINGRUN0000000000000");
                    fs::create_dir_all(&sibling).expect("the sibling private half");
                    write(&sibling.join("evidence"), b"another run's private half");
                    fs::canonicalize(&sibling).expect("canonical sibling")
                },
            ),
            ("a path nested below this run's private half", |husk| {
                let nested = husk
                    .private_root
                    .join("runs")
                    .join(BOUND_RUN)
                    .join("transcripts");
                fs::create_dir_all(&nested).expect("the nested directory");
                fs::canonicalize(&nested).expect("canonical nested")
            }),
        ];
        for (index, (name, build)) in cases.into_iter().enumerate() {
            let mut husk = BoundHusk::new(&format!("locator-prefix{index}"));
            let target = build(&mut husk);
            husk.private = target.clone();
            husk.marker.private_dir = target.to_string_lossy().into_owned();
            husk.publish();
            let before = snapshot_tree(&target);

            match husk.prove() {
                PrivateHalfOwnership::Retained(reason) => assert_eq!(
                    reason.kind(),
                    "locator-outside-authorized-root",
                    "{name}: {reason}"
                ),
                other => panic!(
                    "{name}: a locator that is not <authorized>/runs/<basename> handed out \
                     {other:?}"
                ),
            }
            assert_eq!(
                snapshot_tree(&target),
                before,
                "{name}: and the refusal touched nothing"
            );
        }
    }

    #[test]
    fn every_conjunct_of_the_ownership_proof_refuses_on_its_own() {
        let mut kinds: Vec<(&'static str, Option<OwnerField>)> = Vec::new();
        let mut shapes: Vec<UnboundShape> = Vec::new();
        let mut proven = 0usize;

        for (index, case) in proof_cases().into_iter().enumerate() {
            let mut husk = BoundHusk::new(&format!("proof{index}"));
            (case.before)(&mut husk);
            husk.publish();
            (case.after)(&husk);
            let before_bytes = snapshot_tree(&husk.private);

            let answer = husk.prove();
            match (&case.expect, &answer) {
                (Expect::Proven, PrivateHalfOwnership::Proven(token)) => {
                    assert_eq!(token.run_id(), BOUND_RUN, "{}", case.name);
                    assert_eq!(
                        fs::canonicalize(token.target()).expect("canonical target"),
                        fs::canonicalize(&husk.private).expect("canonical private"),
                        "{}",
                        case.name
                    );
                    proven += 1;
                }
                (Expect::Nothing(expected), PrivateHalfOwnership::NothingBound(shape)) => {
                    assert_eq!(shape, expected, "{}", case.name);
                    shapes.push(*shape);
                }
                (Expect::Retained(kind, field), PrivateHalfOwnership::Retained(reason)) => {
                    assert_eq!(&reason.kind(), kind, "{}: {reason}", case.name);
                    assert_eq!(&reason.owner_field(), field, "{}: {reason}", case.name);
                    kinds.push((reason.kind(), reason.owner_field()));
                }
                (expected, actual) => {
                    panic!("{}: expected {expected:?}, got {actual:?}", case.name)
                }
            }

            // "each yield a RetainReason and leave the target byte-identical".
            assert_eq!(
                snapshot_tree(&husk.private),
                before_bytes,
                "{}: the proof is read-only",
                case.name
            );
        }

        assert_eq!(proven, 1, "exactly one case is the happy path");

        // The counts are what makes a dropped conjunct fail. A suite that
        // asserted only "some negative refuses" passes with any single
        // conjunct deleted; a suite that asserts every *kind* appears exactly
        // once does not.
        let mut distinct = kinds.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            kinds.len(),
            "two cases produced the same reason, so one conjunct is untested: {kinds:?}"
        );

        let mut covered: Vec<&str> = kinds.iter().map(|(kind, _)| *kind).collect();
        covered.sort_unstable();
        covered.dedup();
        let mut expected: Vec<&str> = RetainReason::KINDS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            covered, expected,
            "every RetainReason variant is a conjunct this grid must exercise"
        );

        let mut fields: Vec<OwnerField> = kinds.iter().filter_map(|(_, field)| *field).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            OwnerField::ALL.to_vec(),
            "every field the owner record is checked on has its own case"
        );

        shapes.sort_unstable_by_key(|shape| format!("{shape:?}"));
        let mut expected_shapes = UnboundShape::ALL.to_vec();
        expected_shapes.sort_unstable_by_key(|shape| format!("{shape:?}"));
        assert_eq!(shapes, expected_shapes, "every unbound shape has a case");
    }

    #[test]
    fn a_marker_digest_naming_another_boundary_is_the_same_refusal() {
        // The mismatch the packet calls `runner_digest_mismatch_retained` can
        // be written from either side; both are one comparison and both must
        // refuse. The grid mutates the record's policy, so this mutates the
        // marker's digest.
        let mut husk = BoundHusk::new("markerdigest");
        husk.marker.runner_policy_sha256 = runner_policy_sha256(&another_policy());
        husk.publish();
        match husk.prove() {
            PrivateHalfOwnership::Retained(reason) => {
                assert_eq!(reason.kind(), "owner-record-disagrees");
                assert_eq!(reason.owner_field(), Some(OwnerField::RunnerDigest));
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// `owner.json` **absent** and `committed.json` **present**: the fourth
    /// cell of two axes the grid covers only one at a time.
    ///
    /// The grid has both singles — "private target without an owner record"
    /// answers `owner-record-missing`, "private half carrying a commit record"
    /// answers `possibly-committed` — and neither is the crossing. Measured:
    /// an arm answering `Proven` for exactly this cell survived the whole
    /// suite, and `Proven` here is a `PrivateHalfProof`, the deletion token and
    /// the only key to `remove_private_husk`, handed out for a half that may
    /// have crossed P5b.
    ///
    /// **Standalone rather than a `ProofCase` row, and it has to be.** The grid
    /// asserts that no two cases produce the same `RetainReason` ("two cases
    /// produced the same reason, so one conjunct is untested"), and this cell
    /// answers `owner-record-missing`, which the single-axis case already
    /// claims — so the crossing cannot be written as a row at all. The grid's
    /// own shape is part of why the crossing was missing.
    ///
    /// The conjunct **order** is what decides which reason comes out: the owner
    /// check precedes the commit check, so this cell reports the missing record
    /// rather than the possible commit. Both are safe — neither yields a token
    /// — but they are different things to tell an operator, and nothing else
    /// pins which one it is.
    #[test]
    fn probe_a_commit_record_without_an_owner_record_yields_no_token() {
        let husk = BoundHusk::new("probe-commit-no-owner");
        husk.publish();
        fs::remove_file(husk.private.join(OWNER_RECORD)).expect("remove the owner record");
        write(&husk.private.join(COMMIT_RECORD), b"{}");
        let before = snapshot_tree(&husk.private);

        match husk.prove() {
            PrivateHalfOwnership::Retained(reason) => {
                assert_eq!(reason.kind(), "owner-record-missing");
            }
            other => {
                panic!("a private half that may have crossed P5b must never be proven: {other:?}")
            }
        }
        assert_eq!(
            snapshot_tree(&husk.private),
            before,
            "the private half is byte-identical after the proof"
        );
    }

    /// `owner.json.tmp` present and `owner.json` absent — what an interrupted
    /// P3b leaves — is not a record, and yields no token.
    ///
    /// Neither axis alone can see the difference. `PR5-RUNDIR-045`'s fixture
    /// leaves the staging file where the published record is also present, and
    /// `PR5-RUNDIR-024`'s has neither file, so a proof that fell back from
    /// `owner.json` to `owner.json.tmp` changed no measured answer: an
    /// interrupted publication read as a completed one, and a record that was
    /// never durable became proof of ownership. That fallback survived the
    /// whole suite.
    ///
    /// The fixture is built by **unpublishing** — renaming the published record
    /// back to its staging name — so the half on disk is exactly the state P3a
    /// leaves and P3b has not yet finished. Both halves are compared byte for
    /// byte afterwards, the staging file included, so an implementation that
    /// consumed or tidied it up cannot pass either.
    #[test]
    fn probe_an_owner_staging_file_is_not_an_owner_record() {
        let husk = BoundHusk::new("probe-owner-staged-only");
        husk.publish();
        fs::rename(
            husk.private.join(OWNER_RECORD),
            husk.private.join(OWNER_RECORD_STAGED),
        )
        .expect("unpublish the owner record");
        let before_private = snapshot_tree(&husk.private);
        let before_public = snapshot_tree(&husk.public());

        match husk.prove() {
            PrivateHalfOwnership::Retained(reason) => {
                assert_eq!(reason.kind(), "owner-record-missing");
            }
            other => panic!("an interrupted publication is not a proof of ownership: {other:?}"),
        }
        assert!(
            husk.private.join(OWNER_RECORD_STAGED).is_file(),
            "the staging file is still where the interruption left it"
        );
        assert_eq!(
            snapshot_tree(&husk.private),
            before_private,
            "the private half is byte-identical after the proof"
        );
        assert_eq!(
            snapshot_tree(&husk.public()),
            before_public,
            "and so is the public half"
        );
    }

    #[test]
    fn the_names_on_disk_are_the_names_the_packet_writes() {
        // The funnels and the proof share the path constants, so a rename of
        // one constant would move both together and every other test in this
        // module would still pass. These are literals, written out of
        // `run_creation` and `resource_accounting`.
        let husk = BoundHusk::new("names");
        let public = husk.public();
        stage_marker(&public, &husk.marker, &mut NoHooks).expect("stage");
        assert!(public.join(".creating.tmp").is_file(), "staged marker");
        publish_marker(&public, &mut NoHooks).expect("publish");
        assert!(public.join(".creating").is_file(), "published marker");
        assert!(!public.join(".creating.tmp").exists(), "staging is spent");

        create_private_dir(&husk.private, &mut NoHooks).expect("private");
        stage_owner_record(&husk.private, &husk.owner, &mut NoHooks).expect("stage owner");
        assert!(husk.private.join("owner.json.tmp").is_file());
        publish_owner_record(&husk.private, &mut NoHooks).expect("publish owner");
        assert!(husk.private.join("owner.json").is_file());
        assert!(!husk.private.join("owner.json.tmp").exists());

        let record = CommitRecord {
            run_id: BOUND_RUN.to_owned(),
            repo_key: husk.repo_key.as_str().to_owned(),
            public_dir: husk.owner.public_dir.clone(),
            incarnation: BOUND_INCARNATION.to_owned(),
            run_started_sha256: run_started_sha256(committed_line(BOUND_RUN, 4).as_bytes()),
        };
        stage_commit_record(&husk.private, &record, &mut NoHooks).expect("stage commit");
        assert!(husk.private.join("committed.json.tmp").is_file());
        publish_commit_record(&husk.private, &mut NoHooks).expect("publish commit");
        assert!(husk.private.join("committed.json").is_file());
        assert!(!husk.private.join("committed.json.tmp").exists());

        assert_eq!(
            public.join(EVENT_LOG).file_name().expect("name"),
            "events.jsonl"
        );
        assert_eq!(
            public.join(PLAN).file_name().expect("name"),
            "plan.normalized.json"
        );
        assert_eq!(lock_file(&public).file_name().expect("name"), "run.lock");
        assert_eq!(
            worktree_lock_file(Path::new("g"))
                .file_name()
                .expect("name"),
            "tactus-worktree.lock"
        );
    }

    #[test]
    fn a_committed_private_half_is_never_provable_however_bound_it_is() {
        // The commit-record condition is the last conjunct and the one whose
        // absence is invisible in the happy path: every other field agrees, so
        // a proof that had dropped it would hand out a token for a private
        // half that may have crossed P5b.
        let husk = BoundHusk::new("committedhalf");
        husk.publish();
        assert!(
            matches!(husk.prove(), PrivateHalfOwnership::Proven(_)),
            "the same husk without a commit record is provable"
        );
        write(&husk.private.join(COMMIT_RECORD), b"{}");
        match husk.prove() {
            PrivateHalfOwnership::Retained(RetainReason::PossiblyCommitted) => {}
            other => panic!("a commit record must refuse the token: {other:?}"),
        }
    }

    #[test]
    fn the_proof_token_names_the_half_it_authorises_and_nothing_else() {
        let husk = BoundHusk::new("tokentarget");
        husk.publish();
        let PrivateHalfOwnership::Proven(token) = husk.prove() else {
            panic!("the bound husk proves");
        };
        assert_eq!(token.public_dir(), husk.public());
        assert_eq!(token.run_id(), BOUND_RUN);
        assert!(token.target().ends_with(BOUND_RUN));

        // And spending it removes exactly that half, leaving the public one.
        remove_private_husk(token, &mut NoHooks).expect("the token authorises this deletion");
        assert!(!husk.private.exists(), "the private half is gone");
        assert!(husk.public().is_dir(), "the public half is a separate step");
    }

    #[test]
    fn the_public_husk_is_removed_with_its_marker_last() {
        // `startup_census`: "the public directory is removed with the marker
        // last … so a kill mid-census leaves a husk the next census
        // completes". A marker removed first would leave a marker-less husk
        // with content, which the next census retains rather than finishes.
        let husk = BoundHusk::new("publiclast");
        husk.publish();
        write(&lock_file(&husk.public()), b"");
        write(&husk.public().join(PLAN), b"{}");

        struct MarkerWatcher {
            public: PathBuf,
            marker_present_at_after: bool,
            others_gone_at_after: bool,
        }
        impl RunDirHooks for MarkerWatcher {
            fn hook(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection {
                if site == EffectSiteId::RunDir(RunDirSite::RemovePublicHusk)
                    && phase == HookPhase::After
                {
                    self.marker_present_at_after = self.public.join(MARKER).exists();
                    self.others_gone_at_after = !self.public.join(PLAN).exists();
                }
                Injection::Proceed
            }
        }

        // The `After` hook runs once the directory is gone, so the ordering is
        // observed by killing the removal partway instead: a kill before the
        // marker's own unlink must leave the marker there.
        let mut watcher = MarkerWatcher {
            public: husk.public(),
            marker_present_at_after: false,
            others_gone_at_after: false,
        };
        remove_public_husk(&husk.public(), &mut watcher).expect("remove");
        assert!(!husk.public().exists(), "the public half is gone");
        assert!(
            !watcher.marker_present_at_after && watcher.others_gone_at_after,
            "the whole directory is gone by the after phase"
        );
    }

    /// The marker really is removed **last**, observed by interrupting the
    /// removal (`PR5-RUNDIR-065`).
    ///
    /// `startup_census`: "the public directory is removed with the marker last
    /// (`RunDir.RemovePublicHusk`), **so a kill mid-census leaves a husk the
    /// next census completes**". The clause after the comma is the whole point
    /// of the ordering, and the test above cannot see it — its `After` hook
    /// runs once the directory is already gone, so both observations are the
    /// same under either order. Its own comment says what would work ("a kill
    /// before the marker's own unlink must leave the marker there") and it does
    /// not do it.
    ///
    /// The interruption is a **real** failed removal rather than an injection,
    /// because there is no injectable coordinate inside the loop and inventing
    /// one would mean a new point in a frozen enum. `zz-blocked` sorts after
    /// `plan.json`, so the loop provably got partway: an earlier entry is gone
    /// and a later one failed.
    ///
    /// Unix only. The fixture needs a removal that fails, and file permissions
    /// are how one is built without privilege; a process running as root would
    /// defeat them, which is why the precondition is asserted rather than
    /// assumed — this fails loudly there rather than passing vacuously.
    #[cfg(unix)]
    #[test]
    fn a_public_husk_removal_that_fails_partway_leaves_the_marker_that_locates_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let husk = BoundHusk::new("publiclast-interrupted");
        husk.publish();
        let public = husk.public();
        write(&public.join(PLAN), b"{}");
        let blocked = public.join("zz-blocked");
        write(
            &blocked.join("inside.txt"),
            b"content the removal cannot reach",
        );
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o500)).expect("seal it");
        assert!(
            fs::remove_dir_all(&blocked).is_err(),
            "this fixture needs a removal that fails, and here one does not — a process with              the privilege to ignore the permission bits cannot measure this"
        );
        assert!(public.join(MARKER).is_file(), "the husk has its marker");

        let error = remove_public_husk(&public, &mut NoHooks)
            .expect_err("the removal cannot finish, so it returns the failure");

        assert!(
            public.join(MARKER).is_file(),
            "the marker survived the failure and still locates this husk for the next              census: {error}"
        );
        assert!(
            !public.join(PLAN).exists(),
            "and the loop really got partway — an earlier entry was removed"
        );
        assert!(
            public.exists(),
            "the public directory itself is still there"
        );

        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).expect("unseal");
        // And once the obstruction is gone the same call finishes the job,
        // which is what "the next census completes" means.
        remove_public_husk(&public, &mut NoHooks).expect("the next census completes it");
        assert!(!public.exists(), "including the marker and the directory");
    }

    /// A public half whose only content is `.creating.tmp` is **removed**, not
    /// retained.
    ///
    /// The shape and the removal are each exercised and never composed. The
    /// grid's "staged marker only" case asserts `NothingBound(StagedMarkerOnly)`
    /// and stops at the classification; every fixture that reaches
    /// `remove_public_husk` drives a husk carrying a **published** marker plus
    /// other content. So a removal that skipped the staging file the way it
    /// skips the published marker left the directory non-empty and its final
    /// `remove_dir` failing, with nothing in the suite to observe it — measured
    /// surviving on Linux and on the Windows guest.
    ///
    /// `startup_census` (i) reclaims "a bare directory or one holding only a
    /// staged `.creating.tmp`", and the census reaching it is the whole
    /// obligation: retained-as-markerless-content is the outcome this shape
    /// must never get.
    ///
    /// The retry half **reconstructs** the state an interrupted first pass
    /// leaves — the other content gone, the staging file and the directory
    /// still there — rather than interrupting a real one. Building a genuine
    /// mid-loop failure needs a removal that fails, which is a permission
    /// fixture and therefore Unix-only
    /// (`a_public_husk_removal_that_fails_partway_leaves_the_marker_that_locates_it`
    /// is exactly that and is `#[cfg(unix)]`). What convergence needs is that
    /// the *state* is reached and finished, and this reaches it on both
    /// platforms.
    #[test]
    fn probe_a_staged_marker_only_public_husk_is_removed() {
        let root = scratch("probe-stagedonly");

        let public = root.join("runs").join("01STAGEDONLY");
        fs::create_dir_all(&public).expect("public directory");
        write(&public.join(MARKER_STAGED), b"{}");
        remove_public_husk(&public, &mut NoHooks).expect("the census removes a staged-marker husk");
        assert!(
            !public.exists(),
            "the public directory itself is gone, staging file and all"
        );

        // And it converges across an interrupted first pass.
        let retried = root.join("runs").join("01RETRY");
        fs::create_dir_all(&retried).expect("public directory");
        write(&retried.join(MARKER_STAGED), b"{}");
        write(&retried.join(PLAN), b"{}");
        fs::remove_file(retried.join(PLAN)).expect("the interrupted pass got this far");
        remove_public_husk(&retried, &mut NoHooks).expect("the retry converges");
        assert!(!retried.exists(), "the next census finishes the job");
    }

    /// P0 creates the **public** run directory and nothing else
    /// (`PR5-RUNDIR-036`).
    ///
    /// `run_creation` orders "P0 create the public run directory
    /// (`RunDir.CreatePublicDir`)" before "P3 create the private half at the
    /// recorded locator", and the private half exists so that no agent-authored
    /// byte is reachable from the workspace. Implementing P0 by calling the
    /// legacy `RunPaths::create()` — which builds both halves and both
    /// skeletons — satisfied every site-coverage assertion in this file,
    /// because none of them ever looked at what was on disk at a phase.
    #[test]
    fn p0_creates_the_public_directory_and_nothing_private() {
        let root = scratch("p0-only");
        let paths = paths_in(&root, "01P0ONLY");
        let public = paths.public.clone();
        let private = paths.private.clone();

        create_public_dir(&public, &mut NoHooks).expect("P0");

        assert!(public.is_dir(), "P0 created the public run directory");
        assert_eq!(
            read_dir_names(&public),
            Vec::<String>::new(),
            "and it is bare: no skeleton, no marker, no private half beneath it"
        );
        assert!(
            !private.exists(),
            "the private half is P3's, at the recorded locator, and does not exist yet"
        );
    }

    /// The owner record is the **first content** of a private half
    /// (`PR5-RUNDIR-044`).
    ///
    /// `side_effect_vs_event_ordering` says exactly that, and until now it was
    /// asserted by nothing: no test read the private half's directory listing
    /// at any point in the publication sequence, so moving the five skeleton
    /// directories into `create_private_dir`'s own funnel body — where they
    /// exist before `owner.json` is even staged — changed nothing observable.
    #[test]
    fn the_owner_record_is_the_first_content_of_a_private_half() {
        let root = scratch("owner-first");
        let private = root.join("private").join("runs").join("01OWNERFIRST");
        let owner = OwnerRecord {
            run_id: "01OWNERFIRST".to_owned(),
            repo_key: "0123456789abcdef".to_owned(),
            public_dir: root.join("public").to_string_lossy().into_owned(),
            incarnation: "01INC".to_owned(),
            runner: crate::runner::policy::host_policy(),
        };

        create_private_dir(&private, &mut NoHooks).expect("P3");
        assert_eq!(
            read_dir_names(&private),
            Vec::<String>::new(),
            "immediately after P3 the private half is empty"
        );

        stage_owner_record(&private, &owner, &mut NoHooks).expect("P3a");
        assert_eq!(
            read_dir_names(&private),
            vec![OWNER_RECORD_STAGED.to_owned()],
            "the staged owner record is the only thing in it"
        );

        publish_owner_record(&private, &mut NoHooks).expect("P3b");
        assert_eq!(
            read_dir_names(&private),
            vec![OWNER_RECORD.to_owned()],
            "and after publication the owner record is the only content there has ever been"
        );
    }

    // =======================================================================
    // The funnel
    // =======================================================================

    /// Records what the funnels reached, and answers with whatever was armed.
    #[derive(Debug, Default)]
    struct Observer {
        reached: Vec<(String, HookPhase)>,
        armed: Vec<(EffectSiteId, HookPhase, Injection)>,
    }

    impl Observer {
        fn arm(&mut self, site: EffectSiteId, phase: HookPhase, injection: Injection) {
            self.armed.push((site, phase, injection));
        }

        fn sites(&self) -> Vec<String> {
            let mut sites: Vec<String> =
                self.reached.iter().map(|(site, _)| site.clone()).collect();
            sites.sort_unstable();
            sites.dedup();
            sites
        }

        fn phases_of(&self, site: EffectSiteId) -> Vec<HookPhase> {
            let name = site.to_string();
            let mut phases: Vec<HookPhase> = self
                .reached
                .iter()
                .filter(|(seen, _)| *seen == name)
                .map(|(_, phase)| *phase)
                .collect();
            phases.dedup();
            phases
        }
    }

    impl RunDirHooks for Observer {
        fn hook(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection {
            self.reached.push((site.to_string(), phase));
            self.armed
                .iter()
                .find(|(armed, at, _)| *armed == site && *at == phase)
                .map_or(Injection::Proceed, |(_, _, injection)| *injection)
        }
    }

    /// Every site of the three groups this module funnels, from the frozen
    /// inventory's own `ALL` slices.
    fn sites_this_module_owns() -> Vec<String> {
        let mut names: Vec<String> = RunDirSite::ALL
            .iter()
            .map(|site| EffectSiteId::RunDir(*site).to_string())
            .chain(
                AnswerSite::ALL
                    .iter()
                    .map(|site| EffectSiteId::Answer(*site).to_string()),
            )
            .chain(
                LockSite::ALL
                    .iter()
                    .map(|site| EffectSiteId::Lock(*site).to_string()),
            )
            .collect();
        names.sort_unstable();
        names
    }

    fn commit_record_of(husk: &BoundHusk) -> CommitRecord {
        CommitRecord {
            run_id: BOUND_RUN.to_owned(),
            repo_key: husk.repo_key.as_str().to_owned(),
            public_dir: husk.owner.public_dir.clone(),
            incarnation: BOUND_INCARNATION.to_owned(),
            run_started_sha256: run_started_sha256(committed_line(BOUND_RUN, 4).as_bytes()),
        }
    }

    /// Every atomic publication's **durability sequence**, read out of the
    /// funnel's own ledger (`PR5-RUNDIR-057`).
    ///
    /// `run_creation` spells each of the three the same way — "write
    /// `<name>.tmp`, **fsync**, rename, **fsync the directory**" — and until
    /// this lane had a ledger, two of those four steps were not observables at
    /// all. Deleting `stage_json`'s `file.sync_all()`, which is the staging
    /// half of the marker, the owner record *and* the commit record, left the
    /// entire suite green: every consumer checks the *outcome* of a publication
    /// (the staged name is gone, the published name holds the right JSON, the
    /// census parses it) and an unsynced file is byte-for-byte a synced one on
    /// a machine that does not lose power.
    ///
    /// The ledger's length is the filesystem's own answer rather than a number
    /// the funnel carried along, so a sync that reported a length while the
    /// file held something else would fail here rather than agree with itself.
    #[test]
    fn every_atomic_publication_syncs_the_staged_file_then_renames_then_syncs_its_directory() {
        let root = scratch("durability");
        let public = root.join("public");
        let private = root.join("private");
        create_dir(&public).expect("public");
        create_dir(&private).expect("private");
        let policy = crate::runner::policy::host_policy();
        let marker = CreatingMarker {
            run_id: "01LEDGER".to_owned(),
            repo_key: "0123456789abcdef".to_owned(),
            private_dir: private.to_string_lossy().into_owned(),
            incarnation: "01INC".to_owned(),
            pid: std::process::id(),
            runner_policy_sha256: runner_policy_sha256(&policy),
        };
        let owner = OwnerRecord {
            run_id: "01LEDGER".to_owned(),
            repo_key: "0123456789abcdef".to_owned(),
            public_dir: public.to_string_lossy().into_owned(),
            incarnation: "01INC".to_owned(),
            runner: policy,
        };
        let commit = CommitRecord {
            run_id: "01LEDGER".to_owned(),
            repo_key: "0123456789abcdef".to_owned(),
            public_dir: public.to_string_lossy().into_owned(),
            incarnation: "01INC".to_owned(),
            run_started_sha256: run_started_sha256(b"{}\n"),
        };

        let mut hooks = HarnessHooks::default().recording_durability();
        let ledger = hooks.ledger();
        // The ledger is written *beside* the syscall by the same function, so on
        // its own it certifies itself (`PR5-CONF-012`): with `sync_all` replaced
        // by `Ok(())`, every assertion below still passed. `barriers_performed`
        // counts entries into `util::fsync_file`/`fsync_dir`, so the ledger's
        // claim can be checked against something that is not the ledger.
        //
        // The two axes are the *record* and the *call*. Every assertion below
        // holds the call constant — it is assumed to have happened — and reads
        // the record; this reads the call and holds the record constant. The
        // counter is process-wide and the suite is threaded, so the assertion is
        // a **lower bound on the delta**, which is the strongest thing a shared
        // counter can support and is still zero if the barrier is never entered.
        let barriers_before = util::barriers_performed();
        let publications: Vec<(&str, PathBuf, &str, &str)> = vec![
            ("marker", public.clone(), MARKER_STAGED, MARKER),
            (
                "owner record",
                private.clone(),
                OWNER_RECORD_STAGED,
                OWNER_RECORD,
            ),
            (
                "commit record",
                private.clone(),
                COMMIT_RECORD_STAGED,
                COMMIT_RECORD,
            ),
        ];
        for (which, dir, staged_name, published_name) in publications {
            ledger.clear();
            match which {
                "marker" => {
                    stage_marker(&public, &marker, &mut hooks).expect("P1a");
                    publish_marker(&public, &mut hooks).expect("P1b");
                }
                "owner record" => {
                    stage_owner_record(&private, &owner, &mut hooks).expect("P3a");
                    publish_owner_record(&private, &mut hooks).expect("P3b");
                }
                _ => {
                    stage_commit_record(&private, &commit, &mut hooks).expect("P5a");
                    publish_commit_record(&private, &mut hooks).expect("P5b");
                }
            }

            let records = ledger.records();
            // One expectation for every platform (`PR5-CONF-013`). This used to
            // fork on `cfg!(unix)` because `sync_dir` was a documented no-op on
            // Windows; `run_creation`'s "fsync the directory" carries no
            // platform exception, and now neither does this.
            let expected: Vec<DurableStep> = vec![
                DurableStep::SyncedFile,
                DurableStep::Renamed,
                DurableStep::SyncedDirectory,
            ];
            assert_eq!(
                ledger.steps(),
                expected,
                "{which}: the durability sequence run_creation names, in order"
            );
            assert_eq!(
                records[0].path,
                dir.join(staged_name),
                "{which}: the sync is of the STAGED file, before it has its published name"
            );
            let published_len = fs::metadata(dir.join(published_name))
                .expect("the published record")
                .len();
            assert!(published_len > 0, "{which}: the record has bytes at all");
            assert_eq!(
                records[0].len, published_len,
                "{which}: the whole staged file was synced, not a prefix of it"
            );
            assert_eq!(
                records[1].path,
                dir.join(published_name),
                "{which}: the rename lands on the published name"
            );
            assert_eq!(
                records[2].path, dir,
                "{which}: the directory sync is of the directory the rename changed"
            );
        }

        // Three publications, each recording one file sync and one directory
        // sync: six ledger entries that each claim a barrier was performed.
        let claimed = 6;
        let performed = util::barriers_performed().saturating_sub(barriers_before);
        assert!(
            performed >= claimed,
            "the ledger recorded {claimed} durability barriers and only {performed} \
             were entered; a ledger that certifies the function it is written by \
             cannot tell the two apart (PR5-CONF-012)"
        );
    }

    #[test]
    fn every_site_this_module_owns_is_reached_through_a_funnel_in_both_phases() {
        // Enumerated from `RunDirSite::ALL`, `AnswerSite::ALL` and
        // `LockSite::ALL` rather than from a list of what this file happens to
        // call, so a site the frozen inventory declares and no funnel names
        // fails here rather than being quietly absent from `effect_sites.json`.
        let husk = BoundHusk::new("sitecoverage");
        let mut hooks = Observer::default();
        let public = husk.public();

        create_public_dir(&public, &mut hooks).expect("P0");
        stage_marker(&public, &husk.marker, &mut hooks).expect("P1a");
        publish_marker(&public, &mut hooks).expect("P1b");
        create_private_dir(&husk.private, &mut hooks).expect("P3");
        stage_owner_record(&husk.private, &husk.owner, &mut hooks).expect("P3a");
        publish_owner_record(&husk.private, &mut hooks).expect("P3b");
        write_plan(&public, b"{\"tasks\":[]}", &mut hooks).expect("P5");
        write_report(
            &public,
            &serde_json::json!({"outcome": "parked"}),
            &mut hooks,
        )
        .expect("report");
        let questions = public.join("questions");
        fs::create_dir_all(&questions).expect("questions");
        write_question_payload(&questions, "q-1", &serde_json::json!({}), &mut hooks)
            .expect("question payload");
        let answers = public.join("answers");
        fs::create_dir_all(&answers).expect("answers");
        stage_answer(&answers, "q-1", &serde_json::json!({}), &mut hooks).expect("stage answer");
        publish_answer(&answers, "q-1", &mut hooks).expect("publish answer");
        ingest_answer(&answers, "q-1", &mut hooks).expect("ingest answer");

        // The commit record goes to a private half of its own, so publishing
        // it does not make the husk below unprovable.
        let committed_half = husk
            .root
            .join("private")
            .join("runs")
            .join("01COMMITTEDHALF");
        create_private_dir(&committed_half, &mut hooks).expect("second private half");
        stage_commit_record(&committed_half, &commit_record_of(&husk), &mut hooks).expect("P5a");
        publish_commit_record(&committed_half, &mut hooks).expect("P5b");

        let git_dir = husk.root.join("git-dir");
        fs::create_dir_all(&git_dir).expect("git dir");
        let lease = WorktreeLock::acquire_in_hooked(&husk.repo, &git_dir, &mut hooks)
            .expect("the worktree lease");
        let run_lock = RunLock::acquire_hooked(&public, &mut hooks).expect("the run lock");
        run_lock.release(&mut hooks);
        drop(lease);

        remove_marker(&public, &mut hooks).expect("P7");
        // The marker is gone, so re-publish it for the proof, then spend the
        // token on the half it names.
        stage_marker(&public, &husk.marker, &mut hooks).expect("re-stage");
        publish_marker(&public, &mut hooks).expect("re-publish");
        let PrivateHalfOwnership::Proven(token) = husk.prove() else {
            panic!("the bound husk proves");
        };
        remove_private_husk(token, &mut hooks).expect("private half");
        remove_public_husk(&public, &mut hooks).expect("public half");

        assert_eq!(
            hooks.sites(),
            sites_this_module_owns(),
            "every declared site, and no site this module does not own"
        );
        for name in sites_this_module_owns() {
            let site: EffectSiteId = name.clone().try_into().expect("a declared site");
            assert_eq!(
                hooks.phases_of(site).first(),
                Some(&HookPhase::Before),
                "`{name}` must hook Before its primitive"
            );
            assert!(
                hooks.phases_of(site).contains(&HookPhase::After),
                "`{name}` must hook After it"
            );
        }
    }

    #[test]
    fn the_post_error_stat_helper_stats_rather_than_reading_the_error() {
        // The two cases `run_creation` separates — "a P5b error after which
        // the record is absent" and "a P5b error after which the record is
        // present" — return the *same* error value, because the error-return
        // mode returns `Err` after performing the primitive. A helper that
        // inferred absence from an error would delete a private half that had
        // already crossed the deletion boundary.
        let husk = BoundHusk::new("posterror");
        husk.publish();
        let record = commit_record_of(&husk);
        let site = EffectSiteId::RunDir(RunDirSite::PublishCommitRecord);

        // (1) the rename happened, then the funnel returned Err.
        stage_commit_record(&husk.private, &record, &mut NoHooks).expect("stage");
        let mut after = Observer::default();
        after.arm(site, HookPhase::After, Injection::Error);
        let error = publish_commit_record(&husk.private, &mut after).expect_err("injected");
        assert!(
            error.to_string().contains("RunDir.PublishCommitRecord"),
            "the error names the point reached: {error}"
        );
        assert!(
            husk.private.join(COMMIT_RECORD).is_file(),
            "the record is there"
        );
        assert_eq!(
            commit_record_after_error(&husk.private),
            CommitRecordPresence::Present
        );
        assert!(
            !commit_record_after_error(&husk.private).permits_deletion(),
            "from the moment committed.json exists the creator deletes nothing"
        );
        // And the census agrees with the creator about the same bytes.
        assert!(matches!(
            husk.prove(),
            PrivateHalfOwnership::Retained(RetainReason::PossiblyCommitted)
        ));

        // (2) the same error, returned before the rename.
        fs::remove_file(husk.private.join(COMMIT_RECORD)).expect("reset");
        stage_commit_record(&husk.private, &record, &mut NoHooks).expect("stage again");
        let mut before = Observer::default();
        before.arm(site, HookPhase::Before, Injection::Error);
        publish_commit_record(&husk.private, &mut before).expect_err("injected");
        assert_eq!(
            commit_record_after_error(&husk.private),
            CommitRecordPresence::Absent
        );
        assert!(
            commit_record_after_error(&husk.private).permits_deletion(),
            "the creator knows the run never committed and may remove both halves"
        );
        assert!(
            husk.private.join(COMMIT_RECORD_STAGED).is_file(),
            "committed.json.tmp leaves with the private half"
        );
        assert!(
            matches!(husk.prove(), PrivateHalfOwnership::Proven(_)),
            "a staged-only commit record is not a commit record"
        );

        // (3) an unreadable answer is not "absent".
        assert!(!CommitRecordPresence::Unknown("io".to_owned()).permits_deletion());
    }

    /// The child of [`a_kill_between_stage_and_rename_leaves_only_the_tmp`]:
    /// stages one record and dies at the publication site's `Before` phase.
    #[test]
    #[ignore = "spawned as a subprocess by a_kill_between_stage_and_rename_leaves_only_the_tmp"]
    fn publication_kill_child() {
        let dir = PathBuf::from(std::env::var("TACTUS_TEST_KILL_DIR").expect("dir"));
        let which = std::env::var("TACTUS_TEST_KILL_SITE").expect("site");
        fs::create_dir_all(&dir).expect("dir");
        let policy = crate::runner::policy::host_policy();
        let mut hooks = Observer::default();
        let (site, publish): (RunDirSite, fn(&Path, &mut dyn RunDirHooks) -> _) =
            match which.as_str() {
                "marker" => {
                    let marker = CreatingMarker {
                        run_id: "01KILL".to_owned(),
                        repo_key: "0123456789abcdef".to_owned(),
                        private_dir: dir.to_string_lossy().into_owned(),
                        incarnation: "01INC".to_owned(),
                        pid: std::process::id(),
                        runner_policy_sha256: runner_policy_sha256(&policy),
                    };
                    stage_marker(&dir, &marker, &mut hooks).expect("stage marker");
                    (RunDirSite::PublishMarker, publish_marker)
                }
                "owner" => {
                    let owner = OwnerRecord {
                        run_id: "01KILL".to_owned(),
                        repo_key: "0123456789abcdef".to_owned(),
                        public_dir: dir.to_string_lossy().into_owned(),
                        incarnation: "01INC".to_owned(),
                        runner: policy,
                    };
                    stage_owner_record(&dir, &owner, &mut hooks).expect("stage owner");
                    (RunDirSite::PublishOwnerRecord, publish_owner_record)
                }
                "commit" => {
                    let record = CommitRecord {
                        run_id: "01KILL".to_owned(),
                        repo_key: "0123456789abcdef".to_owned(),
                        public_dir: dir.to_string_lossy().into_owned(),
                        incarnation: "01INC".to_owned(),
                        run_started_sha256: "sha256:00".to_owned(),
                    };
                    stage_commit_record(&dir, &record, &mut hooks).expect("stage commit");
                    (RunDirSite::StageCommitRecord, publish_commit_record)
                }
                other => panic!("unknown site `{other}`"),
            };
        let site = match which.as_str() {
            "commit" => RunDirSite::PublishCommitRecord,
            _ => site,
        };
        hooks.arm(
            EffectSiteId::RunDir(site),
            HookPhase::Before,
            Injection::Kill,
        );
        let _ = publish(&dir, &mut hooks);
        unreachable!("the kill must have taken this process");
    }

    #[test]
    fn a_kill_between_stage_and_rename_leaves_only_the_tmp() {
        // A real process death, not an early return: the claim is what a
        // coordinator that runs *no* cleanup leaves on disk, and the funnel's
        // kill aborts rather than unwinding for exactly that reason.
        let root = scratch("killpublish");
        for (which, staged, published) in [
            ("marker", MARKER_STAGED, MARKER),
            ("owner", OWNER_RECORD_STAGED, OWNER_RECORD),
            ("commit", COMMIT_RECORD_STAGED, COMMIT_RECORD),
        ] {
            let dir = root.join(which);
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "rundir::tests::publication_kill_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TACTUS_TEST_KILL_DIR", &dir)
                .env("TACTUS_TEST_KILL_SITE", which)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("spawn the publishing child");
            assert!(!status.success(), "`{which}`: the child must have died");
            assert!(
                dir.join(staged).is_file(),
                "`{which}`: the staged file survives the kill"
            );
            assert!(
                !dir.join(published).exists(),
                "`{which}`: nothing was published"
            );
        }
    }

    /// Publication re-points the *name*; it never writes through it.
    ///
    /// The kill test above cannot see this. It kills at `Before`, where neither
    /// a rename nor a copy has done anything yet, so it stays green against a
    /// `publish` rewritten as copy-then-delete — measured, and the reason this
    /// test exists. Copy-then-delete is not atomic: it truncates the
    /// destination and then fills it, so a death inside it leaves a *partial*
    /// published record where `T-RUNSTART` requires either the old one or the
    /// new one. `RunDirSite::sub_effects()` is empty for every site in the
    /// frozen inventory, so there is no coordinate to place a fault at inside
    /// the primitive, and the discriminator has to be an observable the two
    /// implementations differ on *after* a successful publication.
    ///
    /// A hard link is that observable, on both platforms. Point a second name
    /// at the destination before publishing: `fs::rename` replaces the
    /// directory entry and leaves the linked file's bytes alone, while
    /// `fs::copy` opens that same file through the link and overwrites it. So
    /// the sentinel's bytes answer "rename or copy?" directly, with no reliance
    /// on `st_ino` — which Windows does not expose on stable Rust
    /// (`MetadataExt::file_index` is behind `windows_by_handle`).
    #[test]
    fn publication_replaces_the_name_rather_than_writing_through_it() {
        let root = scratch("publishrename");
        for (which, staged_name, published_name) in [
            ("marker", MARKER_STAGED, MARKER),
            ("owner", OWNER_RECORD_STAGED, OWNER_RECORD),
            ("commit", COMMIT_RECORD_STAGED, COMMIT_RECORD),
        ] {
            let dir = root.join(which);
            fs::create_dir_all(&dir).expect("dir");

            // The bytes that must survive: an unrelated file that happens to
            // share an inode with the publication's destination.
            let sentinel = dir.join("sentinel");
            let sentinel_bytes = b"the linked file is not the publication's business";
            fs::write(&sentinel, sentinel_bytes).expect("sentinel");
            fs::hard_link(&sentinel, dir.join(published_name)).expect("hard link");

            let staged_bytes = b"{\"published\":true}";
            fs::write(dir.join(staged_name), staged_bytes).expect("staged");
            publish(
                &dir.join(staged_name),
                &dir.join(published_name),
                &DurabilityLedger::off(),
            )
            .expect("publish");

            assert_eq!(
                fs::read(dir.join(published_name)).expect("published"),
                staged_bytes,
                "`{which}`: the published name carries the staged bytes"
            );
            assert!(
                !dir.join(staged_name).exists(),
                "`{which}`: the staged name is gone"
            );
            assert_eq!(
                fs::read(&sentinel).expect("sentinel after"),
                sentinel_bytes,
                "`{which}`: publication wrote *through* the destination name \
                 instead of replacing it, so it is a copy rather than a rename \
                 and a death inside it can leave a partial record"
            );
        }
    }

    // =======================================================================
    // R28: a surviving reaper's shared cleanup hold
    // =======================================================================

    /// A reaper that outlives its coordinator: takes the shared cleanup hold
    /// and keeps it until it is killed.
    #[cfg(unix)]
    #[test]
    #[ignore = "spawned as a subprocess by a_surviving_reaper_hold_refuses_the_next_coordinator_until_released"]
    fn cleanup_hold_child() {
        use std::os::fd::AsRawFd as _;
        let public = PathBuf::from(std::env::var("TACTUS_TEST_CLEANUP_DIR").expect("run dir"));
        let path = cleanup_lock_file(&public);
        let file = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .expect("open the cleanup lock");
        // SHARED, which is what R28 is: "a surviving Unix cleanup reaper's
        // **shared** cleanup.lock hold (one per reaper)".
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
            0,
            "the reaper takes its shared hold"
        );
        println!("held");
        std::io::Write::flush(&mut std::io::stdout()).expect("flush");
        std::thread::sleep(Duration::from_secs(30));
    }

    #[cfg(unix)]
    #[test]
    fn a_surviving_reaper_hold_refuses_the_next_coordinator_until_released() {
        // `PR4-R28-NEXT-COORDINATOR-UNWITNESSED`: two withheld mutations
        // survived the whole suite because no test started a coordinator while
        // a surviving reaper actually held R28. `PR4-WIN-073` turns the
        // would-block branch into continuation; `PR4-WIN-074` replaces the
        // immediate refusal with a loop that waits for the hold and then
        // continues. Both are killed here, and by different assertions.
        //
        // The run is a **husk** on purpose. The run whose reaper is still
        // settling groups is the one that died before its log committed, and
        // `list_runs` no longer returns it — so a lease that scanned the
        // readers' view would leave exactly this hold unobserved.
        let root = scratch("r28witness");
        let repo = root.join("repo");
        let git_dir = root.join("git-dir");
        fs::create_dir_all(&git_dir).expect("git dir");
        let husk_id = "01REAPERHUSK00000000000000";
        let husk = public_dir(&repo, husk_id);
        fs::create_dir_all(&husk).expect("husk");
        assert_eq!(classify_run_dir(&husk), RunDirClass::Husk);
        assert!(
            list_runs(&repo).is_empty(),
            "the reader does not return it, which is the point"
        );

        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "rundir::tests::cleanup_hold_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TACTUS_TEST_CLEANUP_DIR", &husk)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the surviving reaper");
        let mut out = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            line.clear();
            let read = std::io::BufRead::read_line(&mut out, &mut line).expect("read");
            assert!(read > 0, "the reaper ended before taking its hold");
            if line.trim() == "held" {
                break;
            }
            assert!(Instant::now() < deadline, "the reaper never took its hold");
        }

        assert!(
            observe_cleanup_hold(&husk, &mut NoHooks),
            "R28 is held by a live reaper"
        );

        let started = Instant::now();
        let error = WorktreeLock::acquire_in(&repo, &git_dir)
            .expect_err("a coordinator must not overlap a live reaper");
        let waited = started.elapsed();
        assert!(
            error.to_string().contains("still cleaning agent processes"),
            "{error}"
        );
        assert!(
            error.to_string().contains(husk_id),
            "names the run: {error}"
        );
        // Kills the polling-loop mutation: a lease that waited for the hold
        // to release would only have returned after it was gone.
        assert!(
            observe_cleanup_hold(&husk, &mut NoHooks),
            "the refusal returned while the hold was still held"
        );
        assert!(
            waited < Duration::from_secs(5),
            "refused at once rather than waiting the reaper out: {waited:?}"
        );

        // The other observation point: the exclusive probe at run-lock
        // acquisition, which `resource_accounting` names beside the first.
        let error = RunLock::acquire(&husk).expect_err("the exclusive side is refused");
        assert!(error.to_string().contains("already driving run"), "{error}");

        let _ = child.kill();
        let _ = child.wait();

        // Released with the reaper, by the OS, without anybody resetting it.
        assert!(
            !observe_cleanup_hold(&husk, &mut NoHooks),
            "the hold is gone"
        );
        let lease = WorktreeLock::acquire_in(&repo, &git_dir).expect("and now the lease is free");
        drop(lease);
        let run = RunLock::acquire(&husk).expect("and so is the run lock");
        drop(run);
    }

    // =======================================================================
    // The refusal that is a build failure
    // =======================================================================

    /// The fixture that must compile, so a refusal below is a refusal rather
    /// than a broken rustc invocation.
    const CONTROL: &str = r#"
        extern crate tactus;
        use std::path::Path;
        pub fn control(public: &Path, hooks: &mut tactus::rundir::NoHooks) {
            let _ = tactus::rundir::classify_run_dir(public);
            let _ = tactus::rundir::remove_public_husk(public, hooks);
        }
"#;

    struct BuildRefusal {
        name: &'static str,
        source: &'static str,
        /// rustc's own error code. A fixture that only asserted "this does not
        /// compile" is green when it fails for a typo.
        codes: &'static [&'static str],
        names: &'static str,
    }

    fn build_refusals() -> Vec<BuildRefusal> {
        vec![
            BuildRefusal {
                name: "no-proof",
                source: r#"
        extern crate tactus;
        pub fn delete(hooks: &mut tactus::rundir::NoHooks) {
            let _ = tactus::rundir::remove_private_husk(hooks);
        }
"#,
                codes: &["E0061"],
                names: "remove_private_husk",
            },
            BuildRefusal {
                name: "wrong-token",
                source: r#"
        extern crate tactus;
        use std::path::PathBuf;
        pub fn delete(hooks: &mut tactus::rundir::NoHooks) {
            let _ = tactus::rundir::remove_private_husk(PathBuf::from("/tmp/x"), hooks);
        }
"#,
                codes: &["E0308"],
                names: "PrivateHalfProof",
            },
            BuildRefusal {
                name: "forged-token",
                source: r#"
        extern crate tactus;
        use std::path::PathBuf;
        pub fn forge() -> tactus::rundir::PrivateHalfProof {
            tactus::rundir::PrivateHalfProof {
                target: PathBuf::new(),
                public: PathBuf::new(),
                run_id: String::new(),
            }
        }
"#,
                codes: &["E0451", "E0603", "E0063"],
                names: "PrivateHalfProof",
            },
            BuildRefusal {
                name: "cloned-token",
                source: r#"
        extern crate tactus;
        pub fn twice(proof: tactus::rundir::PrivateHalfProof) -> tactus::rundir::PrivateHalfProof {
            let copy = proof.clone();
            copy
        }
"#,
                codes: &["E0599"],
                names: "PrivateHalfProof",
            },
            BuildRefusal {
                name: "defaulted-token",
                source: r#"
        extern crate tactus;
        pub fn out_of_nothing() -> tactus::rundir::PrivateHalfProof {
            tactus::rundir::PrivateHalfProof::default()
        }
"#,
                codes: &["E0599"],
                names: "PrivateHalfProof",
            },
            BuildRefusal {
                name: "spent-token",
                source: r#"
        extern crate tactus;
        pub fn twice(proof: tactus::rundir::PrivateHalfProof, hooks: &mut tactus::rundir::NoHooks) {
            let _ = tactus::rundir::remove_private_husk(proof, hooks);
            let _ = tactus::rundir::remove_private_husk(proof, hooks);
        }
"#,
                codes: &["E0382"],
                names: "proof",
            },
        ]
    }

    /// This crate's rlib, beside the test binary that is running.
    fn this_crates_rlib(deps: &Path) -> PathBuf {
        let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
        for entry in fs::read_dir(deps).expect("the deps directory").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("libtactus-") || !name.ends_with(".rlib") {
                continue;
            }
            let when = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .expect("mtime");
            if best.as_ref().is_none_or(|(seen, _)| when > *seen) {
                best = Some((when, entry.path()));
            }
        }
        best.expect("this crate's rlib is beside its test binary").1
    }

    fn compile_against_this_crate(tag: &str, source: &str) -> (bool, Vec<String>, String) {
        let dir = scratch(&format!("compile-{tag}"));
        let file = dir.join("fixture.rs");
        fs::write(&file, source).expect("fixture source");
        let deps = std::env::current_exe()
            .expect("test binary")
            .parent()
            .expect("deps directory")
            .to_path_buf();
        let rlib = this_crates_rlib(&deps);
        let out = std::process::Command::new("rustc")
            .args([
                "--edition",
                "2024",
                "--crate-type",
                "lib",
                "--emit",
                "metadata",
            ])
            .arg("--extern")
            .arg(format!("tactus={}", rlib.display()))
            .arg("-L")
            .arg(format!("dependency={}", deps.display()))
            .args(["--error-format", "json"])
            .arg("--out-dir")
            .arg(&dir)
            .arg(&file)
            .output()
            .expect("rustc runs; a missing rustc is a failure of this test, never a skip");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let mut codes = Vec::new();
        for line in stderr.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if value["level"] != "error" {
                continue;
            }
            if let Some(code) = value["code"]["code"].as_str() {
                codes.push(code.to_owned());
            }
        }
        (out.status.success(), codes, stderr)
    }

    #[test]
    fn a_private_half_deletion_without_a_proof_does_not_compile_for_the_stated_reason() {
        // `resource_accounting.completeness_rule`: "a private-half deletion
        // outside the proof-token funnel fails to compile". A fixture that
        // only asserted the failure would be green for a typo, so every case
        // pins rustc's own error code and the identifier its message must
        // name — and the control proves the harness compiles anything at all.
        let (ok, codes, rendered) = compile_against_this_crate("control", CONTROL);
        assert!(
            ok && codes.is_empty(),
            "the control fixture must compile, or every refusal below is meaningless:\n{rendered}"
        );

        for case in build_refusals() {
            let (ok, codes, rendered) = compile_against_this_crate(case.name, case.source);
            assert!(!ok, "`{}` must not compile", case.name);
            assert!(
                codes.iter().any(|code| case.codes.contains(&code.as_str())),
                "`{}`: expected one of {:?}, got {codes:?}\n{rendered}",
                case.name,
                case.codes
            );
            assert!(
                rendered.contains(case.names),
                "`{}`: the message must name `{}`:\n{rendered}",
                case.name,
                case.names
            );
        }
    }

    // =======================================================================
    // The repository key
    // =======================================================================

    #[test]
    fn the_repo_key_is_the_construction_the_packet_states() {
        // `workspace_candidates.execution_root`: "repo_key v1 =
        // hex16(sha256('tactus-repo-key-v1' NUL canonical common git dir
        // bytes))". The expected value is computed from that sentence here,
        // and for a fixed path it is a literal computed outside this program
        // entirely — a function may not be its own oracle.
        let dir = scratch("repokey").join("git-dir");
        fs::create_dir_all(&dir).expect("git dir");
        let canonical = fs::canonicalize(&dir).expect("canonical");
        let mut bytes = b"tactus-repo-key-v1".to_vec();
        bytes.push(0);
        bytes.extend_from_slice(canonical.as_os_str().as_encoded_bytes());
        let expected: String = format!("{:x}", Sha256::digest(&bytes))
            .chars()
            .take(16)
            .collect();
        assert_eq!(RepoKey::v1(&canonical).as_str(), expected);
        assert_eq!(expected.len(), 16, "hex16 is sixteen hex characters");

        #[cfg(unix)]
        assert_eq!(
            RepoKey::v1(Path::new("/srv/repo/.git")).as_str(),
            "de053b372aab425c",
            "sha256(b'tactus-repo-key-v1\\x00/srv/repo/.git')[:16], computed elsewhere"
        );

        // Distinguishing, which is the whole job: two repositories, two keys.
        assert_ne!(
            RepoKey::v1(Path::new("/srv/a/.git")),
            RepoKey::v1(Path::new("/srv/b/.git"))
        );
    }

    fn git(cwd: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?} failed in {}", cwd.display());
    }

    #[test]
    fn every_worktree_of_one_repository_has_one_repo_key() {
        // A run created in the main checkout and a census run from a linked
        // worktree must not call each other foreign, so the key is taken over
        // the **common** git dir. A linked worktree's own git dir is
        // `<common>/worktrees/<name>`, and this proves the derivation against
        // a real one rather than against the rule that produced it.
        let root = scratch("worktreekey");
        let main = root.join("main");
        fs::create_dir_all(&main).expect("main");
        git(&main, &["init", "-q", "-b", "main"]);
        git(&main, &["config", "user.email", "t@example.invalid"]);
        git(&main, &["config", "user.name", "t"]);
        fs::write(main.join("f"), "x").expect("file");
        git(&main, &["add", "f"]);
        git(&main, &["commit", "-q", "-m", "one"]);
        let linked = root.join("linked");
        git(
            &main,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                linked.to_str().expect("utf-8"),
            ],
        );

        let main_git_dir = Workspace::open(&main)
            .expect("main workspace")
            .worktree_git_dir()
            .expect("main git dir");
        let linked_git_dir = Workspace::open(&linked)
            .expect("linked workspace")
            .worktree_git_dir()
            .expect("linked git dir");
        assert_ne!(
            main_git_dir, linked_git_dir,
            "the two worktrees really do have different git dirs, so the \
             common-dir derivation is doing work"
        );
        assert!(
            linked_git_dir.parent().and_then(Path::file_name)
                == Some(std::ffi::OsStr::new("worktrees")),
            "the layout this derivation reads: {}",
            linked_git_dir.display()
        );
        assert_eq!(
            RepoKey::for_repo(&main).expect("main key"),
            RepoKey::for_repo(&linked).expect("linked key"),
            "one repository, one key"
        );
    }

    // =======================================================================
    // The wire the marker and the records are read back off
    // =======================================================================

    /// Every field the packet names for each record, written by hand.
    fn marker_json() -> serde_json::Value {
        serde_json::json!({
            "run_id": "01RUN",
            "repo_key": "0123456789abcdef",
            "private_dir": "/private/runs/01RUN",
            "incarnation": "01INC",
            "pid": 4242,
            "runner_policy_sha256": "sha256:aa"
        })
    }

    fn owner_json() -> serde_json::Value {
        serde_json::json!({
            "run_id": "01RUN",
            "repo_key": "0123456789abcdef",
            "public_dir": "/repo/.tactus/runs/01RUN",
            "incarnation": "01INC",
            "runner": {
                "kind": "host",
                "policy": "host-v1",
                "image": null,
                "credential_volumes": null
            }
        })
    }

    fn commit_json() -> serde_json::Value {
        serde_json::json!({
            "run_id": "01RUN",
            "repo_key": "0123456789abcdef",
            "public_dir": "/repo/.tactus/runs/01RUN",
            "incarnation": "01INC",
            "run_started_sha256": "sha256:bb"
        })
    }

    #[test]
    fn each_record_carries_exactly_the_fields_the_packet_names() {
        // Mutation witnessing cannot detect a field that was never written, so
        // this is a transcription check rather than a round trip: the payloads
        // are written out of `run_creation` and `resource_accounting` by hand,
        // every named field is asserted required, and an unknown one is
        // refused because a marker is what a census decides a deletion from.
        for (what, payload, fields) in [
            (
                "marker",
                marker_json(),
                vec![
                    "run_id",
                    "repo_key",
                    "private_dir",
                    "incarnation",
                    "pid",
                    "runner_policy_sha256",
                ],
            ),
            (
                "owner record",
                owner_json(),
                vec!["run_id", "repo_key", "public_dir", "incarnation", "runner"],
            ),
            (
                "commit record",
                commit_json(),
                vec![
                    "run_id",
                    "repo_key",
                    "public_dir",
                    "incarnation",
                    "run_started_sha256",
                ],
            ),
        ] {
            let parses = match what {
                "marker" => serde_json::from_value::<CreatingMarker>(payload.clone()).is_ok(),
                "owner record" => serde_json::from_value::<OwnerRecord>(payload.clone()).is_ok(),
                _ => serde_json::from_value::<CommitRecord>(payload.clone()).is_ok(),
            };
            assert!(parses, "{what}: the packet's own payload must parse");

            assert_eq!(
                payload.as_object().expect("object").len(),
                fields.len(),
                "{what}: the packet names {} fields",
                fields.len()
            );

            for missing in &fields {
                let mut short = payload.clone();
                short.as_object_mut().expect("object").remove(*missing);
                let refused = match what {
                    "marker" => serde_json::from_value::<CreatingMarker>(short).is_err(),
                    "owner record" => serde_json::from_value::<OwnerRecord>(short).is_err(),
                    _ => serde_json::from_value::<CommitRecord>(short).is_err(),
                };
                assert!(refused, "{what}: `{missing}` must be required");
            }

            let mut extra = payload.clone();
            extra
                .as_object_mut()
                .expect("object")
                .insert("unknown".to_owned(), serde_json::json!(1));
            let refused = match what {
                "marker" => serde_json::from_value::<CreatingMarker>(extra).is_err(),
                "owner record" => serde_json::from_value::<OwnerRecord>(extra).is_err(),
                _ => serde_json::from_value::<CommitRecord>(extra).is_err(),
            };
            assert!(refused, "{what}: an unknown field is refused");
        }
    }

    #[test]
    fn what_the_funnels_write_is_what_the_packet_says_they_write() {
        // The other direction: the bytes on disk, compared against the
        // independently written payloads above rather than against whatever
        // this build happens to serialize.
        let root = scratch("wire");
        let dir = root.join("half");
        fs::create_dir_all(&dir).expect("dir");
        let marker: CreatingMarker =
            serde_json::from_value(marker_json()).expect("the packet's marker");
        stage_marker(&dir, &marker, &mut NoHooks).expect("stage");
        publish_marker(&dir, &mut NoHooks).expect("publish");
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(MARKER)).expect("read")).expect("json");
        assert_eq!(written, marker_json());

        let owner: OwnerRecord = serde_json::from_value(owner_json()).expect("the packet's owner");
        stage_owner_record(&dir, &owner, &mut NoHooks).expect("stage");
        publish_owner_record(&dir, &mut NoHooks).expect("publish");
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(OWNER_RECORD)).expect("read")).expect("json");
        assert_eq!(written, owner_json());

        let record: CommitRecord =
            serde_json::from_value(commit_json()).expect("the packet's commit record");
        stage_commit_record(&dir, &record, &mut NoHooks).expect("stage");
        publish_commit_record(&dir, &mut NoHooks).expect("publish");
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(COMMIT_RECORD)).expect("read"))
                .expect("json");
        assert_eq!(written, commit_json());
    }

    #[test]
    fn the_commit_records_digest_is_over_the_exact_line_bytes() {
        // `run_creation`: "run_started_sha256 = the digest of the exact
        // run_started line bytes about to be appended". Pinned against a
        // digest computed outside this program.
        assert_eq!(
            run_started_sha256(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "the FIPS-180-2 example digest of `abc`"
        );
        // The newline is part of the line and therefore part of the digest.
        assert_ne!(run_started_sha256(b"abc"), run_started_sha256(b"abc\n"));

        // **A real `run_started` line, spelled noncanonically**
        // (`PR5-RUNDIR-053`). Neither input above is JSON at all, so a digest
        // computed over a *reserialized* event value falls straight back to the
        // exact bytes for both and every assertion above still holds. The only
        // input that separates the two rules is a valid line whose whitespace
        // and key order are not what a serializer would emit, and the digest it
        // must have is computed outside this program:
        //
        //   python3 -c "import hashlib,sys;
        //     print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())"
        // Built by concatenation rather than as one wrapped literal: a `\` line
        // continuation eats the indentation that follows it and rustfmt then joins
        // the line, so the bytes such a literal produces are not the bytes it looks
        // like — and which exact bytes are digested is the whole of this fixture.
        let mut noncanonical: Vec<u8> = Vec::new();
        noncanonical
            .extend_from_slice(b"{\"ts\":\"2026-08-20T00:00:00Z\" ,  \"event\":\"run_started\",");
        noncanonical.extend_from_slice(b" \"data\" : {\"run_id\":\"01NONCANON\", \"schema\":3}}\n");
        let noncanonical: &[u8] = &noncanonical;
        assert_eq!(
            serde_json::from_slice::<RunStartedHeader>(&noncanonical[..noncanonical.len() - 1])
                .expect("the fixture really is a parseable run_started")
                .event,
            "run_started",
            "a fixture a reserializing digest could not be applied to would prove nothing"
        );
        assert_eq!(
            run_started_sha256(noncanonical),
            "sha256:e0d7e8c55c48fb6c62fd452e4fa95b0a2ceebd60d0375120d35dde1fcd1fb8d9",
            "the digest of these exact bytes, including the terminating newline"
        );
        // And the two rules really do differ here, so the assertion above is
        // not passing for want of a distinction: the canonical reserialization
        // of the same value has a different digest.
        let canonical = serde_json::to_vec(
            &serde_json::from_slice::<serde_json::Value>(&noncanonical[..noncanonical.len() - 1])
                .expect("valid json"),
        )
        .expect("reserialize");
        assert_ne!(
            run_started_sha256(&canonical),
            run_started_sha256(noncanonical),
            "the fixture does not separate exact-bytes from reserialized"
        );
    }

    /// A `.partial` is writer-owned staging residue that **no reader ingests**
    /// and no ingestion consumes (`PR5-RUNDIR-060`, `PR5-RUNDIR-061`).
    ///
    /// `transaction_fault_matrix[17].resume_action` says both halves: "a
    /// `.partial` file is writer-owned staging residue: **ignored by every
    /// reader** and never pruned by the coordinator", and "the file itself is
    /// **persistent run-directory content (R21) in every case**". Neither had a
    /// fixture. The only driver of `ingest_answer` staged, published and
    /// ingested back to back, so the shape this test builds — a valid partial
    /// and *no* published answer — never existed, and nothing ever read a
    /// published answer twice or looked for it afterwards. A reader that fell
    /// back to the partial, and a reader that consumed its input, both looked
    /// exactly like a correct one.
    #[test]
    fn a_staged_partial_is_never_ingested_and_a_published_answer_survives_ingestion() {
        let root = scratch("answer-residue");
        let answers = root.join("answers");
        create_dir(&answers).expect("answers");

        // (a) A valid partial, and nothing published.
        stage_answer(
            &answers,
            "q-1",
            &serde_json::json!({"text": "staged"}),
            &mut NoHooks,
        )
        .expect("stage");
        let partial = answers.join("q-1.json.partial");
        let staged_bytes = fs::read(&partial).expect("the partial exists");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&staged_bytes).is_ok(),
            "the partial is valid JSON, so a fallback reader would happily return it"
        );
        assert!(
            !answers.join("q-1.json").exists(),
            "and nothing is published, which is the state the entry is about"
        );

        assert_eq!(
            ingest_answer(&answers, "q-1", &mut NoHooks).expect("ingest"),
            None,
            "a reader that fell back to the partial would answer with staging residue"
        );
        assert_eq!(
            fs::read(&partial).expect("the partial"),
            staged_bytes,
            "and the read-only ingestion left the partial byte-identical"
        );

        // (b) Published, ingested — and still there afterwards.
        publish_answer(&answers, "q-1", &mut NoHooks).expect("publish");
        let published = answers.join("q-1.json");
        let published_bytes = fs::read(&published).expect("the published answer");
        let first = ingest_answer(&answers, "q-1", &mut NoHooks).expect("ingest");
        assert!(
            first.is_some(),
            "the published answer is what a reader gets"
        );
        assert!(
            published.is_file(),
            "R21 is persistent run-directory content: ingestion is a read, not a take"
        );
        assert_eq!(
            fs::read(&published).expect("the published answer"),
            published_bytes,
            "with its original bytes"
        );
        assert_eq!(
            ingest_answer(&answers, "q-1", &mut NoHooks).expect("ingest again"),
            first,
            "so a second reader gets the same answer as the first"
        );
    }

    /// The moved payload writers keep the **legacy byte shape**
    /// (`PR5-RUNDIR-058`).
    ///
    /// `production_effect`: "shared primitives move behind funnels
    /// behavior-neutrally". Every consumer of these three parses the JSON back,
    /// so indentation and the final newline were unobserved and switching
    /// `report.json` and a question payload from the moved pretty writer to a
    /// compact `serde_json::to_vec` changed nothing any test could see. The
    /// expected bytes are written out here rather than produced by calling the
    /// writer, so this is a golden file rather than a round trip — a round trip
    /// is satisfied by any serializer at all.
    #[test]
    fn the_payload_writers_keep_their_exact_legacy_bytes() {
        let root = scratch("golden-bytes");
        let public = root.join("public");
        let questions = public.join("questions");
        create_dir(&questions).expect("questions");
        let payload = serde_json::json!({"kind": "choice", "options": ["a", "b"]});
        let expected =
            "{\n  \"kind\": \"choice\",\n  \"options\": [\n    \"a\",\n    \"b\"\n  ]\n}\n";

        write_report(&public, &payload, &mut NoHooks).expect("report");
        assert_eq!(
            fs::read_to_string(public.join("report.json")).expect("report.json"),
            expected,
            "report.json is pretty-printed with two-space indentation and ends in a newline"
        );

        write_question_payload(&questions, "q-1", &payload, &mut NoHooks).expect("question");
        assert_eq!(
            fs::read_to_string(questions.join("q-1.json")).expect("q-1.json"),
            expected,
            "and a question payload is written the same way"
        );

        // The plan is a byte pass-through — it is handed bytes that are already
        // serialized and normalized — so its golden property is that nothing
        // touches them at all, trailing newline included.
        let normalized = b"{\"tasks\":[]}";
        write_plan(&public, normalized, &mut NoHooks).expect("plan");
        assert_eq!(
            fs::read(public.join(PLAN)).expect("plan.json"),
            normalized,
            "the plan's exact bytes reach disk unaltered"
        );
    }

    // =======================================================================
    // What `status` says about a husk id
    // =======================================================================

    #[test]
    fn a_husk_id_reports_as_one_of_the_three_things_it_can_be() {
        // `startup_census`: status "asked explicitly for a husk id, reports an
        // unstarted husk that the next write command reclaims, a retained husk
        // with its reason and locator, or a possibly committed run whose
        // public log has no valid committed first line".
        let unstarted = BoundHusk::new("statusunstarted");
        fs::create_dir_all(unstarted.public()).expect("public");
        let report = husk_report(
            &unstarted.repo,
            BOUND_RUN,
            &unstarted.repo_key,
            &unstarted.private_root,
        );
        assert!(
            matches!(report.disposition, HuskDisposition::Unstarted(_)),
            "{:?}",
            report.disposition
        );
        assert!(report.disposition.describe().contains("unstarted"));
        assert!(report.locator.is_none(), "a bare husk records no locator");

        let retained = BoundHusk::new("statusretained");
        retained.publish();
        write(&retained.private.join(OWNER_RECORD), b"{ not json");
        let report = husk_report(
            &retained.repo,
            BOUND_RUN,
            &retained.repo_key,
            &retained.private_root,
        );
        assert!(report.disposition.describe().starts_with("a retained husk"));
        assert_eq!(report.locator.as_deref(), Some(retained.private.as_path()));

        let committed = BoundHusk::new("statuspossibly");
        committed.publish();
        write(&committed.private.join(COMMIT_RECORD), b"{}");
        let report = husk_report(
            &committed.repo,
            BOUND_RUN,
            &committed.repo_key,
            &committed.private_root,
        );
        assert!(
            report.disposition.describe().contains("possibly committed"),
            "{}",
            report.disposition.describe()
        );
        assert!(
            report.disposition.describe().contains("nothing is deleted"),
            "and says so"
        );

        // The three sentences are three sentences.
        let mut said: Vec<String> = [&unstarted, &retained, &committed]
            .iter()
            .map(|husk| {
                husk_report(&husk.repo, BOUND_RUN, &husk.repo_key, &husk.private_root)
                    .disposition
                    .describe()
            })
            .collect();
        said.sort();
        said.dedup();
        assert_eq!(said.len(), 3, "each of the three reads differently");
    }

    #[test]
    fn an_ambiguous_husk_prefix_is_not_reported_as_one_husk() {
        let repo = scratch("ambiguoushusk").join("repo");
        for husk in ["01HUSKA", "01HUSKB"] {
            fs::create_dir_all(runs_root(&repo).join(husk)).expect("husk");
        }
        let error = resolve_run_id(&repo, "01HUSK").expect_err("no committed run");
        assert!(
            !error.to_string().contains("never recorded a committed"),
            "two husks match, so naming one of them would be a guess: {error}"
        );
    }
}
