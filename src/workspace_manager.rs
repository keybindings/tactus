//! `WorkspaceManager` — the typed funnels for the execution root, the detached
//! worktrees, the exact snapshots, the engine refs, and the Git-object creation
//! contexts.
//!
//! `decisions.workspace_candidates.manager`: "WorkspaceManager
//! (src/workspace_manager.rs) owns execution-root derivation and containment,
//! detached linked worktrees with durable synced intents (tasks/k<key>-g<gen>,
//! merge/s<seq>), exact snapshot worktrees with intents, engine refs, byte-safe
//! changed-path capture, worktree quiescence verification, object-residue
//! classification, and forced removal; the user's checkout is read only for
//! base capture; every worktree, snapshot, ref, pin, Git object, lock,
//! reservation, container start, event-log open or append, and run-directory
//! write goes through typed funnel APIs that take a typed site".
//!
//! # What a funnel is here
//!
//! `decisions.effect_site_inventory.identity`: "every effectful funnel API
//! takes its group's site by value, and the funnel itself calls
//! `hook(Before, site) -> primitive -> hook(After, site)`, so hooks exist for
//! every site by construction". [`funnel`] is that sentence, once, and every
//! primitive in this module goes through it. Production passes [`NoHooks`],
//! which answers [`Injection::Proceed`] and records nothing; the ST-07 subset
//! passes [`HarnessEffects`], which records into PR3's [`HookHarness`].
//!
//! The after hook is **not** called when the primitive returned `Err`. The
//! after phase's claim is `AfterEffect::Referenced` / `Unreferenced` /
//! `Released` — "the artifact is present and referenced by the row `row()`
//! names" — and a funnel that ran it after a failed primitive would record an
//! execution of a phase whose claim is false, which is the same false report
//! [`HookHarness`] exists to prevent.
//!
//! # Nothing here is a production caller
//!
//! `slice_contract.non_goals[0]` is "production topology callers", and
//! `production_effect` is "none in behavior". These primitives are reached by
//! the suite and by gate evidence; the schema-4 coordinator that will call them
//! arrives in PR7–PR10. That is why this module adds no call site to
//! `src/engine/**` and changes no existing behaviour.
//!
//! # The reading trap of the packet, applied once here
//!
//! Every sentence quoted in this module comes from `decisions.*`, `invariants`,
//! or `transaction_fault_matrix`. `*_verification_dispositions`,
//! `finding_dispositions[].rationale` and the `v4_`..`v15_` keys are the
//! packet's disposition history and are quoted nowhere.
//!
//! # Allowlist placement
//!
//! `decisions.effect_site_inventory.mechanism` names this file first in the
//! **funnel section** of `effects/allowlist.toml`: "funnel modules
//! (src/workspace_manager.rs, …) each reviewed to perform effects only inside
//! site-taking APIs and never to return writable handles". Both halves of that
//! review are structural here: every effect is issued inside a [`funnel`] call
//! that takes an [`EffectSiteId`] by value, and no public function returns a
//! `File`, an `OpenOptions`, or a `Command` — the only handles that leave this
//! module are paths, object ids, and values.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::error::TactusError;
use crate::topology::effects::{
    EffectSiteId, HookHarness, HookPhase, Injection, InjectionMode, ObjectResidue, ObjectSite,
    RefSite, ResidueElement, ResourceRow, SnapshotSite, SubEffectPoint, WorktreeSite,
};
use crate::topology::paths::{GitPath, PathSet};
use crate::util::{DurabilityLedger, DurableStep};

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/// What a funnel tells whoever is watching, at both hook phases and at the
/// parent-side sub-effect points.
///
/// The shape mirrors [`crate::agent::proc::SpawnHooks`], which PR4 wired onto
/// the same [`HookHarness`], except that these funnels serve many sites each,
/// so the site travels with the call.
pub trait EffectHooks {
    /// The funnel reached `phase` of `site`. The answer says what it must do.
    fn phase(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection;

    /// Where this observer wants the funnel's durability primitives recorded.
    ///
    /// A *handle*, taken before the funnel body runs, rather than a method the
    /// body calls back into: `funnel` already holds `&mut dyn EffectHooks` for
    /// the whole call, so a body that also needed the observer would be a
    /// second mutable borrow of it. The handle is cloneable and shares its log,
    /// so what the body records is what the caller reads.
    ///
    /// The default records nothing, which is what production passes and what
    /// every observer that does not care about durability inherits.
    fn durability_ledger(&self) -> DurabilityLedger {
        DurabilityLedger::off()
    }
}

/// What production passes: nothing is armed and nothing is recorded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl EffectHooks for NoHooks {
    fn phase(&mut self, _site: EffectSiteId, _phase: HookPhase) -> Injection {
        Injection::Proceed
    }
}

/// Wires these funnels onto PR3's [`HookHarness`], the way
/// [`crate::runner::HarnessHooks`] wires the process funnel onto it.
#[derive(Debug, Clone, Default)]
pub struct HarnessEffects {
    harness: Arc<Mutex<HookHarness>>,
    ledger: DurabilityLedger,
}

impl HarnessEffects {
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

impl EffectHooks for HarnessEffects {
    fn phase(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection {
        let mut harness = self
            .harness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        harness.hook(site, phase)
    }

    fn durability_ledger(&self) -> DurabilityLedger {
        self.ledger.clone()
    }
}

/// Do what a hook answered.
///
/// [`Injection::Kill`] aborts, for the reason
/// [`crate::agent::proc`] already gives: the claim under test is what a
/// coordinator that dies **without running any cleanup** leaves durable, and
/// both `panic!` and `std::process::exit` run destructors.
fn apply(injection: Injection, site: EffectSiteId, phase: HookPhase) -> Result<(), TactusError> {
    match injection {
        Injection::Proceed => Ok(()),
        Injection::Kill => std::process::abort(),
        Injection::Error => Err(TactusError::Refused {
            message: format!("the `{site}` funnel was made to fail at its `{phase}` phase"),
        }),
    }
}

/// `hook(Before, site) -> primitive -> hook(After, site)`, once.
fn funnel<T, F>(
    hooks: &mut dyn EffectHooks,
    site: EffectSiteId,
    primitive: F,
) -> Result<T, TactusError>
where
    F: FnOnce() -> Result<T, TactusError>,
{
    apply(
        hooks.phase(site, HookPhase::Before),
        site,
        HookPhase::Before,
    )?;
    let value = primitive()?;
    apply(hooks.phase(site, HookPhase::After), site, HookPhase::After)?;
    Ok(value)
}

/// Consult a parent-side sub-effect point, in every mode the point declares.
///
/// The harness is keyed by `(site, point, mode)` because "a mode is executed
/// when its fault fired", so one funnel position consults it once per declared
/// mode and the first non-`Proceed` answer wins. [`SubEffectPoint::IdUnread`]
/// declares `Kill` alone, so in practice this is one call — but the loop is
/// over [`SubEffectPoint::modes`] rather than over a literal, so a point that
/// gains a mode is consulted for it.
fn point(
    hooks: &mut dyn EffectHooks,
    site: EffectSiteId,
    at: SubEffectPoint,
) -> Result<(), TactusError> {
    let mut decision = Injection::Proceed;
    for mode in at.modes() {
        let answer = hooks.phase(
            site,
            HookPhase::Point {
                point: at,
                mode: *mode,
            },
        );
        if decision == Injection::Proceed {
            decision = answer;
        }
    }
    apply(
        decision,
        site,
        HookPhase::Point {
            point: at,
            mode: InjectionMode::Kill,
        },
    )
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// The runtime refusals this module owns, as values.
///
/// A variant rather than a message so a test pins the *reason* rather than a
/// substring: `expected_failures_refusals` names six runtime refusals in this
/// lane's scope and a suite that matched on prose would pass when the wrong one
/// fired.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Refusal {
    /// `expected_failures_refusals[0]`, and
    /// `transaction_fault_matrix[T-DISPATCH].refusal_condition`: "worktree path
    /// outside execution root **or on a reparse point**".
    #[error(
        "refusing {}: `{}` on the chain is a symlink or reparse point, and \
         decisions.workspace_candidates.execution_root creates a root only when the chain carries \
         none",
        .chain.display(),
        .at.display()
    )]
    ReparsePointOnChain {
        /// The path whose chain was walked.
        chain: PathBuf,
        /// The component that is a symlink, junction, or other reparse point.
        at: PathBuf,
    },

    /// `execution_root`: "the canonical root is inside no repository worktree".
    #[error(
        "refusing execution root {}: it is inside the repository worktree {}",
        .root.display(),
        .worktree.display()
    )]
    RootInsideRepositoryWorktree {
        /// The candidate execution root.
        root: PathBuf,
        /// The worktree that contains it.
        worktree: PathBuf,
    },

    /// `execution_root`: "and no repository worktree is inside it".
    #[error(
        "refusing execution root {}: the repository worktree {} is inside it and is not one this \
         manager registered",
        .root.display(),
        .worktree.display()
    )]
    WorktreeInsideRoot {
        /// The candidate execution root.
        root: PathBuf,
        /// The foreign worktree inside it.
        worktree: PathBuf,
    },

    /// `transaction_fault_matrix[T-SCRUB].refusal_condition`: "path outside
    /// execution root". Also `cleanup`: "cleanup is expected-path, contained,
    /// idempotent, and never establishes authority".
    #[error(
        "refusing to touch {}: it is outside the execution root {}",
        .path.display(),
        .root.display()
    )]
    PathOutsideExecutionRoot {
        /// The execution root.
        root: PathBuf,
        /// The path that is not inside it.
        path: PathBuf,
    },

    /// `execution_root`: "created only when the managed base is a real
    /// directory".
    #[error("refusing to manage {}: the managed base is not a real directory", .path.display())]
    BaseIsNotADirectory {
        /// The base that was offered.
        path: PathBuf,
    },

    /// `ref_rules`: "symbolic refs refused". `INV-17`.
    #[error(
        "refusing to touch `{refname}`: it is a symbolic ref pointing at `{target}`, and \
         INV-17 makes every engine ref direct"
    )]
    SymbolicRef {
        /// The ref that was to be created, moved, or deleted.
        refname: String,
        /// What it points at.
        target: String,
    },

    /// `expected_failures_refusals[4]`: "checked-out integration ref".
    /// `integration_ref`: "never checked out".
    #[error(
        "refusing to publish `{refname}`: it is checked out in the worktree {}, and \
         decisions.workspace_candidates.integration_ref says the integration ref is never checked \
         out",
        .worktree.display()
    )]
    CheckedOutRef {
        /// The ref.
        refname: String,
        /// The worktree that has it checked out.
        worktree: PathBuf,
    },

    /// `expected_failures_refusals[2]`: "unexpected refs under the run
    /// namespace". `transaction_fault_matrix[T-CAND-OBJ].refusal_condition`:
    /// "pin symbolic or an unexpected ref under the run namespace".
    #[error("refusing the run namespace `{namespace}`: it carries the unexpected ref `{refname}`")]
    UnexpectedRefUnderNamespace {
        /// The namespace that was censused.
        namespace: String,
        /// The ref that nothing expected.
        refname: String,
    },

    /// `INV-17`: "moved or deleted only **expected-old**".
    ///
    /// Measured, git 2.43: `git update-ref --no-deref -d <ref>
    /// 0000000000000000000000000000000000000000` **succeeds and deletes the
    /// ref**, because the null object id means "must not exist" rather than
    /// "must be this". A caller that reached this primitive with a recorded
    /// value it had never filled in would therefore perform an *unconditional*
    /// delete through an API whose whole contract is that it cannot. A
    /// non-null wrong value refuses correctly; only this one does not, so it is
    /// refused here.
    #[error(
        "refusing to move or delete `{refname}` against the null object id: `git update-ref` reads \
         it as \"must not exist\" and would delete unconditionally, and INV-17 makes every engine \
         ref move or delete expected-old"
    )]
    NullExpectedOld {
        /// The ref that was to be moved or deleted.
        refname: String,
    },

    /// An object id that is not a full hexadecimal id.
    #[error(
        "refusing `{value}` as the {role} object id of `{refname}`: an engine ref primitive takes \
         a full hexadecimal object id"
    )]
    MalformedObjectId {
        /// The ref.
        refname: String,
        /// Which side of the update it was.
        role: &'static str,
        /// The value as it was offered.
        value: String,
    },

    /// A slot name that is not the shape `workspace_candidates` gives it.
    /// Containment is by construction: a name that could carry a separator or
    /// `..` would put a worktree outside the execution root without any
    /// later check noticing.
    #[error("refusing the {kind} slot name `{name}`: {why}")]
    SlotName {
        /// Which slot kind.
        kind: &'static str,
        /// The name as it was offered.
        name: String,
        /// What is wrong with it.
        why: &'static str,
    },

    /// `slice_contract.invariants_introduced[1]`: "worktree and snapshot
    /// intents **synced before** the add".
    ///
    /// The two are separate sites — the cancellation clause is per clause, and
    /// `WriteIntent` and `Add` each carry their own hooks — so the ordering
    /// cannot be a single funnel body. It is enforced here instead: an add
    /// whose intent is not already durable would create a worktree that
    /// [`WorkspaceManager::reclaim_intents`] can never find, which is exactly
    /// the leak `enforcement_domains.external_physical` writes the intent to
    /// prevent ("a durable per-owner recovery record in its row, reclaimed at
    /// process start (never 'empty')").
    #[error(
        "refusing `git worktree add` for `{slot}`: its durable intent {} does not exist, and \
         the intent is synced before the add so that an interrupted add is always reclaimable",
        .intent.display()
    )]
    AddWithoutIntent {
        /// The slot whose add was refused.
        slot: String,
        /// Where its intent was looked for.
        intent: PathBuf,
    },
}

impl From<Refusal> for TactusError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused {
            message: refusal.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// R18: the repository key and the execution root
// ---------------------------------------------------------------------------

/// The domain-separation prefix of `repo_key` v1.
///
/// `decisions.workspace_candidates.execution_root`: "repo_key v1 =
/// hex16(sha256('tactus-repo-key-v1' NUL canonical common git dir bytes))".
const REPO_KEY_V1_DOMAIN: &[u8] = b"tactus-repo-key-v1";

/// How many hex characters `hex16` keeps.
///
/// Read as sixteen hex *characters* — eight bytes of the digest. The other
/// reading, sixteen bytes rendered as thirty-two characters, is available and
/// is not what "hex16" says: the value is a directory component in
/// `<private_root>/workspaces/<repo_key>/<run_id>`, and every other short
/// digest this project renders (`invocation`'s hash) is named for the character
/// count it produces.
const REPO_KEY_HEX_CHARS: usize = 16;

/// `hex16(sha256(...))` of `decisions.workspace_candidates.execution_root`.
#[must_use]
pub fn repo_key_v1(canonical_common_git_dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REPO_KEY_V1_DOMAIN);
    hasher.update([0u8]);
    hasher.update(canonical_common_git_dir.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize();
    let mut key = String::with_capacity(REPO_KEY_HEX_CHARS);
    for byte in digest.iter().take(REPO_KEY_HEX_CHARS.div_ceil(2)) {
        use std::fmt::Write as _;
        let _ = write!(key, "{byte:02x}");
    }
    key.truncate(REPO_KEY_HEX_CHARS);
    key
}

/// `<private_root>/workspaces/<repo_key>/<run_id>`, recorded exactly.
#[must_use]
pub fn execution_root_of(private_root: &Path, repo_key: &str, run_id: &str) -> PathBuf {
    private_root.join("workspaces").join(repo_key).join(run_id)
}

/// Whether `metadata` describes a symlink, junction, or any other reparse
/// point.
///
/// **Windows and Unix answer different questions on purpose.** On Unix the only
/// such object is a symbolic link. On Windows the set is larger — a directory
/// junction (`mklink /J`) and a mount point are reparse points that are *not*
/// symbolic links, and `FileType::is_symlink` answers true only for the
/// name-surrogate tags. `expected_failures_refusals[0]` is "symlink/**junction**
/// on the chain", so the Windows half reads the raw attribute
/// (`FILE_ATTRIBUTE_REPARSE_POINT`) instead, which is true for every reparse
/// point whatever its tag. A refusal that fired only on POSIX symlinks would
/// pass every Linux test and refuse nothing a Windows operator can build.
#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// See the Windows half for why the two differ.
#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

/// The first component of `path`'s chain **at or below `anchor`** that is a
/// reparse point, if any.
///
/// # Why the walk is anchored
///
/// `decisions.workspace_candidates.execution_root` says "with no
/// symlink/reparse point on the chain", and a chain has to start somewhere.
/// It starts at the operator's own authorized root, canonicalized — which is
/// how the packet anchors the same check on the other half of the same
/// structure: `expected_failures_refusals[9]` requires "a locator chain without
/// reparse points **canonicalizing to** `<authorized private root>/runs/
/// <basename>`". The root is resolved and trusted; what must be reparse-free is
/// everything the run itself builds beneath it.
///
/// The unanchored reading was tried and is wrong on a real platform, not just
/// inconvenient: macOS ships `/var` as a symlink to `private/var` and its
/// `$TMPDIR` lives under it, so an operator whose private root is anywhere
/// under `/var` — including every default temporary directory on that OS —
/// would have every run refused for a link they did not create and cannot
/// remove. No live passage asks for that, and the containment the refusal
/// exists to protect is unaffected: every deletion in this module goes through
/// [`WorkspaceManager::contained`], which compares **canonical** paths, so a
/// resolved link cannot carry a removal outside the root.
///
/// Only components that exist are inspected: a root that has not been created
/// yet has an absent leaf, and refusing on absence would refuse every first
/// run.
fn reparse_point_below(anchor: &Path, path: &Path) -> Result<Option<PathBuf>, TactusError> {
    let Ok(relative) = path.strip_prefix(anchor) else {
        return Ok(None);
    };
    let mut walked = anchor.to_path_buf();
    for component in relative.components() {
        walked.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match fs::symlink_metadata(&walked) {
            Ok(metadata) => {
                if is_reparse_point(&metadata) {
                    return Ok(Some(walked));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(TactusError::Io {
                    path: walked,
                    source,
                });
            }
        }
    }
    Ok(None)
}

/// Refuse `path` when a component of its chain below `anchor` is a reparse
/// point.
fn refuse_reparse_points(anchor: &Path, path: &Path) -> Result<(), TactusError> {
    if let Some(at) = reparse_point_below(anchor, path)? {
        return Err(Refusal::ReparsePointOnChain {
            chain: path.to_path_buf(),
            at,
        }
        .into());
    }
    Ok(())
}

/// The leaf clause of `execution_root`: "the managed base is a **real
/// directory**".
fn refuse_unreal_directory(path: &Path) -> Result<(), TactusError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(Refusal::BaseIsNotADirectory {
            path: path.to_path_buf(),
        }
        .into());
    }
    Ok(())
}

/// Undo Windows' extended-length (`\\?\`) canonical form.
///
/// **Measured on the Windows Server 2025 guest**, and a production defect
/// rather than a test artefact: `fs::canonicalize` on Windows returns
/// `\\?\C:\...`, and Git — an MSYS program — rewrites that to `//?/C:/...`
/// and fails with `could not create leading directories … Invalid argument`.
/// Every `git worktree add` under an execution root derived from a
/// canonicalized private root failed with it. Whatever this module hands to Git
/// has to be a path Git can open, so the verbatim prefix comes back off.
///
/// A path that genuinely *requires* the verbatim form — one longer than
/// `MAX_PATH`, or carrying a component Win32 would reject — is left as it is:
/// stripping it would produce a path that names something else, and Git could
/// not have used either spelling.
#[cfg(windows)]
fn strip_verbatim(path: PathBuf) -> PathBuf {
    use std::path::Prefix;

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path;
    };
    let mut rebuilt = match prefix.kind() {
        Prefix::VerbatimDisk(letter) => PathBuf::from(format!("{}:\\", letter as char)),
        Prefix::VerbatimUNC(server, share) => {
            let mut unc = PathBuf::from("\\\\");
            unc.push(server);
            unc.push(share);
            unc
        }
        _ => return path,
    };
    for component in components {
        if matches!(component, Component::RootDir) {
            continue;
        }
        rebuilt.push(component.as_os_str());
    }
    rebuilt
}

/// See the Windows half: nothing to undo anywhere else.
#[cfg(not(windows))]
fn strip_verbatim(path: PathBuf) -> PathBuf {
    path
}

/// Canonicalize the longest existing prefix of `path` and rejoin the rest.
///
/// `fs::canonicalize` needs the whole path to exist; an execution root is
/// compared for containment before it does.
fn canonical_prefix(path: &Path) -> Result<PathBuf, TactusError> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(strip_verbatim(canonical));
    }
    let mut tail = Vec::new();
    let mut head = path.to_path_buf();
    loop {
        let Some(parent) = head.parent().map(Path::to_path_buf) else {
            return Ok(path.to_path_buf());
        };
        let Some(name) = head.file_name().map(OsStr::to_os_string) else {
            return Ok(path.to_path_buf());
        };
        tail.push(name);
        head = parent;
        if let Ok(canonical) = fs::canonicalize(&head) {
            let mut canonical = strip_verbatim(canonical);
            for name in tail.iter().rev() {
                canonical.push(name);
            }
            return Ok(canonical);
        }
        if head.parent().is_none() {
            return Ok(path.to_path_buf());
        }
    }
}

/// Whether `inner` is `outer` or lies beneath it. Both must already be
/// canonical-prefixed.
fn is_at_or_inside(outer: &Path, inner: &Path) -> bool {
    inner == outer || inner.starts_with(outer)
}

// ---------------------------------------------------------------------------
// Slots: the worktree, staging, and snapshot names the packet gives
// ---------------------------------------------------------------------------

/// The three worktree namespaces of an execution root.
///
/// `decisions.workspace_candidates.manager` names two of them literally —
/// "detached linked worktrees with durable synced intents (`tasks/k<key>-g<gen>`,
/// `merge/s<seq>`)" — and `snapshots` names the third, whose members
/// `decisions.workspace_candidates.snapshots` requires to be "never reused
/// across roles or attempts".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    /// `tasks/k<key>-g<gen>` — a task worktree, R9.
    Task {
        /// The task key.
        key: String,
        /// The generation number.
        generation: u32,
    },
    /// `merge/s<seq>` — a staging worktree, R10. Never created for an
    /// exact-base fast sequence.
    Staging {
        /// The merge sequence number.
        sequence: u64,
    },
    /// `snapshots/<name>` — an exact gate or review snapshot, R24.
    Snapshot {
        /// The snapshot's name, which encodes its role, generation, and
        /// attempt so that no two roles or attempts can collide.
        name: SnapshotName,
    },
}

/// A snapshot's name, built so that "never reused across roles or attempts" is
/// a property of the name rather than of the caller's discipline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotName(String);

impl SnapshotName {
    /// The one snapshot the whole gate set runs on.
    #[must_use]
    pub fn gates(generation: u32, attempt: u32) -> Self {
        Self(format!("g{generation}-a{attempt}-gates"))
    }

    /// One fresh snapshot per reviewer.
    #[must_use]
    pub fn review(generation: u32, attempt: u32, reviewer: u32) -> Self {
        Self(format!("g{generation}-a{attempt}-review{reviewer}"))
    }

    /// The snapshot an integration transaction judges its proposal on.
    #[must_use]
    pub fn integration(sequence: u64) -> Self {
        Self(format!("s{sequence}-integration"))
    }

    /// The name as a directory component.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SnapshotName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `name` is safe as a single path component.
fn safe_component(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("it is empty");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Some("only ASCII alphanumerics, `-`, and `_` are legal in a slot component");
    }
    if name.starts_with('-') {
        return Some(
            "a leading `-` would be read as an option by the Git commands the funnels run",
        );
    }
    None
}

impl Slot {
    /// The slot's path relative to the execution root.
    #[must_use]
    pub fn relative(&self) -> PathBuf {
        match self {
            Self::Task { key, generation } => {
                PathBuf::from("tasks").join(format!("k{key}-g{generation}"))
            }
            Self::Staging { sequence } => PathBuf::from("merge").join(format!("s{sequence}")),
            Self::Snapshot { name } => PathBuf::from("snapshots").join(name.as_str()),
        }
    }

    /// The intent file's name, injective over slots: the two components are
    /// joined by `.`, which [`safe_component`] forbids inside either.
    #[must_use]
    pub fn intent_name(&self) -> String {
        match self {
            Self::Task { key, generation } => format!("tasks.k{key}-g{generation}.intent"),
            Self::Staging { sequence } => format!("merge.s{sequence}.intent"),
            Self::Snapshot { name } => format!("snapshots.{name}.intent"),
        }
    }

    /// The row that accounts for this slot.
    ///
    /// Taken from the frozen site enums rather than restated: `R9`, `R10` and
    /// `R24` are what `WorktreeSite::Add.row()`, `AddStaging.row()` and
    /// `SnapshotSite::Add.row()` already answer.
    #[must_use]
    pub fn row(&self) -> ResourceRow {
        self.add_site().row()
    }

    /// The site the slot's `git worktree add` runs under.
    #[must_use]
    pub fn add_site(&self) -> EffectSiteId {
        match self {
            Self::Task { .. } => EffectSiteId::Worktree(WorktreeSite::Add),
            Self::Staging { .. } => EffectSiteId::Worktree(WorktreeSite::AddStaging),
            Self::Snapshot { .. } => EffectSiteId::Snapshot(SnapshotSite::Add),
        }
    }

    /// The site the slot's intent is written under.
    #[must_use]
    pub fn write_intent_site(&self) -> EffectSiteId {
        match self {
            Self::Task { .. } => EffectSiteId::Worktree(WorktreeSite::WriteIntent),
            Self::Staging { .. } => EffectSiteId::Worktree(WorktreeSite::WriteStagingIntent),
            Self::Snapshot { .. } => EffectSiteId::Snapshot(SnapshotSite::WriteIntent),
        }
    }

    /// The site the slot's forced removal runs under.
    #[must_use]
    pub fn remove_site(&self) -> EffectSiteId {
        match self {
            Self::Task { .. } => EffectSiteId::Worktree(WorktreeSite::Remove),
            Self::Staging { .. } => EffectSiteId::Worktree(WorktreeSite::RemoveStaging),
            Self::Snapshot { .. } => EffectSiteId::Snapshot(SnapshotSite::Remove),
        }
    }

    /// The site the slot's intent removal runs under.
    #[must_use]
    pub fn remove_intent_site(&self) -> EffectSiteId {
        match self {
            Self::Task { .. } => EffectSiteId::Worktree(WorktreeSite::RemoveIntent),
            Self::Staging { .. } => EffectSiteId::Worktree(WorktreeSite::RemoveStagingIntent),
            Self::Snapshot { .. } => EffectSiteId::Snapshot(SnapshotSite::RemoveIntent),
        }
    }

    /// What the intent record calls this kind.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Task { .. } => "task",
            Self::Staging { .. } => "staging",
            Self::Snapshot { .. } => "snapshot",
        }
    }

    /// Refuse a slot whose components could escape the execution root.
    fn validate(&self) -> Result<(), Refusal> {
        let (kind, name) = match self {
            Self::Task { key, .. } => ("task", key.as_str()),
            Self::Staging { .. } => return Ok(()),
            Self::Snapshot { name } => ("snapshot", name.as_str()),
        };
        match safe_component(name) {
            None => Ok(()),
            Some(why) => Err(Refusal::SlotName {
                kind,
                name: name.to_owned(),
                why,
            }),
        }
    }

    /// Rebuild a slot from an intent file name, so reclaim never has to trust
    /// a path stored inside a record.
    fn from_intent_name(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(".intent")?;
        if let Some(rest) = stem.strip_prefix("tasks.k") {
            let (key, generation) = rest.rsplit_once("-g")?;
            return Some(Self::Task {
                key: key.to_owned(),
                generation: generation.parse().ok()?,
            });
        }
        if let Some(rest) = stem.strip_prefix("merge.s") {
            return Some(Self::Staging {
                sequence: rest.parse().ok()?,
            });
        }
        if let Some(rest) = stem.strip_prefix("snapshots.") {
            return Some(Self::Snapshot {
                name: SnapshotName(rest.to_owned()),
            });
        }
        None
    }
}

/// The durable per-owner recovery record `resource_accounting` requires of
/// every worktree, staging, and snapshot slot.
///
/// `enforcement_domains.external_physical`: "every worktree, staging, snapshot,
/// and container intent is a durable per-owner recovery record in its row,
/// reclaimed at process start (never 'empty')".
///
/// The worktree path is **not** a field. Reclaim derives it from the intent's
/// own name and the execution root, so a record cannot name a path outside the
/// root it lives in — the containment `cleanup` requires ("expected-path,
/// contained, idempotent, and never establishes authority") is then structural
/// rather than checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentRecord {
    /// `task`, `staging`, or `snapshot`.
    pub kind: String,
    /// The slot's path relative to the execution root, as Git names paths.
    pub slot: String,
    /// The run that owns it.
    pub run_id: String,
    /// The coordinator incarnation that wrote it, so a later incarnation of the
    /// same run can tell its own residue from a live sibling's.
    pub incarnation: String,
}

// ---------------------------------------------------------------------------
// The manager
// ---------------------------------------------------------------------------

/// A registered worktree of the managed repository, as
/// `git worktree list --porcelain -z` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeRecord {
    /// The checkout path, decoded byte-safely.
    pub path: PathBuf,
    /// The commit its HEAD names, when it has one.
    pub head: Option<String>,
    /// The branch it has checked out, when it is not detached.
    pub branch: Option<String>,
    /// Git's own lock reason. `git worktree add` holds `initializing` for the
    /// whole of its run and releases it only once the checkout is populated, so
    /// this field is how a registered-but-unpopulated worktree announces
    /// itself.
    pub locked: Option<String>,
    /// Git's own prunable reason.
    pub prunable: Option<String>,
}

/// Why [`WorkspaceManager::verify_worktree`] refused to reuse a worktree.
///
/// `decisions.workspace_candidates.generation`: "a worktree is reused across a
/// process boundary or after an interrupted Git command … only after
/// Worktree.Verify: the recorded path is a linked worktree of this repository,
/// HEAD equals the recorded base (or, for RetainedIdle, the worktree holds the
/// retained cumulative tree), the index is unlocked, and no
/// cherry-pick/merge/revert/sequencer/rebase state exists".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailure {
    /// Nothing is registered at the recorded path.
    NotRegistered,
    /// Registered, and `git worktree add` never finished populating it — the
    /// `registered-but-unpopulated` residue element.
    Unpopulated,
    /// Registered at the path but belonging to a different repository.
    ForeignRepository,
    /// The checkout directory is gone.
    Missing,
    /// HEAD is not the recorded base.
    HeadMismatch {
        /// The recorded base.
        expected: String,
        /// What HEAD actually is.
        actual: String,
    },
    /// The retained cumulative tree is not the one the worktree holds.
    TreeMismatch {
        /// The recorded tree.
        expected: String,
        /// Why the index does not hold it: the paths that differ, or the reason
        /// the comparison could not be made against that tree at all.
        ///
        /// This was the tree the index writes out as, and obtaining it meant
        /// running `git write-tree`, which **writes** (`PR5-CONF-002`). A
        /// read-only observation cannot name a tree object that does not exist
        /// yet, so it names the difference instead — which is the more useful
        /// half of that diagnostic anyway.
        difference: String,
    },
    /// Administrative residue of an interrupted command.
    Residue(ResidueElement),
}

impl fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegistered => f.write_str("no worktree is registered at the recorded path"),
            Self::Unpopulated => f.write_str(
                "the worktree is registered and was never populated: `git worktree add` still \
                 holds its `initializing` lock",
            ),
            Self::ForeignRepository => {
                f.write_str("the worktree at the recorded path belongs to another repository")
            }
            Self::Missing => f.write_str("the worktree's checkout directory is gone"),
            Self::HeadMismatch { expected, actual } => {
                write!(f, "HEAD is {actual}, not the recorded base {expected}")
            }
            Self::TreeMismatch {
                expected,
                difference,
            } => write!(
                f,
                "the worktree does not hold the retained cumulative tree {expected}: {difference}"
            ),
            Self::Residue(element) => write!(
                f,
                "administrative residue of an interrupted command is present: {element:?}"
            ),
        }
    }
}

/// What a worktree has to hold for [`WorkspaceManager::verify_worktree`] to
/// pass it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Quiescence {
    /// The ordinary case: HEAD equals the recorded base.
    AtBase(String),
    /// `RetainedIdle`: "the worktree holds the retained cumulative tree".
    HoldsTree(String),
}

/// The owner of an execution root and everything inside it.
#[derive(Debug, Clone)]
pub struct WorkspaceManager {
    base: PathBuf,
    common_git_dir: PathBuf,
    repo_key: String,
    run_id: String,
    incarnation: String,
    /// The operator's authorized private root, canonicalized. It is the anchor
    /// the reparse-point walk starts at — see [`reparse_point_below`].
    private_root: PathBuf,
    execution_root: PathBuf,
}

impl WorkspaceManager {
    /// Derive the execution root of `run_id` from the managed base and the
    /// authorized private root, and refuse every containment condition
    /// `decisions.workspace_candidates.execution_root` names.
    ///
    /// # Errors
    ///
    /// [`Refusal::BaseIsNotADirectory`], [`Refusal::ReparsePointOnChain`],
    /// [`Refusal::RootInsideRepositoryWorktree`], and
    /// [`Refusal::WorktreeInsideRoot`], plus a Git error when the base is not a
    /// repository.
    pub fn derive(
        base: &Path,
        private_root: &Path,
        run_id: &str,
        incarnation: &str,
    ) -> Result<Self, TactusError> {
        refuse_unreal_directory(base)?;
        refuse_unreal_directory(private_root)?;

        let common_git_dir = common_git_dir(base)?;
        let repo_key = repo_key_v1(&common_git_dir);
        let private_root = canonical_prefix(private_root)?;
        let execution_root = execution_root_of(&private_root, &repo_key, run_id);
        let manager = Self {
            base: canonical_prefix(base)?,
            common_git_dir,
            repo_key,
            run_id: run_id.to_owned(),
            incarnation: incarnation.to_owned(),
            private_root,
            execution_root,
        };
        manager.revalidate()?;
        Ok(manager)
    }

    /// The canonicalized authorized private root the execution root hangs from.
    #[must_use]
    pub fn private_root(&self) -> &Path {
        &self.private_root
    }

    /// The managed base checkout. Read only, for base capture.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The repository's canonical common git dir — the bytes `repo_key` is
    /// taken over.
    #[must_use]
    pub fn common_git_dir(&self) -> &Path {
        &self.common_git_dir
    }

    /// `repo_key` v1 of the managed repository.
    #[must_use]
    pub fn repo_key(&self) -> &str {
        &self.repo_key
    }

    /// The execution root, recorded exactly.
    #[must_use]
    pub fn execution_root(&self) -> &Path {
        &self.execution_root
    }

    /// Where a slot's worktree lives.
    #[must_use]
    pub fn slot_path(&self, slot: &Slot) -> PathBuf {
        self.execution_root.join(slot.relative())
    }

    /// Where a slot's intent lives.
    #[must_use]
    pub fn intent_path(&self, slot: &Slot) -> PathBuf {
        self.execution_root.join("intents").join(slot.intent_name())
    }

    /// The three containment conditions, re-checked.
    ///
    /// `execution_root`: "created only when the managed base is a real
    /// directory with no symlink/reparse point on the chain, the canonical root
    /// is inside no repository worktree, and no repository worktree is inside
    /// it; **every create/reclaim/delete revalidates**".
    ///
    /// The third clause is evaluated as *no foreign* worktree is inside it. The
    /// manager's own worktrees are inside the root by construction — that is
    /// what the root is for — so a literal reading would make the second
    /// `add` refuse. A worktree is the manager's when its path is
    /// `<root>/{tasks,merge,snapshots}/<component>`; anything else inside the
    /// root is foreign and refuses.
    ///
    /// # Errors
    ///
    /// The containment refusals, or a Git error reading the worktree list.
    pub fn revalidate(&self) -> Result<(), TactusError> {
        refuse_unreal_directory(&self.base)?;
        refuse_reparse_points(&self.private_root, &self.execution_root)?;
        let root = canonical_prefix(&self.execution_root)?;
        for record in self.worktree_records()? {
            let worktree = canonical_prefix(&record.path)?;
            if is_at_or_inside(&worktree, &root) {
                return Err(Refusal::RootInsideRepositoryWorktree {
                    root,
                    worktree: record.path,
                }
                .into());
            }
            if is_at_or_inside(&root, &worktree) && !self.is_manager_slot_path(&root, &worktree) {
                return Err(Refusal::WorktreeInsideRoot {
                    root,
                    worktree: record.path,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Whether `worktree` occupies one of this manager's own slot namespaces.
    fn is_manager_slot_path(&self, root: &Path, worktree: &Path) -> bool {
        let Ok(relative) = worktree.strip_prefix(root) else {
            return false;
        };
        let components: Vec<_> = relative.components().collect();
        if components.len() != 2 {
            return false;
        }
        let Component::Normal(namespace) = components[0] else {
            return false;
        };
        let Component::Normal(name) = components[1] else {
            return false;
        };
        matches!(
            namespace.to_str(),
            Some("tasks") | Some("merge") | Some("snapshots")
        ) && name
            .to_str()
            .is_some_and(|name| safe_component(name).is_none())
    }

    /// The slot's path, with its name validated first.
    ///
    /// Every primitive that turns a [`Slot`] into a path goes through this
    /// rather than through [`Self::slot_path`]. `Slot`'s fields are public, so
    /// the name is caller data at every entry point, not only at the two that
    /// happen to create something: `git add -A`, `git write-tree`,
    /// `git cherry-pick` and `git diff` all run with the slot path as their
    /// working directory, and a name carrying a separator would run them
    /// outside the execution root. [`Refusal::SlotName`]'s own doc comment says
    /// containment here is "by construction" — this is where that construction
    /// is applied uniformly.
    ///
    /// # Errors
    ///
    /// [`Refusal::SlotName`].
    fn slot_target(&self, slot: &Slot) -> Result<PathBuf, TactusError> {
        slot.validate()?;
        Ok(self.slot_path(slot))
    }

    /// Refuse a path that is not inside the execution root.
    ///
    /// `transaction_fault_matrix[T-SCRUB].refusal_condition` is "path outside
    /// execution root", and it is the whole of what makes the forced removals
    /// safe: they delete a directory tree.
    fn contained(&self, path: &Path) -> Result<PathBuf, TactusError> {
        let root = canonical_prefix(&self.execution_root)?;
        let candidate = canonical_prefix(path)?;
        if candidate == root || !candidate.starts_with(&root) {
            return Err(Refusal::PathOutsideExecutionRoot {
                root,
                path: path.to_path_buf(),
            }
            .into());
        }
        Ok(candidate)
    }

    // -----------------------------------------------------------------------
    // R18 funnels
    // -----------------------------------------------------------------------

    /// `Worktree.CreateExecutionRoot` (R18).
    ///
    /// # Errors
    ///
    /// The containment refusals, or an I/O error creating the directories.
    pub fn create_execution_root(&self, hooks: &mut dyn EffectHooks) -> Result<(), TactusError> {
        self.revalidate()?;
        let ledger = hooks.durability_ledger();
        funnel(
            hooks,
            EffectSiteId::Worktree(WorktreeSite::CreateExecutionRoot),
            || {
                for directory in [
                    self.execution_root.clone(),
                    self.execution_root.join("intents"),
                    self.execution_root.join("tasks"),
                    self.execution_root.join("merge"),
                    self.execution_root.join("snapshots"),
                    self.hooks_dir(),
                ] {
                    fs::create_dir_all(&directory).map_err(|source| TactusError::Io {
                        path: directory,
                        source,
                    })?;
                }
                sync_directory(&self.execution_root, &ledger)
            },
        )
    }

    /// `Worktree.RemoveExecutionRoot` (R18).
    ///
    /// `resource_accounting[R18].lifecycle`: "pruned by finalization when
    /// empty; otherwise resumably_open". The answer says which happened, so a
    /// caller cannot read "did nothing" as "removed".
    ///
    /// # Errors
    ///
    /// The containment refusals, or an I/O error.
    pub fn remove_execution_root(&self, hooks: &mut dyn EffectHooks) -> Result<bool, TactusError> {
        self.revalidate()?;
        funnel(
            hooks,
            EffectSiteId::Worktree(WorktreeSite::RemoveExecutionRoot),
            || {
                if !self.execution_root.exists() {
                    return Ok(false);
                }
                for scaffolding in [
                    self.hooks_dir(),
                    self.execution_root.join("intents"),
                    self.execution_root.join("tasks"),
                    self.execution_root.join("merge"),
                    self.execution_root.join("snapshots"),
                ] {
                    if directory_is_empty(&scaffolding)? {
                        let _ = fs::remove_dir(&scaffolding);
                    }
                }
                if !directory_is_empty(&self.execution_root)? {
                    return Ok(false);
                }
                fs::remove_dir(&self.execution_root).map_err(|source| TactusError::Io {
                    path: self.execution_root.clone(),
                    source,
                })?;
                Ok(true)
            },
        )
    }

    /// The empty directory every funnel points `core.hooksPath` at.
    ///
    /// `decisions.workspace_candidates.candidate` calls the commit "hook-free",
    /// and a repository hook that ran inside an engine worktree would be an
    /// effect no site accounts for.
    fn hooks_dir(&self) -> PathBuf {
        self.execution_root.join("hooks-none")
    }

    // -----------------------------------------------------------------------
    // Intents (R9 / R10 / R24)
    // -----------------------------------------------------------------------

    /// `Worktree.WriteIntent` / `Worktree.WriteStagingIntent` /
    /// `Snapshot.WriteIntent`.
    ///
    /// `slice_contract.invariants_introduced[1]`: "worktree and snapshot
    /// intents **synced before add**". The record is written to a temporary,
    /// fsynced, renamed, and the directory fsynced, so an interrupted write
    /// leaves either nothing or a complete record — never a half-parsed one
    /// that reclaim would refuse.
    ///
    /// # Errors
    ///
    /// A slot refusal, the containment refusals, or an I/O error.
    pub fn write_intent(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
    ) -> Result<(), TactusError> {
        slot.validate()?;
        self.revalidate()?;
        let path = self.intent_path(slot);
        let record = IntentRecord {
            kind: slot.kind().to_owned(),
            slot: slot.relative().to_string_lossy().replace('\\', "/"),
            run_id: self.run_id.clone(),
            incarnation: self.incarnation.clone(),
        };
        let ledger = hooks.durability_ledger();
        funnel(hooks, slot.write_intent_site(), || {
            let bytes = serde_json::to_vec(&record).map_err(|error| TactusError::Git {
                message: format!("serializing the {} intent: {error}", slot.kind()),
            })?;
            write_synced(&path, &bytes, &ledger)
        })
    }

    /// `Worktree.RemoveIntent` / `Worktree.RemoveStagingIntent` /
    /// `Snapshot.RemoveIntent`. Idempotent.
    ///
    /// # Errors
    ///
    /// A slot refusal, the containment refusals, or an I/O error. The name is
    /// validated here too: `intent_name` joins the slot's components with `.`
    /// into a *file name*, so an unvalidated name carrying a separator would
    /// make this `remove_file` a deletion outside the intents directory.
    pub fn remove_intent(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
    ) -> Result<(), TactusError> {
        slot.validate()?;
        self.revalidate()?;
        let path = self.intent_path(slot);
        let ledger = hooks.durability_ledger();
        funnel(hooks, slot.remove_intent_site(), || {
            match fs::remove_file(&path) {
                Ok(()) => sync_directory(path.parent().unwrap_or(&self.execution_root), &ledger),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(TactusError::Io { path, source }),
            }
        })
    }

    /// Every intent the execution root still carries, in directory order.
    ///
    /// # Errors
    ///
    /// An I/O error, or an intent file whose name no slot renders.
    pub fn intents(&self) -> Result<Vec<Slot>, TactusError> {
        let directory = self.execution_root.join("intents");
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(TactusError::Io {
                    path: directory,
                    source,
                });
            }
        };
        let mut slots = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| TactusError::Io {
                path: directory.clone(),
                source,
            })?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| TactusError::Git {
                message: format!("intent {} has a non-UTF-8 name", entry.path().display()),
            })?;
            let slot = Slot::from_intent_name(name).ok_or_else(|| TactusError::Git {
                message: format!(
                    "unexpected file `{name}` in the intent directory of {}",
                    self.execution_root.display()
                ),
            })?;
            slot.validate()?;
            slots.push(slot);
        }
        slots.sort();
        Ok(slots)
    }

    /// Reclaim every intent this execution root carries: forced removal of the
    /// worktree, then the intent.
    ///
    /// `enforcement_domains.external_physical`: intents are "reclaimed at
    /// process start (never 'empty')".
    /// `transaction_fault_matrix[T-DISPATCH].resume_action` and
    /// `[T-PROPOSAL].resume_action` both remove "intent then worktree" with
    /// force, and `decisions.workspace_candidates.snapshots` says an
    /// "interrupted add leaves a registered-but-unpopulated worktree that the
    /// intent-based reclaim removes and prunes".
    ///
    /// # Errors
    ///
    /// The containment refusals or a Git or I/O error.
    pub fn reclaim_intents(&self, hooks: &mut dyn EffectHooks) -> Result<Vec<Slot>, TactusError> {
        self.revalidate()?;
        let slots = self.intents()?;
        for slot in &slots {
            self.remove_worktree(hooks, slot)?;
            self.remove_intent(hooks, slot)?;
        }
        Ok(slots)
    }

    // -----------------------------------------------------------------------
    // Worktree and snapshot funnels (R9 / R10 / R24)
    // -----------------------------------------------------------------------

    /// The fixed argv of the four Git commands the residue kill sampler drives
    /// (Fable's `PR5-CONF-004`).
    ///
    /// `command_internal_sub_effects` (ii) is "real-command kill sampling — the
    /// Git child of the site is killed at uncontrolled points **through the
    /// process funnel** across N runs". The sampler spawns its own `git` child
    /// with an argv it transcribed from these funnels. The transcription was
    /// faithful, and nothing made it stay faithful: changing a funnel's argv —
    /// adding a flag to the stage, say — would leave the sampler silently
    /// sampling a stale command with every assertion green, and the
    /// recovery-proven evidence would no longer describe the funnel's real
    /// child.
    ///
    /// So the transcription is gone. There is one list per command, the funnel
    /// and the sampler both read it, and
    /// `no_sampled_funnel_builds_its_argv_from_a_literal` fails if a funnel
    /// grows an argument that does not come through here. It does **not** make
    /// the kill go through the process funnel — that is
    /// `PR5D-PROCESS-FUNNEL-TAKES-NO-SITE` in `reviews/FINDINGS.md`, owned by
    /// PR6/PR7 with `src/runner/**` frozen — and this comment does not claim it
    /// does.
    pub(crate) const CANDIDATE_STAGE_ARGV: [&str; 4] = ["add", "-A", "--", "."];
    /// See [`Self::CANDIDATE_STAGE_ARGV`]. Takes no dynamic argument.
    pub(crate) const CANDIDATE_WRITE_TREE_ARGV: [&str; 1] = ["write-tree"];
    /// See [`Self::CANDIDATE_STAGE_ARGV`]. Takes the commit to pick.
    pub(crate) const PROPOSAL_CHERRY_PICK_ARGV: [&str; 1] = ["cherry-pick"];
    /// See [`Self::CANDIDATE_STAGE_ARGV`]. Takes the path and the commit.
    pub(crate) const WORKTREE_ADD_ARGV: [&str; 4] = ["worktree", "add", "--detach", "--quiet"];

    /// `Worktree.Add` / `Worktree.AddStaging` / `Snapshot.Add`: a **detached**
    /// linked worktree at `commit`.
    ///
    /// The intent must already be durable, and this funnel **refuses** if it is
    /// not. `write_intent` is a separate site rather than a step inside this
    /// one because the cancellation clause is per clause: "an interrupted
    /// worktree or snapshot add leaves a durable intent that reclaim removes".
    /// Separate sites make the *ordering* a caller's obligation, so the
    /// obligation is checked here — see [`Refusal::AddWithoutIntent`].
    ///
    /// # Errors
    ///
    /// A slot refusal, [`Refusal::AddWithoutIntent`], the containment refusals,
    /// or a Git error.
    pub fn add_worktree(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
        commit: &str,
    ) -> Result<PathBuf, TactusError> {
        let path = self.slot_target(slot)?;
        self.revalidate()?;
        let intent = self.intent_path(slot);
        if !intent.is_file() {
            return Err(Refusal::AddWithoutIntent {
                slot: slot.relative().display().to_string(),
                intent,
            }
            .into());
        }
        funnel(hooks, slot.add_site(), || {
            // Inside the funnel, not before it (`PR5-CONF-003`). `identity` says
            // "the funnel itself calls hook(Before, site) -> primitive ->
            // hook(After, site)" and `scope` requires "every effect through
            // typed funnel APIs taking a site"; this scaffolding `create_dir_all`
            // sat outside the call, so a hook armed to refuse at
            // `Before(Worktree.Add)` returned its refusal *after* the directory
            // had already been created. Measured: against a slot whose
            // scaffolding directory was removed, the refusal arrived and the
            // directory existed.
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|source| TactusError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            let mut argv: Vec<OsString> =
                Self::WORKTREE_ADD_ARGV.iter().map(OsString::from).collect();
            argv.push(path.clone().into_os_string());
            argv.push(OsString::from(commit));
            self.git_ok(&self.base, &argv)?;
            Ok(path.clone())
        })
    }

    /// `Worktree.Verify` — the read-only quiescence observation.
    ///
    /// The site is `is_read_only()`, so it performs nothing at either phase;
    /// its hooks still fire, because ST-07 requires every site observed
    /// executed and a read-only site is still a site.
    ///
    /// # Errors
    ///
    /// The containment refusals or a Git error. A worktree that is *not*
    /// quiescent is `Ok(Err(VerifyFailure))`, not an error: its failure routes
    /// to forced removal and a fresh add, which is a decision the caller makes.
    pub fn verify_worktree(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
        expected: &Quiescence,
    ) -> Result<Result<(), VerifyFailure>, TactusError> {
        self.revalidate()?;
        let path = self.slot_target(slot)?;
        funnel(hooks, EffectSiteId::Worktree(WorktreeSite::Verify), || {
            self.quiescence(&path, expected)
        })
    }

    /// The body of [`Self::verify_worktree`], so the sampling harness can ask
    /// the same question without a second hook execution.
    ///
    /// # Errors
    ///
    /// A Git error.
    pub fn quiescence(
        &self,
        path: &Path,
        expected: &Quiescence,
    ) -> Result<Result<(), VerifyFailure>, TactusError> {
        let Some(record) = self.worktree_record(path)? else {
            return Ok(Err(VerifyFailure::NotRegistered));
        };
        if record.locked.as_deref() == Some("initializing") {
            return Ok(Err(VerifyFailure::Unpopulated));
        }
        if !path.is_dir() {
            return Ok(Err(VerifyFailure::Missing));
        }
        let Some(git_dir) = self.worktree_git_dir(path)? else {
            return Ok(Err(VerifyFailure::Missing));
        };
        match common_git_dir(path) {
            Ok(common) if common == self.common_git_dir => {}
            Ok(_) => return Ok(Err(VerifyFailure::ForeignRepository)),
            Err(_) => return Ok(Err(VerifyFailure::Missing)),
        }
        if let Some(element) = administrative_residue_at(&git_dir)?.first() {
            return Ok(Err(VerifyFailure::Residue(*element)));
        }
        match expected {
            Quiescence::AtBase(base) => {
                let head = self.git_line(path, &["rev-parse", "HEAD"])?;
                if !head.eq_ignore_ascii_case(base) {
                    return Ok(Err(VerifyFailure::HeadMismatch {
                        expected: base.clone(),
                        actual: head,
                    }));
                }
            }
            Quiescence::HoldsTree(tree) => {
                // Read-only, and now literally (`PR5-CONF-002`). This ran
                // `git write-tree`, under a comment claiming it "creates no
                // object that is not already implied by the index it reads" —
                // and "implied by" is not "already present". Measured against
                // git 2.43.0: an index carrying staged content whose tree object
                // was never written gains **two loose objects**, and the index's
                // own bytes are rewritten 104 → 165 with the `TREE` cache-tree
                // extension added. That reachable prefix is exactly the one
                // `Object.CandidateStage` leaves before `Object.CandidateWriteTree`
                // runs. `identity` calls `Worktree.Verify` "a read-only
                // quiescence observation (no effect)" and
                // `WorktreeSite::Verify::is_read_only()` lives in a frozen file,
                // so the code is what had to move.
                if let Some(difference) = self.index_differs_from(path, tree)? {
                    return Ok(Err(VerifyFailure::TreeMismatch {
                        expected: tree.clone(),
                        difference,
                    }));
                }
            }
        }
        Ok(Ok(()))
    }

    /// How the worktree's **index** differs from `tree`, or `None` when it holds
    /// exactly that tree — computed **without writing anything**
    /// (`PR5-CONF-002`).
    ///
    /// `diff-index --cached` asks the question `write-tree` was being used to
    /// answer — *does the index hold this exact tree* — and answers it by
    /// reading. `--no-optional-locks` is what makes that read-only rather than
    /// nearly: without it `diff-index` takes the index lock to write back a
    /// refreshed stat cache, which is a write to `.git/index`.
    ///
    /// Three outcomes, because `--quiet` implies `--exit-code`: 0 is "holds it",
    /// 1 is "differs", and anything else is a Git failure — of which one case is
    /// ordinary rather than exceptional and is answered rather than propagated:
    /// a recorded tree that is not an object in this repository at all. A
    /// worktree cannot hold a tree the repository does not have, so that is a
    /// mismatch, which is also what the pre-repair code reported for it.
    ///
    /// # Errors
    ///
    /// A Git error other than "the index differs" or "the tree is absent".
    fn index_differs_from(&self, path: &Path, tree: &str) -> Result<Option<String>, TactusError> {
        const READ_ONLY: &str = "--no-optional-locks";
        let quiet = read_only_git(
            path,
            &[READ_ONLY, "diff-index", "--cached", "--quiet", tree, "--"],
        )?;
        match quiet.status.code() {
            Some(0) => return Ok(None),
            Some(1) => {}
            _ => {
                let present = read_only_git(
                    path,
                    &[READ_ONLY, "cat-file", "-e", &format!("{tree}^{{tree}}")],
                )?;
                if present.status.success() {
                    return Err(TactusError::Git {
                        message: format!(
                            "git diff-index against {tree} failed in {}: {}",
                            path.display(),
                            String::from_utf8_lossy(&quiet.stderr).trim()
                        ),
                    });
                }
                return Ok(Some(
                    "that tree is not an object in this repository".to_owned(),
                ));
            }
        }

        // NUL-separated, because a path may contain a newline and a diagnostic
        // that split on one would name paths that do not exist.
        let names = read_only_git_ok(
            path,
            &[
                READ_ONLY,
                "diff-index",
                "--cached",
                "--name-only",
                "-z",
                tree,
                "--",
            ],
        )?;
        let differing: Vec<String> = String::from_utf8_lossy(&names)
            .split('\0')
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect();
        let listed: Vec<&String> = differing.iter().take(8).collect();
        let more = differing.len().saturating_sub(listed.len());
        let mut message = format!(
            "{} path(s) differ: {}",
            differing.len(),
            listed
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if more > 0 {
            message.push_str(&format!(" and {more} more"));
        }
        Ok(Some(message))
    }

    /// `Worktree.Remove` / `Worktree.RemoveStaging` / `Snapshot.Remove` —
    /// **forced**, and idempotent.
    ///
    /// `decisions.workspace_candidates.cleanup`: "every worktree, staging, and
    /// snapshot removal is forced (`git worktree remove --force` semantics, or
    /// contained expected-path deletion followed by `git worktree prune`) so
    /// Git administrative residue left by an interrupted command (index.lock,
    /// CHERRY_PICK_HEAD, MERGE_HEAD, MERGE_MSG, ORIG_HEAD, sequencer state, **a
    /// registered-but-unpopulated worktree**) never blocks reclaim".
    ///
    /// The contained-deletion form is the one implemented, because it is the
    /// only one that works when the checkout is already gone — and because it
    /// is the form whose containment is checkable. The `locked` marker
    /// `git worktree add` leaves behind is cleared as part of the removal:
    /// measured, `git worktree prune` skips a locked entry and
    /// `git worktree remove --force` refuses one, so a removal that did not
    /// clear it would leave exactly the residue this sentence promises never
    /// blocks reclaim.
    ///
    /// # Errors
    ///
    /// The containment refusals, or a Git or I/O error.
    pub fn remove_worktree(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
    ) -> Result<(), TactusError> {
        self.revalidate()?;
        let path = self.slot_target(slot)?;
        funnel(hooks, slot.remove_site(), || {
            if path.exists() {
                let contained = self.contained(&path)?;
                fs::remove_dir_all(&contained).map_err(|source| TactusError::Io {
                    path: contained,
                    source,
                })?;
            }
            if let Some(admin) = self.registered_admin_dir(&path)? {
                let locked = admin.join("locked");
                match fs::remove_file(&locked) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(TactusError::Io {
                            path: locked,
                            source,
                        });
                    }
                }
            }
            self.git_ok(
                &self.base,
                &[OsString::from("worktree"), OsString::from("prune")],
            )?;
            Ok(())
        })
    }

    // -----------------------------------------------------------------------
    // The exact snapshot store (R24)
    // -----------------------------------------------------------------------

    /// Add an exact snapshot: a detached checkout of exactly the tree under
    /// judgment.
    ///
    /// `decisions.workspace_candidates.snapshots`: "for a tree-only candidate
    /// input the snapshot funnel first creates an ephemeral commit of that tree
    /// on the recorded parent (Object.SnapshotCommitTree: unreferenced, R27,
    /// until the worktree add makes it the snapshot HEAD, R24 …), while
    /// integration snapshots check out the proposal or head commit and create
    /// no object; **intent synced before `git worktree add`**".
    ///
    /// The order is therefore: commit-tree (when the input is a tree) → intent
    /// → add. That is also the order the cancellation clause depends on — "an
    /// ephemeral snapshot commit created *before* the intent is left to Git" —
    /// so the object exists before anything durable claims it.
    ///
    /// # Errors
    ///
    /// A slot refusal, the containment refusals, or a Git error.
    pub fn add_snapshot(
        &self,
        hooks: &mut dyn EffectHooks,
        name: &SnapshotName,
        input: &SnapshotInput,
    ) -> Result<Snapshot, TactusError> {
        let slot = Slot::Snapshot { name: name.clone() };
        let (head, ephemeral) = match input {
            SnapshotInput::Commit(commit) => (commit.clone(), None),
            SnapshotInput::Tree { tree, parent } => {
                let commit = self.snapshot_commit_tree(hooks, tree, parent)?;
                (commit.clone(), Some(commit))
            }
        };
        self.write_intent(hooks, &slot)?;
        let path = self.add_worktree(hooks, &slot, &head)?;
        Ok(Snapshot {
            slot,
            path,
            head,
            ephemeral,
        })
    }

    /// Remove an exact snapshot: forced worktree removal, then the intent.
    ///
    /// # Errors
    ///
    /// The containment refusals, or a Git or I/O error.
    pub fn remove_snapshot(
        &self,
        hooks: &mut dyn EffectHooks,
        snapshot: &Snapshot,
    ) -> Result<(), TactusError> {
        self.remove_worktree(hooks, &snapshot.slot)?;
        self.remove_intent(hooks, &snapshot.slot)
    }

    // -----------------------------------------------------------------------
    // Ref primitives (R11 / R12 / R21 / R23) — INV-17
    // -----------------------------------------------------------------------

    /// `Ref.*` creation, zero-old and `--no-deref`.
    ///
    /// `ref_rules`: "all refs direct, created zero-old with `--no-deref`, moved
    /// or deleted only expected-old; symbolic refs refused".
    ///
    /// # Errors
    ///
    /// [`Refusal::SymbolicRef`], or a Git error — including the zero-old
    /// failure when the ref already exists.
    pub fn create_ref_zero_old(
        &self,
        hooks: &mut dyn EffectHooks,
        site: RefSite,
        refname: &str,
        new: &str,
    ) -> Result<(), TactusError> {
        self.refuse_symbolic(refname)?;
        refuse_malformed_object_id(refname, "new", new)?;
        funnel(hooks, EffectSiteId::Ref(site), || {
            self.update_ref(&["--no-deref", refname, new, ""])
        })
    }

    /// `Ref.CompareAndSwapIntegration`: expected-old, `--no-deref`.
    ///
    /// # Errors
    ///
    /// [`Refusal::SymbolicRef`], [`Refusal::CheckedOutRef`], or a Git error
    /// when the old value does not match.
    pub fn compare_and_swap_ref(
        &self,
        hooks: &mut dyn EffectHooks,
        site: RefSite,
        refname: &str,
        old: &str,
        new: &str,
    ) -> Result<(), TactusError> {
        self.assert_publishable(refname)?;
        refuse_malformed_object_id(refname, "new", new)?;
        refuse_expected_old(refname, old)?;
        funnel(hooks, EffectSiteId::Ref(site), || {
            self.update_ref(&["--no-deref", refname, new, old])
        })
    }

    /// `Ref.Delete*` / pin pruning: expected-old, `--no-deref`.
    ///
    /// # Errors
    ///
    /// [`Refusal::SymbolicRef`] or a Git error when the old value does not
    /// match.
    pub fn delete_ref_expected_old(
        &self,
        hooks: &mut dyn EffectHooks,
        site: RefSite,
        refname: &str,
        old: &str,
    ) -> Result<(), TactusError> {
        self.refuse_symbolic(refname)?;
        refuse_expected_old(refname, old)?;
        funnel(hooks, EffectSiteId::Ref(site), || {
            self.update_ref(&["--no-deref", "-d", refname, old])
        })
    }

    /// `assert_publishable()` of `decisions.workspace_candidates.integration_ref`
    /// — "before every prepare/CAS/recovery".
    ///
    /// # Errors
    ///
    /// [`Refusal::SymbolicRef`] or [`Refusal::CheckedOutRef`].
    pub fn assert_publishable(&self, refname: &str) -> Result<(), TactusError> {
        self.refuse_symbolic(refname)?;
        for record in self.worktree_records()? {
            if record.branch.as_deref() == Some(refname) {
                return Err(Refusal::CheckedOutRef {
                    refname: refname.to_owned(),
                    worktree: record.path,
                }
                .into());
            }
        }
        Ok(())
    }

    /// The direct target of `refname`, or `None` when nothing is there.
    ///
    /// # Errors
    ///
    /// [`Refusal::SymbolicRef`], or a Git error.
    pub fn direct_ref_target(&self, refname: &str) -> Result<Option<String>, TactusError> {
        self.refuse_symbolic(refname)?;
        let output = self.git(
            &self.base,
            &[
                OsString::from("show-ref"),
                OsString::from("--verify"),
                OsString::from("--"),
                OsString::from(refname),
            ],
        )?;
        if !output.status.success() {
            return Ok(None);
        }
        let line = String::from_utf8_lossy(&output.stdout);
        Ok(line
            .split_whitespace()
            .next()
            .map(std::borrow::ToOwned::to_owned))
    }

    /// Every ref under `namespace`, as `(refname, object id)`.
    ///
    /// # Errors
    ///
    /// A Git error.
    pub fn refs_under(&self, namespace: &str) -> Result<Vec<(String, String)>, TactusError> {
        let output = self.git_ok(
            &self.base,
            &[
                OsString::from("for-each-ref"),
                OsString::from("--format=%(refname) %(objectname)"),
                OsString::from(namespace),
            ],
        )?;
        let listing = String::from_utf8(output).map_err(|error| TactusError::Git {
            message: format!("`git for-each-ref {namespace}` returned non-UTF-8 output: {error}"),
        })?;
        Ok(listing
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(refname, oid)| (refname.to_owned(), oid.to_owned()))
            .collect())
    }

    /// Refuse a run namespace carrying anything `expected` does not name.
    ///
    /// `expected_failures_refusals[2]`: "unexpected refs under the run
    /// namespace".
    ///
    /// # Errors
    ///
    /// [`Refusal::UnexpectedRefUnderNamespace`] or a Git error.
    pub fn refuse_unexpected_refs(
        &self,
        namespace: &str,
        expected: &[String],
    ) -> Result<(), TactusError> {
        for (refname, _) in self.refs_under(namespace)? {
            if !expected.contains(&refname) {
                return Err(Refusal::UnexpectedRefUnderNamespace {
                    namespace: namespace.to_owned(),
                    refname,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Refuse a symbolic ref without touching it.
    fn refuse_symbolic(&self, refname: &str) -> Result<(), TactusError> {
        let output = self.git(
            &self.base,
            &[
                OsString::from("symbolic-ref"),
                OsString::from("-q"),
                OsString::from("--"),
                OsString::from(refname),
            ],
        )?;
        if output.status.success() {
            return Err(Refusal::SymbolicRef {
                refname: refname.to_owned(),
                target: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            }
            .into());
        }
        Ok(())
    }

    fn update_ref(&self, args: &[&str]) -> Result<(), TactusError> {
        let mut argv = vec![OsString::from("update-ref")];
        argv.extend(args.iter().map(OsString::from));
        self.git_ok(&self.base, &argv)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // The Object group (R9 / R10 / R24 / R27)
    // -----------------------------------------------------------------------

    /// `Object.CandidateStage` — `git add -A` in the task worktree.
    ///
    /// The blob objects it writes are referenced by that worktree's index: R9,
    /// which is exactly what `ObjectSite::CandidateStage.row()` answers.
    ///
    /// # Errors
    ///
    /// The containment refusals or a Git error.
    pub fn candidate_stage(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
    ) -> Result<(), TactusError> {
        self.revalidate()?;
        let path = self.slot_target(slot)?;
        funnel(
            hooks,
            EffectSiteId::Object(ObjectSite::CandidateStage),
            || {
                self.git_ok(
                    &path,
                    &Self::CANDIDATE_STAGE_ARGV
                        .iter()
                        .map(OsString::from)
                        .collect::<Vec<_>>(),
                )?;
                Ok(())
            },
        )
    }

    /// `Object.CandidateWriteTree` — `git write-tree` in the task worktree.
    ///
    /// # Errors
    ///
    /// The containment refusals or a Git error.
    pub fn candidate_write_tree(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
    ) -> Result<String, TactusError> {
        self.revalidate()?;
        let path = self.slot_target(slot)?;
        funnel(
            hooks,
            EffectSiteId::Object(ObjectSite::CandidateWriteTree),
            || self.git_line(&path, &Self::CANDIDATE_WRITE_TREE_ARGV),
        )
    }

    /// `Object.SnapshotCommitTree` — the ephemeral commit of a tree-only
    /// snapshot input, on the recorded parent.
    ///
    /// Unreferenced when it is written (R27), and only `Snapshot.Add` moves it
    /// into R24.
    ///
    /// # Errors
    ///
    /// A Git error.
    pub fn snapshot_commit_tree(
        &self,
        hooks: &mut dyn EffectHooks,
        tree: &str,
        parent: &str,
    ) -> Result<String, TactusError> {
        self.commit_tree(
            hooks,
            EffectSiteId::Object(ObjectSite::SnapshotCommitTree),
            tree,
            parent,
            "tactus: ephemeral snapshot input",
        )
    }

    /// `Object.CandidateCommitTree` — the candidate commit.
    ///
    /// Unreferenced when it is written (R27), and only
    /// `Ref.PinCandidatePrepared` moves it into R23.
    ///
    /// # Errors
    ///
    /// A Git error.
    pub fn candidate_commit_tree(
        &self,
        hooks: &mut dyn EffectHooks,
        tree: &str,
        parent: &str,
        message: &str,
    ) -> Result<String, TactusError> {
        self.commit_tree(
            hooks,
            EffectSiteId::Object(ObjectSite::CandidateCommitTree),
            tree,
            parent,
            message,
        )
    }

    /// The two commit-tree sites, including the parent-side `IdUnread` point
    /// they both expose.
    ///
    /// `effect_site_inventory.identity`: "the two commit-tree sites
    /// additionally expose the parent-side sub-effect point IdUnread (the child
    /// has exited with the object written; the coordinator has not yet read or
    /// recorded the printed id — R27 residue)".
    ///
    /// The point is consulted *after* `wait_with_output` and *before* the
    /// printed id is parsed. Buffering the child's stdout is not reading the
    /// id: the durable claim is that the coordinator has not **recorded** it,
    /// and a kill here leaves an object nothing names.
    fn commit_tree(
        &self,
        hooks: &mut dyn EffectHooks,
        site: EffectSiteId,
        tree: &str,
        parent: &str,
        message: &str,
    ) -> Result<String, TactusError> {
        apply(
            hooks.phase(site, HookPhase::Before),
            site,
            HookPhase::Before,
        )?;
        let output = self.git_with_identity(
            &self.base,
            &[
                OsString::from("commit-tree"),
                OsString::from(tree),
                OsString::from("-p"),
                OsString::from(parent),
                OsString::from("-m"),
                OsString::from(message),
            ],
        )?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "`git commit-tree` failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        // The child has exited with the object written and the id is not yet
        // recorded. This is the whole of `IdUnread`.
        point(hooks, site, SubEffectPoint::IdUnread)?;
        let id = String::from_utf8(output.stdout)
            .map_err(|error| TactusError::Git {
                message: format!("`git commit-tree` printed a non-UTF-8 id: {error}"),
            })?
            .trim()
            .to_owned();
        apply(hooks.phase(site, HookPhase::After), site, HookPhase::After)?;
        Ok(id)
    }

    /// `Object.ProposalCherryPick` — the proposal commit and its merge objects
    /// in the staging worktree of a stale candidate.
    ///
    /// Never executed for an exact-base fast sequence: `snapshots` and
    /// `resource_accounting[R10]` both say the staging worktree is "never
    /// created for an exact-base fast sequence", and the fast path's
    /// no-execution entry is asserted against that.
    ///
    /// # Errors
    ///
    /// The containment refusals or a Git error.
    pub fn proposal_cherry_pick(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
        commit: &str,
    ) -> Result<String, TactusError> {
        self.revalidate()?;
        let path = self.slot_target(slot)?;
        funnel(
            hooks,
            EffectSiteId::Object(ObjectSite::ProposalCherryPick),
            || {
                let mut argv: Vec<OsString> = Self::PROPOSAL_CHERRY_PICK_ARGV
                    .iter()
                    .map(OsString::from)
                    .collect();
                argv.push(OsString::from(commit));
                self.git_ok(&path, &argv)?;
                self.git_line(&path, &["rev-parse", "HEAD"])
            },
        )
    }

    /// `Object.RepairMaterialize` — `git cherry-pick --no-commit` in a repair
    /// worktree.
    ///
    /// The merge objects it writes are referenced by that worktree's index: R9.
    /// `--no-commit` deliberately leaves `CHERRY_PICK_HEAD` behind, which is
    /// why the residue classifier reads the *index* for this site's after
    /// phase and never reads `CHERRY_PICK_HEAD` as residue on its own here.
    ///
    /// # Errors
    ///
    /// The containment refusals or a Git error.
    pub fn repair_materialize(
        &self,
        hooks: &mut dyn EffectHooks,
        slot: &Slot,
        commit: &str,
    ) -> Result<(), TactusError> {
        self.revalidate()?;
        let path = self.slot_target(slot)?;
        funnel(
            hooks,
            EffectSiteId::Object(ObjectSite::RepairMaterialize),
            || {
                self.git_ok(
                    &path,
                    &[
                        OsString::from("cherry-pick"),
                        OsString::from("--no-commit"),
                        OsString::from(commit),
                    ],
                )?;
                Ok(())
            },
        )
    }

    // -----------------------------------------------------------------------
    // Byte-safe changed paths
    // -----------------------------------------------------------------------

    /// The paths a worktree's index changed against `base`, byte-safely.
    ///
    /// `topology::paths::PathSet::RepoWide` is "the classification for an
    /// absent, unsafe, unparsable, or **undecodable** answer", and
    /// `GitPath`'s own documentation says "paths that did not decode are never
    /// stored". So the capture reads `-z` bytes, never lines, and one
    /// undecodable path makes the whole answer repo-wide rather than a silently
    /// shorter list.
    ///
    /// # Why `--name-status -M` and not `--name-only`
    ///
    /// `decisions.admission_and_leases.path_policy.actual` is "`git diff-tree
    /// -r -z -M --name-status base tree`; **both rename endpoints**", and
    /// `--name-only` cannot satisfy that sentence. Rename detection is Git's
    /// **default** (`diff.renames` has been true since 2.9), and a detected
    /// rename under `--name-only` prints the destination alone — measured on
    /// git 2.43, where staging `src/auth.rs -> archive/auth.rs` printed
    /// `archive/auth.rs` and nothing else. The old endpoint is the one another
    /// owner may hold a lease on, so dropping it lets two overlapping edits be
    /// admitted at once, which is exactly what `overlap` exists to prevent
    /// (`PR5-CORRECTNESS-005`).
    ///
    /// `-M` is passed explicitly rather than left to configuration, so the
    /// records do not depend on the operator's `diff.renames`, and the status
    /// field is what tells a two-endpoint record from a one-endpoint one.
    ///
    /// `git diff --cached <base>` rather than the passage's `diff-tree base
    /// tree`: this primitive is asked what a worktree's *index* holds, which is
    /// the tree that has not been written yet. The two produce byte-identical
    /// `-z --name-status` records for the same content — measured — and `-r` is
    /// a `diff-tree` option only, because `git diff` always recurses.
    ///
    /// # Errors
    ///
    /// The containment refusals or a Git error.
    pub fn changed_paths(&self, slot: &Slot, base: &str) -> Result<PathSet, TactusError> {
        self.revalidate()?;
        let path = self.slot_target(slot)?;
        let output = self.git_ok(
            &path,
            &[
                OsString::from("diff"),
                OsString::from("--cached"),
                OsString::from("--name-status"),
                OsString::from("-M"),
                OsString::from("-z"),
                OsString::from(base),
            ],
        )?;
        Ok(decode_changed_paths(&output))
    }

    // -----------------------------------------------------------------------
    // Git plumbing
    // -----------------------------------------------------------------------

    /// Run Git in `cwd` with every repository hook and the fsmonitor disabled.
    fn git(&self, cwd: &Path, args: &[OsString]) -> Result<Output, TactusError> {
        self.command(cwd, args)
            .output()
            .map_err(|error| TactusError::Git {
                message: format!("failed to run git: {error}"),
            })
    }

    fn command(&self, cwd: &Path, args: &[OsString]) -> Command {
        let mut hooks_config = OsString::from("core.hooksPath=");
        hooks_config.push(self.hooks_dir());
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(cwd)
            .arg("-c")
            .arg(hooks_config)
            .args(["-c", "core.fsmonitor=false"])
            .args(["-c", "protocol.file.allow=never"])
            .args(args)
            .stdin(Stdio::null());
        command
    }

    fn git_with_identity(&self, cwd: &Path, args: &[OsString]) -> Result<Output, TactusError> {
        self.command(cwd, args)
            // Environment identity overrides repository and global config and
            // any inherited GIT_AUTHOR_*/GIT_COMMITTER_*, so a commit-tree is a
            // function of its inputs and not of the machine.
            .env("GIT_AUTHOR_NAME", "tactus")
            .env("GIT_AUTHOR_EMAIL", "tactus@tactus.local")
            .env("GIT_AUTHOR_DATE", "@0 +0000")
            .env("GIT_COMMITTER_NAME", "tactus")
            .env("GIT_COMMITTER_EMAIL", "tactus@tactus.local")
            .env("GIT_COMMITTER_DATE", "@0 +0000")
            .output()
            .map_err(|error| TactusError::Git {
                message: format!("failed to run git: {error}"),
            })
    }

    fn git_ok(&self, cwd: &Path, args: &[OsString]) -> Result<Vec<u8>, TactusError> {
        let output = self.git(cwd, args)?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "git {} failed in {}: {}",
                    args.iter()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join(" "),
                    cwd.display(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(output.stdout)
    }

    fn git_line(&self, cwd: &Path, args: &[&str]) -> Result<String, TactusError> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let output = self.git_ok(cwd, &argv)?;
        let text = String::from_utf8(output).map_err(|error| TactusError::Git {
            message: format!("git {} returned non-UTF-8 output: {error}", args.join(" ")),
        })?;
        Ok(text.trim().to_owned())
    }

    /// Every registered worktree of the managed repository.
    ///
    /// # Errors
    ///
    /// A Git error.
    pub fn worktree_records(&self) -> Result<Vec<WorktreeRecord>, TactusError> {
        let output = self.git_ok(
            &self.base,
            &[
                OsString::from("worktree"),
                OsString::from("list"),
                OsString::from("--porcelain"),
                OsString::from("-z"),
            ],
        )?;
        Ok(parse_worktree_records(&output))
    }

    fn worktree_record(&self, path: &Path) -> Result<Option<WorktreeRecord>, TactusError> {
        let wanted = canonical_prefix(path)?;
        for record in self.worktree_records()? {
            if canonical_prefix(&record.path)? == wanted {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// The per-worktree administrative directory of a linked worktree.
    fn worktree_git_dir(&self, path: &Path) -> Result<Option<PathBuf>, TactusError> {
        let pointer = path.join(".git");
        let text = match fs::read_to_string(&pointer) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(TactusError::Io {
                    path: pointer,
                    source,
                });
            }
        };
        let Some(target) = text.trim().strip_prefix("gitdir:") else {
            return Ok(None);
        };
        Ok(Some(PathBuf::from(target.trim())))
    }

    /// The administrative directory Git keeps for a registered worktree, found
    /// without trusting the checkout, so a removal can clear the
    /// `initializing` lock of a worktree whose directory is already gone.
    fn registered_admin_dir(&self, path: &Path) -> Result<Option<PathBuf>, TactusError> {
        if self.worktree_record(path)?.is_none() {
            return Ok(None);
        }
        let worktrees = self.common_git_dir.join("worktrees");
        let entries = match fs::read_dir(&worktrees) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(TactusError::Io {
                    path: worktrees,
                    source,
                });
            }
        };
        let wanted = canonical_prefix(path)?;
        for entry in entries {
            let entry = entry.map_err(|source| TactusError::Io {
                path: worktrees.clone(),
                source,
            })?;
            let gitdir = entry.path().join("gitdir");
            let Ok(text) = fs::read_to_string(&gitdir) else {
                continue;
            };
            let recorded = PathBuf::from(text.trim());
            let checkout = recorded.parent().unwrap_or(&recorded).to_path_buf();
            if canonical_prefix(&checkout)? == wanted {
                return Ok(Some(entry.path()));
            }
        }
        Ok(None)
    }
}

/// What a snapshot is checked out at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotInput {
    /// The integration case: an existing commit, and no object is created.
    Commit(String),
    /// The candidate case: a tree, for which the funnel first writes an
    /// ephemeral commit on `parent`.
    Tree {
        /// The immutable tree under judgment.
        tree: String,
        /// The recorded parent the ephemeral commit sits on.
        parent: String,
    },
}

/// One live exact snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Its slot.
    pub slot: Slot,
    /// Its checkout.
    pub path: PathBuf,
    /// The commit its detached HEAD names.
    pub head: String,
    /// The ephemeral commit this snapshot created, when its input was a tree.
    /// It returns to R27 when the snapshot is removed.
    pub ephemeral: Option<String>,
}

// ---------------------------------------------------------------------------
// Residue classification
// ---------------------------------------------------------------------------

/// What the parent recorded of a site's after-phase publication.
///
/// **The packet writes the predicate as `classify_object_residue(site,
/// worktree)`** (`decisions.effect_site_inventory.command_internal_sub_effects`),
/// and for five of the nine sites that is all it needs. For the other four it
/// is not implementable, and the reason is a property of Git rather than of
/// this module: `write-tree`, the two commit-tree sites, and the proposal
/// cherry-pick publish a **content-addressed** object, so "the command
/// completed" and "the command never ran" leave object stores that differ only
/// in an object whose name the classifier would have to compute — and computing
/// it is the effect. So the second argument carries the worktree *and* what the
/// parent recorded, which is exactly the datum `IdUnread` is defined by the
/// absence of.
///
/// [`Self::new`] is the five-site form; [`Self::published`] adds the record.
#[derive(Debug, Clone)]
pub struct ResidueTarget<'a> {
    repository: &'a Path,
    worktree: &'a Path,
    published: Option<&'a str>,
    base: Option<&'a str>,
}

impl<'a> ResidueTarget<'a> {
    /// The worktree the site's Git command ran in — for the two commit-tree
    /// sites, the repository the object was written into.
    #[must_use]
    pub fn new(repository: &'a Path) -> Self {
        Self {
            repository,
            worktree: repository,
            published: None,
            base: None,
        }
    }

    /// The site's owning worktree, when it is not the repository itself.
    ///
    /// Given separately because the worktree of a killed `worktree add` may not
    /// exist at all, and a classifier that asked *it* which worktrees are
    /// registered would answer "none registered" for the very residue it is
    /// there to recognise.
    #[must_use]
    pub fn at(mut self, worktree: &'a Path) -> Self {
        self.worktree = worktree;
        self
    }

    /// The object id the parent read and recorded, for the sites whose
    /// after-phase reference is a **content-addressed object** it must name to
    /// tell "written" from "never written".
    #[must_use]
    pub fn published(mut self, object: &'a str) -> Self {
        self.published = Some(object);
        self
    }

    /// The commit the site's worktree was checked out at, for the site whose
    /// after-phase reference is *movement* of that worktree's HEAD.
    ///
    /// `Object.ProposalCherryPick` is the one: `resource_accounting[R10]` says
    /// "its detached HEAD and index reference the proposal commit … while it
    /// exists", so the after phase is a fact about the staging HEAD rather than
    /// about anything the parent recorded — and the base it moved off is known
    /// before the command runs, because `Worktree.AddStaging` checked it out.
    /// A kill therefore cannot lose it, which is why this site does not need
    /// the parent's record the way the object-printing sites do.
    #[must_use]
    pub fn from_base(mut self, base: &'a str) -> Self {
        self.base = Some(base);
        self
    }

    /// The repository the objects live in.
    #[must_use]
    pub fn repository(&self) -> &Path {
        self.repository
    }

    /// The worktree.
    #[must_use]
    pub fn worktree(&self) -> &Path {
        self.worktree
    }
}

/// Every site the classifier is total over, derived from the frozen enums.
///
/// `command_internal_sub_effects`: "the classifier is total over `{None,
/// Internal, After}` for **every Object site** and for `Worktree.Add` /
/// `Snapshot.Add`". The list is not written out here: it is every site whose
/// `residue_classes()` is non-empty, which is what PR3 froze and what
/// `ObjectSite::residue_classes` and `WorktreeSite::residue_classes` answer.
/// Enumerating it by hand is the `bounded_grid` failure this project has
/// recorded three times — a grid over the sites its author remembered.
#[must_use]
pub fn residue_classified_sites() -> Vec<EffectSiteId> {
    EffectSiteId::all()
        .into_iter()
        .filter(|site| !site.residue_classes().is_empty())
        .collect()
}

/// The read-only inspection predicate of
/// `decisions.effect_site_inventory.command_internal_sub_effects`.
///
/// > "the prefix objects-written-reference-unpublished is registered as the
/// > residue class `ObjectResidue::Internal`, defined by the read-only
/// > inspection predicate `classify_object_residue(site, worktree)`: unreachable
/// > objects per `git fsck --unreachable` and/or Git temporary object files
/// > (R27; Git prunes both) plus administrative residue in the owning
/// > worktree's git dir … or a registered-but-unpopulated worktree, **with the
/// > after-phase reference absent**".
///
/// The order is that sentence's: the after-phase reference decides `After`
/// first, and only its absence lets residue decide `Internal`.
///
/// Read-only. Nothing here writes an object, moves a ref, or touches an index.
///
/// # Errors
///
/// A Git or I/O error, or [`TactusError::Refused`] for a site the frozen enums
/// register no residue class for — the classifier is total over its domain and
/// silent outside it, rather than answering `None` for a question nobody asked.
pub fn classify_object_residue(
    site: EffectSiteId,
    target: &ResidueTarget<'_>,
) -> Result<ObjectResidue, TactusError> {
    if site.residue_classes().is_empty() {
        return Err(TactusError::Refused {
            message: format!(
                "`{site}` registers no residue class, so classify_object_residue has nothing to \
                 be total over there"
            ),
        });
    }
    if after_reference_present(site, target)? {
        return Ok(ObjectResidue::After);
    }
    if internal_residue_present(site, target)? {
        return Ok(ObjectResidue::Internal);
    }
    Ok(ObjectResidue::None)
}

/// Whether the site's after-phase reference is present.
fn after_reference_present(
    site: EffectSiteId,
    target: &ResidueTarget<'_>,
) -> Result<bool, TactusError> {
    let worktree = target.worktree;
    let repository = target.repository;
    match site {
        // The three adds: registered *and* populated. `git worktree add` holds
        // an `initializing` lock for the whole of its run, so a surviving lock
        // is Git's own statement that the population did not finish.
        EffectSiteId::Worktree(WorktreeSite::Add | WorktreeSite::AddStaging)
        | EffectSiteId::Snapshot(SnapshotSite::Add) => {
            let Some(record) = record_for(repository, worktree)? else {
                return Ok(false);
            };
            Ok(record.locked.as_deref() != Some("initializing") && worktree.join(".git").exists())
        }
        // `git add -A` publishes its blobs by renaming index.lock over index.
        // A surviving lock is proof the publication did not happen; otherwise
        // the after state is an index that reflects the working tree.
        EffectSiteId::Object(ObjectSite::CandidateStage) => {
            if index_lock_present(worktree)? {
                return Ok(false);
            }
            Ok(!worktree_has_unstaged_changes(worktree)?)
        }
        // `write-tree` publishes its trees through the index's cache-tree
        // extension, which is a fsck root — so the recorded tree being present
        // *and reachable* is the after phase, and an unreachable one is the
        // interrupted prefix.
        EffectSiteId::Object(ObjectSite::CandidateWriteTree) => {
            if index_lock_present(worktree)? {
                return Ok(false);
            }
            let Some(published) = target.published else {
                return Ok(false);
            };
            Ok(object_exists(repository, published)?
                && !unreachable_objects(repository)?
                    .iter()
                    .any(|id| id == published))
        }
        // The commit-tree sites: `AfterEffect::Unreferenced`. The object is
        // present and nothing references it — the after phase and the R27
        // residue differ only in whether the parent recorded the id, which is
        // what `IdUnread` is.
        EffectSiteId::Object(ObjectSite::SnapshotCommitTree | ObjectSite::CandidateCommitTree) => {
            let Some(published) = target.published else {
                return Ok(false);
            };
            object_exists(repository, published)
        }
        // The proposal cherry-pick publishes its objects through the staging
        // HEAD.
        EffectSiteId::Object(ObjectSite::ProposalCherryPick) => {
            if index_lock_present(worktree)? {
                return Ok(false);
            }
            let Some(head) = head_commit(worktree)? else {
                return Ok(false);
            };
            if let Some(published) = target.published {
                return Ok(head == published);
            }
            Ok(target.base.is_some_and(|base| head != base))
        }
        // `cherry-pick --no-commit` publishes its merge objects through the
        // repair worktree's index. CHERRY_PICK_HEAD survives a *successful*
        // `--no-commit`, so it is never the discriminator here.
        EffectSiteId::Object(ObjectSite::RepairMaterialize) => {
            if index_lock_present(worktree)? {
                return Ok(false);
            }
            index_differs_from_head(worktree)
        }
        other => Err(TactusError::Refused {
            message: format!("`{other}` has no after-phase reference the classifier knows"),
        }),
    }
}

/// Whether the command-internal residue of `site` is present.
fn internal_residue_present(
    site: EffectSiteId,
    target: &ResidueTarget<'_>,
) -> Result<bool, TactusError> {
    Ok(!observed_residue_elements(site, target)?.is_empty())
}

/// Which of the site's own registered residue elements are present.
///
/// The element list is [`EffectSiteId::residue_elements`] — PR3's, frozen —
/// rather than a list written here. A classifier that recognised elements its
/// site does not register would answer `Internal` for states the fault matrix
/// never tables, and one that recognised fewer would answer `None` for durable
/// state no action recovers.
///
/// # Errors
///
/// A Git or I/O error.
pub fn observed_residue_elements(
    site: EffectSiteId,
    target: &ResidueTarget<'_>,
) -> Result<Vec<ResidueElement>, TactusError> {
    let worktree = target.worktree;
    let repository = target.repository;
    let mut present = Vec::new();
    let git_dir = git_dir_of(worktree)?;
    for element in site.residue_elements() {
        let seen = match element {
            ResidueElement::UnreferencedObject => {
                let unreachable = unreachable_objects(repository)?;
                match target.published {
                    Some(published) => unreachable.iter().any(|id| id != published),
                    None => !unreachable.is_empty(),
                }
            }
            ResidueElement::TemporaryObjectFile => temporary_object_files(repository)?,
            ResidueElement::IndexLock => git_dir
                .as_ref()
                .is_some_and(|dir| dir.join("index.lock").exists()),
            ResidueElement::CherryPickHead => git_dir
                .as_ref()
                .is_some_and(|dir| dir.join("CHERRY_PICK_HEAD").exists()),
            ResidueElement::MergeHead => git_dir
                .as_ref()
                .is_some_and(|dir| dir.join("MERGE_HEAD").exists()),
            ResidueElement::MergeMsg => git_dir
                .as_ref()
                .is_some_and(|dir| dir.join("MERGE_MSG").exists()),
            ResidueElement::OrigHead => git_dir
                .as_ref()
                .is_some_and(|dir| dir.join("ORIG_HEAD").exists()),
            ResidueElement::SequencerState => git_dir
                .as_ref()
                .is_some_and(|dir| dir.join("sequencer").exists()),
            ResidueElement::RegisteredUnpopulatedWorktree => record_for(repository, worktree)?
                .is_some_and(|record| {
                    record.locked.as_deref() == Some("initializing")
                        || !worktree.join(".git").exists()
                }),
        };
        if seen {
            present.push(*element);
        }
    }
    Ok(present)
}

/// Whether an element makes the worktree it sits in non-quiescent.
///
/// **A counted, stated boundary.** `command_internal_sub_effects` says of the
/// synthetic evidence that for each element "`classify_object_residue` returns
/// `Internal`, **`Worktree.Verify` fails**, and the tabled recovery converges".
/// That is true of every element that lives in the owning worktree's git dir
/// and of a registered-but-unpopulated worktree. It is *not* true of
/// [`ResidueElement::UnreferencedObject`] or
/// [`ResidueElement::TemporaryObjectFile`]: those live in the shared object
/// store, are R27 — "Git's" — and are left by ordinary Git use (every amended
/// commit leaves one). A `Worktree.Verify` that consulted the object store
/// would refuse to reuse an `OpenNoAttempt` worktree in essentially every real
/// repository, which `decisions.workspace_candidates.generation` requires it to
/// reuse.
///
/// So the suite asserts the `Verify`-fails half for the elements it holds of,
/// asserts its *negation* for the other two, and asserts the partition as a
/// count — see `every_registered_residue_element_is_constructed_and_recovers`.
#[must_use]
pub const fn element_breaks_quiescence(element: ResidueElement) -> bool {
    match element {
        ResidueElement::UnreferencedObject | ResidueElement::TemporaryObjectFile => false,
        ResidueElement::IndexLock
        | ResidueElement::CherryPickHead
        | ResidueElement::MergeHead
        | ResidueElement::MergeMsg
        | ResidueElement::OrigHead
        | ResidueElement::SequencerState
        | ResidueElement::RegisteredUnpopulatedWorktree => true,
    }
}

/// The administrative residue in one worktree's git dir, in the order
/// `command_internal_sub_effects` lists it.
///
/// `ORIG_HEAD` is deliberately absent from what makes a worktree non-quiescent
/// here even though the sentence lists it: no site's frozen
/// `residue_elements()` registers it, and `git reset`, `git merge` and
/// `git rebase` all write one in the ordinary course of events, so reading it
/// as evidence of an interrupted command would close generations that are
/// perfectly reusable. Recorded rather than silently dropped.
fn administrative_residue_at(git_dir: &Path) -> Result<Vec<ResidueElement>, TactusError> {
    let mut present = Vec::new();
    for (name, element) in [
        ("index.lock", ResidueElement::IndexLock),
        ("CHERRY_PICK_HEAD", ResidueElement::CherryPickHead),
        ("MERGE_HEAD", ResidueElement::MergeHead),
        ("MERGE_MSG", ResidueElement::MergeMsg),
        ("sequencer", ResidueElement::SequencerState),
        ("rebase-merge", ResidueElement::SequencerState),
        ("rebase-apply", ResidueElement::SequencerState),
        ("REVERT_HEAD", ResidueElement::SequencerState),
    ] {
        if git_dir.join(name).exists() {
            present.push(element);
        }
    }
    Ok(present)
}

fn git_dir_of(worktree: &Path) -> Result<Option<PathBuf>, TactusError> {
    let pointer = worktree.join(".git");
    match fs::metadata(&pointer) {
        Ok(metadata) if metadata.is_dir() => return Ok(Some(pointer)),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(TactusError::Io {
                path: pointer,
                source,
            });
        }
    }
    let text = fs::read_to_string(&pointer).map_err(|source| TactusError::Io {
        path: pointer.clone(),
        source,
    })?;
    Ok(text
        .trim()
        .strip_prefix("gitdir:")
        .map(|target| PathBuf::from(target.trim())))
}

fn read_only_git(cwd: &Path, args: &[&str]) -> Result<Output, TactusError> {
    Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["-c", "core.fsmonitor=false"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| TactusError::Git {
            message: format!("failed to run git: {error}"),
        })
}

fn read_only_git_ok(cwd: &Path, args: &[&str]) -> Result<Vec<u8>, TactusError> {
    let output = read_only_git(cwd, args)?;
    if !output.status.success() {
        return Err(TactusError::Git {
            message: format!(
                "git {} failed in {}: {}",
                args.join(" "),
                cwd.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(output.stdout)
}

/// Every object `git fsck --unreachable` reports, and nothing else.
///
/// # Errors
///
/// A Git error.
pub fn unreachable_objects(worktree: &Path) -> Result<Vec<String>, TactusError> {
    let output = read_only_git(
        worktree,
        &[
            "fsck",
            "--unreachable",
            "--no-progress",
            "--no-dangling",
            "--connectivity-only",
        ],
    )?;
    let listing = String::from_utf8_lossy(&output.stdout);
    Ok(listing
        .lines()
        .filter_map(|line| line.strip_prefix("unreachable "))
        .filter_map(|rest| rest.split_whitespace().nth(1))
        .map(std::borrow::ToOwned::to_owned)
        .collect())
}

/// Whether Git's own temporary object files are present.
///
/// Git writes a loose object to `objects/tmp_obj_XXXXXX` and renames it into
/// place, and packs to `objects/pack/tmp_pack_*`. `resource_accounting[R27]`
/// accounts for both and says "Git prunes temporary object files itself".
///
/// # Errors
///
/// A Git or I/O error.
pub fn temporary_object_files(worktree: &Path) -> Result<bool, TactusError> {
    let object_dir = object_directory(worktree)?;
    for (directory, prefix) in [
        (object_dir.clone(), "tmp_obj_"),
        (object_dir.join("pack"), "tmp_pack_"),
    ] {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(TactusError::Io {
                    path: directory,
                    source,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|source| TactusError::Io {
                path: directory.clone(),
                source,
            })?;
            if entry.file_name().to_string_lossy().starts_with(prefix) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The repository's object directory.
///
/// # Errors
///
/// A Git error.
pub fn object_directory(worktree: &Path) -> Result<PathBuf, TactusError> {
    let output = read_only_git_ok(
        worktree,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
    )?;
    let text = String::from_utf8(output).map_err(|error| TactusError::Git {
        message: format!("`git rev-parse --git-path objects` returned non-UTF-8: {error}"),
    })?;
    Ok(PathBuf::from(text.trim()))
}

fn object_exists(worktree: &Path, object: &str) -> Result<bool, TactusError> {
    let output = read_only_git(worktree, &["cat-file", "-e", &format!("{object}^{{}}")])?;
    Ok(output.status.success())
}

fn head_commit(worktree: &Path) -> Result<Option<String>, TactusError> {
    let output = read_only_git(worktree, &["rev-parse", "--verify", "--quiet", "HEAD"])?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
    ))
}

fn index_lock_present(worktree: &Path) -> Result<bool, TactusError> {
    Ok(git_dir_of(worktree)?.is_some_and(|dir| dir.join("index.lock").exists()))
}

/// Whether anything in the working tree is not yet in the index.
fn worktree_has_unstaged_changes(worktree: &Path) -> Result<bool, TactusError> {
    // `--no-renames` is load-bearing, not tidiness: `status --porcelain -z`
    // detects renames by default and then emits `R  <new>\0<old>\0`, so the
    // *old path* arrives as a bare field whose second byte is a path character
    // and would be read as an unstaged status.
    let output = read_only_git_ok(
        worktree,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--no-renames",
            "--untracked-files=all",
        ],
    )?;
    for entry in output.split(|byte| *byte == 0) {
        if entry.len() < 2 {
            continue;
        }
        let worktree_status = entry[1];
        if worktree_status != b' ' {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the index has anything staged against HEAD.
fn index_differs_from_head(worktree: &Path) -> Result<bool, TactusError> {
    let output = read_only_git(worktree, &["diff", "--cached", "--quiet"])?;
    Ok(!output.status.success())
}

/// The registration `repository` holds for `worktree`, if any.
///
/// The question is asked of the **repository**, never of the worktree: a killed
/// `git worktree add` can leave a registration whose checkout directory does not
/// exist, and asking a directory that is not there — or asking its parent, which
/// is inside the execution root and is not a repository at all — would answer
/// "nothing is registered" for exactly the residue this is here to see.
fn record_for(repository: &Path, worktree: &Path) -> Result<Option<WorktreeRecord>, TactusError> {
    let output = read_only_git(repository, &["worktree", "list", "--porcelain", "-z"])?;
    if !output.status.success() {
        return Ok(None);
    }
    let wanted = canonical_prefix(worktree)?;
    for record in parse_worktree_records(&output.stdout) {
        if canonical_prefix(&record.path)? == wanted {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// Whether `value` is a full hexadecimal object id of either hash length.
#[must_use]
pub fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `value` is the null object id of either hash length.
#[must_use]
pub fn is_null_object_id(value: &str) -> bool {
    is_object_id(value) && value.bytes().all(|byte| byte == b'0')
}

fn refuse_malformed_object_id(
    refname: &str,
    role: &'static str,
    value: &str,
) -> Result<(), TactusError> {
    if is_object_id(value) {
        return Ok(());
    }
    Err(Refusal::MalformedObjectId {
        refname: refname.to_owned(),
        role,
        value: value.to_owned(),
    }
    .into())
}

/// The expected-old side of every move and delete: a well-formed, non-null id.
fn refuse_expected_old(refname: &str, old: &str) -> Result<(), TactusError> {
    refuse_malformed_object_id(refname, "expected-old", old)?;
    if is_null_object_id(old) {
        return Err(Refusal::NullExpectedOld {
            refname: refname.to_owned(),
        }
        .into());
    }
    Ok(())
}

/// Turn `git diff --name-status -M -z` bytes into a [`PathSet`].
///
/// A separate function from [`WorkspaceManager::changed_paths`] so the hostile
/// byte cases — an undecodable path, an embedded newline, a path that is
/// nothing but a delimiter — can be exercised on every platform rather than
/// only on the one whose filesystem can hold them.
///
/// # The record grammar
///
/// `-z --name-status` emits NUL-*terminated* fields, one status field followed
/// by the paths that status has: `A\0path\0`, `D\0path\0`, `M\0path\0`, and for
/// a detected rename or copy **two** — `R100\0old\0new\0`. Both are kept, which
/// is `path_policy.actual`'s "both rename endpoints": the old endpoint is the
/// one another owner may already hold a lease on, and an answer that omits it
/// is silently smaller than the diff.
///
/// # Why unparsable is repo-wide, not shorter
///
/// One undecodable path makes the **whole** answer [`PathSet::RepoWide`], and
/// so does a status field this grammar does not recognise. The alternative,
/// dropping it and returning the rest, would hand the merge queue a region that
/// is silently *smaller* than the diff and let two overlapping tasks run in
/// parallel; `GitPath`'s own contract is that "paths that did not decode are
/// never stored", and `prediction` classifies "unsafe or unparsable forms" as
/// repo-wide. Repo-wide overlaps everything, so it is the direction that
/// refuses rather than the one that admits.
#[must_use]
pub fn decode_changed_paths(bytes: &[u8]) -> PathSet {
    let mut paths = Vec::new();
    let mut fields = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty());
    while let Some(status) = fields.next() {
        let Some(endpoints) = status_endpoints(status) else {
            return PathSet::RepoWide;
        };
        for _ in 0..endpoints {
            // A record that stops mid-way is a truncated answer, and a
            // truncated answer is a shorter region.
            let Some(field) = fields.next() else {
                return PathSet::RepoWide;
            };
            match std::str::from_utf8(field) {
                Ok(decoded) => paths.push(GitPath::from(decoded)),
                Err(_) => return PathSet::RepoWide,
            }
        }
    }
    paths.sort();
    paths.dedup();
    PathSet::Prefixes { paths }
}

/// How many path fields a `--name-status` status field is followed by, or
/// `None` when this is not a status field at all.
///
/// The letters are `git diff`'s own documented set. `R` and `C` carry a
/// similarity score and two endpoints; everything else carries one and no
/// score. Anything else — including a path that arrived where a status was
/// expected, which is what a decoder reading `--name-only` output would see —
/// is unparsable and makes the answer repo-wide.
fn status_endpoints(status: &[u8]) -> Option<usize> {
    let (letter, score) = status.split_first()?;
    match letter {
        b'R' | b'C' => score
            .iter()
            .all(u8::is_ascii_digit)
            .then_some(2)
            .filter(|_| !score.is_empty()),
        b'A' | b'D' | b'M' | b'T' | b'U' | b'X' => score.is_empty().then_some(1),
        _ => None,
    }
}

/// Parse `git worktree list --porcelain -z`.
///
/// Attributes are NUL-terminated and an empty attribute ends a record. Paths
/// are taken as bytes, because a repository path need not be UTF-8 on Unix.
fn parse_worktree_records(bytes: &[u8]) -> Vec<WorktreeRecord> {
    let mut records = Vec::new();
    let mut current: Option<WorktreeRecord> = None;
    for field in bytes.split(|byte| *byte == 0) {
        if field.is_empty() {
            if let Some(record) = current.take() {
                records.push(record);
            }
            continue;
        }
        if let Some(path) = field.strip_prefix(b"worktree ") {
            if let Some(record) = current.take() {
                records.push(record);
            }
            current = Some(WorktreeRecord {
                path: decode_git_path(path),
                head: None,
                branch: None,
                locked: None,
                prunable: None,
            });
            continue;
        }
        let Some(record) = current.as_mut() else {
            continue;
        };
        let text = String::from_utf8_lossy(field);
        let text = text.trim_end();
        if let Some(head) = text.strip_prefix("HEAD ") {
            record.head = Some(head.to_owned());
        } else if let Some(branch) = text.strip_prefix("branch ") {
            record.branch = Some(branch.to_owned());
        } else if text == "locked" {
            record.locked = Some(String::new());
        } else if let Some(reason) = text.strip_prefix("locked ") {
            record.locked = Some(reason.to_owned());
        } else if text == "prunable" {
            record.prunable = Some(String::new());
        } else if let Some(reason) = text.strip_prefix("prunable ") {
            record.prunable = Some(reason.to_owned());
        }
    }
    if let Some(record) = current.take() {
        records.push(record);
    }
    records
}

#[cfg(unix)]
fn decode_git_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

#[cfg(windows)]
fn decode_git_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).replace('/', "\\"))
}

#[cfg(not(any(unix, windows)))]
fn decode_git_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Small filesystem helpers
// ---------------------------------------------------------------------------

/// Write `bytes` durably: temporary, fsync, rename, fsync the directory.
///
/// Every one of those four steps that is a *durability* step records itself in
/// `ledger`, fused with the primitive it records — the sync and its entry are
/// one call, so a mutation that removes a step from this sequence removes its
/// evidence with it. The residual boundary is the same one the Event lane
/// states in writing: deleting the `sync_all` line *inside* the fused helper is
/// still undetectable by any test on a machine that does not lose power.
fn write_synced(path: &Path, bytes: &[u8], ledger: &DurabilityLedger) -> Result<(), TactusError> {
    let parent = path.parent().ok_or_else(|| TactusError::Git {
        message: format!("{} has no parent directory", path.display()),
    })?;
    fs::create_dir_all(parent).map_err(|source| TactusError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let staged = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&staged).map_err(|source| TactusError::Io {
            path: staged.clone(),
            source,
        })?;
        file.write_all(bytes).map_err(|source| TactusError::Io {
            path: staged.clone(),
            source,
        })?;
        sync_file_recorded(&file, &staged, ledger)?;
    }
    fs::rename(&staged, path).map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    ledger.record(
        DurableStep::Renamed,
        path,
        fs::metadata(path).map(|meta| meta.len()).unwrap_or(0),
    );
    sync_directory(parent, ledger)
}

/// fsync `file` and record what was made durable, in one call.
fn sync_file_recorded(
    file: &fs::File,
    path: &Path,
    ledger: &DurabilityLedger,
) -> Result<(), TactusError> {
    let io = |source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    };
    let outcome = crate::util::fsync_file(file);
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    ledger.record(DurableStep::SyncedFile, path, len);
    outcome.map_err(io)
}

/// fsync a directory, on every platform, and record it (`PR5-CONF-013`).
///
/// The barrier itself is [`crate::util::fsync_dir`], shared with the run-directory
/// and Event funnels so that the one Win32 recipe there is is written once.
fn sync_directory(path: &Path, ledger: &DurabilityLedger) -> Result<(), TactusError> {
    crate::util::fsync_dir(path).map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    ledger.record(DurableStep::SyncedDirectory, path, 0);
    Ok(())
}

fn directory_is_empty(path: &Path) -> Result<bool, TactusError> {
    match fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(source) => Err(TactusError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The repository's canonical common git dir.
fn common_git_dir(inside: &Path) -> Result<PathBuf, TactusError> {
    let output = read_only_git_ok(
        inside,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    let text = String::from_utf8(output).map_err(|error| TactusError::Git {
        message: format!("`git rev-parse --git-common-dir` returned non-UTF-8: {error}"),
    })?;
    let path = PathBuf::from(text.trim());
    fs::canonicalize(&path)
        .map(strip_verbatim)
        .map_err(|source| TactusError::Io { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::topology::effects::{
        ClassHistogram, Evidence, EvidenceLabel, SamplingRecord, SyntheticRecord,
    };

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    /// A scratch directory unique to this process *and* to this call, because
    /// the suite runs tests in parallel and two fixtures sharing a directory
    /// would each measure the other's Git repository.
    fn scratch(tag: &str) -> PathBuf {
        let ordinal = SCRATCH.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("tactus-wm-{tag}-{}-{ordinal}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    fn git_out(dir: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("run git")
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = git_out(dir, args);
        assert!(
            output.status.success(),
            "git {args:?} in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// A real repository, a real private root, and a manager over both.
    struct Fixture {
        root: PathBuf,
        base: PathBuf,
        private: PathBuf,
        manager: WorkspaceManager,
        /// The first commit.
        seed: String,
        /// The tip of `main`.
        head: String,
        /// A commit on a side branch, based on `seed`, for the cherry-picks.
        side: String,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = scratch(tag);
            let base = root.join("repo");
            let private = root.join("private");
            fs::create_dir_all(&base).expect("repo directory");
            fs::create_dir_all(&private).expect("private root");

            git(&base, &["init", "-q", "-b", "main"]);
            git(&base, &["config", "user.email", "tests@tactus.local"]);
            git(&base, &["config", "user.name", "tactus tests"]);
            // `git worktree add` writes a reflog entry; keep the repository
            // self-contained so nothing depends on a global config.
            git(&base, &["config", "core.logAllRefUpdates", "true"]);
            fs::write(base.join("a.txt"), "one\n").expect("seed file");
            git(&base, &["add", "-A"]);
            git(&base, &["commit", "-q", "-m", "seed"]);
            let seed = git(&base, &["rev-parse", "HEAD"]);

            fs::write(base.join("b.txt"), "two\n").expect("second file");
            git(&base, &["add", "-A"]);
            git(&base, &["commit", "-q", "-m", "second"]);
            let head = git(&base, &["rev-parse", "HEAD"]);

            git(&base, &["checkout", "-q", "-b", "side", &seed]);
            fs::write(base.join("c.txt"), "side\n").expect("side file");
            git(&base, &["add", "-A"]);
            git(&base, &["commit", "-q", "-m", "side"]);
            let side = git(&base, &["rev-parse", "HEAD"]);
            git(&base, &["checkout", "-q", "main"]);

            let manager = WorkspaceManager::derive(&base, &private, "run-1", "inc-1")
                .expect("derive the manager");
            Self {
                root,
                base,
                private,
                manager,
                seed,
                head,
                side,
            }
        }

        fn created(tag: &str) -> Self {
            let fixture = Self::new(tag);
            fixture
                .manager
                .create_execution_root(&mut NoHooks)
                .expect("create the execution root");
            fixture
        }

        fn task(&self, key: &str, generation: u32) -> Slot {
            Slot::Task {
                key: key.to_owned(),
                generation,
            }
        }

        /// A task worktree at `head`, intent first.
        fn add_task(&self, hooks: &mut dyn EffectHooks, key: &str, generation: u32) -> Slot {
            let slot = self.task(key, generation);
            self.manager
                .write_intent(hooks, &slot)
                .expect("write the intent");
            self.manager
                .add_worktree(hooks, &slot, &self.head)
                .expect("add the worktree");
            slot
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// A harness that answers `Proceed` and records everything.
    fn harness() -> (HarnessEffects, Arc<Mutex<HookHarness>>) {
        let shared = Arc::new(Mutex::new(HookHarness::new()));
        (HarnessEffects::new(Arc::clone(&shared)), shared)
    }

    fn refusal_of(error: &TactusError) -> String {
        error.to_string()
    }

    /// Every site the four groups this lane owns declare, derived from the
    /// enums rather than written out. A group that grows a variant grows this.
    fn lane_sites() -> Vec<EffectSiteId> {
        EffectSiteId::all()
            .into_iter()
            .filter(|site| {
                matches!(
                    site,
                    EffectSiteId::Worktree(_)
                        | EffectSiteId::Snapshot(_)
                        | EffectSiteId::Ref(_)
                        | EffectSiteId::Object(_)
                )
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // R18: repo_key and the execution root
    // -----------------------------------------------------------------------

    /// The digest is pinned against values computed **outside this program**,
    /// from the packet's formula, so the function is never its own oracle.
    ///
    /// `decisions.workspace_candidates.execution_root`: "repo_key v1 =
    /// hex16(sha256('tactus-repo-key-v1' NUL canonical common git dir bytes))".
    ///
    /// Independently computed with:
    /// `python3 -c "import hashlib;
    ///  print(hashlib.sha256(b'tactus-repo-key-v1\x00' + P).hexdigest()[:16])"`
    #[test]
    fn the_repo_key_is_the_packets_digest_and_not_a_neighbouring_one() {
        assert_eq!(
            repo_key_v1(Path::new("/srv/tactus/.git")),
            "75953321a59371e0",
            "the digest of the packet's own formula"
        );
        assert_eq!(
            repo_key_v1(Path::new("/srv/tactus/.git/")),
            "b79724b7e665f59c",
            "a trailing separator is different bytes and must be a different key"
        );
        assert_eq!(
            repo_key_v1(Path::new(r"C:\repos\tactus\.git")),
            "7d8548c4abb7eb31",
            "a Windows-shaped path hashes its own bytes on either platform"
        );

        // The two neighbouring formulas a transcription slip produces: the
        // domain prefix dropped, and the NUL separator dropped. Neither may be
        // what the function computes.
        assert_ne!(
            repo_key_v1(Path::new("/srv/tactus/.git")),
            "85185d58540dc79c",
            "the NUL separator is part of the formula"
        );
        assert_ne!(
            repo_key_v1(Path::new("/srv/tactus/.git")),
            "c2ed95c96b45a16d",
            "the domain prefix is `tactus-repo-key-v1`"
        );

        // hex16 is sixteen hexadecimal characters, and it is a prefix of the
        // full digest rather than a fold of it.
        let key = repo_key_v1(Path::new("/srv/tactus/.git"));
        assert_eq!(key.len(), 16);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(
            "75953321a59371e05b6a8adf8ad24da6752f85b84a984a0ac8b89163527c849d".starts_with(&key)
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_repo_key_hashes_path_bytes_a_string_cannot_carry() {
        use std::os::unix::ffi::OsStringExt as _;
        let path = PathBuf::from(OsString::from_vec(b"/tmp/\xff\xfe/.git".to_vec()));
        assert_eq!(
            repo_key_v1(&path),
            "1a9063bc0e2cb2e1",
            "a repository path is bytes on Unix, and the key is over those bytes"
        );
    }

    /// The property no digest constant can pin: the key is taken over the
    /// *common* git dir, so two linked worktrees of one repository agree and
    /// two repositories differ.
    #[test]
    fn the_repo_key_is_the_repositorys_and_not_the_worktrees() {
        let fixture = Fixture::created("repokey-common");
        let linked = fixture.root.join("linked");
        git(
            &fixture.base,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                &linked.to_string_lossy(),
                &fixture.head,
            ],
        );
        let from_linked =
            WorkspaceManager::derive(&linked, &fixture.private, "run-2", "inc-1").expect("derive");
        assert_eq!(
            from_linked.repo_key(),
            fixture.manager.repo_key(),
            "a linked worktree of the same repository has the same common git dir"
        );

        let other = Fixture::new("repokey-other");
        assert_ne!(
            other.manager.repo_key(),
            fixture.manager.repo_key(),
            "a different repository has a different common git dir"
        );

        git(
            &fixture.base,
            &["worktree", "remove", "--force", &linked.to_string_lossy()],
        );
    }

    #[test]
    fn the_execution_root_is_the_path_the_packet_names() {
        let fixture = Fixture::new("root-shape");
        // `strip_verbatim` on the canonical root, not the raw canonical root:
        // on Windows `fs::canonicalize` answers `\\?\C:\...`, which Git cannot
        // open, so the recorded root is the Win32 spelling of the same
        // directory. The expected value is built from the packet's own formula
        // — `<private_root>/workspaces/<repo_key>/<run_id>` — rather than from
        // the manager.
        let expected = strip_verbatim(
            fixture
                .private
                .canonicalize()
                .expect("canonical private root"),
        )
        .join("workspaces")
        .join(fixture.manager.repo_key())
        .join("run-1");
        assert_eq!(fixture.manager.execution_root(), expected.as_path());
        assert!(
            !fixture
                .manager
                .execution_root()
                .to_string_lossy()
                .contains("\\\\?\\"),
            "the recorded root is a path Git can open"
        );
    }

    #[test]
    fn the_execution_root_is_pruned_only_when_it_is_empty() {
        let fixture = Fixture::created("root-prune");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        assert!(
            !fixture
                .manager
                .remove_execution_root(&mut NoHooks)
                .expect("attempt the removal"),
            "R18 is pruned by finalization *when empty*; a live worktree is not empty"
        );
        assert!(fixture.manager.execution_root().is_dir());

        fixture
            .manager
            .remove_worktree(&mut NoHooks, &slot)
            .expect("forced removal");
        fixture
            .manager
            .remove_intent(&mut NoHooks, &slot)
            .expect("intent removal");
        assert!(
            fixture
                .manager
                .remove_execution_root(&mut NoHooks)
                .expect("remove the root"),
            "an empty root is pruned"
        );
        assert!(!fixture.manager.execution_root().exists());
    }

    // -----------------------------------------------------------------------
    // The containment refusals — real temp repositories, one test per reason
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn a_symlink_below_the_private_root_refuses_the_execution_root() {
        let fixture = Fixture::new("symlink-chain");
        let workspaces = fixture
            .private
            .canonicalize()
            .expect("canonical")
            .join("workspaces");
        let elsewhere = fixture.root.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("target directory");
        std::os::unix::fs::symlink(&elsewhere, &workspaces).expect("plant the symlink");

        let error = fixture
            .manager
            .create_execution_root(&mut NoHooks)
            .expect_err("a reparse point on the chain refuses");
        let message = refusal_of(&error);
        assert!(
            message.contains("symlink or reparse point"),
            "the refusal must name its reason, not merely fail: {message}"
        );
        assert!(
            message.contains(&workspaces.display().to_string()),
            "and name the component: {message}"
        );
        assert!(
            !fixture.manager.execution_root().exists(),
            "and perform no effect"
        );
    }

    /// The Windows half of `expected_failures_refusals[0]`: a **junction** is a
    /// reparse point that is not a symbolic link, so a refusal written against
    /// `FileType::is_symlink` alone would pass every Linux test and refuse
    /// nothing an operator can actually build with `mklink /J`.
    #[cfg(windows)]
    #[test]
    fn a_junction_below_the_private_root_refuses_the_execution_root() {
        let fixture = Fixture::new("junction-chain");
        let workspaces = fixture
            .private
            .canonicalize()
            .expect("canonical")
            .join("workspaces");
        let elsewhere = fixture.root.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("target directory");
        let made = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&workspaces)
            .arg(&elsewhere)
            .output()
            .expect("run mklink");
        assert!(
            made.status.success(),
            "the fixture must really create a junction: {}",
            String::from_utf8_lossy(&made.stderr)
        );

        // The premise this test exists to hold: a junction is *not* what
        // `FileType::is_symlink` is about on every reparse tag, so the check
        // has to read the attribute.
        let metadata = fs::symlink_metadata(&workspaces).expect("junction metadata");
        assert!(
            is_reparse_point(&metadata),
            "the detector must see a junction as a reparse point"
        );

        let error = fixture
            .manager
            .create_execution_root(&mut NoHooks)
            .expect_err("a junction on the chain refuses");
        let message = refusal_of(&error);
        assert!(
            message.contains("symlink or reparse point"),
            "the refusal must name its reason: {message}"
        );
        assert!(!fixture.manager.execution_root().exists());
    }

    /// A directory reparse point at `link` naming `target`, on either platform.
    ///
    /// A POSIX symlink and a Windows **junction** are the two shapes
    /// `expected_failures_refusals[0]` names ("symlink/junction on the chain"),
    /// and they are the two an operator can actually build: a Windows
    /// *symbolic* link needs a privilege the guest's test user does not have,
    /// while `mklink /J` needs none.
    fn plant_directory_link(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).expect("plant the symlink");
        #[cfg(windows)]
        {
            let made = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .expect("run mklink");
            assert!(
                made.status.success(),
                "the fixture must really create a junction: {}",
                String::from_utf8_lossy(&made.stderr)
            );
        }
        let metadata = fs::symlink_metadata(link).expect("link metadata");
        // The premise, asserted rather than assumed — and it is exactly the
        // difference between the two calls this test exists to keep apart.
        assert!(
            is_reparse_point(&metadata),
            "the fixture must really be a reparse point"
        );
        assert!(
            fs::metadata(link).expect("target metadata").is_dir(),
            "and it must resolve to a real directory, or a check that followed \
             it would refuse for the wrong reason"
        );
    }

    /// The **leaf** of the managed base and of the private root is a chain
    /// component too.
    ///
    /// `execution_root` is "created only when the managed base is a real
    /// directory with **no symlink/reparse point on the chain**", and
    /// `refuse_unreal_directory` is the only check either leaf gets:
    /// `reparse_point_below` walks the components *under* its anchor, and
    /// `canonical_prefix` resolves a link rather than refusing it. So a leaf
    /// that is a link to a real directory reaches every effect unless this
    /// function reads the link itself.
    ///
    /// `PR5-CORRECTNESS-003`: the existing coverage planted its link *below*
    /// the private root, where `refuse_reparse_points` catches it, so
    /// `fs::symlink_metadata` -> `fs::metadata` here survived the whole suite.
    ///
    /// All three call sites, because the class is the call and not the
    /// argument: `derive`'s base, `derive`'s private root, and `revalidate`'s
    /// base — the last reached by replacing an already-derived base with a link
    /// to itself, which is the sequence "every create/reclaim/delete
    /// revalidates" exists for.
    #[test]
    fn a_managed_base_or_private_root_that_is_itself_a_link_refuses_before_any_effect() {
        let mut refused = Vec::new();

        // (1) derive's base.
        let fixture = Fixture::new("leaf-link-base");
        let real = fixture.base.canonicalize().expect("canonical base");
        let link = fixture.root.join("base-link");
        plant_directory_link(&real, &link);
        let error = WorkspaceManager::derive(&link, &fixture.private, "run-9", "inc-1")
            .expect_err("a managed base that is a link refuses");
        refused.push(("derive/base", refusal_of(&error)));

        // (2) derive's private root.
        let fixture = Fixture::new("leaf-link-private");
        let real = fixture.private.canonicalize().expect("canonical private");
        let link = fixture.root.join("private-link");
        plant_directory_link(&real, &link);
        let error = WorkspaceManager::derive(&fixture.base, &link, "run-9", "inc-1")
            .expect_err("a private root that is a link refuses");
        refused.push(("derive/private-root", refusal_of(&error)));

        // (3) revalidate's base — the link arrives *after* derive succeeded.
        let fixture = Fixture::created("leaf-link-revalidate");
        let base = fixture.manager.base().to_path_buf();
        let moved = fixture.root.join("moved-away");
        fs::rename(&base, &moved).expect("move the real repository aside");
        plant_directory_link(&moved, &base);
        let error = fixture
            .manager
            .revalidate()
            .expect_err("a base that became a link refuses on revalidation");
        refused.push(("revalidate/base", refusal_of(&error)));
        // And the refusal reaches the primitives, not merely the private check.
        let slot = fixture.task("alpha", 1);
        fixture
            .manager
            .write_intent(&mut NoHooks, &slot)
            .expect_err("and every primitive revalidates first");

        assert_eq!(refused.len(), 3, "three call sites, each driven");
        for (site, message) in &refused {
            assert!(
                message.contains("not a real directory"),
                "{site}: the refusal must name its reason: {message}"
            );
        }
        // Distinct paths named, so one refusal cannot stand in for three.
        let named: std::collections::BTreeSet<&str> =
            refused.iter().map(|(site, _)| *site).collect();
        assert_eq!(named.len(), 3, "three distinct call sites: {named:?}");
    }

    /// A **deletion** revalidates the chain, and refuses before it acts
    /// (`PR5-WORKSPACE-009`).
    ///
    /// `execution_root`: "every create/reclaim/**delete** revalidates."
    /// `remove_execution_root` had three test callers and all three ran against
    /// an intact chain, so deleting its `self.revalidate()?;` line changed
    /// nothing observable — the create and reclaim thirds of the sentence were
    /// covered and the delete third was not. That third is the one where the
    /// consequence is a deletion outside the managed tree, so the sentinel here
    /// is *outside* the fixture and its bytes are compared after.
    #[test]
    fn a_deletion_revalidates_the_chain_and_refuses_before_it_deletes() {
        let fixture = Fixture::created("delete-revalidates");
        let sentinel_dir = fixture.root.join("outside");
        fs::create_dir_all(&sentinel_dir).expect("sentinel directory");
        let sentinel = sentinel_dir.join("keepme.txt");
        let sentinel_bytes = b"a file the managed tree has no business deleting";
        fs::write(&sentinel, sentinel_bytes).expect("sentinel");

        // A validated component of the chain becomes a link to the sentinel's
        // directory, after derive already succeeded.
        let base = fixture.manager.base().to_path_buf();
        let moved = fixture.root.join("moved-away");
        fs::rename(&base, &moved).expect("move the real repository aside");
        plant_directory_link(&moved, &base);

        let message = refusal_of(
            &fixture
                .manager
                .remove_execution_root(&mut NoHooks)
                .expect_err("a deletion on a chain that changed refuses"),
        );
        assert!(
            message.contains("not a real directory"),
            "the refusal must name its reason: {message}"
        );
        assert!(
            fixture.manager.execution_root().exists(),
            "and it refused BEFORE acting: the execution root is still there"
        );
        assert_eq!(
            fs::read(&sentinel).expect("sentinel"),
            sentinel_bytes,
            "the sentinel outside the managed tree is byte-identical"
        );
    }

    /// A **reclaim** revalidates the chain, and refuses before it removes
    /// anything.
    ///
    /// `execution_root`: "every create/**reclaim**/delete revalidates." The
    /// create third dies at
    /// `a_symlink_below_the_private_root_refuses_the_execution_root` and the
    /// delete third at the test above. The reclaim third had no fixture that
    /// could see it: deleting `reclaim_intents`' own `self.revalidate()?;`
    /// left the whole suite green on Linux and on the Windows guest.
    ///
    /// **The shape is what makes it visible, and it is not the obvious one.**
    /// `remove_worktree` and `remove_intent` each revalidate on their own
    /// before they act, so the outer check is masked the moment there is
    /// anything to remove — and every other fixture reaching `reclaim_intents`
    /// does so with at least one intent written. The one shape where the outer
    /// check is the sole guard is a reclaim over an execution root with **no
    /// intents**, where an unguarded version answers `Ok([])` instead of the
    /// containment refusal. The otherwise identical fixture that writes one
    /// intent first was measured against that same edit and does **not**
    /// distinguish it, so the emptiness below is the premise and is asserted
    /// rather than assumed.
    ///
    /// The sentinel is *outside* the fixture and its bytes are compared after,
    /// for the reason the deletion test gives: what a reclaim through an
    /// exchanged ancestor reaches is a removal outside the managed tree.
    #[test]
    fn a_reclaim_revalidates_the_chain_and_refuses_before_it_removes() {
        let fixture = Fixture::created("reclaim-revalidates");
        let sentinel_dir = fixture.root.join("outside");
        fs::create_dir_all(&sentinel_dir).expect("sentinel directory");
        let sentinel = sentinel_dir.join("keepme.txt");
        let sentinel_bytes = b"a file the managed tree has no business deleting";
        fs::write(&sentinel, sentinel_bytes).expect("sentinel");

        // The premise: nothing to remove, so no inner revalidation can stand in
        // for the outer one. A fixture that grew an intent here would still
        // pass and would stop measuring anything.
        assert!(
            fixture
                .manager
                .intents()
                .expect("the intents of a freshly created root")
                .is_empty(),
            "this fixture is the no-intent reclaim, and only that shape is \
             guarded by `reclaim_intents`' own revalidation"
        );

        // A validated component of the chain becomes a link to the sentinel's
        // directory, after derive already succeeded.
        let base = fixture.manager.base().to_path_buf();
        let moved = fixture.root.join("moved-away");
        fs::rename(&base, &moved).expect("move the real repository aside");
        plant_directory_link(&moved, &base);

        let message = refusal_of(
            &fixture
                .manager
                .reclaim_intents(&mut NoHooks)
                .expect_err("a reclaim on a chain that changed refuses"),
        );
        assert!(
            message.contains("not a real directory"),
            "the refusal must name its reason: {message}"
        );
        assert_eq!(
            fs::read(&sentinel).expect("sentinel"),
            sentinel_bytes,
            "the sentinel outside the managed tree is byte-identical"
        );
    }

    #[test]
    fn a_root_inside_a_repository_worktree_refuses() {
        let fixture = Fixture::new("root-inside");
        // The private root *is* the repository checkout: the execution root
        // would then live inside a worktree of the repository it manages.
        let error = WorkspaceManager::derive(&fixture.base, &fixture.base, "run-3", "inc-1")
            .expect_err("a root inside a repository worktree refuses");
        let message = refusal_of(&error);
        assert!(
            message.contains("inside the repository worktree"),
            "the refusal must name its reason: {message}"
        );
    }

    #[test]
    fn a_foreign_repository_worktree_inside_the_root_refuses() {
        let fixture = Fixture::created("worktree-inside");
        let intruder = fixture.manager.execution_root().join("intruder");
        git(
            &fixture.base,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                &intruder.to_string_lossy(),
                &fixture.head,
            ],
        );
        let error = fixture
            .manager
            .revalidate()
            .expect_err("a foreign worktree inside the root refuses");
        let message = refusal_of(&error);
        assert!(
            message.contains("is inside it"),
            "the refusal must name its reason: {message}"
        );

        // And the manager's own slots are not foreign, which is the half a
        // literal reading of the sentence would get wrong.
        git(
            &fixture.base,
            &["worktree", "remove", "--force", &intruder.to_string_lossy()],
        );
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        fixture
            .manager
            .revalidate()
            .expect("the manager's own worktree is not a foreign one");
        fixture
            .manager
            .remove_worktree(&mut NoHooks, &slot)
            .expect("remove");
    }

    #[test]
    fn nothing_outside_the_execution_root_is_ever_deleted() {
        let fixture = Fixture::created("containment");
        let outside = fixture.root.join("precious");
        fs::create_dir_all(&outside).expect("outside directory");
        fs::write(outside.join("keep.txt"), "keep\n").expect("outside file");

        let error = fixture
            .manager
            .contained(&outside)
            .expect_err("a path outside the root refuses");
        let message = refusal_of(&error);
        assert!(
            message.contains("outside the execution root"),
            "the refusal must name its reason: {message}"
        );
        assert!(outside.join("keep.txt").exists(), "and delete nothing");

        // The root itself is not inside itself: a removal that accepted it
        // would delete the whole root through a per-slot primitive.
        assert!(
            fixture
                .manager
                .contained(fixture.manager.execution_root())
                .is_err(),
            "the root is not a contained target of a slot removal"
        );
        fixture
            .manager
            .contained(&fixture.manager.execution_root().join("tasks").join("kx-g1"))
            .expect("a slot path is contained");
    }

    #[test]
    fn a_slot_name_that_could_escape_the_root_refuses() {
        let fixture = Fixture::created("slot-names");
        for hostile in ["..", "../escape", "a/b", "-force", "", "naïve"] {
            let slot = Slot::Task {
                key: hostile.to_owned(),
                generation: 1,
            };
            let error = fixture
                .manager
                .write_intent(&mut NoHooks, &slot)
                .expect_err("a hostile slot name refuses");
            let message = refusal_of(&error);
            assert!(
                message.contains("slot name"),
                "the refusal must name its reason for `{hostile}`: {message}"
            );
        }
        fixture
            .manager
            .write_intent(
                &mut NoHooks,
                &Slot::Task {
                    key: "ok_key-1".to_owned(),
                    generation: 1,
                },
            )
            .expect("a legal name is accepted");
    }

    /// The hostile slot names, one per **mechanism** by which a name escapes
    /// containment or changes a command's meaning.
    ///
    /// Kept as a table with its mechanism named so that hostility is a
    /// distinct-value count rather than a claim in prose: two entries that
    /// escape the same way are one test, and the count below is asserted.
    const HOSTILE_SLOT_NAMES: &[(&str, &str)] = &[
        ("..", "the parent directory itself"),
        ("../escape", "traversal through a separator"),
        ("a/b", "a POSIX separator, so the name is two components"),
        ("a\\b", "a Windows separator, which POSIX-only checks miss"),
        (
            "-force",
            "a leading dash the Git commands would read as an option",
        ),
        ("", "empty, which collapses the path component away"),
        ("naïve", "non-ASCII, whose NFC/NFD forms are two names"),
        (
            ".",
            "the current directory, which aliases the namespace root",
        ),
    ];

    /// Every public primitive that turns a `&Slot` into a path refuses a
    /// hostile name — over a list **derived from this module's own
    /// signatures**, not from the ones the author remembered.
    ///
    /// `a_slot_name_that_could_escape_the_root_refuses` exercises exactly one
    /// primitive, `write_intent`. That is the `bounded_grid` failure this
    /// project has recorded three times: the grid varies the hostile name and
    /// holds the primitive fixed, so it stays green while
    /// `candidate_stage`, `candidate_write_tree`, `proposal_cherry_pick`,
    /// `repair_materialize` and `changed_paths` run `git add -A`,
    /// `git write-tree`, `git cherry-pick` and `git diff` with a working
    /// directory the name placed outside the execution root. `Slot`'s fields
    /// are `pub`, so the name is caller data at every one of those entry
    /// points.
    ///
    /// The derivation is the scan below: a primitive that can refuse is a
    /// `pub fn` taking `slot: &Slot` and returning a `Result`. Adding one
    /// without an arm here fails this test by name.
    #[test]
    fn every_slot_taking_primitive_refuses_a_hostile_slot_name() {
        let fixture = Fixture::created("slot-grid");
        let manager = &fixture.manager;
        let head = fixture.head.clone();

        type Call<'a> = Box<dyn Fn(&Slot) -> Result<(), TactusError> + 'a>;
        let primitives: Vec<(&str, Call<'_>)> = vec![
            (
                "write_intent",
                Box::new(|slot| manager.write_intent(&mut NoHooks, slot)),
            ),
            (
                "remove_intent",
                Box::new(|slot| manager.remove_intent(&mut NoHooks, slot)),
            ),
            (
                "add_worktree",
                Box::new(|slot| manager.add_worktree(&mut NoHooks, slot, &head).map(drop)),
            ),
            (
                "verify_worktree",
                Box::new(|slot| {
                    manager
                        .verify_worktree(&mut NoHooks, slot, &Quiescence::AtBase(head.clone()))
                        .map(drop)
                }),
            ),
            (
                "remove_worktree",
                Box::new(|slot| manager.remove_worktree(&mut NoHooks, slot)),
            ),
            (
                "candidate_stage",
                Box::new(|slot| manager.candidate_stage(&mut NoHooks, slot)),
            ),
            (
                "candidate_write_tree",
                Box::new(|slot| manager.candidate_write_tree(&mut NoHooks, slot).map(drop)),
            ),
            (
                "proposal_cherry_pick",
                Box::new(|slot| {
                    manager
                        .proposal_cherry_pick(&mut NoHooks, slot, &fixture.side)
                        .map(drop)
                }),
            ),
            (
                "repair_materialize",
                Box::new(|slot| {
                    manager
                        .repair_materialize(&mut NoHooks, slot, &fixture.side)
                        .map(drop)
                }),
            ),
            (
                "changed_paths",
                Box::new(|slot| manager.changed_paths(slot, &head).map(drop)),
            ),
        ];

        let covered: BTreeSet<String> = primitives
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        assert_eq!(
            covered.len(),
            primitives.len(),
            "each primitive appears once"
        );
        assert_eq!(
            covered,
            slot_taking_fallible_primitives(),
            "the grid must be this module's slot-taking fallible `pub fn`s, derived from its \
             signatures — a primitive with no arm here is one nothing refuses for"
        );

        let mechanisms: BTreeSet<&str> = HOSTILE_SLOT_NAMES.iter().map(|(_, why)| *why).collect();
        assert_eq!(
            mechanisms.len(),
            HOSTILE_SLOT_NAMES.len(),
            "every hostile name is a distinct escape mechanism, not a restatement"
        );
        assert_eq!(mechanisms.len(), 8, "eight distinct mechanisms");

        // Something outside the root that a successful escape would reach, so
        // "it refused" is not the only thing asserted.
        let outside = fixture.root.join("precious");
        fs::create_dir_all(&outside).expect("outside directory");
        fs::write(outside.join("keep.txt"), "keep\n").expect("outside file");

        for (name, call) in &primitives {
            for (hostile, why) in HOSTILE_SLOT_NAMES {
                let slot = Slot::Task {
                    key: (*hostile).to_owned(),
                    generation: 1,
                };
                let Err(error) = call(&slot) else {
                    panic!("`{name}` accepted the slot name `{hostile}` ({why})")
                };
                let message = refusal_of(&error);
                assert!(
                    message.contains("slot name"),
                    "`{name}` must refuse `{hostile}` by naming the slot name: {message}"
                );
            }
        }

        assert_eq!(
            fs::read_to_string(outside.join("keep.txt")).expect("still there"),
            "keep\n",
            "and nothing outside the execution root was touched"
        );
    }

    /// The names of this module's `pub fn`s that take `slot: &Slot` and return
    /// a `Result` — read out of the source rather than listed.
    ///
    /// `slot_path` and `intent_path` are deliberately not in this set: they
    /// return a `PathBuf` infallibly and are path arithmetic, which is why the
    /// predicate is "returns a `Result`" rather than "mentions a `Slot`".
    fn slot_taking_fallible_primitives() -> BTreeSet<String> {
        let source = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/workspace_manager.rs"),
        )
        .expect("read this module's source");
        let mut names = BTreeSet::new();
        let mut seen_fns = 0_usize;
        for chunk in source.split("\n    pub fn ").skip(1) {
            seen_fns += 1;
            let Some((signature, _)) = chunk.split_once('{') else {
                continue;
            };
            let Some(name) = signature.split(['(', '<']).next() else {
                continue;
            };
            if signature.contains("slot: &Slot") && signature.contains("-> Result<") {
                names.insert(name.to_owned());
            }
        }
        assert!(
            seen_fns > 30,
            "the scan read this module's signatures rather than nothing: {seen_fns}"
        );
        names
    }

    /// `slice_contract.invariants_introduced[1]`: "worktree and snapshot
    /// intents **synced before** the add".
    ///
    /// `WriteIntent` and `Add` are separate sites — each carries its own hooks
    /// and the cancellation clause is stated per clause — so no single funnel
    /// body can order them. That makes the ordering a *caller's* obligation,
    /// and an unchecked obligation is one the first schema-4 caller in PR7–PR10
    /// can drop silently: the add succeeds, and the worktree it created is
    /// invisible to `reclaim_intents`, which walks intents. The second half of
    /// this test is the consequence the refusal exists to prevent.
    #[test]
    fn an_add_without_a_durable_intent_refuses_and_leaves_nothing_registered() {
        let fixture = Fixture::created("add-without-intent");
        let slots = [
            fixture.task("alpha", 1),
            Slot::Staging { sequence: 7 },
            Slot::Snapshot {
                name: SnapshotName::gates(1, 1),
            },
        ];
        assert_eq!(
            slots
                .iter()
                .map(Slot::add_site)
                .collect::<BTreeSet<_>>()
                .len(),
            3,
            "one slot per add site: Worktree.Add, Worktree.AddStaging, Snapshot.Add"
        );

        for slot in &slots {
            let path = fixture.manager.slot_path(slot);
            let error = fixture
                .manager
                .add_worktree(&mut NoHooks, slot, &fixture.head)
                .expect_err("an add with no durable intent refuses");
            let message = refusal_of(&error);
            assert!(
                message.contains("durable intent"),
                "the refusal must name its reason: {message}"
            );
            assert!(!path.exists(), "and no worktree directory was created");
            assert!(
                fixture
                    .manager
                    .worktree_records()
                    .expect("records")
                    .iter()
                    .all(|record| record.path != path),
                "and nothing was registered with Git either"
            );

            // The same add, with the intent durable, succeeds — so the refusal
            // is about the ordering and not about the slot.
            fixture
                .manager
                .write_intent(&mut NoHooks, slot)
                .expect("intent");
            fixture
                .manager
                .add_worktree(&mut NoHooks, slot, &fixture.head)
                .expect("the same add once the intent is durable");
            assert!(path.exists());
        }

        // And the reason: every worktree the manager created is reachable from
        // an intent, so reclaim finds all three.
        let reclaimed = fixture
            .manager
            .reclaim_intents(&mut NoHooks)
            .expect("reclaim");
        assert_eq!(
            reclaimed.iter().collect::<BTreeSet<_>>(),
            slots.iter().collect::<BTreeSet<_>>(),
            "reclaim walks intents, so an add without one would leave a worktree it never sees"
        );
        for slot in &slots {
            assert!(!fixture.manager.slot_path(slot).exists());
        }
    }

    // -----------------------------------------------------------------------
    // INV-17: the ref primitives
    // -----------------------------------------------------------------------

    #[test]
    fn a_symbolic_ref_is_refused_without_touching_the_victim() {
        let fixture = Fixture::created("symbolic-ref");
        git(
            &fixture.base,
            &["symbolic-ref", "refs/tactus/sym", "refs/heads/main"],
        );
        let before = git(&fixture.base, &["rev-parse", "refs/heads/main"]);

        for attempt in [
            fixture.manager.create_ref_zero_old(
                &mut NoHooks,
                RefSite::CreateCandidates,
                "refs/tactus/sym",
                &fixture.head,
            ),
            fixture.manager.delete_ref_expected_old(
                &mut NoHooks,
                RefSite::DeleteCandidatesRef,
                "refs/tactus/sym",
                &fixture.head,
            ),
            // The CAS arm, which `ref_rules` names beside the other two and
            // which this loop did not drive. `--no-deref` on all three
            // invocations is unreachable defence in depth *because* this guard
            // runs first, so the guard is the thing that has to be complete —
            // and it was covering two of the three primitives it protects.
            fixture.manager.compare_and_swap_ref(
                &mut NoHooks,
                RefSite::CompareAndSwapIntegration,
                "refs/tactus/sym",
                &fixture.head,
                &fixture.seed,
            ),
        ] {
            let message = refusal_of(&attempt.expect_err("a symbolic ref refuses"));
            assert!(
                message.contains("symbolic ref") && message.contains("INV-17"),
                "the refusal must name its reason: {message}"
            );
        }
        assert_eq!(
            git(&fixture.base, &["rev-parse", "refs/heads/main"]),
            before,
            "and the victim is untouched"
        );
        assert_eq!(
            git(&fixture.base, &["symbolic-ref", "refs/tactus/sym"]),
            "refs/heads/main",
            "and the symbolic ref itself is untouched"
        );
    }

    #[test]
    fn a_checked_out_ref_is_refused_before_any_publication() {
        let fixture = Fixture::created("checked-out");
        let message = refusal_of(
            &fixture
                .manager
                .assert_publishable("refs/heads/main")
                .expect_err("a checked-out ref refuses"),
        );
        assert!(
            message.contains("checked out in the worktree"),
            "the refusal must name its reason: {message}"
        );
        fixture
            .manager
            .assert_publishable("refs/heads/tactus/run-1")
            .expect("a ref no worktree has checked out is publishable");
    }

    /// A compare-and-swap honours the **caller's recorded** expected-old, not
    /// a fresh reading of the ref (`PR5-WORKSPACE-030`).
    ///
    /// `invariants[16].recovery`: "symbolic or **substituted** refs refuse".
    /// The suite owns a "wrong expected-old refuses" assertion but drives it
    /// through `delete_ref_expected_old`, never through the CAS; and the CAS's
    /// two production callers both pass the true current value, so a body that
    /// replaced the caller's recorded SHA with a fresh reread produced the
    /// identical argument every time it ran. The distinguishing manipulation is
    /// a **third** SHA substituted between the caller recording expected-old
    /// and the swap — under it, a self-oracle sees its own reading as current
    /// and overwrites another writer's value.
    #[test]
    fn a_compare_and_swap_refuses_a_ref_substituted_since_the_caller_recorded_it() {
        let fixture = Fixture::created("cas-substituted");
        let name = "refs/tactus/runs/run-1/integration";
        fixture
            .manager
            .create_ref_zero_old(
                &mut NoHooks,
                RefSite::CreateIntegration,
                name,
                &fixture.head,
            )
            .expect("create");
        // What the caller recorded, before anyone else touched the ref.
        let recorded = fixture.head.clone();

        // A third value, from a writer this caller never saw.
        git(&fixture.base, &["update-ref", name, &fixture.side]);
        assert_eq!(
            fixture.manager.direct_ref_target(name).expect("read"),
            Some(fixture.side.clone()),
            "the ref really was substituted"
        );
        assert_ne!(recorded, fixture.side);

        let error = fixture
            .manager
            .compare_and_swap_ref(
                &mut NoHooks,
                RefSite::CompareAndSwapIntegration,
                name,
                &recorded,
                &fixture.seed,
            )
            .expect_err("a substituted ref refuses the swap");
        assert_eq!(
            fixture.manager.direct_ref_target(name).expect("read"),
            Some(fixture.side.clone()),
            "and the other writer's value is untouched: {error}"
        );

        // The same swap against the true current value succeeds, so the
        // refusal above is about the substitution and not about the primitive.
        fixture
            .manager
            .compare_and_swap_ref(
                &mut NoHooks,
                RefSite::CompareAndSwapIntegration,
                name,
                &fixture.side,
                &fixture.seed,
            )
            .expect("expected-old matching the current value swaps");
        assert_eq!(
            fixture.manager.direct_ref_target(name).expect("read"),
            Some(fixture.seed.clone())
        );
    }

    /// The direct-ref reader refuses a **symbolic ref that resolves to the
    /// expected object** (`PR5-WORKSPACE-031`).
    ///
    /// `ref_rules`: "all refs **direct** … symbolic refs refused". Every call
    /// of `direct_ref_target` in this file is on a ref the fixture created with
    /// `create_ref_zero_old`, so the reader was never once pointed at a
    /// symbolic ref; the one test that builds a symbolic ref reads its victim
    /// back through a raw `git symbolic-ref` helper instead. The case that
    /// separates a non-dereferencing `show-ref --verify` from a dereferencing
    /// `rev-parse --verify` is exactly the one never constructed: an indirection
    /// that yields the **right** object, and so hides itself.
    #[test]
    fn a_symbolic_ref_that_resolves_to_the_expected_object_is_still_refused() {
        let fixture = Fixture::created("symbolic-reader");
        let direct = "refs/tactus/runs/run-1/candidates/kalpha/1";
        let symbolic = "refs/tactus/runs/run-1/integration";
        fixture
            .manager
            .create_ref_zero_old(
                &mut NoHooks,
                RefSite::CreateCandidates,
                direct,
                &fixture.head,
            )
            .expect("create the direct ref");
        git(&fixture.base, &["symbolic-ref", symbolic, direct]);
        assert_eq!(
            git(&fixture.base, &["rev-parse", "--verify", symbolic]),
            fixture.head,
            "dereferencing yields exactly the object a caller expects, which is what              makes this the hiding case"
        );

        let error = refusal_of(
            &fixture
                .manager
                .direct_ref_target(symbolic)
                .expect_err("a symbolic ref is not a direct one, whatever it resolves to"),
        );
        assert!(
            error.contains("symbolic"),
            "the refusal must name its reason: {error}"
        );
        // And the direct ref beside it still reads back, so the reader has not
        // simply stopped working.
        assert_eq!(
            fixture.manager.direct_ref_target(direct).expect("read"),
            Some(fixture.head.clone())
        );
    }

    #[test]
    fn refs_are_created_zero_old_and_moved_or_deleted_only_expected_old() {
        let fixture = Fixture::created("ref-rules");
        let name = "refs/tactus/runs/run-1/candidates/kalpha/1";
        fixture
            .manager
            .create_ref_zero_old(&mut NoHooks, RefSite::CreateCandidates, name, &fixture.head)
            .expect("zero-old creation");
        assert_eq!(
            fixture
                .manager
                .direct_ref_target(name)
                .expect("read the ref"),
            Some(fixture.head.clone())
        );

        fixture
            .manager
            .create_ref_zero_old(&mut NoHooks, RefSite::CreateCandidates, name, &fixture.seed)
            .expect_err("zero-old refuses a ref that already exists");
        assert_eq!(
            fixture.manager.direct_ref_target(name).expect("read"),
            Some(fixture.head.clone()),
            "and leaves it where it was"
        );

        fixture
            .manager
            .delete_ref_expected_old(
                &mut NoHooks,
                RefSite::DeleteCandidatesRef,
                name,
                &fixture.seed,
            )
            .expect_err("a wrong expected-old refuses");
        assert_eq!(
            fixture.manager.direct_ref_target(name).expect("read"),
            Some(fixture.head.clone()),
            "and leaves it where it was"
        );

        fixture
            .manager
            .delete_ref_expected_old(
                &mut NoHooks,
                RefSite::DeleteCandidatesRef,
                name,
                &fixture.head,
            )
            .expect("the right expected-old deletes");
        assert_eq!(fixture.manager.direct_ref_target(name).expect("read"), None);
    }

    /// The trap this project's guard exists for: a fix that introduces a
    /// defect. `git update-ref -d <ref> 0{40}` **succeeds and deletes**,
    /// because the null id means "must not exist"; a primitive that passed it
    /// through would perform an unconditional delete under a name that
    /// promises expected-old.
    #[test]
    fn the_null_object_id_is_never_an_expected_old_value() {
        let fixture = Fixture::created("null-old");
        let name = "refs/tactus/runs/run-1/candidate-prepared/kalpha/1";
        fixture
            .manager
            .create_ref_zero_old(
                &mut NoHooks,
                RefSite::PinCandidatePrepared,
                name,
                &fixture.head,
            )
            .expect("pin");

        for null in ["0".repeat(40), "0".repeat(64)] {
            let message = refusal_of(
                &fixture
                    .manager
                    .delete_ref_expected_old(&mut NoHooks, RefSite::DeleteCandidatePin, name, &null)
                    .expect_err("the null expected-old refuses"),
            );
            assert!(
                message.contains("null object id") && message.contains("INV-17"),
                "the refusal must name its reason: {message}"
            );
        }
        assert_eq!(
            fixture.manager.direct_ref_target(name).expect("read"),
            Some(fixture.head.clone()),
            "and the pin is still there"
        );

        // The measurement this refusal is derived from: raw Git really does
        // delete on the null id, so the refusal is guarding a live hazard and
        // not a hypothetical one.
        let raw = git_out(
            &fixture.base,
            &["update-ref", "--no-deref", "-d", name, &"0".repeat(40)],
        );
        assert!(
            raw.status.success()
                && fixture
                    .manager
                    .direct_ref_target(name)
                    .expect("read")
                    .is_none(),
            "raw `git update-ref -d <ref> 0{{40}}` deletes unconditionally; that is why the \
             primitive refuses it"
        );
    }

    #[test]
    fn a_malformed_object_id_never_reaches_the_ref_command() {
        let fixture = Fixture::created("malformed-oid");
        for hostile in ["--delete", "", "refs/heads/main", "zzzz", &"a".repeat(39)] {
            let message = refusal_of(
                &fixture
                    .manager
                    .create_ref_zero_old(
                        &mut NoHooks,
                        RefSite::CreateIntegration,
                        "refs/heads/tactus/run-1",
                        hostile,
                    )
                    .expect_err("a malformed object id refuses"),
            );
            assert!(
                message.contains("full hexadecimal object id"),
                "the refusal must name its reason for `{hostile}`: {message}"
            );
        }
        assert_eq!(
            fixture
                .manager
                .direct_ref_target("refs/heads/tactus/run-1")
                .expect("read"),
            None
        );
    }

    #[test]
    fn an_unexpected_ref_under_the_run_namespace_refuses() {
        let fixture = Fixture::created("unexpected-refs");
        let namespace = "refs/tactus/runs/run-1/";
        let mine = "refs/tactus/runs/run-1/candidates/kalpha/1".to_owned();
        fixture
            .manager
            .create_ref_zero_old(
                &mut NoHooks,
                RefSite::CreateCandidates,
                &mine,
                &fixture.head,
            )
            .expect("create");
        fixture
            .manager
            .refuse_unexpected_refs(namespace, std::slice::from_ref(&mine))
            .expect("the namespace carries only what is expected");

        git(
            &fixture.base,
            &[
                "update-ref",
                "refs/tactus/runs/run-1/stowaway",
                &fixture.seed,
            ],
        );
        let message = refusal_of(
            &fixture
                .manager
                .refuse_unexpected_refs(namespace, std::slice::from_ref(&mine))
                .expect_err("an unexpected ref refuses"),
        );
        assert!(
            message.contains("unexpected ref") && message.contains("stowaway"),
            "the refusal must name its reason and the ref: {message}"
        );
    }

    /// A **packed** unexpected ref refuses, and so does a **nested** one
    /// (`PR5-WORKSPACE-033`).
    ///
    /// `expected_failures_refusals[2]` is "unexpected refs under the run
    /// namespace" with no exception for how Git happens to be storing them.
    /// The test above plants its stowaway with a plain `update-ref` and never
    /// runs `pack-refs`, so the stowaway is a loose file and rewriting
    /// `refs_under` to walk `<common git dir>/refs` and ignore `packed-refs`
    /// entirely still found it. Nothing in this file called `pack-refs` at all,
    /// and no fixture nested a ref deeper than the two-level
    /// `candidates/kalpha/1`.
    #[test]
    fn a_packed_or_nested_unexpected_ref_refuses_too() {
        let fixture = Fixture::created("packed-refs");
        let namespace = "refs/tactus/runs/run-1/";
        let mine = "refs/tactus/runs/run-1/candidates/kalpha/1".to_owned();
        fixture
            .manager
            .create_ref_zero_old(
                &mut NoHooks,
                RefSite::CreateCandidates,
                &mine,
                &fixture.head,
            )
            .expect("create");

        let nested = "refs/tactus/runs/run-1/candidates/kalpha/deeper/still/1";
        git(&fixture.base, &["update-ref", nested, &fixture.seed]);
        git(&fixture.base, &["pack-refs", "--all"]);
        assert!(
            fixture.base.join(".git/packed-refs").is_file(),
            "the fixture really packed the refs"
        );
        assert!(
            !fixture.base.join(".git").join(nested).exists(),
            "and the stowaway is no longer a loose file, which is the whole point"
        );

        let listed: Vec<String> = fixture
            .manager
            .refs_under(namespace)
            .expect("enumerate")
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert!(
            listed.contains(&nested.to_owned()),
            "a packed ref is still a ref under the namespace: {listed:?}"
        );

        let message = refusal_of(
            &fixture
                .manager
                .refuse_unexpected_refs(namespace, std::slice::from_ref(&mine))
                .expect_err("a packed, nested, unexpected ref refuses"),
        );
        assert!(
            message.contains("unexpected ref") && message.contains("deeper/still"),
            "the refusal must name the packed nested ref: {message}"
        );

        // And every ref is still exactly where it was: a refusal acts on
        // nothing.
        assert_eq!(
            fixture.manager.direct_ref_target(&mine).expect("read"),
            Some(fixture.head.clone())
        );
        assert_eq!(
            fixture.manager.direct_ref_target(nested).expect("read"),
            Some(fixture.seed.clone())
        );
    }

    /// The integration ref checked out in a **second linked worktree** refuses
    /// (`PR5-WORKSPACE-032`).
    ///
    /// `integration_ref`: "never checked out; `assert_publishable()` before
    /// every prepare/CAS/recovery". The one test of the refusal asks about
    /// `refs/heads/main`, which is checked out in the *primary* worktree — so
    /// truncating the scan to the first worktree record still refused it, and
    /// the negative case is a ref checked out nowhere. A linked worktree is
    /// exactly the shape this manager creates for its own work, so it is the
    /// one that had to be built.
    #[test]
    fn an_integration_ref_checked_out_in_a_second_worktree_is_refused() {
        let fixture = Fixture::created("checked-out-elsewhere");
        let refname = "refs/heads/tactus/run-1";
        git(&fixture.base, &["branch", "tactus/run-1", &fixture.head]);
        fixture
            .manager
            .assert_publishable(refname)
            .expect("checked out nowhere yet");

        let elsewhere = fixture.root.join("elsewhere");
        git(
            &fixture.base,
            &[
                "worktree",
                "add",
                "-q",
                &elsewhere.to_string_lossy(),
                "tactus/run-1",
            ],
        );
        assert_eq!(
            git(&elsewhere, &["symbolic-ref", "-q", "--", "HEAD"]),
            refname,
            "the second worktree really has the integration ref checked out"
        );
        assert!(
            fixture.manager.worktree_records().expect("records").len() >= 2,
            "and it is not the first record, which a truncated scan would still see"
        );

        let message = refusal_of(
            &fixture
                .manager
                .assert_publishable(refname)
                .expect_err("a ref checked out in a linked worktree refuses"),
        );
        assert!(
            message.contains("checked out in the worktree"),
            "the refusal must name its reason: {message}"
        );
    }

    // -----------------------------------------------------------------------
    // Intents: synced before the add, and reclaimed
    // -----------------------------------------------------------------------

    #[test]
    fn the_intent_is_durable_before_the_add_and_reclaim_removes_it() {
        let fixture = Fixture::created("intent-order");
        let (mut hooks, shared) = harness();
        let slot = fixture.task("alpha", 1);

        fixture
            .manager
            .write_intent(&mut hooks, &slot)
            .expect("intent");
        assert!(
            fixture.manager.intent_path(&slot).is_file(),
            "the intent is durable before the add is issued"
        );
        assert!(
            !fixture.manager.slot_path(&slot).exists(),
            "and the worktree does not exist yet — this is the interrupted-add prefix"
        );

        // The cancellation clause, exactly: "an interrupted worktree or
        // snapshot add leaves a durable intent that reclaim removes."
        let reclaimed = fixture
            .manager
            .reclaim_intents(&mut hooks)
            .expect("reclaim");
        assert_eq!(reclaimed, vec![slot.clone()]);
        assert!(!fixture.manager.intent_path(&slot).exists());
        assert!(fixture.manager.intents().expect("intents").is_empty());

        // And the hook order the sentence is about, from the harness's own
        // first-observation order.
        fixture
            .manager
            .write_intent(&mut hooks, &slot)
            .expect("intent again");
        fixture
            .manager
            .add_worktree(&mut hooks, &slot, &fixture.head)
            .expect("add");
        let observed = shared.lock().expect("harness").coverage().to_vec();
        let index = |site: EffectSiteId, phase: HookPhase| {
            observed
                .iter()
                .position(|seen| seen.site == site && seen.phase == phase)
                .unwrap_or_else(|| panic!("{site} {phase} was never observed"))
        };
        assert!(
            index(
                EffectSiteId::Worktree(WorktreeSite::WriteIntent),
                HookPhase::After
            ) < index(EffectSiteId::Worktree(WorktreeSite::Add), HookPhase::Before),
            "the intent's after phase precedes the add's before phase"
        );
    }

    /// A refusal at `Before(Worktree.Add)` refuses **before any effect**
    /// (`PR5-CONF-003`).
    ///
    /// `identity` says "the funnel itself calls hook(Before, site) -> primitive
    /// -> hook(After, site)" and `scope` requires "every effect through typed
    /// funnel APIs taking a site". `add_worktree`'s scaffolding
    /// `fs::create_dir_all` sat *outside* the `funnel(...)` call, so the Before
    /// hook was not the first thing that happened: the directory was already on
    /// disk when the refusal was returned. The module doc at the top of this file
    /// claims "every effect is issued inside a `funnel` call", and
    /// `effects/wrappers.toml` classified `add_worktree` as `effect_free` —
    /// which that file defines as "reaches no effect of its own".
    ///
    /// The two axes this crosses are the *hook answer* and the *filesystem*. The
    /// sibling below holds the hook answer at `Proceed` and reads the durability
    /// ledger; every other add test proceeds too. What varies here is the
    /// answer — `Injection::Error` at the add's Before — and what is held
    /// constant is the state the effect would change: the scaffolding directory
    /// is asserted absent before the call, so its absence afterwards is the
    /// claim rather than an accident of the fixture.
    #[test]
    fn a_refusal_at_the_adds_before_hook_leaves_the_filesystem_untouched() {
        /// Refuses at the add's `Before`, and records that it did.
        #[derive(Default)]
        struct RefuseAtAddBefore {
            refused: bool,
        }

        impl EffectHooks for RefuseAtAddBefore {
            fn phase(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection {
                if site == EffectSiteId::Worktree(WorktreeSite::Add) && phase == HookPhase::Before {
                    self.refused = true;
                    return Injection::Error;
                }
                Injection::Proceed
            }
        }

        let fixture = Fixture::created("add-before-refusal");
        let slot = fixture.task("alpha", 1);
        fixture
            .manager
            .write_intent(&mut NoHooks, &slot)
            .expect("the intent must be durable, or the add refuses for another reason");

        // The directory the effect would create. `slot_path` is private to the
        // manager, so it is derived the way the funnel derives it and then
        // asserted absent — a fixture that already had it would pass this test
        // for a funnel that created it far too early.
        let target = fixture.manager.execution_root().join(slot.relative());
        let scaffolding = target
            .parent()
            .expect("the slot target has a parent")
            .to_path_buf();
        let _ = fs::remove_dir_all(&scaffolding);
        assert!(
            !scaffolding.exists(),
            "the premise: the scaffolding directory must be absent before the call"
        );

        let mut hooks = RefuseAtAddBefore::default();
        let refusal = fixture
            .manager
            .add_worktree(&mut hooks, &slot, &fixture.head)
            .expect_err("the armed Before hook must refuse the add");
        assert!(
            hooks.refused,
            "the hook never fired, so nothing here is measured"
        );
        assert!(
            refusal.to_string().contains("before"),
            "the refusal must name the phase it came from: {refusal}"
        );
        assert!(
            !scaffolding.exists(),
            "the add's Before hook refused and {} exists anyway: an effect ran \
             before the funnel's first hook",
            scaffolding.display()
        );
        assert!(
            !target.exists(),
            "the worktree itself must not exist either: {}",
            target.display()
        );
    }

    /// The intent is **synced** — file and containing directory — before the
    /// add's first hook (`PR5-WORKSPACE-015`, `PR5-WORKSPACE-016`).
    ///
    /// `invariants_introduced[1]` is "worktree and snapshot intents **synced**
    /// before add", and the test above checks that the intent *exists and
    /// parses* before `Worktree.Add` fires. Those are different claims, and an
    /// unsynced file satisfies the weaker one exactly as well as a synced one:
    /// with both `sync_all` calls deleted from `write_synced`, every assertion
    /// in this file still passed. The observer below crosses the two axes the
    /// lane had separately — the hook order, and the durability ledger — by
    /// reading the ledger *at* the add's `Before` hook rather than afterwards.
    #[test]
    fn the_intent_and_its_directory_are_synced_before_the_add_begins() {
        /// Snapshots the durability ledger at the first `Worktree.Add` Before.
        struct LedgerAtAdd {
            inner: HarnessEffects,
            at_add: Option<Vec<crate::util::DurableRecord>>,
        }

        impl EffectHooks for LedgerAtAdd {
            fn phase(&mut self, site: EffectSiteId, phase: HookPhase) -> Injection {
                if site == EffectSiteId::Worktree(WorktreeSite::Add)
                    && phase == HookPhase::Before
                    && self.at_add.is_none()
                {
                    self.at_add = Some(self.inner.ledger().records());
                }
                self.inner.phase(site, phase)
            }

            fn durability_ledger(&self) -> DurabilityLedger {
                self.inner.durability_ledger()
            }
        }

        let fixture = Fixture::created("intent-durability");
        let slot = fixture.task("alpha", 1);
        let intent = fixture.manager.intent_path(&slot);
        let intents_dir = intent
            .parent()
            .expect("the intents directory")
            .to_path_buf();
        let mut hooks = LedgerAtAdd {
            inner: HarnessEffects::new(Arc::new(Mutex::new(HookHarness::new())))
                .recording_durability(),
            at_add: None,
        };

        fixture
            .manager
            .write_intent(&mut hooks, &slot)
            .expect("intent");
        fixture
            .manager
            .add_worktree(&mut hooks, &slot, &fixture.head)
            .expect("add");

        let at_add = hooks
            .at_add
            .expect("the add's Before hook never fired, so nothing here is measured");
        let steps: Vec<DurableStep> = at_add.iter().map(|record| record.step).collect();
        // The staged file, its rename, and the directory entry: both halves of
        // `write_synced`'s durability contract, on every platform
        // (`PR5-CONF-013`). This used to fork on `cfg!(unix)` because a
        // directory fsync was held not to be a call this crate could make on
        // Windows; `util::fsync_dir` makes it.
        let expected = vec![
            DurableStep::SyncedFile,
            DurableStep::Renamed,
            DurableStep::SyncedDirectory,
        ];
        assert_eq!(
            steps, expected,
            "the durability sequence complete at the moment the add begins: {at_add:?}"
        );
        assert_eq!(
            at_add[0].path,
            intent.with_extension("tmp"),
            "the sync is of the staged intent, before it has its published name"
        );
        assert_eq!(
            at_add[0].len,
            fs::metadata(&intent).expect("the intent").len(),
            "the whole intent file was synced, not a prefix of it"
        );
        assert!(at_add[0].len > 0, "the intent has bytes at all");
        assert_eq!(
            at_add[1].path, intent,
            "the rename lands on the intent name"
        );
        #[cfg(unix)]
        assert_eq!(
            at_add[2].path, intents_dir,
            "the directory sync is of the directory the rename changed"
        );
        let _ = &intents_dir;
    }

    /// `snapshots`: "an interrupted add leaves a registered-but-unpopulated
    /// worktree that the intent-based reclaim removes and prunes".
    ///
    /// The residue is constructed the way `git worktree add` leaves it — the
    /// registration plus the `initializing` lock Git itself holds for the whole
    /// of the add — because measured, `git worktree prune` **skips** a locked
    /// entry and `git worktree remove --force` refuses one. A reclaim that did
    /// not clear the lock would leave exactly the residue `cleanup` promises
    /// never blocks it.
    #[test]
    fn reclaim_removes_a_registered_but_unpopulated_worktree() {
        let fixture = Fixture::created("unpopulated");
        let slot = fixture.task("alpha", 1);
        fixture
            .manager
            .write_intent(&mut NoHooks, &slot)
            .expect("intent");
        let path = fixture.manager.slot_path(&slot);
        register_unpopulated(&fixture, &path);

        assert!(
            fixture
                .manager
                .worktree_records()
                .expect("records")
                .iter()
                .any(|record| record.locked.as_deref() == Some("initializing")),
            "the fixture must really build the residue it is about"
        );
        assert_eq!(
            fixture
                .manager
                .quiescence(&path, &Quiescence::AtBase(fixture.head.clone()))
                .expect("verify"),
            Err(VerifyFailure::Unpopulated)
        );

        fixture
            .manager
            .reclaim_intents(&mut NoHooks)
            .expect("reclaim");
        assert!(
            !fixture
                .manager
                .worktree_records()
                .expect("records")
                .iter()
                .any(|record| record.path.ends_with("kalpha-g1")),
            "the registration is pruned"
        );
        assert!(!path.exists());
        assert!(!fixture.manager.intent_path(&slot).exists());
    }

    /// Build the state a killed `git worktree add` leaves: the registration
    /// exists and Git still holds its `initializing` lock.
    fn register_unpopulated(fixture: &Fixture, path: &Path) {
        git(
            &fixture.base,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                &path.to_string_lossy(),
                &fixture.head,
            ],
        );
        let admin = fixture
            .manager
            .registered_admin_dir(path)
            .expect("admin dir")
            .expect("the worktree is registered");
        fs::write(admin.join("locked"), "initializing\n").expect("hold the initializing lock");
        fs::remove_dir_all(path).expect("un-populate the checkout");
    }

    /// The other half of the cancellation clause: "an ephemeral snapshot commit
    /// created *before* the intent is left to Git".
    #[test]
    fn an_ephemeral_snapshot_commit_created_before_the_intent_is_left_to_git() {
        let fixture = Fixture::created("ephemeral-before-intent");
        let (mut hooks, _shared) = harness();
        let tree = git(
            &fixture.base,
            &["rev-parse", &format!("{}^{{tree}}", fixture.head)],
        );

        let commit = fixture
            .manager
            .snapshot_commit_tree(&mut hooks, &tree, &fixture.head)
            .expect("ephemeral commit");
        let slot = Slot::Snapshot {
            name: SnapshotName::gates(1, 1),
        };
        assert!(
            !fixture.manager.intent_path(&slot).exists(),
            "the object exists and nothing durable claims it yet"
        );
        assert!(
            unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&commit),
            "so it is unreferenced R27 residue: Git's"
        );

        // Nothing reclaims it and nothing may: the resume action is to leave it.
        fixture
            .manager
            .reclaim_intents(&mut hooks)
            .expect("reclaim finds no intent");
        assert!(
            unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&commit),
            "reclaim leaves the object exactly where Git put it"
        );

        // And the full sequence puts the commit-tree before the intent.
        //
        // **On a harness of its own** (`PR5-WORKSPACE-022`). `HookHarness::
        // coverage()` is a *first-observation* log — one entry per `(site,
        // phase)` however many times it fires — and this test has already
        // driven `snapshot_commit_tree` standalone above, through `hooks`. So
        // the entry a `position()` first-match found for
        // `SnapshotCommitTree/After` was that earlier, unrelated invocation,
        // which precedes every event `add_snapshot` emits whatever order
        // `add_snapshot` uses internally: the assertion below passed with the
        // intent written first, which is exactly what it exists to forbid, and
        // the ordering it names was never measured at all. A fresh harness
        // starts empty, so every index below is this call's own. Taking a
        // *mark* into the old log would not have worked either — the second
        // occurrence is not recorded, so there is nothing after the mark.
        let (mut measured, ordering) = harness();
        let snapshot = fixture
            .manager
            .add_snapshot(
                &mut measured,
                &SnapshotName::gates(2, 1),
                &SnapshotInput::Tree {
                    tree: tree.clone(),
                    parent: fixture.head.clone(),
                },
            )
            .expect("snapshot");
        let observed = ordering.lock().expect("harness").coverage().to_vec();
        let index = |site: EffectSiteId, phase: HookPhase| {
            observed
                .iter()
                .position(|seen| seen.site == site && seen.phase == phase)
                .unwrap_or_else(|| {
                    panic!("{site} {phase} was never observed inside this add_snapshot")
                })
        };
        assert!(
            index(
                EffectSiteId::Object(ObjectSite::SnapshotCommitTree),
                HookPhase::After
            ) < index(
                EffectSiteId::Snapshot(SnapshotSite::WriteIntent),
                HookPhase::Before
            ),
            "the ephemeral commit is created before the intent"
        );
        // The fresh harness is load-bearing, so it is checked rather than
        // trusted: this log holds this add's own commit-tree and nothing
        // earlier could have supplied it.
        assert_eq!(
            ordering.lock().expect("harness").count(
                EffectSiteId::Object(ObjectSite::SnapshotCommitTree),
                HookPhase::After
            ),
            1,
            "this add's commit-tree fired exactly once, on a log that began empty"
        );
        assert_eq!(snapshot.ephemeral.as_deref(), Some(snapshot.head.as_str()));
        assert!(
            !unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&snapshot.head),
            "and the add makes it the snapshot HEAD: R24, no longer R27"
        );
    }

    /// An integration snapshot **creates no object**, and two snapshot names in
    /// one repository are two live checkouts (`PR5-CONF-007`, `PR5-CONF-008`).
    ///
    /// One function, two clauses of `workspace_candidates`, and neither had a
    /// witness — both mutations survived the whole suite:
    ///
    /// * make the `SnapshotInput::Commit` arm fabricate an ephemeral commit and
    ///   return it as the head, against "integration snapshots check out the
    ///   proposal or head commit and **create no object**";
    /// * ignore the supplied `SnapshotName`, derive one slot from the judged
    ///   tree and hand back the existing checkout on later calls, against "one
    ///   snapshot for the gate set and one fresh snapshot per reviewer, **never
    ///   reused across roles or attempts**".
    ///
    /// The measured cause was the same for both: `SnapshotInput::Commit` and
    /// `SnapshotName::review` were **constructed nowhere in the crate**, and
    /// `add_snapshot`'s two callers each used a separate fixture, so no fixture
    /// ever held two snapshots alive at once. The recorded carry justification
    /// said a second live request needed orchestration "PR5's scope stops
    /// before"; it is two calls in one fixture, and here they are.
    /// `review-common`'s standing ruling is the general form: *"'No production
    /// caller' has a shelf life of one slice."*
    ///
    /// The two axes are the *input variant* and the *name*, and this test is one
    /// test rather than two because the surviving pair is one function: every
    /// other `add_snapshot` call in the tree holds both constant at
    /// `Tree`/`gates(1, 1)`.
    #[test]
    fn snapshots_create_no_object_for_a_commit_and_never_share_a_checkout() {
        let fixture = Fixture::created("snapshot-clauses");
        let common = PathBuf::from(git(
            &fixture.base,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        ));

        // (1) The integration case: an existing commit, and no object created.
        let before = loose_objects(&common);
        let integration = fixture
            .manager
            .add_snapshot(
                &mut NoHooks,
                &SnapshotName::integration(1),
                &SnapshotInput::Commit(fixture.head.clone()),
            )
            .expect("Snapshot.WriteIntent + Snapshot.Add");
        assert_eq!(
            integration.head, fixture.head,
            "an integration snapshot checks out the commit it was given"
        );
        assert_eq!(
            integration.ephemeral, None,
            "…and records no ephemeral commit, because it created none"
        );
        assert_eq!(
            loose_objects(&common),
            before,
            "an integration snapshot created an object; `workspace_candidates` says it \
             checks out the proposal or head commit and **creates no object**"
        );
        assert_eq!(
            git(&integration.path, &["rev-parse", "HEAD"]),
            fixture.head,
            "and the checkout really is at that commit"
        );

        // (2) Two names, one fixture, both alive at once — the shape no fixture
        // in the tree built, and the whole reason the name could be ignored.
        let tree = git(&fixture.base, &["rev-parse", "HEAD^{tree}"]);
        let gates = fixture
            .manager
            .add_snapshot(
                &mut NoHooks,
                &SnapshotName::gates(1, 1),
                &SnapshotInput::Tree {
                    tree: tree.clone(),
                    parent: fixture.head.clone(),
                },
            )
            .expect("the gate snapshot");
        let reviewer = fixture
            .manager
            .add_snapshot(
                &mut NoHooks,
                &SnapshotName::review(1, 1, 0),
                &SnapshotInput::Tree {
                    tree: tree.clone(),
                    parent: fixture.head.clone(),
                },
            )
            .expect("a reviewer's snapshot on the same judged tree");

        assert_ne!(
            gates.slot, reviewer.slot,
            "the gate set and a reviewer are different roles and must not share a slot"
        );
        assert_ne!(
            gates.path,
            reviewer.path,
            "…and therefore not a checkout either: {} vs {}",
            gates.path.display(),
            reviewer.path.display()
        );
        assert!(
            gates.path.is_dir() && reviewer.path.is_dir(),
            "both snapshots are live at once; that is what 'never reused across roles \
             or attempts' means and what no fixture built"
        );
        // Not merely different names for one directory: each is separately
        // registered, and the kernel agrees they are two.
        assert_ne!(
            git(&gates.path, &["rev-parse", "--absolute-git-dir"]),
            git(&reviewer.path, &["rev-parse", "--absolute-git-dir"]),
            "two registered worktrees, not one directory under two names"
        );

        // The same role at a later attempt is a third, again without reuse.
        let retry = fixture
            .manager
            .add_snapshot(
                &mut NoHooks,
                &SnapshotName::gates(1, 2),
                &SnapshotInput::Tree {
                    tree,
                    parent: fixture.head.clone(),
                },
            )
            .expect("the gate snapshot of the next attempt");
        assert_ne!(
            retry.path, gates.path,
            "attempt 2's gate snapshot must not be attempt 1's checkout"
        );

        for snapshot in [&integration, &gates, &reviewer, &retry] {
            fixture
                .manager
                .remove_snapshot(&mut NoHooks, snapshot)
                .expect("Snapshot.Remove + Snapshot.RemoveIntent");
        }
    }

    // -----------------------------------------------------------------------
    // Worktree.Verify and forced removal
    // -----------------------------------------------------------------------

    /// Every loose object in `objects/??/`, sorted.
    ///
    /// Loose rather than `fsck`-reachable on purpose: a tree `write-tree`
    /// creates is referenced by nothing, so a reachability oracle would not see
    /// it, and the thing `identity` forbids is the *write*, not the reference.
    fn loose_objects(common_git_dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let objects = common_git_dir.join("objects");
        let Ok(fanout) = fs::read_dir(&objects) else {
            return found;
        };
        for entry in fanout.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() != 2 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if let Ok(inner) = fs::read_dir(entry.path()) {
                for object in inner.flatten() {
                    found.push(format!("{name}{}", object.file_name().to_string_lossy()));
                }
            }
        }
        found.sort();
        found
    }

    /// `Worktree.Verify` writes **nothing** — no object, and not the index
    /// (`PR5-CONF-002`).
    ///
    /// `identity` says "Worktree.Verify is a read-only quiescence observation
    /// (no effect)" and `WorktreeSite::Verify::is_read_only()` is frozen at
    /// `true`. The implementation ran `git write-tree`, whose own comment
    /// claimed it "creates no object that is not already implied by the index it
    /// reads" — and measured against git 2.43.0, an index carrying staged
    /// content whose tree object was never written gains **two loose objects**,
    /// with the index rewritten 104 → 165 bytes as the `TREE` cache-tree
    /// extension is added. A second `git write-tree` inserted into `quiescence`
    /// survived the whole suite, because nothing observed the object store or
    /// the index around Verify.
    ///
    /// The two axes this crosses are the *verdict* and the *state of the object
    /// store*. Every other Verify test holds the store constant — it calls
    /// `write-tree` in the fixture first, which leaves a valid cache-tree and
    /// every tree already present, the one state in which `write-tree` writes
    /// nothing. What varies here is the state: the reachable prefix
    /// `Object.CandidateStage` leaves *before* `Object.CandidateWriteTree` runs.
    /// Both verdicts are driven in it, so a repair that were read-only only on
    /// the failing path would fail here.
    #[test]
    fn verify_writes_no_object_and_does_not_rewrite_the_index() {
        let fixture = Fixture::created("verify-readonly");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        let path = fixture.manager.slot_path(&slot);
        let common = PathBuf::from(git(
            &path,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        ));
        let index = git_dir_of(&path)
            .expect("git dir")
            .expect("a linked worktree")
            .join("index");

        // ---- The mismatch verdict, in the state where write-tree writes ----
        //
        // The reachable prefix: content staged into the index, and no tree
        // object written for it. `git add` writes the blob and invalidates the
        // cache-tree; the trees are what `Object.CandidateWriteTree` would add.
        // The recorded tree is an *older* one that really is in the store —
        // which is the production shape, since it was written by an earlier
        // `Object.CandidateWriteTree`.
        fs::write(path.join("staged.txt"), "staged\n").expect("stage a file");
        fs::create_dir_all(path.join("nested")).expect("a subdirectory");
        fs::write(path.join("nested/deep.txt"), "deep\n").expect("stage a nested file");
        git(&path, &["add", "-A"]);
        let recorded = git(&path, &["rev-parse", "HEAD^{tree}"]);

        let before_objects = loose_objects(&common);
        let before_index = fs::read(&index).expect("the index");
        let mismatch = fixture
            .manager
            .verify_worktree(
                &mut NoHooks,
                &slot,
                &Quiescence::HoldsTree(recorded.clone()),
            )
            .expect("verify");
        assert!(
            matches!(mismatch, Err(VerifyFailure::TreeMismatch { .. })),
            "staged content the recorded tree does not carry is a mismatch: {mismatch:?}"
        );
        assert_eq!(
            loose_objects(&common),
            before_objects,
            "Worktree.Verify created an object; `identity` calls it a read-only \
             observation with no effect"
        );
        assert_eq!(
            fs::read(&index).expect("the index"),
            before_index,
            "Worktree.Verify rewrote {} ({} bytes before); a read-only observation \
             does not update the index's cache-tree",
            index.display(),
            before_index.len()
        );

        // The premise, proved rather than asserted: this really is a state in
        // which `write-tree` writes. Run it, and watch the store grow. Without
        // this the two assertions above would pass just as well against the one
        // state — valid cache-tree, every tree present — in which the pre-repair
        // code was already read-only by accident.
        let held = git(&path, &["write-tree"]);
        let after_control = loose_objects(&common);
        assert!(
            after_control.len() > before_objects.len(),
            "the control: `git write-tree` here must create objects, or this test \
             measures nothing ({} then, {} now)",
            before_objects.len(),
            after_control.len()
        );
        assert!(
            after_control.contains(&held),
            "and one of them is the tree the index holds"
        );

        // ---- The holds-it verdict, in the state where write-tree rewrites ----
        //
        // A different discriminator, because a different half of the effect is
        // available: the trees now all exist, so `write-tree` would create no
        // object — but the cache-tree can be invalidated without changing what
        // the index *holds*, and then `write-tree` rewrites `.git/index` to put
        // it back. Measured on git 2.43.0: same tree id, 0 new objects, index
        // bytes changed.
        fs::write(path.join("staged.txt"), "other\n").expect("change the file");
        git(&path, &["add", "staged.txt"]);
        fs::write(path.join("staged.txt"), "staged\n").expect("change it back");
        git(&path, &["add", "staged.txt"]);

        let before_objects = loose_objects(&common);
        let before_index = fs::read(&index).expect("the index");
        let held_verdict = fixture
            .manager
            .verify_worktree(&mut NoHooks, &slot, &Quiescence::HoldsTree(held.clone()))
            .expect("verify");
        assert_eq!(
            held_verdict,
            Ok(()),
            "the worktree does hold {held}, and Verify must still say so"
        );
        assert_eq!(
            loose_objects(&common),
            before_objects,
            "Worktree.Verify created an object on the quiescent path"
        );
        assert_eq!(
            fs::read(&index).expect("the index"),
            before_index,
            "Worktree.Verify rewrote {} on the quiescent path: a read-only \
             observation does not restore the index's cache-tree",
            index.display()
        );

        // The second control: `write-tree` in this state writes no object and
        // rewrites the index anyway, so the assertion that bit is the index one.
        assert_eq!(
            git(&path, &["write-tree"]),
            held,
            "the index still holds the same tree"
        );
        assert_eq!(
            loose_objects(&common),
            before_objects,
            "the control: no object was available to create here"
        );
        assert_ne!(
            fs::read(&index).expect("the index"),
            before_index,
            "the control: `git write-tree` here must rewrite the index, or the \
             assertion above measures nothing"
        );
    }

    #[test]
    fn worktree_verify_answers_every_non_quiescence_by_name() {
        let fixture = Fixture::created("verify");
        let slot = fixture.task("alpha", 1);
        let path = fixture.manager.slot_path(&slot);
        let at_head = Quiescence::AtBase(fixture.head.clone());

        assert_eq!(
            fixture.manager.quiescence(&path, &at_head).expect("verify"),
            Err(VerifyFailure::NotRegistered)
        );

        fixture.add_task(&mut NoHooks, "alpha", 1);
        assert_eq!(
            fixture.manager.quiescence(&path, &at_head).expect("verify"),
            Ok(()),
            "a fresh detached worktree at the recorded base is quiescent"
        );

        // HEAD elsewhere.
        assert!(matches!(
            fixture
                .manager
                .quiescence(&path, &Quiescence::AtBase(fixture.seed.clone()))
                .expect("verify"),
            Err(VerifyFailure::HeadMismatch { .. })
        ));

        // The retained cumulative tree.
        let tree = git(&path, &["write-tree"]);
        assert_eq!(
            fixture
                .manager
                .quiescence(&path, &Quiescence::HoldsTree(tree))
                .expect("verify"),
            Ok(())
        );
        assert!(matches!(
            fixture
                .manager
                .quiescence(&path, &Quiescence::HoldsTree("0".repeat(40)))
                .expect("verify"),
            Err(VerifyFailure::TreeMismatch { .. })
        ));

        // Every administrative residue element, one at a time.
        let git_dir = git_dir_of(&path)
            .expect("git dir")
            .expect("linked worktree");
        for (name, element) in [
            ("index.lock", ResidueElement::IndexLock),
            ("CHERRY_PICK_HEAD", ResidueElement::CherryPickHead),
            ("MERGE_HEAD", ResidueElement::MergeHead),
            ("MERGE_MSG", ResidueElement::MergeMsg),
        ] {
            fs::write(git_dir.join(name), "x\n").expect("plant residue");
            assert_eq!(
                fixture.manager.quiescence(&path, &at_head).expect("verify"),
                Err(VerifyFailure::Residue(element)),
                "{name} must make the worktree non-quiescent"
            );
            fs::remove_file(git_dir.join(name)).expect("clear residue");
        }
        fs::create_dir_all(git_dir.join("sequencer")).expect("plant sequencer state");
        assert_eq!(
            fixture.manager.quiescence(&path, &at_head).expect("verify"),
            Err(VerifyFailure::Residue(ResidueElement::SequencerState))
        );
        fs::remove_dir_all(git_dir.join("sequencer")).expect("clear");

        // A missing checkout.
        fs::remove_dir_all(&path).expect("remove the checkout");
        assert_eq!(
            fixture.manager.quiescence(&path, &at_head).expect("verify"),
            Err(VerifyFailure::Missing)
        );
    }

    #[test]
    fn forced_removal_clears_every_administrative_residue_and_is_idempotent() {
        let fixture = Fixture::created("forced-removal");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        let path = fixture.manager.slot_path(&slot);
        let git_dir = git_dir_of(&path)
            .expect("git dir")
            .expect("linked worktree");
        // The element list is `ResidueElement::ALL` — PR3's, frozen — not an
        // array written here. The hand-written array this replaced named six
        // of the seven filesystem elements and omitted the `locked` marker of
        // a registered-but-unpopulated worktree, so the test's own name
        // ("every administrative residue") overclaimed: `git worktree prune`
        // *skips* a locked entry, which is why `remove_worktree` clears it, and
        // deleting that clearing left this test green. Measured as a surviving
        // mutation against this test alone.
        let mut planted = 0;
        for element in ResidueElement::ALL {
            match element {
                ResidueElement::IndexLock => {
                    fs::write(git_dir.join("index.lock"), "x\n").expect("plant");
                }
                ResidueElement::CherryPickHead => {
                    fs::write(git_dir.join("CHERRY_PICK_HEAD"), "x\n").expect("plant");
                }
                ResidueElement::MergeHead => {
                    fs::write(git_dir.join("MERGE_HEAD"), "x\n").expect("plant");
                }
                ResidueElement::MergeMsg => {
                    fs::write(git_dir.join("MERGE_MSG"), "x\n").expect("plant");
                }
                ResidueElement::OrigHead => {
                    fs::write(git_dir.join("ORIG_HEAD"), "x\n").expect("plant");
                }
                ResidueElement::SequencerState => {
                    fs::create_dir_all(git_dir.join("sequencer")).expect("plant");
                }
                ResidueElement::RegisteredUnpopulatedWorktree => {
                    // Git holds this for the whole of an interrupted `add`, and
                    // it is the one element that *blocks* the reclaim path.
                    fs::write(git_dir.join("locked"), "initializing\n").expect("plant");
                }
                // Not administrative residue in a git dir: objects are R27 and
                // leave with Git, never with the worktree.
                ResidueElement::UnreferencedObject | ResidueElement::TemporaryObjectFile => {
                    continue;
                }
            }
            planted += 1;
        }
        assert_eq!(
            planted,
            ResidueElement::ALL.len() - 2,
            "every element of the frozen enum except the two object classes is planted"
        );
        assert_eq!(planted, 7, "seven administrative elements");

        fixture
            .manager
            .remove_worktree(&mut NoHooks, &slot)
            .expect("forced removal succeeds over administrative residue");
        assert!(!path.exists());
        assert!(!git_dir.exists(), "the residue left with the worktree");
        assert!(
            !fixture
                .manager
                .worktree_records()
                .expect("records")
                .iter()
                .any(|record| record.path.ends_with("kalpha-g1"))
        );

        fixture
            .manager
            .remove_worktree(&mut NoHooks, &slot)
            .expect("and is idempotent");
    }

    // -----------------------------------------------------------------------
    // Byte-safe changed paths
    // -----------------------------------------------------------------------

    /// One `-z --name-status` record: a status field and its path fields.
    fn status_record(status: &[u8], paths: &[&[u8]]) -> Vec<u8> {
        let mut bytes = status.to_vec();
        bytes.push(0);
        for path in paths {
            bytes.extend_from_slice(path);
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn changed_paths_decode_byte_wise_and_one_undecodable_path_is_repo_wide() {
        // Hostile, and hostile in independent directions: order, case,
        // separators inside a name, a multi-byte name, a name that is longer
        // than any plausible buffer, and a leading-dot name. The status letters
        // vary independently of the paths, so a decoder that ignored the status
        // field and one that mis-read it are different observations.
        let hostile: &[(&[u8], &[u8])] = &[
            (b"M", b"src/Zebra/UBER.rs"),
            (b"A", b"a b/c\td.rs"),
            (b"D", b".hidden"),
            (b"T", "docs/\u{fc}nicode.md".as_bytes()),
            (
                b"M",
                b"a/very/deep/directory/chain/that/keeps/going/well/past/any/plausible/buffer/size/f.rs",
            ),
            (b"A", b"build.rs"),
        ];
        let mut bytes = Vec::new();
        for (status, path) in hostile {
            bytes.extend_from_slice(&status_record(status, &[path]));
        }
        let decoded = decode_changed_paths(&bytes);
        let paths = decoded.prefixes().expect("every path decoded").to_vec();
        assert_eq!(
            paths.len(),
            hostile.len(),
            "one entry per path, and the count is what says so"
        );
        assert_eq!(
            paths.iter().map(GitPath::as_str).collect::<Vec<_>>().len(),
            paths
                .iter()
                .map(GitPath::as_str)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "and they are distinct"
        );
        for (_, path) in hostile {
            let expected = std::str::from_utf8(path).expect("fixture is UTF-8");
            assert!(
                paths.iter().any(|seen| seen.as_str() == expected),
                "`{expected}` survived the round trip"
            );
        }

        // One undecodable path makes the whole answer repo-wide, not a
        // silently shorter list.
        let mut poisoned = bytes.clone();
        poisoned.extend_from_slice(&status_record(b"M", &[b"bad/\xff\xfe.rs"]));
        assert!(
            decode_changed_paths(&poisoned).is_repo_wide(),
            "an undecodable path is never dropped: the region becomes repo-wide"
        );
        assert!(
            decode_changed_paths(b"")
                .prefixes()
                .expect("empty")
                .is_empty()
        );
    }

    /// **Both** endpoints of a detected rename reach the region.
    ///
    /// `path_policy.actual` is "`--name-status` … both rename endpoints", and
    /// the old endpoint is the one another owner may hold a lease on: an answer
    /// that carries only the destination lets two overlapping edits be admitted
    /// at once (`PR5-CORRECTNESS-005`). Copies carry two endpoints for the same
    /// reason and are decoded the same way.
    ///
    /// The expected paths are written here, not derived from the record, and
    /// the record is written to the grammar in Git's own documentation rather
    /// than produced by this decoder's inverse.
    #[test]
    fn both_endpoints_of_a_rename_or_copy_record_reach_the_region() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&status_record(
            b"R100",
            &[b"src/auth.rs", b"archive/auth.rs"],
        ));
        bytes.extend_from_slice(&status_record(b"C75", &[b"src/lib.rs", b"src/copy.rs"]));
        bytes.extend_from_slice(&status_record(b"A", &[b"src/added.rs"]));
        bytes.extend_from_slice(&status_record(b"D", &[b"src/gone.rs"]));

        let decoded = decode_changed_paths(&bytes);
        let paths: Vec<&str> = decoded
            .prefixes()
            .expect("decoded")
            .iter()
            .map(GitPath::as_str)
            .collect();
        assert_eq!(
            paths,
            vec![
                "archive/auth.rs",
                "src/added.rs",
                "src/auth.rs",
                "src/copy.rs",
                "src/gone.rs",
                "src/lib.rs",
            ],
            "six endpoints from four records: a rename and a copy carry two each"
        );
    }

    /// A status field this grammar does not recognise makes the region
    /// repo-wide rather than shorter.
    ///
    /// `prediction` classifies "unsafe or unparsable forms" as repo-wide, and
    /// repo-wide overlaps everything — so the unparsable direction refuses
    /// rather than admits. The most important cell is the first: it is exactly
    /// what this decoder sees if the invocation ever reverts to `--name-only`,
    /// so that regression cannot produce a plausible short answer.
    #[test]
    fn an_unparsable_status_record_is_repo_wide_and_never_shorter() {
        let cases: &[(&str, Vec<u8>)] = &[
            ("--name-only output, where a path arrives as a status", {
                let mut bytes = Vec::new();
                for path in [b"archive/auth.rs".as_slice(), b"src/added.rs".as_slice()] {
                    bytes.extend_from_slice(path);
                    bytes.push(0);
                }
                bytes
            }),
            (
                "a rename record with only one endpoint",
                status_record(b"R100", &[b"src/auth.rs"]),
            ),
            (
                "a status letter that is not one of Git's",
                status_record(b"Z", &[b"src/auth.rs"]),
            ),
            (
                "a single-endpoint letter carrying a score",
                status_record(b"M50", &[b"src/auth.rs"]),
            ),
            (
                "a rename letter carrying no score",
                status_record(b"R", &[b"src/auth.rs", b"archive/auth.rs"]),
            ),
            (
                "a rename score that is not a number",
                status_record(b"Rxx", &[b"src/auth.rs", b"archive/auth.rs"]),
            ),
            (
                "a status field that does not decode",
                status_record(b"\xff", &[b"src/auth.rs"]),
            ),
        ];
        for (name, bytes) in cases {
            assert!(
                decode_changed_paths(bytes).is_repo_wide(),
                "{name}: an unparsable record must be repo-wide, not a shorter list"
            );
        }
        assert_eq!(cases.len(), 7, "seven independent unparsable shapes");
    }

    /// A Git child that **fails** inside a funnel body records `Before` only
    /// (`PR5-WORKSPACE-047`).
    ///
    /// `effect_site_inventory.identity`: "each Object site has exactly the
    /// parent-executed hook phases `Before` (no object) and `After` (object
    /// present and referenced as `row()` states…)". Every failure path the
    /// suite drove refused *before* the funnel was entered — slot-name
    /// refusals, `AddWithoutIntent`, symbolic-ref, malformed-oid, containment —
    /// so no hooks fired at all, and the harness's own `Injection::Error` is
    /// applied at a phase rather than to the primitive. The state the sentence
    /// is about was therefore never built: `Before` recorded, the primitive
    /// failed, `After` not claimed. A funnel that claimed `After` from an
    /// unconditional cleanup guard would say an object is present and
    /// referenced when the child that would have written it exited non-zero.
    ///
    /// Both funnel shapes are driven: the shared `funnel()` helper, and the
    /// hand-rolled `commit_tree` sequence that also carries `IdUnread`.
    #[test]
    fn a_git_child_that_fails_inside_a_funnel_records_before_and_never_claims_after() {
        let fixture = Fixture::created("funnel-failure");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        // Well-formed and absent: it passes every argument check and then makes
        // the child itself fail, which is the only way into the funnel body.
        let absent = "0".repeat(39) + "1";

        /// One failing drive: it runs a Git child that exits non-zero inside a
        /// funnel body and answers whether the call really failed.
        type FailingDrive = Box<dyn Fn(&mut dyn EffectHooks) -> bool>;
        let cases: Vec<(&str, EffectSiteId, FailingDrive)> = vec![
            (
                "the shared funnel (Object.ProposalCherryPick)",
                EffectSiteId::Object(ObjectSite::ProposalCherryPick),
                Box::new(|hooks: &mut dyn EffectHooks| {
                    let fixture = Fixture::created("funnel-failure-cherry");
                    let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
                    fixture
                        .manager
                        .proposal_cherry_pick(hooks, &slot, &("0".repeat(39) + "1"))
                        .is_err()
                }),
            ),
            (
                "the commit-tree sequence (Object.CandidateCommitTree)",
                EffectSiteId::Object(ObjectSite::CandidateCommitTree),
                Box::new(|hooks: &mut dyn EffectHooks| {
                    let fixture = Fixture::created("funnel-failure-commit");
                    fixture
                        .manager
                        .candidate_commit_tree(
                            hooks,
                            &("0".repeat(39) + "1"),
                            &fixture.head,
                            "tactus: candidate",
                        )
                        .is_err()
                }),
            ),
        ];

        for (what, site, drive) in cases {
            let (mut hooks, shared) = harness();
            assert!(
                drive(&mut hooks),
                "{what}: the child was supposed to fail and did not"
            );
            let harness = shared.lock().expect("harness");
            assert_eq!(
                harness.count(site, HookPhase::Before),
                1,
                "{what}: the funnel was entered, so Before fired once"
            );
            assert_eq!(
                harness.count(site, HookPhase::After),
                0,
                "{what}: the primitive failed, so there is no object present and referenced                  for After to be claiming"
            );
        }

        let _ = &slot;
        let _ = &absent;
    }

    /// Two generations of one task key are two different worktrees
    /// (`PR5-WORKSPACE-010`).
    ///
    /// `manager`: "detached linked worktrees with durable synced intents
    /// (`tasks/k<key>-g<gen>`, `merge/s<seq>`)". Every Task slot in this file
    /// is built at a single generation, so the two paths that would collide
    /// were never both constructed and dropping `-g<generation>` from
    /// `relative()` was invisible. `intent_name` still carried the generation,
    /// and it is `intent_name` the round-trip tests exercise — so the
    /// injectivity they prove is the file name's, not the worktree path's.
    #[test]
    fn two_generations_of_one_task_key_are_two_worktrees() {
        let fixture = Fixture::created("generations");
        let first = fixture.task("alpha", 0);
        let second = fixture.task("alpha", 1);

        assert_ne!(
            fixture.manager.slot_path(&first),
            fixture.manager.slot_path(&second),
            "one key at two generations must not name one directory"
        );
        assert!(
            first
                .relative()
                .ends_with("tasks/k alpha-g0".replace(' ', "").as_str()),
            "the packet spells it tasks/k<key>-g<gen>: {}",
            first.relative().display()
        );
        assert!(
            second.relative().ends_with("tasks/kalpha-g1"),
            "{}",
            second.relative().display()
        );

        // And both really exist at once, which is the state a collision
        // destroys: the second add would land in the first's checkout.
        fixture.add_task(&mut NoHooks, "alpha", 0);
        fixture.add_task(&mut NoHooks, "alpha", 1);
        for slot in [&first, &second] {
            assert_eq!(
                fixture
                    .manager
                    .quiescence(
                        &fixture.manager.slot_path(slot),
                        &Quiescence::AtBase(fixture.head.clone())
                    )
                    .expect("verify"),
                Ok(()),
                "{slot:?} is its own quiescent worktree"
            );
        }
        assert_eq!(
            fixture
                .manager
                .worktree_records()
                .expect("records")
                .iter()
                .filter(|record| record.path.starts_with(fixture.manager.execution_root()))
                .count(),
            2,
            "two registrations, not one directory registered twice"
        );
    }

    /// A task worktree is **detached** even when the commit-ish is a branch
    /// name (`PR5-WORKSPACE-012`).
    ///
    /// `git worktree add <path> <sha>` detaches HEAD with or without
    /// `--detach`, and every fixture in this file passes a raw 40-hex id — so
    /// the flag was behaviour-neutral on everything the suite built, and
    /// nothing ever read HEAD's attachment state after an add or enumerated the
    /// refs an add created. A branch name is the one commit-ish where the flag
    /// decides, and without it `git worktree add` checks the branch out **and
    /// locks it to that worktree**, which is the state `integration_ref`'s
    /// "never checked out" forbids for the run namespace.
    #[test]
    fn a_task_worktree_is_detached_even_when_the_base_names_a_branch() {
        let fixture = Fixture::created("detached");
        let slot = fixture.task("alpha", 1);
        let before: BTreeSet<String> = fixture
            .manager
            .refs_under("refs/heads")
            .expect("refs")
            .into_iter()
            .map(|(name, _)| name)
            .collect();

        fixture
            .manager
            .write_intent(&mut NoHooks, &slot)
            .expect("intent");
        fixture
            .manager
            .add_worktree(&mut NoHooks, &slot, "side")
            .expect("add at a branch NAME, not a sha");

        let path = fixture.manager.slot_path(&slot);
        assert_eq!(
            git(&path, &["rev-parse", "HEAD"]),
            fixture.side,
            "the worktree is at the branch's commit"
        );
        assert_eq!(
            git(&path, &["rev-parse", "--symbolic-full-name", "HEAD"]),
            "HEAD",
            "and its HEAD is detached rather than pointing at refs/heads/side"
        );
        let after: BTreeSet<String> = fixture
            .manager
            .refs_under("refs/heads")
            .expect("refs")
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(after, before, "the add created and moved no branch ref");
    }

    /// A clean worktree of a **different repository** at the recorded path
    /// fails verification (`PR5-WORKSPACE-019`).
    ///
    /// `generation`: "`Worktree.Verify`: the recorded path is a linked worktree
    /// of **this** repository". `worktree_verify_answers_every_non_quiescence_
    /// by_name` drives every other failure by name and never this one — no
    /// fixture built a second repository — so the identity half of the sentence
    /// was unobserved and deleting the common-git-dir comparison changed
    /// nothing. The foreign worktree holds the **same commit object**, so a
    /// verifier that only compared HEAD would still pass it.
    #[test]
    fn a_worktree_of_another_repository_at_the_recorded_path_is_not_this_ones() {
        let fixture = Fixture::created("foreign-repo");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        let path = fixture.manager.slot_path(&slot);

        // A second repository holding the very same commit object, so identity
        // is the only thing that separates its checkout from the real one.
        let foreign = fixture.root.join("foreign");
        fs::create_dir_all(&foreign).expect("foreign repo");
        git(&foreign, &["init", "-q", "-b", "main"]);
        git(&foreign, &["config", "user.email", "tests@tactus.local"]);
        git(&foreign, &["config", "user.name", "tactus tests"]);
        git(
            &foreign,
            &["fetch", "-q", &fixture.base.to_string_lossy(), "main"],
        );
        let fetched = git(&foreign, &["rev-parse", "FETCH_HEAD"]);
        assert_eq!(
            fetched, fixture.head,
            "the foreign repository holds the identical commit object"
        );

        // The recorded path stays registered in **this** repository — a
        // verifier that stopped at "is it registered here" must still be
        // reached — while the checkout sitting there belongs to the other one.
        let theirs = fixture.root.join("theirs");
        git(
            &foreign,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                &theirs.to_string_lossy(),
                &fetched,
            ],
        );
        let foreign_gitfile = fs::read(theirs.join(".git")).expect("their .git file");
        fs::write(path.join(".git"), &foreign_gitfile).expect("point the checkout at their repo");

        assert!(
            fixture
                .manager
                .quiescence(&path, &Quiescence::AtBase(fixture.head.clone()))
                .expect("verify")
                != Err(VerifyFailure::NotRegistered),
            "the path is still registered here, so this is not the registration check"
        );
        assert_eq!(
            git(&path, &["rev-parse", "HEAD"]),
            fixture.head,
            "and a HEAD-only verifier would see exactly what it expects"
        );
        assert_eq!(
            fixture
                .manager
                .quiescence(&path, &Quiescence::AtBase(fixture.head.clone()))
                .expect("verify"),
            Err(VerifyFailure::ForeignRepository),
            "but it is another repository's worktree at this repository's recorded path"
        );
    }

    /// The recorded base is honoured **after the worktree's HEAD has moved off
    /// it** (`PR5-WORKSPACE-038`).
    ///
    /// `path_policy.actual` specifies `git diff-tree -r -z -M --name-status
    /// base tree` — a diff between two *recorded* values. Every other fixture
    /// in this file leaves the worktree checked out at exactly the base it then
    /// passes, so `diff --cached <base>` and a bare `diff --cached` name the
    /// same diff and a primitive that had quietly stopped honouring its
    /// argument was indistinguishable from one that honoured it. Nothing here
    /// asserts a spelling; it moves the one variable the two readings disagree
    /// about and checks the answer.
    #[test]
    fn changed_paths_honour_the_recorded_base_after_head_has_moved_off_it() {
        let fixture = Fixture::created("changed-paths-moved-head");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        let path = fixture.manager.slot_path(&slot);
        fs::write(path.join("staged.rs"), "fn main() {}\n").expect("add");
        fixture
            .manager
            .candidate_stage(&mut NoHooks, &slot)
            .expect("stage");

        // Move the worktree's HEAD to the seed, keeping the index. `head` is
        // still the recorded base; HEAD is now `seed`, one commit behind it.
        git(&path, &["reset", "-q", "--soft", &fixture.seed]);
        assert_eq!(
            git(&path, &["rev-parse", "HEAD"]),
            fixture.seed,
            "the worktree's HEAD really moved off the recorded base"
        );
        assert_ne!(fixture.seed, fixture.head, "the two must differ at all");

        let against_base: Vec<String> = fixture
            .manager
            .changed_paths(&slot, &fixture.head)
            .expect("capture")
            .prefixes()
            .expect("decoded")
            .iter()
            .map(|path| path.as_str().to_owned())
            .collect();
        assert_eq!(
            against_base,
            vec!["staged.rs".to_owned()],
            "the diff is against the recorded base, not against wherever HEAD is now"
        );

        // And the two readings really are different here, so the assertion
        // above is not passing for want of a distinction: `b.txt` arrived
        // between the seed and the base, so a HEAD-relative diff carries it.
        let head_relative = git(&path, &["diff", "--cached", "--name-only"]);
        let head_relative: Vec<&str> = head_relative.lines().collect();
        assert!(
            head_relative.contains(&"b.txt"),
            "the fixture does not separate the two readings: {head_relative:?}"
        );
    }

    /// Each commit-tree site commits onto the **recorded** parent after HEAD
    /// has moved (`PR5-WORKSPACE-023`, `PR5-WORKSPACE-042`).
    ///
    /// `snapshots` says "the snapshot funnel first creates an ephemeral commit
    /// of that tree on **the recorded parent**", and `candidate` says
    /// `parent_sha == base_sha`. Both were asserted against a base the
    /// repository's HEAD already equalled, so `commit-tree <tree> -p <recorded>`
    /// and a body that had re-read the world produced the same commit. The
    /// manipulation is one line — move HEAD — and it is the only one that
    /// separates a primitive that honours its argument from one that does not.
    #[test]
    fn the_commit_tree_sites_use_the_recorded_parent_and_not_current_head() {
        let fixture = Fixture::created("recorded-parent");
        let tree = git(&fixture.base, &["rev-parse", "HEAD^{tree}"]);
        let recorded = fixture.head.clone();

        git(
            &fixture.base,
            &["checkout", "-q", "--detach", &fixture.side],
        );
        assert_eq!(
            git(&fixture.base, &["rev-parse", "HEAD"]),
            fixture.side,
            "HEAD moved off the recorded parent"
        );
        assert_ne!(fixture.side, recorded);

        for (what, commit) in [
            (
                "snapshot",
                fixture
                    .manager
                    .snapshot_commit_tree(&mut NoHooks, &tree, &recorded)
                    .expect("the ephemeral snapshot commit"),
            ),
            (
                "candidate",
                fixture
                    .manager
                    .candidate_commit_tree(&mut NoHooks, &tree, &recorded, "tactus: candidate")
                    .expect("the candidate commit"),
            ),
        ] {
            let parents = git(
                &fixture.base,
                &["rev-list", "--parents", "-n", "1", &commit],
            );
            let parents: Vec<&str> = parents.split_whitespace().skip(1).collect();
            assert_eq!(
                parents,
                vec![recorded.as_str()],
                "{what}: the sole parent is the recorded one, not current HEAD ({})",
                fixture.side
            );
            assert_eq!(
                git(&fixture.base, &["rev-parse", &format!("{commit}^{{tree}}")]),
                tree,
                "{what}: the tree is the supplied one"
            );
        }
    }

    /// An undecodable byte in a rename **source** makes the region repo-wide
    /// (`PR5-WORKSPACE-036`).
    ///
    /// `path_policy.actual`: "both rename endpoints; NUL-delimited bytes;
    /// GitPath byte-safe; **undecodable -> repo-wide**". The lane had solid
    /// coverage on each axis separately and never their intersection: every
    /// rename fixture's four endpoints are valid UTF-8, and every undecodable
    /// fixture plants its bad byte in a single-endpoint record. So the one
    /// field a source-dropping decoder treats differently was never hostile,
    /// and "both endpoints or repo-wide" could not be told from "the
    /// destination, plus the source when it happens to decode" — which loses a
    /// path another owner may hold a lease on, silently.
    #[test]
    fn an_undecodable_rename_source_makes_the_region_repo_wide() {
        // A rename whose DESTINATION is perfectly ordinary, so a decoder that
        // returns what it could read returns something plausible.
        let source_bad = status_record(b"R100", &[b"src/\xff\xfe.rs", b"archive/auth.rs"]);
        assert!(
            decode_changed_paths(&source_bad).is_repo_wide(),
            "an undecodable rename source is not a path that may be quietly dropped"
        );

        // The other endpoint, and a copy record, so this is the field rather
        // than the record kind.
        let destination_bad = status_record(b"R100", &[b"src/auth.rs", b"archive/\xff.rs"]);
        assert!(decode_changed_paths(&destination_bad).is_repo_wide());
        let copy_source_bad = status_record(b"C75", &[b"src/\xff.rs", b"copy/auth.rs"]);
        assert!(decode_changed_paths(&copy_source_bad).is_repo_wide());

        // And the same record with both endpoints decodable is NOT repo-wide,
        // so the assertions above are about the undecodable byte rather than
        // about rename records in general.
        let both_fine = status_record(b"R100", &[b"src/auth.rs", b"archive/auth.rs"]);
        let decoded = decode_changed_paths(&both_fine);
        assert!(!decoded.is_repo_wide());
        let paths: Vec<&str> = decoded
            .prefixes()
            .expect("decoded")
            .iter()
            .map(GitPath::as_str)
            .collect();
        assert_eq!(paths, vec!["archive/auth.rs", "src/auth.rs"]);
    }

    #[test]
    fn changed_paths_come_from_the_index_of_the_recorded_worktree() {
        let fixture = Fixture::created("changed-paths");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        let path = fixture.manager.slot_path(&slot);
        fs::write(path.join("a.txt"), "changed\n").expect("edit");
        fs::create_dir_all(path.join("nested")).expect("nested");
        fs::write(path.join("nested/new.rs"), "fn main() {}\n").expect("add");
        fixture
            .manager
            .candidate_stage(&mut NoHooks, &slot)
            .expect("stage");

        let captured = fixture
            .manager
            .changed_paths(&slot, &fixture.head)
            .expect("capture");
        let paths: Vec<&str> = captured
            .prefixes()
            .expect("decoded")
            .iter()
            .map(GitPath::as_str)
            .collect();
        assert_eq!(paths, vec!["a.txt", "nested/new.rs"]);
    }

    /// The same claim against **real Git**, over the change kinds the previous
    /// test does not contain.
    ///
    /// `PR5-CORRECTNESS-005`: the shipped invocation was `--name-only`, and
    /// rename detection is Git's default — so a staged rename produced the
    /// destination alone and the source, which another owner may hold a lease
    /// on, silently left the region. That coverage held "one modification and
    /// one addition", the two kinds where every invocation agrees.
    ///
    /// Four kinds here, and the expected list is written out rather than
    /// derived: a rename (two endpoints), a deletion, an addition, and a
    /// modification. The rename is made by moving the file on disk and staging
    /// through the production funnel, so detection is Git's decision at diff
    /// time and not something the fixture asserted into being — which is also
    /// why the record is checked to really be an `R`.
    #[test]
    fn every_change_kind_reaches_the_region_including_both_rename_endpoints() {
        let fixture = Fixture::created("changed-paths-kinds");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        let path = fixture.manager.slot_path(&slot);

        // A base inside the worktree holding one file of each kind's
        // pre-state, so all four kinds can be produced against one commit.
        fs::write(path.join("kept.txt"), "before\n").expect("kept");
        fs::write(path.join("doomed.txt"), "doomed\n").expect("doomed");
        fs::write(path.join("moved.txt"), "moved\n").expect("moved");
        git(&path, &["add", "-A"]);
        git(&path, &["commit", "-q", "-m", "the base for this diff"]);
        let base = git(&path, &["rev-parse", "HEAD"]);

        // moved.txt -> archive/moved.txt, byte-identical: 100% similarity.
        fs::create_dir_all(path.join("archive")).expect("archive dir");
        fs::rename(path.join("moved.txt"), path.join("archive/moved.txt")).expect("move");
        fs::remove_file(path.join("doomed.txt")).expect("delete");
        fs::write(path.join("added.rs"), "fn main() {}\n").expect("add");
        fs::write(path.join("kept.txt"), "after\n").expect("modify");

        fixture
            .manager
            .candidate_stage(&mut NoHooks, &slot)
            .expect("stage");

        // Git really did detect a rename here, rather than reporting a delete
        // and an add — otherwise this fixture would pass under `--name-only`
        // too and would be witnessing nothing.
        let records = git(&path, &["diff", "--cached", "--name-status", "-M", &base]);
        assert!(
            records.contains("R100\tmoved.txt\tarchive/moved.txt"),
            "the fixture must contain a *detected* rename, or it tests nothing: {records}"
        );

        let captured = fixture
            .manager
            .changed_paths(&slot, &base)
            .expect("capture");
        let paths: Vec<&str> = captured
            .prefixes()
            .expect("decoded")
            .iter()
            .map(GitPath::as_str)
            .collect();
        assert_eq!(
            paths,
            vec![
                "added.rs",
                "archive/moved.txt",
                "doomed.txt",
                "kept.txt",
                "moved.txt",
            ],
            "both rename endpoints, the deletion, the addition and the modification"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_repository_path_a_string_cannot_carry_makes_the_region_repo_wide() {
        use std::os::unix::ffi::OsStrExt as _;
        let fixture = Fixture::created("nonutf8-paths");
        let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
        let path = fixture.manager.slot_path(&slot);
        let hostile = path.join(OsStr::from_bytes(b"bad-\xff\xfe.txt"));
        if fs::write(&hostile, "bytes\n").is_err() {
            // A filesystem that refuses the name cannot host the fixture; the
            // pure-byte case above still covers the decision.
            return;
        }
        fixture
            .manager
            .candidate_stage(&mut NoHooks, &slot)
            .expect("stage");
        assert!(
            fixture
                .manager
                .changed_paths(&slot, &fixture.head)
                .expect("capture")
                .is_repo_wide(),
            "a path no string can carry makes the region repo-wide rather than shorter"
        );
    }

    // -----------------------------------------------------------------------
    // The Object group: rows, IdUnread, and the residue classifier
    // -----------------------------------------------------------------------

    /// `slice_contract.proof_tests[7]`: "after each creation primitive the
    /// object is referenced by exactly the row `row()` names (index/HEAD
    /// inspection; fsck for R27)".
    ///
    /// The expected row per site comes from the frozen `ObjectSite::row()`, and
    /// the *observation* comes from Git — index, HEAD, or `fsck`. The two are
    /// independent: nothing here asks the site what it expects and then asks it
    /// again what it found.
    #[test]
    fn after_each_object_primitive_the_object_is_referenced_by_the_row_row_names() {
        let fixture = Fixture::created("object-rows");
        let mut checked = Vec::new();

        // R9: Object.CandidateStage — blobs behind the task worktree index.
        let task = fixture.add_task(&mut NoHooks, "alpha", 1);
        let task_path = fixture.manager.slot_path(&task);
        fs::write(task_path.join("staged.txt"), "staged\n").expect("edit");
        let blob = git(&task_path, &["hash-object", "staged.txt"]);
        fixture
            .manager
            .candidate_stage(&mut NoHooks, &task)
            .expect("stage");
        assert_eq!(ObjectSite::CandidateStage.row(), ResourceRow::R9);
        assert!(
            git(&task_path, &["ls-files", "-s"]).contains(&blob),
            "the staged blob is referenced by the task worktree index"
        );
        assert!(
            !unreachable_objects(&task_path)
                .expect("fsck")
                .contains(&blob),
            "so it is not R27"
        );
        checked.push(ObjectSite::CandidateStage);

        // R9: Object.CandidateWriteTree — trees behind that index's cache-tree.
        let tree = fixture
            .manager
            .candidate_write_tree(&mut NoHooks, &task)
            .expect("write-tree");
        assert_eq!(ObjectSite::CandidateWriteTree.row(), ResourceRow::R9);
        assert!(
            !unreachable_objects(&task_path)
                .expect("fsck")
                .contains(&tree),
            "the tree is reachable through the index's cache-tree extension: R9, not R27"
        );
        checked.push(ObjectSite::CandidateWriteTree);

        // R27: Object.SnapshotCommitTree — unreferenced until Snapshot.Add.
        let ephemeral = fixture
            .manager
            .snapshot_commit_tree(&mut NoHooks, &tree, &fixture.head)
            .expect("ephemeral commit");
        assert_eq!(ObjectSite::SnapshotCommitTree.row(), ResourceRow::R27);
        assert!(
            unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&ephemeral),
            "the ephemeral commit is unreferenced: R27"
        );
        checked.push(ObjectSite::SnapshotCommitTree);

        // R27: Object.CandidateCommitTree — unreferenced until the pin.
        let candidate = fixture
            .manager
            .candidate_commit_tree(&mut NoHooks, &tree, &fixture.head, "candidate")
            .expect("candidate commit");
        assert_eq!(ObjectSite::CandidateCommitTree.row(), ResourceRow::R27);
        assert!(
            unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&candidate),
            "the candidate commit is unreferenced: R27"
        );
        // …and R23 once pinned, which is the row that then accounts for it.
        fixture
            .manager
            .create_ref_zero_old(
                &mut NoHooks,
                RefSite::PinCandidatePrepared,
                "refs/tactus/runs/run-1/candidate-prepared/kalpha/1",
                &candidate,
            )
            .expect("pin");
        assert_eq!(RefSite::PinCandidatePrepared.row(), ResourceRow::R23);
        assert!(
            !unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&candidate),
            "the pin moves it out of R27 and into the row that references it"
        );
        checked.push(ObjectSite::CandidateCommitTree);

        // R10: Object.ProposalCherryPick — through the staging HEAD.
        let staging = Slot::Staging { sequence: 1 };
        fixture
            .manager
            .write_intent(&mut NoHooks, &staging)
            .expect("staging intent");
        let staging_path = fixture
            .manager
            .add_worktree(&mut NoHooks, &staging, &fixture.head)
            .expect("staging worktree");
        let proposal = fixture
            .manager
            .proposal_cherry_pick(&mut NoHooks, &staging, &fixture.side)
            .expect("cherry-pick");
        assert_eq!(ObjectSite::ProposalCherryPick.row(), ResourceRow::R10);
        assert_eq!(
            git(&staging_path, &["rev-parse", "HEAD"]),
            proposal,
            "the proposal commit is the staging worktree's HEAD"
        );
        assert!(
            !unreachable_objects(&staging_path)
                .expect("fsck")
                .contains(&proposal),
            "so it is not R27 while the staging worktree exists"
        );
        checked.push(ObjectSite::ProposalCherryPick);

        // R9: Object.RepairMaterialize — merge objects behind the repair index.
        let repair = fixture.add_task(&mut NoHooks, "repair", 1);
        let repair_path = fixture.manager.slot_path(&repair);
        fixture
            .manager
            .repair_materialize(&mut NoHooks, &repair, &fixture.side)
            .expect("materialize");
        assert_eq!(ObjectSite::RepairMaterialize.row(), ResourceRow::R9);
        assert!(
            index_differs_from_head(&repair_path).expect("index"),
            "the materialization is staged in the repair worktree's index"
        );
        let materialized = git(&repair_path, &["rev-parse", ":c.txt"]);
        assert!(
            !unreachable_objects(&repair_path)
                .expect("fsck")
                .contains(&materialized),
            "index-referenced, so R9 rather than R27"
        );
        checked.push(ObjectSite::RepairMaterialize);

        // And the domain is the enum's, not the author's memory.
        checked.sort();
        checked.dedup();
        assert_eq!(
            checked.len(),
            ObjectSite::ALL.len(),
            "every Object site the frozen enum declares has a row observation; missing: {:?}",
            ObjectSite::ALL
                .iter()
                .filter(|site| !checked.contains(site))
                .collect::<Vec<_>>()
        );

        // The scrub releases what the worktree held — and `cleanup` states the
        // disjunction the release obeys: "objects released to R27 **or
        // accounted by the candidate pin/ref**". Both halves are asserted,
        // because a test that checked only the first would be measuring
        // whichever half the fixture happened to build.
        fixture
            .manager
            .remove_worktree(&mut NoHooks, &task)
            .expect("scrub");
        assert!(
            !unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&blob),
            "the staged blob is in the candidate commit's tree, so the candidate-prepared pin \
             (R23) still accounts for it after the scrub"
        );
        fixture
            .manager
            .delete_ref_expected_old(
                &mut NoHooks,
                RefSite::DeleteCandidatePin,
                "refs/tactus/runs/run-1/candidate-prepared/kalpha/1",
                &candidate,
            )
            .expect("prune the pin expected-old");
        assert!(
            unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&blob),
            "and once no pin or ref references it, it is R27"
        );
        fixture
            .manager
            .remove_worktree(&mut NoHooks, &staging)
            .expect("reclaim staging");
        assert!(
            unreachable_objects(&fixture.base)
                .expect("fsck")
                .contains(&proposal),
            "and removing the staging worktree releases the proposal objects"
        );
    }

    /// `slice_contract.proof_tests[7]`: "IdUnread hook tests for the
    /// commit-tree primitives".
    #[test]
    fn the_commit_tree_primitives_consult_their_id_unread_point() {
        let fixture = Fixture::created("id-unread");
        let (mut hooks, shared) = harness();
        let tree = git(
            &fixture.base,
            &["rev-parse", &format!("{}^{{tree}}", fixture.head)],
        );
        fixture
            .manager
            .snapshot_commit_tree(&mut hooks, &tree, &fixture.head)
            .expect("ephemeral");
        fixture
            .manager
            .candidate_commit_tree(&mut hooks, &tree, &fixture.head, "candidate")
            .expect("candidate");

        let harness = shared.lock().expect("harness");
        let mut with_point = Vec::new();
        for site in lane_sites() {
            let declared = site.sub_effects().contains(&SubEffectPoint::IdUnread);
            let reached =
                harness.reached_point(site, SubEffectPoint::IdUnread, InjectionMode::Kill);
            assert_eq!(
                declared, reached,
                "`{site}` declares IdUnread = {declared} but the funnels reached it = {reached}"
            );
            if declared {
                with_point.push(site);
            }
        }
        assert_eq!(
            with_point.len(),
            2,
            "exactly the two commit-tree sites expose IdUnread: {with_point:?}"
        );
        assert!(
            !harness.observed(
                EffectSiteId::Object(ObjectSite::CandidateCommitTree),
                HookPhase::Point {
                    point: SubEffectPoint::IdUnread,
                    mode: InjectionMode::Kill,
                }
            ),
            "reaching a point is not executing its injection: nothing was armed"
        );
    }

    /// The durable state a kill at `IdUnread` leaves, without aborting this
    /// process: the object is written and no id was recorded.
    ///
    /// `transaction_fault_matrix[T-CAND-OBJ].resume_action` for that prefix is
    /// "(a) nothing to delete: the unpinned object is left to Git (never
    /// adopted)". The abort itself is exercised by
    /// `a_kill_at_id_unread_aborts_before_the_id_is_recorded`, which runs in a
    /// child process because `Injection::Kill` aborts by design.
    #[test]
    fn a_kill_at_id_unread_leaves_a_gc_owned_object_nothing_adopts() {
        let fixture = Fixture::created("id-unread-residue");
        let tree = git(
            &fixture.base,
            &["rev-parse", &format!("{}^{{tree}}", fixture.head)],
        );
        let commit = fixture
            .manager
            .candidate_commit_tree(&mut NoHooks, &tree, &fixture.head, "candidate")
            .expect("candidate commit");

        // The parent never recorded the id: exactly `IdUnread`.
        let target = ResidueTarget::new(&fixture.base);
        assert_eq!(
            classify_object_residue(
                EffectSiteId::Object(ObjectSite::CandidateCommitTree),
                &target
            )
            .expect("classify"),
            ObjectResidue::Internal
        );
        // And with the id recorded, the very same durable state is the after
        // phase. The classifier's answer is a function of the record, which is
        // what `IdUnread` is defined by the absence of.
        assert_eq!(
            classify_object_residue(
                EffectSiteId::Object(ObjectSite::CandidateCommitTree),
                &ResidueTarget::new(&fixture.base).published(&commit)
            )
            .expect("classify"),
            ObjectResidue::After
        );

        let before = unreachable_objects(&fixture.base).expect("fsck");
        assert!(before.contains(&commit));
        fixture
            .manager
            .reclaim_intents(&mut NoHooks)
            .expect("the tabled recovery");
        let after = unreachable_objects(&fixture.base).expect("fsck");
        assert!(
            after.contains(&commit),
            "fsck still lists the object unreachable and untouched: the run never deletes it"
        );
    }

    /// The abort half, in a child process. `Injection::Kill` calls
    /// `std::process::abort` on purpose — a coordinator that died running
    /// destructors would not be the thing under test — so the only way to
    /// observe it is from outside.
    #[test]
    fn a_kill_at_id_unread_aborts_before_the_id_is_recorded() {
        let record = scratch("id-unread-kill").join("record");
        let helper = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "workspace_manager::tests::id_unread_kill_helper",
                "--ignored",
                "--nocapture",
            ])
            .env(ID_UNREAD_RECORD, &record)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("run the helper");
        assert!(
            !helper.status.success(),
            "the helper must die at the point rather than finish"
        );
        let written = fs::read_to_string(&record).expect("the helper recorded its repository");
        let mut lines = written.lines();
        let repository = PathBuf::from(lines.next().expect("repository path"));
        let tree = lines.next().expect("tree").to_owned();

        // The child died at `IdUnread`: the object is in the store and no id
        // was ever recorded anywhere.
        let unreachable = unreachable_objects(&repository).expect("fsck");
        assert!(
            !unreachable.is_empty(),
            "the object the child wrote survives its death"
        );
        assert_eq!(
            classify_object_residue(
                EffectSiteId::Object(ObjectSite::CandidateCommitTree),
                &ResidueTarget::new(&repository)
            )
            .expect("classify"),
            ObjectResidue::Internal,
            "and the durable state classifies as the internal residue class"
        );
        assert!(!tree.is_empty());
        let _ = fs::remove_dir_all(repository.parent().unwrap_or(&repository));
    }

    /// Where the helper tells its parent which repository to inspect.
    const ID_UNREAD_RECORD: &str = "TACTUS_PR5A_ID_UNREAD_RECORD";

    /// Spawned by `a_kill_at_id_unread_aborts_before_the_id_is_recorded`.
    #[test]
    #[ignore = "subprocess helper"]
    fn id_unread_kill_helper() {
        let Some(record) = std::env::var_os(ID_UNREAD_RECORD) else {
            return;
        };
        let fixture = Fixture::created("id-unread-helper");
        let tree = git(
            &fixture.base,
            &["rev-parse", &format!("{}^{{tree}}", fixture.head)],
        );
        fs::write(&record, format!("{}\n{tree}\n", fixture.base.display()))
            .expect("record the repository before dying");
        let manager = fixture.manager.clone();
        let head = fixture.head.clone();
        // Keep the repository: the parent inspects it after this process dies,
        // and `Fixture`'s destructor would remove it — which is also exactly
        // what an aborting process does not run.
        std::mem::forget(fixture);

        struct KillAtIdUnread;
        impl EffectHooks for KillAtIdUnread {
            fn phase(&mut self, _site: EffectSiteId, phase: HookPhase) -> Injection {
                match phase {
                    HookPhase::Point {
                        point: SubEffectPoint::IdUnread,
                        ..
                    } => Injection::Kill,
                    _ => Injection::Proceed,
                }
            }
        }
        let _ = manager.candidate_commit_tree(&mut KillAtIdUnread, &tree, &head, "candidate");
        unreachable!("the funnel aborts at IdUnread");
    }

    // -----------------------------------------------------------------------
    // The residue classifier: totality, elements, and kill sampling
    // -----------------------------------------------------------------------

    /// Write an object nothing references.
    fn write_orphan(repository: &Path, content: &str) -> String {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn git hash-object");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(content.as_bytes())
            .expect("feed the object");
        let output = child.wait_with_output().expect("hash-object");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn classify(site: EffectSiteId, target: &ResidueTarget<'_>) -> ObjectResidue {
        classify_object_residue(site, target).expect("the classifier answers")
    }

    #[test]
    fn classify_object_residue_refuses_a_site_that_registers_no_class() {
        let fixture = Fixture::created("classifier-domain");
        let target = ResidueTarget::new(&fixture.base);
        for site in lane_sites() {
            let answer = classify_object_residue(site, &target);
            assert_eq!(
                answer.is_ok(),
                !site.residue_classes().is_empty(),
                "`{site}` registers {} residue classes, so the classifier must {} it",
                site.residue_classes().len(),
                if site.residue_classes().is_empty() {
                    "refuse"
                } else {
                    "answer for"
                }
            );
        }
        let message = refusal_of(
            &classify_object_residue(EffectSiteId::Worktree(WorktreeSite::Verify), &target)
                .expect_err("a site with no class refuses"),
        );
        assert!(
            message.contains("registers no residue class"),
            "the refusal must name its reason: {message}"
        );
    }

    /// `command_internal_sub_effects`: "the classifier is **total** over
    /// `{None, Internal, After}` for every Object site and for `Worktree.Add` /
    /// `Snapshot.Add`".
    ///
    /// Totality is proved by *producing all three at every site*, not by an
    /// exhaustive `match` returning a default. The site list is
    /// [`residue_classified_sites`], derived from the frozen enums — a grid over
    /// the sites its author remembered is the `bounded_grid` failure this
    /// project has recorded three times.
    #[test]
    fn the_classifier_is_total_over_three_classes_for_every_registered_site() {
        let sites = residue_classified_sites();
        assert_eq!(
            sites.len(),
            ObjectSite::ALL.len() + 3,
            "six Object sites plus Worktree.Add, Worktree.AddStaging and Snapshot.Add: {sites:?}"
        );
        for site in &sites {
            let observed = observed_three_classes(*site);
            assert_eq!(
                observed,
                [
                    ObjectResidue::None,
                    ObjectResidue::Internal,
                    ObjectResidue::After
                ],
                "`{site}` must answer each of the three classes for the state that is that class"
            );
        }
        // And every value of the codomain was produced, which is the property
        // a per-site assertion alone would not state.
        assert_eq!(ObjectResidue::ALL.len(), 3);
    }

    /// Drive one site through a state of each class, in the order
    /// `[None, Internal, After]`.
    ///
    /// A site with no arm here panics rather than being skipped: that is what
    /// makes the domain the enum's rather than this function's.
    fn observed_three_classes(site: EffectSiteId) -> [ObjectResidue; 3] {
        let tag = format!("total-{}", site.variant().to_lowercase());
        let fixture = Fixture::created(&tag);
        let base = fixture.base.clone();
        assert!(
            unreachable_objects(&base).expect("fsck").is_empty(),
            "the fixture must start with an empty R27, or `None` would be unobservable"
        );

        match site {
            EffectSiteId::Worktree(WorktreeSite::Add | WorktreeSite::AddStaging)
            | EffectSiteId::Snapshot(SnapshotSite::Add) => {
                let slot = match site {
                    EffectSiteId::Worktree(WorktreeSite::Add) => fixture.task("alpha", 1),
                    EffectSiteId::Worktree(WorktreeSite::AddStaging) => {
                        Slot::Staging { sequence: 1 }
                    }
                    _ => Slot::Snapshot {
                        name: SnapshotName::gates(1, 1),
                    },
                };
                let path = fixture.manager.slot_path(&slot);
                let none = classify(site, &ResidueTarget::new(&base).at(&path));
                register_unpopulated(&fixture, &path);
                let internal = classify(site, &ResidueTarget::new(&base).at(&path));
                fixture
                    .manager
                    .remove_worktree(&mut NoHooks, &slot)
                    .expect("clear the residue");
                // The intent is synced before the add — the add funnel refuses
                // otherwise, which is what makes an interrupted add reclaimable.
                fixture
                    .manager
                    .write_intent(&mut NoHooks, &slot)
                    .expect("intent");
                fixture
                    .manager
                    .add_worktree(&mut NoHooks, &slot, &fixture.head)
                    .expect("a completed add");
                let after = classify(site, &ResidueTarget::new(&base).at(&path));
                [none, internal, after]
            }
            EffectSiteId::Object(ObjectSite::CandidateStage) => {
                let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
                let path = fixture.manager.slot_path(&slot);
                fs::write(path.join("a.txt"), "edited\n").expect("unstaged change");
                let none = classify(site, &ResidueTarget::new(&base).at(&path));
                let git_dir = git_dir_of(&path).expect("git dir").expect("linked");
                // The Internal state is built so that `index.lock` is the ONLY
                // thing that makes it Internal: the edit is staged first, so
                // the index already reflects the working tree and the
                // unstaged-changes half of the after-phase says `After`. A
                // classifier that dropped the lock check would answer `After`
                // here — which is a real reachable state, a second `git add`
                // killed on an already-clean worktree — and a fixture that
                // left the change unstaged would confound the two
                // discriminators and stay green. Measured: this arm with the
                // change unstaged survives deleting the lock check from
                // `after_reference_present`.
                fixture
                    .manager
                    .candidate_stage(&mut NoHooks, &slot)
                    .expect("stage, so the index already reflects the tree");
                fs::write(git_dir.join("index.lock"), "").expect("plant the lock");
                let internal = classify(site, &ResidueTarget::new(&base).at(&path));
                fs::remove_file(git_dir.join("index.lock")).expect("clear the lock");
                fs::write(path.join("a.txt"), "edited again\n").expect("a second unstaged change");
                fixture
                    .manager
                    .candidate_stage(&mut NoHooks, &slot)
                    .expect("stage");
                let after = classify(site, &ResidueTarget::new(&base).at(&path));
                [none, internal, after]
            }
            EffectSiteId::Object(ObjectSite::CandidateWriteTree) => {
                let slot = fixture.add_task(&mut NoHooks, "alpha", 1);
                let path = fixture.manager.slot_path(&slot);
                let none = classify(site, &ResidueTarget::new(&base).at(&path));
                write_orphan(&base, "an object nothing references\n");
                let internal = classify(site, &ResidueTarget::new(&base).at(&path));
                let tree = fixture
                    .manager
                    .candidate_write_tree(&mut NoHooks, &slot)
                    .expect("write-tree");
                let after = classify(site, &ResidueTarget::new(&base).at(&path).published(&tree));
                [none, internal, after]
            }
            EffectSiteId::Object(
                ObjectSite::SnapshotCommitTree | ObjectSite::CandidateCommitTree,
            ) => {
                let none = classify(site, &ResidueTarget::new(&base));
                write_orphan(&base, "an object nothing references\n");
                let internal = classify(site, &ResidueTarget::new(&base));
                let tree = git(&base, &["rev-parse", &format!("{}^{{tree}}", fixture.head)]);
                let commit = if site == EffectSiteId::Object(ObjectSite::SnapshotCommitTree) {
                    fixture
                        .manager
                        .snapshot_commit_tree(&mut NoHooks, &tree, &fixture.head)
                        .expect("ephemeral commit")
                } else {
                    fixture
                        .manager
                        .candidate_commit_tree(&mut NoHooks, &tree, &fixture.head, "candidate")
                        .expect("candidate commit")
                };
                let after = classify(site, &ResidueTarget::new(&base).published(&commit));
                [none, internal, after]
            }
            EffectSiteId::Object(ObjectSite::ProposalCherryPick) => {
                let slot = Slot::Staging { sequence: 1 };
                fixture
                    .manager
                    .write_intent(&mut NoHooks, &slot)
                    .expect("intent");
                let path = fixture
                    .manager
                    .add_worktree(&mut NoHooks, &slot, &fixture.head)
                    .expect("staging worktree");
                let bare = ResidueTarget::new(&base).at(&path).from_base(&fixture.head);
                let none = classify(site, &bare);
                let git_dir = git_dir_of(&path).expect("git dir").expect("linked");
                fs::write(git_dir.join("CHERRY_PICK_HEAD"), &fixture.side).expect("plant");
                let internal = classify(site, &bare);
                fs::remove_file(git_dir.join("CHERRY_PICK_HEAD")).expect("clear");
                let proposal = fixture
                    .manager
                    .proposal_cherry_pick(&mut NoHooks, &slot, &fixture.side)
                    .expect("cherry-pick");
                let after = classify(
                    site,
                    &ResidueTarget::new(&base)
                        .at(&path)
                        .from_base(&fixture.head)
                        .published(&proposal),
                );
                [none, internal, after]
            }
            EffectSiteId::Object(ObjectSite::RepairMaterialize) => {
                let slot = fixture.add_task(&mut NoHooks, "repair", 1);
                let path = fixture.manager.slot_path(&slot);
                let none = classify(site, &ResidueTarget::new(&base).at(&path));
                let git_dir = git_dir_of(&path).expect("git dir").expect("linked");
                fs::write(git_dir.join("index.lock"), "").expect("plant the lock");
                let internal = classify(site, &ResidueTarget::new(&base).at(&path));
                fs::remove_file(git_dir.join("index.lock")).expect("clear the lock");
                fixture
                    .manager
                    .repair_materialize(&mut NoHooks, &slot, &fixture.side)
                    .expect("materialize");
                // Measured, git 2.43: `cherry-pick --no-commit` writes
                // **`MERGE_MSG`**, not `CHERRY_PICK_HEAD` — that file is only
                // set when the pick is going to commit. So the after phase of
                // this site reads the index, and a file the frozen element list
                // does register (`CHERRY_PICK_HEAD`) is one the real command
                // never leaves. It is still constructed synthetically, because
                // `ObjectSite::RepairMaterialize.residue_elements()` registers
                // it and PR3 froze that; it will simply never appear in a
                // sampled histogram.
                assert!(
                    !git_dir.join("CHERRY_PICK_HEAD").exists(),
                    "a successful `cherry-pick --no-commit` sets no CHERRY_PICK_HEAD"
                );
                assert!(
                    git_dir.join("MERGE_MSG").exists(),
                    "what it does leave is MERGE_MSG, which this site's element list does not \
                     register and which `Worktree.Verify` reads as merge state — so the tabled \
                     recovery is entered either way"
                );
                let after = classify(site, &ResidueTarget::new(&base).at(&path));
                [none, internal, after]
            }
            other => panic!(
                "`{other}` registers a residue class and this grid has no arm for it; the domain \
                 is the frozen enums', not this function's"
            ),
        }
    }

    /// `command_internal_sub_effects`, synthetic half: "each residue element …
    /// is constructed in a real temporary repository at the site's worktree,
    /// `classify_object_residue` returns `Internal`, `Worktree.Verify` fails,
    /// and the tabled recovery converges with fsck showing the objects
    /// unreachable and untouched".
    ///
    /// **The `Verify`-fails half is asserted where it holds and its negation
    /// where it does not, and the partition is a count.**
    /// [`element_breaks_quiescence`] carries the argument: an unreferenced
    /// object and a Git temporary object file live in the shared object store,
    /// are R27 — "Git's" — and are left by ordinary Git use, so a
    /// `Worktree.Verify` that saw them would refuse to reuse an `OpenNoAttempt`
    /// worktree in almost every real repository. Reported as a boundary, not
    /// concealed as an omission.
    #[test]
    fn every_registered_residue_element_is_constructed_and_recovers() {
        let mut records: Vec<(EffectSiteId, SyntheticRecord)> = Vec::new();
        let mut quiescence_broken = 0usize;
        let mut object_store_only = 0usize;

        for site in residue_classified_sites() {
            for element in site.residue_elements() {
                let record = construct_and_recover(site, *element);
                assert!(record.constructed, "`{site}`/{element:?} was constructed");
                assert_eq!(
                    record.classified,
                    ObjectResidue::Internal,
                    "`{site}`/{element:?} classifies Internal"
                );
                assert!(record.recovered, "`{site}`/{element:?} recovers");
                if element_breaks_quiescence(*element) {
                    quiescence_broken += 1;
                } else {
                    object_store_only += 1;
                }
                records.push((site, record));
            }
        }

        // Distinct-value counts rather than prose: the grid is 24 (site,
        // element) pairs, and the two halves of the Verify boundary are 12 and
        // 12. A site that grows an element, or an element that changes side,
        // moves one of these.
        assert_eq!(
            records.len(),
            residue_classified_sites()
                .iter()
                .map(|site| site.residue_elements().len())
                .sum::<usize>(),
            "one record per (site, element) the frozen enums register"
        );
        assert_eq!(records.len(), 24, "the frozen grid is 24 pairs");
        assert_eq!(
            quiescence_broken, 12,
            "elements that make a worktree non-quiescent"
        );
        assert_eq!(object_store_only, 12, "elements that are R27 and Git's");
        assert!(
            records
                .iter()
                .all(|(_, record)| record.classified == ObjectResidue::Internal),
            "every element of every registered class classifies into that class"
        );

        // The evidence record, in the packet's own type, per site.
        for site in residue_classified_sites() {
            let synthetic: Vec<SyntheticRecord> = records
                .iter()
                .filter(|(seen, _)| *seen == site)
                .map(|(_, record)| *record)
                .collect();
            assert_eq!(synthetic.len(), site.residue_elements().len());
            let evidence = Evidence::RecoveryProven {
                synthetic,
                sampling: SamplingRecord {
                    n: SAMPLING_N,
                    histogram: ClassHistogram::default(),
                    unclassified: 0,
                    recovered: true,
                },
            };
            assert_eq!(
                evidence.label(),
                EvidenceLabel::RecoveryProven,
                "a residue class never carries an executed-hook claim"
            );
            assert!(!evidence.claims_execution());
        }
    }

    /// Construct one element at one site, classify it, check quiescence, and
    /// run the tabled recovery.
    fn construct_and_recover(site: EffectSiteId, element: ResidueElement) -> SyntheticRecord {
        let tag = format!("syn-{}-{element:?}", site.variant().to_lowercase());
        let fixture = Fixture::created(&tag);
        let base = fixture.base.clone();

        // The site's owning worktree, and the state in which its after-phase
        // reference is absent — which is the state the sentence is about.
        let (slot, path) = match site {
            EffectSiteId::Worktree(WorktreeSite::AddStaging)
            | EffectSiteId::Object(ObjectSite::ProposalCherryPick) => {
                let slot = Slot::Staging { sequence: 1 };
                fixture
                    .manager
                    .write_intent(&mut NoHooks, &slot)
                    .expect("intent");
                let path = fixture.manager.slot_path(&slot);
                (Some(slot), path)
            }
            EffectSiteId::Snapshot(SnapshotSite::Add) => {
                let slot = Slot::Snapshot {
                    name: SnapshotName::gates(1, 1),
                };
                fixture
                    .manager
                    .write_intent(&mut NoHooks, &slot)
                    .expect("intent");
                let path = fixture.manager.slot_path(&slot);
                (Some(slot), path)
            }
            EffectSiteId::Object(
                ObjectSite::SnapshotCommitTree | ObjectSite::CandidateCommitTree,
            ) => (None, base.clone()),
            _ => {
                let slot = fixture.task("alpha", 1);
                fixture
                    .manager
                    .write_intent(&mut NoHooks, &slot)
                    .expect("intent");
                let path = fixture.manager.slot_path(&slot);
                (Some(slot), path)
            }
        };

        // A populated worktree for every site whose residue lives inside one;
        // the three `Add` sites are about a worktree that was never populated.
        let is_add_site = matches!(
            site,
            EffectSiteId::Worktree(WorktreeSite::Add | WorktreeSite::AddStaging)
                | EffectSiteId::Snapshot(SnapshotSite::Add)
        );
        if let Some(slot) = slot.as_ref() {
            if is_add_site {
                register_unpopulated(&fixture, &path);
            } else {
                fixture
                    .manager
                    .add_worktree(&mut NoHooks, slot, &fixture.head)
                    .expect("worktree");
                if site == EffectSiteId::Object(ObjectSite::CandidateStage) {
                    // The after-phase reference of `git add -A` is an index that
                    // reflects the working tree, so the interrupted prefix has
                    // an unstaged change in it.
                    fs::write(path.join("a.txt"), "edited\n").expect("unstaged change");
                }
            }
        }

        let object = construct_element(&fixture, &path, element);
        let target = ResidueTarget::new(&base).at(&path).from_base(&fixture.head);
        let classified = classify(site, &target);

        // The quiescence half, asserted in both directions.
        if let Some(slot) = slot.as_ref() {
            let verified = fixture
                .manager
                .verify_worktree(
                    &mut NoHooks,
                    slot,
                    &Quiescence::AtBase(fixture.head.clone()),
                )
                .expect("verify");
            assert_eq!(
                verified.is_err(),
                element_breaks_quiescence(element),
                "`{site}`/{element:?}: Worktree.Verify must {} — see element_breaks_quiescence",
                if element_breaks_quiescence(element) {
                    "fail"
                } else {
                    "pass, because this element is R27 and Git's"
                }
            );
        }

        // The tabled recovery: the site's before-phase action. Forced removal
        // and a fresh add for a worktree site; nothing at all for the two
        // commit-tree sites, whose T-CAND-OBJ (a) action is "nothing to delete:
        // the unpinned object is left to Git".
        let before = unreachable_objects(&base).expect("fsck");
        let mut recovered = true;
        if let Some(slot) = slot.as_ref() {
            fixture
                .manager
                .remove_worktree(&mut NoHooks, slot)
                .expect("forced removal");
            fixture
                .manager
                .add_worktree(&mut NoHooks, slot, &fixture.head)
                .expect("recreate");
            recovered = fixture
                .manager
                .verify_worktree(
                    &mut NoHooks,
                    slot,
                    &Quiescence::AtBase(fixture.head.clone()),
                )
                .expect("verify")
                .is_ok();
        }
        let after = unreachable_objects(&base).expect("fsck");
        if let Some(object) = object.as_deref() {
            assert!(
                before.iter().any(|id| id == object) && after.iter().any(|id| id == object),
                "fsck lists `{object}` unreachable before and after the recovery, untouched"
            );
        }
        assert!(
            before.iter().all(|id| after.contains(id)),
            "the recovery deletes no object: R27 is Git's"
        );

        SyntheticRecord {
            element,
            constructed: true,
            classified,
            recovered,
        }
    }

    /// Build one residue element in a real repository, returning the object id
    /// when the element is one.
    fn construct_element(
        fixture: &Fixture,
        path: &Path,
        element: ResidueElement,
    ) -> Option<String> {
        let git_dir = || {
            git_dir_of(path)
                .expect("git dir")
                .expect("the worktree has a git dir")
        };
        match element {
            ResidueElement::UnreferencedObject => Some(write_orphan(
                &fixture.base,
                "an object an interrupted command wrote\n",
            )),
            ResidueElement::TemporaryObjectFile => {
                let objects = object_directory(&fixture.base).expect("object directory");
                fs::write(objects.join("tmp_obj_synthetic"), b"partial").expect("temp object");
                None
            }
            ResidueElement::IndexLock => {
                fs::write(git_dir().join("index.lock"), "").expect("index.lock");
                None
            }
            ResidueElement::CherryPickHead => {
                fs::write(git_dir().join("CHERRY_PICK_HEAD"), &fixture.side).expect("plant");
                None
            }
            ResidueElement::MergeHead => {
                fs::write(git_dir().join("MERGE_HEAD"), &fixture.side).expect("plant");
                None
            }
            ResidueElement::MergeMsg => {
                fs::write(git_dir().join("MERGE_MSG"), "interrupted\n").expect("plant");
                None
            }
            ResidueElement::OrigHead => {
                fs::write(git_dir().join("ORIG_HEAD"), &fixture.head).expect("plant");
                None
            }
            ResidueElement::SequencerState => {
                let sequencer = git_dir().join("sequencer");
                fs::create_dir_all(&sequencer).expect("sequencer directory");
                fs::write(sequencer.join("todo"), "pick abc\n").expect("plant");
                None
            }
            // Already built by `register_unpopulated` before this is called:
            // the element *is* the state of the worktree, not a file added to
            // one.
            ResidueElement::RegisteredUnpopulatedWorktree => None,
        }
    }

    /// The frozen sample count, per site.
    ///
    /// `command_internal_sub_effects`: "the Git child of the site is killed at
    /// uncontrolled points through the process funnel across N runs (N frozen
    /// per site in the registry …)". Eight, and the same for all four sampled
    /// commands, because the claim each sample carries is per sample — "every
    /// observed residue must classify into exactly one class and recover by the
    /// classified action" — and is not a coverage claim about the classes. The
    /// delays are a ladder across a *measured* uninterrupted run of the same
    /// command in the same repository rather than a fixed duration, so the
    /// sampler lands inside the command on a fast machine and on a slow one.
    const SAMPLING_N: u32 = 8;

    /// `slice_contract.proof_tests[7]`: "sampling harness kills the Git child
    /// of `git add`, `write-tree`, `cherry-pick`, and `worktree add` across N
    /// runs and every observed residue classifies into exactly one class and
    /// recovers (histogram recorded; **Internal not required**)".
    ///
    /// # The stability claim
    ///
    /// This harness is nondeterministic by construction and the assertion is
    /// chosen so that it is not: what is asserted is that **every** sample
    /// classified into one of the three classes and recovered by that class's
    /// tabled action, and that `unclassified == 0`. Which class a given sample
    /// lands in is a race between the kill and Git, so the *counts* cannot be
    /// asserted — a suite that required `Internal` would be red whenever the
    /// machine was fast, and "no residue observed" is not a class.
    ///
    /// # What the counts being unassertable does **not** excuse
    ///
    /// It used to excuse two things, and `PR5-CONF-004` is both of them
    /// (Fable's `PR5-CONF-002` is the same defect).
    ///
    /// **The tally had no oracle.** `histogram.internal += 1` →
    /// `histogram.none += 1` at the classifier's own match survived the whole
    /// suite: every count moved, every assertion here was about the *total*, and
    /// the total is invariant under a swap. So the observations are now kept
    /// per sample and tallied a second time, here, by a different expression
    /// over the same list — the two axes are the *classifier's answer* and *the
    /// bucket it is counted in*, and only crossing them can see a bucket that is
    /// counted under the wrong name.
    ///
    /// **The histogram was never written down.** `outputs` requires, per site,
    /// "sampling N **and observed-class histogram**", and
    /// `effects/residue-classes.json` carried the N and not the histogram — its
    /// own note conceded that the histogram "is printed … and is a property of
    /// the machine, never asserted", which is a description of the omission
    /// rather than a discharge of it. A byte-pinned artifact genuinely cannot
    /// hold a machine-varying count, so the histogram goes to a **separate,
    /// machine-varying evidence file**, this test writes it, and this test reads
    /// it back: the record exists as a file a gate can collect, and the clause
    /// is discharged by something other than stdout nobody keeps.
    #[test]
    fn sampled_git_child_kills_every_residue_classified_and_recovered() {
        let mut records = Vec::new();
        for site in [
            EffectSiteId::Object(ObjectSite::CandidateStage),
            EffectSiteId::Object(ObjectSite::CandidateWriteTree),
            EffectSiteId::Object(ObjectSite::ProposalCherryPick),
            EffectSiteId::Worktree(WorktreeSite::Add),
        ] {
            let run = sample_site(site);
            let record = run.record;
            println!(
                "residue sampling {site}: n={} none={} internal={} after={} unclassified={}",
                record.n,
                record.histogram.none,
                record.histogram.internal,
                record.histogram.after,
                record.unclassified
            );
            assert_eq!(record.n, SAMPLING_N);
            assert_eq!(
                run.observed.len(),
                SAMPLING_N as usize,
                "one observation per sample, or the tally below is over the wrong list"
            );

            // The independent tally. Not `tally()` again — a second call to the
            // code under test agrees with itself by construction — but a count
            // per class written out separately, so a bucket incremented under
            // the wrong name is a disagreement rather than an invisible swap.
            let counted = |wanted: ObjectResidue| -> u32 {
                u32::try_from(
                    run.observed
                        .iter()
                        .filter(|sample| **sample == Some(wanted))
                        .count(),
                )
                .expect("a sample count fits in u32")
            };
            assert_eq!(
                (
                    record.histogram.none,
                    record.histogram.internal,
                    record.histogram.after
                ),
                (
                    counted(ObjectResidue::None),
                    counted(ObjectResidue::Internal),
                    counted(ObjectResidue::After)
                ),
                "{site}: the histogram does not count what the classifier answered: \
                 {:?}",
                run.observed
            );
            assert_eq!(
                record.histogram.total(),
                SAMPLING_N,
                "every sample is accounted for by exactly one class"
            );
            assert_eq!(
                record.unclassified, 0,
                "an unclassifiable residue is durable state no tabled action recovers"
            );
            assert!(
                record.recovered,
                "every sample recovered by its classified action"
            );
            records.push((site, record));
        }
        assert_eq!(
            records.len(),
            4,
            "the four commands the contract's proof_tests name"
        );

        // What was actually spawned, when the kill fired and what it did to the
        // child — counted independently of the site labels and of the
        // observation list; see `SAMPLED_LAUNCHES`. What is counted per command
        // SHAPE rather than per site record is counted so because "the Git
        // child of `git add`, `write-tree`, `cherry-pick`, and `worktree add`"
        // is a claim about four commands and a site label is not one: two sites
        // that sampled the same shape would leave four records and four labels
        // intact. The kill floor at the end is the one claim that is neither —
        // it is over the sampling as a whole, and only over kills that *landed*,
        // for the reason written there.
        {
            let log = SAMPLED_LAUNCHES.lock().expect("the launch log");
            assert_eq!(
                log.len(),
                4 * SAMPLING_N as usize,
                "every sampled site must launch exactly its frozen N children, \
                 and an observation is pushed whether or not one was"
            );
            for (label, fixed) in [
                ("git add", WorkspaceManager::CANDIDATE_STAGE_ARGV[0]),
                (
                    "git write-tree",
                    WorkspaceManager::CANDIDATE_WRITE_TREE_ARGV[0],
                ),
                (
                    "git cherry-pick",
                    WorkspaceManager::PROPOSAL_CHERRY_PICK_ARGV[0],
                ),
                ("git worktree add", WorkspaceManager::WORKTREE_ADD_ARGV[0]),
            ] {
                let shape: Vec<&SampledLaunch> = log
                    .iter()
                    .filter(|launch| launch.argv[0] == fixed)
                    .collect();
                let launched = shape.len();
                assert_eq!(
                    launched, SAMPLING_N as usize,
                    "{label}: the sampler launched it {launched} times, not N — the four \
                     command SHAPES are what the contract samples, not four site labels"
                );

                // The premise of every count below. A child that failed on its
                // own left the fixture's residue, not the kill's, and a reading
                // of the status loose enough to call that a kill would keep
                // counting kills after the kill was gone.
                let failed: Vec<Option<i32>> = shape
                    .iter()
                    .filter_map(|launch| match launch.end {
                        LaunchEnd::Failed(code) => Some(code),
                        LaunchEnd::Killed | LaunchEnd::Completed => None,
                    })
                    .collect();
                assert!(
                    failed.is_empty(),
                    "{label}: a sampled child neither died by the kill nor reached its \
                     own successful exit (codes {failed:?}) — what the classifier then \
                     saw is this fixture's failure, and no count of kills over these \
                     samples means anything"
                );

                // The rung each kill was **aimed at**.
                // `command_internal_sub_effects` (ii) says "killed at
                // **uncontrolled points** through the process funnel", and one
                // fixed delay is one point sampled N times: the ladder is that
                // clause, so it is asserted beside the kill rather than left to
                // the reader of `sample_site`.
                //
                // This is the aim and only the aim — `PR5-R5-001`. These are
                // the parameters the caller passed, so `sample_site` computing
                // a ladder is the whole of what they can witness: deleting
                // `std::thread::sleep(after)` from `kill_git_child`, which
                // fires every kill at the spawn instant and is the exact
                // negation of the clause cited above, left this list a perfect
                // ladder and the suite green on Linux and on the Windows guest.
                // The two assertions after it are over what the kills *did*.
                let delays: Vec<std::time::Duration> =
                    shape.iter().map(|launch| launch.after).collect();
                assert!(
                    delays.windows(2).all(|rungs| rungs[0] < rungs[1]),
                    "{label}: the N kills must be aimed at N distinct, increasing points \
                     through the command, not at one point N times: {delays:?}"
                );

                // **A kill fired at every one of this command's children**
                // (`PR5-R5-002`). `slice_contract.proof_tests[8]` names four
                // commands — "the Git child of `git add`, `write-tree`,
                // `cherry-pick`, and `worktree add`" — and a floor over the
                // sampling as a whole discharges the clause for none of them:
                // guarding the kill with `if args[0] != "add"` left `git add`'s
                // eight children to reach their own exit 0, and the floor
                // below, the `Failed` arm above, the ladder and the whole suite
                // stayed green on both platforms.
                //
                // What is counted is kills **fired**, not kills that won their
                // race. Landing is a race against a command that may already
                // have finished — `git add` has measured 1 in 8 and 2 in 8, for
                // the reason written at the floor below — so a per-shape floor
                // on landings would stand on a margin of one or two samples and
                // would be red on the next machine. Firing is not a
                // race: the sampler either aimed a kill at this command's child
                // or it did not, N times, which is per command and exact.
                //
                // `fired` is written by `SampledChild::kill` itself, so an edit
                // that skips the kill skips the record with it. A count over
                // records written beside the call is what `PR5-R5-002` walked
                // past.
                let unfired = shape.iter().filter(|launch| launch.fired.is_none()).count();
                assert_eq!(
                    unfired, 0,
                    "{label}: {unfired} of this command's {launched} sampled children were \
                     never fired at — the contract names this command among the four whose \
                     Git child this harness kills, and a kill skipped for one of the four is \
                     invisible to every count taken over all four"
                );

                // **When each kill fired**, read off the clock by the kill
                // rather than off the delay the caller asked for
                // (`PR5-R5-001`). A kill cannot fire before the wait that
                // precedes it has elapsed, so with the ladder above this pins N
                // firings to N distinct, strictly increasing floors: the i-th
                // kill fired later than the rung the (i-1)-th was aimed at, and
                // no two of them can be the spawn instant. That is the
                // strongest statement available deterministically — a *ceiling*
                // on a firing would be an assertion about the scheduler — and
                // it is what the deleted wait destroys, since every kill then
                // fires within microseconds of its spawn.
                for launch in &shape {
                    let fired = launch
                        .fired
                        .expect("every child was fired at, asserted just above");
                    assert!(
                        fired >= launch.after,
                        "{label}: a kill fired {fired:?} after its child was spawned, sooner \
                         than the {:?} rung it was aimed at — a kill that does not wait its \
                         rung is the spawn instant sampled again, and the ladder above is \
                         then a ladder of nothing",
                        launch.after
                    );
                }

                // How many of those N fired kills won their race with the
                // command. Machine-varying, so printed rather than asserted —
                // the same treatment, and for the same reason, as the class
                // histogram above. `git add` has measured 1/8 on Linux and on
                // the Windows guest and 2/8 on that same guest a run later; see
                // the floor below for why that number is reported, not required.
                let killed = shape
                    .iter()
                    .filter(|launch| launch.end == LaunchEnd::Killed)
                    .count();
                println!("kill sampling {label}: killed {killed}/{launched}");
            }

            // **The kill itself** (`PR5-R4-001`), and the one assertion in this
            // test that a completed run does not also satisfy.
            //
            // Until this existed nothing here could tell a killed child from a
            // finished one. With `child.kill()` deleted the sampler still
            // spawned 4 × N children, `SAMPLED_LAUNCHES` still counted them,
            // every residue still classified into a legal class, recovery was
            // still idempotent and `effects/residue-histogram.json` was still
            // written and read back — recording *completion* residue under the
            // kill's name. Only the wait status changes, so only the wait
            // status can be the oracle.
            //
            // **Over the sampling as a whole, not per sample and not per
            // shape.** Per sample is wrong because a child that reaches its own
            // exit before its rung elapses is legal: the last rung is 8/9 of a
            // measured uninterrupted run and is meant to reach past the end of
            // a fast one. Per shape is wrong for a subtler reason — `git add`
            // measures **1** kill in 8 on Linux and on the Windows guest, and
            // **2** on that guest a run later, because `measure_budget`'s probe
            // writes the 1 200 blobs its samples then find already in the object
            // store. (The number moving between runs is the point, not a
            // correction to it: a floor set at either one is a floor on the
            // wrong side of the other on some machine.) Measured
            // outside this suite, same content in three worktrees of one
            // repository: 44 ms for the first `git add -A`, 10 ms and 9 ms for
            // the next two, with the loose-object count unmoved at 1 203. So
            // the samples run in about a fifth of the run their ladder is
            // scaled to, only the shortest rung lands inside them, and a
            // per-shape floor would be an assertion standing on a margin of one
            // sample — a red suite on the next machine rather than a stronger
            // proof. The per-shape counts are printed above so that margin
            // stays visible without being load-bearing.
            //
            // What discharges the **four-command** clause is therefore not this
            // floor — that was `PR5-R5-002` — but the per-shape firing count
            // above. The two are a pair, and each covers what the other cannot:
            // the firing count proves no command was skipped and could not tell
            // a kill from a call that recorded itself and threw its effect
            // away; this floor proves the kills are real and cannot tell which
            // of the four commands they reached.
            let killed = log
                .iter()
                .filter(|launch| launch.end == LaunchEnd::Killed)
                .count();
            assert!(
                killed > 0,
                "not one of the {} sampled Git children died by the kill — this harness \
                 sampled the residue its commands left when they FINISHED, and every \
                 other assertion in this test accepts that residue. Ends: {:?}",
                log.len(),
                log.iter().map(|launch| launch.end).collect::<Vec<_>>()
            );
        }

        // The evidence file `outputs` asks for, written and then read back.
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(crate::effects::RESIDUE_HISTOGRAM_JSON);
        let emitted = serde_json::to_string_pretty(&serde_json::json!({
            "note": "decisions.effect_site_inventory.outputs, the observed-class \
                     histogram half: written by \
                     workspace_manager::tests::sampled_git_child_kills_every_residue_\
                     classified_and_recovered on every run. Machine-varying by \
                     construction -- which class a sample lands in is a race between \
                     the kill and Git -- so it is emitted here rather than pinned into \
                     effects/residue-classes.json, which carries the declarations.",
            "sampling_n": SAMPLING_N,
            "sites": records
                .iter()
                .map(|(site, record)| serde_json::json!({
                    "site": site.name(),
                    "n": record.n,
                    "none": record.histogram.none,
                    "internal": record.histogram.internal,
                    "after": record.histogram.after,
                    "unclassified": record.unclassified,
                    "recovered": record.recovered,
                }))
                .collect::<Vec<_>>(),
        }))
        .expect("the histogram serializes");
        fs::write(&path, emitted + "\n").expect("write the observed-class histogram");

        let back: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read the histogram back"))
                .expect("the emitted histogram parses");
        let sites = back["sites"].as_array().expect("a sites array");
        assert_eq!(sites.len(), 4, "one histogram per sampled site");
        for (entry, (site, record)) in sites.iter().zip(&records) {
            assert_eq!(
                entry["site"],
                site.name(),
                "the sites are in sampling order"
            );
            let total = ["none", "internal", "after"]
                .iter()
                .map(|class| entry[*class].as_u64().expect("a count"))
                .sum::<u64>();
            assert_eq!(
                total,
                u64::from(SAMPLING_N),
                "{site}: the written histogram accounts for every sample"
            );
            assert_eq!(entry["unclassified"], record.unclassified);
        }
    }

    /// One site's sampling run: the packet's record, and the per-sample
    /// observations it was tallied from.
    ///
    /// The two are carried separately because the record alone cannot be
    /// checked (`PR5-CONF-004`). `histogram.internal += 1` → `histogram.none +=
    /// 1` survived the whole suite: which bucket a sample lands in is a race, so
    /// no assertion on the *counts* can catch a swapped arm, and the only
    /// available oracle is the classifier's own answers, tallied a second time
    /// by something that is not the code under test.
    struct SamplingRun {
        record: SamplingRecord,
        /// What `classify_object_residue` answered for each sample, in order.
        /// `None` is a sample it could not classify at all.
        observed: Vec<Option<ObjectResidue>>,
    }

    /// Tally per-sample observations into the packet's histogram.
    ///
    /// The single place the mapping from class to bucket is written, so the test
    /// can check it against an independent tally of the same list.
    fn tally(observed: &[Option<ObjectResidue>]) -> (ClassHistogram, u32) {
        let mut histogram = ClassHistogram::default();
        let mut unclassified = 0;
        for sample in observed {
            match sample {
                Some(ObjectResidue::None) => histogram.none += 1,
                Some(ObjectResidue::Internal) => histogram.internal += 1,
                Some(ObjectResidue::After) => histogram.after += 1,
                None => unclassified += 1,
            }
        }
        (histogram, unclassified)
    }

    /// No sampled funnel builds a Git argument from a literal (Fable's
    /// `PR5-CONF-004`).
    ///
    /// Sharing the lists makes the *transcription* impossible; this is what
    /// stops a funnel growing an argument beside its list and putting the
    /// divergence back. `command_internal_sub_effects` (ii) says the sampled
    /// child is "the Git child of the site", and a child spawned with a
    /// different argv is a different child however faithful the list is.
    ///
    /// The two axes are the *shared list* and the *call site that uses it*.
    /// Sharing covers the first; a funnel that appends `"--force"` inline is
    /// still an un-shared argument, and only reading the call sites can see it.
    /// The dynamic arguments each funnel legitimately adds — a path, a commit —
    /// are counted rather than forbidden, so growing one is a change to this
    /// number rather than a silent widening.
    #[test]
    fn no_sampled_funnel_builds_its_argv_from_a_literal() {
        // (function, how many `OsString::from(<expression>)` arguments it adds
        // beyond its shared list, and what they are).
        const SAMPLED: &[(&str, usize, &str)] = &[
            (
                "pub fn add_worktree(",
                1,
                "the commit; the path is a PathBuf",
            ),
            ("pub fn candidate_stage(", 0, "none"),
            ("pub fn candidate_write_tree(", 0, "none"),
            ("pub fn proposal_cherry_pick(", 1, "the commit to pick"),
        ];
        // CRLF normalized first: the Windows guest checks this tree out with it,
        // and `find("\n    }\n")` does not match `\r\n    }\r\n`. Measured — this
        // census passed on Linux and panicked "the function ends" on the guest.
        let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(file!()))
            .expect("this module's own source")
            .replace("\r\n", "\n");
        for (signature, dynamic, what) in SAMPLED {
            let body = source
                .split_once(signature)
                .unwrap_or_else(|| panic!("`{signature}` is no longer in this file"))
                .1;
            let body = &body[..body.find("\n    }\n").expect("the function ends")];
            let literals = body.matches("OsString::from(\"").count();
            assert_eq!(
                literals, 0,
                "`{signature}` builds {literals} Git argument(s) from a string literal; \
                 every fixed argument belongs in the shared list the kill sampler reads, \
                 or the sampler stops running the command the funnel runs"
            );
            let dynamics = body.matches("OsString::from(").count();
            assert_eq!(
                dynamics, *dynamic,
                "`{signature}` adds {dynamics} dynamic Git argument(s), not {dynamic} \
                 ({what}); if that is deliberate, `sampled_command` needs the same one"
            );
        }
    }

    /// Kill the Git child of one site `SAMPLING_N` times and classify what is
    /// left.
    fn sample_site(site: EffectSiteId) -> SamplingRun {
        let tag = format!("sample-{}", site.variant().to_lowercase());
        let fixture = Fixture::created(&tag);
        let base = fixture.base.clone();
        let budget = measure_budget(site, &fixture);
        let mut observed: Vec<Option<ObjectResidue>> = Vec::new();
        let mut recovered = true;

        for run in 0..SAMPLING_N {
            let slot = sample_slot(site, &fixture, run);
            fixture
                .manager
                .write_intent(&mut NoHooks, &slot)
                .expect("intent");
            let path = fixture.manager.slot_path(&slot);
            if site != EffectSiteId::Worktree(WorktreeSite::Add) {
                fixture
                    .manager
                    .add_worktree(&mut NoHooks, &slot, &fixture.head)
                    .expect("worktree");
                populate_for_sampling(site, &path);
            }

            let (args, cwd) = sampled_command(site, &fixture, &slot);
            let delay = budget.mul_f64(f64::from(run + 1) / f64::from(SAMPLING_N + 1));
            kill_git_child(&cwd, &args, delay);

            let target = ResidueTarget::new(&base).at(&path).from_base(&fixture.head);
            observed.push(classify_object_residue(site, &target).ok());
            if !recover_sample(&fixture, &slot) {
                recovered = false;
            }
        }

        let (histogram, unclassified) = tally(&observed);
        SamplingRun {
            record: SamplingRecord {
                n: SAMPLING_N,
                histogram,
                unclassified,
                recovered,
            },
            observed,
        }
    }

    fn sample_slot(site: EffectSiteId, fixture: &Fixture, run: u32) -> Slot {
        match site {
            EffectSiteId::Object(ObjectSite::ProposalCherryPick) => Slot::Staging {
                sequence: u64::from(run),
            },
            _ => fixture.task("alpha", run),
        }
    }

    /// The exact command the site's funnel runs, and where it runs it.
    fn sampled_command(
        site: EffectSiteId,
        fixture: &Fixture,
        slot: &Slot,
    ) -> (Vec<String>, PathBuf) {
        let path = fixture.manager.slot_path(slot);
        // Read from the funnel's own lists rather than transcribed from them
        // (Fable's `PR5-CONF-004`): the transcription was faithful and nothing
        // kept it so, and a funnel that grew a flag would leave the sampler
        // sampling a stale command with every assertion here still green.
        let fixed =
            |argv: &[&str]| -> Vec<String> { argv.iter().map(|a| (*a).to_owned()).collect() };
        match site {
            EffectSiteId::Object(ObjectSite::CandidateStage) => {
                (fixed(&WorkspaceManager::CANDIDATE_STAGE_ARGV), path)
            }
            EffectSiteId::Object(ObjectSite::CandidateWriteTree) => {
                (fixed(&WorkspaceManager::CANDIDATE_WRITE_TREE_ARGV), path)
            }
            EffectSiteId::Object(ObjectSite::ProposalCherryPick) => {
                let mut argv = fixed(&WorkspaceManager::PROPOSAL_CHERRY_PICK_ARGV);
                argv.push(fixture.side.clone());
                (argv, path)
            }
            EffectSiteId::Worktree(WorktreeSite::Add) => {
                let mut argv = fixed(&WorkspaceManager::WORKTREE_ADD_ARGV);
                argv.push(path.to_string_lossy().into_owned());
                argv.push(fixture.head.clone());
                (argv, fixture.base.clone())
            }
            other => panic!("`{other}` is not one of the four commands the contract samples"),
        }
    }

    /// How long the same command takes when nothing kills it.
    ///
    /// Measured in a **probe slot of its own**, which is then removed. The
    /// first draft measured it in the very worktree the next sample would kill
    /// in, and the probe therefore *performed* the command first: `write-tree`
    /// found a valid cache-tree and every one of its eight samples classified
    /// `None`, which read as a stable histogram and was an artefact of the
    /// fixture. A probe that mutates the state under test is the
    /// "environment assumption in a test" class this project has recorded.
    fn measure_budget(site: EffectSiteId, fixture: &Fixture) -> std::time::Duration {
        let probe = match site {
            EffectSiteId::Object(ObjectSite::ProposalCherryPick) => {
                Slot::Staging { sequence: 9_999 }
            }
            _ => fixture.task("probe", 9_999),
        };
        fixture
            .manager
            .write_intent(&mut NoHooks, &probe)
            .expect("probe intent");
        let path = fixture.manager.slot_path(&probe);
        let elapsed = if site == EffectSiteId::Worktree(WorktreeSite::Add) {
            let (args, cwd) = sampled_command(site, fixture, &probe);
            let start = std::time::Instant::now();
            let output = git_out(&cwd, &args.iter().map(String::as_str).collect::<Vec<_>>());
            assert!(output.status.success(), "the probe must really run");
            start.elapsed()
        } else {
            fixture
                .manager
                .add_worktree(&mut NoHooks, &probe, &fixture.head)
                .expect("probe worktree");
            populate_for_sampling(site, &path);
            let (args, cwd) = sampled_command(site, fixture, &probe);
            let start = std::time::Instant::now();
            let output = git_out(&cwd, &args.iter().map(String::as_str).collect::<Vec<_>>());
            assert!(
                output.status.success(),
                "the probe must really run: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            start.elapsed()
        };
        fixture
            .manager
            .remove_worktree(&mut NoHooks, &probe)
            .expect("remove the probe");
        fixture
            .manager
            .remove_intent(&mut NoHooks, &probe)
            .expect("remove the probe intent");
        elapsed.max(std::time::Duration::from_micros(200))
    }

    /// Enough work in the worktree that the sampled command has a middle to be
    /// killed in: many files across many directories, so `git add` writes many
    /// blobs and `write-tree` writes many trees.
    fn populate_for_sampling(site: EffectSiteId, path: &Path) {
        if site == EffectSiteId::Object(ObjectSite::ProposalCherryPick) {
            return;
        }
        for directory in 0..60 {
            let bulk = path.join(format!("bulk{directory}"));
            fs::create_dir_all(&bulk).expect("bulk directory");
            for index in 0..20 {
                fs::write(
                    bulk.join(format!("f{index}.txt")),
                    format!("{directory}-{index}-{}", "x".repeat(2048)),
                )
                .expect("bulk file");
            }
        }
        if site == EffectSiteId::Object(ObjectSite::CandidateWriteTree) {
            // `write-tree` reads an index, so the bulk has to be in one.
            git(path, &["add", "-A"]);
        }
    }

    /// How one sampled Git child ended.
    ///
    /// The wait status is the **only** thing in this harness that the kill
    /// changes, so it is the only place the kill can be observed. Everything
    /// else — the spawn, the argv, the residue, its class, the recovery, the
    /// evidence file — is identical whether the child was killed or ran to its
    /// own end, which is exactly why `PR5-R4-001` could delete `child.kill()`
    /// and keep the suite green on both platforms.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LaunchEnd {
        /// The status carries this platform's signature of [`Child::kill`].
        ///
        /// [`Child::kill`]: std::process::Child::kill
        Killed,
        /// The child reached its own **successful** exit before the kill
        /// landed. Legal — the delay ladder deliberately reaches past the end
        /// of a fast run — and the reason the kill floor is asserted over the
        /// sampling as a whole rather than per sample.
        Completed,
        /// Neither: the sampled command failed on its own. Then what the
        /// classifier saw is the *fixture's* residue, not the kill's, and no
        /// count of kills over these samples means anything.
        Failed(Option<i32>),
    }

    /// Read a [`LaunchEnd`] off a wait status.
    ///
    /// The signature is a **value** per platform, not the property
    /// `!status.success()`: a command that merely failed also fails to succeed,
    /// and reading that as a kill is how a kill-count keeps counting after the
    /// kill is gone. The third arm exists so that such a command reddens the
    /// suite instead of being miscounted.
    fn launch_end(status: &std::process::ExitStatus) -> LaunchEnd {
        // `Child::kill` sends `SIGKILL`. No exit a child reaches on its own can
        // carry a signal at all, and nothing else here signals this child, so
        // the signal is a fingerprint the kill alone can leave.
        #[cfg(unix)]
        let killed = std::os::unix::process::ExitStatusExt::signal(status) == Some(libc::SIGKILL);
        // `Child::kill` is `TerminateProcess(handle, 1)`, so the fingerprint
        // here is exit code 1. `measure_budget` asserts that this same command
        // in this same fixture exits 0 when nothing kills it, so 1 is not an
        // end any of these four commands reaches by itself.
        #[cfg(windows)]
        let killed = status.code() == Some(1);
        if killed {
            LaunchEnd::Killed
        } else if status.success() {
            LaunchEnd::Completed
        } else {
            LaunchEnd::Failed(status.code())
        }
    }

    /// One Git child the sampler launched: what it ran, which rung of the delay
    /// ladder its kill was **aimed at**, when a kill actually **fired** at it,
    /// and how it ended.
    ///
    /// `after` and `fired` are two different things, and `PR5-R5-001` is the
    /// difference. `after` is the caller's parameter: it is recorded whatever
    /// the sampler does with it, so a ladder of `after`s is a ladder of
    /// *intentions* and stays a perfect one after the wait that realizes it is
    /// deleted. `fired` is the clock, read inside [`SampledChild::kill`]: it
    /// exists only if a kill ran at this child, and it moves when the wait
    /// before the kill does.
    struct SampledLaunch {
        argv: Vec<String>,
        after: std::time::Duration,
        fired: Option<std::time::Duration>,
        end: LaunchEnd,
    }

    /// Every Git child the sampler actually launched, in order.
    ///
    /// The independent observer of *launches and of their kills*.
    /// `command_internal_sub_effects` freezes N per site and
    /// `slice_contract.proof_tests[8]` names four commands, and both are claims
    /// about what was spawned — while every assertion in the sampling test is
    /// over `run.observed`, the list the loop **pushes to**, and over the
    /// residues that list classifies into. Nothing counted a spawn. A run that
    /// skipped one kill and pushed its observation anyway satisfied the length
    /// assertion, the histogram total and the serialized `sampling_n` alike;
    /// and a site that spawned another site's command left every count, class
    /// and evidence record identical, because any Git child that leaves a
    /// classifiable residue in the slot satisfies them all. Both were measured
    /// surviving the whole suite.
    ///
    /// Counting launches is only the first half, and `PR5-R4-001` is the
    /// second: both live passages say the child is **killed**, and with
    /// `child.kill()` deleted the sampler still spawned 4 × N children, still
    /// classified a legal residue from each, still recovered and still wrote
    /// the histogram — of *completion* residue, filed under the kill's name.
    /// So each entry also carries how its child ended and at which rung of the
    /// ladder the kill fired.
    ///
    /// It has to be collected **here** and not at the call site: the edit that
    /// drops a kill skips the call, so an observer beside the call would still
    /// run and would count a launch that never happened.
    ///
    /// Round 5 stopped one level short of that same rule, and `PR5-R5-001` and
    /// `PR5-R5-002` are what it cost. Inside this function the *launch* is
    /// observed and the *kill* was not: the parameter the kill was aimed at was
    /// recorded beside the call, so deleting the wait left the record intact,
    /// and the record was pushed after `wait()` for every child, so skipping the
    /// kill for one of the four commands left the record intact too. The kill's
    /// own record therefore has to be collected inside the kill, which is what
    /// [`SampledChild`] is for.
    static SAMPLED_LAUNCHES: std::sync::Mutex<Vec<SampledLaunch>> =
        std::sync::Mutex::new(Vec::new());

    /// The Git child the sampler kills, wrapped so that **the kill records
    /// itself**.
    ///
    /// [`Self::kill`] is inherent, so `child.kill()` in `kill_git_child` is this
    /// method and not [`Child::kill`], and the note that a kill ran is written
    /// by the statement that runs it rather than beside it. Both of round 5's
    /// surviving mutations are edits that stop a kill happening — one deletes
    /// the wait before it, one skips it for a single command — and both walked
    /// past records that were written whether the kill happened or not.
    ///
    /// It is deliberately **blind to the command it is killing**: no argv
    /// reaches it, so the per-command firing count in the sampling test cannot
    /// be defeated inside this type without first giving it one.
    ///
    /// [`Child::kill`]: std::process::Child::kill
    struct SampledChild {
        child: std::process::Child,
        /// Started once [`Command::spawn`] has returned, so what [`Self::kill`]
        /// reads off it is time the child was left *running* rather than the
        /// cost of starting it — and so an unwaited kill reads as the ~0 it is.
        spawned: std::time::Instant,
        /// What the clock said when a kill fired at this child, or `None` if
        /// none ever did. Written only by [`Self::kill`].
        fired: Option<std::time::Duration>,
    }

    impl SampledChild {
        fn spawn(cwd: &Path, args: &[String]) -> Self {
            let child = Command::new("git")
                .arg("-C")
                .arg(cwd)
                .args(["-c", "core.fsmonitor=false"])
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the sampled git child");
            Self {
                child,
                spawned: std::time::Instant::now(),
                fired: None,
            }
        }

        /// Kill the child, recording when the kill fired.
        ///
        /// The clock is read at the instant of the kill and stored *after* the
        /// kill has returned. Read at that instant, the value is the kill's
        /// actual timing rather than the timing it was asked for; stored after
        /// the call, the record cannot outlive the call's removal, because
        /// deleting `self.child.kill()` leaves `outcome` unbound and the module
        /// stops compiling.
        ///
        /// What that still leaves reachable is a fake that keeps the call and
        /// throws its effect away. The kill floor at the end of the sampling
        /// test is what covers that: it is over wait statuses, which nothing
        /// but a real kill produces.
        fn kill(&mut self) -> std::io::Result<()> {
            let fired = self.spawned.elapsed();
            let outcome = self.child.kill();
            self.fired = Some(fired);
            outcome
        }

        fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            self.child.wait()
        }
    }

    fn kill_git_child(cwd: &Path, args: &[String], after: std::time::Duration) {
        let mut child = SampledChild::spawn(cwd, args);
        std::thread::sleep(after);
        let _ = child.kill();
        // Reaped rather than discarded: this status is the whole observation.
        let status = child.wait().expect("reap the sampled git child");
        SAMPLED_LAUNCHES
            .lock()
            .expect("the launch log")
            .push(SampledLaunch {
                argv: args.to_vec(),
                after,
                fired: child.fired,
                end: launch_end(&status),
            });
    }

    /// The tabled recovery for whatever the sample left: forced removal of the
    /// worktree and its intent, which is the before-phase action every
    /// `Internal` residue routes to and is idempotent for the other two.
    fn recover_sample(fixture: &Fixture, slot: &Slot) -> bool {
        fixture
            .manager
            .remove_worktree(&mut NoHooks, slot)
            .expect("forced removal converges");
        fixture
            .manager
            .remove_intent(&mut NoHooks, slot)
            .expect("intent removal converges");
        let path = fixture.manager.slot_path(slot);
        !path.exists()
            && !fixture
                .manager
                .worktree_records()
                .expect("records")
                .iter()
                .any(|record| canonical_prefix(&record.path).ok() == canonical_prefix(&path).ok())
    }

    // -----------------------------------------------------------------------
    // ST-07 for this lane: every site, both phases
    // -----------------------------------------------------------------------

    /// `fault_injection_registry.completeness_rule`: "every site x hook phase …
    /// is observed executed at least once by the suite … an unobserved site,
    /// phase, point, or mode fails".
    ///
    /// Restricted to the four groups this lane owns, and derived from their
    /// `ALL` slices, so a group that gains a variant fails this until a funnel
    /// executes it.
    #[test]
    fn every_site_this_lane_owns_executes_both_hook_phases() {
        let fixture = Fixture::created("grand-tour");
        let (mut hooks, shared) = harness();
        let manager = &fixture.manager;
        let integration = "refs/heads/tactus/run-1";
        let candidates = "refs/tactus/runs/run-1/candidates/kalpha/1";
        let pin = "refs/tactus/runs/run-1/candidate-prepared/kalpha/1";
        let prepared = "refs/tactus/runs/run-1/prepared/1";

        // The execution root already exists (Fixture::created), so run the site
        // again: it is idempotent and this is the tour's first observation.
        manager
            .create_execution_root(&mut hooks)
            .expect("Worktree.CreateExecutionRoot");
        manager
            .create_ref_zero_old(
                &mut hooks,
                RefSite::CreateIntegration,
                integration,
                &fixture.head,
            )
            .expect("Ref.CreateIntegration");

        // A task worktree, its capture, and its snapshot.
        let task = fixture.task("alpha", 1);
        manager
            .write_intent(&mut hooks, &task)
            .expect("Worktree.WriteIntent");
        let task_path = manager
            .add_worktree(&mut hooks, &task, &fixture.head)
            .expect("Worktree.Add");
        manager
            .verify_worktree(&mut hooks, &task, &Quiescence::AtBase(fixture.head.clone()))
            .expect("Worktree.Verify")
            .expect("quiescent");
        fs::write(task_path.join("worker.txt"), "worker\n").expect("worker edit");
        manager
            .candidate_stage(&mut hooks, &task)
            .expect("Object.CandidateStage");
        let tree = manager
            .candidate_write_tree(&mut hooks, &task)
            .expect("Object.CandidateWriteTree");

        let snapshot = manager
            .add_snapshot(
                &mut hooks,
                &SnapshotName::gates(1, 1),
                &SnapshotInput::Tree {
                    tree: tree.clone(),
                    parent: fixture.head.clone(),
                },
            )
            .expect("Object.SnapshotCommitTree + Snapshot.WriteIntent + Snapshot.Add");
        manager
            .remove_snapshot(&mut hooks, &snapshot)
            .expect("Snapshot.Remove + Snapshot.RemoveIntent");

        let candidate = manager
            .candidate_commit_tree(&mut hooks, &tree, &fixture.head, "candidate")
            .expect("Object.CandidateCommitTree");
        manager
            .create_ref_zero_old(&mut hooks, RefSite::PinCandidatePrepared, pin, &candidate)
            .expect("Ref.PinCandidatePrepared");
        manager
            .create_ref_zero_old(
                &mut hooks,
                RefSite::CreateCandidates,
                candidates,
                &candidate,
            )
            .expect("Ref.CreateCandidates");
        manager
            .delete_ref_expected_old(&mut hooks, RefSite::DeleteCandidatePin, pin, &candidate)
            .expect("Ref.DeleteCandidatePin");
        manager
            .remove_worktree(&mut hooks, &task)
            .expect("Worktree.Remove");
        manager
            .remove_intent(&mut hooks, &task)
            .expect("Worktree.RemoveIntent");

        // A repair worktree, for the last Object site.
        let repair = fixture.task("repair", 1);
        manager.write_intent(&mut hooks, &repair).expect("intent");
        manager
            .add_worktree(&mut hooks, &repair, &fixture.head)
            .expect("worktree");
        manager
            .repair_materialize(&mut hooks, &repair, &fixture.side)
            .expect("Object.RepairMaterialize");
        manager
            .remove_worktree(&mut hooks, &repair)
            .expect("remove");
        manager.remove_intent(&mut hooks, &repair).expect("intent");

        // The stale integration transaction: staging, cherry-pick, pin, CAS.
        let staging = Slot::Staging { sequence: 1 };
        manager
            .write_intent(&mut hooks, &staging)
            .expect("Worktree.WriteStagingIntent");
        manager
            .add_worktree(&mut hooks, &staging, &fixture.head)
            .expect("Worktree.AddStaging");
        let proposal = manager
            .proposal_cherry_pick(&mut hooks, &staging, &fixture.side)
            .expect("Object.ProposalCherryPick");
        manager
            .create_ref_zero_old(&mut hooks, RefSite::PinPrepared, prepared, &proposal)
            .expect("Ref.PinPrepared");
        manager
            .compare_and_swap_ref(
                &mut hooks,
                RefSite::CompareAndSwapIntegration,
                integration,
                &fixture.head,
                &proposal,
            )
            .expect("Ref.CompareAndSwapIntegration");
        manager
            .delete_ref_expected_old(&mut hooks, RefSite::DeletePreparedPin, prepared, &proposal)
            .expect("Ref.DeletePreparedPin");
        manager
            .remove_worktree(&mut hooks, &staging)
            .expect("Worktree.RemoveStaging");
        manager
            .remove_intent(&mut hooks, &staging)
            .expect("Worktree.RemoveStagingIntent");

        // The exact-base fast sequence: it creates no staging worktree,
        // cherry-picks nothing, and takes no prepared pin. The absence is
        // proved *inside* a sequence that demonstrably happened.
        shared
            .lock()
            .expect("harness")
            .begin_fast_sequence("exact-base-fast");
        let fast_task = fixture.task("fast", 1);
        manager
            .write_intent(&mut hooks, &fast_task)
            .expect("intent");
        let fast_path = manager
            .add_worktree(&mut hooks, &fast_task, &proposal)
            .expect("worktree");
        fs::write(fast_path.join("fast.txt"), "fast\n").expect("edit");
        manager
            .candidate_stage(&mut hooks, &fast_task)
            .expect("stage");
        let fast_tree = manager
            .candidate_write_tree(&mut hooks, &fast_task)
            .expect("write-tree");
        let fast_commit = manager
            .candidate_commit_tree(&mut hooks, &fast_tree, &proposal, "fast candidate")
            .expect("commit-tree");
        manager
            .compare_and_swap_ref(
                &mut hooks,
                RefSite::CompareAndSwapIntegration,
                integration,
                &proposal,
                &fast_commit,
            )
            .expect("the fast publication is a CAS of the candidate commit itself");
        manager
            .remove_worktree(&mut hooks, &fast_task)
            .expect("remove");
        manager
            .remove_intent(&mut hooks, &fast_task)
            .expect("intent");
        shared.lock().expect("harness").end_fast_sequence();

        manager
            .delete_ref_expected_old(
                &mut hooks,
                RefSite::DeleteCandidatesRef,
                candidates,
                &candidate,
            )
            .expect("Ref.DeleteCandidatesRef");
        manager
            .remove_execution_root(&mut hooks)
            .expect("Worktree.RemoveExecutionRoot");

        // The bijection, over the enums rather than over a list.
        let harness = shared.lock().expect("harness");
        let sites = lane_sites();
        assert_eq!(
            sites.len(),
            WorktreeSite::ALL.len()
                + SnapshotSite::ALL.len()
                + RefSite::ALL.len()
                + ObjectSite::ALL.len(),
            "the lane's site count comes from the frozen enums"
        );
        assert_eq!(sites.len(), 29, "eleven + four + eight + six");
        let mut missing: Vec<String> = Vec::new();
        for site in &sites {
            for phase in HookPhase::PHASES {
                if !harness.observed(*site, *phase) {
                    missing.push(format!("{site} {phase}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "every site of this lane executes both hook phases; unobserved: {missing:?}"
        );

        // The no-execution record, per sequence and not per process.
        let sequence = harness
            .fast_sequence("exact-base-fast")
            .expect("the suite exercised a fast sequence");
        for absent in [
            EffectSiteId::Worktree(WorktreeSite::AddStaging),
            EffectSiteId::Object(ObjectSite::ProposalCherryPick),
            EffectSiteId::Ref(RefSite::PinPrepared),
        ] {
            assert!(
                !sequence.ran(absent),
                "`{absent}` must not execute for a fast sequence"
            );
        }
        assert!(
            !sequence.touched().is_empty(),
            "and the absence has to be proved inside a sequence that really ran"
        );
        assert!(
            harness.touched(EffectSiteId::Object(ObjectSite::ProposalCherryPick)),
            "…while the suite as a whole did exercise the stale path, so the absence is a \
             statement about the trace and not about the process"
        );
    }
}
