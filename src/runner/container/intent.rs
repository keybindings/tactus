//! The global container intent — its six fields, its name, and its five
//! labels.
//!
//! `decisions.admission_and_leases.permits.crash_reconstruction`, which is the
//! authority for every sentence in this module:
//!
//! > every container invocation writes a synced intent in the global namespace
//! > `<R>/containers/<container-name>.intent` (R = the run's private root, the
//! > one recorded in `run_started.private_dir`) recording owner run id, run
//! > directory (public path), coordinator incarnation id, repo key, invocation
//! > id, and `runner_policy_sha256`; the coordinator incarnation id is a
//! > per-process ULID recorded in `run_started(4)`/`run_resumed(4)` and is never
//! > read from lock-file contents …; the container name is
//! > `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>`, so
//! > deterministic `InvocationId`s never collide across incarnations and no
//! > earlier ownership evidence is overwritten; labels `tactus.private_root`,
//! > `tactus.run`, `tactus.run_dir`, `tactus.incarnation`, `tactus.invocation`
//!
//! Nothing here performs an effect. The write and the removal are funnel APIs
//! in `src/runner/container.rs`, under `ContainerSite::WriteIntent` and
//! `ContainerSite::RemoveIntent`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::TactusError;
use crate::runner::InvocationId;

/// The directory of the global namespace, under the run's recorded private
/// root.
pub const CONTAINERS_DIR: &str = "containers";

/// The suffix of one intent record.
pub const INTENT_SUFFIX: &str = ".intent";

/// The staging suffix. The record is published by rename, like every other
/// durable record this engine writes.
pub const INTENT_STAGED_SUFFIX: &str = ".intent.tmp";

/// The name's fixed prefix.
pub const NAME_PREFIX: &str = "tactus";

/// The separator between the name's components.
///
/// A component may not contain it — [`validate_component`] refuses one that
/// does — which is what makes [`ContainerName::parse`] injective.
pub const NAME_SEPARATOR: char = '-';

/// The domain tag of the invocation hash.
///
/// Domain-separated so the same bytes hashed for another purpose are a
/// different value, in the idiom of `workspace_manager::repo_key_v1` and
/// `runner::policy::CANONICAL_VERSION`.
pub const INVOCATION_HASH_DOMAIN: &str = "tactus.container-invocation.v1";

/// How many hex characters of the invocation digest the name carries.
///
/// Named for the character count it produces, which is this project's
/// convention (`workspace_manager`'s `REPO_KEY_HEX_CHARS` says so in as many
/// words).
pub const INVOCATION_HASH_HEX_CHARS: usize = 16;

/// The longest a single name component may be.
///
/// A run id and an incarnation are 26-character ULIDs and a repo key is 16 hex
/// characters, so this is slack rather than a constraint on anything the engine
/// produces — it exists so a hostile value cannot push the whole name past what
/// a container runtime accepts.
pub const MAX_COMPONENT_LEN: usize = 64;

/// The longest whole name.
///
/// Docker's own limit is far higher; the engine's own longest name is
/// `tactus`(6) + 4 separators + 16 + 26 + 26 + 16 = 94.
pub const MAX_NAME_LEN: usize = 200;

// ---------------------------------------------------------------------------
// The five labels
// ---------------------------------------------------------------------------

/// `tactus.private_root` — the canonical path of `<R>`. Discovery is `docker
/// ps` by this label.
pub const LABEL_PRIVATE_ROOT: &str = "tactus.private_root";
/// `tactus.run` — the owner run id.
pub const LABEL_RUN: &str = "tactus.run";
/// `tactus.run_dir` — the owner's **public** run directory.
pub const LABEL_RUN_DIR: &str = "tactus.run_dir";
/// `tactus.incarnation` — the owning coordinator incarnation.
pub const LABEL_INCARNATION: &str = "tactus.incarnation";
/// `tactus.invocation` — the rendered [`InvocationId`], in full.
pub const LABEL_INVOCATION: &str = "tactus.invocation";

/// The five labels, in the packet's order.
///
/// Written out rather than derived from the map a container carries, so a
/// label dropped from the map is a disagreement with this list rather than a
/// shorter map nobody compares to anything.
pub const LABELS: &[&str] = &[
    LABEL_PRIVATE_ROOT,
    LABEL_RUN,
    LABEL_RUN_DIR,
    LABEL_INCARNATION,
    LABEL_INVOCATION,
];

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// `<R>/containers/<name>.intent` — the six fields, in the packet's order.
///
/// `deny_unknown_fields` for the same reason [`crate::rundir::CreatingMarker`]
/// carries it: a record that grew a seventh field somewhere else is a record
/// this process did not write, and reading it as if it had is how one engine
/// adopts another's ownership evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerIntent {
    /// Owner run id.
    pub run_id: String,
    /// Run directory — the **public** path, canonical.
    pub run_dir: String,
    /// Coordinator incarnation id: a per-process ULID, never read from a lock
    /// file.
    pub incarnation: String,
    /// Repo key.
    pub repo_key: String,
    /// The rendered [`InvocationId`], in full. The name carries a 16-character
    /// digest of it; this field carries the value, so ownership evidence is
    /// exact rather than collision-resistant.
    pub invocation: String,
    /// `runner_policy_sha256` — the digest of the run's `RunnerPolicy`, so
    /// "the census report names each reclaimed container's boundary from its
    /// `runner_policy_sha256`" can be answered from the record alone.
    pub runner_policy_sha256: String,
}

impl ContainerIntent {
    /// The five labels this intent's container carries, given the private root
    /// its record lives under.
    ///
    /// The labels are derived from the record rather than passed beside it, so
    /// a container whose labels and whose intent disagree is not constructible
    /// through this API — `labeled_orphan_without_intent_reclaimed` is about a
    /// container with **no** record, which is a different thing.
    ///
    /// `tactus.private_root` is the one label with no field of its own: the
    /// record's *location* is inside `<R>`, so the root is what the census
    /// already knows when it reads one.
    #[must_use]
    pub fn labels(&self, private_root: &Path) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_PRIVATE_ROOT.to_owned(),
            private_root.to_string_lossy().replace('\\', "/"),
        );
        labels.insert(LABEL_RUN.to_owned(), self.run_id.clone());
        labels.insert(LABEL_RUN_DIR.to_owned(), self.run_dir.clone());
        labels.insert(LABEL_INCARNATION.to_owned(), self.incarnation.clone());
        labels.insert(LABEL_INVOCATION.to_owned(), self.invocation.clone());
        labels
    }
}

// ---------------------------------------------------------------------------
// The name
// ---------------------------------------------------------------------------

/// `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>`.
///
/// **Injective by construction.** No component may contain
/// [`NAME_SEPARATOR`], so a rendered name splits into exactly five fields and
/// two distinct tuples differ in some field and therefore in the rendering.
/// [`ContainerName::parse`] is the inverse and refuses anything else.
///
/// The **incarnation** component is the one carrying the packet's stated
/// purpose: "deterministic `InvocationId`s never collide across incarnations
/// and no earlier ownership evidence is overwritten". A probe identity repeats
/// across incarnations by construction (`InvocationId::Probe`'s own doc says
/// so), so without that component a resuming incarnation would write its intent
/// over the dead one's — destroying the evidence the census needs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerName(String);

/// A name taken back apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerNameParts {
    pub repo_key: String,
    pub run_id: String,
    pub incarnation: String,
    pub invocation_hash: String,
}

impl ContainerName {
    /// Build the name from its four components.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when a component is empty, carries a character
    /// outside `[0-9A-Za-z_]`, is longer than [`MAX_COMPONENT_LEN`], or when
    /// the whole name would exceed [`MAX_NAME_LEN`].
    pub fn new(
        repo_key: &str,
        run_id: &str,
        incarnation: &str,
        invocation: &InvocationId,
    ) -> Result<Self, TactusError> {
        Self::from_parts(repo_key, run_id, incarnation, &invocation_hash(invocation))
    }

    /// Build the name from four already-rendered components.
    ///
    /// Separate from [`Self::new`] so a test can construct a name whose
    /// invocation component is *not* the hash of any invocation — which is what
    /// makes the parse's injectivity testable over the whole component domain
    /// rather than over the digests one function happens to produce.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn from_parts(
        repo_key: &str,
        run_id: &str,
        incarnation: &str,
        invocation_hash: &str,
    ) -> Result<Self, TactusError> {
        validate_component("repo key", repo_key)?;
        validate_component("run id", run_id)?;
        validate_component("incarnation", incarnation)?;
        validate_component("invocation hash", invocation_hash)?;
        let rendered = format!("{NAME_PREFIX}-{repo_key}-{run_id}-{incarnation}-{invocation_hash}");
        if rendered.len() > MAX_NAME_LEN {
            return Err(TactusError::Refused {
                message: format!(
                    "the container name `{rendered}` is {} bytes; the limit is {MAX_NAME_LEN}",
                    rendered.len()
                ),
            });
        }
        Ok(Self(rendered))
    }

    /// The name as the runtime sees it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The file name of this container's intent record.
    #[must_use]
    pub fn intent_file_name(&self) -> String {
        format!("{}{INTENT_SUFFIX}", self.0)
    }

    /// `<R>/containers/<name>.intent`.
    #[must_use]
    pub fn intent_path(&self, private_root: &Path) -> PathBuf {
        containers_dir(private_root).join(self.intent_file_name())
    }

    /// Take a rendered name apart.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when `value` is not `tactus-` followed by
    /// exactly four separator-free components.
    pub fn parse(value: &str) -> Result<ContainerNameParts, TactusError> {
        let refuse = || TactusError::Refused {
            message: format!(
                "`{value}` is not a tactus container name: the name is \
                 `{NAME_PREFIX}{NAME_SEPARATOR}<repo_key>{NAME_SEPARATOR}<run_id>\
                 {NAME_SEPARATOR}<incarnation>{NAME_SEPARATOR}<invocation-hash>` \
                 (decisions.admission_and_leases.permits.crash_reconstruction)"
            ),
        };
        let parts: Vec<&str> = value.split(NAME_SEPARATOR).collect();
        let [prefix, repo_key, run_id, incarnation, invocation_hash] = parts.as_slice() else {
            return Err(refuse());
        };
        if *prefix != NAME_PREFIX {
            return Err(refuse());
        }
        for component in [repo_key, run_id, incarnation, invocation_hash] {
            if component.is_empty() {
                return Err(refuse());
            }
        }
        Ok(ContainerNameParts {
            repo_key: (*repo_key).to_owned(),
            run_id: (*run_id).to_owned(),
            incarnation: (*incarnation).to_owned(),
            invocation_hash: (*invocation_hash).to_owned(),
        })
    }

    /// Rebuild a name from a rendered value, refusing one no funnel could have
    /// written.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`] and [`Self::from_parts`].
    pub fn rebuild(value: &str) -> Result<Self, TactusError> {
        let parts = Self::parse(value)?;
        Self::from_parts(
            &parts.repo_key,
            &parts.run_id,
            &parts.incarnation,
            &parts.invocation_hash,
        )
    }

    /// The name of the container whose intent record this file name belongs to,
    /// or `None`.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when the stem is not a well-formed name.
    pub fn from_intent_file_name(file_name: &str) -> Result<Option<Self>, TactusError> {
        match file_name.strip_suffix(INTENT_SUFFIX) {
            Some(stem) => Self::rebuild(stem).map(Some),
            None => Ok(None),
        }
    }
}

impl std::fmt::Display for ContainerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `<R>/containers`.
#[must_use]
pub fn containers_dir(private_root: &Path) -> PathBuf {
    private_root.join(CONTAINERS_DIR)
}

/// `hex16(sha256(domain || 0x00 || rendered invocation id))`.
///
/// A digest and not the value itself, because the packet says
/// `<invocation-hash>`: a rendered [`InvocationId`] is up to
/// [`crate::runner::invocation::MAX_LEN`] bytes and carries `.` separators,
/// and the name already has four components. The **record** carries the
/// invocation in full, so ownership evidence stays exact — a 64-bit digest is
/// collision-resistant, not injective, and the difference matters for evidence
/// even though it does not matter for a name.
#[must_use]
pub fn invocation_hash(invocation: &InvocationId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INVOCATION_HASH_DOMAIN.as_bytes());
    hasher.update([0u8]);
    hasher.update(invocation.render().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(INVOCATION_HASH_HEX_CHARS);
    for byte in digest.iter().take(INVOCATION_HASH_HEX_CHARS.div_ceil(2)) {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex.truncate(INVOCATION_HASH_HEX_CHARS);
    hex
}

/// Refuse a component that would make the name ambiguous or unusable.
///
/// The charset excludes [`NAME_SEPARATOR`] — which is what
/// [`ContainerName::parse`]'s injectivity rests on — and `.`, which is the
/// separator inside a rendered [`InvocationId`] and the boundary of the
/// `.intent` suffix.
fn validate_component(what: &str, value: &str) -> Result<(), TactusError> {
    if value.is_empty() {
        return Err(TactusError::Refused {
            message: format!("a container name's {what} component is never empty"),
        });
    }
    if value.len() > MAX_COMPONENT_LEN {
        return Err(TactusError::Refused {
            message: format!(
                "a container name's {what} component is {} bytes; the limit is \
                 {MAX_COMPONENT_LEN}",
                value.len()
            ),
        });
    }
    if let Some(bad) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
    {
        return Err(TactusError::Refused {
            message: format!(
                "a container name's {what} component carries `{bad}`, which is outside \
                 [0-9A-Za-z_]; the name joins four components with `{NAME_SEPARATOR}` and \
                 names a file `<name>{INTENT_SUFFIX}`, so a component carrying the separator, \
                 a `.`, or a path separator would name a different container than the record \
                 says"
            ),
        });
    }
    Ok(())
}
