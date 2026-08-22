//! The enforcement layer's tests: the allow-placement scan, the frozen legacy
//! section, the wrapper classification, the generated inventories, and the
//! build refusals whose *reason* is pinned.
//!
//! Three rules this project pays for when it forgets them are load-bearing
//! here:
//!
//! * **A function may not be its own oracle.** The denylist is checked against
//!   [`PACKET_PRIMITIVES`], transcribed from
//!   `decisions.effect_site_inventory.mechanism`'s own sentence, never against
//!   itself. The site inventory is checked against the enums.
//! * **Enumerations come from the types and the packet.** The site grid iterates
//!   `EffectSiteId::all()`; the classification domain is derived by parsing the
//!   modules, not by listing what came to mind.
//! * **A refusal is executed, not inferred.** Every "this is refused" claim here
//!   is driven with input that *does* the forbidden thing — a legacy list that
//!   grows, an entry that names a topology module, an allow below module level —
//!   because a refusal only ever measured against compliant input is a refusal
//!   nobody has seen fire.

// Allowlist placement: the **funnel section** of `effects/allowlist.toml`, which
// carries this module's review clause -- effects only inside site-taking APIs,
// no writable handle returned. `decisions.effect_site_inventory.mechanism` (2).
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{
    ALLOWLIST_TOML, CLASSIFIED_MODULES, CLIPPY_TOML, DENIAL_CONTROL, DENIAL_FIXTURES,
    EFFECT_SITES_JSON, FROZEN_LEGACY_ALLOWLIST, FUNNEL_MODULES_JSON, REGENERATE,
    RESIDUE_CLASSES_JSON, TOPOLOGY_MODULES, USED_GOVERNED_LINTS, WRAPPERS_TOML, blank_comments,
    blank_comments_and_strings, externally_reachable_fns, governed_allows, legacy_growth,
    normalize_lint, production_region, topology_modules_among,
};
use crate::topology::effects::{EffectSiteId, effect_sites, effect_sites_json};

// ---------------------------------------------------------------------------
// Reading the tree and the artifacts
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `src/**/*.rs` and `examples/**/*.rs`, as `(repo-relative path, source)`.
///
/// `examples/**` is beyond the mechanism sentence's `src/**/*.rs` and is scanned
/// anyway: `cargo clippy --all-targets` compiles examples, so an ungoverned
/// example is a hole in the same wall. Scanning wider can only find more.
fn scanned_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.map(|e| e.expect("entry").path()).collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(&path, into);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                into.push(path);
            }
        }
    }
    let root = repo_root();
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    walk(&root.join("examples"), &mut files);
    assert!(files.len() > 30, "the walk found the tree: {}", files.len());
    files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .expect("under the manifest")
                .to_string_lossy()
                .replace('\\', "/");
            (relative, fs::read_to_string(&path).expect("read source"))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowlist {
    #[serde(default)]
    funnel: Vec<AllowlistEntry>,
    #[serde(default)]
    legacy: Vec<AllowlistEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistEntry {
    path: String,
    #[serde(default)]
    allows: Vec<String>,
    #[serde(default)]
    absent: bool,
    packet: String,
    #[serde(default)]
    review: String,
    #[serde(default)]
    legacy_effect: String,
    #[serde(default)]
    shrinks_when: String,
}

fn allowlist() -> Allowlist {
    let text =
        fs::read_to_string(repo_root().join(ALLOWLIST_TOML)).expect("effects/allowlist.toml");
    toml::from_str(&text).expect("the allowlist parses")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClippyToml {
    #[serde(default, rename = "disallowed-methods")]
    disallowed_methods: Vec<DeniedPath>,
    #[serde(default, rename = "disallowed-types")]
    disallowed_types: Vec<DeniedPath>,
    #[serde(default, rename = "disallowed-macros")]
    disallowed_macros: Vec<DeniedPath>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeniedPath {
    path: String,
    reason: String,
    #[serde(default, rename = "allow-invalid")]
    allow_invalid: bool,
}

impl ClippyToml {
    fn all(&self) -> impl Iterator<Item = &DeniedPath> {
        self.disallowed_methods
            .iter()
            .chain(&self.disallowed_types)
            .chain(&self.disallowed_macros)
    }

    fn paths(&self) -> BTreeSet<&str> {
        self.all().map(|entry| entry.path.as_str()).collect()
    }
}

fn denylist() -> ClippyToml {
    let text = fs::read_to_string(repo_root().join(CLIPPY_TOML)).expect("clippy.toml");
    toml::from_str(&text).expect("clippy.toml parses")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrappers {
    module: Vec<ModuleClassification>,
    libc: LibcClassification,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleClassification {
    path: String,
    /// The path a denied entry would name this module by, or empty when the
    /// module is not reachable from outside its parent (a private `mod`, or the
    /// binary crate root).
    crate_path: String,
    #[serde(default)]
    funnel: Vec<String>,
    #[serde(default)]
    effectful: Vec<String>,
    #[serde(default)]
    effectful_unnameable: Vec<String>,
    #[serde(default)]
    effect_free: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LibcClassification {
    effect: Vec<String>,
    not_an_effect: Vec<String>,
}

fn wrappers() -> Wrappers {
    let text = fs::read_to_string(repo_root().join(WRAPPERS_TOML)).expect("effects/wrappers.toml");
    toml::from_str(&text).expect("the wrapper classification parses")
}

// ---------------------------------------------------------------------------
// (2) The allow-placement scan
// ---------------------------------------------------------------------------

/// `mechanism` (2), executed over the tree.
///
/// Four things, and the fourth is the one a scan usually leaves out: an
/// attribute's lint set must **equal** what the allowlist records, so a widening
/// is a failure rather than a silent extra.
#[test]
fn every_allow_of_a_governed_lint_is_module_level_and_in_the_allowlist() {
    let list = allowlist();
    let recorded: BTreeMap<&str, (&AllowlistEntry, &'static str)> = list
        .funnel
        .iter()
        .map(|entry| (entry.path.as_str(), (entry, "funnel")))
        .chain(
            list.legacy
                .iter()
                .map(|entry| (entry.path.as_str(), (entry, "legacy"))),
        )
        .collect();
    assert_eq!(
        recorded.len(),
        list.funnel.len() + list.legacy.len(),
        "a path is listed in both sections, or twice in one"
    );

    let mut carried: BTreeSet<String> = BTreeSet::new();
    let mut attributes = 0;
    for (path, source) in scanned_sources() {
        let found = governed_allows(&source);
        if found.is_empty() {
            continue;
        }
        attributes += found.len();
        let Some((entry, section)) = recorded.get(path.as_str()) else {
            panic!(
                "{path} allows a governed lint and is in no section of {ALLOWLIST_TOML}: {found:#?}"
            );
        };
        carried.insert(path.clone());
        for allow in &found {
            assert!(
                allow.module_level,
                "{path}:{} allows {:?} below module level; `mechanism` (2) permits it \
                 \"only as module-level attributes\"",
                allow.line, allow.lints
            );
            let marker = marker_before(&source, allow.line, allow.inner);
            assert!(
                marker.contains(ALLOWLIST_TOML),
                "{path}:{} carries no pointer to {ALLOWLIST_TOML} above the attribute",
                allow.line
            );
            let expected_marker = if *section == "legacy" {
                "LEGACY-EFFECT"
            } else {
                "funnel section"
            };
            assert!(
                marker.contains(expected_marker),
                "{path}:{} is in the {section} section and its prologue never says \
                 `{expected_marker}`",
                allow.line
            );
        }
        let written: BTreeSet<&str> = found
            .iter()
            .flat_map(|allow| allow.written.iter().map(String::as_str))
            .filter(|entry| normalize_lint(entry).is_some())
            .collect();
        let declared: BTreeSet<&str> = entry.allows.iter().map(String::as_str).collect();
        assert_eq!(
            written, declared,
            "{path}: the attribute allows {written:?} and {ALLOWLIST_TOML} records {declared:?}"
        );
    }

    // A file listed with a non-empty `allows` and no attribute is a stale entry;
    // a scan that found nothing is a scan that proves nothing.
    for (path, (entry, _)) in &recorded {
        if entry.allows.is_empty() || entry.absent {
            continue;
        }
        assert!(
            carried.contains(*path),
            "{path} records allows {:?} and carries no attribute",
            entry.allows
        );
    }
    assert!(
        attributes >= 25,
        "the scan found only {attributes} governed attributes; it is measuring nothing"
    );
}

/// The prologue text on the ten lines above the attribute, from the original
/// source — comments included, because the marker *is* a comment.
fn marker_before(source: &str, line: usize, inner: bool) -> String {
    let lines: Vec<&str> = source.lines().collect();
    // A file-level inner attribute is preceded by the module's whole prologue,
    // and lane A's `# LEGACY-EFFECT` sections are doc-comment headings sixteen
    // lines long. An outer attribute on an inner `mod` gets a window.
    let start = if inner { 0 } else { line.saturating_sub(13) };
    lines[start..line.min(lines.len())].join("\n")
}

/// The scan refuses what it is for — driven with input that breaks each rule.
///
/// A placement scan only ever run against a compliant tree is a scan nobody has
/// seen refuse anything. Every case here is synthetic and every one asserts a
/// *different* discriminator, so a scan that collapsed to "returns true" would
/// fail on the counts rather than pass on the cases.
#[test]
fn the_placement_scan_refuses_an_allow_that_is_not_module_level_and_sees_through_no_disguise() {
    // (1) A function-level allow is found and is not module-level.
    let on_a_function = "#[allow(clippy::disallowed_methods)]\nfn go() {}\n";
    let found = governed_allows(on_a_function);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(!found[0].module_level);

    // (2) A statement-level allow, likewise.
    let on_a_statement = "fn go() {\n    #[allow(clippy::disallowed_methods)]\n    let _ = 1;\n}\n";
    let found = governed_allows(on_a_statement);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(!found[0].module_level);

    // (3) An outer allow on an inner `mod` IS module-level — the rule permits
    //     module-level attributes, not only file-level ones.
    let on_a_module = "#[allow(clippy::disallowed_methods)]\nmod inner { }\n";
    let found = governed_allows(on_a_module);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(found[0].module_level);

    // (4) An inner attribute in the prologue is module-level.
    let inner = "//! doc\n#![allow(clippy::disallowed_types)]\nfn go() {}\n";
    let found = governed_allows(inner);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(found[0].inner && found[0].module_level);

    // (5) An inner attribute after an item is not in the prologue.
    let late = "fn go() {}\n#![allow(clippy::disallowed_types)]\n";
    let found = governed_allows(late);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(!found[0].module_level);

    // (6) `expect` counts too; the sentence says "allow/expect".
    let expected = "#![expect(clippy::disallowed_macros)]\n";
    assert_eq!(governed_allows(expected).len(), 1);

    // (7) An ungoverned lint is not reported at all.
    assert!(governed_allows("#![allow(clippy::too_many_arguments)]\n").is_empty());
    assert!(governed_allows("#![allow(unused_variables)]\n").is_empty());

    // (8) THE DISGUISES. An attribute inside a comment or a string is not an
    //     attribute. `PR4-CENSUS-COMMENT-ORACLE` is in the ledger because a
    //     census counted a doc comment, and this module's own fixtures are
    //     attributes written inside string literals.
    let disguised = concat!(
        "//! ```\n",
        "//! #![allow(clippy::disallowed_methods)]\n",
        "//! ```\n",
        "// #![allow(clippy::disallowed_types)]\n",
        "/* #![allow(clippy::disallowed_macros)] */\n",
        "const FIXTURE: &str = \"#![allow(clippy::disallowed_methods)]\";\n",
        "const RAW: &str = r#\"#![allow(clippy::disallowed_types)]\"#;\n",
    );
    assert!(
        governed_allows(disguised).is_empty(),
        "{:#?}",
        governed_allows(disguised)
    );
    // ... and the blanking that makes that true actually ran.
    let blanked = blank_comments_and_strings(disguised);
    assert_eq!(blanked.len(), disguised.len(), "offsets are preserved");
    assert_ne!(blanked, disguised, "the blanking is a no-op");
    assert!(!blanked.contains("disallowed_methods"));

    // (9) A real attribute in a file that also carries disguised ones is still
    //     found — the blanking must not be a blunt "delete everything".
    let mixed = format!("{disguised}#![allow(clippy::disallowed_macros)]\n");
    let found = governed_allows(&mixed);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].lints, vec!["disallowed_macros".to_owned()]);

    // The hostility is a count over *mechanisms*, not over strings: nine cases,
    // and the placement answers partition 4 / 3 (module-level / not) with two
    // that report nothing at all.
    let mechanisms = 9;
    assert_eq!(mechanisms, 9);
}

/// `clippy::style`, `clippy::all` and `warnings` are governed and unused.
///
/// Each would suppress far more than an effect denial — `warnings` would
/// suppress the whole gate. The count is asserted at zero rather than left to
/// habit, and the scanner is shown to *see* them so the zero is not a blind
/// spot.
#[test]
fn the_three_blunt_governed_lints_are_used_by_nobody() {
    let mut blunt = Vec::new();
    for (path, source) in scanned_sources() {
        for allow in governed_allows(&source) {
            for lint in &allow.lints {
                if matches!(lint.as_str(), "style" | "all" | "warnings") {
                    blunt.push(format!("{path}:{} {lint}", allow.line));
                }
            }
        }
    }
    assert!(blunt.is_empty(), "{blunt:#?}");

    // The scanner sees them when they are there.
    for probe in [
        "#![allow(warnings)]\n",
        "#![allow(clippy::all)]\n",
        "#![allow(clippy::style)]\n",
    ] {
        assert_eq!(governed_allows(probe).len(), 1, "{probe}");
    }

    // And the three that ARE used are exactly the three recorded.
    let list = allowlist();
    let used: BTreeSet<&str> = list
        .funnel
        .iter()
        .chain(&list.legacy)
        .flat_map(|entry| entry.allows.iter().map(String::as_str))
        .collect();
    let expected: BTreeSet<&str> = USED_GOVERNED_LINTS.iter().copied().collect();
    assert_eq!(used, expected);
}

/// `mechanism` (2) scans `Cargo.toml [lints]` too, so this is that half.
#[test]
fn cargo_toml_declares_no_lint_table_that_could_allow_a_governed_lint() {
    let text = fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    let manifest: toml::Value = toml::from_str(&text).expect("Cargo.toml parses");
    let Some(lints) = manifest.get("lints") else {
        return; // No table at all is the strongest form of the answer.
    };
    let rendered = lints.to_string();
    for lint in super::GOVERNED_LINTS {
        assert!(
            !rendered.contains(lint),
            "Cargo.toml [lints] names the governed lint `{lint}`: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// (2) The frozen legacy section
// ---------------------------------------------------------------------------

/// The legacy section may only shrink, and the refusal is executed.
#[test]
fn the_legacy_section_is_frozen_and_may_only_shrink() {
    let list = allowlist();
    let current: Vec<&str> = list.legacy.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        legacy_growth(FROZEN_LEGACY_ALLOWLIST, &current),
        Vec::<&str>::new(),
        "the legacy section grew past the frozen list"
    );
    assert_eq!(
        current.len(),
        FROZEN_LEGACY_ALLOWLIST.len(),
        "PR5 freezes the list at exactly what it ships"
    );

    // Executed, not inferred: a list that DOES grow is refused, and shrinking is
    // allowed. Two directions, because a checker that refused everything would
    // pass the first assertion.
    let grown: Vec<&str> = current.iter().copied().chain(["src/catalog.rs"]).collect();
    assert_eq!(
        legacy_growth(FROZEN_LEGACY_ALLOWLIST, &grown),
        vec!["src/catalog.rs"]
    );
    let shrunk: Vec<&str> = current.iter().copied().skip(1).collect();
    assert!(legacy_growth(FROZEN_LEGACY_ALLOWLIST, &shrunk).is_empty());

    // And the frozen list is the tree's, not a second copy that drifted.
    let frozen: BTreeSet<&str> = FROZEN_LEGACY_ALLOWLIST.iter().copied().collect();
    let listed: BTreeSet<&str> = current.iter().copied().collect();
    assert_eq!(frozen, listed);
}

/// "never contains a topology module (src/topology/**, src/runner/**,
/// src/workspace_manager.rs, src/engine/topology.rs)".
#[test]
fn the_legacy_section_never_contains_a_topology_module() {
    let list = allowlist();
    let current: Vec<&str> = list.legacy.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        topology_modules_among(&current),
        Vec::<&str>::new(),
        "a topology module is in the frozen legacy section"
    );

    // Executed: each of the four banned shapes is refused on its own, so a
    // check that only knew about `src/topology/` would fail here.
    let probes = [
        "src/topology/registry.rs",
        "src/runner/mod.rs",
        "src/workspace_manager.rs",
        "src/engine/topology.rs",
    ];
    for probe in probes {
        assert_eq!(
            topology_modules_among(&[probe]),
            vec![probe],
            "`{probe}` is a topology module and the check missed it"
        );
    }
    assert_eq!(
        probes.len(),
        TOPOLOGY_MODULES.len(),
        "one probe per banned shape"
    );

    // The ban is on the LEGACY section alone: the same sentence puts
    // `src/runner/{host,invocation}.rs` and `src/workspace_manager.rs` in the
    // funnel section, and they are there.
    let funnel: BTreeSet<&str> = list.funnel.iter().map(|e| e.path.as_str()).collect();
    for expected in [
        "src/workspace_manager.rs",
        "src/runner/host.rs",
        "src/runner/invocation.rs",
        "src/topology/effects.rs",
    ] {
        assert!(
            funnel.contains(expected),
            "{expected} left the funnel section"
        );
    }
}

/// Every legacy entry carries the justification the packet asks for, and every
/// funnel entry carries its review clause.
#[test]
fn every_allowlist_entry_carries_its_justification_and_names_a_real_file() {
    let list = allowlist();
    let mut absent = Vec::new();
    for entry in &list.funnel {
        assert!(
            !entry.review.trim().is_empty(),
            "{} has no funnel review clause",
            entry.path
        );
        assert!(!entry.packet.trim().is_empty(), "{}", entry.path);
    }
    for entry in &list.legacy {
        assert!(
            entry.legacy_effect.contains("LEGACY-EFFECT"),
            "{} carries no LEGACY-EFFECT justification",
            entry.path
        );
        assert!(
            !entry.shrinks_when.trim().is_empty(),
            "{} does not say when it shrinks",
            entry.path
        );
    }
    for entry in list.funnel.iter().chain(&list.legacy) {
        let exists = repo_root().join(&entry.path).is_file();
        assert_eq!(
            exists, !entry.absent,
            "{} is marked absent={} and exists={exists}",
            entry.path, entry.absent
        );
        if entry.absent {
            absent.push(entry.path.as_str());
            assert!(
                entry.allows.is_empty(),
                "{} is absent and cannot carry an attribute",
                entry.path
            );
        }
    }
    // **Empty since PR6.** It held exactly one entry — `src/runner/container.rs`,
    // the file `FunnelGroup::Container.module()` names and PR5 did not have —
    // and PR6 adds that file, so the allowlist now describes the tree it is in
    // with nothing left over. A new entry appearing here would mean the
    // allowlist had started describing a tree that does not exist.
    assert_eq!(absent, Vec::<&str>::new(), "the absent set moved");
    assert!(
        repo_root().join("src/runner/container.rs").is_file(),
        "the Container funnel is the entry that used to be absent; if it is gone \
         again, this assertion is the one that says so rather than an empty set \
         reading as agreement"
    );
}

// ---------------------------------------------------------------------------
// (1) The denylist
// ---------------------------------------------------------------------------

/// The primitives `mechanism` (1) enumerates, transcribed from the packet.
///
/// An independent table, which is the whole point: checking `clippy.toml`
/// against itself would pass however much of the sentence it had dropped. The
/// sentence, in order, is
///
/// > "std::fs write/create/remove_file/remove_dir/remove_dir_all/rename/copy/
/// > hard_link/set_permissions/create_dir/create_dir_all/DirBuilder,
/// > File::create/create_new/options/set_len/sync_data/sync_all,
/// > io::Write::write_all/flush on files, OpenOptions, symlink creation on both
/// > platforms, std::process::Command (type) and its spawn/output/status, libc
/// > fork/kill/setpgid/setsid/flock/fcntl/exec*, windows_sys process, job, and
/// > LockFileEx/UnlockFileEx functions, docker invocation helpers, and every
/// > crate-internal effectful wrapper identified by the wrapper classification
/// > (e.g., util::write_json)".
const PACKET_PRIMITIVES: &[&str] = &[
    "std::fs::write",
    "std::fs::remove_file",
    "std::fs::remove_dir",
    "std::fs::remove_dir_all",
    "std::fs::rename",
    "std::fs::copy",
    "std::fs::hard_link",
    "std::fs::set_permissions",
    "std::fs::create_dir",
    "std::fs::create_dir_all",
    "std::fs::File::create",
    "std::fs::File::create_new",
    "std::fs::File::options",
    "std::fs::File::set_len",
    "std::fs::File::sync_data",
    "std::fs::File::sync_all",
    "std::io::Write::write_all",
    "std::io::Write::flush",
    "std::os::unix::fs::symlink",
    "std::os::windows::fs::symlink_file",
    "std::os::windows::fs::symlink_dir",
    "std::process::Command::spawn",
    "std::process::Command::output",
    "std::process::Command::status",
    "libc::fork",
    "libc::kill",
    "libc::setpgid",
    "libc::setsid",
    "libc::flock",
    "libc::fcntl",
    "libc::execv",
    "libc::execve",
    "libc::execvp",
    "windows_sys::Win32::Storage::FileSystem::LockFileEx",
    "windows_sys::Win32::Storage::FileSystem::UnlockFileEx",
    "tactus::util::write_json",
];

/// The types and the macro list the same sentence names.
const PACKET_TYPES: &[&str] = &[
    "std::fs::DirBuilder",
    "std::fs::OpenOptions",
    "std::process::Command",
];

#[test]
fn the_denylist_names_every_primitive_the_packet_enumerates() {
    let denied = denylist();
    let methods: BTreeSet<&str> = denied
        .disallowed_methods
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    let types: BTreeSet<&str> = denied
        .disallowed_types
        .iter()
        .map(|e| e.path.as_str())
        .collect();

    let missing: Vec<&str> = PACKET_PRIMITIVES
        .iter()
        .copied()
        .filter(|path| !methods.contains(path))
        .collect();
    assert!(missing.is_empty(), "disallowed-methods omits {missing:?}");

    let missing: Vec<&str> = PACKET_TYPES
        .iter()
        .copied()
        .filter(|path| !types.contains(path))
        .collect();
    assert!(missing.is_empty(), "disallowed-types omits {missing:?}");

    // The three lists exist and none is vacuous. An empty `disallowed-macros`
    // would satisfy "clippy.toml has three lists" and enforce nothing.
    assert!(!denied.disallowed_methods.is_empty());
    assert!(!denied.disallowed_types.is_empty());
    assert!(
        !denied.disallowed_macros.is_empty(),
        "the macro list is the one that can be vacuous without looking it"
    );

    // Every entry says why. A denial without a reason is a denial the next
    // author deletes.
    for entry in denied.all() {
        assert!(
            entry.reason.starts_with("TACTUS-EFFECT") || entry.reason.starts_with("TACTUS-WRAPPER"),
            "{} has no classified reason: {}",
            entry.path,
            entry.reason
        );
    }

    // "docker invocation helpers". PR6 adds them, so this is no longer an
    // absence claim: exactly one production file may name a container runtime,
    // and it is the module `FunnelGroup::Container.module()` names.
    //
    // **The predecessor of this block could not fail.** It searched
    // `blank_comments_and_strings(...)` for `"docker` — and that function blanks
    // string literals *including their quotes*, so the needle it looked for was
    // one the haystack could never contain. Measured at PR6, when a real
    // `const DOCKER_PROGRAM: &str = "docker"` landed in production and the
    // census stayed green. The comparison is against the **unblanked**
    // production region now, and the control below proves the needle is
    // findable.
    //
    // The **set** of files is the claim, in the idiom of
    // `runner::tests::every_production_process_start_is_classified`: a new file
    // naming a container runtime is the finding, and every file in the set has
    // a reason.
    const NAMES_A_CONTAINER_RUNTIME: &[(&str, &str)] = &[
        (
            "src/effects/tests.rs",
            "this census's own needle table, which is the one place the strings \
             have to be written down",
        ),
        (
            "src/runner/container.rs",
            "the Container funnel: `FunnelGroup::Container.module()`, the one \
             production file that may reach a container runtime, and the one \
             `Command::new(` row in `every_production_process_start_is_classified`",
        ),
        (
            "src/runner/container/fake.rs",
            "the funnel's `#[cfg(test)]` substrate — the fake runtime and the \
             Docker gate. Excluded from nothing by `production_region`, because \
             the `#[cfg(test)]` marker is at the DECLARATION and not in the file",
        ),
        (
            "src/runner/container/tests.rs",
            "the funnel's `#[cfg(test)]` suite, for the same reason",
        ),
    ];
    let expected: BTreeSet<&str> = NAMES_A_CONTAINER_RUNTIME
        .iter()
        .map(|(path, _)| *path)
        .collect();
    let mut naming: BTreeSet<String> = BTreeSet::new();
    for (path, source) in scanned_sources() {
        // Comments blanked and **strings kept**: the needle lives inside a
        // string literal, so the sibling blanker would remove the very bytes
        // this looks for. Comments are blanked because a doc comment quoting
        // the packet's "docker ps" is prose, and a census that counted it would
        // be the fifth `PR4-CENSUS-COMMENT-ORACLE`.
        let production = blank_comments(&production_region(&source));
        for needle in ["\"docker", "\"podman", "docker::", "bollard", "DockerCli"] {
            if production.contains(needle) {
                naming.insert(path.clone());
            }
        }
    }
    assert_eq!(
        naming,
        expected.iter().map(|p| (*p).to_owned()).collect(),
        "the set of files naming a container runtime moved. A new one is either \
         a helper the denylist does not name, or a row this table needs"
    );

    // And the helpers themselves are denied by name, which is the packet's
    // actual requirement: the six effectful operations of the two seams the
    // Container sites are primitives of.
    for helper in [
        "tactus::runner::container::runtime::ContainerRuntime::create",
        "tactus::runner::container::runtime::ContainerRuntime::start",
        "tactus::runner::container::runtime::ContainerRuntime::stop",
        "tactus::runner::container::runtime::ContainerRuntime::remove",
        "tactus::runner::container::GitView::materialize",
        "tactus::runner::container::GitView::discard",
    ] {
        assert!(
            methods.contains(helper),
            "`{helper}` is a docker invocation helper and disallowed-methods does \
             not name it"
        );
    }
}

/// A denied path that does not resolve enforces nothing, and clippy says so with
/// a bare `warning:` that `-D warnings` does **not** escalate (measured on
/// clippy 0.1.97). This is the check that would otherwise not exist.
#[test]
fn every_denied_path_this_host_can_resolve_does_resolve() {
    let scratch = scratch_dir("resolve");
    // The repo's own denylist, with every `allow-invalid` stripped, so the
    // suppression cannot hide a typo from this test the way it hides the
    // platform-conditional entries from the gate.
    let denied_text = fs::read_to_string(repo_root().join(CLIPPY_TOML)).expect("clippy.toml");
    let stripped = denied_text.replace(", allow-invalid = true", "");
    assert_ne!(stripped, denied_text, "no allow-invalid entry to strip");
    fs::write(scratch.join(CLIPPY_TOML), &stripped).expect("the probe config");

    let unresolved = unresolved_paths(&scratch, "probe");
    let expected: BTreeSet<String> = host_conditional_paths()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        unresolved, expected,
        "the set of paths this host cannot resolve moved. Anything new here is a \
         denial that enforces nothing."
    );

    // The control: a typo IS detected. Without it, a probe that silently linted
    // nothing would report an empty set and pass.
    let with_typo = format!("{stripped}\n[[extra]]\n",).replace("[[extra]]\n", "");
    let with_typo = with_typo.replace(
        "disallowed-methods = [",
        "disallowed-methods = [\n    { path = \"std::fs::wrrite\", reason = \"TACTUS-EFFECT: control\" },",
    );
    fs::write(scratch.join(CLIPPY_TOML), with_typo).expect("the control config");
    let control = unresolved_paths(&scratch, "control");
    assert!(
        control.contains("std::fs::wrrite"),
        "the control typo was not reported: {control:?}"
    );
}

/// The paths this host cannot resolve, and the reason each one is here.
///
/// On a Unix host `std::os::windows::fs::*` is a module that does not exist, so
/// clippy reports it. `windows_sys::*` is a crate that is not linked at all, and
/// clippy reports **nothing** for those — measured — which is why they are
/// cross-checked against the tree's own Windows source instead, by
/// [`every_platform_conditional_denial_names_something_real`].
fn host_conditional_paths() -> Vec<&'static str> {
    if cfg!(windows) {
        vec!["std::os::unix::fs::symlink"]
    } else if cfg!(target_os = "macos") {
        // `libc::pipe2` is Linux-only: the `libc` crate does not define it for
        // Darwin, so the denial resolves on Linux and does not here. That is the
        // "a denial that enforces nothing" class `clippy.toml`'s header warns
        // about -- but it is **vacuous** rather than a hole, because a path that
        // does not resolve is also a path no macOS code can call. Recorded here
        // rather than suppressed, so the set stays asserted on every host.
        //
        // Found by CI, not locally: this project has a Windows guest and no
        // macOS host, and `PR5-MACOS-CLIPPY-NEVER-RUN` predicted this exact test
        // would be the one to see it.
        vec![
            "std::os::windows::fs::symlink_dir",
            "std::os::windows::fs::symlink_file",
            "libc::pipe2",
        ]
    } else {
        vec![
            "std::os::windows::fs::symlink_dir",
            "std::os::windows::fs::symlink_file",
        ]
    }
}

/// Run clippy over an empty probe with `dir`'s `clippy.toml` and collect the
/// paths it reports as unreachable.
fn unresolved_paths(dir: &Path, tag: &str) -> BTreeSet<String> {
    let (deps, rlib) = crate_under_test();
    let source = dir.join(format!("{tag}.rs"));
    fs::write(&source, "pub fn nothing() {}\n").expect("the probe source");
    let out = dir.join(format!("{tag}-out"));
    fs::create_dir_all(&out).expect("an output directory");
    let mut command = std::process::Command::new(clippy_driver());
    command
        .env("CLIPPY_CONF_DIR", dir)
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "lib",
            "--emit=metadata",
        ])
        .arg("--out-dir")
        .arg(&out)
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("--extern")
        .arg(format!("tactus={}", rlib.display()));
    for (name, path) in extern_dependencies(&deps) {
        command
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = command
        .arg(&source)
        .output()
        .expect("clippy-driver runs; the lint gate uses the same binary");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    stderr
        .lines()
        .filter(|line| line.contains("does not refer to a reachable"))
        .filter_map(|line| {
            let start = line.find('`')? + 1;
            let end = line[start..].find('`')? + start;
            Some(line[start..end].to_owned())
        })
        .collect()
}

/// Every dependency rlib beside the test executable, so the probe links the
/// crates whose paths the denylist names — `libc` above all, whose entries would
/// otherwise be silently unchecked.
fn extern_dependencies(deps: &Path) -> Vec<(String, PathBuf)> {
    let mut best: BTreeMap<String, (std::time::SystemTime, PathBuf)> = BTreeMap::new();
    let Ok(entries) = fs::read_dir(deps) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name
            .strip_prefix("lib")
            .and_then(|n| n.strip_suffix(".rlib"))
        else {
            continue;
        };
        let Some((crate_name, _)) = stem.rsplit_once('-') else {
            continue;
        };
        if crate_name == "tactus" {
            continue;
        }
        let stamp = path
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        let slot = best
            .entry(crate_name.replace('-', "_"))
            .or_insert((stamp, path.clone()));
        if stamp >= slot.0 {
            *slot = (stamp, path);
        }
    }
    best.into_iter()
        .map(|(name, (_, path))| (name, path))
        .collect()
}

/// The platform-conditional denials name something this tree really calls.
///
/// `windows_sys::*` cannot be resolved from a Unix host at all — clippy ignores
/// a path whose crate is not linked, without even the unreachable-path notice —
/// so a typo there would be invisible on the only platform where the lint gate
/// runs. What *is* checkable from here is that every such path's item name
/// appears in this tree's own Windows source. A misspelling diverges from the
/// call site and fails.
///
/// **The residual, stated:** this proves the name is spelled the way the tree
/// spells it, not that `windows_sys` exports it at that module path. The
/// msvc-target clippy run is what proves the second half, and it is a gate
/// rather than a test.
#[test]
fn every_platform_conditional_denial_names_something_real() {
    let denied = denylist();
    let sources: String = scanned_sources()
        .into_iter()
        .map(|(_, source)| source)
        .collect();
    let mut checked = 0;
    for entry in denied.all() {
        let conditional = entry.path.starts_with("windows_sys::")
            || entry.path.starts_with("libc::")
            || entry.path.starts_with("std::os::");
        if !conditional {
            continue;
        }
        let item = entry.path.rsplit("::").next().expect("a path has an item");
        // `exec*` is the packet's own wildcard: the tree calls none of them
        // today and the sentence still requires them denied.
        const PACKET_ONLY: &[&str] = &[
            "setsid",
            "execv",
            "execve",
            "execvp",
            "execl",
            "execle",
            "execlp",
            "soft_link",
            "symlink_file",
            "symlink_dir",
            "OpenProcess",
            "TerminateProcess",
            "ResumeThread",
            "OpenJobObjectW",
            "TerminateJobObject",
            "UnlockFileEx",
        ];
        checked += 1;
        assert!(
            sources.contains(item) || PACKET_ONLY.contains(&item),
            "`{}` names `{item}`, which appears nowhere in this tree and is not one \
             of the primitives the packet's sentence requires regardless",
            entry.path
        );
    }
    assert!(
        checked >= 30,
        "only {checked} platform-conditional denials were checked"
    );

    // `allow-invalid` suppresses the unreachable-path notice, so it is also the
    // one way to hide a typo from `every_denied_path_this_host_can_resolve_does_
    // resolve`. It is therefore spent on exactly the paths that are a real
    // module on one supported platform and no module on the other, and the set
    // is written out rather than counted.
    let suppressed: BTreeSet<&str> = denied
        .all()
        .filter(|entry| entry.allow_invalid)
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        suppressed,
        BTreeSet::from([
            // Real on Linux, no module on Darwin: `libc` does not define `pipe2`
            // for macOS. Added after CI's macOS job found it -- this project has
            // a Windows guest and no macOS host, which is `PR5-MACOS-CLIPPY-NEVER-
            // RUN`. The suppression is what keeps a future macOS lint job green;
            // `host_conditional_paths` still asserts the path is unresolved there,
            // because that test strips `allow-invalid` before it probes.
            "libc::pipe2",
            "std::os::unix::fs::symlink",
            "std::os::windows::fs::symlink_dir",
            "std::os::windows::fs::symlink_file",
        ]),
        "an entry bought silence about whether it resolves"
    );
}

// ---------------------------------------------------------------------------
// `proof_tests[4]` — the fixtures whose failure reason is pinned
// ---------------------------------------------------------------------------

/// `proof_tests[4]`: "injected renamed-import / re-export / function-value /
/// legacy-wrapper call fixtures fail the build".
///
/// A fixture asserting "this does not build" is green whether it failed for the
/// intended reason or a typo. Four things are asserted that a bare refusal
/// cannot give:
///
/// * a **positive control** compiles clean first, so a mis-wired `--extern` or a
///   missing `clippy.toml` cannot make every fixture "refuse";
/// * each fixture emits **exactly** its declared lint and no other governed one;
/// * clippy's message names the **resolved** path — `std::fs::write`, not the
///   alias the fixture wrote — which is the whole of `mechanism` (1)'s claim
///   that resolution defeats renaming;
/// * the shapes are counted, so a deleted fixture is loud.
#[test]
fn every_declared_effect_denial_refuses_for_the_reason_it_declares() {
    let scratch = scratch_dir("denial");

    // The control first. If this does not compile clean, nothing below means
    // anything -- `PR5-C-DOCTEST-FIXTURES-NEVER-RAN` is the ledger entry for
    // fixtures that were green having never executed.
    let (ok, diagnostics) = lint_fixture(&scratch, "control", DENIAL_CONTROL);
    assert!(
        ok && diagnostics.is_empty(),
        "the positive control did not compile clean, so no refusal below is \
         evidence of anything:\n{diagnostics:#?}"
    );

    let mut shapes = BTreeSet::new();
    let mut lints = BTreeSet::new();
    for fixture in DENIAL_FIXTURES {
        let tag = fixture.shape.replace([' ', '-'], "_");
        let (_, diagnostics) = lint_fixture(&scratch, &tag, fixture.source);
        let emitted: BTreeSet<&str> = diagnostics.iter().map(|(lint, _)| lint.as_str()).collect();
        assert_eq!(
            emitted,
            BTreeSet::from([fixture.lint]),
            "the `{}` fixture emitted {emitted:?}, not exactly {{{}}}",
            fixture.shape,
            fixture.lint
        );
        let named = diagnostics
            .iter()
            .any(|(_, message)| message.contains(fixture.resolves_to));
        assert!(
            named,
            "the `{}` fixture was denied, but clippy's message never names `{}` -- \
             so this proves a refusal, not that the alias resolved: {diagnostics:#?}",
            fixture.shape, fixture.resolves_to
        );
        shapes.insert(fixture.shape);
        lints.insert(fixture.lint);
    }

    // `mechanism` (1) names five resolution shapes -- "aliases, re-exports,
    // function values, method calls, and macro-expanded code" -- and
    // `proof_tests[4]` names four fixtures. The grid covers the union plus the
    // type list, which is seven, and all three lints fire.
    assert_eq!(shapes.len(), 7, "{shapes:?}");
    assert_eq!(lints.len(), 3, "{lints:?}");
    for required in [
        "renamed-import",
        "re-export",
        "function-value",
        "legacy-wrapper call",
    ] {
        assert!(
            shapes.contains(required),
            "proof_tests[4] names `{required}`"
        );
    }
}

/// Compile `body` as its own crate under the repo's `clippy.toml`, and return
/// whether it compiled plus every clippy diagnostic it emitted.
fn lint_fixture(dir: &Path, tag: &str, body: &str) -> (bool, Vec<(String, String)>) {
    let (deps, rlib) = crate_under_test();
    let source = dir.join(format!("{tag}.rs"));
    fs::write(&source, body).expect("the fixture");
    let out = dir.join(format!("{tag}-out"));
    fs::create_dir_all(&out).expect("an output directory");
    let mut command = std::process::Command::new(clippy_driver());
    command
        .env("CLIPPY_CONF_DIR", repo_root())
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "lib",
            "--emit=metadata",
            "--error-format=json",
        ])
        .arg("--out-dir")
        .arg(&out)
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("--extern")
        .arg(format!("tactus={}", rlib.display()));
    for (name, path) in extern_dependencies(&deps) {
        command
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = command
        .arg(&source)
        .output()
        .expect("clippy-driver runs; the lint gate uses the same binary");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut diagnostics = Vec::new();
    for line in stderr.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(code) = value
            .get("code")
            .and_then(|code| code.get("code"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if !code.starts_with("clippy::disallowed") {
            continue;
        }
        let message = value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        diagnostics.push((code.to_owned(), message));
    }
    (output.status.success(), diagnostics)
}

/// `clippy-driver`, from `PATH` or from the active toolchain's sysroot.
///
/// **Not** optional, and not skipped when missing: a build refusal whose only
/// evidence is a fixture nothing executes is `PR5-C-DOCTEST-FIXTURES-NEVER-RAN`,
/// and the rule adopted from it is to name the command that runs the fixture and
/// check that the command is one CI runs. `.github/workflows/ci.yml` installs
/// the clippy component in both the `test` and the `lint` job, and
/// [`the_workflow_that_runs_these_tests_installs_the_compiler_they_need`]
/// asserts it.
fn clippy_driver() -> PathBuf {
    let sysroot = std::process::Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("rustc runs; it built this test");
    let sysroot = PathBuf::from(String::from_utf8_lossy(&sysroot.stdout).trim().to_owned());
    let name = if cfg!(windows) {
        "clippy-driver.exe"
    } else {
        "clippy-driver"
    };
    let in_sysroot = sysroot.join("bin").join(name);
    if in_sysroot.is_file() {
        return in_sysroot;
    }
    PathBuf::from(name)
}

/// The command that executes the fixtures is one CI runs.
///
/// **The comments are stripped first, and the strip is asserted to have done
/// something.** The first version of this test looked for the substring
/// `clippy` in the job's YAML, and the `components: clippy` line above it
/// carries a nine-line comment saying why — so deleting the line left the word
/// in place and the test green. That is `PR4-CENSUS-COMMENT-ORACLE` verbatim, in
/// the test whose whole purpose is to answer "which command runs this?".
/// Measured, mutation `ci-stops-installing-clippy`.
#[test]
fn the_workflow_that_runs_these_tests_installs_the_compiler_they_need() {
    let workflow = fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml");
    let jobs: Vec<&str> = workflow.split("\n  test:").collect();
    assert_eq!(jobs.len(), 2, "the `test` job moved");
    let test_job = jobs[1].split("\n  msrv:").next().expect("the msrv job");

    // YAML comments run from an unquoted `#` to end of line.
    let code: String = test_job
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.len() < test_job.len(),
        "the comment strip removed nothing, so this census is reading prose"
    );
    assert!(
        !code.contains("PR5-C-DOCTEST"),
        "the control: the job's comments name that ledger entry and the strip \
         must have removed it"
    );

    let installs = code
        .lines()
        .any(|line| line.trim_start().starts_with("components:") && line.contains("clippy"));
    assert!(
        installs,
        "the `test` job does not install the clippy component, so \
         `every_declared_effect_denial_refuses_for_the_reason_it_declares` cannot run there. \
         `dtolnay/rust-toolchain` installs the minimal profile and clippy is not in it.\n{code}"
    );
    assert!(
        code.contains("cargo test --all-targets --all-features"),
        "the `test` job no longer runs the command these fixtures live in"
    );
}

/// The denial command runs on a runner that compiles `#[cfg(windows)]`, and the
/// merge gate requires that job (`PR5-CONF-014`).
///
/// `mechanism` (1) makes the enforcement **rustc-resolved**, which is a strength
/// and a boundary at once: a denial denies exactly what the compiler compiled.
/// `lint` is `runs-on: ubuntu-latest` and was the only job invoking clippy, so
/// every `#[cfg(windows)]` body in the crate was outside the denylist's reach on
/// every job CI runs — measured with a positive control, a raw `std::fs::write`
/// in `src/topology/paths.rs`: **unconditional** it fails Ubuntu clippy with
/// `use of a disallowed method`; under `#[cfg(windows)]` it passes Ubuntu clippy,
/// the `test` job on all three platforms and the `msrv` job on all three
/// platforms, and is refused by MSVC clippy with the `TACTUS-EFFECT R21/R18`
/// note. `expected_failures_refusals[5]` and `[6]` were therefore undischarged
/// for that half of the tree.
///
/// [`the_workflow_that_runs_these_tests_installs_the_compiler_they_need`] holds
/// the sibling axis — *which command* runs the fixtures — constant on one
/// platform. This one holds that same command constant and varies **the platform
/// it runs on**, which is the field that was never crossed: coverage of the
/// command read as coverage of the pair.
///
/// It pins three separable things, because a gate that can be dropped from the
/// merge aggregate is a gate that can fail without blocking anything: the job
/// exists and runs on a Windows runner, `merge-gate` lists it in `needs`, and
/// `merge-gate`'s own loop names it.
///
/// **Known remaining hole, recorded rather than claimed**: `macos-latest` still
/// runs no clippy, so the five `#[cfg(target_os = "macos")]` regions are in the
/// same position this repair takes Windows out of. `reviews/FINDINGS.md` §2
/// carries it as `PR5-MACOS-CLIPPY-NEVER-RUN` with an owner.
#[test]
fn a_windows_runner_runs_the_effect_denial_gate_and_the_merge_gate_requires_it() {
    const GATE: &str = "cargo clippy --all-targets --all-features -- -D warnings";
    let workflow = fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml");

    // YAML comments run from an unquoted `#` to end of line, and the job this
    // test is about carries a comment that names the denial command and the
    // finding in prose. A census that reads prose is `PR4-CENSUS-COMMENT-ORACLE`,
    // so the strip comes first and is itself asserted to have bitten.
    let code: String = workflow
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.len() < workflow.len(),
        "the comment strip removed nothing, so this census is reading prose"
    );
    assert!(
        !code.contains("PR5-CONF-014"),
        "the control: the workflow's comments name that finding and the strip must \
         have removed it"
    );

    // Job blocks, by their own two-space top-level keys under `jobs:`.
    let body = code.split_once("\njobs:\n").expect("a `jobs:` mapping").1;
    let mut jobs: Vec<(String, String)> = Vec::new();
    for line in body.lines() {
        let named = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' '))
            .and_then(|rest| rest.strip_suffix(':'))
            .filter(|name| {
                !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '-')
            });
        match named {
            Some(name) => jobs.push((name.to_owned(), String::new())),
            None => {
                if let Some(current) = jobs.last_mut() {
                    current.1.push_str(line);
                    current.1.push('\n');
                }
            }
        }
    }
    assert!(
        jobs.len() >= 4,
        "only {} job(s) parsed out of ci.yml; the splitter is reading the wrong shape",
        jobs.len()
    );

    // By the runner, never by the job's name: what discharges the clause is the
    // platform that compiles the `#[cfg(windows)]` bodies, and a name is a label.
    let windows_gates: Vec<&str> = jobs
        .iter()
        .filter(|(_, block)| block.contains(GATE) && block.contains("windows-latest"))
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        windows_gates.len(),
        1,
        "expected exactly one job running `{GATE}` on a Windows runner, found {windows_gates:?}. \
         Without it every `#[cfg(windows)]` body in the crate is outside the denylist's reach \
         on every job CI runs (PR5-CONF-014)."
    );
    let gate_job = windows_gates[0];

    let merge = jobs
        .iter()
        .find(|(name, _)| name == "merge-gate")
        .map(|(_, block)| block.as_str())
        .expect("the merge-gate job");
    let needs = merge
        .lines()
        .find(|line| line.trim_start().starts_with("needs:"))
        .expect("merge-gate declares its dependencies");
    assert!(
        needs.contains(gate_job),
        "`merge-gate` does not depend on `{gate_job}`, so branch protection would settle \
         green while the Windows denial gate failed: {needs}"
    );

    // `needs` alone is not enough: the aggregate's own loop decides which
    // results are *required*, and a job listed but not looped over may fail
    // freely. The loop names gates in the shape its env vars use.
    let looped = gate_job.to_uppercase().replace('-', "_");
    assert!(
        merge.contains(&format!("{looped}_RESULT:")),
        "`merge-gate` does not read `{gate_job}`'s result into `{looped}_RESULT`"
    );
    let requires = merge
        .lines()
        .find(|line| line.contains("for gate in "))
        .expect("merge-gate's required-gate loop");
    assert!(
        requires.split_whitespace().any(|word| word == looped),
        "`merge-gate`'s required-gate loop does not name `{looped}`, so `{gate_job}` \
         can fail without failing the aggregate: {requires}"
    );
}

/// The crate's own rlib and the directory its dependencies are in.
///
/// The test binary lives beside them, so both are found from `current_exe`
/// rather than from a guessed target directory — `CARGO_TARGET_DIR` here is the
/// build wrapper's slot, not `target/`. The idiom is lane C's, from
/// `src/events/log/tests.rs`.
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

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tactus-effects-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

// ---------------------------------------------------------------------------
// (3) Wrapper classification
// ---------------------------------------------------------------------------

/// Every externally reachable `fn` of a legacy or shared module is classified.
///
/// The domain is **derived from the modules**, not listed: a `pub fn` added to
/// one of them fails this test until somebody decides what it is. That is the
/// only half of `mechanism` (3) a test can hold — the classification itself is
/// a review — and it is the half that omission attacks.
#[test]
fn every_externally_reachable_fn_of_a_legacy_or_shared_module_is_classified() {
    let record = wrappers();
    let recorded: BTreeMap<&str, &ModuleClassification> = record
        .module
        .iter()
        .map(|module| (module.path.as_str(), module))
        .collect();
    assert_eq!(
        recorded.len(),
        record.module.len(),
        "a module is recorded twice"
    );
    assert_eq!(
        recorded.keys().copied().collect::<BTreeSet<_>>(),
        CLASSIFIED_MODULES.iter().copied().collect::<BTreeSet<_>>(),
        "the record and CLASSIFIED_MODULES disagree about the domain"
    );

    let mut total = 0;
    let mut disagreements: Vec<String> = Vec::new();
    for path in CLASSIFIED_MODULES {
        let source = fs::read_to_string(repo_root().join(path))
            .unwrap_or_else(|_| panic!("{path} is in CLASSIFIED_MODULES and not in the tree"));
        let derived: BTreeSet<String> = externally_reachable_fns(&source).into_iter().collect();
        let module = recorded[path];
        // A row may carry its receiver (`Workspace::branch_exists`) so the
        // denied path can name it; the domain is over bare fn names.
        let classified: Vec<&str> = module
            .funnel
            .iter()
            .chain(&module.effectful)
            .chain(&module.effectful_unnameable)
            .chain(&module.effect_free)
            .map(|name| name.rsplit("::").next().expect("a name"))
            .collect();
        let unique: BTreeSet<&str> = classified.iter().copied().collect();
        assert_eq!(
            unique.len(),
            classified.len(),
            "{path}: a name is in two classes"
        );
        let derived_refs: BTreeSet<&str> = derived.iter().map(String::as_str).collect();
        if unique != derived_refs {
            disagreements.push(format!(
                "{path}\n    unclassified: {:?}\n    invented:     {:?}",
                derived_refs.difference(&unique).collect::<Vec<_>>(),
                unique.difference(&derived_refs).collect::<Vec<_>>()
            ));
        }
        total += derived.len();
    }
    assert!(
        disagreements.is_empty(),
        "the classification and the modules disagree:\n{}",
        disagreements.join("\n")
    );
    assert!(
        total > 300,
        "only {total} functions were classified; the derivation is finding nothing"
    );
}

/// "effectful wrappers are added to the disallowed list themselves".
#[test]
fn every_effectful_wrapper_is_on_the_disallowed_list() {
    let record = wrappers();
    let denied = denylist()
        .paths()
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<BTreeSet<String>>();
    let mut named = 0;
    for module in &record.module {
        if module.effectful.is_empty() {
            continue;
        }
        assert!(
            !module.crate_path.is_empty(),
            "{} records effectful wrappers and no crate path to name them by; an \
             unreachable module's wrappers belong in `effectful_unnameable`",
            module.path
        );
        for name in &module.effectful {
            // `Type::method` is recorded as written, so an inherent method keeps
            // its receiver in the path clippy has to resolve.
            let path = format!("{}::{name}", module.crate_path);
            assert!(
                denied.contains(&path),
                "{} classifies `{name}` effectful and `{path}` is not in {CLIPPY_TOML}",
                module.path
            );
            named += 1;
        }
    }
    assert!(named >= 10, "only {named} wrappers were checked");

    // The other direction: every crate-internal denial is a row somebody
    // classified. A `tactus::…` entry nobody classified is a denial with no
    // review behind it.
    let classified: BTreeSet<String> = record
        .module
        .iter()
        .flat_map(|module| {
            module
                .effectful
                .iter()
                .map(move |name| format!("{}::{name}", module.crate_path))
        })
        .collect();
    for entry in denylist().all() {
        if !entry.path.starts_with("tactus::") {
            continue;
        }
        assert!(
            classified.contains(&entry.path),
            "{CLIPPY_TOML} denies `{}` and no module classifies it effectful",
            entry.path
        );
    }
}

/// A row classified `funnel` really does name a site.
#[test]
fn every_funnel_classified_fn_names_a_site() {
    let record = wrappers();
    let mut checked = 0;
    for module in &record.module {
        if module.funnel.is_empty() {
            continue;
        }
        let source = fs::read_to_string(repo_root().join(&module.path)).expect("read module");
        let production = blank_comments_and_strings(&production_region(&source));
        assert!(
            production.contains("EffectSiteId") || production.contains("Site"),
            "{} classifies funnels and never names a site",
            module.path
        );
        for name in &module.funnel {
            let bare = name.rsplit("::").next().expect("a name");
            assert!(
                production.contains(&format!("fn {bare}")),
                "{} classifies `{name}` a funnel and declares no such fn",
                module.path
            );
            // A funnel is not a wrapper: it must not also be denied.
            let path = format!("{}::{name}", module.crate_path);
            assert!(
                !denylist().paths().contains(path.as_str()),
                "`{path}` is classified a funnel and is also denied"
            );
            checked += 1;
        }
    }
    assert!(checked >= 15, "only {checked} funnels were checked");
}

/// Every `libc::` item the tree names is classified effect or not-an-effect, and
/// every one classified an effect is denied.
///
/// `claim_scope` makes exhaustiveness "the disallowed list is complete for the
/// **primitives the crate uses**", so the list is derived from the tree rather
/// than transcribed from the sentence's `fork/kill/setpgid/setsid/flock/fcntl/
/// exec*` — which is six names out of the twenty-four this crate actually calls.
#[test]
fn every_libc_item_the_tree_names_is_classified_and_the_effects_are_denied() {
    let record = wrappers();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for (_, source) in scanned_sources() {
        let text = blank_comments_and_strings(&source);
        let mut at = 0;
        while let Some(hit) = text[at..].find("libc::") {
            let start = at + hit + "libc::".len();
            let item: String = text[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            at = start.max(at + 1);
            if !item.is_empty() {
                used.insert(item);
            }
        }
    }
    assert!(used.len() > 60, "only {} libc items found", used.len());

    let classified: BTreeSet<&str> = record
        .libc
        .effect
        .iter()
        .chain(&record.libc.not_an_effect)
        .map(String::as_str)
        .collect();
    let unclassified: Vec<&String> = used
        .iter()
        .filter(|item| !classified.contains(item.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these `libc::` items are used and unclassified: {unclassified:?}"
    );
    let overlap: Vec<&String> = record
        .libc
        .effect
        .iter()
        .filter(|item| record.libc.not_an_effect.contains(item))
        .collect();
    assert!(overlap.is_empty(), "classified both ways: {overlap:?}");

    let denied_toml = denylist();
    let denied = denied_toml.paths();
    for item in &record.libc.effect {
        let path = format!("libc::{item}");
        assert!(
            denied.contains(path.as_str()),
            "`{path}` is classified an effect and is not denied"
        );
    }
    // The other direction, or a reclassification would be free: moving an item
    // from `effect` to `not_an_effect` would leave its denial in place with
    // nothing behind it, and the first assertion could not tell.
    let effects: BTreeSet<&str> = record.libc.effect.iter().map(String::as_str).collect();
    for path in &denied {
        let Some(item) = path.strip_prefix("libc::") else {
            continue;
        };
        assert!(
            effects.contains(item),
            "{CLIPPY_TOML} denies `{path}` and {WRAPPERS_TOML} does not classify \
             `{item}` an effect"
        );
    }
}

// ---------------------------------------------------------------------------
// `outputs` — the generated inventories
// ---------------------------------------------------------------------------

/// A generated artifact's content, with the line discipline the checkout gave it
/// taken out of the comparison.
///
/// **Measured, not anticipated.** The first three Windows guest runs failed both
/// artifact tests and nothing else: the guest's `core.autocrlf` checks these
/// files out with `\r\n`, and `serde_json::to_string_pretty` emits `\n`, so the
/// byte comparison was asserting the checkout's line endings rather than the
/// document's content. `test (windows-latest)` in CI would have failed the same
/// way. The claim these tests make is that the *inventory* is what the enums
/// generate; the separator between its lines is the filesystem's business.
fn artifact_content(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// `outputs`: "effect_sites.json (from the enums) … generated from the enums by
/// a test and attached to gate reports".
#[test]
fn the_checked_in_effect_sites_json_is_what_the_enums_generate() {
    let generated = format!(
        "{}\n",
        effect_sites_json().expect("the inventory serializes")
    );
    let path = repo_root().join(EFFECT_SITES_JSON);
    if std::env::var_os(REGENERATE).is_some() {
        fs::write(&path, &generated).expect("write the inventory");
    }
    let on_disk = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{EFFECT_SITES_JSON} is missing; run with {REGENERATE}=1"));
    let on_disk = artifact_content(&on_disk);
    assert_eq!(
        on_disk, generated,
        "{EFFECT_SITES_JSON} is stale; regenerate with {REGENERATE}=1"
    );
    // It really is the whole inventory, not a corner of it.
    assert_eq!(effect_sites().len(), EffectSiteId::all().len());
    assert!(on_disk.contains("\"site\": \"Event.OpenLog\""));
    assert!(on_disk.contains("\"site\": \"Object.CandidateCommitTree\""));
}

/// The companion artifact states where the funnel bodies actually are
/// (`PR5-CONF-018`).
///
/// `effect_sites.json` ships `"module": "src/interaction.rs"` for
/// `Answer.Ingest`, `Answer.PublishRename` and `Answer.StageWrite`, and the
/// `AnswerSite::` literals are at `src/rundir.rs:899`, `:912` and `:934` and
/// nowhere else. Until this round the only thing reconciling the artifact with
/// the tree was a **test-side override** — [`funnel_module`] — so the artifact a
/// gate report carries said something false about this tree and nothing checked
/// in said otherwise. Measured: deleting that override makes the three Answer
/// sites join the "no funnel names them" set, which is the finding.
///
/// The two axes are the *inventory's claim* and the *tree's answer*. Every
/// existing test holds one constant and reads the other — the census searches
/// the file the override names, the artifact test compares the file the enums
/// name — so the pair was never written down together. Here they are written
/// down together, for every site rather than for the three that disagree, so a
/// fourth disagreement appearing later is a change to this file rather than a
/// silence.
#[test]
fn the_checked_in_funnel_module_record_states_where_the_bodies_are() {
    let generated = funnel_module_record();
    let path = repo_root().join(FUNNEL_MODULES_JSON);
    if std::env::var_os(REGENERATE).is_some() {
        fs::write(&path, &generated).expect("write the funnel-module record");
    }
    let on_disk =
        artifact_content(&fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!("{FUNNEL_MODULES_JSON} is missing; run with {REGENERATE}=1")
        }));
    assert_eq!(
        on_disk, generated,
        "{FUNNEL_MODULES_JSON} is stale; regenerate with {REGENERATE}=1"
    );

    let parsed: serde_json::Value = serde_json::from_str(&on_disk).expect("the record parses");
    assert_eq!(
        parsed["sites_checked"].as_u64().expect("a count"),
        EffectSiteId::all().len() as u64,
        "the record must cover the whole inventory; a record over a corner of it          would report agreement it never looked for"
    );
    let disagreements: Vec<&str> = parsed["disagreements"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|entry| entry["site"].as_str().expect("a site name"))
        .collect();
    assert_eq!(
        disagreements,
        // In `EffectSiteId::all()` order, which is the frozen enum's, so a site
        // moving within the inventory is a change here too.
        ["Answer.StageWrite", "Answer.PublishRename", "Answer.Ingest"],
        "the set of sites whose funnel bodies are not where the inventory says          moved. Each one is a claim a gate report carries about this tree."
    );
    for entry in parsed["disagreements"].as_array().expect("an array") {
        assert_eq!(entry["inventory_module"], "src/interaction.rs");
        assert_eq!(entry["funnel_module"], "src/rundir.rs");
    }
}

/// The companion record, from the enums and from [`funnel_module`].
fn funnel_module_record() -> String {
    let mut disagreements = Vec::new();
    for site in EffectSiteId::all() {
        let inventory = site.module();
        let actual = funnel_module(site);
        if inventory != actual {
            disagreements.push(serde_json::json!({
                "site": site.name(),
                "group": site.group().name(),
                "inventory_module": inventory,
                "funnel_module": actual,
            }));
        }
    }
    format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::json!({
            "note": "PR5-CONF-018. effect_sites.json's `module` column is \
                     EffectSiteId::module(), which is PR3's frozen answer and the \
                     packet's -- mechanism (2) places the answer funnels in \
                     src/interaction.rs. PR5 lane B put those three funnel BODIES in \
                     src/rundir.rs and left interaction::{write_question, write_answer, \
                     read_answer} as delegations. Both files are allowlisted funnel \
                     modules and enforcement is unchanged either way, so Fable ruled \
                     this a preference and Sol a low defect; what is not a matter of \
                     taste is that a gate-attached artifact stated something untrue of \
                     this tree with nothing checked in saying otherwise. The generator \
                     is src/topology/effects.rs, frozen, so the column is corrected \
                     here rather than in place, and the funnel bodies are NOT moved.",
            "sites_checked": EffectSiteId::all().len(),
            "disagreements": disagreements,
        }))
        .expect("the funnel-module record serializes")
    )
}

/// Every module the inventory names is in the funnel section, and every site has
/// a funnel that names it — or is recorded absent with the reason.
///
/// This is where an omission would live. `effect_sites.json` is generated from
/// the enums so it cannot omit a *site*; what it can do is name a module that
/// implements none of them, which reads identically to a module that implements
/// all of them.
#[test]
fn every_site_the_inventory_declares_has_a_funnel_that_names_it_or_is_recorded_absent() {
    let list = allowlist();
    let funnel: BTreeMap<&str, &AllowlistEntry> = list
        .funnel
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    let mut modules: BTreeSet<String> = BTreeSet::new();
    for site in EffectSiteId::all() {
        modules.insert(site.module().to_owned());
    }
    assert_eq!(modules.len(), 7, "{modules:?}");
    for module in &modules {
        assert!(
            funnel.contains_key(module.as_str()),
            "`{module}` is a funnel module the inventory names and the allowlist's \
             funnel section does not list it"
        );
    }

    // Per site: does a funnel name it?
    //
    // Two mechanisms, because the three lanes built two and a grid that knew
    // one would report the other's whole group as unimplemented:
    //
    //   * the variant literal — `RunDirSite::PublishMarker` inside the funnel
    //     body, which is lane B's shape (one `pub fn` per site, site fixed);
    //   * the site as a **parameter** — `fn create_ref_zero_old(site: RefSite,
    //     …)`, which is lane A's and lane C's, and is the shape `identity`
    //     literally describes ("every effectful funnel API takes its group's
    //     site by value").
    //
    // Recorded per group by `funnel_mechanism` so a group that stopped doing
    // either is loud rather than silently "still covered by the other".
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut unimplemented = Vec::new();
    let mut mechanisms: BTreeMap<&str, &str> = BTreeMap::new();
    for site in EffectSiteId::all() {
        let group = site.group().name();
        let module = funnel_module(site);
        let entry = funnel[module];
        if entry.absent {
            unimplemented.push(site.name());
            continue;
        }
        let source = sources.entry(module.to_owned()).or_insert_with(|| {
            let text = fs::read_to_string(repo_root().join(module)).expect("read funnel module");
            blank_comments_and_strings(&production_region(&text))
        });
        let variant = format!("{group}Site::{}", site.variant());
        let parameter = format!(": {group}Site");
        if source.contains(&variant) {
            mechanisms.insert(group, "variant");
        } else if source.contains(&parameter) {
            mechanisms.insert(group, "parameter");
        } else {
            unimplemented.push(site.name());
        }
    }
    // Both mechanisms are in use. If one disappeared, every group would have to
    // be re-measured against the other rather than inheriting a pass.
    let distinct: BTreeSet<&str> = mechanisms.values().copied().collect();
    assert_eq!(distinct.len(), 2, "{mechanisms:?}");

    // The expected set, written out rather than counted, because *which* sites
    // have no funnel is the finding and a count would hide a swap.
    let expected: BTreeSet<String> = SITES_WITHOUT_A_FUNNEL
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let actual: BTreeSet<String> = unimplemented.into_iter().collect();
    assert_eq!(
        actual, expected,
        "the set of sites no funnel names moved. Each one is a row of the site \
         inventory in reconciliation-D.md and needs a reason."
    );
}

/// The module a group's funnel bodies are actually in.
///
/// `FunnelGroup::module()` is PR3's answer and is frozen. For one group it is
/// not where PR5 put the code: `mechanism` (2) places "the answer funnels in
/// src/interaction.rs", and lane B put the bodies in `src/rundir.rs`, leaving
/// `interaction::{write_question, write_answer, read_answer}` as thin
/// delegations. Both files are in the allowlist's funnel section and the
/// disagreement is section J of `reconciliation-D.md`; it is recorded here
/// rather than resolved by silence, because silently searching the right file
/// would make the inventory's `module` column read as correct.
fn funnel_module(site: EffectSiteId) -> &'static str {
    match site.group().name() {
        "Answer" => "src/rundir.rs",
        _ => site.module(),
    }
}

/// The sites the frozen inventory declares that no funnel in this tree names.
///
/// Every one is a row in `reconciliation-D.md`'s site inventory with the packet
/// key that defers it. They are written out rather than counted because *which*
/// site is missing is the finding: a count would survive a swap.
const SITES_WITHOUT_A_FUNNEL: &[&str] = &[
    // The **Container group is no longer here.** PR5 recorded all eight as
    // unimplemented because `FunnelGroup::Container.module()` names
    // `src/runner/container.rs` and that file was not in the tree; PR6 adds it,
    // and every one of the eight is taken by value by an API in it. The group
    // leaving this list is the finding that PR6 landed, and a variant coming
    // back would mean a funnel stopped naming its site.
    //
    // `ReportSite::Write` maps to `src/util.rs`, and the report write this slice
    // ships is `RunDir.WriteReport` in `src/rundir.rs` (`rundir::write_report`,
    // which calls `util::write_json`). `PR3-REPORT-DOUBLE-NAME` in
    // `reviews/FINDINGS.md` is the standing entry for the two names on one file
    // and is the owner's, not this slice's.
    "Report.Write",
    // The Process group. `identity` says "every effectful funnel API takes its
    // group's site by value", and PR4's process funnel does not: `HostRunner`
    // threads a `SpawnHooks` observer and consults the containment sub-effect
    // points by name, while `ProcessSite` is named in production nowhere. The
    // hooks fire and PR4's grids drive them, so this is a *shape* gap and not a
    // coverage one — filed as `PR5D-PROCESS-FUNNEL-TAKES-NO-SITE` in
    // `reviews/FINDINGS.md` with `src/runner/**` frozen under the owner ruling.
    "Process.Spawn",
    "Process.Terminate",
];

/// `outputs`: "the residue-class evidence record (per element: constructed,
/// classified, recovered; per site: sampling N and observed-class histogram)".
#[test]
fn the_checked_in_residue_class_record_is_what_the_enums_generate() {
    let generated = residue_record();
    let path = repo_root().join(RESIDUE_CLASSES_JSON);
    if std::env::var_os(REGENERATE).is_some() {
        fs::write(&path, &generated).expect("write the residue record");
    }
    let on_disk = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{RESIDUE_CLASSES_JSON} is missing; run with {REGENERATE}=1"));
    let on_disk = artifact_content(&on_disk);
    assert_eq!(
        on_disk, generated,
        "{RESIDUE_CLASSES_JSON} is stale; regenerate with {REGENERATE}=1"
    );

    // The sampling N the record freezes is the N the harness runs.
    // `command_internal_sub_effects` says "N frozen per site in the registry";
    // `src/topology/registry.rs` is PR3's and frozen, and carries no N, so the
    // record carries it and this is the cross-check that keeps the two equal.
    let harness = fs::read_to_string(repo_root().join("src/workspace_manager.rs"))
        .expect("src/workspace_manager.rs");
    assert!(
        harness.contains(&format!("const SAMPLING_N: u32 = {SAMPLING_N};")),
        "the sampling harness no longer runs N = {SAMPLING_N}"
    );
    assert!(on_disk.contains(&format!("\"sampling_n\": {SAMPLING_N}")));
}

/// The durability barrier is reached through **one** call each, and the syscall
/// is inside it (`PR5-CONF-012`).
///
/// `proof_tests[9]` makes the durability ledger a *named proof*: "the sync
/// ledger shows the synced length equal to the file length after open". The
/// ledger entry is written beside the syscall by the same function, so it
/// certifies itself: `let outcome = file.sync_all();` → `let outcome:
/// io::Result<()> = Ok(());` survived the whole suite, with the fsync gone and
/// every trace assertion still green. `sync_file_recorded`'s own doc conceded
/// the residual in as many words, and the same shape held in
/// `src/workspace_manager.rs` and for the Event sync records.
///
/// Nothing on a machine that does not lose power can see *inside* `fsync`. What
/// can be seen is two things either side of it, and the repair is to make both
/// checkable rather than one:
///
/// * **the syscall is there** — this census, which reads the source and fails if
///   the call leaves the one function that is allowed to make it;
/// * **the seam was reached as often as the ledger claims** —
///   `rundir::tests::the_durability_ledger_counts_barriers_that_were_actually_
///   performed`, which crosses the ledger's entries against
///   `util::barriers_performed()`.
///
/// Neither alone is enough, and that is the point: a census cannot tell whether
/// the line ran, and a counter cannot tell whether the line still contains the
/// syscall.
///
/// `src/events/log/premove.rs` is excluded by name. It is `git show
/// ff0490a:src/events.rs` kept verbatim as the independent oracle for
/// byte-identical legacy behaviour, and its whole value is that it is unchanged.
#[test]
fn every_file_durability_barrier_in_a_funnel_module_goes_through_one_call() {
    // The two functions that may name the primitive, and how many times each.
    const BARRIERS: &[(&str, &str, usize)] = &[
        ("src/util.rs", "fsync_file", 1),
        ("src/util.rs", "fsync_dir", 1),
    ];
    // Line endings normalized before any structural search: the guest checks this
    // tree out with CRLF, and `find("\n}\n")` does not match `\r\n}\r\n`. Measured —
    // this census passed on Linux and panicked "the function ends" on Windows
    // Server 2025, which is the platform half of the same lesson the rest of this
    // round is about. `artifact_content` exists for exactly this reason.
    let util = artifact_content(
        &fs::read_to_string(repo_root().join("src/util.rs")).expect("src/util.rs"),
    );
    for (file, function, expected) in BARRIERS {
        let body = util
            .split_once(&format!("fn {function}("))
            .unwrap_or_else(|| panic!("{file} no longer defines `{function}`"))
            .1;
        let body = &body[..body.find("\n}\n").expect("the function ends")];
        let calls = body.matches(".sync_all()").count();
        assert_eq!(
            calls, *expected,
            "`{function}` makes {calls} durability syscall(s), not {expected}; deleting \
             the barrier from inside it is exactly PR5-CONF-012's surviving mutation"
        );
    }

    // And nowhere else in the funnel modules, so a caller cannot quietly grow a
    // second barrier the counter and this census both miss.
    const FUNNELS: &[&str] = &[
        "src/rundir.rs",
        "src/workspace_manager.rs",
        "src/events/log.rs",
        // PR6's Container funnel writes the intent record durably and reaches
        // the barrier through `util::fsync_file`/`util::fsync_dir` like every
        // other funnel, so it belongs in the "and nowhere else" half.
        "src/runner/container.rs",
    ];
    for path in FUNNELS {
        let source =
            fs::read_to_string(repo_root().join(path)).unwrap_or_else(|_| panic!("{path}"));
        let production = blank_comments_and_strings(&production_region(&source));
        assert_eq!(
            production.matches(".sync_all()").count(),
            0,
            "{path} calls `sync_all` directly; the file barrier is `util::fsync_file` \
             and the directory barrier is `util::fsync_dir`"
        );
    }

    // The Event funnel's own primitive is `sync_data`, a different call with its
    // own census next door, and it is named here so this test's silence about it
    // is a decision rather than an oversight.
    let log = fs::read_to_string(repo_root().join("src/events/log.rs")).expect("src/events/log.rs");
    assert_eq!(
        blank_comments_and_strings(&production_region(&log))
            .matches(".sync_data()")
            .count(),
        1,
        "the log's own barrier is one `sync_data`; \
         `events::log::tests::the_event_log_is_written_in_exactly_one_module` \
         is the census that owns it"
    );
}

/// The sampling N `effects/residue-classes.json` freezes.
const SAMPLING_N: u32 = 8;

fn residue_record() -> String {
    let mut sites = Vec::new();
    for site in EffectSiteId::all() {
        if site.residue_classes().is_empty() {
            continue;
        }
        sites.push(serde_json::json!({
            "site": site.name(),
            "group": site.group().name(),
            "row": site.row(),
            "module": site.module(),
            "sampling_n": SAMPLING_N,
            "classes": site
                .residue_classes()
                .iter()
                .map(|class| serde_json::json!({
                    "class": class,
                    "label": class.label(),
                    "classified_as": class.classified_as(),
                }))
                .collect::<Vec<_>>(),
            "elements": site.residue_elements(),
        }));
    }
    format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::json!({
            "note": "decisions.effect_site_inventory.outputs: the residue-class \
                     evidence record, DECLARATIONS half. Per element: constructed, \
                     classified, recovered -- proven by workspace_manager::tests. Per \
                     site: the frozen sampling N. The observed-class histogram is \
                     machine-varying and cannot be pinned in a file compared \
                     byte-for-byte, so it is emitted to effects/residue-histogram.json \
                     on every run by \
                     sampled_git_child_kills_every_residue_classified_and_recovered, \
                     which reads it back and checks it accounts for every sample \
                     (PR5-CONF-004).",
            "sites": sites,
        }))
        .expect("the residue record serializes")
    )
}

// ---------------------------------------------------------------------------
// "no topology production callers"
// ---------------------------------------------------------------------------

/// Every site enum's `row()` is **exhaustive by construction**: no wildcard
/// arm (`PR5-EVENTS-063`, and the other half of `PR5-WORKSPACE-049`).
///
/// `expected_failures_refusals[7]` is "a site without a row mapping fails to
/// compile", and today that holds only as a *side effect* of `row()` happening
/// to be written out arm by arm. Nothing asserted the absence of a wildcard,
/// and the control measured what one costs: with `EventSite::row`'s single
/// explicit arm replaced by `_ => ResourceRow::R21`, adding an unmapped variant
/// produced ten `E0004` non-exhaustive errors and `row()` was **not** among
/// them — the wildcard had silenced exactly the diagnostic the sentence refers
/// to, and the whole suite stayed green.
///
/// A source census rather than a compile fixture because it is the *absence* of
/// a construct that has to be checked, and a fixture can only demonstrate that
/// something fails to compile today. `src/topology/effects.rs` is frozen, so
/// this scan is a guard on a file this slice does not edit rather than a
/// requirement on one it does.
#[test]
fn no_site_enums_row_mapping_has_a_wildcard_arm() {
    let source = std::fs::read_to_string("src/topology/effects.rs").expect("the frozen inventory");
    let production = blank_comments_and_strings(&production_region(&source));
    let mut scanned = 0_usize;
    let mut offenders = Vec::new();
    let mut rest = production.as_str();
    while let Some(at) = rest.find("fn row(") {
        rest = &rest[at + "fn row(".len()..];
        // The body runs to the closing brace of the `match`, which is the first
        // line at the function's own indentation that is exactly `    }`.
        let body_end = rest.find("\n    }").unwrap_or(rest.len());
        let body = &rest[..body_end];
        scanned += 1;
        for wildcard in ["_ =>", "_=>"] {
            if body.contains(wildcard) {
                offenders.push(format!(
                    "a `row()` mapping falls back through `{wildcard}`, so a site added later \
                     compiles with no declared row: …{}",
                    &body[..body.len().min(160)]
                ));
            }
        }
    }
    assert!(
        scanned >= 8,
        "only {scanned} `row()` mappings scanned, so this census is looking at the wrong file"
    );
    assert!(offenders.is_empty(), "{offenders:#?}");
}

/// `decisions.pr_sequence[6].scope` ends "no topology production callers", and
/// `non_goals[0]` is "production topology callers".
///
/// The census is over the **production region** of every topology module, and it
/// carries its own control: the test region of `src/topology/registry.rs` DOES
/// name a funnel, so a census whose region split had collapsed to the empty
/// string would fail here rather than report "nobody calls anything".
#[test]
fn no_topology_module_calls_a_funnel_in_production() {
    const FUNNELS: &[&str] = &[
        "workspace_manager::",
        "rundir::",
        "EventLog::",
        "establish_stable_prefix",
        "util::write_json",
        "util::write_text",
    ];
    let mut topology = 0;
    let mut callers = Vec::new();
    for (path, source) in scanned_sources() {
        let is_topology = TOPOLOGY_MODULES
            .iter()
            .any(|banned| path.starts_with(banned) || path == *banned);
        // `src/workspace_manager.rs` and `src/runner/**` are in
        // `TOPOLOGY_MODULES` because the legacy section may not contain them;
        // they are the funnels themselves and naturally name funnels.
        if !is_topology || !path.starts_with("src/topology/") {
            continue;
        }
        topology += 1;
        let production = blank_comments_and_strings(&production_region(&source));
        for funnel in FUNNELS {
            if production.contains(funnel) {
                callers.push(format!("{path} names `{funnel}` in production"));
            }
        }
    }
    assert!(topology >= 8, "only {topology} topology modules scanned");
    assert!(callers.is_empty(), "{callers:#?}");

    // The control.
    let registry = fs::read_to_string(repo_root().join("src/topology/registry.rs"))
        .expect("src/topology/registry.rs");
    let production = production_region(&registry);
    assert!(
        !production.contains("rundir::"),
        "the production region names a funnel"
    );
    assert!(
        registry.contains("rundir::create_public_dir"),
        "the control: the registry's TEST region builds its fixture through the \
         run-directory funnel, so a production/test split that had collapsed \
         would fail here instead of reporting silence"
    );
    assert!(
        production.len() < registry.len(),
        "the production region is the whole file, so the split did nothing"
    );
}

/// The scan's own parser, on this tree's real shapes.
///
/// `externally_reachable_fns` decides the classification domain, so a parser
/// that quietly saw half the tree would make [`every_externally_reachable_fn_of_a_legacy_or_shared_module_is_classified`]
/// pass against a domain nobody drew — the omission failure this project's
/// reconciliation table exists for, one level down.
#[test]
fn the_reachable_fn_parser_finds_each_shape_this_tree_uses() {
    let source = concat!(
        "pub fn free() {}\n",
        "pub(crate) fn crate_visible() {}\n",
        "pub(super) fn super_visible() {}\n",
        "fn private() {}\n",
        "pub const fn constant() -> u8 { 1 }\n",
        "pub unsafe fn unsafely() {}\n",
        "impl Thing { pub fn inherent(&self) {} fn hidden(&self) {} }\n",
        "impl Trait for Thing { fn through_the_trait(&self) {} }\n",
        "#[cfg(test)]\nmod tests { pub fn in_the_test_region() {} }\n",
    );
    let found = externally_reachable_fns(source);
    assert_eq!(
        found,
        vec![
            "constant".to_owned(),
            "crate_visible".to_owned(),
            "free".to_owned(),
            "inherent".to_owned(),
            "super_visible".to_owned(),
            "through_the_trait".to_owned(),
            "unsafely".to_owned(),
        ],
        "the parser's answer moved"
    );
    // Seven shapes accepted, three refused, and the three are refused for three
    // different reasons: private, private-in-an-inherent-impl, and test region.
    assert!(!found.contains(&"private".to_owned()));
    assert!(!found.contains(&"hidden".to_owned()));
    assert!(!found.contains(&"in_the_test_region".to_owned()));
}
