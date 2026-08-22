//! The compile-time enforcement layer: the effect denylist, the allowlist, the
//! wrapper classification, and the generated inventories.
//!
//! `decisions.effect_site_inventory.mechanism` is the whole of this module's
//! specification, in four numbered parts:
//!
//! 1. **The denylist is rustc-resolved, not lexical.** `clippy.toml`'s
//!    `disallowed-methods` / `disallowed-types` / `disallowed-macros` name every
//!    effect primitive the crate can reach, and "aliases, re-exports, function
//!    values, method calls, and macro-expanded code in this crate resolve to the
//!    same DefId". [`tests::every_declared_effect_denial_refuses_for_the_reason_it_declares`]
//!    compiles one fixture per shape and asserts the lint each emits, because
//!    that sentence is a claim about a toolchain and not a law of nature.
//! 2. **An allow of a governed lint lives only where the allowlist says.**
//!    Module-level, in a file listed in `effects/allowlist.toml`, whose legacy
//!    section is frozen, may only shrink, and never contains a topology module.
//! 3. **Wrapper classification.** Every externally reachable `fn` of a legacy or
//!    shared module is classified; the effectful ones join the denylist, "so a
//!    topology module cannot reach an effect through a legacy wrapper".
//! 4. **Dependency review** — a new dependency performing filesystem, process,
//!    lock or container effects has its API added to the denylist or is confined
//!    to a funnel module.
//!
//! # This module performs no effect
//!
//! Everything above the `#[cfg(test)]` line is a pure function over `&str`: the
//! parsers, the classifiers, the frozen lists. Reading `clippy.toml`, writing
//! `effect_sites.json` and compiling fixtures all happen in the test region,
//! which is where `outputs` puts them anyway ("effect_sites.json (from the
//! enums) … generated from the enums **by a test**"). That is why this file is
//! in the funnel section of the allowlist while claiming something stronger than
//! any other entry there.
//!
//! # The reading trap
//!
//! Every sentence quoted here is from `decisions.*`. `*_verification_dispositions`,
//! `finding_dispositions[].rationale` and the `v4_`..`v15_` keys are the packet's
//! disposition history and are quoted nowhere.

// Allowlist placement: the **funnel section** of `effects/allowlist.toml`, and
// the entry there records `allows = []`. This module carries no attribute at
// all, which is the strongest form of the claim above: it reaches no denied
// primitive, and the one `std::process::Command` its text contains is inside
// `DENIAL_FIXTURES`, a string constant compiled elsewhere in order to be
// refused. `decisions.effect_site_inventory.mechanism` (2).

use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// The artifacts, by the names `outputs` gives them
// ---------------------------------------------------------------------------

/// `effect_site_inventory.outputs`: "clippy.toml".
pub const CLIPPY_TOML: &str = "clippy.toml";

/// `effect_site_inventory.outputs`: "effects/allowlist.toml".
pub const ALLOWLIST_TOML: &str = "effects/allowlist.toml";

/// `effect_site_inventory.outputs`: "the wrapper classification".
pub const WRAPPERS_TOML: &str = "effects/wrappers.toml";

/// `effect_site_inventory.outputs`: "effect_sites.json (from the enums)".
pub const EFFECT_SITES_JSON: &str = "effect_sites.json";

/// `effect_site_inventory.outputs`: "the residue-class evidence record (per
/// element: constructed, classified, recovered; per site: sampling N and
/// observed-class histogram)".
///
/// The *declarations* half. The histogram half is [`RESIDUE_HISTOGRAM_JSON`],
/// and the split is forced rather than chosen — see there.
pub const RESIDUE_CLASSES_JSON: &str = "effects/residue-classes.json";

/// The **observed-class histogram** half of the same record (`PR5-CONF-004`).
///
/// `outputs` requires, per site, "sampling N **and observed-class histogram**".
/// [`RESIDUE_CLASSES_JSON`] is generated from the frozen enums and compared
/// byte-for-byte, which it must be — and a histogram is machine-varying by
/// construction, since which class a kill sample lands in is a race between the
/// kill and Git. A count cannot be byte-pinned and a byte-pinned file cannot
/// carry one, so the histogram is emitted to this path on every run of
/// `workspace_manager::tests::sampled_git_child_kills_every_residue_classified_
/// and_recovered`, which then reads it back. Not checked in: its contents are a
/// property of the machine that produced them, and a stale copy of somebody
/// else's numbers would be worse than no copy.
pub const RESIDUE_HISTOGRAM_JSON: &str = "effects/residue-histogram.json";

/// Where each site's funnel **bodies** actually are, where that is not what
/// [`EFFECT_SITES_JSON`]'s `module` column says (`PR5-CONF-018`).
///
/// `effect_sites.json` is generated from the frozen enums, so its `module`
/// column is `EffectSiteId::module()` — PR3's answer, and the packet's:
/// `mechanism` (2) places "the answer funnels in `src/interaction.rs`". PR5's
/// lane B put the three Answer funnel bodies in `src/rundir.rs` and left
/// `interaction::{write_question, write_answer, read_answer}` as delegations,
/// so for `Answer.Ingest`, `Answer.PublishRename` and `Answer.StageWrite` the
/// checked-in artifact states something that is not true of this tree — and the
/// artifact is attached to gate reports, where a reader has no way to know.
///
/// The generator is `src/topology/effects.rs`, frozen under the owner ruling of
/// 2026-08-20, so the column cannot be corrected in place and the bodies are not
/// moved: `AnswerSite`'s three funnels close over `rundir`'s private `funnel`
/// and `RunDirHooks`, and relocating them to satisfy a column would be a slice
/// redesigning what it implements. What ships instead is this companion, which
/// carries the tree's own answer beside the inventory's for **every** site, so
/// the pair is true where either alone is not. Derived, compared byte-for-byte,
/// and regenerated by the same `REGENERATE` switch, so it cannot drift.
pub const FUNNEL_MODULES_JSON: &str = "effects/funnel-modules.json";

/// The environment variable that turns the generating tests into writers.
///
/// A generated artifact that is only ever *compared* rots into a chore nobody
/// can discharge; one that is only ever *written* proves nothing. Both, keyed on
/// this, is the ordinary resolution.
pub const REGENERATE: &str = "TACTUS_REGENERATE_EFFECT_ARTIFACTS";

// ---------------------------------------------------------------------------
// (2) The governed lints and where an allow of one may live
// ---------------------------------------------------------------------------

/// The six lints `mechanism` (2) governs, as bare names.
///
/// > "permits allow/expect of disallowed_methods, disallowed_types,
/// > disallowed_macros, clippy::style, clippy::all, or warnings only as
/// > module-level attributes in files listed in effects/allowlist.toml"
///
/// Bare, because an attribute may write either `disallowed_methods` or
/// `clippy::disallowed_methods` and the sentence names them both ways in one
/// breath. [`normalize_lint`] is the bridge.
pub const GOVERNED_LINTS: &[&str] = &[
    "disallowed_methods",
    "disallowed_types",
    "disallowed_macros",
    "style",
    "all",
    "warnings",
];

/// The three governed lints this slice actually uses, fully qualified.
///
/// `clippy::style`, `clippy::all` and `warnings` are governed and **unused**:
/// each would suppress far more than an effect denial, and
/// [`tests::the_three_blunt_governed_lints_are_used_by_nobody`] asserts the
/// count is zero rather than leaving it to habit.
pub const USED_GOVERNED_LINTS: &[&str] = &[
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
    "clippy::disallowed_macros",
];

/// The bare lint name an attribute entry refers to, if it is governed.
///
/// `clippy::disallowed_methods` and `disallowed_methods` are the same lint;
/// `clippy::too_many_arguments` is not governed and answers `None`.
#[must_use]
pub fn normalize_lint(entry: &str) -> Option<&'static str> {
    let bare = entry.trim().rsplit("::").next()?.trim();
    GOVERNED_LINTS.iter().copied().find(|name| *name == bare)
}

/// One `allow`/`expect` of a governed lint, as the scan found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedAllow {
    /// 1-based line of the attribute's `#`.
    pub line: usize,
    /// Whether it is an inner attribute (`#![…]`).
    pub inner: bool,
    /// Whether it is module-level: an inner attribute in the file's prologue, or
    /// an outer attribute on a `mod` item.
    pub module_level: bool,
    /// The governed lints it names, normalized, in source order.
    pub lints: Vec<String>,
    /// Every lint it names, as written — so a widening is visible.
    pub written: Vec<String>,
}

/// `source` with every comment and string literal replaced by spaces of the same
/// length, newlines preserved.
///
/// The scan has to be blind to text that only *looks* like an attribute.
/// `PR4-CENSUS-COMMENT-ORACLE` is in the standing ledger because a source census
/// counted a doc comment; this module is worse placed than most, since its own
/// build-refusal fixtures are `#[allow(clippy::disallowed_methods)]` written
/// inside doc comments and string literals. Blanking rather than deleting keeps
/// every byte offset — and therefore every line number — exact.
///
/// Raw strings (`r"…"`, `r#"…"#`), byte strings, char literals and escapes are
/// handled; a `'a` lifetime is not a char literal and is left alone.
/// Comments blanked, **string literals kept**.
///
/// The other half of [`blank_comments_and_strings`], and a separate function
/// because a census whose needle lives *inside* a string cannot use that one:
/// it blanks a literal including its quotes, so a search for `"docker` in its
/// output looks for a byte sequence the haystack can no longer contain. That is
/// not hypothetical — it is what the `mechanism` (1) "docker invocation
/// helpers" census did until PR6, which is why it stayed green when a real
/// `const DOCKER_PROGRAM: &str = "docker"` landed in production.
///
/// **One implementation, one caller shape.** `PR5D-VISIBILITY-CHECK-DUPLICATED`
/// is the standing entry for a parser written twice in this tree, so this lives
/// here beside its sibling rather than in each census that wants it.
///
/// Line comments, block comments (nested) and escapes are handled. **Raw
/// strings are not modelled**: a `//` inside `r"…"` would truncate the rest of
/// that line. The failure mode is therefore a needle this function does *not*
/// find, which makes a census that uses it report something missing — loud —
/// rather than accept something extra. Byte offsets are not preserved; line
/// breaks are.
#[must_use]
pub fn blank_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                let mut depth = 1usize;
                let mut previous = ' ';
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                    }
                    if previous == '/' && next == '*' {
                        depth += 1;
                        previous = ' ';
                        continue;
                    }
                    if previous == '*' && next == '/' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        previous = ' ';
                        continue;
                    }
                    previous = next;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn blank_comments_and_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    // Newlines survive so line numbers do.
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            out[index] = b'\n';
        }
    }
    let keep = |out: &mut Vec<u8>, from: usize, to: usize| {
        out[from..to].copy_from_slice(&bytes[from..to]);
    };

    let mut i = 0;
    let mut code_start = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                keep(&mut out, code_start, i);
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                code_start = i;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                keep(&mut out, code_start, i);
                let mut depth = 1;
                i += 2;
                while i < bytes.len() && depth > 0 {
                    if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                code_start = i;
            }
            b'r' | b'b' => {
                // `r"…"`, `r#"…"#`, `b"…"`, `br#"…"#`
                let mut j = i;
                if bytes[j] == b'b' {
                    j += 1;
                }
                let raw = j < bytes.len() && bytes[j] == b'r';
                if raw {
                    j += 1;
                }
                let hash_start = j;
                while j < bytes.len() && bytes[j] == b'#' {
                    j += 1;
                }
                let hashes = j - hash_start;
                if j < bytes.len() && bytes[j] == b'"' && (raw || hashes == 0) {
                    keep(&mut out, code_start, i);
                    j += 1;
                    if raw {
                        let close: Vec<u8> = std::iter::once(b'"')
                            .chain(std::iter::repeat_n(b'#', hashes))
                            .collect();
                        while j < bytes.len() && !bytes[j..].starts_with(&close) {
                            j += 1;
                        }
                        j = (j + close.len()).min(bytes.len());
                    } else {
                        while j < bytes.len() && bytes[j] != b'"' {
                            j += if bytes[j] == b'\\' { 2 } else { 1 };
                        }
                        j = (j + 1).min(bytes.len());
                    }
                    i = j;
                    code_start = i;
                } else {
                    i += 1;
                }
            }
            b'"' => {
                keep(&mut out, code_start, i);
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(bytes.len());
                code_start = i;
            }
            b'\'' => {
                // A char literal is `'x'`, `'\n'` or `'\u{1}'`; `'a` is a
                // lifetime and must be left alone.
                let is_char = bytes.get(i + 1) == Some(&b'\\')
                    || (bytes.get(i + 2) == Some(&b'\'') && bytes.get(i + 1).is_some());
                if is_char {
                    keep(&mut out, code_start, i);
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\'' {
                        i += if bytes[i] == b'\\' { 2 } else { 1 };
                    }
                    i = (i + 1).min(bytes.len());
                    code_start = i;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    keep(&mut out, code_start, bytes.len());
    String::from_utf8_lossy(&out).into_owned()
}

/// The production region: everything before the first `#[cfg(test)]` that is not
/// inside a comment or a string.
#[must_use]
pub fn production_region(source: &str) -> String {
    let blanked = blank_comments_and_strings(source);
    match blanked.find("#[cfg(test)]") {
        Some(cut) => source[..cut].to_owned(),
        None => source.to_owned(),
    }
}

/// Every `allow`/`expect` of a governed lint in `source`, with where it sits.
///
/// Attributes are found in the blanked text and read out of the original, so a
/// fixture quoted in a doc comment is invisible and a real attribute is not.
#[must_use]
pub fn governed_allows(source: &str) -> Vec<GovernedAllow> {
    let blanked = blank_comments_and_strings(source);
    let bytes = blanked.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'#' {
            i += 1;
            continue;
        }
        let inner = bytes.get(i + 1) == Some(&b'!');
        let open = if inner { i + 2 } else { i + 1 };
        if bytes.get(open) != Some(&b'[') {
            i += 1;
            continue;
        }
        let Some(close) = matching(bytes, open, b'[', b']') else {
            i += 1;
            continue;
        };
        let attribute = &blanked[open + 1..close];
        let mut lints = Vec::new();
        let mut written = Vec::new();
        for keyword in ["allow", "expect"] {
            let mut at = 0;
            while let Some(hit) = attribute[at..].find(keyword) {
                let start = at + hit;
                let after = start + keyword.len();
                let is_word_start = start == 0
                    || !attribute.as_bytes()[start - 1].is_ascii_alphanumeric()
                        && attribute.as_bytes()[start - 1] != b'_';
                if is_word_start && attribute.as_bytes().get(after) == Some(&b'(') {
                    if let Some(end) = matching(attribute.as_bytes(), after, b'(', b')') {
                        for entry in attribute[after + 1..end].split(',') {
                            let entry = entry.trim();
                            if entry.is_empty() || entry.starts_with("reason") {
                                continue;
                            }
                            written.push(entry.to_owned());
                            if let Some(name) = normalize_lint(entry) {
                                lints.push(name.to_owned());
                            }
                        }
                    }
                }
                at = after;
            }
        }
        if !lints.is_empty() {
            found.push(GovernedAllow {
                line: blanked[..i].matches('\n').count() + 1,
                inner,
                module_level: is_module_level(&blanked, i, close, inner),
                lints,
                written,
            });
        }
        i = close + 1;
    }
    found
}

/// The index of the bracket closing the one at `open`, or `None`.
fn matching(bytes: &[u8], open: usize, opener: u8, closer: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if *byte == opener {
            depth += 1;
        } else if *byte == closer {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

/// An inner attribute in the file's prologue, or an outer attribute on a `mod`.
///
/// "Module-level" is the whole of the placement rule, so it is decided here
/// rather than by eye: an `#![allow(…)]` before the first item governs the file
/// module; a `#[allow(…)] mod inner { … }` governs that module; an attribute on
/// a function, a statement or an expression governs neither and is what the rule
/// exists to refuse.
fn is_module_level(blanked: &str, hash: usize, close: usize, inner: bool) -> bool {
    if inner {
        // Nothing but whitespace and other attributes may precede it.
        let mut prefix = &blanked[..hash];
        loop {
            let trimmed = prefix.trim_end();
            if trimmed.ends_with(']') {
                let Some(open) = trimmed.rfind("#![").or_else(|| trimmed.rfind("#[")) else {
                    return false;
                };
                prefix = &trimmed[..open];
                continue;
            }
            return trimmed.is_empty();
        }
    }
    // Outer: skip further attributes and whitespace, then require `mod`.
    let mut rest = &blanked[close + 1..];
    loop {
        rest = rest.trim_start();
        if rest.starts_with('#') {
            let Some(open) = rest.find('[') else {
                return false;
            };
            let Some(end) = matching(rest.as_bytes(), open, b'[', b']') else {
                return false;
            };
            rest = &rest[end + 1..];
            continue;
        }
        for visibility in ["pub(crate)", "pub(super)", "pub", ""] {
            let candidate = rest.strip_prefix(visibility).unwrap_or(rest).trim_start();
            if candidate.starts_with("mod ") {
                return true;
            }
            if visibility.is_empty() {
                return false;
            }
        }
        return false;
    }
}

// ---------------------------------------------------------------------------
// (2) The frozen legacy section
// ---------------------------------------------------------------------------

/// The legacy section of `effects/allowlist.toml` as PR5 freezes it.
///
/// > "the legacy section may only shrink after PR5 (the test compares against
/// > the frozen list) and never contains a topology module"
///
/// Held here rather than only in the TOML because the TOML is the thing under
/// test: a frozen list that lived in the file it freezes would agree with any
/// edit to that file.
pub const FROZEN_LEGACY_ALLOWLIST: &[&str] = &[
    "src/engine/coordinator.rs",
    "src/engine/resume.rs",
    "src/engine/attempt.rs",
    "src/engine/preflight.rs",
    "src/workspace.rs",
    "src/gates.rs",
    "src/review.rs",
    "src/agent/proc.rs",
    "src/agent/bin.rs",
    "src/agent/claude.rs",
    "src/agent/codex.rs",
    "src/agent/copilot.rs",
    "src/capacity.rs",
    "src/export.rs",
    "src/main.rs",
    "src/answer.rs",
    "src/config.rs",
    "src/connect.rs",
    "src/route.rs",
    "src/status.rs",
    "src/validate.rs",
    "src/events/mod.rs",
    "src/events/log/premove.rs",
    "src/engine/tests.rs",
    "examples/probe.rs",
];

/// The modules the legacy section may never contain, verbatim from `mechanism`.
///
/// > "never contains a topology module (src/topology/**, src/runner/**,
/// > src/workspace_manager.rs, src/engine/topology.rs)"
///
/// The ban is on the **legacy** section alone, which is why
/// `src/runner/{host,container,invocation}.rs` and `src/workspace_manager.rs`
/// are in the funnel section without contradiction — the same sentence lists
/// them there.
pub const TOPOLOGY_MODULES: &[&str] = &[
    "src/topology/",
    "src/runner/",
    "src/workspace_manager.rs",
    "src/engine/topology.rs",
];

/// Entries of `current` that the frozen list does not contain — i.e. growth.
///
/// A pure function over its inputs precisely so the refusal can be *executed*
/// against a list that does grow, rather than inferred from one that does not.
#[must_use]
pub fn legacy_growth<'a>(frozen: &[&str], current: &[&'a str]) -> Vec<&'a str> {
    let frozen: BTreeSet<&str> = frozen.iter().copied().collect();
    current
        .iter()
        .copied()
        .filter(|path| !frozen.contains(path))
        .collect()
}

/// Entries of `paths` that name a topology module.
#[must_use]
pub fn topology_modules_among<'a>(paths: &[&'a str]) -> Vec<&'a str> {
    paths
        .iter()
        .copied()
        .filter(|path| {
            TOPOLOGY_MODULES
                .iter()
                .any(|banned| path.starts_with(banned) || *path == *banned)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// (3) Wrapper classification
// ---------------------------------------------------------------------------

/// The modules whose externally reachable `fn`s `mechanism` (3) classifies.
///
/// > "at PR5 every pubfn of a legacy or shared module is classified effectful or
/// > effect-free by review"
///
/// **Legacy** is the frozen legacy section. **Shared** is the modules the slice
/// `scope` names — "shared primitives (locks, run-dir creation and marker,
/// answer staging/ingestion, util JSON write, the exact-snapshot primitive incl.
/// its ephemeral commit, the event-log writer) moved behind funnels with Shared
/// sites" — plus the process funnel, whose `Shared` sites PR4 landed.
///
/// `src/topology/effects.rs` and `src/effects.rs` are deliberately outside the
/// domain: both are in the allowlist's funnel section, and neither is legacy nor
/// shared. Between them they declare 208 + n functions that touch nothing, and
/// classifying them would bury the rows that matter.
pub const CLASSIFIED_MODULES: &[&str] = &[
    // shared
    "src/workspace_manager.rs",
    "src/rundir.rs",
    "src/interaction.rs",
    "src/util.rs",
    "src/events/log.rs",
    "src/runner/host.rs",
    "src/runner/invocation.rs",
    // The third of `mechanism` (2)'s `src/runner/{host,container,invocation}.rs`,
    // added by PR6. It is here rather than only in the allowlist because it
    // denies six of its own paths — the "docker invocation helpers" the same
    // sentence enumerates — and `every_effectful_wrapper_is_on_the_disallowed_list`
    // requires a `tactus::` denial to be a row somebody classified.
    "src/runner/container.rs",
    // legacy
    "src/engine/coordinator.rs",
    "src/engine/resume.rs",
    "src/engine/attempt.rs",
    "src/engine/preflight.rs",
    "src/workspace.rs",
    "src/gates.rs",
    "src/review.rs",
    "src/agent/proc.rs",
    "src/agent/bin.rs",
    "src/agent/claude.rs",
    "src/agent/codex.rs",
    "src/agent/copilot.rs",
    "src/capacity.rs",
    "src/export.rs",
    "src/main.rs",
    "src/answer.rs",
    "src/config.rs",
    "src/connect.rs",
    "src/route.rs",
    "src/status.rs",
    "src/validate.rs",
    "src/events/mod.rs",
    "src/events/log/premove.rs",
];

/// Every `fn` of `source`'s production region that is reachable from outside its
/// module.
///
/// Three shapes, because "pubfn" in the packet's sentence has three of them in
/// this tree and a classification that saw one would be complete against a
/// domain nobody drew:
///
/// * `pub fn` / `pub(crate) fn` / `pub(super) fn` items, free or in an inherent
///   `impl`;
/// * every `fn` inside an `impl <Trait> for <Type>` block, which is reachable
///   through the trait whatever its own visibility says;
/// * associated `fn`s of a public trait's default bodies, which are the same
///   case.
///
/// Names are returned once each, sorted. Two `impl` blocks with a `new` apiece
/// are one row: the classification is of a *name in a module*, and a name that
/// is effectful in one impl is a name the denylist has to carry anyway.
#[must_use]
pub fn externally_reachable_fns(source: &str) -> Vec<String> {
    let region = blank_comments_and_strings(&production_region(source));
    let bytes = region.as_bytes();
    let mut names = BTreeSet::new();
    let mut trait_impl_spans = Vec::new();

    // `impl <something> for <something> {` — the `for` is what makes it a trait
    // impl; an inherent `impl Type {` has none before the brace.
    let mut i = 0;
    while let Some(hit) = region[i..].find("impl") {
        let start = i + hit;
        i = start + 4;
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        if !before_ok || !region[i..].starts_with([' ', '<']) {
            continue;
        }
        let Some(brace) = find_header_brace(&region, i) else {
            continue;
        };
        let header = &region[i..brace];
        if !header.contains(" for ") {
            continue;
        }
        if let Some(end) = matching(bytes, brace, b'{', b'}') {
            trait_impl_spans.push((brace, end));
        }
    }

    for (index, _) in region.match_indices("fn ") {
        if index > 0 && is_ident_byte(bytes[index - 1]) {
            continue;
        }
        let Some(name) = region[index + 3..]
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let visible = declares_visibility(&region[..index]);
        let in_trait_impl = trait_impl_spans
            .iter()
            .any(|(open, close)| index > *open && index < *close);
        if visible || in_trait_impl {
            names.insert(name.to_owned());
        }
    }
    names.into_iter().collect()
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether the text immediately before a `fn` declares it visible outside its
/// module — with the `pub const fn` / `pub unsafe fn` / `pub async fn`
/// modifiers stripped first.
///
/// **One copy, deliberately.** This was written twice — once for the bare case
/// and once inside the modifier-stripping fallback — and a mutation that broke
/// the `pub(crate)` arm of the first copy left the whole suite green, because
/// the second copy still caught it. Two hand-maintained lists of three strings
/// disagree eventually, and the one that disagreed silently would be this one.
/// Measured, mutation `the-parser-misses-pub-crate`.
fn declares_visibility(prefix: &str) -> bool {
    let mut rest = prefix.trim_end();
    for modifier in ["unsafe", "const", "async"] {
        for _ in 0..3 {
            rest = rest.strip_suffix(modifier).unwrap_or(rest).trim_end();
        }
    }
    rest.ends_with("pub") || rest.ends_with("pub(crate)") || rest.ends_with("pub(super)")
}

/// The `{` that opens an `impl` block's body, skipping generics and where-clauses.
fn find_header_brace(region: &str, from: usize) -> Option<usize> {
    let bytes = region.as_bytes();
    let mut angle = 0i32;
    let mut paren = 0i32;
    for (index, byte) in bytes.iter().enumerate().skip(from) {
        match byte {
            b'<' => angle += 1,
            b'>' => angle -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b';' if angle <= 0 && paren <= 0 => return None,
            b'{' if angle <= 0 && paren <= 0 => return Some(index),
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The four build-failure refusals whose reason must be pinned
// ---------------------------------------------------------------------------

/// One shape `mechanism` (1) claims rustc resolution defeats, as a fixture.
///
/// `proof_tests[4]`: "injected renamed-import / re-export / function-value /
/// legacy-wrapper call fixtures fail the build". A fixture asserting "this does
/// not build" is green whether it failed for the intended reason or a typo, so
/// each row carries the lint it must emit **and** the resolved path clippy must
/// name — and the harness runs a control that must compile first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialFixture {
    /// What the shape is called in `proof_tests[4]`.
    pub shape: &'static str,
    /// The fixture body, compiled as its own crate against this crate's rlib.
    pub source: &'static str,
    /// The lint the fixture must emit, and nothing else.
    pub lint: &'static str,
    /// The path clippy's message must name — the *resolved* one, which is the
    /// whole claim: a renamed import reports as `std::fs::write`, not as `w`.
    pub resolves_to: &'static str,
}

/// The fixture set. One row per shape `proof_tests[4]` names, plus the two the
/// mechanism sentence names that the proof test does not (a method call and a
/// macro), because "aliases, re-exports, function values, method calls, and
/// macro-expanded code" is five shapes and a grid short of its domain is the
/// class this project has recorded four times.
pub const DENIAL_FIXTURES: &[DenialFixture] = &[
    DenialFixture {
        shape: "renamed-import",
        source: "use std::fs::write as scribble;\n\
                 pub fn go(p: &str) { let _ = scribble(p, \"x\"); }\n",
        lint: "clippy::disallowed_methods",
        resolves_to: "std::fs::write",
    },
    DenialFixture {
        shape: "re-export",
        source: "pub mod hatch { pub use std::fs::write; }\n\
                 pub fn go(p: &str) { let _ = hatch::write(p, \"x\"); }\n",
        lint: "clippy::disallowed_methods",
        resolves_to: "std::fs::write",
    },
    DenialFixture {
        shape: "function-value",
        source: "pub fn go(p: &str) {\n\
                 \x20   let f = std::fs::write::<&str, &str>;\n\
                 \x20   let _ = f(p, \"x\");\n\
                 }\n",
        lint: "clippy::disallowed_methods",
        resolves_to: "std::fs::write",
    },
    DenialFixture {
        shape: "legacy-wrapper call",
        source: "pub fn go(p: &std::path::Path) {\n\
                 \x20   let _ = tactus::util::write_text(p, \"x\");\n\
                 }\n",
        lint: "clippy::disallowed_methods",
        resolves_to: "tactus::util::write_text",
    },
    DenialFixture {
        shape: "method call",
        source: "pub fn go(p: &std::path::Path) -> std::io::Result<()> {\n\
                 \x20   let f = std::fs::File::open(p)?;\n\
                 \x20   f.sync_all()\n\
                 }\n",
        lint: "clippy::disallowed_methods",
        resolves_to: "std::fs::File::sync_all",
    },
    DenialFixture {
        shape: "macro-expanded code",
        source: "pub fn go() { println!(\"escaped\"); }\n",
        lint: "clippy::disallowed_macros",
        resolves_to: "std::println",
    },
    DenialFixture {
        shape: "type",
        source: "pub fn go() { let _ = std::process::Command::new(\"git\"); }\n",
        lint: "clippy::disallowed_types",
        resolves_to: "std::process::Command",
    },
];

/// A fixture that must compile clean, so a mis-wired invocation cannot make
/// every refusal above "pass".
///
/// `PR5-C-DOCTEST-FIXTURES-NEVER-RAN` is in the standing ledger because three
/// build-refusal fixtures were green having never executed. The control is the
/// difference between "the compiler refused this" and "the compiler could not
/// find a crate to refuse it against".
pub const DENIAL_CONTROL: &str = "pub fn go(p: &std::path::Path) -> bool {\n\
                                  \x20   let _ = tactus::util::tail(\"x\", 1);\n\
                                  \x20   p.exists()\n\
                                  }\n";

#[cfg(test)]
mod tests;
