//! Locating and invoking an agent CLI — the parts every adapter needs and
//! none of them should own privately.
//!
//! Windows is why this module exists. Both agent CLIs ship as npm packages, so
//! the thing on PATH is frequently a `.cmd` shim rather than a native
//! executable, and `CreateProcess` cannot exec a batch script. That used to be
//! handled here by building a `cmd /C` command line by hand and passing it
//! through `raw_arg`.
//!
//! **It is not any more, and the reason is worth recording.** `raw_arg` opts
//! out of everything the standard library does for batch targets, including the
//! argument escaping added in Rust 1.77.2 for CVE-2024-24576; this crate is
//! edition 2024, so that fix is unconditionally present. Measured against a
//! real npm-shape shim, the hand-rolled version expanded `%VAR%` inside
//! arguments — turning `--allow-tool=shell(echo %PATH%)` into the machine's
//! entire PATH — while `Command::args` carried every case through intact:
//! `&`, `|`, `%`, embedded quotes, `^`, spaces, and the empty argument.
//!
//! Copilot is what made that matter. Its permission surface is argv, so gate
//! commands — strings a user writes in `tactus.toml` — now reach a Windows
//! command line, and a mangled `--allow-tool=shell(<gate>)` is a permission
//! grant that no longer matches the command it is meant to authorize. The
//! module comment used to argue that two copies of the quoting logic would be
//! two chances to get it wrong. The right number was zero.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::error::TactusError;
use crate::runner::CommandSpec;
use crate::util;

/// A located agent binary and how to spawn it.
#[derive(Debug, Clone)]
pub struct Invocation {
    path: PathBuf,
}

impl Invocation {
    /// The command to run, as data: `args` are carried verbatim.
    ///
    /// Nothing is quoted, escaped, or wrapped here on purpose: `std` knows
    /// whether the resolved path is a batch shim and applies the right rules,
    /// and every attempt to help it has been a way to get this wrong. The
    /// escaping still happens in exactly one place — the runner, when it turns
    /// this spec into a `Command` — and this returns a
    /// [`CommandSpec`] rather than a `Command` because DESIGN.md:117 says an
    /// adapter "does not decide where the process runs".
    ///
    /// [`CommandSpec::program`] is a `String` (DESIGN.md:222), and a resolved
    /// path that is not valid Unicode cannot become one **without becoming a
    /// different path**. So this refuses rather than converting.
    ///
    /// The rejected alternative was `to_string_lossy`, and it is worth
    /// recording why: `String::from_utf8_lossy` replaces each invalid byte
    /// with `U+FFFD`, so a `claude` inside a `PATH` directory whose name
    /// carries a non-UTF-8 byte — legal on Unix, where a path is bytes —
    /// arrives at the runner as a path that names *nothing*, and the run dies
    /// at `CreateProcess`/`execvp` with "failed to spawn", pointing at a path
    /// the operator never wrote. Before this slice the `PathBuf` reached
    /// `Command::new` unchanged and that installation ran.
    ///
    /// Neither behaviour is "legacy engine behavior unchanged"
    /// (`invariants_preserved[1]`), because the frozen `CommandSpec.program:
    /// String` cannot carry the input at all; the choice is between two ways
    /// of failing. This one fails **at the boundary that cannot represent the
    /// value**, names the path and says why, and cannot be mistaken for a
    /// missing installation. Widening `CommandSpec.program` to an `OsString`
    /// is the repair that would restore the old behaviour, and it is a change
    /// to DESIGN.md:222 rather than to this function.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when the resolved path is not valid Unicode.
    pub fn spec(&self, args: &[String]) -> Result<CommandSpec, TactusError> {
        let Some(program) = self.path.to_str() else {
            return Err(TactusError::Refused {
                message: format!(
                    "the agent binary resolved to `{}`, a path that is not valid Unicode. \
                     A CommandSpec carries its program as a String (DESIGN.md:222), and \
                     converting this path would spawn a different one, so it is refused here \
                     rather than at the spawn. Install the CLI under a Unicode path, or remove \
                     that PATH entry",
                    self.path.to_string_lossy()
                ),
            });
        };
        Ok(CommandSpec {
            program: program.to_owned(),
            args: args.to_vec(),
            env: Vec::new(),
            stdin: Vec::new(),
        })
    }

    pub fn display(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

/// Resolve the first of `names` that exists on PATH, caching the answer in the
/// adapter's own `cache`.
///
/// PATH resolution is process-stable and the engine builds one command per
/// task after probing, so each adapter resolves once. The cache is passed in
/// rather than kept here because two adapters must not share one slot.
///
/// `missing` renders the error when nothing resolves; it takes the names that
/// were tried so the message can name them.
pub fn locate(
    names: &[&str],
    cache: &OnceLock<Option<Invocation>>,
    missing: impl FnOnce(&[&str]) -> String,
) -> Result<Invocation, TactusError> {
    locate_with(names, cache, |_| true, missing)
}

/// Resolve the first usable candidate in shell PATH order and cache it.
///
/// Some platforms expose aliases that look like files but cannot be spawned.
/// The predicate lets an adapter reject one of those and continue through the
/// remaining PATH entries. Rejection happens before the cache is populated, so
/// a bad alias cannot poison every later probe and attempt in this process.
pub fn locate_with(
    names: &[&str],
    cache: &OnceLock<Option<Invocation>>,
    usable: impl FnMut(&Invocation) -> bool,
    missing: impl FnOnce(&[&str]) -> String,
) -> Result<Invocation, TactusError> {
    let mut usable = usable;
    cache
        .get_or_init(|| {
            // util::find_program_candidates skips empty PATH segments, which
            // would otherwise resolve a bare name against the current
            // directory — i.e. run a binary out of the repo being worked on.
            first_usable(
                util::find_program_candidates(names)
                    .into_iter()
                    .map(|path| Invocation { path }),
                &mut usable,
            )
        })
        .clone()
        .ok_or_else(|| TactusError::Agent {
            message: missing(names),
        })
}

fn first_usable(
    candidates: impl IntoIterator<Item = Invocation>,
    usable: &mut impl FnMut(&Invocation) -> bool,
) -> Option<Invocation> {
    candidates.into_iter().find(|candidate| usable(candidate))
}

/// First `digits.digits.digits` token wins; otherwise the trimmed first line
/// verbatim (`--version` formats have churned before, in both CLIs).
pub fn extract_version(stdout: &str) -> String {
    let first_line = stdout.lines().next().unwrap_or_default().trim();
    first_line
        .split_whitespace()
        .find(|token| {
            let mut parts = token.trim_start_matches('v').split('.');
            let numeric = |s: Option<&str>| {
                s.is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            };
            numeric(parts.next()) && numeric(parts.next()) && parts.next().is_some()
        })
        // Trailing punctuation is not part of a version. The Copilot CLI ends
        // its line with a full stop — `GitHub Copilot CLI 1.0.78.` — which
        // otherwise rides along into `Caps.version` and out through every
        // message that quotes it (`tactus capacity`, and the probe refusal that
        // names the version an adapter would not support).
        .map(|t| {
            t.trim_start_matches('v')
                .trim_end_matches(['.', ',', ';'])
                .to_owned()
        })
        .unwrap_or_else(|| first_line.to_owned())
}

/// Test-only constructors.
///
/// Below every production item on purpose: `effects::production_region` cuts a
/// file at its **first** `#[cfg(test)]`, so a test-only item placed among the
/// production ones takes the rest of the file out of the wrapper-classification
/// domain — silently, and `mechanism` (3)'s "every pubfn … is classified" would
/// then be true of a domain nobody drew. That is `PR5D-VISIBILITY-CHECK-
/// DUPLICATED`'s shape one level out, and it was measured here: five of this
/// module's functions left the census the moment a `#[cfg(test)] fn` was added
/// above them.
#[cfg(test)]
impl Invocation {
    /// An invocation naming `path`, for tests that need one without asking
    /// this machine what it has installed.
    ///
    /// Production's only constructors are [`locate`] and [`locate_with`], which
    /// resolve against `PATH` and memoise into a process-wide `OnceLock` that
    /// every sibling test in the binary then reads. A test that needs to drive
    /// a *pre-flight sequence* — the six strict-config parser probes, say —
    /// must not go through them. That is the hazard `4631a3f` repaired once
    /// already.
    pub(crate) fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::Path;

    fn invocation(path: &str) -> Invocation {
        Invocation {
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn arguments_reach_the_command_untouched() {
        use crate::runner::host::build_command;

        // The property the deleted quoting code kept breaking. These are the
        // exact shapes Copilot's permission surface produces: a gate command
        // with spaces and parentheses, a cmd metacharacter, a percent sign, an
        // embedded quote, and an empty argument.
        let args: Vec<String> = [
            "-s",
            "--allow-tool=shell(cargo test)",
            "--allow-tool=shell(echo hi & whoami)",
            "--allow-tool=shell(echo %PATH%)",
            r#"--allow-tool=shell(cargo test -- --exact "my test")"#,
            "--setting-sources",
            "",
        ]
        .map(str::to_owned)
        .to_vec();

        let spec = invocation(r"C:\Users\John Smith\npm\copilot.cmd")
            .spec(&args)
            .expect("a Unicode path");
        assert_eq!(
            spec.program, r"C:\Users\John Smith\npm\copilot.cmd",
            "the shim is the program; nothing wraps it in a shell"
        );
        assert_eq!(spec.args, args, "every argument survives verbatim");

        // And the same through the runner's own translation, which is what
        // actually spawns: the spec surviving intact would be worth nothing if
        // the step that turns it into a `Command` re-quoted it. The `cmd.exe`
        // raw-tail rule applies to `cmd`, and this program is not it.
        let cmd = build_command(&spec);
        assert_eq!(
            cmd.get_program(),
            OsStr::new(r"C:\Users\John Smith\npm\copilot.cmd")
        );
        let seen: Vec<&OsStr> = cmd.get_args().collect();
        let expected: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        assert_eq!(seen, expected, "every argument survives verbatim");
    }

    #[test]
    fn version_extraction_handles_known_formats() {
        assert_eq!(extract_version("2.1.35 (Claude Code)\n"), "2.1.35");
        assert_eq!(extract_version("claude v1.0.128\n"), "1.0.128");
        assert_eq!(extract_version("weird output\n"), "weird output");
        // Verbatim from the Copilot CLI: the sentence's full stop is not part
        // of the version, and rode into `Caps.version` when it was not trimmed.
        assert_eq!(
            extract_version(
                "GitHub Copilot CLI 1.0.78.\nRun 'copilot update' to check for updates.\n"
            ),
            "1.0.78"
        );
    }

    #[test]
    fn a_missing_binary_reports_every_name_it_tried() {
        static CACHE: OnceLock<Option<Invocation>> = OnceLock::new();
        let names = ["tactus-definitely-not-a-real-binary"];
        let error = locate(&names, &CACHE, |tried| {
            format!("not found (looked for {})", tried.join(", "))
        })
        .expect_err("nothing should resolve");
        assert!(
            error
                .to_string()
                .contains("tactus-definitely-not-a-real-binary"),
            "got: {error}"
        );
    }

    #[test]
    fn an_unusable_candidate_is_skipped_before_the_answer_is_cached() {
        let first = invocation(r"C:\WindowsApps\codex.exe");
        let second = invocation(r"C:\Users\me\npm\codex.cmd");
        let mut inspected = Vec::new();

        let selected = first_usable([first, second.clone()], &mut |candidate| {
            inspected.push(candidate.display());
            candidate.display() == second.display()
        })
        .expect("the later usable installation wins");

        assert_eq!(selected.display(), second.display());
        assert_eq!(inspected.len(), 2, "the bad alias was actually tested");
    }

    /// A `.cmd` shim really does execute, and an argument really does arrive.
    ///
    /// Asserting on the constructed `Command` proves we hand `std` the right
    /// thing; only spawning proves `std` then does the right thing with a batch
    /// target, which is the half the old hand-rolled code got wrong.
    #[cfg(windows)]
    #[test]
    fn a_batch_shim_runs_and_receives_its_argument() {
        let dir = std::env::temp_dir().join(format!("tactus-bin-shim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let shim = dir.join("tactus-test-shim.cmd");
        // `%~1` strips the quotes the child got; a benign argument keeps this
        // about plumbing rather than about batch re-parsing.
        std::fs::write(&shim, "@echo off\r\necho GOT:%~1\r\n").expect("write shim");

        let out = crate::runner::host::build_command(
            &invocation(&shim.to_string_lossy())
                .spec(&["hello world".to_owned()])
                .expect("a Unicode path"),
        )
        .output()
        .expect("the shim spawns");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("GOT:hello world"),
            "the shim ran and saw its argument: {stdout:?}"
        );
    }

    /// A resolved path that a `String` cannot carry is refused by name, not
    /// converted into a path that names nothing.
    ///
    /// Both platforms have such a path and neither can be spelled in source as
    /// a `&str`: on Unix a path is bytes, so `0xff` is legal and not UTF-8; on
    /// Windows it is UTF-16, so an unpaired surrogate is legal and not UTF-8.
    /// Every other fixture in this module is valid Unicode, which is why the
    /// lossy conversion this replaced survived the suite while changing what a
    /// supported installation did.
    #[test]
    fn a_program_path_a_string_cannot_carry_is_refused_by_name() {
        #[cfg(unix)]
        let (path, rendered) = {
            use std::os::unix::ffi::OsStringExt;
            let mut bytes = b"/opt/tactus-".to_vec();
            bytes.push(0xff);
            bytes.extend_from_slice(b"/claude");
            (
                PathBuf::from(std::ffi::OsString::from_vec(bytes)),
                "/opt/tactus-\u{fffd}/claude",
            )
        };
        #[cfg(windows)]
        let (path, rendered) = {
            use std::os::windows::ffi::OsStringExt;
            let mut units: Vec<u16> = r"C:\tactus-".encode_utf16().collect();
            units.push(0xd800);
            units.extend(r"\claude.cmd".encode_utf16());
            (
                PathBuf::from(std::ffi::OsString::from_wide(&units)),
                "C:\\tactus-\u{fffd}\\claude.cmd",
            )
        };

        assert!(
            path.to_str().is_none(),
            "the fixture path is valid Unicode, so it witnesses nothing"
        );
        let unusable = Invocation { path };
        let error = unusable
            .spec(&["--version".to_owned()])
            .expect_err("a path a String cannot carry must be refused");
        let message = error.to_string();
        // The operator has to be able to find the entry. `display()` stays
        // lossy on purpose — it is a diagnostic, not a program.
        assert!(message.contains(rendered), "{message}");
        assert!(message.contains("not valid Unicode"), "{message}");
        assert_eq!(unusable.display(), rendered);

        // And the ordinary case is unaffected: same call, a Unicode path.
        let fine = invocation("/usr/local/bin/claude")
            .spec(&["--version".to_owned()])
            .expect("a Unicode path is carried unchanged");
        assert_eq!(fine.program, "/usr/local/bin/claude");
        assert_eq!(fine.args, vec!["--version".to_owned()]);

        // A path that legitimately *contains* `U+FFFD` is carried as itself.
        //
        // `U+FFFD` is an ordinary character in a filename. It is only special
        // as `to_string_lossy`'s substitution marker, so every conversion that
        // treats it as one — `to_string_lossy()` followed by a `replace`, the
        // shape `PR4-SEAMS-004` names — silently renames a directory that
        // really is called that, and spawns something else or nothing.
        //
        // Neither fixture above can see it: the refusal fixture's path is not
        // valid Unicode at all, and the ordinary fixture's path carries no
        // marker. This is the one input on which "refuse" and "substitute"
        // still disagree after the refusal is in place.
        let literal = "/opt/tactus-\u{fffd}/claude";
        assert!(
            literal.contains(char::REPLACEMENT_CHARACTER),
            "the fixture lost its marker, so it witnesses nothing"
        );
        let carried = invocation(literal)
            .spec(&["--version".to_owned()])
            .expect("U+FFFD is a legal character in a path, not a conversion failure");
        assert_eq!(
            carried.program, literal,
            "a path containing U+FFFD was rewritten rather than carried"
        );
    }

    #[test]
    fn display_is_the_resolved_path() {
        assert_eq!(
            invocation("/usr/local/bin/claude").display(),
            "/usr/local/bin/claude"
        );
        assert!(Path::new("/usr/local/bin/claude").is_absolute() || cfg!(windows));
    }
}
