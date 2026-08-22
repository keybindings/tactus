//! GitHub Copilot CLI adapter (DESIGN.md §16) — the multi-vendor pool.
//!
//! One subscription reaches Anthropic, OpenAI, and Google models through one
//! harness, which is what makes §11.3's cross-vendor second opinion a `--model`
//! flag rather than a second product.
//!
//! **Route A, not ACP (v0.1).** §16 names two routes and prefers ACP "once
//! stable for us". It is not yet: neither `--acp` nor `--stdio` appears in
//! GitHub's programmatic CLI reference, so there is no documented surface to
//! pin known-good behaviour against — and pinning per version is exactly what
//! §16 says this adapter must do. ACP also needs a persistent bidirectional
//! JSON-RPC session, where every other part of v0.1 spawns a process, feeds it,
//! and reads what came back ([`super::proc`]). `probe()` still records
//! [`Caps::acp`], so switching routes stays a change inside this file.
//!
//! **The prompt goes on stdin, and there is no `-p`.** GitHub documents
//! `echo "…" | copilot` as a programmatic form, and documents that "piped input
//! is ignored if you also provide a prompt with the `-p` option" — so passing
//! both would silently discard the real prompt. Stdin is also the only delivery
//! that works: npm installs this CLI as `copilot.cmd` on Windows, and a batch
//! target is spawned through the command processor whoever does it — so the
//! ~8,191-character command line applies, while a review prompt carries up to
//! [`crate::review::MAX_DIFF_BYTES`] of diff.
//!
//! **What this CLI does not give us**, recorded honestly rather than guessed at:
//! no JSON envelope (so no session id, no usage, no cost — the ledger shows
//! Copilot attempts as unpriced), and no documented session resume (so §11.4's
//! same-rung retry starts fresh with accumulated feedback instead of resuming a
//! conversation). Both are `Caps` axes the engine already dispatches on.
//!
//! Two further gaps, named rather than papered over: `max_turns` has no
//! counterpart here, so a per-profile turn cap does not apply to Copilot
//! attempts (the wall-clock timeout is the only bound); and whether
//! `--no-ask-user` also suppresses *tool-permission* prompts is undocumented,
//! so an un-allowed tool could in principle hang an attempt until that timeout.
//!
//! **Permissions are argv** (§20). There is no settings file and no path-deny
//! surface as Claude Code has, so the guarantee is the allow-list plus §15's
//! split: an allow-list that names exactly the gate commands, no URL grant at
//! all, and never a skip-all flag. That rests on un-allowed tools being denied
//! by default — which `--allow-url`'s existence implies but nothing here can
//! verify without the binary, so the reviewer profile denies `write` and
//! `shell` outright rather than trusting it where the stakes are highest.
//! Docs:
//! <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference>
//! (flags verified Aug 2026).
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::json;

use super::bin::{self, Invocation};
use super::proc::ProcessOutput;
use super::{AgentAdapter, Caps, Discovery, TaskRun, looks_rate_limited, probe_request};
use crate::error::TactusError;
use crate::ir::{Effort, Outcome, OutcomeStatus, PermissionMode, WorkerProfile};
use crate::runner::{CommandSpec, Runner};
use crate::util;

pub const ADAPTER_ID: &str = "copilot";

/// Budget for one probe call.
///
/// Sixty seconds for `--version` looks absurd until you watch it: this CLI is a
/// Node program behind an npm shim that runs an update check on startup, and it
/// takes ~5s warm on an unloaded machine. Under a loaded one — a full test
/// suite, a CI runner, a laptop doing anything else — 15s was not enough, and
/// the failure mode is the expensive one: §19 makes a probe failure a refusal
/// to START, so a slow machine loses the whole run rather than one attempt.
///
/// Probing happens once per run at pre-flight, so the cost of being generous
/// here is bounded and paid only when something is genuinely wrong. Waiting a
/// minute before refusing beats refusing a working machine in fifteen seconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// Long flags this adapter passes. §16: this CLI auto-updates and has removed
/// programmatic flags without deprecation, so a missing one must surface as a
/// pre-flight refusal rather than as per-task failures once a run is already
/// spending (§19).
const REQUIRED_FLAGS: [&str; 5] = [
    "--model",
    "--effort",
    "--allow-tool",
    "--deny-tool",
    "--no-ask-user",
];

/// Short flags this adapter passes, checked separately because a substring
/// search for them is worthless: `"-s"` occurs inside `--settings`, `--share`
/// and `--stdio`. Since none of `Caps`' other fields drives behaviour yet, this
/// refusal is most of what probing actually buys.
const REQUIRED_SHORT_FLAGS: [&str; 1] = ["-s"];

/// Which of this adapter's pre-flight processes each identity is. See
/// [`super::probe_request`] for why these are named rather than counted.
/// `discover` spawns nothing here — this CLI answers no auth query — so there
/// are two.
mod probe_ordinal {
    pub const VERSION: u32 = 0;
    pub const HELP: u32 = 1;
    /// Every ordinal above, for the uniqueness assertion.
    #[cfg(test)]
    pub const ALL: [u32; 2] = [VERSION, HELP];
}

pub struct CopilotAdapter;

impl AgentAdapter for CopilotAdapter {
    fn id(&self) -> &'static str {
        ADAPTER_ID
    }

    fn probe(&self, runner: &dyn Runner) -> Result<Caps, TactusError> {
        let invocation = locate()?;
        let out = runner.run(&probe_request(
            ADAPTER_ID,
            invocation.spec(&["--version".to_owned()])?,
            probe_ordinal::VERSION,
            PROBE_TIMEOUT,
        )?)?;
        if out.output_limited {
            return Err(TactusError::Agent {
                message: format!(
                    "`{}` --version exceeded the output limit",
                    invocation.display()
                ),
            });
        }
        if out.timed_out {
            return Err(TactusError::Agent {
                message: format!("`{}` --version timed out", invocation.display()),
            });
        }
        if out.code != Some(0) {
            return Err(TactusError::Agent {
                message: format!(
                    "`{}` --version exited with {:?}: {}",
                    invocation.display(),
                    out.code,
                    out.stderr.trim()
                ),
            });
        }
        let version = bin::extract_version(&out.stdout);

        let help = runner.run(&probe_request(
            ADAPTER_ID,
            invocation.spec(&["--help".to_owned()])?,
            probe_ordinal::HELP,
            PROBE_TIMEOUT,
        )?)?;
        let help_text = checked_help(&invocation.display(), &help)?;
        validate_help(&version, &help_text)?;
        let has = |flag: &str| super::advertises_flag(&help_text, flag);
        Ok(Caps {
            version,
            // False even if a JSON flag exists: `Caps` describes what this
            // adapter's route delivers, and Route A neither asks for JSON nor
            // parses it. Reporting the flag would promise a structured envelope
            // no caller could read.
            json_output: false,
            // Optional capabilities stay pessimistic. Required surfaces were
            // proven above; an unreadable help is a refusal, not permission to
            // assume support.
            session_resume: has("--resume"),
            // No JSON envelope on this route, so nothing reports spend. The
            // ledger says so rather than recording zero (§13).
            cost_reporting: false,
            // No single flag; achieved by denying the write and shell tools.
            read_only_mode: true,
            acp: has("--acp"),
            model_list: has("--list-models"),
        })
    }

    fn build(&self, run: &TaskRun) -> Result<CommandSpec, TactusError> {
        // No `current_dir`: the runner owns cwd (DESIGN.md:118).
        locate()?.spec(&build_args(run))
    }

    fn parse(&self, out: &ProcessOutput) -> Result<Outcome, TactusError> {
        Ok(parse_output(out))
    }

    /// Honestly, almost nothing — and the same pessimistic temperament as this
    /// adapter's `Caps`.
    ///
    /// GitHub's programmatic CLI reference documents no non-interactive auth
    /// query and no model listing (checked Aug 2026), so there is nothing to
    /// subprocess that would answer either question. Reporting
    /// [`AuthState::Unknown`] is the truthful result: inferring "signed in"
    /// from the binary merely existing would put a confident wrong line in a
    /// file the operator then trusts.
    ///
    /// The `probe()` this runs beside is what has actually been load-bearing
    /// here, and it still is: [`Caps::model_list`] gates any future
    /// enumeration, so the day this CLI grows one, `connect` starts
    /// cross-checking the catalog without another decision being made.
    fn discover(&self, _runner: &dyn Runner, caps: &Caps) -> Result<Discovery, TactusError> {
        // Still located, so `connect` fails this agent the same way pre-flight
        // would rather than writing a pool for a binary that is not there.
        let invocation = locate()?;
        let mut discovery = Discovery::unknown().with_note(format!(
            "`{}` reports no non-interactive auth state, so whether this account is signed in \
             could not be checked without spending",
            invocation.display()
        ));
        if !caps.model_list {
            discovery.notes.push(
                "and no model listing either, so the roster for this agent is the catalog \
                 shipped with tactus, not something confirmed here"
                    .to_owned(),
            );
        }
        // §13 gives Copilot two billing shapes — credits (post-Jun 2026) and
        // legacy premium requests — and nothing this CLI prints distinguishes
        // them. `shape: None` is what makes the writer say so in the file.
        Ok(discovery)
    }

    /// Nothing to reference: permissions ride on argv, so this returns `None`
    /// and the command carries them itself.
    ///
    /// The file is still written. §15 calls `settings/<task>-<attempt>.json`
    /// "the per-attempt permission surface", and an audit trail that exists for
    /// one agent and silently not for another is worse than none — someone
    /// reading a run tomorrow should be able to see what each attempt was
    /// allowed to do without reconstructing it from this source file.
    fn materialize_permissions(
        &self,
        profile: &WorkerProfile,
        gate_cmds: &[String],
        dir: &std::path::Path,
        stem: &str,
    ) -> Result<Option<PathBuf>, TactusError> {
        let path = dir.join(format!("{stem}.json"));
        util::write_json(
            &path,
            &json!({
                "agent": ADAPTER_ID,
                "profile": profile.name,
                "permissions": profile.permissions,
                "note": "recorded for audit only; copilot takes permissions as argv flags",
                "args": permission_args(profile, gate_cmds),
            }),
        )?;
        Ok(None)
    }
}

fn checked_help(program: &str, output: &ProcessOutput) -> Result<String, TactusError> {
    if output.output_limited {
        return Err(TactusError::Agent {
            message: format!(
                "`{program}` --help exceeded the output limit; effort support could not be verified"
            ),
        });
    }
    if output.timed_out {
        return Err(TactusError::Agent {
            message: format!("`{program}` --help timed out; effort support could not be verified"),
        });
    }
    if output.code != Some(0) {
        return Err(TactusError::Agent {
            message: format!(
                "`{program}` --help exited with {:?}: {}",
                output.code,
                output.stderr.trim()
            ),
        });
    }
    let text = format!("{}\n{}", output.stdout, output.stderr);
    if text.trim().is_empty() {
        return Err(TactusError::Agent {
            message: format!(
                "`{program}` --help returned no output; effort support could not be verified"
            ),
        });
    }
    Ok(text)
}

fn validate_help(version: &str, help: &str) -> Result<(), TactusError> {
    let missing_flags: Vec<&str> = REQUIRED_FLAGS
        .into_iter()
        .filter(|flag| !super::advertises_flag(help, flag))
        .chain(
            REQUIRED_SHORT_FLAGS
                .into_iter()
                .filter(|flag| !super::advertises_flag(help, flag)),
        )
        .collect();
    if !missing_flags.is_empty() {
        return Err(TactusError::Agent {
            message: format!(
                "copilot {version} does not advertise required flag(s): {}. This adapter pins \
                 known-good behavior per version — upgrade tactus or pin an older copilot.",
                missing_flags.join(", ")
            ),
        });
    }
    let missing_efforts = super::missing_effort_levels(help);
    if !missing_efforts.is_empty() {
        return Err(TactusError::Agent {
            message: format!(
                "copilot {version} advertises `--effort` but not required level(s): {}. Refusing \
                 before spend because this run may request any shared effort level.",
                missing_efforts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }
    Ok(())
}

/// Argument list, kept separate from binary resolution so it is testable on
/// machines without the CLI installed.
fn effort_flag(effort: Effort) -> &'static str {
    match effort {
        Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::XHigh => "xhigh",
        Effort::Max => "max",
    }
}

pub fn build_args(run: &TaskRun) -> Vec<String> {
    // NOTE: no `-p`. The prompt arrives on stdin, and GitHub documents that
    // piped input is ignored when `-p` is also given — passing both would send
    // the CLI an empty task and discard the real one.
    let mut args = vec![
        // Only the agent's response on stdout, with no stats or decoration
        // around it: `parse_output` treats stdout as the final message, and
        // that message is where a reviewer's verdict travels.
        "-s".to_owned(),
        // An unattended run must never sit waiting on a clarifying question.
        "--no-ask-user".to_owned(),
        format!("--model={}", run.profile.model),
    ];
    if let Some(effort) = run.profile.effort {
        args.push(format!("--effort={}", effort_flag(effort)));
    }
    // `profile.max_turns` has no counterpart on this CLI and is therefore
    // NOT applied — see the module header. Nothing sets it today, and it is
    // named here rather than silently skipped so that whoever first does has
    // to decide what an unbounded Copilot attempt should cost.
    args.extend(permission_args(&run.profile, &run.gate_cmds));
    // Only reachable on a build whose `--help` advertises `--resume`, because
    // that is what sets `Caps::session_resume` and the engine will not offer a
    // session otherwise. Honouring it here means a future release that ships
    // the flag needs no change beyond the probe noticing it.
    if let Some(session) = &run.resume_session {
        args.push(format!("--resume={session}"));
    }
    args.extend(run.profile.extra_args.iter().cloned());
    args
}

/// The per-attempt permission surface as argv (§20).
///
/// Edit profiles get the write tool and *exactly* the configured gate commands;
/// reviewers get neither. Nobody is granted a URL, so network access stays
/// behind a permission this adapter never gives — and with `--no-ask-user` the
/// agent cannot ask for one either.
///
/// Reading is not granted explicitly because this CLI allows the working
/// directory by default and `--add-dir` is what widens that; the engine never
/// widens it, so an agent sees the workspace and nothing else.
pub fn permission_args(profile: &WorkerProfile, gate_cmds: &[String]) -> Vec<String> {
    let mut args = Vec::new();
    match profile.permissions {
        PermissionMode::Edit => {
            args.push("--allow-tool=write".to_owned());
            for gate in gate_cmds {
                args.push(format!("--allow-tool=shell({gate})"));
            }
        }
        PermissionMode::ReadOnly => {
            // Denied rather than merely not-allowed: a reviewer that edits the
            // code it is judging invalidates the verdict, and one that runs
            // commands is executing the very diff under review.
            args.push("--deny-tool=write".to_owned());
            args.push("--deny-tool=shell".to_owned());
        }
    }
    args
}

/// Outcome parsing for a CLI with no JSON envelope.
///
/// With `-s` the whole of stdout is the agent's final message, so that is what
/// lands in `detail` on success — the field a reviewer's verdict is read from
/// (step-6 finding #1: leaving it empty makes every review unparseable). Diff,
/// transcript path, and pool drain are engine-owned and left empty here.
fn parse_output(out: &ProcessOutput) -> Outcome {
    let mut outcome = Outcome {
        status: OutcomeStatus::AgentError,
        diff: String::new(),
        detail: None,
        // No JSON envelope: nothing to read a session, usage, or cost from.
        session_id: None,
        usage: None,
        cost_usd: None,
        transcript_path: PathBuf::new(),
        duration: out.duration,
    };

    if out.output_limited {
        outcome.status = OutcomeStatus::AgentError;
        outcome.detail = Some("agent exceeded the stdout/stderr output limit".to_owned());
        return outcome;
    }

    if out.timed_out {
        outcome.status = OutcomeStatus::Timeout;
        outcome.detail = Some("attempt exceeded its wall-clock timeout".to_owned());
        return outcome;
    }

    let response = out.stdout.trim();
    if out.code == Some(0) {
        outcome.status = OutcomeStatus::Completed;
        outcome.detail = (!response.is_empty()).then(|| response.to_owned());
        return outcome;
    }

    // Rate-limit detection applies to failures only — see `looks_rate_limited`.
    outcome.status = if looks_rate_limited(&out.stderr) || looks_rate_limited(response) {
        OutcomeStatus::RateLimited
    } else {
        OutcomeStatus::AgentError
    };
    // Give the engine something to report without opening the transcript.
    // stderr first: on a failure it carries the diagnostic, while stdout may
    // hold half an answer.
    let stderr = out.stderr.trim();
    outcome.detail = if !stderr.is_empty() {
        Some(util::tail(stderr, 2000))
    } else if !response.is_empty() {
        Some(util::tail(response, 2000))
    } else {
        None
    };
    outcome
}

// ---------------------------------------------------------------------------
// Binary discovery — npm ships this as copilot.cmd on Windows, which
// CreateProcess cannot exec directly; `super::bin` owns the mechanics.
// ---------------------------------------------------------------------------

fn candidate_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["copilot.exe", "copilot.cmd", "copilot.bat"]
    } else {
        &["copilot"]
    }
}

/// This adapter's own resolution cache; `bin::locate` fills it once.
static RESOLVED: OnceLock<Option<Invocation>> = OnceLock::new();

fn locate() -> Result<Invocation, TactusError> {
    bin::locate(candidate_names(), &RESOLVED, |tried| {
        format!(
            "copilot binary not found on PATH (looked for {}); install the GitHub Copilot CLI \
             (`npm install -g @github/copilot`) or adjust PATH",
            tried.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Permission flags that hand an agent the whole machine, and the URL grant
    /// that would put it on the network. §20 says none of these is ever used,
    /// so the list lives here: its only job is to be asserted against.
    const SKIP_ALL_FLAGS: [&str; 6] = [
        "--allow-all",
        "--yolo",
        "--allow-all-tools",
        "--allow-all-paths",
        "--allow-all-urls",
        "--allow-url",
    ];

    fn profile(permissions: PermissionMode) -> WorkerProfile {
        WorkerProfile {
            name: "impl-frontier".to_owned(),
            agent: ADAPTER_ID.to_owned(),
            model: "gpt-5.3-codex".to_owned(),
            pool: "copilot".to_owned(),
            permissions,
            effort: Some(crate::ir::Effort::Medium),
            max_turns: Some(30),
            extra_args: Vec::new(),
        }
    }

    fn task_run() -> TaskRun {
        TaskRun {
            prompt: "Do the thing.".to_owned(),
            profile: profile(PermissionMode::Edit),
            workspace: PathBuf::from("."),
            gate_cmds: vec!["cargo test".to_owned()],
            resume_session: None,
            settings_path: None,
        }
    }

    fn output(code: Option<i32>, stdout: &str, stderr: &str) -> ProcessOutput {
        ProcessOutput {
            code,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            duration: Duration::from_secs(1),
            timed_out: false,
            output_limited: false,
        }
    }

    /// Every pre-flight process of this adapter carries its own identity.
    ///
    /// `decisions.admission_and_leases.permits.invocation_identity` says
    /// "unique **per process**", and this adapter runs 2 of them, so the
    /// ordinals it fixes must be 2 distinct values. The expected count is
    /// written here from the steps the adapter performs, not read from the
    /// table under test — a table that lost an entry would otherwise agree
    /// with itself.
    #[test]
    fn every_preflight_process_has_its_own_ordinal() {
        use std::collections::BTreeSet;

        let ordinals: BTreeSet<u32> = probe_ordinal::ALL.into_iter().collect();
        assert_eq!(
            ordinals.len(),
            2,
            "`--version` and `--help`; this CLI answers no auth query — 2 processes, 2 identities"
        );
        assert_eq!(probe_ordinal::ALL.len(), 2);

        // And they really do render as 2 distinct identities of the packet's
        // third form, which is the property the ordinals exist for.
        let ids: BTreeSet<String> = probe_ordinal::ALL
            .into_iter()
            .map(|ordinal| {
                crate::runner::InvocationId::probe(
                    crate::runner::ProbeTarget::Agent(crate::runner::AgentId::new(ADAPTER_ID)),
                    ordinal,
                )
                .expect("the adapter id survives an invocation identity")
                .render()
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert!(
            ids.iter().all(|id| id.starts_with("p.agent-copilot.o")),
            "the probe form, naming this agent: {ids:?}"
        );
    }

    #[test]
    fn build_args_cover_the_programmatic_contract() {
        let joined = build_args(&task_run()).join(" ");
        assert!(joined.contains("-s"), "response only: {joined}");
        assert!(joined.contains("--no-ask-user"));
        assert!(joined.contains("--model=gpt-5.3-codex"));
        assert!(joined.contains("--effort=medium"));
        assert!(!joined.contains("--resume"), "no session to resume");
    }

    #[test]
    fn every_effort_has_the_exact_cli_spelling_in_build_args() {
        let expected = [
            (Effort::Low, "low"),
            (Effort::Medium, "medium"),
            (Effort::High, "high"),
            (Effort::XHigh, "xhigh"),
            (Effort::Max, "max"),
        ];
        for (effort, spelling) in expected {
            assert_eq!(effort_flag(effort), spelling);
            let mut run = task_run();
            run.profile.effort = Some(effort);
            assert!(
                build_args(&run)
                    .iter()
                    .any(|arg| arg == &format!("--effort={spelling}")),
                "{effort} must reach argv as {spelling}"
            );
        }
    }

    #[test]
    fn help_validation_requires_every_shared_effort_level() {
        let help = "-s --model --allow-tool --deny-tool --no-ask-user\n  \
                    --effort, --reasoning-effort <level> (choices: \"none\", \"minimal\", \
                    \"low\", \"medium\", \"high\", \"xhigh\", \"max\")\n";
        validate_help("1.0.78", help).expect("full shared vocabulary");

        for (missing, narrowed) in [
            ("xhigh", "none, minimal, low, medium, high, max"),
            ("max", "none, minimal, low, medium, high, xhigh"),
        ] {
            let help = format!(
                "-s --model --allow-tool --deny-tool --no-ask-user\n  --effort <level> \
                 (choices: {narrowed})\n"
            );
            let error = validate_help("1.0.78", &help).expect_err("narrow enum must refuse");
            let message = error.to_string();
            assert!(message.contains(missing), "{message}");
            assert!(message.contains("1.0.78"), "{message}");
        }
    }

    #[test]
    fn unreadable_help_is_a_preflight_refusal() {
        let mut timed_out = output(Some(0), "full help", "");
        timed_out.timed_out = true;
        assert!(
            checked_help("copilot", &timed_out)
                .expect_err("timeout")
                .to_string()
                .contains("could not be verified")
        );

        let failed = output(Some(2), "", "bad option");
        assert!(
            checked_help("copilot", &failed)
                .expect_err("nonzero")
                .to_string()
                .contains("bad option")
        );

        let empty = output(Some(0), "", "");
        assert!(
            checked_help("copilot", &empty)
                .expect_err("empty")
                .to_string()
                .contains("no output")
        );
    }

    #[test]
    fn the_prompt_travels_on_stdin_and_never_as_an_argument() {
        // GitHub documents that piped input is ignored when `-p` is given, so
        // passing both would send an empty task. Stdin is also the only
        // delivery a complete review prompt survives through a Windows cmd shim.
        let args = build_args(&task_run());
        assert!(
            !args.iter().any(|a| a == "-p" || a.starts_with("--prompt")),
            "`-p` would discard the piped prompt: {args:?}"
        );
        let run = task_run();
        assert_eq!(
            CopilotAdapter.stdin_payload(&run),
            "Do the thing.",
            "the prompt is delivered on stdin"
        );
    }

    #[test]
    fn edit_profiles_get_write_and_exactly_the_gate_commands() {
        let gates = vec![
            "cargo check --all-targets".to_owned(),
            "cargo test".to_owned(),
        ];
        let args = permission_args(&profile(PermissionMode::Edit), &gates);
        assert!(args.contains(&"--allow-tool=write".to_owned()));
        assert!(args.contains(&"--allow-tool=shell(cargo test)".to_owned()));
        assert!(args.contains(&"--allow-tool=shell(cargo check --all-targets)".to_owned()));
        assert!(
            !args.iter().any(|a| a == "--allow-tool=shell"),
            "no blanket shell: {args:?}"
        );
    }

    #[test]
    fn reviewers_may_neither_write_nor_run_anything() {
        // A reviewer that edits the code it is judging invalidates its own
        // verdict; one that runs commands is executing the diff under review.
        let args = permission_args(
            &profile(PermissionMode::ReadOnly),
            &["cargo test".to_owned()],
        );
        assert!(args.contains(&"--deny-tool=write".to_owned()));
        assert!(args.contains(&"--deny-tool=shell".to_owned()));
        assert!(
            !args.iter().any(|a| a.starts_with("--allow-tool")),
            "reviewers are granted nothing: {args:?}"
        );
    }

    #[test]
    fn no_profile_is_ever_handed_the_whole_machine() {
        // §20: the skip-all class of flags is never used, and no URL is ever
        // granted — that is what keeps an edit profile off the network.
        for permissions in [PermissionMode::Edit, PermissionMode::ReadOnly] {
            let mut run = task_run();
            run.profile = profile(permissions);
            let joined = build_args(&run).join(" ");
            for flag in SKIP_ALL_FLAGS {
                assert!(
                    !joined.contains(flag),
                    "{permissions:?} must never carry {flag}: {joined}"
                );
            }
        }
    }

    #[test]
    fn the_short_flag_check_is_not_fooled_by_longer_flags() {
        // A bare `contains("-s")` matches `--settings`, `--share` and `--stdio`,
        // so probing would pass on a build that had dropped `-s` — and every
        // attempt would then fail at runtime, which is the failure §16 says
        // probing exists to catch.
        assert!(!crate::agent::advertises_flag(
            "--settings <path>  --share <path>  --stdio",
            "-s"
        ));
        assert!(crate::agent::advertises_flag(
            "  -s, --silent    Suppress stats",
            "-s"
        ));
        assert!(crate::agent::advertises_flag(
            "  -s  Suppress stats and decoration",
            "-s"
        ));
        assert!(
            crate::agent::advertises_flag("-s=VALUE", "-s"),
            "trailing = is a value marker"
        );
        assert!(!crate::agent::advertises_flag("", "-s"));
    }

    #[test]
    fn a_turn_cap_is_not_quietly_pretended_to_apply() {
        // There is no `--max-turns` on this CLI. Nothing sets `max_turns`
        // today, so this pins the gap rather than the behaviour: whoever makes
        // profiles config-driven has to come here and decide.
        let mut run = task_run();
        // A digit that appears nowhere else in the args — model slugs carry
        // version numbers, so a cap of 3 would collide with `gpt-5.3-codex` and
        // the substitution check below would fail on the model rather than on a
        // turn cap that leaked.
        run.profile.max_turns = Some(7);
        let joined = build_args(&run).join(" ");
        assert!(
            !joined.contains("max-turns") && !joined.contains('7'),
            "no invented flag, and no silent substitution: {joined}"
        );
    }

    #[test]
    fn extra_args_are_appended_last() {
        let mut run = task_run();
        run.profile.extra_args = vec!["--add-dir=/srv/shared".to_owned()];
        assert!(
            build_args(&run)
                .join(" ")
                .ends_with("--add-dir=/srv/shared")
        );
    }

    #[test]
    fn a_successful_run_carries_its_response_as_the_detail() {
        // The reviewer's verdict travels in exactly this field on the SUCCESS
        // path — leaving it empty makes every review unparseable (step-6 #1).
        let verdict = "```json\n{\"pass\": true, \"reasons\": [\"ok\"]}\n```";
        let out = output(Some(0), &format!("  {verdict}  \n"), "");
        let outcome = parse_output(&out);
        assert_eq!(outcome.status, OutcomeStatus::Completed);
        assert_eq!(outcome.detail.as_deref(), Some(verdict));
        assert!(outcome.diff.is_empty(), "diff is engine-owned");
        // What the supervisor measured, carried through unchanged: see the
        // same assertion in the Claude adapter for why it is asserted at all.
        assert_eq!(outcome.duration, out.duration);
    }

    #[test]
    fn unreported_spend_is_none_rather_than_zero() {
        // This route has no JSON envelope. Recording 0.0 would tell the ledger
        // a frontier attempt was free (§13); None says it is unknown.
        let outcome = parse_output(&output(Some(0), "done", ""));
        assert_eq!(outcome.cost_usd, None);
        assert_eq!(outcome.session_id, None);
        assert!(outcome.usage.is_none());
    }

    #[test]
    fn failures_carry_a_reportable_detail() {
        let outcome = parse_output(&output(
            Some(1),
            "",
            "error: model `gpt-9` is not available",
        ));
        assert_eq!(outcome.status, OutcomeStatus::AgentError);
        assert_eq!(
            outcome.detail.as_deref(),
            Some("error: model `gpt-9` is not available")
        );

        // Falls back to stdout when the CLI reports through it instead.
        let outcome = parse_output(&output(Some(1), "I could not finish.", ""));
        assert_eq!(outcome.detail.as_deref(), Some("I could not finish."));

        // Nothing at all is still a reportable failure, not a pass.
        let outcome = parse_output(&output(Some(1), "", ""));
        assert_eq!(outcome.status, OutcomeStatus::AgentError);
        assert!(outcome.detail.is_none());
    }

    #[test]
    fn rate_limit_signals_win_over_exit_codes() {
        let outcome = parse_output(&output(
            Some(1),
            "",
            "You are out of credits for this month",
        ));
        assert_eq!(outcome.status, OutcomeStatus::RateLimited);

        let outcome = parse_output(&output(Some(1), "premium request allowance exhausted", ""));
        assert_eq!(outcome.status, OutcomeStatus::RateLimited);
    }

    #[test]
    fn a_successful_task_about_rate_limits_is_not_rate_limited() {
        // The agent's own summary mentioning 429s must not be read as the pool
        // being exhausted — that would roll back verified work.
        let outcome = parse_output(&output(
            Some(0),
            "Added backoff handling for HTTP 429 rate limit responses.",
            "",
        ));
        assert_eq!(outcome.status, OutcomeStatus::Completed);
    }

    #[test]
    fn timeout_maps_to_timeout_status() {
        let mut out = output(None, "", "");
        out.timed_out = true;
        assert_eq!(parse_output(&out).status, OutcomeStatus::Timeout);
    }

    // Runs only where the real CLI exists; skips silently elsewhere so CI
    // without the Copilot CLI stays green.
    #[test]
    fn probe_against_real_binary_when_present() {
        if locate().is_err() {
            eprintln!("copilot not on PATH; skipping live probe");
            return;
        }
        let caps = CopilotAdapter
            .probe(&crate::runner::host::HostRunner::new())
            .expect("probe should succeed");
        assert!(!caps.version.is_empty());
        assert!(!caps.cost_reporting, "this route reports no spend");
    }
}
