// tactus — headless orchestration engine for AI coding agents.
// Copyright (C) 2026 Cameron Lambert. Licensed under the GNU AGPL v3 only;
// see LICENSE, or <https://www.gnu.org/licenses/>. Commercial licences are
// available for use the AGPL does not permit — see README.md.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::io::{BufRead, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use tactus::answer::{self, Reply};
use tactus::capacity;
use tactus::connect;
use tactus::engine::{self, RunOutcome};
use tactus::error::TactusError;
use tactus::export::{self, Format as ExportFormat};
use tactus::interaction::{InteractionMode, RealSleeper};
use tactus::status;
use tactus::validate::{self, ValidateOptions};

/// §12: a run that ends with tasks parked on unanswered questions completed
/// neither cleanly nor in error. CI has to be able to tell the difference, so
/// it gets its own status.
const EXIT_PARKED: u8 = 2;

/// §13: a run stopped by its own budget completed neither cleanly, in error,
/// nor waiting on a human. CI has to tell "your ceiling stopped it" from "a task
/// failed" without parsing prose — and `tactus resume --budget` is what it does
/// about it, which is different from what it does about either of the others.
const EXIT_BUDGET: u8 = 3;

#[derive(Parser)]
#[command(name = "tactus", version, about = "Conductor for AI coding agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover installed agent CLIs and write ~/.tactus/pools.toml
    Connect {
        /// Replace an existing pools file that differs from what this would
        /// write. Without it, connect prints the difference and refuses.
        #[arg(long)]
        force: bool,
        /// Pools file path (default: ~/.tactus/pools.toml)
        #[arg(long)]
        pools: Option<PathBuf>,
    },
    /// Show every pool: remaining estimate, resets, and what each strategy would do
    Capacity {
        /// Repo config path (default: ./tactus.toml, optional)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Pools file path (default: ~/.tactus/pools.toml)
        #[arg(long)]
        pools: Option<PathBuf>,
    },
    /// Parse a plan, resolve routing, and print the task table (no execution)
    Validate {
        /// Path to the plan file (annotated or bare markdown)
        plan: PathBuf,
        /// Write plan.normalized.json (the IR) to the current directory
        #[arg(long)]
        emit_json: bool,
        /// Repo config path (default: ./tactus.toml, optional)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Execute a plan sequentially: run branch, agent per task, commit per task
    Run {
        /// Path to the plan file (annotated or bare markdown)
        plan: PathBuf,
        /// Everything except agents: parse, route, and print the preview at
        /// zero spend
        #[arg(long)]
        dry_run: bool,
        /// Repo config path (default: ./tactus.toml, optional)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override [interaction] mode; `never` is the CI setting — questions
        /// park their tasks and the run reports them instead of waiting
        #[arg(long, value_enum)]
        interaction: Option<Interaction>,
        /// Ceiling on api-equivalent dollars, overriding [budgets] run_usd.
        /// The run stops (exit 3) before the attempt that would cross it
        #[arg(long)]
        budget: Option<f64>,
    },
    /// Continue a run that was interrupted, parked, or stopped at its budget
    Resume {
        /// Run id, or any unambiguous prefix of one
        run_id: String,
        /// Repo config path (default: the one the run recorded)
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, value_enum)]
        interaction: Option<Interaction>,
        /// Raise the ceiling and continue. Budgets are re-derived at resume
        /// rather than inherited from the stopped run
        #[arg(long)]
        budget: Option<f64>,
    },
    /// Show a run: what happened, what it cost, and what it is waiting for
    Status {
        /// Run id or prefix; omit for the most recent run
        run_id: Option<String>,
        /// Stream events as they are appended, ending when the run finishes
        #[arg(long)]
        follow: bool,
    },
    /// Export one settled run's local routing decisions to stdout
    ExportDecisions {
        /// Run id, or any unambiguous prefix of one
        run_id: String,
        /// Output encoding (default: jsonl)
        #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl)]
        format: ExportFormat,
    },
    /// Answer a question a run is parked on (§12)
    Answer {
        /// Question id, or any unambiguous prefix of one
        question_id: String,
        /// Pick one of the question's numbered options
        #[arg(long, conflicts_with_all = ["text", "decline"])]
        option: Option<usize>,
        /// Answer in your own words
        #[arg(long, conflicts_with = "decline")]
        text: Option<String>,
        /// Give up on the task; its dependents will be blocked
        #[arg(long)]
        decline: bool,
    },
}

/// CLI spelling of [`InteractionMode`], so CI does not have to edit
/// `tactus.toml` to stop a run waiting on a human.
#[derive(Clone, Copy, ValueEnum)]
enum Interaction {
    Never,
    OnBlock,
    OnMilestone,
}

impl From<Interaction> for InteractionMode {
    fn from(value: Interaction) -> Self {
        match value {
            Interaction::Never => Self::Never,
            Interaction::OnBlock => Self::OnBlock,
            Interaction::OnMilestone => Self::OnMilestone,
        }
    }
}

/// Whether a command may reach a workspace effect, and therefore whether it
/// has to establish containment before it starts.
///
/// **Which commands are write commands is decided by the packet, not by this
/// file.** `decisions.sequential_substrate.startup_census`: the census is
///
/// > performed by every topology write command **(run, resume)** after taking
/// > the worktree lock and before any run-id use for creation, run-lock
/// > acquisition for a fresh run, slot or reservation initialization,
/// > admission, credential-volume use, or probe
///
/// and `crash_reconstruction` anchors the ambient job at the same coordinate:
/// "at process start **every write command** creates one non-inheritable
/// ambient Job Object … if the ambient job cannot be created or joined the
/// write command refuses at startup with a diagnostic **before any workspace
/// effect** (no degraded mode; deferred)". The parenthesis in the census is the
/// enumeration: a write command is `run` or `resume`.
///
/// For today's binary that is `Command::Run` and `Command::Resume`, and the
/// classification is by **dispatch arm**, so `run --dry-run` is a write command
/// too. That is deliberately one notch wider than "makes a workspace effect":
/// the packet's coordinate is *process start*, which precedes flag
/// interpretation, and a preview that shares an arm with the command that
/// spends should not be the one place containment is skipped. It is asserted
/// rather than left implicit (`the_dry_run_preview_is_classified_with_its_arm`).
///
/// `answer` writes a file into a run directory and `connect` writes the pools
/// file, but neither is a topology write command: neither drives a run, and the
/// census the packet anchors here is a *run's* census. `connect` and `capacity`
/// do spawn agent CLIs to discover them — two commands, counted and asserted in
/// `the_commands_that_spawn_outside_a_run_are_named_and_counted` — and those
/// children are outside INV-18's "the **coordinator's** ambient … Job Object",
/// because neither command is a coordinator of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandClass {
    /// A topology write command: it drives a run and must contain its children.
    Write,
    /// Everything else.
    ReadOnly,
}

/// The class of one parsed command.
///
/// Exhaustive with no wildcard arm: a `Command` variant added later fails to
/// compile here, so no command can join the dispatch without being classified.
const fn command_class(command: &Command) -> CommandClass {
    match command {
        Command::Run { .. } | Command::Resume { .. } => CommandClass::Write,
        Command::Connect { .. }
        | Command::Capacity { .. }
        | Command::Validate { .. }
        | Command::Status { .. }
        | Command::ExportDecisions { .. }
        | Command::Answer { .. } => CommandClass::ReadOnly,
    }
}

/// INV-18's host portion, as a capability rather than a call order.
///
/// > ambient job joined at write-command startup (refusal otherwise)
///
/// [`Contained`] has a private field, so nothing outside this module can build
/// one, and [`execute`] cannot be called without one. The contract's
/// `side_effect_vs_event_ordering` is "no events; ambient job before any
/// spawn", and that ordering is therefore a compile error to transpose rather
/// than a convention a later edit can quietly reverse.
mod containment {
    use super::{Command, CommandClass, command_class};
    use tactus::error::TactusError;

    /// Proof that this process performed its write-command containment
    /// startup. Unit-like with a private field: only [`establish`] can make
    /// one.
    pub struct Contained(());

    /// Establish containment for `command`, or refuse it.
    ///
    /// On Unix the join is a no-op that returns `Ok`: containment there is the
    /// per-invocation reaper and the isolated process group.
    pub fn establish(
        command: &Command,
        join_ambient_job: impl FnOnce() -> Result<(), TactusError>,
    ) -> anyhow::Result<Contained> {
        match command_class(command) {
            CommandClass::Write => join_ambient_job()?,
            CommandClass::ReadOnly => {}
        }
        Ok(Contained(()))
    }
}

use containment::Contained;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// One construction point so `validate` and `run --dry-run` can never drift
/// into previewing different things.
fn validate_options(plan: PathBuf, config: Option<PathBuf>) -> anyhow::Result<ValidateOptions> {
    Ok(ValidateOptions {
        plan_path: plan,
        config_path: config,
        config_root: std::env::current_dir().context("resolving current directory")?,
        pools_path: None,
        // Both callers are previewing a run that does not exist yet, so both
        // want the reading a fresh run gets — including its refusals.
        engine_limits: tactus::config::EngineLimits::Fresh,
    })
}

fn run() -> anyhow::Result<ExitCode> {
    // `NoHooks` is what production passes the process funnel, and the ambient
    // join is threaded the same way: the observer is there so the step has a
    // failure path a test can drive on the platform where it is real
    // (`tactus::runner::host::contain_write_command`), and production arms
    // nothing.
    run_wired(Cli::parse().command, &mut tactus::agent::proc::NoHooks)
}

/// The CLI's own composition of containment and dispatch — the two statements
/// `run` would otherwise hold, with the observer as a parameter.
///
/// It exists because `run` cannot be driven. `Cli::parse` reads this process's
/// real argv and exits on a parse error, so a test cannot call `run` with a
/// command of its choosing, and `run` was therefore the one link in
/// `expected_failures_refusals[1]`'s chain that nothing exercised.
/// `dispatch` is driven with an injected failure and
/// `runner::host::start_write_command` is driven with one on the guest — but
/// the **wiring between them** was a closure no test ever called, so
///
/// ```text
/// || { let _ = tactus::runner::host::start_write_command(&mut tactus::agent::proc::NoHooks); Ok(()) }
/// ```
///
/// left `tactus run … --dry-run` succeeding on a Windows host whose ambient job
/// could not be established, against the slice `scope`'s "refusal with
/// diagnostic if it cannot", with the whole suite green.
///
/// Threading the **observer** rather than the join closure is what makes the
/// difference: `start_write_command` is then inside the function under test
/// instead of inside its caller, and the arm `a_cli_write_command_refuses_when_
/// the_real_containment_step_refuses` drives it with a hook that refuses at
/// `Spawn.AmbientJobJoined`. What is left above it — `run`'s single delegating
/// expression — constructs no `Result` of its own, which is what
/// `the_cli_wires_the_real_containment_step_into_dispatch` reads the source to
/// assert.
fn run_wired(
    command: Command,
    hooks: &mut dyn tactus::agent::proc::SpawnHooks,
) -> anyhow::Result<ExitCode> {
    dispatch(command, || tactus::runner::host::start_write_command(hooks))
}

/// Establish containment, then execute. The ambient join is a parameter so a
/// test can drive a failure that no machine here can produce, and so the
/// ordering between the two is testable rather than merely written down.
fn dispatch(
    command: Command,
    join_ambient_job: impl FnOnce() -> Result<(), TactusError>,
) -> anyhow::Result<ExitCode> {
    let contained = containment::establish(&command, join_ambient_job)?;
    execute(command, contained)
}

fn execute(command: Command, _contained: Contained) -> anyhow::Result<ExitCode> {
    match command {
        Command::Connect { force, pools } => {
            let report = connect::run(&connect::ConnectOptions {
                pools_path: pools,
                force,
            })?;
            print!("{}", connect::render_report(&report));
            // A refusal to clobber is not something a retry fixes, and a script
            // that cannot tell it from success would go on to run against a
            // pools file that says something else entirely.
            if report.refused() {
                return Ok(ExitCode::FAILURE);
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Capacity { config, pools } => {
            let report = capacity::report(
                &capacity::CapacityOptions {
                    config_path: config,
                    pools_path: pools,
                    repo_root: std::env::current_dir().context("resolving current directory")?,
                },
                &engine::BuiltinAdapters,
            )?;
            print!("{}", report.render());
            Ok(ExitCode::SUCCESS)
        }
        Command::Validate {
            plan,
            emit_json,
            config,
        } => {
            let report = validate::run(&validate_options(plan, config)?)?;
            if emit_json {
                let path = PathBuf::from("plan.normalized.json");
                report
                    .write_normalized_json(&path)
                    .with_context(|| format!("writing {}", path.display()))?;
                println!("wrote {}", path.display());
            }
            print!("{}", report.render());
            Ok(ExitCode::SUCCESS)
        }
        Command::Run {
            plan,
            dry_run,
            config,
            interaction,
            budget,
        } => {
            if dry_run {
                let report = validate::run(&validate_options(plan, config)?)?;
                print!("{}", report.render());
                if let Some(budget) = budget {
                    println!(
                        "budget: ${budget:.2} would cap this run; nothing is spent in a dry run"
                    );
                }
                println!("dry run: no agents executed, nothing spent");
                return Ok(ExitCode::SUCCESS);
            }
            let repo_root = std::env::current_dir().context("resolving current directory")?;
            let mut opts = engine::RunOptions::new(plan, repo_root);
            opts.config_path = config;
            opts.interaction = interaction.map(Into::into);
            opts.budget_usd = budget;
            let report = engine::run(&opts)?;
            finish(&report)
        }
        Command::Resume {
            run_id,
            config,
            interaction,
            budget,
        } => {
            let repo_root = std::env::current_dir().context("resolving current directory")?;
            let mut opts = engine::ResumeOptions::new(run_id, repo_root);
            opts.config_path = config;
            opts.interaction = interaction.map(Into::into);
            opts.budget_usd = budget;
            let report = engine::resume(&opts)?;
            finish(&report)
        }
        Command::Status { run_id, follow } => {
            let repo_root = std::env::current_dir().context("resolving current directory")?;
            let run = status::load(&repo_root, run_id.as_deref())?;
            if follow {
                // History first, then live events: dropping a reader into the
                // middle of a run tells them less than showing how it got here.
                status::follow(
                    &run,
                    &RealSleeper,
                    Duration::from_millis(500),
                    IDLE_POLLS_BEFORE_GIVING_UP,
                    &mut std::io::stdout(),
                )?;
                // Re-read: the run has moved since the summary would have been
                // computed, and the closing summary is the useful one.
                let settled = status::load(&repo_root, Some(&run.run_id))?;
                print!("{}", status::render(&settled));
            } else {
                print!("{}", status::render(&run));
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::ExportDecisions { run_id, format } => {
            let repo_root = std::env::current_dir().context("resolving current directory")?;
            let loaded = export::load(&repo_root, &run_id)?;
            for warning in loaded.warnings {
                eprintln!("warning: {warning}");
            }
            export::write(&loaded.rows, format, &mut std::io::stdout())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Answer {
            question_id,
            option,
            text,
            decline,
        } => {
            let repo_root = std::env::current_dir().context("resolving current directory")?;
            let reply = match (option, text, decline) {
                (_, _, true) => Reply::Decline,
                (Some(choice), _, _) => Reply::Option(choice),
                (_, Some(text), _) => Reply::Text(text),
                // Nothing given: show the question and read one line, so the
                // common case is `tactus answer <id>` and then just type.
                (None, None, false) => Reply::Text(prompt_for_answer(&repo_root, &question_id)?),
            };
            let recorded = answer::answer(&repo_root, &question_id, reply)?;
            println!(
                "recorded an answer to {} on run {}",
                recorded.question_id, recorded.run_id
            );
            if recorded.run_is_live {
                println!("that run is live; it will pick this up and un-park the task");
            } else {
                println!(
                    "continue the run with:\n    tactus resume {}",
                    recorded.run_id
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// How long a follower keeps watching a run that nothing is driving any more:
/// roughly two minutes. A live run holds its lock and `follow` waits on that
/// for as long as an agent turn takes, so this budget is not a limit on
/// silence — it starts only once the lock is gone, and exists so a terminal
/// attached to a dead engine does not hang.
const IDLE_POLLS_BEFORE_GIVING_UP: u32 = 240;

fn finish(report: &engine::RunReport) -> anyhow::Result<ExitCode> {
    print!("{}", report.render());
    match report.outcome() {
        RunOutcome::Complete => Ok(ExitCode::SUCCESS),
        // §12: parked is neither clean nor broken. Distinguishable so CI can
        // gate on it without parsing prose.
        RunOutcome::Parked => Ok(ExitCode::from(EXIT_PARKED)),
        // §13: nor is a budget stop. It is not an error — the run did exactly
        // what the ceiling asked — so it does not `bail`, and the report above
        // already printed the resume command that continues it.
        RunOutcome::BudgetExceeded => Ok(ExitCode::from(EXIT_BUDGET)),
        RunOutcome::Halted => anyhow::bail!(
            "run halted at task `{}`",
            report.halted_at.as_deref().unwrap_or("?")
        ),
    }
}

/// Show the question, then take the operator's answer.
fn prompt_for_answer(repo_root: &std::path::Path, question_id: &str) -> anyhow::Result<String> {
    eprint!("{}", answer::show(repo_root, question_id)?);
    let stdin = std::io::stdin();
    let mut line = String::new();
    if stdin.is_terminal() {
        // Enter submits — what the legend promises, and the only thing a
        // person typing at a prompt will try. Reading to end here would wait
        // for EOF instead (Ctrl+D, or Ctrl+Z then Enter on Windows), so
        // pressing Enter would leave the command sitting there saying nothing.
        eprint!("answer (a number picks an option, empty aborts): ");
        stdin
            .lock()
            .read_line(&mut line)
            .context("reading an answer from stdin")?;
    } else {
        // Piped: read to end so an answer can span lines. The interpreter
        // trims and treats the whole thing as the operator's words.
        stdin
            .lock()
            .take(64 * 1024)
            .read_to_string(&mut line)
            .context("reading an answer from stdin")?;
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::CommandFactory;

    use super::*;

    /// Every subcommand this binary dispatches, with an invocation that parses
    /// and the class the packet gives it.
    ///
    /// Written here by hand from `decisions.sequential_substrate.startup_census`
    /// ("every topology write command (run, resume)"), so it is an oracle
    /// independent of [`command_class`]. A command added to the enum without
    /// being added here fails
    /// [`every_dispatch_arm_is_classified_by_the_packets_rule`] — the list that
    /// rots is replaced by a list that is checked.
    const DISPATCH: &[(&str, &[&str], CommandClass)] = &[
        ("connect", &["tactus", "connect"], CommandClass::ReadOnly),
        ("capacity", &["tactus", "capacity"], CommandClass::ReadOnly),
        (
            "validate",
            &["tactus", "validate", "plan.md"],
            CommandClass::ReadOnly,
        ),
        ("run", &["tactus", "run", "plan.md"], CommandClass::Write),
        (
            "resume",
            &["tactus", "resume", "01ABCDEF"],
            CommandClass::Write,
        ),
        ("status", &["tactus", "status"], CommandClass::ReadOnly),
        (
            "export-decisions",
            &["tactus", "export-decisions", "01ABCDEF"],
            CommandClass::ReadOnly,
        ),
        (
            "answer",
            &["tactus", "answer", "q1", "--decline"],
            CommandClass::ReadOnly,
        ),
    ];

    /// A plan path that exists on no machine, so the dispatch arm that reads it
    /// fails in a way nothing else produces.
    const ABSENT_PLAN: &str = "/tactus-pr4-no-such-plan-33f1a9/plan.md";

    /// The whole point of the table: a new subcommand cannot reach the dispatch
    /// without a classification, and cannot be classified in production without
    /// being classified here too.
    #[test]
    fn every_dispatch_arm_is_classified_by_the_packets_rule() {
        let declared: BTreeSet<String> = Cli::command()
            .get_subcommands()
            .map(|sub| sub.get_name().to_owned())
            .collect();
        let tabled: BTreeSet<String> = DISPATCH
            .iter()
            .map(|(name, _, _)| (*name).to_owned())
            .collect();
        assert_eq!(
            declared, tabled,
            "the dispatch and this table name different commands"
        );
        assert_eq!(declared.len(), 8, "eight subcommands");
        assert_eq!(DISPATCH.len(), 8, "eight rows, one per subcommand");

        for (name, argv, expected) in DISPATCH {
            let cli = Cli::try_parse_from(*argv)
                .unwrap_or_else(|error| panic!("`{name}` does not parse from {argv:?}: {error}"));
            assert_eq!(
                command_class(&cli.command),
                *expected,
                "`{name}` is classified against the packet's rule"
            );
        }

        let writes: Vec<&str> = DISPATCH
            .iter()
            .filter(|(_, _, class)| *class == CommandClass::Write)
            .map(|(name, _, _)| *name)
            .collect();
        assert_eq!(
            writes,
            vec!["run", "resume"],
            "the census names the write commands: `every topology write command (run, resume)`"
        );
        assert_eq!(
            DISPATCH
                .iter()
                .filter(|(_, _, class)| *class == CommandClass::ReadOnly)
                .count(),
            6
        );
    }

    /// The classification is by dispatch arm, so the preview shares the class
    /// of the command it previews. Stated in `command_class`, asserted here, so
    /// the widening cannot become invisible.
    #[test]
    fn the_dry_run_preview_is_classified_with_its_arm() {
        let dry = Cli::try_parse_from(["tactus", "run", "plan.md", "--dry-run"]).expect("parse");
        assert_eq!(command_class(&dry.command), CommandClass::Write);
        let wet = Cli::try_parse_from(["tactus", "run", "plan.md"]).expect("parse");
        assert_eq!(command_class(&wet.command), CommandClass::Write);
    }

    /// The two commands that spawn a host child outside a run, counted so the
    /// boundary cannot grow in silence. `connect` and `capacity` both probe the
    /// installed agent CLIs (`connect.rs:133`, `capacity.rs:840`); neither
    /// drives a run, so neither is the "coordinator" whose ambient job INV-18
    /// names.
    #[test]
    fn the_commands_that_spawn_outside_a_run_are_named_and_counted() {
        let outside: Vec<&str> = DISPATCH
            .iter()
            .filter(|(name, _, _)| matches!(*name, "connect" | "capacity"))
            .map(|(name, _, _)| *name)
            .collect();
        assert_eq!(outside, vec!["connect", "capacity"]);
        assert_eq!(outside.len(), 2, "two commands, and this is the count");
        for name in &outside {
            let row = DISPATCH
                .iter()
                .find(|(n, _, _)| n == name)
                .expect("a named command is in the table");
            assert_eq!(row.2, CommandClass::ReadOnly);
        }
    }

    /// A refused ambient join stops the write command **before** its arm runs.
    ///
    /// The oracle is that the two outcomes are different errors from different
    /// places: the refusal names the ambient job, and the arm — reached only
    /// when the join succeeds — names the plan it could not read. If
    /// containment ran after the arm, or not at all, the first call would carry
    /// the plan's error instead.
    #[test]
    fn a_write_command_refuses_before_any_effect_when_containment_fails() {
        let argv = ["tactus", "run", ABSENT_PLAN, "--dry-run"];

        let refused = dispatch(Cli::try_parse_from(argv).expect("parse").command, || {
            Err(TactusError::Refused {
                message: "the ambient Job Object could not be established (simulated failure)"
                    .to_owned(),
            })
        })
        .expect_err("a write command whose ambient job cannot be established must refuse");
        let refused = format!("{refused:#}");
        assert!(
            refused.contains("ambient Job Object"),
            "the refusal must diagnose the ambient job: {refused}"
        );
        assert!(
            !refused.contains(ABSENT_PLAN),
            "the command reached its arm before containment: {refused}"
        );

        let reached = dispatch(Cli::try_parse_from(argv).expect("parse").command, || Ok(()))
            .expect_err("the arm then fails on its own, on the plan");
        let reached = format!("{reached:#}");
        assert!(
            reached.contains(ABSENT_PLAN),
            "with containment established the arm must run: {reached}"
        );
        assert!(
            !reached.contains("ambient Job Object"),
            "a successful join must not be reported as a refusal: {reached}"
        );
    }

    /// **Every** write command joins, and every read-only command does not.
    ///
    /// `crash_reconstruction`: "at process start **every write command**
    /// creates one non-inheritable ambient Job Object"; the contract's
    /// `side_effect_vs_event_ordering` is "no events; ambient job before any
    /// spawn". The two tests below drive `dispatch` with one command each —
    /// `run --dry-run` and two read-only arms — so a containment step
    /// conditioned on *which* write command it is (a wet `run`, a `resume`)
    /// would keep every one of their assertions true while the two commands
    /// that actually spend went unprotected: killed between `CreateProcess`
    /// and private-job assignment, they leave a suspended stub with no owner,
    /// and a real ambient failure could not produce the required startup
    /// refusal.
    ///
    /// So this crosses `establish` — the classification's one consumer — with
    /// every row of [`DISPATCH`] plus the dry-run preview, and asserts the
    /// **count** of joins on each side. `establish` rather than `dispatch`
    /// because it is the mutation site and because running the wet arms would
    /// execute a run.
    #[test]
    fn every_write_command_establishes_containment_and_no_read_only_one_does() {
        let mut argvs: Vec<(Vec<&str>, CommandClass)> = DISPATCH
            .iter()
            .map(|(_, argv, class)| (argv.to_vec(), *class))
            .collect();
        // The preview shares its arm's class, and the arm is what joins.
        argvs.push((
            vec!["tactus", "run", "plan.md", "--dry-run"],
            CommandClass::Write,
        ));
        assert_eq!(argvs.len(), 9, "eight subcommands and the dry-run preview");

        let mut joined = 0_usize;
        let mut skipped = 0_usize;
        for (argv, class) in &argvs {
            let command = Cli::try_parse_from(argv).expect("parse").command;
            let mut calls = 0_usize;
            let contained = containment::establish(&command, || {
                calls += 1;
                Ok(())
            });
            assert!(
                contained.is_ok(),
                "a successful join must not refuse {argv:?}"
            );
            match class {
                CommandClass::Write => {
                    assert_eq!(calls, 1, "{argv:?} did not join the ambient job");
                    joined += 1;
                }
                CommandClass::ReadOnly => {
                    assert_eq!(calls, 0, "{argv:?} joined the ambient job");
                    skipped += 1;
                }
            }

            // And the refusal is per command, not per class: a write command
            // whose join fails refuses, a read-only one cannot fail because it
            // never calls it.
            let command = Cli::try_parse_from(argv).expect("parse").command;
            let outcome = containment::establish(&command, || {
                Err(TactusError::Refused {
                    message: "the ambient Job Object could not be established (simulated)"
                        .to_owned(),
                })
            });
            assert_eq!(
                outcome.is_err(),
                *class == CommandClass::Write,
                "{argv:?}: a failed join must stop exactly the write commands"
            );
        }
        assert_eq!(joined, 3, "`run`, `resume`, and the dry-run preview");
        assert_eq!(skipped, 6, "the six read-only subcommands");
    }

    /// The CLI's own wiring: `run_wired` composes the **real** containment step
    /// with `dispatch`, on every platform.
    ///
    /// `a_write_command_refuses_before_any_effect_when_containment_fails` drives
    /// `dispatch` with a join of the test's choosing, so it says nothing about
    /// which join the CLI passes it; `runner::host`'s own tests drive
    /// `start_write_command` directly, so they say nothing about who calls it.
    /// This is the composition, and the oracle is production's own count:
    /// `containment_establishments()` is incremented by `Contained::new`, which
    /// only `contain_write_command` reaches and only after
    /// `proc::join_ambient_job` returned `Ok`. So a `run_wired` that passed
    /// `|| Ok(())` instead of the real step — or that never established
    /// containment at all — cannot move it.
    #[test]
    fn the_cli_write_path_runs_the_real_containment_step() {
        use tactus::runner::host::containment_establishments;

        let before = containment_establishments();
        let write = Cli::try_parse_from(["tactus", "run", ABSENT_PLAN, "--dry-run"])
            .expect("parse")
            .command;
        let reached = run_wired(write, &mut tactus::agent::proc::NoHooks)
            .expect_err("the arm then fails on its own, on the plan");
        assert_eq!(
            containment_establishments(),
            before + 1,
            "the CLI's write path did not establish containment through the real step"
        );
        // And it established it *before* the arm ran, which is what the count
        // alone cannot say: the error the caller receives is the plan's.
        let reached = format!("{reached:#}");
        assert!(
            reached.contains(ABSENT_PLAN),
            "with containment established the arm must run: {reached}"
        );

        // The other side of the classification, through the same wiring.
        let mark = containment_establishments();
        let read_only = Cli::try_parse_from(["tactus", "validate", ABSENT_PLAN])
            .expect("parse")
            .command;
        let _ = run_wired(read_only, &mut tactus::agent::proc::NoHooks);
        assert_eq!(
            containment_establishments(),
            mark,
            "a read-only command established the coordinator's containment"
        );
    }

    /// And the refusal reaches the caller through that same wiring, on the
    /// platform where the join can fail.
    ///
    /// This is the arm that kills the finding's mutation. `run_wired` threading
    /// the **observer** is what makes it possible: with a hook armed to refuse
    /// at `Spawn.AmbientJobJoined`, a body that discarded
    /// `start_write_command`'s error and answered `Ok(())` would let the
    /// dry-run preview reach its arm and fail on the *plan* instead of refusing
    /// with the ambient job's diagnostic — which is
    /// `expected_failures_refusals[1]` not holding for the CLI.
    ///
    /// Windows-only because the step it drives is: `proc::join_ambient_job` is
    /// a no-op on Unix that never consults the observer, deliberately, so a
    /// Linux cell cannot claim this coverage — the same boundary
    /// `PR4-CONF-005` records for `contain_write_command`.
    #[cfg(windows)]
    #[test]
    fn a_cli_write_command_refuses_when_the_real_containment_step_refuses() {
        use tactus::agent::proc::SpawnHooks;
        use tactus::topology::effects::{Injection, SubEffectPoint};

        struct RefuseAmbientJoin;
        impl SpawnHooks for RefuseAmbientJoin {
            fn point(&mut self, point: SubEffectPoint) -> Injection {
                if point == SubEffectPoint::AmbientJobJoined {
                    Injection::Error
                } else {
                    Injection::Proceed
                }
            }
        }

        let write = Cli::try_parse_from(["tactus", "run", ABSENT_PLAN, "--dry-run"])
            .expect("parse")
            .command;
        let refused = run_wired(write, &mut RefuseAmbientJoin)
            .expect_err("a CLI write command whose ambient join refuses must refuse");
        let refused = format!("{refused:#}");
        // The same three fragments `runner::host::tests::the_production_
        // containment_mint_propagates_a_join_refusal_and_mints_nothing` reads,
        // and for its reason: what the operator has to be told is that it is
        // the ambient job, which invariant it enforces, and that nothing ran.
        // Named fragments rather than the whole sentence, and rather than the
        // `SubEffectPoint` token — the refusal the CLI hands back is
        // production's own diagnostic (`proc::AMBIENT_REFUSAL_PREFIX` +
        // `AMBIENT_REFUSAL_SIMULATED`), not the funnel's internal coordinate.
        for fragment in ["ambient", "INV-18", "No process was spawned"] {
            assert!(
                refused.contains(fragment),
                "the CLI's refusal must say `{fragment}`: {refused}"
            );
        }
        assert!(
            !refused.contains(ABSENT_PLAN),
            "the CLI reached its arm although containment refused: {refused}"
        );
    }

    /// `run` itself cannot fabricate a success, because it constructs no value.
    ///
    /// The runtime tests above hold everything from `run_wired` down. `run` is
    /// the one link above them that no test can call — `Cli::parse` reads this
    /// process's real argv — so it is held the way this project already holds
    /// claims of exactly this shape: by reading the source
    /// (`runner::tests::every_production_process_start_is_classified`,
    /// `every_production_runner_request_is_built_by_its_roles_builder`).
    ///
    /// The oracle is narrow on purpose. Both functions are pure delegations,
    /// so neither has any reason to write an `Ok`; a body that swallowed the
    /// call below it — `let _ = run_wired(…); Ok(ExitCode::SUCCESS)` — has to
    /// construct one. And `start_write_command` must be named exactly once in
    /// the file, inside `run_wired`, so the step cannot be called somewhere
    /// that discards it and called again where a test can see it.
    #[test]
    fn the_cli_wires_the_real_containment_step_into_dispatch() {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
        )
        .expect("read this file");
        // Line endings are the checkout's, not the repository's: the Windows
        // guest checks this file out with CRLF, and a census that split on
        // `"\n#[cfg(test)]\n"` found nothing there and read the test module as
        // production. Normalised first, so the oracle is the source and not the
        // platform that happens to be reading it — the same class as
        // `PR4-CI-ENVIRONMENT-ASSUMPTIONS`, and caught by the same guest.
        let source = source.replace("\r\n", "\n");
        let production = source
            .split("\n#[cfg(test)]\n")
            .next()
            .expect("the production region");
        assert!(
            production.len() < source.len(),
            "the split found no test module, so this census is reading the whole file"
        );

        // Comments are not code, and this census would otherwise be the exact
        // hazard `reviews/FINDINGS.md` records as `PR4-CENSUS-COMMENT-ORACLE`:
        // `run_wired`'s doc comment quotes the mutation it exists to kill, and
        // a source count that read it would make the doc and the code
        // indistinguishable. The rule is deliberately simple — everything from
        // a `//` that is not part of a `://` — and it is checked, below,
        // against a line this file is known to carry.
        let code: String = production
            .lines()
            .map(|line| {
                match line
                    .match_indices("//")
                    .find(|(at, _)| *at == 0 || !line[..*at].ends_with(':'))
                {
                    Some((at, _)) => &line[..at],
                    None => line,
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("let _ = tactus::runner::host::start_write_command"),
            "the comment strip left a doc comment's text in the code region"
        );

        assert_eq!(
            code.matches("start_write_command(").count(),
            1,
            "the CLI names the containment step more than once, so one of the calls is \
             somewhere no test drives"
        );

        for name in ["fn run() -> anyhow::Result<ExitCode> {", "fn run_wired("] {
            let start = code
                .find(name)
                .unwrap_or_else(|| panic!("`{name}` is gone from src/main.rs"));
            let body = &code[start..];
            let end = body.find("\n}\n").expect("the function ends");
            let body = &body[..end];
            assert!(
                !body.contains("Ok("),
                "`{name}` constructs a Result of its own; it is a delegation, and the only \
                 reason to write one is to answer success without asking: {body}"
            );
            if name.starts_with("fn run()") {
                assert!(
                    body.contains("run_wired("),
                    "`run` no longer goes through the wiring the tests drive: {body}"
                );
            }
        }
    }

    /// A read-only command never joins. The oracle is a join that cannot be
    /// called without failing the test.
    #[test]
    fn a_read_only_command_does_not_join_the_ambient_job() {
        for argv in [
            vec!["tactus", "validate", ABSENT_PLAN],
            vec!["tactus", "capacity", "--config", ABSENT_PLAN],
        ] {
            let command = Cli::try_parse_from(&argv).expect("parse").command;
            assert_eq!(command_class(&command), CommandClass::ReadOnly);
            let outcome = dispatch(command, || {
                panic!("a read-only command joined the ambient job: {argv:?}")
            });
            assert!(
                outcome.is_err(),
                "the fixture relies on this arm failing on its own input"
            );
        }
    }

    /// Where the ambient-latch helper writes what it observed.
    #[cfg(windows)]
    const AMBIENT_LATCH_RECORD: &str = "TACTUS_PR4_CLI_LATCH_RECORD";

    /// The child half of
    /// [`a_write_command_establishes_the_ambient_job_and_a_read_only_command_does_not`]:
    /// it drives the CLI's real wiring and records the process-wide latch at
    /// three points, leaving the judgement to its parent.
    ///
    /// It records rather than asserts because the parent's output is where a
    /// developer reads a failure — this child's streams are closed — and
    /// because the record is also the evidence that the child ran at all. Each
    /// observation is flushed as it is taken, so a panic still leaves what was
    /// seen up to it.
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess helper"]
    fn cli_ambient_latch_helper() {
        fn note(stage: &str, record: &std::path::Path, observed: &mut Vec<String>) {
            observed.push(format!(
                "{stage} {}",
                i32::from(tactus::agent::proc::ambient_job_established())
            ));
            std::fs::write(record, observed.join("\n")).expect("record the observation");
        }

        let Some(record) = std::env::var_os(AMBIENT_LATCH_RECORD) else {
            return;
        };
        let record = PathBuf::from(record);
        let mut observed = Vec::new();
        note("start", &record, &mut observed);

        // `run_wired` rather than `dispatch` with a join of our own: it is the
        // composition `run` uses, so the child exercises the CLI's real path to
        // the join instead of a reassembly of it.
        let read_only = Cli::try_parse_from(["tactus", "validate", ABSENT_PLAN])
            .expect("parse")
            .command;
        let _ = run_wired(read_only, &mut tactus::agent::proc::NoHooks);
        note("read-only", &record, &mut observed);

        let write = Cli::try_parse_from(["tactus", "run", ABSENT_PLAN, "--dry-run"])
            .expect("parse")
            .command;
        let _ = run_wired(write, &mut tactus::agent::proc::NoHooks);
        note("write", &record, &mut observed);
    }

    /// The real join, at the real coordinate, on the platform that has one.
    ///
    /// In a subprocess because the ambient job is a process-wide singleton and
    /// this binary's tests run in **threads**: "not yet established" is a fact
    /// about a process, so a test that reads it in a shared one is reading its
    /// siblings too. Held in-process, none of the three readings below was an
    /// observation of this test's own commands:
    /// `the_cli_write_path_runs_the_real_containment_step` drives a write
    /// command through the same real step on another thread, and whichever
    /// reading it lands between is the one that fails — before the first,
    /// "nothing has run a write command in this process yet"; between the first
    /// and the second, "a read-only command established the coordinator's
    /// ambient job". Neither is what happened. Measured on the guest at one
    /// failure in three full-suite runs when it was first seen and one in six
    /// when it was diagnosed. The other tests here are immune for a reason that
    /// does not extend to this one: they read `containment_establishments`, a
    /// **thread-local** count, as a delta around their own call.
    ///
    /// So the oracle is unchanged — the real process-wide latch, not a
    /// thread-local proxy, because the property is that the *process* joins —
    /// and what changes is who observes it: a child with its own latch, running
    /// exactly one test (`--ignored` plus a filter naming one helper), which no
    /// sibling thread can reach.
    ///
    /// The premise stays checked rather than assumed. `start 0` is asserted here
    /// as loudly as the two observations that depend on it, because a child that
    /// somehow began with the latch set would make them vacuous. And the record
    /// file is the evidence the child ran: a libtest filter that matches nothing
    /// exits 0, so a parent that read only the exit status would pass with no
    /// child at all.
    #[cfg(windows)]
    #[test]
    fn a_write_command_establishes_the_ambient_job_and_a_read_only_command_does_not() {
        let record = std::env::temp_dir().join(format!(
            "tactus-pr4-cli-ambient-latch-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&record);
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["cli_ambient_latch_helper", "--ignored", "--nocapture"])
            .env(AMBIENT_LATCH_RECORD, &record)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn the ambient-latch helper");
        let written = std::fs::read_to_string(&record).ok();
        let _ = std::fs::remove_file(&record);
        assert!(
            status.success(),
            "the ambient-latch helper died; it had recorded {written:?}"
        );
        let written = written.unwrap_or_else(|| {
            panic!(
                "the helper wrote nothing to {}: it exited 0 without running, which is what a \
                 libtest filter that matches no test does",
                record.display()
            )
        });
        let observed: Vec<&str> = written.lines().collect();
        assert_eq!(
            observed,
            vec!["start 0", "read-only 0", "write 1"],
            "the child's latch at three points: `start 0` or this test's premise is gone and the \
             rest of it says nothing; `read-only 0` or a read-only command established the \
             coordinator's ambient job; `write 1` or a write command ran without joining it \
             (INV-18)"
        );
    }
}
