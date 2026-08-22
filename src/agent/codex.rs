//! OpenAI Codex CLI adapter (DESIGN.md §16) — a second pool, and a reviewer
//! from a different model family that costs nothing on the first one.
//!
//! §13's capacity engine is built around several subscriptions with independent
//! windows, and until this adapter there was one that tactus could actually
//! drive on its own: Copilot reaches OpenAI models, but through GitHub's
//! harness and GitHub's billing.
//!
//! **Implementing works where the sandbox is real, and only there.** This
//! CLI's sandbox is an external helper, present on Linux and absent on
//! Windows — so on Windows `exec` silently degrades to read-only and
//! [`refuse_edit_profile`] turns an implementer away at build time rather than
//! letting it spend attempts on empty diffs. On Linux the same flags write
//! inside the workspace and are blocked outside it, which is what §20 asks
//! for, so the implementer path is open. The evidence for both lives on that
//! function.
//!
//! The judge's seat works everywhere: `read-only` is enforced on every
//! platform, the family is genuinely different from Anthropic's (§11.3), and a
//! review that spends nothing on the Claude window is worth having on its own —
//! measured end to end on run `01KZRN48A4ZK3AEDST3RJ8HMA4`, where Sonnet
//! implemented and this adapter judged.
//!
//! **Two command shapes, not one with a flag swapped.** `codex exec` and
//! `codex exec resume` accept *different* flag sets: resume takes no `-s`, no
//! `-C`, no `--profile`. That is not a gap to work around. The sandbox is a
//! property of the session, fixed when it is created and inherited by every
//! resumed turn — which is exactly tactus's model, where a same-rung retry has
//! the same profile by definition (§11.4). Observed 2026-08-11 against
//! codex-cli 0.147.0: a resume with no sandbox flag ran under the policy its
//! session recorded.
//!
//! **The prompt goes on stdin, as `-`.** Windows caps a command line at ~8,191
//! characters and a review prompt carries up to
//! [`crate::review::MAX_DIFF_BYTES`] of diff, so argv was never an option. The
//! CLI also *waits* on stdin when it expects input ("Reading additional input
//! from stdin…"), so the payload must always be written and the pipe always
//! closed — [`super::proc`] does both, and an adapter that returned an empty
//! payload here would hang every attempt until the wall-clock timeout.
//!
//! **stdout is JSONL, stderr is tracing.** `--json` emits one event per line —
//! `thread.started`, `turn.started`, `item.started`, `item.completed`,
//! `turn.completed` — while stderr carries `ERROR codex_api::…` log lines.
//! Only stdout is parsed; stderr survives in the transcript for whoever is
//! debugging.
//!
//! **What this route reports, and what it does not.** A session id worth
//! resuming (`thread_id`), the final message, and token usage — but no
//! dollars. Tokens are recorded on the attempt and `cost_reporting` stays
//! false, so the ledger keeps saying `?` for these routes rather than
//! inventing a price. Pricing them here would mean a rate table inside a
//! published binary, going stale silently, to produce a figure that is
//! notional twice over on subscription auth where the marginal dollar is zero.
//! §13 already has the words: an estimate that flatters is worse than none.
//!
//! **Two of this CLI's own features are deliberately unused for model turns.**
//!
//! `codex review` runs a code review non-interactively, and adopting it would
//! swap the standard. §11.3's second opinion is *the same standard, a
//! different judge*: tactus's review prompt carries the task's acceptance
//! criteria, the anti-sycophancy framing, the `DATA UNDER REVIEW` fencing and
//! the operator's decisions (§12). A verdict from OpenAI's own rubric applied
//! to a bare diff is not comparable with one from the Claude reviewer, and a
//! cross-family disagreement between them would be uninterpretable — the model
//! disagreeing, or the rubric? Reviews therefore run through plain `exec` with
//! `-s read-only`, like every other reviewer. This adapter cannot even tell it
//! is reviewing; it sees [`PermissionMode::ReadOnly`] and nothing else, and
//! that is the right amount to know.
//!
//! `--output-schema` would force the model's final message into a JSON shape,
//! which is tempting for §7 verdicts — but it would make a third copy of the
//! verdict shape (prompt, parser, schema) that can drift, hold two reviewers to
//! two different contracts, and push the reviewer's prose into escaped strings
//! where humans read it. The existing re-ask-on-unparseable path already covers
//! the failure it would prevent, and nothing has yet measured that failure
//! happening. Revisit if real runs show it firing more than rarely. Pre-flight
//! does pass a deliberately missing schema path to the CLI's local parser; that
//! is a zero-spend guard proving the exact reasoning key before any model turn,
//! not an output contract for a turn.
//!
//! **Never passed:** `--dangerously-bypass-approvals-and-sandbox`,
//! `--dangerously-bypass-hook-trust`, `-s danger-full-access`. §20 grants the
//! narrowest surface that lets the work happen, and there is no task for which
//! the answer is "turn the sandbox off". `--ephemeral` is also never passed —
//! it would discard the session that §11.4's same-rung retry resumes.
//!
//! Surface captured from `codex --help`, `codex exec --help` and
//! `codex exec resume --help` at 0.147.0, and verified by running it.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use super::bin::{self, Invocation};
use super::proc::ProcessOutput;
use super::{
    AdapterSource, AgentAdapter, AuthState, Caps, Discovery, TaskRun, looks_rate_limited,
    probe_request,
};
use crate::capacity::PoolKind;
use crate::catalog;
use crate::error::TactusError;
use crate::ir::{Effort, Outcome, OutcomeStatus, PermissionMode, Usage, WorkerProfile};
use crate::runner::{CommandSpec, Runner};
use crate::util;

pub const ADAPTER_ID: &str = "codex";

/// Budget for one probe call. Generous for the same reason Copilot's is: §19
/// makes a probe failure a refusal to START, so a slow machine that times out
/// here loses a whole run rather than one attempt. Paid once per run.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// The strict-config control must be rejected before the missing-schema guard.
/// If it is not, a CLI has stopped enforcing the parser contract this probe
/// relies on and an apparently successful effort-key check would mean nothing.
const CONFIG_PROBE_UNKNOWN_KEY: &str = "tactus_probe_deliberately_unknown";
const CONFIG_PROBE_SCHEMA_FILE: &str = "tactus-output-schema-must-not-exist.json";
const CONFIG_PROBE_RESUME_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Flags `exec` must still advertise, checked at pre-flight.
///
/// Every one is load-bearing rather than decorative: without `--json` there is
/// no session id and no usage, and without `--sandbox` a reviewer could edit
/// the code it is judging. A CLI that has dropped one of these must refuse the
/// run up front, not fail attempts once it is already spending (§19).
const REQUIRED_EXEC_FLAGS: [&str; 5] = ["--json", "--sandbox", "--model", "-c", "--config"];
const REQUIRED_RESUME_FLAGS: [&str; 4] = ["--json", "--model", "-c", "--config"];

/// Which of this adapter's pre-flight processes each identity is.
///
/// Named rather than counted, for the reason [`super::probe_request`] gives —
/// and this is the adapter that makes the reason concrete. Binary resolution
/// here *spawns*, once per PATH candidate, and it caches: the second
/// `probe()` in one process performs none of those spawns. A counter would
/// therefore renumber every capability step on the second call, and two
/// pre-flights of one machine would mint different identities for the same
/// work.
///
/// Two blocks, which is what keeps a variable-length step from colliding with
/// a fixed one:
///
/// * `0 .. RESOLUTION_BASE` — the capability probe and discovery, one named
///   ordinal per step, in the order they run.
/// * `RESOLUTION_BASE ..` — one per PATH candidate tested for usability, in
///   PATH order. Unbounded in principle (one candidate per PATH entry per
///   name), which is exactly why it may not share a block with the fixed
///   steps.
mod probe_ordinal {
    pub const VERSION: u32 = 0;
    pub const EXEC_HELP: u32 = 1;
    pub const RESUME_HELP: u32 = 2;
    /// The six strict-config parser probes: two surfaces x
    /// {unknown-key control, xhigh, max}. `CONFIG_BASE + surface * 3 + step`.
    pub const CONFIG_BASE: u32 = 3;
    pub const CONFIG_PER_SURFACE: u32 = 3;
    pub const PROBE_MODELS: u32 = 9;
    pub const LOGIN_STATUS: u32 = 10;
    pub const DISCOVER_MODELS: u32 = 11;
    /// Where the per-PATH-candidate block starts.
    pub const RESOLUTION_BASE: u32 = 1_000;
    /// Every fixed ordinal above, for the uniqueness assertion.
    #[cfg(test)]
    pub const ALL: [u32; 12] = [
        VERSION,
        EXEC_HELP,
        RESUME_HELP,
        CONFIG_BASE,
        CONFIG_BASE + 1,
        CONFIG_BASE + 2,
        CONFIG_BASE + CONFIG_PER_SURFACE,
        CONFIG_BASE + CONFIG_PER_SURFACE + 1,
        CONFIG_BASE + CONFIG_PER_SURFACE + 2,
        PROBE_MODELS,
        LOGIN_STATUS,
        DISCOVER_MODELS,
    ];
}

#[derive(Debug, Deserialize)]
struct DebugModels {
    models: Vec<DebugModel>,
}

#[derive(Debug, Deserialize)]
struct DebugModel {
    slug: String,
    #[serde(default)]
    supported_reasoning_levels: Vec<DebugReasoningLevel>,
}

#[derive(Debug, Deserialize)]
struct DebugReasoningLevel {
    effort: String,
}

pub struct CodexAdapter;

impl AgentAdapter for CodexAdapter {
    fn id(&self) -> &'static str {
        ADAPTER_ID
    }

    fn probe(&self, runner: &dyn Runner) -> Result<Caps, TactusError> {
        let invocation = locate(runner)?;
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

        // Fresh and resumed attempts are different CLI surfaces. Both carry
        // the reasoning override, so both must prove `--config` before spend;
        // only fresh attempts carry the sandbox.
        let fresh_help = runner.run(&probe_request(
            ADAPTER_ID,
            invocation.spec(&["exec".to_owned(), "--help".to_owned()])?,
            probe_ordinal::EXEC_HELP,
            PROBE_TIMEOUT,
        )?)?;
        let fresh_help = checked_help(&invocation.display(), "exec", &fresh_help)?;
        let resume_help = runner.run(&probe_request(
            ADAPTER_ID,
            invocation.spec(&["exec".to_owned(), "resume".to_owned(), "--help".to_owned()])?,
            probe_ordinal::RESUME_HELP,
            PROBE_TIMEOUT,
        )?)?;
        let resume_help = checked_help(&invocation.display(), "exec resume", &resume_help)?;
        validate_probe_contract(&version, &fresh_help, &resume_help)?;
        validate_effort_config_key(runner, &invocation, &version)?;

        // The strict local parser above proves the exact key and the two role
        // policy values. The CLI's local catalog is separate zero-spend
        // evidence for each model × effort pair, so require every known Codex
        // model to expose every shared effort level before a run can start.
        let models = runner.run(&probe_request(
            ADAPTER_ID,
            invocation.spec(&["debug".to_owned(), "models".to_owned()])?,
            probe_ordinal::PROBE_MODELS,
            PROBE_TIMEOUT,
        )?)?;
        let models = checked_model_catalog(&invocation.display(), &models)?;
        let parsed = parse_debug_models(&models)?;
        validate_model_efforts(&version, &parsed)?;

        Ok(Caps {
            version,
            // Asked for and parsed, unlike Copilot's route where the flag's
            // existence would promise an envelope no caller reads.
            json_output: true,
            // `codex exec resume <id>` — proven to round-trip: the resumed turn
            // returned the same `thread_id` and recalled the prior exchange.
            session_resume: true,
            // Tokens, not dollars. See the module header — this is a decision
            // about what tactus is willing to claim, not a missing feature.
            cost_reporting: false,
            read_only_mode: true,
            // The CLI has `mcp-server` and `app-server`, neither of which is
            // ACP, and this adapter spawns a process per attempt either way.
            acp: false,
            // `debug models` is a local catalog rather than a network query;
            // probe validated it above and discovery exposes its slugs.
            model_list: true,
        })
    }

    fn build(&self, run: &TaskRun) -> Result<CommandSpec, TactusError> {
        if let Some(refusal) = edit_refusal(&run.profile) {
            return Err(refusal);
        }
        // The working root comes from the process, not from `-C`: `exec resume`
        // has no `-C`, and one mechanism that works for both shapes beats two
        // that have to agree. It is now the *runner's* cwd
        // (`RunnerRequest.workspace`) rather than one this adapter set, which
        // is DESIGN.md:118's split and changes nothing about the mechanism.
        //
        // `resolved()` rather than `locate()`: `build` is data-only and may
        // not spawn, so it never runs the PATH-candidate usability probe.
        resolved()?.spec(&build_args(run))
    }

    fn parse(&self, out: &ProcessOutput) -> Result<Outcome, TactusError> {
        Ok(parse_output(out))
    }

    /// The one thing this CLI does better than either incumbent: it answers
    /// "am I signed in?" without spending anything.
    ///
    /// `codex login status` is non-interactive, exits 0 either way, and prints
    /// `Logged in using ChatGPT` or `Not logged in` (observed 2026-08-11).
    /// Copilot's adapter has to report [`AuthState::Unknown`] because GitHub
    /// documents no such query; here the honest answer is a real one, so
    /// `tactus connect` writes a pool an operator can trust rather than a
    /// shrug.
    fn discover(&self, runner: &dyn Runner, _caps: &Caps) -> Result<Discovery, TactusError> {
        let invocation = locate(runner)?;
        let out = runner.run(&probe_request(
            ADAPTER_ID,
            invocation.spec(&["login".to_owned(), "status".to_owned()])?,
            probe_ordinal::LOGIN_STATUS,
            PROBE_TIMEOUT,
        )?)?;
        let mut discovery = parse_login_status(&out);
        let models = runner.run(&probe_request(
            ADAPTER_ID,
            invocation.spec(&["debug".to_owned(), "models".to_owned()])?,
            probe_ordinal::DISCOVER_MODELS,
            PROBE_TIMEOUT,
        )?)?;
        let models = checked_model_catalog(&invocation.display(), &models)?;
        discovery.models = parse_debug_models(&models)?
            .models
            .into_iter()
            .map(|model| model.slug)
            .collect();
        Ok(discovery.with_note(
            "model slugs and reasoning levels were confirmed against this CLI's local `debug \
             models` catalog",
        ))
    }

    /// Nothing to reference — permissions are argv here, as they are for
    /// Copilot — but the audit file is still written, because §15 calls
    /// `settings/<task>-<attempt>.json` the per-attempt permission surface and
    /// a trail that exists for one agent and silently not another is worse than
    /// none.
    fn materialize_permissions(
        &self,
        profile: &WorkerProfile,
        _gate_cmds: &[String],
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
                "note": "recorded for audit only; codex takes its sandbox as an argv flag",
                "sandbox": sandbox_mode(profile),
            }),
        )?;
        Ok(None)
    }
}

fn checked_help(
    program: &str,
    surface: &str,
    output: &ProcessOutput,
) -> Result<String, TactusError> {
    if output.output_limited {
        return Err(TactusError::Agent {
            message: format!(
                "`{program} {surface} --help` exceeded the output limit; reasoning configuration support could not be verified"
            ),
        });
    }
    if output.timed_out {
        return Err(TactusError::Agent {
            message: format!(
                "`{program} {surface} --help` timed out; reasoning configuration support could \
                 not be verified"
            ),
        });
    }
    if output.code != Some(0) {
        return Err(TactusError::Agent {
            message: format!(
                "`{program} {surface} --help` exited with {:?}: {}",
                output.code,
                output.stderr.trim()
            ),
        });
    }
    let text = format!("{}\n{}", output.stdout, output.stderr);
    if text.trim().is_empty() {
        return Err(TactusError::Agent {
            message: format!(
                "`{program} {surface} --help` returned no output; reasoning configuration \
                 support could not be verified"
            ),
        });
    }
    Ok(text)
}

fn validate_probe_contract(
    version: &str,
    fresh_help: &str,
    resume_help: &str,
) -> Result<(), TactusError> {
    for (surface, help, required) in [
        ("exec", fresh_help, REQUIRED_EXEC_FLAGS.as_slice()),
        ("exec resume", resume_help, REQUIRED_RESUME_FLAGS.as_slice()),
    ] {
        let missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|flag| !super::advertises_flag(help, flag))
            .collect();
        if !missing.is_empty() {
            return Err(TactusError::Agent {
                message: format!(
                    "codex {version} does not advertise required `{surface}` flag(s): {}. The \
                     reasoning override must work on both fresh and resumed attempts — upgrade \
                     tactus or pin an older codex.",
                    missing.join(", ")
                ),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum ConfigProbeSurface {
    Fresh,
    Resume,
}

impl ConfigProbeSurface {
    fn label(self) -> &'static str {
        match self {
            Self::Fresh => "exec",
            Self::Resume => "exec resume",
        }
    }

    /// Which surface this is, so its three parser probes get their own block
    /// of invocation ordinals.
    const fn index(self) -> u32 {
        match self {
            Self::Fresh => 0,
            Self::Resume => 1,
        }
    }
}

/// A unique empty directory whose child path is guaranteed not to exist.
/// Codex validates `--output-schema` locally before starting a turn, making
/// that absent child a deterministic, zero-spend stopping point.
struct MissingOutputSchema {
    dir: PathBuf,
    path: PathBuf,
}

impl MissingOutputSchema {
    fn create() -> Result<Self, TactusError> {
        let dir =
            std::env::temp_dir().join(format!("tactus-codex-config-probe-{}", crate::ulid::ulid()));
        std::fs::create_dir(&dir).map_err(|source| TactusError::Agent {
            message: format!(
                "could not create Codex configuration probe directory `{}`: {source}",
                dir.display()
            ),
        })?;
        let path = dir.join(CONFIG_PROBE_SCHEMA_FILE);
        Ok(Self { dir, path })
    }
}

impl Drop for MissingOutputSchema {
    fn drop(&mut self) {
        // The child is intentionally never created. Avoid recursive cleanup:
        // if a surprising CLI did write anything, preserving it is safer than
        // deleting an unexpected artifact.
        let _ = std::fs::remove_dir(&self.dir);
    }
}

fn validate_effort_config_key(
    runner: &dyn Runner,
    invocation: &Invocation,
    version: &str,
) -> Result<(), TactusError> {
    let schema = MissingOutputSchema::create()?;
    for surface in [ConfigProbeSurface::Fresh, ConfigProbeSurface::Resume] {
        let base = probe_ordinal::CONFIG_BASE + surface.index() * probe_ordinal::CONFIG_PER_SURFACE;
        let control = run_config_parser_probe(
            runner,
            invocation,
            surface,
            &format!("{CONFIG_PROBE_UNKNOWN_KEY}=true"),
            &schema.path,
            base,
        )?;
        validate_unknown_config_control(version, surface, &control)?;

        // These are the two policy values Tactus promises for the roles this
        // feature introduced. Model catalogs validate the remaining shared
        // values separately; accepting either assignment here proves the exact
        // key, while checking both catches a provider-side enum regression.
        for (step, effort) in [Effort::XHigh, Effort::Max].into_iter().enumerate() {
            let assignment = format!("model_reasoning_effort={}", effort_flag(effort));
            let output = run_config_parser_probe(
                runner,
                invocation,
                surface,
                &assignment,
                &schema.path,
                base + 1 + u32::try_from(step).unwrap_or(u32::MAX),
            )?;
            validate_effort_config_probe(version, surface, effort, &output)?;
        }
    }
    Ok(())
}

fn run_config_parser_probe(
    runner: &dyn Runner,
    invocation: &Invocation,
    surface: ConfigProbeSurface,
    assignment: &str,
    schema_path: &std::path::Path,
    ordinal: u32,
) -> Result<ProcessOutput, TactusError> {
    runner.run(&probe_request(
        ADAPTER_ID,
        invocation.spec(&config_probe_args(surface, assignment, schema_path))?,
        ordinal,
        PROBE_TIMEOUT,
    )?)
}

fn config_probe_args(
    surface: ConfigProbeSurface,
    assignment: &str,
    schema_path: &std::path::Path,
) -> Vec<String> {
    let mut args = vec!["exec".to_owned()];
    if matches!(surface, ConfigProbeSurface::Resume) {
        args.extend(["resume".to_owned(), CONFIG_PROBE_RESUME_ID.to_owned()]);
    }
    args.extend([
        "--ignore-user-config".to_owned(),
        "--strict-config".to_owned(),
        "-c".to_owned(),
        assignment.to_owned(),
        "--output-schema".to_owned(),
        schema_path.to_string_lossy().into_owned(),
        "tactus-config-parser-probe".to_owned(),
    ]);
    args
}

fn validate_unknown_config_control(
    version: &str,
    surface: ConfigProbeSurface,
    output: &ProcessOutput,
) -> Result<(), TactusError> {
    if output.output_limited {
        return Err(TactusError::Agent {
            message: format!(
                "codex {version} `{}` strict-config control exceeded the output limit; truncated output cannot prove local parser behavior",
                surface.label()
            ),
        });
    }
    let text = config_probe_text(output);
    let lower = text.to_ascii_lowercase();
    if !output.timed_out
        && output.code.is_some_and(|code| code != 0)
        && text.contains(CONFIG_PROBE_UNKNOWN_KEY)
        && (lower.contains("unknown") || lower.contains("unrecognized"))
        && !text.contains(CONFIG_PROBE_SCHEMA_FILE)
    {
        return Ok(());
    }
    Err(TactusError::Agent {
        message: format!(
            "codex {version} `{}` did not reject the strict-config control before the local \
             missing-schema guard; exact reasoning-key support cannot be proven without spend \
             (exit {:?}, timeout {}, output: {})",
            surface.label(),
            output.code,
            output.timed_out,
            util::head(&text, 400)
        ),
    })
}

fn validate_effort_config_probe(
    version: &str,
    surface: ConfigProbeSurface,
    effort: Effort,
    output: &ProcessOutput,
) -> Result<(), TactusError> {
    if output.output_limited {
        return Err(TactusError::Agent {
            message: format!(
                "codex {version} `{}` reasoning-key probe exceeded the output limit; truncated output cannot prove `model_reasoning_effort={}`",
                surface.label(),
                effort_flag(effort)
            ),
        });
    }
    let text = config_probe_text(output);
    if !output.timed_out
        && output.code.is_some_and(|code| code != 0)
        && text.contains(CONFIG_PROBE_SCHEMA_FILE)
        && text.to_ascii_lowercase().contains("schema")
    {
        return Ok(());
    }
    Err(TactusError::Agent {
        message: format!(
            "codex {version} `{}` did not accept exact local override \
             `model_reasoning_effort={}` before the zero-spend missing-schema guard (exit {:?}, \
             timeout {}, output: {})",
            surface.label(),
            effort_flag(effort),
            output.code,
            output.timed_out,
            util::head(&text, 400)
        ),
    })
}

fn config_probe_text(output: &ProcessOutput) -> String {
    format!("{}\n{}", output.stdout, output.stderr)
}

fn checked_model_catalog(program: &str, output: &ProcessOutput) -> Result<String, TactusError> {
    if output.timed_out {
        return Err(TactusError::Agent {
            message: format!(
                "`{program} debug models` timed out; model effort support could not be verified"
            ),
        });
    }
    if output.code != Some(0) {
        return Err(TactusError::Agent {
            message: format!(
                "`{program} debug models` exited with {:?}: {}",
                output.code,
                output.stderr.trim()
            ),
        });
    }
    if output.stdout.trim().is_empty() {
        return Err(TactusError::Agent {
            message: format!(
                "`{program} debug models` returned no catalog; model effort support could not be \
                 verified"
            ),
        });
    }
    Ok(output.stdout.clone())
}

fn parse_debug_models(text: &str) -> Result<DebugModels, TactusError> {
    serde_json::from_str(text).map_err(|error| TactusError::Agent {
        message: format!("`codex debug models` returned an unreadable catalog: {error}"),
    })
}

fn validate_model_efforts(version: &str, models: &DebugModels) -> Result<(), TactusError> {
    for slug in catalog::known_models(ADAPTER_ID) {
        let model = models
            .models
            .iter()
            .find(|model| model.slug == slug)
            .ok_or_else(|| TactusError::Agent {
                message: format!(
                    "codex {version}'s local model catalog does not contain known model `{slug}`; \
                     refusing before a configured `--model` fails at runtime"
                ),
            })?;
        let supported: Vec<Effort> = model
            .supported_reasoning_levels
            .iter()
            .filter_map(|level| Effort::parse(&level.effort))
            .collect();
        let missing: Vec<Effort> = Effort::ALL
            .into_iter()
            .filter(|effort| !supported.contains(effort))
            .collect();
        if !missing.is_empty() {
            return Err(TactusError::Agent {
                message: format!(
                    "codex {version} model `{slug}` does not advertise required reasoning \
                     level(s): {}. Refusing before `model_reasoning_effort` can fail an attempt.",
                    missing
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }
    Ok(())
}

/// This CLI's name for a tier-neutral effort level.
///
/// One-to-one today, and a function rather than a `Display` impl because that
/// is the adapter's job: the mapping belongs on this side of the seam where a
/// vendor can differ without the engine learning about it. Every value below
/// is in the provider's validated enum (`low, medium, high, xhigh, max` plus
/// `none` and `minimal`) — checked against the 400 it returns for anything else.
fn effort_flag(effort: Effort) -> &'static str {
    match effort {
        Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::XHigh => "xhigh",
        Effort::Max => "max",
    }
}

/// The sandbox this profile runs under (§20).
///
/// Two modes and no third: `danger-full-access` exists on this CLI and is
/// never used. A reviewer may read and nothing else, because a reviewer that
/// edits the code it is judging has invalidated its own verdict.
fn sandbox_mode(profile: &WorkerProfile) -> &'static str {
    match profile.permissions {
        PermissionMode::Edit => "workspace-write",
        PermissionMode::ReadOnly => "read-only",
    }
}

/// Why an implementer is refused **on Windows only**, and what was measured.
///
/// This CLI's sandbox is an external helper. `codex doctor` reports it as
/// `linux helper: <path>` where one exists and `none` on Windows — where there
/// is therefore nothing to enforce a boundary with. The consequence is a rule
/// the binary states itself:
///
/// > `approval_policy = "never"` cannot be used because requirements do not
/// > allow `sandbox_mode = "danger-full-access"`; Codex would fall back to
/// > read-only permissions with approvals disabled.
///
/// `exec` is non-interactive, so it forces `never`. With no enforceable
/// sandbox that degrades to read-only, and `--sandbox workspace-write` is
/// *accepted and then ignored*: exit 0, no warning, no diff. The silence is the
/// dangerous part — run `01KZRMHA28M5CM88VAXP613X9P` spent both attempts on
/// empty diffs and parked asking for write access it had been granted.
/// `-c approval_policy="on-request"` and `-c permission_profile="…"` were both
/// tried; `exec` wins.
///
/// The only mode that writes there is `--approve-for-me`, which routes
/// approvals through an automatic reviewer rather than a human — and it is not
/// a sandbox. Asked to write outside the repository it did so, and
/// `sandbox_workspace_write.writable_roots` did not constrain it. §20 grants
/// permission by mechanism, not by asking an LLM nicely, and §14's rollback is
/// `git clean -fd` *inside* the workspace: anything written outside it survives
/// a failed attempt, which is the one thing the design rules out.
///
/// **On Linux the sandbox is real and none of this applies.** Same CLI, same
/// flags, helper present: `--sandbox workspace-write` writes inside the
/// workspace and is *blocked* outside it — both measured. So the refusal is
/// scoped to the platform that cannot enforce it, and the implementer path is
/// open everywhere else.
///
/// One trap worth recording for whoever containerises this: Docker's default
/// seccomp profile blocks the syscalls the sandbox needs to initialise, and the
/// failure is a *different* message ("the workspace sandbox failed to
/// initialize") with the same empty-diff result. Granting
/// `--security-opt seccomp=unconfined --cap-add SYS_ADMIN` let it initialise;
/// which of the two is strictly required was not isolated.
/// The platform gate, kept out of [`AgentAdapter::build`] so it is testable on
/// a machine with no codex installed — the same reason [`build_args`] is its
/// own function.
fn edit_refusal(profile: &WorkerProfile) -> Option<TactusError> {
    (cfg!(windows) && profile.permissions == PermissionMode::Edit)
        .then(|| refuse_edit_profile(profile))
}

fn refuse_edit_profile(profile: &WorkerProfile) -> TactusError {
    TactusError::Refused {
        message: format!(
            "codex cannot run `{}` as an implementer on Windows: this CLI's sandbox is an \
             external helper that does not exist here (`codex doctor` reports `linux helper: \
             none`), so `codex exec` degrades to read-only — it accepts `--sandbox \
             workspace-write` and then writes nothing, with no error. Its only writing mode \
             (`--approve-for-me`) auto-approves writes anywhere on the filesystem, including \
             outside the repository, which §14's rollback cannot undo. Run codex under Linux \
             where its sandbox is enforced, or route implementation to another agent and keep \
             codex as a reviewer — its read-only sandbox works everywhere, and its different \
             model family is the point (§11.3).",
            profile.name
        ),
    }
}

/// Argument list, kept separate from binary resolution so it is testable on a
/// machine with no CLI installed.
///
/// Two shapes, because the CLI has two. A fresh attempt sets the sandbox that
/// the session will carry; a resumed one inherits it and would be rejected for
/// passing `-s` at all (observed: exit 2, "unexpected argument '-s' found").
pub fn build_args(run: &TaskRun) -> Vec<String> {
    let mut args = vec!["exec".to_owned()];
    if let Some(session) = &run.resume_session {
        args.push("resume".to_owned());
        args.push(session.clone());
    }
    args.push("--json".to_owned());
    // Passed on both shapes even though a resumed session already knows its
    // model: the recorded command should say what it ran on without a reader
    // having to open the session file, and a future change to the CLI's
    // default must not silently move a resumed retry to another model.
    args.push("--model".to_owned());
    args.push(run.profile.model.clone());
    // Effort, for exactly the reason the model is passed above — and this axis
    // had the bug that argument was written to prevent. This CLI's default
    // comes from the *provider's* roster, not from the flag set: `gpt-5.6-sol`
    // carries `default_reasoning_level: low`, so every review this project ran
    // before this line existed was judged at the lowest setting, silently, and
    // a roster refresh could move it again without a release. Passed on the
    // resumed shape too: `-c` is accepted there (measured — unlike `-s`, which
    // is rejected), and a retry must not think harder or less hard than the
    // attempt it is continuing.
    if let Some(effort) = run.profile.effort {
        args.push("-c".to_owned());
        args.push(format!("model_reasoning_effort={}", effort_flag(effort)));
    }
    if run.resume_session.is_none() {
        args.push("--sandbox".to_owned());
        args.push(sandbox_mode(&run.profile).to_owned());
    }
    args.extend(run.profile.extra_args.iter().cloned());
    // `-` is "read the prompt from stdin" and must be last: everything after it
    // would be taken as the prompt's own arguments.
    args.push("-".to_owned());
    args
}

/// Outcome parsing over the JSONL event stream.
///
/// Defensive throughout, like every other adapter here: a line that is not JSON
/// is skipped rather than failing the attempt, and a missing field degrades the
/// status instead of panicking. The engine owns `diff` and `transcript_path`.
fn parse_output(out: &ProcessOutput) -> Outcome {
    let mut outcome = Outcome {
        status: OutcomeStatus::AgentError,
        diff: String::new(),
        detail: None,
        session_id: None,
        usage: None,
        cost_usd: None,
        transcript_path: PathBuf::new(),
        duration: out.duration,
    };

    let mut message: Option<String> = None;
    let mut errors: Vec<String> = Vec::new();
    let mut usage: Option<Usage> = None;

    for line in out.stdout.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(event): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        match event.get("type").and_then(Value::as_str) {
            Some("thread.started") => {
                outcome.session_id = event
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            Some("item.completed") => {
                let item = event.get("item");
                let is_message = item
                    .and_then(|i| i.get("type"))
                    .and_then(Value::as_str)
                    .is_some_and(|t| t == "agent_message");
                if is_message {
                    // Last one wins: the final message is the agent's answer,
                    // and it is the field a reviewer's verdict travels in.
                    message = item
                        .and_then(|i| i.get("text"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
            }
            Some("turn.completed") => {
                // Summed rather than replaced. One invocation emitted exactly
                // one of these, tool call and all (measured), so this is
                // defence against a future version that reports per step —
                // where taking the last would quietly under-count.
                usage = Some(add_usage(usage, event.get("usage")));
            }
            Some("error") => {
                if let Some(text) = event.get("message").and_then(Value::as_str) {
                    errors.push(text.to_owned());
                }
            }
            _ => {}
        }
    }
    outcome.usage = usage;

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

    if out.code == Some(0) {
        outcome.status = OutcomeStatus::Completed;
        outcome.detail = message;
        return outcome;
    }

    // Failures only — a successful task *about* rate limiting must never read
    // as the pool being exhausted (see `looks_rate_limited`).
    let joined = errors.join("\n");
    outcome.status = if looks_rate_limited(&joined) || looks_rate_limited(&out.stderr) {
        OutcomeStatus::RateLimited
    } else {
        OutcomeStatus::AgentError
    };
    // The `error` events first: on this route stderr is a tracing log, so the
    // event stream carries the diagnostic a human actually wants. An
    // unauthenticated run exits 101 with 401s here, which is an agent error
    // and not a rate limit — a distinction the ladder acts on.
    outcome.detail = [
        (!joined.is_empty()).then(|| util::tail(&joined, 2000)),
        message,
        (!out.stderr.trim().is_empty()).then(|| util::tail(out.stderr.trim(), 2000)),
    ]
    .into_iter()
    .flatten()
    .next();
    outcome
}

/// Fold one `turn.completed`'s usage into the running total.
///
/// `reasoning_output_tokens` is a *subset* of `output_tokens` on this CLI, not
/// an addition to it, so it is carried across rather than added in — summing
/// both would double-count the thinking.
fn add_usage(total: Option<Usage>, reported: Option<&Value>) -> Usage {
    let mut total = total.unwrap_or_default();
    let Some(reported) = reported else {
        return total;
    };
    let field = |name: &str| reported.get(name).and_then(Value::as_u64);
    let add = |slot: &mut Option<u64>, value: Option<u64>| {
        if let Some(value) = value {
            *slot = Some(slot.unwrap_or(0) + value);
        }
    };
    add(&mut total.input_tokens, field("input_tokens"));
    add(&mut total.output_tokens, field("output_tokens"));
    // Vendor names differ; the concepts line up. `cached_input_tokens` is a
    // read from the cache, `cache_write_input_tokens` is a write into it.
    add(
        &mut total.cache_read_input_tokens,
        field("cached_input_tokens"),
    );
    add(
        &mut total.cache_creation_input_tokens,
        field("cache_write_input_tokens"),
    );
    add(
        &mut total.reasoning_output_tokens,
        field("reasoning_output_tokens"),
    );
    // One `turn.completed` is one turn, so this counts them for free.
    total.num_turns = Some(total.num_turns.unwrap_or(0) + 1);
    total
}

/// Read `codex login status`, as defensively as everything else here.
///
/// Observed forms (0.147.0): `Not logged in`, and `Logged in using ChatGPT`.
/// The negative is checked first because it contains the positive as a
/// substring — matching "logged in" first would call a signed-out account
/// signed in, which is the one error `AuthState` exists to prevent.
fn parse_login_status(out: &ProcessOutput) -> Discovery {
    let mut discovery = Discovery::unknown();
    if out.timed_out {
        return discovery.with_note("`codex login status` timed out; auth state unknown");
    }
    let text = format!("{}{}", out.stdout, out.stderr).to_ascii_lowercase();
    if text.contains("not logged in") || text.contains("not authenticated") {
        discovery.auth = AuthState::NotAuthenticated;
        return discovery.with_note("`codex login status` reports no stored credentials");
    }
    if !text.contains("logged in") {
        return discovery.with_note(format!(
            "`codex login status` said something this adapter does not recognise: {}",
            util::head(text.trim(), 120)
        ));
    }
    discovery.auth = AuthState::Authenticated;
    // §13's two billing shapes. A ChatGPT plan is a rate-limit window; an API
    // key is metered dollars. Anything else is left for the caller's documented
    // default rather than guessed at.
    if text.contains("chatgpt") {
        discovery.shape = Some(PoolKind::SubscriptionWindow);
        discovery = discovery.with_note(
            "signed in through a ChatGPT plan, so this pool is a rate-limit window rather than \
             metered dollars",
        );
    } else if text.contains("api key") {
        discovery = discovery.with_note(
            "signed in with an API key; the pool kind below is a default rather than something \
             detected",
        );
    }
    discovery
}

// ---------------------------------------------------------------------------
// Binary discovery — npm ships this as codex.cmd on Windows, which
// CreateProcess cannot exec directly; `super::bin` owns the mechanics.
// ---------------------------------------------------------------------------

fn candidate_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["codex.exe", "codex.cmd", "codex.bat"]
    } else {
        &["codex"]
    }
}

static RESOLVED: OnceLock<Option<Invocation>> = OnceLock::new();

/// Resolve the binary, spawning through `runner` to test each candidate.
///
/// The pre-flight path. Windows Store can put a package payload on PATH that
/// is visible to filesystem lookup but returns access denied when spawned, so
/// each candidate is tested before the answer is cached and a later npm shim
/// in the real PATH order can still win. That test is an agent CLI process
/// like any other, so it goes through the Runner too — one identity per
/// candidate, from `probe_ordinal::RESOLUTION_BASE` in PATH order.
fn locate(runner: &dyn Runner) -> Result<Invocation, TactusError> {
    locate_in(runner, &RESOLVED, candidate_names())
}

/// [`locate`] over the cache and the candidate names it consults.
///
/// Both are parameters for the reason the process funnel takes an observer:
/// the ordinal this loop hands each candidate is **computed**, not declared, so
/// `every_preflight_process_has_its_own_ordinal`'s table cannot speak for it —
/// and driving the real [`RESOLVED`] would spend the process's one memoised
/// answer and change what every sibling test in the binary resolves
/// (`4631a3f`'s class). Production passes [`RESOLVED`] and
/// [`candidate_names`], here and nowhere else.
fn locate_in(
    runner: &dyn Runner,
    cache: &OnceLock<Option<Invocation>>,
    names: &[&str],
) -> Result<Invocation, TactusError> {
    let mut candidate_index = 0u32;
    bin::locate_with(
        names,
        cache,
        |candidate| {
            let ordinal = probe_ordinal::RESOLUTION_BASE + candidate_index;
            candidate_index += 1;
            // A candidate whose path cannot be carried in a `CommandSpec` is
            // simply not usable, and PATH order continues past it: this is the
            // one place where refusing the whole run would be wrong, because
            // the next entry may hold a perfectly ordinary installation.
            candidate
                .spec(&["--version".to_owned()])
                .and_then(|spec| probe_request(ADAPTER_ID, spec, ordinal, PROBE_TIMEOUT))
                .and_then(|request| runner.run(&request))
                .is_ok_and(|output| !output.timed_out && output.code == Some(0))
        },
        missing_codex,
    )
}

/// Resolve the binary **without spawning anything**.
///
/// What `build` uses, because `build` is data-only (DESIGN.md:117) and a
/// `build` that spawned would be carrying a process decision past the Runner —
/// the precise hole `CommandSpec` closes. It shares [`RESOLVED`] with
/// [`locate`], so once pre-flight has resolved and cached a usable binary this
/// returns exactly that one; the engine always probes before it builds
/// (`preflight::prepare` runs before any attempt), which
/// `engine::tests::the_legacy_engine_routes_every_process_through_the_runner`
/// witnesses by ordering. Resolving first here — only reachable outside a
/// run — takes the first PATH candidate without testing it.
fn resolved() -> Result<Invocation, TactusError> {
    bin::locate(candidate_names(), &RESOLVED, missing_codex)
}

fn missing_codex(tried: &[&str]) -> String {
    format!(
        "no usable codex binary found on PATH (looked for {}); install the OpenAI Codex CLI \
         (`npm install -g @openai/codex`) or adjust PATH",
        tried.join(", ")
    )
}

/// Registry entry, so `by_id("codex")` resolves without this module being
/// reached through the concrete type.
impl AdapterSource for CodexAdapter {
    fn get(&self, id: &str) -> Option<&dyn AgentAdapter> {
        (id == ADAPTER_ID).then_some(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::ir::WorkerProfile;

    /// Flags that would hand the agent the machine. §20 says none is ever
    /// passed, so the list exists to be asserted against.
    const FORBIDDEN: [&str; 4] = [
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-bypass-hook-trust",
        "danger-full-access",
        "--ephemeral",
    ];

    fn profile(permissions: PermissionMode) -> WorkerProfile {
        WorkerProfile {
            name: "small-gpt-5.6-sol".to_owned(),
            agent: ADAPTER_ID.to_owned(),
            model: "gpt-5.6-sol".to_owned(),
            pool: String::new(),
            permissions,
            effort: Some(Effort::Medium),
            max_turns: None,
            extra_args: Vec::new(),
        }
    }

    fn run(permissions: PermissionMode, resume: Option<&str>) -> TaskRun {
        TaskRun {
            prompt: "do the thing".to_owned(),
            profile: profile(permissions),
            workspace: PathBuf::from("/repo"),
            gate_cmds: vec!["cargo test".to_owned()],
            resume_session: resume.map(str::to_owned),
            settings_path: None,
        }
    }

    fn output(code: i32, stdout: &str, stderr: &str) -> ProcessOutput {
        ProcessOutput {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            timed_out: false,
            output_limited: false,
            duration: Duration::from_secs(1),
        }
    }

    fn debug_models_json(levels: &[&str]) -> String {
        json!({
            "models": [{
                "slug": "gpt-5.6-sol",
                "supported_reasoning_levels": levels
                    .iter()
                    .map(|effort| json!({ "effort": effort }))
                    .collect::<Vec<_>>(),
            }]
        })
        .to_string()
    }

    #[test]
    fn probe_contract_requires_reasoning_config_on_fresh_and_resume() {
        let fresh = "--json --sandbox --model -c, --config";
        let resumed = "--json --model -c, --config";
        validate_probe_contract("0.147.0", fresh, resumed).expect("complete surfaces");

        let error = validate_probe_contract(
            "0.147.0",
            "--json --sandbox --model --configuration",
            resumed,
        )
        .expect_err("fresh must carry reasoning config")
        .to_string();
        assert!(error.contains("`exec`"), "{error}");
        assert!(error.contains("--config"), "{error}");
        assert!(error.contains("-c"), "{error}");

        let error = validate_probe_contract("0.147.0", fresh, "--json --model --configuration")
            .expect_err("resume must carry reasoning config")
            .to_string();
        assert!(error.contains("`exec resume`"), "{error}");
        assert!(error.contains("--config"), "{error}");
        assert!(error.contains("-c"), "{error}");
    }

    #[test]
    fn exact_key_probe_uses_strict_local_guards_on_both_cli_surfaces() {
        let schema = std::path::Path::new(r"C:\missing\tactus-output-schema-must-not-exist.json");
        for surface in [ConfigProbeSurface::Fresh, ConfigProbeSurface::Resume] {
            let args = config_probe_args(surface, "model_reasoning_effort=xhigh", schema);
            assert!(
                args.contains(&"--ignore-user-config".to_owned()),
                "{args:?}"
            );
            assert!(args.contains(&"--strict-config".to_owned()), "{args:?}");
            assert!(args.contains(&"--output-schema".to_owned()), "{args:?}");
            assert!(
                args.windows(2).any(|pair| {
                    pair == ["-c".to_owned(), "model_reasoning_effort=xhigh".to_owned()]
                }),
                "the exact provider key must reach argv: {args:?}"
            );
            assert!(
                !args.contains(&"--help".to_owned()),
                "help skips config parsing"
            );
            match surface {
                ConfigProbeSurface::Fresh => {
                    assert_eq!(args.first().map(String::as_str), Some("exec"));
                    assert!(!args.contains(&"resume".to_owned()), "{args:?}");
                }
                ConfigProbeSurface::Resume => assert_eq!(
                    &args[..3],
                    ["exec", "resume", CONFIG_PROBE_RESUME_ID],
                    "the resumed surface must be exercised independently"
                ),
            }
        }
    }

    #[test]
    fn strict_config_control_must_fail_before_the_missing_schema_guard() {
        let rejected = output(
            1,
            "",
            "error: unknown configuration key `tactus_probe_deliberately_unknown`",
        );
        validate_unknown_config_control("0.147.0", ConfigProbeSurface::Fresh, &rejected)
            .expect("strict parsing is active");

        let skipped = output(
            1,
            "",
            "failed to read output schema tactus-output-schema-must-not-exist.json",
        );
        let error =
            validate_unknown_config_control("0.147.0", ConfigProbeSurface::Resume, &skipped)
                .expect_err("an ignored unknown key proves nothing")
                .to_string();
        assert!(error.contains("strict-config control"), "{error}");
    }

    #[test]
    fn strict_config_evidence_rejects_output_limited_transcript() {
        let mut truncated = output(
            1,
            "",
            "error: unknown configuration key `tactus_probe_deliberately_unknown`",
        );
        truncated.output_limited = true;
        let error =
            validate_unknown_config_control("0.147.0", ConfigProbeSurface::Fresh, &truncated)
                .expect_err("truncated parser evidence must fail closed")
                .to_string();
        assert!(error.contains("output limit"), "{error}");
        assert!(error.contains("truncated output"), "{error}");
    }

    #[test]
    fn exact_effort_key_must_reach_the_zero_spend_schema_guard() {
        let accepted = output(
            1,
            "",
            "error reading output schema C:\\missing\\tactus-output-schema-must-not-exist.json",
        );
        for surface in [ConfigProbeSurface::Fresh, ConfigProbeSurface::Resume] {
            for effort in [Effort::XHigh, Effort::Max] {
                validate_effort_config_probe("0.147.0", surface, effort, &accepted)
                    .expect("the exact key and value passed strict local parsing");
            }
        }

        let unknown = output(
            1,
            "",
            "error: unknown configuration key `model_reasoning_effort`",
        );
        let error = validate_effort_config_probe(
            "0.147.0",
            ConfigProbeSurface::Fresh,
            Effort::XHigh,
            &unknown,
        )
        .expect_err("a renamed key must refuse before spend")
        .to_string();
        assert!(error.contains("model_reasoning_effort=xhigh"), "{error}");

        let mut timed_out = accepted;
        timed_out.timed_out = true;
        assert!(
            validate_effort_config_probe(
                "0.147.0",
                ConfigProbeSurface::Resume,
                Effort::Max,
                &timed_out,
            )
            .is_err(),
            "a timeout cannot be mistaken for parser evidence"
        );
    }

    #[test]
    fn effort_config_evidence_rejects_output_limited_transcript() {
        let mut truncated = output(
            1,
            "",
            "error reading output schema tactus-output-schema-must-not-exist.json",
        );
        truncated.output_limited = true;
        let error = validate_effort_config_probe(
            "0.147.0",
            ConfigProbeSurface::Resume,
            Effort::Max,
            &truncated,
        )
        .expect_err("truncated reasoning-key evidence must fail closed")
        .to_string();
        assert!(error.contains("output limit"), "{error}");
        assert!(error.contains("model_reasoning_effort=max"), "{error}");
    }

    #[test]
    fn unreadable_fresh_or_resume_help_is_a_preflight_refusal() {
        let mut timed_out = output(0, "full help", "");
        timed_out.timed_out = true;
        let error = checked_help("codex", "exec", &timed_out)
            .expect_err("fresh timeout")
            .to_string();
        assert!(error.contains("exec --help"), "{error}");
        assert!(error.contains("could not be verified"), "{error}");

        let failed = output(2, "", "resume help failed");
        let error = checked_help("codex", "exec resume", &failed)
            .expect_err("resume nonzero")
            .to_string();
        assert!(error.contains("exec resume --help"), "{error}");
        assert!(error.contains("resume help failed"), "{error}");

        let empty = output(0, "", "");
        assert!(
            checked_help("codex", "exec resume", &empty)
                .expect_err("empty")
                .to_string()
                .contains("no output")
        );
    }

    #[test]
    fn model_catalog_requires_every_effort_for_each_known_codex_model() {
        let complete = debug_models_json(&["low", "medium", "high", "xhigh", "max", "ultra"]);
        let parsed = parse_debug_models(&complete).expect("realistic catalog");
        validate_model_efforts("0.147.0", &parsed).expect("all Tactus levels are present");

        for (missing, levels) in [
            ("xhigh", ["low", "medium", "high", "max"]),
            ("max", ["low", "medium", "high", "xhigh"]),
        ] {
            let parsed = parse_debug_models(&debug_models_json(&levels)).expect("catalog");
            let error = validate_model_efforts("0.147.0", &parsed)
                .expect_err("a missing shared level must refuse")
                .to_string();
            assert!(error.contains("gpt-5.6-sol"), "{error}");
            assert!(error.contains(missing), "{error}");
        }

        let unrelated = serde_json::to_string(&json!({
            "models": [{
                "slug": "not-the-configured-model",
                "supported_reasoning_levels": [
                    { "effort": "low" },
                    { "effort": "medium" },
                    { "effort": "high" },
                    { "effort": "xhigh" },
                    { "effort": "max" },
                ],
            }]
        }))
        .expect("json");
        let parsed = parse_debug_models(&unrelated).expect("catalog");
        let error = validate_model_efforts("0.147.0", &parsed)
            .expect_err("another slug cannot satisfy the configured model")
            .to_string();
        assert!(error.contains("gpt-5.6-sol"), "{error}");
    }

    #[test]
    fn unreadable_model_catalog_is_a_preflight_refusal() {
        let mut timed_out = output(0, "{}", "");
        timed_out.timed_out = true;
        assert!(
            checked_model_catalog("codex", &timed_out)
                .expect_err("timeout")
                .to_string()
                .contains("could not be verified")
        );

        let failed = output(2, "", "not available");
        assert!(
            checked_model_catalog("codex", &failed)
                .expect_err("nonzero")
                .to_string()
                .contains("not available")
        );

        let empty = output(0, "", "");
        assert!(
            checked_model_catalog("codex", &empty)
                .expect_err("empty")
                .to_string()
                .contains("no catalog")
        );

        let malformed = checked_model_catalog("codex", &output(0, "not-json", ""))
            .and_then(|text| parse_debug_models(&text))
            .expect_err("malformed catalog")
            .to_string();
        assert!(malformed.contains("unreadable catalog"), "{malformed}");
    }

    #[test]
    fn a_fresh_attempt_sets_its_sandbox_and_a_resumed_one_must_not() {
        // The CLI's two shapes, which are not one shape with a flag swapped.
        // `exec resume` rejects `-s` outright — observed as exit 2, "unexpected
        // argument '-s' found" — because the sandbox belongs to the session and
        // is inherited. Passing it anyway would fail every same-rung retry for
        // a reason that has nothing to do with the code.
        let fresh = build_args(&run(PermissionMode::Edit, None));
        assert!(fresh.starts_with(&["exec".to_owned()]), "{fresh:?}");
        assert!(!fresh.contains(&"resume".to_owned()), "{fresh:?}");
        assert!(fresh.contains(&"--sandbox".to_owned()), "{fresh:?}");
        assert!(fresh.contains(&"workspace-write".to_owned()), "{fresh:?}");

        let resumed = build_args(&run(PermissionMode::Edit, Some("019ff122-4d61")));
        assert_eq!(
            resumed[..3],
            [
                "exec".to_owned(),
                "resume".to_owned(),
                "019ff122-4d61".to_owned()
            ],
            "{resumed:?}"
        );
        assert!(
            !resumed.contains(&"--sandbox".to_owned()),
            "a resumed attempt must not re-specify the sandbox: {resumed:?}"
        );
    }

    #[test]
    fn every_effort_has_the_exact_config_spelling_on_fresh_and_resumed_attempts() {
        let expected = [
            (Effort::Low, "low"),
            (Effort::Medium, "medium"),
            (Effort::High, "high"),
            (Effort::XHigh, "xhigh"),
            (Effort::Max, "max"),
        ];
        for (effort, spelling) in expected {
            assert_eq!(effort_flag(effort), spelling);
            for resume in [None, Some("019ff122-4d61")] {
                let mut task = run(PermissionMode::Edit, resume);
                task.profile.effort = Some(effort);
                let args = build_args(&task);
                let expected = format!("model_reasoning_effort={spelling}");
                assert!(
                    args.windows(2)
                        .any(|window| window[0] == "-c" && window[1] == expected),
                    "{effort} must reach {:?} argv exactly: {args:?}",
                    resume
                );
            }
        }
    }

    #[test]
    fn a_profile_without_an_effort_passes_none_rather_than_guessing() {
        // Only reachable from a hand-built profile: the engine sets an effort
        // on every profile it makes. Passing a guess here would be worse than
        // the CLI's own default, because it would look deliberate.
        let mut run = run(PermissionMode::Edit, None);
        run.profile.effort = None;
        let args = build_args(&run);
        assert!(!args.contains(&"-c".to_owned()), "{args:?}");
    }

    #[test]
    fn the_prompt_is_the_last_argument_and_it_is_stdin() {
        // Windows caps argv at ~8,191 bytes and a review prompt carries the
        // diff, so the prompt has never been passable as an argument. `-` says
        // "read it from stdin", and anything after it would be swallowed as the
        // prompt's own arguments.
        for resume in [None, Some("sess")] {
            let args = build_args(&run(PermissionMode::ReadOnly, resume));
            assert_eq!(args.last().map(String::as_str), Some("-"), "{args:?}");
        }
        // And the payload is actually written, or the CLI sits waiting on a
        // pipe nobody closed.
        let run = run(PermissionMode::Edit, None);
        assert_eq!(CodexAdapter.stdin_payload(&run), "do the thing");
    }

    #[cfg(windows)]
    #[test]
    fn an_implementer_is_refused_where_no_sandbox_can_enforce_it() {
        // Windows has no sandbox helper (`codex doctor`: `linux helper: none`),
        // so `exec` degrades to read-only and writes nothing while returning 0.
        // Measured on run 01KZRMHA28M5CM88VAXP613X9P, which spent both attempts
        // on empty diffs and then parked asking for write access it had been
        // granted. A capability this platform cannot deliver is a refusal to
        // start (§19), not a task that fails after spending.
        let err = edit_refusal(&profile(PermissionMode::Edit))
            .expect("an implementer profile must be refused on Windows");
        let text = err.to_string();
        assert!(text.contains("cannot run"), "{text}");
        assert!(
            text.contains("--approve-for-me"),
            "the refusal has to say which door was tried and why it is shut: {text}"
        );
        // And where to go instead: Linux, or another agent.
        assert!(text.contains("Linux"), "{text}");
        assert!(text.contains("reviewer"), "{text}");
    }

    #[cfg(not(windows))]
    #[test]
    fn an_implementer_is_allowed_where_the_sandbox_is_real() {
        // Same CLI, same flags, helper present: `--sandbox workspace-write`
        // wrote inside the workspace and was blocked outside it, both measured
        // in a container. The refusal above is scoped to the platform that
        // cannot enforce a boundary, not to the CLI.
        assert!(
            edit_refusal(&profile(PermissionMode::Edit)).is_none(),
            "an implementer is fine where the sandbox is enforced"
        );
    }

    #[test]
    fn a_reviewer_is_read_only_and_nothing_is_ever_given_the_machine() {
        // Never refused anywhere: read-only is enforced on every platform, and
        // it is the seat this adapter is most useful in.
        assert!(edit_refusal(&profile(PermissionMode::ReadOnly)).is_none());
        let args = build_args(&run(PermissionMode::ReadOnly, None));
        assert!(args.contains(&"read-only".to_owned()), "{args:?}");
        for permissions in [PermissionMode::Edit, PermissionMode::ReadOnly] {
            for resume in [None, Some("sess")] {
                let args = build_args(&run(permissions, resume)).join(" ");
                for flag in FORBIDDEN {
                    assert!(
                        !args.contains(flag),
                        "`{flag}` must never be passed: {args}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_successful_run_yields_its_session_message_and_tokens() {
        // The real event stream, from a tool-using run against codex-cli
        // 0.147.0 on 2026-08-11.
        let stdout = r#"{"type":"thread.started","thread_id":"019ff122-4d61-7323-a217-843ddfe5932c"}
{"type":"turn.started"}
{"type":"item.started","item":{"id":"item_0","type":"command_execution"}}
{"type":"item.completed","item":{"id":"item_0","type":"command_execution"}}
{"type":"item.completed","item":{"id":"item_1","type":"agent_message","text":"hi"}}
{"type":"turn.completed","usage":{"input_tokens":27707,"cached_input_tokens":22016,"cache_write_input_tokens":0,"output_tokens":102,"reasoning_output_tokens":0}}"#;
        let out = output(0, stdout, "some tracing noise");
        let outcome = parse_output(&out);

        assert_eq!(outcome.status, OutcomeStatus::Completed);
        // What the supervisor measured, carried through unchanged: see the
        // same assertion in the Claude adapter for why it is asserted at all.
        assert_eq!(outcome.duration, out.duration);
        assert_eq!(
            outcome.session_id.as_deref(),
            Some("019ff122-4d61-7323-a217-843ddfe5932c"),
            "the thread id is what `exec resume` takes"
        );
        // The agent's final message, not the command_execution item before it.
        // A reviewer's verdict travels in exactly this field.
        assert_eq!(outcome.detail.as_deref(), Some("hi"));

        let usage = outcome.usage.expect("usage");
        assert_eq!(usage.input_tokens, Some(27707));
        assert_eq!(usage.output_tokens, Some(102));
        assert_eq!(usage.cache_read_input_tokens, Some(22016));
        assert_eq!(usage.num_turns, Some(1));
        // Tokens, never a price: this route reports no dollars and tactus does
        // not own a rate table.
        assert_eq!(outcome.cost_usd, None);
    }

    #[test]
    fn several_turns_are_summed_rather_than_last_wins() {
        // One invocation emits one `turn.completed` today, tool call and all.
        // This is the guard for a version that reports per step, where taking
        // the last would silently under-count the run.
        let stdout = r#"{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":2,"reasoning_output_tokens":1}}
{"type":"turn.completed","usage":{"input_tokens":30,"output_tokens":5,"reasoning_output_tokens":4}}"#;
        let usage = parse_output(&output(0, stdout, "")).usage.expect("usage");
        assert_eq!(usage.input_tokens, Some(40));
        assert_eq!(usage.output_tokens, Some(7));
        // Carried, not double-counted: reasoning tokens are a subset of output.
        assert_eq!(usage.reasoning_output_tokens, Some(5));
        assert_eq!(usage.num_turns, Some(2));
    }

    #[test]
    fn an_unauthenticated_run_is_an_agent_error_not_an_exhausted_pool() {
        // Observed: five 401 retries then exit 101. The ladder acts on this
        // distinction — a rate limit defers and waits for a window, an agent
        // error spends an attempt — so calling a signed-out account "rate
        // limited" would park a run forever on a problem that never resolves.
        let stdout = r#"{"type":"thread.started","thread_id":"t1"}
{"type":"error","message":"Reconnecting... 2/5 (unexpected status 401 Unauthorized: Missing bearer or basic authentication in header)"}"#;
        let outcome = parse_output(&output(101, stdout, "ERROR codex_api::endpoint: 401"));
        assert_eq!(outcome.status, OutcomeStatus::AgentError);
        assert!(
            outcome.detail.as_deref().is_some_and(|d| d.contains("401")),
            "{:?}",
            outcome.detail
        );
    }

    #[test]
    fn a_rate_limited_failure_is_told_apart_from_an_ordinary_one() {
        let stdout =
            r#"{"type":"error","message":"You have hit your usage limit for this window"}"#;
        assert_eq!(
            parse_output(&output(1, stdout, "")).status,
            OutcomeStatus::RateLimited
        );
        let stdout = r#"{"type":"error","message":"the file could not be written"}"#;
        assert_eq!(
            parse_output(&output(1, stdout, "")).status,
            OutcomeStatus::AgentError
        );
    }

    #[test]
    fn junk_on_stdout_never_fails_an_attempt() {
        // Warnings, progress chatter, a half-written line at a kill — none of
        // it is JSON and none of it should turn a finished attempt into a
        // failure.
        let stdout = "Reading additional input from stdin...\n\
                      {\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"ok\"}}\n\
                      {not json at all";
        let outcome = parse_output(&output(0, stdout, ""));
        assert_eq!(outcome.status, OutcomeStatus::Completed);
        assert_eq!(outcome.detail.as_deref(), Some("ok"));
    }

    #[test]
    fn signed_out_is_never_read_as_signed_in() {
        // "Not logged in" contains "logged in", so order of checks is the whole
        // test: a confident wrong "you are signed in" writes a pool the
        // operator trusts and a run then fails against.
        let signed_out = parse_login_status(&output(0, "Not logged in\n", ""));
        assert_eq!(signed_out.auth, AuthState::NotAuthenticated);
        assert_eq!(signed_out.shape, None);

        let signed_in = parse_login_status(&output(0, "Logged in using ChatGPT\n", ""));
        assert_eq!(signed_in.auth, AuthState::Authenticated);
        assert_eq!(
            signed_in.shape,
            Some(PoolKind::SubscriptionWindow),
            "a ChatGPT plan is a window, not metered dollars"
        );

        // Anything unrecognised stays Unknown and says so, rather than being
        // forced into one of the two answers.
        let odd = parse_login_status(&output(0, "something new entirely\n", ""));
        assert_eq!(odd.auth, AuthState::Unknown);
        assert!(!odd.notes.is_empty());
    }

    /// A Runner that records every request and answers each config-probe
    /// surface the way a working `codex` does.
    ///
    /// The answers are what let the sequence *complete*: a validator that
    /// refuses stops the walk, and a walk that stops after one process cannot
    /// say anything about the identities of the other five.
    struct RecordingRunner {
        seen: std::sync::Mutex<Vec<crate::runner::RunnerRequest>>,
        /// `false` makes every candidate unusable, so the resolution loop walks
        /// the whole PATH candidate list instead of stopping at the first.
        candidates_usable: bool,
    }

    impl RecordingRunner {
        fn new(candidates_usable: bool) -> Self {
            Self {
                seen: std::sync::Mutex::new(Vec::new()),
                candidates_usable,
            }
        }

        fn seen(&self) -> Vec<crate::runner::RunnerRequest> {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn identities(&self) -> Vec<String> {
            self.seen()
                .iter()
                .map(|request| request.invocation.render())
                .collect()
        }
    }

    impl Runner for RecordingRunner {
        fn run(
            &self,
            request: &crate::runner::RunnerRequest,
        ) -> Result<ProcessOutput, TactusError> {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request.clone());
            let args = request.command.args.join(" ");
            if args.contains(CONFIG_PROBE_UNKNOWN_KEY) {
                // The control: the strict parser rejects the unknown key
                // *before* the local missing-schema guard.
                return Ok(output(
                    2,
                    "",
                    &format!("error: unknown key `{CONFIG_PROBE_UNKNOWN_KEY}` in -c override"),
                ));
            }
            if args.contains("model_reasoning_effort=") {
                // The key is accepted, and the run then stops on the schema
                // file that deliberately does not exist.
                return Ok(output(
                    2,
                    "",
                    &format!("error: output schema `{CONFIG_PROBE_SCHEMA_FILE}` does not exist"),
                ));
            }
            if args.contains("--version") {
                return Ok(output(
                    i32::from(!self.candidates_usable),
                    "codex-cli 0.9.9\n",
                    "",
                ));
            }
            Ok(output(0, "", ""))
        }
    }

    /// The six strict-config parser probes really are six identities.
    ///
    /// `decisions.admission_and_leases.permits.invocation_identity`:
    /// `InvocationId` is "unique **per process**", and `invariants[19]`
    /// (INV-20) requires every Runner process to carry one. Two processes
    /// sharing an identity collide in the invocation ledger and in every
    /// invocation-derived containment scope.
    ///
    /// `every_preflight_process_has_its_own_ordinal` asserts the *table*
    /// `probe_ordinal::ALL`, which is hand-written and contains only the
    /// **declared** ordinals. These six are **computed** — `CONFIG_BASE +
    /// surface.index() * CONFIG_PER_SURFACE + step` — so a `ConfigProbeSurface::
    /// Resume` whose `index()` returned `Fresh`'s left the six processes
    /// carrying three identities with the whole suite green
    /// (`PR5-CORRECTNESS-008`). The repair is to stop asking the table and
    /// start asking the requests.
    ///
    /// The invocation is built with [`Invocation::at`] rather than resolved, so
    /// nothing here touches [`RESOLVED`] or this machine's `PATH`.
    #[test]
    fn the_six_config_parser_probes_are_six_distinct_identities() {
        let runner = RecordingRunner::new(true);
        let invocation = Invocation::at(if cfg!(windows) {
            r"C:\nowhere\codex.cmd"
        } else {
            "/nowhere/codex"
        });
        validate_effort_config_key(&runner, &invocation, "0.9.9")
            .expect("the scripted CLI satisfies every strict-config validator");

        let identities = runner.identities();
        assert_eq!(
            identities.len(),
            6,
            "two surfaces x {{control, xhigh, max}}: {identities:?}"
        );
        let distinct: BTreeSet<&String> = identities.iter().collect();
        assert_eq!(
            distinct.len(),
            6,
            "six processes carrying {} identities: {identities:?}",
            distinct.len()
        );
        // And they are the probe form naming this agent, so a "distinct" set
        // cannot be six values of some other shape.
        assert!(
            identities
                .iter()
                .all(|id| id.starts_with("p.agent-codex.o")),
            "{identities:?}"
        );

        // The two surfaces are really two: the resumed one carries `resume`
        // and the fresh one does not, so the six requests are six *different*
        // processes and not one repeated six times.
        let resumed = runner
            .seen()
            .iter()
            .filter(|request| request.command.args.iter().any(|arg| arg == "resume"))
            .count();
        assert_eq!(resumed, 3, "three of the six probe the resumed surface");

        // No computed ordinal may land on a declared one, which is the other
        // way this block can collide.
        let declared: BTreeSet<u32> = probe_ordinal::ALL.into_iter().collect();
        let computed: BTreeSet<u32> = identities
            .iter()
            .map(|id| {
                id.rsplit_once(".o")
                    .and_then(|(_, ordinal)| ordinal.parse::<u32>().ok())
                    .expect("a probe identity ends in its ordinal")
            })
            .collect();
        assert_eq!(computed.len(), 6);
        assert!(
            computed.iter().all(|ordinal| declared.contains(ordinal)),
            "the six computed ordinals must be the six the table reserves: \
             computed {computed:?}, declared {declared:?}"
        );
    }

    /// Every candidate the resolution loop tests carries its own identity too.
    ///
    /// The other **computed** ordinal in this adapter, and the same class:
    /// `RESOLUTION_BASE + candidate_index`, which `probe_ordinal::ALL` does not
    /// and cannot enumerate because `PATH` is unbounded.
    ///
    /// A private cache and a caller-supplied name list, so this neither spends
    /// the process's one memoised resolution nor depends on `codex` being
    /// installed. The premise — that this machine really offers more than one
    /// candidate — is asserted rather than hoped for: with one candidate a
    /// collision is unobservable, and a silent skip would measure nothing while
    /// looking green.
    #[test]
    fn every_binary_resolution_candidate_carries_its_own_identity() {
        // Programs every machine of each family has, chosen so the list yields
        // several distinct files. `find_program_candidates` de-duplicates by
        // path, so repeating one name would not widen the list.
        let names: &[&str] = if cfg!(windows) {
            &["cmd.exe", "where.exe", "find.exe"]
        } else {
            &["sh", "ls", "cat"]
        };
        let candidates = crate::util::find_program_candidates(names);
        assert!(
            candidates.len() >= 2,
            "this machine offers {} candidate(s) for {names:?}, so a per-candidate \
             identity collision could not be observed here",
            candidates.len()
        );

        let runner = RecordingRunner::new(false);
        let cache: OnceLock<Option<Invocation>> = OnceLock::new();
        locate_in(&runner, &cache, names)
            .expect_err("every candidate was made unusable, so resolution refuses");

        let identities = runner.identities();
        assert_eq!(
            identities.len(),
            candidates.len(),
            "one process per candidate: {identities:?} for {candidates:?}"
        );
        let distinct: BTreeSet<&String> = identities.iter().collect();
        assert_eq!(
            distinct.len(),
            identities.len(),
            "two candidates were tested under one identity: {identities:?}"
        );

        // The per-candidate block and the fixed block cannot meet.
        let declared: BTreeSet<u32> = probe_ordinal::ALL.into_iter().collect();
        for id in &identities {
            let ordinal: u32 = id
                .rsplit_once(".o")
                .and_then(|(_, ordinal)| ordinal.parse().ok())
                .expect("a probe identity ends in its ordinal");
            assert!(
                ordinal >= probe_ordinal::RESOLUTION_BASE,
                "{id}: a candidate probe took an ordinal below the per-candidate block"
            );
            assert!(
                !declared.contains(&ordinal),
                "{id}: collided with the table"
            );
        }
    }

    /// Every pre-flight process of this adapter carries its own identity.
    ///
    /// `decisions.admission_and_leases.permits.invocation_identity` says
    /// "unique **per process**", and this adapter runs 12 of them, so the
    /// ordinals it fixes must be 12 distinct values. The expected count is
    /// written here from the steps the adapter performs, not read from the
    /// table under test — a table that lost an entry would otherwise agree
    /// with itself.
    #[test]
    fn every_preflight_process_has_its_own_ordinal() {
        use std::collections::BTreeSet;

        let ordinals: BTreeSet<u32> = probe_ordinal::ALL.into_iter().collect();
        assert_eq!(
            ordinals.len(),
            12,
            "`--version`, two `--help` surfaces, six strict-config parser probes, `debug models`, `login status`, and discovery's `debug models` — 12 processes, 12 identities"
        );
        assert_eq!(probe_ordinal::ALL.len(), 12);

        // And they really do render as 12 distinct identities of the packet's
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
        assert_eq!(ids.len(), 12);
        assert!(
            ids.iter().all(|id| id.starts_with("p.agent-codex.o")),
            "the probe form, naming this agent: {ids:?}"
        );

        // The fixed block and the per-candidate block cannot meet: binary
        // resolution here spawns once per PATH candidate and PATH is
        // unbounded, so the two are separated by construction rather than by
        // counting.
        assert!(
            probe_ordinal::ALL
                .into_iter()
                .all(|ordinal| ordinal < probe_ordinal::RESOLUTION_BASE),
            "a fixed step reached the per-candidate block"
        );
    }
    // Runs only where the real CLI exists; deterministic contract fixtures do
    // the compatibility proof, while this catches local help/catalog drift.
    #[test]
    fn probe_against_real_binary_when_present() {
        if resolved().is_err() {
            eprintln!("codex not on PATH; skipping live probe");
            return;
        }
        let caps = CodexAdapter
            .probe(&crate::runner::host::HostRunner::new())
            .expect("probe should succeed");
        assert!(caps.json_output);
        assert!(caps.session_resume);
        assert!(caps.model_list);
        assert!(!caps.version.is_empty());
    }
}
