//! `tactus connect` (DESIGN.md §13, §18): discover the agent CLIs on this
//! machine and write `~/.tactus/pools.toml`.
//!
//! **Invariant 2 is the one to watch here.** Connect subprocesses the vendors'
//! own CLIs and parses what they print. No HTTP, no token ever handled, no
//! credential file read — a vendor CLI talking to its own vendor is the design,
//! not a leak, and it is the same posture §9 sets for plan importers.
//!
//! Two things this deliberately does not do:
//!
//! - **It never invents a profile.** §13 wants `connect` to enumerate
//!   credential profiles, not just binaries, so that one vendor can back
//!   several pools. There is no vendor registry of profiles to enumerate — the
//!   mechanism is a config-directory environment variable, not a list — so v0.1
//!   writes one pool per agent and leaves `profile` for the operator to add by
//!   hand. See [`crate::capacity`]'s module docs for the v0.2 sketch.
//! - **It never clobbers.** §17 calls the pools file hand-editable, and it is
//!   the file that says which subscriptions exist. An existing file whose
//!   *settings* differ is printed and the command exits asking for `--force`;
//!   one that already says the same thing reports "unchanged" and rewrites
//!   nothing. `--force` still carries the operator's own keys across, because
//!   `profile`, `monthly_allowance` and `endpoint` are things discovery cannot
//!   supply and replacing the file must not quietly delete.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use crate::agent::{AdapterSource, BuiltinAdapters, Discovery};
use crate::capacity::{Pool, PoolKind, Source};
use crate::error::TactusError;
use crate::util;

#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Where to write. `None` takes `~/.tactus/pools.toml`; tests always set
    /// it, so no test can reach the operator's real pools file.
    pub pools_path: Option<PathBuf>,
    /// Overwrite an existing file that differs.
    pub force: bool,
}

/// What `connect` did, so the CLI can render it and a test can assert on it
/// without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrote {
    /// The file did not exist, or `--force` replaced one that differed.
    Written,
    /// Configures exactly what is already there, and says exactly the same
    /// thing about it — compared over [`settings_of`] and [`stable_content`]
    /// rather than over bytes.
    Unchanged,
    /// An existing file differs and `--force` was not given.
    Refused,
}

#[derive(Debug)]
pub struct ConnectReport {
    pub path: PathBuf,
    pub outcome: Wrote,
    /// The file `connect` produced — written, or merely proposed when it
    /// refused to clobber.
    pub content: String,
    /// One entry per registered adapter, in registry order.
    pub agents: Vec<AgentReport>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct AgentReport {
    pub agent: String,
    /// `Err` means this agent contributed no pool. It never aborts the others:
    /// a machine with Claude Code and no Copilot is the normal case, not a
    /// broken one.
    pub outcome: Result<Discovery, String>,
    pub pool: Option<Pool>,
}

/// Discover, render, and write — the whole command.
pub fn run(opts: &ConnectOptions) -> Result<ConnectReport, TactusError> {
    run_with(
        opts,
        &BuiltinAdapters,
        crate::agent::ADAPTERS.iter().map(|a| a.id()),
    )
}

/// The injectable form: `adapters` supplies the implementations and `ids` the
/// registry order, so a test can drive scripted discovery with no CLI on the
/// machine at all.
pub fn run_with<'a>(
    opts: &ConnectOptions,
    adapters: &dyn AdapterSource,
    ids: impl IntoIterator<Item = &'a str>,
) -> Result<ConnectReport, TactusError> {
    let path = match &opts.pools_path {
        Some(path) => path.clone(),
        None => util::user_tactus_dir()
            .map(|dir| dir.join("pools.toml"))
            .ok_or_else(|| TactusError::Refused {
                message: "cannot find a home directory to write ~/.tactus/pools.toml into — pass \
                          --pools <path> to say where it should go"
                    .to_owned(),
            })?,
    };

    // Read before anything is written: `--force` must not silently discard the
    // keys only an operator can supply.
    let existing_text = fs::read_to_string(&path).ok();
    let carried = existing_text
        .as_deref()
        .map(operator_keys)
        .unwrap_or_default();

    let mut warnings = Vec::new();
    let mut agents: Vec<AgentReport> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for id in ids {
        // Two entries for one agent would render `[pools.<name>]` twice, and
        // TOML rejects duplicate keys — so `connect` would write a file that
        // `config::load` then refuses to read. The built-in registry has no
        // duplicates, but `run_with` is the public seam and takes any ids.
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        let Some(adapter) = adapters.get(id) else {
            continue;
        };
        // Probe first: §14 already treats a missing or broken binary as a
        // refusal to start, and discovery on a CLI that cannot even report its
        // version would be reading tea leaves.
        // Its own host Runner, for the reason `capacity` states: `connect`
        // drives no run, so there is no run's boundary to borrow, and it is
        // not a coordinator so its children are outside INV-18's ambient job.
        let runner = crate::runner::host::HostRunner::new();
        let discovered = adapter
            .probe(&runner)
            .and_then(|caps| adapter.discover(&runner, &caps));
        match discovered {
            Ok(discovery) => {
                // D1's cross-check, at the moment the roster's provenance is
                // being written into the file. Claude Code and Copilot report
                // no roster today; Codex reports its local `debug models`
                // catalog. Any real listing is where a stale shipped entry
                // should first be caught.
                let missing = crate::catalog::missing_from(id, &discovery.models);
                if !missing.is_empty() {
                    warnings.push(format!(
                        "{id} does not advertise catalogued model(s): {}. Cross-family review \
                         binds to catalogued names, so one this CLI rejects fails at runtime — \
                         upgrade tactus or pin a model it lists.",
                        missing.join(", ")
                    ));
                }
                let mut pool = pool_for_agent(id, &discovery);
                if let Some(kept) = carried.get(&pool.name) {
                    kept.apply(&mut pool);
                }
                agents.push(AgentReport {
                    agent: id.to_owned(),
                    outcome: Ok(discovery),
                    pool: Some(pool),
                });
            }
            Err(error) => {
                warnings.push(format!("{id}: no pool written — {error}"));
                agents.push(AgentReport {
                    agent: id.to_owned(),
                    outcome: Err(error.to_string()),
                    pool: None,
                });
            }
        }
    }

    let content = render(&agents);
    let existing = existing_text;
    // Two comparisons, because two different questions are being asked.
    //
    // *May* this file be replaced turns on the **settings** — the operator's
    // hand edits are what must not be clobbered, and a comment carries none.
    // *Should* it be rewritten turns on everything except the one genuinely
    // volatile line, the header's timestamp. Collapsing the two into a single
    // settings comparison meant a login between two connects reported
    // `unchanged` and left the file still saying NOT signed in; collapsing them
    // the other way made every re-connect a conflict resolvable only by
    // `--force`, the flag that discards hand edits.
    let outcome = match &existing {
        Some(existing) if settings_of(existing) != settings_of(&content) && !opts.force => {
            Wrote::Refused
        }
        Some(existing) if stable_content(existing) == stable_content(&content) => Wrote::Unchanged,
        _ => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|source| TactusError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            util::write_text(&path, &content)?;
            Wrote::Written
        }
    };

    Ok(ConnectReport {
        path,
        outcome,
        content,
        agents,
        warnings,
    })
}

/// The settings a pools file actually carries — comments and blank lines
/// dropped.
///
/// "Differs" has to mean *differs in what it configures*, not "differs in
/// bytes". The header names the write date, so a byte comparison would make
/// two runs a second apart look like a conflict: every re-`connect` would
/// refuse, and the only way past it would be `--force`, which is exactly the
/// flag that discards hand edits. A refusal an operator is trained to bypass
/// protects nothing.
///
/// The other direction holds too: an operator who edits only a comment has
/// changed no setting, and being told their file conflicts would be noise.
fn settings_of(text: &str) -> Vec<String> {
    text.lines()
        .map(strip_comment)
        .filter(|line| !line.is_empty())
        .collect()
}

/// A line with any comment removed, whole-line or trailing.
///
/// Trailing matters because this module writes one: `render_pool` decorates
/// `reserve` with `# headroom kept for your own interactive sessions`, so the
/// single line an operator is most likely to tidy is the one a whole-line-only
/// filter would treat as a changed setting. `#` inside a quoted value is not a
/// comment, so quotes are tracked.
fn strip_comment(line: &str) -> String {
    let mut quoted = false;
    let mut out = String::new();
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                out.push(ch);
            }
            '#' if !quoted => break,
            _ => out.push(ch),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Everything except the one line that moves on its own.
///
/// The header records when `connect` ran, so comparing whole bytes would call
/// two runs a second apart different. Everything else — including every
/// discovery note and the auth line — is content a reader relies on being
/// current, so it belongs in the comparison that decides whether to rewrite.
fn stable_content(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| !line.starts_with("# Written by `tactus connect`"))
        .collect()
}

/// One pool per (agent × discovered account) — today exactly one per agent,
/// because nothing enumerates credential profiles (see the module docs).
fn pool_for_agent(agent: &str, discovery: &Discovery) -> Pool {
    // §13's default where the CLI could not say: Copilot's post-Jun-2026
    // billing is credits, and everything else that reports nothing is treated
    // as a subscription window — the shape whose estimator is the most
    // conservative of the two. The rendered file carries a comment saying so,
    // because a default the operator cannot see is a guess wearing a fact's
    // clothes.
    let kind = discovery.shape.unwrap_or(match agent {
        "copilot" => PoolKind::Credits,
        _ => PoolKind::SubscriptionWindow,
    });
    // §13's trust order, minus the sources v0.1 does not read: writing
    // `local-logs` into a fresh file would promise interactive-usage awareness
    // that has not been built. An operator who wants it recorded can add it —
    // the parser accepts it and the estimate says it is unread.
    Pool::discovered(
        default_pool_name(agent),
        kind,
        agent,
        vec![Source::Signals, Source::SelfMetered],
    )
}

/// The keys only an operator can supply, carried across a `--force`.
///
/// `connect` discovers subscriptions; it cannot discover *which account*
/// (`profile`), *how big* an allowance is (`monthly_allowance`), or where a
/// local model lives (`endpoint`). All three are hand-written, and rewriting
/// the file without them would delete the operator's own work — with the
/// refusal message that recommends `--force` never saying so. `profile` in
/// particular is the entire point of §13's multi-account seam, and
/// `monthly_allowance` is the only thing that makes a self-metered estimate
/// possible at all (`Auto` yields `Unknown`).
#[derive(Debug, Default, Clone, PartialEq, serde::Deserialize)]
struct OperatorKeys {
    profile: Option<String>,
    monthly_allowance: Option<toml::Value>,
    endpoint: Option<String>,
}

impl OperatorKeys {
    fn apply(&self, pool: &mut Pool) {
        if let Some(profile) = &self.profile {
            pool.profile = Some(profile.clone());
        }
        if let Some(endpoint) = &self.endpoint {
            pool.endpoint = Some(endpoint.clone());
        }
        if let Some(units) = self.monthly_allowance.as_ref().and_then(allowance_of) {
            pool.monthly_allowance = units;
        }
    }

    fn any(&self) -> bool {
        self.profile.is_some() || self.monthly_allowance.is_some() || self.endpoint.is_some()
    }
}

fn allowance_of(value: &toml::Value) -> Option<crate::capacity::Allowance> {
    match value {
        toml::Value::String(text) if text.trim().eq_ignore_ascii_case("auto") => {
            Some(crate::capacity::Allowance::Auto)
        }
        toml::Value::Integer(units) => Some(crate::capacity::Allowance::Units(*units as f64)),
        toml::Value::Float(units) => Some(crate::capacity::Allowance::Units(*units)),
        _ => None,
    }
}

/// Pull the operator-written keys out of an existing pools file, by pool name.
///
/// Parsed leniently on purpose: a file this cannot read is one `--force` was
/// always going to replace, and failing the whole command over it would be
/// worse than losing keys that were unreadable anyway.
fn operator_keys(text: &str) -> std::collections::BTreeMap<String, OperatorKeys> {
    #[derive(serde::Deserialize)]
    struct Doc {
        pools: Option<std::collections::BTreeMap<String, OperatorKeys>>,
    }
    toml::from_str::<Doc>(text)
        .ok()
        .and_then(|doc| doc.pools)
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, keys)| keys.any())
        .collect()
}

/// The pool name for an agent: the agent's own id.
///
/// Deliberately not a plan name. Naming every Claude Code pool `claude-max`
/// asserted a subscription tier discovery never established — a Pro subscriber,
/// or someone on API-key billing, got a pool claiming a plan they do not have,
/// in the one file whose whole purpose is to describe their actual
/// subscriptions, from a module that marks its other defaults as defaults. It
/// also put a per-agent alias table here, so adding an adapter meant editing
/// `connect`. Renaming the pool is the operator's call, and the file is
/// hand-editable precisely so they can make it.
fn default_pool_name(agent: &str) -> &str {
    agent
}

/// Render the pools file: §17's shape, plus a header saying who wrote it, when,
/// and where the model roster came from.
fn render(agents: &[AgentReport]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Written by `tactus connect` v{} on {}.\n\
         #\n\
         # Pools are user-level (§17): they describe YOUR subscriptions, not this repo. The file\n\
         # is hand-editable and `tactus connect` will not overwrite your edits without --force.\n\
         #\n\
         # Model roster provenance: catalog {}, the static capability table shipped with this\n\
         # binary. Neither agent CLI offers non-interactive model enumeration as of this writing,\n\
         # so nothing here was cross-checked against what your installed CLI actually accepts.\n\
         #\n\
         # `profile` selects between several accounts on one vendor (§13). It is parsed, shown by\n\
         # `tactus capacity`, and acted on by nothing in v0.1 — add it when v0.2 wires it up.",
        env!("CARGO_PKG_VERSION"),
        util::rfc3339_utc_now(),
        env!("CARGO_PKG_VERSION"),
    );

    for report in agents {
        out.push('\n');
        match (&report.outcome, &report.pool) {
            (Ok(discovery), Some(pool)) => {
                let _ = writeln!(out, "# {}: {}", report.agent, discovery.auth);
                for note in &discovery.notes {
                    let _ = writeln!(out, "#   {note}");
                }
                if discovery.shape.is_none() {
                    let _ = writeln!(
                        out,
                        "#   kind below is a default, not something detected — change it if your \
                         plan differs"
                    );
                }
                out.push_str(&render_pool(pool));
            }
            _ => {
                let _ = writeln!(
                    out,
                    "# {}: not usable on this machine, so no pool was written for it.",
                    report.agent
                );
            }
        }
    }
    out
}

fn render_pool(pool: &Pool) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[pools.{}]", pool.name);
    let _ = writeln!(out, "kind = \"{}\"", pool.kind);
    let _ = writeln!(out, "agent = \"{}\"", pool.agent);
    if let Some(window) = pool.window {
        let _ = writeln!(
            out,
            "window = \"{}\"",
            crate::capacity::render_duration(window)
        );
    }
    if pool.weekly {
        let _ = writeln!(out, "weekly = true");
    }
    let sources: Vec<String> = pool.sources.iter().map(|s| format!("\"{s}\"")).collect();
    let _ = writeln!(out, "sources = [{}]", sources.join(", "));
    let _ = writeln!(out, "safety_margin = {:.2}", pool.safety_margin);
    let _ = writeln!(
        out,
        "reserve = {:.2}                     # headroom kept for your own interactive sessions",
        pool.reserve
    );
    // The operator's own keys, written back out. `connect` never invents any of
    // these — it cannot discover which account, how large an allowance is, or
    // where a local model lives — but once one is in the file it has to survive
    // being rewritten, or `--force` would delete exactly what the refusal it
    // overrides existed to protect.
    if let Some(profile) = &pool.profile {
        let _ = writeln!(out, "profile = \"{profile}\"");
    }
    if let crate::capacity::Allowance::Units(units) = pool.monthly_allowance {
        let _ = writeln!(out, "monthly_allowance = {units}");
    }
    if let Some(endpoint) = &pool.endpoint {
        let _ = writeln!(out, "endpoint = \"{endpoint}\"");
    }
    out
}

/// What the CLI prints.
pub fn render_report(report: &ConnectReport) -> String {
    let mut out = String::new();
    for agent in &report.agents {
        match (&agent.outcome, &agent.pool) {
            (Ok(discovery), Some(pool)) => {
                let _ = writeln!(
                    out,
                    "{}: {} — pool `{}` [{}]",
                    agent.agent, discovery.auth, pool.name, pool.kind
                );
                for note in &discovery.notes {
                    let _ = writeln!(out, "  {note}");
                }
            }
            (Err(error), _) => {
                let _ = writeln!(out, "{}: skipped — {error}", agent.agent);
            }
            (Ok(_), None) => {}
        }
    }
    for warning in &report.warnings {
        let _ = writeln!(out, "warning: {warning}");
    }
    match report.outcome {
        Wrote::Written => {
            let _ = writeln!(out, "wrote {}", report.path.display());
        }
        Wrote::Unchanged => {
            let _ = writeln!(out, "unchanged: {}", report.path.display());
        }
        Wrote::Refused => {
            let _ = writeln!(
                out,
                "{} already exists and differs from what connect would write. That file is \
                 hand-editable (§17), so it is not overwritten silently.\n\nWhat connect would \
                 write:\n{}\nRe-run with --force to replace it.",
                report.path.display(),
                indent(&report.content)
            );
        }
    }
    out
}

fn indent(text: &str) -> String {
    text.lines().map(|line| format!("  {line}\n")).collect()
}

/// A refusal to clobber is not an error the operator can fix by retrying, and
/// exit status is how a script tells the difference.
impl ConnectReport {
    pub fn refused(&self) -> bool {
        self.outcome == Wrote::Refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{AgentAdapter, AuthState, Caps, ProcessOutput, TaskRun};
    use crate::ir::Outcome;
    use crate::runner::CommandSpec;
    use std::path::Path;

    /// A scripted stand-in, so these tests run on a machine with no agent CLI
    /// installed at all.
    struct FakeAdapter {
        id: &'static str,
        discovery: Option<Discovery>,
    }

    impl AgentAdapter for FakeAdapter {
        fn id(&self) -> &'static str {
            self.id
        }

        fn probe(&self, _runner: &dyn crate::runner::Runner) -> Result<Caps, TactusError> {
            if self.discovery.is_none() {
                return Err(TactusError::Agent {
                    message: "binary not found on PATH".to_owned(),
                });
            }
            Ok(Caps {
                version: "0.0.0-fake".to_owned(),
                json_output: true,
                session_resume: true,
                cost_reporting: true,
                read_only_mode: true,
                acp: false,
                model_list: false,
            })
        }

        fn build(&self, _run: &TaskRun) -> Result<CommandSpec, TactusError> {
            unreachable!("connect never spawns an attempt")
        }

        fn parse(&self, _out: &ProcessOutput) -> Result<Outcome, TactusError> {
            unreachable!("connect never parses an attempt")
        }

        fn discover(
            &self,
            _runner: &dyn crate::runner::Runner,
            _caps: &Caps,
        ) -> Result<Discovery, TactusError> {
            self.discovery.clone().ok_or_else(|| TactusError::Agent {
                message: "binary not found on PATH".to_owned(),
            })
        }
    }

    struct Machine {
        adapters: Vec<FakeAdapter>,
    }

    impl AdapterSource for Machine {
        fn get(&self, id: &str) -> Option<&dyn AgentAdapter> {
            self.adapters
                .iter()
                .find(|a| a.id == id)
                .map(|a| a as &dyn AgentAdapter)
        }
    }

    fn machine() -> Machine {
        Machine {
            adapters: vec![
                FakeAdapter {
                    id: "claude-code",
                    discovery: Some(Discovery {
                        auth: AuthState::Authenticated,
                        models: Vec::new(),
                        shape: Some(PoolKind::SubscriptionWindow),
                        notes: vec!["auth method `subscription`".to_owned()],
                    }),
                },
                // Installed nowhere: the normal single-vendor machine.
                FakeAdapter {
                    id: "copilot",
                    discovery: None,
                },
            ],
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tactus-connect-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir.join("pools.toml")
    }

    fn connect(path: &Path, force: bool) -> ConnectReport {
        run_with(
            &ConnectOptions {
                pools_path: Some(path.to_path_buf()),
                force,
            },
            &machine(),
            ["claude-code", "copilot"],
        )
        .expect("connect runs")
    }

    #[test]
    fn a_missing_agent_skips_its_pool_without_taking_the_others_with_it() {
        let path = scratch("partial");
        let report = connect(&path, false);
        assert_eq!(report.outcome, Wrote::Written);
        let written = fs::read_to_string(&path).expect("file");
        assert!(written.contains("[pools.claude-code]"), "{written}");
        assert!(
            !written.contains("[pools.copilot]"),
            "no pool for a CLI that is not installed: {written}"
        );
        assert!(
            written.contains("# copilot: not usable"),
            "and it says why: {written}"
        );
        assert!(
            report.warnings.iter().any(|w| w.contains("copilot")),
            "warnings: {:?}",
            report.warnings
        );
    }

    #[test]
    fn what_connect_writes_parses_back_into_the_pools_it_describes() {
        // The round trip is the whole contract: a file this command writes must
        // be one `config::load` accepts, or `tactus capacity` reports on
        // something `connect` cannot produce.
        let path = scratch("roundtrip");
        connect(&path, false);
        let mut warnings = Vec::new();
        let hermetic = path.parent().expect("parent").to_path_buf();
        let cfg = crate::config::load(None, &hermetic, Some(&path), &mut warnings)
            .expect("the written file parses");
        assert_eq!(cfg.pools.len(), 1);
        let pool = &cfg.pools[0];
        assert_eq!(pool.name, "claude-code");
        assert_eq!(pool.kind, PoolKind::SubscriptionWindow);
        assert_eq!(pool.agent, "claude-code");
        assert_eq!(pool.sources, [Source::Signals, Source::SelfMetered]);
        assert_eq!(pool.safety_margin, crate::capacity::DEFAULT_SAFETY_MARGIN);
        assert_eq!(pool.reserve, crate::capacity::DEFAULT_RESERVE);
        assert_eq!(pool.profile, None, "connect never invents a profile");
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
    }

    #[test]
    fn an_existing_file_that_differs_is_never_clobbered() {
        // §17 says the file is hand-editable, so silently overwriting a hand
        // edit destroys the operator's own record of their subscriptions.
        let path = scratch("clobber");
        let mine = "[pools.claude-code]\nkind = \"subscription-window\"\nagent = \
                    \"claude-code\"\nprofile = \"work\"\nmonthly_allowance = 300\n";
        fs::write(&path, mine).expect("hand-written file");

        let report = connect(&path, false);
        assert_eq!(report.outcome, Wrote::Refused);
        assert!(report.refused());
        assert_eq!(
            fs::read_to_string(&path).expect("still there"),
            mine,
            "the hand-written file is untouched"
        );
        let rendered = render_report(&report);
        assert!(rendered.contains("--force"), "{rendered}");
        assert!(
            rendered.contains("[pools.claude-code]"),
            "it shows what it would have written: {rendered}"
        );

        // --force is the escape hatch, and it really does replace — but it
        // carries the operator's own keys across. `profile` is the whole point
        // of §13's multi-account seam and discovery cannot supply it, so a
        // replacement that dropped it would silently delete the one setting
        // the refusal above existed to protect.
        let forced = connect(&path, true);
        assert_eq!(forced.outcome, Wrote::Written);
        let after = fs::read_to_string(&path).expect("file");
        assert!(
            after.contains("profile = \"work\"") && after.contains("monthly_allowance = 300"),
            "--force keeps operator keys:
{after}"
        );
        assert!(
            after.contains("weekly = true"),
            "and still refreshes the rest:
{after}"
        );
    }

    #[test]
    fn re_connecting_an_unchanged_machine_reports_unchanged_rather_than_a_conflict() {
        // The header names the write date, so a byte comparison would call
        // every second run a conflict — and the only way past a conflict is
        // `--force`, the flag that discards hand edits. A refusal an operator
        // is trained to bypass protects nothing, so the comparison is over
        // settings, not bytes.
        let path = scratch("idempotent");
        connect(&path, false);
        let first = fs::read_to_string(&path).expect("file");

        let again = connect(&path, false);
        assert_eq!(again.outcome, Wrote::Unchanged, "{:?}", again.outcome);
        assert_eq!(
            fs::read_to_string(&path).expect("file"),
            first,
            "nothing changed, so nothing was rewritten — including the date it says it was written"
        );

        // A comment-only difference is never a *conflict* — settings are what
        // may not be clobbered — but it is a rewrite, because the comments are
        // where discovery's findings live. The trade is deliberate: a note an
        // operator adds is regenerated away, and in exchange a login between
        // two connects cannot leave the file insisting they are signed out.
        // Their real edits (`profile`, `monthly_allowance`, `endpoint`) survive
        // both paths — see `an_existing_file_that_differs_is_never_clobbered`.
        fs::write(&path, format!("# my own note\n{first}")).expect("annotate");
        assert_eq!(connect(&path, false).outcome, Wrote::Written);
    }

    #[test]
    fn a_login_between_connects_updates_the_file() {
        // Auth state is rendered only as a comment, so a settings-only
        // comparison reported `unchanged` and left the file telling an operator
        // who had just logged in that they were not signed in.
        let path = scratch("relogin");
        let with = |auth: AuthState| Machine {
            adapters: vec![FakeAdapter {
                id: "claude-code",
                discovery: Some(Discovery {
                    auth,
                    models: Vec::new(),
                    shape: Some(PoolKind::SubscriptionWindow),
                    notes: Vec::new(),
                }),
            }],
        };
        let opts = |force| ConnectOptions {
            pools_path: Some(path.clone()),
            force,
        };
        run_with(
            &opts(false),
            &with(AuthState::NotAuthenticated),
            ["claude-code"],
        )
        .expect("first connect");
        assert!(
            fs::read_to_string(&path)
                .expect("file")
                .contains("NOT signed in"),
            "precondition"
        );

        let second = run_with(
            &opts(false),
            &with(AuthState::Authenticated),
            ["claude-code"],
        )
        .expect("second connect");
        assert_eq!(second.outcome, Wrote::Written, "the auth state changed");
        assert!(
            !fs::read_to_string(&path)
                .expect("file")
                .contains("NOT signed in"),
            "the file must not still say the operator is signed out:\n{}",
            fs::read_to_string(&path).expect("file")
        );
    }

    #[test]
    fn a_cli_that_lists_models_is_cross_checked_against_the_catalog() {
        // D1's guard. It cannot fire against a real CLI today — neither
        // enumerates models — so it is driven through a scripted discovery
        // that does, which is the shape the check exists for.
        let machine = Machine {
            adapters: vec![FakeAdapter {
                id: "copilot",
                discovery: Some(Discovery {
                    auth: AuthState::Authenticated,
                    // A roster that has moved on without the catalog.
                    // Overlaps the roster — zero overlap is a format
                    // mismatch, not a stale catalog — but has moved on from
                    // the frontier slug the second opinion depends on.
                    models: [
                        "gpt-5-mini",
                        "gemini-3.1-pro",
                        "claude-sonnet-5",
                        "claude-opus-5",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                    shape: Some(PoolKind::Credits),
                    notes: Vec::new(),
                }),
            }],
        };
        let report = run_with(
            &ConnectOptions {
                pools_path: Some(scratch("crosscheck")),
                force: false,
            },
            &machine,
            ["copilot"],
        )
        .expect("connect runs");
        let warning = report
            .warnings
            .iter()
            .find(|w| w.contains("does not advertise"))
            .unwrap_or_else(|| panic!("expected a cross-check warning: {:?}", report.warnings));
        assert!(
            warning.contains("gpt-5.3-codex"),
            "names the frontier slug the second opinion depends on: {warning}"
        );
    }

    #[test]
    fn an_undetectable_plan_shape_takes_a_default_and_says_so() {
        // The Copilot case: §13 gives it two billing shapes and the CLI
        // distinguishes neither. A default is fine; a silent default is not.
        let machine = Machine {
            adapters: vec![FakeAdapter {
                id: "copilot",
                discovery: Some(Discovery::unknown().with_note("no auth query exists")),
            }],
        };
        let path = scratch("shape");
        let report = run_with(
            &ConnectOptions {
                pools_path: Some(path),
                force: false,
            },
            &machine,
            ["copilot"],
        )
        .expect("connect runs");
        assert!(
            report.content.contains("kind = \"credits\""),
            "{}",
            report.content
        );
        assert!(
            report.content.contains("kind below is a default"),
            "the default is visible in the file: {}",
            report.content
        );
        assert!(
            report
                .content
                .contains("auth state could not be determined"),
            "unknown auth never renders as 'not connected': {}",
            report.content
        );
    }

    #[test]
    fn discovery_against_the_real_claude_binary_when_present() {
        // §13's discovery is a claim about a real CLI, so it is checked against
        // one where the machine has it — and skipped cleanly where it does not,
        // which is the shape every other binary-touching test here takes.
        let runner = crate::runner::host::HostRunner::new();
        let Ok(caps) = crate::agent::claude::ClaudeCodeAdapter.probe(&runner) else {
            eprintln!("skipped: no claude on PATH");
            return;
        };
        let discovery = crate::agent::claude::ClaudeCodeAdapter
            .discover(&runner, &caps)
            .expect("discovery never fails on a CLI that probes");
        // Whatever it answers, it must be one of the three states and it must
        // explain itself — including when the answer is "could not tell".
        assert!(
            !discovery.notes.is_empty(),
            "discovery always says how it worked it out"
        );
        assert!(
            discovery.models.is_empty() || caps.model_list,
            "models may only be reported by a CLI whose --help advertises listing"
        );
    }
}
