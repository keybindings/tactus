use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::agent::Caps;
use crate::config;
use crate::error::TactusError;
use crate::events::{self, BindingSummary, ChainSummary, GateSummary};
use crate::gates::{self, ShellGate};
use crate::interaction::{self, InteractionMode, Notifier};
use crate::ir::Plan;
use crate::review::{self, PassBinding, ReviewPlan};
use crate::runner::Runner;
use crate::validate::{self, Analysis, ValidateOptions};

use super::options::{Harness, RunOptions};

/// Everything `run` and `resume` both establish before an agent is spawned.
///
/// Shared so the two cannot drift: §15 requires a resume to re-probe agents
/// and re-check gates, and the surest way to guarantee it performs the same
/// checks as a fresh run is for there to be one function that performs them.
pub(super) struct Preflight {
    pub(super) analysis: Analysis,
    pub(super) caps: BTreeMap<String, Caps>,
    pub(super) review_plan: ReviewPlan,
    /// Each pass gets this independent frozen allowance. It comes from the
    /// review plan rather than today's config on resume.
    pub(super) review_pass_timeout: Duration,
    /// The effective gates, in the one shape everything else projects from —
    /// the record, the permission grants, and the report all read this rather
    /// than walking `analysis.gates` again, so they cannot drift apart.
    pub(super) gates: Vec<GateSummary>,
    pub(super) gate_cmds: Vec<String>,
    pub(super) warnings: Vec<String>,
    pub(super) mode: InteractionMode,
    pub(super) notifiers: Vec<&'static dyn Notifier>,
    /// §17's ceilings with `--budget` folded in and validated — computed at
    /// pre-flight so a bad flag refuses before the run branch exists.
    pub(super) budgets: config::Budgets,
}

/// What a resume takes from the run's own record instead of from today's
/// machine (§15). Empty for a fresh run, which has no record to take from.
#[derive(Default)]
pub(super) struct Recorded {
    /// Who judges this run's code. `None` for a log written before step 9.
    pub(super) reviews: Option<ReviewPlan>,
    /// What verifies it. `None` for a log written before the gate record.
    pub(super) gates: Option<Vec<GateSummary>>,
    /// The legacy record identifies the reviewers but predates schema 3's
    /// explicit per-pass timeout. Its first complete-review resume must choose
    /// and serialize that missing part of the verification identity.
    pub(super) legacy_review_timeout_missing: bool,
    /// Whether those gates came from `[[gates]]` rather than the repo's shape.
    ///
    /// Travels with them, and read only when `gates` is `Some`: it is a label
    /// *on the recorded list*, so leaving it to be re-derived would have the
    /// run's own report and a later `status` disagree about the same gates —
    /// the drift this record exists to stop, one field short of stopped.
    pub(super) gates_from_config: bool,
    /// The run's routing structure plus the first snapshot that names every
    /// resolved rung binding. Present only on resume.
    pub(super) routing: Option<RecordedRouting>,
}

pub(super) struct RecordedRouting {
    pub(super) run_id: String,
    pub(super) structure: Vec<ChainSummary>,
    pub(super) bindings: Option<Vec<ChainSummary>>,
}

/// The pure half of pre-flight: the part that only reads files.
///
/// It exists because of *when* it can run rather than what it does. §14's
/// read-only refusals — the plan parsing, the graph, the routing chains, and
/// every `[engine]` ceiling — have to land before the first effect of a write
/// command, which is the worktree lease. Nothing here spawns a process, takes a
/// lock, or writes a byte, so it can run before that lease and refuse there.
///
/// The other half of pre-flight — probing agents, resolving gate programs —
/// genuinely inspects the machine and stays behind the lease.
///
/// `analysis` is what `inputs` says, and only what `inputs` says: the capture is
/// the source [`validate::analyze_captured`] parses, not a fingerprint taken
/// alongside a second read. That is the whole point of the type. A snapshot
/// beside an independent read proves nothing about what was validated — bytes
/// that change and change back leave two equal snapshots either side of a
/// validation performed on the value in between — so there is one read, and this
/// is it.
pub(super) struct Validated {
    analysis: Analysis,
    /// Every file the analysis came out of: the plan, the repo config, the pools
    /// file, and the worktree files the gate derivation reads.
    inputs: validate::CapturedInputs,
    limits: config::EngineLimits,
}

/// Capture every input, then validate that capture.
///
/// Callers run this **before** the worktree lease, and again under it. See
/// [`Validated`] and [`Validated::confirm_under_lease`].
pub(super) fn validate_inputs(
    opts: &RunOptions,
    limits: config::EngineLimits,
) -> Result<Validated, TactusError> {
    let validate_opts = ValidateOptions {
        plan_path: opts.plan_path.clone(),
        config_path: opts.config_path.clone(),
        config_root: opts.repo_root.clone(),
        pools_path: opts.pools_path.clone(),
        engine_limits: limits,
    };
    // Capture first, then parse the capture. Not "snapshot, then read": the
    // ordering is not the point, having a single read is.
    let inputs = validate::CapturedInputs::capture(&validate_opts);
    // §14: plan parses cycle-free, config loads, chains resolve.
    let analysis = validate::analyze_captured(&inputs, &validate_opts)?;
    Ok(Validated {
        analysis,
        inputs,
        limits,
    })
}

impl Validated {
    /// Adopt an analysis, now that the lease is held.
    ///
    /// The pre-lock check buys the ordering: a refusal reaches the operator
    /// without a lock file, a run directory, or a branch behind it. What it
    /// cannot buy is that the files did not move in the window between it and
    /// the lease, and a run that executed inputs nothing ever checked would be a
    /// worse defect than the ordering it fixed.
    ///
    /// So the lease-holder captures and validates again, and adopts *that*
    /// analysis rather than the pre-lock one, on the condition that the two
    /// captures agree. The re-validation is not redundant with the comparison:
    /// it is what puts the gate derivation — the one input `analyze` reaches the
    /// filesystem for rather than parsing out of the capture — behind the lease,
    /// where the worktree is this run's and a read of it is a fact about it. The
    /// comparison is what makes the pre-lock refusal mean something: it says the
    /// question answered before the lease was asked about these bytes.
    ///
    /// Every retry does the whole thing — capture, validate that capture,
    /// confirm it against the previous one — so an adopted analysis is always
    /// one whose own bytes were seen twice with nothing in between.
    ///
    /// `limits` is passed again rather than remembered because a resume derives
    /// it from a header it read before the lock; if the authoritative read
    /// disagrees, the reading has to be redone under the one that counts.
    ///
    /// Bounded, because inputs being rewritten faster than they can be read
    /// twice is a broken machine rather than a race worth waiting out, and
    /// looping forever there would hold the lease while doing so.
    pub(super) fn confirm_under_lease(
        self,
        opts: &RunOptions,
        limits: config::EngineLimits,
    ) -> Result<Analysis, TactusError> {
        const ATTEMPTS: usize = 3;
        // The pre-lock analysis is deliberately dropped rather than returned on
        // agreement: it answered "may this start", out of a worktree that was
        // still anybody's. What survives it is its capture, which is the thing
        // the reading taken under the lease has to agree with.
        let Self {
            mut inputs,
            limits: mut validated_for,
            ..
        } = self;
        for _ in 0..ATTEMPTS {
            let confirmed = validate_inputs(opts, limits)?;
            if confirmed.inputs == inputs && limits == validated_for {
                return Ok(confirmed.analysis);
            }
            inputs = confirmed.inputs;
            validated_for = limits;
        }
        Err(TactusError::Refused {
            message: format!(
                "{} kept changing while tactus was reading them; refusing to run inputs it \
                 could not check and then hold still",
                inputs
                    .paths()
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
    }
}

pub(super) fn preflight(
    opts: &RunOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
    analysis: Analysis,
) -> Result<Preflight, TactusError> {
    preflight_with_recorded(opts, harness, runner, analysis, Recorded::default())
}

/// Pre-flight, with whatever a previous process already resolved for this run.
///
/// Both halves of §14's verification — who reviews and what gates — are read
/// from the record on resume rather than re-derived, for one reason stated
/// twice: they are facts about the *run*, not about today's machine. A CLI
/// installed or removed since the run started must not change who judges it,
/// and a `tactus.toml` edited since — including by an implementer, in the very
/// workspace it edits — must not change what verifies it. A live run already
/// works this way by construction, holding one analysis in memory for its whole
/// length; this is what makes a resume the same run rather than a new one
/// wearing its branch.
///
/// `None` on either means the log predates that record and said nothing. Both
/// re-derive in that case rather than inherit an empty value, because an empty
/// review plan reads as "review is off" and an empty gate list reads as "there
/// was nothing to pass" — each would finish the run less verified than it began.
/// The caller warns; only it knows which absence it is looking at.
///
/// `analysis` arrives already validated, from [`validate_inputs`] run before
/// the worktree lease and confirmed under it — see [`Validated`]. Everything
/// from here on may inspect the machine.
pub(super) fn preflight_with_recorded(
    opts: &RunOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
    mut analysis: Analysis,
    recorded: Recorded,
) -> Result<Preflight, TactusError> {
    let mut warnings = analysis.warnings.clone();

    // Bindings are execution identity just like reviewers and gates. Restore
    // them before resolving reviewers or probing agents: probing today's pin
    // and only swapping later would let a harmless config edit refuse a resume
    // on an agent this run was never going to use.
    if let Some(routing) = recorded.routing.as_ref() {
        restore_recorded_routing(&mut analysis, routing, &mut warnings)?;
    }

    // The recorded gates replace the re-derived ones *here*, before anything
    // reads them — so the pre-flight resolution below, the `Bash(<cmd>)` grants
    // the workers get, the prompt that names their allowed commands, and the
    // report all describe the gates this run actually verifies against. One
    // substitution point rather than a comparison the rest of the function
    // could forget about.
    if let Some(record) = &recorded.gates {
        if let Some(difference) = gates_differ(record, &gate_summaries(&analysis)) {
            warnings.push(difference);
        }
        analysis.gates = record.iter().map(ShellGate::from_record).collect();
        analysis.gates_from_config = recorded.gates_from_config;
    }

    let mut review_plan = match recorded.reviews {
        Some(mut plan) => {
            let configured = analysis.config.review_pass_timeout.as_secs();
            if recorded.legacy_review_timeout_missing {
                plan.pass_timeout_secs = Some(configured);
                warnings.push(format!(
                    "this run's recorded review plan predates schema 3's per-pass timeout; this \
                     resume establishes today's configured {configured}s timeout in the \
                     append-only log before any more work starts"
                ));
            } else if plan.pass_timeout_secs != Some(configured) {
                let recorded = plan
                    .pass_timeout_secs
                    .expect("a non-legacy recorded review plan has an explicit timeout");
                warnings.push(format!(
                    "today's review pass timeout ({configured}s) differs from the one this run \
                     recorded ({}s). This resume keeps the recorded timeout so one run has one \
                     verification standard. Start a new run to adopt today's timeout.",
                    recorded
                ));
            }
            if plan.enabled.is_none() || plan.alternative_available.is_none() {
                plan.enabled.get_or_insert(plan.primary.is_some());
                plan.alternative_available
                    .get_or_insert(plan.alternative.is_some());
                warnings.push(
                    "this run's recorded review plan predates schema 3's explicit reviewer-identity markers; this resume records them before any more work starts"
                        .to_owned(),
                );
            }
            plan
        }
        // Resolved against the adapters *this harness* holds, not the built-in
        // registry: the harness is what can actually spawn something, and
        // asking the wrong one would let a preview's answer stand in for a
        // capability the run does not have.
        None => review::plan_for(
            &analysis.plan,
            &analysis.chains,
            &analysis.config,
            |id| harness.adapters.get(id).is_some(),
            &mut warnings,
        )?,
    };
    // A legacy record is not trustworthy merely because its missing marker
    // fields can be filled. Validate the complete inherited identity before
    // probing an adapter or dispatching any paid work; otherwise a malformed
    // schema-2 pass list can run once and only be rejected after it has been
    // appended as schema 3.
    events::validate_review_identity(&review_plan, analysis.plan.tasks.len(), &opts.plan_path)?;
    let review_pass_timeout = review_plan.pass_timeout()?;

    // Probe every agent the chains reference; a missing binary is a refusal
    // to start, not a task failure (§19). The capabilities are kept, not
    // discarded: §11.4's same-rung retry resumes a session only where the
    // adapter says it can.
    //
    // Reviewers are probed on the same footing as implementers — step-6
    // finding #10 — but in two classes. Everything the config *asked* for is
    // required. The anti-self-review alternative was tactus's own idea, so a
    // machine that cannot run it loses the upgrade rather than the run.
    //
    // Resume draws the line in the same place. Requiring the alternative there
    // — on the grounds that a run should keep one verification standard — would
    // refuse to continue over a reviewer that may never have judged anything,
    // and the per-attempt record already names who judged each attempt, so the
    // ledger stays honest either way. A loud warning beats a dead run.
    let required = review_plan.required_agents();
    let optional: Vec<String> = review_plan
        .agents()
        .into_iter()
        .filter(|id| !required.contains(id))
        .map(str::to_owned)
        .collect();
    let mut agent_ids: Vec<&str> = analysis
        .chains
        .iter()
        .flat_map(|c| c.rungs.iter().map(|r| r.binding.agent.as_str()))
        .chain(required)
        .collect();
    agent_ids.sort_unstable();
    agent_ids.dedup();
    let mut caps: BTreeMap<String, Caps> = BTreeMap::new();
    for id in agent_ids {
        let adapter = harness.adapters.get(id).ok_or_else(|| TactusError::Agent {
            message: format!("no adapter registered for agent `{id}`"),
        })?;
        caps.insert(id.to_owned(), adapter.probe(runner)?);
    }
    for id in optional {
        if caps.contains_key(&id) {
            continue;
        }
        let probed = harness
            .adapters
            .get(&id)
            .ok_or_else(|| TactusError::Agent {
                message: format!("no adapter registered for agent `{id}`"),
            })
            .and_then(|adapter| adapter.probe(runner));
        match probed {
            Ok(caps_for_id) => {
                caps.insert(id, caps_for_id);
            }
            Err(error) => {
                let binding = review_plan
                    .alternative
                    .as_ref()
                    .map_or_else(|| id.clone(), PassBinding::describe);
                warnings.push(format!(
                    "{binding} would have reviewed tasks their own model implemented, but it \
                     could not be probed: {error}. Those tasks fall back to same-model review \
                     (§11.3)."
                ));
                review_plan.drop_alternative();
                // Now say WHICH tasks. Resolution could not: a shipped binary
                // always has the Copilot adapter, so the only way the rebind
                // actually goes missing is right here, and naming the tasks is
                // the difference between a note and something actionable.
                let tier = analysis
                    .config
                    .review_tier
                    .unwrap_or(crate::ir::Tier::Frontier);
                if let Some(warning) =
                    review_plan.self_review_warning(&analysis.plan, &analysis.chains, tier)
                {
                    warnings.push(warning);
                }
            }
        }
    }

    // Effective gates come from the shared analysis (single derivation point
    // with `validate`), or from the record above. §14 pre-flight: the shell and
    // every gate command must resolve before any agent tokens are spent — and
    // on a resume that check runs against the *recorded* gates, so a machine
    // that cannot run what this run verifies against says so plainly instead of
    // quietly proceeding.
    //
    // Per gate rather than per config: a recorded gate carries the shell it ran
    // under, and nothing requires every gate in a list to share one.
    if !analysis.gates.is_empty() {
        let mut shells: Vec<crate::gates::ShellKind> =
            analysis.gates.iter().map(|gate| gate.shell).collect();
        shells.sort_unstable_by_key(|shell| shell.program());
        shells.dedup();
        for shell in shells {
            gates::shell_available(shell)?;
        }
        gates::resolve_programs(&analysis.gates, &opts.repo_root, &mut warnings)?;
    }
    let gates = gate_summaries(&analysis);
    let gate_cmds: Vec<String> = gates.iter().map(|gate| gate.cmd.clone()).collect();

    let mode = opts.interaction.unwrap_or(analysis.config.interaction_mode);
    let notifiers = interaction::notifiers_for(&analysis.config.notify, &mut warnings);
    // Here, with the other pre-flight refusals, rather than where the ceiling
    // is first read: `--budget 0` must not create a branch and a run directory
    // before discovering it cannot spend anything (§14 — pre-flight refuses
    // before any agent token is spent, and before the workspace is touched).
    let budgets = effective_budgets(analysis.config.budgets, opts.budget_usd)?;

    Ok(Preflight {
        analysis,
        caps,
        review_plan,
        review_pass_timeout,
        gates,
        gate_cmds,
        warnings,
        mode,
        notifiers,
        budgets,
    })
}

/// `[budgets]` with `--budget` folded in.
///
/// The flag overrides `run_usd` only. `task_usd` has no flag because a
/// per-task ceiling is a property of how the plan is shaped, not of one
/// invocation — and a single `--budget` that quietly moved both would be
/// impossible to reason about at the ledger afterwards.
fn effective_budgets(
    configured: config::Budgets,
    flag: Option<f64>,
) -> Result<config::Budgets, TactusError> {
    // Validated through the same check `[budgets]` uses. A flag that overrides
    // a validated key must not be a way around the validation: `--budget 0` and
    // `--budget -5` both stop the run before it spends anything, and
    // `--budget nan` silently never fires at all — three different broken
    // behaviours behind one mistyped number, where the config key refuses all
    // three at load.
    if let Some(limit) = flag {
        config::check_budget("--budget", limit)
            .map_err(|message| TactusError::Refused { message })?;
    }
    Ok(config::Budgets {
        run_usd: flag.or(configured.run_usd),
        task_usd: configured.task_usd,
    })
}

/// A path as the run record should carry it: relative to the repo root where
/// possible, so the record survives the repository being moved or cloned
/// somewhere else before a resume.
pub(super) fn repo_relative(repo_root: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// The resolved chain per task, as it stood at this moment.
pub(super) fn chain_summaries(analysis: &Analysis) -> Vec<ChainSummary> {
    analysis
        .plan
        .tasks
        .iter()
        .zip(&analysis.chains)
        .map(|(task, chain)| ChainSummary {
            task: task.id.to_string(),
            tiers: chain.rungs.iter().map(|rung| rung.tier).collect(),
            attempts_per: chain.attempts_per,
            bindings: Some(
                chain
                    .rungs
                    .iter()
                    .map(|rung| BindingSummary {
                        tier: rung.tier,
                        agent: rung.binding.agent.clone(),
                        model: rung.binding.model.clone(),
                        pinned: rung.binding.pinned,
                    })
                    .collect(),
            ),
        })
        .collect()
}

/// Validate the rung index space and restore the exact bindings the run began
/// with. Structural changes still refuse: an existing `Progress.rung` cannot be
/// interpreted against a different tier list. Binding-only changes warn and
/// continue with the snapshot, matching gates and effort.
fn restore_recorded_routing(
    analysis: &mut Analysis,
    recorded: &RecordedRouting,
    warnings: &mut Vec<String>,
) -> Result<(), TactusError> {
    let current = chain_summaries(analysis);
    let same_structure = current.len() == recorded.structure.len()
        && current.iter().zip(&recorded.structure).all(|(now, then)| {
            now.task == then.task
                && now.tiers == then.tiers
                && now.attempts_per == then.attempts_per
        });
    if !same_structure {
        let moved: Vec<String> = current
            .iter()
            .zip(&recorded.structure)
            .filter(|(now, then)| {
                now.task != then.task
                    || now.tiers != then.tiers
                    || now.attempts_per != then.attempts_per
            })
            .map(|(now, then)| {
                format!(
                    "`{}` ran on [{}] with {} attempt(s) per rung and would now run on [{}] with {}",
                    then.task,
                    render_tiers(then),
                    then.attempts_per,
                    render_tiers(now),
                    now.attempts_per,
                )
            })
            .collect();
        let detail = if moved.is_empty() {
            format!(
                "the run recorded {} task chain(s), while today's plan resolves {}",
                recorded.structure.len(),
                current.len()
            )
        } else {
            moved.join("; ")
        };
        return Err(TactusError::Resume {
            run_id: recorded.run_id.clone(),
            message: format!(
                "routing has changed since this run started, so a recorded rung would now mean a \
                 different tier or allowance: {detail}. Restore the config it ran with, or start \
                 a new run."
            ),
        });
    }

    let Some(snapshot) = recorded.bindings.as_ref() else {
        warnings.push(
            "this run's log predates the resolved-binding record, so worker agent/model bindings \
             were re-derived from today's config rather than read from the run — earlier attempts \
             may have used different bindings"
                .to_owned(),
        );
        return Ok(());
    };
    if snapshot.len() != analysis.chains.len() {
        return Err(TactusError::Resume {
            run_id: recorded.run_id.clone(),
            message: "the recorded binding snapshot does not align with the run's task chains; \
                      the event log cannot safely identify which model belongs to which task"
                .to_owned(),
        });
    }

    let mut changed = Vec::new();
    for ((chain, now), then) in analysis.chains.iter_mut().zip(&current).zip(snapshot) {
        if then.task != now.task || then.tiers != now.tiers || then.attempts_per != now.attempts_per
        {
            return Err(TactusError::Resume {
                run_id: recorded.run_id.clone(),
                message: format!(
                    "the recorded binding snapshot for `{}` does not match its frozen chain",
                    then.task
                ),
            });
        }
        let Some(bindings) = then.bindings.as_ref() else {
            return Err(TactusError::Resume {
                run_id: recorded.run_id.clone(),
                message: format!(
                    "the recorded binding snapshot for `{}` is missing its bindings",
                    then.task
                ),
            });
        };
        if bindings.len() != chain.rungs.len() {
            return Err(TactusError::Resume {
                run_id: recorded.run_id.clone(),
                message: format!(
                    "the recorded binding snapshot for `{}` has {} binding(s) for {} rung(s)",
                    then.task,
                    bindings.len(),
                    chain.rungs.len()
                ),
            });
        }
        for (rung, binding) in chain.rungs.iter_mut().zip(bindings) {
            if binding.tier != rung.tier {
                return Err(TactusError::Resume {
                    run_id: recorded.run_id.clone(),
                    message: format!(
                        "the recorded binding snapshot for `{}` assigns tier `{}` to a `{}` rung",
                        then.task, binding.tier, rung.tier
                    ),
                });
            }
            if rung.binding.agent != binding.agent
                || rung.binding.model != binding.model
                || rung.binding.pinned != binding.pinned
            {
                changed.push(format!(
                    "`{}` {}: recorded {}/{}, today {}/{}",
                    then.task,
                    rung.tier,
                    binding.agent,
                    binding.model,
                    rung.binding.agent,
                    rung.binding.model
                ));
            }
            rung.binding.agent = binding.agent.clone();
            rung.binding.model = binding.model.clone();
            rung.binding.pinned = binding.pinned;
        }
    }
    if !changed.is_empty() {
        warnings.push(format!(
            "today's worker bindings differ from the ones this run recorded ({}). This resume \
             keeps the recorded bindings. Start a new run to adopt today's routing.",
            changed.join("; ")
        ));
    }
    Ok(())
}

/// The effective gates, in full, as they stood at this moment.
fn gate_summaries(analysis: &Analysis) -> Vec<GateSummary> {
    analysis
        .gates
        .iter()
        .map(|gate| GateSummary {
            name: gate.name.clone(),
            cmd: gate.cmd.clone(),
            timeout: gate.timeout,
            shell: gate.shell,
        })
        .collect()
}

fn render_tiers(chain: &ChainSummary) -> String {
    chain
        .tiers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" → ")
}

/// What today's config would gate with, against what the run recorded — `None`
/// when they agree.
///
/// This is a **warning**, not a refusal: the run continues under the gates it
/// recorded, and the operator's edit simply does not apply to it. Saying so is
/// still worth a line, because an edit that silently does nothing is how
/// somebody concludes the gate is broken.
///
/// Matching is by whole gate, then paired up by name, which is what makes the
/// message survive the shapes a by-name lookup got wrong: duplicate names are
/// legal in `[[gates]]`, so `find`-by-name silently answers for the wrong entry
/// — reporting an edit nobody made, or finding every name present and claiming
/// a reorder when a gate was added.
pub(super) fn gates_differ(recorded: &[GateSummary], now: &[GateSummary]) -> Option<String> {
    if recorded == now {
        return None;
    }
    // Whole-gate multiset difference: what the record has that today lacks, and
    // the reverse. Anything appearing in both cancels, however many times.
    let mut unmatched: Vec<&GateSummary> = now.iter().collect();
    let mut dropped: Vec<&GateSummary> = Vec::new();
    for gate in recorded {
        match unmatched.iter().position(|other| *other == gate) {
            Some(index) => {
                unmatched.remove(index);
            }
            None => dropped.push(gate),
        }
    }
    if dropped.is_empty() && unmatched.is_empty() {
        // Same gates, listed in a different order. Worth a line — the record is
        // what runs, and the order it runs in decides which failure a task sees
        // first — but not the same claim as a changed command.
        return Some(
            "the gates in today's config are the ones this run recorded, in a different order; \
             it continues in its recorded order"
                .to_owned(),
        );
    }
    // A name in exactly one dropped and one added gate is one gate edited, not
    // one removed and an unrelated one added. Only when it is unambiguous:
    // with duplicates, "which `check` became which" has no answer worth
    // guessing at, so both sides are reported plainly instead.
    let once = |gates: &[&GateSummary], name: &str| {
        gates.iter().filter(|gate| gate.name == name).count() == 1
    };
    let mut items: Vec<String> = Vec::new();
    let mut paired: Vec<&GateSummary> = Vec::new();
    for gate in &dropped {
        let edited = unmatched
            .iter()
            .find(|other| {
                other.name == gate.name
                    && once(&dropped, &gate.name)
                    && once(&unmatched, &gate.name)
            })
            .copied();
        match edited {
            Some(other) => {
                paired.push(other);
                items.push(format!("`{}` {}", gate.name, changes_between(gate, other)));
            }
            None => items.push(format!(
                "`{}` (`{}`) is in the record and not in today's config",
                gate.name, gate.cmd
            )),
        }
    }
    for gate in unmatched {
        if paired.iter().any(|other| std::ptr::eq(*other, gate)) {
            continue;
        }
        items.push(format!(
            "`{}` (`{}`) is in today's config and not in the record",
            gate.name, gate.cmd
        ));
    }
    Some(format!(
        "the gates in today's config differ from the ones this run recorded, and a run keeps the \
         gates it started with, so these edits do not apply to it: {}. Start a new run to adopt \
         them.",
        items.join("; ")
    ))
}

/// How one gate's recorded form and its form in today's config differ.
fn changes_between(recorded: &GateSummary, now: &GateSummary) -> String {
    let mut parts: Vec<String> = Vec::new();
    if recorded.cmd != now.cmd {
        parts.push(format!(
            "runs `{}` and today's config says `{}`",
            recorded.cmd, now.cmd
        ));
    }
    if recorded.shell != now.shell {
        parts.push(format!(
            "runs under `{}` and today's config says `{}`",
            recorded.shell.program(),
            now.shell.program()
        ));
    }
    if recorded.timeout != now.timeout {
        parts.push(format!(
            "has {}s to finish and today's config allows {}s",
            recorded.timeout.as_secs(),
            now.timeout.as_secs()
        ));
    }
    parts.join(", and ")
}

pub(super) fn normalized_plan_bytes(plan: &Plan, path: &Path) -> Result<Vec<u8>, TactusError> {
    let mut bytes = serde_json::to_vec_pretty(plan).map_err(|error| TactusError::Parse {
        message: format!("serializing {}: {error}", path.display()),
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}
