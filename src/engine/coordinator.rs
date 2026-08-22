// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::time::Duration;

use crate::agent::{AdapterSource, Caps};
use crate::capacity;
use crate::config::{self, OnTaskFailure};
use crate::error::TactusError;
use crate::events::{
    self, AttemptRecord, EventBody, EventLog, FailureRecord, Progress, RunState, TaskState,
};
use crate::interaction::{self, AnswerSource, Notifier, QuestionRecord, RealSleeper, Sleeper};
use crate::ir::{
    Answer, PermissionMode, Question, QuestionId, QuestionKind, ResolvedEffortPolicy, Task,
    WorkerProfile,
};
use crate::ladder::{
    self, AttemptFailure, FailureKind, FailureOrigin, LadderPolicy, LadderState, Next,
};
use crate::review::{PassBinding, ReviewPass, ReviewPlan};
use crate::rundir::{self, RunLock, RunPaths, WorktreeLock};
use crate::runner::Runner;
use crate::topology::effects::EventSite;
use crate::ulid;
use crate::util;
use crate::validate::Analysis;
use crate::workspace::Workspace;

use super::attempt::{AttemptCx, RetryBrief, Reviewer, pool_option, run_attempt};
#[cfg(test)]
use super::options::AfterCandidateCapture;
use super::options::{Harness, RunOptions};
use super::preflight::{
    Preflight, chain_summaries, normalized_plan_bytes, preflight, repo_relative, validate_inputs,
};
use super::report::{
    ReportHeader, RunOutcome, RunReport, TaskRunStatus, build_report, last_reason,
};

/// Also hands back the state the run ended with — its own fold of its own log.
///
/// Only tests use the second half, to hold the live fold and a replay of the
/// same file side by side. Nothing in the engine reads state back.
#[cfg(test)]
pub(super) fn run_harness_inner(
    opts: &RunOptions,
    harness: &Harness<'_>,
) -> Result<(RunReport, RunState), TactusError> {
    let contained = crate::runner::host::contain_write_command(&mut crate::agent::proc::NoHooks)?;
    run_harness_inner_on(
        opts,
        harness,
        &crate::runner::host::HostRunner::new(),
        &contained,
    )
}

/// The same run, on an explicit boundary. See [`super::run_harness_on`].
///
/// `_contained` is INV-18's host portion as a capability: "on Windows every
/// host child is a member of the coordinator's ambient kill-on-close Job
/// Object **from creation**", enforced by "ambient job joined at write-command
/// startup (refusal otherwise)". This function is the write coordinator, and
/// [`crate::runner::host::Contained`] cannot be built outside
/// `crate::runner::host`, so no caller — a CLI arm, the frozen public engine
/// facade, or an entry point added later — can reach a spawn without having
/// established containment first. That is a compile error rather than a
/// convention, which is what the previous shape was: the CLI established it
/// and `engine::run_with` did not.
pub(super) fn run_harness_inner_on(
    opts: &RunOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
    _contained: &crate::runner::host::Contained,
) -> Result<(RunReport, RunState), TactusError> {
    // Every read-only refusal precedes every lock: the plan, the config, and
    // `[engine]`'s ceilings are checked here, where nothing has been created
    // yet, so a config this engine cannot honour cannot leave a git-dir lock
    // file behind on its way to being refused — and cannot lose a race to a
    // competing holder of the lease it never needed.
    let validated = validate_inputs(opts, config::EngineLimits::Fresh)?;
    let workspace = Workspace::open(&opts.repo_root)?;
    // Preflight reads the source plan, config, and gate programs from this
    // physical worktree. Own it before taking that snapshot so another run
    // cannot leave us with an analysis of its transient edits.
    let worktree_git_dir = workspace.worktree_git_dir()?;
    let _worktree_lock = WorktreeLock::acquire_in(workspace.root(), &worktree_git_dir)?;
    // The lease is what makes a read of this worktree a fact about it, so the
    // analysis the run executes is captured and validated here rather than
    // before — and adopted only once it agrees, byte for byte, with what the
    // refusal above was decided on.
    let analysis = validated.confirm_under_lease(opts, config::EngineLimits::Fresh)?;
    let Preflight {
        analysis,
        caps,
        review_plan,
        review_pass_timeout,
        gates,
        gate_cmds,
        mut warnings,
        mode,
        notifiers,
        budgets,
    } = preflight(opts, harness, runner, analysis)?;

    workspace.ensure_execution_prerequisites()?;
    workspace.ensure_run_exclusions()?;
    if !workspace.is_clean()? {
        return Err(TactusError::Git {
            message: "working tree is not clean; commit or stash first (the engine refuses \
                      dirty trees)"
                .to_owned(),
        });
    }
    let base_sha = workspace.head_sha_full()?;
    let wait_on_block = opts.wait_on_block;

    let run_id = ulid::ulid();
    let branch = format!("tactus/run-{run_id}");
    let paths = opts.paths(&run_id);
    paths.create()?;
    // Held for the whole run, released by the OS if this process dies — so a
    // crash leaves nothing for `resume` to clear by hand.
    let _lock = RunLock::acquire(&paths.public)?;
    let _cleanup_scope = _lock.enter_cleanup_scope();

    // Nothing is on the record until the first event lands, so a failure in
    // this window would leave a run directory with no `events.jsonl` in it —
    // and that husk becomes `latest_run`, so a bare `tactus status` reports
    // "no event log here" for a run that never began, shadowing the real
    // latest one until someone deletes it by hand. Best-effort: failing to
    // tidy up must not mask the error that actually stopped the run.
    let plan_path = paths.plan_json();
    let normalized_plan = normalized_plan_bytes(&analysis.plan, &plan_path)?;
    let normalized_plan_digest = events::normalized_plan_digest(&normalized_plan);
    let opened = rundir::write_plan(&paths.public, &normalized_plan, &mut rundir::NoHooks)
        .and_then(|()| {
            let read_back = fs::read(&plan_path).map_err(|source| TactusError::Io {
                path: plan_path.clone(),
                source,
            })?;
            if read_back != normalized_plan {
                return Err(TactusError::Refused {
                    message: format!(
                        "{} changed while tactus was freezing it; refusing to record a digest for bytes it did not write",
                        plan_path.display()
                    ),
                });
            }
            workspace.create_branch(&branch)
        });
    if let Err(error) = opened {
        drop(_cleanup_scope);
        drop(_lock);
        let _ = fs::remove_dir_all(&paths.public);
        let _ = fs::remove_dir_all(&paths.private);
        return Err(error);
    }

    let effort_policy = analysis.config.resolved_effort_policy();
    let started = events::RunStarted {
        schema: events::SCHEMA_VERSION,
        tactus_version: env!("CARGO_PKG_VERSION").to_owned(),
        run_id: run_id.clone(),
        branch: branch.clone(),
        base_sha,
        plan_path: repo_relative(&opts.repo_root, &opts.plan_path),
        config_path: opts
            .config_path
            .as_ref()
            .map(|path| repo_relative(&opts.repo_root, path)),
        plan_hash: analysis.plan.source.hash.clone(),
        normalized_plan_digest: Some(normalized_plan_digest),
        private_dir: paths.private.to_string_lossy().into_owned(),
        // Names for the reader, the full gates for the resume — both from the
        // one list pre-flight resolved, so the log cannot name a gate its own
        // record does not describe.
        gates: gates.iter().map(|gate| gate.name.clone()).collect(),
        gates_from_config: analysis.gates_from_config,
        interaction_mode: mode.to_string(),
        chains: chain_summaries(&analysis),
        effort_policy: Some(effort_policy),
        reviews: Some(review_plan.clone()),
        gate_cmds: Some(gates),
    };

    let sleeper = harness.sleeper.unwrap_or(&RealSleeper);
    let default_answers = interaction::answers_for(
        mode,
        paths.answers(),
        wait_on_block.unwrap_or(analysis.config.wait_on_block),
        sleeper,
    );
    let log = EventLog::open(EventSite::LegacyOpenLog, &paths.events(), &mut warnings)?;
    let mut run = Run {
        state: RunState::new(
            analysis
                .plan
                .tasks
                .iter()
                .map(|task| task.id.to_string())
                .collect(),
        ),
        analysis: &analysis,
        workspace: &workspace,
        paths,
        log,
        log_hooks: legacy_append_hooks(opts),
        gate_cmds,
        adapters: harness.adapters,
        runner,
        answers: harness.answers.unwrap_or(default_answers.as_ref()),
        notifiers,
        sleeper,
        caps,
        review_plan,
        effort_policy,
        attempt_timeout: opts.attempt_timeout,
        review_pass_timeout,
        defer_backoff: opts.defer_backoff,
        max_defers: opts.max_defers,
        on_task_failure: analysis.config.on_task_failure,
        budgets,
        ask_before: analysis.config.ask_before,
        run_id,
        branch,
        warnings,
        unanswerable: Vec::new(),
        exhausted_pools: std::collections::BTreeSet::new(),
        #[cfg(test)]
        after_candidate_capture: opts.after_candidate_capture,
    };
    run.emit(EventBody::RunStarted {
        data: Box::new(started),
    })?;
    // A fresh run has no signals of its own yet, and §13's other sources are
    // not read in v0.1 — so this snapshot is honestly a record of how little
    // was known when the run started.
    run.emit_capacity_snapshot(&BTreeMap::new())?;
    let report = run.drain_and_report()?;
    Ok((report, run.state.clone()))
}

pub(super) fn prepared_pin_ref(run_id: &str, task_index: usize, attempt: u32) -> String {
    format!("refs/tactus/prepared/{run_id}/{task_index}-{attempt}")
}

pub(super) struct Run<'a> {
    pub(super) analysis: &'a Analysis,
    pub(super) workspace: &'a Workspace,
    pub(super) paths: RunPaths,
    /// The append-only record. Every mutation below goes through
    /// [`Run::emit`], never straight at `state`.
    pub(super) log: EventLog,
    /// The observer the **legacy** append funnel is driven through.
    ///
    /// Production passes [`NoEventHooks`], which is precisely what
    /// `EventLog::append` passes on its own, so nothing about the legacy
    /// engine's behaviour moves — `invariants_preserved[1]`. What moves is that
    /// the failure is now *reachable* (`PR5-CONF-010`, `PR5-CONF-011`).
    ///
    /// `production_effect` says "the legacy engine's handling of a returned
    /// append error is unchanged — **it reports and stops**". The shipped code
    /// did; nothing required it to. Replacing this function's `?` with an arm
    /// that pushed a warning and returned `Ok` survived the whole suite, because
    /// every append failure the suite injects targets an `EventLog` a test
    /// built directly, and no fixture could make a **live `Run`**'s append fail:
    /// `emit` called `append`, which hard-codes `NoEventHooks`. A source census
    /// cannot tell propagation from swallowing inside a live run.
    ///
    /// This is the resolution `PR4-CONF-005` reached for the same shape — no
    /// machine here can make the real primitive fail, so the observer becomes a
    /// parameter and production passes the no-op one.
    pub(super) log_hooks: Box<dyn crate::events::log::EventHooks>,
    /// Derived state — the same fold `resume` and `status` build from the log.
    pub(super) state: RunState,
    pub(super) gate_cmds: Vec<String>,
    pub(super) adapters: &'a dyn AdapterSource,
    /// Where every process of this run executes (DESIGN.md:118). Held for the
    /// whole run because pre-flight's probes and the attempts must cross the
    /// same boundary — "Probes run through that same runner, or pre-flight
    /// could certify a host CLI/version different from the one the attempt
    /// executes" (DESIGN.md:612).
    pub(super) runner: &'a dyn Runner,
    pub(super) answers: &'a dyn AnswerSource,
    pub(super) notifiers: Vec<&'static dyn Notifier>,
    pub(super) sleeper: &'a dyn Sleeper,
    /// Probe results per agent id — `session_resume` gates §11.4's resume.
    pub(super) caps: BTreeMap<String, Caps>,
    /// Who judges each task (§11.2–§11.3), resolved once at pre-flight and
    /// recorded in `run_started`.
    pub(super) review_plan: ReviewPlan,
    /// The run's recorded effort standard. Both worker attempts and all review
    /// passes read this snapshot, including after a resume under changed config.
    pub(super) effort_policy: ResolvedEffortPolicy,
    pub(super) attempt_timeout: Duration,
    /// Independent wall clock for each configured review pass. Frozen in
    /// `review_plan`, materialized once by pre-flight.
    pub(super) review_pass_timeout: Duration,
    pub(super) defer_backoff: Duration,
    pub(super) max_defers: u32,
    pub(super) on_task_failure: OnTaskFailure,
    /// §17's ceilings, with `--budget` already folded in. Checked before every
    /// spawn; never consulted when deciding *what* binds.
    pub(super) budgets: config::Budgets,
    /// §12's `ask_before` thresholds.
    pub(super) ask_before: config::AskBefore,
    pub(super) run_id: String,
    pub(super) branch: String,
    pub(super) warnings: Vec<String>,
    /// Questions no channel could reach a human for. Never asked twice — that
    /// is what stops a hard block spinning.
    ///
    /// Deliberately *not* replayed: it records that a channel was unreachable
    /// in this process, not something true about the run. A question nobody
    /// could answer at 2am is exactly the one the operator answers when they
    /// come back, so a resume has to be free to ask it again.
    pub(super) unanswerable: Vec<QuestionId>,
    /// Pools this run has already recorded a rate-limit signal for.
    ///
    /// Only the *transition* is worth an event. One outage produces a failed
    /// attempt per deferral (up to `max_defers`), and emitting on each wrote N
    /// identical records of a single fact — inflating any later count of
    /// outages by the deferral factor and repeating the same line N times in
    /// `status --follow`. Retired when an attempt proves the pool is serving
    /// again, mirroring [`capacity::observe`]'s rule so the log the engine
    /// writes and the fold a reader performs agree about when a pool came back.
    ///
    /// Process-local rather than folded state, like `unanswerable`: seeded on
    /// resume from the log's own signals, so a resumed run neither re-announces
    /// an outage the previous process recorded nor misses a fresh one.
    pub(super) exhausted_pools: std::collections::BTreeSet<String>,
    #[cfg(test)]
    pub(super) after_candidate_capture: Option<AfterCandidateCapture>,
}

/// The observer the live run's legacy append funnel is driven through.
///
/// Production is [`NoEventHooks`] — the same thing `EventLog::append` passes —
/// on both arms. The `#[cfg(test)]` arm exists so a fixture can make a live
/// `Run`'s append fail (`PR5-CONF-010`, `PR5-CONF-011`).
#[cfg(test)]
fn legacy_append_hooks(opts: &RunOptions) -> Box<dyn crate::events::log::EventHooks> {
    match opts.log_hooks {
        Some(make) => make(),
        None => Box::new(crate::events::log::NoEventHooks),
    }
}

/// See the `#[cfg(test)]` twin above.
#[cfg(not(test))]
fn legacy_append_hooks(_opts: &RunOptions) -> Box<dyn crate::events::log::EventHooks> {
    Box::new(crate::events::log::NoEventHooks)
}

impl Run<'_> {
    /// Append an event and fold it in.
    ///
    /// The only way run state changes. Everything below emits; nothing reaches
    /// past this into `state`, which is what makes a live run and a replay of
    /// its own log the same computation rather than two that agree by
    /// inspection.
    pub(super) fn emit(&mut self, body: EventBody) -> Result<(), TactusError> {
        let site = EventSite::LegacyAppend;
        let event = self
            .log
            .append_hooked(site, body, self.log_hooks.as_mut())?;
        self.state.apply(&event);
        Ok(())
    }

    /// Drain, settle, and report.
    pub(super) fn drain_and_report(&mut self) -> Result<RunReport, TactusError> {
        if let Err(error) = self.drain() {
            // The log already holds everything that happened, including the
            // attempt this died inside — that is what `resume` reads. The
            // report beside it is a courtesy for whoever opens the directory
            // next, and failing to write it must not mask the error that
            // actually stopped the run.
            let partial = self.finish();
            let _ = rundir::write_report(&self.paths.public, &partial, &mut rundir::NoHooks);
            return Err(error);
        }
        let report = self.finish();
        let committed = report
            .tasks
            .iter()
            .filter(|task| matches!(task.status, TaskRunStatus::Committed { .. }))
            .count();
        self.emit(EventBody::RunFinished {
            data: events::RunFinished {
                outcome: match report.outcome() {
                    RunOutcome::Complete => events::RunOutcome::Complete,
                    RunOutcome::Parked => events::RunOutcome::Parked,
                    RunOutcome::Halted => events::RunOutcome::Halted,
                    RunOutcome::BudgetExceeded => events::RunOutcome::BudgetExceeded,
                },
                halted_at: report.halted_at.clone(),
                committed: u32::try_from(committed).unwrap_or(u32::MAX),
                parked: u32::try_from(report.parked_tasks().len()).unwrap_or(u32::MAX),
            },
        })?;
        rundir::write_report(&self.paths.public, &report, &mut rundir::NoHooks)?;
        Ok(report)
    }

    /// Drain the graph (§14, §12).
    ///
    /// The four branches are the whole interaction model: pick up answers that
    /// arrived from somewhere else; run what is ready; if only deferred work is
    /// left, wait for the pool rather than burning attempts against it; and
    /// only when none of those is possible — the precise definition of a hard
    /// block — ask a human.
    ///
    /// **Why this terminates.** Every branch consumes something finite and
    /// nothing replenishes any of them:
    ///
    /// - the answer sweep fires only for an *open* question and closes it, and
    ///   questions are created only by `step_task`;
    /// - `step_task` moves its task out of `Pending`, and the only routes back
    ///   are a deferral — bounded by `max_defers`, after which the ladder parks
    ///   the task instead — or an answer, which closed a question to get there;
    /// - the wait branch requires a `Deferred` task, which only a deferral
    ///   creates;
    /// - the ask branch either closes a question or adds it to `unanswerable`,
    ///   which is only ever appended to and is checked before asking.
    ///
    /// So no cycle exists that does not spend an attempt, a deferral, or a
    /// question. `an_exhausted_pool_and_a_silent_operator_still_terminate`
    /// holds it to that against an adapter that never succeeds and an operator
    /// who never replies.
    fn drain(&mut self) -> Result<(), TactusError> {
        let mut defer_round = 0u32;
        loop {
            // Invariant 6 in its most useful form: an answer that arrives while
            // other work is still running un-parks its task there and then,
            // rather than waiting for the run to have nothing else to do.
            //
            // Guarded on the budget stop like the two branches below, and for a
            // sharper reason than theirs: an answer this run cannot act on is
            // merely wasted, but a *declined* one routes through `fail_task`,
            // which sets `halted_at` — and halted outranks budget in
            // `outcome()`. A decline file sitting on disk would relabel a
            // budget stop as a task failure, so CI gating on exit 3 to raise a
            // ceiling would instead see exit 1 and a task blamed for something
            // the ceiling did. The answers keep for the resume (§15).
            if self.state.budget_stop.is_none() && self.sweep_answers()? {
                continue;
            }
            if let Some(index) = self.next_ready() {
                let deferred = self.step_task(index)?;
                if !deferred {
                    defer_round = 0;
                }
                continue;
            }
            if self.state.states.contains(&TaskState::Deferred)
                && self.state.halted_at.is_none()
                && self.state.budget_stop.is_none()
            {
                let waited = interaction::defer_backoff(self.defer_backoff, defer_round);
                self.sleeper.sleep(waited);
                defer_round = defer_round.saturating_add(1);
                self.emit(EventBody::DeferWaitElapsed {
                    data: events::DeferWaitElapsed {
                        waited,
                        round: defer_round,
                    },
                })?;
                continue;
            }
            // Guarded like the other branches: once the run has halted, no
            // answer can reach an attempt this session, so asking would spend
            // a human's attention on a decision the scheduler cannot act on —
            // and a decline would relabel `halted_at` with a task that was not
            // the cause. The questions stay open on disk for a resume (§15).
            if self.state.halted_at.is_none()
                && self.state.budget_stop.is_none()
                && self.resolve_one_question()?
            {
                continue;
            }
            break;
        }
        Ok(())
    }

    /// Stable order: among tasks whose dependencies are all done, lowest plan
    /// index first (§14). Parked, deferred, and blocked tasks are simply not
    /// ready — which is exactly the skip-ahead §14 asks for.
    fn next_ready(&self) -> Option<usize> {
        // A halt and a budget stop both end scheduling, for the same reason:
        // whatever runs next would be work the run has already decided not to
        // do. The remaining tasks settle as skipped exactly as they do after a
        // halt, and the questions already open stay open for a resume (§15).
        if self.state.halted_at.is_some() || self.state.budget_stop.is_some() {
            return None;
        }
        let tasks = &self.analysis.plan.tasks;
        (0..tasks.len()).find(|&i| {
            matches!(self.state.states[i], TaskState::Pending)
                && tasks[i].depends_on.iter().all(|dep| {
                    tasks
                        .iter()
                        .position(|t| t.id == *dep)
                        // An unknown dependency cannot exist on a validated
                        // plan; treating it as satisfied keeps the scheduler
                        // total rather than deadlocking.
                        .is_none_or(|j| matches!(self.state.states[j], TaskState::Done(_)))
                })
        })
    }

    /// Drive one task until it yields the scheduler: done, failed, deferred,
    /// or parked. Retries and escalations happen *inside* — a resumed retry
    /// keeps the working tree (§14), so no other task may run in between, and
    /// this loop is what guarantees that.
    ///
    /// Returns whether the task ended deferred.
    fn step_task(&mut self, index: usize) -> Result<bool, TactusError> {
        // Copied out of `self` so they carry the run's lifetime rather than
        // this method's `&mut self` borrow.
        let analysis = self.analysis;
        let adapters = self.adapters;
        let workspace = self.workspace;
        let task = &analysis.plan.tasks[index];
        let task_id = task.id.to_string();
        let chain = &analysis.chains[index];
        let policy = LadderPolicy {
            attempts_per: chain.attempts_per,
            rungs: chain.rungs.len(),
            max_defers: self.max_defers,
        };
        let stem = format!("{index:02}-{}", util::filename_component(task.id.as_str()));

        loop {
            let rung_index = self.state.progress[index].rung;
            let Some(rung) = chain.rungs.get(rung_index) else {
                self.fail_task(
                    index,
                    FailureKind::NoChain,
                    "resolved chain has no rung to run on".to_owned(),
                )?;
                return Ok(false);
            };
            // §13's ceiling, checked before EVERY spawn rather than once per
            // task. The placement is the whole point: an escalation onto a
            // frontier rung happens inside this loop, so a check that ran only
            // on the way in would let the most expensive attempt of the run be
            // the one that dodged the budget. It never influences *what* binds
            // — capacity-driven routing is v0.2 (§13) — only whether the next
            // attempt happens at all.
            if let Some(exceeded) = self.budget_breach(index) {
                // The ceiling is recorded first, and nothing below may take it
                // back. It is what `outcome()` reads to return `BudgetExceeded`
                // rather than a task failure, what turns into exit 3 for the CI
                // job gating on it, and what `resume --budget` needs to find in
                // order to have a stop to get past. Tidying up afterwards is a
                // courtesy; the record is the run's account of itself.
                self.emit(EventBody::BudgetExceeded { data: exceeded })?;
                // The tree may still hold a rejected attempt's edits, kept by
                // the ladder below for a resumed retry that is now never going
                // to run. Handing those back is the one thing §14 rules out —
                // they are unverified, and staged changes follow `git switch`
                // onto whatever branch the operator visits next. Nor can they
                // be saved for the resume: `run_resumed` discards every
                // uncommitted path and clears the session they belong to, so
                // keeping them past this point buys nothing at all.
                //
                // A git that cannot do it says so and the run still stops at
                // its ceiling, the way it did before the tidying existed. The
                // sibling discard on the error path below is `let _ =` for the
                // same reason; this one warns, because here there is a report
                // left to carry the warning.
                if let Err(error) = workspace.discard_uncommitted() {
                    self.warnings.push(format!(
                        "the budget stopped the run, but the working tree could not be cleaned: \
                         {error}"
                    ));
                }
                return Ok(false);
            }

            let profile = WorkerProfile {
                name: format!("{}-{}", rung.tier, rung.binding.model),
                agent: rung.binding.agent.clone(),
                model: rung.binding.model.clone(),
                // Attribution only (§13 read-only): which subscription pays for
                // this attempt, so the ledger and the estimator can say so.
                // Nothing routes on it.
                pool: self.pool_name_for(&rung.binding.agent).unwrap_or_default(),
                permissions: PermissionMode::Edit,
                // What the rung's tier is worth on an agent with an effort
                // axis: without this the whole chain runs at one vendor
                // default and escalating a rung moves nothing (§10).
                effort: Some(self.effort_policy.implementation_for(rung.tier)),
                max_turns: None,
                extra_args: Vec::new(),
            };
            let adapter = adapters
                .get(&profile.agent)
                .ok_or_else(|| TactusError::Agent {
                    message: format!("no adapter registered for agent `{}`", profile.agent),
                })?;

            let attempt = self.state.progress[index].attempts + 1;
            let resume = self.state.progress[index]
                .resume_next
                .then(|| self.state.progress[index].session.clone())
                .flatten();

            // Recorded *before* the agent is spawned, so a process that dies
            // mid-attempt leaves an `attempt_started` with no
            // `attempt_finished`. That dangling pair is precisely what tells a
            // later replay an attempt was interrupted (§19's crash row) — the
            // engine cannot write a record of its own death afterwards.
            let rung_number = u32::try_from(rung_index).unwrap_or(u32::MAX);
            self.emit(EventBody::AttemptStarted {
                task: task_id.clone(),
                attempt,
                rung: rung_number,
                profile: profile.name.clone(),
                data: events::AttemptStarted {
                    tier: rung.tier.to_string(),
                    agent: profile.agent.clone(),
                    model: profile.model.clone(),
                    adapter: Some(adapter.id().to_owned()),
                    preflight_cli_version: self
                        .caps
                        .get(&profile.agent)
                        .map(|caps| caps.version.clone()),
                    effort: profile.effort,
                    selection_origin: Some(if rung.binding.pinned {
                        events::SelectionOrigin::Pin
                    } else {
                        events::SelectionOrigin::Auto
                    }),
                    pool: pool_option(&profile.pool),
                    resume_session: resume.clone(),
                },
            })?;

            // Scoped so every borrow the attempt takes on `self` is released
            // before the ladder updates this task's progress below.
            let result = {
                let retry = (attempt > 1).then(|| RetryBrief {
                    resumed: resume.is_some(),
                    // Owned: the ladder appends to this task's feedback the
                    // moment the attempt returns, and one clone per attempt
                    // costs less than threading that borrow through.
                    feedback: self.state.progress[index].feedback.clone(),
                });
                let attempt_cx = AttemptCx {
                    task,
                    profile: profile.clone(),
                    adapter,
                    runner: self.runner,
                    // The legacy engine's own scope for an invocation
                    // identity: this task's position in the plan. See
                    // `AttemptCx::invocation`.
                    task_index: u32::try_from(index).unwrap_or(u32::MAX),
                    attempt,
                    stem: stem.clone(),
                    paths: &self.paths,
                    gates: &analysis.gates,
                    gate_cmds: &self.gate_cmds,
                    reviewers: self.reviewers(index, &profile)?,
                    timeout: self.attempt_timeout,
                    review_pass_timeout: self.review_pass_timeout,
                    retry,
                    // The same entries the worker prompt quotes as operator
                    // instruction, routed to the judge as well (§12).
                    decisions: self.state.progress[index]
                        .feedback
                        .iter()
                        .filter(|entry| entry.human)
                        .filter_map(|entry| entry.detail.clone())
                        .collect(),
                    #[cfg(test)]
                    after_candidate_capture: self.after_candidate_capture,
                };

                // Any error between the agent editing files and the verdict
                // leaves the tree dirty; the run cannot continue but must not
                // hand the user a half-staged workspace either (§14).
                match run_attempt(&attempt_cx, workspace, resume.clone()) {
                    Ok(result) => result,
                    Err(error) => {
                        let _ = workspace.discard_uncommitted();
                        return Err(error);
                    }
                }
            };

            // Decide the ladder transition before writing the settlement, then
            // carry both in one event. A failure record without its decision is
            // not a safe crash prefix: replay would otherwise buy another
            // attempt on the old rung or lose an outage refund.
            let next = result.failure.as_ref().map(|failure| {
                let settlement_session = result.outcome.session_id.as_ref().or(resume.as_ref());
                let resumable = settlement_session.is_some()
                    && self
                        .caps
                        .get(&profile.agent)
                        .is_some_and(|c| c.session_resume);
                ladder::next_step(
                    failure,
                    &LadderState {
                        rung: self.state.progress[index].rung,
                        attempts_on_rung: self.state.progress[index].attempts_on_rung,
                        defers: self.state.progress[index].defers,
                        resumable,
                    },
                    &policy,
                )
            });
            let mut transition = None;
            let mut parking = None;
            let mut parking_question = None;
            let pending_spend = result.outcome.cost_usd.unwrap_or(0.0)
                + result
                    .reviews
                    .iter()
                    .map(|review| review.cost_usd.unwrap_or(0.0))
                    .sum::<f64>();
            let pending_unpriced = result.outcome.cost_usd.is_none()
                || result
                    .reviews
                    .iter()
                    .any(|review| review.cost_usd.is_none());
            if let (Some(failure), Some(next)) = (result.failure.as_ref(), next) {
                match next {
                    Next::RetrySameRung { resume } => {
                        transition = Some(Box::new(events::AttemptTransition::Retry(
                            events::LadderRetry {
                                resume,
                                tier: rung.tier.to_string(),
                                summary: failure.reason.clone(),
                                detail: failure.feedback.clone(),
                            },
                        )));
                    }
                    Next::Escalate => {
                        transition = Some(Box::new(events::AttemptTransition::Escalate(
                            events::LadderEscalated {
                                to_rung: rung_number.saturating_add(1),
                                tier: rung.tier.to_string(),
                                summary: failure.reason.clone(),
                                detail: failure.feedback.clone(),
                            },
                        )));
                        if let Some(onto) = chain.rungs.get(rung_index + 1).map(|next| next.tier) {
                            if self.should_approve_spend(rung.tier, onto, pending_spend) {
                                let question = self.build_spend_approval(
                                    index,
                                    onto,
                                    pending_spend,
                                    pending_unpriced,
                                );
                                parking = Some(Box::new(events::AttemptParking {
                                    question: question.clone(),
                                    refund_attempt: false,
                                }));
                                parking_question = Some(question);
                            }
                        }
                    }
                    Next::Defer => {
                        transition = Some(Box::new(events::AttemptTransition::Defer(
                            events::TaskDeferred {
                                reason: failure.reason.clone(),
                                defers: self.state.progress[index].defers.saturating_add(1),
                            },
                        )));
                    }
                    Next::AskHuman(kind) => {
                        let context =
                            question_context(task, kind, failure, &self.state.progress[index]);
                        let question = self.build_question(index, kind, context);
                        parking = Some(Box::new(events::AttemptParking {
                            question: question.clone(),
                            // An outage or clarification never received a code
                            // verdict, so its allowance is returned even when
                            // the outage ceiling sends it to a human.
                            refund_attempt: kind == QuestionKind::Clarify || failure.is_outage(),
                        }));
                        parking_question = Some(question);
                    }
                    Next::Fail => {
                        transition = Some(Box::new(events::AttemptTransition::Fail(
                            events::TaskFailed {
                                kind: failure.kind,
                                reason: failure.reason.clone(),
                                halts_run: self.on_task_failure == OnTaskFailure::Halt,
                            },
                        )));
                    }
                }
            }

            // A passing attempt is turned into an immutable commit object and
            // pinned before its settlement becomes durable. The event, HEAD
            // CAS, and pin deletion can therefore be recovered at every crash
            // prefix without re-running paid work or trusting the mutable
            // index.
            let prepared_commit = if result.failure.is_none() {
                let message = format!("[tactus] {}: {}", task.id, task.title);
                let pin_ref = prepared_pin_ref(&self.run_id, index, attempt);
                let recorded_branch_ref = format!("refs/heads/{}", self.branch);
                if result.candidate_branch_ref != recorded_branch_ref {
                    let _ = self.workspace.discard_uncommitted();
                    return Err(TactusError::Git {
                        message: format!(
                            "candidate was captured from `{}`, not recorded run branch `{recorded_branch_ref}`; refusing publication",
                            result.candidate_branch_ref
                        ),
                    });
                }
                match self.workspace.prepare_commit_from_candidate(
                    &result.candidate_branch_ref,
                    &result.candidate_parent,
                    &result.candidate_tree,
                    &message,
                    &pin_ref,
                ) {
                    Ok(prepared) => Some(prepared),
                    Err(error) => {
                        let _ = self.workspace.discard_uncommitted();
                        return Err(error);
                    }
                }
            } else {
                None
            };

            let settlement = self.emit(EventBody::AttemptFinished {
                task: task_id.clone(),
                attempt,
                rung: rung_number,
                profile: profile.name.clone(),
                parking,
                transition,
                prepared_commit: prepared_commit.clone().map(Box::new),
                data: Box::new(AttemptRecord {
                    attempt,
                    tier: rung.tier.to_string(),
                    model: profile.model.clone(),
                    pool: pool_option(&profile.pool),
                    resumed: resume.is_some(),
                    duration: result.outcome.duration,
                    cost_usd: result.outcome.cost_usd,
                    reviews: result.reviews.clone(),
                    session_id: result.outcome.session_id.clone(),
                    usage: result.outcome.usage.clone(),
                    failure: result.failure.as_ref().map(|f| FailureRecord {
                        kind: f.kind,
                        origin: f.origin,
                        reason: f.reason.clone(),
                    }),
                }),
            });
            if let Err(error) = settlement {
                // A write/flush/sync error cannot prove whether the newline-
                // committed event reached disk. Deliberately retain a prepared
                // pin: resume removes it as an orphan if no settlement landed,
                // or publishes it if the complete settlement is readable.
                // Deleting it here would turn an ambiguous sync error into a
                // schema-3 settlement whose exact object is no longer durable.
                if let Err(cleanup) = self.workspace.discard_uncommitted() {
                    return Err(TactusError::Git {
                        message: format!(
                            "{error}; additionally failed to clean the unreviewed workspace: {cleanup}"
                        ),
                    });
                }
                return Err(error);
            }
            if let Some(question) = parking_question.as_ref() {
                if let Err(error) = self.materialize_question(question) {
                    // The durable settlement is authoritative and already carries
                    // the complete question. A crash or write failure here cannot
                    // expose an orphan projection; resume rematerializes the
                    // question from the event before accepting an answer.
                    if let Err(cleanup) = self.workspace.discard_uncommitted() {
                        return Err(TactusError::Git {
                            message: format!(
                                "{error}; additionally failed to clean the unreviewed workspace: {cleanup}"
                            ),
                        });
                    }
                    return Err(error);
                }
            }

            let Some(failure) = result.failure else {
                let prepared = prepared_commit
                    .expect("a successful schema-3 settlement has a prepared commit");
                self.workspace
                    .advance_prepared_commit(&result.candidate_branch_ref, &prepared)?;
                // Scrub gate side-effects (build artifacts, lockfile churn) so
                // they cannot leak into the next task's captured diff; the
                // commit recorded exactly the verified staged set.
                self.workspace.discard_uncommitted()?;
                self.emit(EventBody::TaskCommitted {
                    task: task_id.clone(),
                    data: events::TaskCommitted {
                        sha: prepared.commit_sha,
                        message: prepared.message,
                    },
                })?;
                return Ok(false);
            };

            // §13 source 1: a rate-limit signal is ground truth about a pool,
            // and the only thing in v0.1 that can call one empty rather than
            // unmeasured. Recorded separately from the deferral that follows
            // because they are facts with different lifetimes — the deferral is
            // about this task's next move, this is about a subscription, and a
            // later run's estimator reads it back out of the log.
            if failure.kind != FailureKind::Interrupted
                && !(failure.kind == FailureKind::RateLimited
                    && failure.origin == FailureOrigin::Worker)
            {
                // This attempt reached a model and got an answer, whatever the
                // verdict on its code, so any pool it drew on is serving again.
                // Same rule as `capacity::observe`'s, applied to the engine's
                // own view so the two cannot disagree about when a pool
                // recovered — without it, the *next* outage on the same pool
                // would go unrecorded because the set still held it.
                self.exhausted_pools.remove(&profile.pool);
            }
            for review in &result.reviews {
                if review.outcome != events::ReviewPassOutcome::Unavailable {
                    if let Some(pool) = &review.pool {
                        self.exhausted_pools.remove(pool);
                    }
                }
            }
            if failure.kind == FailureKind::RateLimited {
                self.record_pool_exhausted(&task_id, &profile, &result.reviews, &failure)?;
            }

            let next = next.expect("a failed attempt has a ladder decision");

            // §14: the tree survives only for a resumed retry, where the
            // *cumulative* diff is what gets re-gated. Every other branch
            // hands the scheduler a clean workspace, because another task may
            // run before this one does again.
            if !matches!(next, Next::RetrySameRung { resume: true }) {
                self.workspace.discard_uncommitted()?;
            }

            match next {
                Next::RetrySameRung { .. } => {}
                Next::Escalate => {
                    if parking_question.is_some() {
                        return Ok(false);
                    }
                }
                Next::Defer => return Ok(true),
                Next::AskHuman(_) | Next::Fail => return Ok(false),
            }
        }
    }

    /// §11.2/§11.3: the read-only passes that judge one task's attempt.
    ///
    /// Reviewers bind at the configured review tier (frontier by default)
    /// rather than the implementer's rung — a small model reviewing its own
    /// work is not verification — and [`ReviewPlan::passes_for`] decides
    /// whether that means one pass or two, and whether the primary rebinds
    /// away from the model that wrote the code.
    ///
    /// An empty list means review is switched off explicitly. A pass whose
    /// adapter cannot be built is a hard error: verification vanishing without
    /// a word is worse than a refusal, and pre-flight has already probed every
    /// agent named here.
    fn reviewers(
        &self,
        index: usize,
        implementer: &WorkerProfile,
    ) -> Result<Vec<Reviewer<'_>>, TactusError> {
        let running_on = PassBinding::new(implementer.agent.clone(), implementer.model.clone());
        self.review_plan
            .passes_for(index, &running_on)
            .into_iter()
            .map(|pass: ReviewPass| {
                // Every pass judges at the review tier's effort, including a
                // second opinion bound to another vendor: the standard belongs
                // to the review, not to whichever family happens to apply it.
                let mut profile = pass.profile(self.effort_policy.review);
                // A cross-vendor second opinion draws on a different
                // subscription than the implementer (§11.3, §13), so its pool
                // is looked up from its own agent rather than inherited.
                profile.pool = self.pool_name_for(&profile.agent).unwrap_or_default();
                Ok(Reviewer {
                    adapter: self.adapters.get(&pass.binding.agent).ok_or_else(|| {
                        TactusError::Agent {
                            message: format!(
                                "the {} pass binds to agent `{}`, which has no adapter in this \
                                 build",
                                pass.lens.name(),
                                pass.binding.agent
                            ),
                        }
                    })?,
                    profile,
                    lens: pass.lens,
                    preflight_cli_version: self
                        .caps
                        .get(&pass.binding.agent)
                        .map(|caps| caps.version.clone()),
                })
            })
            .collect()
    }

    /// §14's pre-flight capacity snapshot, from the state this run has folded
    /// so far.
    ///
    /// Deliberately does **not** probe. Everything a probe would add — auth
    /// state, versions — is already established by pre-flight, and spawning the
    /// vendors' CLIs a second time to fill in a metadata event would be work
    /// nothing reads. The estimator's inputs come from the run's own log, which
    /// on a fresh run is empty and on a resume carries every signal the earlier
    /// process recorded.
    pub(super) fn emit_capacity_snapshot(
        &mut self,
        signals: &BTreeMap<String, Option<String>>,
    ) -> Result<(), TactusError> {
        // No early return on an empty pools file: "nothing was connected" is
        // exactly as worth recording as a list, and its absence is otherwise
        // indistinguishable from a pre-step-10 log, or from a binary that never
        // took a snapshot at all (§14).
        let pools = &self.analysis.config.pools;
        // Signals come from the caller's fold of this run's log (empty on a
        // fresh run) rather than from a field kept here, so there is exactly one
        // place that turns `pool_exhausted` events into observations — the same
        // reasoning that keeps `RunState::apply` the only writer of run state.
        let estimates = capacity::estimate(
            pools,
            &capacity::Observations {
                exhausted: signals.clone(),
                self_spend: capacity::drain_of(
                    self.state
                        .progress
                        .iter()
                        .flat_map(|progress| progress.records.iter()),
                ),
            },
        );
        let snapshot = events::CapacitySnapshot {
            strategy: self.analysis.config.strategy.mode.clone(),
            pools: estimates
                .iter()
                .map(|estimate| events::PoolSnapshot {
                    pool: estimate.pool.clone(),
                    agent: estimate.agent.clone(),
                    kind: estimate.kind.to_string(),
                    remaining: estimate.remaining.to_string(),
                    confidence: estimate.confidence.to_string(),
                    reset_at: estimate.reset_at.clone(),
                })
                .collect(),
        };
        self.emit(EventBody::CapacitySnapshot { data: snapshot })
    }

    /// Which pool an agent's attempts drain (§13), or `None` when the pools
    /// file names none for it. Attribution only — nothing routes on it.
    fn pool_name_for(&self, agent: &str) -> Option<String> {
        capacity::pool_for(agent, &self.analysis.config.pools).map(|pool| pool.name.clone())
    }

    /// §13's reported spend so far — the ledger's own figure, with the ledger's
    /// own honesty: unpriced attempts contribute nothing, so this is a floor
    /// wherever a route reports no spend at all.
    fn reported_spend(&self, task: Option<usize>) -> f64 {
        let indices: Vec<usize> = match task {
            Some(index) => vec![index],
            None => (0..self.state.progress.len()).collect(),
        };
        indices
            .into_iter()
            .filter_map(|index| self.state.progress.get(index))
            .flat_map(|progress| progress.records.iter())
            .map(|record| record.cost_usd.unwrap_or(0.0) + record.review_cost_usd().unwrap_or(0.0))
            .sum()
    }

    /// Whether a ceiling has been reached, and which one.
    ///
    /// `run_usd` is checked before `task_usd` because it is the stricter claim:
    /// a run at its overall ceiling is done whatever any individual task has
    /// spent, and naming the run budget is what tells the operator which number
    /// to raise.
    fn budget_breach(&self, index: usize) -> Option<events::BudgetExceeded> {
        let task = self.analysis.plan.tasks[index].id.to_string();
        if let Some(limit) = self.budgets.run_usd {
            let spent = self.reported_spend(None);
            if spent >= limit {
                return Some(events::BudgetExceeded {
                    budget: events::BudgetKind::Run,
                    limit_usd: limit,
                    spent_usd: spent,
                    task,
                });
            }
        }
        if let Some(limit) = self.budgets.task_usd {
            let spent = self.reported_spend(Some(index));
            if spent >= limit {
                return Some(events::BudgetExceeded {
                    budget: events::BudgetKind::Task,
                    limit_usd: limit,
                    spent_usd: spent,
                    task,
                });
            }
        }
        None
    }

    /// §12's `ask_before`: does this escalation need a person's approval first?
    ///
    /// Only a move *onto* a frontier rung from somewhere cheaper counts. A
    /// chain that starts at frontier is where the operator deliberately routed
    /// the task in config or in an annotation, and §12's concern is silent
    /// escalation — asking permission for a decision the operator already made
    /// in writing would train them to answer without reading.
    fn should_approve_spend(
        &self,
        from: crate::ir::Tier,
        onto: crate::ir::Tier,
        pending_spend: f64,
    ) -> bool {
        let Some(threshold) = self.ask_before.frontier_escalation_over_usd else {
            return false;
        };
        onto == crate::ir::Tier::Frontier
            && from != crate::ir::Tier::Frontier
            && self.reported_spend(None) + pending_spend >= threshold
    }

    /// §13 source 1, recorded: attribute a rate limit to the pool that hit it.
    ///
    /// A reviewer's rate limit belongs to the *reviewer's* pool, which on a
    /// cross-vendor second opinion is a different subscription from the one the
    /// implementer drained — attributing it to the implementer's would mark a
    /// healthy pool exhausted and leave the empty one looking fine.
    fn record_pool_exhausted(
        &mut self,
        task: &str,
        implementer: &WorkerProfile,
        reviews: &[events::ReviewRecord],
        failure: &AttemptFailure,
    ) -> Result<(), TactusError> {
        let (pool, agent) = match failure.origin {
            FailureOrigin::Reviewer => match reviews.last() {
                Some(review) => (review.pool.clone(), review.agent.clone()),
                None => return Ok(()),
            },
            FailureOrigin::Worker => (pool_option(&implementer.pool), implementer.agent.clone()),
        };
        // No pool named for that agent means no subscription to mark. The
        // signal is still in the log on the attempt record; inventing a pool id
        // to hang it on would put a fact about nothing into the estimator.
        let Some(pool) = pool else { return Ok(()) };
        // Only the transition (see `exhausted_pools`).
        if !self.exhausted_pools.insert(pool.clone()) {
            return Ok(());
        }
        self.emit(EventBody::PoolExhausted {
            task: task.to_owned(),
            data: events::PoolExhausted {
                pool,
                agent,
                // §13 wants a retry-at-reset timer here. Neither CLI reports a
                // machine-readable reset time today, and parsing one out of
                // prose would be a guess dressed as a timestamp — so it stays
                // `None`, `DEFAULT_MAX_DEFERS` stays the bound, and the estimate
                // says the reset is unknown.
                reset_at: None,
                detail: util::head(&failure.reason, 400),
            },
        })
    }

    fn fail_task(
        &mut self,
        index: usize,
        kind: FailureKind,
        reason: String,
    ) -> Result<(), TactusError> {
        // The halt policy is resolved here and recorded, not re-derived on
        // replay: a `tactus.toml` edited between a run and its resume must not
        // rewrite which task the report blames for stopping.
        let halts_run = self.on_task_failure == OnTaskFailure::Halt;
        self.fail_task_with_policy(index, kind, reason, halts_run)
    }

    pub(super) fn fail_task_with_policy(
        &mut self,
        index: usize,
        kind: FailureKind,
        reason: String,
        halts_run: bool,
    ) -> Result<(), TactusError> {
        let task = self.analysis.plan.tasks[index].id.to_string();
        self.emit(EventBody::TaskFailed {
            task,
            data: events::TaskFailed {
                kind,
                reason,
                halts_run,
            },
        })
    }

    /// §12: raise eagerly, park exactly the affected task, tell the notifiers,
    /// and write the payload where a UI or `tactus answer` can read it.
    /// §12's `ask_before` question: this task is about to escalate onto a
    /// frontier rung, and the run has already reported enough spend that the
    /// operator asked to be consulted first.
    fn build_spend_approval(
        &self,
        index: usize,
        onto: crate::ir::Tier,
        pending_spend: f64,
        pending_unpriced: bool,
    ) -> Question {
        let context = spend_question_context(
            &self.analysis.plan.tasks[index],
            onto,
            self.reported_spend(None) + pending_spend,
            self.ask_before.frontier_escalation_over_usd.unwrap_or(0.0),
            self.unpriced_attempts() > 0 || pending_unpriced,
        );
        self.build_question(index, QuestionKind::ApproveSpend, context)
    }

    /// Attempts whose route reported no spend at all (§13), so the figures this
    /// run quotes are floors rather than totals.
    fn unpriced_attempts(&self) -> u32 {
        let unpriced = self
            .state
            .progress
            .iter()
            .flat_map(|progress| progress.records.iter())
            .filter(|record| record.cost_usd.is_none() || record.review_cost_incomplete())
            .count();
        u32::try_from(unpriced).unwrap_or(u32::MAX)
    }

    fn build_question(&self, index: usize, kind: QuestionKind, context: String) -> Question {
        let task = &self.analysis.plan.tasks[index];
        Question {
            id: interaction::new_question_id(),
            kind,
            // v0.1 parks only the task that raised it. Dependents are held by
            // the graph, not by the question, so they stay eligible the moment
            // an answer arrives.
            affected_tasks: vec![task.id.clone()],
            context,
            options: question_options(kind),
        }
    }

    fn materialize_question(&mut self, question: &Question) -> Result<(), TactusError> {
        // Materialize before notifying: a recipient must always be able to open
        // the payload it was told about. The caller decides whether the
        // authoritative event belongs before (atomic settlement parking) or
        // after (ordinary question flow) this projection.
        interaction::write_question(
            &self.paths.questions(),
            &QuestionRecord::open(question.clone()),
        )?;
        let id = question.id.clone();
        for notifier in &self.notifiers {
            // A notifier that cannot deliver must not take the run with it: the
            // question is already on disk either way (§12).
            if let Err(error) = notifier.ask(question) {
                self.warnings.push(format!(
                    "notifier `{}` could not deliver question {id}: {error}",
                    notifier.id()
                ));
            }
        }
        Ok(())
    }

    /// Ingest answers left by `tactus answer` in another process.
    ///
    /// Returns whether anything changed. This is what makes the answer command
    /// useful while a run is alive rather than only between runs: an operator
    /// answering from a phone at 2am un-parks the task on the next scheduler
    /// turn, with no resume needed.
    fn sweep_answers(&mut self) -> Result<bool, TactusError> {
        let open: Vec<QuestionId> = self
            .state
            .open_questions()
            .iter()
            .map(|record| record.question.id.clone())
            .collect();
        if open.is_empty() {
            return Ok(false);
        }
        let dir = self.paths.answers();
        let mut changed = false;
        for id in open {
            let Some(answer) = interaction::read_answer(&dir, &id)? else {
                continue;
            };
            // Only what actually applied counts as change. A file the engine
            // reads but declines to act on — an `Unanswered` one, say, which
            // nothing in `tactus answer` will write but a hand-edit can —
            // would otherwise report progress on every turn, and the drain
            // loop would spin on it forever: this branch is only bounded
            // because it closes the question it fires for.
            if self.ingest_answer(&id, answer, "answer-file")? {
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Record an answer and let it take effect. Returns whether it applied.
    ///
    /// One path for every channel — a terminal reply, a file written by
    /// `tactus answer`, or an answer picked up on resume — so what an answer
    /// *does* cannot depend on where it came from. The guards below are also
    /// what makes it safe to offer the same answer twice: a question that is
    /// already closed absorbs the second one instead of applying it.
    fn ingest_answer(
        &mut self,
        id: &QuestionId,
        answer: Answer,
        via: &str,
    ) -> Result<bool, TactusError> {
        let Some(record) = self
            .state
            .questions
            .iter()
            .find(|record| record.question.id == *id)
        else {
            return Ok(false);
        };
        if !record.is_open() || answer == Answer::Unanswered {
            return Ok(false);
        }
        let context = record.question.context.clone();
        let affected = record.question.affected_tasks.clone();

        self.emit(EventBody::QuestionAnswered {
            data: events::QuestionAnswered {
                question: id.clone(),
                answer: answer.clone(),
                decline_halts_run: (answer == Answer::Declined)
                    .then_some(self.on_task_failure == OnTaskFailure::Halt),
                via: via.to_owned(),
            },
        })?;

        // §5: a question that reached a human at runtime is, by definition, a
        // design-phase defect — logged as one so the accumulated defects can
        // become review material for the designer prompt.
        self.emit(EventBody::DesignDefect {
            data: events::DesignDefect {
                question: id.clone(),
                context: util::head(context.trim(), 600),
                answer: match &answer {
                    Answer::Answered { text } => text.clone(),
                    _ => "declined".to_owned(),
                },
            },
        })?;

        // A decline is the task's failure, not the question's, so it goes
        // through the one place that owns the halt policy. `apply` leaves a
        // declined task parked precisely so this can still see who was waiting.
        if answer == Answer::Declined {
            for task_id in affected {
                let Some(index) = self.state.index_of(task_id.as_str()) else {
                    continue;
                };
                if !matches!(&self.state.states[index], TaskState::AwaitingInput(q) if q == id) {
                    continue;
                }
                let reason = format!(
                    "declined at the human rung: {}",
                    last_reason(&self.state.progress[index])
                );
                self.fail_task(index, FailureKind::Declined, reason)?;
            }
        }

        // Rewrite the payload so a late reader — a UI, or someone opening the
        // directory tomorrow — sees the whole exchange, not just the question.
        if let Some(record) = self
            .state
            .questions
            .iter()
            .find(|record| record.question.id == *id)
        {
            interaction::write_question(&self.paths.questions(), record)?;
        }
        Ok(true)
    }

    /// Ask about the oldest open question. Returns whether anything changed.
    ///
    /// This runs only at a hard block, and each question is asked at most
    /// once: an `Unanswered` result marks it unreachable rather than looping
    /// back to a channel that already said nobody is there.
    fn resolve_one_question(&mut self) -> Result<bool, TactusError> {
        let Some(position) = self.state.questions.iter().position(|record| {
            record.is_open() && !self.unanswerable.contains(&record.question.id)
        }) else {
            return Ok(false);
        };
        let question = self.state.questions[position].question.clone();
        let answer = self.answers.resolve(&question)?;

        // The channel may have been waiting on the very file the sweep reads,
        // so sweep before applying what it returned — and then still apply it.
        // `ingest_answer` is guarded on the question being open, which is what
        // makes doing both safe: if the sweep answered *this* question the
        // typed reply is absorbed, and if it answered a different one — an
        // operator working through a backlog of parked tasks — this reply
        // still lands instead of being discarded along with it.
        self.sweep_answers()?;
        if answer == Answer::Unanswered {
            // §12 CI mode: the task stays parked and the run's exit status
            // reports it. Not a failure — nobody rejected anything.
            self.unanswerable.push(question.id);
            return Ok(true);
        }
        self.ingest_answer(&question.id, answer, self.answers.id())?;
        Ok(true)
    }

    /// Settle every task that never ran, then report.
    fn finish(&self) -> RunReport {
        build_report(
            ReportHeader {
                run_id: &self.run_id,
                branch: &self.branch,
                gates: self.analysis.gates.iter().map(|g| g.name.clone()).collect(),
                gates_from_config: self.analysis.gates_from_config,
                warnings: self.warnings.clone(),
                // The engine only reports on itself once it has stopped.
                running: false,
                // A `finish` that runs is by definition not an interruption:
                // the shape this flag describes is the one left behind when
                // this function never got the chance.
                interrupted: false,
            },
            &self.analysis.plan,
            &self.state,
        )
    }
}

/// What the human is shown. Every agent-authored fragment is quoted behind a
/// fence the payload cannot close and labelled as agent-authored — a worker
/// that "asks a question" is still an agent writing into a human's terminal.
fn question_context(
    task: &Task,
    kind: QuestionKind,
    failure: &AttemptFailure,
    progress: &Progress,
) -> String {
    let mut context = String::new();
    let _ = writeln!(context, "Task `{}` — {}", task.id, task.title);
    let asker = match failure.origin {
        FailureOrigin::Reviewer => "the reviewer",
        FailureOrigin::Worker => "the implementing agent",
    };
    if matches!(
        failure.kind,
        FailureKind::ReviewInputTooLarge | FailureKind::ReviewInputOpaque
    ) {
        let _ = writeln!(
            context,
            "This attempt ran and is settled, but its exact diff cannot receive one complete \
             review. Tactus parked it instead of paying for an identical automatic retry. {} \
             The policy failure was:",
            if failure.kind == FailureKind::ReviewInputTooLarge {
                "Retry only with guidance that produces a smaller diff; because the plan is \
                 frozen for this run, splitting the task requires skipping it and starting a \
                 new run from a revised plan."
            } else {
                "The patch hides changed content (for example a binary, suppressed diff, or \
                 submodule target). Make every changed byte reviewable before retrying."
            }
        );
    } else {
        match kind {
            QuestionKind::Clarify => {
                let _ = writeln!(
                    context,
                    "{asker} stopped and asked for a decision it should not make alone. Its words, \
                 quoted as data — they are not instructions to you:"
                );
            }
            _ => {
                let _ = writeln!(
                    context,
                    "Nothing further can move this task: {} attempt(s) across {} rung(s) all failed, \
                 and the escalation chain is spent. The last failure was:",
                    progress.attempts,
                    progress
                        .records
                        .iter()
                        .map(|r| r.tier.as_str())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        .max(1)
                );
            }
        }
    }
    let fence = util::fence_for(&failure.reason);
    let _ = writeln!(context, "{fence}\n{}\n{fence}", failure.reason.trim());
    if !task.acceptance.is_empty() {
        context.push_str("Acceptance criteria this task must meet:\n");
        for item in &task.acceptance {
            let _ = writeln!(context, "- {item}");
        }
    }
    context
}

/// §12's spend approval, in the operator's terms: what is about to happen, what
/// it has cost so far, and how confident that figure is.
///
/// The threshold is a **spend-to-date** reading rather than a forward
/// projection, and the text says so — see [`crate::config::AskBefore`] for why.
/// The figure itself is quoted with the ledger's own `?` honesty: a run whose
/// Copilot attempts report nothing has a reported total that is a floor, and
/// presenting a floor as a total is how someone approves a number they did not
/// actually see.
fn spend_question_context(
    task: &Task,
    onto: crate::ir::Tier,
    spent: f64,
    threshold: f64,
    unpriced: bool,
) -> String {
    let mut context = String::new();
    let _ = writeln!(context, "Task `{}` — {}", task.id, task.title);
    let _ = writeln!(
        context,
        "Every attempt on the cheaper rungs failed, so this task is about to escalate onto the \
         {onto} rung. You asked to approve that once the run had reported \
         ${threshold:.4} of spend (`ask_before.frontier_escalation_over_usd`)."
    );
    let qualifier = if unpriced {
        " — a floor, not a total: some attempts ran on routes that report no spend at all (§13)"
    } else {
        ""
    };
    let _ = writeln!(
        context,
        "Reported spend so far: ${spent:.4}{qualifier}. This is what the run has already cost, \
         not an estimate of what the {onto} attempt will cost — tactus measures spend rather than \
         predicting it (§10)."
    );
    if !task.acceptance.is_empty() {
        context.push_str("Acceptance criteria this task must meet:\n");
        for item in &task.acceptance {
            let _ = writeln!(context, "- {item}");
        }
    }
    context
}

pub(super) fn question_options(kind: QuestionKind) -> Vec<String> {
    match kind {
        QuestionKind::Clarify => {
            vec!["answer in your own words (typed free text is sent back to the agent)".to_owned()]
        }
        QuestionKind::ApproveSpend => vec![
            "approve: run the escalated attempt".to_owned(),
            "decline (`skip`) — this task fails and its dependents are blocked".to_owned(),
        ],
        _ => vec![
            "retry this task with guidance you type below".to_owned(),
            "give up on this task (`skip`) — its dependents will be blocked".to_owned(),
        ],
    }
}
