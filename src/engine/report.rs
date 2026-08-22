use std::fmt::Write as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capacity;
use crate::events::{self, AttemptRecord, Progress, RunState, TaskState};
use crate::interaction::QuestionRecord;
use crate::ir::{Plan, Task};
use crate::ladder::FailureKind;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TaskRunStatus {
    Committed {
        sha: String,
    },
    Failed {
        kind: FailureKind,
        reason: String,
    },
    /// Waiting on a human. The rest of the run kept moving (invariant 6), and
    /// nothing about this task is lost — the question carries its context.
    Parked {
        question: String,
        reason: String,
    },
    /// A dependency failed, or parked and was never answered.
    Blocked {
        by: String,
    },
    /// Not attempted because the run halted earlier.
    Skipped,
    /// An attempt is running right now. Only a live `status` produces this: a
    /// run that has ended has nothing left in flight.
    Running {
        attempt: u32,
        tier: String,
        model: String,
    },
    /// Its turn has not come yet, and the run is still going — distinct from
    /// `Skipped`, which means the run ended before this task got a turn.
    Queued,
    /// A status this build does not know, from a `report.json` a newer tactus
    /// wrote. Never produced by this crate.
    ///
    /// `report.json` is a projection for whoever reads the run afterwards, and
    /// this enum is `pub` and `Deserialize` because that reader may be someone
    /// else's program. Without a fallback, every variant added here is a hard
    /// `unknown variant` error in every consumer built against an older
    /// version — which is what `running`, `Queued` and this one did to anything
    /// compiled against 0.0.1, and that break is already published. Adding it
    /// now cannot undo that; it stops the next one.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskReport {
    pub id: String,
    pub title: String,
    /// The final attempt's implementer model. `cost_usd` is the implementer's
    /// spend across every attempt; reviewer spend is a separate field because
    /// it is a different model at a different tier, and folding them together
    /// makes cheap rungs look expensive to anyone reading the ledger (§13).
    pub model: String,
    pub status: TaskRunStatus,
    pub duration: Duration,
    pub cost_usd: Option<f64>,
    /// Every model that judged this task, in the order first seen.
    ///
    /// Across *all* attempts, not just the last, because `review_cost_usd`
    /// beside it sums all of them — a list scoped to the final attempt next to
    /// a total scoped to every attempt reads as though one explains the other.
    pub review_models: Vec<String>,
    pub review_cost_usd: Option<f64>,
    /// At least one review pass reported no spend, so `review_cost_usd` is a
    /// floor (§13). Rendered as a `?` rather than left to look exact.
    pub review_cost_incomplete: bool,
    pub session_id: Option<String>,
    /// Every attempt, oldest first — the escalation trail.
    pub attempts: Vec<AttemptRecord>,
}

impl TaskReport {
    /// Implementer plus reviewer, across every attempt.
    pub fn total_cost_usd(&self) -> Option<f64> {
        match (self.cost_usd, self.review_cost_usd) {
            (None, None) => None,
            (worker, review) => Some(worker.unwrap_or(0.0) + review.unwrap_or(0.0)),
        }
    }

    /// Whether an attempt reported no spend, making `cost_usd` a floor.
    ///
    /// The worker-side twin of [`Self::review_cost_incomplete`], and a method
    /// rather than a field because it is derivable from the attempts already
    /// carried here — no schema change, so an older `report.json` reads back
    /// with the same answer this computes.
    ///
    /// Two kinds of attempt land here, and both genuinely spent something
    /// nobody can name: one on a route that reports no dollars at all (Codex
    /// reports tokens — §13), and one the engine was killed inside, whose
    /// `cost_usd` is `null` precisely because the record of its ending was
    /// never written. `unpriced_attempts` counts the same condition for the
    /// capacity estimator, so the ledger and the estimator now agree about
    /// which attempts are unpriced.
    pub fn cost_incomplete(&self) -> bool {
        self.attempts.iter().any(|record| record.cost_usd.is_none())
    }

    /// Compact escalation trail, e.g. `small×2 failed → mid ok`.
    pub fn trail(&self) -> String {
        let mut parts: Vec<(String, u32, bool)> = Vec::new();
        for record in &self.attempts {
            let failed = record.failure.is_some();
            match parts.last_mut() {
                Some((tier, count, last_failed)) if *tier == record.tier => {
                    *count += 1;
                    *last_failed = failed;
                }
                _ => parts.push((record.tier.clone(), 1, failed)),
            }
        }
        parts
            .into_iter()
            .map(|(tier, count, failed)| {
                let count = if count > 1 {
                    format!("×{count}")
                } else {
                    String::new()
                };
                let verdict = if failed { "failed" } else { "ok" };
                format!("{tier}{count} {verdict}")
            })
            .collect::<Vec<_>>()
            .join(" → ")
    }
}

/// How the run ended.
///
/// `Parked` is deliberately not `Halted`: §12 requires CI to tell a clean
/// completion from one that left questions unanswered. `BudgetExceeded` earns
/// its own variant for the same reason one step further out — "your ceiling
/// stopped it" is neither a failure nor a question, and `tactus resume` means
/// something different after each of the three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Complete,
    Halted,
    BudgetExceeded,
    Parked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub branch: String,
    /// Effective gate names, and whether they came from config or derivation.
    pub gates: Vec<String>,
    pub gates_from_config: bool,
    pub warnings: Vec<String>,
    pub tasks: Vec<TaskReport>,
    /// Task id the run halted at, if any.
    pub halted_at: Option<String>,
    /// Every question raised, with its answer where one arrived (§12).
    pub questions: Vec<QuestionRecord>,
    /// The §13 ceiling that stopped the run, if one did.
    #[serde(default)]
    pub budget_stop: Option<events::BudgetExceeded>,
    pub total_cost_usd: f64,
    /// What each pool drained, folded from this run's own attempts (§13).
    #[serde(default)]
    pub pool_drain: Vec<PoolDrainRow>,
    /// Whether an engine is driving this run right now. A live run must not be
    /// rendered as a finished one: its in-flight attempt has not failed, and
    /// the tasks queued behind it have not been skipped.
    #[serde(default)]
    pub running: bool,
    /// Whether this run stopped without ever recording that it finished — the
    /// signature of a kill, a power loss, or an aborting error.
    ///
    /// A run in that state has no outcome, and `outcome()` cannot tell: a
    /// killed run has nothing halted, no budget stop and nothing parked, which
    /// is indistinguishable from a clean finish. So the flag has to be carried
    /// rather than derived, exactly as `running` is.
    ///
    /// Not to be confused with `RunStatus::interrupted`, which is a `u32`
    /// counting the attempts that were cut off mid-flight. This is the yes/no.
    #[serde(default)]
    pub interrupted: bool,
}

/// One pool's line in the ledger: what this run drew from which subscription.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolDrainRow {
    pub pool: String,
    pub attempts: u32,
    /// Reported api-equivalent dollars, `None` when nothing on this pool
    /// reported any.
    pub cost_usd: Option<f64>,
    /// Attempts whose route reports no spend at all (§13), making the figure
    /// above a floor rather than a total.
    pub unpriced: u32,
}

impl RunReport {
    pub fn parked_tasks(&self) -> Vec<&str> {
        self.tasks
            .iter()
            .filter(|t| matches!(t.status, TaskRunStatus::Parked { .. }))
            .map(|t| t.id.as_str())
            .collect()
    }

    /// Whether `total_cost_usd` is a floor rather than a figure.
    ///
    /// `total_cost_usd` is an `f64`, so it cannot say this for itself: a run
    /// that reported nothing and a run that genuinely cost nothing both arrive
    /// as `0.0`. The distinction has to be carried alongside, and §13 is
    /// explicit that a ledger which cannot tell free from unreported is worse
    /// than no ledger.
    ///
    /// Both halves count. The review side has been marked since step 9; the
    /// worker side became reachable the moment an implementer could report
    /// tokens without dollars, and is now the *normal* case for a
    /// codex-implemented run rather than an edge one.
    pub fn total_is_floor(&self) -> bool {
        self.tasks
            .iter()
            .any(|task| task.cost_incomplete() || task.review_cost_incomplete)
    }

    /// How much of the plan actually landed — the one figure every ending
    /// wants, whether the run finished, is still going, or was cut off.
    fn committed_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.status, TaskRunStatus::Committed { .. }))
            .count()
    }

    /// Precedence: a halt outranks a budget stop, which outranks parked work.
    ///
    /// That order falls out of what actually happened rather than being a
    /// policy: a halt stops the drain before any further budget check can run,
    /// so a run with both is one that halted and then found its ceiling
    /// irrelevant. And a budget stop leaves tasks parked-or-skipped behind it,
    /// so reporting `Parked` would name a symptom instead of the cause.
    pub fn outcome(&self) -> RunOutcome {
        if self.halted_at.is_some() {
            RunOutcome::Halted
        } else if self.budget_stop.is_some() {
            RunOutcome::BudgetExceeded
        } else if self.parked_tasks().is_empty() {
            RunOutcome::Complete
        } else {
            RunOutcome::Parked
        }
    }
}

impl RunReport {
    /// Build a report from a replayed log.
    ///
    /// `status` and the `report.json` a run writes go through the same
    /// function, so what an operator sees mid-run and what the file says
    /// afterwards cannot drift into disagreeing.
    pub fn from_state(
        started: &events::RunStarted,
        plan: &Plan,
        state: &RunState,
        warnings: Vec<String>,
        running: bool,
        interrupted: bool,
    ) -> Self {
        build_report(
            ReportHeader {
                run_id: &started.run_id,
                branch: &started.branch,
                gates: started.gates.clone(),
                gates_from_config: started.gates_from_config,
                warnings,
                running,
                interrupted,
            },
            plan,
            state,
        )
    }
}

/// Everything a report needs that is not the plan or the state, kept together
/// so `build_report` stays readable at its call sites.
pub(super) struct ReportHeader<'a> {
    pub(super) run_id: &'a str,
    pub(super) branch: &'a str,
    pub(super) gates: Vec<String>,
    pub(super) gates_from_config: bool,
    pub(super) warnings: Vec<String>,
    /// Whether an engine is driving this run right now.
    pub(super) running: bool,
    /// Whether this run stopped without ever recording that it finished.
    pub(super) interrupted: bool,
}

pub(super) fn build_report(header: ReportHeader<'_>, plan: &Plan, state: &RunState) -> RunReport {
    let ReportHeader {
        run_id,
        branch,
        gates,
        gates_from_config,
        warnings,
        running,
        interrupted,
    } = header;
    let settled = settle(plan, &state.states, running);
    let tasks: Vec<TaskReport> = state
        .order
        .iter()
        .copied()
        // Tasks that never started append in plan order, so the report reads
        // as the run happened and still accounts for everything.
        .chain((0..plan.tasks.len()).filter(|i| !state.order.contains(i)))
        .map(|index| {
            task_report(
                &plan.tasks[index],
                &settled[index],
                &state.progress[index],
                running,
            )
        })
        .collect();
    let total_cost_usd = total_of(&tasks);
    // §13's second currency: what each subscription drained, folded from the
    // same attempt records the dollar column comes from — so the two halves of
    // the ledger cannot disagree about the same attempt.
    let pool_drain = capacity::drain_of(state.progress.iter().flat_map(|p| p.records.iter()))
        .into_iter()
        .map(|(pool, spend)| PoolDrainRow {
            pool,
            attempts: spend.attempts,
            cost_usd: spend.usd,
            unpriced: spend.unpriced,
        })
        .collect();
    RunReport {
        run_id: run_id.to_owned(),
        branch: branch.to_owned(),
        gates,
        gates_from_config,
        warnings,
        tasks,
        halted_at: state.halted_at.clone(),
        questions: state.questions.clone(),
        budget_stop: state.budget_stop.clone(),
        total_cost_usd,
        pool_drain,
        running,
        interrupted,
    }
}

/// Derive how an ended run's untouched tasks are reported.
///
/// This is a *view*, not state, and deliberately not recorded as events. A
/// task blocked behind an unanswered question has to become runnable again the
/// moment that question is answered — so if `Blocked` were folded in from the
/// log, every resume would have to un-fold it. Deriving it fresh from whatever
/// the log says is true right now means there is nothing to undo.
fn settle(plan: &Plan, states: &[TaskState], running: bool) -> Vec<TaskState> {
    let tasks = &plan.tasks;
    let mut settled = states.to_vec();
    // Blocking propagates: a dependent of a blocked task is blocked too.
    // Repeat until stable rather than assuming plan order carries it — a plan
    // may list a dependent before the task it waits on.
    loop {
        let mut changed = false;
        for index in 0..tasks.len() {
            if settled[index] != TaskState::Pending {
                continue;
            }
            let blocker = tasks[index].depends_on.iter().find(|dep| {
                tasks
                    .iter()
                    .position(|t| t.id == **dep)
                    .is_some_and(|j| blocks_dependents(&settled[j], running))
            });
            if let Some(blocker) = blocker {
                settled[index] = TaskState::Blocked(blocker.to_string());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Whatever is still Pending was never reached: the run halted. A run that
    // is still going has not halted — those tasks are queued, or one of them
    // is working right now — so leave them Pending for `task_report` to tell
    // apart.
    if !running {
        for state in &mut settled {
            if *state == TaskState::Pending {
                *state = TaskState::Skipped;
            }
        }
    }
    settled
}

/// Whether a dependency in this state will keep its dependents from ever
/// running.
///
/// `Blocked` means one thing to an operator — "a dependency failed, or parked
/// and was never answered" — and that is a claim about the future, not the
/// present. On an ended run the two coincide: anything short of `Done` is
/// final, because nothing more is coming. On a live one they do not. A
/// dependency that is merely pending, deferred, or in flight is a task whose
/// turn has not come, and its dependent is *queued behind* it rather than
/// blocked by it. Deciding this from `Done`-ness alone made `Queued`
/// unreachable for every task with a dependency, so the entire first half of a
/// live run read as a graph of failures.
fn blocks_dependents(state: &TaskState, running: bool) -> bool {
    match state {
        TaskState::Done(_) => false,
        // Still on the way. Only an ended run turns that into "never".
        TaskState::Pending | TaskState::Deferred => !running,
        // Terminal even mid-run, which is what keeps the propagation working
        // while the engine is still going: a parked dependency really does
        // block its dependents until somebody answers.
        TaskState::AwaitingInput(_)
        | TaskState::Failed { .. }
        | TaskState::Blocked(_)
        | TaskState::Skipped => true,
    }
}

/// Why a task is parked or failed, for the report.
///
/// The most recent *attempt failure* wins, not the most recent feedback entry:
/// the branches that park a task never record feedback, so once an operator has
/// answered anything, their answer would otherwise shadow every later failure
/// and the report would tell them a task is parked because they answered a
/// question. Human entries are excluded from the fallback for the same reason.
pub(super) fn last_reason(progress: &Progress) -> String {
    progress
        .records
        .last()
        .and_then(|r| r.failure.as_ref())
        .map(|f| f.reason.clone())
        .or_else(|| {
            progress
                .feedback
                .iter()
                .rev()
                .find(|f| !f.human)
                .map(|f| f.summary.clone())
        })
        .unwrap_or_else(|| "no attempt on record".to_owned())
}

pub(super) fn task_report(
    task: &Task,
    state: &TaskState,
    progress: &Progress,
    running: bool,
) -> TaskReport {
    let records = &progress.records;
    let last = records.last();
    TaskReport {
        id: task.id.to_string(),
        title: task.title.clone(),
        model: last.map(|r| r.model.clone()).unwrap_or_default(),
        status: match state {
            TaskState::Done(sha) => TaskRunStatus::Committed { sha: sha.clone() },
            TaskState::Failed { kind, reason } => TaskRunStatus::Failed {
                kind: *kind,
                reason: reason.clone(),
            },
            TaskState::AwaitingInput(question) => TaskRunStatus::Parked {
                question: question.to_string(),
                reason: last_reason(progress),
            },
            TaskState::Blocked(by) => TaskRunStatus::Blocked { by: by.clone() },
            // On an ended run, Deferred cannot survive `finish` and Pending is
            // settled away, so both mean the run stopped before this task got
            // its turn. On a live one `settle` leaves them alone, and the
            // attempt record says which of the two it is.
            //
            // Every arm here is about a run that is still going, which is why
            // both are guarded. `Running` says of itself that only a live
            // `status` produces it, and a dangling `in_flight` on an ended run
            // is not a counter-example — it is an attempt whose engine died
            // between `attempt_started` and `attempt_finished`, which any error
            // out of `run_attempt` leaves behind. `finish` then wrote it into
            // `report.json` as `t1: running now — attempt 2 on mid` beside a
            // top-level `"running": false`: a stored document contradicting
            // itself, outliving the process that wrote it.
            TaskState::Deferred | TaskState::Pending => match &progress.in_flight {
                Some(flight) if running => TaskRunStatus::Running {
                    attempt: flight.attempt,
                    tier: flight.tier.clone(),
                    model: flight.model.clone(),
                },
                None if running => TaskRunStatus::Queued,
                _ => TaskRunStatus::Skipped,
            },
            TaskState::Skipped => TaskRunStatus::Skipped,
        },
        duration: records.iter().map(|r| r.duration).sum(),
        cost_usd: sum_opt(records.iter().map(|r| r.cost_usd)),
        review_models: {
            // Deduped, first-seen order: an escalated task can be judged by one
            // model on its first rung and another on the next, and both belong
            // beside a cost that counts both.
            let mut seen: Vec<String> = Vec::new();
            for model in records.iter().flat_map(AttemptRecord::review_models) {
                if !seen.contains(&model) {
                    seen.push(model);
                }
            }
            seen
        },
        review_cost_usd: sum_opt(records.iter().map(AttemptRecord::review_cost_usd)),
        review_cost_incomplete: records.iter().any(AttemptRecord::review_cost_incomplete),
        session_id: last.and_then(|r| r.session_id.clone()),
        attempts: records.clone(),
    }
}

/// What every task cost, added up.
///
/// Deliberately not `Iterator::sum`, which folds floats from `-0.0`. That is
/// the *correct* additive identity in IEEE 754 — `-0.0 + x` preserves the sign
/// of `x` where `0.0 + x` does not — but it means the sum of no costs at all is
/// negative zero, and a run that has not yet spent anything rendered its ledger
/// as `total: $-0.0000`. Folding from `+0.0` cannot change a non-empty sum,
/// because the only value `+0.0` fails to preserve is `-0.0`, and a cost is
/// never that.
pub(super) fn total_of(tasks: &[TaskReport]) -> f64 {
    tasks
        .iter()
        .filter_map(TaskReport::total_cost_usd)
        .fold(0.0, |total, cost| total + cost)
}

/// Sum, preserving "nothing was reported" as `None` rather than `0.0` — a
/// ledger that cannot tell free from unreported is worse than no ledger.
pub(super) fn sum_opt(values: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    let mut total: Option<f64> = None;
    for value in values.flatten() {
        total = Some(total.unwrap_or(0.0) + value);
    }
    total
}

/// Stable topological order: among ready tasks, lowest plan index first (§14).
/// Used for previews and reporting; the live scheduler derives readiness per
/// step instead, so parked work can be skipped past.
pub fn topo_order(plan: &Plan) -> Vec<usize> {
    let mut done = vec![false; plan.tasks.len()];
    let mut order = Vec::with_capacity(plan.tasks.len());
    let index_of = |id: &str| plan.tasks.iter().position(|t| t.id.as_str() == id);
    while order.len() < plan.tasks.len() {
        let mut advanced = false;
        for i in 0..plan.tasks.len() {
            if done[i] {
                continue;
            }
            let ready = plan.tasks[i]
                .depends_on
                .iter()
                .all(|d| index_of(d.as_str()).is_none_or(|j| done[j]));
            if ready {
                done[i] = true;
                order.push(i);
                advanced = true;
                break;
            }
        }
        if !advanced {
            // Unreachable on a validated plan; degrade to plan order.
            for (i, flag) in done.iter_mut().enumerate() {
                if !*flag {
                    *flag = true;
                    order.push(i);
                }
            }
        }
    }
    order
}

impl RunReport {
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "run: {}", self.run_id);
        let _ = writeln!(out, "branch: {} (return with: git switch -)", self.branch);
        if self.gates.is_empty() {
            let _ = writeln!(out, "gates: none");
        } else {
            let _ = writeln!(
                out,
                "gates: {} [{}]",
                self.gates.join(", "),
                if self.gates_from_config {
                    "from config"
                } else {
                    "derived"
                }
            );
        }
        for warning in &self.warnings {
            let _ = writeln!(out, "warning: {warning}");
        }
        for task in &self.tasks {
            match &task.status {
                TaskRunStatus::Committed { sha } => {
                    // `?` marks a total with unreported components — the
                    // Copilot route bills nothing back, so a two-pass review
                    // shows one reviewer's spend and must not read as both.
                    let partial = if task.review_cost_incomplete { "?" } else { "" };
                    let review = match (task.review_models.as_slice(), task.review_cost_usd) {
                        ([], _) => String::new(),
                        (models, Some(cost)) => {
                            format!(" + review {} ${cost:.4}{partial}", models.join(", "))
                        }
                        // Reviewed only by routes that report no spend (§13) —
                        // say who judged it rather than imply it was free.
                        (models, None) => format!(" + review {} $?", models.join(", ")),
                    };
                    // Same rule as the reviewer half beside it, which has said
                    // `$?` since step 9: a route that reports no spend has not
                    // reported zero. `unwrap_or(0.0)` printed `$0.0000` for a
                    // codex-implemented task while the ledger three lines below
                    // correctly showed `—`, so one run said both.
                    let worker = match task.cost_usd {
                        Some(cost) => format!("${cost:.4}"),
                        None => "$?".to_owned(),
                    };
                    let _ = writeln!(
                        out,
                        "  {}: committed {sha} — {} [{}] ({:.1}s, {} {worker}{review})",
                        task.id,
                        task.title,
                        task.trail(),
                        task.duration.as_secs_f64(),
                        task.model,
                    );
                }
                TaskRunStatus::Failed { reason, .. } => {
                    let _ = writeln!(out, "  {}: FAILED [{}] — {reason}", task.id, task.trail());
                }
                TaskRunStatus::Parked { question, reason } => {
                    let _ = writeln!(
                        out,
                        "  {}: PARKED on {question} [{}] — {reason}",
                        task.id,
                        task.trail()
                    );
                }
                TaskRunStatus::Blocked { by } => {
                    let _ = writeln!(out, "  {}: blocked by `{by}`", task.id);
                }
                TaskRunStatus::Skipped => {
                    // Why it never got its turn, since the two endings are not
                    // the same thing to an operator: a halt is a decision the
                    // run reached, an interruption is one that happened to it
                    // and that `resume` undoes.
                    let ending = if self.interrupted {
                        "run interrupted"
                    } else {
                        "run halted"
                    };
                    let _ = writeln!(out, "  {}: skipped ({ending})", task.id);
                }
                TaskRunStatus::Running {
                    attempt,
                    tier,
                    model,
                } => {
                    let _ = writeln!(
                        out,
                        "  {}: running now — attempt {attempt} on {tier} ({model})",
                        task.id
                    );
                }
                TaskRunStatus::Queued => {
                    let _ = writeln!(out, "  {}: queued", task.id);
                }
                // Only reachable from a `report.json` written by a newer
                // tactus. Say that, rather than picking a familiar-looking
                // status and being confidently wrong about someone's run.
                TaskRunStatus::Unknown => {
                    let _ = writeln!(
                        out,
                        "  {}: status not recognised by this version of tactus",
                        task.id
                    );
                }
            }
        }
        let open: Vec<&QuestionRecord> = self.questions.iter().filter(|q| q.is_open()).collect();
        if !open.is_empty() {
            let _ = writeln!(out, "open questions ({}):", open.len());
            for record in open {
                let _ = writeln!(
                    out,
                    "  {} [{}] — {}",
                    record.question.id,
                    record.question.kind,
                    util::head(
                        record
                            .question
                            .context
                            .lines()
                            .next()
                            .unwrap_or("(no context)"),
                        120
                    )
                );
            }
            let _ = writeln!(
                out,
                "  payloads: {}",
                std::path::Path::new(".tactus")
                    .join("runs")
                    .join(&self.run_id)
                    .join("questions")
                    .display()
            );
        }
        let _ = writeln!(
            out,
            "total: ${:.4}{} (api-equivalent)",
            self.total_cost_usd,
            if self.total_is_floor() { "?" } else { "" }
        );
        // A live run has no outcome yet, and every arm below claims one. Say
        // what is true instead: how far it has got.
        if self.running {
            let _ = writeln!(
                out,
                "run in progress: {} task(s) committed so far on {}",
                self.committed_count(),
                self.branch
            );
            return out;
        }
        // Neither has a run that stopped without recording a finish, and for
        // the same reason: there is no outcome to report yet. `outcome()`
        // cannot see that — a killed run has nothing halted, no budget stop and
        // nothing parked, which reads as `Complete` — so it used to print `run
        // complete: N task(s) committed` about a run that died mid-attempt,
        // one line above `status`'s own `state: interrupted`.
        //
        // "So far" is the live line's word on purpose: more may yet come, once
        // somebody resumes. Which is also why the resume command is not
        // repeated here — the `state:` line in `status` already carries it, and
        // saying it twice invites the two copies to drift.
        if self.interrupted {
            let _ = writeln!(
                out,
                "run interrupted: {} task(s) committed so far on {}",
                self.committed_count(),
                self.branch
            );
            return out;
        }
        match self.outcome() {
            RunOutcome::Halted => {
                let _ = writeln!(
                    out,
                    "run halted at `{}`; completed tasks are committed on {}",
                    self.halted_at.as_deref().unwrap_or("?"),
                    self.branch
                );
            }
            RunOutcome::BudgetExceeded => {
                // `outcome()` only returns this when `budget_stop` is set, so
                // the fallback is unreachable — and it says so rather than
                // naming a plausible ceiling. A specific, checkable, false
                // claim about the operator's own config is the worst thing to
                // print here.
                let stopped = self.budget_stop.as_ref().map_or_else(
                    || "run stopped at a budget it did not record".to_owned(),
                    |stop| {
                        format!(
                            "run stopped at its budget: [budgets] {} = ${:.4}, reported spend \
                             ${:.4}",
                            stop.budget, stop.limit_usd, stop.spent_usd
                        )
                    },
                );
                let _ = writeln!(
                    out,
                    "{stopped}. Committed tasks are on {}; raise the ceiling and continue \
                     with:\n    tactus resume {} --budget <usd>",
                    self.branch, self.run_id
                );
            }
            RunOutcome::Parked => {
                let _ = writeln!(
                    out,
                    "run ended with {} task(s) parked on unanswered questions: {}",
                    self.parked_tasks().len(),
                    self.parked_tasks().join(", ")
                );
            }
            RunOutcome::Complete => {
                let committed = self.committed_count();
                let _ = writeln!(
                    out,
                    "run complete: {committed} task(s) committed on {}",
                    self.branch
                );
            }
        }
        out
    }

    /// §21's definition-of-done (e): what each task cost, and on what.
    ///
    /// Implementer and reviewer spend stay in separate columns because they
    /// are different models at different tiers — folding them together makes a
    /// cheap rung look expensive to anyone reading the ledger (§13). An
    /// unreported cost prints as `—` rather than `$0.0000`: a ledger that
    /// cannot tell free from unreported is worse than no ledger.
    pub fn render_ledger(&self) -> String {
        let mut out = String::new();
        let money = |value: Option<f64>| match value {
            Some(amount) => format!("${amount:.4}"),
            None => "—".to_owned(),
        };
        // A figure that omits a reviewer whose route bills nothing back is not
        // the total, and this column is where someone decides what a run cost.
        let partial = |rendered: String, incomplete: bool| {
            if incomplete && rendered != "—" {
                format!("{rendered}?")
            } else {
                rendered
            }
        };
        let rows: Vec<[String; 6]> = self
            .tasks
            .iter()
            .map(|task| {
                [
                    task.id.clone(),
                    task.attempts.len().to_string(),
                    if task.trail().is_empty() {
                        "—".to_owned()
                    } else {
                        task.trail()
                    },
                    partial(money(task.cost_usd), task.cost_incomplete()),
                    partial(money(task.review_cost_usd), task.review_cost_incomplete),
                    partial(
                        money(task.total_cost_usd()),
                        task.cost_incomplete() || task.review_cost_incomplete,
                    ),
                ]
            })
            .collect();
        let headers = ["task", "attempts", "trail", "worker", "review", "total"];
        let widths: Vec<usize> = (0..headers.len())
            .map(|column| {
                rows.iter()
                    .map(|row| row[column].chars().count())
                    .chain(std::iter::once(headers[column].chars().count()))
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let line = |cells: &[String]| {
            let mut rendered = String::from("  ");
            for (index, cell) in cells.iter().enumerate() {
                let pad = widths[index].saturating_sub(cell.chars().count());
                let _ = write!(rendered, "{cell}{:pad$}", "", pad = pad);
                if index + 1 < cells.len() {
                    rendered.push_str("  ");
                }
            }
            rendered.trim_end().to_owned()
        };

        let _ = writeln!(out, "ledger:");
        let _ = writeln!(out, "{}", line(&headers.map(str::to_owned)));
        for row in &rows {
            let _ = writeln!(out, "{}", line(row));
        }
        let _ = writeln!(
            out,
            "  total ${:.4}{} (api-equivalent; subscription spend is notional — §13)",
            self.total_cost_usd,
            if self.total_is_floor() { "?" } else { "" }
        );
        if self.total_is_floor() {
            let _ = writeln!(
                out,
                "  `?` marks a figure missing an attempt whose route reports no spend, or one \
                 the engine was killed inside — a floor, not a total (§13)"
            );
        }
        // §13's second currency. An empty section means no attempt in this run
        // named a pool — which is the honest reading of "no pools connected",
        // and is said rather than left as a blank column that looks like
        // "nothing was spent".
        if self.pool_drain.is_empty() {
            let _ = writeln!(
                out,
                "  per-pool drain: no pool is connected for the agents this run used — run \
                 `tactus connect`"
            );
        } else {
            let _ = writeln!(out, "  per-pool drain:");
            for row in &self.pool_drain {
                let spend = match row.cost_usd {
                    Some(cost) if row.unpriced > 0 => format!("${cost:.4}?"),
                    Some(cost) => format!("${cost:.4}"),
                    // Every attempt on this pool ran on a route that reports no
                    // spend (§13) — saying "$0.0000" would read as free.
                    None => "— (this route reports no spend)".to_owned(),
                };
                let _ = writeln!(
                    out,
                    "    {}: {} attempt(s), {spend}",
                    row.pool, row.attempts
                );
            }
        }
        if let Some(stop) = &self.budget_stop {
            let _ = writeln!(
                out,
                // The ledger annotates; `render` owns the outcome line and the
                // resume advice. Printing both put two near-identical
                // paragraphs, formatted to different precision, with two copies
                // of the same command, back to back in `tactus status` — which
                // reads as two things having happened.
                "  stopped by [budgets] {} = ${:.4} before `{}` (§13)",
                stop.budget, stop.limit_usd, stop.task
            );
        }
        out
    }
}
