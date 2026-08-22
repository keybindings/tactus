//! `tactus status` — the run, folded out of its own log (DESIGN.md §15).
//!
//! Status is a pure read: it opens no branch, spawns no agent, and takes no
//! lock. Everything it shows is derived by replaying `events.jsonl` through
//! the same [`RunState::apply`](crate::events::RunState::apply) the engine
//! writes through, so a running engine and a watching operator are looking at
//! one computation rather than two that ought to agree.
//!
//! The plan comes from the run's own `plan.normalized.json` rather than from
//! the plan file on disk: §5 freezes a plan at run start, and status should
//! describe the run that happened even if the source plan has since moved on.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::engine::RunReport;
use crate::error::TactusError;
use crate::events::{self, Event, EventBody, LogTail, RunStarted, RunState};
use crate::interaction::Sleeper;
use crate::ir::Plan;
use crate::rundir::{self, RunPaths};

/// One run, as read back from disk.
pub struct RunStatus {
    pub run_id: String,
    pub paths: RunPaths,
    pub started: RunStarted,
    pub state: RunState,
    pub plan: Plan,
    /// Whether an engine is driving this run *and* the run has not recorded
    /// that it finished — the two halves of "still going", which the lock
    /// alone does not answer.
    pub running: bool,
    /// Whether anything holds the run's lock, finished or not.
    ///
    /// Kept beside `running` rather than folded into it because a process
    /// claiming a run that already ended is real and worth saying: `resume`
    /// takes the lock and holds it across a dozen git subprocesses before it
    /// writes `run_resumed`. During that window the run has an owner and an
    /// outcome at the same time, and an operator asking `status` deserves
    /// both.
    pub held: bool,
    /// Attempts that were in flight when a previous process stopped.
    pub interrupted: u32,
    pub warnings: Vec<String>,
}

impl RunStatus {
    /// The same projection a run writes to `report.json`.
    pub fn report(&self) -> RunReport {
        RunReport::from_state(
            &self.started,
            &self.plan,
            &self.state,
            self.warnings.clone(),
            self.running,
            self.interrupted_run(),
        )
    }

    /// Whether this run stopped without recording that it had finished — the
    /// signature of a kill, a power loss, or an aborting error.
    pub fn interrupted_run(&self) -> bool {
        !self.running && self.state.finished.is_none()
    }
}

/// What `status` says about a husk id, or `None` if `wanted` names no husk.
///
/// Read-only end to end, and it never resolves a husk into a run: the answer
/// is the refusal, carrying which of the three kinds of husk this is, its
/// reason and its private locator. The authorized private root is the default
/// one, which is the root a read-only command is configured with.
fn husk_answer(repo_root: &Path, wanted: &str) -> Option<TactusError> {
    let husk_id = rundir::list_husks(repo_root)
        .into_iter()
        .find(|id| id.eq_ignore_ascii_case(wanted))?;
    let repo_key = rundir::RepoKey::for_repo(repo_root).ok()?;
    let report = rundir::husk_report(
        repo_root,
        &husk_id,
        &repo_key,
        &rundir::default_private_root(),
    );
    let locator = report.locator.as_ref().map_or_else(
        || " It records no private locator.".to_owned(),
        |path| format!(" Its private locator is {}.", path.display()),
    );
    Some(TactusError::Refused {
        message: format!(
            "run `{husk_id}` never recorded a committed run_started: it is {}.{locator}",
            report.disposition.describe()
        ),
    })
}

/// Load a run: the newest one, or any unambiguous id prefix.
pub fn load(repo_root: &Path, run_id: Option<&str>) -> Result<RunStatus, TactusError> {
    let run_id = match run_id {
        Some(wanted) => match rundir::resolve_run_id(repo_root, wanted) {
            Ok(resolved) => resolved,
            // `startup_census`: "status is read-only: it ignores husks and,
            // asked explicitly for a husk id, reports an unstarted husk that
            // the next write command reclaims, a retained husk with its reason
            // and locator, or a possibly committed run whose public log has no
            // valid committed first line".
            Err(error) => return Err(husk_answer(repo_root, wanted).unwrap_or(error)),
        },
        None => rundir::latest_run(repo_root).ok_or_else(|| TactusError::Refused {
            message: format!(
                "no runs found under {} — nothing has run in this repository yet",
                rundir::runs_root(repo_root).display()
            ),
        })?,
    };
    let public = rundir::public_dir(repo_root, &run_id);
    let events_path = public.join("events.jsonl");

    let (bytes, held) = stable_event_bytes_with(
        &events_path,
        || events::read_bytes(&events_path),
        || rundir::is_running(&public),
    )?;
    let parsed = events::parse_bytes(&events_path, &bytes)?;
    let mut warnings = Vec::new();
    warnings.extend(parsed.torn_tail_warning);
    let events = parsed.events;
    let started = events::started_of(&events, &events_path)?.clone();
    let effective_schema = events::ensure_supported_schema(&started, &events, &events_path)?;
    if started.run_id != run_id {
        return Err(TactusError::EventLog {
            path: events_path.clone(),
            message: format!(
                "run_started id `{}` does not match directory `{run_id}`",
                started.run_id
            ),
        });
    }
    let paths = RunPaths::from_parts(public.clone(), PathBuf::from(&started.private_dir));

    let plan_path = paths.plan_json();
    let plan_bytes = std::fs::read(&plan_path).map_err(|source| TactusError::Io {
        path: plan_path.clone(),
        source,
    })?;
    if effective_schema >= 3 {
        let recorded = events::recorded_normalized_plan_digest(&events).ok_or_else(|| {
            TactusError::EventLog {
                path: events_path.clone(),
                message: "event schema 3 does not record the normalized-plan SHA-256 digest"
                    .to_owned(),
            }
        })?;
        let actual = events::normalized_plan_digest(&plan_bytes);
        if actual != recorded {
            return Err(TactusError::EventLog {
                path: plan_path.clone(),
                message: format!(
                    "normalized plan digest `{actual}` does not match recorded digest `{recorded}`"
                ),
            });
        }
    }
    let plan: Plan = serde_json::from_slice(&plan_bytes).map_err(|e| TactusError::Parse {
        message: format!("{}: {e}", plan_path.display()),
    })?;
    if plan.source.hash != started.plan_hash {
        return Err(TactusError::EventLog {
            path: plan_path.clone(),
            message: format!(
                "frozen plan hash `{}` does not match run-start hash `{}`",
                plan.source.hash, started.plan_hash
            ),
        });
    }

    let task_ids = plan.tasks.iter().map(|task| task.id.to_string()).collect();
    let mut replayed = events::replay(events, task_ids, &events_path)?;
    // Two questions, not one. The lock says whether a process has claimed this
    // run; the log says whether the run still has anywhere to go. `running`
    // needs both, for the same reason `interrupted_run` below does: `resume`
    // claims the lock before it writes anything, so a budget-stopped run has an
    // owner for as long as that resume takes to get going. Reading the lock
    // alone made those seconds render as `run in progress`, dropping the stop
    // reason, the parked list, and the `resume --budget` line the operator is
    // there to find.
    let running = held && replayed.state.finished.is_none();
    // Settled in memory only: status is a pure read and must not write to a
    // run it is merely looking at. A resume records the same settlement as
    // events instead.
    //
    // And only for a run nothing is driving. An attempt in flight under a live
    // engine has not been interrupted — it is working — so settling it here
    // would report a running attempt as a failure and the whole run as halted.
    // `status` is the only window into a run that holds its own terminal, so
    // that reading is worse than no reading at all.
    let interrupted = if running {
        0
    } else {
        replayed.state.settle_interrupted()
    };

    Ok(RunStatus {
        run_id,
        paths,
        started: replayed.started,
        state: replayed.state,
        plan,
        running,
        held,
        interrupted,
        warnings,
    })
}

/// The whole view: what happened, what it cost, and what it is waiting for.
pub fn render(status: &RunStatus) -> String {
    use std::fmt::Write as _;

    let report = status.report();
    let mut out = report.render();
    out.push_str(&report.render_ledger());

    // Liveness first among the trailing lines, because it decides whether any
    // of the above is still moving.
    if status.running {
        let _ = writeln!(out, "state: running now (another process holds this run)");
    } else if status.interrupted_run() {
        let _ = writeln!(
            out,
            "state: interrupted — this run stopped without finishing{}. Continue it with:\n    \
             tactus resume {}",
            if status.interrupted > 0 {
                format!(
                    ", with {} attempt(s) cut off mid-flight",
                    status.interrupted
                )
            } else {
                String::new()
            },
            status.run_id
        );
    } else if status.held {
        // Finished, and somebody has claimed it anyway — a `resume` between
        // taking the lock and writing `run_resumed`. The outcome above is still
        // this run's outcome; it may just not be the last word for long.
        let _ = writeln!(
            out,
            "state: another process holds this run (a resume, most likely)"
        );
    }

    let open = status.state.open_questions();
    if !open.is_empty() {
        let _ = writeln!(out, "waiting on {} answer(s):", open.len());
        for record in open {
            let _ = writeln!(out, "    tactus answer {}", record.question.id);
        }
    }
    let _ = writeln!(out, "transcripts: {}", status.paths.private.display());
    out
}

/// One human line per event, for `--follow`.
pub fn describe(event: &Event) -> String {
    let at = event.ts.get(11..19).unwrap_or(&event.ts);
    let body = match &event.body {
        EventBody::RunStarted { data } => {
            format!("run {} started on {}", data.run_id, data.branch)
        }
        EventBody::RunResumed { data } => format!(
            "resumed at {} ({} interrupted attempt(s))",
            short(&data.head_sha),
            data.interrupted_attempts
        ),
        EventBody::RunSchemaUpgraded { data } => {
            format!("event schema upgraded from {} to {}", data.from, data.to)
        }
        EventBody::AttemptStarted {
            task,
            attempt,
            data,
            ..
        } => format!(
            "{task}: attempt {attempt} on {} ({}){}",
            data.tier,
            data.model,
            if data.resume_session.is_some() {
                ", resuming the session"
            } else {
                ""
            }
        ),
        EventBody::AttemptFinished {
            task,
            attempt,
            data,
            parking,
            transition,
            ..
        } => {
            if let Some(parking) = parking {
                let reason = data
                    .failure
                    .as_ref()
                    .map(|failure| failure.reason.as_str())
                    .unwrap_or("policy refusal");
                if let Some(events::AttemptTransition::Escalate(escalation)) = transition.as_deref()
                {
                    format!(
                        "{task}: attempt {attempt} failed — {reason}; escalating past {} to rung \
                         {} and parked on question {}",
                        escalation.tier, escalation.to_rung, parking.question.id
                    )
                } else {
                    format!(
                        "{task}: attempt {attempt} failed and parked on question {} — {reason}",
                        parking.question.id
                    )
                }
            } else {
                match &data.failure {
                    Some(failure) => match transition.as_deref() {
                        Some(events::AttemptTransition::Retry(data)) => format!(
                            "{task}: attempt {attempt} failed — {}; retrying on {}{}",
                            failure.reason,
                            data.tier,
                            if data.resume {
                                " in the same session"
                            } else {
                                ""
                            }
                        ),
                        Some(events::AttemptTransition::Escalate(data)) => format!(
                            "{task}: attempt {attempt} failed — {}; escalating past {} to rung {}",
                            failure.reason, data.tier, data.to_rung
                        ),
                        Some(events::AttemptTransition::Defer(data)) => format!(
                            "{task}: attempt {attempt} failed — {}; deferred ({}) — {}",
                            failure.reason, data.defers, data.reason
                        ),
                        Some(events::AttemptTransition::Fail(data)) => format!(
                            "{task}: attempt {attempt} failed — {}; task failed ({:?})",
                            failure.reason, data.kind
                        ),
                        None => format!("{task}: attempt {attempt} failed — {}", failure.reason),
                    },
                    None => format!("{task}: attempt {attempt} passed"),
                }
            }
        }
        EventBody::AttemptInterrupted { task, attempt, .. } => format!(
            "{task}: attempt {attempt} was cut off mid-flight; its spend is unknown and the \
             rung's allowance is intact"
        ),
        EventBody::LadderRetry { task, data, .. } => format!(
            "{task}: retrying on {}{}",
            data.tier,
            if data.resume {
                " in the same session"
            } else {
                ""
            }
        ),
        EventBody::LadderEscalated { task, data, .. } => {
            format!(
                "{task}: escalating past {} to rung {}",
                data.tier, data.to_rung
            )
        }
        EventBody::TaskDeferred { task, data } => {
            format!("{task}: deferred ({}) — {}", data.defers, data.reason)
        }
        EventBody::DeferWaitElapsed { data } => {
            format!("waited {}s for a pool to come back", data.waited.as_secs())
        }
        EventBody::TaskParked { task, data } => {
            format!("{task}: parked on {}", data.question)
        }
        EventBody::TaskCommitted { task, data } => {
            format!("{task}: committed {}", short(&data.sha))
        }
        EventBody::TaskFailed { task, data } => format!("{task}: failed — {}", data.reason),
        EventBody::QuestionRaised { task, data } => format!(
            "{task}: asking {} — answer with `tactus answer {}`",
            data.question.kind, data.question.id
        ),
        EventBody::QuestionAnswered { data } => {
            format!("{} answered via {}", data.question, data.via)
        }
        EventBody::DesignDefect { data } => {
            format!("design defect recorded for {}", data.question)
        }
        EventBody::CapacitySnapshot { data } => format!(
            "capacity snapshot under `{}`: {}",
            data.strategy,
            if data.pools.is_empty() {
                "no pools connected".to_owned()
            } else {
                data.pools
                    .iter()
                    .map(|pool| format!("{} {} [{}]", pool.pool, pool.remaining, pool.confidence))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
        EventBody::PoolExhausted { task, data } => format!(
            "{task}: pool `{}` reported exhausted{}",
            data.pool,
            match &data.reset_at {
                Some(at) => format!(", resets {at}"),
                None => ", reset time unknown".to_owned(),
            }
        ),
        EventBody::BudgetExceeded { data } => format!(
            "budget {} = ${:.2} reached at ${:.4}; `{}` did not start",
            data.budget, data.limit_usd, data.spent_usd, data.task
        ),
        EventBody::RunFinished { data } => format!(
            "run finished: {:?} ({} committed, {} parked)",
            data.outcome, data.committed, data.parked
        ),
    };
    format!("{at}  {body}")
}

fn short(sha: &str) -> String {
    sha.chars().take(10).collect()
}

/// Stream a run's events, from the beginning and then as they arrive.
///
/// Starting from the beginning is deliberate: `--follow` on a run already in
/// progress should show how it got here, not drop the reader into the middle
/// of a story. Reads only whole lines, so a follower attached to a live engine
/// never sees half an event. Returns once the run records that it is done —
/// or, once nothing is driving the run any more, after `max_idle_polls` with
/// nothing new, so a follower attached to a run whose engine has died gives up
/// instead of waiting forever.
pub fn follow(
    status: &RunStatus,
    sleeper: &dyn Sleeper,
    poll: Duration,
    max_idle_polls: u32,
    out: &mut dyn std::io::Write,
) -> Result<(), TactusError> {
    let mut tail = LogTail::new(status.paths.events());
    let mut warnings = Vec::new();
    let mut idle = 0;
    let mut terminal = false;
    loop {
        let events = tail.poll(&mut warnings)?;
        if events.is_empty() {
            // The idle budget is not a timeout on silence. A whole attempt —
            // the agent's thinking, its tool calls, the gates, the review —
            // folds into a single `attempt_finished`, so a healthy run says
            // nothing for minutes at a time; giving up on one would drop the
            // live view mid-run. The budget exists only to release a terminal
            // attached to an engine that has died, so it starts counting when
            // the run's lock does not.
            //
            // One syscall per poll, asked plainly. This used to need a cheaper
            // variant of its own, because the check waited out a contention
            // grace every time the answer was yes — which on a healthy run is
            // every poll. The lock now answers exactly, so there is no cheaper
            // question to ask.
            let running = rundir::is_running(&status.paths.public);
            if terminal && !running {
                return Ok(());
            }
            if running {
                idle = 0;
            } else {
                idle += 1;
                if idle > max_idle_polls {
                    return Ok(());
                }
            }
            sleeper.sleep(poll);
            continue;
        }
        idle = 0;
        for event in &events {
            let _ = writeln!(out, "{}", describe(event));
            match &event.body {
                EventBody::RunFinished { .. } => terminal = true,
                EventBody::RunResumed { .. } => terminal = false,
                _ => {}
            }
        }
        // A resume owns the lock before it can append RunResumed. A follower
        // that sees the previous epoch's RunFinished in that window must wait
        // for the marker rather than treating historical terminal state as the
        // current process's result.
        if terminal && !rundir::is_running(&status.paths.public) {
            return Ok(());
        }
    }
}

/// Pair event bytes with a stable liveness observation. A dead snapshot is
/// trusted only after an identical second read and a second dead probe; this
/// prevents status from reading `attempt_started`, observing the conductor
/// release its lock after writing the settlement, and then inventing an
/// interrupted attempt from the stale prefix.
fn stable_event_bytes_with(
    path: &Path,
    mut read: impl FnMut() -> Result<Vec<u8>, TactusError>,
    mut held: impl FnMut() -> bool,
) -> Result<(Vec<u8>, bool), TactusError> {
    const MAX_SNAPSHOT_ATTEMPTS: usize = 8;
    for _ in 0..MAX_SNAPSHOT_ATTEMPTS {
        let held_before = held();
        let first = read()?;
        let held_after = held();
        if held_before != held_after {
            continue;
        }
        if held_after {
            return Ok((first, true));
        }

        let second = read()?;
        let held_final = held();
        if !held_final && first == second {
            return Ok((second, false));
        }
    }
    Err(TactusError::Refused {
        message: format!(
            "{} kept changing while status checked whether its engine was live; retry status once the transition settles",
            path.display()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{
        AttemptRecord, AttemptStarted, AttemptTransition, LadderEscalated, LadderRetry,
        RunFinished, RunOutcome, TaskCommitted, TaskDeferred, TaskFailed,
    };
    use crate::ir::{Answer, Question, QuestionId, QuestionKind, TaskId};
    use crate::ladder::{FailureKind, FailureOrigin};

    fn event(body: EventBody) -> Event {
        Event {
            ts: "2026-08-09T14:03:07Z".to_owned(),
            body,
        }
    }

    /// `load` composes `resolve_run_id`'s refusal with `rundir::husk_report`,
    /// and a composition nobody drives is the shape `PR4-CONF-008` was: both
    /// halves were tested and their join was not. So this asks `status` itself.
    #[test]
    fn status_asked_for_a_husk_id_names_which_husk_it_is() {
        let root = std::env::temp_dir().join(format!(
            "tactus-status-husk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        // A real repository, because the husk answer takes this repository's
        // key over its canonical common git dir.
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q", "-b", "main"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git runs");
        assert!(status.success(), "git init");

        let husk = "01STATUSHUSK00000000000000";
        std::fs::create_dir_all(rundir::public_dir(&root, husk)).expect("husk");
        let Err(error) = load(&root, Some(husk)) else {
            panic!("a husk is not a run and status must not load one");
        };
        let said = error.to_string();
        assert!(said.contains(husk), "names the id: {said}");
        assert!(
            said.contains("never recorded a committed run_started"),
            "says why: {said}"
        );
        assert!(
            said.contains("unstarted husk"),
            "and which of the three it is: {said}"
        );
        assert!(
            said.contains("records no private locator"),
            "and its locator, or that there is none: {said}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_live_to_dead_transition_retries_instead_of_settling_a_stale_prefix() {
        use std::collections::VecDeque;

        let mut reads = VecDeque::from([
            b"attempt-started\n".to_vec(),
            b"attempt-started\nattempt-finished\n".to_vec(),
            b"attempt-started\nattempt-finished\n".to_vec(),
        ]);
        let mut probes = VecDeque::from([true, false, false, false, false]);
        let (bytes, held) = stable_event_bytes_with(
            Path::new("events.jsonl"),
            || Ok(reads.pop_front().expect("bounded read sequence")),
            || probes.pop_front().expect("bounded probe sequence"),
        )
        .expect("the second snapshot is stable");

        assert!(!held);
        assert_eq!(bytes, b"attempt-started\nattempt-finished\n");
        assert!(reads.is_empty());
        assert!(probes.is_empty());
    }

    #[test]
    fn every_event_describes_itself_in_one_line() {
        let lines = [
            event(EventBody::AttemptStarted {
                task: "t1".to_owned(),
                attempt: 1,
                rung: 0,
                profile: "small-haiku".to_owned(),
                data: AttemptStarted {
                    adapter: None,
                    preflight_cli_version: None,
                    effort: None,
                    selection_origin: None,
                    tier: "small".to_owned(),
                    agent: "claude-code".to_owned(),
                    model: "claude-haiku-4-5".to_owned(),
                    pool: Some("claude-max".to_owned()),
                    resume_session: None,
                },
            }),
            event(EventBody::TaskCommitted {
                task: "t1".to_owned(),
                data: TaskCommitted {
                    sha: "0123456789abcdef".to_owned(),
                    message: "[tactus] t1: do it".to_owned(),
                },
            }),
            event(EventBody::RunFinished {
                data: RunFinished {
                    outcome: RunOutcome::Complete,
                    halted_at: None,
                    committed: 1,
                    parked: 0,
                },
            }),
        ];
        let rendered: Vec<String> = lines.iter().map(describe).collect();
        assert!(rendered[0].starts_with("14:03:07  "), "{:?}", rendered[0]);
        assert!(rendered[0].contains("t1: attempt 1 on small"));
        assert!(rendered[1].contains("committed 0123456789"));
        assert!(rendered[2].contains("run finished"));
        for line in &rendered {
            assert_eq!(line.lines().count(), 1, "one line per event: {line:?}");
        }
    }

    #[test]
    fn a_raised_question_tells_the_operator_the_command_to_run() {
        let line = describe(&event(EventBody::QuestionRaised {
            task: "t1".to_owned(),
            data: Box::new(events::QuestionRaised {
                question: Question {
                    id: QuestionId::from("q-01ABC"),
                    kind: QuestionKind::Unblock,
                    affected_tasks: vec![TaskId::from("t1")],
                    context: "every rung failed".to_owned(),
                    options: Vec::new(),
                },
            }),
        }));
        assert!(line.contains("tactus answer q-01ABC"), "{line}");
    }

    #[test]
    fn describe_atomic_attempt_transitions() {
        let cases = [
            (
                AttemptTransition::Retry(LadderRetry {
                    resume: true,
                    tier: "mid".to_owned(),
                    summary: "try again".to_owned(),
                    detail: None,
                }),
                "retrying on mid in the same session",
            ),
            (
                AttemptTransition::Escalate(LadderEscalated {
                    to_rung: 2,
                    tier: "frontier".to_owned(),
                    summary: "go higher".to_owned(),
                    detail: None,
                }),
                "escalating past frontier to rung 2",
            ),
            (
                AttemptTransition::Defer(TaskDeferred {
                    reason: "pool unavailable".to_owned(),
                    defers: 3,
                }),
                "deferred (3) — pool unavailable",
            ),
            (
                AttemptTransition::Fail(TaskFailed {
                    kind: FailureKind::GateFailed,
                    reason: "gates exhausted".to_owned(),
                    halts_run: true,
                }),
                "task failed (GateFailed)",
            ),
        ];

        for (transition, expected) in cases {
            let line = describe(&event(EventBody::AttemptFinished {
                task: "t1".to_owned(),
                attempt: 1,
                rung: 0,
                profile: "implement".to_owned(),
                data: Box::new(AttemptRecord {
                    attempt: 1,
                    tier: "small".to_owned(),
                    model: "model".to_owned(),
                    pool: None,
                    resumed: false,
                    duration: Duration::from_secs(1),
                    cost_usd: None,
                    reviews: Vec::new(),
                    session_id: None,
                    usage: None,
                    failure: Some(events::FailureRecord {
                        kind: FailureKind::GateFailed,
                        origin: FailureOrigin::Worker,
                        reason: "the attempt failed".to_owned(),
                    }),
                }),
                parking: None,
                transition: Some(Box::new(transition)),
                prepared_commit: None,
            }));
            assert!(line.contains(expected), "{line}");
        }
    }

    #[test]
    fn describe_composes_escalation_with_spend_approval_parking() {
        let line = describe(&event(EventBody::AttemptFinished {
            task: "t1".to_owned(),
            attempt: 1,
            rung: 0,
            profile: "implement".to_owned(),
            data: Box::new(AttemptRecord {
                attempt: 1,
                tier: "small".to_owned(),
                model: "model".to_owned(),
                pool: None,
                resumed: false,
                duration: Duration::from_secs(1),
                cost_usd: None,
                reviews: Vec::new(),
                session_id: None,
                usage: None,
                failure: Some(events::FailureRecord {
                    kind: FailureKind::GateFailed,
                    origin: FailureOrigin::Worker,
                    reason: "the attempt failed".to_owned(),
                }),
            }),
            parking: Some(Box::new(events::AttemptParking {
                question: Question {
                    id: QuestionId::from("q-spend"),
                    kind: QuestionKind::ApproveSpend,
                    affected_tasks: vec![TaskId::from("t1")],
                    context: "approve the next rung".to_owned(),
                    options: Vec::new(),
                },
                refund_attempt: false,
            })),
            transition: Some(Box::new(AttemptTransition::Escalate(LadderEscalated {
                to_rung: 1,
                tier: "small".to_owned(),
                summary: "escalate".to_owned(),
                detail: None,
            }))),
            prepared_commit: None,
        }));
        assert!(line.contains("escalating past small to rung 1"), "{line}");
        assert!(line.contains("parked on question q-spend"), "{line}");
        assert_eq!(line.lines().count(), 1, "{line:?}");
    }

    #[test]
    fn the_ledger_keeps_worker_and_review_spend_apart() {
        let report = RunReport {
            run_id: "01RUN".to_owned(),
            branch: "tactus/run-01RUN".to_owned(),
            gates: vec!["check".to_owned()],
            gates_from_config: true,
            warnings: Vec::new(),
            tasks: vec![crate::engine::TaskReport {
                id: "t1".to_owned(),
                title: "Do it".to_owned(),
                model: "claude-haiku-4-5".to_owned(),
                status: crate::engine::TaskRunStatus::Committed {
                    sha: "abc".to_owned(),
                },
                duration: Duration::from_secs(3),
                cost_usd: Some(0.01),
                review_models: vec!["claude-opus-5".to_owned()],
                review_cost_usd: Some(0.05),
                review_cost_incomplete: false,
                session_id: None,
                attempts: vec![AttemptRecord {
                    attempt: 1,
                    tier: "small".to_owned(),
                    model: "claude-haiku-4-5".to_owned(),
                    pool: Some("claude-max".to_owned()),
                    resumed: false,
                    duration: Duration::from_secs(3),
                    cost_usd: Some(0.01),
                    reviews: Vec::new(),
                    session_id: None,
                    usage: None,
                    failure: None,
                }],
            }],
            halted_at: None,
            questions: Vec::new(),
            budget_stop: None,
            running: false,
            interrupted: false,
            total_cost_usd: 0.06,
            pool_drain: vec![crate::engine::PoolDrainRow {
                pool: "claude-max".to_owned(),
                attempts: 1,
                cost_usd: Some(0.01),
                unpriced: 0,
            }],
        };
        let ledger = report.render_ledger();
        assert!(ledger.contains("worker"), "{ledger}");
        assert!(ledger.contains("$0.0100"), "implementer's own spend");
        assert!(ledger.contains("$0.0500"), "reviewer's, kept apart");
        assert!(ledger.contains("$0.0600"), "and the total");
        // §13's second currency, beside the dollars and derived from the same
        // attempt records.
        assert!(ledger.contains("per-pool drain:"), "{ledger}");
        assert!(
            ledger.contains("claude-max: 1 attempt(s), $0.0100"),
            "{ledger}"
        );
    }

    #[test]
    fn an_unreported_cost_is_not_rendered_as_free() {
        let report = RunReport {
            run_id: "01RUN".to_owned(),
            branch: "b".to_owned(),
            gates: Vec::new(),
            gates_from_config: false,
            warnings: Vec::new(),
            tasks: vec![crate::engine::TaskReport {
                id: "t1".to_owned(),
                title: "Never ran".to_owned(),
                model: String::new(),
                status: crate::engine::TaskRunStatus::Skipped,
                duration: Duration::ZERO,
                cost_usd: None,
                review_models: Vec::new(),
                review_cost_usd: None,
                review_cost_incomplete: false,
                session_id: None,
                attempts: Vec::new(),
            }],
            halted_at: None,
            questions: Vec::new(),
            budget_stop: None,
            running: false,
            interrupted: false,
            total_cost_usd: 0.0,
            pool_drain: Vec::new(),
        };
        let ledger = report.render_ledger();
        assert!(
            ledger.contains('—'),
            "unreported must not read as $0.0000: {ledger}"
        );
    }

    #[test]
    fn answers_and_defects_render_without_quoting_the_operator() {
        // The operator's words are an instruction to the agent, not something
        // status needs to echo into a terminal it does not control.
        let line = describe(&event(EventBody::QuestionAnswered {
            data: events::QuestionAnswered {
                question: QuestionId::from("q-1"),
                answer: Answer::Answered {
                    text: "\u{1b}[31mnot a control sequence\u{1b}[0m".to_owned(),
                },
                decline_halts_run: None,
                via: "answer-file".to_owned(),
            },
        }));
        assert!(
            !line.contains('\u{1b}'),
            "no escape codes reach the terminal"
        );
        assert!(line.contains("q-1 answered via answer-file"), "{line}");
    }
}
