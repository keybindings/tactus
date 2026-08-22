// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use crate::capacity;
use crate::config;
use crate::error::TactusError;
use crate::events::{self, EventBody, EventLog, RunState, TaskState};
use crate::interaction::{self, RealSleeper};
use crate::ir::{Answer, Plan, QuestionId, ResolvedEffortPolicy};
use crate::ladder::FailureKind;
use crate::rundir::{self, RunLock, RunPaths, WorktreeLock};
use crate::runner::Runner;
use crate::util;
use crate::workspace::Workspace;

use super::coordinator::{Run, prepared_pin_ref};
use super::options::{Harness, ResumeOptions, RunOptions};
use super::preflight::{
    Preflight, Recorded, RecordedRouting, chain_summaries, normalized_plan_bytes,
    preflight_with_recorded, validate_inputs,
};
use super::report::{RunReport, last_reason};
use crate::topology::effects::EventSite;

#[cfg(test)]
pub(super) fn resume_harness_inner(
    opts: &ResumeOptions,
    harness: &Harness<'_>,
) -> Result<(RunReport, RunState), TactusError> {
    let contained = crate::runner::host::contain_write_command(&mut crate::agent::proc::NoHooks)?;
    resume_harness_inner_on(
        opts,
        harness,
        &crate::runner::host::HostRunner::new(),
        &contained,
    )
}

/// The same resume, on an explicit boundary. See [`super::run_harness_on`], and
/// [`super::coordinator::run_harness_inner_on`] for why `_contained` is a
/// parameter: a resume is a write command too, and the ambient job it needs is
/// the one no facade used to establish.
pub(super) fn resume_harness_inner_on(
    opts: &ResumeOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
    _contained: &crate::runner::host::Contained,
) -> Result<(RunReport, RunState), TactusError> {
    let run_id = rundir::resolve_run_id(&opts.repo_root, &opts.run_id)?;
    let public = rundir::public_dir(&opts.repo_root, &run_id);
    let refuse = |message: String| TactusError::Resume {
        run_id: run_id.clone(),
        message,
    };
    let events_path = public.join("events.jsonl");

    // Read-only, and before either lock. §14's refusals must reach the operator
    // without a worktree lease and without a `run.lock` file behind them, and
    // the config is one of them — so the two things deciding *how* to read
    // today's config have to be read first: the schema this run was recorded
    // at, which chooses between refusing an impossible ceiling and warning
    // about one, and where the run's config lives.
    //
    // Only that. The authoritative whole-log read is below, under the locks,
    // and everything the resume actually acts on comes from there. This read
    // decides what to refuse before taking anything.
    let mut header_warnings = Vec::new();
    let header_events = events::read_all(&events_path, &mut header_warnings)?;
    let header = events::started_of(&header_events, &events_path)?.clone();
    let header_schema = events::ensure_supported_schema(&header, &header_events, &events_path)?;

    // The run knows its own plan and config; the CLI may override the config
    // but never the plan, which is frozen (§5).
    let mut run_opts = RunOptions::new(
        opts.repo_root.join(&header.plan_path),
        opts.repo_root.clone(),
    );
    run_opts.config_path = opts
        .config_path
        .clone()
        .or_else(|| header.config_path.as_ref().map(|p| opts.repo_root.join(p)));
    run_opts.pools_path = opts.pools_path.clone();
    run_opts.interaction = opts.interaction;
    run_opts.attempt_timeout = opts.attempt_timeout;
    run_opts.defer_backoff = opts.defer_backoff;
    run_opts.max_defers = opts.max_defers;
    run_opts.private_root = opts.private_root.clone();
    run_opts.wait_on_block = opts.wait_on_block;
    let wait_on_block = opts.wait_on_block;

    // This run's ceilings were fixed when it started. Today's `[engine]` keys
    // are read for the same reason today's gates are — the file is what is
    // here — but a value this engine cannot honour is a statement about some
    // future run, not an instruction to this one, so it warns rather than
    // stranding a run whose only fault is that someone edited a file it reads.
    let limits = config::EngineLimits::for_resume(header_schema);
    let validated = validate_inputs(&run_opts, limits)?;

    // The first effect of the command.
    let workspace = Workspace::open(&opts.repo_root)?;
    let worktree_git_dir = workspace.worktree_git_dir()?;
    let _worktree_lock = WorktreeLock::acquire_in(workspace.root(), &worktree_git_dir)?;

    // Claimed before anything is acted on, so two resumes cannot race each
    // other into the same branch. The lock sits beside the ops surface, which
    // is the only half of the run directory known this early: where the private
    // half went is recorded in `run_started`, which the authoritative read
    // below is about to establish.
    let _lock = RunLock::acquire(&public)?;
    let _cleanup_scope = _lock.enter_cleanup_scope();

    let mut warnings = Vec::new();
    let events = events::read_all(&events_path, &mut warnings)?;
    let started = events::started_of(&events, &events_path)?.clone();
    let effective_schema = events::ensure_supported_schema(&started, &events, &events_path)?;
    // `run_started` is the first line of an append-only log, so the read under
    // the lease must agree with the one before it about where this run's plan
    // and config live. If it does not, something rewrote history while we were
    // waiting for the lease, and the pre-lock refusals were answered about
    // files this run never named.
    if started.plan_path != header.plan_path || started.config_path != header.config_path {
        return Err(refuse(
            "this run's opening record changed while the resume was waiting for the worktree \
             lease: it now names a different plan or config. Preserve this log for recovery and \
             start a new run rather than continuing against a record that moved."
                .to_owned(),
        ));
    }
    // Adopted only now, and only against the schema the authoritative read
    // settled on: a resume that raced an appended schema upgrade must not run
    // on a reading derived from the header it saw first.
    let analysis = validated.confirm_under_lease(
        &run_opts,
        config::EngineLimits::for_resume(effective_schema),
    )?;
    let recorded_normalized_plan_digest =
        events::recorded_normalized_plan_digest(&events).map(str::to_owned);
    let frozen_plan_path = public.join("plan.normalized.json");
    let frozen_plan_bytes = fs::read(&frozen_plan_path).map_err(|source| TactusError::Io {
        path: frozen_plan_path.clone(),
        source,
    })?;
    let frozen_plan_digest = events::normalized_plan_digest(&frozen_plan_bytes);
    if let Some(recorded) = recorded_normalized_plan_digest.as_deref() {
        if frozen_plan_digest != recorded {
            return Err(refuse(format!(
                "the exact bytes at {} no longer match this run's recorded normalized-plan digest ({recorded}, now {frozen_plan_digest}). Restore the frozen snapshot or start a new run.",
                frozen_plan_path.display()
            )));
        }
    }
    if let Some(failure) = events::legacy_unsettled_failure(started.schema, &events) {
        let detail = match failure.kind {
            events::LegacyUnsettledFailureKind::MissingDecision => {
                "without its durable ladder or parking decision"
            }
            events::LegacyUnsettledFailureKind::MissingSpendParking => {
                "after raising an ApproveSpend question but before durably parking the task"
            }
        };
        return Err(refuse(format!(
            "legacy event schema {} records failed attempt {} for `{}` on rung {} {detail}. The old writer may have stopped between two appends, so resuming could repeat paid work, choose the wrong rung, or bypass required spend approval. Preserve this log for recovery and start a new run rather than guessing.",
            started.schema, failure.attempt, failure.task, failure.rung,
        )));
    }
    // Usually `run_started`'s, but a log too old to carry them there may have
    // had them established by an earlier resume instead — which is what stops
    // the re-derivation repeating, and drifting, on every resume after that.
    let recorded_gates = events::recorded_gates(&events).cloned();
    let recorded_effort_policy = events::recorded_effort_policy(&events);
    let recorded_complete_reviews = events::recorded_complete_reviews(&events).cloned();
    let recorded_reviews = events::recorded_reviews(&events).cloned();
    let recorded_chains = events::recorded_chains(&events).cloned();

    // Re-probes agents and re-reads config, exactly as a fresh run does —
    // except for the two things that are facts about *this run* rather than
    // about today's machine: who reviews it and what verifies it. Both come
    // from the record (see `preflight_with_recorded`), so a resume continues
    // the run it is resuming rather than starting a differently-judged one on
    // the same branch.
    let Preflight {
        analysis,
        caps,
        review_plan,
        review_pass_timeout,
        gates,
        gate_cmds,
        warnings: preflight_warnings,
        mode,
        notifiers,
        budgets,
    } = preflight_with_recorded(
        &run_opts,
        harness,
        runner,
        analysis,
        Recorded {
            reviews: recorded_reviews.clone(),
            gates: recorded_gates.clone(),
            legacy_review_timeout_missing: recorded_reviews
                .as_ref()
                .is_some_and(|plan| plan.pass_timeout_secs.is_none()),
            gates_from_config: started.gates_from_config,
            routing: Some(RecordedRouting {
                run_id: run_id.clone(),
                structure: started.chains.clone(),
                bindings: recorded_chains.clone(),
            }),
        },
    )?;
    if recorded_reviews.is_none() {
        warnings.push(
            "this run's log predates the review record (step 9), so who reviews was re-derived \
             from today's config rather than read from the run — earlier tasks may have been \
             judged differently"
                .to_owned(),
        );
    }
    if recorded_gates.is_none() {
        // A log from before the gate record, resumed for the first time — the
        // only case with nothing to rebuild from, since this resume writes down
        // what it settles on and the next one is ordinary.
        //
        // It still recorded gate *names*, which is not enough to rebuild the
        // gates but is enough to say something better than "anything may have
        // changed": if the names have moved, that is proof rather than
        // suspicion, and if they have not, the only undetectable edit left is a
        // command behind an unchanged name.
        let names_now: Vec<String> = gates.iter().map(|gate| gate.name.clone()).collect();
        if names_now != started.gates {
            warnings.push(format!(
                "this run's log predates the gate record, so its gates were re-derived from \
                 today's config — and the gate names have moved, so the tasks it already \
                 committed were verified differently: it recorded [{}], today resolves [{}]",
                render_names(&started.gates),
                render_names(&names_now),
            ));
        } else if !names_now.is_empty() {
            warnings.push(format!(
                "this run's log predates the gate record, so its gates were re-derived from \
                 today's config rather than rebuilt from the run. The names still match what it \
                 recorded ([{}]), but a log this old cannot show whether a command behind one of \
                 them changed",
                render_names(&names_now),
            ));
        }
        // Both empty: the run recorded no gates and none resolve today, so
        // there is nothing a command could have hidden behind. Saying "may have
        // been verified differently" here would be a false alarm on every
        // gateless run, and a warning that cries wolf on the harmless case is
        // one nobody reads on the harmful one.
    }
    let current_effort_policy = analysis.config.resolved_effort_policy();
    let effort_policy = recorded_effort_policy.unwrap_or(current_effort_policy);
    match recorded_effort_policy {
        None => warnings.push(
            "this run's log predates the effort-policy record, so implementation and review \
             effort were re-derived from today's config rather than read from the run — earlier \
             attempts may have used a different effort standard"
                .to_owned(),
        ),
        Some(recorded) if recorded != current_effort_policy => warnings.push(format!(
            "today's effort policy ({}) differs from the one this run recorded ({}). This \
             resume keeps the recorded policy so one run has one execution and review standard. \
             Start a new run to adopt today's policy.",
            render_effort_policy(current_effort_policy),
            render_effort_policy(recorded),
        )),
        Some(_) => {}
    }
    warnings.extend(preflight_warnings);

    // The plan is frozen. A different hash means the file moved under the run,
    // so every task index in the log — which is what `Progress` is keyed by —
    // may now mean a different task.
    if analysis.plan.source.hash != started.plan_hash {
        return Err(refuse(format!(
            "the plan at {} has changed since this run froze it (recorded {}, now {}). Task \
             progress is recorded per task, so replaying it against a different plan would \
             attribute work to the wrong tasks. Restore the plan, or start a new run.",
            run_opts.plan_path.display(),
            started.plan_hash,
            analysis.plan.source.hash
        )));
    }
    let canonical_plan_bytes = normalized_plan_bytes(&analysis.plan, &frozen_plan_path)?;
    let canonical_plan_digest = events::normalized_plan_digest(&canonical_plan_bytes);
    let established_normalized_plan_digest = if let Some(recorded) =
        recorded_normalized_plan_digest.as_deref()
    {
        if canonical_plan_digest != recorded {
            return Err(refuse(format!(
                "the validated source plan now normalizes to digest {canonical_plan_digest}, but this run recorded {recorded}. Restore the source plan semantics or start a new run."
            )));
        }
        None
    } else {
        if canonical_plan_bytes != frozen_plan_bytes {
            return Err(refuse(format!(
                "legacy frozen plan {} does not exactly match the canonical serialization of the validated source plan. Refusing to bless a mutable legacy snapshot during the schema-3 upgrade; restore it or start a new run.",
                frozen_plan_path.display()
            )));
        }
        Some(frozen_plan_digest.clone())
    };

    let task_ids: Vec<String> = analysis
        .plan
        .tasks
        .iter()
        .map(|task| task.id.to_string())
        .collect();
    let replayed = events::replay(events, task_ids, &events_path)?;

    match replayed.state.finished.as_ref().map(|f| &f.outcome) {
        Some(events::RunOutcome::Complete) => {
            return Err(refuse(
                "this run already completed; there is nothing left to continue".to_owned(),
            ));
        }
        Some(events::RunOutcome::Halted) => {
            return Err(refuse(format!(
                "this run halted at `{}` under `on_task_failure = \"halt\"`. Nothing can run \
                 while it is halted — fix what failed and start a new run.",
                replayed.state.halted_at.as_deref().unwrap_or("?")
            )));
        }
        // Ended parked, at a budget, or never ended at all — all three are
        // exactly what resume is for. A budget stop in particular is *designed*
        // to be resumable: `--budget` re-derives the ceiling (see
        // `ResumeOptions::budget_usd`), so raising it and continuing is one
        // command rather than a new run and a lost branch.
        Some(events::RunOutcome::Parked | events::RunOutcome::BudgetExceeded) | None => {}
    }

    // `question_answered`, its design-defect record, and a declined task's
    // failure predate atomic parking and are three durable appends. Preserve
    // every crash prefix so a closed question can never strand its task in
    // AwaitingInput with no legal way to answer it again.
    let defect_questions: BTreeSet<QuestionId> = replayed
        .events
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::DesignDefect { data } => Some(data.question.clone()),
            _ => None,
        })
        .collect();
    let missing_answer_defects: Vec<_> = replayed
        .state
        .questions
        .iter()
        .filter_map(|record| {
            let answer = record.answer.as_ref()?;
            (!defect_questions.contains(&record.question.id)).then(|| {
                (
                    record.question.id.clone(),
                    util::head(record.question.context.trim(), 600),
                    match answer {
                        Answer::Answered { text } => text.clone(),
                        _ => "declined".to_owned(),
                    },
                )
            })
        })
        .collect();
    let decline_halt_policies: BTreeMap<_, _> = replayed
        .events
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::QuestionAnswered { data } if data.answer == Answer::Declined => {
                Some((data.question.clone(), data.decline_halts_run))
            }
            _ => None,
        })
        .collect();
    let mut declined_questions = Vec::new();
    for record in replayed
        .state
        .questions
        .iter()
        .filter(|record| record.answer.as_ref() == Some(&Answer::Declined))
    {
        let affected: Vec<_> = record
            .question
            .affected_tasks
            .iter()
            .filter(|task_id| {
                replayed
                    .state
                    .index_of(task_id.as_str())
                    .is_some_and(|index| {
                        matches!(
                            &replayed.state.states[index],
                            TaskState::AwaitingInput(open) if open == &record.question.id
                        )
                    })
            })
            .cloned()
            .collect();
        if affected.is_empty() {
            continue;
        }
        let Some(halts_run) = decline_halt_policies
            .get(&record.question.id)
            .copied()
            .flatten()
        else {
            return Err(refuse(format!(
                "legacy declined answer {} stopped before settling its affected task, but the log does not record the contemporaneous on_task_failure policy. Today's config cannot safely decide an old answer; preserve this log for recovery and start a new run.",
                record.question.id
            )));
        };
        declined_questions.push((record.question.id.clone(), affected, halts_run));
    }

    // Resolve the recorded private root before touching the worktree so a
    // killed engine's durable snapshot registrations are reclaimed first.
    let paths = match &opts.private_root {
        Some(root) => RunPaths::with_private_root(&opts.repo_root, &run_id, root),
        None => RunPaths::from_parts(public.clone(), PathBuf::from(&started.private_dir)),
    };
    paths.create()?;

    let reclaimed = workspace.reclaim_gate_workspaces(&paths.gate_worktrees())?;
    if reclaimed > 0 {
        warnings.push(format!(
            "reclaimed {reclaimed} gate/review snapshot worktree(s) left by the interrupted run"
        ));
    }
    workspace.ensure_execution_prerequisites()?;
    workspace.ensure_run_exclusions()?;
    if !workspace.branch_exists(&started.branch)? {
        return Err(refuse(format!(
            "the run branch `{}` no longer exists. Its commits are what this run's record \
             refers to; without it there is nothing to continue onto.",
            started.branch
        )));
    }
    if workspace.current_branch()? != started.branch {
        if !workspace.is_clean()? {
            return Err(refuse(format!(
                "you have uncommitted changes and are not on `{}`. Commit or stash them, then \
                 resume — switching branches over them would lose work that is not this run's \
                 to discard.",
                started.branch
            )));
        }
        workspace.switch_branch(&started.branch)?;
    }

    // §15's check, before anything is discarded: if HEAD moved, refusing has
    // to leave the operator's tree exactly as they left it.
    let recorded_head = last_committed_sha(&replayed.events).unwrap_or(started.base_sha.clone());
    let mut head = workspace.head_sha_full()?;

    // A schema-3 successful settlement durably names the exact commit object
    // that passed review. Recovery may publish that object from its pin, or
    // finish recording it when HEAD already advanced. Subject/parent matching
    // is intentionally insufficient: another commit can share both while
    // containing arbitrary bytes.
    let mut adopted = None;
    if let Some((task, message, prepared)) = unrecorded_commit(&replayed, &analysis.plan) {
        let Some(prepared) = prepared else {
            if head != recorded_head {
                return Err(refuse(format!(
                    "`{}` is at {head}, but the successful legacy settlement for `{task}` did \
                     not record an exact prepared commit. Refusing to adopt a commit by subject \
                     alone; move the branch back to {recorded_head}, or start a new run.",
                    started.branch
                )));
            }
            return Err(refuse(format!(
                "the successful legacy settlement for `{task}` has no exact prepared commit. \
                 It cannot be replayed safely; preserve this log for recovery and start a new run."
            )));
        };
        if prepared.parent_sha != recorded_head
            || prepared.message != message
            || !workspace.prepared_commit_matches(&prepared)?
        {
            return Err(refuse(format!(
                "the recorded prepared commit for `{task}` does not match its task, parent, or \
                 Git object. Refusing to publish or adopt it; preserve the log for recovery."
            )));
        }
        let observed_branch_ref = workspace.current_branch_ref()?;
        if observed_branch_ref != prepared.branch_ref {
            return Err(refuse(format!(
                "HEAD is on `{observed_branch_ref}`, not the prepared commit's recorded branch \
                 `{}`; refusing prepared recovery.",
                prepared.branch_ref
            )));
        }

        if head == prepared.parent_sha {
            if workspace.prepared_pin_target(&prepared.pin_ref)?.as_deref()
                != Some(prepared.commit_sha.as_str())
            {
                return Err(refuse(format!(
                    "the recorded prepared commit for `{task}` is not pinned by `{}`. Refusing \
                     to publish an unprotected or substituted object; preserve the log for recovery.",
                    prepared.pin_ref
                )));
            }
            workspace.advance_prepared_commit(&prepared.branch_ref, &prepared)?;
            head = prepared.commit_sha.clone();
            warnings.push(format!(
                "published prepared commit {head} for `{task}` after the run stopped between \
                 settlement and the branch update"
            ));
            adopted = Some((task, message));
        } else if head == prepared.commit_sha {
            match workspace.prepared_pin_target(&prepared.pin_ref)? {
                Some(target) if target == prepared.commit_sha => {
                    workspace.remove_prepared_pin(&prepared)?;
                }
                Some(target) => {
                    return Err(refuse(format!(
                        "prepared ref `{}` points at {target}, not the recorded commit {}; \
                         refusing to delete or adopt a substituted object.",
                        prepared.pin_ref, prepared.commit_sha
                    )));
                }
                None => {}
            }
            warnings.push(format!(
                "adopted commit {head} as `{task}` from its exact prepared identity after the \
                 run stopped before recording it"
            ));
            adopted = Some((task, message));
        }
    }

    if adopted.is_none() && head != recorded_head {
        return Err(refuse(format!(
            "`{}` is at {head}, but this run's record ends at {recorded_head}. Something \
             committed, reset, or rebased the branch after the run stopped, so replaying the \
             log would describe work that is no longer what is on the branch. Move the branch \
             back to {recorded_head}, or start a new run.",
            started.branch
        )));
    }

    // A pin with no successful settlement is from a crash between preparing
    // the object and appending AttemptFinished. It has no authority to move
    // HEAD and is removed with an expected-old-value CAS before retrying.
    for interrupted in replayed.state.interrupted_attempts() {
        let task_index = replayed
            .state
            .index_of(&interrupted.task)
            .expect("an interrupted task belongs to the replayed plan");
        let pin_ref = prepared_pin_ref(&run_id, task_index, interrupted.flight.attempt);
        if workspace.prepared_pin_target(&pin_ref)?.is_some() {
            workspace.remove_orphan_prepared_pin(&pin_ref)?;
            warnings.push(format!(
                "removed orphan prepared commit pin `{pin_ref}` for interrupted attempt {}",
                interrupted.flight.attempt
            ));
        }
    }

    // Crash residue: a dead agent's half-written edits. §14 rolls a failed
    // attempt back to the last commit, and an attempt that never reported is
    // no different — the session that would have explained these edits is
    // gone, so nothing can verify them.
    let discarded = workspace.uncommitted_summary()?;
    if !discarded.is_empty() {
        warnings.push(format!(
            "discarded {} uncommitted path(s) left by the interrupted run: {}",
            discarded.len(),
            discarded.join(", ")
        ));
        workspace.discard_uncommitted()?;
    }

    // Where the agent-authored half lives is a fact about the run, not about
    // today's defaults. A resume under a different HOME — a service account, a
    // container, the no-home fallback — would otherwise scatter the rest of
    // this run's transcripts into a second private root while `status` went on
    // pointing at the first. An explicit override still wins, for a private
    // root that has genuinely moved.
    let sleeper = harness.sleeper.unwrap_or(&RealSleeper);
    let default_answers = interaction::answers_for(
        mode,
        paths.answers(),
        wait_on_block.unwrap_or(analysis.config.wait_on_block),
        sleeper,
    );
    // §13's ground-truth signals, folded from this run's own log before its
    // state is moved into the scheduler — what the earlier process learned
    // about the pools, which a resumed run's snapshot must not forget.
    let prior_signals = capacity::observe(&replayed.events).exhausted;
    let log = EventLog::open(EventSite::LegacyOpenLog, &paths.events(), &mut warnings)?;
    let established_reviews = recorded_complete_reviews
        .is_none()
        .then(|| review_plan.clone());
    let mut run = Run {
        state: replayed.state,
        analysis: &analysis,
        workspace: &workspace,
        paths,
        log,
        log_hooks: Box::new(crate::events::log::NoEventHooks),
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
        // Re-derived from today's config and flags, deliberately (see
        // `ResumeOptions::budget_usd`): raising the ceiling and resuming is the
        // one-command recovery a budget stop is supposed to have.
        budgets,
        ask_before: analysis.config.ask_before,
        run_id,
        branch: started.branch.clone(),
        warnings,
        unanswerable: Vec::new(),
        // Seeded from the log so a resume neither re-announces an outage the
        // previous process recorded nor swallows a fresh one.
        exhausted_pools: prior_signals.keys().cloned().collect(),
        #[cfg(test)]
        after_candidate_capture: None,
    };
    // The `task_committed` the dead process never got to must be the first
    // append after its successful settlement. Schema 3 treats that adjacency
    // as part of the exact prepared-commit binding, so unrelated legacy answer
    // repairs cannot interpose and poison the log.
    if let Some((task, message)) = adopted {
        run.emit(EventBody::TaskCommitted {
            task,
            data: events::TaskCommitted {
                sha: head.clone(),
                message,
            },
        })?;
    }
    // A legacy run cannot have its opening event rewritten without violating
    // append-only history. This no-op event is the current downgrade boundary:
    // schema-1 binaries do not know its tag, while schema-2 binaries reject a
    // transition to schema 3 before applying their old partial-review contract.
    if effective_schema < events::SCHEMA_VERSION {
        run.emit(EventBody::RunSchemaUpgraded {
            data: events::RunSchemaUpgraded {
                from: effective_schema,
                to: events::SCHEMA_VERSION,
            },
        })?;
    }
    for (question, context, answer) in missing_answer_defects {
        run.emit(EventBody::DesignDefect {
            data: events::DesignDefect {
                question,
                context,
                answer,
            },
        })?;
    }
    for (question, affected, halts_run) in declined_questions {
        for task_id in affected {
            let Some(index) = run.state.index_of(task_id.as_str()) else {
                continue;
            };
            if !matches!(&run.state.states[index], TaskState::AwaitingInput(open) if open == &question)
            {
                continue;
            }
            let reason = format!(
                "declined at the human rung: {}",
                last_reason(&run.state.progress[index])
            );
            run.fail_task_with_policy(index, FailureKind::Declined, reason, halts_run)?;
        }
    }
    // A crash between `question_answered` and the payload rewrite leaves a
    // file that still reads as open, which `tactus answer` would accept a
    // second answer against — one no engine can ever ingest, because the
    // question is already closed in the log. The log is what is authoritative;
    // make the payloads agree with it again.
    for record in &run.state.questions {
        interaction::write_question(&run.paths.questions(), record)?;
    }

    // Write the `attempt_finished` the dead process never got to.
    //
    // Recorded rather than settled in memory, because a settlement only a
    // reader performs is lost the moment someone else replays the log: the
    // ledger line vanishes and, worse, the rung's refunded allowance vanishes
    // with it, so a later resume would think the attempt had been spent.
    let interrupted = run.state.interrupted_attempts();
    for attempt in &interrupted {
        run.emit(attempt.event())?;
    }

    // Applying this is what drops every session and wakes deferred work — the
    // §14 pairing, enforced by the same fold a replay uses rather than by this
    // function remembering to do it.
    run.emit(EventBody::RunResumed {
        data: events::RunResumed {
            head_sha: head,
            interrupted_attempts: u32::try_from(interrupted.len()).unwrap_or(u32::MAX),
            discarded,
            // Only when this resume is the one that had to settle the question.
            // Where the log already answers it, re-stating the answer would put
            // the same fact in two places that a later change could pull apart.
            gates: recorded_gates.is_none().then(|| gates.clone()),
            effort_policy: recorded_effort_policy.is_none().then_some(effort_policy),
            reviews: established_reviews,
            chains: recorded_chains
                .is_none()
                .then(|| chain_summaries(&analysis)),
            normalized_plan_digest: established_normalized_plan_digest,
        },
    })?;
    // §14 takes a capacity snapshot at pre-flight, and §15 makes a resume
    // re-establish everything a fresh run establishes. A resume that skipped it
    // would leave the log claiming the pools looked, hours later, exactly as
    // they did when the run began.
    run.emit_capacity_snapshot(&prior_signals)?;
    let report = run.drain_and_report()?;
    Ok((report, run.state.clone()))
}

/// A gate name list, for a message.
fn render_names(names: &[String]) -> String {
    names.join(", ")
}

fn render_effort_policy(policy: ResolvedEffortPolicy) -> String {
    format!(
        "implementation small={}, mid={}, frontier={}; review={}",
        policy.small, policy.mid, policy.frontier, policy.review
    )
}

/// The sha the run's record ends at — what HEAD must still be.
fn last_committed_sha(events: &[events::Event]) -> Option<String> {
    events.iter().rev().find_map(|event| match &event.body {
        EventBody::TaskCommitted { data, .. } => Some(data.sha.clone()),
        _ => None,
    })
}

/// The task an interrupted run committed without living long enough to record.
///
/// The shape is narrow, which is what makes it safe to act on: the log must
/// *end* at an attempt that passed, for a task that never reached `Done`. No
/// other event can follow, because the process that would have written one is
/// the process that died. Returns the task and the message the engine would
/// have used, so the caller can confirm the commit really is the one it is
/// about to adopt rather than trusting the log's shape alone.
fn unrecorded_commit(
    replayed: &events::Replay,
    plan: &Plan,
) -> Option<(String, String, Option<events::PreparedCommit>)> {
    let EventBody::AttemptFinished {
        task,
        data,
        prepared_commit,
        ..
    } = &replayed.events.last()?.body
    else {
        return None;
    };
    if data.failure.is_some() {
        return None;
    }
    let index = replayed.state.index_of(task)?;
    if replayed.state.states[index] != TaskState::Pending {
        return None;
    }
    let task = plan.tasks.get(index)?;
    Some((
        task.id.to_string(),
        format!("[tactus] {}: {}", task.id, task.title),
        prepared_commit.as_deref().cloned(),
    ))
}
