// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::agent::{AgentAdapter, TaskRun, proc};
use crate::error::TactusError;
use crate::events::{self, Feedback};
use crate::gates::{self, ShellGate};
use crate::ir::{Outcome, OutcomeStatus, Task, TaskKind, WorkerProfile};
use crate::ladder::{AttemptFailure, FailureKind};
use crate::review;
use crate::rundir::RunPaths;
use crate::runner::invocation::{AttemptRole, InvocationId};
use crate::runner::{AgentId, Runner};
use crate::topology::events::AttemptNumber;
use crate::topology::registry::TaskKey;
use crate::util;
use crate::workspace::Workspace;

#[cfg(test)]
use super::options::AfterCandidateCapture;

/// Most recent feedback entries carried into an escalated prompt. Older
/// failures are summarized; the newest keeps its full log tail.
const MAX_FEEDBACK_ENTRIES: usize = 6;

/// §12: how a worker flags a decision it should not make alone. The prompt
/// teaches this marker; nothing else in the engine parses agent prose.
pub(super) const QUESTION_MARKER: &str = "TACTUS-QUESTION:";

/// A `WorkerProfile.pool` as the log records it: `None` rather than `""` when
/// no pool is configured, so a reader can tell "no pools file" from "a pool
/// whose name is empty" — and so a fold never attributes spend to `""`.
pub(super) fn pool_option(pool: &str) -> Option<String> {
    (!pool.is_empty()).then(|| pool.to_owned())
}

/// Everything one attempt needs, so the ladder can loop over (rung, attempt)
/// without re-deriving any of it.
pub(super) struct AttemptCx<'a> {
    pub(super) task: &'a Task,
    pub(super) profile: WorkerProfile,
    pub(super) adapter: &'a dyn AgentAdapter,
    /// Where every process of this attempt executes (DESIGN.md:118). The host
    /// runner today; PR6 swaps in the container one behind the same `dyn`.
    pub(super) runner: &'a dyn Runner,
    /// This task's position in the plan, which is the legacy engine's own
    /// scope for [`InvocationId`]. See [`AttemptCx::invocation`].
    pub(super) task_index: u32,
    pub(super) attempt: u32,
    /// Collision-free file stem for this task's run artifacts.
    pub(super) stem: String,
    pub(super) paths: &'a RunPaths,
    pub(super) gates: &'a [ShellGate],
    pub(super) gate_cmds: &'a [String],
    /// The ordered review passes for this task (§11.3). Empty only when review
    /// is switched off explicitly.
    pub(super) reviewers: Vec<Reviewer<'a>>,
    pub(super) timeout: Duration,
    /// Independent allowance for every reviewer in `reviewers`; one pass may
    /// use it across its initial verdict and one format-only re-ask.
    pub(super) review_pass_timeout: Duration,
    /// `None` on the first attempt.
    pub(super) retry: Option<RetryBrief>,
    /// Answers the operator has given about this task (§12), in the order they
    /// arrived. The worker gets these as instructions; so must the judge.
    pub(super) decisions: Vec<String>,
    #[cfg(test)]
    pub(super) after_candidate_capture: Option<AfterCandidateCapture>,
}

impl AttemptCx<'_> {
    /// The identity of one process of this attempt.
    ///
    /// The contract's `invariants_introduced[1]`: "legacy engine assigns
    /// **legacy-scoped** values". The scope is
    /// [`crate::runner::invocation::LEGACY_GENERATION`] — generation 0, which
    /// [`InvocationId::legacy_attempt`] supplies — because the legacy engine
    /// has no generations: it never re-dispatches a task from a fresh worktree,
    /// so there is no second generation for a value to sit in. A legacy run is
    /// schema-1..3 and a generation-bearing run is schema-4, and INV-23 forbids
    /// a run changing schema between epochs, so the two sets never share a
    /// ledger and generation 0 is a scope rather than a coincidence.
    ///
    /// The key is the task's **position in the plan**, not a topology
    /// `TaskKey`: the legacy engine has no task registry to draw one from, and
    /// what the identity has to be is unique per process, which a dense
    /// position is. `(position, attempt, role, ordinal)` is unique because a
    /// position names one task, `attempt` increments per attempt of it
    /// (INV-20's "changes with every attempt"), `role` distinguishes the
    /// worker from gate `n` and review pass `n`, and nothing inside one
    /// attempt runs a given role twice — so every ordinal here is 0, and a
    /// re-dispatch that did run one twice would need a second ordinal rather
    /// than a reused identity.
    fn invocation(&self, role: AttemptRole) -> InvocationId {
        InvocationId::legacy_attempt(
            TaskKey(self.task_index),
            AttemptNumber(self.attempt),
            role,
            0,
        )
    }
}

/// What the retry prompt needs to know (§11.4).
pub(super) struct RetryBrief {
    /// The session carries the earlier conversation, so the prompt is terse.
    pub(super) resumed: bool,
    /// Every failure so far, oldest first.
    pub(super) feedback: Vec<Feedback>,
}

/// One read-only worker judging an attempt (§11.2). The list is empty only
/// when the user explicitly set `review = { enabled = false }`; a pass that
/// cannot be resolved is a hard error, never a silent downgrade.
#[derive(Clone)]
pub(super) struct Reviewer<'a> {
    pub(super) adapter: &'a dyn AgentAdapter,
    pub(super) profile: WorkerProfile,
    pub(super) lens: review::Lens,
    pub(super) preflight_cli_version: Option<String>,
}

pub(super) struct AttemptResult {
    pub(super) outcome: Outcome,
    pub(super) failure: Option<AttemptFailure>,
    /// Immutable git identities captured with the diff before any gate or
    /// reviewer ran. A successful commit is prepared from these exact objects.
    pub(super) candidate_branch_ref: String,
    pub(super) candidate_parent: String,
    pub(super) candidate_tree: String,
    /// The passes that actually ran, in order — empty when the cheap checks
    /// failed first and no review happened. Derived from the reviews having
    /// happened rather than from passes being configured, so the ledger never
    /// credits a model with work it did not do (§13).
    pub(super) reviews: Vec<events::ReviewRecord>,
}

/// Run one attempt and verify it, without deciding what happens next: the
/// caller owns commit, rollback, retry, and escalation (§11/§14).
pub(super) fn run_attempt(
    cx: &AttemptCx<'_>,
    workspace: &Workspace,
    resume_session: Option<String>,
) -> Result<AttemptResult, TactusError> {
    let settings_path = cx.adapter.materialize_permissions(
        &cx.profile,
        cx.gate_cmds,
        &cx.paths.settings(),
        &format!("{}-{}", cx.stem, cx.attempt),
    )?;

    let task_run = TaskRun {
        prompt: materialize_prompt(
            cx.task,
            cx.gate_cmds,
            &cx.paths.artifacts(),
            cx.retry.as_ref(),
        ),
        profile: cx.profile.clone(),
        workspace: workspace.root().to_path_buf(),
        gate_cmds: cx.gate_cmds.to_vec(),
        resume_session,
        settings_path,
    };
    // The adapter says what to run; the runner says where. `ExecutionRole::
    // Implement` with the bound agent is what makes this process slotted
    // (R3) and what tells `host-v1` to supply that agent's credential
    // location — both properties of the role, not of this call site.
    let command = cx
        .adapter
        .build(&task_run)?
        .stdin(cx.adapter.stdin_payload(&task_run).as_bytes().to_vec());
    let output = cx.runner.run(&crate::runner::worker_request(
        command,
        task_run.workspace.clone(),
        AgentId::new(cx.adapter.id()),
        cx.timeout,
        cx.invocation(AttemptRole::Worker),
    ))?;

    let transcripts = cx.paths.transcripts();
    let transcript_path = transcripts.join(format!("{}-{}.json", cx.stem, cx.attempt));
    util::write_text(&transcript_path, &output.stdout)?;
    if !output.stderr.trim().is_empty() {
        util::write_text(
            &transcripts.join(format!("{}-{}.stderr.log", cx.stem, cx.attempt)),
            &output.stderr,
        )?;
    }

    let mut outcome: Outcome = cx.adapter.parse(&output)?;
    let candidate = workspace.capture_candidate()?;
    #[cfg(test)]
    if let Some(after_capture) = cx.after_candidate_capture {
        after_capture(workspace, &candidate)?;
    }
    outcome.diff = candidate.diff;
    outcome.transcript_path = transcript_path;

    // Verification ladder (§11): outcome sanity → cheap static provenance →
    // gates → review. Cheapest and most objective first.
    let mut failure = evaluate_outcome(&outcome, &output);
    if failure.is_none() {
        if let Some(error) = review::complete_diff_error(&outcome.diff) {
            if matches!(error, review::CompleteDiffError::Opaque) || !cx.reviewers.is_empty() {
                let kind = match error {
                    review::CompleteDiffError::Opaque => FailureKind::ReviewInputOpaque,
                    review::CompleteDiffError::TooLarge { .. } => FailureKind::ReviewInputTooLarge,
                };
                failure = Some(AttemptFailure::new(kind, error.to_string()).from_reviewer());
            }
        }
    }
    if failure.is_none() && cx.task.kind == TaskKind::Test && !gates::diff_adds_tests(&outcome.diff)
    {
        failure = Some(
            AttemptFailure::new(
                FailureKind::TestProvenance,
                "test provenance: this Test task adds no test code — a Test task that changes no \
                 tests proves nothing",
            )
            .with_feedback(
                "The diff contains no test code. Add tests that would fail without your change."
                    .to_owned(),
            ),
        );
    }
    if failure.is_none() {
        if let Some(problem) = workspace.review_input_problem_for_tree(&candidate.tree_oid)? {
            failure =
                Some(AttemptFailure::new(FailureKind::ReviewInputOpaque, problem).from_reviewer());
        }
    }
    if failure.is_none() && !cx.gates.is_empty() {
        let gate_workspace = workspace.gate_snapshot_for_candidate_in_store(
            &candidate.parent_oid,
            &candidate.tree_oid,
            &cx.paths.gate_worktrees(),
        )?;
        if let Some(gate_failure) = gates::run_all(
            cx.gates,
            cx.runner,
            &|index| cx.invocation(AttemptRole::Gate(index)),
            gate_workspace.workspace(),
            &cx.paths.gates(),
            &cx.stem,
            cx.attempt,
        )? {
            failure = Some(
                AttemptFailure::new(
                    FailureKind::GateFailed,
                    format!(
                        "gate `{}` failed: {}",
                        gate_failure.gate, gate_failure.summary
                    ),
                )
                .with_feedback(gate_failure.log_tail),
            );
        }
    }

    // §11.2: gates are objective but shallow — a strong reviewer judges the
    // diff against the acceptance criteria only once the cheap checks pass.
    // §11.3: on blast-radius paths a second reviewer from another model family
    // judges the same diff, and both must pass.
    //
    // Passes short-circuit, like gates do (§11.1): once one has said no, a
    // second opinion on the same diff changes nothing about what happens next
    // and costs another frontier invocation to learn it.
    let mut reviews = Vec::new();
    if failure.is_none() && !cx.reviewers.is_empty() {
        let artifacts = load_artifacts(&cx.paths.artifacts(), cx.task);
        // Like gates, reviewers may inspect repository context beyond the
        // supplied diff. Give them the exact staged candidate, never ignored
        // worker inputs or residue from the authoritative workspace.
        let review_workspace = workspace.gate_snapshot_for_candidate_in_store(
            &candidate.parent_oid,
            &candidate.tree_oid,
            &cx.paths.gate_worktrees(),
        )?;
        for (pass, reviewer) in cx.reviewers.iter().enumerate() {
            let pass = u32::try_from(pass).unwrap_or(u32::MAX);
            let review = review::run_review(
                &review::ReviewCx {
                    adapter: reviewer.adapter,
                    profile: reviewer.profile.clone(),
                    lens: reviewer.lens,
                    task: cx.task,
                    diff: &outcome.diff,
                    artifacts: &artifacts,
                    decisions: &cx.decisions,
                    workspace: review_workspace.workspace().root(),
                    settings_dir: &cx.paths.settings(),
                    reviews_dir: &cx.paths.reviews(),
                    stem: format!("{}-{}", cx.stem, cx.attempt),
                    timeout: cx.review_pass_timeout,
                },
                cx.runner,
                // `pass` is which reviewer in this attempt's ordered list, so
                // the two members the packet gives a review — `review_pass(n)`
                // and `review_reask(n)` — index the same `n`.
                &review::ReviewInvocations {
                    pass: cx.invocation(AttemptRole::ReviewPass(pass)),
                    reask: cx.invocation(AttemptRole::ReviewReask(pass)),
                },
            )?;
            let cost_usd = review.cost_usd;
            // Read before the result is consumed: a judge that never ran is not
            // a judge that said no, and the ledger has to show which happened.
            let unavailable = matches!(review.result, review::ReviewResult::Unavailable { .. });
            failure = review_failure(review.result);
            reviews.push(events::ReviewRecord {
                pass: reviewer.lens.name().to_owned(),
                agent: reviewer.profile.agent.clone(),
                model: reviewer.profile.model.clone(),
                adapter: Some(reviewer.adapter.id().to_owned()),
                preflight_cli_version: reviewer.preflight_cli_version.clone(),
                effort: reviewer.profile.effort,
                pool: pool_option(&reviewer.profile.pool),
                cost_usd,
                outcome: match (unavailable, failure.is_none()) {
                    (true, _) => events::ReviewPassOutcome::Unavailable,
                    (false, true) => events::ReviewPassOutcome::Passed,
                    (false, false) => events::ReviewPassOutcome::Failed,
                },
            });
            if failure.is_some() {
                break;
            }
        }
    }

    Ok(AttemptResult {
        outcome,
        failure,
        candidate_branch_ref: candidate.branch_ref,
        candidate_parent: candidate.parent_oid,
        candidate_tree: candidate.tree_oid,
        reviews,
    })
}

/// Turn a review result into an attempt failure, or `None` if it passed.
pub(super) fn review_failure(result: review::ReviewResult) -> Option<AttemptFailure> {
    let verdict = match result {
        // The judge could not run. That is an environment problem, not a
        // rejection of the code: it is attributed to the reviewer so the
        // ladder defers instead of blaming the implementer.
        review::ReviewResult::Unavailable { status, detail } => {
            let kind = match status {
                OutcomeStatus::RateLimited => FailureKind::RateLimited,
                OutcomeStatus::Timeout => FailureKind::Timeout,
                _ => FailureKind::ReviewUnavailable,
            };
            return Some(
                AttemptFailure::new(
                    kind,
                    format!("reviewer unavailable: {}", util::head(&detail, 400)),
                )
                .from_reviewer(),
            );
        }
        review::ReviewResult::Judged(verdict) => verdict,
    };

    // §12: the reviewer declined to judge and asked for a person. That is not
    // a rejection of the code, so it must not spend an attempt or escalate —
    // it parks the task and asks.
    if verdict.needs_human {
        let reasons = if verdict.reasons.is_empty() {
            "the reviewer asked for a human decision but gave no reason".to_owned()
        } else {
            verdict.reasons.join("; ")
        };
        return Some(
            AttemptFailure::new(
                FailureKind::NeedsHuman,
                format!("reviewer asked for a human decision: {reasons}"),
            )
            .from_reviewer(),
        );
    }

    // A pass carrying required changes contradicts itself, and the engine is
    // about to commit on the strength of it — fail closed and say why rather
    // than discard the blockers the reviewer took the trouble to write.
    let contradictory = verdict.pass && !verdict.required_changes.is_empty();
    if verdict.pass && !contradictory {
        return None;
    }
    let summary = if contradictory {
        format!(
            "reviewer passed the change but still required: {}",
            verdict.required_changes.join("; ")
        )
    } else if verdict.reasons.is_empty() {
        "no reasons given".to_owned()
    } else {
        verdict.reasons.join("; ")
    };
    // required_changes is what the retry gets back verbatim (§11.4).
    let feedback = if verdict.required_changes.is_empty() {
        summary.clone()
    } else {
        verdict
            .required_changes
            .iter()
            .map(|c| format!("- {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    Some(
        AttemptFailure::new(
            FailureKind::ReviewFailed,
            // Head, not tail: the reviewer's first reason is its primary
            // finding, and that is what has to reach the user.
            format!("review failed: {}", util::head(&summary, 400)),
        )
        .with_feedback(feedback),
    )
}

/// Artifacts this task should be judged against: its declared inputs, plus
/// the conventions brief whenever one exists (§11.2 injects it into every
/// downstream prompt).
fn load_artifacts(artifacts_dir: &Path, task: &Task) -> Vec<(String, String)> {
    let mut wanted: Vec<String> = vec![CONVENTIONS_BRIEF.to_owned()];
    wanted.extend(task.artifacts_in.iter().map(|id| id.as_str().to_owned()));
    // A task's own outputs are not evidence for judging it: the reviewer
    // would be validating the change against a standard the same attempt just
    // wrote. Declared inputs and the brief only.
    let produced: Vec<&str> = task.artifacts_out.iter().map(|id| id.as_str()).collect();
    let mut seen: Vec<String> = Vec::new();
    wanted
        .into_iter()
        .filter(|id| !produced.contains(&id.as_str()))
        .filter(|id| {
            let fresh = !seen.contains(id);
            if fresh {
                seen.push(id.clone());
            }
            fresh
        })
        .filter_map(|id| {
            let content = fs::read_to_string(artifact_path(artifacts_dir, &id)).ok()?;
            (!content.trim().is_empty()).then_some((id, content))
        })
        .collect()
}

const CONVENTIONS_BRIEF: &str = "conventions-brief";

/// Outcome-level failure reasons, before gates get a say.
pub(super) fn evaluate_outcome(
    outcome: &Outcome,
    output: &proc::ProcessOutput,
) -> Option<AttemptFailure> {
    let detail = || {
        outcome
            .detail
            .clone()
            .filter(|d| !d.trim().is_empty())
            .unwrap_or_else(|| {
                let stderr = util::tail(&output.stderr, 400);
                if stderr.is_empty() {
                    "no diagnostic output; see the transcript".to_owned()
                } else {
                    stderr
                }
            })
    };
    match outcome.status {
        // §12: the marker is honoured only on a run that actually completed.
        // `detail` carries the agent's partial output on every failure path,
        // and the prompt puts the marker string in front of the agent on every
        // fresh attempt — so scanning before the status match let a timed-out
        // or rate-limited attempt reclassify itself as a question purely by
        // quoting its own instructions back. That silently defeated "a rate
        // limit defers rather than burning an attempt" (§19), which is most of
        // the point of dispatching on `FailureKind` at all.
        OutcomeStatus::Completed => {
            // An agent that stopped to ask has not failed at anything —
            // punishing it for the empty diff its own question explains would
            // teach it never to ask, so this precedes the evidence rules.
            if let Some(question) = worker_question(outcome.detail.as_deref()) {
                return Some(AttemptFailure::new(FailureKind::NeedsHuman, question));
            }
            if !outcome.diff.trim().is_empty() {
                return None;
            }
            // §11 evidence axis: an empty diff can never pass.
            Some(
                AttemptFailure::new(
                    FailureKind::EmptyDiff,
                    "agent reported success but the diff is empty — \"done\" claims require \
                     changed code",
                )
                .with_feedback(
                    "You reported the task complete, but the repository is unchanged. Either make \
                     the change the task asks for, or explain what blocks it using the \
                     TACTUS-QUESTION marker."
                        .to_owned(),
                ),
            )
        }
        OutcomeStatus::AgentError => Some(
            AttemptFailure::new(
                FailureKind::AgentError,
                format!("agent error (exit {:?}): {}", output.code, detail()),
            )
            .with_feedback(detail()),
        ),
        OutcomeStatus::Timeout => Some(
            AttemptFailure::new(
                FailureKind::Timeout,
                "attempt hit the wall-clock timeout",
            )
            // §19: the feedback is the transcript tail. Without it the retry
            // starts blind on a task already known to run long.
            .with_feedback(format!(
                "Your previous attempt was cut off at its time limit. Work in smaller steps and \
                 finish the highest-value change first. Its last output was:\n{}",
                util::tail(&outcome.detail.clone().unwrap_or_default(), 2000)
            )),
        ),
        OutcomeStatus::RateLimited => Some(AttemptFailure::new(
            FailureKind::RateLimited,
            format!("pool rate-limited: {}", detail()),
        )),
    }
}

/// §12: a worker may flag a decision it should not make alone. Everything from
/// the marker onward is taken, so a multi-line question survives.
///
/// The LAST marker wins, matching the prompt's "end your message with it" and
/// `review.rs`'s rule for verdicts: models restate an instruction before acting
/// on it, so an earlier occurrence is an echo, not the question. The engine
/// itself puts the marker in front of the agent — the empty-diff feedback names
/// it verbatim — so an echo is the expected case, not a rare one.
pub(super) fn worker_question(detail: Option<&str>) -> Option<String> {
    let detail = detail?;
    let start = detail.rfind(QUESTION_MARKER)?;
    let text = detail[start + QUESTION_MARKER.len()..].trim();
    (!text.is_empty()).then(|| util::head(text, 2000))
}

/// §14 prompt materialization: body + acceptance + artifact inputs + the
/// exact gate commands the agent is permitted to run (the allow rules are
/// exact-match, so the agent must know the literal strings), plus — on a
/// retry — why the last attempt did not pass (§11.4).
pub(super) fn materialize_prompt(
    task: &Task,
    gate_cmds: &[String],
    artifacts_dir: &Path,
    retry: Option<&RetryBrief>,
) -> String {
    // A resumed session already holds the task, the artifacts, and the rules;
    // re-sending them buys nothing and buries the one thing that changed.
    if let Some(retry) = retry {
        if retry.resumed {
            let mut prompt = String::new();
            prompt.push_str(
                "Your previous attempt did not pass verification. Fix it in this same session — the \
                 task and its rules have not changed.\n\n",
            );
            prompt.push_str(&feedback_section(&retry.feedback, false));
            prompt.push_str(
                "\nMake the smallest change that resolves the above, then stop and summarize.\n",
            );
            return prompt;
        }
    }

    let mut prompt = String::new();
    prompt.push_str(
        "You are executing one task from a frozen plan, conducted by the tactus engine.\n\n",
    );
    let _ = writeln!(prompt, "# Task: {}\n", task.title);
    if !task.body.is_empty() {
        prompt.push_str(&task.body);
        prompt.push_str("\n\n");
    }
    if !task.acceptance.is_empty() {
        prompt.push_str("Acceptance criteria (all must hold when you finish):\n");
        for item in &task.acceptance {
            let _ = writeln!(prompt, "- {item}");
        }
        prompt.push('\n');
    }
    // Artifacts are real files in the run directory: a consumer is shown the
    // content that exists, never told to look for something nothing wrote.
    for id in &task.artifacts_in {
        let path = artifact_path(artifacts_dir, id.as_str());
        match fs::read_to_string(&path) {
            Ok(content) if !content.trim().is_empty() => {
                let _ = writeln!(
                    prompt,
                    "Input artifact `{id}` (produced by an earlier task):\n---\n{}\n---\n",
                    content.trim()
                );
            }
            _ => {
                let _ = writeln!(
                    prompt,
                    "Note: this task expected input artifact `{id}`, but the earlier task did \
                     not leave one. Work from the repository as it stands.\n"
                );
            }
        }
    }
    for id in &task.artifacts_out {
        let _ = writeln!(
            prompt,
            "Before you finish, write artifact `{id}` — the notes later tasks depend on — to:\n\
             {}\n",
            artifact_path(artifacts_dir, id.as_str()).display()
        );
    }
    if !gate_cmds.is_empty() {
        prompt.push_str(
            "Verification gates run after you finish. You may run EXACTLY these commands \
             yourself to check your work (any other shell command is denied):\n",
        );
        for cmd in gate_cmds {
            let _ = writeln!(prompt, "- {cmd}");
        }
        prompt.push('\n');
    }
    // Whatever earlier rungs learned travels with the task, even though the
    // conversation does not (§11.4).
    if let Some(retry) = retry {
        prompt.push_str(&feedback_section(&retry.feedback, true));
    }
    prompt.push_str(
        "Rules:\n\
         - Complete ONLY this task; leave work that belongs to other tasks alone.\n\
         - Edit files inside this repository only.\n\
         - NEVER run git commit, branch, merge, push, or reset — the engine owns git.\n\
         - When the acceptance criteria hold, stop and summarize what changed.\n\
         - If a decision genuinely is not yours to make — the task is ambiguous in a way that \
           changes what \"correct\" means, or it turns on a product or policy call you cannot \
           settle from this repository — stop and end your message with a line beginning \
           `TACTUS-QUESTION:` followed by the decision a person has to make. That pauses this \
           task and asks them. Do not use it for uncertainty you could resolve by reading the \
           code.\n",
    );
    prompt
}

/// What earlier attempts learned. `all` carries the accumulated history for a
/// fresh rung; otherwise only the most recent failure, which is what a
/// same-rung retry needs.
fn feedback_section(feedback: &[Feedback], all: bool) -> String {
    let entries: Vec<&Feedback> = if all {
        feedback
            .iter()
            .skip(feedback.len().saturating_sub(MAX_FEEDBACK_ENTRIES))
            .collect()
    } else {
        feedback.last().into_iter().collect()
    };
    if entries.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    if all && entries.len() > 1 {
        out.push_str(
            "Earlier attempts at this task failed. You are a fresh, stronger worker on the same \
             task — do not repeat these:\n\n",
        );
    }
    let last = entries.len() - 1;
    for (position, entry) in entries.iter().enumerate() {
        if entry.human {
            let fence = util::fence_for(entry.detail.as_deref().unwrap_or_default());
            let _ = writeln!(
                out,
                "The operator answered the question that paused this task. This is an \
                 instruction from a person, and it takes precedence over your earlier \
                 assumptions:\n{fence}\n{}\n{fence}\n",
                entry.detail.as_deref().unwrap_or_default().trim()
            );
            continue;
        }
        let where_ = if entry.tier.is_empty() {
            String::new()
        } else {
            format!(" on the {} rung", entry.tier)
        };
        let _ = writeln!(
            out,
            "Attempt {}{where_} failed: {}",
            entry.attempt, entry.summary
        );
        // Only the newest failure carries its full output; older ones would
        // bury it, and the newest is the one still standing in the way.
        if position == last {
            if let Some(detail) = &entry.detail {
                if !detail.trim().is_empty() {
                    let fence = util::fence_for(detail);
                    let _ = writeln!(out, "{fence}\n{}\n{fence}", detail.trim());
                }
            }
        }
        out.push('\n');
    }
    out
}

/// Where an artifact lives for the duration of a run (§15 `artifacts/`).
pub(super) fn artifact_path(artifacts_dir: &Path, id: &str) -> PathBuf {
    artifacts_dir.join(format!("{}.md", util::filename_component(id)))
}
