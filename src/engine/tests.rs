// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use super::attempt::{
    QUESTION_MARKER, artifact_path, evaluate_outcome, materialize_prompt, review_failure,
    worker_question,
};
use super::coordinator::{question_options, run_harness_inner};
use super::preflight::{gates_differ, validate_inputs};
use super::report::{sum_opt, task_report, total_of};
use super::resume::resume_harness_inner;
use super::*;
use crate::agent::{AgentAdapter, Caps, ProcessOutput, TaskRun};
use crate::capacity;
use crate::config;
use crate::events::{self, EventBody, EventLog, GateSummary, Progress, RunState, TaskState};
use crate::interaction::{self, AnswerSource, QuestionRecord, Sleeper};
use crate::ir::{
    Answer, Effort, Outcome, OutcomeStatus, PermissionMode, Question, QuestionId, QuestionKind,
    ResolvedEffortPolicy, Task, TaskId, TaskKind, Usage, WorkerProfile,
};
use crate::review;
use crate::rundir::{self, RunLock, RunPaths, WorktreeLock};
use crate::runner::CommandSpec;
use crate::topology::effects::EventSite;
use crate::workspace::Workspace;

#[derive(Clone, Copy, PartialEq)]
enum Effect {
    /// Simulates an agent that edits the workspace and succeeds.
    EditFile,
    /// Simulates an agent that writes real test code.
    EditTest,
    /// Produces a complete diff larger than the review input boundary.
    LargeEdit,
    /// Produces a binary patch whose changed bytes cannot be semantically
    /// reviewed from the unified diff.
    OpaqueEdit,
    /// Adds an ignored, uncommitted input that a gate could observe in the
    /// worker tree but that is absent from the staged review candidate.
    IgnoredGateInput,
    /// Lets the test mutate the authoritative index after capture and
    /// records which immutable tree the reviewer actually received.
    FrozenCandidate,
    /// After the reviewer workspace exists, plants a stale lock in the
    /// common git directory so the later authoritative cleanup fails.
    JamCleanupAfterReview,
    /// Produces the same oversized diff, then makes the question payload
    /// directory unwritable so parking preparation fails deterministically.
    LargeEditQuestionWriteFailure,
    /// Simulates a lying agent: success report, no changes.
    NoEdit,
    /// Command construction succeeds, but the worker executable cannot be
    /// spawned — the shape of an agent CLI removed, renamed, or self-updated
    /// out from under a run that has already passed pre-flight.
    SpawnError,
    /// Simulates an agent-side failure.
    Error,
    /// Simulates the pool being exhausted.
    RateLimited,
    /// Edits, then stops and asks the operator a question (§12).
    AskQuestion,
    /// Kills the whole process partway through the attempt, leaving the
    /// on-disk shape a `kill -9` or a power loss leaves: a dirty working
    /// tree and an `attempt_started` with no `attempt_finished`.
    Exit,
}

/// Distinctive so the parent can tell a deliberate death from a panic,
/// which would also exit non-zero.
const CRASH_EXIT_CODE: i32 = 42;

#[derive(Clone, Copy, PartialEq)]
enum ReviewBehavior {
    Pass,
    Fail,
    /// Prose with no verdict block: drives the re-ask path.
    Unparseable,
    /// The judge itself could not run.
    RateLimited,
    /// Command construction succeeds, but the reviewer executable cannot
    /// be spawned.
    SpawnError,
    /// §12: the reviewer declines to judge and asks for a person.
    NeedsHuman,
}

/// Scripted stand-in for a real CLI. `build` performs the "agent edit"
/// directly (test-only shortcut) and returns a trivial command; `parse`
/// reports the scripted outcome. Read-only profiles are review
/// invocations and answer with a verdict, exercising the real
/// command → stdout → parse → verdict path.
///
/// Both scripts are consumed per invocation and the final entry repeats,
/// so a one-element script behaves exactly like the fixed adapter did.
struct FakeAdapter {
    /// Which agent this stands in for. Cross-vendor tests (§11.3) need two
    /// ids, because "a different model family" is unreachable otherwise.
    id: &'static str,
    effects: Vec<Effect>,
    reviews: Vec<ReviewBehavior>,
    /// Simulates a CLI that is installed but broken, for the pre-flight
    /// probe classes: required agents refuse the run, the opportunistic
    /// cross-family one only warns.
    probe_error: Option<&'static str>,
    /// Whether this route reports spend. Copilot's does not.
    reports_cost: bool,
    calls: Mutex<Calls>,
}

#[derive(Default)]
struct Calls {
    worker: usize,
    review: usize,
    review_spawn_failures: usize,
    runs: Vec<RecordedRun>,
    review_snapshots: Vec<(String, String)>,
}

#[derive(Clone)]
struct RecordedRun {
    model: String,
    resume: Option<String>,
    prompt: String,
}

/// Marker the fake's review command prints so `parse` can tell a review
/// invocation from an implementation one.
const REVIEW_MARKER: &str = "TACTUS-FAKE-REVIEW";

impl FakeAdapter {
    fn new(effects: Vec<Effect>, reviews: Vec<ReviewBehavior>) -> Self {
        Self {
            id: "claude-code",
            effects,
            reviews,
            probe_error: None,
            reports_cost: true,
            calls: Mutex::new(Calls::default()),
        }
    }

    /// The second vendor. It only ever reviews in these tests, so it needs
    /// no effects script.
    fn copilot(reviews: Vec<ReviewBehavior>) -> Self {
        Self {
            id: "copilot",
            effects: Vec::new(),
            reviews,
            probe_error: None,
            reports_cost: true,
            calls: Mutex::new(Calls::default()),
        }
    }

    fn broken(mut self, message: &'static str) -> Self {
        self.probe_error = Some(message);
        self
    }

    /// Stands in for the Copilot route, which has no JSON envelope and so
    /// reports no spend at all (§13).
    fn unpriced(mut self) -> Self {
        self.reports_cost = false;
        self
    }

    fn runs(&self) -> Vec<RecordedRun> {
        self.calls
            .lock()
            .map(|c| c.runs.clone())
            .unwrap_or_default()
    }

    /// How many review invocations this adapter was asked for.
    fn reviews_run(&self) -> usize {
        self.calls.lock().map(|c| c.review).unwrap_or_default()
    }

    fn review_spawn_failures(&self) -> usize {
        self.calls
            .lock()
            .map(|c| c.review_spawn_failures)
            .unwrap_or_default()
    }

    fn review_snapshots(&self) -> Vec<(String, String)> {
        self.calls
            .lock()
            .map(|calls| calls.review_snapshots.clone())
            .unwrap_or_default()
    }
}

fn fake(effect: Effect) -> FakeSource {
    source(vec![effect], vec![ReviewBehavior::Pass])
}

fn source(effects: Vec<Effect>, reviews: Vec<ReviewBehavior>) -> FakeSource {
    FakeSource {
        adapter: FakeAdapter::new(effects, reviews),
        copilot: None,
    }
}

/// A machine with both CLIs installed: claude-code implements and gives the
/// acceptance verdict, copilot gives the §11.3 second opinion. Each adapter
/// keeps its own review script and counter, so a test can say what each
/// vendor answered and check which of them was asked at all.
fn cross_vendor(
    effects: Vec<Effect>,
    reviews: Vec<ReviewBehavior>,
    second: Vec<ReviewBehavior>,
) -> FakeSource {
    FakeSource {
        adapter: FakeAdapter::new(effects, reviews),
        copilot: Some(FakeAdapter::copilot(second)),
    }
}

/// The last scripted entry repeats forever.
fn scripted<T: Copy>(script: &[T], index: usize, fallback: T) -> T {
    script
        .get(index)
        .copied()
        .or_else(|| script.last().copied())
        .unwrap_or(fallback)
}

impl AgentAdapter for FakeAdapter {
    fn id(&self) -> &'static str {
        self.id
    }

    fn probe(&self, _runner: &dyn crate::runner::Runner) -> Result<Caps, TactusError> {
        if let Some(message) = self.probe_error {
            return Err(TactusError::Agent {
                message: message.to_owned(),
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

    fn build(&self, run: &TaskRun) -> Result<CommandSpec, TactusError> {
        if run.profile.permissions == PermissionMode::ReadOnly {
            let effect = self
                .calls
                .lock()
                .map(|calls| {
                    scripted(
                        &self.effects,
                        calls.worker.saturating_sub(1),
                        Effect::EditFile,
                    )
                })
                .unwrap_or(Effect::EditFile);
            let behavior = {
                let mut calls = self.calls.lock().map_err(|_| TactusError::Agent {
                    message: "fake adapter lock poisoned".to_owned(),
                })?;
                let index = calls.review + calls.review_spawn_failures;
                let behavior = scripted(&self.reviews, index, ReviewBehavior::Pass);
                if behavior == ReviewBehavior::SpawnError {
                    calls.review_spawn_failures += 1;
                }
                behavior
            };
            if behavior == ReviewBehavior::SpawnError {
                return Ok(CommandSpec::new(
                    run.workspace
                        .join("missing-reviewer-executable")
                        .to_string_lossy(),
                ));
            }
            if effect == Effect::FrozenCandidate {
                let tree = Command::new("git")
                    .arg("-C")
                    .arg(&run.workspace)
                    .args(["rev-parse", "HEAD^{tree}"])
                    .output()
                    .map_err(|e| TactusError::Agent {
                        message: format!("fake could not inspect reviewer tree: {e}"),
                    })?;
                if !tree.status.success() {
                    return Err(TactusError::Agent {
                        message: format!(
                            "fake could not inspect reviewer tree: {}",
                            String::from_utf8_lossy(&tree.stderr).trim()
                        ),
                    });
                }
                let contents =
                    fs::read_to_string(run.workspace.join("agent-output.txt")).map_err(|e| {
                        TactusError::Agent {
                            message: format!("fake could not inspect reviewer candidate: {e}"),
                        }
                    })?;
                self.calls
                    .lock()
                    .map_err(|_| TactusError::Agent {
                        message: "fake adapter lock poisoned".to_owned(),
                    })?
                    .review_snapshots
                    .push((
                        String::from_utf8_lossy(&tree.stdout).trim().to_owned(),
                        contents,
                    ));
            }
            if effect == Effect::JamCleanupAfterReview {
                let common = Command::new("git")
                    .arg("-C")
                    .arg(&run.workspace)
                    .args(["rev-parse", "--git-common-dir"])
                    .output()
                    .map_err(|e| TactusError::Agent {
                        message: format!("fake could not inspect git common dir: {e}"),
                    })?;
                if !common.status.success() {
                    return Err(TactusError::Agent {
                        message: format!(
                            "fake could not inspect git common dir: {}",
                            String::from_utf8_lossy(&common.stderr).trim()
                        ),
                    });
                }
                let common = PathBuf::from(String::from_utf8_lossy(&common.stdout).trim());
                let common = if common.is_absolute() {
                    common
                } else {
                    run.workspace.join(common)
                };
                fs::write(common.join("index.lock"), "jam\n").map_err(|e| TactusError::Agent {
                    message: format!("fake could not jam cleanup: {e}"),
                })?;
            }
            // No `current_dir`: the runner puts the process in
            // `RunnerRequest.workspace`, which is `run.workspace`.
            return Ok(shell_spec(&format!("echo {REVIEW_MARKER}")));
        }
        let index = {
            let mut calls = self.calls.lock().map_err(|_| TactusError::Agent {
                message: "fake adapter lock poisoned".to_owned(),
            })?;
            let index = calls.worker;
            calls.worker += 1;
            calls.runs.push(RecordedRun {
                model: run.profile.model.clone(),
                resume: run.resume_session.clone(),
                prompt: run.prompt.clone(),
            });
            index
        };
        let edit: Option<(&str, String)> = match scripted(&self.effects, index, Effect::EditFile) {
            Effect::Exit => {
                // Half-finished edits first, then die without
                // unwinding — no destructors, no flush of anything the
                // engine has not already synced. That is what makes
                // this a faithful stand-in for a kill rather than a
                // tidy shutdown, and it happens at a deterministic
                // point instead of racing a signal.
                let _ = fs::write(
                    run.workspace.join("agent-output.txt"),
                    "half-written by an agent that never came back\n",
                );
                std::process::exit(CRASH_EXIT_CODE);
            }
            Effect::EditFile
            | Effect::AskQuestion
            | Effect::JamCleanupAfterReview
            | Effect::FrozenCandidate => {
                let marker = run.workspace.join("agent-output.txt");
                let previous = fs::read_to_string(&marker).unwrap_or_default();
                Some(("agent-output.txt", format!("{previous}edited: {index}\n")))
            }
            Effect::EditTest => Some((
                "widget_test.rs",
                "#[test]\nfn widget_works() {\n    assert!(true);\n}\n".to_owned(),
            )),
            Effect::LargeEdit | Effect::LargeEditQuestionWriteFailure => Some((
                "large-agent-output.txt",
                "x".repeat(review::MAX_DIFF_BYTES + 1),
            )),
            Effect::OpaqueEdit => Some(("opaque-agent-output.bin", "\0hidden bytes".to_owned())),
            Effect::IgnoredGateInput => {
                fs::write(run.workspace.join(".gitignore"), "ignored.flag\n").map_err(|e| {
                    TactusError::Agent {
                        message: format!("fake ignore rule failed: {e}"),
                    }
                })?;
                fs::write(run.workspace.join("ignored.flag"), "gate-only input\n").map_err(
                    |e| TactusError::Agent {
                        message: format!("fake ignored input failed: {e}"),
                    },
                )?;
                Some(("agent-output.txt", "reviewed edit\n".to_owned()))
            }
            Effect::SpawnError => {
                // Return before editing anything: this attempt never gets to
                // run, so it must not leave the workspace looking as though it
                // did.
                return Ok(CommandSpec::new(
                    run.workspace
                        .join("missing-worker-executable")
                        .to_string_lossy(),
                ));
            }
            Effect::NoEdit | Effect::Error | Effect::RateLimited => None,
        };
        if let Some((name, content)) = edit {
            fs::write(run.workspace.join(name), content).map_err(|e| TactusError::Agent {
                message: format!("fake edit failed: {e}"),
            })?;
        }
        if scripted(&self.effects, index, Effect::EditFile) == Effect::LargeEditQuestionWriteFailure
        {
            let run_id = rundir::latest_run(&run.workspace).ok_or_else(|| TactusError::Agent {
                message: "fake could not find the active run".to_owned(),
            })?;
            let questions = rundir::public_dir(&run.workspace, &run_id).join("questions");
            fs::remove_dir(&questions).map_err(|e| TactusError::Agent {
                message: format!("fake could not remove questions directory: {e}"),
            })?;
            fs::write(&questions, "not a directory\n").map_err(|e| TactusError::Agent {
                message: format!("fake could not block question writes: {e}"),
            })?;
        }
        Ok(shell_spec("exit 0"))
    }

    // Delegate to the real generator so the engine's permission wiring is
    // exercised, not stubbed out.
    fn materialize_permissions(
        &self,
        profile: &WorkerProfile,
        gate_cmds: &[String],
        dir: &Path,
        stem: &str,
    ) -> Result<Option<PathBuf>, TactusError> {
        crate::agent::claude::ClaudeCodeAdapter
            .materialize_permissions(profile, gate_cmds, dir, stem)
    }

    fn parse(&self, out: &ProcessOutput) -> Result<Outcome, TactusError> {
        if out.stdout.contains(REVIEW_MARKER) {
            let index = {
                let mut calls = self.calls.lock().map_err(|_| TactusError::Agent {
                    message: "fake adapter lock poisoned".to_owned(),
                })?;
                let index = calls.review + calls.review_spawn_failures;
                calls.review += 1;
                index
            };
            let behavior = scripted(&self.reviews, index, ReviewBehavior::Pass);
            if behavior == ReviewBehavior::RateLimited {
                return Ok(fake_outcome(
                    OutcomeStatus::RateLimited,
                    Some("5-hour limit reached".to_owned()),
                    "fake-review-session",
                    Some(0.0),
                    out.duration,
                ));
            }
            let answer = match behavior {
                ReviewBehavior::Pass => {
                    "```json\n{\"pass\": true, \"reasons\": [\"meets the acceptance \
                         criteria\"], \"required_changes\": []}\n```"
                }
                ReviewBehavior::Fail => {
                    "```json\n{\"pass\": false, \"reasons\": [\"no error handling for \
                         empty input\"], \"required_changes\": \
                         [\"handle the empty-input case\"]}\n```"
                }
                ReviewBehavior::NeedsHuman => {
                    "```json\n{\"pass\": false, \"reasons\": [\"the acceptance criteria \
                         contradict the API contract\"], \"needs_human\": true}\n```"
                }
                ReviewBehavior::Unparseable => "Looks fine to me, ship it.",
                ReviewBehavior::RateLimited => unreachable!("handled above"),
                ReviewBehavior::SpawnError => unreachable!("handled during command build"),
            };
            return Ok(fake_outcome(
                OutcomeStatus::Completed,
                Some(answer.to_owned()),
                "fake-review-session",
                self.reports_cost.then_some(0.05),
                out.duration,
            ));
        }
        // `build` already consumed this invocation's slot.
        let index = self
            .calls
            .lock()
            .map(|c| c.worker.saturating_sub(1))
            .unwrap_or(0);
        let effect = scripted(&self.effects, index, Effect::EditFile);
        let status = match effect {
            Effect::Error => OutcomeStatus::AgentError,
            Effect::RateLimited => OutcomeStatus::RateLimited,
            // `Exit` never reaches here — `build` ends the process.
            Effect::EditFile
            | Effect::EditTest
            | Effect::LargeEdit
            | Effect::OpaqueEdit
            | Effect::IgnoredGateInput
            | Effect::FrozenCandidate
            | Effect::JamCleanupAfterReview
            | Effect::LargeEditQuestionWriteFailure
            | Effect::NoEdit
            | Effect::AskQuestion
            // `SpawnError` never reaches here either: the runner fails to
            // spawn it, so nothing is parsed.
            | Effect::SpawnError
            | Effect::Exit => OutcomeStatus::Completed,
        };
        let detail = match effect {
            Effect::Error => Some("fake adapter error detail".to_owned()),
            Effect::RateLimited => Some("5-hour limit reached".to_owned()),
            Effect::AskQuestion => Some(
                "I made a start but stopped.\nTACTUS-QUESTION: should cursors be opaque or \
                     signed?"
                    .to_owned(),
            ),
            _ => None,
        };
        let mut outcome = fake_outcome(
            status,
            detail,
            &format!("s{index}"),
            Some(0.01),
            out.duration,
        );
        outcome.usage = Some(Usage::default());
        Ok(outcome)
    }
}

fn fake_outcome(
    status: OutcomeStatus,
    detail: Option<String>,
    session: &str,
    cost_usd: Option<f64>,
    duration: Duration,
) -> Outcome {
    Outcome {
        status,
        diff: String::new(),
        detail,
        session_id: Some(session.to_owned()),
        usage: None,
        cost_usd,
        transcript_path: PathBuf::new(),
        duration,
    }
}

struct FakeSource {
    adapter: FakeAdapter,
    /// `None` is the single-vendor machine — which is also the shape that
    /// makes a cross-family reviewer unresolvable.
    copilot: Option<FakeAdapter>,
}

impl FakeSource {
    fn copilot(&self) -> &FakeAdapter {
        self.copilot.as_ref().expect("this source has a copilot")
    }
}

impl AdapterSource for FakeSource {
    fn get(&self, id: &str) -> Option<&dyn AgentAdapter> {
        if id == self.adapter.id {
            return Some(&self.adapter as &dyn AgentAdapter);
        }
        self.copilot
            .as_ref()
            .filter(|a| a.id == id)
            .map(|a| a as &dyn AgentAdapter)
    }
}

/// Answers handed out in order; anything past the script is unanswered,
/// which is exactly how a detached terminal behaves.
struct ScriptedAnswers {
    answers: Mutex<std::collections::VecDeque<Answer>>,
}

impl ScriptedAnswers {
    fn new(answers: Vec<Answer>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
        }
    }
}

impl AnswerSource for ScriptedAnswers {
    fn id(&self) -> &'static str {
        "scripted"
    }

    fn resolve(&self, _question: &Question) -> Result<Answer, TactusError> {
        Ok(self
            .answers
            .lock()
            .ok()
            .and_then(|mut a| a.pop_front())
            .unwrap_or(Answer::Unanswered))
    }
}

#[derive(Default)]
struct RecordingSleeper {
    waits: Mutex<Vec<Duration>>,
}

impl Sleeper for RecordingSleeper {
    fn sleep(&self, duration: Duration) {
        if let Ok(mut waits) = self.waits.lock() {
            waits.push(duration);
        }
    }
}

impl RecordingSleeper {
    fn waits(&self) -> Vec<Duration> {
        self.waits.lock().map(|w| w.clone()).unwrap_or_default()
    }
}

/// Shared with the production path so tests exercise the same shell
/// invocation (including its Windows quoting) rather than a parallel one.
fn shell_spec(script: &str) -> CommandSpec {
    crate::gates::ShellKind::native().spec(script)
}

fn git_in(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn candidate_mutation_marker(repo: &Path) -> PathBuf {
    let name = repo
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "repo".to_owned());
    repo.with_file_name(format!("{name}-candidate-mutation.txt"))
}

fn mutate_index_after_candidate_capture(
    workspace: &Workspace,
    candidate: &crate::workspace::CapturedCandidate,
) -> Result<(), TactusError> {
    fs::write(
        workspace.root().join("agent-output.txt"),
        "tampered after capture\n",
    )
    .map_err(|error| TactusError::Git {
        message: format!("test could not mutate the captured worktree: {error}"),
    })?;
    let add = Command::new("git")
        .arg("-C")
        .arg(workspace.root())
        .args(["add", "-A"])
        .output()
        .map_err(|error| TactusError::Git {
            message: format!("test could not stage its post-capture mutation: {error}"),
        })?;
    if !add.status.success() {
        return Err(TactusError::Git {
            message: format!(
                "test could not stage its post-capture mutation: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            ),
        });
    }
    let tampered_tree = Command::new("git")
        .arg("-C")
        .arg(workspace.root())
        .arg("write-tree")
        .output()
        .map_err(|error| TactusError::Git {
            message: format!("test could not inspect its post-capture tree: {error}"),
        })?;
    if !tampered_tree.status.success() {
        return Err(TactusError::Git {
            message: format!(
                "test could not inspect its post-capture tree: {}",
                String::from_utf8_lossy(&tampered_tree.stderr).trim()
            ),
        });
    }
    let tampered_tree = String::from_utf8_lossy(&tampered_tree.stdout)
        .trim()
        .to_owned();
    if tampered_tree == candidate.tree_oid {
        return Err(TactusError::Git {
            message: "test post-capture mutation did not change the staged tree".to_owned(),
        });
    }
    fs::write(
        candidate_mutation_marker(workspace.root()),
        format!(
            "{}\n{}\n{tampered_tree}\n",
            candidate.parent_oid, candidate.tree_oid
        ),
    )
    .map_err(|error| TactusError::Git {
        message: format!("test could not record its capture identities: {error}"),
    })
}

fn temp_engine_repo(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tactus-engine-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create repo dir");
    git_in(&dir, &["init", "-q", "-b", "main"]);
    git_in(&dir, &["config", "user.email", "test@tactus.local"]);
    git_in(&dir, &["config", "user.name", "tactus tests"]);
    fs::write(dir.join("README.md"), "seed\n").expect("seed");
    fs::write(
        dir.join("plan.md"),
        "## Implement the widget\n<!-- tactus: id=t1 depends= -->\nMake it.\n\n\
             ## Document the widget\n<!-- tactus: id=t2 depends=t1 -->\nWrite it up.\n",
    )
    .expect("plan");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "seed"]);
    dir
}

/// Replace the plan and config, then commit so the tree is clean.
fn seed(repo: &Path, plan: &str, config: Option<&str>) {
    fs::write(repo.join("plan.md"), plan).expect("plan");
    if let Some(config) = config {
        fs::write(repo.join("tactus.toml"), config).expect("config");
    }
    git_in(repo, &["add", "-A"]);
    git_in(repo, &["commit", "-q", "-m", "fixture"]);
}

fn options(repo: &Path) -> RunOptions {
    let mut opts = RunOptions::new(repo.join("plan.md"), repo.to_path_buf());
    opts.pools_path = Some(no_pools());
    opts.attempt_timeout = Duration::from_secs(60);
    // Tests must never actually wait — not out a rate limit, and not at a
    // hard block either. The test harness has no terminal, so an
    // interactive mode resolves to the waiting answer channel; without a
    // zero budget every parking test would sit out the real one.
    opts.defer_backoff = Duration::ZERO;
    opts.wait_on_block = Some(Duration::ZERO);
    opts.private_root = Some(private_root_for(repo));
    opts
}

/// An explicit pools path with no pools in it.
///
/// A real, empty file rather than an absent one: an explicit `--pools` that
/// does not exist is a hard error now, and `None` would reach for the
/// operator's real `~/.tactus/pools.toml` — which no test may touch.
/// An empty pools file, created once for the whole test process.
///
/// Every test routes through here, and this used to *rewrite* the file on
/// each call — one shared path truncated and rewritten while other threads
/// were reading it. The content is the same for every caller, so there is
/// nothing to rewrite: build it once and hand back the path.
fn no_pools() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("tactus-engine-nopools-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("pools.toml");
        fs::write(
            &path,
            "# no pools
",
        )
        .expect("empty pools file");
        path
    })
    .clone()
}

/// A scratch stand-in for `~/.tactus`, so tests never touch the real one.
///
/// A *sibling* of the repo, never a directory inside it. That is not
/// tidiness: §14's rollback is `git clean -fd`, which deletes untracked
/// directories — a private root inside the workspace would have its
/// transcripts and verdicts destroyed by the first failed attempt. The
/// same reasoning is why production puts it under the user's home.
fn private_root_for(repo: &Path) -> PathBuf {
    let name = repo
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "run".to_owned());
    repo.with_file_name(format!("{name}-home"))
}

/// Resume options matching [`options`], for the same reasons.
fn resume_options(repo: &Path, run_id: &str) -> ResumeOptions {
    let mut opts = ResumeOptions::new(run_id.to_owned(), repo.to_path_buf());
    opts.pools_path = Some(no_pools());
    opts.attempt_timeout = Duration::from_secs(60);
    opts.defer_backoff = Duration::ZERO;
    opts.wait_on_block = Some(Duration::ZERO);
    opts.private_root = Some(private_root_for(repo));
    opts
}

/// The paths a test's run wrote to.
fn paths_of(repo: &Path, run_id: &str) -> RunPaths {
    RunPaths::with_private_root(repo, run_id, &private_root_for(repo))
}

fn committed(report: &RunReport, id: &str) -> bool {
    report
        .tasks
        .iter()
        .any(|t| t.id == id && matches!(t.status, TaskRunStatus::Committed { .. }))
}

fn task<'a>(report: &'a RunReport, id: &str) -> &'a TaskReport {
    report
        .tasks
        .iter()
        .find(|t| t.id == id)
        .unwrap_or_else(|| panic!("no task `{id}` in {report:?}"))
}

// ---- a returned legacy append error ------------------------------------

/// Fails the **third** legacy append of a live run, by returning an error at
/// `Event.LegacyAppend`'s `Written` point.
///
/// The third, and the number is load-bearing rather than arbitrary:
/// `run_harness_inner_on` emits `run_started` and then the capacity snapshot —
/// two appends — *before* `drain_and_report` is called at all, so a fault at
/// either tests the startup path and never reaches the branch both findings are
/// about. The third is the first append inside `drain()`, which is where
/// `production_effect`'s "it reports and stops" and the partial report live.
/// `a_returned_legacy_append_error_still_leaves_the_partial_report` checks that
/// the two startup appends really did land, so if this number ever stops being
/// the right one it fails loudly instead of passing for the wrong reason.
#[derive(Default)]
struct FailTheThirdLegacyAppend {
    entered: u32,
}

impl crate::events::log::EventHooks for FailTheThirdLegacyAppend {
    fn point(
        &mut self,
        site: EventSite,
        point: crate::topology::effects::SubEffectPoint,
        mode: crate::topology::effects::InjectionMode,
    ) -> crate::topology::effects::Injection {
        use crate::topology::effects::{Injection, InjectionMode, SubEffectPoint};
        if site != EventSite::LegacyAppend
            || point != SubEffectPoint::Written
            || mode != InjectionMode::ErrorReturn
        {
            return Injection::Proceed;
        }
        self.entered += 1;
        if self.entered == 3 {
            Injection::Error
        } else {
            Injection::Proceed
        }
    }
}

fn fail_the_third_legacy_append() -> Box<dyn crate::events::log::EventHooks> {
    Box::<FailTheThirdLegacyAppend>::default()
}

/// A returned append error **stops the run** — it is not swallowed and carried
/// on from (`PR5-CONF-010`).
///
/// `production_effect` says "the legacy engine's handling of a returned append
/// error is unchanged — **it reports and stops**". The shipped code did;
/// nothing required it to. Replacing `Run::emit`'s `?` with an arm that pushed
/// a warning and returned `Ok` **survived the whole suite**: every append
/// failure the suite injected targeted an `EventLog` a test had built directly,
/// and `emit` reached `EventLog::append`, which hard-codes `NoEventHooks`, so
/// no fixture could make a **live `Run`**'s append fail at all.
///
/// The two axes this crosses are *whose* `EventLog` fails and *what observes
/// the failure*. `src/events/log/tests.rs` holds the first constant at "a log
/// the test owns" and varies the second exhaustively; the census beside those
/// tests reads the coordinator's source and can see that the branch returns,
/// but not that the error ever gets to it. What varies here is the log: it is
/// the live run's own, reached through `engine::run_with`, and the assertion is
/// on the value the *caller* receives.
#[test]
fn a_returned_legacy_append_error_stops_the_run() {
    let repo = temp_engine_repo("legacy-append-error");
    let mut opts = options(&repo);
    opts.log_hooks = Some(fail_the_third_legacy_append);
    let source = fake(Effect::EditFile);

    let error = run_with(&opts, &source)
        .expect_err("a returned append error must reach the caller, not be swallowed");
    let message = error.to_string();
    assert!(
        message.contains("Event.LegacyAppend"),
        "the error must be the append's own, naming its site: {message}"
    );
    assert!(
        message.contains("Written"),
        "…and its point, so an operator can tell which coordinate failed: {message}"
    );
}

/// …and the partial report is written beside the log on the way out
/// (`PR5-CONF-011`).
///
/// Deleting `drain_and_report`'s partial `finish()` and `rundir::write_report`
/// survived the whole suite, for the same reason and one branch further on.
///
/// **This is the legacy path and the repair must not generalize.**
/// `coordinator_integration.append_error_protocol` forbids exactly the
/// opposite for schema-4 — "no report, status, question payload, or cleanup is
/// derived from the poisoned fold" and "still performs no retry, **report from
/// memory**, cleanup, or fold mutation". So the assertion below is on the
/// legacy `report.json` only, and nothing here is asserted of the topology
/// coordinator.
///
/// Held constant with the sibling above: the same fault, at the same append, in
/// the same fixture. What varies is what is examined — the caller's return
/// value there, the run directory here.
#[test]
fn a_returned_legacy_append_error_still_leaves_the_partial_report() {
    let repo = temp_engine_repo("legacy-append-partial");
    let mut opts = options(&repo);
    opts.log_hooks = Some(fail_the_third_legacy_append);
    let source = fake(Effect::EditFile);

    run_with(&opts, &source).expect_err("the append error stops the run");

    // The run directory the failed run created, found by its own log rather
    // than by a run id the caller never received.
    let runs = opts.repo_root.join(".tactus").join("runs");
    let public = fs::read_dir(&runs)
        .expect("the runs root")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.join("events.jsonl").is_file())
        .expect("the failed run left its public directory and its log");
    // The premise: the fault fired *inside* `drain()`, not during startup.
    // `run_started` and the capacity snapshot are appends 1 and 2 and both must
    // have landed whole; the third is the one that failed, and its Written
    // error-return arm leaves a torn prefix rather than a complete line.
    let log = fs::read_to_string(public.join("events.jsonl")).expect("the log");
    let complete = log.lines().filter(|line| line.ends_with('}')).count();
    assert!(
        complete >= 2,
        "only {complete} complete line(s) in the log: the injected failure landed on \
         a startup append, so this test never reached drain_and_report's branch"
    );

    let report = public.join("report.json");
    assert!(
        report.is_file(),
        "no report beside {}: the legacy engine's partial report is a courtesy for \
         whoever opens the directory next, and failing to write it must not be \
         silent (PR5-CONF-011)",
        public.display()
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("read the partial report"))
            .expect("the partial report is JSON");
    assert!(
        parsed.get("tasks").is_some(),
        "the partial report is a report, not a stub: {parsed}"
    );
}

// ---- step 1-6 behaviour, unchanged by the ladder ----------------------

#[test]
fn happy_path_commits_one_commit_per_task() {
    let repo = temp_engine_repo("happy");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run succeeds");

    assert_eq!(report.outcome(), RunOutcome::Complete);
    assert_eq!(report.tasks.len(), 2);
    assert!(
        report
            .tasks
            .iter()
            .all(|t| matches!(t.status, TaskRunStatus::Committed { .. })),
        "report: {report:?}"
    );
    // Per task: implementer 0.01 + reviewer 0.05 (§11.2 reviews every
    // attempt), so both spends are accounted for.
    assert!(
        (report.total_cost_usd - 0.12).abs() < 1e-9,
        "worker and reviewer spend both counted: {}",
        report.total_cost_usd
    );

    let branch = git_in(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
    assert!(branch.trim().starts_with("tactus/run-"), "on run branch");
    let count = git_in(&repo, &["rev-list", "--count", "main..HEAD"]);
    assert_eq!(count.trim(), "2", "one commit per task");
    let log = git_in(&repo, &["log", "--format=%s", "main..HEAD"]);
    assert!(
        log.contains("[tactus] t1: Implement the widget"),
        "log: {log}"
    );
    assert!(log.contains("[tactus] t2: Document the widget"));
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "clean tree after run"
    );
    assert!(
        repo.join(".tactus").join("runs").exists(),
        "run dir written"
    );
}

#[test]
fn gates_review_and_commit_use_one_frozen_candidate_tree() {
    let repo = temp_engine_repo("one-frozen-candidate");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [[gates]]\nname = \"frozen-candidate\"\n\
                 cmd = 'git grep -q \"edited: 0\" -- agent-output.txt'\n",
        ),
    );
    let base = git_in(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
    let marker = candidate_mutation_marker(&repo);
    let _ = fs::remove_file(&marker);
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.after_candidate_capture = Some(mutate_index_after_candidate_capture);
    let source = fake(Effect::FrozenCandidate);

    let report = run_with(&opts, &source).expect("the frozen candidate remains authoritative");
    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");
    assert_eq!(report.gates, ["frozen-candidate"]);

    let capture: Vec<_> = fs::read_to_string(&marker)
        .expect("the post-capture mutation hook ran")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(capture.len(), 3, "capture marker: {capture:?}");
    assert_eq!(capture[0], base, "captured parent is the attempt parent");
    assert_ne!(
        capture[1], capture[2],
        "the mutable index really changed after capture"
    );

    let logged = events_of(&repo, &report.run_id);
    let prepared = logged
        .iter()
        .find_map(|event| match &event.body {
            EventBody::AttemptFinished {
                prepared_commit, ..
            } => prepared_commit.as_deref().cloned(),
            _ => None,
        })
        .expect("successful settlement records its prepared object");
    assert_eq!(
        prepared.branch_ref,
        format!("refs/heads/{}", report.branch),
        "the durable settlement owns the exact run ref"
    );
    assert_eq!(prepared.parent_sha, capture[0]);
    assert_eq!(prepared.tree_sha, capture[1]);
    assert_ne!(prepared.tree_sha, capture[2]);

    let review_snapshots = source.adapter.review_snapshots();
    assert_eq!(review_snapshots.len(), 1, "one reviewer snapshot");
    assert_eq!(review_snapshots[0].0, prepared.tree_sha);
    assert_eq!(
        review_snapshots[0].1.replace("\r\n", "\n"),
        "edited: 0\n",
        "review sees the captured tree, not the later staged mutation"
    );

    let committed = logged
        .iter()
        .find_map(|event| match &event.body {
            EventBody::TaskCommitted { data, .. } => Some(data),
            _ => None,
        })
        .expect("task_committed follows the prepared settlement");
    let head = git_in(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
    let head_tree = git_in(&repo, &["rev-parse", "HEAD^{tree}"])
        .trim()
        .to_owned();
    assert_eq!(head, prepared.commit_sha);
    assert_eq!(committed.sha, prepared.commit_sha);
    assert_eq!(head_tree, prepared.tree_sha);
    assert_eq!(
        git_in(&repo, &["show", "HEAD:agent-output.txt"]),
        "edited: 0\n",
        "the staged post-capture mutation is never published"
    );
}

#[test]
fn an_oversized_review_diff_is_settled_once_before_the_task_parks() {
    let repo = temp_engine_repo("oversizedreviewsettlement");
    seed(
        &repo,
        "## Generate the large fixture\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 3 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::LargeEdit);
    let report = run_with(&opts, &source).expect("policy failure is a settled run outcome");

    assert_eq!(report.outcome(), RunOutcome::Parked, "{report:?}");
    let task_report = task(&report, "t1");
    assert_eq!(
        task_report.attempts.len(),
        1,
        "the policy boundary is not retried"
    );
    let attempt = &task_report.attempts[0];
    let failure = attempt.failure.as_ref().expect("settled policy failure");
    assert_eq!(failure.kind, FailureKind::ReviewInputTooLarge);
    assert_eq!(failure.origin, FailureOrigin::Reviewer);
    assert_eq!(attempt.cost_usd, Some(0.01), "worker spend is retained");
    assert_eq!(attempt.session_id.as_deref(), Some("s0"));
    assert!(attempt.usage.is_some(), "worker usage is retained");
    assert!(attempt.reviews.is_empty(), "no reviewer was dispatched");
    assert_eq!(source.adapter.reviews_run(), 0);

    let logged = events_of(&repo, &report.run_id);
    assert_eq!(
        logged
            .iter()
            .filter(|event| matches!(event.body, EventBody::AttemptFinished { .. }))
            .count(),
        1,
        "the attempt has a terminal ledger event"
    );
    let parking = logged.iter().find_map(|event| match &event.body {
        EventBody::AttemptFinished { parking, .. } => parking.as_deref(),
        _ => None,
    });
    assert!(
        parking.is_some(),
        "the settlement atomically carries its parking question"
    );
    assert!(
        !logged.iter().any(|event| matches!(
            event.body,
            EventBody::QuestionRaised { .. } | EventBody::TaskParked { .. }
        )),
        "policy parking must not reopen a crash window with follow-up events"
    );
    assert!(
        !logged
            .iter()
            .any(|event| matches!(event.body, EventBody::AttemptInterrupted { .. })),
        "replay must never invent an interruption for the settled refusal"
    );
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "parking cleans the unreviewed oversized diff"
    );
    let question = report.questions.first().expect("scope question");
    assert_eq!(question.question.kind, QuestionKind::Unblock);
    assert!(question.question.context.contains("smaller diff"));
    assert!(question.question.context.contains("starting a new run"));
    assert!(
        !question.question.context.contains("chain is spent")
            && !question.question.context.contains("all failed"),
        "policy parking must not pretend the escalation chain was exhausted: {}",
        question.question.context
    );

    // Rewind to the exact atomic settlement, then add dirty residue to
    // model death before ordinary post-attempt cleanup. Replay must retain
    // both the paid ledger line and the question, discard the residue, and
    // never dispatch another worker for the known-oversized identity.
    let paths = paths_of(&repo, &report.run_id);
    truncate_log_after(&paths, "attempt_finished");
    fs::write(repo.join("crash-residue.txt"), "unreviewed\n").expect("crash residue");
    let retry = fake(Effect::EditFile);
    let resumed =
        resume_with(&resume_options(&repo, &report.run_id), &retry).expect("resume parks");
    assert_eq!(resumed.outcome(), RunOutcome::Parked, "{resumed:?}");
    assert!(
        retry.adapter.runs().is_empty(),
        "resume paid for the oversized attempt again"
    );
    assert_eq!(task(&resumed, "t1").attempts.len(), 1);
    assert_eq!(resumed.questions.len(), 1);
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "resume did not discard crash residue"
    );
}

#[test]
fn opaque_review_input_has_distinct_failure_and_remediation() {
    let repo = temp_engine_repo("opaquereviewsettlement");
    seed(
        &repo,
        "## Generate an opaque artifact\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 3 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::OpaqueEdit);
    let report = run_with(&opts, &source).expect("opaque evidence parks fail-closed");

    assert_eq!(report.outcome(), RunOutcome::Parked, "{report:?}");
    let attempt = &task(&report, "t1").attempts[0];
    assert_eq!(
        attempt.failure.as_ref().map(|failure| failure.kind),
        Some(FailureKind::ReviewInputOpaque)
    );
    assert_eq!(source.adapter.reviews_run(), 0);
    let context = &report.questions[0].question.context;
    assert!(context.contains("hides changed content"), "{context}");
    assert!(!context.contains("smaller diff"), "{context}");
}

#[test]
fn opaque_test_task_parks_before_test_provenance_retry() {
    let repo = temp_engine_repo("opaquetestprovenance");
    seed(
        &repo,
        "## Add the regression\n<!-- tactus: id=t1 kind=test depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\ntest = { chain = [\"small\"], attempts_per = 3 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::OpaqueEdit);
    let report = run_with(&opts, &source).expect("opaque evidence parks fail-closed");

    assert_eq!(report.outcome(), RunOutcome::Parked, "{report:?}");
    let task = task(&report, "t1");
    assert_eq!(task.attempts.len(), 1, "opaque evidence is not retried");
    assert_eq!(
        task.attempts[0]
            .failure
            .as_ref()
            .map(|failure| failure.kind),
        Some(FailureKind::ReviewInputOpaque),
        "the intrinsic evidence failure wins over Test provenance"
    );
    assert_eq!(source.adapter.reviews_run(), 0);
    assert!(
        report.questions[0]
            .question
            .context
            .contains("hides changed content")
    );
}

#[test]
fn failed_parking_payload_still_settles_and_cleans_the_attempt() {
    let repo = temp_engine_repo("oversizedreviewquestionwrite");
    seed(
        &repo,
        "## Generate the large fixture\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 3 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::LargeEditQuestionWriteFailure);
    let error = run_with(&opts, &source).expect_err("question projection must fail");
    assert!(
        error.to_string().contains("questions"),
        "wrong failure surfaced: {error}"
    );

    let run_id = rundir::latest_run(&repo).expect("failed run remains resumable");
    let logged = events_of(&repo, &run_id);
    let parking = logged.iter().find_map(|event| match &event.body {
        EventBody::AttemptFinished { parking, .. } => parking.as_deref(),
        _ => None,
    });
    assert!(
        parking.is_some(),
        "the event must retain parking even when its JSON projection fails"
    );
    assert_eq!(
        logged
            .iter()
            .filter(|event| matches!(event.body, EventBody::AttemptFinished { .. }))
            .count(),
        1,
        "the paid attempt must settle exactly once"
    );
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "a failed question write leaked the oversized unreviewed diff"
    );

    let paths = paths_of(&repo, &run_id);
    fs::remove_file(paths.questions()).expect("remove injected blocker");
    fs::create_dir(paths.questions()).expect("restore questions directory");
    let retry = fake(Effect::EditFile);
    let resumed = resume_with(&resume_options(&repo, &run_id), &retry)
        .expect("resume repairs the projection and remains parked");
    assert_eq!(resumed.outcome(), RunOutcome::Parked, "{resumed:?}");
    assert!(
        retry.adapter.runs().is_empty(),
        "resume paid for an already-settled attempt"
    );
    assert_eq!(task(&resumed, "t1").attempts.len(), 1);
    let question = resumed.questions.first().expect("restored question");
    assert!(
        interaction::answer_path(&paths.questions(), &question.question.id).exists(),
        "resume did not rematerialize the authoritative question"
    );
}

#[test]
fn dirty_tree_is_refused() {
    let repo = temp_engine_repo("dirty");
    fs::write(repo.join("stray.txt"), "uncommitted\n").expect("stray");
    let source = fake(Effect::EditFile);
    let err = run_with(&options(&repo), &source).expect_err("must refuse");
    assert!(err.to_string().contains("not clean"), "got: {err}");
    let branch = git_in(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
    assert_eq!(branch.trim(), "main", "no run branch created");
}

#[test]
fn sparse_checkout_preflight_refusal_leaves_worktree_clean() {
    let repo = temp_engine_repo("sparse-worker-preflight");
    git_in(&repo, &["update-index", "--skip-worktree", "README.md"]);
    let source = fake(Effect::EditFile);

    let error = run_with(&options(&repo), &source)
        .expect_err("incomplete materialization must be refused")
        .to_string();
    assert!(error.contains("sparse checkout is active"), "{error}");
    assert!(
        source.adapter.runs().is_empty(),
        "a worker was dispatched before sparse-checkout refusal"
    );
    assert_eq!(
        git_in(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]).trim(),
        "main",
        "preflight refusal must not create or switch a run branch"
    );
    git_in(&repo, &["update-index", "--no-skip-worktree", "README.md"]);
    let worktree_git_dir = Workspace::open(&repo)
        .expect("open worktree")
        .worktree_git_dir()
        .expect("resolve private git dir");
    assert!(
        worktree_git_dir.join("tactus-worktree.lock").exists(),
        "the regression must exercise acquisition of the private worktree lease"
    );
    assert!(
        !repo.join(".tactus").exists(),
        "a refused preflight must not create working-tree coordinator state"
    );
    assert!(
        git_in(&repo, &["status", "--porcelain", "--untracked-files=all"])
            .trim()
            .is_empty(),
        "a refused preflight left coordinator state visible to Git"
    );
}

#[test]
fn passing_configured_gates_commit_and_are_reported() {
    let repo = temp_engine_repo("gatepass");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 depends= -->\n",
        Some("[[gates]]\nname = \"version\"\ncmd = \"git --version\"\n"),
    );

    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "report: {report:?}");
    assert_eq!(report.gates, ["version"]);
    assert!(report.gates_from_config);
    assert!(report.render().contains("gates: version [from config]"));
}

#[test]
fn ignored_worker_input_cannot_make_a_gate_pass() {
    let repo = temp_engine_repo("ignored-gate-input");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [[gates]]\nname = \"ignored-input\"\ncmd = \"git hash-object ignored.flag\"\n",
        ),
    );

    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::IgnoredGateInput);
    let report = run_with(&opts, &source).expect("gate failure settles the task");

    assert!(!committed(&report, "t1"), "report: {report:?}");
    assert!(task(&report, "t1").attempts.iter().any(|attempt| {
        attempt
            .failure
            .as_ref()
            .is_some_and(|failure| failure.kind == FailureKind::GateFailed)
    }));
    assert!(
        !repo.join("ignored.flag").exists(),
        "ignored worker-only input was cleaned from the authoritative workspace"
    );
}

#[test]
fn unresolvable_gate_refuses_at_preflight() {
    let repo = temp_engine_repo("gateresolve");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 depends= -->\n",
        Some("[[gates]]\nname = \"ghost\"\ncmd = \"definitely-not-a-real-tool-xyz build\"\n"),
    );

    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let err = run_with(&opts, &source).expect_err("must refuse");
    assert!(err.to_string().contains("not found on PATH"), "got: {err}");
    let branch = git_in(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
    assert_eq!(branch.trim(), "main", "refused before branching");
}

#[test]
fn test_task_without_test_code_fails_provenance() {
    let repo = temp_engine_repo("provenance");
    seed(
        &repo,
        "## Test the widget\n<!-- tactus: id=tt depends= -->\nAdd coverage.\n",
        // One rung, one attempt: the provenance failure is what is under
        // test, not the ladder's reaction to it.
        Some("[routing]\ntest = { chain = [\"small\"], attempts_per = 1 }\n"),
    );

    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let report = run_with(&opts, &source).expect("engine ok");
    let reason = &task(&report, "tt").attempts[0]
        .failure
        .as_ref()
        .expect("provenance should fail")
        .reason;
    assert!(reason.contains("provenance"), "reason: {reason}");
}

#[test]
fn test_task_adding_real_tests_passes_provenance() {
    let repo = temp_engine_repo("provenance-ok");
    seed(
        &repo,
        "## Test the widget\n<!-- tactus: id=tt depends= -->\n",
        None,
    );

    let source = fake(Effect::EditTest);
    let report = run_with(&options(&repo), &source).expect("engine ok");
    assert_eq!(report.outcome(), RunOutcome::Complete, "report: {report:?}");
    assert!(committed(&report, "tt"));
}

#[test]
fn gate_residue_is_scrubbed_not_committed() {
    let repo = temp_engine_repo("residue");
    // A gate that creates a file: residue must never reach a commit nor
    // survive the task.
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 depends= -->\n",
        Some("[[gates]]\nname = \"leaky\"\ncmd = \"echo residue> residue.txt\"\n"),
    );

    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "report: {report:?}");
    assert!(!repo.join("residue.txt").exists(), "residue scrubbed");
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "clean tree after run"
    );
    let log = git_in(&repo, &["log", "--name-only", "--format=", "main..HEAD"]);
    assert!(!log.contains("residue.txt"), "log: {log}");
}

#[test]
fn the_reviewer_is_read_only_and_bound_to_the_review_tier() {
    let repo = temp_engine_repo("reviewbinding");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");
    let settings = paths_of(&repo, &report.run_id).settings();
    let allow_list = |file: &str| -> Vec<String> {
        let text = fs::read_to_string(settings.join(file)).expect("settings written");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        value["permissions"]["allow"]
            .as_array()
            .expect("allow list")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_owned())
            .collect()
    };

    let reviewer = allow_list("00-t1-1-review.json");
    assert_eq!(reviewer, ["Read", "Glob", "Grep"], "read-only, no shell");

    let implementer = allow_list("00-t1-1.json");
    assert!(
        implementer.contains(&"Edit".to_owned()),
        "implementer can edit"
    );

    // §15 split: the file describing an agent's own sandbox is not
    // somewhere that agent can read.
    assert!(
        !settings.starts_with(&repo),
        "settings live outside the workspace: {}",
        settings.display()
    );
}

#[test]
fn review_can_be_switched_off_explicitly() {
    let repo = temp_engine_repo("noreview");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 depends= -->\n",
        Some("[routing]\nreview = { enabled = false }\n"),
    );

    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // A reviewer that would REJECT everything: if review still ran, the
    // task would never commit.
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Fail]);
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "report: {report:?}");
    assert!(report.tasks[0].review_models.is_empty());
    assert!(report.tasks[0].review_cost_usd.is_none());
}

#[test]
fn reviewer_spend_is_attributed_separately() {
    let repo = temp_engine_repo("reviewcost");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");
    let t1 = task(&report, "t1");
    assert_eq!(t1.cost_usd, Some(0.01), "implementer's own spend");
    assert_eq!(t1.review_cost_usd, Some(0.05), "reviewer's, kept apart");
    assert_eq!(t1.review_models, ["claude-opus-5"]);
    assert!((t1.total_cost_usd().expect("both") - 0.06).abs() < 1e-9);
    let rendered = report.render();
    assert!(rendered.contains("+ review claude-opus-5"), "{rendered}");
}

// ---- step 9: cross-vendor review (§11.3) -----------------------------

/// A plan whose one task runs at frontier and touches `src/auth/**`, so
/// both step-9 mechanisms are in play: its implementer binds to the same
/// model as the reviewer, and its paths can match a `second_opinion`
/// override.
const FRONTIER_AUTH_PLAN: &str = "## Rotate the signing key\n\
         <!-- tactus: id=t1 kind=implement depends= tier=frontier paths=src/auth/** -->\n\
         Rotate it.\n";

const SECOND_OPINION_CONFIG: &str = "[routing]\n\
         implement = { chain = [\"frontier\"], attempts_per = 1 }\n\n\
         [[routing.overrides]]\n\
         paths = [\"src/auth/**\"]\n\
         second_opinion = \"different-vendor\"\n";

/// Same task, no override — the implicit anti-self-review path.
const FRONTIER_ONLY_CONFIG: &str =
    "[routing]\nimplement = { chain = [\"frontier\"], attempts_per = 1 }\n";

fn cross_vendor_opts(repo: &Path) -> RunOptions {
    let mut opts = options(repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts
}

#[test]
fn a_second_opinion_runs_a_second_family_and_leaves_the_primary_alone() {
    // §11.3: both verdicts must pass. And the primary must NOT rebind here
    // even though it matches the implementer — rebinding would resolve both
    // passes to copilot/gpt-5.3-codex and drop the Anthropic review entirely, which
    // is worse than the self-review the rebind exists to prevent.
    let repo = temp_engine_repo("secondopinion");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");

    assert!(committed(&report, "t1"), "both passed: {report:?}");
    let t1 = task(&report, "t1");
    assert_eq!(
        t1.review_models,
        ["claude-opus-5", "gpt-5.3-codex"],
        "one pass per family, primary first"
    );
    assert_eq!(t1.model, "claude-opus-5", "written by the frontier model");
    assert_eq!(source.adapter.reviews_run(), 1);
    assert_eq!(source.copilot().reviews_run(), 1);
    // Both reviewers' spend lands in the review column, not the worker's.
    assert_eq!(t1.review_cost_usd, Some(0.10), "0.05 per pass");
    assert_eq!(t1.cost_usd, Some(0.01), "implementer's own");
    let rendered = report.render();
    assert!(
        rendered.contains("+ review claude-opus-5, gpt-5.3-codex"),
        "{rendered}"
    );
}

#[test]
fn a_second_opinion_that_fails_fails_the_attempt() {
    // The point of two passes: the one that says no decides, even when the
    // first already approved.
    let repo = temp_engine_repo("secondopinionfail");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::Fail],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");

    assert!(!committed(&report, "t1"), "a rejected change cannot commit");
    let t1 = task(&report, "t1");
    let last = t1.attempts.last().expect("an attempt ran");
    assert_eq!(
        last.failure.as_ref().map(|f| f.kind),
        Some(FailureKind::ReviewFailed)
    );
    assert_eq!(
        last.reviews.iter().map(|r| r.outcome).collect::<Vec<_>>(),
        [
            events::ReviewPassOutcome::Passed,
            events::ReviewPassOutcome::Failed
        ],
        "the record says which pass objected, and that it really judged"
    );
    assert_eq!(last.reviews[1].agent, "copilot");
}

#[test]
fn a_failing_first_pass_never_spends_the_second_reviewer() {
    // Passes short-circuit like gates do (§11.1): once one has said no, a
    // second opinion on the same diff changes nothing and costs a frontier
    // invocation to learn it.
    let repo = temp_engine_repo("shortcircuit");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Fail],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");

    assert!(!committed(&report, "t1"));
    assert_eq!(source.adapter.reviews_run(), 1);
    assert_eq!(
        source.copilot().reviews_run(),
        0,
        "the second vendor was never asked"
    );
    let last = task(&report, "t1").attempts.last().expect("attempt");
    assert_eq!(last.reviews.len(), 1, "only what actually ran is recorded");
}

#[test]
fn a_frontier_task_is_not_reviewed_by_the_model_that_wrote_it() {
    // The item carried since step 6: both binders resolve `frontier`
    // identically, so without the rebind the reviewer IS the implementer.
    let repo = temp_engine_repo("selfreview");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(FRONTIER_ONLY_CONFIG));
    // The claude adapter's review script says FAIL and the copilot one says
    // PASS, so a committed task proves which of them was actually asked.
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Fail],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");

    assert!(committed(&report, "t1"), "{report:?}");
    assert_eq!(task(&report, "t1").review_models, ["gpt-5.3-codex"]);
    assert_eq!(source.adapter.reviews_run(), 0, "never judged its own work");
    assert_eq!(source.copilot().reviews_run(), 1);
}

#[test]
fn a_lower_rung_keeps_the_frontier_reviewer() {
    // A mid-tier implementer judged by the frontier reviewer is already a
    // genuine second look, so nothing rebinds. Triggering on family
    // similarity instead of exact identity would send most of a run
    // cross-vendor for no verification gain.
    let repo = temp_engine_repo("noneedtorebind");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"mid\"], attempts_per = 1 }\n"),
    );
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");

    assert_eq!(task(&report, "t1").model, "claude-sonnet-5");
    assert_eq!(task(&report, "t1").review_models, ["claude-opus-5"]);
    assert_eq!(source.copilot().reviews_run(), 0);
}

#[test]
fn a_configured_second_opinion_with_no_second_family_refuses_before_spending() {
    // Step-6 finding #10's posture: the operator asked for two model
    // families on their blast-radius paths. Quietly giving them one is the
    // failure that finding exists to prevent, so this refuses instead.
    let repo = temp_engine_repo("nosecondfamily");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Pass]);
    let error = run_with(&cross_vendor_opts(&repo), &source)
        .expect_err("a promised reviewer that cannot exist must stop the run");
    let message = error.to_string();
    assert!(message.contains("t1"), "names the task: {message}");
    assert!(
        message.contains("src/auth/**"),
        "names the override: {message}"
    );
    assert!(
        message.contains("second opinion"),
        "says what is missing: {message}"
    );
    assert_eq!(source.adapter.runs().len(), 0, "nothing was spent");
}

#[test]
fn without_a_second_vendor_self_review_warns_rather_than_refusing() {
    // The implicit rebind is tactus's own idea, not the operator's, so a
    // single-vendor machine loses the upgrade rather than the run — but it
    // is told, because a verification property that quietly is not there is
    // exactly what step 6 objected to.
    let repo = temp_engine_repo("selfreviewwarn");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(FRONTIER_ONLY_CONFIG));
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Pass]);
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run still works");

    assert!(committed(&report, "t1"));
    assert_eq!(task(&report, "t1").review_models, ["claude-opus-5"]);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("t1") && w.contains("also the reviewer")),
        "warnings: {:?}",
        report.warnings
    );
}

#[test]
fn an_unprobeable_cross_family_reviewer_downgrades_instead_of_halting() {
    // Installed but broken is different from absent, and the two probe
    // classes have to agree about which is which: the opportunistic
    // reviewer only warns.
    let repo = temp_engine_repo("brokencopilot");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(FRONTIER_ONLY_CONFIG));
    let source = FakeSource {
        adapter: FakeAdapter::new(vec![Effect::EditFile], vec![ReviewBehavior::Pass]),
        copilot: Some(FakeAdapter::copilot(vec![ReviewBehavior::Pass]).broken("not logged in")),
    };
    let report =
        run_with(&cross_vendor_opts(&repo), &source).expect("a broken upgrade is not a broken run");

    assert!(committed(&report, "t1"));
    assert_eq!(
        task(&report, "t1").review_models,
        ["claude-opus-5"],
        "fell back to same-model review"
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("not logged in") && w.contains("same-model review")),
        "warnings: {:?}",
        report.warnings
    );
    // And it names the tasks. Resolution cannot reach this warning — a
    // shipped binary always has the Copilot adapter, so the only way the
    // rebind really goes missing is a probe failure, and a warning that
    // never fires for a real user is not a warning.
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("t1") && w.contains("also the reviewer")),
        "warnings: {:?}",
        report.warnings
    );
}

#[test]
fn the_same_broken_reviewer_is_fatal_when_the_config_asked_for_it() {
    // Same machine, same breakage — but now a `second_opinion` names it, so
    // it is load-bearing rather than opportunistic.
    let repo = temp_engine_repo("brokenrequired");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = FakeSource {
        adapter: FakeAdapter::new(vec![Effect::EditFile], vec![ReviewBehavior::Pass]),
        copilot: Some(FakeAdapter::copilot(vec![ReviewBehavior::Pass]).broken("not logged in")),
    };
    let error = run_with(&cross_vendor_opts(&repo), &source)
        .expect_err("a required reviewer that cannot run stops the run");
    assert!(error.to_string().contains("not logged in"), "got: {error}");
}

#[test]
fn a_resume_keeps_the_reviewers_the_run_started_with() {
    // Who judged this run is a fact about the run, not about today's
    // machine — step-8 finding #8's lesson on `private_dir`. Re-deriving it
    // would let a CLI installed since the run began become the judge for
    // the back half, leaving one run with two verification standards.
    //
    // The work left over has to be work the rebind would OTHERWISE claim,
    // or this proves nothing: the task resumed onto is at frontier, where
    // the implementer and the reviewer are the same model.
    let repo = temp_engine_repo("resumereviewers");
    seed(
        &repo,
        "## Rotate the signing key\n\
             <!-- tactus: id=t1 kind=implement depends= tier=frontier -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"frontier\"], attempts_per = 1 }\n",
        ),
    );

    // First process: no copilot on the machine, and the agent changes
    // nothing — so t1 exhausts its chain and parks, still unbuilt.
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let first = run_with(&cross_vendor_opts(&repo), &source).expect("run");
    assert!(
        matches!(task(&first, "t1").status, TaskRunStatus::Parked { .. }),
        "{first:?}"
    );

    let paths = paths_of(&repo, &first.run_id);
    let recorded = {
        let mut warnings = Vec::new();
        let events = events::read_all(&paths.events(), &mut warnings).expect("log");
        events::started_of(&events, &paths.events())
            .expect("run_started")
            .reviews
            .clone()
    };
    let recorded = recorded.expect("step 9 records who reviews");
    assert_eq!(
        recorded.alternative, None,
        "there was nothing to rebind to when this run started"
    );
    assert_eq!(recorded.pass_timeout_secs, Some(5400));

    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"frontier\"], attempts_per = 1 }\n\
             review = { timeout_secs = 60 }\n",
    )
    .expect("edit only the future review timeout");

    crate::answer::answer(
        &repo,
        &first.questions[0].question.id.to_string(),
        crate::answer::Reply::Text("put the key in src/auth/keys.rs".to_owned()),
    )
    .expect("answer");

    // Second process: copilot has appeared since. The record still rules,
    // so the retry is judged by the model the run started with.
    let later = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::Pass],
    );
    let resumed =
        resume_with(&resume_options(&repo, &first.run_id), &later).expect("resume continues");

    assert!(committed(&resumed, "t1"), "{resumed:?}");
    assert_eq!(
        task(&resumed, "t1").review_models,
        ["claude-opus-5"],
        "the recorded reviewer judged the resumed attempt"
    );
    assert_eq!(
        later.copilot().reviews_run(),
        0,
        "a CLI installed since the run began must not become its judge"
    );
    let warning = resumed
        .warnings
        .iter()
        .find(|warning| warning.contains("review pass timeout"))
        .unwrap_or_else(|| panic!("no timeout-difference warning: {:?}", resumed.warnings));
    assert!(warning.contains("60s"), "{warning}");
    assert!(warning.contains("5400s"), "{warning}");
    assert!(warning.contains("Start a new run"), "{warning}");
}

#[test]
fn resume_runs_with_the_effort_policy_the_run_recorded_not_todays_config() {
    let original = "[interaction]\nmode = \"never\"\n\n\
                        [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                        [routing.effort]\nimplementation = \"xhigh\"\nreview = \"max\"\n";
    let (repo, run_id) = parked_run_with_config("resumeeffort", original);
    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
             [routing.effort]\nimplementation = \"low\"\nreview = \"high\"\n",
    )
    .expect("edit effort only");

    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    let logged = events_of(&repo, &run_id);
    let resumed_worker = logged
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::AttemptStarted { data, .. } => Some(data),
            _ => None,
        })
        .next_back()
        .expect("resumed worker start");
    assert_eq!(resumed_worker.effort, Some(Effort::XHigh));
    let resumed_reviews = logged
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::AttemptFinished { data, .. } if !data.reviews.is_empty() => {
                Some(&data.reviews)
            }
            _ => None,
        })
        .next_back()
        .expect("resumed review records");
    assert!(
        resumed_reviews
            .iter()
            .all(|review| review.effort == Some(Effort::Max)),
        "every review pass keeps max: {resumed_reviews:?}"
    );
    let warning = resumed
        .warnings
        .iter()
        .find(|warning| warning.contains("today's effort policy"))
        .unwrap_or_else(|| panic!("no effort difference warning: {:?}", resumed.warnings));
    assert!(warning.contains("implementation small=low"), "{warning}");
    assert!(warning.contains("implementation small=xhigh"), "{warning}");
    assert!(warning.contains("review=max"), "{warning}");
    assert!(warning.contains("Start a new run"), "{warning}");
}

#[test]
fn resume_restores_the_recorded_worker_binding_before_preflight() {
    let original = "[interaction]\nmode = \"never\"\n\n\
                        [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n";
    let (repo, run_id) = parked_run_with_config("resumebinding", original);
    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
             [[pins]]\ntier = \"small\"\nagent = \"copilot\"\nmodel = \"gpt-5-mini\"\n",
    )
    .expect("edit only the binding");

    // `resume_answering` exposes only the Claude fake. If pre-flight probes
    // today's Copilot pin before restoring the record, this refuses before
    // the behavioral assertions below can run.
    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    let logged = events_of(&repo, &run_id);
    let worker = logged
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::AttemptStarted { data, .. } => Some(data),
            _ => None,
        })
        .next_back()
        .expect("resumed worker");
    assert_eq!(worker.agent, "claude-code");
    assert_eq!(worker.model, "claude-haiku-4-5");
    assert_eq!(
        worker.selection_origin,
        Some(events::SelectionOrigin::Auto),
        "the recorded absence of a pin is part of the snapshot too"
    );
    assert!(
        resumed
            .warnings
            .iter()
            .any(|warning| warning.contains("today's worker bindings")
                && warning.contains("gpt-5-mini")
                && warning.contains("claude-haiku-4-5")),
        "binding difference warning: {:?}",
        resumed.warnings
    );
}

#[test]
fn the_resume_that_rederives_an_old_logs_effort_records_it_for_the_next_one() {
    let original = "[interaction]\nmode = \"never\"\n\n\
                        [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                        [routing.effort]\nimplementation = \"xhigh\"\nreview = \"max\"\n";
    let (repo, run_id) = parked_run_with_config("oldlogeffort", original);
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_one(&paths, &["effort_policy"]);

    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
             [routing.effort]\nimplementation = \"high\"\nreview = \"xhigh\"\n",
    )
    .expect("first derived policy");
    let first = resume_answering(&repo, &run_id, Effect::NoEdit);
    assert_eq!(first.outcome(), RunOutcome::Parked, "{first:?}");
    assert!(
        first
            .warnings
            .iter()
            .any(|warning| warning.contains("predates the effort-policy record")),
        "legacy warning: {:?}",
        first.warnings
    );
    let established = ResolvedEffortPolicy {
        small: Effort::High,
        mid: Effort::High,
        frontier: Effort::High,
        review: Effort::XHigh,
    };
    assert_eq!(
        events::recorded_effort_policy(&events_of(&repo, &run_id)),
        Some(established),
        "the first resume writes down what it derived"
    );
    let after_first = events_of(&repo, &run_id);
    assert!(events::recorded_chains(&after_first).is_some());
    assert_eq!(
        after_first
            .iter()
            .filter(|event| matches!(event.body, EventBody::RunSchemaUpgraded { .. }))
            .count(),
        1,
        "the first current-binary resume appends one downgrade barrier"
    );

    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
             [routing.effort]\nimplementation = \"low\"\nreview = \"medium\"\n",
    )
    .expect("later policy");
    let second = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(second.outcome(), RunOutcome::Complete, "{second:?}");
    let logged = events_of(&repo, &run_id);
    let worker = logged
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::AttemptStarted { data, .. } => Some(data),
            _ => None,
        })
        .next_back()
        .expect("second resumed worker");
    assert_eq!(worker.effort, Some(Effort::High));
    let reviews = logged
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::AttemptFinished { data, .. } if !data.reviews.is_empty() => {
                Some(&data.reviews)
            }
            _ => None,
        })
        .next_back()
        .expect("second resumed reviews");
    assert!(
        reviews
            .iter()
            .all(|review| review.effort == Some(Effort::XHigh)),
        "reviews retain the established legacy policy: {reviews:?}"
    );
    assert!(
        second
            .warnings
            .iter()
            .any(|warning| warning.contains("today's effort policy")),
        "the later edit is reported: {:?}",
        second.warnings
    );
    assert!(
        !second
            .warnings
            .iter()
            .any(|warning| warning.contains("predates the effort-policy record")),
        "the legacy absence was established once: {:?}",
        second.warnings
    );
    assert_eq!(
        events_of(&repo, &run_id)
            .iter()
            .filter(|event| matches!(event.body, EventBody::RunSchemaUpgraded { .. }))
            .count(),
        1,
        "later resumes must not append duplicate schema transitions"
    );
}

#[test]
fn the_resume_that_rederives_an_old_review_plan_records_it_for_the_next_one() {
    let original = "[interaction]\nmode = \"never\"\n\n\
                        [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n";
    let (repo, run_id) = parked_run_with_config("oldlogreviews", original);
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_two(&paths);
    strip_run_started_field(&paths, "reviews");

    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\
             review = { timeout_secs = 60 }\n",
    )
    .expect("first derived review plan");
    let first = resume_answering(&repo, &run_id, Effect::NoEdit);
    assert_eq!(first.outcome(), RunOutcome::Parked, "{first:?}");
    assert!(
        first
            .warnings
            .iter()
            .any(|warning| warning.contains("predates the review record")),
        "legacy warning: {:?}",
        first.warnings
    );
    let established = events::recorded_reviews(&events_of(&repo, &run_id))
        .cloned()
        .expect("the first resume writes down what it derived");
    assert_eq!(established.pass_timeout_secs, Some(60));

    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\
             review = { timeout_secs = 120 }\n",
    )
    .expect("later review plan");
    let second = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(second.outcome(), RunOutcome::Complete, "{second:?}");
    assert_eq!(
        events::recorded_reviews(&events_of(&repo, &run_id))
            .expect("record survives")
            .pass_timeout_secs,
        Some(60),
        "a later config edit cannot replace the established plan"
    );
    let warning = second
        .warnings
        .iter()
        .find(|warning| warning.contains("today's review pass timeout"))
        .unwrap_or_else(|| panic!("no timeout drift warning: {:?}", second.warnings));
    assert!(warning.contains("120s"), "{warning}");
    assert!(warning.contains("60s"), "{warning}");
    assert!(
        !second
            .warnings
            .iter()
            .any(|warning| warning.contains("predates the review record")),
        "the legacy absence is established exactly once: {:?}",
        second.warnings
    );
}

#[test]
fn a_schema_two_resume_records_the_complete_review_barrier_before_work() {
    let (repo, run_id) = parked_run("schema2reviewbarrier");
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_two(&paths);
    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\
             review = { timeout_secs = 47 }\n",
    )
    .expect("first explicit complete-review timeout");

    let resumed = resume_answering(&repo, &run_id, Effect::NoEdit);
    assert_eq!(resumed.outcome(), RunOutcome::Parked, "{resumed:?}");

    let logged = events_of(&repo, &run_id);
    let barrier = logged
        .iter()
        .position(|event| {
            matches!(
                &event.body,
                EventBody::RunSchemaUpgraded { data }
                    if data.from == 2 && data.to == events::SCHEMA_VERSION
            )
        })
        .expect("schema 2 -> 3 downgrade barrier");
    let resumed_attempt = logged
        .iter()
        .enumerate()
        .skip(barrier + 1)
        .find(|(_, event)| matches!(event.body, EventBody::AttemptStarted { .. }))
        .map(|(index, _)| index)
        .expect("resumed attempt after the barrier");
    assert!(
        barrier < resumed_attempt,
        "the old verification contract must be fenced off before work starts"
    );
    let upgraded_reviews = events::recorded_complete_reviews(&logged)
        .expect("schema-3 resume records a complete review plan");
    assert_eq!(upgraded_reviews.pass_timeout_secs, Some(47));
    assert_eq!(upgraded_reviews.enabled, Some(true));
    assert_eq!(
        upgraded_reviews.alternative_available,
        Some(upgraded_reviews.alternative.is_some())
    );
    assert_eq!(upgraded_reviews.second_opinion.len(), 1);

    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\
             review = { timeout_secs = 83 }\n",
    )
    .expect("later configured timeout");
    let second = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(second.outcome(), RunOutcome::Complete, "{second:?}");
    assert_eq!(
        events::recorded_reviews(&events_of(&repo, &run_id))
            .expect("upgraded review plan survives")
            .pass_timeout_secs,
        Some(47),
        "a later binary/config default cannot reinterpret the upgraded timeout"
    );
    assert!(
        second.warnings.iter().any(|warning| {
            warning.contains("today's review pass timeout")
                && warning.contains("83s")
                && warning.contains("47s")
        }),
        "timeout drift warning: {:?}",
        second.warnings
    );
}

#[test]
fn max_parallel_above_one_refuses_before_the_run_touches_the_workspace() {
    // The config refusal is only worth having if it lands before the run has
    // done anything an operator must undo. Pre-flight loads the config ahead of
    // the run id, the run directory, the run lock, and the branch — so a
    // ceiling this engine cannot honour leaves the repository exactly as it
    // was, rather than a husk under `.tactus/runs` that `latest_run` then
    // reports on in place of the real one.
    let repo = temp_engine_repo("maxparallelrefusal");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[engine]\nmax_parallel = 3\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let head_before = git_in(&repo, &["rev-parse", "HEAD"]);
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);

    let error = run_with(&opts, &source).expect_err("a refused ceiling must not start a run");
    assert!(error.to_string().contains("max_parallel = 3"), "{error}");

    assert!(
        source.adapter.runs().is_empty(),
        "nothing may be spawned, let alone paid for"
    );
    assert!(
        rundir::list_runs(&repo).is_empty(),
        "no run directory: {:?}",
        rundir::list_runs(&repo)
    );
    assert_eq!(
        git_in(&repo, &["branch", "--list", "tactus/run-*"]),
        "",
        "no run branch"
    );
    assert_eq!(git_in(&repo, &["rev-parse", "HEAD"]), head_before);
    assert_eq!(
        git_in(&repo, &["status", "--porcelain"]),
        "",
        "working tree untouched"
    );
}

/// Where this repository's worktree lease file would be, held or not.
fn worktree_lock_path(repo: &Path) -> PathBuf {
    Workspace::open(repo)
        .expect("workspace")
        .worktree_git_dir()
        .expect("worktree git dir")
        .join("tactus-worktree.lock")
}

#[test]
fn a_refused_ceiling_beats_the_lease_rather_than_racing_it() {
    // The ordering claim itself, tested where cleanup cannot fake it.
    //
    // A run that took the lease, *then* read the config, then tidied up on its
    // way out would leave a repository indistinguishable from this one — so an
    // end-state assertion proves nothing about when the config was read. These
    // two do:
    //
    //  (a) The lock file is created by acquisition and is never removed by
    //      release, by design (a killed engine must leave nothing to clear by
    //      hand, and the OS releases the hold; the file stays). Its absence is
    //      therefore proof that acquisition never happened, not proof that it
    //      was undone.
    //
    //  (b) With a competing holder already on the lease, an acquisition-first
    //      order cannot produce a config error at all: the acquisition is what
    //      fails, and the operator is told another process owns the worktree —
    //      the wrong diagnosis for a file they can fix in five seconds. Move
    //      `validate_inputs` back below `WorktreeLock::acquire_in` and this
    //      half fails no matter what any cleanup does afterwards.
    let repo = temp_engine_repo("ceilingbeforelease");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[engine]\nmax_parallel = 3\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let lease = worktree_lock_path(&repo);
    assert!(
        !lease.exists(),
        "the fixture has never taken the lease, so the file cannot exist yet"
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));

    // (a) Uncontended: the refusal must not have created the lease file.
    let source = fake(Effect::EditFile);
    let refused = run_with(&opts, &source)
        .expect_err("a ceiling this engine cannot honour must not start a run")
        .to_string();
    assert!(refused.contains("max_parallel = 3"), "{refused}");
    assert!(
        !lease.exists(),
        "the worktree lock file at {} was created before the config was read",
        lease.display()
    );

    // (b) Contended: the config error must still be the one that comes back.
    let competitor = WorktreeLock::acquire(&repo).expect("a competing holder takes the lease");
    assert!(
        lease.exists(),
        "the competing holder is what creates the file, which is how (a) means anything"
    );
    let contended = run_with(&opts, &source)
        .expect_err("a refused ceiling still refuses while somebody holds the lease")
        .to_string();
    assert!(
        contended.contains("max_parallel = 3"),
        "the config error must win the race it never needed to enter: {contended}"
    );
    assert!(
        !contended.contains("another tactus process"),
        "lock contention must not be the diagnosis for a config error: {contended}"
    );
    drop(competitor);

    assert!(
        source.adapter.runs().is_empty(),
        "nothing may be spawned, let alone paid for"
    );
    assert!(
        rundir::list_runs(&repo).is_empty(),
        "and no run directory: {:?}",
        rundir::list_runs(&repo)
    );
}

#[test]
fn a_refused_ceiling_beats_both_locks_on_resume() {
    // The same claim for the other write command, which takes two locks rather
    // than one. `max_per_agent = 0` is the ceiling to test a resume's ordering
    // with: the legacy reading below softens `max_parallel > 1` for a run that
    // is already sequential, but a limit with no meaning at all is refused for
    // fresh runs and resumes alike, so this refusal is genuinely about *when*.
    let (repo, run_id) = parked_run("resumeceilingbeforelocks");
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_two(&paths);
    fs::write(
        repo.join("tactus.toml"),
        format!("{PARKED_RUN_CONFIG}\n[engine]\nmax_per_agent = 0\n"),
    )
    .expect("today's config");

    // The fixture run created both lock files. Remove them, so that a file
    // found afterwards is evidence about this resume rather than history.
    let lease = worktree_lock_path(&repo);
    let run_lock = rundir::lock_file(&paths.public);
    for path in [&lease, &run_lock] {
        fs::remove_file(path).unwrap_or_else(|error| {
            panic!("the fixture run left {}: {error}", path.display());
        });
    }

    let refused = resume_err(&repo, &run_id);
    assert!(refused.contains("max_per_agent"), "{refused}");
    assert!(
        !lease.exists(),
        "the worktree lease was taken before the config was read"
    );
    assert!(
        !run_lock.exists(),
        "the run lock was taken before the config was read"
    );

    // And with the lease already held, so that an acquisition-first order
    // could only ever answer with contention.
    let competitor = WorktreeLock::acquire(&repo).expect("a competing holder takes the lease");
    let contended = resume_err(&repo, &run_id);
    assert!(
        contended.contains("max_per_agent"),
        "the config error must win the race it never needed to enter: {contended}"
    );
    assert!(
        !contended.contains("another tactus process"),
        "lock contention must not be the diagnosis for a config error: {contended}"
    );
    drop(competitor);
    assert!(
        !run_lock.exists(),
        "and the run lock stays untaken either way"
    );
}

/// A config with a distinguishable, harmless ceiling in it.
///
/// `max_merge_repairs` is the right knob for the tests below: it is kept
/// verbatim by every reading, it loads without refusing, and its value is
/// visible on the `Analysis` — so "which bytes produced this analysis" has a
/// direct answer rather than an inferred one.
fn config_with_repairs(repairs: u32) -> String {
    format!(
        "[engine]\nmax_merge_repairs = {repairs}\n\n\
         [routing]\nimplement = {{ chain = [\"small\"], attempts_per = 1 }}\n"
    )
}

#[test]
fn the_analysis_adopted_under_the_lease_is_the_one_its_own_bytes_were_validated_from() {
    // The pre-lock check answers "may this start", from files the worktree did
    // not yet belong to this run. Adopting *that* analysis afterwards would
    // execute an answer about bytes that no longer exist, so what the lease
    // holder adopts is an analysis it captured and validated itself — on the
    // condition that the two captures agree about what it was reading.
    let repo = temp_engine_repo("confirmunderlease");
    let config = repo.join("tactus.toml");
    let mut opts = options(&repo);
    opts.config_path = Some(config.clone());

    // (a) A change that is still there at the lease is adopted, not papered
    //     over with the pre-lock reading. Nothing here is refused: the point is
    //     that a stale-adopting implementation returns 5 and a re-validating
    //     one returns 7, and only one of those is the config the run will hold.
    fs::write(&config, config_with_repairs(5)).expect("the config before the lease");
    let validated = validate_inputs(&opts, config::EngineLimits::Fresh).expect("pre-lock check");
    fs::write(&config, config_with_repairs(7)).expect("the config at the lease");
    let analysis = validated
        .confirm_under_lease(&opts, config::EngineLimits::Fresh)
        .expect("a valid config is still valid");
    assert_eq!(
        analysis.config.max_merge_repairs, 7,
        "the adopted analysis must describe the bytes the run is holding"
    );

    // (b) And if the change is one this engine must refuse, it refuses — under
    //     the lease rather than never. A run whose config was checked in an
    //     earlier life and replaced since is a run executing something nothing
    //     ever validated, which is the whole defect.
    fs::write(&config, config_with_repairs(5)).expect("the config before the lease");
    let validated = validate_inputs(&opts, config::EngineLimits::Fresh).expect("pre-lock check");
    fs::write(
        &config,
        "[engine]\nmax_parallel = 3\n\n\
         [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
    )
    .expect("a ceiling this engine cannot honour");
    let refused = validated
        .confirm_under_lease(&opts, config::EngineLimits::Fresh)
        .expect_err("an unhonourable ceiling must not be adopted because an older file was fine")
        .to_string();
    assert!(refused.contains("max_parallel = 3"), "{refused}");

    // (c) The A-to-B-to-A interleaving, end to end. The excursion is invisible
    //     to both captures — which is precisely why the analysis may not come
    //     from a read taken beside them. It comes from the capture itself, so
    //     what is adopted is A whether or not B ever existed.
    fs::write(&config, config_with_repairs(5)).expect("A");
    let validated = validate_inputs(&opts, config::EngineLimits::Fresh).expect("pre-lock check");
    fs::write(&config, config_with_repairs(9)).expect("B");
    fs::write(&config, config_with_repairs(5)).expect("A again");
    let analysis = validated
        .confirm_under_lease(&opts, config::EngineLimits::Fresh)
        .expect("A is what was captured and A is what is there");
    assert_eq!(
        analysis.config.max_merge_repairs, 5,
        "B was adopted from an excursion neither capture can see"
    );
}

#[test]
fn the_gate_derivation_is_taken_under_the_lease_not_carried_over_it() {
    // The one input `analyze` still reads from the filesystem rather than out
    // of the capture: `gates::derive` is handed a directory. So the derivation
    // has to happen where the worktree is this run's — which means the adopted
    // analysis cannot be the pre-lock one, and the files it looks at have to be
    // in the captured set so that a change to them is a change this confirmation
    // notices.
    let repo = temp_engine_repo("gatesunderlease");
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    fs::write(opts.config_path.as_ref().expect("config path"), "").expect("an empty config");

    let validated = validate_inputs(&opts, config::EngineLimits::Fresh).expect("pre-lock check");
    // The repo becomes a Rust repo between the check and the lease.
    fs::write(repo.join("Cargo.toml"), "[package]\nname = \"x\"\n").expect("a rust repo now");
    let analysis = validated
        .confirm_under_lease(&opts, config::EngineLimits::Fresh)
        .expect("a shape change is not a refusal");
    assert_eq!(
        analysis
            .gates
            .iter()
            .map(|gate| gate.name.clone())
            .collect::<Vec<_>>(),
        vec!["check".to_owned(), "test".to_owned()],
        "the gates a run is held to must be derived from the worktree it holds"
    );
}

/// What two runs of one fixture can never share: their run id, and the two
/// absolute paths their identity is built out of.
fn volatile_strings(repo: &Path, run_id: &str) -> Vec<String> {
    let mut volatile = vec![run_id.to_owned()];
    // Longest first, so a path that contains another is replaced whole.
    for path in [private_root_for(repo), repo.to_path_buf()] {
        let text = path.to_string_lossy().into_owned();
        volatile.push(text.replace('\\', "/"));
        volatile.push(text);
    }
    volatile
}

/// Replace every maximal run of `member` that is exactly `len` long.
///
/// Length-exact and maximal so that content-derived digests keep their meaning:
/// a 16-character plan hash and a 64-character normalized-plan digest are facts
/// two identical fixtures must agree on, and only the 40-character Git object
/// names and the 26-character ULIDs are unshareable.
fn replace_exact_runs(
    text: &str,
    len: usize,
    token: &str,
    member: impl Fn(char) -> bool,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.chars().count() == len {
            out.push_str(token);
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for ch in text.chars() {
        if member(ch) {
            run.push(ch);
            continue;
        }
        flush(&mut run, &mut out);
        out.push(ch);
    }
    flush(&mut run, &mut out);
    out
}

/// One JSON value with everything two runs of one fixture legitimately differ
/// by replaced by a token, in place.
fn canonicalize_json(value: &mut serde_json::Value, volatile: &[String]) {
    match value {
        serde_json::Value::String(text) => {
            let mut canonical = text.clone();
            for needle in volatile {
                canonical = canonical.replace(needle.as_str(), "<volatile>");
            }
            canonical = replace_exact_runs(&canonical, 40, "<sha>", |ch| {
                ch.is_ascii_digit() || ch.is_ascii_lowercase() && ch.is_ascii_hexdigit()
            });
            *text = replace_exact_runs(&canonical, 26, "<ulid>", |ch| {
                ch.is_ascii_digit() || ch.is_ascii_uppercase()
            });
        }
        serde_json::Value::Array(items) => {
            for item in items {
                canonicalize_json(item, volatile);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                // Wall-clock, not meaning. Everything else — cost, usage,
                // effort, tier, model, reviewer, session, rung — is compared.
                if matches!(key.as_str(), "ts" | "duration_ms" | "duration") {
                    *field = serde_json::Value::String(format!("<{key}>"));
                    continue;
                }
                canonicalize_json(field, volatile);
            }
        }
        _ => {}
    }
}

/// One run's log as a semantic trace two runs of the same fixture can be
/// compared by.
///
/// Whole event bodies, not kinds. A config key that changed which reviewer
/// judged the retry, what effort it ran at, how long a review was allowed, or
/// which rung the ladder resumed on would leave the sequence of event kinds and
/// the run's outcome untouched — so comparing those alone would pass on exactly
/// the reinterpretation this exists to rule out.
fn canonical_trace(events: &[events::Event], repo: &Path, run_id: &str) -> Vec<String> {
    let volatile = volatile_strings(repo, run_id);
    events
        .iter()
        .map(|event| {
            let mut value = serde_json::to_value(event).expect("an event serializes");
            canonicalize_json(&mut value, &volatile);
            value.to_string()
        })
        .collect()
}

/// The run's report and every task record in it, canonicalized the same way.
///
/// `warnings` is dropped rather than compared: saying what today's config
/// contains is the one thing the two arms are *supposed* to differ by, and the
/// assertions about it are separate and explicit.
fn canonical_projection(report: &RunReport, repo: &Path, run_id: &str) -> String {
    let volatile = volatile_strings(repo, run_id);
    let mut value = serde_json::to_value(report).expect("a report serializes");
    value
        .as_object_mut()
        .expect("a report is an object")
        .remove("warnings")
        .expect("a report records its warnings");
    canonicalize_json(&mut value, &volatile);
    value.to_string()
}

/// All four §17 ceilings, written the way an operator waiting for the parallel
/// engine would write them — `max_parallel` included, and above 1.
const LEGACY_RESUME_LIMITS: &str = "\n[engine]\nmax_parallel = 2\nmax_merge_repairs = 7\n\
                                    max_per_agent = 4\nmax_per_pool = 5\n";

/// What the control arm appends instead.
///
/// An edit rather than nothing: §14 rolls an interrupted run's uncommitted
/// paths back, so an arm that left `tactus.toml` untouched would record no
/// discard while the other recorded one — a difference about which fixture
/// edited a file, not about what the ceilings did. Both arms edit it; only one
/// says anything.
const LEGACY_RESUME_NO_LIMITS: &str = "\n# no [engine] ceilings in this arm\n";

/// Which resume shape a legacy-limits fixture exercises.
#[derive(Clone, Copy)]
enum LegacyFixture {
    /// The ordinary case: a parked run answered and carried to the end.
    Parked,
    /// A crash prefix: the log ends inside an attempt that never settled, so
    /// the resume has to record the interrupted settlement, refund the rung,
    /// and retry before it can finish. This is where an unacted-on ceiling
    /// would be most tempting to act on, because it is the only path that
    /// re-decides how much of the ladder is left.
    InterruptedAttempt,
}

/// One arm of a legacy-limits comparison: everything two resumes of the same
/// fixture must agree about, plus the warnings they are allowed to differ by.
struct LegacyArm {
    report: RunReport,
    /// Every event, whole, with the tokens two runs cannot share replaced.
    trace: Vec<String>,
    /// The report and its task records, canonicalized the same way.
    projection: String,
    /// The tree the run committed. Content-addressed, so it is directly
    /// comparable across two repositories whose commits can never share a sha.
    tree: String,
    events: Vec<events::Event>,
}

/// Run one legacy fixture twice — once with the four ceilings in today's
/// config, once without — and hand back what each resume did.
fn legacy_resume_pair(tag: &str, fixture: LegacyFixture) -> Vec<LegacyArm> {
    let mut observed = Vec::new();
    for (arm, extra) in [
        ("control", LEGACY_RESUME_NO_LIMITS),
        ("limits", LEGACY_RESUME_LIMITS),
    ] {
        let (repo, run_id) = parked_run(&format!("legacylimits-{tag}-{arm}"));
        let paths = paths_of(&repo, &run_id);
        rewrite_run_started_as_schema_two(&paths);
        if matches!(fixture, LegacyFixture::InterruptedAttempt) {
            truncate_log_after(&paths, "attempt_started");
        }
        fs::write(
            repo.join("tactus.toml"),
            format!("{PARKED_RUN_CONFIG}{extra}"),
        )
        .expect("today's config");

        let report = resume_answering(&repo, &run_id, Effect::EditFile);
        let events = events_of(&repo, &run_id);
        observed.push(LegacyArm {
            trace: canonical_trace(&events, &repo, &run_id),
            projection: canonical_projection(&report, &repo, &run_id),
            tree: git_in(&repo, &["rev-parse", "HEAD^{tree}"]),
            events,
            report,
        });
    }
    observed
}

#[test]
fn a_legacy_resume_is_not_reinterpreted_by_the_new_engine_limits() {
    // The keys are new; the run is not. A resume that reads all four — the one
    // a fresh run refuses among them — must continue exactly as it would have
    // without them, and say so rather than act on them.
    //
    // Proved against a control resume of the identical fixture rather than by
    // reading the resume path: "the engine ignores these fields" is a claim
    // about every line of that path, and only a comparison covers all of them.
    //
    // And compared *semantically*, not by event kinds and an outcome. A ceiling
    // that changed which reviewer judged the retry, what effort it ran at, how
    // long the review was allowed, which rung the ladder resumed on, or what
    // the attempt cost would leave the sequence of event kinds and the final
    // outcome identical — so a comparison that could not see those would pass
    // on exactly the reinterpretation it exists to rule out. Three comparisons
    // together close that: every event body, the report and its task records,
    // and the tree the run actually committed.
    for (fixture, tag) in [
        (LegacyFixture::Parked, "parked"),
        (LegacyFixture::InterruptedAttempt, "interrupted"),
    ] {
        let observed = legacy_resume_pair(tag, fixture);
        let control = &observed[0];
        let limits = &observed[1];

        assert_eq!(
            control.report.outcome(),
            RunOutcome::Complete,
            "the {tag} control resume continues to the end: {:?}",
            control.report
        );
        assert_eq!(
            limits.report.outcome(),
            control.report.outcome(),
            "the new keys must not change how a legacy run ends ({tag})"
        );
        assert_eq!(
            limits.trace, control.trace,
            "nor what it records, nor with what contents, nor in what order ({tag})"
        );
        assert_eq!(
            limits.projection, control.projection,
            "nor what it reports about each task ({tag})"
        );
        assert_eq!(
            limits.tree, control.tree,
            "nor the tree it committed ({tag})"
        );
        assert!(
            !control.tree.is_empty(),
            "the fixture must actually have committed something for that to mean anything"
        );

        // Sequential all the way through, stated as a property of the log
        // rather than of the outcome: one attempt open at a time is what
        // `max_parallel = 2` would have changed if anything acted on it.
        let mut open = 0i32;
        let mut peak = 0i32;
        for event in &limits.events {
            match &event.body {
                EventBody::AttemptStarted { .. } => open += 1,
                // Both settlements close one: a crashed attempt's recovery
                // record is as much an end as a finished one.
                EventBody::AttemptFinished { .. } | EventBody::AttemptInterrupted { .. } => {
                    open -= 1;
                }
                _ => continue,
            }
            peak = peak.max(open);
        }
        assert_eq!(peak, 1, "the resume ran one attempt at a time ({tag})");
        assert_eq!(open, 0, "and settled every one of them ({tag})");

        // Every one of the four is named, and only where it was written.
        for key in [
            "max_parallel",
            "max_merge_repairs",
            "max_per_agent",
            "max_per_pool",
        ] {
            assert!(
                limits
                    .report
                    .warnings
                    .iter()
                    .any(|warning| warning.contains(key) && warning.contains("not acted on")),
                "`{key}` must be reported as unacted-on ({tag}): {:?}",
                limits.report.warnings
            );
            assert!(
                !control
                    .report
                    .warnings
                    .iter()
                    .any(|warning| warning.contains(key)),
                "and only when it was written ({tag}): {:?}",
                control.report.warnings
            );
        }
        assert!(
            limits.report.warnings.iter().any(|warning| {
                warning.contains("max_parallel = 2") && warning.contains("this resume")
            }),
            "and the refused-for-fresh-runs ceiling says which run it is talking about: {:?}",
            limits.report.warnings
        );
    }
}

#[test]
fn schema_two_review_markers_upgrade_independently_of_timeout() {
    let (repo, run_id) = parked_run("schema2reviewmarkers");
    let paths = paths_of(&repo, &run_id);
    let recorded_timeout = events::recorded_reviews(&events_of(&repo, &run_id))
        .and_then(|plan| plan.pass_timeout_secs)
        .expect("current run records a timeout");
    rewrite_run_started_as_schema_two_missing_review_fields(
        &paths,
        &["enabled", "alternative_available"],
    );

    let first = resume_answering(&repo, &run_id, Effect::NoEdit);
    assert_eq!(first.outcome(), RunOutcome::Parked, "{first:?}");
    assert!(
        first
            .warnings
            .iter()
            .any(|warning| warning.contains("explicit reviewer-identity markers")),
        "marker-upgrade warning: {:?}",
        first.warnings
    );
    let upgraded = events::recorded_complete_reviews(&events_of(&repo, &run_id))
        .cloned()
        .expect("schema-3 resume records the complete identity");
    assert_eq!(upgraded.pass_timeout_secs, Some(recorded_timeout));
    assert_eq!(upgraded.enabled, Some(upgraded.primary.is_some()));
    assert_eq!(
        upgraded.alternative_available,
        Some(upgraded.alternative.is_some())
    );

    let second = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(second.outcome(), RunOutcome::Complete, "{second:?}");
    assert_eq!(
        events::recorded_complete_reviews(&events_of(&repo, &run_id)),
        Some(&upgraded),
        "the next replay accepts and preserves the explicit markers"
    );
}

#[test]
fn schema_two_inconsistent_review_identity_is_refused_before_upgrade_and_spend() {
    let (repo, run_id) = parked_run("schema2badreviewidentity");
    let paths = paths_of(&repo, &run_id);
    let text = fs::read_to_string(paths.events()).expect("log");
    let mut rewritten = false;
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            let mut value: serde_json::Value = serde_json::from_str(line).expect("event json");
            if value.get("event").and_then(serde_json::Value::as_str) == Some("run_started") {
                let data = value
                    .get_mut("data")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("run_started data");
                data.insert("schema".to_owned(), serde_json::Value::from(2));
                let reviews = data
                    .get_mut("reviews")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("review plan");
                reviews.insert("enabled".to_owned(), serde_json::Value::Bool(true));
                reviews.insert("primary".to_owned(), serde_json::Value::Null);
                rewritten = true;
            }
            value.to_string()
        })
        .collect();
    assert!(rewritten);
    fs::write(paths.events(), format!("{}\n", lines.join("\n"))).expect("rewrite");

    let question = events_of(&repo, &run_id)
        .iter()
        .find_map(|event| match &event.body {
            EventBody::QuestionRaised { data, .. } => Some(data.question.id.to_string()),
            EventBody::AttemptFinished {
                parking: Some(parking),
                ..
            } => Some(parking.question.id.to_string()),
            _ => None,
        })
        .expect("parked question");
    crate::answer::answer(
        &repo,
        &question,
        crate::answer::Reply::Text("continue".to_owned()),
    )
    .expect("answer");
    let source = fake(Effect::EditFile);
    let error = resume_harness_inner(
        &resume_options(&repo, &run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect_err("an inconsistent inherited review identity must fail closed");
    assert!(
        error
            .to_string()
            .contains("reviews.enabled does not match the recorded primary reviewer"),
        "wrong error: {error}"
    );
    assert!(
        source.adapter.runs().is_empty(),
        "no worker may run under the malformed identity"
    );
    assert!(
        !events_of(&repo, &run_id)
            .iter()
            .any(|event| matches!(event.body, EventBody::RunSchemaUpgraded { .. })),
        "the malformed identity must not be blessed by a schema upgrade"
    );
}

#[test]
fn a_resume_whose_effort_policy_did_not_move_says_nothing_about_it() {
    let config = "[interaction]\nmode = \"never\"\n\n\
                      [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                      [routing.effort]\nimplementation = \"xhigh\"\nreview = \"max\"\n";
    let (repo, run_id) = parked_run_with_config("effortunmoved", config);
    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(
        !resumed
            .warnings
            .iter()
            .any(|warning| warning.contains("effort policy") || warning.contains("effort-policy")),
        "an unchanged policy must be silent: {:?}",
        resumed.warnings
    );
}

#[test]
fn a_log_written_before_step_9_still_gets_reviewed_on_resume() {
    // `RunStarted.reviews` is #[serde(default)] so a step-8 log still
    // parses — but the default is an EMPTY plan, which every later reader
    // cannot tell apart from `review = { enabled = false }`.
    let repo = temp_engine_repo("oldlogresume");
    seed(
        &repo,
        "## Rotate the signing key\n\
             <!-- tactus: id=t1 kind=implement depends= tier=frontier -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"frontier\"], attempts_per = 1 }\n",
        ),
    );
    let first_source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let first = run_with(&cross_vendor_opts(&repo), &first_source).expect("run");

    // Rewrite run_started as a pre-step-9 process would have written it.
    let paths = paths_of(&repo, &first.run_id);
    rewrite_run_started_as_schema_two(&paths);
    strip_run_started_field(&paths, "reviews");

    crate::answer::answer(
        &repo,
        &first.questions[0].question.id.to_string(),
        crate::answer::Reply::Text("put the key in src/auth/keys.rs".to_owned()),
    )
    .expect("answer");

    // A reviewer that rejects everything: if review still runs, nothing can
    // commit. If the absent field read as "review disabled", it commits —
    // verification gone without a word, which is step-6 finding #10.
    let later = source(vec![Effect::EditFile], vec![ReviewBehavior::Fail]);
    let resumed =
        resume_with(&resume_options(&repo, &first.run_id), &later).expect("resume continues");
    assert!(
        !committed(&resumed, "t1"),
        "an older log must not silently switch review off: {resumed:?}"
    );
}

#[test]
fn an_unavailable_reviewer_is_recorded_as_such_not_as_a_rejection() {
    // Step-6 finding #8's distinction, carried into the ledger: a judge
    // that never ran said nothing about the code, and recording it as a
    // plain "did not pass" puts a rejection against a model that never read
    // the diff.
    let repo = temp_engine_repo("outagerecord");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::RateLimited, ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");

    let first = &task(&report, "t1").attempts[0];
    assert_eq!(
        first.reviews.iter().map(|r| r.outcome).collect::<Vec<_>>(),
        [
            events::ReviewPassOutcome::Passed,
            events::ReviewPassOutcome::Unavailable
        ],
        "the second vendor was down, not unimpressed"
    );
    // And the ladder treated it as an outage: deferred, then committed.
    assert!(committed(&report, "t1"), "{report:?}");
}

#[test]
fn second_reviewer_spawn_failure_settles_worker_and_first_review_evidence() {
    let repo = temp_engine_repo("secondreviewerspawnsettlement");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::SpawnError, ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("settled run");

    assert!(
        committed(&report, "t1"),
        "the deferred retry recovers: {report:?}"
    );
    let task = task(&report, "t1");
    assert_eq!(task.attempts.len(), 2, "one settled outage, one recovery");
    let first = &task.attempts[0];
    let failure = first.failure.as_ref().expect("spawn failure is recorded");
    assert_eq!(failure.kind, FailureKind::ReviewUnavailable);
    assert_eq!(failure.origin, FailureOrigin::Reviewer);
    assert_eq!(first.cost_usd, Some(0.01), "worker spend survives");
    assert_eq!(first.session_id.as_deref(), Some("s0"));
    assert!(first.usage.is_some(), "worker usage survives");
    assert_eq!(
        first.reviews.iter().map(|r| r.outcome).collect::<Vec<_>>(),
        [
            events::ReviewPassOutcome::Passed,
            events::ReviewPassOutcome::Unavailable
        ],
        "the completed first verdict is not discarded"
    );
    assert_eq!(first.reviews[0].cost_usd, Some(0.05));
    assert_eq!(first.reviews[1].cost_usd, None);
    assert_eq!(source.copilot().review_spawn_failures(), 1);

    let logged = events_of(&repo, &report.run_id);
    assert!(logged.iter().any(|event| matches!(
        &event.body,
        EventBody::AttemptFinished {
            task,
            attempt: 1,
            ..
        } if task == "t1"
    )));
    assert!(!logged.iter().any(|event| matches!(
        &event.body,
        EventBody::AttemptInterrupted {
            task,
            attempt: 1,
            ..
        } if task == "t1"
    )));
}

#[test]
fn a_total_missing_an_unreported_reviewer_is_marked_rather_than_implied() {
    // The Copilot route bills nothing back (§13), so a two-pass review
    // shows one reviewer's spend. Presenting that as the total is exactly
    // what `render_ledger` says is worse than no ledger at all.
    let repo = temp_engine_repo("partialcost");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = FakeSource {
        adapter: FakeAdapter::new(vec![Effect::EditFile], vec![ReviewBehavior::Pass]),
        copilot: Some(FakeAdapter::copilot(vec![ReviewBehavior::Pass]).unpriced()),
    };
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");

    let t1 = task(&report, "t1");
    assert_eq!(t1.review_cost_usd, Some(0.05), "only what was reported");
    assert!(t1.review_cost_incomplete, "and it is not the whole story");
    assert!(
        report.render().contains("$0.0500?"),
        "the summary marks it: {}",
        report.render()
    );
    let ledger = report.render_ledger();
    assert!(ledger.contains("$0.0500?"), "{ledger}");
    assert!(
        ledger.contains("reports no spend"),
        "legend present: {ledger}"
    );
}

#[test]
fn every_model_that_judged_a_task_is_listed_beside_the_cost_of_all_of_them() {
    // An escalated task can be judged on one rung by one model and on the
    // next by another. `review_cost_usd` sums every attempt, so a list
    // scoped to the final attempt would read as though it explained a total
    // it does not cover.
    let repo = temp_engine_repo("reviewtrail");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"mid\", \"frontier\"], attempts_per = 1 }\n",
        ),
    );
    // Mid fails review, escalates to frontier, which passes. The frontier
    // rung is self-review, so its pass rebinds to the other family.
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Fail, ReviewBehavior::Pass],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");
    let t1 = task(&report, "t1");
    assert_eq!(t1.attempts.len(), 2, "escalated: {t1:?}");
    assert_eq!(
        t1.review_models,
        ["claude-opus-5", "gpt-5.3-codex"],
        "both judges, in the order they judged"
    );
}

#[test]
fn each_pass_writes_its_own_verdict_transcript() {
    // Two reviewers, two records. The acceptance pass keeps the bare name
    // it has had since step 6, so a run directory reads the same way
    // whether or not a second opinion was configured.
    let repo = temp_engine_repo("passtranscripts");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let source = cross_vendor(
        vec![Effect::EditFile],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&cross_vendor_opts(&repo), &source).expect("run");
    let reviews = paths_of(&repo, &report.run_id).reviews();
    assert!(reviews.join("00-t1-1-review.json").is_file());
    assert!(
        reviews.join("00-t1-1-second-opinion-review.json").is_file(),
        "the second verdict cannot overwrite the first"
    );
}

#[test]
fn the_run_record_survives_completion() {
    let repo = temp_engine_repo("record");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");
    let report_path = repo
        .join(".tactus")
        .join("runs")
        .join(&report.run_id)
        .join("report.json");
    let text = fs::read_to_string(&report_path).expect("report.json written");
    let restored: RunReport = serde_json::from_str(&text).expect("report round-trips");
    assert_eq!(restored.tasks.len(), 2);
    assert_eq!(restored.branch, report.branch);
    assert!(matches!(
        restored.tasks[0].status,
        TaskRunStatus::Committed { .. }
    ));
    assert_eq!(
        restored.tasks[0].attempts.len(),
        1,
        "the per-attempt ledger persists too"
    );
}

#[test]
fn forward_dependencies_run_in_topo_order_not_plan_order() {
    let repo = temp_engine_repo("topo");
    seed(
        &repo,
        "## Second by dependency\n<!-- tactus: id=late depends=early -->\n\n\
             ## First by dependency\n<!-- tactus: id=early depends= -->\n",
        None,
    );

    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");
    let ids: Vec<&str> = report.tasks.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, ["early", "late"], "dependency beats document order");
}

#[test]
fn a_contradictory_pass_fails_closed() {
    let failure = review_failure(review::ReviewResult::Judged(crate::ir::Verdict {
        pass: true,
        reasons: vec!["looks fine".to_owned()],
        required_changes: vec!["parameterize the SQL".to_owned()],
        needs_human: false,
    }))
    .expect("a pass that still demands changes cannot commit");
    assert_eq!(failure.kind, FailureKind::ReviewFailed);
    assert!(
        failure.reason.contains("parameterize the SQL"),
        "{}",
        failure.reason
    );

    // A clean pass still passes.
    assert!(
        review_failure(review::ReviewResult::Judged(crate::ir::Verdict {
            pass: true,
            reasons: vec!["meets the criteria".to_owned()],
            required_changes: Vec::new(),
            needs_human: false,
        }))
        .is_none()
    );
}

#[test]
fn an_unavailable_reviewer_is_not_a_rejection() {
    // A rate-limited or hung judge must not read as "your code is wrong",
    // or the ladder retries the implementer for an outage.
    let failure = review_failure(review::ReviewResult::Unavailable {
        status: OutcomeStatus::RateLimited,
        detail: "5-hour limit reached".to_owned(),
    })
    .expect("still fails the attempt");
    assert_eq!(failure.kind, FailureKind::RateLimited);
    assert_eq!(failure.origin, FailureOrigin::Reviewer);
    assert!(failure.is_outage(), "defers instead of blaming the worker");
    assert!(failure.reason.contains("reviewer unavailable"));

    let failure = review_failure(review::ReviewResult::Unavailable {
        status: OutcomeStatus::Timeout,
        detail: String::new(),
    })
    .expect("still fails");
    assert_eq!(failure.kind, FailureKind::Timeout);
    assert_eq!(failure.origin, FailureOrigin::Reviewer);

    let failure = review_failure(review::ReviewResult::Unavailable {
        status: OutcomeStatus::AgentError,
        detail: "spawn failed".to_owned(),
    })
    .expect("still fails");
    assert_eq!(failure.kind, FailureKind::ReviewUnavailable);
}

#[test]
fn required_changes_reach_the_retry_as_a_clean_list() {
    let failure = review_failure(review::ReviewResult::Judged(crate::ir::Verdict {
        pass: false,
        reasons: vec!["incomplete".to_owned()],
        required_changes: vec![
            "handle the empty-input case".to_owned(),
            "add a round-trip test".to_owned(),
        ],
        needs_human: false,
    }))
    .expect("fails");
    assert_eq!(
        failure.feedback.as_deref(),
        Some("- handle the empty-input case\n- add a round-trip test"),
        "every item bulleted, including the first"
    );
    assert_eq!(
        failure.origin,
        FailureOrigin::Worker,
        "a rejected diff is the worker's to fix"
    );
}

#[test]
fn prompt_names_the_allowed_gate_commands() {
    let task = Task {
        id: TaskId::from("t1"),
        kind: TaskKind::Implement,
        title: "Do the thing".to_owned(),
        body: String::new(),
        depends_on: Vec::new(),
        acceptance: Vec::new(),
        path_hints: Vec::new(),
        suggested_tier: None,
        min_tier: None,
        artifacts_in: Vec::new(),
        artifacts_out: Vec::new(),
    };
    let run_dir = std::env::temp_dir().join(format!("tactus-prompt-{}", std::process::id()));
    fs::create_dir_all(run_dir.join("artifacts")).expect("run dir");
    let prompt = materialize_prompt(
        &task,
        &["cargo check --all-targets".to_owned()],
        &run_dir,
        None,
    );
    assert!(prompt.contains("EXACTLY these commands"));
    assert!(prompt.contains("- cargo check --all-targets"));
    assert!(
        prompt.contains(QUESTION_MARKER),
        "the worker is told how to ask (§12)"
    );
    let bare = materialize_prompt(&task, &[], &run_dir, None);
    assert!(!bare.contains("EXACTLY these commands"));
}

#[test]
fn prompt_wires_artifacts_to_real_files() {
    let run_dir = std::env::temp_dir().join(format!("tactus-artifact-{}", std::process::id()));
    let _ = fs::remove_dir_all(&run_dir);
    fs::create_dir_all(run_dir.join("artifacts")).expect("run dir");
    let mut task = Task {
        id: TaskId::from("t1"),
        kind: TaskKind::Implement,
        title: "Build it".to_owned(),
        body: String::new(),
        depends_on: Vec::new(),
        acceptance: Vec::new(),
        path_hints: Vec::new(),
        suggested_tier: None,
        min_tier: None,
        artifacts_in: vec![crate::ir::ArtifactId::from("api-contract")],
        artifacts_out: vec![crate::ir::ArtifactId::from("notes")],
    };

    // Missing input: say so plainly rather than pointing at nothing.
    let prompt = materialize_prompt(&task, &[], &run_dir, None);
    assert!(prompt.contains("did \n     not leave one") || prompt.contains("did not leave one"));
    assert!(
        prompt.contains("write artifact `notes`"),
        "producer told where to write"
    );

    // Present input: content is inlined.
    fs::write(
        artifact_path(&run_dir, "api-contract"),
        "cursor = base64(offset)",
    )
    .expect("artifact");
    let prompt = materialize_prompt(&task, &[], &run_dir, None);
    assert!(
        prompt.contains("cursor = base64(offset)"),
        "content inlined"
    );

    task.artifacts_in.clear();
    task.artifacts_out.clear();
    let bare = materialize_prompt(&task, &[], &run_dir, None);
    assert!(!bare.contains("artifact"));
}

// ---- step 7: the ladder in the engine ---------------------------------

#[test]
fn a_gate_failure_recovers_on_the_same_rung_via_session_resume() {
    // §21 definition-of-done (b). The gate demands a file only the second
    // attempt writes, so recovery is real rather than scripted around.
    let repo = temp_engine_repo("resume");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n\n\
                 [[gates]]\nname = \"needs-test\"\ncmd = \"git ls-files --error-unmatch \
                 widget_test.rs\"\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::EditFile, Effect::EditTest],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");

    assert!(committed(&report, "t1"), "report: {report:?}");
    let t1 = task(&report, "t1");
    assert_eq!(t1.attempts.len(), 2, "one retry, not an escalation");
    assert_eq!(t1.attempts[0].tier, "small");
    assert_eq!(t1.attempts[1].tier, "small", "same rung");
    assert!(!t1.attempts[0].resumed);
    assert!(t1.attempts[1].resumed, "§11.4 retries in-session");

    let runs = source.adapter.runs();
    assert_eq!(runs[0].resume, None);
    assert_eq!(
        runs[1].resume.as_deref(),
        Some("s0"),
        "the retry resumed the failed attempt's session"
    );
    assert!(
        runs[1].prompt.contains("gate `needs-test` failed"),
        "the gate's own words go back: {}",
        runs[1].prompt
    );
    assert!(
        !runs[1].prompt.contains("# Task:"),
        "a resumed session already holds the task; the prompt stays terse"
    );

    // §14: a resumed retry keeps the tree, so the commit carries BOTH
    // attempts' work rather than only the last one's.
    let files = git_in(&repo, &["show", "--name-only", "--format=", "HEAD"]);
    assert!(files.contains("agent-output.txt"), "files: {files}");
    assert!(files.contains("widget_test.rs"), "files: {files}");
}

#[test]
fn exhausting_a_rung_escalates_with_a_fresh_session_and_the_history() {
    // §21 definition-of-done (c).
    let repo = temp_engine_repo("escalate");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");

    assert!(committed(&report, "t1"), "report: {report:?}");
    let t1 = task(&report, "t1");
    assert_eq!(t1.attempts.len(), 2);
    assert_eq!(t1.attempts[0].tier, "small");
    assert_eq!(t1.attempts[0].model, "claude-haiku-4-5");
    assert_eq!(t1.attempts[1].tier, "mid", "one rung up");
    assert_eq!(t1.attempts[1].model, "claude-sonnet-5");
    assert!(
        !t1.attempts[1].resumed,
        "§11.4: a new rung is a new session — a different model cannot \
             inherit another's conversation"
    );
    assert_eq!(t1.trail(), "small failed → mid ok");

    let runs = source.adapter.runs();
    // The adapter's own record, not just the report echoing what the
    // engine intended: the second attempt really was dispatched to the
    // higher rung's model.
    assert_eq!(runs[0].model, "claude-haiku-4-5");
    assert_eq!(runs[1].model, "claude-sonnet-5");
    assert_eq!(runs[1].resume, None, "fresh session");
    assert!(
        runs[1].prompt.contains("# Task:"),
        "a fresh worker gets the whole task again"
    );
    assert!(
        runs[1].prompt.contains("diff is empty"),
        "and what the previous rung got wrong: {}",
        runs[1].prompt
    );
}

#[test]
fn a_parked_question_does_not_stop_the_runnable_frontier() {
    // §21 definition-of-done (d) and invariant 6: t1 exhausts its chain
    // and parks; the independent t3 must still commit.
    let repo = temp_engine_repo("park");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Depends on the doomed one\n<!-- tactus: id=t2 kind=implement depends=t1 -->\n\n\
             ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // t1 fails; every later attempt (t3's) edits and passes.
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");

    let TaskRunStatus::Parked { question, .. } = &task(&report, "t1").status else {
        panic!("t1 should park on a question: {report:?}");
    };
    assert!(committed(&report, "t3"), "independent work kept going");
    assert!(
        matches!(&task(&report, "t2").status, TaskRunStatus::Blocked { by } if by == "t1"),
        "a dependent of a parked task is blocked, not failed"
    );
    assert!(report.halted_at.is_none(), "parking never halts a run");
    assert_eq!(report.outcome(), RunOutcome::Parked);
    assert_eq!(report.parked_tasks(), ["t1"]);

    // The question is on disk where a notifier, `tactus answer`, or a UI
    // can read it — that file is the contract, not the terminal output.
    let path = repo
        .join(".tactus")
        .join("runs")
        .join(&report.run_id)
        .join("questions")
        .join(format!("{question}.json"));
    let record: QuestionRecord =
        serde_json::from_str(&fs::read_to_string(&path).expect("question file")).expect("parses");
    assert_eq!(record.question.kind, QuestionKind::Unblock);
    assert_eq!(record.question.affected_tasks, [TaskId::from("t1")]);
    assert!(record.answer.is_none(), "still open");
    assert!(record.question.context.contains("Doomed"));

    let rendered = report.render();
    assert!(rendered.contains("PARKED"), "{rendered}");
    assert!(rendered.contains("open questions (1)"), "{rendered}");
}

#[test]
fn answering_the_question_retries_the_task_with_the_operators_words() {
    let repo = temp_engine_repo("answered");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let answers = ScriptedAnswers::new(vec![Answer::Answered {
        text: "the widget lives in src/widget.rs — write it there".to_owned(),
    }]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run");

    assert!(committed(&report, "t1"), "report: {report:?}");
    assert_eq!(report.outcome(), RunOutcome::Complete);
    let t1 = task(&report, "t1");
    assert_eq!(t1.attempts.len(), 2, "the answer bought a fresh allowance");
    assert_eq!(
        t1.attempts[1].tier, "small",
        "an answer does not move the rung — the chain was already spent"
    );

    let runs = source.adapter.runs();
    assert!(
        runs[1].prompt.contains("src/widget.rs"),
        "the operator's answer reaches the agent: {}",
        runs[1].prompt
    );
    assert!(
        runs[1].prompt.contains("instruction from a person"),
        "and is labelled as an instruction, not quoted data"
    );

    let record = report.questions.first().expect("one question");
    assert!(
        matches!(&record.answer, Some(Answer::Answered { text }) if text.contains("widget.rs")),
        "the answer is recorded against the question: {record:?}"
    );
}

#[test]
fn declining_fails_the_task_and_halt_is_the_default() {
    let repo = temp_engine_repo("declined");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let answers = ScriptedAnswers::new(vec![Answer::Declined]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run");

    let TaskRunStatus::Failed { kind, reason } = &task(&report, "t1").status else {
        panic!("a declined question fails its task: {report:?}");
    };
    assert_eq!(*kind, FailureKind::Declined);
    assert!(!reason.is_empty());
    assert_eq!(
        report.halted_at.as_deref(),
        Some("t1"),
        "§17's default on_task_failure is halt"
    );
    assert_eq!(report.outcome(), RunOutcome::Halted);
}

#[test]
fn resume_repairs_every_decline_settlement_crash_prefix() {
    for (tag, last_durable_event) in [
        ("answered", "question_answered"),
        ("defect", "design_defect"),
    ] {
        let repo = temp_engine_repo(&format!("declineprefix-{tag}"));
        seed(
            &repo,
            "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
            Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
        );
        let mut opts = options(&repo);
        opts.config_path = Some(repo.join("tactus.toml"));
        let initial = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
        let answers = ScriptedAnswers::new(vec![Answer::Declined]);
        let report = run_harness(
            &opts,
            &Harness {
                adapters: &initial,
                answers: Some(&answers),
                sleeper: None,
            },
        )
        .expect("build a complete decline sequence");
        let paths = paths_of(&repo, &report.run_id);
        truncate_log_after(&paths, last_durable_event);
        fs::write(
            repo.join("tactus.toml"),
            "[engine]\non_task_failure = \"continue\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        )
        .expect("change today's policy after the decline was durable");

        let resumed_source = fake(Effect::EditFile);
        let resumed = resume_with(&resume_options(&repo, &report.run_id), &resumed_source)
            .expect("resume repairs the incomplete settlement");
        assert_eq!(
            resumed.outcome(),
            RunOutcome::Halted,
            "prefix {tag}: repair must use the policy recorded with the answer"
        );
        assert!(
            matches!(
                task(&resumed, "t1").status,
                TaskRunStatus::Failed {
                    kind: FailureKind::Declined,
                    ..
                }
            ),
            "prefix {tag}: {resumed:?}"
        );
        assert!(
            resumed_source.adapter.runs().is_empty(),
            "repair must settle the decline before another paid attempt"
        );

        let logged = events_of(&repo, &report.run_id);
        assert_eq!(
            logged
                .iter()
                .filter(|event| matches!(event.body, EventBody::DesignDefect { .. }))
                .count(),
            1,
            "the missing prefix is appended once"
        );
        assert_eq!(
            logged
                .iter()
                .filter(|event| matches!(event.body, EventBody::TaskFailed { .. }))
                .count(),
            1,
            "the declined task is settled once"
        );
    }
}

#[test]
fn schema_two_decline_prefix_preserves_or_refuses_unknown_halt_policy() {
    let repo = temp_engine_repo("legacydeclinepolicy");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let initial = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let answers = ScriptedAnswers::new(vec![Answer::Declined]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &initial,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("build a complete decline sequence");
    let paths = paths_of(&repo, &report.run_id);
    truncate_log_after(&paths, "question_answered");
    rewrite_run_started_as_schema_two(&paths);
    strip_event_data_field(&paths, "question_answered", "decline_halts_run");
    fs::write(
        repo.join("tactus.toml"),
        "[engine]\non_task_failure = \"continue\"\n\n\
             [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
    )
    .expect("today's policy differs");

    let error = resume_err(&repo, &report.run_id);
    assert!(
        error.contains("contemporaneous on_task_failure policy"),
        "{error}"
    );
    assert!(
        error.contains("cannot safely decide an old answer"),
        "{error}"
    );
}

#[test]
fn on_task_failure_continue_keeps_independent_work_moving() {
    let repo = temp_engine_repo("continue");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Depends on the doomed one\n<!-- tactus: id=t2 kind=implement depends=t1 -->\n\n\
             ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some(
            "[engine]\non_task_failure = \"continue\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let answers = ScriptedAnswers::new(vec![Answer::Declined]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run");

    assert!(report.halted_at.is_none(), "configured to continue");
    assert!(matches!(
        task(&report, "t1").status,
        TaskRunStatus::Failed { .. }
    ));
    assert!(committed(&report, "t3"));
    assert!(
        matches!(&task(&report, "t2").status, TaskRunStatus::Blocked { by } if by == "t1"),
        "§19: dependents of a failed task are blocked"
    );
}

#[test]
fn a_rate_limit_defers_without_spending_an_attempt() {
    let repo = temp_engine_repo("ratelimit");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        // A single attempt on a single rung: if the rate limit spent it,
        // the task could never commit.
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::RateLimited, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let sleeper = RecordingSleeper::default();
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: Some(&sleeper),
        },
    )
    .expect("run");

    assert!(
        committed(&report, "t1"),
        "the rate limit cost no attempt: {report:?}"
    );
    let t1 = task(&report, "t1");
    assert_eq!(t1.attempts.len(), 2);
    assert_eq!(
        t1.attempts[0].failure.as_ref().map(|f| f.kind),
        Some(FailureKind::RateLimited)
    );
    assert_eq!(t1.attempts[1].tier, "small", "never escalated for a pool");
    assert_eq!(
        sleeper.waits().len(),
        1,
        "waited once, because deferred work was all that was left"
    );
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "a deferred task hands back a clean tree — another task may run next"
    );
}

#[test]
fn a_pool_that_never_returns_ends_at_the_human_rung() {
    let repo = temp_engine_repo("ratelimit-forever");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.max_defers = 2;
    let source = source(vec![Effect::RateLimited], vec![ReviewBehavior::Pass]);
    let sleeper = RecordingSleeper::default();
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: Some(&sleeper),
        },
    )
    .expect("run");

    assert!(
        matches!(task(&report, "t1").status, TaskRunStatus::Parked { .. }),
        "an exhausted pool becomes a question, not an infinite retry: {report:?}"
    );
    assert_eq!(
        task(&report, "t1").attempts.len(),
        3,
        "two deferrals, then the attempt that gave up"
    );
    assert!(
        task(&report, "t1")
            .attempts
            .iter()
            .all(|a| a.tier == "small"),
        "a busy pool never pushes the task up-tier"
    );
    assert_eq!(sleeper.waits().len(), 2, "one wait per deferral");
}

#[test]
fn an_unavailable_reviewer_defers_the_task_instead_of_escalating_it() {
    let repo = temp_engine_repo("reviewdown");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::EditFile],
        vec![ReviewBehavior::RateLimited, ReviewBehavior::Pass],
    );
    let sleeper = RecordingSleeper::default();
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: Some(&sleeper),
        },
    )
    .expect("run");

    assert!(committed(&report, "t1"), "report: {report:?}");
    let t1 = task(&report, "t1");
    assert_eq!(t1.attempts.len(), 2);
    assert_eq!(
        t1.attempts[0].failure.as_ref().map(|f| f.origin),
        Some(FailureOrigin::Reviewer),
        "the outage is attributed to the judge"
    );
    assert_eq!(
        t1.attempts[1].tier, "small",
        "the implementer was never escalated for the reviewer being down"
    );
}

#[test]
fn a_reviewer_asking_for_a_human_parks_without_spending_the_chain() {
    let repo = temp_engine_repo("needshuman");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::NeedsHuman]);
    let report = run_with(&opts, &source).expect("run");

    let t1 = task(&report, "t1");
    assert!(
        matches!(t1.status, TaskRunStatus::Parked { .. }),
        "report: {report:?}"
    );
    assert_eq!(
        t1.attempts.len(),
        1,
        "the reviewer declined to judge, so nothing was retried or escalated"
    );
    assert_eq!(
        t1.attempts[0].failure.as_ref().map(|f| f.kind),
        Some(FailureKind::NeedsHuman)
    );
    let record = report.questions.first().expect("question raised");
    assert_eq!(record.question.kind, QuestionKind::Clarify);
    assert!(
        record
            .question
            .context
            .contains("contradict the API contract"),
        "the reviewer's reason reaches the person: {}",
        record.question.context
    );
    assert!(
        record.question.context.contains("not instructions to you"),
        "agent-authored text is labelled as data"
    );
}

#[test]
fn a_worker_can_stop_and_ask_rather_than_guess() {
    let repo = temp_engine_repo("workerasks");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::AskQuestion, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let answers = ScriptedAnswers::new(vec![Answer::Answered {
        text: "opaque cursors".to_owned(),
    }]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run");

    let record = report.questions.first().expect("the worker's question");
    assert_eq!(record.question.kind, QuestionKind::Clarify);
    assert!(
        record.question.context.contains("opaque or signed"),
        "context: {}",
        record.question.context
    );
    // Independent work ran while t1 waited, and the answer resumed it.
    assert!(committed(&report, "t3"));
    assert!(committed(&report, "t1"), "report: {report:?}");
    let t1 = task(&report, "t1");
    assert_eq!(
        t1.attempts.len(),
        2,
        "asking cost no attempt — only the retry after the answer"
    );
    // Parking rolled the tree back, so the session's account of what it
    // wrote no longer matches the repository (§14 pairs resume with tree
    // retention). The retry therefore starts fresh and carries the whole
    // task again, with the operator's answer as an instruction.
    assert!(
        !t1.attempts[1].resumed,
        "a parked task never resumes into a tree that was reverted underneath it"
    );
    // Invocation order across the whole run, not just this task: t1 asks
    // (0), the independent t3 proceeds while t1 is parked (1), then t1
    // retries once the answer arrives (2). That interleaving is the point
    // of invariant 6, so the retry is the third invocation.
    let runs = source.adapter.runs();
    let retry = &runs[2];
    assert_eq!(retry.resume, None, "fresh session, not --resume");
    assert!(
        retry.prompt.contains("# Task:"),
        "the whole task is re-sent, since the session no longer carries it: {}",
        retry.prompt
    );
    assert!(
        retry.prompt.contains("opaque cursors"),
        "and the operator's answer travels with it: {}",
        retry.prompt
    );
    assert!(
        retry.prompt.contains("instruction from a person"),
        "labelled as an instruction rather than quoted as data"
    );
}

#[test]
fn ci_mode_parks_rather_than_failing_and_says_so() {
    // §12: `interaction = "never"` degrades questions to parked-task
    // reporting, and the outcome is distinguishable from both a clean run
    // and a halt.
    let repo = temp_engine_repo("ci");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Depends on the doomed one\n<!-- tactus: id=t2 kind=implement depends=t1 -->\n\n\
             ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");

    assert_eq!(report.outcome(), RunOutcome::Parked);
    assert!(report.halted_at.is_none(), "parked is not halted");
    assert!(matches!(
        task(&report, "t1").status,
        TaskRunStatus::Parked { .. }
    ));
    assert!(committed(&report, "t3"));
    assert!(matches!(
        task(&report, "t2").status,
        TaskRunStatus::Blocked { .. }
    ));
    assert!(
        report.questions.iter().all(QuestionRecord::is_open),
        "nothing answered it, and nothing pretended to"
    );
}

#[test]
fn an_unanswerable_question_is_never_asked_twice() {
    // Without this the hard block spins: ask, get nothing, ask again.
    let repo = temp_engine_repo("noloop");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let answers = CountingAnswers::default();
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run terminates");
    assert_eq!(report.outcome(), RunOutcome::Parked);
    assert_eq!(
        answers.count(),
        1,
        "asked once; an unreachable channel is not retried"
    );
}

#[derive(Default)]
struct CountingAnswers {
    calls: Mutex<usize>,
}

impl CountingAnswers {
    fn count(&self) -> usize {
        self.calls.lock().map(|c| *c).unwrap_or(0)
    }
}

impl AnswerSource for CountingAnswers {
    fn id(&self) -> &'static str {
        "counting"
    }

    fn resolve(&self, _question: &Question) -> Result<Answer, TactusError> {
        if let Ok(mut calls) = self.calls.lock() {
            *calls += 1;
        }
        Ok(Answer::Unanswered)
    }
}

#[test]
fn agent_errors_and_empty_diffs_carry_feedback_the_retry_can_use() {
    let repo = temp_engine_repo("feedback");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::Error, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");
    assert!(committed(&report, "t1"), "report: {report:?}");
    let runs = source.adapter.runs();
    assert!(
        runs[1].prompt.contains("fake adapter error detail"),
        "the adapter's own diagnosis reaches the retry: {}",
        runs[1].prompt
    );
}

#[test]
fn an_unparseable_reviewer_fails_after_one_reask() {
    let repo = temp_engine_repo("reviewprose");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Unparseable]);
    let report = run_with(&opts, &source).expect("engine ok");

    let failure = task(&report, "t1").attempts[0]
        .failure
        .as_ref()
        .expect("a reviewer that never answers cannot pass a task");
    assert_eq!(failure.kind, FailureKind::ReviewFailed);
    assert!(
        failure.reason.contains("re-ask"),
        "reason: {}",
        failure.reason
    );
    // The re-ask actually happened, and both sides are on record.
    let reviews = paths_of(&repo, &report.run_id).reviews();
    assert!(reviews.join("00-t1-1-review.json").is_file());
    assert!(
        reviews.join("00-t1-1-review-reask.json").is_file(),
        "one re-ask before giving up (§11.2)"
    );
    assert_eq!(
        git_in(&repo, &["rev-list", "--count", "main..HEAD"]).trim(),
        "0",
        "nothing commits without a passing verdict"
    );
}

#[test]
fn gate_logs_are_named_by_the_collision_free_stem() {
    let repo = temp_engine_repo("gatelogs");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [[gates]]\nname = \"never\"\ncmd = \"git frobnicate-not-a-command\"\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let report = run_with(&opts, &source).expect("engine ok");

    let failure = task(&report, "t1").attempts[0]
        .failure
        .as_ref()
        .expect("gate should fail");
    assert_eq!(failure.kind, FailureKind::GateFailed);
    let gates_dir = paths_of(&repo, &report.run_id).gates();
    assert!(
        gates_dir.join("00-t1-1-never.log").is_file(),
        "the log stem matches the task's other artifacts, so two ids that \
             sanitize alike cannot overwrite each other"
    );
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "rolled back"
    );
}

#[test]
fn the_trail_summarizes_the_ladder() {
    let report = TaskReport {
        id: "t1".to_owned(),
        title: "x".to_owned(),
        model: "m".to_owned(),
        status: TaskRunStatus::Skipped,
        duration: Duration::ZERO,
        cost_usd: None,
        review_models: Vec::new(),
        review_cost_usd: None,
        review_cost_incomplete: false,
        session_id: None,
        attempts: vec![
            attempt_record(1, "small", true),
            attempt_record(2, "small", true),
            attempt_record(3, "mid", false),
        ],
    };
    assert_eq!(report.trail(), "small×2 failed → mid ok");
}

fn attempt_record(attempt: u32, tier: &str, failed: bool) -> AttemptRecord {
    AttemptRecord {
        attempt,
        tier: tier.to_owned(),
        model: "m".to_owned(),
        pool: None,
        resumed: false,
        duration: Duration::ZERO,
        cost_usd: None,
        reviews: Vec::new(),
        session_id: None,
        usage: None,
        failure: failed.then(|| FailureRecord {
            kind: FailureKind::GateFailed,
            origin: FailureOrigin::Worker,
            reason: "no".to_owned(),
        }),
    }
}

#[test]
fn a_worker_question_is_read_from_the_marker_onward() {
    assert_eq!(
        worker_question(Some("Did some work.\nTACTUS-QUESTION: opaque or signed?")).as_deref(),
        Some("opaque or signed?")
    );
    // Multi-line questions survive, because the prompt asks for it last.
    assert_eq!(
        worker_question(Some("TACTUS-QUESTION: which store?\nRedis or Postgres?")).as_deref(),
        Some("which store?\nRedis or Postgres?")
    );
    assert_eq!(worker_question(Some("TACTUS-QUESTION:   ")), None);
    assert_eq!(worker_question(Some("no marker here")), None);
    assert_eq!(worker_question(None), None);
}

#[test]
fn an_echoed_marker_does_not_swallow_the_real_question() {
    // The engine hands the agent this marker in every fresh prompt, and
    // the empty-diff feedback names it verbatim — so an agent mentioning
    // it before asking is the expected shape, not a corner case. Taking
    // the first occurrence would hand the operator the agent's reasoning
    // with the question buried at the end.
    let reply = "The retry feedback says I can use the TACTUS-QUESTION: marker if I am \
                     blocked. I considered whether this needs one.\n\n\
                     TACTUS-QUESTION: should cursors be opaque or signed?";
    assert_eq!(
        worker_question(Some(reply)).as_deref(),
        Some("should cursors be opaque or signed?"),
        "last marker wins, matching the prompt and review.rs's verdict rule"
    );
}

#[test]
fn an_outage_is_never_reclassified_as_a_question() {
    // `detail` carries the agent's partial output on every failure path,
    // and that output routinely quotes the prompt. Reading the marker
    // before the status would turn a rate limit into a parked question —
    // silently defeating "RateLimited defers rather than burning an
    // attempt", and losing the timeout's transcript-tail feedback.
    let quoting = "I will end with the TACTUS-QUESTION: marker if I get stuck.";
    let output = crate::agent::ProcessOutput {
        stdout: String::new(),
        stderr: String::new(),
        code: Some(1),
        timed_out: false,
        output_limited: false,
        duration: Duration::ZERO,
    };
    for (status, expected) in [
        (OutcomeStatus::RateLimited, FailureKind::RateLimited),
        (OutcomeStatus::Timeout, FailureKind::Timeout),
        (OutcomeStatus::AgentError, FailureKind::AgentError),
    ] {
        let outcome = fake_outcome(status, Some(quoting.to_owned()), "s0", None, Duration::ZERO);
        let failure = evaluate_outcome(&outcome, &output).expect("still a failure");
        assert_eq!(failure.kind, expected, "{status:?} must keep its own kind");
    }

    // A genuine question on a completed run still parks the task.
    let mut asked = fake_outcome(
        OutcomeStatus::Completed,
        Some("TACTUS-QUESTION: opaque or signed?".to_owned()),
        "s0",
        None,
        Duration::ZERO,
    );
    asked.diff = "diff --git a/x b/x\n+x\n".to_owned();
    assert_eq!(
        evaluate_outcome(&asked, &output).expect("parks").kind,
        FailureKind::NeedsHuman
    );
}

#[test]
fn a_halted_run_stops_asking_and_keeps_naming_the_real_cause() {
    // t1 parks on a question, t2 fails terminally under the default halt
    // policy. Asking about t1 afterwards spends the operator's attention
    // on an answer no attempt can consume, and a decline would relabel
    // `halted_at` with t1 — sending triage at the wrong task.
    let repo = temp_engine_repo("haltpark");
    seed(
        &repo,
        "## Asks a question\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Exhausts its chain\n<!-- tactus: id=t2 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // t1 asks and parks; t2 changes nothing and parks on chain exhaustion.
    let source = source(
        vec![Effect::AskQuestion, Effect::NoEdit],
        vec![ReviewBehavior::Pass],
    );
    // Declining t1 fails it, which halts the run under the default policy.
    // The second answer must never be consumed: t2's question cannot be
    // asked once nothing can act on the reply.
    let answers = ScriptedAnswers::new(vec![
        Answer::Declined,
        Answer::Answered {
            text: "this answer must never be used".to_owned(),
        },
    ]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run");

    assert!(
        matches!(
            task(&report, "t1").status,
            TaskRunStatus::Failed {
                kind: FailureKind::Declined,
                ..
            }
        ),
        "the decline is what halts the run: {report:?}"
    );
    assert_eq!(
        report.halted_at.as_deref(),
        Some("t1"),
        "halted_at names the task that actually caused the halt"
    );
    // The distinguishing assertion. Unguarded, t2's question would be
    // asked, answered, and flipped back to Pending — where `next_ready`
    // refuses it because the run has halted, so it would surface as
    // `Skipped` with the operator's answer sitting unused on disk.
    assert!(
        matches!(task(&report, "t2").status, TaskRunStatus::Parked { .. }),
        "t2 is never asked after the halt, so it stays parked rather than \
             silently consuming an answer: {report:?}"
    );
    let t2_question = report
        .questions
        .iter()
        .find(|q| q.question.affected_tasks.iter().any(|t| t.as_str() == "t2"))
        .expect("t2 raised a question");
    assert!(
        t2_question.is_open(),
        "left open on disk for a later resume (§15)"
    );
}

#[test]
fn unreported_cost_stays_unreported_rather_than_zero() {
    assert_eq!(sum_opt([None, None].into_iter()), None);
    assert_eq!(
        sum_opt([Some(0.01), None, Some(0.02)].into_iter()),
        Some(0.03)
    );
}

// ---- step 8: the event log is the state ------------------------------

/// Fold a run's log the way `status` and `resume` do.
fn replay_of(repo: &Path, run_id: &str) -> crate::status::RunStatus {
    crate::status::load(repo, Some(run_id)).expect("the run reads back")
}

/// One path through the ladder, for the live-equals-replay property.
struct Scenario {
    name: &'static str,
    config: &'static str,
    /// Overrides the default two-task plan where a scenario needs path
    /// hints or a particular tier.
    plan: Option<&'static str>,
    effects: Vec<Effect>,
    reviews: Vec<ReviewBehavior>,
    /// `Some` puts a second vendor on the machine (§11.3).
    second_opinion: Option<Vec<ReviewBehavior>>,
    answers: Vec<Answer>,
}

impl Scenario {
    fn new(name: &'static str, config: &'static str, effects: Vec<Effect>) -> Self {
        Self {
            name,
            config,
            plan: None,
            effects,
            reviews: vec![ReviewBehavior::Pass],
            second_opinion: None,
            answers: Vec::new(),
        }
    }

    fn reviewed(mut self, reviews: Vec<ReviewBehavior>) -> Self {
        self.reviews = reviews;
        self
    }

    fn cross_vendor(mut self, plan: &'static str, second: Vec<ReviewBehavior>) -> Self {
        self.plan = Some(plan);
        self.second_opinion = Some(second);
        self
    }

    fn answered(mut self, answers: Vec<Answer>) -> Self {
        self.answers = answers;
        self
    }
}

/// The property the whole design rests on: a live run and a replay of its
/// own log are the same computation, not two that happen to agree.
///
/// Asserted on `RunState` rather than on the report, because the report is
/// a lossy projection — it drops `feedback`, `resume_next`, `session`, and
/// the rung a task is standing on, which are exactly the fields a resume
/// depends on being right.
fn assert_live_equals_replay(repo: &Path, live: &RunState, report: &RunReport) {
    let replayed = replay_of(repo, &report.run_id);
    assert_eq!(
        &replayed.state, live,
        "replaying the log produced different state than the run that wrote it"
    );
    // Warnings are the one field deliberately excluded. They are
    // diagnostics of the *process* — what this invocation noticed about a
    // missing notifier or a discarded working tree — not facts about the
    // run, so a later reader legitimately has different ones. Anything
    // that genuinely belongs to the run is an event instead (a discarded
    // tree, for instance, rides on `run_resumed`).
    let strip = |report: &RunReport| {
        let mut value = serde_json::to_value(report).expect("serialize");
        if let Some(object) = value.as_object_mut() {
            object.remove("warnings");
        }
        value
    };
    assert_eq!(
        strip(&replayed.report()),
        strip(report),
        "the report derived from the log differs from the one the run wrote"
    );
}

#[test]
fn live_state_equals_replayed_state_across_every_ladder_path() {
    // One scenario per branch the engine can take, so the equality is
    // exercised against commits, retries, escalations, deferrals, parks,
    // answers, and a halt — not just the happy path.
    let scenarios = vec![
        Scenario::new(
            "commit",
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
            vec![Effect::EditFile],
        ),
        Scenario::new(
            "retry",
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n",
            vec![Effect::NoEdit, Effect::EditFile],
        ),
        Scenario::new(
            "escalate",
            "[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 1 }\n",
            vec![Effect::NoEdit, Effect::EditFile],
        ),
        Scenario::new(
            "defer",
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
            vec![Effect::RateLimited, Effect::EditFile],
        ),
        Scenario::new(
            "park-then-answer",
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
            vec![Effect::NoEdit, Effect::EditFile],
        )
        .answered(vec![Answer::Answered {
            text: "the widget lives in src/widget.rs".to_owned(),
        }]),
        Scenario::new(
            "decline-and-halt",
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
            vec![Effect::NoEdit],
        )
        .answered(vec![Answer::Declined]),
        Scenario::new(
            "reviewer-asks-for-a-human",
            "[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 2 }\n",
            vec![Effect::EditFile],
        )
        .reviewed(vec![ReviewBehavior::NeedsHuman]),
        // §11.3: two review passes per attempt, so `AttemptRecord.reviews`
        // carries more than one entry through serialize → deserialize. The
        // list replaced a scalar pair in step 9; this is what proves the
        // new shape survives the wire.
        Scenario::new(
            "second-opinion-passes",
            SECOND_OPINION_CONFIG,
            vec![Effect::EditFile],
        )
        .cross_vendor(FRONTIER_AUTH_PLAN, vec![ReviewBehavior::Pass]),
        // And the same with the second reviewer rejecting, so a `false`
        // verdict on a non-final pass replays too.
        Scenario::new(
            "second-opinion-rejects",
            SECOND_OPINION_CONFIG,
            vec![Effect::EditFile],
        )
        .cross_vendor(FRONTIER_AUTH_PLAN, vec![ReviewBehavior::Fail])
        .answered(vec![Answer::Declined]),
        // The anti-self-review rebind: the acceptance pass runs on a model
        // no chain rung names, so the record has to carry the binding
        // rather than let a replay re-derive it.
        Scenario::new(
            "self-review-rebind",
            FRONTIER_ONLY_CONFIG,
            vec![Effect::EditFile],
        )
        .cross_vendor(FRONTIER_AUTH_PLAN, vec![ReviewBehavior::Pass]),
        // Step 10's two new branches. `budget_exceeded` folds into a
        // run-level field and `capacity_snapshot` folds into nothing —
        // opposite shapes, and both have to come back the same on replay.
        Scenario::new(
            "budget-stop",
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [budgets]\nrun_usd = 0.05\n",
            vec![Effect::EditFile],
        ),
        // And the ApproveSpend park, whose fold depends on the escalation
        // having landed *before* the park — the ordering D3 turns on.
        Scenario::new(
            "approve-spend",
            "[routing]\nimplement = { chain = [\"mid\", \"frontier\"], attempts_per = 1 }\n\n\
                 [interaction]\nask_before = { frontier_escalation_over_usd = 0.005 }\n",
            vec![Effect::NoEdit, Effect::EditFile],
        )
        .answered(vec![Answer::Answered {
            text: "approve: run the escalated attempt".to_owned(),
        }]),
    ];

    for Scenario {
        name,
        config,
        plan,
        effects,
        reviews,
        second_opinion,
        answers,
    } in scenarios
    {
        let repo = temp_engine_repo(&format!("replay-{name}"));
        seed(
            &repo,
            plan.unwrap_or(
                "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
                     ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
            ),
            Some(config),
        );
        let mut opts = options(&repo);
        opts.config_path = Some(repo.join("tactus.toml"));
        let cross_vendor_scenario = second_opinion.is_some();
        let source = match second_opinion {
            Some(second) => cross_vendor(effects, reviews, second),
            None => source(effects, reviews),
        };
        let scripted = ScriptedAnswers::new(answers);
        let (report, live) = run_harness_inner(
            &opts,
            &Harness {
                adapters: &source,
                answers: Some(&scripted),
                sleeper: None,
            },
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        // A cross-vendor scenario that quietly resolved to one pass would
        // still replay identically and prove nothing about the shape this
        // step introduced. Check the run did what the scenario claims
        // before trusting the equality below.
        if cross_vendor_scenario {
            let judged: Vec<&str> = report
                .tasks
                .iter()
                .flat_map(|t| &t.attempts)
                .flat_map(|a| &a.reviews)
                .map(|r| r.agent.as_str())
                .collect();
            assert!(
                judged.contains(&"copilot"),
                "{name}: the second vendor never judged anything, so this scenario \
                     exercises nothing new: {judged:?}"
            );
        }
        assert_live_equals_replay(&repo, &live, &report);
    }
}

#[test]
fn an_aborting_error_still_leaves_a_replayable_log() {
    // The engine dying between the agent's edits and a verdict is §19's
    // "engine crash" row. Nothing gets to write a tidy ending, so the log
    // has to be enough on its own.
    let repo = temp_engine_repo("abortlog");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // Run it through, then rewind the log by hand: reproducing a real
    // abort at exactly this point needs a failure the fake adapter cannot
    // raise, and the on-disk shape is what this test is actually about.
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Pass]);
    opts.attempt_timeout = Duration::from_secs(60);
    let report = run_with(&opts, &source).expect("the run itself succeeds");

    // Now truncate the log to the moment before the attempt reported, the
    // exact on-disk shape a kill leaves, and confirm it still folds.
    let paths = paths_of(&repo, &report.run_id);
    let text = fs::read_to_string(paths.events()).expect("log");
    let lines: Vec<&str> = text.lines().collect();
    let cut = lines
        .iter()
        .position(|line| line.contains("\"attempt_finished\""))
        .expect("the run recorded an attempt");
    fs::write(paths.events(), format!("{}\n", lines[..cut].join("\n"))).expect("truncate");

    let replayed = replay_of(&repo, &report.run_id);
    assert_eq!(replayed.interrupted, 1, "the dangling attempt is settled");
    assert!(
        replayed.interrupted_run(),
        "and the run reads as interrupted rather than finished"
    );
    assert_eq!(replayed.state.states[0], TaskState::Pending);
}

#[test]
fn a_run_that_has_spent_nothing_totals_positive_zero() {
    // Observed as `total: $-0.0000` in the ledger of a run whose first
    // attempt was still in flight. This first assertion is the diagnosis,
    // kept because it is the whole reason `total_of` exists: if std ever
    // folds from `+0.0`, the helper can go.
    let nothing: [f64; 0] = [];
    assert!(
        nothing.iter().sum::<f64>().is_sign_negative(),
        "`sum` no longer folds from -0.0, so `total_of` is obsolete"
    );

    assert!(!total_of(&[]).is_sign_negative(), "a spent-nothing total");
    assert_eq!(format!("${:.4}", total_of(&[])), "$0.0000");

    // And the fold change cannot have moved a real total: `+0.0` preserves
    // every value a cost can be.
    let spent = vec![
        task_report_costing(Some(0.25), Some(1.5)),
        task_report_costing(None, None),
        task_report_costing(Some(0.0), None),
    ];
    assert!((total_of(&spent) - 1.75).abs() < f64::EPSILON);
}

/// A report carrying nothing but the two cost columns.
fn task_report_costing(worker: Option<f64>, review: Option<f64>) -> TaskReport {
    TaskReport {
        id: "t".to_owned(),
        title: String::new(),
        model: String::new(),
        status: TaskRunStatus::Skipped,
        duration: Duration::ZERO,
        cost_usd: worker,
        review_models: Vec::new(),
        review_cost_usd: review,
        review_cost_incomplete: false,
        session_id: None,
        attempts: Vec::new(),
    }
}

#[test]
fn a_live_run_reads_as_running_rather_than_halted() {
    // The settlement above, inverted. A run an engine is still driving has
    // a dangling attempt at every instant, exactly like a killed one — so
    // settling unconditionally reports a working attempt as a failure and
    // the whole run as halted. `status` is the only window into a run that
    // holds its own terminal, and a window that lies is worse than none.
    let repo = temp_engine_repo("livestatus");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Waits on the widget\n<!-- tactus: id=t2 kind=implement depends=t1 -->\n\n\
             ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let paths = paths_of(&repo, &report.run_id);

    // Rewind to mid-attempt: the shape a live engine's log has the whole
    // time it is working, not only the shape a kill leaves behind.
    let text = fs::read_to_string(paths.events()).expect("log");
    let lines: Vec<&str> = text.lines().collect();
    let cut = lines
        .iter()
        .position(|line| line.contains("\"attempt_finished\""))
        .expect("an attempt");
    fs::write(paths.events(), format!("{}\n", lines[..cut].join("\n"))).expect("truncate");

    // With nothing holding the run, that shape still means interrupted —
    // and `t2` really is blocked, because on an ended run a dependency that
    // never finished never will.
    let stopped = replay_of(&repo, &report.run_id);
    assert!(stopped.interrupted_run());
    let out = crate::status::render(&stopped);
    assert!(out.contains("skipped (run interrupted)"), "{out}");
    assert!(out.contains("t2: blocked by `t1`"), "{out}");

    // Now hold the lock the way a working engine does — through the same
    // `RunLock` a run takes, not a hand-rolled `flock` on the same path.
    // Which primitive holds a run is `rundir`'s to decide, and a test that
    // reaches around it is testing a lock nothing else uses.
    let lock = RunLock::acquire(&paths.public).expect("simulate a live engine");

    let live = replay_of(&repo, &report.run_id);
    assert!(live.running, "a held lock means an engine is driving this");
    assert_eq!(
        live.interrupted, 0,
        "an attempt in flight has not been interrupted"
    );
    let out = crate::status::render(&live);
    assert!(out.contains("t1: running now"), "{out}");
    // The one the dependency-free pair could not catch: `t2` is waiting on
    // a task that is working, which is what `Queued` means. Reading that as
    // `Blocked` tells the operator a dependency failed when it is running.
    assert!(out.contains("t2: queued"), "{out}");
    assert!(out.contains("t3: queued"), "{out}");
    assert!(out.contains("run in progress"), "{out}");
    for lie in [
        "small failed",
        "skipped (run halted)",
        "skipped (run interrupted)",
        "run complete",
        "run interrupted",
        "blocked by",
    ] {
        assert!(!out.contains(lie), "a live run reported `{lie}`:\n{out}");
    }
    drop(lock);
}

#[test]
fn a_truncated_run_resumes_without_spending_the_interrupted_attempt() {
    // Decision 3, end to end: the attempt shows up in the ledger, the
    // rung's allowance does not, and the task completes on the retry.
    let repo = temp_engine_repo("resumetrunc");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        // One attempt on one rung: if the interrupted attempt had been
        // counted, the task could never commit.
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let report = run_with(&opts, &source).expect("run");
    let run_id = report.run_id.clone();
    let paths = paths_of(&repo, &run_id);

    // Rewind the record to mid-attempt and put the tree back the way a
    // dead agent would have left it.
    let text = fs::read_to_string(paths.events()).expect("log");
    let lines: Vec<&str> = text.lines().collect();
    let cut = lines
        .iter()
        .position(|line| line.contains("\"attempt_finished\""))
        .expect("an attempt");
    fs::write(paths.events(), format!("{}\n", lines[..cut].join("\n"))).expect("truncate");
    git_in(&repo, &["reset", "-q", "--hard", "HEAD~1"]);
    fs::write(repo.join("agent-output.txt"), "half-written\n").expect("residue");

    let source = fake(Effect::EditFile);
    let (resumed, state) = resume_harness_inner(
        &resume_options(&repo, &run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume");

    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(committed(&resumed, "t1"));

    let t1 = task(&resumed, "t1");
    assert_eq!(
        t1.attempts.len(),
        2,
        "the interrupted attempt is on the record beside the one that worked"
    );
    assert_eq!(
        t1.attempts[0].failure.as_ref().map(|f| f.kind),
        Some(FailureKind::Interrupted)
    );
    assert_eq!(
        t1.attempts[0].cost_usd, None,
        "unknown spend is reported as unknown, not as free"
    );
    assert_eq!(t1.attempts[1].tier, "small", "still on the same rung");
    assert!(
        !t1.attempts[1].resumed,
        "§14: the tree was discarded, so the session cannot be trusted"
    );

    // The residue is gone and the branch is linear.
    assert!(
        git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "crash residue discarded"
    );
    assert_eq!(
        git_in(&repo, &["rev-list", "--count", "main..HEAD"]).trim(),
        "1",
        "one commit, not a duplicate of the interrupted attempt's work"
    );
    assert!(
        resumed
            .warnings
            .iter()
            .any(|w| w.contains("discarded") && w.contains("agent-output.txt")),
        "the operator is told what was thrown away: {:?}",
        resumed.warnings
    );
    assert_live_equals_replay(&repo, &state, &resumed);
}

#[test]
fn killing_a_run_mid_attempt_leaves_a_resumable_record() {
    // The real thing: a separate process is driven into an attempt and
    // dies inside it, exactly as `kill -9` or a power cut would.
    let repo = temp_engine_repo("crashkill");
    seed(
        &repo,
        "## First\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Second\n<!-- tactus: id=t2 kind=implement depends=t1 -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );

    let exe = std::env::current_exe().expect("test binary");
    let status = Command::new(exe)
        .args([
            "--exact",
            "engine::tests::crash_child_dies_inside_an_attempt",
            "--ignored",
            "--test-threads",
            "1",
        ])
        .env("TACTUS_CRASH_REPO", &repo)
        .output()
        .expect("spawn the child run");
    assert_eq!(
        status.status.code(),
        Some(CRASH_EXIT_CODE),
        "the child must die inside the attempt, not finish or panic: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    let run_id = rundir::latest_run(&repo).expect("the child started a run");
    let paths = paths_of(&repo, &run_id);

    // What a kill leaves: a dirty tree and an attempt that never reported.
    assert!(
        !git_in(&repo, &["status", "--porcelain"]).trim().is_empty(),
        "the dead agent's edits are still in the tree"
    );
    let log = fs::read_to_string(paths.events()).expect("log");
    let last = log.lines().last().expect("events");
    assert!(
        last.contains("\"attempt_started\"") && last.contains("\"t2\""),
        "the log ends mid-attempt: {last}"
    );
    assert!(
        !log.contains("\"run_finished\""),
        "a killed run never records an ending"
    );

    let before = replay_of(&repo, &run_id);
    assert!(before.interrupted_run(), "status calls it interrupted");
    assert_eq!(before.interrupted, 1);
    assert!(
        crate::status::render(&before).contains(&format!("tactus resume {run_id}")),
        "and tells the operator how to continue it"
    );

    // The lock died with the process, so nothing has to be cleared by hand.
    assert!(
        !rundir::is_running(&paths.public),
        "the OS released the lock"
    );

    // And the summary line says what happened rather than claiming an
    // outcome. A killed run replays into `Complete` — nothing halted it, no
    // budget stopped it, nothing is parked — so the ledger used to be
    // followed by `run complete: 1 task(s) committed` and then, one line
    // later, `state: interrupted`. Two adjacent lines contradicting each
    // other about a run that died mid-attempt with work left undone.
    let rendered = crate::status::render(&before);
    assert!(
        rendered.contains("run interrupted: 1 task(s) committed so far"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("run complete"),
        "a killed run claimed it completed:\n{rendered}"
    );
    // Its unreached tasks were not skipped because the run *halted* — that
    // is a different ending, and one an operator acts on differently.
    assert!(rendered.contains("skipped (run interrupted)"), "{rendered}");

    let source = fake(Effect::EditFile);
    let (resumed, state) = resume_harness_inner(
        &resume_options(&repo, &run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume the killed run");

    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(committed(&resumed, "t1"), "the work it did survived");
    assert!(
        committed(&resumed, "t2"),
        "and the work it died in got done"
    );
    assert_eq!(
        git_in(&repo, &["rev-list", "--count", "main..HEAD"]).trim(),
        "2",
        "one commit per task, with nothing duplicated by the resume"
    );
    let t2 = task(&resumed, "t2");
    assert_eq!(
        t2.attempts[0].failure.as_ref().map(|f| f.kind),
        Some(FailureKind::Interrupted),
        "the attempt it died in is on the record: {t2:?}"
    );
    assert_live_equals_replay(&repo, &state, &resumed);
}

/// Spawned by `killing_a_run_mid_attempt_leaves_a_resumable_record`.
/// Ends its own process on purpose, which is why it must never run as part
/// of the ordinary suite.
#[test]
#[ignore = "spawned by killing_a_run_mid_attempt_leaves_a_resumable_record"]
fn crash_child_dies_inside_an_attempt() {
    let Ok(repo) = std::env::var("TACTUS_CRASH_REPO") else {
        return;
    };
    let repo = PathBuf::from(repo);
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // t1 commits; the process dies inside t2's first attempt.
    let source = source(
        vec![Effect::EditFile, Effect::Exit],
        vec![ReviewBehavior::Pass],
    );
    let _ = run_with(&opts, &source);
    // Only reachable if the adapter never got a second invocation, which
    // would mean this test is not exercising what it claims to.
    std::process::exit(0);
}

#[test]
fn a_parked_run_is_answered_out_of_band_and_resumed() {
    // §21's definition-of-done (d) across processes: the run ends parked,
    // a person answers with `tactus answer` while nothing is running, and
    // the resume picks the answer up.
    let repo = temp_engine_repo("answerresume");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Depends on it\n<!-- tactus: id=t2 kind=implement depends=t1 -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let report = run_with(&opts, &source).expect("run");

    assert_eq!(report.outcome(), RunOutcome::Parked);
    let run_id = report.run_id.clone();
    let question = report
        .questions
        .first()
        .expect("a question was raised")
        .question
        .id
        .to_string();

    // Nothing is running; the answer is written by the CLI path.
    let recorded = crate::answer::answer(
        &repo,
        &question[..8],
        crate::answer::Reply::Text("the widget lives in src/widget.rs".to_owned()),
    )
    .expect("answer by prefix");
    assert_eq!(recorded.run_id, run_id);
    assert!(!recorded.run_is_live);

    let source = fake(Effect::EditFile);
    let (resumed, state) = resume_harness_inner(
        &resume_options(&repo, &run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume");

    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(committed(&resumed, "t1"), "the answer un-parked it");
    assert!(committed(&resumed, "t2"), "and its dependent ran");

    // This adapter is fresh for the resume, so its first invocation is
    // t1's retry — the one the answer released. t2 runs after it.
    let runs = source.adapter.runs();
    let retry = runs.first().expect("a retry ran");
    assert!(
        retry.prompt.contains("src/widget.rs"),
        "the operator's answer reached the agent: {}",
        retry.prompt
    );
    assert!(
        retry.prompt.contains("instruction from a person"),
        "labelled as an instruction, not quoted as data"
    );
    assert_live_equals_replay(&repo, &state, &resumed);
}

#[test]
fn an_answer_arriving_mid_run_unparks_without_a_hard_block() {
    // Invariant 6 at its most useful: the operator answers from elsewhere
    // while other work is still going, and the task is released on the
    // next scheduler turn rather than at the end of the run.
    let repo = temp_engine_repo("midrun");
    seed(
        &repo,
        "## Asks a question\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Independent\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::AskQuestion, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    // Nobody is reachable through the answer *channel* at all: if the
    // sweep did not exist, t1 could only ever end parked.
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&AnsweringViaFile { repo: repo.clone() }),
            sleeper: None,
        },
    )
    .expect("run");

    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");
    assert!(committed(&report, "t1"), "the file answer released it");
    assert!(committed(&report, "t3"));
    let answered = report.questions.first().expect("one question");
    assert!(
        matches!(&answered.answer, Some(Answer::Answered { text }) if text.contains("opaque")),
        "the answer is recorded against the question: {answered:?}"
    );
}

/// Stands in for an operator running `tactus answer` in another terminal
/// while the run is still going: it writes the file and tells the engine
/// nobody replied, so only the sweep can find it.
struct AnsweringViaFile {
    repo: PathBuf,
}

impl AnswerSource for AnsweringViaFile {
    fn id(&self) -> &'static str {
        "test-file-writer"
    }

    fn resolve(&self, question: &Question) -> Result<Answer, TactusError> {
        let _ = crate::answer::answer(
            &self.repo,
            question.id.as_str(),
            crate::answer::Reply::Text("opaque cursors".to_owned()),
        );
        Ok(Answer::Unanswered)
    }
}

#[test]
fn blocking_propagates_transitively_and_against_plan_order() {
    // The chain is listed backwards on purpose: a single pass in plan
    // order would settle `late` before `mid` was known to be blocked, and
    // report it as merely skipped.
    let repo = temp_engine_repo("blocked");
    seed(
        &repo,
        "## Last\n<!-- tactus: id=late kind=implement depends=mid -->\n\n\
             ## Middle\n<!-- tactus: id=mid kind=implement depends=first -->\n\n\
             ## First\n<!-- tactus: id=first kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let report = run_with(&opts, &source).expect("run");

    assert!(matches!(
        task(&report, "first").status,
        TaskRunStatus::Parked { .. }
    ));
    assert!(
        matches!(&task(&report, "mid").status, TaskRunStatus::Blocked { by } if by == "first"),
        "the direct dependent is blocked: {report:?}"
    );
    assert!(
        matches!(&task(&report, "late").status, TaskRunStatus::Blocked { by } if by == "mid"),
        "and so is its dependent, naming the nearest blocker: {report:?}"
    );
}

#[test]
fn answering_a_blocker_releases_the_chain_behind_it() {
    // Blocked is a *view*, not recorded state — which is what lets an
    // answer make a whole chain runnable again on resume.
    let repo = temp_engine_repo("unblock");
    seed(
        &repo,
        "## Last\n<!-- tactus: id=late kind=implement depends=mid -->\n\n\
             ## Middle\n<!-- tactus: id=mid kind=implement depends=first -->\n\n\
             ## First\n<!-- tactus: id=first kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let report = run_with(&opts, &source).expect("run");
    let run_id = report.run_id.clone();
    let question = report.questions[0].question.id.to_string();

    crate::answer::answer(
        &repo,
        &question,
        crate::answer::Reply::Text("write src/first.rs".to_owned()),
    )
    .expect("answer");

    let source = fake(Effect::EditFile);
    let resumed = resume_with(&resume_options(&repo, &run_id), &source).expect("resume");
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    for id in ["first", "mid", "late"] {
        assert!(committed(&resumed, id), "{id} should have run: {resumed:?}");
    }
}

#[test]
fn an_exhausted_pool_and_a_silent_operator_still_terminate() {
    // The drain loop's termination argument, executed: an adapter that
    // never succeeds, a pool that never returns, and a channel nobody
    // answers. Every branch of the loop fires and the run still ends.
    let repo = temp_engine_repo("terminate");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Two\n<!-- tactus: id=t2 kind=implement depends= -->\n\n\
             ## After one\n<!-- tactus: id=t3 kind=implement depends=t1 -->\n",
        Some("[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.max_defers = 2;
    let source = source(vec![Effect::RateLimited], vec![ReviewBehavior::Pass]);
    let answers = CountingAnswers::default();
    let sleeper = RecordingSleeper::default();
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: Some(&sleeper),
        },
    )
    .expect("the run terminates rather than spinning");

    assert_eq!(report.outcome(), RunOutcome::Parked);
    for id in ["t1", "t2"] {
        assert!(
            matches!(task(&report, id).status, TaskRunStatus::Parked { .. }),
            "{id}: {report:?}"
        );
    }
    assert!(matches!(
        task(&report, "t3").status,
        TaskRunStatus::Blocked { .. }
    ));
    assert_eq!(
        answers.count(),
        2,
        "each question is asked exactly once, however many times the loop turns"
    );
    assert!(
        !sleeper.waits().is_empty(),
        "the deferral branch really fired"
    );
    assert!(
        sleeper.waits().len() <= 8,
        "and it was bounded: {:?}",
        sleeper.waits()
    );
}

// ---- step 8: resume refuses rather than guessing -----------------------

fn resume_err(repo: &Path, run_id: &str) -> String {
    let source = fake(Effect::EditFile);
    resume_with(&resume_options(repo, run_id), &source)
        .expect_err("resume must refuse")
        .to_string()
}

/// The base config every parked-run fixture starts from: one rung, one
/// attempt, no interaction — so a task that cannot pass parks immediately.
const PARKED_RUN_CONFIG: &str = "[interaction]\nmode = \"never\"\n\n\
         [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n";

/// A run that ends parked — the resumable shape every refusal test starts
/// from, so each one isolates exactly the thing it breaks.
fn parked_run(tag: &str) -> (PathBuf, String) {
    parked_run_with_config(tag, PARKED_RUN_CONFIG)
}

/// As [`parked_run`], with the config spelled out — for the tests that need
/// a `[[gates]]` section in the record.
///
/// One recipe, not two: the chains check runs before anything gate-related,
/// so a copy whose `[routing]` line drifted from the original would fail
/// these tests on "routing has changed" and point at the wrong thing.
fn parked_run_with_config(tag: &str, config: &str) -> (PathBuf, String) {
    let repo = temp_engine_repo(tag);
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(config),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Parked);
    (repo, report.run_id)
}

#[test]
fn resume_refuses_schema_two_failed_attempt_without_recorded_decision() {
    let (repo, run_id) = parked_run("legacyfailedprefix");
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_two(&paths);
    strip_event_field(&paths, "attempt_finished", "parking");
    truncate_log_after(&paths, "attempt_finished");
    let before = fs::read(paths.events()).expect("legacy prefix");

    let error = resume_err(&repo, &run_id);
    assert!(error.contains("failed attempt 1"), "{error}");
    assert!(
        error.contains("without its durable ladder or parking decision"),
        "{error}"
    );
    assert_eq!(
        fs::read(paths.events()).expect("refused log"),
        before,
        "refusal must not upgrade or otherwise mutate the ambiguous prefix"
    );
}

#[test]
fn resume_refuses_when_the_branch_moved_under_it() {
    // §15's HEAD check. Something committed after the run stopped, so the
    // log no longer describes what is on the branch.
    let (repo, run_id) = parked_run("headmoved");
    fs::write(repo.join("someone-else.txt"), "a hand-made commit\n").expect("file");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "not the engine's work"]);

    let err = resume_err(&repo, &run_id);
    assert!(err.contains("record ends at"), "got: {err}");
    assert!(
        err.contains("Move the branch back"),
        "and says what to do: {err}"
    );
}

#[test]
fn resume_refuses_when_the_frozen_plan_changed() {
    let (repo, run_id) = parked_run("planmoved");
    fs::write(
        repo.join("plan.md"),
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\nNow with a body.\n",
    )
    .expect("edit the plan");

    let err = resume_err(&repo, &run_id);
    assert!(
        err.contains("has changed since this run froze it"),
        "got: {err}"
    );
    assert!(
        err.contains("attribute work to the wrong tasks"),
        "and why it matters: {err}"
    );
}

#[test]
fn status_export_and_resume_refuse_mutated_normalized_plan_bytes() {
    let (repo, run_id) = parked_run("normalized-plan-tamper");
    let plan_path = paths_of(&repo, &run_id).plan_json();
    let mut plan: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("frozen plan"))
            .expect("valid frozen plan");
    plan["tasks"][0]["title"] =
        serde_json::Value::String("tampered but self-hash unchanged".to_owned());
    fs::write(
        &plan_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&plan).expect("serialize plan")
        ),
    )
    .expect("replace frozen plan");

    let status_error = match crate::status::load(&repo, Some(&run_id)) {
        Ok(_) => panic!("status must authenticate the exact normalized bytes"),
        Err(error) => error.to_string(),
    };
    assert!(
        status_error.contains("normalized plan digest"),
        "{status_error}"
    );

    let export_error = match crate::export::load(&repo, &run_id) {
        Ok(_) => panic!("export must authenticate the exact normalized bytes"),
        Err(error) => error.to_string(),
    };
    assert!(
        export_error.contains("normalized plan digest"),
        "{export_error}"
    );

    let resume_error = resume_err(&repo, &run_id);
    assert!(
        resume_error.contains("exact bytes") && resume_error.contains("normalized-plan digest"),
        "{resume_error}"
    );
}

#[test]
fn resume_refuses_schema_two_spend_question_without_task_parked() {
    let (repo, run_id) = parked_run("legacyspendprefix");
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_two(&paths);
    strip_event_field(&paths, "attempt_finished", "parking");
    truncate_log_after(&paths, "attempt_finished");
    let mut warnings = Vec::new();
    let mut log = EventLog::open(EventSite::LegacyOpenLog, &paths.events(), &mut warnings)
        .expect("legacy log");
    log.append(
        EventSite::LegacyAppend,
        EventBody::LadderEscalated {
            task: "t1".to_owned(),
            attempt: 1,
            rung: 0,
            data: events::LadderEscalated {
                to_rung: 1,
                tier: "small".to_owned(),
                summary: "escalate".to_owned(),
                detail: None,
            },
        },
    )
    .expect("legacy escalation");
    log.append(
        EventSite::LegacyAppend,
        EventBody::QuestionRaised {
            task: "t1".to_owned(),
            data: Box::new(events::QuestionRaised {
                question: Question {
                    id: QuestionId::from("q-spend-prefix"),
                    kind: QuestionKind::ApproveSpend,
                    affected_tasks: vec![TaskId::from("t1")],
                    context: "approve spend".to_owned(),
                    options: Vec::new(),
                },
            }),
        },
    )
    .expect("legacy question");
    drop(log);
    let before = fs::read(paths.events()).expect("ambiguous prefix");

    let error = resume_err(&repo, &run_id);
    assert!(error.contains("ApproveSpend"), "{error}");
    assert!(error.contains("before durably parking the task"), "{error}");
    assert_eq!(
        fs::read(paths.events()).expect("refused log"),
        before,
        "refusal never upgrades the spend-approval gap"
    );
}

#[test]
fn legacy_status_still_refuses_a_mismatched_self_reported_plan_hash() {
    let (repo, run_id) = parked_run("legacy-status-plan-hash");
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_two(&paths);
    let plan_path = paths.plan_json();
    let mut plan: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).expect("frozen plan"))
            .expect("valid frozen plan");
    plan["source"]["hash"] = serde_json::Value::String("different-plan".to_owned());
    fs::write(
        &plan_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&plan).expect("serialize plan")
        ),
    )
    .expect("replace frozen plan");

    let error = match crate::status::load(&repo, Some(&run_id)) {
        Ok(_) => panic!("legacy status retains its source-hash boundary"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("frozen plan hash"), "{error}");
    assert!(error.contains("different-plan"), "{error}");
}

#[test]
fn legacy_upgrade_never_blesses_a_modified_normalized_snapshot() {
    let (repo, run_id) = parked_run("legacy-plan-upgrade-tamper");
    let paths = paths_of(&repo, &run_id);
    rewrite_run_started_as_schema_two(&paths);
    let plan_path = paths.plan_json();
    let mut plan: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).expect("frozen plan"))
            .expect("valid frozen plan");
    plan["tasks"][0]["title"] = serde_json::Value::String("modified snapshot".to_owned());
    fs::write(
        &plan_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&plan).expect("serialize plan")
        ),
    )
    .expect("tamper legacy snapshot");
    let before = fs::read(paths.events()).expect("legacy log");

    let error = resume_err(&repo, &run_id);
    assert!(error.contains("Refusing to bless"), "{error}");
    assert_eq!(
        fs::read(paths.events()).expect("refused log"),
        before,
        "refusal happens before the schema upgrade append"
    );
}

#[test]
fn resume_compares_canonical_source_semantics_to_the_recorded_plan_digest() {
    let (repo, run_id) = parked_run("source-semantics-digest");
    fs::write(
        repo.join("plan.md"),
        "## Changed semantics\n<!-- tactus: id=t1 kind=implement depends= -->\nDifferent body.\n",
    )
    .expect("change source plan");
    let new_hash = crate::ir::content_hash(&fs::read(repo.join("plan.md")).expect("plan"));
    let paths = paths_of(&repo, &run_id);
    let text = fs::read_to_string(paths.events()).expect("log");
    let rewritten = text
        .lines()
        .map(|line| {
            let mut value: serde_json::Value = serde_json::from_str(line).expect("event");
            if value["event"] == "run_started" {
                value["data"]["plan_hash"] = serde_json::Value::String(new_hash.clone());
            }
            value.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(paths.events(), format!("{rewritten}\n")).expect("force legacy hash guard equal");

    let error = resume_err(&repo, &run_id);
    assert!(
        error.contains("validated source plan now normalizes to digest"),
        "{error}"
    );
}

#[test]
fn resume_refuses_when_routing_moved_under_a_recorded_rung() {
    // `Progress.rung` is an index into the chain; re-resolving a different
    // chain would point it at another tier without saying so.
    let (repo, run_id) = parked_run("chainmoved");
    fs::write(
        repo.join("tactus.toml"),
        "[interaction]\nmode = \"never\"\n\n\
             [routing]\nimplement = { chain = [\"mid\", \"frontier\"], attempts_per = 1 }\n",
    )
    .expect("edit config");

    let err = resume_err(&repo, &run_id);
    assert!(err.contains("routing has changed"), "got: {err}");
    assert!(err.contains("`t1` ran on [small]"), "names the task: {err}");
}

/// [`parked_run`], with one `[[gates]]` entry — the resumable shape for the
/// gate tests, which need a recorded gate to diverge from.
fn parked_run_with_gate(tag: &str, cmd: &str) -> (PathBuf, String) {
    parked_run_with_config(tag, &gate_config(cmd))
}

/// [`PARKED_RUN_CONFIG`] plus a `check` gate running `cmd`.
fn gate_config(cmd: &str) -> String {
    format!("{PARKED_RUN_CONFIG}\n[[gates]]\nname = \"check\"\ncmd = \"{cmd}\"\n")
}

/// Resume and answer the question the parked task is waiting on, so the
/// task actually runs again and its gates actually execute.
fn resume_answering(repo: &Path, run_id: &str, effect: Effect) -> RunReport {
    let source = source(vec![effect], vec![ReviewBehavior::Pass]);
    let answers = ScriptedAnswers::new(vec![Answer::Answered {
        text: "carry on".to_owned(),
    }]);
    resume_harness(
        &resume_options(repo, run_id),
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("resume")
}

#[test]
fn resume_runs_the_gates_the_run_recorded_not_todays() {
    // The load-bearing test for the whole gate record, and behavioural
    // rather than textual: the recorded gate passes, today's config would
    // fail, and the task commits — which it can only do if the gate that
    // actually executed came from the log.
    //
    // This is the self-hosting hazard from the gate-config record, closed
    // at the point
    // that matters. The workspace an implementer edits contains the very
    // tactus.toml its gates come from, so an edited gate must not become
    // the standard for what follows. Refusing would also have stopped the
    // weakened gate running, but it would have stopped the *run* too, and
    // a legitimately-committed config edit would have left it unresumable.
    let (repo, run_id) = parked_run_with_gate("gaterecorded", "git --version");
    // `git` still resolves at pre-flight, so nothing refuses before the
    // gate runs — it just exits non-zero when it does.
    fs::write(
        repo.join("tactus.toml"),
        gate_config("git frobnicate-not-a-command"),
    )
    .expect("edit config");

    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(
        committed(&resumed, "t1"),
        "the recorded gate ran, not the one in today's config: {resumed:?}"
    );
    // And the operator learns their edit did not take effect here, rather
    // than concluding the gate is broken when it never ran.
    let warning = resumed
        .warnings
        .iter()
        .find(|w| w.contains("differ from the ones this run recorded"))
        .unwrap_or_else(|| panic!("no gate-difference warning: {:?}", resumed.warnings));
    assert!(
        warning.contains(
            "`check` runs `git --version` and today's config says `git \
                              frobnicate-not-a-command`"
        ),
        "names the edit: {warning}"
    );
    assert!(
        warning.contains("Start a new run to adopt them"),
        "and what to do about it: {warning}"
    );
    // The report describes the gates that ran, not the ones on disk.
    assert_eq!(resumed.gates, ["check"]);
}

#[test]
fn the_report_labels_gates_from_the_record_not_todays_config() {
    // `gates` came from the record but `gates_from_config` did not, so the
    // run's own report and a later `status` disagreed about the same list:
    // `finish()` read today's analysis while `RunReport::from_state` read
    // the record. The doc above `from_state` promises those two cannot
    // drift, and this is the one field that still let them.
    let (repo, run_id) = parked_run_with_gate("gatelabel", "git --version");
    // `[[gates]]` deleted, so today's flag would be false and today's
    // derivation empty — the temp repo has no project marker.
    fs::write(repo.join("tactus.toml"), PARKED_RUN_CONFIG).expect("edit config");

    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(resumed.gates, ["check"], "the recorded gate ran");
    assert!(
        resumed.gates_from_config,
        "and is labelled as the record has it, not as today's config would"
    );
    // The other half of the same promise: a reader replaying the log agrees.
    let replayed = replay_of(&repo, &run_id).report();
    assert_eq!(replayed.gates, resumed.gates);
    assert_eq!(replayed.gates_from_config, resumed.gates_from_config);
}

#[test]
fn a_resume_whose_gates_did_not_move_says_nothing_about_them() {
    // The success path, with a non-empty gate list — the direction a false
    // positive would break. Every other gate test edits the config, so
    // without this one an over-eager comparison (order, whitespace, a
    // re-derived timeout) would warn on every ordinary resume unnoticed.
    let (repo, run_id) = parked_run_with_gate("gateunmoved", "git --version");
    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(
        !resumed
            .warnings
            .iter()
            .any(|w| w.contains("gates") && w.contains("recorded")),
        "an untouched config must warn about nothing: {:?}",
        resumed.warnings
    );
}

#[test]
fn a_gate_difference_is_described_without_inventing_edits() {
    // `[[gates]]` does not require unique names, so the obvious by-name
    // lookup answers for the wrong entry: it reports edits nobody made,
    // and — worse — finds every name present and concludes "reordered"
    // when a gate was added. Each case here produced a false sentence
    // before the comparison paired whole gates instead of names.
    let gate = |name: &str, cmd: &str| GateSummary {
        name: name.to_owned(),
        cmd: cmd.to_owned(),
        timeout: Duration::from_secs(600),
        shell: crate::gates::ShellKind::Sh,
    };
    let check = gate("check", "cargo test");
    let only_check = std::slice::from_ref(&check);

    assert_eq!(
        gates_differ(only_check, only_check),
        None,
        "identical gates are not a difference"
    );

    // A duplicate name added. The record's `check` is present and unchanged,
    // so nothing was edited and nothing reordered — one gate appeared.
    let added =
        gates_differ(only_check, &[check.clone(), gate("check", "true")]).expect("a difference");
    assert!(
        added.contains("`check` (`true`) is in today's config and not in the record"),
        "names the added gate: {added}"
    );
    assert!(
        !added.contains("different order"),
        "and does not invent a reorder: {added}"
    );

    // One of two same-named gates removed. Pairing by name would report
    // `check` as edited from one command to the other; both are real
    // entries and neither changed.
    let removed = gates_differ(&[check.clone(), gate("check", "cargo clippy")], only_check)
        .expect("a difference");
    assert!(
        removed.contains("`check` (`cargo clippy`) is in the record and not in today's config"),
        "names the removed gate: {removed}"
    );

    // An unambiguous single-name edit still reads as one edit.
    let edited = gates_differ(only_check, &[gate("check", "true")]).expect("a difference");
    assert!(
        edited.contains("`check` runs `cargo test` and today's config says `true`"),
        "{edited}"
    );

    // A rename is two facts, and saying so beats guessing which gate the
    // operator meant to rename into which.
    let renamed = gates_differ(only_check, &[gate("verify", "cargo test")]).expect("a difference");
    assert!(
        renamed.contains("`check` (`cargo test`) is in the record"),
        "{renamed}"
    );
    assert!(
        renamed.contains("`verify` (`cargo test`) is in today's config"),
        "{renamed}"
    );

    // Shell and timeout are recorded because they decide what a command
    // means and how long it has to mean it — `true` always passes under sh
    // and is not a program at all under cmd.
    let reshelled = gates_differ(
        only_check,
        &[GateSummary {
            shell: crate::gates::ShellKind::Bash,
            ..check.clone()
        }],
    )
    .expect("a difference");
    assert!(
        reshelled.contains("`check` runs under `sh` and today's config says `bash`"),
        "{reshelled}"
    );

    // Same gates, different order: a difference worth a line, but not the
    // same claim as a changed command.
    let other = gate("test", "cargo test");
    let reordered =
        gates_differ(&[check.clone(), other.clone()], &[other, check]).expect("a difference");
    assert!(reordered.contains("in a different order"), "{reordered}");
    assert!(
        !reordered.contains("not in the record"),
        "nothing came or went: {reordered}"
    );
}

#[test]
fn a_log_that_predates_the_gate_record_rederives_and_says_what_it_can() {
    // A v0.1 log recorded gate names and nothing else. Refusing would
    // strand every run written before the record over a field it could
    // never have carried, so resume re-derives — and uses the one thing
    // such a log *does* have. A moved name is proof the standard changed,
    // not a suspicion, and the warning says which.
    let (repo, run_id) = parked_run_with_gate("oldgatelog", "git --version");
    strip_run_started_field(&paths_of(&repo, &run_id), "gate_cmds");
    // Re-derivation must be a real re-derivation, or this test would pass
    // against a resume that ignored today's config entirely.
    fs::write(
        repo.join("tactus.toml"),
        format!("{PARKED_RUN_CONFIG}\n[[gates]]\nname = \"renamed\"\ncmd = \"git --version\"\n"),
    )
    .expect("edit config");

    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    let warning = resumed
        .warnings
        .iter()
        .find(|w| w.contains("predates the gate record"))
        .unwrap_or_else(|| panic!("no warning: {:?}", resumed.warnings));
    assert!(
        warning.contains("the gate names have moved"),
        "an old log still knows this much: {warning}"
    );
    assert!(
        warning.contains("recorded [check]") && warning.contains("resolves [renamed]"),
        "and says which: {warning}"
    );
}

#[test]
fn the_resume_that_rederives_an_old_logs_gates_records_them_for_the_next_one() {
    // Without this, the pre-record population never gains a record: every
    // resume re-derives, so a gate weakened between two of them is adopted
    // silently — the exact substitution the record exists to prevent,
    // surviving in the one population that could not carry it.
    //
    // Behavioural, and it takes two resumes to show: the first establishes
    // `git --version`, the gate is then weakened to something that fails,
    // and the second must still commit. It can only do that by running the
    // gate the first resume wrote down.
    let (repo, run_id) = parked_run_with_gate("oldgateestablish", "git --version");
    strip_run_started_field(&paths_of(&repo, &run_id), "gate_cmds");

    // First resume: nothing to rebuild from, so it re-derives and says so.
    // `Effect::NoEdit` leaves the task parked, so there is a second resume
    // to make.
    let first = resume_answering(&repo, &run_id, Effect::NoEdit);
    assert_eq!(first.outcome(), RunOutcome::Parked, "{first:?}");
    assert!(
        first
            .warnings
            .iter()
            .any(|w| w.contains("predates the gate record")),
        "the first resume re-derived: {:?}",
        first.warnings
    );

    // It wrote down what it settled on.
    let paths = paths_of(&repo, &run_id);
    let mut log_warnings = Vec::new();
    let logged = events::read_all(&paths.events(), &mut log_warnings).expect("log");
    let established = events::recorded_gates(&logged).expect("the resume recorded its gates");
    assert_eq!(established.len(), 1);
    assert_eq!(established[0].cmd, "git --version");

    // Now weaken the gate, exactly as an implementer editing the workspace
    // would. Under the old behaviour the second resume re-derived and
    // adopted this.
    fs::write(
        repo.join("tactus.toml"),
        gate_config("git frobnicate-not-a-command"),
    )
    .expect("edit config");

    let second = resume_answering(&repo, &run_id, Effect::EditFile);
    assert_eq!(second.outcome(), RunOutcome::Complete, "{second:?}");
    assert!(
        committed(&second, "t1"),
        "the established gate ran, not the weakened one: {second:?}"
    );
    // And it is an ordinary record-bearing resume now: it warns about the
    // difference rather than about the log's age.
    assert!(
        second
            .warnings
            .iter()
            .any(|w| w.contains("differ from the ones this run recorded")),
        "{:?}",
        second.warnings
    );
    assert!(
        !second
            .warnings
            .iter()
            .any(|w| w.contains("predates the gate record")),
        "the log is no longer speechless about its gates: {:?}",
        second.warnings
    );
}

#[test]
fn an_old_gateless_log_is_not_warned_at_about_nothing() {
    // The run recorded no gates and none resolve today, so no command can
    // have hidden behind an unchanged name. A warning here would fire on
    // every gateless pre-record run, and one that cries wolf on the
    // harmless case is not read on the harmful one.
    let (repo, run_id) = parked_run("oldgatelessslog");
    strip_run_started_field(&paths_of(&repo, &run_id), "gate_cmds");

    let resumed = resume_answering(&repo, &run_id, Effect::EditFile);
    assert!(
        !resumed.warnings.iter().any(|w| w.contains("gate")),
        "nothing to say: {:?}",
        resumed.warnings
    );
}

#[test]
fn resume_refuses_when_the_run_branch_is_gone() {
    let (repo, run_id) = parked_run("branchgone");
    let branch = git_in(&repo, &["rev-parse", "--abbrev-ref", "HEAD"])
        .trim()
        .to_owned();
    git_in(&repo, &["switch", "-q", "main"]);
    git_in(&repo, &["branch", "-q", "-D", &branch]);

    let err = resume_err(&repo, &run_id);
    assert!(err.contains("no longer exists"), "got: {err}");
}

#[test]
fn resume_refuses_to_switch_over_uncommitted_work() {
    let (repo, run_id) = parked_run("dirtyelsewhere");
    git_in(&repo, &["switch", "-q", "main"]);
    fs::write(
        repo.join("my-own-work.txt"),
        "not the engine's to discard\n",
    )
    .expect("file");

    let err = resume_err(&repo, &run_id);
    assert!(err.contains("Commit or stash"), "got: {err}");
    assert!(
        repo.join("my-own-work.txt").exists(),
        "a refusal must not destroy the work it refused over"
    );
}

#[test]
fn resume_refuses_a_run_that_already_finished_or_halted() {
    let repo = temp_engine_repo("finished");
    let complete = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &complete).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete);
    let err = resume_err(&repo, &report.run_id);
    assert!(err.contains("already completed"), "got: {err}");

    let repo = temp_engine_repo("halted");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let answers = ScriptedAnswers::new(vec![Answer::Declined]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run");
    assert_eq!(report.outcome(), RunOutcome::Halted);
    let err = resume_err(&repo, &report.run_id);
    assert!(err.contains("halted at `t1`"), "got: {err}");
}

#[test]
fn resume_refuses_while_another_process_holds_the_run() {
    let (repo, run_id) = parked_run("locked");
    let paths = paths_of(&repo, &run_id);
    let _held = RunLock::acquire(&paths.public).expect("hold it");

    let err = resume_err(&repo, &run_id);
    assert!(err.contains("already driving run"), "got: {err}");
}

#[test]
fn an_unknown_run_id_lists_what_is_there() {
    let (repo, _) = parked_run("unknownid");
    let err = resume_err(&repo, "01NOPE");
    assert!(err.contains("known runs"), "got: {err}");
}

// ---- step 8: status and the ledger -------------------------------------

#[test]
fn status_reports_a_live_run_and_the_ledger_reads_from_the_log() {
    let repo = temp_engine_repo("statusledger");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");

    let loaded = replay_of(&repo, &report.run_id);
    assert!(!loaded.running, "nothing holds a finished run");
    assert!(!loaded.interrupted_run());

    let rendered = crate::status::render(&loaded);
    assert!(rendered.contains("ledger:"), "{rendered}");
    assert!(rendered.contains("t1"), "{rendered}");
    assert!(
        // No pools file in these tests, so no attempt names a pool — and
        // the ledger says exactly that rather than showing a blank column
        // that reads as "nothing was spent".
        rendered.contains("per-pool drain: no pool is connected"),
        "{rendered}"
    );
    assert!(
        rendered.contains(&loaded.paths.private.display().to_string()),
        "and points at where the transcripts actually are"
    );

    // The ledger totals are the run's, derived from the log rather than
    // carried over from the process that wrote it.
    assert!(
        (loaded.report().total_cost_usd - report.total_cost_usd).abs() < 1e-9,
        "{} vs {}",
        loaded.report().total_cost_usd,
        report.total_cost_usd
    );

    // Holding the lock on a run that has already recorded its finish does
    // not make it live again. It says a process has claimed the run —
    // which is what a `resume` looks like before it writes anything — and
    // leaves the outcome above alone. A live run is covered by
    // `a_live_run_reads_as_running_rather_than_halted`, which truncates the
    // log so that the run genuinely has somewhere left to go.
    let paths = paths_of(&repo, &report.run_id);
    let _held = RunLock::acquire(&paths.public).expect("claim the finished run");
    let claimed = replay_of(&repo, &report.run_id);
    assert!(!claimed.running, "a finished run is not running");
    assert!(claimed.held, "but something does hold it");
    let rendered = crate::status::render(&claimed);
    assert!(
        rendered.contains("another process holds this run"),
        "{rendered}"
    );
    assert!(rendered.contains("run complete"), "{rendered}");
    assert!(!rendered.contains("run in progress"), "{rendered}");
}

#[test]
fn following_a_finished_run_replays_it_and_stops() {
    let repo = temp_engine_repo("follow");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");

    let loaded = replay_of(&repo, &report.run_id);
    let sleeper = RecordingSleeper::default();
    let mut out: Vec<u8> = Vec::new();
    crate::status::follow(&loaded, &sleeper, Duration::ZERO, 2, &mut out).expect("follow");
    let text = String::from_utf8(out).expect("utf8");

    assert!(text.contains("run"), "{text}");
    assert!(text.contains("t1: committed"), "{text}");
    assert!(
        text.contains("run finished"),
        "it stops at the ending rather than idling: {text}"
    );
    assert!(
        sleeper.waits().is_empty(),
        "a finished run needs no waiting at all"
    );
    for line in text.lines() {
        assert!(!line.is_empty());
    }
}

#[test]
fn follow_ignores_a_terminal_marker_superseded_by_resume() {
    let repo = temp_engine_repo("followresume");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");
    let paths = paths_of(&repo, &report.run_id);
    let mut warnings = Vec::new();
    let mut log = events::EventLog::open(EventSite::LegacyOpenLog, &paths.events(), &mut warnings)
        .expect("open log");
    log.append(
        EventSite::LegacyAppend,
        EventBody::RunResumed {
            data: events::RunResumed {
                head_sha: "second-epoch".to_owned(),
                interrupted_attempts: 0,
                discarded: Vec::new(),
                gates: None,
                effort_policy: None,
                reviews: None,
                chains: None,
                normalized_plan_digest: None,
            },
        },
    )
    .expect("resume marker");
    log.append(
        EventSite::LegacyAppend,
        EventBody::RunFinished {
            data: events::RunFinished {
                outcome: events::RunOutcome::Complete,
                halted_at: None,
                committed: 1,
                parked: 0,
            },
        },
    )
    .expect("second finish");
    drop(log);

    let loaded = replay_of(&repo, &report.run_id);
    let sleeper = RecordingSleeper::default();
    let mut out = Vec::new();
    crate::status::follow(&loaded, &sleeper, Duration::ZERO, 2, &mut out).expect("follow");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("resumed at second-epo"), "{text}");
    assert_eq!(
        text.matches("run finished").count(),
        2,
        "the historical finish must not truncate the later epoch: {text}"
    );
}

#[test]
fn follow_waits_at_held_historical_terminal_until_resume_marker() {
    struct ResumeOnSleep {
        events: PathBuf,
        lock: Mutex<Option<RunLock>>,
    }

    impl Sleeper for ResumeOnSleep {
        fn sleep(&self, _: Duration) {
            let Ok(mut lock) = self.lock.lock() else {
                return;
            };
            if lock.is_none() {
                return;
            }
            let mut warnings = Vec::new();
            let mut log =
                events::EventLog::open(EventSite::LegacyOpenLog, &self.events, &mut warnings)
                    .expect("log");
            log.append(
                EventSite::LegacyAppend,
                EventBody::RunResumed {
                    data: events::RunResumed {
                        head_sha: "resumed-head".to_owned(),
                        interrupted_attempts: 0,
                        discarded: Vec::new(),
                        gates: None,
                        effort_policy: None,
                        reviews: None,
                        chains: None,
                        normalized_plan_digest: None,
                    },
                },
            )
            .expect("resume marker");
            log.append(
                EventSite::LegacyAppend,
                EventBody::RunFinished {
                    data: events::RunFinished {
                        outcome: events::RunOutcome::Complete,
                        halted_at: None,
                        committed: 1,
                        parked: 0,
                    },
                },
            )
            .expect("new terminal");
            drop(log);
            drop(lock.take());
        }
    }

    let repo = temp_engine_repo("followheldterminal");
    let report = run_with(&options(&repo), &fake(Effect::EditFile)).expect("run");
    let paths = paths_of(&repo, &report.run_id);
    let loaded = replay_of(&repo, &report.run_id);
    let sleeper = ResumeOnSleep {
        events: paths.events(),
        lock: Mutex::new(Some(
            RunLock::acquire(&paths.public).expect("resume owns lock before marker"),
        )),
    };
    let mut out = Vec::new();
    crate::status::follow(&loaded, &sleeper, Duration::ZERO, 1, &mut out).expect("follow");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("resumed at resumed-he"), "{text}");
    assert_eq!(text.matches("run finished").count(), 2, "{text}");
}

#[test]
fn transcripts_live_outside_the_workspace_and_survive_a_rollback() {
    // The §15 split, and the reason the private root cannot be inside the
    // repo: §14's rollback is `git clean -fd`, which would delete it.
    let repo = temp_engine_repo("private");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // The first attempt fails, so a rollback happens before the second.
    let adapters = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &adapters).expect("run");
    let paths = paths_of(&repo, &report.run_id);

    for private in [paths.transcripts(), paths.reviews(), paths.settings()] {
        assert!(
            !private.starts_with(&repo),
            "{} must be outside the workspace",
            private.display()
        );
        assert!(
            fs::read_dir(&private).into_iter().flatten().count() > 0,
            "{} kept its contents across the rollback",
            private.display()
        );
    }
    // The ops surface stays where §15 documents it.
    assert!(paths.events().starts_with(&repo));
    assert!(paths.questions().starts_with(&repo));
    // And nothing agent-authored is reachable from the repo.
    let in_repo = repo.join(".tactus").join("runs").join(&report.run_id);
    for leaked in ["transcripts", "reviews", "settings", "gates"] {
        assert!(
            !in_repo.join(leaked).exists(),
            "{leaked}/ must not exist inside the workspace"
        );
    }
}

// ---- step 8.1: the seams either side of the log ------------------------

/// Drop a field from a log's `run_started` — the shape a log written before
/// that field existed has.
///
/// Selects the event by its tag rather than by line number: `run_started`
/// is first today, and a helper that hard-codes that would silently rewrite
/// an unrelated event the day something precedes it.
fn strip_run_started_field(paths: &RunPaths, field: &str) {
    let text = fs::read_to_string(paths.events()).expect("log");
    let mut stripped = false;
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            let mut value: serde_json::Value =
                serde_json::from_str(line).expect("every line is an event");
            if value.get("event").and_then(|e| e.as_str()) == Some("run_started") {
                if let Some(data) = value.get_mut("data").and_then(|d| d.as_object_mut()) {
                    data.remove(field)
                        .unwrap_or_else(|| panic!("the run recorded no `{field}`"));
                    stripped = true;
                }
            }
            value.to_string()
        })
        .collect();
    assert!(
        stripped,
        "the log has no run_started to strip `{field}` from"
    );
    fs::write(paths.events(), format!("{}\n", rewritten.join("\n"))).expect("rewrite");
}

/// Rewrite the opening event into the exact compatibility shape a
/// schema-1 binary wrote: selected top-level fields absent and no per-chain
/// binding snapshot. Used only by downgrade/resume regressions.
fn rewrite_run_started_as_schema_one(paths: &RunPaths, absent: &[&str]) {
    let text = fs::read_to_string(paths.events()).expect("log");
    let mut rewritten_start = false;
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            let mut value: serde_json::Value =
                serde_json::from_str(line).expect("every line is an event");
            if value.get("event").and_then(|event| event.as_str()) == Some("run_started") {
                let data = value
                    .get_mut("data")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("run_started data");
                data.insert("schema".to_owned(), serde_json::Value::from(1));
                data.remove("normalized_plan_digest");
                for field in absent {
                    data.remove(*field)
                        .unwrap_or_else(|| panic!("the run recorded no `{field}`"));
                }
                for chain in data
                    .get_mut("chains")
                    .and_then(serde_json::Value::as_array_mut)
                    .expect("run_started chains")
                {
                    chain
                        .as_object_mut()
                        .expect("chain object")
                        .remove("bindings")
                        .expect("a schema-2 run records chain bindings");
                }
                rewritten_start = true;
            }
            value.to_string()
        })
        .collect();
    assert!(rewritten_start, "the log has no run_started event");
    fs::write(paths.events(), format!("{}\n", rewritten.join("\n"))).expect("rewrite");
}

/// Rewrite a current start into the shape written immediately before the
/// complete-review contract: schema 2 and no per-pass timeout field.
fn rewrite_run_started_as_schema_two(paths: &RunPaths) {
    rewrite_run_started_as_schema_two_missing_review_fields(paths, &["pass_timeout_secs"]);
}

fn rewrite_run_started_as_schema_two_missing_review_fields(
    paths: &RunPaths,
    absent_review_fields: &[&str],
) {
    let text = fs::read_to_string(paths.events()).expect("log");
    let mut rewritten_start = false;
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            let mut value: serde_json::Value =
                serde_json::from_str(line).expect("every line is an event");
            if value.get("event").and_then(|event| event.as_str()) == Some("run_started") {
                let data = value
                    .get_mut("data")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("run_started data");
                data.insert("schema".to_owned(), serde_json::Value::from(2));
                data.remove("normalized_plan_digest");
                let reviews = data
                    .get_mut("reviews")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("recorded review plan");
                for field in absent_review_fields {
                    reviews
                        .remove(*field)
                        .unwrap_or_else(|| panic!("current review plan records `{field}`"));
                }
                rewritten_start = true;
            }
            value.to_string()
        })
        .collect();
    assert!(rewritten_start, "the log has no run_started event");
    fs::write(paths.events(), format!("{}\n", rewritten.join("\n"))).expect("rewrite");
}

fn strip_event_field(paths: &RunPaths, event: &str, field: &str) {
    rewrite_event_field(paths, event, field, false);
}

fn strip_event_data_field(paths: &RunPaths, event: &str, field: &str) {
    rewrite_event_field(paths, event, field, true);
}

fn rewrite_event_field(paths: &RunPaths, event: &str, field: &str, nested_in_data: bool) {
    let text = fs::read_to_string(paths.events()).expect("log");
    let mut stripped = false;
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            let mut value: serde_json::Value =
                serde_json::from_str(line).expect("every line is an event");
            if value.get("event").and_then(serde_json::Value::as_str) == Some(event) {
                let object = if nested_in_data {
                    value
                        .get_mut("data")
                        .and_then(serde_json::Value::as_object_mut)
                        .expect("event data")
                } else {
                    value.as_object_mut().expect("event object")
                };
                object
                    .remove(field)
                    .unwrap_or_else(|| panic!("{event} records `{field}`"));
                stripped = true;
            }
            value.to_string()
        })
        .collect();
    assert!(stripped, "the log has no `{event}.{field}` to strip");
    fs::write(paths.events(), format!("{}\n", rewritten.join("\n"))).expect("rewrite");
}

/// Rewind a log to just before the named event — the shape a process
/// killed at that instant leaves behind.
fn truncate_log_before(paths: &RunPaths, event: &str) {
    let text = fs::read_to_string(paths.events()).expect("log");
    let lines: Vec<&str> = text.lines().collect();
    let cut = lines
        .iter()
        .position(|line| line.contains(&format!("\"{event}\"")))
        .unwrap_or_else(|| panic!("the run recorded no {event}"));
    fs::write(paths.events(), format!("{}\n", lines[..cut].join("\n"))).expect("truncate");
}

/// Rewind a log through the named event — the shape a process killed
/// immediately after its durable transition leaves behind.
fn truncate_log_after(paths: &RunPaths, event: &str) {
    let text = fs::read_to_string(paths.events()).expect("log");
    let lines: Vec<&str> = text.lines().collect();
    let cut = lines
        .iter()
        .position(|line| line.contains(&format!("\"{event}\"")))
        .unwrap_or_else(|| panic!("the run recorded no {event}"))
        + 1;
    fs::write(paths.events(), format!("{}\n", lines[..cut].join("\n"))).expect("truncate");
}

fn prepared_commit_of(paths: &RunPaths) -> events::PreparedCommit {
    let mut warnings = Vec::new();
    events::read_all(&paths.events(), &mut warnings)
        .expect("read prepared settlement")
        .into_iter()
        .find_map(|event| match event.body {
            EventBody::AttemptFinished {
                prepared_commit: Some(prepared),
                ..
            } => Some(*prepared),
            _ => None,
        })
        .expect("successful settlement records its prepared commit")
}

fn recreate_prepared_pin(repo: &Path, prepared: &events::PreparedCommit, target: &str) {
    let zero = "0".repeat(target.len());
    git_in(repo, &["update-ref", &prepared.pin_ref, target, &zero]);
}

#[test]
fn resume_adopts_the_commit_it_made_but_never_recorded() {
    // §14 commits, reads the sha back, scrubs the tree, and only then
    // appends `task_committed`. A process killed inside those three git
    // calls leaves the branch one commit past its own log — which is what
    // foreign history looks like too. Refusing would tell the operator to
    // reset away a commit that already passed its gates and its review,
    // and to spend the attempt a second time.
    let repo = temp_engine_repo("adoptcommit");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let run_id = report.run_id.clone();
    let paths = paths_of(&repo, &run_id);
    let sha = git_in(&repo, &["rev-parse", "HEAD"]).trim().to_owned();

    // The commit is on the branch; the log stops just short of it.
    truncate_log_before(&paths, "task_committed");

    let source = fake(Effect::EditFile);
    let (resumed, state) = resume_harness_inner(
        &resume_options(&repo, &run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume");

    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(committed(&resumed, "t1"), "adopted rather than redone");
    assert_eq!(
        git_in(&repo, &["rev-parse", "HEAD"]).trim(),
        sha,
        "and the branch was left exactly where it stood"
    );
    assert_eq!(
        git_in(&repo, &["rev-list", "--count", "main..HEAD"]).trim(),
        "1",
        "one commit, not a second one for the same work"
    );
    assert_eq!(
        task(&resumed, "t1").attempts.len(),
        1,
        "the attempt that passed was not spent again: {resumed:?}"
    );
    assert!(
        resumed
            .warnings
            .iter()
            .any(|w| w.contains("adopted commit")),
        "and the operator is told: {:?}",
        resumed.warnings
    );
    assert_live_equals_replay(&repo, &state, &resumed);
}

#[test]
fn resume_recovers_every_prepared_commit_ref_crash_prefix() {
    for (tag, reset_to_parent, recreate_pin) in [
        ("prepared-same-head", true, true),
        ("prepared-head-with-pin", false, true),
        ("prepared-head-no-pin", false, false),
    ] {
        let repo = temp_engine_repo(tag);
        seed(
            &repo,
            "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
            Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
        );
        let mut opts = options(&repo);
        opts.config_path = Some(repo.join("tactus.toml"));
        let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
        let paths = paths_of(&repo, &report.run_id);
        let prepared = prepared_commit_of(&paths);
        truncate_log_before(&paths, "task_committed");
        if reset_to_parent {
            git_in(&repo, &["reset", "-q", "--soft", &prepared.parent_sha]);
        }
        if recreate_pin {
            let target = prepared.commit_sha.clone();
            recreate_prepared_pin(&repo, &prepared, &target);
        }

        let source = fake(Effect::EditFile);
        let resumed = resume_harness(
            &resume_options(&repo, &report.run_id),
            &Harness {
                adapters: &source,
                answers: None,
                sleeper: None,
            },
        )
        .expect("recover exact prepared object");
        assert_eq!(
            resumed.outcome(),
            RunOutcome::Complete,
            "{tag}: {resumed:?}"
        );
        assert_eq!(
            git_in(&repo, &["rev-parse", "HEAD"]).trim(),
            prepared.commit_sha,
            "{tag}: the exact reviewed object is published"
        );
        assert_eq!(task(&resumed, "t1").attempts.len(), 1, "{tag}");
        let workspace = Workspace::open(&repo).expect("workspace");
        assert_eq!(
            workspace
                .prepared_pin_target(&prepared.pin_ref)
                .expect("pin lookup"),
            None,
            "{tag}: recovery cleans the private pin"
        );
    }
}

#[test]
fn resume_removes_a_pin_whose_successful_settlement_never_landed() {
    let repo = temp_engine_repo("prepared-orphan");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let paths = paths_of(&repo, &report.run_id);
    let prepared = prepared_commit_of(&paths);
    truncate_log_before(&paths, "attempt_finished");
    git_in(&repo, &["reset", "-q", "--soft", &prepared.parent_sha]);
    let target = prepared.commit_sha.clone();
    recreate_prepared_pin(&repo, &prepared, &target);

    let source = fake(Effect::EditFile);
    let resumed = resume_harness(
        &resume_options(&repo, &report.run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("orphan pin is not a settlement");
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert_eq!(task(&resumed, "t1").attempts.len(), 2);
    assert!(
        resumed
            .warnings
            .iter()
            .any(|warning| warning.contains("removed orphan prepared commit pin")),
        "{:?}",
        resumed.warnings
    );
    assert_eq!(
        Workspace::open(&repo)
            .expect("workspace")
            .prepared_pin_target(&prepared.pin_ref)
            .expect("pin lookup"),
        None
    );
}

#[test]
fn resume_refuses_a_substituted_prepared_pin_without_deleting_it() {
    let repo = temp_engine_repo("prepared-pin-mismatch");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let paths = paths_of(&repo, &report.run_id);
    let prepared = prepared_commit_of(&paths);
    truncate_log_before(&paths, "task_committed");
    git_in(&repo, &["reset", "-q", "--soft", &prepared.parent_sha]);
    recreate_prepared_pin(&repo, &prepared, &prepared.parent_sha);

    let err = resume_err(&repo, &report.run_id);
    assert!(err.contains("not pinned"), "{err}");
    assert_eq!(
        Workspace::open(&repo)
            .expect("workspace")
            .prepared_pin_target(&prepared.pin_ref)
            .expect("pin lookup")
            .as_deref(),
        Some(prepared.parent_sha.as_str()),
        "refusal never deletes the substituted target"
    );
    assert_eq!(
        git_in(&repo, &["rev-parse", "HEAD"]).trim(),
        prepared.parent_sha,
        "HEAD remains at the recorded parent"
    );
}

#[test]
fn resume_refuses_symbolic_run_ref_at_already_published_prepared_prefix() {
    let repo = temp_engine_repo("prepared-symbolic-run-ref");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let paths = paths_of(&repo, &report.run_id);
    let prepared = prepared_commit_of(&paths);
    truncate_log_before(&paths, "task_committed");
    recreate_prepared_pin(&repo, &prepared, &prepared.commit_sha);

    git_in(&repo, &["branch", "victim", prepared.commit_sha.as_str()]);
    git_in(
        &repo,
        &[
            "symbolic-ref",
            prepared.branch_ref.as_str(),
            "refs/heads/victim",
        ],
    );
    let events_before = fs::read(paths.events()).expect("event bytes before refusal");
    let victim_before = git_in(&repo, &["rev-parse", "refs/heads/victim"]);

    let error = resume_err(&repo, &report.run_id);
    assert!(error.contains("itself symbolic"), "{error}");
    assert_eq!(
        fs::read(paths.events()).expect("event bytes after refusal"),
        events_before,
        "refusal happens before task_committed or any other repair append"
    );
    assert_eq!(
        Workspace::open(&repo)
            .expect("workspace")
            .prepared_pin_target(&prepared.pin_ref)
            .expect("pin lookup")
            .as_deref(),
        Some(prepared.commit_sha.as_str()),
        "refusal preserves the durable prepared pin"
    );
    assert_eq!(
        git_in(&repo, &["rev-parse", "refs/heads/victim"]),
        victim_before,
        "the symbolic run ref never advances or deletes its victim"
    );
    assert_eq!(
        git_in(
            &repo,
            &["symbolic-ref", "--no-recurse", prepared.branch_ref.as_str(),],
        )
        .trim(),
        "refs/heads/victim",
        "refusal preserves the substituted symbolic run ref for inspection"
    );
}

#[test]
fn recovered_prepared_commit_precedes_unrelated_answer_defect_repair() {
    let repo = temp_engine_repo("prepared-before-repair");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let paths = paths_of(&repo, &report.run_id);
    truncate_log_before(&paths, "task_committed");

    // Model an earlier answered question whose DesignDefect append was
    // interrupted. It is unrelated to the later successful settlement,
    // but resume still owes the repair after closing that settlement.
    let question_id = QuestionId::from("q-before-success");
    let question = Question {
        id: question_id.clone(),
        kind: QuestionKind::Unblock,
        affected_tasks: vec![TaskId::from("t1")],
        context: "an earlier question".to_owned(),
        options: Vec::new(),
    };
    let inserted = [
        events::Event::now(EventBody::QuestionRaised {
            task: "t1".to_owned(),
            data: Box::new(events::QuestionRaised {
                question: question.clone(),
            }),
        }),
        events::Event::now(EventBody::TaskParked {
            task: "t1".to_owned(),
            data: events::TaskParked {
                question: question_id.to_string(),
                refund_attempt: false,
            },
        }),
        events::Event::now(EventBody::QuestionAnswered {
            data: events::QuestionAnswered {
                question: question_id,
                answer: Answer::Answered {
                    text: "continue".to_owned(),
                },
                decline_halts_run: None,
                via: "answer-file".to_owned(),
            },
        }),
    ];
    let mut lines: Vec<String> = fs::read_to_string(paths.events())
        .expect("log")
        .lines()
        .map(str::to_owned)
        .collect();
    let before_attempt = lines
        .iter()
        .position(|line| line.contains("\"attempt_started\""))
        .expect("attempt start");
    lines.splice(
        before_attempt..before_attempt,
        inserted
            .iter()
            .map(|event| serde_json::to_string(event).expect("event json")),
    );
    fs::write(paths.events(), format!("{}\n", lines.join("\n"))).expect("insert prefix");

    let source = fake(Effect::EditFile);
    let resumed = resume_harness(
        &resume_options(&repo, &report.run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume closes settlement before repairing older metadata");
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    let logged = events_of(&repo, &report.run_id);
    let settlement = logged
        .iter()
        .rposition(|event| matches!(event.body, EventBody::AttemptFinished { .. }))
        .expect("settlement");
    assert!(
        matches!(
            logged.get(settlement + 1).map(|event| &event.body),
            Some(EventBody::TaskCommitted { task, .. }) if task == "t1"
        ),
        "task_committed must immediately close the prepared settlement"
    );
    assert!(
        logged
            .iter()
            .skip(settlement + 2)
            .any(|event| matches!(event.body, EventBody::DesignDefect { .. })),
        "the older answer repair still lands after the commit"
    );
    events::replay(logged, vec!["t1".to_owned()], &paths.events())
        .expect("the repaired log remains replayable");
}

#[test]
fn resume_refuses_an_arbitrary_tree_with_the_same_parent_and_subject() {
    // Exact object identity, not a plausible subject, is the authority.
    let repo = temp_engine_repo("adoptforeign");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    truncate_log_before(&paths_of(&repo, &report.run_id), "task_committed");
    let subject = git_in(&repo, &["show", "-s", "--format=%s", "HEAD"]);
    fs::write(repo.join("foreign.txt"), "not reviewed\n").expect("foreign tree");
    git_in(&repo, &["add", "foreign.txt"]);
    git_in(&repo, &["commit", "-q", "--amend", "--no-edit"]);
    assert_eq!(
        git_in(&repo, &["show", "-s", "--format=%s", "HEAD"]),
        subject,
        "the substituted commit deliberately has the expected subject"
    );

    let err = resume_err(&repo, &report.run_id);
    assert!(err.contains("record ends at"), "got: {err}");
}

#[test]
fn legacy_success_without_prepared_identity_is_never_adopted_by_subject() {
    let repo = temp_engine_repo("legacy-subject");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let paths = paths_of(&repo, &report.run_id);
    truncate_log_before(&paths, "task_committed");
    rewrite_run_started_as_schema_two(&paths);
    strip_event_field(&paths, "attempt_finished", "prepared_commit");

    let err = resume_err(&repo, &report.run_id);
    assert!(err.contains("subject alone"), "{err}");
    assert_eq!(
        git_in(&repo, &["rev-list", "--count", "main..HEAD"]).trim(),
        "1",
        "refusal preserves the plausible legacy commit"
    );
}

#[test]
fn resume_writes_where_the_run_recorded_not_where_defaults_point() {
    // Which private root a run used is a fact about that run. Recomputing
    // it from today's environment — another HOME, a service account, the
    // no-home fallback — would scatter the rest of its transcripts
    // somewhere `status` never looks.
    let repo = temp_engine_repo("privatedir");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let run_id = report.run_id.clone();
    let recorded = paths_of(&repo, &run_id);
    // Stop before the successful settlement, so this is a genuinely
    // interrupted attempt rather than a settled prepared commit whose pin
    // a real process would still retain.
    truncate_log_before(&recorded, "attempt_finished");
    git_in(&repo, &["reset", "-q", "--hard", "HEAD~1"]);

    // No override, so the resume has to read the location off the record.
    let mut resume = resume_options(&repo, &run_id);
    resume.private_root = None;
    let source = fake(Effect::EditFile);
    let resumed = resume_harness(
        &resume,
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume");
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(
        recorded.transcripts().join("00-t1-2.json").is_file(),
        "the resumed attempt wrote under {}",
        recorded.transcripts().display()
    );
}

#[test]
fn resume_makes_a_stale_question_payload_agree_with_the_log() {
    // The engine emits `question_answered` and then rewrites the payload
    // beside it. A crash in between leaves a file that still reads as
    // open — and `tactus answer` will accept a second answer against it,
    // one no engine can ever ingest, because the log has already closed
    // the question.
    let repo = temp_engine_repo("stalepayload");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let doomed = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let report = run_with(&opts, &doomed).expect("run");
    let run_id = report.run_id.clone();
    let first = report.questions[0].question.id.to_string();

    crate::answer::answer(
        &repo,
        &first,
        crate::answer::Reply::Text("try again".to_owned()),
    )
    .expect("answer");

    // The retry fails the same way, so the run ends parked on a *second*
    // question with the first one answered in the log.
    let retry = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let resumed = resume_with(&resume_options(&repo, &run_id), &retry).expect("resume");
    assert_eq!(resumed.outcome(), RunOutcome::Parked, "{resumed:?}");

    // Rewind the payload to what a crash mid-ingest leaves.
    let questions = rundir::public_dir(&repo, &run_id).join("questions");
    let path = questions.join(format!("{first}.json"));
    let mut record: QuestionRecord =
        serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
    record.answer = None;
    interaction::write_question(&questions, &record).expect("rewrite");
    crate::answer::answer(&repo, &first, crate::answer::Reply::Decline)
        .expect("a stale payload is exactly what makes a second answer look acceptable");

    let source = fake(Effect::EditFile);
    resume_with(&resume_options(&repo, &run_id), &source).expect("second resume");

    let record: QuestionRecord =
        serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
    assert!(
        !record.is_open(),
        "the payload agrees with the log again, so nobody answers it twice"
    );
}

#[test]
fn a_run_that_never_started_leaves_no_directory_behind() {
    // Nothing is on the record until the first event lands. A failure in
    // that window would otherwise leave a run directory with no
    // `events.jsonl`, and since run ids sort newest-last it becomes what a
    // bare `tactus status` reports on — "no event log here" for a run that
    // never began, shadowing the real latest one.
    let repo = temp_engine_repo("husk");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    // Git stores refs as paths, so a branch literally named `tactus` is a
    // file where `tactus/run-<id>` needs a directory: branch creation
    // cannot succeed.
    git_in(&repo, &["branch", "tactus"]);

    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    run_with(&opts, &source).expect_err("the run branch cannot be created");

    assert_eq!(
        rundir::latest_run(&repo),
        None,
        "no husk left behind to shadow the next run"
    );
}

/// An operator working a backlog: they answer some other parked question
/// out of band, reply to this one at the prompt, and then walk away — so a
/// dropped answer never gets a second chance.
struct BacklogAnswers {
    repo: PathBuf,
    used: Mutex<bool>,
}

impl AnswerSource for BacklogAnswers {
    fn id(&self) -> &'static str {
        "backlog"
    }

    fn resolve(&self, question: &Question) -> Result<Answer, TactusError> {
        let Ok(mut used) = self.used.lock() else {
            return Ok(Answer::Unanswered);
        };
        if *used {
            return Ok(Answer::Unanswered);
        }
        *used = true;
        let run = rundir::latest_run(&self.repo).expect("a run");
        let dir = rundir::public_dir(&self.repo, &run).join("questions");
        let other = fs::read_dir(&dir)
            .expect("questions dir")
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".json").map(str::to_owned)
            })
            .find(|id| id.as_str() != question.id.as_str());
        if let Some(other) = other {
            let _ = crate::answer::answer(
                &self.repo,
                &other,
                crate::answer::Reply::Text("write src/other.rs".to_owned()),
            );
        }
        Ok(Answer::Answered {
            text: "write src/widget.rs".to_owned(),
        })
    }
}

#[test]
fn a_typed_answer_survives_another_question_being_answered_at_the_same_time() {
    // Both channels can produce an answer on one scheduler turn. The sweep
    // must not swallow the reply the operator typed: it closed a different
    // question, and discarding this one throws away words a person sat and
    // wrote — words nothing will ask for again.
    let repo = temp_engine_repo("backlog");
    seed(
        &repo,
        "## First\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Second\n<!-- tactus: id=t2 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // Both tasks fail into a question, then both succeed once released.
    let source = source(
        vec![Effect::NoEdit, Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let answers = BacklogAnswers {
        repo: repo.clone(),
        used: Mutex::new(false),
    };
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&answers),
            sleeper: None,
        },
    )
    .expect("run");

    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");
    for id in ["t1", "t2"] {
        assert!(committed(&report, id), "{id} was released: {report:?}");
    }
}

#[test]
fn an_answer_file_that_changes_nothing_does_not_spin_the_scheduler() {
    // `sweep_answers` reports whether anything *changed*, and the drain
    // loop trusts that to mean it made progress. A file the sweep reads
    // but declines to apply — `unanswered`, which `tactus answer` refuses
    // to write but a hand-edit produces — must not read as progress: that
    // branch terminates only because it closes the question it fires for.
    // A regression here hangs this test rather than failing it.
    let repo = temp_engine_repo("nullanswer");
    seed(
        &repo,
        "## Doomed\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[interaction]\nmode = \"never\"\n\n\
                 [routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::NoEdit], vec![ReviewBehavior::Pass]);
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Parked);
    let run_id = report.run_id.clone();
    let question = report.questions[0].question.id.clone();

    let answers = rundir::public_dir(&repo, &run_id).join("answers");
    fs::create_dir_all(&answers).expect("answers dir");
    interaction::write_answer(&answers, &question, &Answer::Unanswered).expect("write");

    let source = fake(Effect::EditFile);
    let resumed = resume_with(&resume_options(&repo, &run_id), &source).expect("resume");
    assert_eq!(
        resumed.outcome(),
        RunOutcome::Parked,
        "still waiting on a real answer, and the run ended saying so: {resumed:?}"
    );
}

/// Holds a run's lock and lets go after a set number of sleeps — an engine
/// that finishes while a follower is waiting on it.
struct LockReleasingSleeper {
    waits: Mutex<u32>,
    release_after: u32,
    lock: Mutex<Option<RunLock>>,
}

impl LockReleasingSleeper {
    fn new(lock: RunLock, release_after: u32) -> Self {
        Self {
            waits: Mutex::new(0),
            release_after,
            lock: Mutex::new(Some(lock)),
        }
    }

    fn waits(&self) -> u32 {
        self.waits.lock().map(|w| *w).unwrap_or(0)
    }
}

impl Sleeper for LockReleasingSleeper {
    fn sleep(&self, _: Duration) {
        let Ok(mut waits) = self.waits.lock() else {
            return;
        };
        *waits += 1;
        if *waits == self.release_after {
            if let Ok(mut lock) = self.lock.lock() {
                drop(lock.take());
            }
        }
    }
}

#[test]
fn following_waits_out_a_silent_live_run_and_stops_once_it_dies() {
    // A whole attempt — the agent's thinking, its tool calls, the gates,
    // the review — folds into one `attempt_finished`, so a healthy run
    // says nothing for minutes at a time. The idle budget exists to
    // release a terminal attached to a dead engine; spending it on a live
    // one drops the operator's view mid-run.
    let repo = temp_engine_repo("followlive");
    let source = fake(Effect::EditFile);
    let report = run_with(&options(&repo), &source).expect("run");
    let paths = paths_of(&repo, &report.run_id);

    // Drop the ending, so `follow` idles rather than stopping at it.
    let text = fs::read_to_string(paths.events()).expect("log");
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| !line.contains("\"run_finished\""))
        .collect();
    fs::write(paths.events(), format!("{}\n", kept.join("\n"))).expect("truncate");

    let loaded = replay_of(&repo, &report.run_id);
    let held = RunLock::acquire(&paths.public).expect("simulate a live engine");
    let sleeper = LockReleasingSleeper::new(held, 5);
    let mut out: Vec<u8> = Vec::new();
    // A budget of one idle poll: without the liveness check this returns
    // after two sleeps, whatever the run is doing.
    crate::status::follow(&loaded, &sleeper, Duration::ZERO, 1, &mut out).expect("follow");

    assert!(
        sleeper.waits() > 5,
        "watched the live run past its idle budget and stopped once the lock went, \
             instead of timing out its silence: {} sleeps",
        sleeper.waits()
    );
}

// ---- step 10: pools, budgets, and spend approval (§13) ------------------

/// A pools file beside the repo — never `~/.tactus`, which is the
/// operator's, and never inside the workspace, where §14's `git clean -fd`
/// would delete it.
fn pools_file(repo: &Path, content: &str) -> PathBuf {
    let dir = private_root_for(repo);
    fs::create_dir_all(&dir).expect("pools dir");
    let path = dir.join("pools.toml");
    fs::write(&path, content).expect("pools file");
    path
}

const CLAUDE_POOL: &str = "[pools.claude-max]\nkind = \"subscription-window\"\nagent = \
                               \"claude-code\"\nsources = [\"signals\", \"self\"]\n";

fn events_of(repo: &Path, run_id: &str) -> Vec<events::Event> {
    let mut ignored = Vec::new();
    events::read_all(&paths_of(repo, run_id).events(), &mut ignored).expect("the log reads")
}

fn budget_events(events: &[events::Event]) -> Vec<&events::BudgetExceeded> {
    events
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::BudgetExceeded { data } => Some(data),
            _ => None,
        })
        .collect()
}

#[test]
fn a_run_budget_stops_the_run_exactly_once_and_survives_replay() {
    // The one-fold property, on the branch step 10 added: the stop is an
    // event, `RunState::apply` is what turns it into state, and a replay of
    // the log lands on the same state the live run held.
    let repo = temp_engine_repo("budgetstop");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Two\n<!-- tactus: id=t2 kind=implement depends= -->\n\n\
             ## Three\n<!-- tactus: id=t3 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [budgets]\nrun_usd = 0.05\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let (report, live) = run_harness_inner(
        &opts,
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("a budget stop is not an engine error");

    // Each task costs 0.06 (0.01 implementer + 0.05 review), so the ceiling
    // is crossed after the first and the second task is refused before it
    // spawns anything.
    assert_eq!(report.outcome(), RunOutcome::BudgetExceeded, "{report:?}");
    assert!(committed(&report, "t1"));
    let stop = report.budget_stop.as_ref().expect("a recorded stop");
    assert_eq!(stop.budget, events::BudgetKind::Run);
    assert_eq!(stop.task, "t2", "names the task that did not start");
    assert!(stop.spent_usd >= 0.05, "spent: {}", stop.spent_usd);

    // Exactly once: the scheduler stops scheduling on the first stop, so a
    // second would describe a spawn that never happened.
    let events = events_of(&repo, &report.run_id);
    assert_eq!(
        budget_events(&events).len(),
        1,
        "{:?}",
        budget_events(&events)
    );

    // Nothing after t1 ran, and the untouched tasks settle as skipped.
    assert!(matches!(task(&report, "t2").status, TaskRunStatus::Skipped));
    assert!(task(&report, "t2").attempts.is_empty());
    assert_live_equals_replay(&repo, &live, &report);
}

#[test]
fn a_task_budget_also_ends_the_run_and_says_which_ceiling_it_was() {
    let repo = temp_engine_repo("taskbudget");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\", \"mid\"], attempts_per = 1 }\n\n\
                 [budgets]\ntask_usd = 0.005\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // Fails on the first rung, so a second attempt is asked for — and
    // refused, because this task has already spent past its own ceiling.
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::BudgetExceeded, "{report:?}");
    let stop = report.budget_stop.as_ref().expect("a recorded stop");
    assert_eq!(stop.budget, events::BudgetKind::Task);
    assert_eq!(stop.task, "t1");
    assert_eq!(
        task(&report, "t1").attempts.len(),
        1,
        "the escalated attempt never spawned"
    );
    let rendered = report.render();
    assert!(rendered.contains("task_usd"), "{rendered}");
    assert!(rendered.contains("tactus resume"), "{rendered}");
}

#[test]
fn resuming_with_a_higher_ceiling_continues_the_run_the_budget_stopped() {
    // D4's whole point: a budget stop is recoverable in one command,
    // because budgets are re-derived at resume rather than inherited.
    let repo = temp_engine_repo("budgetresume");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Two\n<!-- tactus: id=t2 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.budget_usd = Some(0.05);
    let source = fake(Effect::EditFile);
    let stopped = run_with(&opts, &source).expect("run");
    assert_eq!(stopped.outcome(), RunOutcome::BudgetExceeded);
    assert!(!committed(&stopped, "t2"));

    let mut resume_opts = resume_options(&repo, &stopped.run_id);
    resume_opts.budget_usd = Some(10.0);
    let source = fake(Effect::EditFile);
    let resumed = resume_harness(
        &resume_opts,
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("a budget stop is exactly what resume is for");
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(committed(&resumed, "t2"));
    assert!(
        resumed.budget_stop.is_none(),
        "the stop the resume got past must not still be reported"
    );
}

#[test]
fn a_resume_that_does_not_raise_the_ceiling_stops_again_rather_than_running_past_it() {
    let repo = temp_engine_repo("budgetresumelow");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Two\n<!-- tactus: id=t2 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [budgets]\nrun_usd = 0.05\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let stopped = run_with(&opts, &source).expect("run");
    assert_eq!(stopped.outcome(), RunOutcome::BudgetExceeded);

    let source = fake(Effect::EditFile);
    let again = resume_harness(
        &resume_options(&repo, &stopped.run_id),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume");
    assert_eq!(again.outcome(), RunOutcome::BudgetExceeded, "{again:?}");
    assert!(!committed(&again, "t2"));
}

#[test]
fn a_frontier_escalation_over_the_threshold_parks_for_approval_then_runs_it() {
    // D3, end to end. The engine escalates FIRST and then asks, so an
    // approved task un-parks already standing on the frontier rung with a
    // fresh allowance — and `answer_question` needs no ApproveSpend arm.
    let repo = temp_engine_repo("approvespend");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"mid\", \"frontier\"], attempts_per = 1 }\n\n\
                 [interaction]\nask_before = { frontier_escalation_over_usd = 0.005 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let scripted = ScriptedAnswers::new(vec![Answer::Answered {
        text: "approve: run the escalated attempt".to_owned(),
    }]);
    let (report, live) = run_harness_inner(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&scripted),
            sleeper: None,
        },
    )
    .expect("run");

    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");
    assert!(committed(&report, "t1"));
    let asked: Vec<&QuestionRecord> = report
        .questions
        .iter()
        .filter(|q| q.question.kind == QuestionKind::ApproveSpend)
        .collect();
    assert_eq!(asked.len(), 1, "asked once: {:?}", report.questions);
    assert!(
        asked[0].question.context.contains("frontier"),
        "the question names where the money is going: {}",
        asked[0].question.context
    );
    assert!(
        asked[0].question.context.contains("$0.0100"),
        "and quotes reported spend to date: {}",
        asked[0].question.context
    );

    // The approved attempt really ran on the frontier rung with the
    // allowance the escalation reset — not a re-run of the mid rung.
    let tiers: Vec<&str> = task(&report, "t1")
        .attempts
        .iter()
        .map(|a| a.tier.as_str())
        .collect();
    assert_eq!(tiers, ["mid", "frontier"], "{tiers:?}");
    assert_live_equals_replay(&repo, &live, &report);
}

#[test]
fn a_declined_spend_approval_fails_the_task_through_the_halt_policy() {
    let repo = temp_engine_repo("declinespend");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"mid\", \"frontier\"], attempts_per = 1 }\n\n\
                 [interaction]\nask_before = { frontier_escalation_over_usd = 0.005 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let scripted = ScriptedAnswers::new(vec![Answer::Declined]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&scripted),
            sleeper: None,
        },
    )
    .expect("run");

    // Through `ingest_answer`'s existing Declined path — the one place that
    // owns the halt policy, with no ApproveSpend special case beside it.
    assert_eq!(report.outcome(), RunOutcome::Halted, "{report:?}");
    assert!(matches!(
        task(&report, "t1").status,
        TaskRunStatus::Failed {
            kind: FailureKind::Declined,
            ..
        }
    ));
    assert_eq!(
        task(&report, "t1").attempts.len(),
        1,
        "declining must not have spent the frontier attempt"
    );
}

#[test]
fn a_chain_that_starts_at_frontier_never_asks_to_approve_spend() {
    // §12's target is silent escalation. A task the operator deliberately
    // routed to frontier in config was not escalated onto it silently, and
    // asking anyway trains people to approve without reading.
    let repo = temp_engine_repo("frontierstart");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"frontier\"], attempts_per = 2 }\n\n\
                 [interaction]\nask_before = { frontier_escalation_over_usd = 0.0 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");
    assert!(
        report
            .questions
            .iter()
            .all(|q| q.question.kind != QuestionKind::ApproveSpend),
        "questions: {:?}",
        report.questions
    );
}

#[test]
fn attempts_are_attributed_to_the_pool_that_paid_them() {
    let repo = temp_engine_repo("poolattrib");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [routing.effort]\nimplementation = \"xhigh\"\nreview = \"max\"\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.pools_path = Some(pools_file(&repo, CLAUDE_POOL));
    let source = fake(Effect::EditFile);
    let report = run_with(&opts, &source).expect("run");

    let attempt = &task(&report, "t1").attempts[0];
    assert_eq!(attempt.pool.as_deref(), Some("claude-max"));
    assert!(
        attempt
            .reviews
            .iter()
            .all(|r| r.pool.as_deref() == Some("claude-max")),
        "the reviewer's own pool is attributed too: {:?}",
        attempt.reviews
    );

    // §13's second currency in the ledger, folded from the same records the
    // dollar column comes from.
    let drain = &report.pool_drain;
    assert_eq!(drain.len(), 1, "{drain:?}");
    assert_eq!(drain[0].pool, "claude-max");
    assert_eq!(drain[0].attempts, 2, "implementer plus its reviewer");
    let ledger = report.render_ledger();
    assert!(ledger.contains("claude-max"), "{ledger}");

    // And §14's pre-flight snapshot is on the record — folding to nothing,
    // which `assert_live_equals_replay` elsewhere is what proves.
    let events = events_of(&repo, &report.run_id);
    let started = events
        .iter()
        .find_map(|event| match &event.body {
            EventBody::AttemptStarted { data, .. } => Some(data),
            _ => None,
        })
        .expect("worker start was emitted");
    assert_eq!(started.adapter.as_deref(), Some("claude-code"));
    assert_eq!(started.preflight_cli_version.as_deref(), Some("0.0.0-fake"));
    assert_eq!(started.effort, Some(Effort::XHigh));
    assert_eq!(
        started.selection_origin,
        Some(events::SelectionOrigin::Auto)
    );

    let review = events
        .iter()
        .find_map(|event| match &event.body {
            EventBody::AttemptFinished { data, .. } => data.reviews.first(),
            _ => None,
        })
        .expect("review pass actually ran");
    assert_eq!(review.adapter.as_deref(), Some("claude-code"));
    assert_eq!(review.preflight_cli_version.as_deref(), Some("0.0.0-fake"));
    assert_eq!(review.effort, Some(Effort::Max));
    let snapshots: Vec<&events::CapacitySnapshot> = events
        .iter()
        .filter_map(|e| match &e.body {
            EventBody::CapacitySnapshot { data } => Some(data),
            _ => None,
        })
        .collect();
    assert_eq!(snapshots.len(), 1, "one snapshot per run start (§14)");
    assert_eq!(snapshots[0].pools.len(), 1);
    assert_eq!(
        snapshots[0].pools[0].remaining, "unknown",
        "never optimistic: an unmeasured pool is unknown, not full"
    );
}

#[test]
fn a_pinned_live_attempt_records_its_selection_origin() {
    let repo = temp_engine_repo("pinorigin");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\
                 [[pins]]\ntier = \"small\"\nagent = \"claude-code\"\n\
                 model = \"claude-haiku-4-5\"\neffort = \"max\"\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let report = run_with(&opts, &fake(Effect::EditFile)).expect("run");
    let events = events_of(&repo, &report.run_id);
    let started = events
        .iter()
        .find_map(|event| match &event.body {
            EventBody::AttemptStarted { data, .. } => Some(data),
            _ => None,
        })
        .expect("worker start was emitted");
    assert_eq!(started.selection_origin, Some(events::SelectionOrigin::Pin));
    assert_eq!(started.effort, Some(Effort::Max));
}

#[test]
fn a_rate_limit_marks_its_pool_exhausted_and_a_recovery_retires_the_signal() {
    // §13 source 1 made real: the signal is ground truth, and the estimator
    // that reads it back must never let a self-metered figure talk it up.
    let repo = temp_engine_repo("poolexhausted");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let pools = pools_file(&repo, CLAUDE_POOL);
    opts.pools_path = Some(pools.clone());
    let source = source(
        vec![Effect::RateLimited, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");

    let events = events_of(&repo, &report.run_id);
    let signals: Vec<&events::PoolExhausted> = events
        .iter()
        .filter_map(|e| match &e.body {
            EventBody::PoolExhausted { data, .. } => Some(data),
            _ => None,
        })
        .collect();
    assert_eq!(signals.len(), 1, "{signals:?}");
    assert_eq!(signals[0].pool, "claude-max");
    assert_eq!(signals[0].agent, "claude-code");

    // A fold that stops at the signal reads the pool as exhausted, at the
    // top confidence rank — the signal is ground truth about that moment.
    let signal_at = events
        .iter()
        .position(|e| matches!(e.body, EventBody::PoolExhausted { .. }))
        .expect("the signal is in the log");
    let through_signal = events[..=signal_at].to_vec();
    let mut warnings = Vec::new();
    let cfg = config::load(None, &repo, Some(&pools), &mut warnings).expect("pools");
    let at_the_signal = capacity::estimate(&cfg.pools, &capacity::observe(&through_signal));
    assert_eq!(at_the_signal[0].remaining, capacity::Remaining::Exhausted);
    assert_eq!(at_the_signal[0].confidence, capacity::Confidence::Signal);

    // But the whole log has the pool serving an attempt afterwards, so the
    // signal is retired rather than standing forever. Reporting `exhausted`
    // here — on the same line that reports the attempts it served — was the
    // shape the review caught.
    let settled = capacity::estimate(&cfg.pools, &capacity::observe(&events));
    assert_ne!(
        settled[0].remaining,
        capacity::Remaining::Exhausted,
        "{}",
        settled[0].describe()
    );
}

#[test]
fn reviewer_rate_limit_retires_recovered_implementer_pool_live() {
    let repo = temp_engine_repo("reviewerlimitretiresworker");
    seed(&repo, FRONTIER_AUTH_PLAN, Some(SECOND_OPINION_CONFIG));
    let pools = pools_file(
        &repo,
        "[pools.claude-max]\nkind = \"subscription-window\"\nagent = \"claude-code\"\n\
             sources = [\"signals\"]\n\n[pools.copilot-window]\nkind = \"subscription-window\"\n\
             agent = \"copilot\"\nsources = [\"signals\"]\n",
    );
    let mut opts = cross_vendor_opts(&repo);
    opts.pools_path = Some(pools);
    let source = cross_vendor(
        vec![
            Effect::RateLimited,
            Effect::EditFile,
            Effect::RateLimited,
            Effect::EditFile,
        ],
        vec![ReviewBehavior::Pass],
        vec![ReviewBehavior::RateLimited, ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("outages eventually recover");
    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");

    let signals: Vec<String> = events_of(&repo, &report.run_id)
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::PoolExhausted { data, .. } => Some(data.pool.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        signals,
        ["claude-max", "copilot-window", "claude-max"],
        "the reviewer outage must not leave the successfully serving worker pool retired forever"
    );
}

#[test]
fn the_budget_flag_is_validated_like_the_config_key() {
    // `[budgets] run_usd = 0.0` is a hard error at load. The flag that
    // overrides it must not be a way around that: zero and negative both
    // stopped the run before it spent anything, and NaN silently never
    // fired at all.
    let repo = temp_engine_repo("budgetflag");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    for bad in [0.0, -5.0, f64::NAN] {
        let mut opts = options(&repo);
        opts.config_path = Some(repo.join("tactus.toml"));
        opts.budget_usd = Some(bad);
        let source = fake(Effect::EditFile);
        let err = run_with(&opts, &source).expect_err("a meaningless ceiling must refuse");
        assert!(
            err.to_string().contains("not a spendable ceiling"),
            "--budget {bad}: {err}"
        );
    }
    // And refused at pre-flight, before a branch or a run directory exists.
    let branch = git_in(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
    assert_eq!(branch.trim(), "main", "refused before branching");
}

#[test]
fn a_spend_approval_is_not_fed_back_to_the_agent_as_an_instruction() {
    // Every other question's answer is guidance for the next attempt. An
    // ApproveSpend answer is a yes/no about money whose meaning was already
    // consumed by the un-park, and `feedback_section` frames feedback as
    // "an instruction from a person… it takes precedence over your earlier
    // assumptions" — which is not a thing to tell a coding agent about a
    // billing decision.
    let repo = temp_engine_repo("approvalfeedback");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"mid\", \"frontier\"], attempts_per = 1 }\n\n\
                 [interaction]\nask_before = { frontier_escalation_over_usd = 0.005 }\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(
        vec![Effect::NoEdit, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let scripted = ScriptedAnswers::new(vec![Answer::Answered {
        text: "approve: run the escalated attempt".to_owned(),
    }]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&scripted),
            sleeper: None,
        },
    )
    .expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");

    let frontier = &source.adapter.runs()[1].prompt;
    assert!(
        !frontier.contains("approve: run the escalated attempt"),
        "the approval reached the implementer as guidance:
{frontier}"
    );
    // An Unblock answer still does, because there it really is guidance.
    assert!(
        !frontier.contains("instruction from a person"),
        "and no human-instruction framing at all:
{frontier}"
    );
}

#[test]
fn picking_an_option_is_an_un_park_and_not_a_decision() {
    // The options a question carries are the engine's instructions to the
    // operator: "retry this task with guidance you type below", "answer in
    // your own words". `tactus answer <id> --option 1` resolved to that
    // sentence and pushed it as human feedback — so it reached the
    // implementer framed as "an instruction from a person", and once §12's
    // decisions were routed to the judge as well, it reached the reviewer
    // as "a decision from a person… a change that departs from it is a
    // defect however well argued". There is no diff that satisfies a
    // sentence about where to type, so an honest judge rejects every
    // attempt until the ladder is spent.
    let repo = temp_engine_repo("cannedoption");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // Ask, then answer by picking the first option verbatim — what
    // `--option 1` writes.
    let source = source(
        vec![Effect::AskQuestion, Effect::EditFile],
        vec![ReviewBehavior::Pass],
    );
    let scripted = ScriptedAnswers::new(vec![Answer::Answered {
        text: question_options(QuestionKind::Clarify)[0].clone(),
    }]);
    let report = run_harness(
        &opts,
        &Harness {
            adapters: &source,
            answers: Some(&scripted),
            sleeper: None,
        },
    )
    .expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");

    // The retry happened — the answer still un-parks the task.
    let runs = source.adapter.runs();
    let retry = &runs
        .iter()
        .filter(|r| !r.prompt.contains("DATA UNDER REVIEW"))
        .nth(1)
        .expect("a second implementer attempt")
        .prompt;
    assert!(
        !retry.contains("answer in your own words"),
        "the option label reached the implementer as guidance:\n{retry}"
    );
    assert!(
        !retry.contains("instruction from a person"),
        "and with no human-instruction framing at all:\n{retry}"
    );
    // And nothing reached the judge as an operator decision either.
    for review in runs
        .iter()
        .filter(|r| r.prompt.contains("DATA UNDER REVIEW"))
    {
        assert!(
            !review.prompt.contains("answer in your own words"),
            "the option label reached the reviewer as a decision:\n{}",
            review.prompt
        );
    }
}

#[test]
fn one_outage_records_one_signal_however_many_deferrals_it_causes() {
    let repo = temp_engine_repo("onesignal");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.pools_path = Some(pools_file(&repo, CLAUDE_POOL));
    // Down for three attempts, then back.
    let source = source(
        vec![
            Effect::RateLimited,
            Effect::RateLimited,
            Effect::RateLimited,
            Effect::EditFile,
        ],
        vec![ReviewBehavior::Pass],
    );
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::Complete, "{report:?}");
    let signals = events_of(&repo, &report.run_id)
        .iter()
        .filter(|e| matches!(e.body, EventBody::PoolExhausted { .. }))
        .count();
    assert_eq!(
        signals, 1,
        "one outage is one fact; the deferrals are already on `task_deferred`"
    );
}

#[test]
fn a_budget_stop_hands_back_a_clean_tree() {
    // §14 keeps the working tree for a resumed same-rung retry, because
    // that retry re-gates the *cumulative* diff. The ceiling is checked at
    // the top of the same loop, so a budget reached between the two
    // returns to the operator with a rejected attempt's edits still staged
    // in their repository — and staged changes follow `git switch` onto
    // whatever branch is visited next. Observed on a real repository:
    // run 01KZNMR59E5ATC9MBYY29WZB6E left two files staged after exit 3.
    //
    // Keeping them buys nothing even in principle: `run_resumed` discards
    // every uncommitted path and clears `session`/`resume_next` on every
    // task, so the retry those edits were preserved for cannot use them.
    let repo = temp_engine_repo("budgetdirty");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    // Enough for the first attempt, not for the retry that attempt asks
    // for — so the stop lands exactly between the two.
    opts.budget_usd = Some(0.05);
    let rejected = source(vec![Effect::EditFile], vec![ReviewBehavior::Fail]);
    let stopped = run_with(&opts, &rejected).expect("run");
    assert_eq!(stopped.outcome(), RunOutcome::BudgetExceeded, "{stopped:?}");

    let workspace = Workspace::open(&repo).expect("open");
    let left = workspace.uncommitted_summary().expect("status");
    assert!(
        left.is_empty(),
        "a clean stop left the rejected attempt in the operator's tree: {left:?}"
    );

    // And the run is still exactly as resumable as it was before.
    let mut resume_opts = resume_options(&repo, &stopped.run_id);
    resume_opts.budget_usd = Some(10.0);
    let accepted = source(vec![Effect::EditFile], vec![ReviewBehavior::Pass]);
    let resumed = resume_harness(
        &resume_opts,
        &Harness {
            adapters: &accepted,
            answers: None,
            sleeper: None,
        },
    )
    .expect("resume");
    assert_eq!(resumed.outcome(), RunOutcome::Complete, "{resumed:?}");
    assert!(committed(&resumed, "t1"));
    assert!(
        !resumed
            .warnings
            .iter()
            .any(|w| w.contains("discarded") && w.contains("uncommitted")),
        "nothing should have been left for the resume to discard: {:?}",
        resumed.warnings
    );
}

/// One attempt that reported its spend and one that did not — the shape a
/// kill/resume leaves, and a mixed-route ladder too.
fn priced_and_unpriced_attempts() -> TaskReport {
    let attempt = |cost: Option<f64>| AttemptRecord {
        attempt: 1,
        tier: "frontier".to_owned(),
        model: "m".to_owned(),
        pool: None,
        resumed: false,
        duration: Duration::ZERO,
        cost_usd: cost,
        reviews: Vec::new(),
        session_id: None,
        usage: None,
        failure: None,
    };
    let mut task = task_report_costing(Some(0.2020), None);
    task.status = TaskRunStatus::Committed {
        sha: "abc123".to_owned(),
    };
    task.attempts = vec![attempt(None), attempt(Some(0.2020))];
    task
}

/// A `RunReport` with nothing in it, for tests that care about one field.
fn empty_report() -> RunReport {
    RunReport {
        run_id: "01RUN".to_owned(),
        branch: "b".to_owned(),
        gates: Vec::new(),
        gates_from_config: false,
        warnings: Vec::new(),
        tasks: Vec::new(),
        halted_at: None,
        questions: Vec::new(),
        budget_stop: None,
        total_cost_usd: 0.0,
        pool_drain: Vec::new(),
        running: false,
        interrupted: false,
    }
}

#[test]
fn an_unpriced_worker_reads_as_unreported_rather_than_free() {
    // §13's rule, on the line an operator actually reads. The ledger has
    // always shown `—` for a route that reports no dollars, and the review
    // half of this line has said `$?` since step 9 — but the worker half
    // used `unwrap_or(0.0)`, so a codex-implemented task printed
    // `gpt-5.6-sol $0.0000` above a ledger row reading `—`. One run, two
    // answers, and the wrong one is the one that looks precise.
    let mut task = task_report_costing(None, None);
    task.id = "t1".to_owned();
    task.model = "gpt-5.6-sol".to_owned();
    task.status = TaskRunStatus::Committed {
        sha: "abc123".to_owned(),
    };
    // The attempt that actually ran, as a route reporting no dollars
    // records it. Without this the task has no attempts at all, which is a
    // different thing entirely — nothing ran, so nothing is missing, and
    // the ledger correctly prints `—` rather than a floor.
    task.attempts = vec![AttemptRecord {
        attempt: 1,
        tier: "frontier".to_owned(),
        model: "gpt-5.6-sol".to_owned(),
        pool: None,
        resumed: false,
        duration: Duration::from_secs(46),
        cost_usd: None,
        reviews: Vec::new(),
        session_id: None,
        usage: None,
        failure: None,
    }];
    let report = RunReport {
        tasks: vec![task],
        ..empty_report()
    };

    let rendered = report.render();
    assert!(rendered.contains("gpt-5.6-sol $?"), "{rendered}");
    let task_line = rendered
        .lines()
        .find(|l| l.contains("t1: committed"))
        .expect("the task line");
    assert!(
        !task_line.contains("$0.0000"),
        "unreported spend rendered as free: {task_line}"
    );
    // And the same rule one level up. `total_cost_usd` is an `f64`, so it
    // cannot distinguish a zero sum from an unreported one — the floor has
    // to be carried beside it. Measured on run 01KZRTZ9ZKKF1YS7MVT4350X7M,
    // where a codex-implemented task made `total $0.1561` read as complete
    // while the worker's real spend was unknown.
    assert!(
        report.total_is_floor(),
        "an unpriced worker makes it a floor"
    );
    assert!(rendered.contains("total: $0.0000?"), "{rendered}");
    let ledger = report.render_ledger();
    assert!(ledger.contains("total $0.0000?"), "{ledger}");
    assert!(ledger.contains("a floor, not a total"), "{ledger}");
    // Here every attempt was unpriced, so the worker column is `—`, which
    // already says "unreported" — `partial` leaves it alone rather than
    // decorating it into `—?`.
    let row = ledger
        .lines()
        .find(|l| l.trim_start().starts_with("t1"))
        .expect("the ledger row");
    assert!(row.contains('—'), "{row}");

    // The `?` belongs on a figure that exists but is short: two attempts,
    // one priced and one not. That is what a resumed run looks like after
    // the engine was killed inside the first attempt, and what a mixed
    // ladder looks like when one rung reports and another does not.
    let mut mixed = priced_and_unpriced_attempts();
    mixed.id = "t2".to_owned();
    let row = RunReport {
        tasks: vec![mixed],
        ..empty_report()
    }
    .render_ledger();
    let row = row
        .lines()
        .find(|l| l.trim_start().starts_with("t2"))
        .expect("the ledger row");
    assert!(row.contains("$0.2020?"), "a floor must say so: {row}");

    // And a route that does report keeps its figure.
    let mut priced = report;
    priced.tasks[0].cost_usd = Some(0.2020);
    assert!(priced.render().contains("$0.2020"), "{}", priced.render());
}

#[test]
fn a_status_from_a_newer_tactus_does_not_fail_the_whole_report() {
    // `report.json` is a projection for whoever reads the run afterwards,
    // and `TaskRunStatus` is `pub` and `Deserialize` because that reader
    // may be someone else's program. Every variant added to a serde-tagged
    // enum with no fallback is a hard `unknown variant` error in every
    // consumer built against an older version — one unreadable status makes
    // the entire report unreadable.
    //
    // `running`, `Queued` and `Running` did that to anything compiled
    // against 0.0.1, and that break is published and cannot be taken back.
    // This is so the next variant is not another one.
    let text = r#"{
          "run_id": "01RUN", "branch": "b", "gates": [], "gates_from_config": false,
          "warnings": [], "halted_at": null, "questions": [], "total_cost_usd": 0.0,
          "tasks": [
            {"id": "t1", "title": "One", "model": "m",
             "status": {"status": "teleported", "destination": "elsewhere"},
             "duration": {"secs": 0, "nanos": 0}, "cost_usd": null,
             "review_models": [], "review_cost_usd": null,
             "review_cost_incomplete": false, "session_id": null, "attempts": []},
            {"id": "t2", "title": "Two", "model": "m",
             "status": {"status": "committed", "sha": "abc123"},
             "duration": {"secs": 0, "nanos": 0}, "cost_usd": null,
             "review_models": [], "review_cost_usd": null,
             "review_cost_incomplete": false, "session_id": null, "attempts": []}
          ]
        }"#;

    let report: RunReport =
        serde_json::from_str(text).expect("one unknown status must not sink the report");
    assert!(matches!(task(&report, "t1").status, TaskRunStatus::Unknown));
    // And everything the reader *can* understand still arrives intact.
    assert!(
        matches!(&task(&report, "t2").status, TaskRunStatus::Committed { sha } if sha == "abc123")
    );
    let rendered = report.render();
    assert!(rendered.contains("t1: status not recognised"), "{rendered}");
    assert!(rendered.contains("t2: committed abc123"), "{rendered}");
}

#[test]
fn a_report_for_a_dead_run_never_says_a_task_is_running() {
    // `Running` says of itself that only a live `status` produces it, and
    // the arm that built it consulted `in_flight` alone — while the arm
    // directly below, for `Queued`, guards on `running`. What actually held
    // the promise was a guarantee made one function away: `settle` turns
    // every `Pending` into `Skipped` before `task_report` sees it when the
    // run has ended, so the only way in is `Deferred`, which is recorded
    // after an attempt finishes and therefore never has anything in flight.
    //
    // Unreachable is not the same as impossible, and the distance between
    // the promise and the code keeping it is the whole hazard: a dangling
    // `in_flight` is what any error out of `run_attempt` leaves behind, and
    // `drain_and_report` writes a partial `report.json` on exactly that
    // path. One reordering away, that file reads `t1: running now — attempt
    // 2 on mid` beside a top-level `"running": false`, and outlives the
    // process that wrote it. So the invariant is stated where it is relied
    // upon.
    let task = Task {
        id: TaskId::from("t1"),
        kind: TaskKind::Implement,
        title: "One".to_owned(),
        body: String::new(),
        depends_on: Vec::new(),
        acceptance: Vec::new(),
        path_hints: Vec::new(),
        suggested_tier: None,
        min_tier: None,
        artifacts_in: Vec::new(),
        artifacts_out: Vec::new(),
    };
    let mid_attempt = Progress {
        in_flight: Some(events::InFlight {
            attempt: 2,
            rung: 1,
            tier: "mid".to_owned(),
            model: "claude-sonnet-5".to_owned(),
            profile: "mid-claude-sonnet-5".to_owned(),
            pool: None,
        }),
        ..Progress::default()
    };

    for state in [TaskState::Pending, TaskState::Deferred] {
        let dead = task_report(&task, &state, &mid_attempt, false);
        assert!(
            matches!(dead.status, TaskRunStatus::Skipped),
            "a report for an ended run claimed a live attempt from {state:?}: {:?}",
            dead.status
        );
        let live = task_report(&task, &state, &mid_attempt, true);
        assert!(
            matches!(live.status, TaskRunStatus::Running { .. }),
            "and a live one still reports it: {:?}",
            live.status
        );
    }
}

#[test]
fn a_budget_stop_keeps_its_outcome_while_a_resume_holds_the_lock() {
    // `resume` takes the run's lock and then does a dozen git subprocesses
    // — branch checks, a switch, a discard — before it writes
    // `run_resumed`. Deriving liveness from the lock alone made that whole
    // window read as a live run: `status` printed `run in progress: N
    // task(s) committed so far` and returned early, dropping the stop
    // reason, the parked list, and the `resume --budget` line an operator
    // at a budget stop is running `status` to find.
    //
    // The lock answers who has claimed the run. Whether the run still has
    // anywhere to go is a question only its log answers.
    let repo = temp_engine_repo("resumewindow");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.budget_usd = Some(0.05);
    let rejected = source(vec![Effect::EditFile], vec![ReviewBehavior::Fail]);
    let stopped = run_with(&opts, &rejected).expect("run");
    assert_eq!(stopped.outcome(), RunOutcome::BudgetExceeded, "{stopped:?}");

    let paths = paths_of(&repo, &stopped.run_id);
    let _held = RunLock::acquire(&paths.public).expect("the resume claims it");

    let seen = replay_of(&repo, &stopped.run_id);
    assert!(
        !seen.running,
        "a run that recorded its finish is not running"
    );
    assert!(seen.held, "though a resume does hold it");
    let out = crate::status::render(&seen);
    assert!(out.contains("run stopped at its budget"), "{out}");
    assert!(out.contains("tactus resume"), "{out}");
    assert!(out.contains("another process holds this run"), "{out}");
    assert!(!out.contains("run in progress"), "{out}");
}

#[test]
fn a_budget_stop_survives_a_git_that_cannot_clean_the_tree() {
    // Handing back a clean tree was added *before* the ceiling was
    // recorded, with a `?` on it. So a `git reset --hard` that failed for
    // any of the ordinary reasons — a locked index, a read-only path, a
    // hook that exits non-zero — took the whole budget stop with it: no
    // `budget_exceeded` event, `budget_stop` left `None`, exit 1 with a git
    // error where CI was gating on exit 3, and a `resume --budget` with no
    // stop to get past. The tidying is a courtesy; the ceiling is the run's
    // account of why it stopped.
    //
    // The fake reviewer plants a stale lock only after its exact candidate
    // worktree exists. This reaches the budget-stop cleanup without using
    // ordinary gate residue to pierce the new workspace isolation.
    let repo = temp_engine_repo("budgetjam");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    opts.budget_usd = Some(0.05);
    let rejected = source(
        vec![Effect::JamCleanupAfterReview],
        vec![ReviewBehavior::Fail],
    );
    let stopped = run_with(&opts, &rejected).expect("the ceiling still ends the run");

    assert_eq!(
        stopped.outcome(),
        RunOutcome::BudgetExceeded,
        "a failed cleanup relabelled the stop: {stopped:?}"
    );
    let stop = stopped
        .budget_stop
        .as_ref()
        .expect("the ceiling is on the record even when the cleanup failed");
    assert_eq!(stop.budget, events::BudgetKind::Run);
    // And it says so rather than leaving the operator to find the mess.
    assert!(
        stopped
            .warnings
            .iter()
            .any(|w| w.contains("could not be cleaned")),
        "the dirty tree went unmentioned: {:?}",
        stopped.warnings
    );
}

#[test]
fn a_budget_stop_survives_a_stale_decline_file() {
    // A decline routes through `fail_task`, which sets `halted_at`, and
    // halted outranks budget in `outcome()`. A decline sitting on disk when
    // the ceiling hits would have relabelled the stop as a task failure —
    // exit 1 where CI was gating on exit 3 to raise the ceiling.
    let repo = temp_engine_repo("budgetdecline");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Two\n<!-- tactus: id=t2 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [budgets]\nrun_usd = 0.05\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = fake(Effect::EditFile);
    let report = run_with(&opts, &source).expect("run");
    assert_eq!(report.outcome(), RunOutcome::BudgetExceeded, "{report:?}");
    assert!(report.halted_at.is_none(), "nothing failed: {report:?}");
}

// ---------------------------------------------------------------------------
// PR4: every process the legacy engine starts goes through the Runner
// ---------------------------------------------------------------------------

/// One process the engine asked a runner to execute.
#[derive(Debug, Clone)]
struct RoutedProcess {
    role: crate::runner::ExecutionRole,
    program: String,
    invocation: String,
    workspace: PathBuf,
    agent: Option<String>,
    slotted: bool,
    /// What the child receives on stdin. The adapter says *whether* a prompt
    /// is delivered this way (`AgentAdapter::stdin_payload`); the spec is what
    /// carries the bytes, and the runner is what writes them.
    stdin: String,
}

/// A real [`HostRunner`](crate::runner::host::HostRunner) that writes down what
/// it was asked to run.
///
/// It delegates rather than stubs: a recorder that returned canned output
/// would prove the engine *called* something and nothing about the run still
/// working. Every assertion below is therefore made about a run that actually
/// committed its tasks.
struct RecordingRunner {
    inner: crate::runner::host::HostRunner,
    seen: Mutex<Vec<RoutedProcess>>,
}

impl RecordingRunner {
    fn new() -> Self {
        Self {
            inner: crate::runner::host::HostRunner::new(),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<RoutedProcess> {
        self.seen.lock().expect("recorder").clone()
    }
}

impl crate::runner::Runner for RecordingRunner {
    fn run(
        &self,
        request: &crate::runner::RunnerRequest,
    ) -> Result<ProcessOutput, crate::error::TactusError> {
        self.seen.lock().expect("recorder").push(RoutedProcess {
            role: request.role.clone(),
            program: request.command.program.clone(),
            invocation: request.invocation.render(),
            workspace: request.workspace.clone(),
            agent: request.agent.as_ref().map(|id| id.as_str().to_owned()),
            slotted: request.role.is_slotted(),
            stdin: String::from_utf8_lossy(&request.command.stdin).into_owned(),
        });
        crate::runner::Runner::run(&self.inner, request)
    }
}

/// The file stem of a program path, however it was spelled.
fn program_stem(program: &str) -> String {
    Path::new(program)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// `decisions.pr_sequence[5].scope`: "probes, workers, gates, reviews go
/// through the Runner", and `invariants_preserved`: "legacy engine behavior
/// unchanged (**the legacy engine does not run the shell probe**)".
///
/// One run of two tasks, each with two gates and one review pass, driven
/// through a recorder wrapped around the real host runner. What it establishes,
/// in the order the contract asks for it:
///
/// 1. **Every** process the run started is a Runner request — the count is the
///    run's shape (2 workers + 4 gates + 2 reviews), so a process that had
///    gone round the seam would leave the count short and a process that had
///    been added would leave it long.
/// 2. The identities are the packet's first form in the **legacy generation**,
///    written out by hand, and they are unique.
/// 3. **No `probe(shell)` request**, and the recorder can see one — the same
///    recorder is handed a real shell probe afterwards and the count moves
///    from 0 to 1, so the zero is a measurement rather than a blind spot.
/// 4. **Authoritative Git never crosses the boundary** (DESIGN.md:612): the
///    run made commits, and not one recorded request is a `git` process.
#[test]
fn the_legacy_engine_routes_every_process_through_the_runner() {
    let repo = temp_engine_repo("routed");
    seed(
        &repo,
        "## One\n<!-- tactus: id=t1 kind=implement depends= -->\n\n\
             ## Two\n<!-- tactus: id=t2 kind=implement depends= -->\n",
        Some(
            "[routing]\nimplement = { chain = [\"small\"], attempts_per = 1 }\n\n\
                 [[gates]]\nname = \"first\"\ncmd = \"echo gate-one\"\n\n\
                 [[gates]]\nname = \"second\"\ncmd = \"echo gate-two\"\n",
        ),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Pass]);
    let runner = RecordingRunner::new();
    let report = run_harness_on(
        &opts,
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
        &runner,
    )
    .expect("run");

    assert!(committed(&report, "t1"), "report: {report:?}");
    assert!(committed(&report, "t2"), "report: {report:?}");
    let seen = runner.seen();

    // (1) and (2): the exact identities of the run, in order, written from the
    // plan's shape and the packet's grammar rather than read back from the
    // engine. Two tasks at plan positions 0 and 1, one attempt each, generation
    // 0 because the legacy engine has none, and inside each attempt the worker,
    // then gate 0 and gate 1, then review pass 0.
    let expected_ids = vec![
        "k0.g0.a1.worker.o0",
        "k0.g0.a1.gate0.o0",
        "k0.g0.a1.gate1.o0",
        "k0.g0.a1.review_pass0.o0",
        "k1.g0.a1.worker.o0",
        "k1.g0.a1.gate0.o0",
        "k1.g0.a1.gate1.o0",
        "k1.g0.a1.review_pass0.o0",
    ];
    let ids: Vec<&str> = seen.iter().map(|p| p.invocation.as_str()).collect();
    assert_eq!(ids, expected_ids, "recorded: {seen:#?}");
    assert_eq!(
        seen.len(),
        2 * (1 + 2 + 1),
        "two tasks x (worker + two gates + one review)"
    );
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        ids.len(),
        "two processes of one run share an identity"
    );
    assert!(
        ids.iter().all(|id| id.contains(".g0.")),
        "the legacy engine assigns legacy-scoped values: generation 0"
    );

    // The roles, and what each buys. R3, via `ExecutionRole::is_slotted`: a
    // worker and a review take an {agent, pool} pair; a gate does not, because
    // a gate is repository-controlled code and runs no agent CLI — which is
    // also why it is handed no agent.
    use crate::runner::ExecutionRole;
    let by_role = |role: &ExecutionRole| seen.iter().filter(|p| &p.role == role).count();
    assert_eq!(by_role(&ExecutionRole::Implement), 2);
    assert_eq!(by_role(&ExecutionRole::Gate), 4);
    assert_eq!(by_role(&ExecutionRole::Review), 2);
    for process in &seen {
        match process.role {
            ExecutionRole::Implement | ExecutionRole::Review => {
                assert!(process.slotted, "{process:?}");
                assert_eq!(process.agent.as_deref(), Some("claude-code"), "{process:?}");
            }
            ExecutionRole::Gate => {
                assert!(!process.slotted, "{process:?}");
                assert_eq!(process.agent, None, "{process:?}");
            }
            ExecutionRole::Probe(_) => panic!("the legacy engine probes nothing: {process:?}"),
        }
    }

    // The prompt still reaches the child the way the adapter says it should.
    // `stdin_payload` is delivery policy and the spec is what carries those
    // bytes, so the two routed agent processes must be carrying them: a worker
    // gets the materialized task prompt, a reviewer gets the verdict prompt,
    // and a gate — which is a shell command, not an agent — gets nothing.
    let worker_stdin = &seen
        .iter()
        .find(|p| p.role == ExecutionRole::Implement)
        .expect("a worker")
        .stdin;
    assert!(
        worker_stdin.contains("## One") || worker_stdin.contains("One"),
        "the worker prompt is delivered on stdin: {worker_stdin:?}"
    );
    assert!(
        worker_stdin.contains("Acceptance") || worker_stdin.len() > 200,
        "and it is the materialized prompt, not a token: {} bytes",
        worker_stdin.len()
    );
    let review_stdin = &seen
        .iter()
        .find(|p| p.role == ExecutionRole::Review)
        .expect("a review")
        .stdin;
    assert!(
        review_stdin.contains("READ-ONLY"),
        "the review prompt is delivered on stdin: {review_stdin:?}"
    );
    assert_ne!(
        worker_stdin, review_stdin,
        "a worker and a judge are not sent the same prompt"
    );
    for gate in seen.iter().filter(|p| p.role == ExecutionRole::Gate) {
        assert!(gate.stdin.is_empty(), "a gate reads no stdin: {gate:?}");
    }

    // (3) The clause, and the control that makes it a measurement. The run has
    // a recorded shell and ran four gate commands through it, and still never
    // asked that shell to `exit 0` through the Runner — `gates::shell_available`
    // is a PATH check and stays one.
    let shell_probes = |seen: &[RoutedProcess]| {
        seen.iter()
            .filter(|p| p.role == ExecutionRole::Probe(crate::runner::ProbeTarget::Shell))
            .count()
    };
    assert_eq!(
        shell_probes(&seen),
        0,
        "the legacy engine ran a shell probe"
    );
    crate::runner::host::run_shell_probe(
        &runner,
        crate::gates::ShellKind::native(),
        repo.clone(),
        crate::runner::InvocationId::probe(crate::runner::ProbeTarget::Shell, 0)
            .expect("the shell probe identity"),
    )
    .expect("the recorded shell runs `exit 0`");
    assert_eq!(
        shell_probes(&runner.seen()),
        1,
        "the recorder cannot see a shell probe, so the zero above proved nothing"
    );

    // (4) Authoritative Git never crosses the boundary. The run committed both
    // tasks — every one of those commits was git work — and not one process
    // the runner was asked to execute is git.
    assert!(
        seen.iter().all(|p| program_stem(&p.program) != "git"),
        "a git process went through the Runner: {seen:#?}"
    );
    assert!(
        !git_in(&repo, &["log", "--oneline", &report.branch]).is_empty(),
        "the run's branch has commits, so authoritative Git did run"
    );

    // The workspace is the runner's to set, and it set a different one for the
    // worker than for the gates and the review: an attempt edits the repo,
    // while gates and reviewers judge the frozen candidate snapshot.
    //
    // `same_path`, not `==`: the runner is given the workspace root the run
    // resolved and this test holds the `temp_dir()` name it created the repo
    // under, and those are two spellings of one directory on any host whose
    // temp directory is reached through a symlink (macOS: `/var` →
    // `/private/var`) or whose user directory has an 8.3 short name (Windows
    // CI: `RUNNER~1` for `runneradmin`). Comparing the directories rather than
    // the strings is also what makes the `!` case below mean anything — an
    // inequality between two spellings holds for free.
    let worker = seen
        .iter()
        .find(|p| p.role == ExecutionRole::Implement)
        .expect("a worker");
    assert!(
        crate::util::same_path(&worker.workspace, &repo),
        "the worker runs in the repo root: {} is not {}",
        worker.workspace.display(),
        repo.display()
    );
    for process in seen.iter().filter(|p| p.role != ExecutionRole::Implement) {
        assert!(
            !crate::util::same_path(&process.workspace, &repo),
            "a gate or reviewer judged the live worktree: {process:?}"
        );
        assert!(process.workspace.is_absolute(), "{process:?}");
    }
}

/// Every identity a *retried* attempt with two review passes and a re-ask
/// assigns, recorded from production rather than constructed by the test.
///
/// `the_legacy_engine_routes_every_process_through_the_runner` above records a
/// run whose every task runs once, with one review pass and no re-ask — so the
/// three fields that vary *inside* an attempt's identity never vary in it:
/// `AttemptNumber`, the review pass index, and pass-versus-re-ask. Each of
/// those is a distinct call site in `engine::attempt`, and a call site that
/// passes a constant where it should pass its argument is invisible to a grid
/// of hand-built identities (`runner::tests::invocation_ids_are_unique_within_a_run…`
/// synthesizes its tuples; `review::tests::the_one_format_reask_is_its_own_invocation…`
/// is handed a correct pair). `invocation_identity` requires "unique per
/// process" and "a retry attempt has a new attempt number", and INV-20 makes
/// `review_pass(n)` and `review_reask(n)` distinct members.
///
/// So: one task that fails its first attempt and is retried, two gates, two
/// review passes from two families, and a first verdict the reviewer botches.
/// The expected list is written from the packet's grammar and this run's
/// shape.
#[test]
fn a_retried_attempt_with_two_passes_and_a_reask_assigns_every_identity_from_production() {
    let repo = temp_engine_repo("identities");
    seed(
        &repo,
        FRONTIER_AUTH_PLAN,
        Some(
            "[routing]\n\
             implement = { chain = [\"frontier\"], attempts_per = 2 }\n\n\
             [[routing.overrides]]\n\
             paths = [\"src/auth/**\"]\n\
             second_opinion = \"different-vendor\"\n\n\
             [[gates]]\nname = \"first\"\ncmd = \"echo gate-one\"\n\n\
             [[gates]]\nname = \"second\"\ncmd = \"echo gate-two\"\n",
        ),
    );
    let source = cross_vendor(
        // The first attempt reports success and edits nothing, which fails
        // outcome sanity before any gate runs; the second does the work.
        vec![Effect::NoEdit, Effect::EditFile],
        // The primary reviewer's first verdict is prose, so the pass spends
        // its one format-only re-ask and then answers.
        vec![ReviewBehavior::Unparseable, ReviewBehavior::Pass],
        vec![ReviewBehavior::Pass],
    );
    let runner = RecordingRunner::new();
    let report = run_harness_on(
        &cross_vendor_opts(&repo),
        &Harness {
            adapters: &source,
            answers: None,
            sleeper: None,
        },
        &runner,
    )
    .expect("run");
    assert!(committed(&report, "t1"), "report: {report:?}");

    let seen = runner.seen();
    let ids: Vec<&str> = seen.iter().map(|p| p.invocation.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            // Attempt 1: the worker alone — nothing downstream of a lying
            // agent runs.
            "k0.g0.a1.worker.o0",
            // Attempt 2 carries a *new attempt number* through every process
            // it starts, not only through the worker.
            "k0.g0.a2.worker.o0",
            "k0.g0.a2.gate0.o0",
            "k0.g0.a2.gate1.o0",
            // Pass 0's verdict, and the one re-ask it is allowed — two
            // processes, two identities, and the second is not a second run of
            // the first.
            "k0.g0.a2.review_pass0.o0",
            "k0.g0.a2.review_reask0.o0",
            // Pass 1 is the other family's, and it is pass *one*.
            "k0.g0.a2.review_pass1.o0",
        ],
        "recorded: {seen:#?}"
    );

    // Hostility as counts, so the list above cannot be satisfied by a run that
    // exercised fewer of the varying fields than it claims.
    use std::collections::BTreeSet;
    let attempts: BTreeSet<&str> = ids
        .iter()
        .map(|id| id.split('.').nth(2).expect("the attempt field"))
        .collect();
    assert_eq!(
        attempts,
        BTreeSet::from(["a1", "a2"]),
        "two attempt numbers"
    );
    let roles: BTreeSet<&str> = ids
        .iter()
        .map(|id| id.split('.').nth(3).expect("the role field"))
        .collect();
    assert_eq!(
        roles,
        BTreeSet::from([
            "worker",
            "gate0",
            "gate1",
            "review_pass0",
            "review_reask0",
            "review_pass1",
        ]),
        "six distinct role members across the run"
    );
    assert_eq!(
        ids.iter().collect::<BTreeSet<_>>().len(),
        ids.len(),
        "two processes of one run share an identity"
    );
    // `reviews_run` counts *invocations*, so the primary's two are the
    // verdict and its re-ask — the same two the identity list names.
    assert_eq!(
        source.adapter.reviews_run(),
        2,
        "the primary reviewer's verdict and its one re-ask"
    );
    assert_eq!(
        source.copilot().reviews_run(),
        1,
        "the second family answered once, and was not re-asked"
    );
}

/// A worker that cannot be spawned is an **infrastructure error**, not a task
/// failure — and the engine synthesizes no settlement for it.
///
/// `expected_failures_refusals[2]`: "a spawn failure uses the existing
/// runner/engine semantics: returned error; **no halting settlement is
/// synthesized**" (at integration, PR8's Deferred/Parked outcomes handle it).
/// Every fake worker in this file returns a spawnable shell command, and the
/// reviewer's spawn failures are converted to `ReviewUnavailable` *inside*
/// `run_review` before they ever reach the coordinator's error arm — so
/// nothing here exercised that arm, and converting it into `fail_task` would
/// have left the suite green while turning an outage into an attributed task
/// failure with a halt.
///
/// The oracle is threefold, because "returned error" alone would also be true
/// of a run that had recorded a failure first: the call returns `Err`, the
/// error is the runner's own spawn diagnostic, and the log carries
/// `attempt_started` with **no** settlement after it.
#[test]
fn a_worker_that_cannot_be_spawned_returns_an_error_and_settles_nothing() {
    let repo = temp_engine_repo("workerspawn");
    seed(
        &repo,
        "## Implement the widget\n<!-- tactus: id=t1 kind=implement depends= -->\n",
        Some("[routing]\nimplement = { chain = [\"small\"], attempts_per = 2 }\n"),
    );
    let mut opts = options(&repo);
    opts.config_path = Some(repo.join("tactus.toml"));
    let source = source(vec![Effect::SpawnError], vec![ReviewBehavior::Pass]);
    let error = run_with(&opts, &source).expect_err(
        "a worker that cannot be spawned is an infrastructure error, not a run that finished",
    );
    let message = error.to_string();
    assert!(
        message.contains("failed to spawn"),
        "the runner's own diagnostic reaches the caller: {message}"
    );
    assert!(
        message.contains("missing-worker-executable"),
        "and it names the program: {message}"
    );

    // Nothing was settled: one attempt started, no attempt finished, no task
    // failed, and the ladder bought no second attempt.
    let run_id = rundir::latest_run(&repo).expect("the run created its directory");
    let log = fs::read_to_string(paths_of(&repo, &run_id).events()).expect("events.jsonl");
    let kinds: Vec<String> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("an event")
                .get("event")
                .and_then(|kind| kind.as_str())
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| *kind == "attempt_started")
            .count(),
        1,
        "exactly one attempt was dispatched: {kinds:?}"
    );
    for settled in [
        "attempt_finished",
        "task_failed",
        "task_completed",
        "run_finished",
    ] {
        assert_eq!(
            kinds.iter().filter(|kind| *kind == settled).count(),
            0,
            "a spawn failure synthesized `{settled}`: {kinds:?}"
        );
    }
    assert_eq!(source.adapter.runs().len(), 1, "the ladder bought no retry");
}

/// The engine facade's public surface is the one the packet enumerates — no
/// wider.
///
/// `decisions.phase_zero_modules.visibility`: "pub(super) only where a sibling
/// or tests reference an item; **no new pub or pub(crate)**; public paths
/// unchanged", and `modules["src/engine/mod.rs"]` lists the facade item by
/// item: the five `pub use` groups, `pub fn run/run_with/run_harness`, and
/// `pub fn resume/resume_with/resume_harness`.
///
/// This slice added `run_harness_on` and `resume_harness_on`, which take the
/// boundary as a parameter. Inside the crate that is exactly right — it is how
/// `engine::tests` drives a recording runner. Public, it is a hole in
/// `invariants[22]` ("schema-1..3 runs are host-only and no run changes its
/// boundary or image between epochs"): a downstream crate could execute a
/// legacy run through a Docker or remote `Runner` with no `RunnerPolicy`
/// recorded and no refusal, and a later ordinary `resume` would move it back
/// on-host between epochs.
///
/// A `pub`/`pub(crate)` widening is invisible to every in-crate test — each
/// caller compiles either way — so this reads the facade's own text. The
/// expected sets are transcribed from the packet, not derived from the file.
#[test]
fn the_engine_facade_exposes_exactly_the_items_the_packet_enumerates() {
    use std::collections::BTreeSet;

    let source = include_str!("mod.rs");

    // Every `pub fn` at the facade's top level.
    let public_fns: BTreeSet<&str> = source
        .lines()
        .filter_map(|line| line.strip_prefix("pub fn "))
        .filter_map(|rest| rest.split(['(', '<', ' ']).next())
        .collect();
    assert_eq!(
        public_fns,
        BTreeSet::from([
            "run",
            "run_with",
            "run_harness",
            "resume",
            "resume_with",
            "resume_harness",
        ]),
        "the engine facade's public functions moved away from the packet's list"
    );

    // And nothing else is exported by any other route.
    for widening in [
        "pub(crate) fn",
        "pub(crate) use",
        "pub struct",
        "pub enum",
        "pub const",
    ] {
        assert!(
            !source.contains(widening),
            "`{widening}` appeared in the engine facade, which the visibility rule forbids"
        );
    }

    // The re-exports, flattened. `pub use` is the other way a name reaches the
    // public path, and the packet enumerates these too.
    let mut reexported: BTreeSet<&str> = BTreeSet::new();
    let mut rest = source;
    while let Some(start) = rest.find("pub use ") {
        rest = &rest[start + "pub use ".len()..];
        let end = rest.find(';').expect("a `pub use` ends in a semicolon");
        let statement = &rest[..end];
        rest = &rest[end..];
        match (statement.find('{'), statement.find('}')) {
            (Some(open), Some(close)) => {
                for name in statement[open + 1..close].split(',') {
                    let name = name.trim();
                    if !name.is_empty() {
                        reexported.insert(name);
                    }
                }
            }
            _ => {
                reexported.insert(
                    statement
                        .rsplit("::")
                        .next()
                        .expect("a path")
                        .trim()
                        .trim_end_matches(';'),
                );
            }
        }
    }
    assert_eq!(
        reexported,
        BTreeSet::from([
            // options
            "RunOptions",
            "ResumeOptions",
            "Harness",
            "DEFAULT_ATTEMPT_TIMEOUT",
            "DEFAULT_MAX_DEFERS",
            // report
            "RunReport",
            "TaskReport",
            "TaskRunStatus",
            "RunOutcome",
            "PoolDrainRow",
            "topo_order",
            // crate::agent
            "AdapterSource",
            "BuiltinAdapters",
            // crate::events
            "AttemptRecord",
            "FailureRecord",
            // crate::ladder
            "AttemptFailure",
            "FailureKind",
            "FailureOrigin",
        ]),
        "the engine facade's re-exports moved away from the packet's list"
    );
    assert_eq!(reexported.len(), 18, "five groups, eighteen names");

    // The boundary-taking helpers exist and are *not* public: this test would
    // pass just as well if they had been deleted, which is not what it is for.
    for private in ["fn run_harness_on(", "fn resume_harness_on("] {
        assert!(source.contains(private), "`{private}` is gone");
    }
    assert!(
        !source.contains("pub fn run_harness_on") && !source.contains("pub fn resume_harness_on"),
        "an explicit-Runner entry point is public again"
    );
}

/// The six public entry points of the facade, as the facade's own text spells
/// them.
///
/// Read from `mod.rs` rather than written out, so a seventh public entry point
/// cannot be added without appearing here — and therefore without being
/// classified by the two tests below, which cross this set against a table of
/// calls.
fn public_facade_entry_points() -> Vec<&'static str> {
    let source = include_str!("mod.rs");
    let mut names: Vec<&str> = source
        .lines()
        .filter_map(|line| line.strip_prefix("pub fn "))
        .filter_map(|rest| rest.split(['(', '<', ' ']).next())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// **Every** public way to become a write coordinator establishes containment
/// first — not only the CLI's.
///
/// `invariants[INV-18]` is "on Windows every host child is a member of the
/// **coordinator's** ambient kill-on-close Job Object *from creation*", and
/// `expected_failures_refusals[1]` is "ambient job cannot be created or joined
/// (Windows) → write command refuses at startup with a diagnostic". Neither
/// says "when the coordinator was started by `src/main.rs`".
/// `decisions.phase_zero_modules.modules["src/engine/mod.rs"]` freezes
/// `run/run_with/run_harness` and `resume/resume_with/resume_harness` as the
/// facade, so all six are supported entry points: a downstream crate calling
/// `engine::run_with` is a write coordinator, and until this test existed it
/// established nothing at all. A kill between `CreateProcessW` and private-job
/// assignment then left the suspended stub alive — the exact residue INV-18
/// exists to prevent — and an ambient failure could not produce the required
/// pre-effect refusal, because nothing attempted the join.
///
/// The oracle is [`crate::runner::host::containment_establishments`], which
/// counts on the calling thread: "this call established containment", not "some
/// earlier call in this process did". Each entry point is driven with input it
/// must refuse (an absent plan, an unknown run id) so the assertion is about
/// the entry point and not about a run.
///
/// The *class* is what is asserted: the table is crossed against the facade's
/// own `pub fn` list, so this cannot be satisfied by covering the two the
/// review named.
#[test]
fn every_public_write_coordinator_entry_point_establishes_containment() {
    let repo = temp_engine_repo("containment-facade");
    let mut run_opts = options(&repo);
    run_opts.plan_path = repo.join("absent-plan.md");
    let mut resume_opts = ResumeOptions::new("01ABSENTRUN".to_owned(), repo.clone());
    resume_opts.pools_path = Some(no_pools());
    resume_opts.private_root = Some(private_root_for(&repo));
    let adapters = BuiltinAdapters;

    type Call<'a> = Box<dyn Fn() -> Result<RunReport, TactusError> + 'a>;
    let entry_points: Vec<(&str, Call<'_>)> = vec![
        ("run", Box::new(|| run(&run_opts))),
        ("run_with", Box::new(|| run_with(&run_opts, &adapters))),
        (
            "run_harness",
            Box::new(|| run_harness(&run_opts, &Harness::new(&adapters))),
        ),
        ("resume", Box::new(|| resume(&resume_opts))),
        (
            "resume_with",
            Box::new(|| resume_with(&resume_opts, &adapters)),
        ),
        (
            "resume_harness",
            Box::new(|| resume_harness(&resume_opts, &Harness::new(&adapters))),
        ),
    ];

    // The class, not the instance: every public entry point of the facade is
    // in this table, and every row of the table is one of them.
    let mut driven: Vec<&str> = entry_points.iter().map(|(name, _)| *name).collect();
    driven.sort_unstable();
    assert_eq!(
        driven,
        public_facade_entry_points(),
        "a public engine entry point is not driven here; every one of them makes its caller a \
         write coordinator"
    );
    assert_eq!(driven.len(), 6, "six entry points, and this is the count");

    for (name, call) in &entry_points {
        let before = crate::runner::host::containment_establishments();
        let outcome = call();
        assert!(
            outcome.is_err(),
            "{name}: the fixture relies on this refusing on its own input"
        );
        assert_eq!(
            crate::runner::host::containment_establishments(),
            before + 1,
            "`engine::{name}` entered the write coordinator without establishing containment \
             (INV-18); a kill after CreateProcessW and before private-job assignment would leave \
             a suspended stub alive"
        );
        // Windows has the other half of the same fact: the coordinator process
        // really is a member of an ambient job now. (Process-wide and latching,
        // so it corroborates the count above rather than replacing it.)
        #[cfg(windows)]
        assert!(
            crate::agent::proc::ambient_job_established(),
            "`engine::{name}` returned without this process joining its ambient Job Object"
        );
    }
}

/// The other side of the same census: a public entry point that is *not* a
/// write coordinator does not establish containment, and there are six of them.
///
/// `crash_reconstruction` anchors the ambient job at "every **write** command",
/// and `src/main.rs`'s `command_class` is the CLI's half of that split
/// (`every_write_command_establishes_containment_and_no_read_only_one_does`,
/// which asserts `skipped == 6`, "the six read-only subcommands"). This is the
/// library's half, and the six rows below are **the functions those six arms
/// call** — one per read-only subcommand, so the two censuses count the same
/// six things from opposite ends and the distinction survives when the CLI is
/// not involved at all.
///
/// `connect` and `capacity` are the interesting rows — they *do* spawn agent
/// CLIs — and they are still not coordinators, so INV-18's "the
/// **coordinator's** ambient … Job Object" does not reach their children.
/// Protecting those is a stronger guarantee than the packet asks for; it is
/// recorded as `PR4A-SPAWN-WITHOUT-AMBIENT` in `reviews/FINDINGS.md` with an
/// owner, not done here.
#[test]
fn no_read_only_public_entry_point_establishes_containment() {
    let repo = temp_engine_repo("containment-readonly");
    let scratch = private_root_for(&repo);
    fs::create_dir_all(&scratch).expect("scratch");
    let absent = repo.join("absent-plan.md");

    type Call<'a> = Box<dyn Fn() + 'a>;
    let read_only: Vec<(&str, Call<'_>)> = vec![
        (
            "validate::run",
            Box::new(|| {
                let _ = crate::validate::run(&crate::validate::ValidateOptions {
                    plan_path: absent.clone(),
                    config_path: None,
                    config_root: repo.clone(),
                    pools_path: Some(no_pools()),
                    engine_limits: config::EngineLimits::Fresh,
                });
            }),
        ),
        (
            "status::load",
            Box::new(|| {
                let _ = crate::status::load(&repo, None);
            }),
        ),
        (
            "export::load",
            Box::new(|| {
                let _ = crate::export::load(&repo, "01ABSENTRUN");
            }),
        ),
        (
            "answer::answer",
            Box::new(|| {
                let _ = crate::answer::answer(&repo, "q1", crate::answer::Reply::Decline);
            }),
        ),
        (
            "capacity::report",
            Box::new(|| {
                let _ = capacity::report(
                    &capacity::CapacityOptions {
                        config_path: Some(absent.clone()),
                        pools_path: Some(no_pools()),
                        repo_root: repo.clone(),
                    },
                    &BuiltinAdapters,
                );
            }),
        ),
        (
            "connect::run_with",
            Box::new(|| {
                let _ = crate::connect::run_with(
                    &crate::connect::ConnectOptions {
                        pools_path: Some(scratch.join("pools.toml")),
                        force: true,
                    },
                    &BuiltinAdapters,
                    // No ids: the seam exists so this test spawns nothing. What
                    // is under test is the containment step, which happens
                    // before any spawn or not at all.
                    std::iter::empty(),
                );
            }),
        ),
    ];
    assert_eq!(
        read_only.len(),
        6,
        "one library entry point per read-only subcommand — the same six \
         `src/main.rs` counts on the dispatch side"
    );

    for (name, call) in &read_only {
        let before = crate::runner::host::containment_establishments();
        call();
        assert_eq!(
            crate::runner::host::containment_establishments(),
            before,
            "`{name}` is not a write coordinator and established containment anyway"
        );
    }
}

/// Containment comes **before** the coordinator, and a failure to establish it
/// refuses the run before any effect.
///
/// `side_effect_vs_event_ordering` is "no events; ambient job before any
/// spawn", and `expected_failures_refusals[1]` is a refusal "at startup with a
/// diagnostic". The oracle is `src/main.rs`'s: the two outcomes are different
/// errors from different places. A refused containment names the ambient job
/// and *not* the plan; with containment established the coordinator runs and
/// fails on the plan instead. If establishment happened after the coordinator,
/// or not at all, the first call would carry the plan's error.
///
/// The step is a parameter here for the reason `dispatch` takes one: no machine
/// can make the real join fail on demand, and on Unix it cannot fail at all.
/// The seam is not a hole — `Contained`'s field is private to
/// `crate::runner::host`, so a closure that returns one has established
/// containment.
#[test]
fn a_facade_run_refuses_before_any_effect_when_containment_fails() {
    let repo = temp_engine_repo("containment-order");
    let mut opts = options(&repo);
    opts.plan_path = repo.join("absent-plan.md");
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Pass]);
    let harness = Harness::new(&source);
    let runner = RecordingRunner::new();

    let refused = run_contained(&opts, &harness, &runner, || {
        Err(TactusError::Refused {
            message: "the ambient Job Object could not be established (simulated failure)"
                .to_owned(),
        })
    })
    .expect_err("a run whose ambient job cannot be established must refuse");
    let refused = refused.to_string();
    assert!(
        refused.contains("ambient Job Object"),
        "the refusal must diagnose the ambient job: {refused}"
    );
    assert!(
        !refused.contains("absent-plan"),
        "the coordinator ran before containment: {refused}"
    );
    assert!(
        runner.seen().is_empty(),
        "a run refused at startup spawned a process: {:?}",
        runner.seen()
    );

    let reached = run_contained(&opts, &harness, &runner, || {
        crate::runner::host::contain_write_command(&mut crate::agent::proc::NoHooks)
    })
    .expect_err("the coordinator then fails on its own, on the plan");
    let reached = reached.to_string();
    assert!(
        reached.contains("absent-plan"),
        "with containment established the coordinator must run: {reached}"
    );
    assert!(
        !reached.contains("ambient Job Object"),
        "a successful establishment must not be reported as a refusal: {reached}"
    );
}

/// The same ordering, for the other coordinator. A resume is a write command:
/// `startup_census` enumerates them "(run, resume)".
#[test]
fn a_facade_resume_refuses_before_any_effect_when_containment_fails() {
    let repo = temp_engine_repo("containment-order-resume");
    let mut opts = ResumeOptions::new("01ABSENTRUN".to_owned(), repo.clone());
    opts.pools_path = Some(no_pools());
    opts.private_root = Some(private_root_for(&repo));
    let source = source(vec![Effect::EditFile], vec![ReviewBehavior::Pass]);
    let harness = Harness::new(&source);
    let runner = RecordingRunner::new();

    let refused = resume_contained(&opts, &harness, &runner, || {
        Err(TactusError::Refused {
            message: "the ambient Job Object could not be established (simulated failure)"
                .to_owned(),
        })
    })
    .expect_err("a resume whose ambient job cannot be established must refuse");
    // The resume's own refusal names the run directory it looked in; the
    // containment refusal cannot, because it happens before the coordinator
    // resolves anything.
    let looked_in = repo.display().to_string();
    let refused = refused.to_string();
    assert!(
        refused.contains("ambient Job Object"),
        "the refusal must diagnose the ambient job: {refused}"
    );
    assert!(
        !refused.contains(&looked_in),
        "the coordinator ran before containment: {refused}"
    );
    assert!(
        runner.seen().is_empty(),
        "a resume refused at startup spawned a process: {:?}",
        runner.seen()
    );

    let reached = resume_contained(&opts, &harness, &runner, || {
        crate::runner::host::contain_write_command(&mut crate::agent::proc::NoHooks)
    })
    .expect_err("the coordinator then fails on its own, on the run it cannot find");
    let reached = reached.to_string();
    assert!(
        reached.contains(&looked_in),
        "with containment established the coordinator must run: {reached}"
    );
    assert!(
        !reached.contains("ambient Job Object"),
        "a successful establishment must not be reported as a refusal: {reached}"
    );
}
