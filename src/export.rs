//! Local, read-only projection of a run's recorded routing decisions.
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::error::TactusError;
use crate::events::{self, AttemptRecord, Event, EventBody, ReviewPassOutcome, SelectionOrigin};
use crate::ir::{Effort, Plan, Task, TaskKind, Tier, Usage};
use crate::ladder::{FailureKind, FailureOrigin};
use crate::rundir;

const EXPORT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Format {
    Jsonl,
    Csv,
}

#[derive(Serialize)]
pub struct Row {
    schema_version: u32,
    run_id: String,
    tactus_version: String,
    run_started_at: String,
    attempt_started_at: String,
    attempt_finished_at: Option<String>,
    task_id: String,
    task_title: String,
    attempt: u32,
    rung: u32,
    task_features: TaskFeatures,
    chain: Chain,
    selected_tier: String,
    selection_origin: &'static str,
    adapter_id: String,
    adapter_cli_version: Option<String>,
    model: String,
    effort: Option<&'static str>,
    pool: Option<String>,
    session_resumed: bool,
    duration_ms: Option<u64>,
    cost_usd: Option<f64>,
    usage: Option<ExportUsage>,
    outcome: &'static str,
    failure_kind: Option<&'static str>,
    failure_origin: Option<&'static str>,
    failure_category: Option<&'static str>,
    work_evidence: Option<&'static str>,
    failure_reason: Option<String>,
    reviews: Vec<Review>,
}

#[derive(Serialize)]
struct TaskFeatures {
    kind: String,
    suggested_tier: Option<String>,
    minimum_tier: Option<String>,
    dependency_count: usize,
    acceptance_count: usize,
    path_hints: Vec<String>,
    artifact_input_count: usize,
    artifact_output_count: usize,
}

#[derive(Serialize)]
struct Chain {
    tiers: Vec<String>,
    attempts_per: u32,
}

#[derive(Serialize)]
struct Review {
    pass: String,
    adapter_id: String,
    adapter_cli_version: Option<String>,
    model: String,
    effort: Option<&'static str>,
    pool: Option<String>,
    cost_usd: Option<f64>,
    outcome: &'static str,
}

/// A successful load plus recoverable residue the caller must surface on a
/// separate channel from the machine-readable export.
pub struct Loaded {
    pub rows: Vec<Row>,
    pub warnings: Vec<String>,
}

/// Export-schema-1 usage. This intentionally is not the engine's `Usage`:
/// adding an internal field must not silently add a public JSON key.
#[derive(Serialize)]
struct ExportUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    num_turns: Option<u32>,
    reasoning_output_tokens: Option<u64>,
}

type AttemptKey = (String, u32, u32);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettlementKind {
    Finished,
    Interrupted,
}

struct Settlement<'a> {
    index: usize,
    kind: SettlementKind,
    ts: &'a str,
    profile: &'a str,
    record: &'a AttemptRecord,
    parking: Option<&'a events::AttemptParking>,
    transition: Option<&'a events::AttemptTransition>,
}

struct RunContext<'a> {
    events_path: &'a Path,
    run_id: &'a str,
    tactus_version: &'a str,
    started_at: &'a str,
}

/// Load and validate one stable run snapshot. No config, source plan, adapter,
/// or report is consulted.
pub fn load(repo_root: &Path, wanted: &str) -> Result<Loaded, TactusError> {
    let run_id = rundir::resolve_run_id(repo_root, wanted)?;
    let public = rundir::public_dir(repo_root, &run_id);
    let events_path = public.join("events.jsonl");
    let snapshot_bytes = begin_snapshot(&public, &run_id, &events_path)?;

    // Always perform the closing stability check before returning a projection
    // error. Otherwise a racing resume could make a transient moving view look
    // like permanently invalid input.
    let projected = (|| {
        let events::ParsedLines {
            events: log,
            torn_tail_warning,
        } = events::parse_bytes(&events_path, &snapshot_bytes)?;
        let warnings = torn_tail_warning.into_iter().collect();
        let mut run_starts = log
            .iter()
            .filter(|event| matches!(event.body, EventBody::RunStarted { .. }));
        let started_event = run_starts.next().ok_or_else(|| TactusError::EventLog {
            path: events_path.clone(),
            message: "no run_started event".to_owned(),
        })?;
        if run_starts.next().is_some() {
            return invalid(&events_path, "duplicate run_started event".to_owned());
        }
        let EventBody::RunStarted { data: started } = &started_event.body else {
            unreachable!()
        };
        let effective_schema = events::ensure_supported_schema(started, &log, &events_path)?;
        if started.run_id != run_id {
            return invalid(
                &events_path,
                format!(
                    "run_started id `{}` does not match directory `{run_id}`",
                    started.run_id
                ),
            );
        }
        validate_timestamp(
            &events_path,
            &format!("run `{run_id}` run_started"),
            &started_event.ts,
        )?;

        let plan_path = public.join("plan.normalized.json");
        let plan_bytes = std::fs::read(&plan_path).map_err(|source| TactusError::Io {
            path: plan_path.clone(),
            source,
        })?;
        if effective_schema >= 3 {
            let recorded = events::recorded_normalized_plan_digest(&log).ok_or_else(|| {
                TactusError::EventLog {
                    path: events_path.clone(),
                    message: "event schema 3 does not record the normalized-plan SHA-256 digest"
                        .to_owned(),
                }
            })?;
            let actual = events::normalized_plan_digest(&plan_bytes);
            if actual != recorded {
                return invalid(
                    &plan_path,
                    format!(
                        "normalized plan digest `{actual}` does not match recorded digest `{recorded}`"
                    ),
                );
            }
        }
        let plan: Plan =
            serde_json::from_slice(&plan_bytes).map_err(|error| TactusError::Parse {
                message: format!("{}: {error}", plan_path.display()),
            })?;
        if plan.source.hash != started.plan_hash {
            return invalid(
                &plan_path,
                format!(
                    "frozen plan hash `{}` does not match run-start hash `{}`",
                    plan.source.hash, started.plan_hash
                ),
            );
        }
        let tasks = unique_tasks(&plan, &events_path)?;
        let chains = unique_chains(&started.chains, &tasks, &events_path)?;
        let settlements = settlements(&log, &events_path)?;
        let mut seen_starts = BTreeSet::new();
        let mut rows = Vec::new();
        let context = RunContext {
            events_path: &events_path,
            run_id: &run_id,
            tactus_version: &started.tactus_version,
            started_at: &started_event.ts,
        };

        for (start_index, event) in log.iter().enumerate() {
            let EventBody::AttemptStarted {
                task,
                attempt,
                rung,
                profile,
                data,
            } = &event.body
            else {
                continue;
            };
            let key = (task.clone(), *attempt, *rung);
            if *attempt == 0 {
                return invalid(
                    &events_path,
                    format!("attempt number must be positive for {}", key_text(&key)),
                );
            }
            validate_timestamp(
                &events_path,
                &format!("run `{run_id}`, {} start", key_text(&key)),
                &event.ts,
            )?;
            if !seen_starts.insert(key.clone()) {
                return invalid(
                    &events_path,
                    format!("duplicate attempt start {}", key_text(&key)),
                );
            }
            let task_plan = tasks
                .get(task)
                .ok_or_else(|| bad_join(&events_path, task, "frozen plan"))?;
            let chain = chains
                .get(task)
                .ok_or_else(|| bad_join(&events_path, task, "run-start chains"))?;
            let expected_tier = usize::try_from(*rung)
                .ok()
                .and_then(|index| chain.tiers.get(index))
                .ok_or_else(|| TactusError::EventLog {
                    path: events_path.clone(),
                    message: format!("rung is outside the recorded chain for {}", key_text(&key)),
                })?;
            if tier(*expected_tier) != data.tier {
                return invalid(
                    &events_path,
                    format!(
                        "start tier `{}` does not match recorded rung tier `{expected_tier}` for {}",
                        data.tier,
                        key_text(&key)
                    ),
                );
            }
            let settlement = settlements.get(&key);
            if let Some(done) = settlement {
                validate_settlement(&events_path, &key, start_index, profile, data, done)?;
                validate_timestamp(
                    &events_path,
                    &format!("run `{run_id}`, {} settlement", key_text(&key)),
                    done.ts,
                )?;
            }
            rows.push(build_row(&context, event, task_plan, chain, settlement)?);
        }
        for key in settlements.keys() {
            if !seen_starts.contains(key) {
                return invalid(
                    &events_path,
                    format!("settlement without a start for {}", key_text(key)),
                );
            }
        }
        Ok(Loaded { rows, warnings })
    })();

    finish_snapshot(&public, &run_id, &events_path, &snapshot_bytes)?;
    projected
}

fn unique_tasks<'a>(
    plan: &'a Plan,
    path: &Path,
) -> Result<BTreeMap<String, &'a Task>, TactusError> {
    let mut out = BTreeMap::new();
    for task in &plan.tasks {
        if out.insert(task.id.to_string(), task).is_some() {
            return invalid(path, format!("duplicate task `{}` in frozen plan", task.id));
        }
    }
    Ok(out)
}

fn unique_chains<'a>(
    chains: &'a [events::ChainSummary],
    tasks: &BTreeMap<String, &'_ Task>,
    path: &Path,
) -> Result<BTreeMap<String, &'a events::ChainSummary>, TactusError> {
    let mut out = BTreeMap::new();
    for chain in chains {
        if !tasks.contains_key(&chain.task) {
            return invalid(
                path,
                format!(
                    "run-start chain task `{}` is absent from the frozen plan",
                    chain.task
                ),
            );
        }
        if chain.tiers.is_empty() {
            return invalid(
                path,
                format!("recorded chain for task `{}` has no tiers", chain.task),
            );
        }
        if chain.attempts_per == 0 {
            return invalid(
                path,
                format!(
                    "recorded chain for task `{}` has attempts_per 0",
                    chain.task
                ),
            );
        }
        if out.insert(chain.task.clone(), chain).is_some() {
            return invalid(
                path,
                format!("duplicate recorded chain for task `{}`", chain.task),
            );
        }
    }
    for task in tasks.keys() {
        if !out.contains_key(task) {
            return invalid(
                path,
                format!("frozen-plan task `{task}` has no run-start chain"),
            );
        }
    }
    Ok(out)
}

fn settlements<'a>(
    log: &'a [Event],
    path: &Path,
) -> Result<BTreeMap<AttemptKey, Settlement<'a>>, TactusError> {
    let mut out = BTreeMap::new();
    for (index, event) in log.iter().enumerate() {
        let (kind, task, attempt, rung, profile, record, parking, transition) = match &event.body {
            EventBody::AttemptFinished {
                task,
                attempt,
                rung,
                profile,
                data,
                parking,
                transition,
                ..
            } => (
                SettlementKind::Finished,
                task,
                attempt,
                rung,
                profile,
                &**data,
                parking.as_deref(),
                transition.as_deref(),
            ),
            EventBody::AttemptInterrupted {
                task,
                attempt,
                rung,
                profile,
                data,
            } => (
                SettlementKind::Interrupted,
                task,
                attempt,
                rung,
                profile,
                &**data,
                None,
                None,
            ),
            _ => continue,
        };
        let key = (task.clone(), *attempt, *rung);
        if out
            .insert(
                key.clone(),
                Settlement {
                    index,
                    kind,
                    ts: &event.ts,
                    profile,
                    record,
                    parking,
                    transition,
                },
            )
            .is_some()
        {
            return invalid(path, format!("duplicate settlement for {}", key_text(&key)));
        }
    }
    Ok(out)
}

fn validate_settlement(
    path: &Path,
    key: &AttemptKey,
    start_index: usize,
    start_profile: &str,
    start: &events::AttemptStarted,
    settlement: &Settlement<'_>,
) -> Result<(), TactusError> {
    if settlement.index <= start_index {
        return invalid(
            path,
            format!("settlement appears before its start for {}", key_text(key)),
        );
    }
    if settlement.profile != start_profile
        || settlement.record.attempt != key.1
        || settlement.record.tier != start.tier
        || settlement.record.model != start.model
        || settlement.record.pool != start.pool
    {
        return invalid(
            path,
            format!("mismatched settlement identity for {}", key_text(key)),
        );
    }

    let failure_kind = settlement
        .record
        .failure
        .as_ref()
        .map(|failure| failure.kind);
    let failure_origin = settlement
        .record
        .failure
        .as_ref()
        .map(|failure| failure.origin);
    let outage = matches!(
        (failure_kind, failure_origin),
        (
            Some(FailureKind::RateLimited | FailureKind::ReviewUnavailable),
            _
        ) | (Some(FailureKind::Timeout), Some(FailureOrigin::Reviewer))
    );
    if let Some(transition) = settlement.transition {
        let valid = match transition {
            events::AttemptTransition::Retry(_) | events::AttemptTransition::Escalate(_) => {
                failure_kind.is_some()
            }
            events::AttemptTransition::Defer(_) => outage,
            events::AttemptTransition::Fail(data) => failure_kind == Some(data.kind),
        };
        if !valid {
            return invalid(
                path,
                format!("invalid atomic attempt transition for {}", key_text(key)),
            );
        }
    }
    if let Some(parking) = settlement.parking {
        let associated = parking.question.affected_tasks.len() == 1
            && parking.question.affected_tasks[0].as_str() == key.0;
        let semantics = match parking.question.kind {
            crate::ir::QuestionKind::Clarify => {
                failure_kind == Some(FailureKind::NeedsHuman)
                    && settlement.transition.is_none()
                    && parking.refund_attempt
            }
            crate::ir::QuestionKind::ApproveSpend => {
                matches!(
                    settlement.transition,
                    Some(events::AttemptTransition::Escalate(_))
                ) && !parking.refund_attempt
            }
            crate::ir::QuestionKind::Unblock
                if matches!(
                    failure_kind,
                    Some(FailureKind::ReviewInputTooLarge | FailureKind::ReviewInputOpaque)
                ) =>
            {
                failure_origin == Some(FailureOrigin::Reviewer)
                    && settlement.transition.is_none()
                    && !parking.refund_attempt
            }
            crate::ir::QuestionKind::Unblock if outage => {
                settlement.transition.is_none() && parking.refund_attempt
            }
            crate::ir::QuestionKind::Unblock => {
                failure_kind.is_some() && settlement.transition.is_none() && !parking.refund_attempt
            }
            crate::ir::QuestionKind::Continue => false,
        };
        if !associated || !semantics {
            return invalid(
                path,
                format!("invalid atomic policy parking for {}", key_text(key)),
            );
        }
    }
    match settlement.kind {
        SettlementKind::Finished if failure_kind == Some(FailureKind::Interrupted) => invalid(
            path,
            format!(
                "attempt_finished carries interruption semantics for {}",
                key_text(key)
            ),
        ),
        SettlementKind::Interrupted if failure_kind != Some(FailureKind::Interrupted) => invalid(
            path,
            format!(
                "attempt_interrupted lacks an interrupted failure for {}",
                key_text(key)
            ),
        ),
        SettlementKind::Interrupted
            if settlement
                .record
                .failure
                .as_ref()
                .map(|failure| failure.origin)
                != Some(FailureOrigin::Worker) =>
        {
            invalid(
                path,
                format!(
                    "attempt_interrupted is not attributed to the worker for {}",
                    key_text(key)
                ),
            )
        }
        SettlementKind::Finished | SettlementKind::Interrupted => Ok(()),
    }
}

fn build_row(
    context: &RunContext<'_>,
    start_event: &Event,
    task: &Task,
    chain: &events::ChainSummary,
    settlement: Option<&Settlement<'_>>,
) -> Result<Row, TactusError> {
    let EventBody::AttemptStarted {
        attempt,
        rung,
        data,
        ..
    } = &start_event.body
    else {
        unreachable!()
    };
    let failure = settlement.and_then(|done| done.record.failure.as_ref());
    let kind = failure
        .map(|f| f.kind)
        .or_else(|| settlement.is_none().then_some(FailureKind::Interrupted));
    let origin = failure
        .map(|f| f.origin)
        .or_else(|| settlement.is_none().then_some(FailureOrigin::Worker));
    let (category, evidence) = kind.map(failure_projection).unzip();
    let interrupted = settlement
        .map(|done| done.kind == SettlementKind::Interrupted)
        .unwrap_or(true);
    let record = settlement.map(|done| done.record);
    let identity = format!(
        "run `{}`, {}",
        context.run_id,
        key_text(&(task.id.to_string(), *attempt, *rung))
    );
    let duration_ms = record
        .map(|record| duration_ms(context.events_path, &identity, record.duration))
        .transpose()?;
    validate_cost(
        context.events_path,
        &format!("{identity}, worker"),
        record.and_then(|record| record.cost_usd),
    )?;
    if let Some(record) = record {
        for (index, review) in record.reviews.iter().enumerate() {
            validate_cost(
                context.events_path,
                &format!("{identity}, review pass {index}"),
                review.cost_usd,
            )?;
        }
    }
    Ok(Row {
        schema_version: EXPORT_SCHEMA_VERSION,
        run_id: context.run_id.to_owned(),
        tactus_version: context.tactus_version.to_owned(),
        run_started_at: context.started_at.to_owned(),
        attempt_started_at: start_event.ts.clone(),
        attempt_finished_at: settlement.map(|done| done.ts.to_owned()),
        task_id: task.id.to_string(),
        task_title: task.title.clone(),
        attempt: *attempt,
        rung: *rung,
        task_features: TaskFeatures {
            kind: task_kind(task.kind).to_owned(),
            suggested_tier: task.suggested_tier.map(|value| tier(value).to_owned()),
            minimum_tier: task.min_tier.map(|value| tier(value).to_owned()),
            dependency_count: task.depends_on.len(),
            acceptance_count: task.acceptance.len(),
            path_hints: task.path_hints.clone(),
            artifact_input_count: task.artifacts_in.len(),
            artifact_output_count: task.artifacts_out.len(),
        },
        chain: Chain {
            tiers: chain
                .tiers
                .iter()
                .map(|value| tier(*value).to_owned())
                .collect(),
            attempts_per: chain.attempts_per,
        },
        selected_tier: data.tier.clone(),
        selection_origin: selection_origin(data.selection_origin),
        adapter_id: data.adapter.clone().unwrap_or_else(|| data.agent.clone()),
        adapter_cli_version: data.preflight_cli_version.clone(),
        model: data.model.clone(),
        effort: data.effort.map(effort),
        pool: data.pool.clone(),
        session_resumed: data.resume_session.is_some(),
        duration_ms,
        cost_usd: record.and_then(|r| r.cost_usd),
        usage: record
            .and_then(|record| record.usage.as_ref())
            .map(export_usage),
        outcome: if interrupted {
            "interrupted"
        } else if kind.is_some() {
            "failed"
        } else {
            "passed"
        },
        failure_kind: kind.map(failure_kind),
        failure_origin: origin.map(failure_origin),
        failure_category: category,
        work_evidence: evidence,
        failure_reason: failure.map(|f| f.reason.clone()),
        reviews: record
            .map(|r| r.reviews.iter().map(review).collect())
            .unwrap_or_default(),
    })
}

fn review(value: &events::ReviewRecord) -> Review {
    Review {
        pass: value.pass.clone(),
        adapter_id: value.adapter.clone().unwrap_or_else(|| value.agent.clone()),
        adapter_cli_version: value.preflight_cli_version.clone(),
        model: value.model.clone(),
        effort: value.effort.map(effort),
        pool: value.pool.clone(),
        cost_usd: value.cost_usd,
        outcome: review_outcome(value.outcome),
    }
}

fn selection_origin(value: Option<SelectionOrigin>) -> &'static str {
    match value {
        None => "unknown",
        Some(SelectionOrigin::Auto) => "auto",
        Some(SelectionOrigin::Pin) => "pin",
        Some(SelectionOrigin::UserOverride) => "user_override",
        Some(SelectionOrigin::Exploration) => "exploration",
    }
}

fn effort(value: Effort) -> &'static str {
    match value {
        Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::XHigh => "xhigh",
        Effort::Max => "max",
    }
}

fn task_kind(value: TaskKind) -> &'static str {
    match value {
        TaskKind::Design => "design",
        TaskKind::Implement => "implement",
        TaskKind::Fix => "fix",
        TaskKind::Refactor => "refactor",
        TaskKind::Test => "test",
        TaskKind::Docs => "docs",
        TaskKind::Chore => "chore",
    }
}

fn tier(value: Tier) -> &'static str {
    match value {
        Tier::Small => "small",
        Tier::Mid => "mid",
        Tier::Frontier => "frontier",
    }
}

fn review_outcome(value: ReviewPassOutcome) -> &'static str {
    match value {
        ReviewPassOutcome::Passed => "passed",
        ReviewPassOutcome::Failed => "failed",
        ReviewPassOutcome::Unavailable => "unavailable",
    }
}

fn failure_kind(value: FailureKind) -> &'static str {
    match value {
        FailureKind::NoChain => "no_chain",
        FailureKind::EmptyDiff => "empty_diff",
        FailureKind::AgentError => "agent_error",
        FailureKind::Timeout => "timeout",
        FailureKind::RateLimited => "rate_limited",
        FailureKind::GateFailed => "gate_failed",
        FailureKind::TestProvenance => "test_provenance",
        FailureKind::ReviewInputTooLarge => "review_input_too_large",
        FailureKind::ReviewInputOpaque => "review_input_opaque",
        FailureKind::ReviewFailed => "review_failed",
        FailureKind::ReviewUnavailable => "review_unavailable",
        FailureKind::NeedsHuman => "needs_human",
        FailureKind::Declined => "declined",
        FailureKind::Interrupted => "interrupted",
    }
}

fn failure_origin(value: FailureOrigin) -> &'static str {
    match value {
        FailureOrigin::Worker => "worker",
        FailureOrigin::Reviewer => "reviewer",
    }
}

fn export_usage(value: &Usage) -> ExportUsage {
    ExportUsage {
        input_tokens: value.input_tokens,
        output_tokens: value.output_tokens,
        cache_creation_input_tokens: value.cache_creation_input_tokens,
        cache_read_input_tokens: value.cache_read_input_tokens,
        num_turns: value.num_turns,
        reasoning_output_tokens: value.reasoning_output_tokens,
    }
}

/// Deliberately exhaustive and wildcard-free: a new FailureKind is a compile error here.
fn failure_projection(kind: FailureKind) -> (&'static str, &'static str) {
    match kind {
        FailureKind::GateFailed => ("capability", "gate"),
        FailureKind::ReviewFailed => ("capability", "review"),
        FailureKind::AgentError | FailureKind::RateLimited | FailureKind::ReviewUnavailable => {
            ("provider", "none")
        }
        FailureKind::Timeout | FailureKind::Interrupted => ("infrastructure", "none"),
        FailureKind::NoChain | FailureKind::NeedsHuman | FailureKind::Declined => {
            ("policy", "none")
        }
        FailureKind::EmptyDiff | FailureKind::TestProvenance => ("policy", "engine"),
        FailureKind::ReviewInputTooLarge | FailureKind::ReviewInputOpaque => ("policy", "review"),
    }
}

fn duration_ms(
    path: &Path,
    identity: &str,
    value: std::time::Duration,
) -> Result<u64, TactusError> {
    u64::try_from(value.as_millis()).map_err(|_| TactusError::EventLog {
        path: path.to_owned(),
        message: format!("attempt duration exceeds export schema range for {identity}"),
    })
}

fn validate_cost(path: &Path, label: &str, cost: Option<f64>) -> Result<(), TactusError> {
    if let Some(cost) = cost {
        if !cost.is_finite() || cost < 0.0 {
            return Err(TactusError::EventLog {
                path: path.to_owned(),
                message: format!("{label} cost must be finite and non-negative, got {cost}"),
            });
        }
    }
    Ok(())
}

fn validate_timestamp(path: &Path, label: &str, value: &str) -> Result<(), TactusError> {
    if !is_supported_rfc3339(value) {
        return Err(TactusError::EventLog {
            path: path.to_owned(),
            message: format!(
                "{label} timestamp `{value}` is not RFC 3339 in tactus's supported \
                 no-leap-second profile"
            ),
        });
    }
    Ok(())
}

/// Validate the RFC 3339 subset Tactus can record.
///
/// Event timestamps come from `SystemTime` as ordinary Unix seconds, so the
/// writer can never emit `:60`. Rejecting leap-second notation avoids accepting
/// it on arbitrary dates (which requires an external announcement table) while
/// retaining every timestamp an authentic Tactus writer can produce.
fn is_supported_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let Some(year) = decimal(bytes, 0, 4) else {
        return false;
    };
    let Some(month) = decimal(bytes, 5, 2) else {
        return false;
    };
    let Some(day) = decimal(bytes, 8, 2) else {
        return false;
    };
    let Some(hour) = decimal(bytes, 11, 2) else {
        return false;
    };
    let Some(minute) = decimal(bytes, 14, 2) else {
        return false;
    };
    let Some(second) = decimal(bytes, 17, 2) else {
        return false;
    };
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return false;
    }

    let mut zone = 19;
    if bytes.get(zone) == Some(&b'.') {
        zone += 1;
        let fraction_start = zone;
        while bytes.get(zone).is_some_and(u8::is_ascii_digit) {
            zone += 1;
        }
        if zone == fraction_start {
            return false;
        }
    }
    match bytes.get(zone..) {
        Some([b'Z' | b'z']) => true,
        Some([b'+' | b'-', _, _, b':', _, _]) => {
            decimal(bytes, zone + 1, 2).is_some_and(|value| value <= 23)
                && decimal(bytes, zone + 4, 2).is_some_and(|value| value <= 59)
        }
        _ => false,
    }
}

fn decimal(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let digits = bytes.get(start..start.checked_add(len)?)?;
    digits.iter().try_fold(0_u32, |value, digit| {
        digit
            .is_ascii_digit()
            .then(|| value * 10 + u32::from(*digit - b'0'))
    })
}

fn begin_snapshot(public: &Path, run_id: &str, path: &Path) -> Result<Vec<u8>, TactusError> {
    begin_snapshot_with(
        run_id,
        || rundir::is_running(public),
        || events::read_bytes(path),
    )
}

fn begin_snapshot_with(
    run_id: &str,
    mut is_running: impl FnMut() -> bool,
    mut read: impl FnMut() -> Result<Vec<u8>, TactusError>,
) -> Result<Vec<u8>, TactusError> {
    if is_running() {
        return Err(live_refusal(run_id));
    }
    let text = read()?;
    if is_running() {
        return Err(live_refusal(run_id));
    }
    Ok(text)
}

fn finish_snapshot(
    public: &Path,
    run_id: &str,
    path: &Path,
    original: &[u8],
) -> Result<(), TactusError> {
    finish_snapshot_with(
        run_id,
        original,
        || rundir::is_running(public),
        || events::read_bytes(path),
    )
}

fn finish_snapshot_with(
    run_id: &str,
    original: &[u8],
    mut is_running: impl FnMut() -> bool,
    mut read: impl FnMut() -> Result<Vec<u8>, TactusError>,
) -> Result<(), TactusError> {
    let current = read()?;
    if is_running() {
        return Err(live_refusal(run_id));
    }
    if current != original {
        return Err(TactusError::Refused {
            message: format!(
                "run `{run_id}` changed while its decision snapshot was being read; retry once the run is settled"
            ),
        });
    }
    Ok(())
}

fn live_refusal(run_id: &str) -> TactusError {
    TactusError::Refused {
        message: format!(
            "run `{run_id}` is live and its decision dataset is still moving; wait for it to finish or stop it before exporting"
        ),
    }
}

pub fn write(rows: &[Row], format: Format, out: &mut impl Write) -> anyhow::Result<()> {
    match format {
        Format::Jsonl => {
            for row in rows {
                serde_json::to_writer(&mut *out, row)?;
                out.write_all(b"\n")?;
            }
        }
        Format::Csv => write_csv(rows, out)?,
    }
    Ok(())
}

const CSV_HEADER: &str = "schema_version,run_id,tactus_version,run_started_at,attempt_started_at,attempt_finished_at,task_id,task_title,attempt,rung,task_kind,suggested_tier,minimum_tier,dependency_count,acceptance_count,path_hints_json,artifact_input_count,artifact_output_count,chain_tiers_json,attempts_per,selected_tier,selection_origin,adapter_id,adapter_cli_version,model,effort,pool,session_resumed,duration_ms,cost_usd,usage_input_tokens,usage_output_tokens,usage_cache_creation_input_tokens,usage_cache_read_input_tokens,usage_num_turns,usage_reasoning_output_tokens,outcome,failure_kind,failure_origin,failure_category,work_evidence,failure_reason,reviews_json\r\n";

fn write_csv(rows: &[Row], out: &mut impl Write) -> anyhow::Result<()> {
    out.write_all(CSV_HEADER.as_bytes())?;
    for row in rows {
        let usage = row.usage.as_ref();
        let fields = vec![
            row.schema_version.to_string(),
            row.run_id.clone(),
            row.tactus_version.clone(),
            row.run_started_at.clone(),
            row.attempt_started_at.clone(),
            opt(&row.attempt_finished_at),
            row.task_id.clone(),
            row.task_title.clone(),
            row.attempt.to_string(),
            row.rung.to_string(),
            row.task_features.kind.clone(),
            opt(&row.task_features.suggested_tier),
            opt(&row.task_features.minimum_tier),
            row.task_features.dependency_count.to_string(),
            row.task_features.acceptance_count.to_string(),
            serde_json::to_string(&row.task_features.path_hints)?,
            row.task_features.artifact_input_count.to_string(),
            row.task_features.artifact_output_count.to_string(),
            serde_json::to_string(&row.chain.tiers)?,
            row.chain.attempts_per.to_string(),
            row.selected_tier.clone(),
            row.selection_origin.to_owned(),
            row.adapter_id.clone(),
            opt(&row.adapter_cli_version),
            row.model.clone(),
            row.effort.unwrap_or_default().to_owned(),
            opt(&row.pool),
            row.session_resumed.to_string(),
            scalar(row.duration_ms),
            scalar(row.cost_usd),
            scalar(usage.and_then(|u| u.input_tokens)),
            scalar(usage.and_then(|u| u.output_tokens)),
            scalar(usage.and_then(|u| u.cache_creation_input_tokens)),
            scalar(usage.and_then(|u| u.cache_read_input_tokens)),
            scalar(usage.and_then(|u| u.num_turns)),
            scalar(usage.and_then(|u| u.reasoning_output_tokens)),
            row.outcome.to_owned(),
            row.failure_kind.unwrap_or_default().to_owned(),
            row.failure_origin.unwrap_or_default().to_owned(),
            row.failure_category.unwrap_or_default().to_owned(),
            row.work_evidence.unwrap_or_default().to_owned(),
            opt(&row.failure_reason),
            serde_json::to_string(&row.reviews)?,
        ];
        for (index, field) in fields.iter().enumerate() {
            if index != 0 {
                out.write_all(b",")?;
            }
            write_csv_field(field, out)?;
        }
        out.write_all(b"\r\n")?;
    }
    Ok(())
}

fn write_csv_field(value: &str, out: &mut impl Write) -> std::io::Result<()> {
    if value.contains([',', '"', '\r', '\n']) {
        out.write_all(b"\"")?;
        out.write_all(value.replace('"', "\"\"").as_bytes())?;
        out.write_all(b"\"")
    } else {
        out.write_all(value.as_bytes())
    }
}

fn opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}
fn scalar<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}
fn key_text(key: &AttemptKey) -> String {
    format!("task `{}`, attempt {}, rung {}", key.0, key.1, key.2)
}
fn bad_join(path: &Path, task: &str, source: &str) -> TactusError {
    TactusError::EventLog {
        path: path.to_owned(),
        message: format!("attempt task `{task}` is absent from {source}"),
    }
}
fn invalid<T>(path: &Path, message: String) -> Result<T, TactusError> {
    Err(TactusError::EventLog {
        path: path.to_owned(),
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const RUN_ID: &str = "01EXPORTTEST00000000000000";

    #[test]
    fn the_decision_index_names_the_shipped_export_schema() {
        let index = include_str!("../decisions/README.md");
        let expected = format!("schema-{EXPORT_SCHEMA_VERSION} JSONL/CSV projection");
        assert!(
            index.contains(&expected),
            "decision index must track the public exporter constant: expected `{expected}`"
        );
    }

    #[test]
    fn review_finding_ledger_uses_canonical_category_tokens() {
        let maintaining = include_str!("../MAINTAINING.md");
        for token in ["crash-consistency", "security-trust", "docs-contract"] {
            assert!(
                maintaining.contains(&format!("`{token}`")),
                "missing {token}"
            );
        }
        for stale in ["crash_consistency", "security_trust", "docs_contract"] {
            assert!(!maintaining.contains(stale), "stale category {stale}");
        }
    }

    #[test]
    fn export_schema_decision_lists_every_failure_kind() {
        let decision = include_str!("../decisions/2026-08-11-export-decisions-schema.md");
        for kind in [
            FailureKind::NoChain,
            FailureKind::EmptyDiff,
            FailureKind::AgentError,
            FailureKind::Timeout,
            FailureKind::RateLimited,
            FailureKind::GateFailed,
            FailureKind::TestProvenance,
            FailureKind::ReviewInputTooLarge,
            FailureKind::ReviewInputOpaque,
            FailureKind::ReviewFailed,
            FailureKind::ReviewUnavailable,
            FailureKind::NeedsHuman,
            FailureKind::Declined,
            FailureKind::Interrupted,
        ] {
            let token = failure_kind(kind);
            assert!(
                decision.contains(&format!("| `{token}` |")),
                "export decision omits `{token}`"
            );
        }
    }

    #[test]
    fn readme_does_not_promise_unconditional_anti_self_review() {
        let readme = include_str!("../README.md");
        assert!(!readme.contains("Nothing reviews its own work"));
        assert!(readme.contains("falls back to the"));
        assert!(readme.contains("frozen same-model reviewer"));
        assert!(readme.contains("A configured blast-radius"));
        assert!(readme.contains("second opinion is stricter"));
    }

    #[test]
    fn windows_crash_containment_docs_match_shipped_job_ownership() {
        let readme = include_str!("../README.md");
        let design = include_str!("../DESIGN.md");
        assert!(readme.contains("kill-on-close Job Object"), "{readme}");
        assert!(readme.contains("before its primary"), "{readme}");
        assert!(readme.contains("thread runs"), "{readme}");
        assert!(design.contains("created suspended"), "{design}");
        assert!(
            design.contains("boundedly observe that job empty"),
            "{design}"
        );
        assert!(!readme.contains("run the conductor under WSL"), "{readme}");
        assert!(!design.contains("run the conductor under WSL"), "{design}");
    }

    #[test]
    fn design_does_not_authorize_legacy_subject_only_adoption() {
        let design = include_str!("../DESIGN.md");
        assert!(
            design.contains("never** adopted from parent plus subject alone"),
            "schema-1/2 recovery must stay fail-closed"
        );
        assert!(
            design.contains("compare-and-swaps the **recorded full branch ref**"),
            "schema-3 recovery must name the explicit-ref CAS authority"
        );
        assert!(
            !design.contains("carries the message this engine would have written"),
            "the removed subject heuristic must not return as normative design"
        );
    }

    struct Fixture {
        root: PathBuf,
        public: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str, events: Vec<Value>, tasks: Vec<Value>) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "tactus-export-{tag}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let public = rundir::public_dir(&root, RUN_ID);
            fs::create_dir_all(&public).expect("run directory");
            fs::write(
                public.join("plan.normalized.json"),
                serde_json::to_vec(&json!({
                    "source": { "adapter": "frozen", "hash": "frozen-hash" },
                    "tasks": tasks,
                    "artifacts": []
                }))
                .expect("plan json"),
            )
            .expect("write frozen plan");
            let log = events
                .iter()
                .map(|event| serde_json::to_string(event).expect("event json"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            fs::write(public.join("events.jsonl"), log).expect("write event log");
            Self { root, public }
        }

        fn loaded(&self) -> Loaded {
            load(&self.root, "01EXPORT").expect("prefix resolves and export loads")
        }

        fn rows(&self) -> Vec<Row> {
            self.loaded().rows
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn task(id: &str, title: &str) -> Value {
        json!({
            "id": id,
            "kind": "fix",
            "title": title,
            "body": "frozen body",
            "depends_on": ["dep-a", "dep-b"],
            "acceptance": ["one", "two", "three"],
            "path_hints": ["src/exact,a.rs", "tests/\"quoted\".rs"],
            "suggested_tier": "mid",
            "min_tier": "small",
            "artifacts_in": ["input"],
            "artifacts_out": ["output-a", "output-b"]
        })
    }

    fn run_started(tasks: &[&str]) -> Value {
        let chains = tasks
            .iter()
            .map(|task| json!({ "task": task, "tiers": ["small", "mid"], "attempts_per": 2 }))
            .collect::<Vec<_>>();
        json!({
            "ts": "2026-08-01T00:00:00.000Z",
            "event": "run_started",
            "data": {
                "schema": 1,
                "tactus_version": "0.0-old",
                "run_id": RUN_ID,
                "branch": "tactus/run-test",
                "base_sha": "abc",
                "plan_path": "today.md",
                "config_path": "tactus.toml",
                "plan_hash": "frozen-hash",
                "private_dir": "/not/read",
                "gates": [],
                "gates_from_config": false,
                "interaction_mode": "never",
                "chains": chains
            }
        })
    }

    fn attempt_started(task: &str, attempt: u32, ts: &str, legacy: bool) -> Value {
        let mut data = json!({
            "tier": "small",
            "agent": "recorded-agent",
            "model": "recorded/model",
            "pool": "recorded-pool",
            "resume_session": null
        });
        if !legacy {
            data["adapter"] = json!("recorded-adapter");
            data["preflight_cli_version"] = json!("1.2.3");
            data["effort"] = json!("low");
            data["selection_origin"] = json!("auto");
        }
        json!({
            "ts": ts,
            "event": "attempt_started",
            "task": task,
            "attempt": attempt,
            "rung": 0,
            "profile": "small-worker",
            "data": data
        })
    }

    fn attempt_finished(
        task: &str,
        attempt: u32,
        ts: &str,
        failure: Option<FailureKind>,
        with_review: bool,
    ) -> Value {
        let reviews = if with_review {
            vec![json!({
                "pass": "review",
                "agent": "review-agent",
                "adapter": "review-adapter",
                "preflight_cli_version": "9.0",
                "model": "review/model",
                "effort": "high",
                "pool": "review-pool",
                "cost_usd": 0.25,
                "outcome": "passed"
            })]
        } else {
            Vec::new()
        };
        let failure = failure.map(|kind| {
            json!({
                "kind": kind,
                "origin": "worker",
                "reason": format!("recorded {kind:?}")
            })
        });
        json!({
            "ts": ts,
            "event": "attempt_finished",
            "task": task,
            "attempt": attempt,
            "rung": 0,
            "profile": "small-worker",
            "data": {
                "attempt": attempt,
                "tier": "small",
                "model": "recorded/model",
                "pool": "recorded-pool",
                "resumed": false,
                "duration_ms": 1234,
                "cost_usd": 1.5,
                "reviews": reviews,
                "session_id": null,
                "usage": { "input_tokens": 10, "output_tokens": 20 },
                "failure": failure
            }
        })
    }

    fn attempt_interrupted(task: &str, attempt: u32, ts: &str) -> Value {
        let mut event = attempt_finished(task, attempt, ts, Some(FailureKind::Interrupted), false);
        event["event"] = json!("attempt_interrupted");
        event["data"]["duration_ms"] = json!(0);
        event["data"]["cost_usd"] = Value::Null;
        event["data"]["usage"] = Value::Null;
        event
    }

    fn csv_records(text: &str) -> Vec<Vec<String>> {
        let mut records = Vec::new();
        let mut record = Vec::new();
        let mut field = String::new();
        let mut chars = text.chars().peekable();
        let mut quoted = false;
        while let Some(ch) = chars.next() {
            match ch {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = !quoted,
                ',' if !quoted => record.push(std::mem::take(&mut field)),
                '\r' if !quoted && chars.peek() == Some(&'\n') => {
                    chars.next();
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                other => field.push(other),
            }
        }
        assert!(!quoted, "unterminated quoted CSV field");
        assert!(field.is_empty() && record.is_empty(), "missing final CRLF");
        records
    }

    fn snapshot(path: &Path) -> BTreeMap<PathBuf, (u64, std::time::SystemTime)> {
        fn visit(
            root: &Path,
            path: &Path,
            out: &mut BTreeMap<PathBuf, (u64, std::time::SystemTime)>,
        ) {
            for entry in fs::read_dir(path).expect("read snapshot directory") {
                let entry = entry.expect("directory entry");
                let metadata = entry.metadata().expect("metadata");
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .expect("relative path")
                    .to_owned();
                out.insert(
                    relative,
                    (metadata.len(), metadata.modified().expect("modified time")),
                );
                if metadata.is_dir() {
                    visit(root, &entry.path(), out);
                }
            }
        }
        let mut out = BTreeMap::new();
        visit(path, path, &mut out);
        out
    }

    fn load_error(fixture: &Fixture) -> String {
        match load(&fixture.root, RUN_ID) {
            Ok(_) => panic!("invalid fixture exported successfully"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn csv_quotes_rfc_4180_special_characters() {
        for (input, expected) in [
            ("plain", "plain"),
            ("a,b", "\"a,b\""),
            ("a\"b", "\"a\"\"b\""),
            ("a\nb", "\"a\nb\""),
            ("a\rb", "\"a\rb\""),
            ("a\r\nb", "\"a\r\nb\""),
        ] {
            let mut output = Vec::new();
            write_csv_field(input, &mut output).expect("write");
            assert_eq!(String::from_utf8(output).expect("utf8"), expected);
        }
    }

    #[test]
    fn exported_timestamps_use_the_supported_rfc3339_profile() {
        for valid in [
            "1970-01-01T00:00:00Z",
            "2024-02-29T23:59:59.123Z",
            "2026-08-01t12:34:56+05:30",
            "2026-08-01T12:34:56.000-00:00",
        ] {
            assert!(
                is_supported_rfc3339(valid),
                "supported RFC 3339 timestamp: {valid}"
            );
        }
        for rejected in [
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-08-01 00:00:00Z",
            "2026-08-01T24:00:00Z",
            "2026-08-01T00:00:00",
            "2026-08-01T00:00:00.Z",
            // `:60` is not accepted blindly on a leap-year date, and even a
            // historical leap second is outside the writer's supported subset.
            "2024-02-29T23:59:60.123Z",
            "2016-12-31T23:59:60Z",
        ] {
            assert!(
                !is_supported_rfc3339(rejected),
                "unsupported timestamp: {rejected}"
            );
        }

        let fixture = Fixture::new(
            "bad-timestamp",
            vec![
                run_started(&["task"]),
                attempt_started("task", 1, "not-a-timestamp", false),
            ],
            vec![task("task", "task")],
        );
        let error = load_error(&fixture);
        assert!(error.contains(RUN_ID), "run identity: {error}");
        assert!(error.contains("task `task`, attempt 1, rung 0"), "{error}");
        assert!(error.contains("not RFC 3339"), "{error}");
    }

    #[test]
    fn every_failure_kind_has_the_decided_projection() {
        let cases = [
            (FailureKind::GateFailed, "capability", "gate"),
            (FailureKind::ReviewFailed, "capability", "review"),
            (FailureKind::AgentError, "provider", "none"),
            (FailureKind::RateLimited, "provider", "none"),
            (FailureKind::ReviewUnavailable, "provider", "none"),
            (FailureKind::ReviewInputTooLarge, "policy", "review"),
            (FailureKind::ReviewInputOpaque, "policy", "review"),
            (FailureKind::Timeout, "infrastructure", "none"),
            (FailureKind::Interrupted, "infrastructure", "none"),
            (FailureKind::NoChain, "policy", "none"),
            (FailureKind::EmptyDiff, "policy", "engine"),
            (FailureKind::TestProvenance, "policy", "engine"),
            (FailureKind::NeedsHuman, "policy", "none"),
            (FailureKind::Declined, "policy", "none"),
        ];
        for (kind, category, evidence) in cases {
            assert_eq!(failure_projection(kind), (category, evidence));
        }
    }

    #[test]
    fn both_formats_preserve_start_order_reviews_and_frozen_features() {
        let fixture = Fixture::new(
            "formats",
            vec![
                run_started(&["first", "second"]),
                attempt_started("first", 1, "2026-08-01T00:00:01.000Z", false),
                attempt_started("second", 1, "2026-08-01T00:00:02.000Z", false),
                attempt_finished("second", 1, "2026-08-01T00:00:03.000Z", None, false),
                attempt_finished("first", 1, "2026-08-01T00:00:04.000Z", None, true),
            ],
            vec![task("first", "first, \"quoted\""), task("second", "second")],
        );
        // These current inputs are traps: the exporter must never consult them.
        fs::write(
            fixture.root.join("today.md"),
            "# today\n<!-- tactus: kind=docs tier=frontier paths=WRONG -->",
        )
        .expect("source-plan trap");
        fs::write(
            fixture.root.join("tactus.toml"),
            "[routing]\nfix = { chain = [\"frontier\"], attempts_per = 99 }\n",
        )
        .expect("config trap");
        let before = snapshot(&fixture.public);
        let rows = fixture.rows();
        assert_eq!(snapshot(&fixture.public), before, "export changed the run");

        let mut jsonl = Vec::new();
        write(&rows, Format::Jsonl, &mut jsonl).expect("jsonl");
        let values = String::from_utf8(jsonl)
            .expect("utf8")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("valid JSONL row"))
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["task_id"], "first");
        assert_eq!(values[1]["task_id"], "second");
        assert_eq!(values[0]["reviews"][0]["adapter_id"], "review-adapter");
        assert_eq!(values[1]["reviews"], json!([]));
        assert_eq!(
            values[0]["task_features"],
            json!({
                "kind": "fix", "suggested_tier": "mid", "minimum_tier": "small",
                "dependency_count": 2, "acceptance_count": 3,
                "path_hints": ["src/exact,a.rs", "tests/\"quoted\".rs"],
                "artifact_input_count": 1, "artifact_output_count": 2
            })
        );
        assert!(values[0].get("diff_size").is_none());
        assert!(values[0]["task_features"].get("diff_size").is_none());
        assert!(!values[0].to_string().contains("WRONG"));
        let top_level_keys = values[0]
            .as_object()
            .expect("row object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            top_level_keys,
            [
                "adapter_cli_version",
                "adapter_id",
                "attempt",
                "attempt_finished_at",
                "attempt_started_at",
                "chain",
                "cost_usd",
                "duration_ms",
                "effort",
                "failure_category",
                "failure_kind",
                "failure_origin",
                "failure_reason",
                "model",
                "outcome",
                "pool",
                "reviews",
                "run_id",
                "run_started_at",
                "rung",
                "schema_version",
                "selected_tier",
                "selection_origin",
                "session_resumed",
                "tactus_version",
                "task_features",
                "task_id",
                "task_title",
                "usage",
                "work_evidence",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            values[0]["usage"]
                .as_object()
                .expect("usage object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
                "input_tokens",
                "num_turns",
                "output_tokens",
                "reasoning_output_tokens",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            values[0]["task_features"]
                .as_object()
                .expect("task-features object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "acceptance_count",
                "artifact_input_count",
                "artifact_output_count",
                "dependency_count",
                "kind",
                "minimum_tier",
                "path_hints",
                "suggested_tier",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            values[0]["chain"]
                .as_object()
                .expect("chain object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["attempts_per", "tiers"].into_iter().collect()
        );
        assert_eq!(
            values[0]["reviews"][0]
                .as_object()
                .expect("review object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "adapter_cli_version",
                "adapter_id",
                "cost_usd",
                "effort",
                "model",
                "outcome",
                "pass",
                "pool",
            ]
            .into_iter()
            .collect()
        );

        let mut csv = Vec::new();
        write(&rows, Format::Csv, &mut csv).expect("csv");
        let csv = String::from_utf8(csv).expect("utf8 csv");
        assert!(csv.starts_with(CSV_HEADER));
        let records = csv_records(&csv);
        assert_eq!(records.len(), 3, "header plus two rows");
        assert!(
            records.iter().all(|record| record.len() == 43),
            "schema 2 CSV records must retain exactly 43 columns: {records:?}"
        );
        assert!(csv.contains("\"first, \"\"quoted\"\"\""));
        assert!(csv.contains("src/exact,a.rs"));
        assert!(csv.contains("quoted"));
        assert!(csv.contains("review-adapter"));
    }

    #[test]
    fn dangling_and_legacy_attempts_stay_unknown_and_interrupted() {
        let fixture = Fixture::new(
            "dangling",
            vec![
                run_started(&["old"]),
                attempt_started("old", 1, "2026-08-01T00:00:01.000Z", true),
            ],
            vec![task("old", "old task")],
        );
        fs::write(
            fixture.root.join("tactus.toml"),
            "[pins.small]\nagent = \"today-agent\"\nmodel = \"today-model\"\n",
        )
        .expect("config trap");
        let rows = fixture.rows();
        let value = serde_json::to_value(&rows[0]).expect("row value");
        assert_eq!(value["attempt_finished_at"], Value::Null);
        assert_eq!(value["duration_ms"], Value::Null);
        assert_eq!(value["cost_usd"], Value::Null);
        assert_eq!(value["usage"], Value::Null);
        assert_eq!(value["outcome"], "interrupted");
        assert_eq!(value["failure_kind"], "interrupted");
        assert_eq!(value["failure_origin"], "worker");
        assert_eq!(value["failure_category"], "infrastructure");
        assert_eq!(value["work_evidence"], "none");
        assert_eq!(value["failure_reason"], Value::Null);
        assert_eq!(value["selection_origin"], "unknown");
        assert_eq!(value["adapter_id"], "recorded-agent");
        assert_eq!(value["adapter_cli_version"], Value::Null);
        assert_ne!(value["adapter_id"], "today-agent");
    }

    #[test]
    fn xhigh_worker_and_max_review_effort_are_preserved_in_schema_two() {
        let mut start = attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false);
        start["data"]["effort"] = json!("xhigh");
        let mut finish = attempt_finished("task", 1, "2026-08-01T00:00:02.000Z", None, true);
        finish["data"]["reviews"][0]["effort"] = json!("max");
        let fixture = Fixture::new(
            "role-effort",
            vec![run_started(&["task"]), start, finish],
            vec![task("task", "role effort")],
        );

        let rows = fixture.rows();
        let value = serde_json::to_value(&rows[0]).expect("row value");
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["effort"], "xhigh");
        assert_eq!(value["reviews"][0]["effort"], "max");
        let mut csv = Vec::new();
        write(&rows, Format::Csv, &mut csv).expect("csv");
        let csv = String::from_utf8(csv).expect("utf8 csv");
        assert!(csv.contains("xhigh"), "worker effort is represented: {csv}");
        assert!(csv.contains("max"), "review effort is represented: {csv}");
    }

    #[test]
    fn a_live_run_is_refused_actionably() {
        let fixture = Fixture::new(
            "live",
            vec![run_started(&["task"])],
            vec![task("task", "task")],
        );
        let _lock = rundir::RunLock::acquire(&fixture.public).expect("hold live lock");
        let error = match load(&fixture.root, RUN_ID) {
            Ok(_) => panic!("live export was not refused"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("is live"));
        assert!(message.contains("wait for it to finish or stop it"));
    }

    #[test]
    fn snapshot_protocol_catches_a_resume_and_a_changed_event_file() {
        let mut probes = [false, true].into_iter();
        let error = begin_snapshot_with(
            RUN_ID,
            || probes.next().expect("pre and post probes"),
            || Ok(b"stable-so-far".to_vec()),
        )
        .expect_err("a run that resumes during the first read is live");
        assert!(error.to_string().contains("is live"));

        let error = finish_snapshot_with(
            RUN_ID,
            b"before",
            || false,
            || Ok(b"before\nnew attempt_started".to_vec()),
        )
        .expect_err("an append after the post-read probe moves the snapshot");
        assert!(error.to_string().contains("changed while"));

        assert_eq!(
            begin_snapshot_with(RUN_ID, || false, || Ok(b"stable".to_vec()))
                .expect("stable first read"),
            b"stable"
        );
        finish_snapshot_with(RUN_ID, b"stable", || false, || Ok(b"stable".to_vec()))
            .expect("unchanged closing read");
    }

    #[test]
    fn a_torn_tail_is_exported_with_a_separate_warning() {
        let fixture = Fixture::new(
            "torn-tail",
            vec![
                run_started(&["task"]),
                attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false),
            ],
            vec![task("task", "task")],
        );
        let path = fixture.public.join("events.jsonl");
        let mut log = fs::read(&path).expect("read fixture log");
        log.extend_from_slice(b"{\"ts\":\"2026-08-01T00:00");
        log.extend_from_slice(&[0xf0, 0x9f]);
        fs::write(&path, log).expect("write torn tail");

        let loaded = fixture.loaded();
        assert_eq!(loaded.rows.len(), 1);
        assert_eq!(loaded.rows[0].outcome, "interrupted");
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("incomplete final line"));
    }

    #[test]
    fn a_complete_semantically_invalid_final_event_is_rejected() {
        let mut invalid_start = attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false);
        invalid_start["data"]["selection_origin"] = json!("unknown");
        let fixture = Fixture::new(
            "semantic-tail",
            vec![run_started(&["task"]), invalid_start],
            vec![task("task", "task")],
        );

        let error = load_error(&fixture);
        assert!(
            error.contains("line 2"),
            "invalid final record is committed: {error}"
        );
        assert!(
            error.contains("unknown variant"),
            "domain error is preserved: {error}"
        );
    }

    #[test]
    fn a_future_event_schema_is_rejected_before_projection() {
        let mut started = run_started(&["task"]);
        started["data"]["schema"] = json!(events::SCHEMA_VERSION + 1);
        let fixture = Fixture::new("future-schema", vec![started], vec![task("task", "task")]);
        let error = load_error(&fixture);
        assert!(error.contains("written by a newer tactus"), "{error}");
        assert!(error.contains("Upgrade rather than"), "{error}");
    }

    #[test]
    fn invalid_recorded_invariants_are_refused() {
        let hash = Fixture::new(
            "bad-hash",
            vec![run_started(&["task"])],
            vec![task("task", "task")],
        );
        let plan_path = hash.public.join("plan.normalized.json");
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).expect("read plan")).expect("plan json");
        plan["source"]["hash"] = json!("tampered");
        fs::write(&plan_path, serde_json::to_vec(&plan).expect("plan json"))
            .expect("write tampered plan");
        assert!(load_error(&hash).contains("frozen plan hash"));

        let zero = Fixture::new(
            "zero-attempt",
            vec![
                run_started(&["task"]),
                attempt_started("task", 0, "2026-08-01T00:00:01.000Z", false),
            ],
            vec![task("task", "task")],
        );
        assert!(load_error(&zero).contains("must be positive"));

        let mut wrong_tier = attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false);
        wrong_tier["data"]["tier"] = json!("mid");
        let tier = Fixture::new(
            "wrong-tier",
            vec![run_started(&["task"]), wrong_tier],
            vec![task("task", "task")],
        );
        assert!(load_error(&tier).contains("does not match recorded rung tier"));

        let mut out_of_range = attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false);
        out_of_range["rung"] = json!(9);
        let rung = Fixture::new(
            "bad-rung",
            vec![run_started(&["task"]), out_of_range],
            vec![task("task", "task")],
        );
        assert!(load_error(&rung).contains("outside the recorded chain"));

        let mut bad_review = attempt_finished("task", 1, "2026-08-01T00:00:02.000Z", None, true);
        bad_review["data"]["reviews"][0]["cost_usd"] = json!(-0.25);
        let cost = Fixture::new(
            "bad-review-cost",
            vec![
                run_started(&["task"]),
                attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false),
                bad_review,
            ],
            vec![task("task", "task")],
        );
        assert!(load_error(&cost).contains("review pass 0 cost"));

        let mut missing_chain_start = run_started(&["attempted", "idle"]);
        missing_chain_start["data"]["chains"]
            .as_array_mut()
            .expect("chains")
            .pop();
        let missing_chain = Fixture::new(
            "missing-idle-chain",
            vec![
                missing_chain_start,
                attempt_started("attempted", 1, "2026-08-01T00:00:01.000Z", false),
            ],
            vec![task("attempted", "attempted"), task("idle", "idle")],
        );
        assert!(load_error(&missing_chain).contains("`idle` has no run-start chain"));

        let mut orphan_start = run_started(&["task"]);
        orphan_start["data"]["chains"]
            .as_array_mut()
            .expect("chains")
            .push(json!({ "task": "ghost", "tiers": ["small"], "attempts_per": 1 }));
        let orphan = Fixture::new(
            "orphan-chain",
            vec![orphan_start],
            vec![task("task", "task")],
        );
        assert!(load_error(&orphan).contains("`ghost` is absent from the frozen plan"));

        for (tag, field, value, expected) in [
            ("empty-chain", "tiers", json!([]), "has no tiers"),
            ("zero-chain", "attempts_per", json!(0), "has attempts_per 0"),
        ] {
            let mut start = run_started(&["task"]);
            start["data"]["chains"][0][field] = value;
            let fixture = Fixture::new(tag, vec![start], vec![task("task", "task")]);
            assert!(load_error(&fixture).contains(expected));
        }
    }

    #[test]
    fn settlement_order_kind_and_duplicated_identity_are_validated() {
        let finish = attempt_finished("task", 1, "2026-08-01T00:00:01.000Z", None, false);
        let before = Fixture::new(
            "settlement-before-start",
            vec![
                run_started(&["task"]),
                finish,
                attempt_started("task", 1, "2026-08-01T00:00:02.000Z", false),
            ],
            vec![task("task", "task")],
        );
        assert!(load_error(&before).contains("appears before its start"));

        let mut fake_interruption =
            attempt_finished("task", 1, "2026-08-01T00:00:02.000Z", None, false);
        fake_interruption["event"] = json!("attempt_interrupted");
        let missing_kind = Fixture::new(
            "interrupted-without-kind",
            vec![
                run_started(&["task"]),
                attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false),
                fake_interruption,
            ],
            vec![task("task", "task")],
        );
        assert!(load_error(&missing_kind).contains("lacks an interrupted failure"));

        let wrong_event = Fixture::new(
            "finished-as-interrupted",
            vec![
                run_started(&["task"]),
                attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false),
                attempt_finished(
                    "task",
                    1,
                    "2026-08-01T00:00:02.000Z",
                    Some(FailureKind::Interrupted),
                    false,
                ),
            ],
            vec![task("task", "task")],
        );
        assert!(load_error(&wrong_event).contains("carries interruption semantics"));

        for (tag, field, value) in [
            ("settlement-model", "model", json!("different/model")),
            ("settlement-pool", "pool", json!("different-pool")),
        ] {
            let mut finish = attempt_finished("task", 1, "2026-08-01T00:00:02.000Z", None, false);
            finish["data"][field] = value;
            let fixture = Fixture::new(
                tag,
                vec![
                    run_started(&["task"]),
                    attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false),
                    finish,
                ],
                vec![task("task", "task")],
            );
            assert!(load_error(&fixture).contains("mismatched settlement identity"));
        }
    }

    #[test]
    fn atomic_policy_parking_is_bound_to_its_review_refusal_and_task() {
        let parked_finish = || {
            let mut finish = attempt_finished(
                "task",
                1,
                "2026-08-01T00:00:02.000Z",
                Some(FailureKind::ReviewInputTooLarge),
                false,
            );
            finish["data"]["failure"]["origin"] = json!("reviewer");
            finish["parking"] = json!({
                "question": {
                    "id": "q-01ATOMIC",
                    "kind": "unblock",
                    "affected_tasks": ["task"],
                    "context": "split the exact diff",
                    "options": ["retry with a smaller diff"]
                },
                "refund_attempt": false
            });
            finish
        };
        let events = |finish| {
            vec![
                run_started(&["task"]),
                attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false),
                finish,
            ]
        };

        let valid = Fixture::new(
            "valid-atomic-parking",
            events(parked_finish()),
            vec![task("task", "task")],
        );
        assert_eq!(valid.rows().len(), 1);

        let mut wrong_task = parked_finish();
        wrong_task["parking"]["question"]["affected_tasks"] = json!(["other"]);
        let invalid = Fixture::new(
            "wrong-atomic-parking-task",
            events(wrong_task),
            vec![task("task", "task")],
        );
        assert!(load_error(&invalid).contains("invalid atomic policy parking"));
    }

    #[test]
    fn atomic_attempt_transitions_are_bound_to_their_failure() {
        let events = |finish| {
            vec![
                run_started(&["task"]),
                attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false),
                finish,
            ]
        };
        let mut retry = attempt_finished(
            "task",
            1,
            "2026-08-01T00:00:02.000Z",
            Some(FailureKind::GateFailed),
            false,
        );
        retry["transition"] = json!({
            "action": "retry",
            "data": {
                "resume": false,
                "tier": "small",
                "summary": "gate failed",
                "detail": null
            }
        });
        let valid = Fixture::new(
            "valid-atomic-transition",
            events(retry),
            vec![task("task", "task")],
        );
        assert_eq!(valid.rows().len(), 1);

        let mut invalid = attempt_finished(
            "task",
            1,
            "2026-08-01T00:00:02.000Z",
            Some(FailureKind::GateFailed),
            false,
        );
        invalid["transition"] = json!({
            "action": "defer",
            "data": { "reason": "not an outage", "defers": 1 }
        });
        let invalid = Fixture::new(
            "invalid-atomic-transition",
            events(invalid),
            vec![task("task", "task")],
        );
        assert!(load_error(&invalid).contains("invalid atomic attempt transition"));
    }

    #[test]
    fn duplicate_and_orphan_attempt_events_are_refused() {
        let start = attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false);
        let duplicate_start = Fixture::new(
            "duplicate-start",
            vec![run_started(&["task"]), start.clone(), start],
            vec![task("task", "task")],
        );
        assert!(
            load_error(&duplicate_start).contains("duplicate attempt start"),
            "a repeated key is ambiguous rather than a second logical attempt"
        );

        let start = attempt_started("task", 1, "2026-08-01T00:00:01.000Z", false);
        let finish = attempt_finished("task", 1, "2026-08-01T00:00:02.000Z", None, false);
        let duplicate_settlement = Fixture::new(
            "duplicate-settlement",
            vec![run_started(&["task"]), start, finish.clone(), finish],
            vec![task("task", "task")],
        );
        assert!(
            load_error(&duplicate_settlement).contains("duplicate settlement"),
            "one start cannot have two authorities for its outcome"
        );

        let orphan = Fixture::new(
            "orphan-settlement",
            vec![
                run_started(&["task"]),
                attempt_finished("task", 1, "2026-08-01T00:00:02.000Z", None, false),
            ],
            vec![task("task", "task")],
        );
        assert!(
            load_error(&orphan).contains("settlement without a start"),
            "a finish-only record has no pre-spawn routing authority"
        );
    }

    #[test]
    fn every_failure_kind_reaches_an_emitted_row() {
        let cases = [
            (FailureKind::GateFailed, "capability", "gate"),
            (FailureKind::ReviewFailed, "capability", "review"),
            (FailureKind::AgentError, "provider", "none"),
            (FailureKind::RateLimited, "provider", "none"),
            (FailureKind::ReviewUnavailable, "provider", "none"),
            (FailureKind::ReviewInputTooLarge, "policy", "review"),
            (FailureKind::ReviewInputOpaque, "policy", "review"),
            (FailureKind::Timeout, "infrastructure", "none"),
            (FailureKind::Interrupted, "infrastructure", "none"),
            (FailureKind::NoChain, "policy", "none"),
            (FailureKind::EmptyDiff, "policy", "engine"),
            (FailureKind::TestProvenance, "policy", "engine"),
            (FailureKind::NeedsHuman, "policy", "none"),
            (FailureKind::Declined, "policy", "none"),
        ];
        let ids = (0..cases.len()).map(|index| format!("f{index}"));
        let mut events = vec![run_started(
            &ids.clone()
                .map(|id| Box::leak(id.into_boxed_str()) as &str)
                .collect::<Vec<_>>(),
        )];
        let ids = (0..cases.len())
            .map(|index| format!("f{index}"))
            .collect::<Vec<_>>();
        for (index, (id, (kind, _, _))) in ids.iter().zip(cases.iter()).enumerate() {
            events.push(attempt_started(
                id,
                1,
                &format!("2026-08-01T00:01:{index:02}.000Z"),
                false,
            ));
            let ts = format!("2026-08-01T00:02:{index:02}.000Z");
            events.push(if *kind == FailureKind::Interrupted {
                attempt_interrupted(id, 1, &ts)
            } else {
                attempt_finished(id, 1, &ts, Some(*kind), false)
            });
        }
        let fixture = Fixture::new(
            "failures",
            events,
            ids.iter().map(|id| task(id, id)).collect(),
        );
        let rows = fixture.rows();
        let mut jsonl = Vec::new();
        write(&rows, Format::Jsonl, &mut jsonl).expect("jsonl");
        let values = String::from_utf8(jsonl)
            .expect("utf8")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("row"))
            .collect::<Vec<_>>();
        assert_eq!(values.len(), cases.len());
        for (value, (kind, category, evidence)) in values.iter().zip(cases) {
            assert_eq!(
                value["failure_kind"],
                serde_json::to_value(kind).expect("kind")
            );
            assert_eq!(value["failure_category"], category);
            assert_eq!(value["work_evidence"], evidence);
            assert_eq!(
                value["outcome"],
                if kind == FailureKind::Interrupted {
                    "interrupted"
                } else {
                    "failed"
                }
            );
        }
    }
}
