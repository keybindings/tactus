//! Sequential execution engine (DESIGN.md §14) and the verification ladder it
//! drives (§11.4, §12, §19).
//!
//! Pre-flight, run branch, then a scheduler that drains the task graph one
//! attempt at a time: agent run → engine-captured diff → gates with evidence
//! axes (§11.1) → read-only review with a structured verdict (§11.2) →
//! engine-owned commit. A failed attempt does not end the task — it feeds the
//! failure back to the same rung (resuming the session where the adapter
//! supports it), then escalates a rung on a fresh session with the accumulated
//! feedback, and finally asks a human, who is the top rung.
//!
//! The scheduler's defining property is invariant 6: **a question parks only
//! the tasks it affects.** Everything else keeps draining, and the run
//! hard-blocks only when the runnable frontier is empty and everything left is
//! waiting on an answer. That is the moment — and the only moment — a human is
//! asked.
//!
//! Every transition here is an event (invariant 4). The engine never mutates
//! run state directly: it appends to `events.jsonl` and folds the event back in
//! through [`crate::events::RunState::apply`], the same function `resume` and
//! `status` use to rebuild state from the file. A live run and a replay of its
//! own log therefore cannot disagree — there is no second path for them to
//! disagree along. `report.json` is written from that state as a projection for
//! humans; nothing ever reads it back.

mod attempt;
mod coordinator;
mod options;
mod preflight;
mod report;
mod resume;

use crate::agent::proc::NoHooks;
use crate::error::TactusError;
use crate::runner::Runner;
use crate::runner::host::{Contained, HostRunner, contain_write_command};

pub use options::{
    DEFAULT_ATTEMPT_TIMEOUT, DEFAULT_MAX_DEFERS, Harness, ResumeOptions, RunOptions,
};
pub use report::{PoolDrainRow, RunOutcome, RunReport, TaskReport, TaskRunStatus, topo_order};

// Re-exported so `engine::AdapterSource` still resolves for callers that
// reasonably think of it as the engine's seam.
pub use crate::agent::{AdapterSource, BuiltinAdapters};
pub use crate::events::{AttemptRecord, FailureRecord};
pub use crate::ladder::{AttemptFailure, FailureKind, FailureOrigin};

pub fn run(opts: &RunOptions) -> Result<RunReport, TactusError> {
    run_with(opts, &BuiltinAdapters)
}

pub fn run_with(opts: &RunOptions, adapters: &dyn AdapterSource) -> Result<RunReport, TactusError> {
    run_harness(opts, &Harness::new(adapters))
}

pub fn run_harness(opts: &RunOptions, harness: &Harness<'_>) -> Result<RunReport, TactusError> {
    run_harness_on(opts, harness, &HostRunner::new())
}

/// The same run, on an explicit [`Runner`].
///
/// The boundary is a parameter rather than a `Harness` field because it is not
/// an injectable stand-in for a collaborator: it is where every process of
/// this run executes, and DESIGN.md:612 makes it a configured choice —
/// "`[runner]` config selects `host` or `container`". PR6 passes the container
/// runner here; PR4 passes [`HostRunner`] and nothing else.
///
/// **Private, and it has to be.** `decisions.phase_zero_modules.visibility` is
/// "pub(super) only where a sibling or tests reference an item; **no new pub
/// or pub(crate)**; public paths unchanged", and the module's own entry
/// enumerates the facade without it. The reason is not bookkeeping: this
/// function drives the *schema-1..3* coordinator, and `invariants[22]` is
/// "schema-1..3 runs are host-only and no run changes its boundary or image
/// between epochs". A `pub` here lets a downstream crate execute a legacy run
/// off-host, with no `RunnerPolicy` to record it and no refusal — and lets the
/// same run come back on `HostRunner` at the next resume. Private is what
/// makes that unreachable rather than merely undocumented.
///
/// # Errors
///
/// Whatever the run refuses or fails on.
fn run_harness_on(
    opts: &RunOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
) -> Result<RunReport, TactusError> {
    // `NoHooks` is what production passes the process funnel, and the
    // containment step is threaded the same way: the observer exists so the
    // step has a drivable failure path (`runner::host::contain_write_command`),
    // and production arms nothing.
    run_contained(opts, harness, runner, || {
        contain_write_command(&mut NoHooks)
    })
}

/// The same run, over the containment step it must perform **first**.
///
/// Every public entry point above reaches the coordinator through here, so
/// this one call is what makes `run`, `run_with` and `run_harness` write
/// commands in INV-18's sense: "on Windows every host child is a member of the
/// coordinator's ambient kill-on-close Job Object from creation", and
/// `expected_failures_refusals[1]`, "ambient job cannot be created or joined
/// (Windows) → write command refuses at startup with a diagnostic". A
/// downstream crate calling `engine::run_with` is a coordinator exactly as the
/// CLI is; before this it established nothing, so a kill between
/// `CreateProcessW` and private-job assignment left the suspended stub alive
/// and a real ambient failure could not produce the required refusal.
///
/// `contain` is a parameter for the same reason `src/main.rs`'s `dispatch`
/// takes its join: no machine here can make the real one fail, and the
/// *ordering* between containment and the first thing the coordinator does is
/// then a testable fact rather than a written-down one
/// (`a_facade_run_refuses_before_any_effect_when_containment_fails`). It is
/// not a hole in the guarantee: `Contained` has a private field, so the only
/// closure that can return one is one that establishes containment.
fn run_contained(
    opts: &RunOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
    contain: impl FnOnce() -> Result<Contained, TactusError>,
) -> Result<RunReport, TactusError> {
    let contained = contain()?;
    coordinator::run_harness_inner_on(opts, harness, runner, &contained).map(|(report, _)| report)
}

pub fn resume(opts: &ResumeOptions) -> Result<RunReport, TactusError> {
    resume_with(opts, &BuiltinAdapters)
}

pub fn resume_with(
    opts: &ResumeOptions,
    adapters: &dyn AdapterSource,
) -> Result<RunReport, TactusError> {
    resume_harness(opts, &Harness::new(adapters))
}

/// §15: replay, verify the run branch still matches the record, re-probe, and
/// continue — parked questions intact.
///
/// Every refusal below exists because continuing would produce a *wrong*
/// result rather than merely an awkward one, and each says which of the four
/// things moved — the run, the plan, the config, or the branch — because that
/// is what decides what the operator does next.
///
/// Note what is *not* a refusal: gates that resolve differently today. Those
/// are taken from the record and run, so there is nothing to refuse — the
/// difference is a warning about an edit that does not apply here. A refusal is
/// for the cases where continuing would be wrong, and continuing under the
/// gates this run has been using all along is exactly right.
pub fn resume_harness(
    opts: &ResumeOptions,
    harness: &Harness<'_>,
) -> Result<RunReport, TactusError> {
    resume_harness_on(opts, harness, &HostRunner::new())
}

/// The same resume, on an explicit [`Runner`]. See [`run_harness_on`],
/// including why this is private.
///
/// # Errors
///
/// Whatever the resume refuses or fails on.
fn resume_harness_on(
    opts: &ResumeOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
) -> Result<RunReport, TactusError> {
    resume_contained(opts, harness, runner, || {
        contain_write_command(&mut NoHooks)
    })
}

/// The same resume, over the containment step it must perform first. See
/// [`run_contained`]: a resume drives a run, so it is a write command, and the
/// three public resume entry points reach the coordinator only through here.
fn resume_contained(
    opts: &ResumeOptions,
    harness: &Harness<'_>,
    runner: &dyn Runner,
    contain: impl FnOnce() -> Result<Contained, TactusError>,
) -> Result<RunReport, TactusError> {
    let contained = contain()?;
    resume::resume_harness_inner_on(opts, harness, runner, &contained).map(|(report, _)| report)
}

#[cfg(test)]
mod tests;
