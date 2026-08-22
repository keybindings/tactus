use std::path::PathBuf;
use std::time::Duration;

use crate::agent::AdapterSource;
#[cfg(test)]
use crate::error::TactusError;
use crate::interaction::{self, AnswerSource, InteractionMode, Sleeper};
use crate::rundir::RunPaths;
#[cfg(test)]
use crate::workspace::Workspace;

/// §14: per-attempt wall clock, default 30 minutes.
pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How many rate limits (or reviewer outages) one task rides out before the
/// pool counts as down and a human is asked instead.
///
/// Step 10 gave the capacity engine reset times — [`crate::capacity`] carries
/// them on an estimate, and `pool_exhausted` records one whenever a signal
/// includes it — so the obvious question is why this bound still exists. Two
/// reasons, both current: neither CLI actually reports a machine-readable reset
/// time today, so the field is almost always `None`; and §13 ships the capacity
/// engine read-only in v0.1, so nothing routes on a reset even when there is
/// one. Waiting for a reset instead of counting deferrals is capacity-*driven*
/// behaviour, and it arrives with the rest of it in v0.2. Until then this is
/// what keeps an exhausted pool from deferring forever.
pub const DEFAULT_MAX_DEFERS: u32 = 3;

#[cfg(test)]
pub(super) type AfterCandidateCapture =
    fn(&Workspace, &crate::workspace::CapturedCandidate) -> Result<(), TactusError>;

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub plan_path: PathBuf,
    pub config_path: Option<PathBuf>,
    pub pools_path: Option<PathBuf>,
    /// Repo the run executes in (agents run at its root — §14).
    pub repo_root: PathBuf,
    pub attempt_timeout: Duration,
    /// CLI override for `[interaction] mode`; `None` takes the config's.
    pub interaction: Option<InteractionMode>,
    /// First wait after a rate-limited attempt, doubling per consecutive
    /// round of nothing-but-deferred-work.
    pub defer_backoff: Duration,
    pub max_defers: u32,
    /// Where the agent-authored half of the run directory goes (§15 split).
    /// `None` takes `~/.tactus`; tests point it at a scratch directory so they
    /// never touch the real one.
    pub private_root: Option<PathBuf>,
    /// Override `[interaction] wait_on_block_secs` — how long a detached
    /// interactive run waits at a hard block. `None` takes the config's.
    pub wait_on_block: Option<Duration>,
    /// `--budget <usd>`, overriding `[budgets] run_usd` (§17).
    pub budget_usd: Option<f64>,
    /// Deterministic test seam for changing the mutable index immediately
    /// after the engine has frozen its candidate object identities.
    #[cfg(test)]
    pub(super) after_candidate_capture: Option<AfterCandidateCapture>,
    /// The observer the live run's **legacy** append funnel is driven through.
    ///
    /// `None` is production and means [`crate::events::log::NoEventHooks`],
    /// which is what `EventLog::append` uses anyway. It is here so a fixture can
    /// make a **live `Run`**'s append fail (`PR5-CONF-010`, `PR5-CONF-011`);
    /// nothing else in the tree can, and both surviving mutations were on the
    /// path that failure takes.
    #[cfg(test)]
    pub(super) log_hooks: Option<fn() -> Box<dyn crate::events::log::EventHooks>>,
}

impl RunOptions {
    /// Everything but the paths at its documented default.
    pub fn new(plan_path: PathBuf, repo_root: PathBuf) -> Self {
        Self {
            plan_path,
            config_path: None,
            pools_path: None,
            repo_root,
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
            interaction: None,
            defer_backoff: interaction::DEFAULT_DEFER_BACKOFF,
            max_defers: DEFAULT_MAX_DEFERS,
            private_root: None,
            wait_on_block: None,
            budget_usd: None,
            #[cfg(test)]
            after_candidate_capture: None,
            #[cfg(test)]
            log_hooks: None,
        }
    }

    pub(super) fn paths(&self, run_id: &str) -> RunPaths {
        match &self.private_root {
            Some(root) => RunPaths::with_private_root(&self.repo_root, run_id, root),
            None => RunPaths::new(&self.repo_root, run_id),
        }
    }
}

/// Injectable collaborators. `None` means "use the real one", chosen from
/// config where the config has a say.
pub struct Harness<'a> {
    pub adapters: &'a dyn AdapterSource,
    /// `None` derives the channel from `[interaction] mode` (§12).
    pub answers: Option<&'a dyn AnswerSource>,
    /// `None` really sleeps.
    pub sleeper: Option<&'a dyn Sleeper>,
}

impl<'a> Harness<'a> {
    pub fn new(adapters: &'a dyn AdapterSource) -> Self {
        Self {
            adapters,
            answers: None,
            sleeper: None,
        }
    }
}

/// What to continue, and what may be overridden while continuing it.
#[derive(Debug, Clone)]
pub struct ResumeOptions {
    /// Run id, or any unambiguous prefix of one.
    pub run_id: String,
    pub repo_root: PathBuf,
    /// `None` takes the config the run recorded.
    pub config_path: Option<PathBuf>,
    pub pools_path: Option<PathBuf>,
    pub interaction: Option<InteractionMode>,
    pub attempt_timeout: Duration,
    pub defer_backoff: Duration,
    pub max_defers: u32,
    pub private_root: Option<PathBuf>,
    pub wait_on_block: Option<Duration>,
    /// `--budget <usd>` (§17), overriding `[budgets] run_usd` for this resume.
    ///
    /// Budgets are **re-derived from today's config and flags**, unlike the
    /// three things a resume takes from the run's own record: the plan (frozen,
    /// and refused on a hash mismatch), the resolved chains (refused, because a
    /// recorded rung is an index into one), and the gates and reviewers (taken
    /// and used, because they are what "this code was verified" means). Those
    /// protect a run's *identity*. A budget is not identity — it is an
    /// operator's ceiling on their own spending, and re-reading it is precisely
    /// what makes a budget stop recoverable in one command instead of a dead
    /// run and a new branch.
    pub budget_usd: Option<f64>,
}

impl ResumeOptions {
    pub fn new(run_id: String, repo_root: PathBuf) -> Self {
        Self {
            run_id,
            repo_root,
            config_path: None,
            pools_path: None,
            interaction: None,
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
            defer_backoff: interaction::DEFAULT_DEFER_BACKOFF,
            max_defers: DEFAULT_MAX_DEFERS,
            private_root: None,
            wait_on_block: None,
            budget_usd: None,
        }
    }
}
