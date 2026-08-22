//! The capacity engine (DESIGN.md §13) — **read-only in v0.1**.
//!
//! Three things live here: the pool types `~/.tactus/pools.toml` parses into,
//! the estimator that turns observations into a per-pool remaining figure, and
//! the fold that collects those observations from a run's event log.
//!
//! §13's sequencing is the reason nothing routes on any of it yet: v0.1 ships
//! the estimator so `tactus capacity` and the dry-run preview can show what each
//! strategy *would* do, and v0.2 wires it into the binder once the estimates
//! have been watched for a while. So `pool_for` fills `WorkerProfile.pool` for
//! **attribution only** — the binder still picks models from the catalog and
//! pins, exactly as it did before this module existed.
//!
//! The estimator is a pure function over plain values ([`estimate`]), so every
//! rule in §13 is exercisable with no CLI installed and no file on disk. Only
//! collection touches the world, and even that is a fold over events someone
//! else read.
//!
//! Three properties hold by construction and are pinned by tests:
//!
//! 1. **Never optimistic.** No observation means [`Remaining::Unknown`], never
//!    "full". A pool nobody has measured is not a pool with capacity.
//! 2. **Conservative.** Effective remaining is
//!    `max(0, raw × (1 − safety_margin) − reserve)` — the margin covers usage
//!    on other machines that local parsing cannot see, and the reserve is
//!    headroom the engine leaves for the operator's own interactive work.
//! 3. **Trust order is ranked and fixed.** `Signal > SelfMetered > Assumed >
//!    Unknown` ([`Confidence`]), and a lower-ranked source can never overwrite
//!    a higher one — a rate-limit signal is ground truth, and a self-metered
//!    guess must not talk it back up.
//!
//! **v0.2 sketch — credential profiles.** §13 wants one vendor backing several
//! pools (two Claude Max accounts, say), selected per attempt "through the
//! provider's own profile mechanism, an environment variable on the subprocess
//! rather than a token the engine ever handles". That mechanism is real on both
//! vendors and is a config-*directory* variable: `COPILOT_HOME` (documented) and
//! `CLAUDE_CONFIG_DIR` (works, undocumented as of Aug 2026). The shape that
//! fits is tactus-defined profile directories — `~/.tactus/profiles/<name>` —
//! handed to the CLI through that variable, with login staying a user-driven
//! interactive step the engine never automates. "Does this CLI honour profile
//! selection" then becomes a `probe()` axis like any other, verified at
//! pre-flight instead of discovered mid-spend. v0.1 stops at [`Pool::profile`]:
//! the field is parsed, displayed, and attributed through, and **nothing sets
//! any environment variable**, because everything multi-profile actually buys
//! (per-profile attribution, asymmetric reserve, rebind-instead-of-wait) is
//! capacity-*driven* behaviour, which is v0.2 by sequencing.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::events::{AttemptRecord, Event, EventBody, ReviewPassOutcome};
use crate::ladder::FailureKind;

/// §13's pool shapes. Which one a pool is decides which estimator rule applies,
/// so an unknown value is a config error rather than a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolKind {
    /// Claude Max and friends: a rolling window plus a weekly cap.
    SubscriptionWindow,
    /// Copilot on AI-credit billing: a monthly allowance plus pay-as-you-go.
    Credits,
    /// Copilot on a legacy annual plan: premium requests × per-model multiplier.
    RequestPool,
    /// Direct API billing — dollars, no reset, budget-only.
    ApiKey,
    /// A local endpoint: hardware-bound rather than quota-bound.
    Unmetered,
}

impl PoolKind {
    /// Accepted spellings, named once so the parser and its error message
    /// cannot disagree about what is legal.
    pub const ACCEPTED: [&'static str; 5] = [
        "subscription-window",
        "credits",
        "request-pool",
        "api-key",
        "unmetered",
    ];

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "subscription-window" => Some(Self::SubscriptionWindow),
            "credits" => Some(Self::Credits),
            "request-pool" => Some(Self::RequestPool),
            "api-key" => Some(Self::ApiKey),
            "unmetered" => Some(Self::Unmetered),
            _ => None,
        }
    }
}

impl fmt::Display for PoolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SubscriptionWindow => "subscription-window",
            Self::Credits => "credits",
            Self::RequestPool => "request-pool",
            Self::ApiKey => "api-key",
            Self::Unmetered => "unmetered",
        })
    }
}

/// §13's estimation sources, in trust order. Listing one is a statement about
/// where a pool's numbers may come from — dropping `signals` by typo would
/// discard ground truth, which is why an unknown entry errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// (4) Provider usage endpoints — fragile, never load-bearing. Parsed in
    /// v0.1, never read.
    ProviderEndpoint,
    /// (3) ccusage-style parsing of the agent's own logs, which is what sees
    /// the operator's interactive sessions. Parsed in v0.1, never read.
    LocalLogs,
    /// (2) Self-metering of everything this engine spawned.
    SelfMetered,
    /// (1) Rate-limit signals from the CLIs — ground truth.
    Signals,
}

impl Source {
    pub const ACCEPTED: [&'static str; 4] = ["signals", "self", "local-logs", "provider-endpoint"];

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "signals" => Some(Self::Signals),
            "self" => Some(Self::SelfMetered),
            "local-logs" => Some(Self::LocalLogs),
            "provider-endpoint" => Some(Self::ProviderEndpoint),
            _ => None,
        }
    }

    /// Whether v0.1 actually reads this source. The two that are only parsed
    /// get a note on the estimate rather than a pretend number.
    pub fn read_in_v0_1(self) -> bool {
        matches!(self, Self::Signals | Self::SelfMetered)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Signals => "signals",
            Self::SelfMetered => "self",
            Self::LocalLogs => "local-logs",
            Self::ProviderEndpoint => "provider-endpoint",
        })
    }
}

/// `monthly_allowance = "auto"` or a number of units.
///
/// `Auto` is honest rather than convenient: it means the size of the allowance
/// is not known to tactus, which is different from it being zero and different
/// again from it being unlimited.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Allowance {
    Auto,
    Units(f64),
}

impl fmt::Display for Allowance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Units(units) => write!(f, "{units}"),
        }
    }
}

/// §13's default margins, applied when the pools file is silent. Both are also
/// what `tactus connect` writes, so a hand-edited file and a generated one mean
/// the same thing.
pub const DEFAULT_SAFETY_MARGIN: f64 = 0.15;
pub const DEFAULT_RESERVE: f64 = 0.20;

/// One `[pools.<name>]` entry (§17).
#[derive(Debug, Clone, PartialEq)]
pub struct Pool {
    pub name: String,
    pub kind: PoolKind,
    /// Which agent drains it. A pool naming an agent this build has no adapter
    /// for is kept and marked unusable rather than rejected — §17's own example
    /// ships `[pools.local] agent = "aider"`.
    pub agent: String,
    /// Rolling window, e.g. `"5h"`.
    pub window: Option<Duration>,
    pub weekly: bool,
    pub sources: Vec<Source>,
    pub safety_margin: f64,
    pub reserve: f64,
    pub monthly_allowance: Allowance,
    pub endpoint: Option<String>,
    /// §13's credential-profile seam: an operator-writable config-directory
    /// path identifying *which account* this pool draws from. Parsed, carried,
    /// and displayed; **nothing acts on it in v0.1** (see the module docs).
    pub profile: Option<String>,
    /// No adapter in this build for [`Pool::agent`]. The pool is still listed —
    /// it describes the operator's subscriptions, not this binary's features.
    pub usable: bool,
}

impl Pool {
    /// A pool as `connect` writes one: §13's defaults, nothing invented.
    pub fn discovered(name: &str, kind: PoolKind, agent: &str, sources: Vec<Source>) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            agent: agent.to_owned(),
            window: (kind == PoolKind::SubscriptionWindow).then(|| Duration::from_secs(5 * 3600)),
            weekly: kind == PoolKind::SubscriptionWindow,
            sources,
            safety_margin: DEFAULT_SAFETY_MARGIN,
            reserve: DEFAULT_RESERVE,
            monthly_allowance: Allowance::Auto,
            endpoint: None,
            profile: None,
            usable: true,
        }
    }

    /// One line for a preview or a listing: what this pool is and whose it is.
    pub fn describe(&self) -> String {
        let mut line = format!("{} [{}] agent={}", self.name, self.kind, self.agent);
        if let Some(window) = self.window {
            line.push_str(&format!(" window={}", render_duration(window)));
        }
        if self.weekly {
            line.push_str(" +weekly");
        }
        if let Some(profile) = &self.profile {
            line.push_str(&format!(" profile={profile}"));
        }
        if let Some(endpoint) = &self.endpoint {
            line.push_str(&format!(" endpoint={endpoint}"));
        }
        line.push_str(&format!(
            " margin={:.2} reserve={:.2}",
            self.safety_margin, self.reserve
        ));
        if !self.usable {
            line.push_str(" (no adapter in this build)");
        }
        line
    }
}

/// Which pool an attempt on `agent` drains: the first matching entry, table
/// order as preference — the same convention `different_family_at` uses, so
/// moving a pool up the file promotes it.
///
/// **Attribution only.** Nothing routes on the answer in v0.1; it fills
/// `WorkerProfile.pool` so the ledger can say which subscription paid.
pub fn pool_for<'a>(agent: &str, pools: &'a [Pool]) -> Option<&'a Pool> {
    pools.iter().find(|pool| pool.agent == agent)
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// What one pool has drained *through this engine*, in the run being folded.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Spend {
    /// Reported api-equivalent dollars. `None` means nothing reported any —
    /// which is not the same as nothing costing anything (§13: the Copilot
    /// route reports no spend at all).
    pub usd: Option<f64>,
    pub attempts: u32,
    /// Attempts whose route reported no cost, so `usd` above is a floor.
    pub unpriced: u32,
}

impl Spend {
    fn add(&mut self, cost: Option<f64>) {
        self.attempts = self.attempts.saturating_add(1);
        match cost {
            Some(cost) => self.usd = Some(self.usd.unwrap_or(0.0) + cost),
            None => self.unpriced = self.unpriced.saturating_add(1),
        }
    }
}

/// Everything the estimator is allowed to look at.
///
/// Deliberately plain data: [`estimate`] cannot reach past this into a file, a
/// process, or a clock, which is what makes every §13 rule testable without a
/// CLI installed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observations {
    /// §13 source 1 — pools a rate-limit signal marked exhausted, with the
    /// reset time where the signal carried one. Ground truth.
    pub exhausted: BTreeMap<String, Option<String>>,
    /// §13 source 2 — self-metering of what this engine spawned.
    pub self_spend: BTreeMap<String, Spend>,
}

impl Observations {
    pub fn is_empty(&self) -> bool {
        self.exhausted.is_empty() && self.self_spend.is_empty()
    }
}

/// Fold a run's events into observations.
///
/// A pure function over events someone else read, so the estimator's inputs are
/// derived by exactly the mechanism every other reader uses (§15: the log is
/// the source of truth). Attempts that name no pool contribute nothing — an
/// unattributed cost belongs to no subscription, and guessing which would be
/// worse than leaving the pool unmeasured.
pub fn observe(events: &[Event]) -> Observations {
    let mut obs = Observations::default();
    for event in events {
        match &event.body {
            EventBody::PoolExhausted { data, .. } => {
                obs.exhausted
                    .insert(data.pool.clone(), data.reset_at.clone());
            }
            EventBody::AttemptFinished { data, .. }
            | EventBody::AttemptInterrupted { data, .. } => {
                accumulate(&mut obs.self_spend, data);
                retire_signals(&mut obs.exhausted, data);
            }
            _ => {}
        }
    }
    obs
}

/// Withdraw the exhausted mark from any pool this attempt proves is serving
/// again.
///
/// Without this a rate limit is permanent: `exhausted` was only ever inserted
/// into, nothing emits a recovery event, and [`Confidence::Signal`] outranks
/// every other source **by design** — so the one thing that could correct the
/// record was the one thing forbidden from doing so. A pool that refused an
/// attempt at 10:00, came back at 10:05 and served the rest of the run still
/// read `exhausted [signal]` at midnight, on the same line that reported the
/// successful attempts it had served since.
///
/// Events arrive in order, so a later signal re-marks a pool this retired —
/// which is right: the pool went down again.
///
/// What counts as proof is deliberately narrow. A *completed* attempt reached
/// the model and got an answer, whatever the verdict on its code — a gate
/// failure says nothing about the subscription. A rate-limited one proves the
/// opposite. An interrupted one proves nothing at all: the engine died without
/// ever learning whether a reply was coming.
fn retire_signals(exhausted: &mut BTreeMap<String, Option<String>>, record: &AttemptRecord) {
    let worker_served = record.failure.as_ref().is_none_or(|failure| {
        failure.kind != FailureKind::Interrupted
            && !(failure.kind == FailureKind::RateLimited
                && failure.origin == crate::ladder::FailureOrigin::Worker)
    });
    if worker_served {
        if let Some(pool) = &record.pool {
            exhausted.remove(pool);
        }
    }
    // A review pass that reached a verdict proves its own pool served, which on
    // a cross-vendor second opinion is a different subscription entirely.
    for review in &record.reviews {
        if review.outcome != ReviewPassOutcome::Unavailable {
            if let Some(pool) = &review.pool {
                exhausted.remove(pool);
            }
        }
    }
    // The attempt settlement itself is the durable source of a rate-limit
    // signal. `pool_exhausted` remains useful detail, but a crash between the
    // two appends must not make replay forget which subscription refused work.
    if let Some(failure) = &record.failure {
        if failure.kind == FailureKind::RateLimited {
            let pool = match failure.origin {
                crate::ladder::FailureOrigin::Worker => record.pool.as_ref(),
                crate::ladder::FailureOrigin::Reviewer => record
                    .reviews
                    .last()
                    .and_then(|review| review.pool.as_ref()),
            };
            if let Some(pool) = pool {
                exhausted.insert(pool.clone(), None);
            }
        }
    }
}

/// The same fold, over attempt records rather than events — what the ledger
/// needs, and what a reader holding folded state rather than raw events has.
///
/// Shared with [`observe`] rather than written twice: the ledger's per-pool
/// column and the estimator's self-metered source must be the same number, or
/// one of them is wrong and nothing says which.
pub fn drain_of<'a>(
    records: impl IntoIterator<Item = &'a AttemptRecord>,
) -> BTreeMap<String, Spend> {
    let mut drain = BTreeMap::new();
    for record in records {
        accumulate(&mut drain, record);
    }
    drain
}

fn accumulate(drain: &mut BTreeMap<String, Spend>, record: &AttemptRecord) {
    // An attempt naming no pool contributes nothing: unattributed cost belongs
    // to no subscription, and guessing which would be worse than leaving the
    // pool unmeasured.
    if let Some(pool) = &record.pool {
        drain.entry(pool.clone()).or_default().add(record.cost_usd);
    }
    // A cross-vendor second opinion drains a different subscription than the
    // implementer it judged (§11.3), so each pass is attributed on its own.
    for review in &record.reviews {
        if let Some(pool) = &review.pool {
            drain.entry(pool.clone()).or_default().add(review.cost_usd);
        }
    }
}

// ---------------------------------------------------------------------------
// The estimate
// ---------------------------------------------------------------------------

/// How much of a pool is left, after margins.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Remaining {
    /// Nothing measured this pool. **Never rendered as "full"** — the whole
    /// point of the variant is that "we do not know" and "there is plenty" are
    /// different answers (§13, invariant 7).
    Unknown,
    /// A rate-limit signal said so. Ground truth.
    Exhausted,
    /// An **upper bound** on the fraction still available, after
    /// `safety_margin` and `reserve`, clamped to `0.0..=1.0`.
    ///
    /// Deliberately not "the fraction remaining". Self-metering sees only what
    /// this engine spawned in this repository, so `1 − draw/allowance` is what
    /// is left *if nothing else drew on the pool* — and something else almost
    /// always did: earlier runs, other repositories, and the operator's own
    /// interactive sessions (§13's source 3, which v0.1 parses and does not
    /// read). Every one of those can only reduce what is left, never increase
    /// it, so the figure is sound as a ceiling and false as a measurement.
    /// Rendered with `≤` for exactly that reason.
    AtMost(f64),
    /// Hardware-bound rather than quota-bound (§13's local pools).
    Unmetered,
}

impl fmt::Display for Remaining {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("unknown"),
            Self::Exhausted => f.write_str("exhausted"),
            Self::AtMost(bound) => write!(f, "≤{:.0}%", bound * 100.0),
            Self::Unmetered => f.write_str("unmetered"),
        }
    }
}

/// Where an estimate came from, ranked. §13's trust order made into a type, so
/// "a lower-ranked source can never overwrite a higher one" is enforced by
/// [`Ord`] rather than by every call site remembering it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Nothing measured it.
    Unknown,
    /// Derived from the pool's declared shape rather than from anything
    /// observed — e.g. a local endpoint that cannot run out.
    Assumed,
    /// Self-metering of what this engine spawned.
    SelfMetered,
    /// A rate-limit signal from the CLI itself.
    Signal,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Assumed => "assumed",
            Self::SelfMetered => "self-metered",
            Self::Signal => "signal",
        })
    }
}

/// One pool's estimated state.
#[derive(Debug, Clone, PartialEq)]
pub struct PoolEstimate {
    pub pool: String,
    pub agent: String,
    pub kind: PoolKind,
    pub profile: Option<String>,
    pub remaining: Remaining,
    pub confidence: Confidence,
    /// When the signal said the window reopens, where it said so.
    pub reset_at: Option<String>,
    /// What this engine has drawn from the pool in the run being folded.
    pub self_spend: Option<Spend>,
    /// Everything the estimate could not account for, said out loud.
    pub notes: Vec<String>,
}

impl PoolEstimate {
    /// One line: the pool, what is left, and how confident that is.
    pub fn describe(&self) -> String {
        let mut line = format!("{}: {} [{}]", self.pool, self.remaining, self.confidence);
        if let Some(reset) = &self.reset_at {
            line.push_str(&format!(" resets {reset}"));
        }
        if let Some(spend) = &self.self_spend {
            let unpriced = if spend.unpriced > 0 { "?" } else { "" };
            match spend.usd {
                Some(usd) => line.push_str(&format!(
                    " — this run drew ${usd:.4}{unpriced} over {} attempt(s)",
                    spend.attempts
                )),
                None => line.push_str(&format!(
                    " — this run drew {} attempt(s), none of which reported spend",
                    spend.attempts
                )),
            }
        }
        line
    }
}

/// §13's estimator: pools plus observations in, one estimate per pool out.
///
/// Pure and total. Every branch is reachable from plain values, so the three
/// properties in the module docs are testable without a CLI, a repo, or a file.
pub fn estimate(pools: &[Pool], obs: &Observations) -> Vec<PoolEstimate> {
    pools.iter().map(|pool| estimate_one(pool, obs)).collect()
}

fn estimate_one(pool: &Pool, obs: &Observations) -> PoolEstimate {
    let mut notes = Vec::new();
    let self_spend = obs.self_spend.get(&pool.name).cloned();

    // Ranked candidates, strongest first. `take` refuses anything that does not
    // outrank what is already held, so the trust order cannot be inverted by
    // adding a rule below an existing one.
    let mut remaining = Remaining::Unknown;
    let mut confidence = Confidence::Unknown;
    let mut reset_at = None;
    let mut take = |candidate: Remaining, rank: Confidence| {
        if rank > confidence {
            remaining = candidate;
            confidence = rank;
            true
        } else {
            false
        }
    };

    // (1) Signals — ground truth, and the only thing that can say "exhausted".
    if let Some(reset) = obs.exhausted.get(&pool.name) {
        take(Remaining::Exhausted, Confidence::Signal);
        reset_at = reset.clone();
        if reset.is_none() {
            notes.push(
                "the rate-limit signal carried no reset time, so when it comes back is unknown"
                    .to_owned(),
            );
        }
    }

    // A pool that cannot run out is a fact about its shape, not a measurement.
    if pool.kind == PoolKind::Unmetered {
        take(Remaining::Unmetered, Confidence::Assumed);
    }

    // (2) Self-metering. It bounds what is left only when the allowance's size
    // is known: `spend / auto` is not a fraction of anything. Otherwise the
    // draw is reported beside an Unknown remaining rather than dressed up as
    // one — §13's conservatism is about never overstating what is left, and
    // "we measured some spend" is not a measurement of the ceiling.
    if let (Some(spend), Allowance::Units(allowance)) = (&self_spend, pool.monthly_allowance) {
        if allowance > 0.0 {
            if let Some(usd) = spend.usd {
                let raw = 1.0 - (usd / allowance);
                if take(
                    Remaining::AtMost(effective_remaining(raw, pool)),
                    Confidence::SelfMetered,
                ) {
                    notes.push(
                        "a ceiling, not a measurement: this counts only what tactus spawned in this \
                         repository, so earlier runs, other repositories, and your own interactive \
                         sessions have all drawn against the same allowance unseen"
                            .to_owned(),
                    );
                    if spend.unpriced > 0 {
                        notes.push(format!(
                            "{} attempt(s) on this pool reported no spend, so even the draw behind that \
                             ceiling is a floor (§13)",
                            spend.unpriced
                        ));
                    }
                }
            }
        }
    }

    if confidence == Confidence::Unknown {
        notes.push(
            "nothing has measured this pool, so what is left is unknown — not full (§13)"
                .to_owned(),
        );
    }

    // The two sources v0.1 parses but does not read. Saying so is the point: a
    // pool that lists `local-logs` and gets an estimate anyway would read as
    // though interactive usage had been accounted for.
    let unread: Vec<String> = pool
        .sources
        .iter()
        .filter(|source| !source.read_in_v0_1())
        .map(ToString::to_string)
        .collect();
    if !unread.is_empty() {
        notes.push(format!(
            "source(s) {} are parsed but not read in v0.1, so usage they would see — including \
             your own interactive sessions — is not in this figure",
            unread.join(", ")
        ));
    }
    if !pool.usable {
        notes.push(format!(
            "no adapter for agent `{}` in this build, so this engine can never draw from it",
            pool.agent
        ));
    }

    PoolEstimate {
        pool: pool.name.clone(),
        agent: pool.agent.clone(),
        kind: pool.kind,
        profile: pool.profile.clone(),
        remaining,
        confidence,
        reset_at,
        self_spend,
        notes,
    }
}

/// §13's conservatism, in one place: `max(0, raw × (1 − safety_margin) −
/// reserve)`, clamped into `0.0..=1.0`.
///
/// The margin covers what local measurement cannot see (the same subscription
/// used from another machine); the reserve is headroom deliberately left for the
/// operator's own interactive work. Applied multiplicatively then additively
/// because they are different claims: the margin says the measurement may be
/// wrong, the reserve says some of what is left is not ours to spend.
pub fn effective_remaining(raw: f64, pool: &Pool) -> f64 {
    if !raw.is_finite() {
        return 0.0;
    }
    let discounted = raw.clamp(0.0, 1.0) * (1.0 - pool.safety_margin) - pool.reserve;
    discounted.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Durations
// ---------------------------------------------------------------------------

/// Parse §17's window spellings: `"5h"`, `"30m"`, `"7d"`, `"90s"`.
///
/// Dependency-free, and deliberately narrow — a window is one number and one
/// unit, so anything else is a typo worth naming rather than a format worth
/// guessing at.
pub fn parse_duration(raw: &str) -> Option<Duration> {
    let text = raw.trim();
    let (digits, unit) = text.split_at(text.len().checked_sub(1)?);
    let value: u64 = digits.trim().parse().ok()?;
    let seconds = match unit {
        "s" | "S" => 1,
        "m" | "M" => 60,
        "h" | "H" => 3600,
        "d" | "D" => 86_400,
        _ => return None,
    };
    Some(Duration::from_secs(value.checked_mul(seconds)?))
}

/// The inverse, in the largest unit that divides exactly — so a window read
/// from a file and written back out again is the same string.
pub fn render_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    for (unit, size) in [("d", 86_400u64), ("h", 3600), ("m", 60)] {
        if seconds >= size && seconds % size == 0 {
            return format!("{}{unit}", seconds / size);
        }
    }
    format!("{seconds}s")
}

// ---------------------------------------------------------------------------
// Strategy preview
// ---------------------------------------------------------------------------

/// What each §13 strategy *would* do with these estimates — the read-only half
/// of the capacity engine, and the whole of what v0.1 ships.
///
/// Phrased as "would", every line of it, because none of it is wired to the
/// binder. A preview that reads as a description of what is about to happen
/// would be a lie by tense.
pub fn strategy_preview(mode: &str, estimates: &[PoolEstimate]) -> Vec<String> {
    let exhausted: Vec<&str> = estimates
        .iter()
        .filter(|e| e.remaining == Remaining::Exhausted)
        .map(|e| e.pool.as_str())
        .collect();
    let measured = estimates
        .iter()
        .any(|e| e.confidence >= Confidence::SelfMetered);

    let mut lines = Vec::new();
    lines.push(match mode {
        "value-max" => "value-max: prepaid capacity that expires unused has zero marginal cost, \
                        so surplus near a reset would bias default tiers UP (spend-down), bounded \
                        by each task's min/max and the pool reserve"
            .to_owned(),
        "deadline" => "deadline: wall-clock first — throughput within capacity, spilling to API \
                       dollars where a $/hour ceiling justified it"
            .to_owned(),
        _ => "conserve: route down aggressively, escalate only on failure, and defer \
              frontier-hungry tasks toward a window reset when a pool is projected to run dry"
            .to_owned(),
    });
    if !exhausted.is_empty() {
        lines.push(format!(
            "exhausted now: {} — under a capacity-driven binder these would demote or defer \
             (§13); today a rate limit still only defers the task that hit it (§19)",
            exhausted.join(", ")
        ));
    }
    if !measured {
        lines.push(
            "no pool has a measured estimate yet, so every strategy above would be working from \
             the same absence of evidence"
                .to_owned(),
        );
    }
    lines.push(
        "v0.1 ships the capacity engine read-only (§13): none of the above changes what binds — \
         the binder still picks from the catalog and your pins."
            .to_owned(),
    );
    lines
}

// ---------------------------------------------------------------------------
// `tactus capacity`
// ---------------------------------------------------------------------------

/// `tactus capacity [--config <path>] [--pools <path>]` (§18).
#[derive(Debug, Clone, Default)]
pub struct CapacityOptions {
    pub config_path: Option<std::path::PathBuf>,
    pub pools_path: Option<std::path::PathBuf>,
    /// Where to look for runs to self-meter from. Outside a git repository
    /// there simply are none, which the report says rather than erroring on.
    pub repo_root: std::path::PathBuf,
}

#[derive(Debug)]
pub struct CapacityReport {
    pub pools: Vec<Pool>,
    pub estimates: Vec<PoolEstimate>,
    /// Live probe + discovery per agent named by a pool. **This** is where
    /// probing belongs: `capacity` is allowed to spawn the vendors' CLIs, and
    /// `validate` is not (§18).
    pub agents: Vec<AgentStatus>,
    pub strategy: String,
    /// The run the self-metered figures were folded from.
    pub run_id: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct AgentStatus {
    pub agent: String,
    pub auth: String,
    pub version: Option<String>,
    pub notes: Vec<String>,
}

/// Collect everything `tactus capacity` reports: pools from config, self-metered
/// spend from the latest run in this repo, and a live probe per agent.
pub fn report(
    opts: &CapacityOptions,
    adapters: &dyn crate::agent::AdapterSource,
) -> Result<CapacityReport, crate::error::TactusError> {
    let mut warnings = Vec::new();
    let config = crate::config::load(
        opts.config_path.as_deref(),
        &opts.repo_root,
        opts.pools_path.as_deref(),
        &mut warnings,
    )?;

    // Self-metering needs a repository with runs in it. Pools are user-level
    // (§17), so a listing outside a repo is still worth having — it just cannot
    // say what has been drawn. Reporting that beats refusing to run.
    let (observations, run_id) = match crate::rundir::latest_run(&opts.repo_root) {
        Some(run_id) => {
            let path = crate::rundir::public_dir(&opts.repo_root, &run_id).join("events.jsonl");
            match crate::events::read_all(&path, &mut warnings) {
                Ok(events) => (observe(&events), Some(run_id)),
                Err(error) => {
                    warnings.push(format!(
                        "could not fold run {run_id} for self-metered spend ({error}); showing \
                         signals only"
                    ));
                    (Observations::default(), None)
                }
            }
        }
        None => (Observations::default(), None),
    };

    let mut agents: Vec<AgentStatus> = Vec::new();
    for pool in &config.pools {
        if agents.iter().any(|a| a.agent == pool.agent) {
            continue;
        }
        let Some(adapter) = adapters.get(&pool.agent) else {
            agents.push(AgentStatus {
                agent: pool.agent.clone(),
                auth: "no adapter in this build".to_owned(),
                version: None,
                notes: Vec::new(),
            });
            continue;
        };
        // `capacity` runs no run, so it has no run's Runner to borrow: it
        // makes its own host one. That is still the Runner seam rather than a
        // bare spawn — `invariants_introduced[0]` is "every CLI and gate
        // process executes through Runner" — but it is deliberately *not*
        // inside INV-18's ambient job, which is the coordinator's and which
        // this command is not (`main::the_commands_that_spawn_outside_a_run_
        // are_named_and_counted`).
        let runner = crate::runner::host::HostRunner::new();
        match adapter.probe(&runner).and_then(|caps| {
            adapter
                .discover(&runner, &caps)
                .map(|discovery| (caps.version.clone(), discovery))
        }) {
            Ok((version, discovery)) => {
                // D1's cross-check: where the CLI can actually list its models,
                // say so when the shipped catalog names one it does not offer.
                // Load-bearing rather than tidy — a stale frontier slug fails
                // every cross-vendor second opinion at runtime, on exactly the
                // paths §11.3 exists to protect.
                let missing = crate::catalog::missing_from(&pool.agent, &discovery.models);
                if !missing.is_empty() {
                    warnings.push(format!(
                        "{} does not advertise catalogued model(s): {}. Pins and cross-family \
                         review may bind to a `--model` value this CLI rejects — upgrade tactus \
                         or pin a model it lists.",
                        pool.agent,
                        missing.join(", ")
                    ));
                }
                agents.push(AgentStatus {
                    agent: pool.agent.clone(),
                    auth: discovery.auth.to_string(),
                    version: Some(version),
                    notes: discovery.notes,
                });
            }
            // A CLI that is not installed is a fact worth reporting, not a
            // reason to refuse the whole listing: an operator asking about
            // capacity on a machine missing one vendor still wants the other.
            Err(error) => agents.push(AgentStatus {
                agent: pool.agent.clone(),
                auth: format!("could not probe: {error}"),
                version: None,
                notes: Vec::new(),
            }),
        }
    }

    let estimates = estimate(&config.pools, &observations);
    Ok(CapacityReport {
        pools: config.pools,
        estimates,
        agents,
        strategy: config.strategy.mode.clone(),
        run_id,
        warnings,
    })
}

impl CapacityReport {
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        for warning in &self.warnings {
            let _ = writeln!(out, "warning: {warning}");
        }
        if self.pools.is_empty() {
            out.push_str(
                "no pools connected. Run `tactus connect` to discover the agent CLIs on this \
                 machine and write ~/.tactus/pools.toml.\n",
            );
            return out;
        }
        for status in &self.agents {
            let _ = writeln!(
                out,
                "{} {}: {}",
                status.agent,
                status.version.as_deref().unwrap_or("(version unknown)"),
                status.auth
            );
            for note in &status.notes {
                let _ = writeln!(out, "  {note}");
            }
        }
        out.push('\n');
        for (pool, estimate) in self.pools.iter().zip(&self.estimates) {
            let _ = writeln!(out, "{}", pool.describe());
            let _ = writeln!(out, "  {}", estimate.describe());
            for note in &estimate.notes {
                let _ = writeln!(out, "  - {note}");
            }
        }
        out.push('\n');
        match &self.run_id {
            Some(run_id) => {
                let _ = writeln!(
                    out,
                    "self-metered draw folded from run {run_id}, the latest in this repository"
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "no run in this repository yet, so estimates rest on rate-limit signals \
                     alone — estimates need a repo with runs"
                );
            }
        }
        let _ = writeln!(out, "strategy: {}", self.strategy);
        for line in strategy_preview(&self.strategy, &self.estimates) {
            let _ = writeln!(out, "  {line}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(name: &str) -> Pool {
        Pool::discovered(
            name,
            PoolKind::SubscriptionWindow,
            "claude-code",
            vec![Source::Signals, Source::SelfMetered],
        )
    }

    #[test]
    fn an_unmeasured_pool_is_unknown_never_full() {
        // Property 1. The trap this exists to stop: rendering "no observation"
        // as 100% would make a dry subscription look like the best pool to
        // route to, which is exactly backwards.
        let estimates = estimate(&[pool("claude-max")], &Observations::default());
        assert_eq!(estimates[0].remaining, Remaining::Unknown);
        assert_eq!(estimates[0].confidence, Confidence::Unknown);
        assert!(
            estimates[0].notes.iter().any(|n| n.contains("not full")),
            "notes: {:?}",
            estimates[0].notes
        );
    }

    #[test]
    fn margins_apply_multiplicatively_then_subtract_the_reserve() {
        // Property 2, on the arithmetic itself: 0.5 × 0.85 − 0.20 = 0.225.
        let pool = pool("claude-max");
        assert!((effective_remaining(0.5, &pool) - 0.225).abs() < 1e-9);
        // Never negative, never above one, and never NaN-propagating.
        assert_eq!(effective_remaining(0.1, &pool), 0.0);
        assert!((effective_remaining(2.0, &pool) - 0.65).abs() < 1e-9);
        assert_eq!(effective_remaining(f64::NAN, &pool), 0.0);

        let mut generous = pool.clone();
        generous.safety_margin = 0.0;
        generous.reserve = 0.0;
        assert!((effective_remaining(0.5, &generous) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn a_self_metered_estimate_is_conservative_end_to_end() {
        let mut p = pool("api");
        p.kind = PoolKind::ApiKey;
        p.monthly_allowance = Allowance::Units(100.0);
        let mut obs = Observations::default();
        obs.self_spend.insert(
            "api".to_owned(),
            Spend {
                usd: Some(50.0),
                attempts: 4,
                unpriced: 0,
            },
        );
        let estimates = estimate(&[p], &obs);
        assert_eq!(estimates[0].confidence, Confidence::SelfMetered);
        // Half the allowance spent, and the margins take it down from there —
        // it must never come out at the raw 50%.
        let Remaining::AtMost(left) = estimates[0].remaining else {
            panic!("expected an upper bound: {:?}", estimates[0].remaining);
        };
        assert!((left - 0.225).abs() < 1e-9, "left: {left}");
        // And it is presented as the ceiling it is, not as a measurement: this
        // counts one run's draw against a *monthly* allowance, so every earlier
        // run and every interactive session is unseen.
        assert!(
            estimates[0].describe().contains("≤22%"),
            "{}",
            estimates[0].describe()
        );
        assert!(
            estimates[0]
                .notes
                .iter()
                .any(|n| n.contains("a ceiling, not a measurement")),
            "notes: {:?}",
            estimates[0].notes
        );
    }

    #[test]
    fn a_pool_that_serves_again_stops_reading_as_exhausted() {
        // A signal is ground truth about the moment it was recorded, not
        // forever. Without retirement `Confidence::Signal` outranks every
        // source that could correct it, so one rate limit at 10:00 makes the
        // pool read as empty at midnight — on the same line that reports the
        // attempts it served in between.
        use crate::events::{AttemptRecord, Event, EventBody, PoolExhausted};
        use crate::ladder::{FailureKind, FailureOrigin};

        let record = |failure: Option<FailureKind>| {
            Event::now(EventBody::AttemptFinished {
                task: "t1".to_owned(),
                attempt: 1,
                rung: 0,
                profile: "p".to_owned(),
                parking: None,
                transition: None,
                prepared_commit: None,
                data: Box::new(AttemptRecord {
                    attempt: 1,
                    tier: "small".to_owned(),
                    model: "m".to_owned(),
                    pool: Some("claude-max".to_owned()),
                    resumed: false,
                    duration: Duration::ZERO,
                    cost_usd: None,
                    reviews: Vec::new(),
                    session_id: None,
                    usage: None,
                    failure: failure.map(|kind| crate::events::FailureRecord {
                        kind,
                        origin: FailureOrigin::Worker,
                        reason: "r".to_owned(),
                    }),
                }),
            })
        };
        let signal = Event::now(EventBody::PoolExhausted {
            task: "t1".to_owned(),
            data: PoolExhausted {
                pool: "claude-max".to_owned(),
                agent: "claude-code".to_owned(),
                reset_at: None,
                detail: "5-hour limit reached".to_owned(),
            },
        });

        // Signal, then an attempt that completed: the pool is serving.
        let obs = observe(&[signal.clone(), record(None)]);
        assert!(obs.exhausted.is_empty(), "{:?}", obs.exhausted);

        // A gate failure also proves the model answered — the verdict on the
        // code says nothing about the subscription.
        let obs = observe(&[signal.clone(), record(Some(FailureKind::GateFailed))]);
        assert!(obs.exhausted.is_empty(), "{:?}", obs.exhausted);

        // A second rate limit proves the opposite, and an interrupted attempt
        // proves nothing at all — the engine died without learning whether a
        // reply was coming.
        for still_down in [FailureKind::RateLimited, FailureKind::Interrupted] {
            let obs = observe(&[signal.clone(), record(Some(still_down))]);
            assert!(
                obs.exhausted.contains_key("claude-max"),
                "{still_down:?} must not retire the signal"
            );
        }

        // And order is respected: recovery then a fresh outage stays down.
        let obs = observe(&[signal.clone(), record(None), signal]);
        assert!(obs.exhausted.contains_key("claude-max"));

        // A reviewer-side limit is attached to the failed review pool, while
        // the same settlement proves the worker and earlier reviewers served.
        let reviewer_limited = Event::now(EventBody::AttemptFinished {
            task: "t1".to_owned(),
            attempt: 2,
            rung: 0,
            profile: "p".to_owned(),
            parking: None,
            transition: None,
            prepared_commit: None,
            data: Box::new(AttemptRecord {
                attempt: 2,
                tier: "small".to_owned(),
                model: "worker".to_owned(),
                pool: Some("worker-pool".to_owned()),
                resumed: false,
                duration: Duration::ZERO,
                cost_usd: None,
                reviews: vec![
                    crate::events::ReviewRecord {
                        pass: "review".to_owned(),
                        agent: "codex".to_owned(),
                        model: "sol".to_owned(),
                        adapter: None,
                        preflight_cli_version: None,
                        effort: None,
                        pool: Some("recovered-reviewer".to_owned()),
                        cost_usd: None,
                        outcome: crate::events::ReviewPassOutcome::Passed,
                    },
                    crate::events::ReviewRecord {
                        pass: "second-opinion".to_owned(),
                        agent: "claude-code".to_owned(),
                        model: "opus".to_owned(),
                        adapter: None,
                        preflight_cli_version: None,
                        effort: None,
                        pool: Some("limited-reviewer".to_owned()),
                        cost_usd: None,
                        outcome: crate::events::ReviewPassOutcome::Unavailable,
                    },
                ],
                session_id: None,
                usage: None,
                failure: Some(crate::events::FailureRecord {
                    kind: FailureKind::RateLimited,
                    origin: FailureOrigin::Reviewer,
                    reason: "review pool limited".to_owned(),
                }),
            }),
        });
        let mut prior = Observations::default();
        for pool in ["worker-pool", "recovered-reviewer", "limited-reviewer"] {
            prior.exhausted.insert(pool.to_owned(), None);
        }
        let mut events = Vec::new();
        for pool in prior.exhausted.keys() {
            events.push(Event::now(EventBody::PoolExhausted {
                task: "t1".to_owned(),
                data: PoolExhausted {
                    pool: pool.clone(),
                    agent: "agent".to_owned(),
                    reset_at: None,
                    detail: "old signal".to_owned(),
                },
            }));
        }
        events.push(reviewer_limited);
        let obs = observe(&events);
        assert!(!obs.exhausted.contains_key("worker-pool"), "{obs:?}");
        assert!(!obs.exhausted.contains_key("recovered-reviewer"), "{obs:?}");
        assert!(obs.exhausted.contains_key("limited-reviewer"), "{obs:?}");
    }

    #[test]
    fn self_metering_cannot_talk_an_exhausted_pool_back_up() {
        // Property 3, in the form that matters: a signal said the pool is
        // empty, and a self-metered figure computed from a generous allowance
        // must not overwrite it. Getting this backwards would route work at a
        // pool the CLI has already refused.
        let mut p = pool("claude-max");
        p.monthly_allowance = Allowance::Units(100.0);
        let mut obs = Observations::default();
        obs.exhausted.insert(
            "claude-max".to_owned(),
            Some("2026-08-09T18:00:00Z".to_owned()),
        );
        obs.self_spend.insert(
            "claude-max".to_owned(),
            Spend {
                usd: Some(1.0),
                attempts: 1,
                unpriced: 0,
            },
        );
        let estimates = estimate(&[p], &obs);
        assert_eq!(estimates[0].remaining, Remaining::Exhausted);
        assert_eq!(estimates[0].confidence, Confidence::Signal);
        assert_eq!(
            estimates[0].reset_at.as_deref(),
            Some("2026-08-09T18:00:00Z")
        );
        // The draw is still reported — the signal says the pool is empty, not
        // that this run drew nothing.
        assert_eq!(
            estimates[0].self_spend.as_ref().map(|s| s.attempts),
            Some(1)
        );
    }

    #[test]
    fn an_unknown_allowance_reports_the_draw_without_inventing_a_ceiling() {
        // `spend / auto` is not a fraction of anything.
        let mut obs = Observations::default();
        obs.self_spend.insert(
            "claude-max".to_owned(),
            Spend {
                usd: Some(3.0),
                attempts: 2,
                unpriced: 1,
            },
        );
        let estimates = estimate(&[pool("claude-max")], &obs);
        assert_eq!(estimates[0].remaining, Remaining::Unknown);
        assert!(
            estimates[0].describe().contains("$3.0000?"),
            "{}",
            estimates[0].describe()
        );
    }

    #[test]
    fn unread_sources_get_a_note_rather_than_a_pretend_estimate() {
        let mut p = pool("claude-max");
        p.sources = vec![Source::Signals, Source::SelfMetered, Source::LocalLogs];
        let estimates = estimate(&[p], &Observations::default());
        assert!(
            estimates[0]
                .notes
                .iter()
                .any(|n| n.contains("local-logs") && n.contains("not read")),
            "notes: {:?}",
            estimates[0].notes
        );
    }

    #[test]
    fn a_local_pool_is_unmetered_by_shape_not_by_measurement() {
        let mut p = Pool::discovered("local", PoolKind::Unmetered, "aider", vec![Source::Signals]);
        p.usable = false;
        let estimates = estimate(&[p], &Observations::default());
        assert_eq!(estimates[0].remaining, Remaining::Unmetered);
        assert_eq!(estimates[0].confidence, Confidence::Assumed);
        assert!(
            estimates[0].notes.iter().any(|n| n.contains("no adapter")),
            "notes: {:?}",
            estimates[0].notes
        );
    }

    #[test]
    fn pool_selection_is_first_match_in_file_order() {
        let pools = vec![pool("claude-max-a"), pool("claude-max-b")];
        assert_eq!(
            pool_for("claude-code", &pools).map(|p| p.name.as_str()),
            Some("claude-max-a")
        );
        assert!(pool_for("copilot", &pools).is_none());
    }

    #[test]
    fn durations_round_trip_through_their_own_spellings() {
        for (text, secs) in [
            ("5h", 18_000u64),
            ("30m", 1800),
            ("7d", 604_800),
            ("90s", 90),
        ] {
            let parsed = parse_duration(text).expect(text);
            assert_eq!(parsed.as_secs(), secs);
            assert_eq!(render_duration(parsed), text);
        }
        for bad in [
            "",
            "h",
            "5",
            "5 hours",
            "-1h",
            "5x",
            "999999999999999999999h",
        ] {
            assert!(parse_duration(bad).is_none(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn every_strategy_preview_says_it_changes_nothing() {
        // The read-only promise is the one line that must survive every mode:
        // a preview that reads as a description of what is about to happen
        // would be a lie by tense (§13's sequencing).
        for mode in ["conserve", "value-max", "deadline", "something-else"] {
            let lines = strategy_preview(mode, &[]);
            assert!(
                lines.iter().any(|l| l.contains("read-only")),
                "{mode}: {lines:?}"
            );
        }
    }
}
