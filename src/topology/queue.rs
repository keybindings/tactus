//! The candidate queue: which prepared candidate the run integrates next.
//!
//! FIFO by `task_candidate_created` append order over every candidate,
//! including lineage members — the order is the log's, so a replay and a live
//! run reach the same next candidate without either of them sorting anything.
//!
//! Position is not eligibility. A candidate keeps its place while it is
//! ineligible, and the run integrates the first entry that *is* eligible rather
//! than blocking behind the head. Four things make an entry ineligible:
//!
//! * its task is awaiting input (a verification park, or a repair admission);
//! * its verification is deferred, until the next `defer_wait_elapsed` or
//!   resume;
//! * it is an ordinary candidate overlapping any active lineage lease;
//! * it is a lineage member overlapping an *older* active lineage lease.
//!
//! The last two are one rule read from both sides. A lineage holds the region a
//! rejection made contentious, so ordinary work stays out of it entirely, and
//! two lineages contending for one region resolve by age instead of taking
//! turns blocking each other.

use crate::topology::events::{CandidateRef, GenerationId, SequenceId};
use crate::topology::leases::LeaseTable;
use crate::topology::paths::{PathPolicy, PathSet};
use crate::topology::registry::TaskKey;

/// One candidate holding a place in the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueEntry {
    pub candidate: CandidateRef,
    /// The region the candidate's diff actually touched.
    pub paths: PathSet,
    /// The lineage this candidate belongs to, if it is a repair.
    pub lineage_root: Option<TaskKey>,
    /// Set by a deferred verification outage, cleared by `defer_wait_elapsed`
    /// or a resume.
    pub verification_deferred: bool,
    /// How many times this candidate's verification has been deferred, counted
    /// against the run's frozen ceiling.
    pub defers: u32,
    /// The verification sequence currently open for this candidate, if one is.
    pub sequence: Option<SequenceId>,
}

impl QueueEntry {
    pub fn key(&self) -> TaskKey {
        self.candidate.key
    }

    pub fn generation(&self) -> GenerationId {
        self.candidate.generation
    }
}

/// Why a queued candidate cannot be integrated right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible {
    /// The task is parked on a question.
    AwaitingInput,
    /// An outage deferred the verification and the backoff has not elapsed.
    VerificationDeferred,
    /// An ordinary candidate inside a region a lineage holds.
    InsideLineage { root: TaskKey },
    /// A lineage member inside a region an older lineage holds.
    BehindOlderLineage { root: TaskKey },
}

/// Every prepared candidate, in the order their refs were created.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CandidateQueue {
    entries: Vec<QueueEntry>,
}

impl CandidateQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a candidate to the back of the queue.
    pub fn push(&mut self, entry: QueueEntry) {
        self.entries.push(entry);
    }

    /// Remove the entry for one candidate, keeping the order of the rest.
    pub fn remove(&mut self, key: TaskKey, generation: GenerationId) {
        self.entries
            .retain(|entry| entry.key() != key || entry.generation() != generation);
    }

    pub fn entries(&self) -> &[QueueEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, key: TaskKey, generation: GenerationId) -> Option<&QueueEntry> {
        self.entries
            .iter()
            .find(|entry| entry.key() == key && entry.generation() == generation)
    }

    pub fn get_mut(&mut self, key: TaskKey, generation: GenerationId) -> Option<&mut QueueEntry> {
        self.entries
            .iter_mut()
            .find(|entry| entry.key() == key && entry.generation() == generation)
    }

    /// Whether any queued candidate belongs to `key`.
    pub fn holds_task(&self, key: TaskKey) -> bool {
        self.entries.iter().any(|entry| entry.key() == key)
    }

    /// Clear every deferred flag: the backoff elapsed, or the run resumed.
    pub fn wake_deferred(&mut self) {
        for entry in &mut self.entries {
            entry.verification_deferred = false;
        }
    }

    /// Why this entry is not integrable, or `None` when it is.
    pub fn ineligible<F>(
        entry: &QueueEntry,
        awaiting_input: &F,
        leases: &LeaseTable,
        policy: &PathPolicy,
    ) -> Option<Ineligible>
    where
        F: Fn(TaskKey) -> bool,
    {
        if awaiting_input(entry.key()) {
            return Some(Ineligible::AwaitingInput);
        }
        if entry.verification_deferred {
            return Some(Ineligible::VerificationDeferred);
        }
        let mut overlapping = leases.overlapping_lineages(&entry.paths, policy);
        match entry.lineage_root {
            None => overlapping
                .next()
                .map(|lease| Ineligible::InsideLineage { root: lease.root }),
            Some(mine) => {
                // Its own lineage overlaps by construction — that is what the
                // lease is for. Only a lineage created earlier holds it back.
                let own_age = leases.lineage(mine).map_or(u32::MAX, |lease| lease.age);
                overlapping
                    .find(|lease| lease.root != mine && lease.age < own_age)
                    .map(|lease| Ineligible::BehindOlderLineage { root: lease.root })
            }
        }
    }

    /// The candidate the run is entitled to integrate next.
    pub fn first_eligible<F>(
        &self,
        awaiting_input: F,
        leases: &LeaseTable,
        policy: &PathPolicy,
    ) -> Option<&QueueEntry>
    where
        F: Fn(TaskKey) -> bool,
    {
        self.entries
            .iter()
            .find(|entry| Self::ineligible(entry, &awaiting_input, leases, policy).is_none())
    }
}
