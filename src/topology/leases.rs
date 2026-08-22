//! Who holds which region of the repository, and what a settlement may do to
//! that holding.
//!
//! Two tasks may run in parallel exactly when the regions they touch do not
//! overlap, so a lease is the run's admission currency. There are three owners
//! and they are not interchangeable:
//!
//! * **Generation** — the *predicted* region an ordinary dispatch took from the
//!   plan's path hints. It is a guess, and it is replaced rather than confirmed.
//! * **Candidate** — the *actual* region the diff touched, taken when the
//!   candidate is prepared. This is what the merge queue is entitled to trust.
//! * **Lineage** — the region a rejected candidate and every repair descended
//!   from it hold together, widened by each rejection's conflict paths.
//!
//! The comparison itself is [`PathPolicy`]'s: component-wise
//! equal/ancestor/descendant, case-folded when the run resolved a case-folding
//! filesystem, and [`PathSet::RepoWide`] overlapping everything. Component-wise
//! is the whole of the subtlety — `src/foo` and `src/foobar` are different
//! regions, and a byte-prefix comparison would serialize them against each
//! other forever.

use std::collections::BTreeMap;

use crate::topology::events::{GenerationId, LeaseDisposition};
use crate::topology::paths::{GitPath, PathPolicy, PathSet};
use crate::topology::registry::TaskKey;

/// Whose holding a region is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeaseOwner {
    /// The predicted region of one generation.
    Generation {
        key: TaskKey,
        generation: GenerationId,
    },
    /// The actual region of one prepared candidate.
    Candidate {
        key: TaskKey,
        generation: GenerationId,
    },
    /// The region a repair lineage holds, named by the original it descends
    /// from.
    Lineage { root: TaskKey },
}

impl LeaseOwner {
    /// The task this holding is attributed to.
    pub fn key(self) -> TaskKey {
        match self {
            Self::Generation { key, .. } | Self::Candidate { key, .. } => key,
            Self::Lineage { root } => root,
        }
    }

    /// Whether this is the lineage holding, which no settlement ever changes.
    pub fn is_lineage(self) -> bool {
        matches!(self, Self::Lineage { .. })
    }
}

/// Whether two regions have any path in common.
///
/// [`PathSet::RepoWide`] overlaps everything, including another `RepoWide` and
/// including the empty region: it is the answer for a region nobody could read,
/// and the safe reading of an unread region is that it might be anywhere.
pub fn regions_overlap(left: &PathSet, right: &PathSet, policy: &PathPolicy) -> bool {
    match (left.prefixes(), right.prefixes()) {
        (None, _) | (_, None) => true,
        (Some(left), Some(right)) => left
            .iter()
            .any(|one| right.iter().any(|other| paths_overlap(one, other, policy))),
    }
}

/// Whether two paths name regions that contain one another.
///
/// Equal, ancestor, or descendant — decided component by component, so
/// `src/foo` neither contains nor is contained by `src/foobar` even though one
/// is a byte prefix of the other.
pub fn paths_overlap(left: &GitPath, right: &GitPath, policy: &PathPolicy) -> bool {
    let mut left = components(left);
    let mut right = components(right);
    loop {
        match (left.next(), right.next()) {
            // One list ran out while every component so far matched: the
            // shorter path is an ancestor of the longer one, or they are equal.
            (None, _) | (_, None) => return true,
            (Some(one), Some(other)) => {
                if !components_equal(one, other, policy.case_fold) {
                    return false;
                }
            }
        }
    }
}

/// A Git path's components, ignoring empty ones so that a trailing or doubled
/// separator cannot make two names of one directory look like two directories.
fn components(path: &GitPath) -> impl Iterator<Item = &str> {
    path.as_str().split('/').filter(|part| !part.is_empty())
}

/// Whether two path components name the same component.
///
/// Case-folded by Unicode simple lowercase rather than by ASCII alone: a
/// case-folding filesystem folds `Ü` the same way it folds `U`, and a
/// comparison that only folded ASCII would admit two tasks in parallel over one
/// file whose name is not written in it. Compared lazily so nothing allocates.
fn components_equal(left: &str, right: &str, case_fold: bool) -> bool {
    if !case_fold {
        return left == right;
    }
    let mut left = left.chars().flat_map(char::to_lowercase);
    let mut right = right.chars().flat_map(char::to_lowercase);
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (one, other) if one == other => {}
            _ => return false,
        }
    }
}

/// One lineage's holding, with the order it was created in.
///
/// The order is load-bearing: a lineage member's candidate is ineligible while
/// it overlaps an *older* lineage's lease, so that two lineages contending for
/// one region resolve in a fixed direction instead of taking turns blocking
/// each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageLease {
    pub root: TaskKey,
    pub paths: PathSet,
    /// Run-local creation ordinal, dense from 0.
    pub age: u32,
}

/// Every region this run currently holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaseTable {
    held: BTreeMap<LeaseOwner, PathSet>,
    lineages: Vec<LineageLease>,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a holding for `owner`, replacing any it already had.
    pub fn grant(&mut self, owner: LeaseOwner, paths: PathSet) {
        if let LeaseOwner::Lineage { root } = owner {
            let age = u32::try_from(self.lineages.len()).unwrap_or(u32::MAX);
            match self.lineages.iter_mut().find(|lease| lease.root == root) {
                Some(existing) => existing.paths = paths,
                None => self.lineages.push(LineageLease { root, paths, age }),
            }
            return;
        }
        self.held.insert(owner, paths);
    }

    /// Add `paths` to a lineage's holding. A lineage only ever grows.
    pub fn widen_lineage(&mut self, root: TaskKey, paths: &PathSet) {
        let widened = match self.lineages.iter().find(|lease| lease.root == root) {
            Some(existing) => union(&existing.paths, paths),
            None => paths.clone(),
        };
        self.grant(LeaseOwner::Lineage { root }, widened);
    }

    /// Give up a holding. Releasing one nobody holds is not an error: the
    /// caller is stating an outcome, not performing a bookkeeping operation.
    pub fn release(&mut self, owner: LeaseOwner) {
        if let LeaseOwner::Lineage { root } = owner {
            self.lineages.retain(|lease| lease.root != root);
            return;
        }
        self.held.remove(&owner);
    }

    pub fn holds(&self, owner: LeaseOwner) -> bool {
        match owner {
            LeaseOwner::Lineage { root } => self.lineage(root).is_some(),
            _ => self.held.contains_key(&owner),
        }
    }

    pub fn lineage(&self, root: TaskKey) -> Option<&LineageLease> {
        self.lineages.iter().find(|lease| lease.root == root)
    }

    pub fn lineages(&self) -> &[LineageLease] {
        &self.lineages
    }

    /// Whether any candidate or lineage holding is active — the two `Complete`
    /// refuses to leave behind.
    pub fn any_candidate_or_lineage(&self) -> bool {
        !self.lineages.is_empty()
            || self
                .held
                .keys()
                .any(|owner| matches!(owner, LeaseOwner::Candidate { .. }))
    }

    /// Whether `paths` collide with a holding belonging to anyone but `owner`.
    ///
    /// The dispatch check: an ordinary dispatch is blocked by any overlapping
    /// active lease of another owner, and a repair dispatch is never
    /// lease-blocked, which is the caller's distinction rather than this one's.
    pub fn overlaps_another(
        &self,
        owner: LeaseOwner,
        paths: &PathSet,
        policy: &PathPolicy,
    ) -> bool {
        self.held
            .iter()
            .any(|(held, region)| *held != owner && regions_overlap(region, paths, policy))
            || self.lineages.iter().any(|lease| {
                !matches!(owner, LeaseOwner::Lineage { root } if root == lease.root)
                    && regions_overlap(&lease.paths, paths, policy)
            })
    }

    /// Every lineage holding that collides with `paths`, oldest first.
    pub fn overlapping_lineages<'a>(
        &'a self,
        paths: &'a PathSet,
        policy: &'a PathPolicy,
    ) -> impl Iterator<Item = &'a LineageLease> {
        self.lineages
            .iter()
            .filter(move |lease| regions_overlap(&lease.paths, paths, policy))
    }
}

/// The region covering both, with `RepoWide` absorbing everything.
fn union(left: &PathSet, right: &PathSet) -> PathSet {
    let (Some(left), Some(right)) = (left.prefixes(), right.prefixes()) else {
        return PathSet::RepoWide;
    };
    let mut paths: Vec<GitPath> = left.to_vec();
    for path in right {
        if !paths.contains(path) {
            paths.push(path.clone());
        }
    }
    PathSet::Prefixes { paths }
}

/// What kind of holding a generation has, which is what decides the
/// dispositions its settlements may record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationLease {
    /// The generation's own predicted region, later replaced by its
    /// candidate's actual one.
    Own,
    /// A repair executes inside the lineage lease its root already holds and
    /// takes nothing of its own.
    InheritedLineage { root: TaskKey },
}

impl GenerationLease {
    /// The disposition an event must record, given whether the generation
    /// survives it.
    ///
    /// Total, and the whole of the rule. A repair never changes a lineage
    /// lease, so every one of its settlements records
    /// [`LeaseDisposition::LineageHeld`]. An ordinary generation holds a
    /// region of its own, so the disposition is exactly whether it still holds
    /// it: a settlement that closes the generation releases it, and one that
    /// leaves the generation open — an interruption, or the success that hands
    /// the region to the candidate — keeps it.
    pub fn expected(self, survives: bool) -> LeaseDisposition {
        match self {
            Self::InheritedLineage { .. } => LeaseDisposition::LineageHeld,
            Self::Own if survives => LeaseDisposition::PredictedRetained,
            Self::Own => LeaseDisposition::PredictedReleased,
        }
    }
}
