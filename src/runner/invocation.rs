//! The typed identity every Runner process carries.
//!
//! `decisions.admission_and_leases.permits.invocation_identity` **enumerates**
//! it, and the enumeration is the type:
//!
//! > InvocationId = (key, generation, attempt, role, ordinal) with role in
//! > {worker, gate(n), review_pass(n), review_reask(n)}, or (sequence, role,
//! > ordinal) with role in {gate(n), review_pass(n), review_reask(n)}, or
//! > (probe, target: Agent(name) | Shell, ordinal) at pre-flight (the shell
//! > probe is target Shell, non-slotted; agent probes are slotted); unique per
//! > process; a retry attempt has a new attempt number; **deterministic in the
//! > sequential substrate**; every RunnerRequest carries it
//!
//! Three closed forms, nine role/target members, and no fourth shape. The
//! properties follow from the shape rather than from a generator:
//!
//! * *unique per process* — distinct tuples render distinctly
//!   ([`InvocationId::render`] is injective; `distinct_tuples_render_distinctly`
//!   crosses every field).
//! * *a retry attempt has a new attempt number* — `attempt` is a field, so a
//!   retry that did not change it is a value equal to the one before it.
//! * *deterministic in the sequential substrate* — the rendering is a pure
//!   function of the tuple. Nothing here reads a clock, a pid, or a random
//!   source. This is load-bearing beyond fidelity: `crash_reconstruction`
//!   builds container names as
//!   `tactus-<repo_key>-<run_id>-<incarnation>-<invocation-hash>` "so
//!   **deterministic** InvocationIds never collide across incarnations and no
//!   earlier ownership evidence is overwritten".
//!
//! PR4 owns the type and its properties. **PR7 assigns them**:
//! `decisions.sequential_substrate.runner` — "RunnerRequest carries invocation:
//! InvocationId from PR4 (assigned by PR7, new per attempt)". No ledger, no
//! broker and no allocation policy lives here.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::TactusError;
use crate::runner::{AgentId, ProbeTarget};
use crate::topology::events::{AttemptNumber, GenerationId, SequenceId};
use crate::topology::registry::TaskKey;

/// The role of an invocation identified by `(key, generation, attempt, …)`.
///
/// The packet's first form: "role in {worker, gate(n), review_pass(n),
/// review_reask(n)}".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttemptRole {
    /// The worker process of this attempt.
    Worker,
    /// Gate `n` of this attempt's gate list.
    Gate(u32),
    /// Review pass `n`.
    ReviewPass(u32),
    /// Re-ask `n` of a review pass.
    ReviewReask(u32),
}

/// The role of an invocation identified by `(sequence, …)`.
///
/// The packet's second form: "role in {gate(n), review_pass(n),
/// review_reask(n)}" — **without** `worker`. A separate type rather than a
/// runtime check on [`AttemptRole`], because "a sequence has no worker" is then
/// a compile error at the call site instead of a refusal at run time. INV-20
/// draws the same line: "every completion is bound to (key, generation,
/// attempt) or (sequence, candidate)" — a sequence integrates candidates other
/// processes produced, so there is no worker of a sequence to identify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SequenceRole {
    /// Gate `n` of this integration transaction.
    Gate(u32),
    /// Review pass `n`.
    ReviewPass(u32),
    /// Re-ask `n` of a review pass.
    ReviewReask(u32),
}

impl AttemptRole {
    /// The token this role renders as.
    const fn token(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Gate(_) => "gate",
            Self::ReviewPass(_) => "review_pass",
            Self::ReviewReask(_) => "review_reask",
        }
    }

    fn render(self) -> String {
        match self {
            Self::Worker => self.token().to_owned(),
            Self::Gate(n) | Self::ReviewPass(n) | Self::ReviewReask(n) => {
                format!("{}{n}", self.token())
            }
        }
    }

    fn parse(text: &str) -> Option<Self> {
        if text == "worker" {
            return Some(Self::Worker);
        }
        let indexed = SequenceRole::parse(text)?;
        Some(match indexed {
            SequenceRole::Gate(n) => Self::Gate(n),
            SequenceRole::ReviewPass(n) => Self::ReviewPass(n),
            SequenceRole::ReviewReask(n) => Self::ReviewReask(n),
        })
    }
}

impl SequenceRole {
    /// The token this role renders as.
    const fn token(self) -> &'static str {
        match self {
            Self::Gate(_) => "gate",
            Self::ReviewPass(_) => "review_pass",
            Self::ReviewReask(_) => "review_reask",
        }
    }

    fn render(self) -> String {
        match self {
            Self::Gate(n) | Self::ReviewPass(n) | Self::ReviewReask(n) => {
                format!("{}{n}", self.token())
            }
        }
    }

    fn parse(text: &str) -> Option<Self> {
        // Longest token first: `review_pass` and `review_reask` share no
        // prefix, but `gate` must not swallow a token that merely starts the
        // same way if one is ever added.
        for (token, build) in [
            ("review_pass", Self::ReviewPass as fn(u32) -> Self),
            ("review_reask", Self::ReviewReask as fn(u32) -> Self),
            ("gate", Self::Gate as fn(u32) -> Self),
        ] {
            if let Some(rest) = text.strip_prefix(token) {
                return rest.parse::<u32>().ok().map(build);
            }
        }
        None
    }
}

/// The identity of one Runner process — one of the packet's three forms.
///
/// A closed enumeration rather than a string, because the value is a key in
/// four separate ledgers (R3's slot pairs, R4's invocation registrations, PR6's
/// container names and intent paths, PR7's completion identity check) and
/// because every property the packet states about it is a property of the
/// tuple. An opaque string can hold a value no form describes; this cannot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvocationId {
    /// `(key, generation, attempt, role, ordinal)`.
    Attempt {
        key: TaskKey,
        generation: GenerationId,
        attempt: AttemptNumber,
        role: AttemptRole,
        /// Which invocation of this role within this attempt, dense from 0. The
        /// role index says *which* gate; the ordinal says which run of it, so a
        /// re-dispatch inside one attempt is a new identity rather than a
        /// reused one.
        ordinal: u32,
    },
    /// `(sequence, role, ordinal)`.
    Sequence {
        sequence: SequenceId,
        role: SequenceRole,
        ordinal: u32,
    },
    /// `(probe, target: Agent(name) | Shell, ordinal)` at pre-flight.
    Probe {
        target: ProbeTarget,
        /// Which pre-flight this is. Probe identities repeat across
        /// incarnations by construction — the packet says so, and says how it
        /// is handled: "because probe identities repeat across incarnations,
        /// every container name and intent path additionally carries the
        /// coordinator incarnation id".
        ordinal: u32,
    },
}

/// The generation the legacy sequential engine assigns.
///
/// The contract's `invariants_introduced[1]` is "legacy engine assigns
/// legacy-scoped values". The legacy engine has no generations — it never
/// re-dispatches a task from a fresh worktree — so every value it assigns sits
/// in generation 0 and says so through [`InvocationId::legacy_attempt`]. The
/// scope is real rather than decorative: a legacy run is schema-1..3 and a
/// generation-bearing run is schema-4, and no run changes schema between
/// epochs (INV-23), so the two never share a ledger.
pub const LEGACY_GENERATION: GenerationId = GenerationId(0);

/// The longest value the enumeration can render.
///
/// Not a policy number: it is the maximum of [`InvocationId::render`] over the
/// whole domain, which `the_longest_value_the_domain_can_render_is_the_limit`
/// computes from `u32::MAX` and the longest role token. Deriving it this way is
/// what stops the validator refusing a value the domain contains — the failure
/// mode a hand-picked limit has. The only construction it can therefore refuse
/// is an over-long agent name in the probe form.
pub const MAX_LEN: usize = 70;

/// Every character a rendered id may carry.
///
/// PR6 puts this value inside a container name and inside the file name
/// `<R>/containers/<name>.intent` (`decisions.pr_sequence[7].scope`), so a
/// value carrying a path separator, a space, or a control character is a value
/// that names a different file than the one the record says. `.` is the field
/// separator, so no component may contain one.
const SEPARATOR: char = '.';

impl InvocationId {
    /// `(key, generation, attempt, role, ordinal)`.
    #[must_use]
    pub const fn attempt(
        key: TaskKey,
        generation: GenerationId,
        attempt: AttemptNumber,
        role: AttemptRole,
        ordinal: u32,
    ) -> Self {
        Self::Attempt {
            key,
            generation,
            attempt,
            role,
            ordinal,
        }
    }

    /// `(key, generation, attempt, role, ordinal)` in the legacy engine's
    /// generation. See [`LEGACY_GENERATION`].
    #[must_use]
    pub const fn legacy_attempt(
        key: TaskKey,
        attempt: AttemptNumber,
        role: AttemptRole,
        ordinal: u32,
    ) -> Self {
        Self::attempt(key, LEGACY_GENERATION, attempt, role, ordinal)
    }

    /// `(sequence, role, ordinal)`.
    #[must_use]
    pub const fn sequence(sequence: SequenceId, role: SequenceRole, ordinal: u32) -> Self {
        Self::Sequence {
            sequence,
            role,
            ordinal,
        }
    }

    /// `(probe, target, ordinal)`.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when the target names an agent whose id
    /// carries a character outside `[0-9A-Za-z_-]`, or is long enough to push
    /// the rendering past [`MAX_LEN`]. Every other form is infallible: its
    /// fields are integers, and their longest rendering *is* [`MAX_LEN`].
    pub fn probe(target: ProbeTarget, ordinal: u32) -> Result<Self, TactusError> {
        // The *component*, not only the whole rendering. `.` is inside the
        // charset the whole value is checked against, so an agent named
        // `claude.code` would render a value that passes `validate` and yet
        // splits into four components no form has — writable and unreadable.
        if let ProbeTarget::Agent(agent) = &target {
            let name = agent.as_str();
            if name.is_empty() {
                return Err(TactusError::Refused {
                    message: "a probe target names an agent, and an agent id is never empty"
                        .to_owned(),
                });
            }
            if let Some(bad) = name
                .chars()
                .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-')))
            {
                return Err(TactusError::Refused {
                    message: format!(
                        "agent id `{name}` carries `{bad}`; a probe identity renders it as one \
                         field of `p.agent-<id>.o<n>`, so it may not carry the `{SEPARATOR}` \
                         separator or anything outside [0-9A-Za-z_-]"
                    ),
                });
            }
        }
        let id = Self::Probe { target, ordinal };
        validate(&id.render())?;
        Ok(id)
    }

    /// The value as it is recorded: injective over the whole domain.
    ///
    /// The grammar, one line per form:
    ///
    /// ```text
    /// k<key>.g<generation>.a<attempt>.<role>.o<ordinal>
    /// s<sequence>.<role>.o<ordinal>
    /// p.shell.o<ordinal>   |   p.agent-<id>.o<ordinal>
    /// ```
    ///
    /// The leading component is `k…`, `s…` or `p`, which no other form can
    /// produce, so the forms are disjoint; within a form the component count is
    /// fixed and no component may contain the separator, so two distinct tuples
    /// differ in some component and therefore in the rendering.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Attempt {
                key,
                generation,
                attempt,
                role,
                ordinal,
            } => format!(
                "k{}.g{}.a{}.{}.o{ordinal}",
                key.0,
                generation.0,
                attempt.0,
                role.render()
            ),
            Self::Sequence {
                sequence,
                role,
                ordinal,
            } => format!("s{}.{}.o{ordinal}", sequence.0, role.render()),
            Self::Probe { target, ordinal } => {
                let target = match target {
                    ProbeTarget::Shell => "shell".to_owned(),
                    ProbeTarget::Agent(agent) => format!("agent-{agent}"),
                };
                format!("p.{target}.o{ordinal}")
            }
        }
    }

    /// Rebuild a recorded identity.
    ///
    /// The domain is closed on the way back in as well as on the way out: a
    /// value that is not one of the three forms is refused rather than carried
    /// as an opaque string, so a record cannot smuggle a fourth shape into a
    /// ledger keyed by this type.
    ///
    /// # Errors
    ///
    /// [`TactusError::Refused`] when `value` is not the rendering of any tuple.
    pub fn parse(value: &str) -> Result<Self, TactusError> {
        validate(value)?;
        parse_forms(value).ok_or_else(|| TactusError::Refused {
            message: format!(
                "`{value}` is not an invocation id: the identity is (key, generation, attempt, \
                 role, ordinal), (sequence, role, ordinal), or (probe, target, ordinal) \
                 (decisions.admission_and_leases.permits.invocation_identity), rendered \
                 `k<key>.g<gen>.a<attempt>.<role>.o<n>`, `s<seq>.<role>.o<n>`, or \
                 `p.shell.o<n>` / `p.agent-<id>.o<n>`"
            ),
        })
    }

    /// The probe target, when this identity is a pre-flight probe.
    ///
    /// INV-18 accounts the two targets differently — "every agent CLI
    /// invocation incl. agent probes acquires its atomic {agent, pool?} pair
    /// while gates and the shell probe register without slots" — so the target
    /// is readable from the identity and not only from the request's role.
    #[must_use]
    pub const fn probe_target(&self) -> Option<&ProbeTarget> {
        match self {
            Self::Probe { target, .. } => Some(target),
            Self::Attempt { .. } | Self::Sequence { .. } => None,
        }
    }
}

/// Refuse a rendering no funnel could have written.
fn validate(value: &str) -> Result<(), TactusError> {
    if value.is_empty() {
        return Err(TactusError::Refused {
            message: "an invocation id is never empty: every Runner process carries one (INV-20)"
                .to_owned(),
        });
    }
    if value.len() > MAX_LEN {
        return Err(TactusError::Refused {
            message: format!(
                "invocation id `{value}` is {} bytes; the limit is {MAX_LEN}, the longest value \
                 the identity's own enumeration can render, and the value names a container and \
                 an intent file",
                value.len()
            ),
        });
    }
    if let Some(bad) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        return Err(TactusError::Refused {
            message: format!(
                "invocation id `{value}` carries `{bad}`, which is outside [0-9A-Za-z._-]; the \
                 value names a container and an intent file, so it may not carry a path \
                 separator or a control character"
            ),
        });
    }
    Ok(())
}

/// The inverse of [`InvocationId::render`], or `None`.
fn parse_forms(value: &str) -> Option<InvocationId> {
    let parts: Vec<&str> = value.split(SEPARATOR).collect();
    match parts.as_slice() {
        ["p", target, ordinal] => {
            let target = if *target == "shell" {
                ProbeTarget::Shell
            } else {
                let name = target.strip_prefix("agent-")?;
                if name.is_empty()
                    || name
                        .contains(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-')))
                {
                    return None;
                }
                ProbeTarget::Agent(AgentId::new(name))
            };
            Some(InvocationId::Probe {
                target,
                ordinal: field(ordinal, "o")?,
            })
        }
        [sequence, role, ordinal] => Some(InvocationId::Sequence {
            sequence: SequenceId(field(sequence, "s")?),
            role: SequenceRole::parse(role)?,
            ordinal: field(ordinal, "o")?,
        }),
        [key, generation, attempt, role, ordinal] => Some(InvocationId::Attempt {
            key: TaskKey(field(key, "k")?),
            generation: GenerationId(field(generation, "g")?),
            attempt: AttemptNumber(field(attempt, "a")?),
            role: AttemptRole::parse(role)?,
            ordinal: field(ordinal, "o")?,
        }),
        _ => None,
    }
}

/// One `<tag><digits>` component. Rejects a leading `+`, a leading zero on a
/// multi-digit number, and anything else `u32::from_str` would accept but
/// `render` would never produce, so `parse ∘ render` is a bijection and not
/// merely a left inverse.
fn field(component: &str, tag: &str) -> Option<u32> {
    let digits = component.strip_prefix(tag)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

impl fmt::Display for InvocationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl Serialize for InvocationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.render())
    }
}

impl<'de> Deserialize<'de> for InvocationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    // -----------------------------------------------------------------------
    // the grid, and what bounds it
    // -----------------------------------------------------------------------
    //
    // Every numeric field is a `u32`, so no grid can be exhaustive. What a grid
    // has to catch is a rendering that *drops* a field, *conflates* two, or
    // loses a separator. Dropping and conflation are caught by a full Cartesian
    // product in which every field varies independently — if the rendering is a
    // function of fewer fields than the tuple has, two grid points collide.
    // Three values per field is the smallest set that also distinguishes "uses
    // the value" from "uses whether the value is zero". A lost separator is a
    // different defect (adjacent fields concatenate), so it gets its own table
    // of pairs chosen to collide under exactly that mutation.

    const KEYS: [u32; 3] = [0, 1, 12];
    const GENERATIONS: [u32; 3] = [0, 2, 13];
    const ATTEMPTS: [u32; 3] = [1, 3, 14];
    const SEQUENCES: [u32; 3] = [0, 1, 12];
    const ORDINALS: [u32; 3] = [0, 5, 15];
    const ROLE_INDEXES: [u32; 3] = [0, 1, 11];
    const AGENTS: [&str; 3] = ["claude-code", "copilot", "codex"];

    fn attempt_roles() -> Vec<AttemptRole> {
        let mut roles = vec![AttemptRole::Worker];
        for n in ROLE_INDEXES {
            roles.push(AttemptRole::Gate(n));
            roles.push(AttemptRole::ReviewPass(n));
            roles.push(AttemptRole::ReviewReask(n));
        }
        roles
    }

    fn sequence_roles() -> Vec<SequenceRole> {
        let mut roles = Vec::new();
        for n in ROLE_INDEXES {
            roles.push(SequenceRole::Gate(n));
            roles.push(SequenceRole::ReviewPass(n));
            roles.push(SequenceRole::ReviewReask(n));
        }
        roles
    }

    fn probe_targets() -> Vec<ProbeTarget> {
        let mut targets = vec![ProbeTarget::Shell];
        for agent in AGENTS {
            targets.push(ProbeTarget::Agent(AgentId::new(agent)));
        }
        targets
    }

    /// Every identity the grid describes.
    fn grid() -> Vec<InvocationId> {
        let mut ids = Vec::new();
        for key in KEYS {
            for generation in GENERATIONS {
                for attempt in ATTEMPTS {
                    for role in attempt_roles() {
                        for ordinal in ORDINALS {
                            ids.push(InvocationId::attempt(
                                TaskKey(key),
                                GenerationId(generation),
                                AttemptNumber(attempt),
                                role,
                                ordinal,
                            ));
                        }
                    }
                }
            }
        }
        for sequence in SEQUENCES {
            for role in sequence_roles() {
                for ordinal in ORDINALS {
                    ids.push(InvocationId::sequence(SequenceId(sequence), role, ordinal));
                }
            }
        }
        for target in probe_targets() {
            for ordinal in ORDINALS {
                ids.push(InvocationId::probe(target.clone(), ordinal).expect("a probe identity"));
            }
        }
        ids
    }

    /// The grid's size, computed from the grid's *definition* — the product of
    /// the dimensions — so a renderer that lost a field cannot also lower the
    /// number it is compared against.
    const fn grid_size() -> usize {
        let attempt_form = KEYS.len() * GENERATIONS.len() * ATTEMPTS.len() * 10 * ORDINALS.len();
        let sequence_form = SEQUENCES.len() * 9 * ORDINALS.len();
        let probe_form = 4 * ORDINALS.len();
        attempt_form + sequence_form + probe_form
    }

    #[test]
    fn the_grid_varies_every_field_independently() {
        // Fixture hostility as a distinct-value count, per field, not as prose.
        assert_eq!(BTreeSet::from(KEYS).len(), 3);
        assert_eq!(BTreeSet::from(GENERATIONS).len(), 3);
        assert_eq!(BTreeSet::from(ATTEMPTS).len(), 3);
        assert_eq!(BTreeSet::from(SEQUENCES).len(), 3);
        assert_eq!(BTreeSet::from(ORDINALS).len(), 3);
        assert_eq!(BTreeSet::from(ROLE_INDEXES).len(), 3);
        assert_eq!(BTreeSet::from(AGENTS).len(), 3);
        assert_eq!(attempt_roles().len(), 10, "worker + 3 indexed roles x 3");
        assert_eq!(
            attempt_roles().iter().collect::<BTreeSet<_>>().len(),
            10,
            "ten distinct roles, not ten values of one"
        );
        assert_eq!(sequence_roles().len(), 9, "3 indexed roles x 3, no worker");
        assert_eq!(probe_targets().len(), 4, "shell + one per agent");
        assert_eq!(grid().len(), grid_size());
        assert_eq!(grid_size(), 903);
    }

    /// The packet enumerates nine role/target members across the three forms:
    /// four attempt roles, three sequence roles (no worker), two probe targets.
    #[test]
    fn the_enumeration_has_exactly_the_nine_members_the_packet_names() {
        let attempt: BTreeSet<&'static str> = [
            AttemptRole::Worker,
            AttemptRole::Gate(0),
            AttemptRole::ReviewPass(0),
            AttemptRole::ReviewReask(0),
        ]
        .iter()
        .map(|role| role.token())
        .collect();
        assert_eq!(
            attempt,
            BTreeSet::from(["worker", "gate", "review_pass", "review_reask"]),
            "form 1: role in {{worker, gate(n), review_pass(n), review_reask(n)}}"
        );
        let sequence: BTreeSet<&'static str> = [
            SequenceRole::Gate(0),
            SequenceRole::ReviewPass(0),
            SequenceRole::ReviewReask(0),
        ]
        .iter()
        .map(|role| role.token())
        .collect();
        assert_eq!(
            sequence,
            BTreeSet::from(["gate", "review_pass", "review_reask"]),
            "form 2: role in {{gate(n), review_pass(n), review_reask(n)}} — no worker"
        );
        assert!(
            !sequence.contains("worker"),
            "a sequence has no worker; INV-20 binds it to (sequence, candidate)"
        );
        let targets: BTreeSet<String> = probe_targets()
            .iter()
            .map(|target| InvocationId::Probe {
                target: target.clone(),
                ordinal: 0,
            })
            .map(|id| id.render())
            .collect();
        assert_eq!(targets.len(), 4, "form 3: Shell plus one Agent(name) each");
        assert_eq!(attempt.len() + sequence.len() + 2, 9, "nine members");
    }

    /// Expected values written by hand from the packet's field order, never
    /// from `render`. A rendering that reordered, dropped, or re-spelled a
    /// field fails here even if it stayed injective.
    #[test]
    fn the_three_forms_render_as_the_packet_spells_them() {
        let table: Vec<(InvocationId, &str)> = vec![
            (
                InvocationId::attempt(
                    TaskKey(7),
                    GenerationId(2),
                    AttemptNumber(3),
                    AttemptRole::Worker,
                    0,
                ),
                "k7.g2.a3.worker.o0",
            ),
            (
                InvocationId::attempt(
                    TaskKey(0),
                    GenerationId(0),
                    AttemptNumber(1),
                    AttemptRole::Gate(4),
                    1,
                ),
                "k0.g0.a1.gate4.o1",
            ),
            (
                InvocationId::attempt(
                    TaskKey(12),
                    GenerationId(1),
                    AttemptNumber(2),
                    AttemptRole::ReviewPass(0),
                    5,
                ),
                "k12.g1.a2.review_pass0.o5",
            ),
            (
                InvocationId::attempt(
                    TaskKey(3),
                    GenerationId(9),
                    AttemptNumber(4),
                    AttemptRole::ReviewReask(2),
                    0,
                ),
                "k3.g9.a4.review_reask2.o0",
            ),
            (
                InvocationId::sequence(SequenceId(0), SequenceRole::Gate(1), 0),
                "s0.gate1.o0",
            ),
            (
                InvocationId::sequence(SequenceId(11), SequenceRole::ReviewPass(2), 3),
                "s11.review_pass2.o3",
            ),
            (
                InvocationId::sequence(SequenceId(4), SequenceRole::ReviewReask(0), 1),
                "s4.review_reask0.o1",
            ),
            (
                InvocationId::probe(ProbeTarget::Shell, 0).expect("shell probe"),
                "p.shell.o0",
            ),
            (
                InvocationId::probe(ProbeTarget::Agent(AgentId::new("claude-code")), 2)
                    .expect("agent probe"),
                "p.agent-claude-code.o2",
            ),
        ];
        assert_eq!(table.len(), 9, "every form, and every role token, once");
        for (id, expected) in &table {
            assert_eq!(&id.render(), expected, "{id:?}");
            assert_eq!(&id.to_string(), expected, "Display and render disagree");
        }
    }

    #[test]
    fn distinct_tuples_render_distinctly() {
        let ids = grid();
        let rendered: BTreeSet<String> = ids.iter().map(InvocationId::render).collect();
        assert_eq!(
            rendered.len(),
            grid_size(),
            "two distinct identities rendered the same value"
        );
        // Uniqueness within a run is therefore structural: it does not depend
        // on a generator not colliding, and no expected value here came from
        // the constructor.
        let tuples: BTreeSet<&InvocationId> = ids.iter().collect();
        assert_eq!(
            tuples.len(),
            grid_size(),
            "the grid built a duplicate tuple"
        );
    }

    /// A lost separator concatenates two adjacent fields. Each pair below is
    /// two distinct tuples whose renderings become equal under exactly that
    /// mutation, so the pair fails the moment a `.` is dropped.
    #[test]
    fn adjacent_fields_cannot_be_confused_for_one() {
        let pairs: Vec<(InvocationId, InvocationId)> = vec![
            (
                InvocationId::attempt(
                    TaskKey(1),
                    GenerationId(12),
                    AttemptNumber(1),
                    AttemptRole::Worker,
                    1,
                ),
                InvocationId::attempt(
                    TaskKey(11),
                    GenerationId(2),
                    AttemptNumber(1),
                    AttemptRole::Worker,
                    1,
                ),
            ),
            (
                InvocationId::attempt(
                    TaskKey(1),
                    GenerationId(1),
                    AttemptNumber(23),
                    AttemptRole::Gate(1),
                    4,
                ),
                InvocationId::attempt(
                    TaskKey(1),
                    GenerationId(1),
                    AttemptNumber(2),
                    AttemptRole::Gate(31),
                    4,
                ),
            ),
            (
                InvocationId::sequence(SequenceId(1), SequenceRole::Gate(23), 4),
                InvocationId::sequence(SequenceId(1), SequenceRole::Gate(2), 34),
            ),
            (
                InvocationId::probe(ProbeTarget::Agent(AgentId::new("shell")), 0)
                    .expect("an agent may be called anything the charset allows"),
                InvocationId::probe(ProbeTarget::Shell, 0).expect("the shell probe"),
            ),
        ];
        assert_eq!(pairs.len(), 4);
        for (left, right) in pairs {
            assert_ne!(left, right, "the pair is two tuples, not one");
            assert_ne!(
                left.render(),
                right.render(),
                "{left:?} and {right:?} render the same value"
            );
        }
    }

    /// [`MAX_LEN`] is the domain's own maximum, so the validator can never
    /// refuse a value the enumeration can produce.
    #[test]
    fn the_longest_value_the_domain_can_render_is_the_limit() {
        let longest = InvocationId::attempt(
            TaskKey(u32::MAX),
            GenerationId(u32::MAX),
            AttemptNumber(u32::MAX),
            AttemptRole::ReviewReask(u32::MAX),
            u32::MAX,
        );
        // Written out rather than computed: `k` + 10 digits, `.g` + 10, `.a` +
        // 10, `.review_reask` + 10, `.o` + 10.
        assert_eq!(
            longest.render(),
            "k4294967295.g4294967295.a4294967295.review_reask4294967295.o4294967295"
        );
        assert_eq!(longest.render().len(), 70);
        assert_eq!(
            MAX_LEN, 70,
            "the limit is that maximum, not a policy number"
        );
        for id in grid() {
            let rendered = id.render();
            assert!(rendered.len() <= MAX_LEN, "{rendered} is over the limit");
            validate(&rendered).expect("every value the domain renders is a valid value");
        }
    }

    /// "deterministic in the sequential substrate" — the rendering is a pure
    /// function of the tuple, so the same identity built twice is the same
    /// value. A ULID, a pid, or a counter fails this.
    #[test]
    fn the_same_tuple_always_renders_the_same_value() {
        let build = || {
            InvocationId::attempt(
                TaskKey(3),
                GenerationId(1),
                AttemptNumber(2),
                AttemptRole::Gate(0),
                0,
            )
        };
        let first = build();
        // Work between the two constructions, so anything reading a clock or a
        // monotonic nonce has had the chance to move.
        let mut noise = 0u64;
        for i in 0..100_000u64 {
            noise = noise.wrapping_add(i);
        }
        assert!(noise > 0);
        let second = build();
        assert_eq!(first, second);
        assert_eq!(first.render(), second.render());
        assert_eq!(first.render(), "k3.g1.a2.gate0.o0");
    }

    /// "a retry attempt has a new attempt number".
    #[test]
    fn a_retry_is_a_new_attempt_number_and_a_new_identity() {
        let attempts: Vec<InvocationId> = (1..=5)
            .map(|n| {
                InvocationId::attempt(
                    TaskKey(2),
                    GenerationId(0),
                    AttemptNumber(n),
                    AttemptRole::Worker,
                    0,
                )
            })
            .collect();
        let rendered: BTreeSet<String> = attempts.iter().map(InvocationId::render).collect();
        assert_eq!(rendered.len(), 5, "five attempts, five identities");
        assert_eq!(
            attempts[0].render(),
            "k2.g0.a1.worker.o0",
            "the first attempt is attempt 1: AttemptNumber is dense from 1"
        );
        assert_eq!(attempts[4].render(), "k2.g0.a5.worker.o0");
    }

    #[test]
    fn parse_is_the_inverse_of_render_over_the_whole_grid() {
        for id in grid() {
            let rendered = id.render();
            let read = InvocationId::parse(&rendered)
                .unwrap_or_else(|error| panic!("`{rendered}` did not parse: {error}"));
            assert_eq!(read, id, "`{rendered}` parsed to a different tuple");
        }
    }

    /// The domain is closed on the way in. Every value here is one a reader
    /// might plausibly be handed — including the opaque forms this type used to
    /// accept.
    #[test]
    fn parse_refuses_what_no_form_can_render() {
        for bad in [
            "",
            "legacy-t1-a2",               // the old open-ended scope form
            "01K3Q9V0Z3B8N9RJ4F2A6C7D8E", // a ULID
            "k1.g1.a1.worker",            // a field short
            "k1.g1.a1.worker.o1.x2",      // a field long
            "k1.g1.a1.boss.o1",           // a role outside the enumeration
            "s1.worker.o1",               // worker is not a sequence role
            "k1.g1.a1.gate.o1",           // an indexed role without its index
            "x1.g1.a1.worker.o1",         // an unknown form tag
            "k1.g1.a1.worker.1",          // an untagged field
            "k01.g1.a1.worker.o1",        // a leading zero render never writes
            "k+1.g1.a1.worker.o1",
            "k1.g1.a1.worker.o4294967296", // past u32
            "p.agent-.o1",                 // an empty agent name
            "p.agent-a b.o1",              // outside the charset
            "p.shell.o1.o2",
            "has/slash",
            "has space",
        ] {
            assert!(
                InvocationId::parse(bad).is_err(),
                "`{bad}` was accepted as an invocation id"
            );
        }
    }

    #[test]
    fn probe_refuses_a_target_that_would_not_survive_a_container_name() {
        assert!(InvocationId::probe(ProbeTarget::Agent(AgentId::new("claude.code")), 0).is_err());
        assert!(InvocationId::probe(ProbeTarget::Agent(AgentId::new("a/b")), 0).is_err());
        assert!(InvocationId::probe(ProbeTarget::Agent(AgentId::new("")), 0).is_err());
        // `p.agent-<name>.o<ordinal>` spends `p`, two separators, `agent-`,
        // `o` and up to ten ordinal digits: 1 + 1 + 6 + 1 + 1 + 10 = 20. So
        // MAX_LEN leaves exactly 50 characters for the name, and the boundary
        // is asserted on both sides rather than described.
        let longest = "a".repeat(50);
        assert!(InvocationId::probe(ProbeTarget::Agent(AgentId::new(&longest)), u32::MAX).is_ok());
        assert_eq!(
            InvocationId::probe(ProbeTarget::Agent(AgentId::new(&longest)), u32::MAX)
                .expect("the longest nameable agent")
                .render()
                .len(),
            MAX_LEN
        );
        let over = "a".repeat(51);
        assert!(InvocationId::probe(ProbeTarget::Agent(AgentId::new(&over)), u32::MAX).is_err());
    }

    /// The wire form is the bare rendered string, pinned against payloads
    /// written here rather than against this type's own output.
    #[test]
    fn the_wire_form_is_the_bare_string() {
        let id = InvocationId::attempt(
            TaskKey(4),
            GenerationId(0),
            AttemptNumber(2),
            AttemptRole::ReviewPass(1),
            0,
        );
        assert_eq!(
            serde_json::to_string(&id).expect("serialize"),
            "\"k4.g0.a2.review_pass1.o0\""
        );
        let read: InvocationId =
            serde_json::from_str("\"k4.g0.a2.review_pass1.o0\"").expect("deserialize");
        assert_eq!(read, id);
        let probe: InvocationId = serde_json::from_str("\"p.shell.o0\"").expect("deserialize");
        assert_eq!(probe.probe_target(), Some(&ProbeTarget::Shell));
        // A value outside the enumeration does not become an InvocationId by
        // being written into a record.
        assert!(serde_json::from_str::<InvocationId>("\"legacy-t1-a2\"").is_err());
    }

    #[test]
    fn legacy_values_sit_in_the_legacy_generation() {
        let id = InvocationId::legacy_attempt(TaskKey(5), AttemptNumber(2), AttemptRole::Worker, 0);
        assert_eq!(id.render(), "k5.g0.a2.worker.o0");
        assert_eq!(LEGACY_GENERATION, GenerationId(0));
        let InvocationId::Attempt { generation, .. } = id else {
            panic!("the legacy engine assigns the attempt form");
        };
        assert_eq!(generation, LEGACY_GENERATION);
    }

    #[test]
    fn only_a_probe_identity_has_a_target() {
        assert_eq!(
            InvocationId::probe(ProbeTarget::Shell, 0)
                .expect("shell")
                .probe_target(),
            Some(&ProbeTarget::Shell)
        );
        assert_eq!(
            InvocationId::attempt(
                TaskKey(0),
                GenerationId(0),
                AttemptNumber(1),
                AttemptRole::Worker,
                0
            )
            .probe_target(),
            None
        );
        assert_eq!(
            InvocationId::sequence(SequenceId(0), SequenceRole::Gate(0), 0).probe_target(),
            None
        );
    }
}
