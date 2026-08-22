//! Resolution, canonical serialization and the digest of the run's
//! [`RunnerPolicy`] (INV-23).
//!
//! ## One record, not two
//!
//! The wire type is PR3's [`crate::topology::events::RunnerPolicy`], shipped
//! for `run_started(4).runner`. This module deliberately does not define a
//! second one. INV-23's enforcement is an **exact-equality** check across four
//! copies of one record — the marker digest (P1), `owner.json.runner` (P3b),
//! `run_started(4).runner` (P6) and `run_resumed(4).runner` — and
//! `decisions.pr_sequence[5].scope` names the digest that binds them:
//! "canonical serialization and `runner_policy_sha256`". Two Rust definitions
//! of one record are two things that drift, and the fold's `difference()`
//! would compare a record against itself while the *other* definition moved.
//!
//! So: `topology::events` owns the shape and the equality; this module owns
//! **resolution**, **canonicalisation** and **the digest** over that shape.
//!
//! ## Why a hand-rolled encoding rather than `serde_json`
//!
//! The digest goes into the P1 marker and into every container intent
//! (`decisions.pr_sequence[7].scope`: "owner run, run directory, incarnation,
//! repo key, invocation, `runner_policy_sha256`"), so it is compared across
//! processes and across binary versions. `serde_json` does not promise a
//! stable byte sequence for a map, and a field renamed on the wire would move
//! the digest silently. A length-prefixed encoding written out field by field
//! is injective by construction and can be written by hand in a test — which
//! is the only way to pin an encoding against something other than itself.

use sha2::{Digest, Sha256};

use crate::error::TactusError;
use crate::topology::events::{RunnerContract, RunnerKind, RunnerPolicy};

/// The version tag the canonical encoding opens with.
///
/// Part of the digested bytes, so a future encoding change is a different
/// digest rather than the same digest over different bytes.
pub const CANONICAL_VERSION: &str = "tactus.runner-policy.v1";

/// The host runner's resolved policy: `RunnerPolicy{kind: Host, policy:
/// host-v1, image: None, credential_volumes: None}`.
///
/// INV-23 requires resolution "by read-only inspection before the worktree
/// lock (… the runtime must already hold the image and the volumes must
/// exist)". For the host there is nothing to inspect: the boundary is this
/// process's own machine, there is no image and there are no credential
/// volumes — `image` and `credential_volumes` are `None` because a host
/// runner carrying either is [`RunnerRecordDefect::HostWithContainerFields`],
/// which PR3's `completeness()` already refuses. The inspection that can fail
/// is the container runner's, and that is PR6.
///
/// [`RunnerRecordDefect::HostWithContainerFields`]:
///     crate::topology::events::RunnerRecordDefect::HostWithContainerFields
#[must_use]
pub fn host_policy() -> RunnerPolicy {
    RunnerPolicy {
        kind: RunnerKind::Host,
        policy: RunnerContract::HostV1,
        image: None,
        credential_volumes: None,
    }
}

/// Resolve the host runner's policy, refusing a record PR3 would call
/// incomplete.
///
/// The check is not decorative: this value is written into the marker, the
/// owner record and `run_started(4)`, and the fold refuses an incomplete one
/// on the way back in. Refusing here means a run cannot start with a record
/// its own resume would reject.
///
/// # Errors
///
/// [`TactusError::Refused`] if the resolved record is not complete.
pub fn resolve_host() -> Result<RunnerPolicy, TactusError> {
    let policy = host_policy();
    policy
        .completeness()
        .map_err(|defect| TactusError::Refused {
            message: format!("the host runner resolved an unusable RunnerPolicy: {defect}"),
        })?;
    Ok(policy)
}

/// The canonical bytes of `policy`.
///
/// Field order and shape, written out because a test has to be able to
/// reproduce them by hand:
///
/// ```text
/// f("tactus.runner-policy.v1")
/// f(kind)                  "host" | "container"
/// f(policy)                "host-v1" | "container-v1"
/// b(image.is_some)
///     f(image.reference) f(image.id) b(image.digest.is_some) [f(image.digest)]
/// b(credential_volumes.is_some)
///     n(len) [ f(agent) f(volume) ]*     in the map's own (sorted) order
/// ```
///
/// where `f(s)` is `<byte-length>:<bytes>;`, `b(x)` is `f("1")` or `f("0")`,
/// and `n(x)` is `f(<decimal>)`. The same encoding
/// [`crate::topology::registry`] uses, for the same reason: a length prefix is
/// injective over values that may contain the delimiter.
#[must_use]
pub fn canonical_bytes(policy: &RunnerPolicy) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, CANONICAL_VERSION);
    field(&mut out, kind_tag(policy.kind));
    field(&mut out, contract_tag(policy.policy));
    match &policy.image {
        Some(image) => {
            flag(&mut out, true);
            field(&mut out, &image.reference);
            field(&mut out, &image.id);
            match &image.digest {
                Some(digest) => {
                    flag(&mut out, true);
                    field(&mut out, digest);
                }
                None => flag(&mut out, false),
            }
        }
        None => flag(&mut out, false),
    }
    match &policy.credential_volumes {
        Some(volumes) => {
            flag(&mut out, true);
            field(&mut out, &volumes.len().to_string());
            for (agent, volume) in volumes {
                field(&mut out, agent);
                field(&mut out, volume);
            }
        }
        None => flag(&mut out, false),
    }
    out
}

/// `sha256:<hex>` over [`canonical_bytes`].
///
/// The `sha256:<hex>` shape rather than a bare hex string, matching the
/// registry digest and the normalized plan digest, "so a log carries one shape
/// of digest rather than two" ([`crate::topology::registry`]).
#[must_use]
pub fn runner_policy_sha256(policy: &RunnerPolicy) -> String {
    format!("sha256:{:x}", Sha256::digest(canonical_bytes(policy)))
}

/// The wire tag of a kind.
///
/// Written out rather than taken from serde, so the canonical encoding does
/// not move when a serde attribute does. That is exactly the drift the digest
/// exists to detect, and it must not be able to detect it by moving with it.
const fn kind_tag(kind: RunnerKind) -> &'static str {
    match kind {
        RunnerKind::Host => "host",
        RunnerKind::Container => "container",
    }
}

/// The wire tag of a contract version.
const fn contract_tag(contract: RunnerContract) -> &'static str {
    match contract {
        RunnerContract::HostV1 => "host-v1",
        RunnerContract::ContainerV1 => "container-v1",
    }
}

fn field(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value.as_bytes());
    out.push(b';');
}

fn flag(out: &mut Vec<u8>, value: bool) {
    field(out, if value { "1" } else { "0" });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::topology::events::ImageIdentity;

    /// The host record, spelled out from INV-23's own field list rather than
    /// from `host_policy()`.
    #[test]
    fn the_host_policy_is_inv23s_host_record() {
        let policy = resolve_host().expect("host policy resolves");
        assert_eq!(policy.kind, RunnerKind::Host);
        assert_eq!(policy.policy, RunnerContract::HostV1);
        assert_eq!(policy.image, None, "a host runner has no image");
        assert_eq!(
            policy.credential_volumes, None,
            "a host runner has no credential volumes"
        );
        policy
            .completeness()
            .expect("PR3 accepts the record PR4 resolves");
    }

    /// The bytes, written by hand from the field list in the module docs.
    ///
    /// Not produced by `canonical_bytes` and not round-tripped: a suite that
    /// consumes its own canonical output cannot see a symmetric rename, which
    /// is `PR3-WIRE-PINNING`.
    const HOST_CANONICAL: &[u8] = b"23:tactus.runner-policy.v1;4:host;7:host-v1;1:0;1:0;";

    const CONTAINER_CANONICAL: &[u8] = b"23:tactus.runner-policy.v1;9:container;12:container-v1;\
                                         1:1;13:tactus/ci:3.2;8:sha256:a;1:1;8:sha256:b;1:1;1:2;\
                                         11:claude-code;8:creds-cc;5:codex;8:creds-cx;";

    fn container_fixture() -> RunnerPolicy {
        let mut volumes = BTreeMap::new();
        volumes.insert("claude-code".to_owned(), "creds-cc".to_owned());
        volumes.insert("codex".to_owned(), "creds-cx".to_owned());
        RunnerPolicy {
            kind: RunnerKind::Container,
            policy: RunnerContract::ContainerV1,
            image: Some(ImageIdentity {
                reference: "tactus/ci:3.2".to_owned(),
                id: "sha256:a".to_owned(),
                digest: Some("sha256:b".to_owned()),
            }),
            credential_volumes: Some(volumes),
        }
    }

    /// The encoding separates records the type separates.
    ///
    /// INV-23 enforces **exact equality** between three copies of this record,
    /// so an encoding that maps two distinguishable records onto one digest
    /// makes a genuine mismatch invisible rather than loud. The digest fixtures
    /// here are well-formed records crossed against each other, which catches a
    /// field that stops being encoded — but not a pair deliberately collapsed.
    ///
    /// Two pairs, because there are two places this encoding could collapse:
    /// `Option<map>`'s absent/present-but-empty boundary, which no fixture
    /// carried, and a host record carrying container-only fields, which nothing
    /// pushed through `canonical_bytes` at all.
    #[test]
    fn the_canonical_encoding_separates_records_the_type_separates() {
        // Absent is not the same as present-and-empty. "No credential volumes
        // were configured" and "credential volumes were configured, and there
        // are none" are different records, and `Option` is how the type says so.
        let absent = host_policy();
        let mut empty = host_policy();
        empty.credential_volumes = Some(BTreeMap::new());
        assert_ne!(
            absent.credential_volumes, empty.credential_volumes,
            "the two fixtures are the same value, so this test proves nothing"
        );
        assert_ne!(
            canonical_bytes(&absent),
            canonical_bytes(&empty),
            "an absent volume set and an empty one canonicalize alike, so they \
             carry one runner_policy_sha256 between them"
        );
        assert_ne!(
            runner_policy_sha256(&absent),
            runner_policy_sha256(&empty),
            "and the digest INV-23 compares does not separate them either"
        );
        // Written by hand from the field list, like the two above it: version,
        // kind, contract, image-absent, volumes-present, zero entries.
        assert_eq!(
            canonical_bytes(&empty),
            b"23:tactus.runner-policy.v1;4:host;7:host-v1;1:0;1:1;1:0;",
            "the empty-map encoding is not the one the field list describes"
        );

        // A malformed record is encoded as what it is, not projected into the
        // record it ought to have been. `canonical_bytes` is INV-23's
        // comparison surface; silently normalising here would let a host runner
        // that had acquired an image agree with one that had not.
        let mut mislabelled = host_policy();
        mislabelled.image = Some(ImageIdentity {
            reference: "tactus/ci:3.2".to_owned(),
            id: "sha256:a".to_owned(),
            digest: None,
        });
        assert_ne!(
            canonical_bytes(&host_policy()),
            canonical_bytes(&mislabelled),
            "a host record carrying container-only fields canonicalizes as a \
             clean host record"
        );
        mislabelled
            .completeness()
            .expect_err("a host record carrying an image is not a complete record");
    }

    #[test]
    fn canonical_bytes_match_the_hand_written_payload() {
        assert_eq!(
            canonical_bytes(&host_policy()),
            HOST_CANONICAL,
            "host encoding drifted from the documented field list"
        );
        assert_eq!(
            canonical_bytes(&container_fixture()),
            CONTAINER_CANONICAL,
            "container encoding drifted from the documented field list"
        );
    }

    #[test]
    fn host_runner_declares_host_v1_policy_with_stable_digest() {
        let policy = resolve_host().expect("host policy resolves");
        // The expected digest is computed over the hand-written bytes, so the
        // oracle is the payload rather than the function under test.
        let expected = format!("sha256:{:x}", Sha256::digest(HOST_CANONICAL));
        assert_eq!(runner_policy_sha256(&policy), expected);
        assert_eq!(
            runner_policy_sha256(&policy).len(),
            "sha256:".len() + 64,
            "the digest shape the marker and every container intent carry"
        );
        // Stable: the value a second incarnation resolves is the value the
        // first recorded, which is the whole of INV-23's equality check.
        assert_eq!(
            runner_policy_sha256(&resolve_host().expect("resolve again")),
            expected
        );
    }

    #[test]
    fn container_digest_is_pinned_too() {
        assert_eq!(
            runner_policy_sha256(&container_fixture()),
            format!("sha256:{:x}", Sha256::digest(CONTAINER_CANONICAL))
        );
    }

    /// Every independently meaningful field, varied independently, with the
    /// distinct-value counts asserted rather than described.
    #[test]
    fn the_digest_separates_every_field_of_the_record() {
        let base = container_fixture();
        let mut moved_reference = base.clone();
        let mut moved_id = base.clone();
        let mut moved_digest = base.clone();
        let mut dropped_digest = base.clone();
        let mut renamed_volume = base.clone();
        let mut extra_volume = base.clone();
        let mut dropped_volumes = base.clone();
        let mut swapped_volume_values = base.clone();

        moved_reference.image.as_mut().expect("image").reference = "tactus/ci:3.3".to_owned();
        moved_id.image.as_mut().expect("image").id = "sha256:z".to_owned();
        moved_digest.image.as_mut().expect("image").digest = Some("sha256:c".to_owned());
        dropped_digest.image.as_mut().expect("image").digest = None;
        renamed_volume
            .credential_volumes
            .as_mut()
            .expect("volumes")
            .insert("codex".to_owned(), "creds-other".to_owned());
        extra_volume
            .credential_volumes
            .as_mut()
            .expect("volumes")
            .insert("copilot".to_owned(), "creds-cp".to_owned());
        dropped_volumes.credential_volumes = Some(BTreeMap::new());
        {
            let volumes = swapped_volume_values
                .credential_volumes
                .as_mut()
                .expect("volumes");
            volumes.insert("claude-code".to_owned(), "creds-cx".to_owned());
            volumes.insert("codex".to_owned(), "creds-cc".to_owned());
        }

        let fixtures = vec![
            host_policy(),
            base.clone(),
            moved_reference,
            moved_id,
            moved_digest,
            dropped_digest,
            renamed_volume,
            extra_volume,
            dropped_volumes,
            swapped_volume_values,
        ];

        // Hostility as counts, not prose: every field the record has takes at
        // least two values across the set.
        let kinds: std::collections::BTreeSet<_> =
            fixtures.iter().map(|p| kind_tag(p.kind)).collect();
        let contracts: std::collections::BTreeSet<_> =
            fixtures.iter().map(|p| contract_tag(p.policy)).collect();
        let references: std::collections::BTreeSet<_> = fixtures
            .iter()
            .map(|p| p.image.as_ref().map(|i| i.reference.clone()))
            .collect();
        let ids: std::collections::BTreeSet<_> = fixtures
            .iter()
            .map(|p| p.image.as_ref().map(|i| i.id.clone()))
            .collect();
        let digests: std::collections::BTreeSet<_> = fixtures
            .iter()
            .map(|p| p.image.as_ref().and_then(|i| i.digest.clone()))
            .collect();
        let volumes: std::collections::BTreeSet<_> = fixtures
            .iter()
            .map(|p| p.credential_volumes.clone())
            .collect();
        assert_eq!(kinds.len(), 2, "kind takes both values");
        assert_eq!(contracts.len(), 2, "policy version takes both values");
        assert_eq!(references.len(), 3, "absent, tactus/ci:3.2, tactus/ci:3.3");
        assert_eq!(ids.len(), 3, "absent, sha256:a, sha256:z");
        assert_eq!(digests.len(), 3, "absent, sha256:b, sha256:c");
        assert_eq!(
            volumes.len(),
            6,
            "absent, the pair, renamed, extended, empty, swapped"
        );

        let seen: std::collections::BTreeSet<String> =
            fixtures.iter().map(runner_policy_sha256).collect();
        assert_eq!(
            seen.len(),
            fixtures.len(),
            "two distinguishable runner records share a digest"
        );

        // And the same record digests the same however it was built: the
        // volume map is compared as a set, so insertion order may not move the
        // digest (PR3's own reason for making it a map).
        let mut rebuilt = BTreeMap::new();
        rebuilt.insert("codex".to_owned(), "creds-cx".to_owned());
        rebuilt.insert("claude-code".to_owned(), "creds-cc".to_owned());
        let reordered = RunnerPolicy {
            credential_volumes: Some(rebuilt),
            ..base.clone()
        };
        assert_eq!(
            runner_policy_sha256(&reordered),
            runner_policy_sha256(&base),
            "insertion order moved the digest"
        );
    }

    /// ASCII case is significant in **every** string field of the record.
    ///
    /// PR3 compares `RunnerPolicy` records exactly — `difference()` reports
    /// `ImageId` for `sha256:ab` against `SHA256:AB` — and INV-23 binds four
    /// copies of one record through this digest: the P1 marker, the P3b owner
    /// record, `run_started(4).runner`, and `run_resumed(4).runner`, the last
    /// of which `validation_at_fold[14]` requires to equal the first "exactly
    /// (kind, policy, image reference, id, digest, credential-volume set)". A
    /// canonicalisation that folded case would let a marker attest a record
    /// the fold calls different: the husk ownership proof would accept a
    /// policy that is not the one it names.
    ///
    /// Every other digest fixture is lowercase — including the delimiter one —
    /// so a `to_ascii_lowercase()` anywhere in `field()` passes all of them.
    /// This crosses each field with a case-distinct twin and asserts the
    /// **count** of distinct digests.
    #[test]
    fn ascii_case_is_significant_in_every_string_field_of_the_record() {
        let base = container_fixture();
        let mut upper_reference = base.clone();
        let mut upper_id = base.clone();
        let mut upper_digest = base.clone();
        let mut upper_volume_value = base.clone();
        let mut upper_volume_agent = base.clone();

        upper_reference.image.as_mut().expect("image").reference = "Tactus/CI:3.2".to_owned();
        upper_id.image.as_mut().expect("image").id = "SHA256:A".to_owned();
        upper_digest.image.as_mut().expect("image").digest = Some("SHA256:B".to_owned());
        upper_volume_value
            .credential_volumes
            .as_mut()
            .expect("volumes")
            .insert("codex".to_owned(), "CREDS-CX".to_owned());
        {
            // A case-distinct *key*: `Codex` and `codex` are two entries of
            // the map, so this also proves the agent name is encoded and not
            // normalised on the way in.
            let volumes = upper_volume_agent
                .credential_volumes
                .as_mut()
                .expect("volumes");
            volumes.remove("codex");
            volumes.insert("Codex".to_owned(), "creds-cx".to_owned());
        }

        let fixtures = [
            ("lowercase", base.clone()),
            ("reference", upper_reference),
            ("image id", upper_id),
            ("image digest", upper_digest),
            ("volume value", upper_volume_value),
            ("volume agent", upper_volume_agent),
        ];
        // Every twin differs from the base in ASCII case alone, which is what
        // makes the digest counts below a statement about case.
        for (name, policy) in &fixtures[1..] {
            assert_ne!(
                policy, &base,
                "the `{name}` twin is not distinguishable from the base at all"
            );
            let lower = |value: &str| value.to_ascii_lowercase();
            assert_eq!(
                policy
                    .image
                    .as_ref()
                    .map(|image| (lower(&image.reference), lower(&image.id))),
                base.image
                    .as_ref()
                    .map(|image| (lower(&image.reference), lower(&image.id))),
                "the `{name}` twin differs by more than ASCII case"
            );
        }

        let digests: std::collections::BTreeSet<String> = fixtures
            .iter()
            .map(|(_, policy)| runner_policy_sha256(policy))
            .collect();
        assert_eq!(
            digests.len(),
            fixtures.len(),
            "two records differing only in ASCII case share a digest, so the canonical \
             encoding is not injective over the values PR3 compares exactly"
        );

        // And the bytes themselves carry the case, pinned against a payload
        // written by hand rather than against `canonical_bytes` output.
        let upper_host = RunnerPolicy {
            kind: RunnerKind::Container,
            policy: RunnerContract::ContainerV1,
            image: Some(ImageIdentity {
                reference: "R".to_owned(),
                id: "ID".to_owned(),
                digest: None,
            }),
            credential_volumes: None,
        };
        assert_eq!(
            canonical_bytes(&upper_host),
            b"23:tactus.runner-policy.v1;9:container;12:container-v1;1:1;1:R;2:ID;1:0;1:0;",
            "an uppercase field did not survive canonicalisation byte for byte"
        );
    }

    /// `field` copies its value's **bytes**, and does nothing else to them.
    ///
    /// The module docs give the grammar as `f(s) = <byte-length>:<bytes>;`, and
    /// that is written out here rather than read from `field` — a length prefix
    /// computed by the function under test would agree with any transformation
    /// the function also applied.
    ///
    /// This is the whole class in one assertion. `PR5-CORRECTNESS-004` is
    /// `value.replace('_', "-")` and `PR5-SEAMS-002` is `value.trim()`; a
    /// `to_ascii_lowercase`, a whitespace collapse, a Unicode normalisation and
    /// a delimiter escape are the same defect wearing different clothes, and
    /// every one of them changes these bytes. INV-23 makes this record
    /// "execution identity", compared **exactly** across the P1 marker, the P3b
    /// owner record and `run_started(4).runner`, so any two values the type
    /// distinguishes must reach the digest distinguishable.
    #[test]
    fn field_writes_its_values_bytes_and_transforms_nothing() {
        let hostile = [
            "",
            " ",
            "creds",
            "Creds",
            "CREDS",
            "creds_a",
            "creds-a",
            "creds a",
            "creds  a",
            "creds\ta",
            " creds",
            "creds ",
            "creds\n",
            "creds\r\n",
            "creds:1;",
            "creds/../etc",
            "cafe\u{301}",
            "caf\u{e9}",
            "\u{1f600}",
            "creds\0a",
        ];
        let mut encodings = std::collections::BTreeSet::new();
        for value in hostile {
            let mut out = Vec::new();
            field(&mut out, value);
            let mut expected = value.len().to_string().into_bytes();
            expected.push(b':');
            expected.extend_from_slice(value.as_bytes());
            expected.push(b';');
            assert_eq!(
                out,
                expected,
                "`{}` was not written verbatim: `{}`",
                value.escape_debug(),
                String::from_utf8_lossy(&out).escape_debug()
            );
            encodings.insert(out);
        }
        assert_eq!(
            encodings.len(),
            hostile.len(),
            "two of the hostile values encode alike, so the set is not the \
             witness it claims to be"
        );
        // The length prefix counts **bytes**, not characters — a two-byte `é`
        // and a four-byte emoji say so, and a `chars().count()` would not.
        let mut wide = Vec::new();
        field(&mut wide, "caf\u{e9}");
        assert_eq!(wide, b"5:caf\xc3\xa9;".to_vec());
    }

    /// Two records differing by a character a normaliser would collapse carry
    /// two digests, in **every** string position of the record.
    ///
    /// `PR5-CORRECTNESS-004` names one position (a credential volume's value)
    /// and one pair (`creds_a` vs `creds-a`); `PR5-SEAMS-002` names the same
    /// position and a whitespace pair. The class is neither: it is any
    /// normalisation, anywhere a string reaches [`canonical_bytes`]. So the
    /// pairs are crossed against every position the record has — image
    /// reference, image id, image digest, credential-volume **key**, and
    /// credential-volume **value** — and the counts are asserted rather than
    /// described.
    ///
    /// The failure this prevents is not a wrong answer but a *silent* one: the
    /// marker's `runner_policy_sha256` and `owner.json`'s full record would
    /// agree while carrying different execution identities, and
    /// `prove_private_half_ownership`'s digest conjunct would mint deletion
    /// authority for a private half belonging to a different runner.
    #[test]
    fn a_normalisable_difference_in_any_string_position_moves_the_digest() {
        /// Pairs a normaliser would fold together. Each is *one* transformation
        /// away from its twin, so a digest that cannot separate them names the
        /// transformation that was applied.
        const PAIRS: &[(&str, &str, &str)] = &[
            ("underscore/hyphen", "creds_a", "creds-a"),
            ("trailing space", "creds", "creds  "),
            ("leading space", "creds", "  creds"),
            ("interior collapse", "creds a", "creds  a"),
            ("tab for space", "creds\ta", "creds a"),
            ("trailing newline", "creds", "creds\n"),
            ("carriage return", "creds", "creds\r"),
            ("ascii case", "creds", "Creds"),
            ("unicode composition", "cafe\u{301}", "caf\u{e9}"),
            ("empty against blank", "", " "),
            ("dotted", "creds", "creds."),
        ];

        // Every string position of the record, by name, as a setter.
        #[allow(clippy::type_complexity)]
        let positions: &[(&str, fn(&mut RunnerPolicy, &str))] = &[
            ("image reference", |policy, value| {
                policy.image.as_mut().expect("image").reference = value.to_owned();
            }),
            ("image id", |policy, value| {
                policy.image.as_mut().expect("image").id = value.to_owned();
            }),
            ("image digest", |policy, value| {
                policy.image.as_mut().expect("image").digest = Some(value.to_owned());
            }),
            ("credential volume key", |policy, value| {
                let volumes = policy.credential_volumes.as_mut().expect("volumes");
                volumes.remove("codex");
                volumes.insert(value.to_owned(), "creds-cx".to_owned());
            }),
            ("credential volume value", |policy, value| {
                policy
                    .credential_volumes
                    .as_mut()
                    .expect("volumes")
                    .insert("codex".to_owned(), value.to_owned());
            }),
        ];

        let mut checked = 0_usize;
        for (position, set) in positions {
            for (pair, left, right) in PAIRS {
                assert_ne!(left, right, "{pair}: the fixture pair is one value");
                let mut a = container_fixture();
                let mut b = container_fixture();
                set(&mut a, left);
                set(&mut b, right);
                assert_ne!(
                    a, b,
                    "{position}/{pair}: the two records are equal, so the digest \
                     is not being asked anything"
                );
                assert_ne!(
                    canonical_bytes(&a),
                    canonical_bytes(&b),
                    "{position}/{pair}: `{}` and `{}` canonicalize alike",
                    left.escape_debug(),
                    right.escape_debug()
                );
                assert_ne!(
                    runner_policy_sha256(&a),
                    runner_policy_sha256(&b),
                    "{position}/{pair}: two execution identities share one \
                     runner_policy_sha256, so INV-23's exact equality cannot see \
                     the difference"
                );
                checked += 1;
            }
        }
        assert_eq!(
            positions.len(),
            5,
            "five string positions: reference, id, digest, volume key, volume value"
        );
        assert_eq!(PAIRS.len(), 11, "eleven normalisations");
        assert_eq!(
            checked, 55,
            "every position crossed with every normalisation"
        );
    }

    /// A length-prefixed encoding is injective; a delimiter-only one is not.
    #[test]
    fn field_values_carrying_the_delimiters_do_not_collide() {
        let sneaky = RunnerPolicy {
            kind: RunnerKind::Container,
            policy: RunnerContract::ContainerV1,
            image: Some(ImageIdentity {
                reference: "a;1:b".to_owned(),
                id: "c".to_owned(),
                digest: None,
            }),
            credential_volumes: Some(BTreeMap::new()),
        };
        let plain = RunnerPolicy {
            image: Some(ImageIdentity {
                reference: "a".to_owned(),
                id: "1:b;c".to_owned(),
                digest: None,
            }),
            ..sneaky.clone()
        };
        assert_ne!(
            runner_policy_sha256(&sneaky),
            runner_policy_sha256(&plain),
            "a value carrying the delimiter forged another field boundary"
        );
    }
}
