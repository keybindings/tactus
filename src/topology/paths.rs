//! The path vocabulary a schema-4 run leases and rejects by.
//!
//! Two tasks may run in parallel exactly when the regions of the repository
//! they touch do not overlap, so "which paths" is a fact the log has to record
//! rather than recompute. It is recorded twice, deliberately: a **predicted**
//! region taken from the plan's path hints when a task is dispatched, and an
//! **actual** region taken from the diff when its candidate is prepared. The
//! prediction is what admission can know; the actual set is what the merge
//! queue is entitled to trust.
//!
//! Both are [`PathSet`]s, and both can be [`PathSet::RepoWide`] — the answer
//! for a task that gave no usable hint, and the answer for a diff whose byte
//! paths did not decode. Repo-wide overlaps everything, so an unparsable
//! answer costs parallelism and never costs correctness. That asymmetry is the
//! whole reason the variant exists rather than an empty set or an error.
//!
//! How the two are compared is the fold's business and arrives with it; what
//! is here is the frozen record itself, including the [`PathPolicy`] the run
//! resolved once and every later comparison must be read against.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The comparison rules a run froze at pre-flight.
///
/// Versioned because path comparison is execution identity in the same sense
/// effort and reviewer bindings are: a run that admitted two tasks in parallel
/// under one case-folding rule must not have its later half admitted under
/// another because the machine changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathPolicy {
    pub version: PathPolicyVersion,
    /// Whether two paths differing only in case name the same file. Resolved
    /// from the repository's filesystem, not guessed per comparison.
    pub case_fold: bool,
    /// The syntax the plan's hints are written in.
    pub grammar: PathGrammar,
}

/// Which generation of the comparison rules a record was written under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathPolicyVersion {
    /// Component-wise equal/ancestor/descendant overlap, literal prefix taken
    /// before the first glob metacharacter, repo-wide for anything unsafe.
    V1,
}

/// The syntax a plan's path hints are interpreted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathGrammar {
    Globset,
}

/// One repository path as Git names it: forward slashes, relative to the repo
/// root, and never a filesystem path on the machine reading it.
///
/// Distinct from [`std::path::PathBuf`] on purpose. A recorded region has to
/// mean the same thing on the Windows machine that resumes the run as on the
/// Linux one that wrote it, and a platform path type would make that a
/// question about separators. Paths that did not decode are never stored: the
/// classification becomes [`PathSet::RepoWide`] instead, which is why this can
/// be a `String` without losing the byte-safe answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GitPath(pub String);

impl GitPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for GitPath {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for GitPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A region of the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "region", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathSet {
    /// Everything. The classification for an absent, unsafe, unparsable, or
    /// undecodable answer — and therefore the one that must never be produced
    /// by accident, because it serializes every task against every other.
    RepoWide,
    /// The literal prefixes a region is bounded by.
    Prefixes { paths: Vec<GitPath> },
}

impl PathSet {
    /// Whether this region is the everything region.
    pub fn is_repo_wide(&self) -> bool {
        matches!(self, Self::RepoWide)
    }

    /// The prefixes bounding this region, or `None` when it is unbounded.
    ///
    /// `Some(&[])` is a real and different answer from `None`: a task whose
    /// diff touched nothing has an empty region that overlaps nobody, while a
    /// task whose paths could not be read has an unbounded one that overlaps
    /// everybody.
    pub fn prefixes(&self) -> Option<&[GitPath]> {
        match self {
            Self::RepoWide => None,
            Self::Prefixes { paths } => Some(paths),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hostile prefixes: deranged against sorted order, mixed case, padded,
    /// multi-byte, and long enough that a truncating writer would show.
    fn hostile_prefixes() -> Vec<GitPath> {
        vec![
            GitPath::from("src/Zebra/ÜBER.rs"),
            GitPath::from("  leading-and-trailing  "),
            GitPath::from("Docs/ADR/0001-ünicode-decisions.md"),
            GitPath::from(
                "a/very/deep/directory/chain/that/keeps/going/well/past/any/plausible/buffer/size/file.rs",
            ),
            GitPath::from("build.rs"),
        ]
    }

    fn hostile_policy() -> PathPolicy {
        PathPolicy {
            version: PathPolicyVersion::V1,
            // Off-default: `bool::default()` is false, and a policy that lost
            // this field would still deserialize to the common case.
            case_fold: true,
            grammar: PathGrammar::Globset,
        }
    }

    #[test]
    fn path_policy_round_trips_every_field_it_records() {
        let policy = hostile_policy();
        let json = serde_json::to_string(&policy).expect("serialize");
        assert_eq!(
            serde_json::from_str::<PathPolicy>(&json).expect("deserialize"),
            policy
        );
        // Named fields, not positional: a record whose keys were renamed would
        // still round-trip, and a resume reading a differently-named record
        // would fall back to a default it must never fall back to.
        assert!(json.contains(r#""version":"v1""#), "{json}");
        assert!(json.contains(r#""case_fold":true"#), "{json}");
        assert!(json.contains(r#""grammar":"globset""#), "{json}");
    }

    #[test]
    fn a_path_policy_refuses_an_unknown_field() {
        // The policy is execution identity; a field this binary does not
        // understand means the record was written under rules it cannot apply.
        let json = r#"{"version":"v1","case_fold":true,"grammar":"globset","ordering":"lexical"}"#;
        assert!(serde_json::from_str::<PathPolicy>(json).is_err());
    }

    #[test]
    fn an_unknown_key_stays_unknown_when_it_replaces_a_required_field_as_well_as_when_it_joins_one()
    {
        // A fixture that only ever *adds* an unknown key next to a complete
        // record is satisfied by an alias: the record is refused as a
        // duplicate, not as an unknown field. The replacement form is the one
        // that distinguishes them — with the real key removed, an aliased
        // spelling deserializes and the policy is silently accepted under a
        // name the frozen shape does not define.
        //
        // Every hostile key is same-typed with the field it replaces, so a
        // type error cannot stand in for the refusal either.
        let intruders: [(&str, &str, &str); 3] = [
            ("version", "policy_version", r#""v1""#),
            ("case_fold", "fold_case", "true"),
            ("grammar", "ordering", r#""globset""#),
        ];
        for (required, intruder, value) in intruders {
            // (a) in place of the required field: the record is incomplete and
            //     the intruder is unknown, and both are refusals.
            let mut replaced: serde_json::Value =
                serde_json::from_str(r#"{"version":"v1","case_fold":true,"grammar":"globset"}"#)
                    .expect("fixture parses");
            let object = replaced.as_object_mut().expect("object");
            object.remove(required).expect("field present");
            object.insert(
                intruder.to_owned(),
                serde_json::from_str(value).expect("value parses"),
            );
            assert!(
                serde_json::from_value::<PathPolicy>(replaced).is_err(),
                "`{intruder}` was accepted in place of `{required}`",
            );

            // (b) in addition to it: still unknown, and refused for being so
            //     rather than for a field that is missing.
            let mut added: serde_json::Value =
                serde_json::from_str(r#"{"version":"v1","case_fold":true,"grammar":"globset"}"#)
                    .expect("fixture parses");
            added.as_object_mut().expect("object").insert(
                intruder.to_owned(),
                serde_json::from_str(value).expect("value parses"),
            );
            assert!(
                serde_json::from_value::<PathPolicy>(added).is_err(),
                "`{intruder}` was accepted alongside `{required}`",
            );
        }
    }

    #[test]
    fn both_case_fold_values_survive_the_wire_exactly_as_written() {
        // `case_fold` is an independent boolean that decides whether two paths
        // differing only in case name the same file. Every fixture that sets
        // it to one value permits a writer that hard-codes that value: replay
        // would then turn a case-sensitive run into a case-folding one and
        // change every overlap decision the merge queue made.
        //
        // The expected payloads are written out here rather than produced by
        // the serializer, so the assertion is about the frozen encoding rather
        // than about serde agreeing with itself.
        let expectations = [
            (
                false,
                r#"{"version":"v1","case_fold":false,"grammar":"globset"}"#,
            ),
            (
                true,
                r#"{"version":"v1","case_fold":true,"grammar":"globset"}"#,
            ),
        ];
        for (case_fold, expected) in expectations {
            let policy = PathPolicy {
                version: PathPolicyVersion::V1,
                case_fold,
                grammar: PathGrammar::Globset,
            };
            assert_eq!(
                serde_json::to_string(&policy).expect("serialize"),
                expected,
                "case_fold {case_fold} did not serialize to the frozen payload"
            );
            assert_eq!(
                serde_json::from_str::<PathPolicy>(expected).expect("deserialize"),
                policy,
                "the frozen payload for case_fold {case_fold} did not decode to it"
            );
            // And the two encodings are different documents, so a serializer
            // that emitted a constant would collide here.
            assert_eq!(policy.case_fold, case_fold);
        }
        assert_ne!(expectations[0].1, expectations[1].1);
    }

    #[test]
    fn an_unsupported_policy_version_or_grammar_spelling_is_refused_rather_than_folded_into_v1() {
        // The frozen authority defines exactly one version and one grammar. A
        // record declaring another one was written under rules this binary
        // does not implement, and reading it as v1/globset would apply the
        // wrong comparison to every lease the run took.
        for version in ["v2", "V1", "v1 ", "", "v10", "v0"] {
            let json = format!(r#"{{"version":"{version}","case_fold":true,"grammar":"globset"}}"#);
            assert!(
                serde_json::from_str::<PathPolicy>(&json).is_err(),
                "version `{version}` was accepted",
            );
        }
        for grammar in ["globset2", "Globset", "glob", "", "globset "] {
            let json = format!(r#"{{"version":"v1","case_fold":true,"grammar":"{grammar}"}}"#);
            assert!(
                serde_json::from_str::<PathPolicy>(&json).is_err(),
                "grammar `{grammar}` was accepted",
            );
        }
        // The canonical spellings, so the negatives above cannot be satisfied
        // by refusing everything.
        assert_eq!(
            serde_json::from_str::<PathPolicy>(
                r#"{"version":"v1","case_fold":true,"grammar":"globset"}"#
            )
            .expect("the canonical policy decodes"),
            hostile_policy()
        );
        assert_eq!(
            serde_json::to_string(&PathPolicyVersion::V1).expect("serialize"),
            r#""v1""#
        );
        assert_eq!(
            serde_json::to_string(&PathGrammar::Globset).expect("serialize"),
            r#""globset""#
        );
    }

    #[test]
    fn a_path_policy_refuses_a_missing_field_rather_than_defaulting_it() {
        // Each field removed in turn: `case_fold` is the dangerous one, since
        // a default would silently pick the case-sensitive comparison.
        for absent in ["version", "case_fold", "grammar"] {
            let mut value: serde_json::Value =
                serde_json::from_str(r#"{"version":"v1","case_fold":true,"grammar":"globset"}"#)
                    .expect("fixture parses");
            value
                .as_object_mut()
                .expect("object")
                .remove(absent)
                .expect("field present");
            assert!(
                serde_json::from_value::<PathPolicy>(value).is_err(),
                "a policy without `{absent}` was accepted"
            );
        }
    }

    #[test]
    fn the_three_regions_are_distinguishable_on_the_wire() {
        // Repo-wide, empty, and non-empty are three different answers and the
        // most damaging confusion is between the first two: an unbounded
        // region serialized as an empty one overlaps nobody and would admit
        // every task in parallel against every other.
        let repo_wide = PathSet::RepoWide;
        let empty = PathSet::Prefixes { paths: Vec::new() };
        let bounded = PathSet::Prefixes {
            paths: hostile_prefixes(),
        };

        let rendered: Vec<String> = [&repo_wide, &empty, &bounded]
            .iter()
            .map(|set| serde_json::to_string(set).expect("serialize"))
            .collect();
        assert_ne!(rendered[0], rendered[1]);
        assert_ne!(rendered[1], rendered[2]);
        assert_ne!(rendered[0], rendered[2]);

        for (set, json) in [&repo_wide, &empty, &bounded].iter().zip(&rendered) {
            assert_eq!(
                &&serde_json::from_str::<PathSet>(json).expect("deserialize"),
                set
            );
        }
        assert!(
            rendered[0].contains(r#""region":"repo_wide""#),
            "{}",
            rendered[0]
        );
        assert!(
            rendered[1].contains(r#""region":"prefixes""#),
            "{}",
            rendered[1]
        );
    }

    #[test]
    fn the_unbounded_region_is_the_only_one_without_prefixes() {
        assert!(PathSet::RepoWide.is_repo_wide());
        assert_eq!(PathSet::RepoWide.prefixes(), None);

        let empty = PathSet::Prefixes { paths: Vec::new() };
        assert!(!empty.is_repo_wide());
        assert_eq!(empty.prefixes(), Some(&[][..]));

        let bounded = PathSet::Prefixes {
            paths: hostile_prefixes(),
        };
        assert!(!bounded.is_repo_wide());
        assert_eq!(bounded.prefixes(), Some(&hostile_prefixes()[..]));
    }

    #[test]
    fn prefixes_survive_in_the_order_and_bytes_they_were_recorded_in() {
        // Not sorted, not trimmed, not normalized: the recorded region is
        // evidence about a past diff, and a writer that tidied it would make
        // two different diffs indistinguishable.
        let bounded = PathSet::Prefixes {
            paths: hostile_prefixes(),
        };
        let json = serde_json::to_string(&bounded).expect("serialize");
        let back: PathSet = serde_json::from_str(&json).expect("deserialize");
        let paths = back.prefixes().expect("bounded");
        assert_eq!(paths, hostile_prefixes());
        assert_eq!(paths[0].as_str(), "src/Zebra/ÜBER.rs");
        assert_eq!(paths[1].as_str(), "  leading-and-trailing  ");
        assert_eq!(paths[4].as_str(), "build.rs");

        let mut sorted = hostile_prefixes();
        sorted.sort();
        assert_ne!(paths, sorted, "the fixture must not already be sorted");
    }

    /// The longest hostile prefix, written out as a literal rather than
    /// produced by [`GitPath::from`]. An oracle built through the constructor
    /// is truncated by exactly the mutation it is supposed to catch.
    const LONG_PREFIX_LITERAL: &str =
        "a/very/deep/directory/chain/that/keeps/going/well/past/any/plausible/buffer/size/file.rs";

    /// The canonical encoding of the hostile region, written by hand. Not
    /// produced by the serializer, so it detects a change to the encoding
    /// rather than agreeing with whatever the encoding currently is.
    const HOSTILE_REGION_JSON: &str = concat!(
        r#"{"region":"prefixes","paths":["#,
        r#""src/Zebra/ÜBER.rs","#,
        r#""  leading-and-trailing  ","#,
        r#""Docs/ADR/0001-ünicode-decisions.md","#,
        r#""a/very/deep/directory/chain/that/keeps/going/well/past/any/plausible/buffer/size/file.rs","#,
        r#""build.rs""#,
        r#"]}"#
    );

    #[test]
    fn an_over_length_path_keeps_every_byte_it_was_given() {
        // The oracle is the literal above, not a second call to the
        // constructor: comparing `GitPath::from(x)` against `GitPath::from(x)`
        // normalizes both sides identically, so a constructor that truncated,
        // trimmed, or lower-cased its input would agree with itself and the
        // recorded region would silently name a different part of the tree.
        assert_eq!(LONG_PREFIX_LITERAL.len(), 88);
        assert!(
            LONG_PREFIX_LITERAL.len() > 64,
            "the fixture must exceed any plausible buffer"
        );

        let path = GitPath::from(LONG_PREFIX_LITERAL);
        assert_eq!(path.as_str(), LONG_PREFIX_LITERAL);
        assert_eq!(path.as_str().len(), 88);
        assert_eq!(path.to_string(), LONG_PREFIX_LITERAL);
        assert!(path.as_str().ends_with("size/file.rs"), "{path}");

        // Through the wire too, against a hand-written payload.
        assert_eq!(
            serde_json::to_string(&path).expect("serialize"),
            format!("\"{LONG_PREFIX_LITERAL}\"")
        );

        // And in place: index 3 of the hostile set is the long one, and the
        // earlier byte assertions in this module cover 0, 1 and 4 only.
        let recorded = PathSet::Prefixes {
            paths: hostile_prefixes(),
        };
        let paths = recorded.prefixes().expect("bounded");
        assert_eq!(paths[3].as_str(), LONG_PREFIX_LITERAL);
        assert_eq!(paths[2].as_str(), "Docs/ADR/0001-ünicode-decisions.md");
        assert_eq!(paths.len(), 5);
        let json = serde_json::to_string(&recorded).expect("serialize");
        assert!(
            json.contains(LONG_PREFIX_LITERAL),
            "the recorded region lost bytes of its longest prefix: {json}"
        );
    }

    #[test]
    fn every_region_encodes_to_the_payload_written_out_here_and_decodes_from_it() {
        // Round trips compare one serde implementation against itself, so a
        // symmetric rename of `region`, `paths`, `repo_wide` or `prefixes`
        // changes the durable format invisibly. These payloads are written by
        // hand, so any such change fails here in both directions.
        let cases: [(PathSet, &str); 3] = [
            (PathSet::RepoWide, r#"{"region":"repo_wide"}"#),
            (
                PathSet::Prefixes { paths: Vec::new() },
                r#"{"region":"prefixes","paths":[]}"#,
            ),
            (
                PathSet::Prefixes {
                    paths: hostile_prefixes(),
                },
                HOSTILE_REGION_JSON,
            ),
        ];
        for (set, expected) in cases {
            assert_eq!(
                serde_json::to_string(&set).expect("serialize"),
                expected,
                "{set:?} did not serialize to its frozen payload"
            );
            assert_eq!(
                serde_json::from_str::<PathSet>(expected).expect("deserialize"),
                set,
                "the frozen payload did not decode to {set:?}"
            );
        }
    }

    #[test]
    fn a_git_path_is_transparent_on_the_wire() {
        // A bare string, so a recorded region reads as one in `jq` and in the
        // file itself. A wrapper object here would change every recorded set.
        let path = GitPath::from("src/Zebra/ÜBER.rs");
        assert_eq!(
            serde_json::to_string(&path).expect("serialize"),
            r#""src/Zebra/ÜBER.rs""#
        );
        assert_eq!(path.to_string(), "src/Zebra/ÜBER.rs");
    }
}
