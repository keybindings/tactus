//! Routing resolution (DESIGN.md §10) and the binder preview.
//!
//! Chains stay abstract tiers; the binder normally resolves them at attempt
//! time against live capacity. Step 1 has no capacity engine, so every rung
//! carries a catalog-derived example binding tagged `preview` (or the pinned
//! binding tagged `pin`).
// LEGACY-EFFECT: this module is in the **frozen legacy section** of
// `effects/allowlist.toml`, which carries its justification and the condition
// under which the section shrinks. `decisions.effect_site_inventory.mechanism` (2).
#![allow(clippy::disallowed_methods)]

use std::fmt;

use crate::catalog;
use crate::config::Config;
use crate::ir::{Task, Tier};

/// Why a rung sits where it does in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSource {
    Default,
    Annotation,
    Override,
}

impl fmt::Display for ChainSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::Annotation => "annotation",
            Self::Override => "override",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub agent: String,
    pub model: String,
    pub pinned: bool,
}

#[derive(Debug, Clone)]
pub struct Rung {
    pub tier: Tier,
    pub source: ChainSource,
    pub binding: Binding,
}

#[derive(Debug, Clone)]
pub struct ResolvedChain {
    pub rungs: Vec<Rung>,
    pub notes: Vec<String>,
    pub attempts_per: u32,
}

/// Resolve a task's escalation chain: config baseline, then blast-radius
/// floors, then the designer's advisory `tier=`, then the binding `min=` clip.
pub fn resolve(task: &Task, cfg: &Config) -> ResolvedChain {
    let kind_chain = cfg.chain_for(task.kind);
    let mut tiers: Vec<(Tier, ChainSource)> = kind_chain
        .chain
        .iter()
        .map(|t| (*t, ChainSource::Default))
        .collect();
    let mut notes = Vec::new();

    // Blast-radius floors: a matching override raises the start. Blast radius
    // beats nominal difficulty (§10.2). An override carrying only a
    // `second_opinion` has no floor to apply and is handled by the reviewer
    // (§11.3), not here.
    for ov in &cfg.overrides {
        if let Some(start_at) = ov.start_at {
            if task.path_hints.iter().any(|h| ov.globs.is_match(h))
                && raise_start(&mut tiers, start_at, ChainSource::Override)
            {
                notes.push(format!(
                    "override paths [{}] raised start to {start_at}",
                    ov.raw_paths.join(", "),
                ));
            }
        }
    }

    // `tier=` is advisory: it becomes the chain start only if it outranks the
    // current start. An annotation that merely agrees with a blast-radius
    // floor must not take credit for it — the override is what binds, and the
    // preview has to say so (§10.2: blast radius beats nominal difficulty).
    if let Some(tier) = task.suggested_tier {
        let raised = raise_start(&mut tiers, tier, ChainSource::Annotation);
        // Agreeing with a silent default still counts as the designer's
        // decision; agreeing with an override does not — the override is what
        // holds the start up, and removing the annotation would not lower it.
        if !raised {
            if let Some(first) = tiers.first_mut() {
                if first.0 == tier && first.1 == ChainSource::Default {
                    first.1 = ChainSource::Annotation;
                }
            }
        }
    }

    // `min=` is binding: clip everything below it.
    if let Some(min) = task.min_tier {
        if raise_start(&mut tiers, min, ChainSource::Annotation) {
            notes.push(format!("min={min} clipped the chain start"));
        }
    }

    if !task.path_hints.is_empty() {
        notes.push(format!("paths: {}", task.path_hints.join(", ")));
    }

    let rungs = tiers
        .into_iter()
        .map(|(tier, source)| Rung {
            tier,
            source,
            binding: bind(tier, cfg),
        })
        .collect();
    ResolvedChain {
        rungs,
        notes,
        attempts_per: kind_chain.attempts_per,
    }
}

/// Drop rungs below `floor`; if that empties the chain, the floor itself
/// becomes the only rung. Returns whether anything changed, relabeling the new
/// start when it did.
fn raise_start(tiers: &mut Vec<(Tier, ChainSource)>, floor: Tier, source: ChainSource) -> bool {
    let before = tiers.len();
    tiers.retain(|(t, _)| *t >= floor);
    if tiers.is_empty() {
        tiers.push((floor, source));
        return true;
    }
    let changed = tiers.len() != before;
    if changed {
        if let Some(first) = tiers.first_mut() {
            first.1 = source;
        }
    }
    changed
}

fn bind(tier: Tier, cfg: &Config) -> Binding {
    if let Some(pin) = cfg.pins.iter().find(|p| p.tier == tier) {
        return Binding {
            agent: pin.agent.clone(),
            model: pin.model.clone(),
            pinned: true,
        };
    }
    let example = catalog::example_binding(tier);
    Binding {
        agent: example.agent.to_owned(),
        model: example.model.to_owned(),
        pinned: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::ir::{TaskId, TaskKind};
    use std::path::PathBuf;
    use std::sync::OnceLock;

    /// A directory with no config and one empty pools file, built once.
    ///
    /// Every test here routes through it, and it used to be rewritten on every
    /// call at a path shared by *every process on the machine* — not even
    /// pid-scoped, so a second `cargo test` binary truncated it under this
    /// one's readers. The content is identical for every caller, so there was
    /// never anything to rewrite.
    fn hermetic() -> (PathBuf, PathBuf) {
        static DIRS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
        DIRS.get_or_init(|| {
            let dir =
                std::env::temp_dir().join(format!("tactus-route-hermetic-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            // A real, empty pools file: an explicit pools path that does not
            // exist is a hard error, and `None` would read the operator's own.
            let empty = dir.join("no-pools.toml");
            std::fs::write(&empty, "# no pools\n").expect("empty pools file");
            (dir, empty)
        })
        .clone()
    }

    fn default_config() -> Config {
        let mut warnings = Vec::new();
        let (dir, empty) = hermetic();
        config::load(None, &dir, Some(&empty), &mut warnings).expect("default config")
    }

    fn task(kind: TaskKind) -> Task {
        Task {
            id: TaskId::from("t"),
            kind,
            title: String::new(),
            body: String::new(),
            depends_on: Vec::new(),
            acceptance: Vec::new(),
            path_hints: Vec::new(),
            suggested_tier: None,
            min_tier: None,
            artifacts_in: Vec::new(),
            artifacts_out: Vec::new(),
        }
    }

    fn tiers(rc: &ResolvedChain) -> Vec<Tier> {
        rc.rungs.iter().map(|r| r.tier).collect()
    }

    #[test]
    fn default_chains_have_default_source_and_preview_bindings() {
        let cfg = default_config();
        let rc = resolve(&task(TaskKind::Fix), &cfg);
        assert_eq!(tiers(&rc), [Tier::Small, Tier::Mid, Tier::Frontier]);
        assert!(rc.rungs.iter().all(|r| r.source == ChainSource::Default));
        assert!(rc.rungs.iter().all(|r| !r.binding.pinned));
        assert_eq!(rc.attempts_per, 2);
    }

    #[test]
    fn min_clips_and_notes() {
        let cfg = default_config();
        let mut t = task(TaskKind::Fix);
        t.min_tier = Some(Tier::Mid);
        let rc = resolve(&t, &cfg);
        assert_eq!(tiers(&rc), [Tier::Mid, Tier::Frontier]);
        assert_eq!(rc.rungs[0].source, ChainSource::Annotation);
        assert_eq!(rc.rungs[1].source, ChainSource::Default);
        assert!(rc.notes.iter().any(|n| n.contains("min=mid")));
    }

    #[test]
    fn advisory_tier_raises_or_relabels_but_never_lowers() {
        let cfg = default_config();

        let mut raiser = task(TaskKind::Fix);
        raiser.suggested_tier = Some(Tier::Frontier);
        let rc = resolve(&raiser, &cfg);
        assert_eq!(tiers(&rc), [Tier::Frontier]);
        assert_eq!(rc.rungs[0].source, ChainSource::Annotation);

        // Equal to the baseline start: relabeled as the designer's decision.
        let mut equal = task(TaskKind::Design);
        equal.suggested_tier = Some(Tier::Frontier);
        let rc = resolve(&equal, &cfg);
        assert_eq!(tiers(&rc), [Tier::Frontier]);
        assert_eq!(rc.rungs[0].source, ChainSource::Annotation);

        // Below the baseline start: advisory is ignored.
        let mut lower = task(TaskKind::Design);
        lower.suggested_tier = Some(Tier::Small);
        let rc = resolve(&lower, &cfg);
        assert_eq!(tiers(&rc), [Tier::Frontier]);
        assert_eq!(rc.rungs[0].source, ChainSource::Default);
    }

    #[test]
    fn path_floor_raises_start_with_override_source() {
        let dir = std::env::temp_dir().join(format!("tactus-route-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let cfg_path: PathBuf = dir.join("floor.toml");
        std::fs::write(
            &cfg_path,
            "[[routing.overrides]]\npaths = [\"src/auth/**\"]\nstart_at = \"frontier\"\n",
        )
        .expect("write config");
        let missing = dir.join("missing-pools.toml");
        std::fs::write(
            &missing,
            "# no pools
",
        )
        .expect("empty pools file");
        let mut warnings = Vec::new();
        let cfg = config::load(Some(&cfg_path), &dir, Some(&missing), &mut warnings).expect("load");

        let mut t = task(TaskKind::Fix);
        t.path_hints.push("src/auth/login.rs".to_owned());
        let rc = resolve(&t, &cfg);
        assert_eq!(tiers(&rc), [Tier::Frontier]);
        assert_eq!(rc.rungs[0].source, ChainSource::Override);
        assert!(rc.notes.iter().any(|n| n.contains("src/auth/**")));

        // Non-matching paths keep the full default chain.
        let mut unmatched = task(TaskKind::Fix);
        unmatched.path_hints.push("src/api/list.rs".to_owned());
        let rc = resolve(&unmatched, &cfg);
        assert_eq!(tiers(&rc), [Tier::Small, Tier::Mid, Tier::Frontier]);

        // An annotation agreeing with the override must not take credit for
        // a floor the override is holding up.
        let mut agreeing = task(TaskKind::Fix);
        agreeing.path_hints.push("src/auth/login.rs".to_owned());
        agreeing.suggested_tier = Some(Tier::Frontier);
        let rc = resolve(&agreeing, &cfg);
        assert_eq!(
            rc.rungs[0].source,
            ChainSource::Override,
            "blast radius is what binds"
        );
    }

    #[test]
    fn pins_bind_their_tier() {
        let dir = std::env::temp_dir().join(format!("tactus-route-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let cfg_path = dir.join("pin.toml");
        std::fs::write(
            &cfg_path,
            "[[pins]]\ntier = \"frontier\"\nagent = \"claude-code\"\nmodel = \"claude-opus-4-8\"\n",
        )
        .expect("write config");
        let missing = dir.join("missing-pools.toml");
        std::fs::write(
            &missing,
            "# no pools
",
        )
        .expect("empty pools file");
        let mut warnings = Vec::new();
        let cfg = config::load(Some(&cfg_path), &dir, Some(&missing), &mut warnings).expect("load");

        let rc = resolve(&task(TaskKind::Design), &cfg);
        assert_eq!(rc.rungs[0].binding.model, "claude-opus-4-8");
        assert!(rc.rungs[0].binding.pinned);

        let rc = resolve(&task(TaskKind::Docs), &cfg);
        assert!(
            rc.rungs.iter().all(|r| !r.binding.pinned),
            "pin scoped to its tier"
        );
    }
}
