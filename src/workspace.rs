//! Workspace (DESIGN.md §6): the engine owns git. Agents edit files; only the
//! engine stages, commits, branches, and rolls back (invariant 1). Every git
//! operation is a subprocess of the system `git` binary — no library binding.
//!
//! # LEGACY-EFFECT
//!
//! `decisions.effect_site_inventory.mechanism` puts this module in the **frozen
//! legacy section** of `effects/allowlist.toml` by name: "legacy modules frozen
//! at PR5 (… legacy branch/checkout/commit operations in src/workspace.rs …)
//! each carrying a LEGACY-EFFECT justification". The justification is that
//! sentence's own: these are the schema-1..3 engine's Git operations, they are
//! reached only by legacy paths, and `invariants_preserved[1]` requires their
//! behaviour to be untouched by this slice. The schema-4 primitives —
//! execution root, detached worktrees with intents, exact snapshots, engine
//! refs, and the Git-object creation contexts — live behind typed funnels in
//! [`crate::workspace_manager`] instead, and nothing here calls them.
//!
//! The section "may only shrink after PR5 (the test compares against the frozen
//! list)", so this attribute is a ceiling rather than a licence.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::error::TactusError;
use crate::events::PreparedCommit;

pub struct Workspace {
    root: PathBuf,
}

/// The immutable candidate captured immediately after staging. Every gate,
/// review, prepared commit, and CAS uses these object identities rather than
/// consulting a mutable index again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedCandidate {
    /// The exact direct branch ref that owned `parent_oid` when this candidate
    /// was captured. An object id alone is insufficient: two branches may
    /// legitimately point at the same commit while only one belongs to the run.
    pub branch_ref: String,
    pub parent_oid: String,
    pub tree_oid: String,
    pub diff: String,
}

impl Workspace {
    /// Open an existing git worktree, normalizing to its top level. Running
    /// from a subdirectory would otherwise scope `git clean` to that
    /// subdirectory while staging stays whole-tree, so rollback would leave
    /// residue above the current directory.
    pub fn open(root: &Path) -> Result<Self, TactusError> {
        let probe = Self {
            root: root.to_path_buf(),
        };
        let inside = probe.git(&["rev-parse", "--is-inside-work-tree"])?;
        if inside.trim() != "true" {
            return Err(TactusError::Git {
                message: format!("{} is not a git worktree", root.display()),
            });
        }
        let toplevel = probe.git_path(&["rev-parse", "--show-toplevel"])?;
        Ok(Self {
            root: if toplevel.as_os_str().is_empty() {
                probe.root
            } else {
                toplevel
            },
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The administrative directory private to this physical worktree.
    ///
    /// A linked worktree's `.git` is a pointer into the common repository, so
    /// joining the visible `.git` path would either fail or collapse distinct
    /// worktrees onto one lease. Git resolves the exact per-worktree directory
    /// for us without changing tracked or working-tree state.
    pub(crate) fn worktree_git_dir(&self) -> Result<PathBuf, TactusError> {
        let git_dir = self.git_path(&["rev-parse", "--absolute-git-dir"])?;
        if !git_dir.is_absolute() {
            return Err(TactusError::Git {
                message: format!(
                    "git rev-parse --absolute-git-dir returned a relative path: {}",
                    git_dir.display()
                ),
            });
        }
        Ok(git_dir)
    }

    /// Decode one path printed by Git without requiring Unix path bytes to be
    /// UTF-8. Git appends a platform line ending; remove only that delimiter,
    /// never legal leading or trailing path bytes.
    fn git_path(&self, args: &[&str]) -> Result<PathBuf, TactusError> {
        let mut output = self.git_output(args)?;
        #[cfg(windows)]
        {
            if output.ends_with(b"\r\n") {
                output.truncate(output.len() - 2);
            } else if output.ends_with(b"\n") {
                output.pop();
            }
            let path = String::from_utf8(output).map_err(|error| TactusError::Git {
                message: format!(
                    "git {} returned a path that is not valid UTF-8: {error}",
                    args.join(" ")
                ),
            })?;
            Ok(PathBuf::from(path))
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            if output.ends_with(b"\n") {
                output.pop();
            }
            Ok(PathBuf::from(OsString::from_vec(output)))
        }
        #[cfg(not(any(unix, windows)))]
        {
            if output.ends_with(b"\n") {
                output.pop();
            }
            let path = String::from_utf8(output).map_err(|error| TactusError::Git {
                message: format!(
                    "git {} returned a path that is not valid UTF-8: {error}",
                    args.join(" ")
                ),
            })?;
            Ok(PathBuf::from(path))
        }
    }

    fn git(&self, args: &[&str]) -> Result<String, TactusError> {
        let output = self.git_output(args)?;
        String::from_utf8(output).map_err(|error| TactusError::Git {
            message: format!(
                "git {} returned output that is not valid UTF-8: {error}",
                args.join(" ")
            ),
        })
    }

    fn git_output(&self, args: &[&str]) -> Result<Vec<u8>, TactusError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(output.stdout)
    }

    /// Run a Git command with every repository-configured hook and fsmonitor
    /// disabled. Keep this raw-output primitive reusable by reference updates,
    /// whose expected compare-and-swap failures need the real exit status.
    pub(crate) fn run_git_with_private_hooks(&self, args: &[&str]) -> Result<Output, TactusError> {
        let hooks = PrivateHooksDir::create()?;
        let mut hooks_config = OsString::from("core.hooksPath=");
        hooks_config.push(&hooks.path);
        Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .arg("-c")
            .arg(hooks_config)
            .args(["-c", "core.fsmonitor=false"])
            .args(args)
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })
    }

    fn git_output_with_private_hooks(&self, args: &[&str]) -> Result<Vec<u8>, TactusError> {
        let output = self.run_git_with_private_hooks(args)?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(output.stdout)
    }

    fn git_with_private_hooks(&self, args: &[&str]) -> Result<String, TactusError> {
        let output = self.git_output_with_private_hooks(args)?;
        String::from_utf8(output).map_err(|error| TactusError::Git {
            message: format!(
                "git {} returned output that is not valid UTF-8: {error}",
                args.join(" ")
            ),
        })
    }

    fn git_output_with_input(&self, args: &[&str], input: Vec<u8>) -> Result<Vec<u8>, TactusError> {
        let hooks = PrivateHooksDir::create()?;
        let mut hooks_config = OsString::from("core.hooksPath=");
        hooks_config.push(&hooks.path);
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .arg("-c")
            .arg(hooks_config)
            .args(["-c", "core.fsmonitor=false"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        let mut stdin = child.stdin.take().ok_or_else(|| TactusError::Git {
            message: format!("git {} did not open stdin", args.join(" ")),
        })?;
        // Read stdout/stderr while feeding the complete NUL-delimited path
        // list. A large index can otherwise fill check-attr's stdout pipe and
        // deadlock the parent while it is still writing stdin.
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let output = child.wait_with_output().map_err(|e| TactusError::Git {
            message: format!("waiting for git {}: {e}", args.join(" ")),
        })?;
        let write_result = writer.join().map_err(|_| TactusError::Git {
            message: format!("writing paths to git {} panicked", args.join(" ")),
        })?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        write_result.map_err(|e| TactusError::Git {
            message: format!("writing paths to git {}: {e}", args.join(" ")),
        })?;
        Ok(output.stdout)
    }

    fn prepared_update_ref(&self, args: &[&str]) -> Result<(), TactusError> {
        let output = self.run_git_with_private_hooks(args)?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(())
    }

    fn commit_tree_with_tactus_identity(
        &self,
        tree_oid: &str,
        parent_oid: &str,
        message: &str,
    ) -> Result<String, TactusError> {
        let args = ["commit-tree", tree_oid, "-p", parent_oid, "-m", message];
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            // Environment identity overrides repository/global config and any
            // inherited GIT_AUTHOR_* or GIT_COMMITTER_* values.
            .env("GIT_AUTHOR_NAME", "tactus")
            .env("GIT_AUTHOR_EMAIL", "tactus@tactus.local")
            .env("GIT_COMMITTER_NAME", "tactus")
            .env("GIT_COMMITTER_EMAIL", "tactus@tactus.local")
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        String::from_utf8(output.stdout).map_err(|error| TactusError::Git {
            message: format!(
                "git {} returned output that is not valid UTF-8: {error}",
                args.join(" ")
            ),
        })
    }

    /// §14 pre-flight: the engine refuses dirty trees.
    pub fn is_clean(&self) -> Result<bool, TactusError> {
        self.refuse_worktree_filters_before("git status")?;
        Ok(self
            .git_with_private_hooks(&["status", "--porcelain"])?
            .trim()
            .is_empty())
    }

    /// Repository prerequisites whose absence would make the captured tree
    /// incomplete or its attribute policy unverifiable. Run this before any
    /// worker is dispatched on both fresh and resumed runs.
    pub fn ensure_execution_prerequisites(&self) -> Result<(), TactusError> {
        require_check_attr_source(self.git_output_with_input(
            &["check-attr", "--source=HEAD", "--stdin", "-z", "filter"],
            Vec::new(),
        ))?;
        self.refuse_sparse_checkout()
    }

    fn refuse_sparse_checkout(&self) -> Result<(), TactusError> {
        let configured =
            self.run_git_with_private_hooks(&["config", "--bool", "--get", "core.sparseCheckout"])?;
        let sparse_configured = if configured.status.success() {
            match configured.stdout.as_slice() {
                b"true\n" | b"true\r\n" => true,
                b"false\n" | b"false\r\n" => false,
                other => {
                    return Err(TactusError::Git {
                        message: format!(
                            "git config returned an invalid core.sparseCheckout value `{}`",
                            String::from_utf8_lossy(other).trim()
                        ),
                    });
                }
            }
        } else if configured.status.code() == Some(1) {
            false
        } else {
            return Err(TactusError::Git {
                message: format!(
                    "checking core.sparseCheckout failed: {}",
                    String::from_utf8_lossy(&configured.stderr).trim()
                ),
            });
        };
        // `-t` reports the skip-worktree tag as an uppercase `S` even when an
        // entry is also marked assume-unchanged. (`-v` would lowercase that
        // tag and could let a manually sparse index evade this preflight.)
        let index = self.git_output_with_private_hooks(&["ls-files", "-t", "-z"])?;
        let has_skipped_entry = index
            .split(|byte| *byte == 0)
            .any(|entry| entry.starts_with(b"S "));
        if sparse_configured || has_skipped_entry {
            return Err(TactusError::Refused {
                message: "sparse checkout is active (or the index has skip-worktree entries); tactus requires a complete worktree so workers, gates, and reviewers see every candidate path. Run `git sparse-checkout disable` and clear any manual skip-worktree bits before starting or resuming."
                    .to_owned(),
            });
        }
        Ok(())
    }

    pub fn current_branch(&self) -> Result<String, TactusError> {
        Ok(self
            .git(&["rev-parse", "--abbrev-ref", "HEAD"])?
            .trim()
            .to_owned())
    }

    /// The full direct branch ref currently checked out by this worktree.
    /// Prepared publication is deliberately unavailable from detached HEAD or
    /// through a symbolic branch alias: the run records one concrete local ref.
    pub fn current_branch_ref(&self) -> Result<String, TactusError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["symbolic-ref", "--quiet", "--no-recurse", "HEAD"])
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: "HEAD is detached; tactus requires the recorded run branch to own every candidate"
                    .to_owned(),
            });
        }
        let branch_ref = String::from_utf8(output.stdout).map_err(|error| TactusError::Git {
            message: format!("git symbolic-ref returned output that is not valid UTF-8: {error}"),
        })?;
        let branch_ref = branch_ref.trim().to_owned();
        self.validate_branch_ref(&branch_ref)?;
        if self.symbolic_ref_target(&branch_ref)?.is_some() {
            return Err(TactusError::Git {
                message: format!(
                    "recorded branch ref `{branch_ref}` is itself symbolic; refusing ambiguous publication"
                ),
            });
        }
        Ok(branch_ref)
    }

    pub fn head_sha(&self) -> Result<String, TactusError> {
        Ok(self
            .git(&["rev-parse", "--short", "HEAD"])?
            .trim()
            .to_owned())
    }

    /// Full HEAD sha. The event log records these rather than short ones
    /// because `--short` picks its length from `core.abbrev` and the repo's
    /// object count — a sha written by one checkout would not compare equal to
    /// the same sha read by another, which is exactly the check §15 asks
    /// `resume` to make.
    pub fn head_sha_full(&self) -> Result<String, TactusError> {
        Ok(self.git(&["rev-parse", "HEAD"])?.trim().to_owned())
    }

    /// The full sha of a commit's first parent — `None` at a root commit.
    ///
    /// How `resume` tells a commit sitting directly on its own record apart
    /// from history that arrived some other way.
    pub fn parent_sha(&self, sha: &str) -> Result<Option<String>, TactusError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{sha}^"))
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        if !output.status.success() {
            // A root commit has no parent. That is an answer, not a failure.
            return Ok(None);
        }
        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ))
    }

    /// A commit's subject — the first line of its message.
    pub fn commit_subject(&self, sha: &str) -> Result<String, TactusError> {
        Ok(self
            .git(&["log", "-1", "--format=%s", sha, "--"])?
            .trim()
            .to_owned())
    }

    pub fn create_branch(&self, name: &str) -> Result<(), TactusError> {
        self.refuse_worktree_filters_before("git switch")?;
        let tree_oid = self.git(&["rev-parse", "HEAD^{tree}"])?;
        self.refuse_unsafe_checkout_tree(tree_oid.trim())?;
        let create = format!("--create={name}");
        self.git_with_private_hooks(&["switch", "-q", "--no-recurse-submodules", &create, "--"])
            .map(|_| ())
    }

    /// Move to an existing branch — how `resume` gets back onto the run's own
    /// branch when the operator has wandered off it.
    pub fn switch_branch(&self, name: &str) -> Result<(), TactusError> {
        self.refuse_worktree_filters_before("git switch")?;
        let revision = format!("refs/heads/{name}^{{tree}}");
        let tree_oid = self.git(&["rev-parse", "--verify", &revision])?;
        self.refuse_unsafe_checkout_tree(tree_oid.trim())?;
        self.git_with_private_hooks(&["switch", "-q", "--no-recurse-submodules", "--", name])
            .map(|_| ())
    }

    /// Whether a branch exists locally.
    pub fn branch_exists(&self, name: &str) -> Result<bool, TactusError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("refs/heads/{name}"))
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        Ok(output.status.success())
    }

    /// A one-line-per-path summary of everything uncommitted, for telling the
    /// operator what a resume is about to discard.
    pub fn uncommitted_summary(&self) -> Result<Vec<String>, TactusError> {
        self.refuse_worktree_filters_before("git status")?;
        Ok(self
            .git_with_private_hooks(&["status", "--porcelain"])?
            .lines()
            .map(|line| line.trim_end().to_owned())
            .filter(|line| !line.is_empty())
            .collect())
    }

    /// Keep `.tactus/` (run dirs, transcripts) out of `status` and out of the
    /// engine's own commits.
    ///
    /// This is a self-ignoring `.tactus/.gitignore` containing `*` (the
    /// pattern cargo uses for `target/`) rather than an entry in
    /// `.git/info/exclude`: it needs no read-modify-write of a file the user
    /// owns, disappears with the directory, and — unlike `info/exclude` under
    /// `--git-dir` — behaves correctly in a linked worktree, where git reads
    /// excludes only from the common directory.
    pub fn ensure_run_exclusions(&self) -> Result<(), TactusError> {
        let dir = self.root.join(".tactus");
        fs::create_dir_all(&dir).map_err(|e| TactusError::Git {
            message: format!("creating {}: {e}", dir.display()),
        })?;
        let ignore_path = dir.join(".gitignore");
        if fs::read_to_string(&ignore_path).is_ok_and(|c| c.contains('*')) {
            return Ok(());
        }
        fs::write(&ignore_path, "*\n").map_err(|e| TactusError::Git {
            message: format!("writing {}: {e}", ignore_path.display()),
        })
    }

    /// Stage everything, freeze one parent and tree object, and return their
    /// complete diff. The diff names those frozen objects rather than rereading
    /// HEAD or the index, so all three values remain one candidate even if a
    /// ref or the index changes afterward.
    ///
    /// The diff must be a plain unified diff regardless of user config: a
    /// configured `diff.external` (difftastic and friends) would replace it
    /// wholesale and `color.ui` would inject escape codes, corrupting every
    /// downstream check that reads it.
    pub fn capture_candidate(&self) -> Result<CapturedCandidate, TactusError> {
        let branch_ref = self.current_branch_ref()?;
        let parent_oid = self.head_sha_full()?;
        if let Some(problem) = self.worktree_filter_problem("git add")? {
            return Err(TactusError::Git { message: problem });
        }
        self.git_with_private_hooks(&["add", "-A"])?;
        let tree_oid = self.staged_tree_oid()?;
        let diff = self.git(&[
            "-c",
            "color.ui=false",
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            &parent_oid,
            &tree_oid,
            "--",
        ])?;
        let observed_branch_ref = self.current_branch_ref()?;
        let observed_parent = self.head_sha_full()?;
        if observed_branch_ref != branch_ref || observed_parent != parent_oid {
            return Err(TactusError::Git {
                message: format!(
                    "HEAD moved from {branch_ref} at {parent_oid} to {observed_branch_ref} at {observed_parent} while capturing the candidate"
                ),
            });
        }
        Ok(CapturedCandidate {
            branch_ref,
            parent_oid,
            tree_oid,
            diff,
        })
    }

    /// Backward-compatible diff-only capture for existing callers.
    pub fn capture_diff(&self) -> Result<String, TactusError> {
        Ok(self.capture_candidate()?.diff)
    }

    fn worktree_filter_problem(&self, operation: &str) -> Result<Option<String>, TactusError> {
        // Commands that inspect or update worktree entries (`add`, `status`,
        // `switch`, `commit`) can run clean/process filters before a later
        // tree policy check. Enumerate tracked and addable untracked paths
        // without refreshing fsmonitor, then evaluate the worktree's
        // attributes without invoking a driver.
        let paths = self.git_output_with_private_hooks(&[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])?;
        self.filter_problem_for_paths(paths, None, operation)
    }

    fn refuse_worktree_filters_before(&self, operation: &str) -> Result<(), TactusError> {
        if let Some(problem) = self.worktree_filter_problem(operation)? {
            return Err(TactusError::Git { message: problem });
        }
        Ok(())
    }

    /// Refuse staged evidence whose bytes are not the bytes a gate would see,
    /// or whose worktree still contains unstaged nested state after `git add`.
    /// A clean/smudge filter makes the cached diff describe the transformed
    /// blob while gates see the smudged file. Dirty submodules similarly hide
    /// executable inputs behind an unchanged gitlink. Neither can be reviewed
    /// completely, so both are policy failures rather than gate results.
    pub fn review_input_problem(&self) -> Result<Option<String>, TactusError> {
        let tree_oid = self.staged_tree_oid()?;
        self.review_input_problem_for_tree(&tree_oid)
    }

    /// Inspect live nested-worktree state, then bind every semantic input check
    /// to one captured tree rather than to an index that may have moved since
    /// its diff was produced.
    pub fn review_input_problem_for_tree(
        &self,
        tree_oid: &str,
    ) -> Result<Option<String>, TactusError> {
        self.validate_tree_oid(tree_oid)?;
        if let Some(problem) = self.worktree_filter_problem("git status")? {
            return Ok(Some(problem));
        }
        let status = self.git_output_with_private_hooks(&[
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
            "--ignore-submodules=none",
        ])?;
        for line in status
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if line.len() < 3 || line[1] != b' ' {
                return Ok(Some(format!(
                    "the staged task still has unstaged or dirty nested-worktree state (`{}`); gates could observe bytes absent from the reviewed commit",
                    String::from_utf8_lossy(line)
                )));
            }
        }

        self.tree_input_problem(tree_oid)
    }

    fn tree_input_problem(&self, tree_oid: &str) -> Result<Option<String>, TactusError> {
        // A captured .gitattributes can attach a filter to an otherwise
        // unchanged file, so changed names are insufficient. `ls-tree`
        // enumerates every path in the exact candidate and exposes gitlinks.
        let entries = self.git_output(&["ls-tree", "-r", "-z", "--full-tree", tree_oid])?;
        let mut paths = Vec::new();
        for entry in entries
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let tab = entry
                .iter()
                .position(|byte| *byte == b'\t')
                .ok_or_else(|| TactusError::Git {
                    message: "git ls-tree returned a malformed tree entry".to_owned(),
                })?;
            let metadata = &entry[..tab];
            let path = &entry[tab + 1..];
            let mode = metadata
                .split(|byte| *byte == b' ')
                .next()
                .unwrap_or_default();
            if mode == b"160000" {
                return Ok(Some(format!(
                    "candidate-tree path `{}` is a submodule (mode 160000); exact gate snapshots do not materialize submodules",
                    String::from_utf8_lossy(path)
                )));
            }
            paths.extend_from_slice(path);
            paths.push(0);
        }

        self.filter_problem_for_paths(paths, Some(tree_oid), "")
    }

    fn filter_problem_for_paths(
        &self,
        paths: Vec<u8>,
        tree_oid: Option<&str>,
        operation: &str,
    ) -> Result<Option<String>, TactusError> {
        let attrs = if paths.is_empty() {
            Vec::new()
        } else if let Some(tree_oid) = tree_oid {
            let source = format!("--source={tree_oid}");
            self.git_output_with_input(&["check-attr", &source, "--stdin", "-z", "filter"], paths)?
        } else {
            self.git_output_with_input(&["check-attr", "--stdin", "-z", "filter"], paths)?
        };
        let mut fields: Vec<&[u8]> = attrs.split(|byte| *byte == 0).collect();
        if fields.last().is_some_and(|field| field.is_empty()) {
            fields.pop();
        }
        if fields.len() % 3 != 0 {
            return Err(TactusError::Git {
                message: "git check-attr returned malformed NUL-delimited output".to_owned(),
            });
        }
        for record in fields.chunks_exact(3) {
            let path = record[0];
            let attribute = record[1];
            let value = record[2];
            if attribute != b"filter" {
                return Err(TactusError::Git {
                    message: "git check-attr returned an unexpected attribute".to_owned(),
                });
            }
            if !matches!(value, b"unspecified" | b"unset") {
                let path = String::from_utf8_lossy(path);
                let value = String::from_utf8_lossy(value);
                return Ok(Some(if tree_oid.is_some() {
                    format!(
                        "candidate-tree path `{path}` uses clean/smudge filter `{value}`; the captured diff and gate worktree can contain different bytes"
                    )
                } else {
                    format!(
                        "working-tree path `{path}` uses clean/smudge filter `{value}`; refusing before {operation} can execute configured filter code"
                    )
                }));
            }
        }
        Ok(None)
    }

    fn refuse_unsafe_checkout_tree(&self, tree_oid: &str) -> Result<(), TactusError> {
        self.validate_tree_oid(tree_oid)?;
        if let Some(problem) = self.tree_input_problem(tree_oid)? {
            return Err(TactusError::Git {
                message: format!("refusing checkout before configured code can run: {problem}"),
            });
        }
        Ok(())
    }

    /// Read the full object ID of the index tree once. Callers that run more
    /// than one verifier can retain this identity and materialize the same
    /// bytes for each verifier even if the source index later changes.
    pub fn staged_tree_oid(&self) -> Result<String, TactusError> {
        let tree = self.git_with_private_hooks(&["write-tree"])?;
        let tree = tree.trim().to_owned();
        self.validate_tree_oid(&tree)?;
        Ok(tree)
    }

    /// A clean detached worktree whose HEAD tree is exactly the staged tree.
    /// Kept for existing callers; new callers that need more than one snapshot
    /// should retain `capture_candidate()` and use
    /// `gate_snapshot_for_candidate()`.
    pub fn gate_snapshot(&self) -> Result<GateWorkspace, TactusError> {
        let parent_oid = self.head_sha_full()?;
        let tree = self.staged_tree_oid()?;
        let observed_parent = self.head_sha_full()?;
        if observed_parent != parent_oid {
            return Err(TactusError::Git {
                message: format!(
                    "HEAD moved from {parent_oid} to {observed_parent} while preparing the gate snapshot"
                ),
            });
        }
        self.gate_snapshot_for_candidate(&parent_oid, &tree)
    }

    /// Materialize a clean detached worktree for one exact tree object ID.
    /// Gates run here, never in the worker's workspace, so ignored files,
    /// build residue, and gate side-effects cannot influence or contaminate the
    /// commit under review.
    pub fn gate_snapshot_for_tree(&self, tree_oid: &str) -> Result<GateWorkspace, TactusError> {
        let parent_oid = self.head_sha_full()?;
        self.gate_snapshot_for_candidate(&parent_oid, tree_oid)
    }

    /// Materialize one frozen candidate. Both object IDs are supplied so a
    /// concurrent ref move cannot silently change the ephemeral commit's
    /// parent after the candidate was reviewed.
    pub fn gate_snapshot_for_candidate(
        &self,
        parent_oid: &str,
        tree_oid: &str,
    ) -> Result<GateWorkspace, TactusError> {
        self.gate_snapshot_for_candidate_in(parent_oid, tree_oid, &std::env::temp_dir())
    }

    /// Materialize a candidate under a durable, caller-owned snapshot store.
    /// The intent is synced before Git registers the worktree, allowing resume
    /// to reclaim a snapshot whose owner was terminated without running Drop.
    pub fn gate_snapshot_for_candidate_in_store(
        &self,
        parent_oid: &str,
        tree_oid: &str,
        store: &Path,
    ) -> Result<GateWorkspace, TactusError> {
        self.gate_snapshot_for_candidate_in_with_mode(
            parent_oid,
            tree_oid,
            store,
            SnapshotStoreMode::ExactDurable,
            |path, hooks_path, commit| self.add_gate_worktree(path, hooks_path, commit),
        )
    }

    /// Reclaim every durable gate-worktree intent in `store`. Callers must use
    /// the same repository that created the store; intent names contain no
    /// path supplied by the candidate and cannot escape these fixed children.
    pub fn reclaim_gate_workspaces(&self, store: &Path) -> Result<usize, TactusError> {
        let intents = store.join("intents");
        let entries = match fs::read_dir(&intents) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(source) => {
                return Err(TactusError::Io {
                    path: intents,
                    source,
                });
            }
        };
        let mut reclaimed = 0;
        for entry in entries {
            let entry = entry.map_err(|source| TactusError::Io {
                path: intents.clone(),
                source,
            })?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| TactusError::Git {
                message: format!(
                    "snapshot intent {} has a non-UTF-8 name",
                    entry.path().display()
                ),
            })?;
            let Some(snapshot) = name.strip_suffix(".intent") else {
                return Err(TactusError::Git {
                    message: format!(
                        "unexpected file {} in the snapshot intent directory",
                        entry.path().display()
                    ),
                });
            };
            if !valid_snapshot_name(snapshot) {
                return Err(TactusError::Git {
                    message: format!("invalid snapshot intent name `{name}`"),
                });
            }
            cleanup_gate_workspace(
                &self.root,
                &store.join("worktrees").join(snapshot),
                &store.join("hooks").join(snapshot),
                &entry.path(),
            )?;
            reclaimed += 1;
        }
        Ok(reclaimed)
    }

    fn gate_snapshot_for_candidate_in(
        &self,
        parent_oid: &str,
        tree_oid: &str,
        temp_root: &Path,
    ) -> Result<GateWorkspace, TactusError> {
        self.gate_snapshot_for_candidate_in_with(
            parent_oid,
            tree_oid,
            temp_root,
            |path, hooks_path, commit| self.add_gate_worktree(path, hooks_path, commit),
        )
    }

    fn gate_snapshot_for_candidate_in_with<F>(
        &self,
        parent_oid: &str,
        tree_oid: &str,
        temp_root: &Path,
        add_worktree: F,
    ) -> Result<GateWorkspace, TactusError>
    where
        F: FnOnce(&Path, &Path, &str) -> Result<(), TactusError>,
    {
        self.gate_snapshot_for_candidate_in_with_mode(
            parent_oid,
            tree_oid,
            temp_root,
            SnapshotStoreMode::EphemeralUnderRoot,
            add_worktree,
        )
    }

    fn gate_snapshot_for_candidate_in_with_mode<F>(
        &self,
        parent_oid: &str,
        tree_oid: &str,
        store_or_root: &Path,
        store_mode: SnapshotStoreMode,
        add_worktree: F,
    ) -> Result<GateWorkspace, TactusError>
    where
        F: FnOnce(&Path, &Path, &str) -> Result<(), TactusError>,
    {
        self.validate_commit_oid(parent_oid)?;
        self.validate_tree_oid(tree_oid)?;
        if let Some(problem) = self.tree_input_problem(tree_oid)? {
            return Err(TactusError::Git { message: problem });
        }
        let commit = self.git(&[
            "-c",
            "user.name=tactus",
            "-c",
            "user.email=tactus@tactus.local",
            "commit-tree",
            tree_oid,
            "-p",
            parent_oid,
            "-m",
            "[tactus] ephemeral gate snapshot",
        ])?;
        let pending = match store_mode {
            SnapshotStoreMode::EphemeralUnderRoot => {
                PendingGateWorkspace::create(&self.root, store_or_root)?
            }
            SnapshotStoreMode::ExactDurable => {
                PendingGateWorkspace::create_in_store(&self.root, store_or_root)?
            }
        };
        add_worktree(&pending.path, &pending.hooks_path, commit.trim())?;
        self.verify_gate_worktree(&pending.path, &pending.hooks_path)?;

        // The exact path is already known to be the new worktree's top level.
        // Avoid round-tripping it through Git's textual path output, which is
        // not necessarily UTF-8 on Unix.
        let workspace = Workspace {
            root: pending.path.clone(),
        };
        Ok(pending.finish(workspace))
    }

    fn validate_tree_oid(&self, tree_oid: &str) -> Result<(), TactusError> {
        self.validate_object_oid(tree_oid, "tree")
    }

    fn validate_commit_oid(&self, commit_oid: &str) -> Result<(), TactusError> {
        self.validate_object_oid(commit_oid, "commit")
    }

    fn validate_object_oid(&self, oid: &str, expected_kind: &str) -> Result<(), TactusError> {
        if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TactusError::Git {
                message: format!("`{oid}` is not a full Git object ID"),
            });
        }
        let kind = self.git(&["cat-file", "-t", oid])?;
        if kind.trim() != expected_kind {
            return Err(TactusError::Git {
                message: format!(
                    "Git object {oid} is a {}, not a {expected_kind}",
                    kind.trim()
                ),
            });
        }
        Ok(())
    }

    fn add_gate_worktree(
        &self,
        path: &Path,
        hooks_path: &Path,
        commit: &str,
    ) -> Result<(), TactusError> {
        let mut hooks_config = OsString::from("core.hooksPath=");
        hooks_config.push(hooks_path);
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .arg("-c")
            .arg(hooks_config)
            .args([
                "-c",
                "core.fsmonitor=false",
                "worktree",
                "add",
                "-q",
                "--detach",
                "--force",
            ])
            .arg(path)
            .arg(commit)
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git worktree add: {e}"),
            })?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "git worktree add failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(())
    }

    fn verify_gate_worktree(&self, path: &Path, hooks_path: &Path) -> Result<(), TactusError> {
        let mut hooks_config = OsString::from("core.hooksPath=");
        hooks_config.push(hooks_path);
        let output = Command::new("git")
            .arg("-C")
            .arg(path)
            .arg("-c")
            .arg(hooks_config)
            .args([
                "-c",
                "core.fsmonitor=false",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ])
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to verify gate worktree: {e}"),
            })?;
        if !output.status.success() {
            return Err(TactusError::Git {
                message: format!(
                    "verifying gate worktree failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        if !output.stdout.is_empty() {
            return Err(TactusError::Git {
                message: format!(
                    "gate worktree materialized with unexpected tracked or untracked state: {}",
                    String::from_utf8_lossy(&output.stdout)
                ),
            });
        }
        Ok(())
    }

    /// Prepare and pin a commit from the exact candidate identities already
    /// used by gates and review. This never rereads the mutable index.
    pub fn prepare_commit_from_candidate(
        &self,
        branch_ref: &str,
        parent_oid: &str,
        tree_oid: &str,
        message: &str,
        pin_ref: &str,
    ) -> Result<PreparedCommit, TactusError> {
        self.validate_branch_ref(branch_ref)?;
        self.validate_commit_oid(parent_oid)?;
        self.validate_tree_oid(tree_oid)?;
        let observed_branch_ref = self.current_branch_ref()?;
        let observed_parent = self.head_sha_full()?;
        if observed_branch_ref != branch_ref || observed_parent != parent_oid {
            return Err(TactusError::Git {
                message: format!(
                    "HEAD moved from captured branch {branch_ref} at {parent_oid} to {observed_branch_ref} at {observed_parent}; refusing to prepare it"
                ),
            });
        }
        if message.trim().is_empty() || message.contains('\r') || message.contains('\n') {
            return Err(TactusError::Git {
                message: "refusing to prepare a commit with an empty or multi-line subject"
                    .to_owned(),
            });
        }
        self.validate_prepared_ref(pin_ref)?;
        if let Some(target) = self.symbolic_ref_target(pin_ref)? {
            return Err(TactusError::Git {
                message: format!(
                    "prepared ref `{pin_ref}` is symbolic to `{target}`; refusing to follow it"
                ),
            });
        }
        let commit_sha = self
            .commit_tree_with_tactus_identity(tree_oid, parent_oid, message)?
            .trim()
            .to_owned();
        let prepared = PreparedCommit {
            branch_ref: branch_ref.to_owned(),
            parent_sha: parent_oid.to_owned(),
            tree_sha: tree_oid.to_owned(),
            commit_sha,
            message: message.to_owned(),
            pin_ref: pin_ref.to_owned(),
        };
        if !self.prepared_commit_matches(&prepared)? {
            return Err(TactusError::Git {
                message: "git created a commit object that does not match the prepared identity"
                    .to_owned(),
            });
        }
        let zero = "0".repeat(parent_oid.len());
        self.prepared_update_ref(&[
            "update-ref",
            "--no-deref",
            "-m",
            "tactus: pin prepared task",
            pin_ref,
            &prepared.commit_sha,
            &zero,
        ])?;
        if self.prepared_pin_target(pin_ref)?.as_deref() != Some(prepared.commit_sha.as_str()) {
            return Err(TactusError::Git {
                message: format!(
                    "prepared ref `{pin_ref}` did not become the exact direct pin for {}",
                    prepared.commit_sha
                ),
            });
        }
        Ok(prepared)
    }

    /// Commit whatever `capture_diff` staged. §14: commit-per-task,
    /// `[tactus] <task-id>: <title>`.
    pub fn commit(&self, message: &str) -> Result<String, TactusError> {
        self.refuse_worktree_filters_before("git commit")?;
        self.git_with_private_hooks(&["commit", "-q", "-m", message])?;
        self.head_sha()
    }

    pub fn prepared_commit_matches(&self, prepared: &PreparedCommit) -> Result<bool, TactusError> {
        if !valid_object_id(&prepared.parent_sha)
            || !valid_object_id(&prepared.tree_sha)
            || !valid_object_id(&prepared.commit_sha)
            || self.validate_branch_ref(&prepared.branch_ref).is_err()
        {
            return Ok(false);
        }
        if self.validate_prepared_ref(&prepared.pin_ref).is_err() {
            return Ok(false);
        }
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["cat-file", "commit", &prepared.commit_sha])
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        if !output.status.success() {
            return Ok(false);
        }
        let object = String::from_utf8(output.stdout).map_err(|error| TactusError::Git {
            message: format!("prepared commit object is not valid UTF-8: {error}"),
        })?;
        let Some((headers, body)) = object.split_once("\n\n") else {
            return Ok(false);
        };
        let tree = headers.lines().find_map(|line| line.strip_prefix("tree "));
        let parents: Vec<&str> = headers
            .lines()
            .filter_map(|line| line.strip_prefix("parent "))
            .collect();
        let author = headers
            .lines()
            .find_map(|line| line.strip_prefix("author "));
        let committer = headers
            .lines()
            .find_map(|line| line.strip_prefix("committer "));
        Ok(tree == Some(prepared.tree_sha.as_str())
            && parents == [prepared.parent_sha.as_str()]
            && author.is_some_and(|value| value.starts_with("tactus <tactus@tactus.local> "))
            && committer.is_some_and(|value| value.starts_with("tactus <tactus@tactus.local> "))
            && body.trim_end_matches('\n') == prepared.message)
    }

    fn validate_prepared_ref(&self, pin_ref: &str) -> Result<(), TactusError> {
        if !pin_ref.starts_with("refs/tactus/prepared/") {
            return Err(TactusError::Git {
                message: format!("prepared ref `{pin_ref}` is outside tactus's private namespace"),
            });
        }
        self.git(&["check-ref-format", pin_ref]).map(|_| ())
    }

    fn validate_branch_ref(&self, branch_ref: &str) -> Result<(), TactusError> {
        if !branch_ref.starts_with("refs/heads/") {
            return Err(TactusError::Git {
                message: format!(
                    "refusing prepared publication outside a local branch: `{branch_ref}`"
                ),
            });
        }
        self.git(&["check-ref-format", branch_ref]).map(|_| ())
    }

    /// Return the immediate symbolic target without dereferencing it.
    fn symbolic_ref_target(&self, refname: &str) -> Result<Option<String>, TactusError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["symbolic-ref", "--quiet", "--no-recurse", refname])
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        if output.status.success() {
            return String::from_utf8(output.stdout)
                .map(|target| Some(target.trim().to_owned()))
                .map_err(|error| TactusError::Git {
                    message: format!(
                        "git symbolic-ref returned output that is not valid UTF-8: {error}"
                    ),
                });
        }
        if output.status.code() == Some(1) {
            return Ok(None);
        }
        Err(TactusError::Git {
            message: format!(
                "git symbolic-ref --quiet {refname} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        })
    }

    pub fn prepared_pin_target(&self, pin_ref: &str) -> Result<Option<String>, TactusError> {
        self.validate_prepared_ref(pin_ref)?;
        if let Some(target) = self.symbolic_ref_target(pin_ref)? {
            return Err(TactusError::Git {
                message: format!(
                    "prepared ref `{pin_ref}` is symbolic to `{target}`; refusing to follow it"
                ),
            });
        }
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "--verify", "--quiet", pin_ref])
            .output()
            .map_err(|e| TactusError::Git {
                message: format!("failed to run git: {e}"),
            })?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ))
    }

    pub fn remove_prepared_pin(&self, prepared: &PreparedCommit) -> Result<(), TactusError> {
        match self.prepared_pin_target(&prepared.pin_ref)? {
            None => Ok(()),
            Some(target) if target == prepared.commit_sha => self.prepared_update_ref(&[
                "update-ref",
                "--no-deref",
                "-d",
                &prepared.pin_ref,
                &prepared.commit_sha,
            ]),
            Some(target) => Err(TactusError::Git {
                message: format!(
                    "prepared ref `{}` points at {target}, not the recorded commit {}; refusing to delete another object",
                    prepared.pin_ref, prepared.commit_sha
                ),
            }),
        }
    }

    /// Remove a private pin for an attempt that never durably recorded a
    /// successful settlement. The target is read then supplied as the expected
    /// old value, so even cleanup is compare-and-swap.
    pub fn remove_orphan_prepared_pin(&self, pin_ref: &str) -> Result<(), TactusError> {
        if let Some(target) = self.prepared_pin_target(pin_ref)? {
            self.prepared_update_ref(&["update-ref", "--no-deref", "-d", pin_ref, &target])?;
        }
        Ok(())
    }

    pub fn advance_prepared_commit(
        &self,
        branch_ref: &str,
        prepared: &PreparedCommit,
    ) -> Result<(), TactusError> {
        self.validate_branch_ref(branch_ref)?;
        if prepared.branch_ref != branch_ref {
            return Err(TactusError::Git {
                message: format!(
                    "prepared commit belongs to `{}`, not requested publication ref `{branch_ref}`",
                    prepared.branch_ref
                ),
            });
        }
        let observed_branch_ref = self.current_branch_ref()?;
        if observed_branch_ref != branch_ref {
            return Err(TactusError::Git {
                message: format!(
                    "HEAD is on `{observed_branch_ref}`, not recorded run branch `{branch_ref}`; refusing publication"
                ),
            });
        }
        if !self.prepared_commit_matches(prepared)? {
            return Err(TactusError::Git {
                message: "refusing to advance HEAD to a commit that does not match its durable prepared identity".to_owned(),
            });
        }
        if self.prepared_pin_target(&prepared.pin_ref)?.as_deref()
            != Some(prepared.commit_sha.as_str())
        {
            return Err(TactusError::Git {
                message: format!(
                    "prepared ref `{}` does not pin {}; refusing to advance HEAD",
                    prepared.pin_ref, prepared.commit_sha
                ),
            });
        }
        self.prepared_update_ref(&[
            "update-ref",
            "--no-deref",
            "-m",
            "tactus: publish reviewed task",
            branch_ref,
            &prepared.commit_sha,
            &prepared.parent_sha,
        ])?;
        let published_branch_ref = self.current_branch_ref()?;
        let published_head = self.head_sha_full()?;
        if published_branch_ref != branch_ref || published_head != prepared.commit_sha {
            return Err(TactusError::Git {
                message: format!(
                    "recorded run branch {branch_ref} advanced to {}, but worktree HEAD is now {published_branch_ref} at {published_head}; preserving the prepared pin for resume",
                    prepared.commit_sha
                ),
            });
        }
        self.remove_prepared_pin(prepared)
    }

    /// Discard everything since the last commit: staged, unstaged, and
    /// untracked (ignored files survive). This is both the §14 rollback on a
    /// failed attempt and the post-commit scrub that keeps gate side-effects
    /// (build artifacts, lockfile churn) from leaking into the next task's
    /// captured diff.
    pub fn discard_uncommitted(&self) -> Result<(), TactusError> {
        let tree_oid = self.git(&["rev-parse", "HEAD^{tree}"])?;
        self.refuse_unsafe_checkout_tree(tree_oid.trim())?;
        self.git_with_private_hooks(&["reset", "-q", "--hard", "HEAD"])?;
        self.git_with_private_hooks(&["clean", "-qfd"]).map(|_| ())
    }
}

fn require_check_attr_source(probe: Result<Vec<u8>, TactusError>) -> Result<(), TactusError> {
    probe.map(|_| ()).map_err(|error| TactusError::Refused {
        message: format!(
            "Git 2.40 or newer is required: tactus must bind filter-attribute checks to the exact captured tree with `git check-attr --source` before gates or review ({error})"
        ),
    })
}

struct PrivateHooksDir {
    path: PathBuf,
}

impl PrivateHooksDir {
    fn create() -> Result<Self, TactusError> {
        let path = std::env::temp_dir().join(format!(
            "tactus-empty-hooks-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        create_private_dir(&path).map_err(|error| TactusError::Git {
            message: format!(
                "creating private empty hooks directory {}: {error}",
                path.display()
            ),
        })?;
        Ok(Self { path })
    }
}

impl Drop for PrivateHooksDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

#[derive(Clone, Copy)]
enum SnapshotStoreMode {
    /// `store_or_root` is a shared parent such as the system temp directory.
    /// Create one atomically private child and remove it after normal cleanup.
    EphemeralUnderRoot,
    /// `store_or_root` is the stable per-run store whose intents resume scans.
    ExactDurable,
}

struct PendingGateWorkspace {
    source_root: PathBuf,
    path: PathBuf,
    hooks_path: PathBuf,
    intent_path: PathBuf,
    ephemeral_store: Option<PathBuf>,
    armed: bool,
}

impl PendingGateWorkspace {
    /// Create a uniquely named, owner-private store beneath a caller-owned
    /// root. The root may be shared (notably `/tmp`) and is never chmodded.
    fn create(source_root: &Path, temp_root: &Path) -> Result<Self, TactusError> {
        let store = temp_root.join(format!(
            "tactus-gate-worktrees-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        create_private_dir(&store).map_err(|error| TactusError::Git {
            message: format!(
                "creating private gate snapshot store {}: {error}",
                store.display()
            ),
        })?;
        match Self::create_in_store_inner(source_root, &store, Some(store.clone())) {
            Ok(pending) => Ok(pending),
            Err(error) => {
                let _ = fs::remove_dir_all(&store);
                Err(error)
            }
        }
    }

    /// Use the exact stable store whose synced intents resume will reclaim.
    fn create_in_store(source_root: &Path, store: &Path) -> Result<Self, TactusError> {
        if store == std::env::temp_dir() {
            return Err(TactusError::Git {
                message: format!(
                    "the shared system temp root {} is not a durable snapshot store; supply an owner-private child directory",
                    store.display()
                ),
            });
        }
        Self::create_in_store_inner(source_root, store, None)
    }

    fn create_in_store_inner(
        source_root: &Path,
        store: &Path,
        ephemeral_store: Option<PathBuf>,
    ) -> Result<Self, TactusError> {
        let name = format!(
            "tactus-gates-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        );
        let intents = store.join("intents");
        let worktrees = store.join("worktrees");
        let hooks = store.join("hooks");
        for directory in [
            store,
            intents.as_path(),
            worktrees.as_path(),
            hooks.as_path(),
        ] {
            create_private_dir_all(directory).map_err(|error| TactusError::Git {
                message: format!(
                    "creating private gate snapshot store {}: {error}",
                    directory.display()
                ),
            })?;
        }
        let intent_path = intents.join(format!("{name}.intent"));
        create_snapshot_intent(&intent_path)?;
        let path = worktrees.join(&name);
        let hooks_path = hooks.join(&name);
        if let Err(error) = create_private_dir(&path) {
            let _ = fs::remove_file(&intent_path);
            return Err(TactusError::Git {
                message: format!(
                    "creating private gate snapshot directory {}: {error}",
                    path.display()
                ),
            });
        }
        if let Err(error) = create_private_dir(&hooks_path) {
            let _ = fs::remove_dir(&path);
            let _ = fs::remove_file(&intent_path);
            return Err(TactusError::Git {
                message: format!(
                    "creating private empty hooks directory {}: {error}",
                    hooks_path.display()
                ),
            });
        }
        Ok(Self {
            source_root: source_root.to_path_buf(),
            path,
            hooks_path,
            intent_path,
            ephemeral_store,
            armed: true,
        })
    }

    fn finish(mut self, workspace: Workspace) -> GateWorkspace {
        self.armed = false;
        GateWorkspace {
            source_root: self.source_root.clone(),
            path: self.path.clone(),
            hooks_path: self.hooks_path.clone(),
            intent_path: self.intent_path.clone(),
            ephemeral_store: self.ephemeral_store.clone(),
            workspace,
        }
    }
}

impl Drop for PendingGateWorkspace {
    fn drop(&mut self) {
        if self.armed {
            let cleaned = cleanup_gate_workspace(
                &self.source_root,
                &self.path,
                &self.hooks_path,
                &self.intent_path,
            );
            if cleaned.is_ok() {
                remove_ephemeral_store(self.ephemeral_store.as_deref());
            }
        }
    }
}

fn create_snapshot_intent(path: &Path) -> Result<(), TactusError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| TactusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), TactusError> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or_else(|| TactusError::Git {
            message: format!("snapshot intent {} has no parent", path.display()),
        })?;
        let directory = fs::File::open(parent).map_err(|source| TactusError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        directory.sync_all().map_err(|source| TactusError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn valid_snapshot_name(name: &str) -> bool {
    name.starts_with("tactus-gates-")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::DirBuilder::new().create(path)
    }
}

fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn remove_ephemeral_store(store: Option<&Path>) {
    if let Some(store) = store {
        let _ = fs::remove_dir(store);
    }
}

fn cleanup_gate_workspace(
    source_root: &Path,
    path: &Path,
    hooks_path: &Path,
    intent_path: &Path,
) -> Result<(), TactusError> {
    let mut hooks_config = OsString::from("core.hooksPath=");
    hooks_config.push(hooks_path);
    let removal = Command::new("git")
        .arg("-C")
        .arg(source_root)
        .arg("-c")
        .arg(&hooks_config)
        .args([
            "-c",
            "core.fsmonitor=false",
            "worktree",
            "remove",
            "--force",
        ])
        .arg(path)
        .output()
        .map_err(|error| TactusError::Git {
            message: format!("failed to remove gate worktree {}: {error}", path.display()),
        })?;
    if worktree_is_registered(source_root, path, &hooks_config)? {
        return Err(TactusError::Git {
            message: format!(
                "could not reclaim registered gate worktree {}: {}",
                path.display(),
                String::from_utf8_lossy(&removal.stderr).trim()
            ),
        });
    }
    // `worktree remove` normally removes the directory too. Once Git confirms
    // no registration remains, these exact private paths are safe to remove
    // even if a partially failed add populated only part of either one.
    let _ = fs::remove_dir_all(path);
    let _ = fs::remove_dir_all(hooks_path);
    match fs::remove_file(intent_path) {
        Ok(()) => sync_parent(intent_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(TactusError::Io {
                path: intent_path.to_path_buf(),
                source,
            });
        }
    }
    for directory in [intent_path.parent(), hooks_path.parent(), path.parent()]
        .into_iter()
        .flatten()
    {
        let _ = fs::remove_dir(directory);
    }
    Ok(())
}

fn worktree_is_registered(
    source_root: &Path,
    path: &Path,
    hooks_config: &std::ffi::OsStr,
) -> Result<bool, TactusError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(source_root)
        .arg("-c")
        .arg(hooks_config)
        .args([
            "-c",
            "core.fsmonitor=false",
            "worktree",
            "list",
            "--porcelain",
            "-z",
        ])
        .output()
        .map_err(|error| TactusError::Git {
            message: format!("failed to verify gate-worktree reclamation: {error}"),
        })?;
    if !output.status.success() {
        return Err(TactusError::Git {
            message: format!(
                "verifying gate-worktree reclamation failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter_map(|field| field.strip_prefix(b"worktree "))
        .any(|field| git_path_field_matches(field, path)))
}

#[cfg(unix)]
fn git_path_field_matches(field: &[u8], path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    field == path.as_os_str().as_bytes()
}

#[cfg(windows)]
fn git_path_field_matches(field: &[u8], path: &Path) -> bool {
    let rendered = String::from_utf8_lossy(field).replace('/', "\\");
    Path::new(&rendered) == path
}

#[cfg(not(any(unix, windows)))]
fn git_path_field_matches(field: &[u8], path: &Path) -> bool {
    String::from_utf8_lossy(field) == path.to_string_lossy()
}

fn valid_object_id(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub struct GateWorkspace {
    source_root: PathBuf,
    path: PathBuf,
    hooks_path: PathBuf,
    intent_path: PathBuf,
    ephemeral_store: Option<PathBuf>,
    workspace: Workspace,
}

impl GateWorkspace {
    pub fn workspace(&self) -> &Workspace {
        &self.workspace
    }
}

impl Drop for GateWorkspace {
    fn drop(&mut self) {
        let cleaned = cleanup_gate_workspace(
            &self.source_root,
            &self.path,
            &self.hooks_path,
            &self.intent_path,
        );
        if cleaned.is_ok() {
            remove_ephemeral_store(self.ephemeral_store.as_deref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_repo(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("tactus-ws-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create repo dir");
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .expect("run git");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "-q", "-b", "main"]);
        run(&["config", "user.email", "test@tactus.local"]);
        run(&["config", "user.name", "tactus tests"]);
        fs::write(dir.join("README.md"), "seed\n").expect("seed file");
        run(&["add", "-A"]);
        run(&["commit", "-q", "-m", "seed"]);
        dir
    }

    fn run_git(repo: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(path).expect("hook metadata").permissions();
            permissions.set_mode(permissions.mode() | 0o111);
            fs::set_permissions(path, permissions).expect("make hook executable");
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    #[test]
    fn open_requires_a_git_worktree() {
        let repo = temp_repo("open");
        assert!(Workspace::open(&repo).is_ok());

        let plain = env::temp_dir().join(format!("tactus-ws-plain-{}", std::process::id()));
        fs::create_dir_all(&plain).expect("plain dir");
        assert!(Workspace::open(&plain).is_err());
    }

    #[test]
    fn sparse_checkout_is_refused_before_worker_spend() {
        let repo = temp_repo("sparse-preflight");
        // Set these in separate commands: update-index applies only the final
        // mode option from one invocation. The combination guards against a
        // detector accidentally keying off assume-unchanged's presentation.
        run_git(&repo, &["update-index", "--skip-worktree", "README.md"]);
        run_git(&repo, &["update-index", "--assume-unchanged", "README.md"]);
        let workspace = Workspace::open(&repo).expect("open");

        let error = workspace
            .ensure_execution_prerequisites()
            .expect_err("an incomplete index must fail closed")
            .to_string();
        assert!(error.contains("sparse checkout is active"), "{error}");
        run_git(&repo, &["update-index", "--no-skip-worktree", "README.md"]);
        run_git(
            &repo,
            &["update-index", "--no-assume-unchanged", "README.md"],
        );
        workspace
            .ensure_execution_prerequisites()
            .expect("a complete checkout is accepted");
    }

    #[test]
    fn git_without_check_attr_source_is_refused_before_worker_spend() {
        let error = require_check_attr_source(Err(TactusError::Git {
            message: "error: unknown option `source=HEAD`".to_owned(),
        }))
        .expect_err("missing exact-tree attribute support must fail closed")
        .to_string();
        assert!(error.contains("Git 2.40 or newer"), "{error}");
        assert!(error.contains("check-attr --source"), "{error}");
    }

    #[test]
    fn clean_detection_and_rollback() {
        let repo = temp_repo("clean");
        let ws = Workspace::open(&repo).expect("open");
        assert!(ws.is_clean().expect("clean check"));

        fs::write(repo.join("README.md"), "changed\n").expect("edit");
        fs::write(repo.join("stray.txt"), "untracked\n").expect("stray");
        assert!(!ws.is_clean().expect("dirty check"));

        ws.discard_uncommitted().expect("discard");
        assert!(ws.is_clean().expect("clean again"));
        assert!(!repo.join("stray.txt").exists(), "untracked cleaned");
        // core.autocrlf may legitimately restore CRLF on Windows checkouts.
        let readme = fs::read_to_string(repo.join("README.md")).expect("read");
        assert_eq!(readme.replace("\r\n", "\n"), "seed\n");
    }

    #[test]
    fn branch_diff_commit_cycle() {
        let repo = temp_repo("cycle");
        let ws = Workspace::open(&repo).expect("open");
        ws.create_branch("tactus/run-TEST").expect("branch");
        assert_eq!(ws.current_branch().expect("branch name"), "tactus/run-TEST");

        fs::write(repo.join("new.rs"), "fn main() {}\n").expect("new file");
        let diff = ws.capture_diff().expect("diff");
        assert!(diff.contains("new.rs"), "diff sees new files: {diff}");
        assert!(diff.contains("fn main"), "diff carries content");

        let sha = ws.commit("[tactus] t1: demo").expect("commit");
        assert!(!sha.is_empty());
        assert!(ws.is_clean().expect("clean after commit"));
        assert!(ws.capture_diff().expect("empty diff").trim().is_empty());

        // What `resume` reads to recognise a commit as its own.
        let full = ws.head_sha_full().expect("full sha");
        assert_eq!(
            ws.commit_subject(&full).expect("subject"),
            "[tactus] t1: demo"
        );
        let parent = ws.parent_sha(&full).expect("parent").expect("has a parent");
        assert_ne!(parent, full);
        assert_eq!(
            ws.parent_sha(&parent).expect("root lookup"),
            None,
            "the seed commit is the root, and that is an answer rather than an error"
        );
    }

    #[test]
    fn captured_candidate_keeps_one_parent_tree_and_diff() {
        let repo = temp_repo("captured-candidate");
        let ws = Workspace::open(&repo).expect("open");
        let original_parent = ws.head_sha_full().expect("parent before capture");
        fs::write(repo.join("README.md"), "first candidate\n").expect("first edit");

        let candidate = ws.capture_candidate().expect("capture candidate");
        assert_eq!(candidate.branch_ref, "refs/heads/main");
        assert_eq!(candidate.parent_oid, original_parent);
        assert!(
            candidate.diff.contains("first candidate"),
            "{}",
            candidate.diff
        );
        assert_eq!(
            ws.git(&["cat-file", "-t", &candidate.tree_oid])
                .expect("tree type")
                .trim(),
            "tree"
        );

        // Advance the index after capture, then prove the supplied tree still
        // materializes the first candidate rather than rereading that index.
        fs::write(repo.join("README.md"), "second candidate\n").expect("second edit");
        ws.capture_diff().expect("stage second candidate");
        let snapshot = ws
            .gate_snapshot_for_candidate(&candidate.parent_oid, &candidate.tree_oid)
            .expect("materialize frozen tree");
        assert_eq!(
            fs::read_to_string(snapshot.workspace().root().join("README.md"))
                .expect("frozen README")
                .replace("\r\n", "\n"),
            "first candidate\n"
        );
        let snapshot_commit = snapshot
            .workspace()
            .head_sha_full()
            .expect("snapshot commit");
        assert_eq!(
            snapshot
                .workspace()
                .parent_sha(&snapshot_commit)
                .expect("snapshot parent"),
            Some(candidate.parent_oid.clone()),
            "the ephemeral commit must retain the captured parent, not mutable HEAD"
        );

        let error = match ws.gate_snapshot_for_tree(&candidate.parent_oid) {
            Ok(_) => panic!("a commit object is not a supplied tree OID"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("not a tree"), "{error}");
    }

    #[test]
    fn prepared_commit_uses_frozen_objects_identity_and_hook_free_ref_transactions() {
        let repo = temp_repo("prepared");
        let ws = Workspace::open(&repo).expect("open");
        let hook_marker = repo.join("hook-ran");
        ws.git(&["config", "core.hooksPath", ".githooks"])
            .expect("candidate-controlled hooks path");
        fs::create_dir_all(repo.join(".githooks")).expect("hooks directory");
        let hook = repo.join(".githooks").join("reference-transaction");
        fs::write(
            &hook,
            format!(
                "#!/bin/sh\nprintf ran > '{}'\nexit 1\n",
                hook_marker.display()
            ),
        )
        .expect("hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("executable hook");
        }

        fs::write(repo.join("README.md"), "reviewed candidate\n").expect("candidate");
        let candidate = ws.capture_candidate().expect("freeze candidate");
        fs::write(repo.join("README.md"), "later unreviewed index\n").expect("later edit");
        ws.capture_diff().expect("move index past candidate");

        let pin_ref = "refs/tactus/prepared/01RUN/0-1";
        let prepared = ws
            .prepare_commit_from_candidate(
                &candidate.branch_ref,
                &candidate.parent_oid,
                &candidate.tree_oid,
                "[tactus] t1: task",
                pin_ref,
            )
            .expect("commit-tree and pin creation ignore candidate hooks");
        assert_eq!(ws.head_sha_full().expect("head"), candidate.parent_oid);
        assert_eq!(
            ws.prepared_pin_target(pin_ref).expect("pin").as_deref(),
            Some(prepared.commit_sha.as_str()),
            "the object is reachable before settlement"
        );
        let object = ws
            .git(&["cat-file", "commit", &prepared.commit_sha])
            .expect("prepared object");
        assert!(
            object.contains("author tactus <tactus@tactus.local> "),
            "{object}"
        );
        assert!(
            object.contains("committer tactus <tactus@tactus.local> "),
            "{object}"
        );
        assert_eq!(
            ws.git(&["show", &format!("{}:README.md", prepared.commit_sha)])
                .expect("frozen blob"),
            "reviewed candidate\n",
            "preparation never rereads the later index"
        );
        assert!(!hook_marker.exists(), "pin creation never ran the ref hook");

        ws.advance_prepared_commit(&candidate.branch_ref, &prepared)
            .expect("branch CAS");
        assert_eq!(
            ws.head_sha_full().expect("advanced head"),
            prepared.commit_sha
        );
        assert_eq!(ws.prepared_pin_target(pin_ref).expect("deleted pin"), None);
        assert!(
            !hook_marker.exists(),
            "neither HEAD publication nor pin deletion ran the ref hook"
        );
    }

    #[test]
    fn prepared_pins_reject_symbolic_refs_without_touching_the_victim() {
        let repo = temp_repo("prepared-symbolic-pin");
        let ws = Workspace::open(&repo).expect("open");
        let victim_before = ws.head_sha_full().expect("victim target");
        run_git(&repo, &["branch", "victim", &victim_before]);

        fs::write(repo.join("README.md"), "reviewed candidate\n").expect("candidate");
        let candidate = ws.capture_candidate().expect("capture");
        let pin_ref = "refs/tactus/prepared/01RUN/0-1";
        run_git(&repo, &["symbolic-ref", pin_ref, "refs/heads/victim"]);

        let prepare_error = ws
            .prepare_commit_from_candidate(
                &candidate.branch_ref,
                &candidate.parent_oid,
                &candidate.tree_oid,
                "[tactus] t1: task",
                pin_ref,
            )
            .expect_err("a private prepared pin must be direct");
        assert!(
            prepare_error.to_string().contains("is symbolic"),
            "{prepare_error}"
        );

        let cleanup_error = ws
            .remove_orphan_prepared_pin(pin_ref)
            .expect_err("cleanup must not dereference the private symref");
        assert!(
            cleanup_error.to_string().contains("is symbolic"),
            "{cleanup_error}"
        );
        assert_eq!(
            String::from_utf8(run_git(&repo, &["rev-parse", "refs/heads/victim"]))
                .expect("utf8")
                .trim(),
            victim_before,
            "the victim branch survives both create and cleanup paths"
        );
        assert_eq!(
            ws.symbolic_ref_target(pin_ref)
                .expect("inspect symref")
                .as_deref(),
            Some("refs/heads/victim"),
            "refusal preserves the hostile pin for explicit operator repair"
        );
    }

    #[test]
    fn prepared_publication_refuses_same_oid_symbolic_head_change_after_capture() {
        let repo = temp_repo("prepared-branch-binding");
        let ws = Workspace::open(&repo).expect("open");
        fs::write(repo.join("README.md"), "reviewed candidate\n").expect("candidate");
        let candidate = ws.capture_candidate().expect("capture on main");
        assert_eq!(candidate.branch_ref, "refs/heads/main");

        ws.create_branch("other").expect("same-OID branch switch");
        assert_eq!(
            ws.head_sha_full().expect("same parent"),
            candidate.parent_oid
        );
        let before_prepare = ws
            .prepare_commit_from_candidate(
                &candidate.branch_ref,
                &candidate.parent_oid,
                &candidate.tree_oid,
                "[tactus] t1: task",
                "refs/tactus/prepared/01RUN/0-1",
            )
            .expect_err("same object on another branch is still the wrong owner");
        assert!(
            before_prepare.to_string().contains("HEAD moved"),
            "{before_prepare}"
        );

        ws.switch_branch("main").expect("return to captured branch");
        let prepared = ws
            .prepare_commit_from_candidate(
                &candidate.branch_ref,
                &candidate.parent_oid,
                &candidate.tree_oid,
                "[tactus] t1: task",
                "refs/tactus/prepared/01RUN/0-1",
            )
            .expect("prepare on captured branch");
        ws.switch_branch("other").expect("switch after preparation");
        let publish_error = ws
            .advance_prepared_commit(&candidate.branch_ref, &prepared)
            .expect_err("publication must not follow mutable HEAD");
        assert!(
            publish_error
                .to_string()
                .contains("not recorded run branch"),
            "{publish_error}"
        );
        assert_eq!(
            String::from_utf8(run_git(&repo, &["rev-parse", "refs/heads/main"]))
                .expect("utf8")
                .trim(),
            candidate.parent_oid,
            "the recorded branch is unchanged"
        );
        assert_eq!(
            String::from_utf8(run_git(&repo, &["rev-parse", "refs/heads/other"]))
                .expect("utf8")
                .trim(),
            candidate.parent_oid,
            "the current unrelated branch is unchanged"
        );
        assert_eq!(
            ws.prepared_pin_target(&prepared.pin_ref)
                .expect("pin retained")
                .as_deref(),
            Some(prepared.commit_sha.as_str()),
            "resume still has the exact prepared object"
        );
    }

    #[test]
    fn run_exclusions_hide_tactus_dir() {
        let repo = temp_repo("exclude");
        let ws = Workspace::open(&repo).expect("open");
        ws.ensure_run_exclusions().expect("exclude");
        ws.ensure_run_exclusions().expect("idempotent");
        fs::create_dir_all(repo.join(".tactus").join("runs")).expect("run dir");
        fs::write(repo.join(".tactus").join("runs").join("x.json"), "{}").expect("artifact");
        assert!(ws.is_clean().expect("tactus dir invisible"));
        assert!(
            ws.capture_diff().expect("diff").trim().is_empty(),
            "run artifacts never enter a commit"
        );
    }

    #[test]
    fn exclusions_work_in_a_linked_worktree() {
        let repo = temp_repo("worktree-main");
        let linked = repo
            .parent()
            .expect("parent")
            .join(format!("tactus-ws-worktree-linked-{}", std::process::id()));
        let _ = fs::remove_dir_all(&linked);
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["worktree", "add", "-q", "-b", "wt"])
            .arg(&linked)
            .output()
            .expect("git worktree add");
        assert!(
            out.status.success(),
            "worktree add: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let ws = Workspace::open(&linked).expect("open linked worktree");
        let main_ws = Workspace::open(&repo).expect("open main worktree");
        assert_ne!(
            fs::canonicalize(ws.worktree_git_dir().expect("linked private git dir"))
                .expect("canonical linked git dir"),
            fs::canonicalize(main_ws.worktree_git_dir().expect("main private git dir"))
                .expect("canonical main git dir"),
            "each physical worktree needs an independent lease directory"
        );
        ws.ensure_run_exclusions().expect("exclude");
        fs::create_dir_all(linked.join(".tactus").join("runs")).expect("run dir");
        fs::write(linked.join(".tactus").join("runs").join("t.json"), "{}").expect("artifact");
        assert!(
            ws.is_clean().expect("status"),
            "linked worktrees read excludes from the common dir, so info/exclude would not work"
        );
    }

    #[test]
    fn open_normalizes_to_the_worktree_toplevel() {
        let repo = temp_repo("toplevel");
        let nested = repo.join("crates").join("inner");
        fs::create_dir_all(&nested).expect("nested dirs");
        let ws = Workspace::open(&nested).expect("open from a subdirectory");
        // Compare canonically: temp dirs may be reached via a symlinked path.
        let expected = fs::canonicalize(&repo).expect("canonical repo");
        let actual = fs::canonicalize(ws.root()).expect("canonical root");
        assert_eq!(
            actual, expected,
            "root normalized to the worktree top level"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worktree_git_dir_preserves_non_utf8_repo_path() {
        use std::os::unix::ffi::OsStringExt;

        let mut name = format!("tactus-ws-non-utf8-git-dir-{}-", std::process::id()).into_bytes();
        name.push(0xff);
        let repo = env::temp_dir().join(OsString::from_vec(name));
        let _ = fs::remove_dir_all(&repo);
        fs::create_dir(&repo).expect("create non-UTF-8 repo");
        run_git(&repo, &["init", "-q", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "test@tactus.local"]);
        run_git(&repo, &["config", "user.name", "tactus tests"]);
        fs::write(repo.join("README.md"), "seed\n").expect("seed file");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "seed"]);

        let workspace = Workspace::open(&repo).expect("open non-UTF-8 worktree");
        assert_eq!(
            fs::canonicalize(workspace.root()).expect("canonical workspace root"),
            fs::canonicalize(&repo).expect("canonical expected root")
        );
        assert_eq!(
            fs::canonicalize(
                workspace
                    .worktree_git_dir()
                    .expect("resolve non-UTF-8 git dir")
            )
            .expect("canonical resolved git dir"),
            fs::canonicalize(repo.join(".git")).expect("canonical expected git dir")
        );
        fs::remove_dir_all(repo).expect("remove non-UTF-8 repo");
    }

    #[test]
    fn capture_diff_is_immune_to_user_diff_config() {
        let repo = temp_repo("extdiff");
        // Simulate a user with difftastic-style config and forced color.
        let set = |k: &str, v: &str| {
            let out = Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["config", "--local", k, v])
                .output()
                .expect("git config");
            assert!(out.status.success());
        };
        set("diff.external", "definitely-not-a-real-differ");
        set("color.ui", "always");
        set("color.diff", "always");

        let ws = Workspace::open(&repo).expect("open");
        fs::write(repo.join("new.rs"), "#[test]\nfn works() {}\n").expect("file");
        let diff = ws.capture_diff().expect("diff");
        assert!(diff.contains("+++ "), "plain unified diff: {diff}");
        assert!(!diff.contains('\u{1b}'), "no ANSI escapes: {diff}");
    }

    #[test]
    fn opaque_git_diffs_are_rejected_before_review() {
        let repo = temp_repo("opaque-diff");
        let ws = Workspace::open(&repo).expect("open");

        // A candidate controls .gitattributes. Without --binary, marking a
        // source path -diff replaces all changed bytes with the tiny sentence
        // "Binary files differ", which a read-only reviewer cannot recover.
        fs::write(repo.join(".gitattributes"), "hidden.rs -diff\n").expect("attributes");
        fs::write(repo.join("hidden.rs"), "fn hidden_change() {}\n").expect("hidden source");
        fs::write(repo.join("asset.bin"), b"\0opaque bytes\xff").expect("binary asset");

        let diff = ws.capture_diff().expect("binary-complete diff");
        assert!(
            diff.lines().any(|line| line == "GIT binary patch"),
            "opaque paths must be represented explicitly: {diff}"
        );
        let refusal = crate::review::complete_diff_error(&diff)
            .expect("an opaque patch cannot receive a semantic review");
        assert!(refusal.to_string().contains("opaque binary"), "{refusal}");
    }

    #[test]
    fn non_utf8_text_diff_is_refused_before_review() {
        let repo = temp_repo("non-utf8-diff");
        let ws = Workspace::open(&repo).expect("open");
        fs::write(repo.join("invalid.rs"), b"fn changed() { // \xff\n}\n").expect("invalid text");

        let error = ws
            .capture_diff()
            .expect_err("lossy conversion would change the evidence the reviewer sees");
        assert!(error.to_string().contains("not valid UTF-8"), "{error}");
    }

    #[test]
    fn ignored_worker_input_is_absent_from_gate_snapshot() {
        let repo = temp_repo("ignored-gate-input");
        let ws = Workspace::open(&repo).expect("open");
        fs::write(repo.join(".gitignore"), "worker-toggle\n").expect("ignore rule");
        ws.capture_diff().expect("stage ignore rule");
        ws.commit("seed ignore rule").expect("commit ignore rule");

        fs::write(repo.join("README.md"), "changed\n").expect("tracked edit");
        fs::write(repo.join("worker-toggle"), "make the gate pass\n").expect("ignored input");
        ws.capture_diff().expect("stage candidate");
        assert!(
            ws.review_input_problem()
                .expect("inspect evidence")
                .is_none(),
            "ignored state is isolated by materialization rather than misreported as staged"
        );

        let snapshot = ws.gate_snapshot().expect("exact staged snapshot");
        assert_eq!(
            fs::read_to_string(snapshot.workspace().root().join("README.md"))
                .expect("snapshot tracked file")
                .replace("\r\n", "\n"),
            "changed\n"
        );
        assert!(
            !snapshot.workspace().root().join("worker-toggle").exists(),
            "worker-created ignored input must not reach gates"
        );
        assert!(snapshot.workspace().is_clean().expect("clean snapshot"));
    }

    #[test]
    fn filtered_paths_are_refused_before_gates_and_review() {
        let repo = temp_repo("filtered-evidence");
        let ws = Workspace::open(&repo).expect("open");
        fs::write(
            repo.join(".gitattributes"),
            "filtered.txt filter=tactus-test\n",
        )
        .expect("filter attribute");
        fs::write(repo.join("filtered.txt"), "semantic bytes\n").expect("filtered file");
        let error = ws
            .capture_diff()
            .expect_err("filters must be refused before staging")
            .to_string();
        assert!(error.contains("before git add"), "{error}");
        assert!(error.contains("filtered.txt"), "{error}");

        // Preserve the independent post-stage guard for a caller opening an
        // index prepared outside Workspace::capture_candidate.
        run_git(&repo, &["add", "-A"]);
        let filtered_tree = ws.staged_tree_oid().expect("filtered tree");
        fs::write(repo.join(".gitattributes"), "").expect("clear live attributes");
        run_git(&repo, &["add", ".gitattributes"]);

        let problem = ws
            .review_input_problem_for_tree(&filtered_tree)
            .expect("inspect attributes")
            .expect("filtered evidence must fail closed");
        assert!(problem.contains("filtered.txt"), "{problem}");
        assert!(problem.contains("tactus-test"), "{problem}");
        assert!(problem.contains("different bytes"), "{problem}");
    }

    #[test]
    fn filter_on_unchanged_tracked_path_is_refused_before_materialization() {
        let repo = temp_repo("filter-on-unchanged-path");
        let ws = Workspace::open(&repo).expect("open");
        fs::write(repo.join("unchanged.txt"), "tracked baseline\n").expect("tracked file");
        ws.capture_diff().expect("stage baseline file");
        ws.commit("seed unchanged file")
            .expect("commit baseline file");

        // Only the attributes file changes. The filter target itself is absent
        // from `diff --cached --name-only` but is still a gate input.
        fs::write(
            repo.join(".gitattributes"),
            "unchanged.txt filter=tactus-test\n",
        )
        .expect("candidate attributes");
        let error = ws
            .capture_candidate()
            .expect_err("unchanged filtered targets must fail before add")
            .to_string();
        assert!(error.contains("unchanged.txt"), "{error}");
        run_git(&repo, &["add", "-A"]);
        let tree_oid = ws.staged_tree_oid().expect("externally captured tree");
        fs::remove_file(repo.join(".gitattributes")).expect("move index past candidate");
        run_git(&repo, &["add", "-A"]);

        let problem = ws
            .review_input_problem_for_tree(&tree_oid)
            .expect("inspect every path in the captured tree")
            .expect("filter on unchanged path must fail closed");
        assert!(problem.contains("unchanged.txt"), "{problem}");
        assert!(problem.contains("tactus-test"), "{problem}");
    }

    #[test]
    fn capture_candidate_refuses_filter_before_candidate_helper_executes() {
        let repo = temp_repo("pre-add-filter-helper");
        fs::create_dir_all(repo.join(".githooks")).expect("helper directory");
        fs::write(
            repo.join(".githooks").join("filter-helper"),
            "#!/bin/sh\ncat\n",
        )
        .expect("baseline helper");
        fs::write(repo.join("payload.txt"), "baseline\n").expect("payload");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "seed filter helper"]);
        run_git(
            &repo,
            &[
                "config",
                "filter.tactus-test.clean",
                "sh .githooks/filter-helper",
            ],
        );
        run_git(&repo, &["config", "filter.tactus-test.smudge", "cat"]);

        fs::write(
            repo.join(".githooks").join("filter-helper"),
            "#!/bin/sh\nprintf 'ran\\n' > filter-ran\ncat\n",
        )
        .expect("candidate helper");
        fs::write(
            repo.join(".gitattributes"),
            "payload.txt filter=tactus-test\n",
        )
        .expect("candidate attributes");
        fs::write(repo.join("payload.txt"), "candidate\n").expect("candidate payload");
        let ws = Workspace::open(&repo).expect("open");

        let error = ws
            .capture_candidate()
            .expect_err("filter must be refused before git add")
            .to_string();
        assert!(error.contains("before git add"), "{error}");
        assert!(error.contains("payload.txt"), "{error}");
        assert!(
            !repo.join("filter-ran").exists(),
            "attribute inspection must not execute the candidate-edited filter helper"
        );

        // Control: the exact raw command that capture used to run executes the
        // fixture, proving marker absence above is suppression rather than a
        // helper that could never run on this platform.
        run_git(&repo, &["add", "-A"]);
        assert!(repo.join("filter-ran").exists(), "raw git add ran filter");
    }

    #[test]
    fn status_and_switch_refuse_filter_before_candidate_helper_executes() {
        let repo = temp_repo("status-filter-helper");
        fs::create_dir_all(repo.join(".githooks")).expect("helper directory");
        fs::write(
            repo.join(".githooks").join("status-filter"),
            "#!/bin/sh\ncat\n",
        )
        .expect("baseline helper");
        fs::write(repo.join("payload.txt"), "baseline\n").expect("payload");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "seed status helper"]);
        run_git(&repo, &["branch", "alternate"]);
        run_git(&repo, &["config", "core.trustctime", "false"]);
        run_git(&repo, &["config", "core.checkStat", "minimal"]);
        run_git(
            &repo,
            &[
                "config",
                "filter.tactus-status.clean",
                "sh .githooks/status-filter",
            ],
        );
        run_git(&repo, &["config", "filter.tactus-status.smudge", "cat"]);

        fs::write(
            repo.join(".githooks").join("status-filter"),
            "#!/bin/sh\nprintf 'ran\\n' > status-filter-ran\ncat\n",
        )
        .expect("candidate helper");
        fs::write(
            repo.join(".gitattributes"),
            "payload.txt filter=tactus-status\n",
        )
        .expect("candidate attributes");
        let payload = repo.join("payload.txt");
        let indexed_mtime = fs::metadata(&payload)
            .and_then(|metadata| metadata.modified())
            .expect("indexed payload mtime");
        fs::write(&payload, "changed!\n").expect("same-size candidate payload");
        fs::OpenOptions::new()
            .write(true)
            .open(&payload)
            .and_then(|file| file.set_times(fs::FileTimes::new().set_modified(indexed_mtime)))
            .expect("restore indexed mtime");
        fs::OpenOptions::new()
            .write(true)
            .open(repo.join(".git").join("index"))
            .and_then(|file| file.set_times(fs::FileTimes::new().set_modified(indexed_mtime)))
            .expect("force a deterministic racily-clean index comparison");
        let ws = Workspace::open(&repo).expect("open");

        let clean_error = ws
            .is_clean()
            .expect_err("status preflight must refuse the filter")
            .to_string();
        assert!(clean_error.contains("before git status"), "{clean_error}");
        let summary_error = ws
            .uncommitted_summary()
            .expect_err("resume summary must refuse the filter")
            .to_string();
        assert!(
            summary_error.contains("before git status"),
            "{summary_error}"
        );
        let head_tree = ws.git(&["rev-parse", "HEAD^{tree}"]).expect("head tree");
        let review_problem = ws
            .review_input_problem_for_tree(head_tree.trim())
            .expect("review preflight")
            .expect("review status must refuse the filter");
        assert!(
            review_problem.contains("before git status"),
            "{review_problem}"
        );
        let switch_error = ws
            .switch_branch("alternate")
            .expect_err("branch switch must refuse the live filter")
            .to_string();
        assert!(switch_error.contains("before git switch"), "{switch_error}");
        let commit_error = ws
            .commit("must not inspect filtered worktree")
            .expect_err("commit must refuse the live filter")
            .to_string();
        assert!(commit_error.contains("before git commit"), "{commit_error}");
        assert!(
            !repo.join("status-filter-ran").exists(),
            "preflight inspection must not execute the candidate-edited filter helper"
        );

        run_git(&repo, &["status", "--porcelain"]);
        assert!(
            repo.join("status-filter-ran").exists(),
            "raw git status ran the candidate-edited clean filter"
        );
    }

    #[test]
    fn capture_candidate_disables_candidate_fsmonitor() {
        let repo = temp_repo("capture-fsmonitor");
        fs::create_dir_all(repo.join(".githooks")).expect("hooks directory");
        fs::write(
            repo.join(".githooks").join("fsmonitor"),
            "#!/bin/sh\nprintf 'baseline-token\\0'\n",
        )
        .expect("baseline fsmonitor");
        make_executable(&repo.join(".githooks").join("fsmonitor"));
        run_git(&repo, &["add", "-A"]);
        run_git(
            &repo,
            &["update-index", "--chmod=+x", ".githooks/fsmonitor"],
        );
        run_git(&repo, &["commit", "-q", "-m", "seed fsmonitor"]);
        run_git(&repo, &["config", "core.fsmonitor", ".githooks/fsmonitor"]);
        run_git(&repo, &["config", "core.fsmonitorHookVersion", "2"]);
        run_git(&repo, &["status", "--porcelain"]);

        fs::write(
            repo.join(".githooks").join("fsmonitor"),
            "#!/bin/sh\nprintf 'ran\\n' > fsmonitor-ran\nprintf 'candidate-token\\0'\n",
        )
        .expect("candidate fsmonitor");
        fs::write(repo.join("README.md"), "candidate\n").expect("candidate edit");
        let ws = Workspace::open(&repo).expect("open without fsmonitor execution");
        ws.capture_candidate()
            .expect("capture with fsmonitor explicitly disabled");
        assert!(!repo.join("fsmonitor-ran").exists());
        assert!(!ws.is_clean().expect("status with fsmonitor disabled"));
        assert!(!repo.join("fsmonitor-ran").exists());

        fs::write(repo.join("README.md"), "control\n").expect("control edit");
        run_git(&repo, &["add", "-A"]);
        assert!(
            repo.join("fsmonitor-ran").exists(),
            "raw git add ran the candidate-edited fsmonitor"
        );
    }

    #[test]
    fn capture_candidate_disables_post_index_change_hook() {
        let repo = temp_repo("capture-post-index-change");
        fs::create_dir_all(repo.join(".githooks")).expect("hooks directory");
        fs::write(
            repo.join(".githooks").join("post-index-change"),
            "#!/bin/sh\nexit 0\n",
        )
        .expect("baseline hook");
        make_executable(&repo.join(".githooks").join("post-index-change"));
        run_git(&repo, &["add", "-A"]);
        run_git(
            &repo,
            &["update-index", "--chmod=+x", ".githooks/post-index-change"],
        );
        run_git(&repo, &["commit", "-q", "-m", "seed index hook"]);
        run_git(&repo, &["config", "core.hooksPath", ".githooks"]);

        fs::write(
            repo.join(".githooks").join("post-index-change"),
            "#!/bin/sh\nprintf 'ran\\n' > post-index-ran\n",
        )
        .expect("candidate hook");
        fs::write(repo.join("README.md"), "candidate\n").expect("candidate edit");
        let ws = Workspace::open(&repo).expect("open");
        ws.capture_candidate()
            .expect("capture with private empty hooks path");
        assert!(!repo.join("post-index-ran").exists());

        fs::write(repo.join("README.md"), "control\n").expect("control edit");
        run_git(&repo, &["add", "-A"]);
        assert!(
            repo.join("post-index-ran").exists(),
            "raw git add ran post-index-change"
        );
    }

    #[test]
    fn branch_creation_and_switch_do_not_execute_post_checkout_hook() {
        let repo = temp_repo("branch-post-checkout");
        fs::create_dir_all(repo.join(".githooks")).expect("hooks directory");
        fs::write(
            repo.join(".githooks").join("post-checkout"),
            "#!/bin/sh\nprintf 'ran\\n' > post-checkout-ran\n",
        )
        .expect("checkout hook");
        make_executable(&repo.join(".githooks").join("post-checkout"));
        run_git(&repo, &["add", "-A"]);
        run_git(
            &repo,
            &["update-index", "--chmod=+x", ".githooks/post-checkout"],
        );
        run_git(&repo, &["commit", "-q", "-m", "seed checkout hook"]);
        run_git(&repo, &["config", "core.hooksPath", ".githooks"]);
        let ws = Workspace::open(&repo).expect("open");

        ws.create_branch("safe-create")
            .expect("hook-suppressed branch creation");
        assert!(!repo.join("post-checkout-ran").exists());
        ws.switch_branch("main")
            .expect("hook-suppressed branch switch");
        assert!(!repo.join("post-checkout-ran").exists());

        run_git(&repo, &["switch", "-q", "safe-create"]);
        assert!(
            repo.join("post-checkout-ran").exists(),
            "raw git switch ran post-checkout"
        );
    }

    #[test]
    fn branch_switch_refuses_filter_before_target_helper_executes() {
        let repo = temp_repo("branch-filter-helper");
        fs::create_dir_all(repo.join(".githooks")).expect("helper directory");
        fs::write(
            repo.join(".githooks").join("smudge-helper"),
            "#!/bin/sh\nprintf 'ran\\n' > smudge-ran\ncat\n",
        )
        .expect("smudge helper");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "seed smudge helper"]);
        run_git(&repo, &["switch", "-q", "-c", "filtered"]);
        fs::write(
            repo.join(".gitattributes"),
            "payload.txt filter=tactus-switch\n",
        )
        .expect("attributes");
        fs::write(repo.join("payload.txt"), "filtered branch\n").expect("payload");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "seed filtered branch"]);
        run_git(&repo, &["switch", "-q", "main"]);
        run_git(&repo, &["config", "filter.tactus-switch.clean", "cat"]);
        run_git(
            &repo,
            &[
                "config",
                "filter.tactus-switch.smudge",
                "sh .githooks/smudge-helper",
            ],
        );
        let ws = Workspace::open(&repo).expect("open");

        let error = ws
            .switch_branch("filtered")
            .expect_err("target filters must fail before checkout")
            .to_string();
        assert!(error.contains("refusing checkout"), "{error}");
        assert!(error.contains("payload.txt"), "{error}");
        assert!(!repo.join("smudge-ran").exists());
        assert_eq!(ws.current_branch().expect("still on main"), "main");

        run_git(&repo, &["switch", "-q", "filtered"]);
        assert!(
            repo.join("smudge-ran").exists(),
            "raw git switch ran the target's configured smudge helper"
        );
    }

    #[test]
    fn commit_and_discard_do_not_execute_candidate_hooks() {
        let repo = temp_repo("commit-reset-hooks");
        fs::create_dir_all(repo.join(".githooks")).expect("hooks directory");
        fs::write(
            repo.join(".githooks").join("pre-commit"),
            "#!/bin/sh\nprintf 'ran\\n' > pre-commit-ran\n",
        )
        .expect("commit hook");
        fs::write(
            repo.join(".githooks").join("post-index-change"),
            "#!/bin/sh\nprintf 'ran\\n' > reset-index-ran\n",
        )
        .expect("index hook");
        make_executable(&repo.join(".githooks").join("pre-commit"));
        make_executable(&repo.join(".githooks").join("post-index-change"));
        run_git(&repo, &["add", "-A"]);
        run_git(
            &repo,
            &["update-index", "--chmod=+x", ".githooks/pre-commit"],
        );
        run_git(
            &repo,
            &["update-index", "--chmod=+x", ".githooks/post-index-change"],
        );
        run_git(&repo, &["commit", "-q", "-m", "seed hooks"]);
        run_git(&repo, &["config", "core.hooksPath", ".githooks"]);
        let ws = Workspace::open(&repo).expect("open");

        fs::write(repo.join("README.md"), "candidate commit\n").expect("edit");
        ws.capture_candidate().expect("capture");
        assert!(!repo.join("reset-index-ran").exists());
        ws.commit("candidate without hooks")
            .expect("hook-suppressed commit");
        assert!(!repo.join("pre-commit-ran").exists());

        fs::write(repo.join("README.md"), "candidate reset\n").expect("reset edit");
        ws.capture_candidate().expect("capture reset candidate");
        ws.discard_uncommitted()
            .expect("hook-suppressed reset and clean");
        assert!(!repo.join("reset-index-ran").exists());

        fs::write(repo.join("README.md"), "control\n").expect("control edit");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "control commit"]);
        assert!(repo.join("pre-commit-ran").exists(), "raw commit ran hook");
    }

    #[test]
    fn discard_refuses_target_filter_before_candidate_helper_executes() {
        let repo = temp_repo("reset-filter-helper");
        fs::write(
            repo.join(".gitattributes"),
            "README.md filter=tactus-reset\n",
        )
        .expect("target attributes");
        fs::write(repo.join("zz-reset-helper"), "#!/bin/sh\ncat\n").expect("baseline helper");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "seed reset filter"]);
        run_git(&repo, &["config", "filter.tactus-reset.clean", "cat"]);
        run_git(
            &repo,
            &["config", "filter.tactus-reset.smudge", "sh zz-reset-helper"],
        );

        fs::write(
            repo.join("zz-reset-helper"),
            "#!/bin/sh\nprintf 'ran\\n' > reset-filter-ran\ncat\n",
        )
        .expect("candidate helper");
        fs::write(repo.join("README.md"), "candidate\n").expect("candidate payload");
        let ws = Workspace::open(&repo).expect("open");

        let error = ws
            .discard_uncommitted()
            .expect_err("reset target filters must fail before checkout")
            .to_string();
        assert!(error.contains("refusing checkout"), "{error}");
        assert!(error.contains("README.md"), "{error}");
        assert!(
            !repo.join("reset-filter-ran").exists(),
            "tree inspection must not execute the candidate-edited smudge helper"
        );

        run_git(&repo, &["reset", "-q", "--hard", "HEAD"]);
        assert!(
            repo.join("reset-filter-ran").exists(),
            "raw git reset ran the candidate-edited smudge helper"
        );
    }

    #[test]
    fn gate_snapshot_does_not_execute_post_checkout_hook() {
        let repo = temp_repo("snapshot-checkout-hook");
        run_git(&repo, &["config", "core.autocrlf", "false"]);
        run_git(&repo, &["config", "core.hooksPath", ".githooks"]);
        fs::create_dir_all(repo.join(".githooks")).expect("hooks directory");
        fs::write(
            repo.join(".githooks").join("post-checkout"),
            "#!/bin/sh\nprintf 'ran\\n' > hook-ran\n",
        )
        .expect("candidate checkout hook");
        let ws = Workspace::open(&repo).expect("open");
        ws.capture_diff().expect("stage candidate hook");
        run_git(
            &repo,
            &["update-index", "--chmod=+x", ".githooks/post-checkout"],
        );

        let snapshot = ws.gate_snapshot().expect("hook-suppressed snapshot");
        assert!(
            snapshot
                .workspace()
                .root()
                .join(".githooks")
                .join("post-checkout")
                .exists(),
            "the candidate hook itself remains part of the reviewed tree"
        );
        assert!(
            !snapshot.workspace().root().join("hook-ran").exists(),
            "materialization must never execute candidate-controlled checkout hooks"
        );
        assert!(
            fs::read_dir(&snapshot.hooks_path)
                .expect("private hooks directory")
                .next()
                .is_none(),
            "the override must point at a private empty directory"
        );
    }

    #[test]
    fn failed_gate_snapshot_add_cleans_registered_worktree() {
        let repo = temp_repo("failed-snapshot-add-cleanup");
        let ws = Workspace::open(&repo).expect("open");
        let parent = ws.head_sha_full().expect("parent");
        let tree = ws.staged_tree_oid().expect("tree");
        let registrations_before = ws
            .git(&["worktree", "list", "--porcelain"])
            .expect("registrations before");
        let temp_root = env::temp_dir();
        let mut attempted_path = None;
        let mut attempted_hooks_path = None;

        let result = ws.gate_snapshot_for_candidate_in_with(
            &parent,
            &tree,
            &temp_root,
            |path, hooks_path, commit| {
                attempted_path = Some(path.to_path_buf());
                attempted_hooks_path = Some(hooks_path.to_path_buf());
                // Model the dangerous failure boundary: Git has registered and
                // populated the worktree, then the overall add operation is
                // reported as failed (as a failing post-checkout hook did).
                ws.add_gate_worktree(path, hooks_path, commit)?;
                Err(TactusError::Git {
                    message: "synthetic late worktree-add failure".to_owned(),
                })
            },
        );
        let error = match result {
            Ok(_) => panic!("synthetic worktree-add failure must propagate"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("synthetic late"), "{error}");

        let attempted_path = attempted_path.expect("attempted snapshot path");
        let attempted_hooks_path = attempted_hooks_path.expect("attempted hooks path");
        assert!(!attempted_path.exists(), "snapshot directory cleaned");
        assert!(!attempted_hooks_path.exists(), "hooks directory cleaned");
        assert_eq!(
            ws.git(&["worktree", "list", "--porcelain"])
                .expect("registrations after"),
            registrations_before,
            "a failed add must not leave a registered worktree"
        );
    }

    #[test]
    fn unexpected_materialization_residue_is_rejected_and_cleaned() {
        let repo = temp_repo("snapshot-residue-cleanup");
        let ws = Workspace::open(&repo).expect("open");
        let parent = ws.head_sha_full().expect("parent");
        let tree = ws.staged_tree_oid().expect("tree");
        let registrations_before = ws
            .git(&["worktree", "list", "--porcelain"])
            .expect("registrations before");
        let temp_root = env::temp_dir();
        let mut attempted_path = None;

        let result = ws.gate_snapshot_for_candidate_in_with(
            &parent,
            &tree,
            &temp_root,
            |path, hooks_path, commit| {
                attempted_path = Some(path.to_path_buf());
                ws.add_gate_worktree(path, hooks_path, commit)?;
                fs::write(path.join("unexpected-residue"), "not in candidate\n").map_err(
                    |error| TactusError::Git {
                        message: format!("creating synthetic residue: {error}"),
                    },
                )?;
                Ok(())
            },
        );
        let error = match result {
            Ok(_) => panic!("unexpected materialization residue must fail closed"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("unexpected tracked or untracked state"),
            "{error}"
        );
        assert!(
            !attempted_path.expect("attempted path").exists(),
            "rejected snapshot directory cleaned"
        );
        assert_eq!(
            ws.git(&["worktree", "list", "--porcelain"])
                .expect("registrations after"),
            registrations_before,
            "rejected materialization must not stay registered"
        );
    }

    #[test]
    #[ignore = "subprocess helper"]
    fn gate_snapshot_owner_helper() {
        if env::var_os("TACTUS_SNAPSHOT_OWNER").is_none() {
            return;
        }
        let repo = PathBuf::from(env::var_os("TACTUS_REPO").expect("repo path"));
        let store = PathBuf::from(env::var_os("TACTUS_SNAPSHOT_STORE").expect("store path"));
        let ready = PathBuf::from(env::var_os("TACTUS_READY").expect("ready path"));
        let workspace = Workspace::open(&repo).expect("open helper workspace");
        let parent = workspace.head_sha_full().expect("snapshot parent");
        let tree = workspace.staged_tree_oid().expect("snapshot tree");
        let snapshot = workspace
            .gate_snapshot_for_candidate_in_store(&parent, &tree, &store)
            .expect("create durable snapshot");
        fs::write(
            &ready,
            snapshot.workspace().root().to_string_lossy().as_bytes(),
        )
        .expect("publish snapshot path");
        std::thread::sleep(std::time::Duration::from_secs(30));
        drop(snapshot);
    }

    #[test]
    fn hard_killed_snapshot_owner_is_reclaimed_before_resume() {
        let repo = temp_repo("snapshot-hard-kill");
        let store = env::temp_dir().join(format!(
            "tactus-snapshot-store-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        let ready = store.with_extension("ready");
        let workspace = Workspace::open(&repo).expect("open");
        let registrations_before = workspace
            .git(&["worktree", "list", "--porcelain"])
            .expect("registrations before");
        let mut owner = Command::new(env::current_exe().expect("test executable"))
            .args(["gate_snapshot_owner_helper", "--ignored", "--nocapture"])
            .env("TACTUS_SNAPSHOT_OWNER", "1")
            .env("TACTUS_REPO", &repo)
            .env("TACTUS_SNAPSHOT_STORE", &store)
            .env("TACTUS_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn disposable snapshot owner");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "snapshot owner never published readiness");
        let snapshot_path = PathBuf::from(
            String::from_utf8(fs::read(&ready).expect("read snapshot path"))
                .expect("test temp path is UTF-8"),
        );
        assert!(snapshot_path.exists(), "snapshot was not materialized");
        assert_ne!(
            workspace
                .git(&["worktree", "list", "--porcelain"])
                .expect("registrations while live"),
            registrations_before,
            "helper did not register a linked worktree"
        );

        owner.kill().expect("hard-kill snapshot owner");
        owner.wait().expect("reap snapshot owner");
        assert!(
            snapshot_path.exists(),
            "hard kill unexpectedly ran the snapshot destructor"
        );
        assert_eq!(
            workspace
                .reclaim_gate_workspaces(&store)
                .expect("resume reclaims durable intents"),
            1
        );
        assert!(!snapshot_path.exists(), "snapshot directory was reclaimed");
        assert_eq!(
            workspace
                .git(&["worktree", "list", "--porcelain"])
                .expect("registrations after reclaim"),
            registrations_before,
            "resume left a registered snapshot worktree"
        );
        assert_eq!(
            workspace
                .reclaim_gate_workspaces(&store)
                .expect("reclamation is idempotent"),
            0
        );
        let _ = fs::remove_file(ready);
        let _ = fs::remove_dir_all(store);
    }

    #[cfg(unix)]
    #[test]
    fn gate_snapshot_target_is_atomically_private() {
        use std::os::unix::fs::PermissionsExt;

        let repo = temp_repo("private-snapshot-target");
        let system_temp = env::temp_dir();
        let system_temp_mode = fs::metadata(&system_temp)
            .expect("system temp metadata")
            .permissions()
            .mode()
            & 0o7777;
        let refusal = match PendingGateWorkspace::create_in_store(&repo, &system_temp) {
            Ok(_) => panic!("the system temp root must not be used as an exact store"),
            Err(error) => error.to_string(),
        };
        assert!(
            refusal.contains("not a durable snapshot store"),
            "{refusal}"
        );
        assert_eq!(
            fs::metadata(&system_temp)
                .expect("system temp metadata after refusal")
                .permissions()
                .mode()
                & 0o7777,
            system_temp_mode,
            "snapshot setup must never chmod the system temp root"
        );

        let temp_root = env::temp_dir().join(format!(
            "tactus-shared-temp-root-{}-{}",
            std::process::id(),
            crate::ulid::ulid()
        ));
        fs::create_dir(&temp_root).expect("create shared-like temp root");
        fs::set_permissions(&temp_root, fs::Permissions::from_mode(0o1777))
            .expect("make temp root shared-like");

        let pending = PendingGateWorkspace::create(&repo, &temp_root)
            .expect("atomically create private snapshot directories");
        let path = pending.path.clone();
        let hooks_path = pending.hooks_path.clone();
        let intent_path = pending.intent_path.clone();
        let store = pending
            .ephemeral_store
            .clone()
            .expect("temp-root snapshots own a child store");
        assert_eq!(store.parent(), Some(temp_root.as_path()));
        assert_eq!(
            fs::metadata(&temp_root)
                .expect("shared root metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o1777,
            "snapshot setup must not chmod a pre-existing shared root"
        );
        assert_eq!(
            fs::metadata(&store)
                .expect("private store metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("snapshot metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&hooks_path)
                .expect("hooks metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(fs::read_dir(&path).expect("empty target").next().is_none());
        assert!(
            fs::read_dir(&hooks_path)
                .expect("empty hooks path")
                .next()
                .is_none()
        );
        assert_eq!(
            fs::metadata(&intent_path)
                .expect("intent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the durable intent is private before worktree registration"
        );
        drop(pending);
        assert!(!path.exists());
        assert!(!hooks_path.exists());
        assert!(!intent_path.exists());
        assert!(!store.exists(), "ephemeral child store was cleaned");
        assert_eq!(
            fs::metadata(&temp_root)
                .expect("shared root survives cleanup")
                .permissions()
                .mode()
                & 0o7777,
            0o1777,
            "snapshot cleanup must not chmod or remove the shared root"
        );
        fs::remove_dir(&temp_root).expect("remove test-owned shared root");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gate_snapshot_accepts_non_utf8_tmpdir_on_linux() {
        use std::os::unix::ffi::OsStringExt;

        let repo = temp_repo("non-utf8-snapshot-root");
        let ws = Workspace::open(&repo).expect("open");
        let parent = ws.head_sha_full().expect("parent");
        let tree = ws.staged_tree_oid().expect("tree");
        let mut name = format!("tactus-non-utf8-tmp-{}-", std::process::id()).into_bytes();
        name.push(0xff);
        let temp_root = env::temp_dir().join(OsString::from_vec(name));
        let _ = fs::remove_dir_all(&temp_root);
        fs::create_dir(&temp_root).expect("non-UTF-8 temp root");

        let snapshot = ws
            .gate_snapshot_for_candidate_in(&parent, &tree, &temp_root)
            .expect("Path/OsStr must reach git without UTF-8 conversion");
        assert!(snapshot.workspace().root().starts_with(&temp_root));
        assert!(snapshot.workspace().is_clean().expect("clean snapshot"));
        drop(snapshot);
        fs::remove_dir(&temp_root).expect("clean non-UTF-8 temp root");
    }

    #[test]
    fn dirty_submodule_worktree_is_refused_before_gates() {
        let child = temp_repo("dirty-submodule-child");
        let repo = temp_repo("dirty-submodule-parent");
        let add = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["-c", "protocol.file.allow=always", "submodule", "add", "-q"])
            .arg(&child)
            .arg("nested")
            .output()
            .expect("add submodule");
        assert!(
            add.status.success(),
            "submodule add: {}",
            String::from_utf8_lossy(&add.stderr)
        );
        let ws = Workspace::open(&repo).expect("open parent");
        ws.capture_diff().expect("stage gitlink");
        ws.commit("seed submodule").expect("commit gitlink");
        fs::write(
            repo.join("nested").join("README.md"),
            "dirty nested bytes\n",
        )
        .expect("dirty submodule");
        ws.capture_diff().expect("stage parent");

        let problem = ws
            .review_input_problem()
            .expect("inspect nested state")
            .expect("dirty submodule must fail closed");
        assert!(problem.contains("nested"), "{problem}");
        assert!(
            problem.contains("absent from the reviewed commit"),
            "{problem}"
        );
    }

    #[test]
    fn clean_unchanged_submodule_is_refused_before_gate_snapshot() {
        let child = temp_repo("clean-submodule-child");
        let repo = temp_repo("clean-submodule-parent");
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["-c", "protocol.file.allow=always", "submodule", "add", "-q"])
            .arg(&child)
            .arg("nested")
            .output()
            .expect("add submodule");
        assert!(
            output.status.success(),
            "submodule add: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let ws = Workspace::open(&repo).expect("open parent");
        ws.capture_diff().expect("stage submodule");
        ws.commit("seed clean submodule").expect("commit submodule");
        assert!(ws.is_clean().expect("clean parent and submodule"));

        let problem = ws
            .review_input_problem()
            .expect("inspect complete index")
            .expect("even a clean unchanged gitlink must fail closed");
        assert!(problem.contains("nested"), "{problem}");
        assert!(problem.contains("mode 160000"), "{problem}");

        let tree = ws.staged_tree_oid().expect("indexed tree");
        let error = match ws.gate_snapshot_for_tree(&tree) {
            Ok(_) => panic!("a gitlink tree must not be materialized incompletely"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("nested"), "{error}");
        assert!(error.contains("mode 160000"), "{error}");
    }
}
