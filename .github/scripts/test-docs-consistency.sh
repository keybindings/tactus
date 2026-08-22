#!/usr/bin/env bash
# Documentation and workflow-trigger claims that go stale silently, checked
# against the tree rather than against a hard-coded copy of it.
#
# THE CLAIMS THIS GATE ENFORCES -- exactly these, nothing else is in its scope:
#
#   C1  CLAUDE.md and CONTRIBUTING.md exist. Every repository path either names
#       in backticks exists at this head, or EACH occurrence is qualified within
#       its own window (three lines before to four after) by one of the marker
#       phrases below. Qualification is syntactic: the gate checks that a phrase
#       is present near that occurrence, not what the phrase refers to. And
#       CLAUDE.md does not carry a sentence matching
#       /CONTRIBUTING\.md.{0,40}(omits|is stale|does not (carry|include))/ while
#       CONTRIBUTING.md carries `--all-features` -- the stale cross-document
#       claim PR #20's review had to catch by hand.
#   C2  ci.yml's msrv job selects exactly one toolchain, and it is Cargo.toml's
#       rust-version or a patch release of it.
#   C3  CLAUDE.md's gate-count claim equals the tree, and the set of test-*.sh
#       files in .github/scripts EQUALS the set the lint job invokes, both
#       directions. An invocation from any other job does not count.
#   C4  The workflow trigger contract is EXACTLY what the slice-PR record
#       decided (decisions/2026-08-21-stacked-slice-prs.md): ci.yml triggers on
#       push and pull_request, pr-policy.yml on pull_request, each with the branch
#       list [master, codex/parallelism-design] and nothing else;
#       frontier-review.yml triggers on repository_dispatch and nothing else;
#       frontier-review-invalidate.yml triggers on pull_request_target with
#       branches [master] and nothing else; and neither attestation workflow
#       names the integration branch anywhere.
#
# WITHDRAWN, DELIBERATELY (round 5 of this file's review): this gate makes NO
# claim about which cargo commands CI runs, whether CI executes them, or which
# commands the documents list. Four review rounds showed that surface to be
# open-ended for a text checker -- a command can be present and skipped
# (`if: false`), a document can be missing, an example can contain the string --
# and the release gates are not enforced by prose in the first place: the
# trusted attestation workflow (.github/workflows/frontier-review.yml) reruns
# them from its own default-branch definition on every dispatch, and the
# reviewer reads both the documents and ci.yml. The mutations that demonstrated
# the withdrawn claims are kept by name as history, not as kills:
# MUT-TEMPLATE-MSRV-REMOVED, MUT-CI-CLIPPY-ALL-FEATURES-REMOVED,
# MUT-CI-MSRV-TOOLCHAIN-DRIFT's document half, MUT-CI-CARGO-TEST-STEP-DELETED,
# MUT-CLAUDE-TEST-SCOPE-NARROWED, MUT-CI-CARGO-TEST-STEP-SKIPPED and
# MUT-TEMPLATE-DELETED.
#
# EVERY CHECK THAT REMAINS IS AN EQUALITY OR AN EXACT PIN. A presence test -- a
# substring, a one-way subset, a forbidden value standing in for a required one,
# a flag per path instead of per occurrence -- is how every earlier version of
# this file was killed, and each fix below names the mutation it exists to kill:
#   round 1: MUT-CI-PR-BRANCH-MASKED (whole-file grep),
#            MUT-ROOT-PATH-MISSPELLED (path regex blind to root files),
#            MUT-GATE-COUNT-STALE (a count nobody checked);
#   round 2: MUT-INVALIDATOR-MASTER-REMOVED (forbidding a value is not pinning
#            one), MUT-CI-MSRV-TOOLCHAIN-DRIFT (toolchain never compared),
#            MUT-CI-BASH-GATE-OMITTED (files counted, invocations not);
#   round 3: MUT-MASTER-TRIGGERS-REMOVED (integration branch present, master
#            not required), MUT-FORWARD-PATH-REUSED-AS-CURRENT (one qualified
#            occurrence marked the path for all of them);
#   round 4: MUT-CONTRIBUTING-DELETED (a required document treated as optional).
set -euo pipefail
export PATH="/usr/bin:/bin:$PATH"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/../.." && pwd)"
cd "$root"

failed=0
error() { echo "$*" >&2; failed=1; }

# block <file> <key>: the lines nested under a two-space-indented YAML key --
# an `on:` event such as `pull_request_target`, or a job such as `lint`. The
# block ends at the next key at that indentation or at the next top-level key.
# Keys may carry hyphens (`merge-gate`), or the lint block would run on into
# the next job and a gate invoked from the wrong job would count as invoked.
block() {
  awk -v key="  $2:" '
    $0 == key { inblock = 1; next }
    inblock && /^  [A-Za-z0-9_-]+:/ { inblock = 0 }
    inblock && /^[A-Za-z]/ { inblock = 0 }
    inblock { print }
  ' "$1"
}

# events <file>: the event keys under `on:`, one per line, in file order.
events() {
  awk '
    /^on:/ { inon = 1; next }
    inon && /^[A-Za-z]/ { inon = 0 }
    inon && match($0, /^  [A-Za-z_]+:/) { print substr($0, 3, RLENGTH - 3) }
  ' "$1"
}

# branches_line <file> <event>: the branch filter under one event, with the
# surrounding whitespace stripped. Every line under the event that starts with
# `branches:` is printed, so two filters -- or none -- fail the exact comparison.
branches_line() {
  block "$1" "$2" | grep -E '^\s*branches:' | sed -E 's/^\s+//; s/\s+$//' || true
}

# --- C1. the documents exist; every path they name resolves, per occurrence --
# MUT-CONTRIBUTING-DELETED: a document this gate reads is required, not
# optional -- a missing one is a failure, never a vacuous pass.
# MUT-ROOT-PATH-MISSPELLED: bare document names must exist at the root, not only
# directory-prefixed paths. MUT-FORWARD-PATH-REUSED-AS-CURRENT: a qualified
# forward reference used to mark the PATH, so a second, unqualified occurrence of
# the same missing path passed as a current pointer. Each occurrence is judged
# on its own window now. A qualifier may say the path is coming, or that it
# deliberately does not exist ("there is **no** rust-toolchain.toml").
marker='arrives with|arrive with|not yet|until that merges|until it merges|lands with|forward reference|\*\*no |there is \*\*?no|does not exist|must not exist'
for doc in CLAUDE.md CONTRIBUTING.md; do
  [[ -f "$doc" ]] || { error "$doc is missing: this gate requires it"; continue; }
  rooted=$(grep -oE '`(src|infra|\.github|acceptance|decisions|proposals|reviews|examples|fixtures|docs)/[A-Za-z0-9_./-]*`' "$doc" | tr -d '`' || true)
  bare=$(grep -oE '`[A-Za-z0-9][A-Za-z0-9_.-]*\.(md|toml|lock)`' "$doc" | tr -d '`' || true)
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    [[ -e "$path" ]] && continue
    while IFS= read -r line_no; do
      [[ -z "$line_no" ]] && continue
      from=$(( line_no > 3 ? line_no - 3 : 1 ))
      sed -n "${from},$(( line_no + 4 ))p" "$doc" | grep -qiE "$marker" \
        || error "$doc:$line_no names \`$path\`, which does not exist at this head; this occurrence is neither marked as a forward reference nor stated as deliberately absent"
    done < <(grep -nF -- "\`$path\`" "$doc" | cut -d: -f1)
  done < <(printf '%s\n%s\n' "$rooted" "$bare" | grep -v '^$' | sort -u)
done

# A claim that another document is stale must not outlive the fix. This is the
# sentence PR #20's review caught by hand: CLAUDE.md asserted CONTRIBUTING.md
# omitted --all-features while the same commit added it. The pattern is the
# claim; a differently worded claim is outside C1.
if [[ -f CLAUDE.md && -f CONTRIBUTING.md ]] \
   && grep -Fq -- '--all-features' CONTRIBUTING.md \
   && grep -qiE 'CONTRIBUTING\.md.{0,40}(omits|is stale|does not (carry|include))' CLAUDE.md; then
  error "CLAUDE.md claims CONTRIBUTING.md omits --all-features, but CONTRIBUTING.md carries it at this head"
fi

# --- C2. MSRV: ci.yml's msrv job agrees with Cargo.toml ----------------------
# MUT-CI-MSRV-TOOLCHAIN-DRIFT: the msrv job could move to 1.86.0 while
# Cargo.toml still promised 1.85. The job's toolchain is compared with
# rust-version directly; no document is consulted.
rust_version=$(sed -nE 's/^rust-version\s*=\s*"([0-9]+\.[0-9]+(\.[0-9]+)?)"\s*$/\1/p' Cargo.toml | head -1)
[[ -n "$rust_version" ]] || error "Cargo.toml carries no rust-version to pin the msrv job against"
msrv_toolchains=$(block .github/workflows/ci.yml msrv | grep -E '^\s*toolchain:' | sed -E 's/^\s*toolchain:\s*//; s/\s+$//' || true)
if [[ -z "$msrv_toolchains" ]]; then
  error "ci.yml has no msrv job selecting a toolchain"
elif [[ "$(wc -l <<< "$msrv_toolchains")" -ne 1 ]]; then
  error "ci.yml msrv job must select exactly one toolchain, got: $(tr '\n' ' ' <<< "$msrv_toolchains")"
elif [[ -n "$rust_version" && "$msrv_toolchains" != "$rust_version" && "$msrv_toolchains" != "$rust_version".* ]]; then
  error "ci.yml msrv job runs toolchain $msrv_toolchains but Cargo.toml rust-version is $rust_version"
fi

# --- C3. the gate inventory: tree == lint-job invocations; CLAUDE.md's count --
# MUT-GATE-COUNT-STALE: a count is a fact about the tree; check it.
# MUT-CI-BASH-GATE-OMITTED: files in the tree prove nothing about CI running
# them; every test-*.sh must be invoked by a `- run: bash .github/scripts/<name>`
# line inside the lint job's own block, and the lint job must invoke nothing the
# tree does not carry. An invocation from another job does not count: block()
# ends at the next job.
tree_gates=$(ls .github/scripts/test-*.sh 2>/dev/null | sed 's|^\.github/scripts/||' | sort -u)
lint_gates=$(block .github/workflows/ci.yml lint \
  | grep -oE '^\s*- run: bash \.github/scripts/test-[A-Za-z0-9_.-]+\.sh\s*$' \
  | sed -E 's|^\s*- run: bash \.github/scripts/||; s|\s*$||' | sort -u || true)
[[ -n "$lint_gates" ]] || error "ci.yml's lint job invokes no .github/scripts/test-*.sh gate"
while IFS= read -r gate; do
  [[ -z "$gate" ]] && continue
  grep -qxF "$gate" <<< "$lint_gates" \
    || error ".github/scripts/$gate exists but ci.yml's lint job never runs it"
done <<< "$tree_gates"
while IFS= read -r gate; do
  [[ -z "$gate" ]] && continue
  grep -qxF "$gate" <<< "$tree_gates" \
    || error "ci.yml's lint job runs .github/scripts/$gate, which is not in the tree"
done <<< "$lint_gates"
actual_gates=$(printf '%s\n' "$tree_gates" | grep -c . || true)
if [[ -f CLAUDE.md ]]; then
  while IFS= read -r claimed; do
    [[ -z "$claimed" ]] && continue
    [[ "$claimed" == "$actual_gates" ]] \
      || error "CLAUDE.md claims $claimed \`test-*.sh\` gates; the tree has $actual_gates"
  done < <(grep -oE '[0-9]+ `test-\*\.sh` gates' CLAUDE.md | grep -oE '^[0-9]+')
  grep -qE '[0-9]+ `test-\*\.sh` gates' CLAUDE.md \
    || error "CLAUDE.md must state the gate count as 'N \`test-*.sh\` gates' so it can be checked"
fi

# --- C4. the trigger contract, pinned exactly --------------------------------
# MUT-CI-PR-BRANCH-MASKED: each event's own block, never the whole file.
# MUT-MASTER-TRIGGERS-REMOVED: requiring the integration branch to be present
# let master be removed; the branch list is compared for exact equality.
# MUT-INVALIDATOR-MASTER-REMOVED: forbidding the integration-branch name is not
# pinning master; the invalidator's filter is compared for exact equality too.
# The event set of every workflow is pinned as well, so a trigger cannot be
# added to the attestation path, or removed from the slice path, unnoticed.
# decisions/2026-08-21-stacked-slice-prs.md
slice_list='branches: [master, codex/parallelism-design]'
pin_events() {  # pin_events <file> <expected events, sorted, space separated>
  local f="$1" want="$2" got
  got="$(events "$f" | sort | tr '\n' ' ' | sed -E 's/ +$//')"
  [[ "$got" == "$want" ]] \
    || error "$f must trigger on exactly [$want], got [${got:-<none>}]"
}
pin_branches() {  # pin_branches <file> <event> <expected branches line>
  local f="$1" event="$2" want="$3" got
  got="$(branches_line "$f" "$event")"
  [[ "$got" == "$want" ]] \
    || error "$f: $event must carry exactly '$want', got: ${got:-<none>}"
}
for f in .github/workflows/ci.yml .github/workflows/pr-policy.yml \
         .github/workflows/frontier-review.yml .github/workflows/frontier-review-invalidate.yml; do
  [[ -f "$f" ]] || error "$f is missing"
done
if [[ -f .github/workflows/ci.yml ]]; then
  pin_events .github/workflows/ci.yml "pull_request push"
  pin_branches .github/workflows/ci.yml push "$slice_list"
  pin_branches .github/workflows/ci.yml pull_request "$slice_list"
fi
if [[ -f .github/workflows/pr-policy.yml ]]; then
  pin_events .github/workflows/pr-policy.yml "pull_request"
  pin_branches .github/workflows/pr-policy.yml pull_request "$slice_list"
fi
if [[ -f .github/workflows/frontier-review.yml ]]; then
  pin_events .github/workflows/frontier-review.yml "repository_dispatch"
fi
if [[ -f .github/workflows/frontier-review-invalidate.yml ]]; then
  pin_events .github/workflows/frontier-review-invalidate.yml "pull_request_target"
  pin_branches .github/workflows/frontier-review-invalidate.yml pull_request_target 'branches: [master]'
fi
# Attestation is never minted for a slice pull request, so neither attestation
# workflow may name the integration branch at all -- in a trigger or anywhere.
for wf in frontier-review frontier-review-invalidate; do
  f=".github/workflows/$wf.yml"
  [[ -f "$f" ]] || continue
  grep -Fq 'codex/parallelism-design' "$f" \
    && error "$f must stay master-only: attestation is never minted for a slice pull request"
done

if (( failed )); then
  echo "documentation consistency fixtures: FAIL" >&2
  exit 1
fi
echo "documentation consistency fixtures: PASS"
