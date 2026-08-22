# reviews/

Dated **implementation reviews** — the last stage of the design lifecycle
(`proposals/` → council → `decisions/` → implementation → here). Scope is a
commit or build step; result is findings and their fixes, named
`YYYY-MM-DD-<slug>.md`.

Design critiques of proposals do not live here; they sit beside their proposal
in [`proposals/`](../proposals/README.md).

[`FINDINGS.md`](FINDINGS.md) is the standing finding ledger — every finding across every slice,
its disposition, and whether it has recurred. It is an **input to every review**: a reviewer reads
it before reviewing, does not re-raise a settled entry without new evidence, and appends a challenge
rather than overturning a disposition. The implementer holds the disposition and adjudicates
challenges.
