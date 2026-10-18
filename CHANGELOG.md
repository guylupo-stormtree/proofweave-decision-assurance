# Changelog

## Unreleased
- P2 ProofWeave: RepoAudit and Semgrep adapters (every observation carries the exact byte span or JSON pointer of its native source), Bind (envelope, privacy treatment, context), append-only hash-chained ledger with content-addressed native blobs, Graph Weaver (deterministic, rebuildable from the ledger; entity resolution by our own `ast` parse of the target), Query API (A/V witness queries, readiness probe), Graphviz export.
- Stage 2: timed replay t0–t4 per bundle against the 5 s reference threshold over repetitions; determinism checks; corpus E sealed (content-derived, reproducible across cycles).
- Stage 3: volume sweep 10 → 10,000 records with marked, segregated synthetic bundles that carry distinct native bytes (no blob deduplication bias).
- `pwexp run-stage 2|3 --cycle ID`.
- P0 foundation: `pwexp` package, hashing, hash-chained logs, protocol check/lock, experiment cycles with stage gating, in-memory model/key entries, plain CLI.
- P1 Stage 1: RepoAudit as a pinned submodule, Python-only tool setup, model gateway (OpenAI, Anthropic), Stage 1 acquisition with GREEN mapping, sealing and checks; pinned Semgrep rules; fixtures.
- `pwexp paper-tex`: generates the paper's experiment-dependent LaTeX from the published cycle.
- Public design summary (`docs/DESIGN.md`) with diagrams.
- `pwexp import-iceccs`: imports the first study's public RepoAudit runs as fixture pilot cycles; five runs included under `tests/fixtures/iceccs-live-v1/` (byte-identical, Apache-2.0, provenance recorded).
