# Changelog

## Unreleased

## pw-v0.2.1
- `pwexp model-check --model provider:model [--key-stdin]`: one minimal call per entry to confirm the key and model work; the key appears in no output.
- `pwexp run-stage 1 --key-stdin`: keys read from standard input, one per `--model`, for a calling program that already holds them in memory (still never stored).
- Decision schedules also run the protocol's `acquisition.semgrep_runs` standalone Semgrep scans, in no decision's basis.

## pw-v0.2.0
- Opt-in decision binding (DR-23): decision bundles written by Stage 1 under a decision protocol; `EvidencePlane.ingest_decision`; event types `proofweave.intent`, `proofweave.policy`, `proofweave.decision`, `proofweave.decision_binding`; decision, intent and policy graph nodes; `QueryAPI.decision`, `basis`, `policy_text` with complete/partial/unavailable status; `.dot` decision views; synthetic decisions for scale planes.
- Decision protocols: `protocol check` and `protocol lock` accept `decisions:`, `policies:` and `manifests:` and hash the referenced files.
- Command line: `--protocol` and `--records-root` on every command; `run-stage 1` (keys typed at a masked prompt, memory only); `pwexp setup`; `import-dev --protocol` for development decision bundles.
- Run manifests record `start_us` so the order of decision context, runs and decision is checkable.
- Regression guard: with decision binding unused, the development fixtures' ledger head, graph hash and corpus hash equal `pw-v0.1.0` (`tests/fixtures/regression-pw-v0.1.0.json`).

## pw-v0.1.0
- Pathways: the Graph Weaver records how each RepoAudit analysis step was reached (from a None source, as a callee's return value, or as an argument) and `QueryAPI.pathway(run)` returns each run's followed steps with their ledger records. A flow requirement is covered when the run followed the None along it, or a validated chain passes through it; witnesses carry `via`. The independent oracle applies the same rule with its own parsing. Pathway divergence (DR-22) leads the report: a pathway × run table and a pairwise similarity for same-model, other-temperature and different-model pairs.
- Report wording: missing-flow explanations now state that the run never carried the None into the receiving function; the contrast excerpt is RepoAudit's own prompt for that step.
- On the development fixture the declared pair now covers every flow between them (P5 PASS), while each single GREEN run leaves flows unfollowed (P2 and P3 HOLD).
- P4 reporting: `pwexp report --cycle ID` writes `RESULTS.md`, `EXHIBIT.html` (self-contained, for presenting), `timing.csv`, `assurance.csv`, `results.json` (every value with its source) and the paper LaTeX into the cycle's `report/` folder. Pilot output is stamped PILOT DATA.
- Worked-example exhibit: the Three-GREENs view with each run's model and settings, verdict-only vs ProofWeave + TAIP vs oracle, an item × run coverage matrix, and a contrast for one requirement that one run covered and another (for example another model) did not, showing RepoAudit's own log excerpt by byte span. `--item` and `--runs` choose what to show; the default follows a declared rule.
- `pwexp publish` (maintainer): publishes only the complete campaign cycle chosen by the protocol's selection rule, once, with a hash-chained publication record listing every campaign cycle; `--preview` rehearses publication for any complete cycle without recording it.
- P3 Stage 4: required set R (kinds A analysed / V flow validated / S rule-scanned; `pwexp required-set draft` from our own `ast` parse, for human review), TAIP evaluator (admissibility: integrity, compatibility, synthetic exclusion; support, missing and violation sets; posture; gateway), verdict-only comparator, divergent-pair selection (fixed rule, same model context), evidence views P0–P9 and P2w, independent oracle package (`oracle`, no `pwexp` imports), deterministic replay, per-view `.dot` graphs. `pwexp run-stage 4`, `pwexp import-dev`.
- Development fixture `tests/fixtures/dev-guarded-users/`: five GREEN RepoAudit runs (local development model) and one Semgrep run on `targets/fixture-guarded-users`, with a development-reviewed required set.
- Stage 2 now checks that the target snapshot is available for entity resolution.
- P2 ProofWeave: RepoAudit and Semgrep adapters (every observation carries the exact byte span or JSON pointer of its native source), Bind (envelope, privacy treatment, context), append-only hash-chained ledger with content-addressed native blobs, Graph Weaver (deterministic, rebuildable from the ledger; entity resolution by our own `ast` parse of the target), Query API (A/V witness queries, readiness probe), Graphviz export.
- Stage 2: timed replay t0–t4 per bundle against the 5 s reference threshold over repetitions; determinism checks; corpus E sealed (content-derived, reproducible across cycles).
- Stage 3: volume sweep 10 → 10,000 records with marked, segregated synthetic bundles that carry distinct native bytes (no blob deduplication bias).
- `pwexp run-stage 2|3 --cycle ID`.
- P0 foundation: `pwexp` package, hashing, hash-chained logs, protocol check/lock, experiment cycles with stage gating, in-memory model/key entries, plain CLI.
- P1 Stage 1: RepoAudit as a pinned submodule, Python-only tool setup, model gateway (OpenAI, Anthropic), Stage 1 acquisition with GREEN mapping, sealing and checks; pinned Semgrep rules; fixtures.
- `pwexp paper-tex`: generates the paper's experiment-dependent LaTeX from the published cycle.
- Public design summary (`docs/DESIGN.md`) with diagrams.
- `pwexp import-iceccs`: imports the first study's public RepoAudit runs as fixture pilot cycles; five runs included under `tests/fixtures/iceccs-live-v1/` (byte-identical, Apache-2.0, provenance recorded).
