# Build status

Design: [DESIGN.md](DESIGN.md). This file tracks which parts of the design are built.

| Phase | Scope | Status |
|---|---|---|
| P0 Foundation | package, hashing, hash-chained logs, protocol check/lock, cycles + stage gating, in-memory model/key entries, plain CLI | **done**, tests passing |
| P1 Stage 1 | RepoAudit submodule + setup, Semgrep setup, model gateway (OpenAI, Claude, dev-local), Stage 1 runner, GREEN mapping (DR-11), sealing, checks | **done**: 26 tests; end-to-end pilot verified (local model via gateway; all checks pass) |
| P2 ProofWeave + Stages 2–3 | adapter with source refs, Bind, JSONL ledger, Graph Weaver, Query API, t0–t4 timing, scale workloads, seal 2 | **done**: 48 tests; Stages 2–3 pass on real first-study runs; corpus E reproducible across cycles |
| P3 Stage 4 | TAIP obligations, posture, gateway, verdict-only rule, views P0–P9/P2w, divergent pair, independent oracle, replay | **done**: 53 tests; natural Three-GREENs HOLD on the dev fixture; PASS, withholding and FAIL paths tested; oracle agreement and replay checked |
| P4 Reporting + publish | RESULTS.md, tables, `.dot`, generated LaTeX, maintainer publish | **done**: 60 tests; pathways (DR-22); `pwexp report` (RESULTS.md, EXHIBIT.html, CSV tables, results.json with a source for every value, paper LaTeX), worked-example exhibit (three GREENs vs coverage, item × run matrix, model-vs-model contrast with the exact RepoAudit log excerpt), `pwexp publish` (campaign-only, selection-rule guard, publication record; `--preview` for any cycle) |
| DR-23 Decision binding | decision bundles, binding at ingest, decision queries, decision protocols, CLI options | **done** (`pw-v0.2.0`): 70 tests; regression guard against `pw-v0.1.0` |
| P5 Terminal UI | Textual TUI: entry menu, cycles, stage buttons, model/key menu, exhibit screen, Question the graph | not started |
| P6 Run | pilot cycles → protocol lock → campaign → publish | blocked on protocol decisions (`pwexp protocol check`) |

## Developer commands

```bash
uv venv --python 3.13 .venv && VIRTUAL_ENV=$PWD/.venv uv pip install -e '.[dev]'   # or python -m venv + pip
.venv/bin/python -m pytest -q
.venv/bin/pwexp protocol check
.venv/bin/pwexp report --cycle ID [--item R13] [--runs RUN …]   # results + worked example for a cycle
.venv/bin/pwexp publish --cycle ID --preview                    # rehearse publication (maintainer)
PWEXP_DEV=1 …   # enables the dev-only "local" OpenAI-compatible provider (never in a campaign)
```

## P2 work plan: ProofWeave core + Stages 2–3

| Module | Responsibility | Timing mark |
|---|---|---|
| `proofweave/envelope.py` | Evidence envelope (id, producer, run, repo, commit, config χ, collection policy, eventType, sourceRef, payloadHash, time, completion, ledgerRef) | — |
| `proofweave/adapters/repoaudit.py` | Native bundle → verdict record + analysis units (A) + validated chains (V), each with `sourceRef` = (native file sha256, byte span of the log entry) | inside Bind |
| `proofweave/adapters/semgrep.py` | Semgrep JSON → completion + rule/finding records with source refs | inside Bind |
| `proofweave/ingress.py` | Receives a bundle, stamps t0 (monotonic `perf_counter_ns`), drives Bind → Ledger → Weaver → probe, stamps t1–t4 | t0 |
| `proofweave/bind.py` | Schema validation, privacy treatment (absolute paths → repository-relative), context binding | t1 |
| `proofweave/ledger.py` | Append-only JSONL hash chain; one batch per bundle; declared fsync policy; content-addressed native blobs | t2 |
| `proofweave/graph.py` | `GraphStore` interface + in-memory store; Graph Weaver consumes records after its watermark; entity resolution of log text against a Python `ast` parse of the target snapshot (independent of RepoAudit); JSON checkpoint | t3 |
| `proofweave/query.py` | Witness queries; registered readiness probe at the committed watermark | t4 |
| `proofweave/export_dot.py` | Graphviz `.dot` export (full graph + per-decision views) | after timing |
| `stages/stage2_timing.py` | Replay sealed Stage 1 bundles into a reset plane per repetition; record t0–t4 and Δ_ready vs 5 s; seal ledger + graph as corpus E | — |
| `stages/stage3_scale.py` | Marked, segregated synthetic expansion to 10 / 100 / 1,000 / 10,000 records; repeated measurements; crossing point | — |

Tests: adapter on real native logs (source refs resolve to the exact bytes); ledger tamper and deletion detection; graph rebuilt from ledger alone is identical; components sum to t4 − t0; synthetic records never mixed into the authentic corpus; replay of Stage 2 gives identical corpus E hash.

Development evidence: five RepoAudit runs from the first study's public dataset (`tests/fixtures/iceccs-live-v1/`, imported with `pwexp import-iceccs`) give real-model analysis units and validated chains for the tests. They are fixtures, never results.
