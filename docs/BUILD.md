# Build status

Design: [DESIGN.md](DESIGN.md). This file tracks which parts of the design are built.

| Phase | Scope | Status |
|---|---|---|
| P0 Foundation | package, hashing, hash-chained logs, protocol check/lock, cycles + stage gating, in-memory model/key entries, plain CLI | **done**, tests passing |
| P1 Stage 1 | RepoAudit submodule + setup, Semgrep setup, model gateway (OpenAI, Claude, dev-local), Stage 1 runner, GREEN mapping (DR-11), sealing, checks | **done**: 26 tests; end-to-end pilot verified (local model via gateway; all checks pass) |
| P2 ProofWeave + Stages 2–3 | adapter with source refs, Bind, JSONL ledger, Graph Weaver, Query API, t0–t4 timing, scale workloads, seal 2 | not started |
| P3 Stage 4 | TAIP obligations, posture, gateway, verdict-only rule, views P0–P9/P2w, divergent pair, independent oracle, replay | not started |
| P4 Reporting + publish | RESULTS.md, tables, `.dot`, generated LaTeX, maintainer publish | **started**: `pwexp paper-tex` (paper LaTeX generator, 5 tests) |
| P5 Terminal UI | Textual TUI: entry menu, cycles, stage buttons, model/key menu, Question the graph | not started |
| P6 Run | pilot cycles → protocol lock → campaign → publish | blocked on protocol decisions (`pwexp protocol check`) |

## Developer commands

```bash
uv venv --python 3.13 .venv && VIRTUAL_ENV=$PWD/.venv uv pip install -e '.[dev]'   # or python -m venv + pip
.venv/bin/python -m pytest -q
.venv/bin/pwexp protocol check
PWEXP_DEV=1 …   # enables the dev-only "local" OpenAI-compatible provider (never in a campaign)
```
