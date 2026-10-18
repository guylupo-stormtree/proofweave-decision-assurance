# ProofWeave Decision Assurance: experiment

Companion experiment for *"Assuring Non-Deterministic Controls at Decision Gateways: From Predefined Control Verdicts to Decision-Time Evidence Interrogation"* (Lupo et al.).

> **Status: under construction.** Build phases P0 (foundation) and P1 (Stage 1) are in progress; see [docs/BUILD.md](docs/BUILD.md). The published results, sealed evidence set and replication instructions will appear here once the campaign is published.

## What this experiment shows

A Decision Gateway that relies on a non-deterministic security control (here, the LLM-based auditor RepoAudit) can receive the same **GREEN** verdict from runs that examined different parts of the code. *Green no longer necessarily means go.* The experiment runs in four stages:

| Stage | What it does | Research question |
|---|---|---|
| 1 Acquire and freeze evidence | Run RepoAudit (several times, one or more models) and Semgrep on the same code, keep every result, seal it | feeds RQ1, RQ2 |
| 2 ProofWeave within the threshold | Time ProofWeave from evidence-write request to "queryable for posture calculation", against a 5 s reference threshold | RQ2 |
| 3 Scale and threshold again | Repeat as the evidence volume grows from 10 to 10,000 records | RQ2 |
| 4 Three GREENs, not enough coverage | Show the gateway three GREEN verdicts whose evidence does not cover the required checks, and verify it holds | RQ1 |

## For reviewers (once published)

- **Review without running anything:** `RESULTS.md`, the tables, the `.dot` graphs and the complete sealed evidence set are committed under `records/published/`.
- **Re-run Stages 2–4 on the published evidence** (Python only, no API key): `python -m pwexp`, then choose *Re-run Stages 2–4*.
- **Create your own evidence set** (your own API keys, full Stages 1–4): `python -m pwexp`, then choose *Create my own evidence set*.

Only the maintainer can publish the master set behind the paper. Its hash is printed in the paper, and `python -m pwexp verify` checks it.

## Install (Python 3.11+)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m pwexp            # terminal UI (build phase P5); plain CLI: python -m pwexp --help
```

Creating new evidence also needs RepoAudit's one-time setup (git, network access, a C compiler):
`git submodule update --init` and then the setup step offered by `python -m pwexp`.

## Third-party software

RepoAudit (Purdue University) is referenced as an **unmodified git submodule** under its own licence; see [NOTICE](NOTICE). It is never vendored, modified or relicensed here.
