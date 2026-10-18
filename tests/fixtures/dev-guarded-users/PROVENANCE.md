# Fixture provenance (development only)

RepoAudit runs on `targets/fixture-guarded-users`, produced on 2026-10-13 by the maintainers while checking feasibility:

- Subject: unmodified RepoAudit 160f5bc (dfbscan, Python NPD), invoked as a fresh process per run.
- Model: local `qwen2.5-coder:3b` (via Ollama, OpenAI-compatible endpoint). This is a development model, never a campaign model.
- `guarded-users/…`: temperature 0.0; `guarded-users-t05/…`: temperature 0.5 (RepoAudit's command-line default).
- `semgrep/run001`: Semgrep CE 1.181.0 with `protocol/semgrep-rules/python-none-deref.yaml` (pinned in this repository).

Every RepoAudit run here is GREEN (zero accepted findings, confirmed by RepoAudit's own log line `0 bug(s) was/were detected`) and the runs differ in what they analysed, so they exercise Stage 4 (the Three-GREENs decision test). They are fixtures, never results.

Notes:
- RepoAudit writes `detect_info.json` only when it accepts a finding. The `detect_info.json` files here (`{}`) were written by the feasibility harness, not by RepoAudit. The importer keeps them only as `harness-detect_info.json` and establishes zero findings from RepoAudit's log.
- The original feasibility harness did not record provider calls, so imported runs carry an empty `calls.jsonl`.
- Native logs contain absolute paths from the producing machine. Bind's privacy treatment makes them repository-relative; native files are never edited.
- `manifest.json` checksums (`output_checksums`) verify every native file.
