# Requirements

Requirement IDs referenced in the code. Each one is a property the experiment harness must preserve.

| ID | Requirement |
|---|---|
| DR-01 | Results flow automatically into the paper: running the experiment generates the LaTeX the paper includes; no result is typed by hand. |
| DR-02 | Traceability: every generated value carries its source records and hashes; every generated file states the generator, inputs and code commit. |
| DR-03 | No favourable defaults: missing, unattained, timed-out or zero results are printed as such. |
| DR-04 | Fallback: without generated files the paper still compiles and shows *pending*. |
| DR-05 | Pilot isolation: pilot output is visibly watermarked; campaign output requires a frozen campaign corpus. |
| DR-06 | Generated files are never edited by hand; results change only by regenerating from inputs. |
| DR-07 | Deterministic regeneration: the same inputs give the same output (only timestamp/commit comment lines vary). |
| DR-08 | One command per stage; everything also runnable from the command line. |
| DR-09 | Model registry: any number of models; secrets never recorded; each stratum uses exactly one model. |
| DR-10 | ProofWeave is implemented in this repository and version-stamped. |
| DR-11 | GREEN mapping (RepoAudit): normal completion (exit 0, no traceback, native log present, not timed out) and zero accepted findings, confirmed by RepoAudit's own report or log. Failed or incomplete runs are never GREEN; all runs are retained. |
| DR-12 | The causality graph is exported to Graphviz `.dot` at the end of a cycle (full graph plus one view per decision). |
| DR-13 | Stage gating: one stage at a time; a stage completes only when every check passes; completion attests execution, not favourability; failed attempts are retained. |
| DR-14 | Experiment cycles: each cycle is stored in its own folder and never edited or deleted. |
| DR-15 | Graph questions use an operator-supplied API key held in memory only; every question becomes a recorded deterministic query; answers never change results. |
| DR-16 | Publish: one campaign cycle under the locked protocol becomes the paper's result; the selection rule is declared in advance; all campaign cycles are reported; repository and paper always come from the same cycle. |
| DR-17 | Reproducibility: committed results and sealed evidence; Python only; reviewers can replay Stages 2–4 or create their own evidence; only the maintainer publishes the master set, whose hash is printed in the paper. |
| DR-18 | Command-line menu and plain flags share one engine; terse step-by-step output. |
| DR-19 | Interactive front end is a terminal UI (no web server). |
| DR-20 | Per-run model and key entry (OpenAI or Anthropic, model name, key); multiple RepoAudit models; keys in memory only; RepoAudit reaches providers only through the local gateway; a campaign cycle's models must match the locked protocol. |
| DR-21 | Worked-example exhibit: each completed cycle's report and the terminal UI show the Three-GREENs case (verdicts, models, verdict-only PROCEED vs TAIP HOLD), a coverage matrix (required items × runs), and a run-vs-run / model-vs-model contrast with the exact, privacy-treated RepoAudit log excerpts behind it; exported as a self-contained HTML page; illustrative, never a replacement for the reported results. |
| DR-22 | Pathway divergence is the central observation. For every RepoAudit run, ProofWeave records the pathways it explored on the target: each None source, each function the None was carried into (returned into a caller, or passed as an argument into a callee), and each path-validator question, all traced to RepoAudit's own log bytes. Reports and the terminal UI show these pathways side by side for runs of the same model and settings, of the same model at another temperature, and of different models, with their verdicts and a pairwise similarity. A flow requirement (kind V) is covered when the run followed the None along it, or a validated chain passes through it; every witness says which. |
| DR-23 | Opt-in decision binding. A protocol may declare a decision schedule (`decisions:`, `policies:`, `manifests:`). Stage 1 then writes, for each scheduled decision, a decision bundle: the decision context (intent, policy-at-event, planned basis runs) before the first basis run, and the decision after the last. Stage 2 ingests each decision bundle after its basis runs and appends, in two consecutive batches, the intent, policy and decision records and then a binding record (decision, intent and policy record ids, policy digest, basis record ids, basis root = sha256 of the sorted basis record hashes, basis count). A missing basis run fails the ingest before anything is written. `QueryAPI.decision`, `basis` and `policy_text` answer with `complete`, `partial` or `unavailable`; only `complete` can support a judgement. Without decision bundles, ledger, graph and corpus hashes are byte-identical to `pw-v0.1.0` (regression test). |
