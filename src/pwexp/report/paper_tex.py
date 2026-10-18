"""Generate the paper's experiment-dependent LaTeX from the published master set (DR-01..DR-07, DR-16, DR-17).

Outputs (into --out; the published copy lives in records/published/<cycle>/paper/):
  protocol-macros.tex      protocol parameters + registration-table status cells (from protocol.lock.json)
  results-macros.tex       every result macro the paper uses (from the cycle's results.json)
  tab-timing-body.tex      rows of the paper's Table tab:timing-results (Stages 2-3, RQ2)
  tab-assurance-body.tex   rows of the paper's Table tab:assurance-results (Stage 4, RQ1)

Absent inputs leave every value as \\pending (identical to the manuscript's defaults).
Each result value in results.json must carry a "source" (record path / hash), so it stays traceable.
Modes (results.json "mode"): pending (no input), pilot (every status stamped PILOT DATA),
campaign (refused unless results.json names its freeze manifest hash).

Every macro is emitted as \\providecommand + \\renewcommand, so a generated file never fails
on a macro the manuscript does not define. Output is deterministic: only the comment lines
"% code:" and "% generated:" vary between regenerations of the same inputs.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..hashing import sha256_file
from ..paths import code_commit, protocol_dir, published_dir

GENERATOR_VERSION = "0.2.0"
PENDING = r"\pending"

# macro -> (producing stage, meaning, where it appears in the paper)
PROTOCOL_MACROS = {
    "PWBudget": ("setup", "Evidence-readiness reference threshold B_ref (RQ2); 5 s",
                 "abstract, introduction, RQ2, Eq. readiness-reference, results, discussion, threats, conclusion"),
    "PWTau": ("setup", "Divergence threshold tau (Eq. divergent-pairs)", "available"),
    "PWRunsPlanned": ("setup", "Declared RepoAudit runs per model, N", "available"),
    "PWSemgrepRuns": ("setup", "Declared Semgrep runs, M", "available"),
    "PWPrimaryModel": ("setup", "Declared RepoAudit model(s), identifiers only", "available"),
    "PWProtocolHash": ("setup", "Short sha256 of protocol.lock", "available"),
}
REG_STATUS = {  # paper Table tab:registration, "Status" column
    "PWRegTarget": ("Common target", "To be locked"),
    "PWRegOracle": ("Independent oracle", "To be locked"),
    "PWRegRepoAudit": ("RepoAudit campaign", "To be locked"),
    "PWRegSemgrep": ("Semgrep configuration", "To be locked"),
    "PWRegPath": ("Path comparison", "To be locked"),
    "PWRegContract": ("Evidence contract", "To be locked"),
    "PWRegPlane": ("Evidence plane", "To be locked"),
    "PWRegTiming": ("Timing protocol", "To be locked"),
    "PWRegThreshold": ("Reference threshold", "Threshold fixed"),
    "PWRegViews": ("Frozen views", "To be locked"),
}
RESULT_MACROS = {
    "PWRunTotal": ("Stage 1", "Scheduled and accounted-for RepoAudit runs", "Table acquisition-results"),
    "PWRunGreen": ("Stage 1", "GREEN RepoAudit runs (DR-11)", "Table acquisition-results"),
    "PWRunIncomplete": ("Stage 1", "Failed or incomplete RepoAudit runs", "Table acquisition-results"),
    "PWRunPathObservable": ("Stage 4", "Runs with comparable observable paths", "Table acquisition-results"),
    "PWEligiblePairs": ("Stage 4", "Eligible positive pairs", "Table acquisition-results"),
    "PWDivergentPairs": ("Stage 4", "Qualifying divergent positive pairs |D|", "Table acquisition-results"),
    "PWSelectedPair": ("Stage 4", "Selected run pair (lexicographic rule) or 'unattained'", "Table acquisition-results"),
    "PWCorpusRecords": ("Stage 2", "Authentic canonical evidence records in E", "Table acquisition-results"),
    "PWCorpusHash": ("Stage 2", "Frozen corpus identifier and hash", "Table acquisition-results"),
    "PWMaximumScale": ("Stage 3", "Largest measured evidence population", "Results, Experiment 1 text"),
    "PWMaximumReady": ("Stage 3", "Maximum observed T_PW-ready at that population", "Results, Experiment 1 text"),
    "PWBudgetBoundary": ("Stage 3", "Workload where T_PW-ready crosses B_ref, or 'no crossing in tested range'", "Results, Experiment 1 text"),
    "PWOracleAgreement": ("Stage 4", "Agreement with the independent oracle (k/n)", "Results, Experiment 2 text"),
    "PWUnsupportedProceed": ("Stage 4", "Unsupported PROCEED count (k/n)", "Results, Experiment 2 text"),
    "PWReplayAgreement": ("Stage 4", "Deterministic replay agreement (k/n)", "Results, Experiment 2 text"),
    "PWResultStatus": ("report", "One-sentence results status", "Results opening, conclusion"),
    "PWAbstractResults": ("report", "Results sentence(s) closing the abstract", "abstract"),
}
TIMING_TARGETS = ["10", "100", "1000", "10000"]
TIMING_COLS = ("actual", "repetitions", "median", "maximum", "failures_threshold")
ASSURANCE_VIEWS = ["P0", "P1", "P2", "P2w", "P3", "P4", "P5", "P6", "P7", "P8", "P9"]
ASSURANCE_COLS = ("verdict_only", "oracle", "observed", "trace")
VOLATILE = ("% code:", "% generated:")


class PaperTexError(ValueError):
    pass


def default_results() -> Path | None:
    """results.json of the (single) published cycle, if one is published."""
    base = published_dir()
    found = sorted(base.glob("*/results.json")) if base.exists() else []
    if len(found) > 1:
        raise PaperTexError(f"more than one published cycle: {[p.parent.name for p in found]}")
    return found[0] if found else None


def default_lock() -> Path:
    return protocol_dir() / "protocol.lock.json"


def _tex_target(t: str) -> str:
    return "$" + f"{int(t):,}".replace(",", "{,}") + "$"


def _load(p: Path | None) -> dict | None:
    return json.loads(p.read_text()) if p and p.exists() else None


def _macro(name: str, value: str) -> str:
    return rf"\providecommand{{\{name}}}{{}}\renewcommand{{\{name}}}{{{value}}}"


def _val(results: dict | None, key: str) -> str:
    if not results or key not in results.get("macros", {}):
        return PENDING
    v = results["macros"][key]
    if not isinstance(v, dict) or "value" not in v or "source" not in v:
        raise PaperTexError(f"results.json: macro {key} needs {{'value', 'source'}} (traceability)")
    return str(v["value"])


def build(lock_path: Path | None, results_path: Path | None) -> dict[str, str]:
    lock, results = _load(lock_path), _load(results_path)
    mode = (results or {}).get("mode", "pending")
    if mode not in {"pending", "pilot", "campaign"}:
        raise PaperTexError(f"unknown mode {mode!r}")
    if mode == "campaign" and not (results or {}).get("freeze_manifest_sha256"):
        raise PaperTexError("campaign mode requires freeze_manifest_sha256 in results.json")
    code = code_commit()
    sources = {
        "protocol.lock.json": sha256_file(lock_path) if lock_path and lock_path.exists() else "absent",
        "results.json": sha256_file(results_path) if results_path and results_path.exists() else "absent",
        "cycle": (results or {}).get("cycle", "none"),
    }

    def header(name: str, m: str) -> list[str]:
        return [f"% GENERATED by pwexp paper-tex v{GENERATOR_VERSION} (proofweave-decision-assurance): {name}. Do not edit.",
                f"% mode: {m}", *[f"% source {k}: {v}" for k, v in sources.items()],
                f"% code: {code['commit']}{' (dirty)' if code['dirty'] else ''}",
                f"% generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"]

    files: dict[str, str] = {}
    lines = header("protocol-macros.tex", "locked" if lock else "unlocked (defaults)")
    pm = (lock or {}).get("macros", {})
    lines += [_macro(n, pm[n]) for n in PROTOCOL_MACROS if n in pm]
    rs = (lock or {}).get("registration_status", {})
    lines += [_macro(n, rs.get(n, default)) for n, (_, default) in REG_STATUS.items()]
    files["protocol-macros.tex"] = "\n".join(lines) + "\n"

    lines = header("results-macros.tex", mode)
    for name in RESULT_MACROS:
        if name in ("PWResultStatus", "PWAbstractResults") and mode == "pending":
            continue  # keep the author-written placeholders in the manuscript
        val = _val(results, name)
        if mode == "pilot" and name == "PWResultStatus":
            val = r"\textbf{PILOT DATA, NOT CAMPAIGN RESULTS.} " + val
        lines.append(_macro(name, val))
    files["results-macros.tex"] = "\n".join(lines) + "\n"

    rows = (results or {}).get("timing_rows", {})
    lines = header("tab-timing-body.tex", mode)
    for t in TIMING_TARGETS:
        r = rows.get(t, {})
        lines.append(" & ".join([_tex_target(t)] + [str(r.get(k, PENDING)) for k in TIMING_COLS]) + r" \\")
    files["tab-timing-body.tex"] = "\n".join(lines) + "\n"

    rows = (results or {}).get("assurance_rows", {})
    lines = header("tab-assurance-body.tex", mode)
    for v in ASSURANCE_VIEWS:
        r = rows.get(v, {})
        lines.append(" & ".join([v] + [str(r.get(k, PENDING)) for k in ASSURANCE_COLS]) + r" \\")
    files["tab-assurance-body.tex"] = "\n".join(lines) + "\n"
    return files


def strip_volatile(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.startswith(VOLATILE))


def stale(out: Path, files: dict[str, str]) -> list[str]:
    return [n for n, c in files.items()
            if not (out / n).exists() or strip_volatile((out / n).read_text()) != strip_volatile(c)]


def write(out: Path, files: dict[str, str]) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for n, c in files.items():
        (out / n).write_text(c)
        written.append(out / n)
    return written
