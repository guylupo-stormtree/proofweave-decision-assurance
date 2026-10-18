"""Import RepoAudit runs published with the first study (development and test fixtures only).

Source: https://github.com/guylupo-stormtree/taip-repoaudit-posture (Apache-2.0), dataset
`datasets/live-v1/python_npd/<model>/<run>/`: unmodified RepoAudit 160f5bc on RepoAudit's own toy
Python NPD benchmark, OpenAI gpt-4.1 and gpt-4o-mini, temperature 0.

These runs use the same RepoAudit revision and native log format as Stage 1, so they exercise the
ProofWeave adapter, ledger and graph on real model behaviour. They are NOT results of this study:
they were collected under a different protocol, and no run is GREEN at project level (every run
reports planted bugs). An imported cycle is always a `pilot` cycle carrying `imported_from`.

Native files (dfbscan.log, detect_info.json, console.log) are copied byte-identical and verified
against the source run's own checksums.json. Only wrapper files are converted to the Stage 1 layout.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .. import cycles
from ..hashing import manifest_hash, sha256_file, tree_manifest
from ..stages.stage1_acquire import green_repoaudit

SOURCE_REPO = "https://github.com/guylupo-stormtree/taip-repoaudit-posture"
SOURCE_COMMIT = "3b3968f78f3f739500364aea4585fb6b050e51ee"
SOURCE_LICENCE = "Apache-2.0"
NATIVE = ("dfbscan.log", "detect_info.json", "console.log")
TARGET = "vendor/RepoAudit/benchmark/Python/toy"


class ImportError_(ValueError):
    pass


def _alias_map(runs: list[str]) -> dict[str, str]:
    models = sorted({r.split("/")[0] for r in runs})
    return {m: f"gpt-pw-m{i}" for i, m in enumerate(models, 1)}


def import_run(src: Path, dst: Path, alias: str, rep: int) -> dict:
    """Copy one source run into Stage 1 layout. Returns the Stage 1 run manifest."""
    src_checks = json.loads((src / "checksums.json").read_text())
    src_man = json.loads((src / "manifest.json").read_text())
    dst.mkdir(parents=True, exist_ok=False)
    for name in NATIVE:
        if not (src / name).exists():
            continue
        if sha256_file(src / name) != src_checks.get(name):
            raise ImportError_(f"{src}/{name}: sha256 does not match the source checksums.json")
        shutil.copy2(src / name, dst / name)
    tag = f"{alias}/run{rep:03d}"
    calls = []
    for line in (src / "provider_calls.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        c = json.loads(line)
        calls.append({"ts": c["ts"], "run": tag, "alias": alias, "provider": src_man.get("routed_provider", "openai"),
                      "requested_model": c.get("requested_model"), "response_model": c.get("response_model"),
                      "status": c.get("status"), "input_tokens": c.get("input_tokens", 0),
                      "output_tokens": c.get("output_tokens", 0), "latency_s": c.get("latency_s"), "error": c.get("error")})
    with (dst / "calls.jsonl").open("w") as f:
        for c in calls:
            f.write(json.dumps(c, sort_keys=True) + "\n")
    shutil.copy2(src / "manifest.json", dst / "source-manifest.json")
    findings = src_man.get("findings_count")
    if (dst / "detect_info.json").exists():
        native = json.loads((dst / "detect_info.json").read_text() or "{}")
        if findings is not None and len(native) != findings:
            raise ImportError_(f"{src}: findings_count {findings} != {len(native)} reports in detect_info.json")
        findings = len(native)
    complete = src_man.get("completion_state") == "complete" and src_man.get("exit_code") == 0
    man = {
        "run": tag, "control": "repoaudit", "alias": alias, "provider": src_man.get("routed_provider", "openai"),
        "requested_model": src_man.get("requested_model"),
        "response_models_observed": src_man.get("response_models_observed", []),
        "provider_calls": len(calls), "failed_calls": sum(1 for c in calls if c["status"] != 200),
        "input_tokens": src_man.get("input_tokens", 0), "output_tokens": src_man.get("output_tokens", 0),
        "cmd": src_man.get("cmd", [])[1:], "temperature": src_man.get("temperature"),
        "start": src_man.get("start_time"), "wall_clock_s": src_man.get("wall_clock_seconds"),
        "exit_code": src_man.get("exit_code"), "timed_out": False, "complete": complete, "findings": findings,
        "detect_info_source": "native" if (dst / "detect_info.json").exists() else "missing",
        "green": green_repoaudit(complete, findings),
        "imported_from": {"repo": SOURCE_REPO, "commit": SOURCE_COMMIT, "licence": SOURCE_LICENCE,
                          "path": f"datasets/live-v1/python_npd/{src.parent.name}/{src.name}",
                          "source_run_id": src_man.get("run_id"), "source_checksums": src_checks},
    }
    man["output_sha256"] = {f.name: sha256_file(f) for f in sorted(dst.iterdir()) if f.is_file()}
    (dst / "manifest.json").write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    return man


def import_cycle(dataset: Path, runs: list[str], operator: str = "importer") -> cycles.Cycle:
    """Create a pilot cycle whose Stage 1 consists of the selected source runs ("<model>/<run>")."""
    dataset = Path(dataset)
    aliases = _alias_map(runs)
    meta = {"imported_from": {"repo": SOURCE_REPO, "commit": SOURCE_COMMIT, "licence": SOURCE_LICENCE,
                              "dataset": "datasets/live-v1/python_npd", "runs": runs,
                              "purpose": "development and test fixture; not a result of this study"}}
    models = [{"role": "repoaudit", "provider": "openai", "model": m, "alias": a} for m, a in aliases.items()]
    c = cycles.create("pilot", None, models=models, meta=meta)
    attempt = c.start(1)
    out = c.stage_dir(1) / f"attempt{attempt}"
    out.mkdir(parents=True)
    reps: dict[str, int] = {}
    manifests = []
    for r in runs:
        model = r.split("/")[0]
        reps[model] = reps.get(model, 0) + 1
        alias = aliases[model]
        manifests.append(import_run(dataset / r, out / "repoaudit" / alias / f"run{reps[model]:03d}", alias, reps[model]))
    (out / "plan.json").write_text(json.dumps({"imported": True, "target": TARGET, "runs": runs, "aliases": aliases,
                                               **meta}, indent=2, sort_keys=True) + "\n")
    files = tree_manifest(out)
    sealed = {"cycle": c.id, "attempt": attempt, "files": files, "files_sha256": manifest_hash(files)}
    (out / "sealed-manifest.json").write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n")
    checks = {"every selected run imported": len(manifests) == len(runs),
              "native files byte-identical to the source checksums": True,  # import_run raises otherwise
              "findings consistent with native reports": True}
    outcome = {"repoaudit_runs": len(manifests), "repoaudit_green": sum(m["green"] for m in manifests),
               "repoaudit_adverse": sum(m["complete"] and not m["green"] for m in manifests),
               "repoaudit_failed": sum(not m["complete"] for m in manifests), "semgrep_runs": 0,
               "sealed_manifest_sha256": sealed["files_sha256"], "attempt_dir": out.name, "imported": True}
    c.finish(1, checks, sealed["files_sha256"], outcome, operator)
    return c
