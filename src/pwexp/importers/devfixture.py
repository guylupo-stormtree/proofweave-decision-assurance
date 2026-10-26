"""Import the development fixture runs in tests/fixtures/dev-guarded-users (fixtures only, never results).

Source format: the maintainers' feasibility harness (RepoAudit 160f5bc, local qwen2.5-coder:3b) plus one
Semgrep run from this repository's Stage 1 code. Native RepoAudit files (dfbscan.log, console.log) are
copied byte-identical and verified against the source manifest's `output_checksums`. The feasibility
harness wrote `detect_info.json` itself when RepoAudit reported nothing (RepoAudit only writes it when it
accepts a finding), so that file is kept as `harness-detect_info.json` and zero findings are established
from RepoAudit's own log line, as the GREEN mapping requires. An imported cycle is always a `pilot`.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .. import cycles
from ..hashing import manifest_hash, sha256_file, tree_manifest
from ..stages.stage1_acquire import green_repoaudit

TARGET = "targets/fixture-guarded-users"
ZERO = "0 bug(s) was/were detected"


class DevFixtureError(ValueError):
    pass


def import_run(src: Path, dst: Path, alias: str, rep: int) -> dict:
    sm = json.loads((src / "manifest.json").read_text())
    for name, h in sm.get("output_checksums", {}).items():
        if name != "manifest.json" and sha256_file(src / name) != h:
            raise DevFixtureError(f"{src}/{name}: sha256 does not match the source manifest")
    dst.mkdir(parents=True, exist_ok=False)
    for name in ("dfbscan.log", "console.log"):
        shutil.copy2(src / name, dst / name)
    native_findings = None
    if (src / "detect_info.json").exists():
        d = json.loads((src / "detect_info.json").read_text() or "{}")
        if d:  # non-empty: RepoAudit itself wrote it
            shutil.copy2(src / "detect_info.json", dst / "detect_info.json")
            native_findings = len(d)
        else:
            shutil.copy2(src / "detect_info.json", dst / "harness-detect_info.json")
    log = (dst / "dfbscan.log").read_text(errors="replace")
    complete = sm.get("completion_state") == "complete" and sm.get("exit_code") == 0 and not sm.get("timed_out")
    if native_findings is not None:
        findings, source = native_findings, "native"
    elif complete and ZERO in log:
        findings, source = 0, "log-confirmed-empty"
    else:
        findings, source = None, "missing"
    (dst / "calls.jsonl").write_text("")
    man = {
        "run": f"{alias}/run{rep:03d}", "control": "repoaudit", "alias": alias, "provider": "local",
        "requested_model": sm.get("requested_model"), "response_models_observed": [],
        "provider_calls": None, "failed_calls": None, "input_tokens": None, "output_tokens": None,
        "cmd": sm.get("cmd", [])[1:], "temperature": sm.get("temperature"), "start": sm.get("start_time"),
        "wall_clock_s": sm.get("wall_clock_seconds"), "exit_code": sm.get("exit_code"),
        "timed_out": bool(sm.get("timed_out")), "complete": complete, "findings": findings,
        "detect_info_source": source, "green": green_repoaudit(complete, findings),
        "imported_from": {"fixture": "tests/fixtures/dev-guarded-users", "path": f"{src.parent.parent.name}/{src.parent.name}/{src.name}",
                          "source_run_id": sm.get("run_id"), "note": "development model; provider calls not recorded"},
    }
    man["output_sha256"] = {f.name: sha256_file(f) for f in sorted(dst.iterdir()) if f.is_file()}
    (dst / "manifest.json").write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    return man


def _write_decisions(out: Path, mans: list[dict], proto: dict, base: Path) -> list[dict]:
    """Development decision bundles (DR-23) over imported runs: the declared schedule, with the imported runs
    assigned in import order. Written after the runs, so each context says so (`provenance`)."""
    from ..proofweave import decision_bundle
    from ..stages.stage1_acquire import schedule
    plan = schedule(proto["decisions"], proto["decisions"]["seed"])
    ra = [m["run"] for m in mans if m["control"] == "repoaudit"]
    sg = [m["run"] for m in mans if m["control"] == "semgrep"]
    need_ra = sum("repoaudit" in d["basis"] for d in plan)
    need_sg = sum("semgrep" in d["basis"] for d in plan)
    standalone = int((proto.get("acquisition") or {}).get("semgrep_runs") or 0)   # in no decision's basis
    if (need_ra, need_sg + standalone) != (len(ra), len(sg)):
        raise DevFixtureError(f"the decision schedule needs {need_ra} RepoAudit and {need_sg} Semgrep runs "
                              f"(+{standalone} standalone); {len(ra)} and {len(sg)} were imported")
    sg = sg[:need_sg]                                  # decisions take the first; the rest stay standalone
    green = {m["run"]: bool(m["green"]) for m in mans}
    it = {"repoaudit": iter(ra), "semgrep": iter(sg)}
    i = proto["decisions"]["intent"]
    for d in plan:
        tags = [next(it[b]) for b in ("repoaudit", "semgrep") if b in d["basis"]]
        pid, pver = d["policy"].split("@", 1)
        intent = {"intent_id": f"intent-{d['decision_id']}", "action": i["action"], "repo": i["repo"],
                  "commit": i["commit"], "bug_type": i["bug_type"],
                  "scope_ref": {"file": i["scope"], "sha256": sha256_file(base / i["scope"])},
                  "requested_by": i["requested_by"], "created_at": decision_bundle.now_us()}
        b = out / "decisions" / d["decision_id"]
        decision_bundle.write_context(b, d["decision_id"], d["control"], "development-import", intent, pid, pver,
                                      (base / proto["policies"][d["policy"]]["file"]).read_bytes(), tags, d["rule"])
        ctx = json.loads((b / "decision_context.json").read_text())
        ctx["provenance"] = "development import: context written after the imported runs, not before"
        (b / "decision_context.json").write_text(json.dumps(ctx, indent=2, sort_keys=True) + "\n")
        decision_bundle.write_decision(b, {t: green[t] for t in tags}, harness_version="pwexp devfixture import")
        d["basis_runs"] = tags
    return plan


def import_cycle(fixture: Path, runs: list[str], semgrep: list[str] = (), operator: str = "importer",
                 decisions: dict | None = None, base: Path | None = None) -> cycles.Cycle:
    """runs: '<variant>/<model>/<run>' paths under `fixture`; semgrep: 'semgrep/<run>' paths.
    decisions: a decision protocol (its `decisions` and `policies` blocks, paths relative to `base`); when
    given, development decision bundles are written over the imported runs (fixtures only)."""
    fixture = Path(fixture)
    variants = sorted({r.split("/")[0] for r in runs})
    aliases = {v: f"gpt-pw-m{i}" for i, v in enumerate(variants, 1)}
    meta = {"imported_from": {"fixture": "tests/fixtures/dev-guarded-users", "runs": list(runs), "semgrep": list(semgrep),
                              "purpose": "development and test fixture; not a result of this study"}}
    c = cycles.create("pilot", None, models=[{"role": "repoaudit", "provider": "local", "model": "qwen2.5-coder:3b",
                                              "alias": a, "variant": v} for v, a in aliases.items()], meta=meta)
    attempt = c.start(1)
    out = c.stage_dir(1) / f"attempt{attempt}"
    out.mkdir(parents=True)
    reps: dict[str, int] = {}
    mans = []
    for r in runs:
        v = r.split("/")[0]
        reps[v] = reps.get(v, 0) + 1
        mans.append(import_run(fixture / r, out / "repoaudit" / aliases[v] / f"run{reps[v]:03d}", aliases[v], reps[v]))
    for k, s in enumerate(semgrep, 1):
        dst = out / "semgrep" / f"run{k:03d}"
        shutil.copytree(fixture / s, dst)
        sm = json.loads((dst / "manifest.json").read_text())
        if any(sha256_file(dst / n) != h for n, h in sm["output_sha256"].items() if n != "manifest.json"):
            raise DevFixtureError(f"{s}: Semgrep output does not match its manifest")
        mans.append(sm)
    plan_decisions = _write_decisions(out, mans, decisions, Path(base)) if decisions else []
    (out / "plan.json").write_text(json.dumps({"imported": True, "target": TARGET, "runs": list(runs),
                                               "semgrep": list(semgrep), "aliases": aliases, **meta,
                                               **({"decisions": plan_decisions} if decisions else {})},
                                              indent=2, sort_keys=True) + "\n")
    files = tree_manifest(out)
    sealed = {"cycle": c.id, "attempt": attempt, "files": files, "files_sha256": manifest_hash(files)}
    (out / "sealed-manifest.json").write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n")
    ra = [m for m in mans if m["control"] == "repoaudit"]
    sg = [m for m in mans if m["control"] == "semgrep"]
    checks = {"every selected run imported": len(ra) == len(runs) and len(sg) == len(semgrep),
              "native files match the source checksums": True}
    outcome = {"repoaudit_runs": len(ra), "repoaudit_green": sum(m["green"] for m in ra),
               "repoaudit_adverse": sum(m["complete"] and not m["green"] for m in ra),
               "repoaudit_failed": sum(not m["complete"] for m in ra), "semgrep_runs": len(sg),
               "semgrep_green": sum(m["green"] for m in sg), "sealed_manifest_sha256": sealed["files_sha256"],
               "attempt_dir": out.name, "imported": True}
    if decisions:
        outcome["decisions"] = {"count": len(plan_decisions), "development_import": True}
    c.finish(1, checks, sealed["files_sha256"], outcome, operator)
    return c
