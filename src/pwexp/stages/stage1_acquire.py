"""Stage 1: acquire and freeze evidence (DR-11, DR-20).

Runs every scheduled control execution on one immutable target and keeps every outcome:
  N RepoAudit runs per model entry (fresh process each, model order shuffled per replicate
  with a recorded seed) through the local model gateway, and M Semgrep runs with pinned rules.
Applies the frozen GREEN mapping, hashes every output, seals the evidence bed
(stage1/sealed-manifest.json) and records the stage result in the cycle's stage log.

Decision schedule (DR-23, opt-in): when the protocol declares `decisions:`, Stage 1 runs a seeded, shuffled
list of recorded decisions instead of N runs per model. For each decision it writes the decision context
(intent, policy-at-event, planned basis runs) BEFORE the first basis run, runs the basis (one RepoAudit
run, or one RepoAudit and one Semgrep run), and writes the decision AFTER the last one
(decisions/<id>/, see proofweave.decision_bundle). Every scheduled decision and run is kept.

RepoAudit is never modified: it is invoked as a subprocess with the gateway URL and a
per-run gateway token in its environment, and no provider key ever enters its environment.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .. import setup_env
from ..cycles import Cycle
from ..gateway import ModelGateway
from ..hashing import manifest_hash, sha256_file, tree_manifest
from ..models import RunModels
from ..proofweave import decision_bundle

Progress = Callable[[str], None]
_SECRET_ENV = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY2", "GEMINI_API_KEY",
               "GOOGLE_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "OPENAI_BASE_URL")


@dataclass
class Stage1Config:
    target: Path
    language: str
    bug_type: str
    runs_per_model: int
    semgrep_runs: int
    semgrep_ruleset: Path
    temperature: float = 0.0
    call_depth: int = 3
    workers: int = 4
    timeout_s: int = 3600
    seed: int = field(default_factory=lambda: random.SystemRandom().randrange(1, 2**31))
    decisions: dict | None = None      # protocol `decisions:` block (decision schedule mode)
    policies: dict | None = None       # protocol `policies:` block
    base: Path | None = None           # directory relative protocol paths resolve against
    semgrep_version: str = ""

    @classmethod
    def from_protocol(cls, proto: dict, root: Path, seed: int | None = None) -> "Stage1Config":
        a, t = proto["acquisition"], proto["target"]
        kw = dict(target=root / t["snapshot_path"], language=t["language"], bug_type=t["bug_type"],
                  runs_per_model=a.get("repoaudit_runs_per_model", 0), semgrep_runs=a.get("semgrep_runs", 0),
                  semgrep_ruleset=root / proto["semgrep"]["ruleset"], temperature=a["temperature"],
                  call_depth=a["call_depth"], workers=a.get("workers", 4), timeout_s=a["timeout_s"],
                  decisions=proto.get("decisions"), policies=proto.get("policies"), base=root,
                  semgrep_version=str(proto["semgrep"].get("version") or ""))
        if seed is not None:
            kw["seed"] = seed
        elif proto.get("decisions"):
            kw["seed"] = proto["decisions"]["seed"]
        return cls(**kw)


def schedule(decisions: dict, seed: int) -> list[dict]:
    """Expand the declared groups into decisions and shuffle them with the recorded seed, so policy
    assignment is independent of run order."""
    out = []
    for g in decisions["groups"]:
        for i in range(1, g["count"] + 1):
            out.append({"decision_id": f"{g['group']}-{i:02d}", "group": g["group"],
                        "control": g.get("control", "repoaudit"), "basis": list(g["basis"]),
                        "policy": g["policy"], "rule": g["rule"]})
    random.Random(seed).shuffle(out)
    return out


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_us() -> str:
    return decision_bundle.now_us()


def green_repoaudit(complete: bool, findings: int | None) -> bool:
    """DR-11: normal completion and zero accepted findings (native, or confirmed by the native log)."""
    return complete and findings == 0


def green_semgrep(exit_code: int | None, results: int | None, errors: int | None) -> bool:
    """Semgrep counterpart of DR-11: completed without errors and zero findings."""
    return exit_code == 0 and errors == 0 and results == 0


def _clean_env(extra: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _SECRET_ENV and not k.endswith("_API_KEY")}
    env.update(extra)
    return env


def _leaf_dirs(base: Path) -> set[Path]:
    if not base.exists():
        return set()
    return {p for p in base.rglob("*") if p.is_dir() and not any(c.is_dir() for c in p.iterdir())}


# RepoAudit skips every function whose absolute file path contains one of these words (its test and example
# filter), so a checkout under e.g. ~/dev/my-testing/ would be skipped entirely and every run would be an empty GREEN.
SKIPPED_PATH_WORDS = ("test", "example")


def _subject_copy(target: Path) -> Path:
    """A byte-identical copy of the target at a neutral path that RepoAudit's filter does not match. Bind makes
    every path relative to the recorded --project-path, so the records are the same as for the original."""
    base = Path(tempfile.mkdtemp(prefix="pwexp-subject-"))
    if any(w in str(base).lower() for w in SKIPPED_PATH_WORDS):
        shutil.rmtree(base, ignore_errors=True)
        raise RuntimeError(f"temporary directory {base} contains one of {SKIPPED_PATH_WORDS}, which RepoAudit "
                           "skips; set TMPDIR to a neutral directory")
    copy = base / target.name
    shutil.copytree(target, copy, symlinks=True)
    if manifest_hash(tree_manifest(copy)) != manifest_hash(tree_manifest(target)):
        shutil.rmtree(base, ignore_errors=True)
        raise RuntimeError("the subject copy of the target differs from the target")
    return copy


def _run_repoaudit(cfg: Stage1Config, alias: str, out: Path, gw: ModelGateway, tag: str) -> dict:
    subject = _subject_copy(cfg.target.resolve())
    try:
        return _run_repoaudit_on(cfg, alias, out, gw, tag, subject)
    finally:
        shutil.rmtree(subject.parent, ignore_errors=True)


def _run_repoaudit_on(cfg: Stage1Config, alias: str, out: Path, gw: ModelGateway, tag: str, subject: Path) -> dict:
    ra = setup_env.repoaudit_dir()
    log_root, res_root = ra / "log" / "dfbscan", ra / "result" / "dfbscan"
    before_log, before_res = _leaf_dirs(log_root), _leaf_dirs(res_root)
    cmd = [str(setup_env.repoaudit_python()), "repoaudit.py", "--scan-type", "dfbscan",
           "--language", cfg.language, "--model-name", alias, "--project-path", str(subject),
           "--bug-type", cfg.bug_type, "--is-reachable", "--temperature", str(cfg.temperature),
           "--call-depth", str(cfg.call_depth), "--max-neural-workers", str(cfg.workers)]
    out.mkdir(parents=True, exist_ok=False)
    gw.mark(tag)
    t0, start, start_us = time.monotonic(), _now(), _now_us()
    try:
        p = subprocess.run(cmd, cwd=ra / "src", env=_clean_env(gw.child_env()), capture_output=True,
                           text=True, timeout=cfg.timeout_s)
        code, console, timed_out = p.returncode, p.stdout + p.stderr, False
    except subprocess.TimeoutExpired as e:
        code, timed_out = None, True
        console = "".join(x.decode() if isinstance(x, bytes) else (x or "") for x in (e.stdout, e.stderr))
    wall = round(time.monotonic() - t0, 3)
    gw.mark(None)
    (out / "console.log").write_text(console)
    new_log = sorted(_leaf_dirs(log_root) - before_log, key=lambda d: d.stat().st_mtime)
    new_res = sorted(_leaf_dirs(res_root) - before_res, key=lambda d: d.stat().st_mtime)
    if new_log and (new_log[-1] / "dfbscan.log").exists():
        shutil.copy2(new_log[-1] / "dfbscan.log", out / "dfbscan.log")
    detect_source = "missing"
    if new_res and (new_res[-1] / "detect_info.json").exists():
        shutil.copy2(new_res[-1] / "detect_info.json", out / "detect_info.json")
        detect_source = "native"
    for d in new_log + new_res:  # keep the subject's tree clean; the copies are the record
        shutil.rmtree(d, ignore_errors=True)
    calls = gw.calls_for(tag)
    with (out / "calls.jsonl").open("w") as f:
        for c in calls:
            f.write(json.dumps(c, sort_keys=True) + "\n")
    log_text = (out / "dfbscan.log").read_text(errors="replace") if (out / "dfbscan.log").exists() else ""
    complete = code == 0 and not timed_out and "Traceback" not in console and bool(log_text)
    findings: int | None = None
    if detect_source == "native":
        d = json.loads((out / "detect_info.json").read_text() or "{}")
        findings = len(d) if isinstance(d, (dict, list)) else None
    elif complete and "0 bug(s) was/were detected" in log_text:
        findings, detect_source = 0, "log-confirmed-empty"
    entry = gw.models.by_alias(alias)
    man = {
        "run": tag, "control": "repoaudit", "alias": alias, "provider": entry.provider, "requested_model": entry.model,
        "response_models_observed": sorted({c["response_model"] for c in calls if c["response_model"]}),
        "provider_calls": len(calls), "failed_calls": sum(1 for c in calls if c["status"] != 200),
        "input_tokens": sum(c["input_tokens"] for c in calls), "output_tokens": sum(c["output_tokens"] for c in calls),
        "cmd": [*cmd[1:]], "temperature": cfg.temperature, "start": start, "start_us": start_us, "wall_clock_s": wall,
        "exit_code": code, "timed_out": timed_out, "complete": complete, "findings": findings,
        "detect_info_source": detect_source, "green": green_repoaudit(complete, findings),
    }
    man["output_sha256"] = {f.name: sha256_file(f) for f in sorted(out.iterdir()) if f.is_file()}
    (out / "manifest.json").write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    return man


def _run_semgrep(cfg: Stage1Config, out: Path, tag: str) -> dict:
    cmd = [str(setup_env.semgrep_bin()), "scan", "--config", str(cfg.semgrep_ruleset), "--json", "--metrics=off",
           "--disable-version-check", "--quiet", str(cfg.target.resolve())]
    out.mkdir(parents=True, exist_ok=False)
    t0, start, start_us = time.monotonic(), _now(), _now_us()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.timeout_s, env=_clean_env({}))
        code, stdout, stderr = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        code, stdout, stderr = None, "", "timeout"
    (out / "semgrep.json").write_text(stdout)
    (out / "console.log").write_text(stderr)
    results = errors = None
    try:
        d = json.loads(stdout)
        results, errors = len(d.get("results", [])), len(d.get("errors", []))
    except ValueError:
        pass
    man = {"run": tag, "control": "semgrep", "cmd": cmd[1:], "ruleset_sha256": sha256_file(cfg.semgrep_ruleset),
           "start": start, "start_us": start_us, "wall_clock_s": round(time.monotonic() - t0, 3), "exit_code": code,
           "results": results, "errors": errors, "green": green_semgrep(code, results, errors)}
    man["output_sha256"] = {f.name: sha256_file(f) for f in sorted(out.iterdir()) if f.is_file()}
    (out / "manifest.json").write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    return man


def _run_dir(m: dict) -> str:
    return ("repoaudit/" + m["run"]) if m["control"] == "repoaudit" else m["run"]


def _secret_scan(root: Path, models: RunModels) -> list[str]:
    keys = [e.key for e in models.entries() if len(e.key) >= 8]
    hits = []
    for f in root.rglob("*"):
        if f.is_file():
            data = f.read_bytes()
            if any(k.encode() in data for k in keys):
                hits.append(f.relative_to(root).as_posix())
    return hits


def run(cycle: Cycle, cfg: Stage1Config, models: RunModels, operator: str = "unknown",
        progress: Progress = print) -> bool:
    """Run Stage 1 on `cycle`. Returns True when every check passes (the next stage unlocks)."""
    ra_models = models.entries("repoaudit")
    if not ra_models:
        raise ValueError("Stage 1 needs at least one RepoAudit model entry")
    if cycle.data["mode"] == "campaign":
        from .. import protocol
        if not models.matches_protocol(protocol.load()["acquisition"]["models"]):
            raise ValueError("campaign cycle: the model list must equal the locked protocol (DR-20)")
    attempt = cycle.start(1)
    out = cycle.stage_dir(1) / f"attempt{attempt}"
    out.mkdir(parents=True, exist_ok=False)
    before = setup_env.subject_state()
    target_manifest = manifest_hash(tree_manifest(cfg.target))
    plan = {"target": str(cfg.target), "target_manifest_sha256": target_manifest, "seed": cfg.seed,
            "decision_schedule": bool(cfg.decisions),
            "runs_per_model": cfg.runs_per_model, "semgrep_runs": cfg.semgrep_runs, "models": models.public(),
            "subject_before": before, "started": _now()}
    gw = ModelGateway(models)
    gw.start()
    manifests: list[dict] = []
    plan_decisions: list[dict] = []
    try:
        if cfg.decisions:
            if len(ra_models) != 1:
                raise ValueError("a decision schedule uses exactly one RepoAudit model entry")
            plan_decisions = schedule(cfg.decisions, cfg.seed)
            manifests = _run_decisions(cfg, plan_decisions, ra_models[0].alias, out, gw, before, progress)
        total = 0 if cfg.decisions else cfg.runs_per_model * len(ra_models)
        k = 0
        for rep in range(1, cfg.runs_per_model + 1):
            order = [e.alias for e in ra_models]
            random.Random(cfg.seed + rep).shuffle(order)
            for alias in order:
                k += 1
                tag = f"{alias}/run{rep:03d}"
                progress(f"RepoAudit {k}/{total}  {gw.models.by_alias(alias).model}  run {rep}")
                m = _run_repoaudit(cfg, alias, out / "repoaudit" / alias / f"run{rep:03d}", gw, tag)
                manifests.append(m)
                progress(f"  {'GREEN' if m['green'] else ('adverse' if m['complete'] else 'failed')}"
                         f" · findings {m['findings']} · {m['wall_clock_s']} s")
        n_sg = sum("semgrep" in d["basis"] for d in plan_decisions)   # Semgrep runs already used as decision basis
        for s in range(n_sg + 1, n_sg + cfg.semgrep_runs + 1):   # standalone scans: in no decision's basis
            progress(f"Semgrep {s}/{cfg.semgrep_runs}")
            manifests.append(_run_semgrep(cfg, out / "semgrep" / f"run{s:03d}", f"semgrep/run{s:03d}"))
    finally:
        gw.stop()
    after = setup_env.subject_state()
    plan.update(subject_after=after, finished=_now(), decisions=plan_decisions)
    (out / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")

    ra = [m for m in manifests if m["control"] == "repoaudit"]
    sg = [m for m in manifests if m["control"] == "semgrep"]
    secret_hits = _secret_scan(out, models)
    files = tree_manifest(out)
    sealed = {"cycle": cycle.id, "attempt": attempt, "files": files, "files_sha256": manifest_hash(files)}
    (out / "sealed-manifest.json").write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n")
    if cfg.decisions:
        want_ra = sum("repoaudit" in d["basis"] for d in plan_decisions)
        want_sg = sum("semgrep" in d["basis"] for d in plan_decisions) + cfg.semgrep_runs
    else:
        want_ra, want_sg = cfg.runs_per_model * len(ra_models), cfg.semgrep_runs
    checks = {
        "every scheduled run accounted for": len(ra) == want_ra and len(sg) == want_sg,
        "every output hashed in the sealed manifest": all(
            all(files.get(f"{_run_dir(m)}/{name}") == h for name, h in m["output_sha256"].items() if name != "manifest.json")
            for m in manifests),
        "RepoAudit pinned and unmodified before and after": all(
            s["pinned"] and not s["tracked_files_modified"] for s in (before, after)),
        "no API key in any retained output": not secret_hits,
        "every provider call attributed to a run": all(c.run for c in gw.calls),
    }
    if cfg.decisions:
        checks.update(_decision_checks(out, plan_decisions, manifests))
    by_model = {}
    for e in ra_models:
        ms = [m for m in ra if m["alias"] == e.alias]
        by_model[f"{e.provider}:{e.model}"] = {
            "runs": len(ms), "green": sum(m["green"] for m in ms),
            "adverse": sum(m["complete"] and not m["green"] for m in ms),
            "failed": sum(not m["complete"] for m in ms),
            "input_tokens": sum(m["input_tokens"] for m in ms), "output_tokens": sum(m["output_tokens"] for m in ms)}
    outcome = {
        "repoaudit_runs": len(ra), "repoaudit_green": sum(m["green"] for m in ra),
        "repoaudit_adverse": sum(m["complete"] and not m["green"] for m in ra),
        "repoaudit_failed": sum(not m["complete"] for m in ra), "by_model": by_model,
        "semgrep_runs": len(sg), "semgrep_green": sum(m["green"] for m in sg),
        "sealed_manifest_sha256": sealed["files_sha256"], "attempt_dir": out.name,
        "secret_hits": secret_hits,
    }
    if cfg.decisions:
        dec = {b.name: json.loads((b / "decision.json").read_text()) for b in decision_bundle.bundles(out)
               if (b / "decision.json").exists()}
        by_group: dict[str, dict] = {}
        for pd in plan_decisions:
            g = by_group.setdefault(pd["group"], {"decisions": 0, "recorded": 0, "green": 0})
            g["decisions"] += 1
            if pd["decision_id"] in dec:
                g["recorded"] += 1
                g["green"] += dec[pd["decision_id"]]["verdict"] == "green"
        dec = list(dec.values())
        outcome["decisions"] = {"count": len(dec), "green": sum(d["verdict"] == "green" for d in dec), "by_group": by_group}
    return cycle.finish(1, checks, sealed["files_sha256"], outcome, operator)


def _intent(cfg: Stage1Config, decision_id: str) -> dict:
    i = cfg.decisions["intent"]
    scope = cfg.base / i["scope"]
    return {"intent_id": f"intent-{decision_id}", "action": i["action"], "repo": i["repo"], "commit": i["commit"],
            "bug_type": i["bug_type"], "scope_ref": {"file": i["scope"], "sha256": sha256_file(scope)},
            "requested_by": i["requested_by"], "created_at": _now_us()}


def _control_version(cfg: Stage1Config, before: dict, basis: list[str]) -> str:
    parts = [f"repoaudit@{str(before.get('head', ''))[:12]}"] if "repoaudit" in basis else []
    if "semgrep" in basis:
        parts.append(f"semgrep@{cfg.semgrep_version}")
    return "+".join(parts)


def _run_decisions(cfg: Stage1Config, plan: list[dict], alias: str, out: Path, gw: ModelGateway, before: dict,
                   progress: Progress) -> list[dict]:
    manifests, n_ra, n_sg = [], 0, 0
    for k, d in enumerate(plan, 1):
        tags = []
        if "repoaudit" in d["basis"]:
            n_ra += 1
            tags.append(f"{alias}/run{n_ra:03d}")
        if "semgrep" in d["basis"]:
            n_sg += 1
            tags.append(f"semgrep/run{n_sg:03d}")
        pid, pver = d["policy"].split("@", 1)
        pbytes = (cfg.base / cfg.policies[d["policy"]]["file"]).read_bytes()
        bundle = out / "decisions" / d["decision_id"]
        decision_bundle.write_context(bundle, d["decision_id"], d["control"], _control_version(cfg, before, d["basis"]),
                                      _intent(cfg, d["decision_id"]), pid, pver, pbytes, tags, d["rule"])
        progress(f"Decision {k}/{len(plan)}  {d['decision_id']} · policy {d['policy']} · basis {', '.join(tags)}")
        per_run = {}
        for tag in tags:
            if tag.startswith("semgrep/"):
                m = _run_semgrep(cfg, out / "semgrep" / tag.split("/")[1], tag)
            else:
                m = _run_repoaudit(cfg, alias, out / "repoaudit" / alias / tag.split("/")[1], gw, tag)
            manifests.append(m)
            per_run[tag] = bool(m["green"])
            progress(f"  {tag}: {'GREEN' if m['green'] else 'not GREEN'} · {m['wall_clock_s']} s")
        dec = decision_bundle.write_decision(bundle, per_run, harness_version=f"pwexp stage1 {_harness_commit()}")
        progress(f"  decision {d['decision_id']}: {dec['verdict']}")
    return manifests


def _harness_commit() -> str:
    from ..paths import code_commit
    c = code_commit()
    return f"{c['commit'][:12]}{'+dirty' if c['dirty'] else ''}"


def _decision_checks(out: Path, plan: list[dict], manifests: list[dict]) -> dict[str, bool]:
    starts = {m["run"]: m.get("start_us", "") for m in manifests}
    ok_bundle, ok_order, ok_basis = True, True, True
    found = {b.name for b in decision_bundle.bundles(out)}
    for d in plan:
        try:
            b = decision_bundle.load(out / "decisions" / d["decision_id"])
        except decision_bundle.DecisionBundleError:
            ok_bundle = False
            continue
        ctx = b["context"]
        ok_basis &= all(t in starts for t in ctx["basis_runs"])
        ok_order &= all(ctx["context_written_at"] < starts.get(t, "") for t in ctx["basis_runs"]) and \
            all(starts.get(t, "~") < b["decision"]["decided_at"] for t in ctx["basis_runs"])
    return {"every scheduled decision recorded with a complete bundle": ok_bundle and found == {d["decision_id"] for d in plan},
            "decision context written before its first basis run, decision after its last": ok_order,
            "every decision's basis runs retained": ok_basis}
