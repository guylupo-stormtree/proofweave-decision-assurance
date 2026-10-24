"""Plain command line (DR-18, DR-19). The terminal UI (P5) calls the same functions.

  pwexp                      open the terminal UI (P5)
  pwexp protocol check       list unset or invalid declarations
  pwexp protocol lock        write protocol/protocol.lock.json
  pwexp cycle new --mode M   create a cycle (pilot | campaign)
  pwexp cycle list           list published and local cycles
  pwexp cycle show ID        show one cycle's stages
  pwexp paper-tex --out DIR  write the paper's generated LaTeX (from the published cycle, else pending)
  pwexp setup                install RepoAudit's environment and the pinned Semgrep
  pwexp run-stage 1 --cycle ID --model openai:gpt-4.1   Stage 1 (keys typed at a masked prompt)
  pwexp verify               verify the published master set           (P4)
  pwexp replay --published   re-run Stages 2-4 on the published set     (P2-P3)

Every command accepts --protocol FILE (a protocol other than protocol/protocol.yaml; its relative paths
resolve against that file's directory) and --records-root DIR (keep cycles in DIR instead of records/).
"""
from __future__ import annotations

import argparse
import os
import sys

from . import cycles, protocol

OK, FAIL = "✓", "✗"


def _p(msg: str = "") -> None:
    print(msg, flush=True)


def cmd_protocol(a) -> int:
    if a.action == "check":
        try:
            errs = protocol.problems(protocol.load())
        except protocol.ProtocolError as e:
            _p(f"{FAIL} {e}")
            return 1
        if errs:
            _p(f"{FAIL} protocol has {len(errs)} open item(s):")
            for e in errs:
                _p(f"   - {e}")
            return 1
        ok, info = protocol.check_lock()
        _p(f"{OK} protocol complete · lock: {'valid ' + info[:12] if ok else info}")
        return 0
    try:
        doc = protocol.lock()
    except protocol.ProtocolError as e:
        _p(f"{FAIL} {e}")
        return 1
    _p(f"{OK} protocol locked · {doc['lock_sha256'][:16]} · protocol/protocol.lock.json")
    return 0


def cmd_cycle(a) -> int:
    if a.action == "new":
        lock = None
        ok, info = protocol.check_lock()
        if a.mode == "campaign":
            if not ok:
                _p(f"{FAIL} campaign cycle needs a valid protocol lock ({info})")
                return 1
            lock = info
        elif ok:
            lock = info
        try:
            c = cycles.create(a.mode, lock)
        except cycles.CycleError as e:
            _p(f"{FAIL} {e}")
            return 1
        _p(f"{OK} created {c.id} · mode {c.data['mode']} · lock {lock[:12] if lock else 'none'} · {c.path}")
        return 0
    if a.action == "list":
        cs = cycles.list_cycles()
        if not cs:
            _p("no cycles yet")
        for c in cs:
            done = sum(1 for n in cycles.STAGES if c.stage_state(n) == "complete")
            _p(f"{c.id:15} {c.data['mode']:9} {c.data['status']:12} stages {done}/4  {c.data['created_at']}")
        return 0
    c = cycles.load(a.id)
    _p(f"{c.id} · {c.data['mode']} · {c.data['status']} · lock {str(c.data.get('protocol_lock_sha256'))[:12]}")
    for n, name in cycles.STAGES.items():
        st = c.data["stages"][str(n)]
        mark = {"complete": OK, "failed": FAIL, "running": "▶"}.get(st["status"], " ")
        _p(f"  {mark} Stage {n}  {name:36} {st['status']:9} attempt {st['attempt']}")
    problems = c.log.verify()
    _p(f"  stage log: {'intact' if not problems else 'BROKEN: ' + '; '.join(problems)}")
    return 0


def cmd_paper_tex(a) -> int:
    from pathlib import Path
    from .report import paper_tex
    try:
        results = Path(a.results) if a.results else paper_tex.default_results()
        lock = Path(a.lock) if a.lock else paper_tex.default_lock()
        files = paper_tex.build(lock, results)
    except paper_tex.PaperTexError as e:
        _p(f"{FAIL} {e}")
        return 1
    out = Path(a.out)
    if a.check:
        st = paper_tex.stale(out, files)
        _p(f"{OK} up to date" if not st else f"{FAIL} stale: {', '.join(st)}")
        return 1 if st else 0
    paper_tex.write(out, files)
    _p(f"{OK} wrote {len(files)} files to {out} · results: {results or 'none (pending)'}")
    return 0


def cmd_import_iceccs(a) -> int:
    from pathlib import Path
    from .importers import iceccs
    try:
        c = iceccs.import_cycle(Path(a.dataset), a.runs)
    except (iceccs.ImportError_, OSError) as e:
        _p(f"{FAIL} {e}")
        return 1
    o = c.data["stages"]["1"]["outcome"]
    _p(f"{OK} imported {o['repoaudit_runs']} runs as {c.id} (pilot, fixture only) · GREEN {o['repoaudit_green']}"
       f" · Stage 2 unlocked")
    return 0


STAGE1_FIELDS = ("target.snapshot_path", "target.language", "target.bug_type", "acquisition.temperature",
                 "acquisition.call_depth", "acquisition.timeout_s", "semgrep.ruleset")


def _stage1_models(specs: list[str], base_url: str) -> "RunModels":
    import getpass
    from .models import RunModels
    models = RunModels()
    for spec in specs:
        provider, _, model = spec.partition(":")
        key = getpass.getpass(f"  API key for {provider}:{model} (kept in memory for this run only): ")
        models.add("repoaudit", provider, model, key, base_url=base_url if provider == "local" else "")
    return models


def _run_stage1(c, a, prog) -> bool:
    from .stages import stage1_acquire
    proto = protocol.load()
    missing = [k for k in STAGE1_FIELDS if protocol._unset(protocol._get(proto, k))]
    if not protocol.is_decision_protocol(proto):
        missing += [k for k in ("acquisition.repoaudit_runs_per_model", "acquisition.semgrep_runs")
                    if protocol._unset(protocol._get(proto, k))]
    else:
        missing += protocol._decision_problems(proto, protocol.base_dir())
    if missing:
        raise ValueError("protocol is not ready for Stage 1: " + "; ".join(missing))
    if not a.model:
        raise ValueError("Stage 1 needs at least one --model provider:model")
    cfg = stage1_acquire.Stage1Config.from_protocol(proto, protocol.base_dir(), seed=a.seed)
    models = _stage1_models(a.model, a.base_url)
    try:
        return stage1_acquire.run(c, cfg, models, operator=a.operator, progress=prog)
    finally:
        models.clear()


def cmd_setup(a) -> int:
    from . import setup_env
    try:
        version = str(protocol.load().get("semgrep", {}).get("version") or "1.181.0")
        setup_env.ensure_repoaudit(log=lambda m: _p(f"  {m}"))
        setup_env.ensure_semgrep("1.181.0" if protocol._unset(version) else version, log=lambda m: _p(f"  {m}"))
    except (setup_env.SetupError, protocol.ProtocolError, OSError) as e:
        _p(f"{FAIL} {e}")
        return 1
    st = setup_env.subject_state()
    _p(f"{OK if st['pinned'] and not st['tracked_files_modified'] else FAIL} RepoAudit {st['head'][:12]} · "
       f"pinned {st['pinned']} · unmodified {not st['tracked_files_modified']}")
    return 0


def cmd_run_stage(a) -> int:
    from pathlib import Path
    from .stages import stage2_timing, stage3_scale, stage4_decisions
    try:
        c = cycles.load(a.cycle)
        ok, why = c.can_start(a.stage)
        if not ok:
            _p(f"{FAIL} cannot start Stage {a.stage}: {why}")
            return 1
        prog = lambda m: _p(f"  {m}")  # noqa: E731
        _p(f"Stage {a.stage}  {cycles.STAGES[a.stage]} …")
        if a.stage == 1:
            passed = _run_stage1(c, a, prog)
        elif a.stage == 2:
            passed = stage2_timing.run(c, repetitions=a.repetitions, operator=a.operator, progress=prog)
        elif a.stage == 3:
            passed = stage3_scale.run(c, repetitions=a.repetitions, operator=a.operator, progress=prog)
        else:
            passed = stage4_decisions.run(c, required_path=Path(a.required) if a.required else None, tau=a.tau,
                                          operator=a.operator, progress=prog)
    except (cycles.CycleError, ValueError, protocol.ProtocolError) as e:
        _p(f"{FAIL} {e}")
        return 1
    st = c.data["stages"][str(a.stage)]
    for name, v in st["checks"].items():
        _p(f"  {OK if v else FAIL} {name}")
    o = st["outcome"]
    if a.stage == 1:
        _p(f"{OK if passed else FAIL} Stage 1 · RepoAudit GREEN {o['repoaudit_green']}/{o['repoaudit_runs']} · "
           f"Semgrep GREEN {o['semgrep_green']}/{o['semgrep_runs']} · sealed {o['sealed_manifest_sha256'][:12]}")
        if "decisions" in o:
            _p(f"  decisions recorded {o['decisions']['count']} · green {o['decisions']['green']} · "
               + " · ".join(f"{g} {v['green']}/{v['decisions']} green" for g, v in o["decisions"]["by_group"].items()))
    elif a.stage == 2:
        _p(f"{OK if passed else FAIL} Stage 2 · median {o['median_ms']} ms · max {o['max_ms']} ms · "
           f"{o['within_threshold']}/{o['observations']} within {o['threshold_s']} s · corpus E {o['corpus_sha256'][:12]}")
        if "decisions" in o:
            _p(f"  decision bindings: " + " · ".join(f"{d} {s}" for d, s in o["decisions"].items()))
    elif a.stage == 3:
        _p(f"{OK if passed else FAIL} Stage 3 · largest {o['largest_volume']} records · max ready "
           f"{o['max_ready_ms_at_largest']} ms · threshold crossing: {o['threshold_crossing']}")
    else:
        _p(f"  {'view':5} {'verdict-only':12} {'TAIP':13} {'gateway':8} oracle")
        for vid, r in o["views"].items():
            if r["attainable"]:
                _p(f"  {vid:5} {r['verdict_only']:12} {r['observed']:13} {r['action']:8} {'agrees' if r['agree'] else 'DISAGREES'}")
            else:
                _p(f"  {vid:5} unattained: {r['note']}")
        _p(f"{OK if passed else FAIL} Stage 4 · Three-GREEN case: {o['three_green_case']}")
        _p(f"  oracle agreement {o['oracle_agreement']} · unsupported PROCEED {o['unsupported_proceed']} · "
           f"replay {o['replay_agreement']}")
    return 0 if passed else 1


def cmd_import_dev(a) -> int:
    from pathlib import Path
    from .importers import devfixture
    from .paths import repo_root
    fix = repo_root() / "tests" / "fixtures" / "dev-guarded-users"
    runs = ["guarded-users/gpt-local-qwen3b/run02", "guarded-users/gpt-local-qwen3b/run04",
            "guarded-users/gpt-local-qwen3b/run06", "guarded-users-t05/gpt-local-qwen3b/run01",
            "guarded-users-t05/gpt-local-qwen3b/run05"]
    proto = None
    if os.environ.get("PWEXP_PROTOCOL"):
        proto = protocol.load()
        if not protocol.is_decision_protocol(proto):
            _p(f"{FAIL} import-dev --protocol expects a decision protocol (with decisions: and policies:)")
            return 1
    try:
        c = devfixture.import_cycle(fix, runs, semgrep=["semgrep/run001"], decisions=proto,
                                    base=protocol.base_dir() if proto else None)
    except devfixture.DevFixtureError as e:
        _p(f"{FAIL} {e}")
        return 1
    o = c.data["stages"]["1"]["outcome"]
    _p(f"{OK} imported dev fixture as {c.id} (pilot, fixture only) · RepoAudit GREEN {o['repoaudit_green']}/"
       f"{o['repoaudit_runs']} · Semgrep GREEN {o['semgrep_green']}/{o['semgrep_runs']} · Stage 2 unlocked")
    if proto:
        _p(f"  development decision bundles: {o['decisions']['count']} (contexts written after the runs; never a result)")
    _p(f"  Stage 4 required set: {fix / 'required-set.json'}")
    return 0


def cmd_required_draft(a) -> int:
    import json
    from pathlib import Path
    from .taip.requirements import draft
    d = draft(Path(a.target))
    Path(a.out).write_text(json.dumps(d, indent=2) + "\n")
    kinds = {k: sum(1 for i in d["items"] if i["kind"] == k) for k in "AVS"}
    _p(f"{OK} drafted {len(d['items'])} items (A {kinds['A']} · V {kinds['V']} · S {kinds['S']}) → {a.out}")
    _p("  This is a DRAFT from our own parse of the target. It must be reviewed by a person before the protocol lock.")
    return 0


def cmd_report(a) -> int:
    from .report import results
    try:
        out = results.write(cycles.load(a.cycle), item_id=a.item, runs=a.runs)
    except (cycles.CycleError, ValueError) as e:
        _p(f"{FAIL} {e}")
        return 1
    _p(f"{OK} report for {a.cycle} → {out}")
    _p(f"  RESULTS.md · EXHIBIT.html (open in a browser to present) · timing.csv · assurance.csv · paper/*.tex")
    return 0


def cmd_publish(a) -> int:
    from .report import publish
    try:
        dest = publish.publish(a.cycle, a.reason, a.operator, preview=a.preview)
    except (publish.PublishError, cycles.CycleError, protocol.ProtocolError) as e:
        _p(f"{FAIL} {e}")
        return 1
    _p(f"{OK} {'preview of publication' if a.preview else 'published'} {a.cycle} → {dest}")
    return 0


def cmd_pending(a) -> int:
    _p(f"'{a.cmd}' becomes available in a later build phase (see docs/BUILD.md).")
    return 2


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--protocol", default=argparse.SUPPRESS, help="protocol file (default protocol/protocol.yaml)")
    common.add_argument("--records-root", default=argparse.SUPPRESS, help="records directory (default records/)")
    ap = argparse.ArgumentParser(prog="pwexp", description="ProofWeave Decision Gateway experiment", parents=[common])
    sub = ap.add_subparsers(dest="cmd")
    _sub_add = sub.add_parser
    sub.add_parser = lambda *x, **k: _sub_add(*x, **{"parents": [common], **k})  # every command takes the options
    p = sub.add_parser("protocol", help="check or lock the protocol")
    p.add_argument("action", choices=["check", "lock"])
    p.set_defaults(fn=cmd_protocol)
    c = sub.add_parser("cycle", help="create, list or show experiment cycles")
    c.add_argument("action", choices=["new", "list", "show"])
    c.add_argument("id", nargs="?")
    c.add_argument("--mode", choices=["pilot", "campaign"], default="pilot")
    c.set_defaults(fn=cmd_cycle)
    t = sub.add_parser("paper-tex", help="write the paper's generated LaTeX")
    t.add_argument("--out", required=True)
    t.add_argument("--results")
    t.add_argument("--lock")
    t.add_argument("--check", action="store_true")
    t.set_defaults(fn=cmd_paper_tex)
    im = sub.add_parser("import-iceccs", help="import first-study RepoAudit runs as a fixture pilot cycle")
    im.add_argument("dataset", help="path to datasets/live-v1/python_npd")
    im.add_argument("--runs", nargs="+", required=True, help="e.g. gpt-4.1/run25 gpt-4o-mini/run01")
    im.set_defaults(fn=cmd_import_iceccs)
    sub.add_parser("setup", help="install RepoAudit's environment and the pinned Semgrep").set_defaults(fn=cmd_setup)
    rs = sub.add_parser("run-stage", help="run a stage on a cycle")
    rs.add_argument("stage", type=int, choices=[1, 2, 3, 4])
    rs.add_argument("--model", action="append", help="Stage 1: provider:model (repeatable); the key is prompted")
    rs.add_argument("--base-url", default="", help="Stage 1: endpoint for the dev-only local provider")
    rs.add_argument("--seed", type=int, help="Stage 1: run-order seed (default: protocol or random, recorded)")
    rs.add_argument("--required", help="required set JSON (pilot cycles; campaign cycles use the locked one)")
    rs.add_argument("--tau", type=float, help="divergence threshold (pilot cycles; campaign uses the lock)")
    rs.add_argument("--cycle", required=True)
    rs.add_argument("--repetitions", type=int)
    rs.add_argument("--operator", default="cli")
    rs.set_defaults(fn=cmd_run_stage)
    rd = sub.add_parser("required-set", help="draft the required set R from a target (for human review)")
    rd.add_argument("action", choices=["draft"])
    rd.add_argument("--target", required=True)
    rd.add_argument("--out", required=True)
    rd.set_defaults(fn=cmd_required_draft)
    rp = sub.add_parser("report", help="write a cycle's results page, tables, exhibit and paper LaTeX")
    rp.add_argument("--cycle", required=True)
    rp.add_argument("--item", help="exhibit: requirement to contrast (default: declared rule)")
    rp.add_argument("--runs", nargs="+", help="exhibit: runs to show as the case (default: view P5)")
    rp.set_defaults(fn=cmd_report)
    pb = sub.add_parser("publish", help="maintainer: publish a campaign cycle as the paper's result")
    pb.add_argument("--cycle", required=True)
    pb.add_argument("--reason", default="")
    pb.add_argument("--operator", default="maintainer")
    pb.add_argument("--preview", action="store_true", help="rehearse into records/tmp (any complete cycle)")
    pb.set_defaults(fn=cmd_publish)
    sub.add_parser("import-dev", help="import the development fixture (GREEN runs, guarded-users)").set_defaults(fn=cmd_import_dev)
    for name in ("verify", "replay", "ui"):
        s = sub.add_parser(name)
        s.add_argument("--published", action="store_true")
        s.set_defaults(fn=cmd_pending)
    a = ap.parse_args(argv)
    if getattr(a, "protocol", None):
        os.environ["PWEXP_PROTOCOL"] = os.path.abspath(a.protocol)
    if getattr(a, "records_root", None):
        os.environ["PWEXP_RECORDS_ROOT"] = os.path.abspath(a.records_root)
    if a.cmd is None:
        a.cmd = "ui"
        return cmd_pending(a)
    if a.cmd == "cycle" and a.action == "show" and not a.id:
        ap.error("cycle show needs an ID")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
