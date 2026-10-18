"""Publish one campaign cycle as the paper's result (DR-16, DR-17). Maintainer action.

Refuses unless: the cycle is a complete **campaign** cycle; it ran under the current, valid protocol lock;
the selection rule declared in protocol.yaml (before any campaign cycle ran) selects it; and no cycle is
published yet (a second publication would be a new protocol revision). On success: the cycle is copied
to records/published/<id>/, its report and the paper's LaTeX are written there, and a hash-chained record
in records/publications.jsonl lists the chosen cycle, the rule, the reason and **every** campaign cycle.
`preview=True` rehearses the publication for any complete cycle into records/tmp/publish-preview/<id>
(pilot output stays watermarked PILOT DATA) and writes no publication record.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .. import cycles, protocol
from ..chain import HashChainLog
from ..paths import cycles_dir, published_dir, records_dir
from . import results

RULES = {"first-complete-campaign-cycle"}


class PublishError(Exception):
    pass


def _campaign_cycles() -> list[cycles.Cycle]:
    return sorted((c for c in cycles.list_cycles() if c.data["mode"] == "campaign"), key=lambda c: c.data["created_at"])


def publish(cycle_id: str, reason: str, operator: str, preview: bool = False) -> Path:
    c = cycles.load(cycle_id)
    if c.data["status"] != "complete":
        raise PublishError(f"{cycle_id} has not completed all four stages")
    if preview:
        dest = records_dir() / "tmp" / "publish-preview" / cycle_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(c.path, dest)
        pc = cycles.Cycle(dest, json.loads((dest / "cycle.json").read_text()))
        results.write(pc, dest / "report")
        shutil.copy2(dest / "report" / "results.json", dest / "results.json")
        return dest
    if c.data["mode"] != "campaign":
        raise PublishError("only a campaign cycle can be published (pilot cycles never are)")
    ok, lock = protocol.check_lock()
    if not ok or c.data.get("protocol_lock_sha256") != lock:
        raise PublishError(f"cycle was not run under the current valid protocol lock ({lock if not ok else 'lock differs'})")
    rule = protocol.load().get("selection_rule")
    if rule not in RULES:
        raise PublishError(f"unknown or missing selection_rule {rule!r}")
    campaign = _campaign_cycles()
    chosen = next((x for x in campaign if x.data["status"] == "complete"), None)
    if chosen is None or chosen.id != cycle_id:
        raise PublishError(f"selection rule {rule!r} selects {chosen.id if chosen else 'no cycle'}, not {cycle_id}")
    if published_dir().exists() and any(p.is_dir() for p in published_dir().iterdir()):
        raise PublishError("a cycle is already published; publishing another requires a new protocol revision")
    dest = published_dir() / cycle_id
    shutil.copytree(c.path, dest)
    pc = cycles.Cycle(dest, json.loads((dest / "cycle.json").read_text()))
    report = results.write(pc, dest / "report")
    shutil.copy2(report / "results.json", dest / "results.json")
    shutil.copytree(report / "paper", dest / "paper")
    HashChainLog(records_dir() / "publications.jsonl").append({
        "event": "publish", "cycle": cycle_id, "selection_rule": rule, "reason": reason, "operator": operator,
        "protocol_lock_sha256": lock, "corpus_sha256": c.data["stages"]["2"]["outcome"]["corpus_sha256"],
        "campaign_cycles": [{"id": x.id, "status": x.data["status"], "created_at": x.data["created_at"],
                             "three_green_case": x.data["stages"]["4"].get("outcome", {}).get("three_green_case")}
                            for x in campaign],
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    shutil.rmtree(cycles_dir() / cycle_id)  # the published copy is now the record
    return dest
