"""Experiment cycles and stage gating (DR-13, DR-14).

A cycle is one pass through Stages 1-4 (+ bonus) stored in its own folder:
  records/cycles/<cycle-id>/cycle.json        state, mode, protocol lock, code commit
  records/cycles/<cycle-id>/stage-log.jsonl   hash-chained completion/failure records
  records/cycles/<cycle-id>/stage<N>/         stage outputs
A cycle may also be a *replay* of the published set: it then starts at Stage 2 and reads
the published Stage 1 evidence bed read-only.

Gating: a stage can start only if every earlier stage is complete. Completing a stage
requires every check to pass; a failed check marks the stage failed and stops the cycle
until it is re-run under a new attempt number. Failed attempts are retained.

Pause and resume (Stage 1): an interrupted Stage 1 (Ctrl-C, a closed terminal, a reboot) can be resumed
under the same attempt; finished work is kept and only the unfinished work runs again. Stages 2-4 are short and
offline: one left 'running' by a process that no longer exists is recorded as stopped (its folder kept) and runs
again under a new attempt number.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .chain import HashChainLog
from .paths import code_commit, cycles_dir, published_dir

STAGES = {
    1: "Acquire and freeze evidence",
    2: "ProofWeave within the threshold",
    3: "Scale and threshold again",
    4: "Three GREENs, not enough coverage",
}
MODES = ("pilot", "campaign", "replay")
_ID = re.compile(r"^(pilot|campaign|replay)-\d{4}$")


class CycleError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Cycle:
    path: Path
    data: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ persistence
    @property
    def id(self) -> str:
        return self.data["id"]

    def save(self) -> None:
        tmp = self.path / "cycle.json.tmp"
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n")
        tmp.replace(self.path / "cycle.json")

    @property
    def log(self) -> HashChainLog:
        return HashChainLog(self.path / "stage-log.jsonl")

    def stage_dir(self, n: int) -> Path:
        d = self.path / f"stage{n}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ------------------------------------------------------------------ gating
    def stage_state(self, n: int) -> str:
        return self.data["stages"][str(n)]["status"]

    def next_stage(self) -> int | None:
        for n in STAGES:
            if self.stage_state(n) != "complete":
                return n
        return None

    def can_start(self, n: int) -> tuple[bool, str]:
        if n not in STAGES:
            return False, f"unknown stage {n}"
        if self.data["status"] == "complete":
            return False, "cycle already complete"
        for m in range(1, n):
            if self.stage_state(m) != "complete":
                return False, f"Stage {m} is not complete"
        if self._stale(n):
            return True, ""
        if self.stage_state(n) in ("complete", "running", "paused"):
            return False, f"Stage {n} is {self.stage_state(n)}" + (" (resume it)" if self.stage_state(n) == "paused" else "")
        return True, ""

    def can_resume(self, n: int) -> tuple[bool, str]:
        """A paused stage, or one left 'running' by a process that no longer exists, can be resumed."""
        if n != 1:
            return False, "only Stage 1 can be resumed"
        state = self.stage_state(n)
        if state not in ("paused", "running"):
            return False, f"Stage {n} is {state}, not paused"
        if state == "running" and _running_elsewhere(self.id):
            return False, f"Stage {n} is still running in another process"
        return True, ""

    def resume(self, n: int) -> int:
        ok, why = self.can_resume(n)
        if not ok:
            raise CycleError(why)
        st = self.data["stages"][str(n)]
        was = st["status"]
        st.setdefault("resumed", []).append({"at": _now(), "from": was if was == "paused" else "stopped without pausing"})
        st["status"], self.data["status"] = "running", "in progress"
        self.log.append({"event": "stage_resumed", "stage": n, "attempt": st["attempt"], "from": was,
                         "code": code_commit(), "time": st["resumed"][-1]["at"]})
        self.save()
        return st["attempt"]

    def pause(self, n: int, reason: str) -> None:
        st = self.data["stages"][str(n)]
        if st["status"] != "running":
            raise CycleError(f"Stage {n} is not running")
        st["status"], self.data["status"] = "paused", "paused"
        st.setdefault("pauses", []).append({"at": _now(), "reason": reason})
        self.log.append({"event": "stage_paused", "stage": n, "attempt": st["attempt"], "reason": reason,
                         "time": st["pauses"][-1]["at"]})
        self.save()

    def _stale(self, n: int) -> bool:
        """Stages 2-4 left 'running' by a process that no longer exists (Stage 1 is resumed instead)."""
        return n != 1 and self.stage_state(n) == "running" and not _running_elsewhere(self.id)

    def start(self, n: int) -> int:
        ok, why = self.can_start(n)
        if not ok:
            raise CycleError(why)
        st = self.data["stages"][str(n)]
        if self._stale(n):
            self.log.append({"event": "stage_stopped", "stage": n, "stage_name": STAGES[n], "attempt": st["attempt"],
                             "reason": "left running by a process that no longer exists; rerun as a new attempt",
                             "code": self.data.get("code"), "time": _now()})
            st.setdefault("stopped_attempts", []).append(st["attempt"])
            st["attempt"] += 1
        elif st["status"] == "failed":
            st["attempt"] += 1
        st["status"], st["started_at"] = "running", _now()
        self.data["status"] = "in progress"
        self.save()
        return st["attempt"]

    def finish(self, n: int, checks: dict[str, bool], outputs_manifest_sha256: str,
               outcome: dict[str, Any], operator: str = "unknown") -> bool:
        """Record the end of a stage. Returns True if every check passed."""
        st = self.data["stages"][str(n)]
        if st["status"] != "running":
            raise CycleError(f"Stage {n} is not running")
        passed = bool(checks) and all(checks.values())
        st["status"] = "complete" if passed else "failed"
        st["finished_at"], st["checks"], st["outcome"] = _now(), checks, outcome
        st["outputs_manifest_sha256"] = outputs_manifest_sha256
        self.log.append({
            "event": "stage_complete" if passed else "stage_failed",
            "stage": n, "stage_name": STAGES[n], "attempt": st["attempt"],
            "checks": checks, "outputs_manifest_sha256": outputs_manifest_sha256,
            "protocol_lock_sha256": self.data.get("protocol_lock_sha256"),
            "code": self.data.get("code"), "operator": operator, "time": st["finished_at"],
        })
        if passed and self.next_stage() is None:
            self.data["status"], self.data["completed_at"] = "complete", _now()
        elif not passed:
            self.data["status"] = "failed"
        self.save()
        return passed


def _running_elsewhere(cycle_id: str) -> bool:
    """True if another process on this host is running a stage of this cycle (`pwexp run-stage ... --cycle ID`)."""
    proc = Path("/proc")
    if not proc.is_dir():
        return False
    for d in proc.iterdir():
        if not d.name.isdigit() or int(d.name) == os.getpid():
            continue
        try:
            argv = (d / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if b"run-stage" in argv and cycle_id.encode() in argv:
            return True
    return False


def _next_id(mode: str) -> str:
    base = cycles_dir()
    nums = [int(p.name.split("-")[1]) for p in base.glob(f"{mode}-*") if _ID.match(p.name)] if base.exists() else []
    return f"{mode}-{max(nums, default=0) + 1:04d}"


def create(mode: str, protocol_lock_sha256: str | None, models: list[dict[str, str]] | None = None,
           replay_of: str | None = None, meta: dict[str, Any] | None = None) -> Cycle:
    if mode not in MODES:
        raise CycleError(f"mode must be one of {MODES}")
    if mode == "campaign" and not protocol_lock_sha256:
        raise CycleError("a campaign cycle requires a valid protocol lock")
    if mode == "replay" and not replay_of:
        raise CycleError("a replay cycle must name the published cycle it replays")
    cid = _next_id(mode)
    path = cycles_dir() / cid
    path.mkdir(parents=True, exist_ok=False)
    stages = {str(n): {"name": name, "status": "pending", "attempt": 1} for n, name in STAGES.items()}
    if mode == "replay":
        stages["1"].update(status="complete", source=f"published:{replay_of}", attempt=0)
    data = {
        "id": cid, "mode": mode, "created_at": _now(), "status": "created",
        "protocol_lock_sha256": protocol_lock_sha256, "code": code_commit(),
        "models": models or [], "replay_of": replay_of, "stages": stages,
    }
    if meta:
        data.update(meta)
    c = Cycle(path, data)
    c.save()
    return c


def load(cycle_id: str) -> Cycle:
    for base in (cycles_dir(), published_dir()):
        p = base / cycle_id
        if (p / "cycle.json").exists():
            return Cycle(p, json.loads((p / "cycle.json").read_text()))
    raise CycleError(f"cycle {cycle_id} not found")


def list_cycles() -> list[Cycle]:
    out = []
    for base in (published_dir(), cycles_dir()):
        if base.exists():
            for p in sorted(base.iterdir()):
                if (p / "cycle.json").exists():
                    out.append(Cycle(p, json.loads((p / "cycle.json").read_text())))
    return out
