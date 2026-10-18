"""Independent oracle for Stage 4 (paper §5.1: "an oracle independent of the ProofWeave evaluator").

It must not import `pwexp` (enforced by a Stage 4 check). It derives the expected posture and gateway action
for each evidence view directly from the native Stage 1 files (RepoAudit dfbscan.log / detect_info.json,
Semgrep semgrep.json), the required set and the target source, using its own parsing, its own `ast`
resolution and its own coverage rules. It never reads the ledger, the graph or the evaluator's answers.
"""
from .core import expected  # noqa: F401
