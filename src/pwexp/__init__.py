"""ProofWeave Decision Gateway experiment harness (pwexp).

Package layout:
  pwexp.hashing     content hashing and canonical JSON
  pwexp.chain       append-only, hash-chained JSON Lines logs
  pwexp.paths       repository and records locations
  pwexp.protocol    protocol.yaml validation and protocol.lock
  pwexp.cycles      experiment cycles and stage gating
  pwexp.models      per-run model/key entries (keys in memory only)
  pwexp.stages      Stages 1-4
  pwexp.proofweave  the evidence plane under test (Stages 2-3)
  pwexp.taip        deterministic assurance and gateway (Stage 4)
  pwexp.report      results page, tables and generated LaTeX
The independent oracle lives in the separate top-level package `oracle` and must not import pwexp.
"""
__version__ = "0.1.0"
