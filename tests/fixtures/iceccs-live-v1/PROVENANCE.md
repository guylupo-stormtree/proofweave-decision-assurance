# Fixture provenance

Five RepoAudit runs copied unchanged from the first study's public dataset:

- Repository: https://github.com/guylupo-stormtree/taip-repoaudit-posture (Apache-2.0)
- Commit: 3b3968f78f3f739500364aea4585fb6b050e51ee
- Path: `datasets/live-v1/python_npd/{gpt-4.1/run01, run15, run25, run28; gpt-4o-mini/run01}`
- Subject: unmodified RepoAudit 160f5bc (dfbscan, Python NPD) on RepoAudit's own toy benchmark, OpenAI gpt-4.1 / gpt-4o-mini, temperature 0.

**Purpose:** development and test fixtures for the ProofWeave adapter, ledger and graph. These runs are not results of this study. They were collected under a different protocol, and every run reports planted bugs, so none is GREEN at project level.

Files are byte-identical to the source (each run's `checksums.json` verifies them). The native logs contain absolute file paths from the machine that produced them, exactly as already published in the source repository. Privacy treatment of such paths happens in ProofWeave's Bind step, never by editing native evidence.
