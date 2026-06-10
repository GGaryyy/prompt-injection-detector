# ISSUE_001 — Dev shell has no Docker or system pip

## Problem
During v1.0 development the active WSL2 shell cannot run the project's defined
Docker workflow: `docker` is not on PATH (Docker Desktop WSL integration is off
for this distro) and the host Python 3.12 has no `pip`, `venv` (ensurepip), and
is PEP-668 externally-managed. So `pip install`, `docker compose build`, and the
full test suite (which needs torch / sentence-transformers / sklearn) cannot run
here as-is.

## Cause
- Docker Desktop → Settings → Resources → WSL Integration not enabled for this distro.
- Minimal system Python without `python3-pip` / `python3-venv` packages, and PEP 668
  blocks `--user` installs into the system interpreter.

## Solution
Bootstrapped an isolated dev venv without touching the system interpreter:
1. `python3 -m venv --without-pip .venv-dev`
2. `.venv-dev/bin/python /tmp/get-pip.py` (pip lands inside the venv, not system)
3. `.venv-dev/bin/pip install pydantic pyyaml httpx fastapi pytest` (light deps only)

This is enough to import + unit-test all **pure-logic** guards and the gateway
glue. The ML-dependent path (LLM01 detector real inference) and e2e/stress tests
are deferred to Docker and run before the work is marked complete.

`.venv-dev/` is git-ignored.

## Prevention
- Document the Docker requirement in `docs/workflow/workflow.md`.
- Keep pure-logic guards free of heavy ML imports (lazy-import the detector) so the
  bulk of the suite stays runnable in the light venv — this is now an architectural
  rule, not just a workaround.
- Before marking v1.0 complete: enable Docker WSL integration and run the full
  suite (`docker compose build` + `pytest`) to validate the ML + e2e paths.
