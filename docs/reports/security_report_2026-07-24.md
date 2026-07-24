# Security Report — 2026-07-24

**Scope**: SAST (bandit) on `src/` after the fail-closed / circuit-breaker fix. This is a defensive scan of the project's own code. Dependency and secret scans were not re-run in the offline `.venv-dev` (see note).

## Executive summary

**PASS** — no Critical or High findings introduced or outstanding from the changed code.

| Severity | Count | New this change |
|---|---|---|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 5 | 0 |
| Low | 3 | 0 |

All 8 residual bandit findings are pre-existing and already annotated with `# nosec` where intentional (9 issues explicitly disabled). The change in this task added no new SAST-relevant constructs.

## SAST (bandit -r src/)

- **High: 0.** The change touched control-flow in `src/pipeline.py`, a config field removal in `src/config.py`/`config.yaml`, and a read-only accessor + `getattr` fallback in `src/gateway.py::health`. No `eval`/`exec`, subprocess, deserialization, path handling, or credential material was added.
- **Medium/Low (pre-existing):** detection-pattern regexes and the intentional container bind (`0.0.0.0`, `# nosec B104`), plus the known `pickle.load` of the self-produced classifier artifact (trusted-source only; joblib migration tracked in OVERVIEW limitations). Unchanged by this task.

## OWASP-relevant review of the change

- **Broken access control / fail-open:** the change *strengthens* posture — it closes a path where a tripped fail-closed guard silently let traffic through. This was the motivating defect; regression tests now lock the correct behavior.
- **Security logging failures:** `/_guard/health` now surfaces `tripped_guards`, improving observability of a degraded guard (previously silent).
- **Injection / SSRF / deserialization:** not applicable — no new external input handling, network calls, or deserialization introduced.

## Dependency scan (pip-audit) & Secret leak (detect-secrets)

**Not re-run this task.** No dependency versions changed (`pyproject.toml` edit was the project version string `0.0.1`→`1.0.0` only, no dep add/bump) and no secrets/config values were introduced. Last full run: `docs/reports/security_report_2026-06-10.md` (pip-audit pass, detect-secrets clean). Re-run on the next Docker validation cycle.

## Remediation actions
None required — no new findings. Behavioral fix itself is a security improvement.
