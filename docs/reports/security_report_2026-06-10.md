# Security Report — v1.0 LLM Guard Gateway — 2026-06-10

## Executive summary

**Verdict: PASS (no High/Critical findings).** SAST clean, no secret leaks. The gateway
is itself a security control; this report covers the security of *its own code*, plus how
it maps to the threats it is built to stop.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 (1 reviewed + suppressed: intentional container bind) |
| Low | 0 (7 reviewed + suppressed: detection-pattern false positives) |

## SAST — bandit

Run: `bandit -r src/guards/ src/pipeline.py src/audit.py src/gateway.py src/config.py src/textio.py src/owasp_gaps.py`
Result after review: **0 / 0 / 0** (low/medium/high).

Findings reviewed and suppressed (all false positives, annotated inline):
| File:line | Rule | Why it's a false positive |
|-----------|------|---------------------------|
| `config.py:51` | B104 bind-all-interfaces | Gateway binds `0.0.0.0` *inside its container*; host networking governs exposure. `# nosec B104`. |
| `secret_guard.py` (AWS_SECRET, SLACK_TOKEN, HEX_TOKEN, B64_TOKEN) | B105 hardcoded-password | These are **detection regexes**, not credentials. `# nosec B105`. |
| `secret_guard.py` (`_SEVERITY` floats) | B105 | Severity weights (0.8/0.7/0.4), not passwords. `# nosec B105`. |

## Secret leak — detect-secrets

Run: `detect-secrets scan src/`
Result after review: **NONE.** One flag on `secret_guard.py` (the literal
`-----BEGIN PRIVATE KEY-----` used as a detection pattern + masked display string) was a
false positive, annotated `# pragma: allowlist secret`.

Confirmed: no API key / token / password / private key committed. Config carries no
secrets; the gateway needs none (offline, no external API).

## Dependency scan — pip-audit ✅

Ran in Docker on a **freshly rebuilt image**: `test_security_audits::test_pip_audit_no_unfixed_runtime_vulns` **passes**.

History: the first run against a stale 6-week image flagged CVEs in dev/transitive deps
(jupyter-server, jupyterlab, notebook, mistune, aiohttp, idna, urllib3, starlette 1.0.0→1.0.1,
pip). Rebuilding pulled current versions and cleared all unaccepted findings. New runtime deps
this cycle (`httpx`, `pyyaml`) are clean. Carried-over accepted: pip build-tool CVE (no runtime impact).

Hardening note (v1.1): ship a **slim production image** that installs runtime deps only
(no jupyter/datasets dev stack) to shrink the gateway's dependency attack surface.

## OWASP Top 10 — gateway's own surface

| Risk | Status |
|------|--------|
| A01 Broken Access Control | Management endpoints under `/_guard`; no auth yet (gateway is meant to sit on a trusted network behind the edge). **Noted for v1.1: optional mgmt-endpoint auth.** |
| A03 Injection | No SQL string-building — audit uses parameterized queries (`executemany` with `?`). No `eval`/`exec`. |
| A06 Vulnerable Components | httpx/pyyaml current; `yaml.safe_load` only (no `yaml.load`). |
| A09 Logging Failures | Every flagged/blocked/redacted verdict audited to JSONL + SQLite; payload excerpts truncated + whitespace-collapsed to bound log size. |
| A10 SSRF | Gateway forwards only to the **configured** `upstream_url`; client-controlled paths cannot retarget the host. |

## Threat-model coverage (what it defends)

See `docs/owasp_coverage.md`. Runtime-enforced: LLM01, LLM02, LLM05, LLM07, LLM10.
Partial: LLM06, LLM09. **Declared non-defensible gaps: LLM03, LLM04, LLM08** — logged to the
`gaps` table and `/_guard/owasp` so coverage is never overstated.

## Hardening notes / follow-ups (non-blocking)
- v1.1: optional auth/allowlist on `/_guard/*`.
- v1.1: rate-limit state is in-process — for multi-replica, externalize (Redis) or use sticky routing.
- Before release: run `pip-audit` + full security suite under Docker.
