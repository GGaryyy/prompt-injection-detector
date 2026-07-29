# Security Report — 2026-07-28

Scope: OOD benchmark feature. Defensive scan of this project's own code and dependencies.

## Executive summary

**Pass.** No Critical or High findings. One Medium finding introduced by this change was
fixed; four dependency CVEs were found and resolved.

| Severity | Found | Resolved | Remaining |
|---|---|---|---|
| Critical | 0 | — | 0 |
| High | 0 | — | 0 |
| Medium | 7 (SAST) + 4 (CVE) | 5 SAST + 4 CVE | 2 SAST (1 accepted, 1 blocked on HF login) |
| Low | 4 | 1 | 3 (accepted) |

## Dependency scan — `pip-audit`

Four CVEs across two packages, both transitive:

| Package | Version | CVE | Fix version | Action |
|---|---|---|---|---|
| `starlette` | 1.2.1 | PYSEC-2026-248 | 1.3.0 | Upgraded to ≥1.3.1 |
| `starlette` | 1.2.1 | PYSEC-2026-249 | 1.3.1 | Upgraded to ≥1.3.1 |
| `setuptools` | 78.1.0 | PYSEC-2025-49 | 78.1.1 | Upgraded to ≥83.0.0 |
| `setuptools` | 78.1.0 | PYSEC-2026-3447 | 83.0.0 | Upgraded to ≥83.0.0 |

Re-scan after upgrade: **no known vulnerabilities**. Full suite re-run after the upgrade:
219 passed.

Two caveats on scope, because they change how much this result means:

- These versions were resolved in `.venv-dev` on 2026-07-28. `pyproject.toml` declares
  floors, not pins, so a container built on a different day resolves differently. This
  scan describes the dev environment, not a guarantee about the shipped image.
- `torch` could not be audited — the CPU wheel `2.13.0+cpu` comes from the PyTorch index
  and pip-audit could not resolve it on PyPI. It is unscanned, not clean.

## SAST — `bandit`

3,244 lines scanned across `src/` and `scripts/`. 0 High, 5 Medium, 3 Low after fixes.

### Introduced by this change and fixed

| ID | Location | Issue | Resolution |
|---|---|---|---|
| B615 | `src/data_loader.py` (deepset loader) | HuggingFace download without revision pinning | Pinned to `4f61ecb0…` |
| B615 | `src/data_loader.py` (alpaca loader) | Same | Pinned to `dce01c9b…` |
| B311 | `scripts/paraphrase_probe.py:141` | Non-cryptographic RNG | `# nosec B311` with justification — determinism is the requirement; the probe must select the same 200 prompts each run |

The B615 findings mattered more than their severity suggests. The benchmark report claims
its results are reproducible; with an unpinned dataset that claim is false, because the
held-out data can change under it. After pinning, both sources re-loaded to identical
counts (deepset 662/263 positive, alpaca 3,000/0 positive), confirming the reported
numbers still hold.

### Pre-existing, accepted

| ID | Location | Issue | Disposition |
|---|---|---|---|
| B615 ×3 | `src/data_loader.py` training loaders | No revision pinning on Lakera / JBB / Dolly | **Fixed 2026-07-29.** Initially deferred for fear of changing the training corpus. Instead verified: the pinned revisions were downloaded to a scratch cache and rebuilt `dataset_v1.jsonl` to an identical SHA-256 digest over (id, prompt, label, source) for all 6,732 samples, so the shipped model artifact remains valid. AdvBench is a raw CSV, not an HF dataset, so B615 never applied to it |
| B615 ×1 | `src/data_loader.py` wildjailbreak | No revision pinning | **Open.** Gated behind an HF login; the revision cannot be resolved without authenticating. Unused until then |
| B301, B403 | `src/classifier.py` | `pickle` deserialisation | Known and documented in `OVERVIEW.md` limitation 6; artifacts are self-produced. `joblib` migration still pending |
| B101 | `src/embedder.py:63` | `assert` for an internal invariant | Accepted |
| B105 | `src/schema.py:116` | "Possible hardcoded password: 'pass'" | False positive — it is the `GuardDecision.PASS` enum value |

## Secret leak detection — `detect-secrets`

Findings in 5 files. **No real secrets.**

| File | Finding | Assessment |
|---|---|---|
| `src/data_loader.py:35,36` | Hex High Entropy String ×2 | **False positive introduced by this change** — the two pinned dataset revision SHAs |
| `tests/unit/test_secret_guard.py` | Private Key, JWT, Base64, Secret Keyword | Deliberate fixtures; this is the guard that detects leaked secrets and needs specimens to detect |
| `tests/integration/test_gateway.py:31` | AWS Access Key | Same — gateway redaction test fixture |
| `scripts/seed_demo_attacks.py:22` | AWS Access Key | Demo payload, non-functional |
| `docs/reports/security_report_2026-06-10.md:32` | Private Key | Quoted finding in a prior report |

## OWASP review of the changed code

The new code is offline batch tooling with no network endpoint, no user input, and no
authentication surface, so most categories do not apply. What was checked:

| Category | Result |
|---|---|
| Insecure deserialization | `pickle` load of self-produced artifacts only; pre-existing, documented |
| Injection | No SQL, shell, or template construction in the new scripts |
| Sensitive data exposure | Outputs contain scores and metrics, no prompt text; `ood_scores.npz` stores numeric arrays only |
| Supply chain | The real finding of this scan — see B615 above |
| Logging failures | `load_holdout()` deliberately does not swallow failures the way `load_all()` does; `eval_ood.py` aborts rather than reporting metrics over partial data |

## Actions taken

1. Upgraded `starlette` ≥1.3.1 and `setuptools` ≥83.0.0; re-audited clean; re-ran suite.
2. Pinned both held-out dataset revisions; verified sample counts unchanged.
3. Annotated the RNG use with `# nosec B311` and a written justification.

## Open items

- Pin `allenai/wildjailbreak` once someone has authenticated to HF.
- `joblib` migration to remove `pickle` (pre-existing, `OVERVIEW.md` limitation 6).
- Add pinned versions or a lock file so dependency scans describe the shipped image rather
  than whatever the dev environment resolved that day.
- `torch` is outside pip-audit's reach; if it needs coverage, scan it separately.
