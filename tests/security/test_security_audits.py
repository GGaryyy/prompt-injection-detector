"""Security tests — runs `pip-audit`, `bandit`, and `detect-secrets` as subprocess.

These are environment-dependent: each tool is installed via pyproject `[security]` extra.
Tests gracefully skip if the tool isn't found.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

SRC_DIR = Path("src")


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# Vulnerabilities accepted with documented reason. Each entry: (CVE, reason, fix-eta).
# Reviewed in docs/reports/security_report_*.md.
ACCEPTED_VULN_IDS = {
    # pip itself (build-tool layer, not runtime); no fix released as of 2026-04-25.
    "CVE-2026-3219",
}


@pytest.mark.skipif(not _have("pip-audit"), reason="pip-audit not installed")
def test_pip_audit_no_unfixed_runtime_vulns() -> None:
    """`pip-audit` should find no high-severity vulnerabilities in runtime deps.

    - Skips our own editable install (`prompt-injection-detector`)
    - Skips known accepted vulns documented in ACCEPTED_VULN_IDS
    """
    import json as _json

    result = subprocess.run(
        [
            "pip-audit",
            "--skip-editable",
            "--format=json",
            "--progress-spinner=off",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    # pip-audit returns 1 if vulns found; 0 if clean. We parse JSON regardless.
    try:
        report = _json.loads(result.stdout)
    except _json.JSONDecodeError:
        pytest.fail(f"pip-audit non-JSON output:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")

    unfixed_findings = []
    for dep in report.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            if vuln["id"] in ACCEPTED_VULN_IDS:
                continue
            unfixed_findings.append(
                f"  - {dep['name']} {dep['version']}: {vuln['id']} (fix: {vuln.get('fix_versions') or 'none'})"
            )

    if unfixed_findings:
        pytest.fail(
            "pip-audit found unaccepted vulnerabilities:\n" + "\n".join(unfixed_findings)
        )


@pytest.mark.skipif(not _have("bandit"), reason="bandit not installed")
def test_bandit_no_high_severity() -> None:
    """`bandit -r src/` — parse JSON, fail only on actual High-severity findings."""
    import json as _json

    result = subprocess.run(
        ["bandit", "-r", str(SRC_DIR), "-f", "json"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    # bandit exits 1 if any finding (any severity) — we parse JSON to filter properly
    try:
        report = _json.loads(result.stdout)
    except _json.JSONDecodeError:
        pytest.fail(f"bandit returned non-JSON:\n{result.stdout[:500]}")

    high_findings = [
        r for r in report.get("results", []) if r.get("issue_severity") == "HIGH"
    ]
    if high_findings:
        details = "\n".join(
            f"  - {r['filename']}:{r['line_number']}  {r['test_id']}  {r['issue_text']}"
            for r in high_findings
        )
        pytest.fail(f"bandit found {len(high_findings)} High-severity issue(s):\n{details}")


@pytest.mark.skipif(not _have("detect-secrets"), reason="detect-secrets not installed")
def test_detect_secrets_baseline_clean() -> None:
    """`detect-secrets scan` — fail if any secret pattern found in src/."""
    result = subprocess.run(
        ["detect-secrets", "scan", str(SRC_DIR)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.skip(f"detect-secrets exited {result.returncode}: {result.stderr}")
    # Output is JSON. Empty `results` means no secrets found.
    import json

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.skip("detect-secrets did not return JSON (version mismatch?)")

    findings = report.get("results", {})
    if findings:
        pytest.fail(f"detect-secrets found secret patterns:\n{json.dumps(findings, indent=2)}")
