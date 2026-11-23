"""Import bounded JUnit XML results from PesaGuard-owned regression tests."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import xml.etree.ElementTree as ET

from .models import AssessmentReport, Environment, Finding
from .risk import score_findings

def _domain(name: str, classname: str) -> str:
    value = f"{classname} {name}".lower()
    if any(term in value for term in ("tenant", "rbac", "authorization", "scope", "export")):
        return "tenancy"
    if any(term in value for term in ("daraja", "mpesa", "callback", "webhook")):
        return "daraja"
    if any(term in value for term in ("ledger", "journal", "balance", "double_entry")):
        return "ledger"
    if any(term in value for term in ("idempotency", "concurrency", "transaction", "replay")):
        return "transactions"
    if any(term in value for term in ("auth", "session", "token", "password", "otp", "login", "mfa")):
        return "identity"
    if any(term in value for term in ("pipeline", "lineage", "data_protection", "ingestion")):
        return "data_pipeline"
    return "general"

def import_junit(path: str | Path) -> tuple[AssessmentReport, dict]:
    file_path = Path(path)
    if not file_path.is_file() or file_path.stat().st_size > 5_000_000:
        raise ValueError("JUnit report must be an existing XML file no larger than 5 MB.")
    raw = file_path.read_bytes()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("DTD and entity declarations are not accepted in JUnit XML.")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("JUnit report is not valid XML.") from exc
    cases = list(root.iter("testcase"))
    if not cases:
        raise ValueError("JUnit report contains no testcase elements.")
    findings: list[Finding] = []
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    domains: set[str] = set()
    for case in cases:
        name = str(case.attrib.get("name", "unnamed"))[:200]
        classname = str(case.attrib.get("classname", ""))[:200]
        domain = _domain(name, classname)
        domains.add(domain)
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        if failure is not None:
            counts["failed"] += 1
            severity = "critical" if domain in {"tenancy", "transactions", "ledger", "daraja"} else "high"
            findings.append(Finding(check=domain, title="PesaGuard regression test failed",
                severity=severity, confidence="high",
                description="A PesaGuard-owned security regression test reported a failure.",
                evidence={"test": f"{classname}.{name}"[:360], "result": "failure"},
                recommendation="Inspect the original test runner output, fix the underlying control, and rerun the isolated regression test. Failure text is intentionally not copied into the assessment.",
                verified=True))
        elif error is not None:
            counts["errors"] += 1
            findings.append(Finding(check=domain, title="PesaGuard regression test errored",
                severity="high", confidence="high",
                description="A security regression test errored before producing a reliable assertion result.",
                evidence={"test": f"{classname}.{name}"[:360], "result": "error"},
                recommendation="Resolve the test environment or setup error and rerun the regression test.",
                verified=True))
        elif skipped is not None:
            counts["skipped"] += 1
            findings.append(Finding(check=domain, title="PesaGuard security regression test was skipped",
                severity="medium", confidence="high",
                description="A relevant regression test did not execute.",
                evidence={"test": f"{classname}.{name}"[:360], "result": "skipped"},
                recommendation="Confirm whether the test requires a disposable PostgreSQL fixture or explicit opt-in configuration, then execute it in the correct test environment.",
                verified=False))
        else:
            counts["passed"] += 1
    now = datetime.now(timezone.utc)
    report = AssessmentReport(assessment_id=str(uuid4()), target_id="pesaguard-junit-import",
        target_url="file://junit-import", environment=Environment.LOCAL,
        started_at=now, completed_at=now, status="completed", findings=findings,
        checks_run=sorted(domains),
        notes=[f"Imported {len(cases)} JUnit test cases: {counts}.",
               "JUnit results are imported evidence, not cryptographic proof of the test runner or source checkout.",
               "Failure output and captured stdout/stderr are intentionally not copied to avoid leaking secrets or customer data."])
    risk = score_findings(findings)
    risk["test_counts"] = counts
    return report, risk
