"""Run offline assessment checks over sanitized snapshots and synthetic test observations."""
from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any
from .domain_checks import (database_checks, daraja_checks, identity_checks, infrastructure_checks,
    ledger_checks, outbound_webhook_checks, pipeline_checks, tenancy_checks, transaction_checks)
from .models import AssessmentReport, Environment
from .risk import score_findings

DOMAINS = ("identity", "tenancy_cases", "transaction_cases", "ledger_entries", "daraja",
           "database", "pipeline", "infrastructure_files", "outbound_webhook")

def run_bundle(bundle: dict[str, Any]) -> tuple[AssessmentReport, dict[str, Any]]:
    started = datetime.now(timezone.utc)
    findings = []
    checks = []
    dispatch = {
        "identity": lambda: identity_checks(bundle.get("identity", {})),
        "tenancy": lambda: tenancy_checks(bundle.get("tenancy_cases", [])),
        "transactions": lambda: transaction_checks(bundle.get("transaction_cases", [])),
        "ledger": lambda: ledger_checks(bundle.get("ledger_entries", [])),
        "daraja": lambda: daraja_checks(bundle.get("daraja", {}), bundle.get("daraja_callbacks", [])),
        "database": lambda: database_checks(bundle.get("database", {})),
        "data_pipeline": lambda: pipeline_checks(bundle.get("pipeline", {}), bundle.get("pipeline_source_files", [])),
        "infrastructure": lambda: infrastructure_checks(bundle.get("infrastructure_files", [])),
        "webhook": lambda: outbound_webhook_checks(bundle.get("outbound_webhook", {})),
    }
    for name, runner in dispatch.items():
        if name in bundle or name == "tenancy" and "tenancy_cases" in bundle or name == "transactions" and "transaction_cases" in bundle or name == "ledger" and "ledger_entries" in bundle or name == "data_pipeline" and ("pipeline" in bundle or "pipeline_source_files" in bundle) or name == "infrastructure" and "infrastructure_files" in bundle or name == "webhook" and "outbound_webhook" in bundle:
            findings.extend(runner())
            checks.append(name)
    risk = score_findings(findings)
    report = AssessmentReport(assessment_id=str(uuid4()), target_id=str(bundle.get("assessment_target_id", "offline-bundle")),
        target_url="offline://sanitized-assessment-bundle", environment=Environment.LOCAL,
        started_at=started, completed_at=datetime.now(timezone.utc), status="completed",
        findings=findings, checks_run=checks,
        notes=["Offline configuration and synthetic-fixture assessment; no live systems contacted.",
               "Only supplied domains were assessed. Missing domains are not verified.",
               "Risk score is a prioritization aid, not a probability or compliance rating."])
    return report, risk
