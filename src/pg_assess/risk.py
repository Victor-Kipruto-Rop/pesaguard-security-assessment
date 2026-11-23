"""Transparent deterministic risk scoring. Scores prioritize review; they are not probabilities."""
from collections import Counter
from typing import Iterable
from .models import Finding

SEVERITY = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}
CONFIDENCE = {"high": 1.0, "medium": 0.75, "low": 0.5}

def score_findings(findings: Iterable[Finding]) -> dict:
    items = list(findings)
    weighted = sum(SEVERITY.get(f.severity.lower(), 0) * CONFIDENCE.get(f.confidence.lower(), 0.5)
                   for f in items)
    counts = Counter(f.severity.lower() for f in items)
    score = min(100, round(weighted * 2))
    band = "critical" if score >= 70 else "high" if score >= 40 else "moderate" if score >= 15 else "low"
    return {"score": score, "band": band, "finding_count": len(items),
            "severity_counts": dict(counts),
            "method": "sum(severity_weight × confidence_factor) × 2, capped at 100; prioritization only, not a probability."}
