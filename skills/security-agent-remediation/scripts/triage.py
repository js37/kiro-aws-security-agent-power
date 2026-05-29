#!/usr/bin/env python3
"""Rank exported AWS Security Agent findings by risk for triage.

This reads the ``findings_*.json`` files written by ``fetch_findings.py`` and prints a
severity-ordered list, so prioritization is deterministic rather than re-derived by hand
each time. Sorting is by riskLevel, then riskScore (highest first), then confidence.

Stdlib only — no boto3 or third-party deps — so it runs with plain ``python3`` without the
uv environment:

    python3 scripts/triage.py                       # table for ./.securityagent
    python3 scripts/triage.py --input-dir .securityagent --top 10
    python3 scripts/triage.py --json                # machine-readable, for building a summary

Note: titles and short metadata are safe to print, but the full description/reasoning/
attackScript stay in the JSON files — keep that sensitive detail out of shared output.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

# Lower number = more urgent. Unknown levels sort last.
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5}
CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNCONFIRMED": 3, "FALSE_POSITIVE": 4}


def _coerce_score(value) -> float | None:
    """riskScore may be a float, a numeric string ('10.0'), or None. Return a float or None."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _location(finding: dict) -> str:
    """Best-effort code location for a finding (code reviews carry these; pentests often don't)."""
    if finding.get("filePath"):
        return str(finding["filePath"])
    locations = finding.get("codeLocations") or []
    if locations:
        loc = locations[0]
        path = loc.get("filePath", "")
        # Strip the scanner's sandbox prefix so the repo-relative path is readable.
        marker = "/agentcore-public-stack-main/"
        if marker in path:
            path = path.split(marker, 1)[1]
        else:
            path = os.path.basename(path)
        start = loc.get("lineStart")
        return f"{path}:{start}" if start else path
    return ""


def load_findings(input_dir: Path) -> list[dict]:
    rows: list[dict] = []
    paths = sorted(glob.glob(str(input_dir / "findings_*.json")))
    if not paths:
        sys.exit(
            f"No findings_*.json files found in {input_dir}. "
            "Run fetch_findings.py first, or pass --input-dir."
        )
    for path in paths:
        with open(path) as fh:
            data = json.load(fh)
        # fetch_findings.py writes a JSON array; tolerate {"findings": [...]} too.
        findings = data if isinstance(data, list) else data.get("findings", [])
        for f in findings:
            rows.append(
                {
                    "findingId": f.get("findingId", ""),
                    "name": f.get("name", ""),
                    "source": f.get("source", ""),
                    "riskType": f.get("riskType", ""),
                    "riskLevel": (f.get("riskLevel") or "UNKNOWN").upper(),
                    "riskScore": _coerce_score(f.get("riskScore")),
                    "confidence": (f.get("confidence") or "").upper(),
                    "location": _location(f),
                }
            )
    return rows


def sort_findings(rows: list[dict]) -> list[dict]:
    return sorted(
        rows,
        key=lambda r: (
            RISK_ORDER.get(r["riskLevel"], 9),
            -(r["riskScore"] if r["riskScore"] is not None else -1.0),
            CONFIDENCE_ORDER.get(r["confidence"], 9),
        ),
    )


def severity_counts(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
        n = sum(1 for r in rows if r["riskLevel"] == level)
        if n:
            counts[level] = n
    return counts


def print_table(rows: list[dict], counts: dict[str, int]) -> None:
    summary = " · ".join(f"{n} {lvl}" for lvl, n in counts.items())
    print(f"TOTAL: {len(rows)}  ({summary})\n")
    for i, r in enumerate(rows, 1):
        score = f"{r['riskScore']:.1f}" if r["riskScore"] is not None else "-"
        line = (
            f"{i:2}. [{r['riskLevel']:<13} score={score:>4} {r['confidence']:<6} "
            f"{r['source']:<11}] {r['name']}"
        )
        print(line)
        if r["location"]:
            print(f"      @ {r['location']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rank exported Security Agent findings by risk for triage.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input-dir", default=".securityagent", help="Directory holding findings_*.json.")
    parser.add_argument("--top", type=int, default=0, help="Show only the top N findings (0 = all).")
    parser.add_argument("--json", action="store_true", help="Emit ranked findings as JSON instead of a table.")
    args = parser.parse_args(argv)

    rows = sort_findings(load_findings(Path(args.input_dir)))
    counts = severity_counts(rows)
    if args.top > 0:
        rows = rows[: args.top]

    if args.json:
        print(json.dumps({"total": len(rows), "severityCounts": counts, "findings": rows}, indent=2))
    else:
        print_table(rows, counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
