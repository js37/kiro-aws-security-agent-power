#!/usr/bin/env python3
"""Fetch AWS Security Agent findings (pentest and/or code review) to a local,
gitignored directory.

The findings produced by AWS Security Agent contain working attack scripts,
reproduction steps, and sometimes leaked secrets. They must never be committed to
source control, so this script writes only into the output directory (default
``.securityagent``) and drops a ``.gitignore`` there as a safety net.

Workflow (mirrors the Security Agent data model):

    Agent Space -> Pentest / Code Review -> Job -> Findings

For each requested source the script resolves the agent space, the scan, and the
latest COMPLETED job (unless pinned via flags), lists finding summaries, filters by
confidence, fetches full detail in batches, and writes a JSON + CSV per job plus a
manifest describing the run.

Requires: boto3, AWS credentials with access to AWS Security Agent.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("fetch_findings")

# Confidence values the service may report, ordered weakest -> strongest.
CONFIDENCE_CHOICES = ["FALSE_POSITIVE", "UNCONFIRMED", "LOW", "MEDIUM", "HIGH"]

# Max finding ids accepted per batch_get_findings call.
BATCH_SIZE = 25

# Columns flattened into the per-job CSV. Pentest and code-review findings share the
# core schema; extra keys present on only one source are merged in dynamically.
CSV_COLUMNS = [
    "findingId",
    "agentSpaceId",
    "source",
    "pentestId",
    "pentestJobId",
    "codeReviewId",
    "codeReviewJobId",
    "taskId",
    "name",
    "status",
    "riskType",
    "riskLevel",
    "riskScore",
    "confidence",
    "filePath",
    "description",
    "reasoning",
    "remediation",
    "suggestedFix",
    "attackScript",
    "createdAt",
    "updatedAt",
]


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def _paginate(client, op_name: str, result_key: str, **kwargs) -> list[dict]:
    """Collect every item across all pages of a list operation.

    Falls back to a manual NextToken loop when the operation has no registered
    paginator, so the script keeps working as the API surface evolves.
    """
    items: list[dict] = []
    if client.can_paginate(op_name):
        paginator = client.get_paginator(op_name)
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(result_key, []))
        return items

    method = getattr(client, op_name)
    next_token = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["nextToken"] = next_token
        resp = method(**call_kwargs)
        items.extend(resp.get(result_key, []))
        next_token = resp.get("nextToken")
        if not next_token:
            return items


def _latest(items: list[dict], key: str) -> dict | None:
    return max(items, key=lambda i: i.get(key, ""), default=None) if items else None


def resolve_agent_space(client, agent_space_id: str | None) -> dict:
    spaces = _paginate(client, "list_agent_spaces", "agentSpaceSummaries")
    if not spaces:
        sys.exit("No Agent Spaces found in this account/Region.")
    if agent_space_id:
        match = next((s for s in spaces if s["agentSpaceId"] == agent_space_id), None)
        if not match:
            sys.exit(f"Agent Space {agent_space_id} not found.")
        return match
    space = _latest(spaces, "updatedAt")
    logger.info("Using latest Agent Space: %s (%s)", space.get("name"), space["agentSpaceId"])
    return space


def _latest_completed_job(client, op_name, result_key, id_field, scan_id_kwarg, scan_id, asid):
    jobs = _paginate(client, op_name, result_key, agentSpaceId=asid, **{scan_id_kwarg: scan_id})
    completed = [j for j in jobs if j.get("status") == "COMPLETED"]
    if not completed:
        return None
    return _latest(completed, "createdAt")


def _filter_by_confidence(summaries: list[dict], confidence: list[str]) -> list[dict]:
    keep = set(confidence)
    return [s for s in summaries if s.get("confidence") in keep]


def _batch_get(client, finding_ids: list[str], agent_space_id: str) -> list[dict]:
    findings: list[dict] = []
    for i in range(0, len(finding_ids), BATCH_SIZE):
        batch = finding_ids[i : i + BATCH_SIZE]
        resp = client.batch_get_findings(findingIds=batch, agentSpaceId=agent_space_id)
        findings.extend(resp.get("findings", []))
    return findings


def collect_pentest(client, args, asid: str) -> list[dict]:
    pentests = _paginate(client, "list_pentests", "pentestSummaries", agentSpaceId=asid)
    if not pentests:
        logger.info("No penetration tests found in this Agent Space.")
        return []

    if args.pentest_id:
        pentest = next((p for p in pentests if p["pentestId"] == args.pentest_id), None)
        if not pentest:
            sys.exit(f"Penetration test {args.pentest_id} not found.")
    else:
        pentest = _latest(pentests, "updatedAt")
    logger.info("Pentest: %s (%s)", pentest.get("title"), pentest["pentestId"])

    if args.pentest_job_id:
        job_id = args.pentest_job_id
    else:
        job = _latest_completed_job(
            client,
            "list_pentest_jobs_for_pentest",
            "pentestJobSummaries",
            "pentestJobId",
            "pentestId",
            pentest["pentestId"],
            asid,
        )
        if not job:
            logger.info("No COMPLETED pentest jobs found.")
            return []
        job_id = job["pentestJobId"]
    logger.info("Pentest job: %s", job_id)

    summaries = _paginate(client, "list_findings", "findingsSummaries", agentSpaceId=asid, pentestJobId=job_id)
    summaries = _filter_by_confidence(summaries, args.confidence)
    if not summaries:
        logger.info("No pentest findings matched the confidence filter.")
        return []

    findings = _batch_get(client, [s["findingId"] for s in summaries], asid)
    for f in findings:
        f["source"] = "pentest"
    return findings


def collect_code_review(client, args, asid: str) -> list[dict]:
    reviews = _paginate(client, "list_code_reviews", "codeReviewSummaries", agentSpaceId=asid)
    if not reviews:
        logger.info("No code reviews found in this Agent Space.")
        return []

    if args.code_review_id:
        review = next((r for r in reviews if r["codeReviewId"] == args.code_review_id), None)
        if not review:
            sys.exit(f"Code review {args.code_review_id} not found.")
    else:
        review = _latest(reviews, "updatedAt")
    logger.info("Code review: %s (%s)", review.get("title"), review["codeReviewId"])

    if args.code_review_job_id:
        job_id = args.code_review_job_id
    else:
        job = _latest_completed_job(
            client,
            "list_code_review_jobs_for_code_review",
            "codeReviewJobSummaries",
            "codeReviewJobId",
            "codeReviewId",
            review["codeReviewId"],
            asid,
        )
        if not job:
            logger.info("No COMPLETED code review jobs found.")
            return []
        job_id = job["codeReviewJobId"]
    logger.info("Code review job: %s", job_id)

    summaries = _paginate(client, "list_findings", "findingsSummaries", agentSpaceId=asid, codeReviewJobId=job_id)
    summaries = _filter_by_confidence(summaries, args.confidence)
    if not summaries:
        logger.info("No code review findings matched the confidence filter.")
        return []

    findings = _batch_get(client, [s["findingId"] for s in summaries], asid)
    for f in findings:
        f["source"] = "code-review"
    return findings


def ensure_gitignored(output_dir: Path) -> None:
    """Make sure the findings directory can't be committed.

    Adds the directory to the nearest repo .gitignore (searching upward) and also
    drops a self-contained .gitignore inside the directory as a belt-and-suspenders
    guard in case the script runs outside a git repo or the root ignore is missed.
    """
    dir_name = output_dir.name

    # 1) Inner guard: ignore everything inside the findings dir.
    output_dir.mkdir(parents=True, exist_ok=True)
    inner = output_dir / ".gitignore"
    if not inner.exists():
        inner.write_text("# Sensitive Security Agent findings - never commit.\n*\n!.gitignore\n")

    # 2) Repo-level guard: find an enclosing .git dir and update its .gitignore.
    entry = f"{dir_name}/"
    for parent in [output_dir.resolve()] + list(output_dir.resolve().parents):
        if (parent / ".git").exists():
            gitignore = parent / ".gitignore"
            existing = gitignore.read_text().splitlines() if gitignore.exists() else []
            if entry not in existing and dir_name not in existing:
                with gitignore.open("a") as fh:
                    if existing and existing[-1].strip():
                        fh.write("\n")
                    fh.write(f"# AWS Security Agent findings (sensitive - do not commit)\n{entry}\n")
                logger.info("Added '%s' to %s", entry, gitignore)
            return


def write_outputs(findings: list[dict], output_dir: Path, args, agent_space: dict) -> None:
    by_job: dict[str, list[dict]] = {}
    for f in findings:
        job_id = f.get("pentestJobId") or f.get("codeReviewJobId") or "unknown-job"
        by_job.setdefault(job_id, []).append(f)

    manifest: dict[str, Any] = {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "agentSpaceId": agent_space["agentSpaceId"],
        "agentSpaceName": agent_space.get("name"),
        "region": args.region,
        "sources": args.source,
        "confidence": args.confidence,
        "totalFindings": len(findings),
        "jobs": [],
    }

    for job_id, job_findings in by_job.items():
        json_path = output_dir / f"findings_{job_id}.json"
        json_path.write_text(json.dumps(job_findings, indent=2, default=_json_default))

        csv_path = output_dir / f"findings_{job_id}.csv"
        extra = sorted({k for f in job_findings for k in f} - set(CSV_COLUMNS))
        columns = CSV_COLUMNS + extra
        with csv_path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for f in job_findings:
                row = {
                    k: (v.isoformat() if isinstance(v, (datetime, date)) else v)
                    for k, v in f.items()
                }
                writer.writerow(row)

        manifest["jobs"].append(
            {
                "jobId": job_id,
                "source": job_findings[0].get("source"),
                "findingCount": len(job_findings),
                "json": json_path.name,
                "csv": csv_path.name,
            }
        )
        logger.info("Wrote %d findings -> %s and %s", len(job_findings), json_path.name, csv_path.name)

    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    logger.info("Manifest: %s", output_dir / "manifest.json")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export AWS Security Agent findings to a local gitignored directory.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source",
        choices=["pentest", "code-review", "both"],
        default="both",
        help="Which scan type(s) to export findings from.",
    )
    parser.add_argument(
        "--confidence",
        nargs="+",
        choices=CONFIDENCE_CHOICES,
        default=["HIGH", "MEDIUM"],
        help="Confidence levels to include. Widen to capture more (noisier) findings.",
    )
    parser.add_argument("--region", default="us-east-1", help="AWS Region where Security Agent is configured.")
    parser.add_argument("--output-dir", default=".securityagent", help="Directory to write findings into (gitignored).")
    parser.add_argument("--agent-space-id", help="Pin a specific agent space (default: most recently updated).")
    parser.add_argument("--pentest-id", help="Pin a specific penetration test.")
    parser.add_argument("--pentest-job-id", help="Pin a specific pentest job (default: latest COMPLETED).")
    parser.add_argument("--code-review-id", help="Pin a specific code review.")
    parser.add_argument("--code-review-job-id", help="Pin a specific code review job (default: latest COMPLETED).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir)

    # Guard the output location BEFORE writing any sensitive data.
    ensure_gitignored(output_dir)

    try:
        import boto3
    except ImportError:  # pragma: no cover - environment guard
        sys.stderr.write(
            "boto3 is required. Run this script with 'uv run' so the bundled dependency is\n"
            "installed automatically (the script declares boto3 via PEP 723 inline metadata):\n"
            "  uv run .kiro/skills/security-agent-remediation/scripts/fetch_findings.py\n"
            "Or install it manually: 'pip install boto3'.\n"
        )
        return 2

    client = boto3.client("securityagent", region_name=args.region)
    agent_space = resolve_agent_space(client, args.agent_space_id)
    asid = agent_space["agentSpaceId"]

    findings: list[dict] = []
    if args.source in ("pentest", "both"):
        findings += collect_pentest(client, args, asid)
    if args.source in ("code-review", "both"):
        findings += collect_code_review(client, args, asid)

    if not findings:
        logger.info("No findings to export. Check that a scan has a COMPLETED job and the Region is correct.")
        return 1

    write_outputs(findings, output_dir, args, agent_space)
    logger.info("\nExported %d finding(s) to %s/ — review and remediate in priority order.", len(findings), output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
