---
name: security-agent-remediation
description: >-
  Pull AWS Security Agent findings (penetration tests and code reviews) and drive
  remediation. Use this whenever the user mentions Security Agent, security findings,
  pentest or penetration test results, code review findings, vulnerabilities found in
  their AWS account, "what did the security scan find", remediating or triaging security
  risks, or wants to start fixing reported vulnerabilities — even if they don't name the
  service explicitly. Trigger it for phrases like "get my security findings", "what
  vulnerabilities do we have", "let's fix the pentest results", or "triage the security
  report". The skill discovers scans, exports findings to a gitignored local directory
  (so sensitive exploit detail is never committed), produces a prioritized triage
  summary, and offers to start a spec session to fix the highest-risk issues.
---

# Security Agent Remediation

AWS Security Agent is a frontier agent that runs on-demand penetration tests and code
reviews against a customer's applications and reports verified security risks. This skill
takes you from "I have findings somewhere in AWS" to "I'm actively fixing the most
important ones," while keeping the sensitive exploit detail out of source control.

The flow has four stages, and they matter in order:

1. **Discover** which scans exist and how the account is configured (live, read-only).
2. **Export** the findings to a local gitignored directory using a deterministic script.
3. **Triage** the findings into a prioritized, human-readable plan.
4. **Remediate** by offering to start a Kiro spec session for the top issues.

## Why the ordering and the guardrails matter

Findings contain working attack scripts, reproduction steps, file paths, and sometimes
leaked secrets or environment details. If that lands in a Git repo, a customer can
accidentally commit and publish a step-by-step exploit for their own production system.
So the non-negotiable rule is: **findings are written only to `.securityagent/`, and that
path is gitignored before anything is written.** The bundled script enforces this with a
belt-and-suspenders `.gitignore` inside the directory too, but you should still confirm
the repo-level ignore is in place.

Discovery is read-only and uses live AWS calls so the user sees their real scans. The bulk
findings pull is a deterministic Python script (boto3) rather than ad-hoc calls, because
pagination, batching, and confidence filtering should behave the same way every time and
not depend on the model improvising CLI invocations.

## Stage 1: Discover scans (live, read-only)

Find out what the account has. Prefer the AWS API MCP server (the `call_aws` tool) so the
calls are visible and audited; if it isn't available, run the same commands with the AWS
CLI directly. All commands are read-only `list-*` operations.

AWS Security Agent organizes data as a hierarchy — work down it:

```
Application (account + Region)
└── Agent Space        (workspace for design review, code review, and pentests)
    ├── Penetration test → Pentest job → Findings
    └── Code review      → Code review job → Findings
```

Run these to orient yourself and show the user what exists:

```bash
aws securityagent list-agent-spaces
aws securityagent list-pentests          --agent-space-id <as-...>
aws securityagent list-code-reviews      --agent-space-id <as-...>
aws securityagent list-pentest-jobs-for-pentest         --agent-space-id <as-...> --pentest-id <pt-...>
aws securityagent list-code-review-jobs-for-code-review --agent-space-id <as-...> --code-review-id <cr-...>
```

Job `status` is one of `IN_PROGRESS`, `STOPPING`, `STOPPED`, `FAILED`, `COMPLETED`. Only
`COMPLETED` jobs have a stable, full set of findings.

### Match the codebase to a scan, then confirm

Agent spaces, pentests, and code reviews are named after the application they target
(e.g. `JuiceShop`, `Boise`, `TP-Link`). Before asking the user to pick from a raw list,
make an informed guess about which scan corresponds to *this* repository — the user is
working in a codebase for a reason, and the relevant findings are almost always for the
app in front of them.

Infer the app identity from the workspace using cheap, high-signal sources:

- The repository / root directory name and the Git remote URL (`git remote -v`).
- Project manifests and their `name`/`description` (`package.json`, `pyproject.toml`,
  `*.csproj`, `go.mod`, `Cargo.toml`).
- README titles, product/steering docs, and any obvious product or company name.
- Distinctive frameworks or domains that match a scan title.

Compare those signals against the agent space / scan names (case-insensitive, allow
partial and fuzzy matches — `boisestate.ai` in a README maps to a `Boise` agent space).
Then **always confirm before exporting** — present your best guess and your reasoning, and
let the user correct it:

> "This repo looks like **<product>** (from `<signal>`), which matches the **<name>** agent
> space. Use that, or pick another? [Boise, School, JuiceShop, ...]"

If nothing matches with reasonable confidence, say so plainly and show the full list rather
than forcing a wrong guess. If several scans match, surface the top candidates and ask.
Never export from a guessed scan without the user's confirmation — pulling the wrong app's
findings wastes time and writes unrelated sensitive data locally. Once the user confirms,
pass the chosen IDs explicitly to the export script rather than relying on its
"most recent" default.

## Stage 2: Export findings to `.securityagent/` (gitignored)

First make sure the output directory can't be committed. Add `.securityagent/` to the
repo's `.gitignore` if it isn't already there. Then run the bundled script, which resolves
the agent space / scan / latest completed job, pulls finding summaries, fetches full detail
in batches, and writes the results.

The script is self-contained: it ships with its own `pyproject.toml` declaring `boto3` as
a dependency. Running it with `uv run --project` provisions a dedicated virtual environment
for the skill (under the skill's own `.venv/`, which is gitignored), so it works in any repo
whether or not boto3 is installed — and it never touches the host project's environment.
The dependency is intentionally unpinned: AWS Security Agent is a new, fast-evolving
service, so each environment setup resolves the latest boto3 to pick up the newest
`securityagent` API model. The first run installs it; later runs reuse the cached venv.

Always invoke it with `--project` pointing at the skill directory so uv uses the skill's
own `pyproject.toml` and environment rather than the current repo's:

```bash
SKILL=.kiro/skills/security-agent-remediation

# Both pentest and code-review findings from the latest completed jobs, HIGH+MEDIUM confidence:
uv run --project "$SKILL" "$SKILL/scripts/fetch_findings.py"

# Target a specific scan / job, widen confidence, or pick a source:
uv run --project "$SKILL" "$SKILL/scripts/fetch_findings.py" \
  --source code-review \
  --agent-space-id as-... \
  --code-review-id cr-... \
  --confidence HIGH MEDIUM LOW \
  --region us-east-1
```

Run `uv run --project "$SKILL" "$SKILL/scripts/fetch_findings.py" --help` for the full set
of options. (If `uv` isn't available, the script still runs under any Python that already
has boto3 installed.) Key flags:

- `--source {pentest,code-review,both}` — which scan types to export (default `both`).
- `--confidence` — confidence levels to keep (default `HIGH MEDIUM`). Low-confidence and
  false-positive findings are noisy; widen only when the user asks.
- `--agent-space-id` / `--pentest-id` / `--pentest-job-id` / `--code-review-id` /
  `--code-review-job-id` — pin to a specific scan or run instead of "latest".
- `--region` (default `us-east-1`) and `--output-dir` (default `.securityagent`).

The script writes, per job, a full-fidelity `*.json` and a flattened `*.csv`, plus a
`manifest.json` describing what was pulled. It exits non-zero if no agent space, scan, or
completed job is found — surface that message to the user rather than retrying blindly,
since it usually means the scan hasn't finished or credentials point at the wrong account.

If the script fails because credentials or the service aren't available, check with
`aws sts get-caller-identity` and confirm the Region. Don't paste finding contents into
chat beyond short titles and counts — the detail belongs in the gitignored files.

## Stage 3: Triage into a prioritized plan

Rank by risk, because remediation time is finite and a CRITICAL unauthenticated RCE
outranks a LOW informational finding every time. Use the bundled `triage.py` to produce the
ranking deterministically rather than re-deriving the sort by hand — it reads the exported
`findings_*.json`, orders by `riskLevel` then `riskScore` (highest first) then `confidence`,
and pulls out the code location for each finding. It's stdlib-only, so run it with plain
`python3` (no uv/boto3 needed):

```bash
SKILL=.kiro/skills/security-agent-remediation

python3 "$SKILL/scripts/triage.py"                 # ranked table + severity counts
python3 "$SKILL/scripts/triage.py" --top 10        # just the top N
python3 "$SKILL/scripts/triage.py" --json          # machine-readable, to build the summary
```

`riskScore` is a string for pentest findings and absent for code-review findings; the
script normalizes that, so don't try to sort the raw values yourself. Use its output to
write a compact summary for the user with this structure:

```
## Security Agent triage — <agent space name>

<N> findings exported (<by source: P pentest, C code review>) · confidence: <levels>

### Priority order
1. [CRITICAL · score 10.0 · HIGH confidence] <finding name>
   - Type: <riskType> · Source: <pentest|code-review>
   - Where: <file:line or endpoint, if present>
   - Impact: <one-line plain-language summary>
2. [HIGH · ...] ...

### Recommended remediation order
<short rationale: which to fix first and why — e.g. "1 and 3 are both
unauthenticated RCE on internet-facing endpoints; fix those before the
stored-XSS issues.">
```

Keep impact descriptions in plain language and one line each — the full `description`,
`reasoning`, and `attackScript` stay in the files. Code review findings usually carry a
`filePath`/location and a suggested fix; call those out since they map directly to repo
changes. Pentest findings describe endpoints and attack chains; map them to the responsible
code where you can. Look for findings that corroborate each other (a pentest and a code
review flagging the same root cause) — those are strong signals for what to fix first.

## Stage 4: Offer to remediate via a spec session

After presenting the triage, offer to start fixing — don't silently begin editing code.
Security fixes change behavior (auth, validation, parsing) and deserve a deliberate plan,
so the natural next step is a **bugfix spec session** scoped to the top finding(s).

Ask the user something like: "Want me to start a spec session to fix the top finding(s)?
I'd recommend starting with #1 (<name>)." If they agree, kick off a spec by describing the
selected finding as a bug to fix — feed in the finding's title, affected location, impact,
and the suggested fix (for code reviews) as the seed for the spec. Reference the finding by
`findingId` and pull detail from the gitignored file rather than restating exploit steps in
the spec prose.

If the user wants to handle several findings, scope one spec per finding (or one per tightly
related cluster) so each fix stays reviewable, and proceed in the priority order from
Stage 3.

## Notes and edge cases

- **No completed jobs**: a scan may still be `IN_PROGRESS`. Tell the user; offer to re-check
  later rather than exporting a partial job.
- **Re-running**: each run overwrites the files for that job id. The directory is safe to
  delete; it only holds exported copies, not source-of-truth data.
- **Multiple accounts/Regions**: findings are Region-scoped. If the user expected results
  and got none, confirm `--region` matches where Security Agent is configured.
- **Data handling**: treat exported findings as sensitive per the org's data-handling
  policy. They are CSV/JSON copies of verified exploits against the user's own systems.
