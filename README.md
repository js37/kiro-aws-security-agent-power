# AWS Security Agent — Kiro

This repo contains Kiro Powers and Skills for AWS Security Agent.

## Kiro Power

### What it does

- Run full security code scans on your workspace to help find vulnerabilities
- Orchestrate penetration tests against live applications
- Retrieve findings with code locations and severity
- Access all AWS Security Agent API operations

### Prerequisites

- AWS account
- AWS credentials configured (`aws configure` or environment variables)
- [uv](https://docs.astral.sh/uv/) installed (`brew install uv` or `pip install uv`)

### Installation

**Step 1: Install `uv` (if not already installed)**

```bash
brew install uv
# or: pip install uv
```

**Step 2: Install the MCP server (one-time)**

```bash
uv tool install --from "git+https://github.com/ljainiaz/mcp.git@security-agent-mcp#subdirectory=src/security-agent-mcp-server" awslabs.security-agent-mcp-server
```

This installs the `awslabs.security-agent-mcp-server` binary to `~/.local/bin/`.

**Step 3: Add the power to Kiro**

In Kiro, open the Powers panel and add from this repository URL, or install from local path during development.

### Updating

To get the latest version of the MCP server:

```bash
uv tool upgrade awslabs.security-agent-mcp-server
```

Once the server is published to PyPI, installation will simplify to `uv tool install awslabs.security-agent-mcp-server`.

## Security Agent remediation skill

Skill for remediating findings from AWS Security Agent Code Review and Penetration test.

### What it does

- Discovers recent pentests and compares to repo. Automatically suggests which one is relevant
- Deterministically pulls findings and triages with packaged python scripts
- Deterministically adds .gitignore to finding directory so customers are less likely to commit it
- Starts bugfix workflow in Kiro. Uses all the existing steering files customers have setup

### Installation

1. Open Kiro and navigate to the **Kiro** tab
2. Under **Agent Steering & Skills**, choose **+**
3. Choose either workspace or global for Skill location
4. Import Skill from Github URL
5. Enter https://github.com/ljainiaz/kiro-aws-security-agent-power/skills/security-agent-remediation

### Get started

1. Open repo with code related to the scan you performed in Security Agent.
2. Start a new chat, try requests like

"Help me remediate findings from Security Agent"

## Supported Regions

us-east-1, us-west-2, ap-southeast-2, eu-central-1, eu-west-1, ap-northeast-1

## License

Apache-2.0 — See [LICENSE](https://github.com/awslabs/mcp/blob/main/LICENSE)
