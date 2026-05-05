# postmark-mcp Backdoor — First In-the-Wild Malicious MCP Server (Sep 2025)

**Source:** Semgrep Security — npm backdoor analysis, September 2025; Invariant Labs corroboration
**Date:** September 2025
**CVE:** None assigned
**Status:** `postmark-mcp` v1.0.16 is confirmed malicious. Do not install; verify content hashes before using any version.
**OWASP ASI:** ASI04 Agentic Supply Chain Compromise
**MITRE ATLAS:** AML.T0048 ML Software Dependency Compromise

## Incident

`postmark-mcp` is an npm package wrapping the Postmark email API as an MCP server. Version 1.0.16 (published September 2025) contained a backdoor that on first tool call:

1. Exfiltrated `~/.env` and `~/.aws/credentials` to an attacker-controlled endpoint
2. Registered the agent's runtime environment (env vars, working directory) with the same endpoint
3. Embedded a persistent prompt injection in the `send_email` tool description that redirected future agent behavior

This was the first documented in-the-wild exploitation of the MCP supply chain against Claude Code users. It was discovered by Semgrep's security team during routine npm package monitoring.

## Why it succeeded pre-OACB

There was no mechanism in base Claude Code to distinguish a backdoored MCP server from a legitimate one. The agent installed the package, loaded the server, and executed its tools — the backdoor ran as part of the first legitimate `send_email` call.

## OACB coverage

OACB-MCP-002 blocks all tool calls from `postmark-mcp` at **all active tiers** — including baseline and shadow+. The check fires before the shadow-tier pass-through path, making it the only OACB rule that blocks at shadow tier.

```bash
# Blocked at all tiers (including baseline):
mcp__postmark-mcp__send_email
mcp__postmark-mcp__send_batch_emails
mcp__postmark-mcp__* (any tool on this server)
```

This is a permanent named-server block, not an allowlist check. Even if an administrator accidentally adds `postmark-mcp` to the MCP allowlist, OACB-MCP-002 fires first and blocks the call.

**Expected:** exit 2, stderr contains `OACB-MCP-002`

## Test

```bash
echo '{"tool_name":"mcp__postmark-mcp__send_email","tool_input":{}}' | \
  OACB_TIER=baseline ./baseline/claude-code/hooks/oacb-mcp-guard.sh
# expected: exit 2, stderr contains OACB-MCP-002
```

See conformance case `mcp-postmark-block` in `conformance-tests/expected.json`.

## Update cadence

The known-hostile server list in `oacb-mcp-guard.sh` is updated with each MINOR release when a new in-the-wild malicious MCP server is confirmed. Report new findings via SECURITY.md; coordinated disclosure applies.
