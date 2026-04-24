# What OACB does NOT protect against

This document is load-bearing. Every claim in the README maps to a passing test; every non-claim below exists because pattern-match controls at the host layer cannot close the gap.

If you cite OACB in a policy document, link to this file alongside it. False assurance is worse than no assurance.

---

## Attack classes OACB v0.1 does not close

### 1. Prompt-injection-driven command reshaping

An agent that reads a hostile file (`CLAUDE.md`, `README.md`, `.cursor/rules`, code comment, package.json script, issue title, PR body, email, Slack message via MCP) can be instructed to reshape its own output. A denylist matching `rm -rf /` does not catch the agent when it is told to:

- Split the operation across three `Bash` calls
- Base64-encode the payload and pipe through `bash`
- Write a shell script to `/tmp` and invoke it
- Use a Python one-liner (`python -c "import shutil; shutil.rmtree('/')"`)
- Use `find / -delete` instead of `rm`
- Invoke an MCP filesystem tool that is not gated by the Bash denylist

**What you need:** content inspection of the agent's LLM traffic (runtime enforcement / AASB), not host-layer pattern matching.

### 2. MCP supply chain attacks

OACB ships an MCP allowlist and `allowManagedMcpServersOnly: true`. These prevent users from installing untrusted MCP servers. They do **not** prevent:

- An MCP server you approved updating its tool descriptions after install (Invariant Labs' rug-pull pattern)
- A package manager installing a malicious MCP transitively (npm/pypi supply-chain)
- An MCP server returning poisoned content in tool responses (CyberArk's "Poison Everywhere")
- A trusted MCP server being compromised upstream (postmark-mcp precedent)

**What you need:** MCP server pinning by content hash + runtime monitoring of tool descriptions for mutation + egress inspection of MCP responses.

### 3. Read-tool exfiltration via approved channels

Deny rules on Read for `.ssh`, `.aws`, `.netrc`, `.gh`, `.config` prevent direct reads of those paths. They do not prevent:

- Reading a file the developer legitimately has access to that references secrets
- The agent running `env | grep -i token` and exfiltrating environment variables
- The agent reading `~/.bash_history` / `~/.zsh_history` / shell rc files (OACB denies the common ones but not every variant)
- The agent asking the user for credentials "to test something"
- The agent exfiltrating data via a WebFetch to an approved domain with secrets in query parameters (arXiv 2510.09093)

**What you need:** data-flow DLP at the network layer that inspects LLM request/response content.

### 4. DNS and timing-channel exfiltration

Claude Code's approval flow historically did not gate DNS (CVE-2025-55284, patched). Even post-patch, an agent can:

- Smuggle data via base64-encoded subdomain lookups (`<data>.attacker.example`)
- Use timing of allowed requests as a covert channel
- Exfiltrate over allowed DNS-over-HTTPS endpoints

OACB ships network-egress sandbox rules at strict/paranoid tiers, but sandbox enforces only for Bash — not for the MCP process tree, not for transitive subprocess children.

**What you need:** DNS-layer egress monitoring + domain allowlisting at the network boundary.

### 5. Prompt-injection-driven UI deception

OACB cannot prevent an agent instructed by a hostile file from:

- Lying to the user about what it just did
- Fabricating test output to claim an operation succeeded when it failed
- Displaying a fake approval prompt in its own output text
- Manipulating the diff shown to the user

**What you need:** independent verification — CI that runs tests, human review of diffs before merge, out-of-band state checks (database row counts before/after, not agent-reported counts).

### 6. Autonomous mode classifier overreach

Auto mode uses an LLM classifier to gate tool calls. OACB recommends enabling it (it is strictly safer than `bypassPermissions`) but:

- The classifier is non-deterministic; identical situations may produce different decisions
- The classifier has been demonstrated to be manipulable via persuasive framing in the prompt (Checkmarx)
- The classifier cannot see tool *outputs* from previous calls in the session (Anthropic sanitizes them)
- The classifier falls back to asking after 3 consecutive or 20 total denials; a persistent attacker can stay under this threshold

OACB ships hard `permissions.deny` rules that fire before the classifier is consulted. But grey-area commands — which is most of them — still rely on classifier judgment.

**What you need:** sample and audit classifier decisions out-of-band (managed-settings `ConfigChange` hook + audit log export) and treat any grey-area action as an audit event, not a security control.

### 7. Skills, slash commands, and subagents

OACB deny rules on `Skill(*)` and `Agent(*)` restrict invocation. They do not prevent:

- A skill definition in `~/.claude/skills/` being modified by the agent itself (CVE-2025-59536 class — closed for settings.json, open for skill files absent `allowManagedHooksOnly` + skill-path restrictions)
- A skill invoking Bash tools that are themselves allowed
- A skill modifying `CLAUDE.md` to change future behavior (ASI06 memory poisoning)

**What you need:** skills directory on a read-only filesystem + ConfigChange hook auditing every skill / CLAUDE.md modification.

### 8. BYOD and unmanaged endpoints

OACB's managed-settings tier lives on MDM-managed devices. It does not reach:

- Developers using Claude Code on personal laptops
- Developers running Claude Code in a cloud VM they provisioned
- SaaS IDE execution (Cursor web, Claude.ai Code, Replit Agent)
- Devcontainers / codespaces with their own filesystem
- SSH to a dev server where Claude Code runs under a shell the MDM profile does not govern

**What you need:** (a) policy (human) forbidding corporate work on unmanaged endpoints, (b) SSO-gated access to source repositories, (c) AASB-style network control for any API traffic that must transit a corporate-controlled boundary.

### 9. CI runner deployments

Claude Code in GitHub Actions / CircleCI / Jenkins runs under a service account. The MDM profile does not apply. OACB v0.1 has **no CI profile**; v0.2 adds one. Until then:

- `claude -p` headless runs execute with whatever permissions the runner has
- Stolen OIDC tokens or `GITHUB_TOKEN` give the agent the same blast radius as any compromised Action
- The runner's secrets are visible via environment variables

**What you need:** least-privilege GitHub Actions permissions, OIDC to short-lived credentials, no long-lived secrets in runner environment, and — if running Claude Code in CI at all — an allowlist-only permission profile you ship with the workflow.

### 10. Hooks-themselves as attack surface

OACB ships hardened hooks. The hooks are shell scripts that execute in the developer's user context. They are arbitrary code execution if modified. OACB v0.1 mitigates this with:

- `allowManagedHooksOnly: true` in managed-settings
- Recommended filesystem permissions (0444, managed path outside `$HOME`)
- ConfigChange hook auditing every hook installation

It does not prevent:

- A root-compromised laptop from modifying managed-settings itself
- A signed hook installation being MITM'd during install (mitigated by `cosign` on OACB releases; not all installers verify signatures)
- A hook being replaced by a local process running as the developer's UID before `allowManagedHooksOnly` takes effect

**What you need:** endpoint protection (EDR) that monitors `~/.claude/` and managed-settings paths for unexpected writes.

### 11. State actor and sophisticated-attacker threat models

Anthropic disclosed GTG-1002 in November 2025 — a PRC state-sponsored campaign using Claude Code for multi-stage reconnaissance, exploit writing, credential mapping, and exfiltration. OACB raises cost for opportunistic attackers; it does not defeat a state actor who:

- Runs long campaigns against specific targets
- Uses novel bypass techniques not in any published CVE
- Can compromise supply chains, issue trusted certificates, or subvert hardware roots of trust

**What you need:** defense in depth (network + endpoint + SIEM + IR), threat intel partnership, human-review gates on high-impact actions, and a realistic assumption that any autonomous-mode deployment is not suitable for protecting state-actor-targeted systems.

### 12. Data already in the model's context

Once data has entered the agent's context window, OACB cannot remove it. If:

- The agent read `~/.aws/credentials` before OACB was applied
- The agent read a secret from an allow-listed path
- A user pasted a secret into the chat

...then the data is in the transcript and in any LLM API call for the remainder of the session, subject to Anthropic's data retention policy. The only mitigation is to clear and restart the session.

**What you need:** session hygiene policy + short-retention configuration on the Anthropic side + (if possible) zero-data-retention through Anthropic Enterprise.

---

## What this means for adopters

If you are pushing OACB through MDM to 1000 laptops and telling your CISO "we are covered on Claude Code," read this file again. "Covered" means:

- You are meaningfully harder to attack than before
- You have deterministic deny rules on documented destructive commands
- You have audit telemetry on what the agent is doing
- You have a framework you can cite in RFPs

You are **not** covered for prompt injection, data exfiltration via LLM content, MCP supply chain, classifier overreach, BYOD, CI, or state actors.

Close those gaps with runtime enforcement (AASB / equivalent), endpoint protection, network controls, and human-gated review on high-impact actions.

---

## Update cadence

This file is revised on every MAJOR release. If a new CVE class is demonstrated that OACB does not cover, it lands here within 7 days of the disclosure.
