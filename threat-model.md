# OACB Threat Model — v0.1 (Claude Code Auto Mode Profile)

**Framework:** OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10), MITRE ATLAS v5.4.0 (February 2026), Meta/Anthropic/OpenAI/DeepMind Agents Rule of Two.
**Design primitive:** A session must not hold all three of: untrusted data, private data, external state change.

---

## Trust boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│  Developer laptop (MDM-managed)                                        │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Claude Code process                                             │  │
│  │                                                                  │  │
│  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │  │
│  │   │ Model context│ ←→ │ Tool dispatch│ ←→ │ PreToolUse hook  │   │  │
│  │   │  (untrusted) │    │  (permission │    │  (OACB enforce)  │   │  │
│  │   │              │    │   + classifier)   │                   │   │  │
│  │   └──────────────┘    └──────────────┘    └──────────────────┘   │  │
│  │          ↑                    ↓                    ↓              │  │
│  └──────────│────────────────────│────────────────────│──────────────┘  │
│             │                    │                    │                 │
│        Anthropic API       OS syscalls          Unbound API             │
│                                                  (AASB Gateway)         │
└─────────────│────────────────────│────────────────────│────────────────┘
              ↓                    ↓                    ↓
      ┌───────────────┐    ┌───────────────┐    ┌────────────────┐
      │ Anthropic     │    │ Corporate /   │    │ Unbound policy │
      │ infra (GPAI)  │    │ prod systems  │    │ backend        │
      └───────────────┘    └───────────────┘    └────────────────┘
```

**Boundaries:**
- B1: Model context ↔ Tool dispatch — prompt contents are untrusted; tool calls are the agent's output
- B2: Tool dispatch ↔ OS — where OACB's managed-settings + hooks enforce
- B3: Laptop ↔ Anthropic API — GPAI boundary (Anthropic terms apply)
- B4: Laptop ↔ Corporate/prod — where real damage occurs
- B5: Hook ↔ Unbound API — policy fetch + telemetry

---

## STRIDE × ASI × ATLAS × CVE threat register

Each row: a specific attack class, the frameworks it maps to, concrete evidence, OACB coverage in v0.1, residual risk.

| ID | Threat | STRIDE | OWASP ASI | MITRE ATLAS | Evidence (CVE / incident / research) | OACB v0.1 coverage | Residual risk |
|----|--------|--------|-----------|-------------|--------------------------------------|--------------------|----------------|
| T-01 | Hostile `.claude/settings.json` in cloned repo defines hooks that execute on session start | Elevation, Tampering | ASI04, ASI05 | AML.CS0041 Rules File Backdoor; AML.T0018 Manipulate AI Model | CVE-2025-59536 (Check Point), fixed in Claude Code 1.0.111 | Managed-settings tier enforces `allowManagedHooksOnly: true`. Patches ensure the class is closed on modern Claude Code. | Low. Requires managed-settings deployment. |
| T-02 | Bash denylist bypass via variable expansion, base64 eval, path tricks, abbreviated args, history manipulation | Tampering | ASI02 | AML.T0017.001 Prompt Injection; AML.T0048 Software Dependency | CVE-2025-66032 (Flatt 8-way), fixed; Adversa compound-command bypass (April 2026, open) | Adversarial corpus includes all 8 Flatt variants + Adversa compound case. Strict tier: BLOCK compound > 10 subcommands. Fail-closed hook. | Medium. Pattern matching is adversarially defeated by the agent controlling the input. Needs runtime enforcement. |
| T-03 | Path-restriction bypass + command injection via whitelisted `echo` / benign commands | Tampering, Elevation | ASI02 | AML.T0085.001 AI Agent Tools | CVE-2025-54794, CVE-2025-54795 (Cymulate InversePrompt), fixed | Adversarial corpus + allow-list carefully scoped | Medium. New variants of this class will emerge. |
| T-04 | DNS exfiltration via subdomain encoding; not gated by approval flow | Information Disclosure | ASI02, ASI09 | AML.T0024 Exfiltration via C2 Channel | CVE-2025-55284 (Embrace The Red), fixed | Strict/paranoid tier: sandbox network rules restrict DNS resolution. v0.2 adds DNS-layer egress recommendations. | **High.** Sandbox covers Bash-child network only, not MCP child processes. |
| T-05 | MCP server tool-description rug-pull (post-install mutation) | Tampering | ASI04 | AML.T0048 Software Dependency Compromise; AML.T0065 ML Artifact Collection | Invariant Labs' MCP Tool Poisoning research; first in-the-wild (`postmark-mcp` v1.0.16, Sep 2025) | MCP allowlist + `allowManagedMcpServersOnly: true`; install-time scan via `unbound oacb doctor` | **High.** Scan-time check does not cover post-install mutation. Needs runtime MCP monitoring. |
| T-06 | Read-tool credential exfiltration (`.env`, `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.netrc`, `~/.config/gh`) | Information Disclosure | ASI02, ASI09 | AML.T0024.002 Exfiltration via Cyber Means | Knostic research; vett.sh demonstration | Read denylist in managed-settings at all tiers covers the common paths. Enforce via hook (Claude Code permission deny doesn't always fire for Read — open issue #6699). | Medium. Agent can read through symlinks, env vars, or approved paths that reference secrets. |
| T-07 | WebFetch as exfiltration channel (base64 query string to attacker domain) | Information Disclosure | ASI02, ASI09 | AML.T0024 | arXiv 2510.09093 | Baseline tier: domain allowlist (`WebFetch(domain:*)` patterns). Paranoid tier: managed domain allowlist only. | Medium-High. Domain allowlist catches obvious exfil; attacker can use allowed domains with crafted URLs. |
| T-08 | Prompt injection via untrusted repo files (`CLAUDE.md`, `.cursor/rules`, `README.md`, code comments, package.json scripts, issue titles) | Spoofing, Tampering | ASI01, ASI06 | AML.T0051 LLM Prompt Injection; AML.CS0041 | Pillar Security "Rules File Backdoor" (Mar 2025); Simon Willison's Cline case (issue-title injection) | UserPromptSubmit hook flags suspicious patterns and logs to audit channel. Strict tier: BLOCK on matched patterns; Baseline: WARN. Does not close the class. | **High.** Content-layer defense requires runtime (AASB) — host pattern matching cannot enumerate all injection forms. |
| T-09 | Compound command abuse — >50 subcommands joined with `&&/||/;` defeats per-subcommand analysis | Tampering | ASI02, ASI03 | AML.T0051 | Adversa AI April 2026 disclosure | BLOCK compound command with > 10 subcommands at strict tier, warn at baseline. Adversarial corpus includes Adversa's 51-subcommand case. | Medium. Attacker can tune subcommand count; detection by heuristic. |
| T-10 | `rm -rf` against home / system / mount root | Destruction | ASI02, ASI05 | AML.T0018 | GitHub issue #10077 (Claude Code deleted home); Nextcloud NFS incident | Deny: `Bash(rm -rf /*)`, `Bash(rm -rf ~*)`, `Bash(rm -rf ${HOME}*)`, variants. Adversarial corpus includes `${IFS}`, `$(echo rm)`, abbreviated paths. | Medium. Agent can use `find -delete`, Python, or MCP filesystem tool. |
| T-11 | `terraform destroy` / `terraform apply -auto-approve` on production | Destruction | ASI02, ASI05, ASI09 | AML.T0018 | Replit incident (Jul 2025, 4000 fake users + DB wipe); DataTalks.Club incident (Feb 2026, 1.94M rows) | Deny `terraform destroy`; REQUIRE_SLACK_APPROVAL on `terraform apply`. Paranoid tier also BLOCKs `terraform state rm`. autoMode.soft_deny includes "Never run terraform destroy under any circumstance." | Medium. Classifier-gated grey area; out-of-band approval required. |
| T-12 | Force-push to main / release branches | Tampering, Repudiation | ASI02, ASI09 | AML.T0018 | Known industry pattern; not Claude-specific but readily reproducible | Deny `Bash(git push --force *)`, `Bash(git push -f *)`, variants including `--force-with-lease` on main (allow on feature branches). | Low. |
| T-13 | Database migration / schema-destroy tools (`drizzle-kit push --force`, `alembic downgrade`, `prisma migrate reset`) | Destruction | ASI02, ASI05 | AML.T0018 | Trading-platform Drizzle incident | Deny the documented destructive variants; REQUIRE_SLACK_APPROVAL on migration commands. | Medium. |
| T-14 | Autonomous mode classifier manipulation via persuasive prompt framing | Spoofing | ASI01, ASI03 | AML.T0051 | Checkmarx research on bypassing Claude Code reviewer; academic survey showing 100% of tested agents fall to one class | autoMode.environment + autoMode.soft_deny hardening; `permissions.disableAutoMode: "disable"` at paranoid tier. | **High.** Classifier decisions are not deterministic. |
| T-15 | `bypassPermissions` / `--dangerously-skip-permissions` weaponization | Elevation | ASI03 | AML.T0085.001 | Inherent mode behavior; documented by Anthropic | `permissions.disableBypassPermissionsMode: "disable"` at baseline tier and above. Forbids `--dangerously-skip-permissions` launches. | Low. Managed-settings tier enforces. |
| T-16 | Slash command / subagent supply chain (malicious skill in `~/.claude/skills/`) | Tampering, Elevation | ASI04, ASI05 | AML.T0048 | vett.sh research; awesome-claude-skills-security published offensive payloads | Deny `Write(**/.claude/**)`, `Edit(**/.claude/**)` at all tiers. Skill allowlist at strict+. | Medium. Skills installed via legitimate channels bypass Write deny. |
| T-17 | Skill hot-swap — installed skill modified by agent mid-session | Tampering | ASI05, ASI06 | AML.CS0041 | vett.sh | ConfigChange hook audits `~/.claude/skills/` modifications. | Medium. Audit vs prevention. |
| T-18 | Data exfiltration via Slack / Discord / external MCP sinks | Information Disclosure | ASI02, ASI07 | AML.T0024 | CyberArk "Poison Everywhere" | MCP allowlist. Strict+: managed MCP servers only. | Medium. Any allowed MCP with external write capability is a channel. |
| T-19 | Session context poisoning via edited CLAUDE.md | Tampering | ASI06 | AML.CS0041 | Class of attack documented across multiple sources | Deny `Write(**/CLAUDE.md)`, `Edit(**/CLAUDE.md)` at baseline and above. ConfigChange hook audits edits. | Low-medium. |
| T-20 | Network egress to unapproved domains via Bash (`curl`, `wget`, arbitrary script download + exec) | Information Disclosure, Tampering | ASI02 | AML.T0024 | Multiple incidents | Baseline: deny `Bash(curl *)`, `Bash(wget *)`. Allowlist specific install commands (`brew`, `apt`, `npm`, `cargo`, `rustup` via `curl`) in allow section. Strict tier: sandbox network allowlist. | Medium. Script-download + exec paths vary. |
| T-21 | State-actor multi-stage campaign orchestrated via Claude Code | Multiple | ASI01, ASI02, ASI03, ASI04, ASI05 | AML.CS0041 et al | Anthropic GTG-1002 disclosure (PRC state actor, Nov 2025) | OACB raises cost but does not close state-actor threat. Log + audit + AASB recommended. | **High.** Explicitly out of OACB v0.1 threat model scope. |

---

## Agents Rule of Two application

For each OACB-protected flow, we verify the Rule of Two invariant: **no session holds all three of (untrusted data, private data, external state change).**

Enforcement:

| Flow | Untrusted data? | Private data? | External state change? | Rule of Two status | OACB response |
|------|----------------|---------------|------------------------|--------------------|---------------|
| `claude` on a PR review (read-only) | Yes (PR content) | Yes (codebase) | No | Safe (2 of 3) | Allow with plan/acceptEdits modes |
| `claude -p` in CI with `GITHUB_TOKEN` | Yes (issue/PR content) | Yes (repo secrets) | Yes (can push, open PRs) | **Violation (3 of 3)** | v0.2 CI profile will require stripping one: either no untrusted input or no write token or no private read |
| `claude` reading prod DB credentials | No (dev-authored) | Yes (creds) | Yes (DB writes) | Safe if input is trusted | Baseline: allow. Strict: REQUIRE_SLACK_APPROVAL on prod DB write. |
| MCP server with filesystem + network tools | Depends (MCP responses are untrusted) | Yes (local files) | Yes (network writes) | **Violation (3 of 3)** | MCP allowlist + managed-only + server-specific tool allowlist required |
| Claude autonomously reviewing untrusted issues + writing code + committing | Yes (issue) | Yes (repo) | Yes (commit) | **Violation (3 of 3)** | Block at baseline+. v0.2 introduces review-only mode that strips write capability. |

The Rule of Two is the first-line design check. If a proposed deployment is a 3-of-3 flow, OACB's default posture is to strip one axis, not to harden the denylist.

---

## Out of scope for v0.1

These threats are acknowledged but not addressed in v0.1. See residual risks above and [non-claims.md](non-claims.md) for the full honest list.

- ASI07 Insecure Inter-Agent Communication (multi-agent coordination) — v0.3+
- ASI08 Cascading Agent Failures — v0.3+
- ASI10 Rogue Agents (agents breaking designed goals) — v0.3+
- Non-coding autonomous agents (customer support, SRE, ops bots) — sibling framework
- SaaS IDE coverage (Cursor web, Claude.ai Code mode, Replit Agent) — cannot be addressed at host layer
- BYOD / unmanaged endpoint coverage — requires organizational policy + network-layer enforcement

---

## Review and update

This threat model is reviewed on every MAJOR release and whenever a new Claude Code CVE class is disclosed. New CVE disclosures land here within 7 days of publication.

Contributions welcome — threat classes demonstrated in public research with a working PoC get added; classes without evidence are tracked in `threat-model-candidates.md` until a PoC lands.
