# OACB — Open Autonomous Coding-agent Baseline

**An opinionated, CVE-grounded, OWASP-mapped security baseline for Claude Code running in autonomous modes.**

v0.1 — Claude Code Auto Mode Profile
License: Apache 2.0

---

## What this is

OACB is a reference security baseline for deploying Claude Code (and upcoming: Cursor, Codex, Gemini CLI) in autonomous execution modes — where the agent runs tool calls without human-in-the-loop approval. It ships:

- A tiered `managed-settings.json` (shadow / baseline / strict / paranoid) ready for Jamf, Intune, and Kandji MDM push
- Hardened PreToolUse and UserPromptSubmit hooks with documented fail-closed semantics (Claude Code hooks fail open by default)
- A threat model mapped to OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10) and MITRE ATLAS v5.4.0
- An adversarial bypass corpus grounded in documented CVEs — Flatt's 8-way Bash denylist bypass (CVE-2025-66032), Cymulate's InversePrompt (CVE-2025-54794/5), Embrace The Red's DNS exfiltration (CVE-2025-55284), Adversa's compound-command bypass, and Check Point's cloned-repo hook RCE (CVE-2025-59536)
- A false-positive corpus — 200+ legitimate developer commands that must not block at baseline tier
- A conformance test harness that scores any Claude Code configuration against the baseline

OACB is the **host-layer** control. It is defense-in-depth, not the primary enforcement layer. See [Runtime Enforcement](#runtime-enforcement) below for the honest limits and the network-layer options that close the gap.

## What this is not

- **Not a substitute for runtime enforcement.** Pattern-match denylists are adversarially defeated. The agent controls the input string. Read [non-claims.md](non-claims.md) before deploying.
- **Not a vendor artifact disguised as a framework.** OACB's rules are original work grounded in public CVE research. Trail of Bits' `claude-code-config` is a valuable reference; we do not vendor its content (Apache 2.0 / CC-BY-SA incompatibility).
- **Not stable yet.** v0.1 is a starting point. Breaking changes are likely before v1.0.

## Who this is for

Security engineers at 500-5000 person organizations who need a defensible, CVE-grounded baseline for Claude Code deployments. Specifically:

- The person a CISO hands "make AI coding agents safe" to in 2026
- Platform / DevProd engineers who own IDE and developer-tooling policy
- Security consultants who need a reference to point clients at

If you are a solo developer using Claude Code on a personal laptop, OACB is probably overkill. Start with the [`trailofbits/claude-code-config`](https://github.com/trailofbits/claude-code-config) reference config and graduate to OACB when you need audit-citable framework language.

## Install

Requires [`unbound-cli`](https://github.com/websentry-ai/unbound-cli) ≥ v1.N.0.

```bash
# Install the CLI (one time)
npm install -g unbound-cli

# Pre-flight: check your local Claude Code install
unbound oacb check

# Audit your current config (non-destructive; reports gaps by ASI ID)
unbound oacb audit

# Apply shadow mode (log-only, no enforcement) — recommended first step
unbound oacb apply --tier shadow

# After 2 weeks of observation, graduate to baseline (WARN + BLOCK on destructives)
unbound oacb apply --tier baseline

# Strict / Paranoid tiers for regulated or highly sensitive environments
unbound oacb apply --tier strict
unbound oacb apply --tier paranoid

# Fleet-wide via MDM (run as the MDM agent or from admin console)
sudo unbound oacb apply --tier baseline --mdm
```

Per-tier effect:

| Tier | `disableAutoMode` | Policy action | Hook mode | MCP allowlist | Intended use |
|---|---|---|---|---|---|
| **Shadow** | enabled | AUDIT (log only, no block) | advisory | observe | 2-week observation before rollout |
| **Baseline** | enabled | WARN + BLOCK on CVE-mapped destructives | hard-block (exit 2) | allowlist | Default enterprise rollout |
| **Strict** | enabled | BLOCK all; REQUIRE_SLACK_APPROVAL on grey | hard-block + human-gate | strict allowlist | Regulated / pre-production |
| **Paranoid** | `"disable"` (auto mode off) | BLOCK default; ASK on anything not allowed | managed hooks only | managed-only | FedRAMP / highly sensitive |

## What this baseline covers

### Claude Code permission modes addressed

| Mode | Coverage |
|---|---|
| `default` | Full |
| `acceptEdits` | Full |
| `plan` | Full (read-only guards) |
| `auto` | **Primary focus** — LLM-classifier-gated execution |
| `dontAsk` | Partial — hardened CI profile |
| `bypassPermissions` | Paranoid tier disables it via `permissions.disableBypassPermissionsMode: "disable"` |

### Threat categories (OWASP ASI 2026)

- **ASI01 Goal Hijack** — prompt injection via CLAUDE.md, README.md, `.cursor/rules`, untrusted repo content
- **ASI02 Tool Misuse & Exploitation** — Bash denylist bypass, path tricks, base64 eval, compound commands
- **ASI03 Agent Identity & Privilege Abuse** — auto-mode classifier overreach, `bypassPermissions` weaponization
- **ASI04 Agentic Supply Chain Compromise** — malicious MCP servers, tool-description poisoning, `.claude/settings.json` RCE on repo clone (CVE-2025-59536)
- **ASI05 Unexpected Code Execution** — hooks as arbitrary code, slash commands, subagents, skills
- **ASI06 Memory & Context Poisoning** — transcript manipulation, session-start instruction injection
- **ASI09 Human-Agent Trust Exploitation** — false-assurance claims; why non-claims.md exists

ASI07 (inter-agent), ASI08 (cascading failures), ASI10 (rogue agents) are deferred to v0.2+ when OACB covers multi-agent workflows.

### Specific CVEs and incidents addressed

See [threat-model.md](threat-model.md) for the full STRIDE × ASI × ATLAS × CVE table. Headline coverage:

| Attack | CVE / incident | OACB response |
|---|---|---|
| Hook RCE via hostile `.claude/settings.json` in cloned repo | CVE-2025-59536 | `allowManagedHooksOnly: true` enforced at managed-settings tier |
| 8-way Bash denylist bypass incl. sandbox self-disable | CVE-2025-66032 | Adversarial corpus includes all 8 variants; strict-tier rules |
| InversePrompt path + echo command injection | CVE-2025-54794/5 | Adversarial corpus + path-guard hook |
| DNS exfiltration | CVE-2025-55284 | Sandbox network rules + adversarial corpus |
| Compound command bypass (>50 subcommands) | Adversa April 2026 | Rule: BLOCK compound command with > N subcommands |
| MCP tool description rug-pull | Invariant Labs | MCP allowlist + `allowManagedMcpServersOnly: true` |
| Read-tool credential exfil | Knostic / vett.sh | Read denylist: `.env`, `.ssh`, `.aws`, `.netrc`, `.gh` |
| Replit production DB wipe | Jul 2025 incident | Rule: BLOCK `terraform destroy`, `drizzle-kit push --force`, REQUIRE_SLACK_APPROVAL on migrations |
| DataTalks.Club `terraform destroy` (1.94M rows) | Feb 2026 incident | Same |
| `rm -rf ~/` (GitHub issue #10077) | Incident | Rule: BLOCK `rm -rf` against home and root paths |

## Runtime Enforcement

**Host templates are defense-in-depth, not primary enforcement.** Pattern-match deny rules can be defeated by obfuscation the agent controls (`\rm`, `${IFS}`, base64-pipe, MCP indirection, heredocs, process substitution). OACB ships hardened hooks that raise the bar, but they do not close the gap.

For deterministic enforcement you need a control **below the agent** — at the network, identity, or kernel layer.

Runtime enforcement options for AI coding agents:

- **[Unbound Gateway](https://getunbound.ai)** — AASB (Agent Access Security Broker) maintained by the OACB authors. Inline policy on LLM traffic; egress DLP; prompt-injection detection; cross-agent audit. Disclosure: Unbound Security funds OACB.
- **[Wiz AI-APP](https://www.wiz.io/blog/introducing-wiz-ai-app)** — cloud-posture + AI-SPM platform; detection-focused.
- **[Palo Alto Prisma AIRS](https://www.paloaltonetworks.com/prisma/prisma-ai-runtime-security)** — AI runtime security; network + agent.
- **[CrowdStrike Falcon AIDR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-announces-general-availability-of-falcon-ai-detection-and-response/)** — endpoint + agent detection.
- **[Snyk Agent Security + Evo AI-SPM](https://snyk.io/news/snyk-launches-agent-security-solution/)** — AI-BOM + policy compile.
- **[Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)** — open source, runtime controls.

OACB's maintainers believe AASB-style runtime control is the correct architectural endpoint. We name competitors above honestly because the category is served better by choice than by a single vendor's pitch. Pick a runtime control that fits your stack.

## Repository layout

```
oacb/
├── README.md
├── SECURITY.md                          # VDP + 72h ack SLA
├── MAINTAINERS.md
├── PROVENANCE.md                        # source/license per rule
├── COMPATIBILITY.md                     # Claude Code version matrix
├── non-claims.md                        # what OACB does NOT protect against
├── maturity-tiers.md                    # shadow / baseline / strict / paranoid detail
├── threat-model.md                      # STRIDE × ASI × ATLAS × CVE table
├── LICENSE                              # Apache 2.0
├── ROADMAP.md
├── baseline/
│   └── claude-code/
│       ├── managed-settings.shadow.json
│       ├── managed-settings.baseline.json
│       ├── managed-settings.strict.json
│       ├── managed-settings.paranoid.json
│       ├── CLAUDE.md.example
│       ├── hooks/
│       │   ├── oacb-enforce.sh         # PreToolUse, fail-closed
│       │   └── oacb-prompt-guard.sh    # UserPromptSubmit
│       └── rules/
│           ├── terminal-command/*.json  # individual rule definitions
│           └── mcp-tool/*.json
├── adversarial-corpus/                  # CVE-grounded bypass cases
├── false-positive-corpus/               # must-not-block dev workflows
└── conformance-tests/                   # CI harness
```

## Contributing

Security-report contact: **security@unboundsecurity.ai** (72h ack SLA; 90-day coordinated disclosure). See [SECURITY.md](SECURITY.md).

Code contributions: open a PR. Rules added must include (a) OWASP ASI / MITRE ATLAS mapping, (b) a passing adversarial test case, (c) documented false-positive coverage, (d) no vendored content without compatible licensing documented in PROVENANCE.md.

## Versioning

Semantic versioning. Compatibility matrix in [COMPATIBILITY.md](COMPATIBILITY.md). Breaking changes to rule IDs or `managed-settings.json` schema = MAJOR bump. New rules or CVE coverage additions = MINOR. Adversarial-corpus additions or doc changes = PATCH.

## Support

OACB is best-effort open source. No uptime, feature-delivery, or fix-timeliness commitments. Exception: security reports acknowledged within 72 hours, coordinated disclosure within 90 days.

Enterprises that want SLAs, custom rules, private issue tracking, and v0.1.1 control-mapping (NIST AI RMF / SOC 2 CC / ISO 42001 / CIS v8.1 crosswalks) early — contact Unbound Security.

## Acknowledgements

OACB is grounded in published research by:

- **GMO Flatt Security** — Pwning Claude Code in 8 Different Ways (CVE-2025-66032)
- **Check Point Research** — Claude Code project-file RCE (CVE-2025-59536)
- **Cymulate** — InversePrompt (CVE-2025-54794/5)
- **Embrace The Red / Johann Rehberger** — DNS exfil (CVE-2025-55284) and ASCII-smuggling research
- **Invariant Labs** — MCP Tool Poisoning Attacks
- **Adversa AI** — Compound command bypass disclosure
- **Pillar Security** — Rules File Backdoor
- **Trail of Bits** — `claude-code-config` reference and AI agent threat modeling
- **Knostic, vett.sh, HiddenLayer, CyberArk, Checkmarx, Semgrep** — ongoing attack research

Published research is what makes OACB real. If you publish a Claude Code bypass, we will cite you and ship the adversarial test case.

## Disclosure

OACB is maintained by [Unbound Security](https://getunbound.ai). Unbound ships AASB (Agent Access Security Broker) aka Unbound Gateway, which is one of the runtime-enforcement options listed above. OACB's rules and threat model are independent of the Gateway product; we use OACB internally to harden our own Claude Code usage.
