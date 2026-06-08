# OACB — Open Autonomous Coding-agent Baseline

Security hooks and settings for Claude Code running in autonomous (auto) mode. Enforces strict controls to prevent accidental or malicious damage by autonomous agents. 

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![OACB v0.2.0 beta](https://img.shields.io/badge/OACB-v0.2.0%20beta-orange)](https://github.com/websentry-ai/oacb/releases)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange)](https://github.com/websentry-ai/oacb/releases/tag/v0.2.0)

> **Beta release.** OACB is under active development. Interfaces — rule IDs, audit-log JSON schema, managed-settings keys, tier semantics — may change before `v1.0.0`. Recommended for evaluation, shadow-tier observation, and pre-production rollout. Pin a specific tag (`v0.2.0`) in fleet deployments; do not track `main` in production.

---

## Quick start

```bash
npm install -g unbound-cli

unbound oacb check                    # verify your Claude Code install
unbound oacb apply                    # shadow tier - log-only, safe first step
unbound oacb doctor                   # confirm hooks are working
```

After a week or two in shadow mode, graduate to enforcement:

```bash
unbound oacb apply --tier baseline    # block destructive commands
```

---

## What OACB does

OACB installs shell hooks and a settings overlay into `~/.claude/` that:

- **Block** destructive Bash commands (`rm -rf`, `terraform destroy`, force-push, DB wipe) before they run
- **Block** Claude Code's `--dangerously-skip-permissions` bypass at all tiers
- **Warn or block** prompt injection patterns in user input (bidi Unicode, instruction-override markers)
- **Audit** every MCP tool call; block allowlist violations at strict/paranoid
- **Log** all decisions to `~/.claude/hooks/oacb-audit.log`

---

## Tiers

| Tier | What it does | When to use |
|---|---|---|
| `shadow` | Log only — never blocks | Observe for 1–2 weeks before rollout |
| `baseline` | Block CVE-mapped destructives | Default for most teams |
| `strict` | Block all; human-gate on ambiguous | Regulated environments, pre-prod |
| `paranoid` | Auto mode disabled; managed hooks only | FedRAMP, high-sensitivity |

```bash
unbound oacb apply --tier shadow
unbound oacb apply --tier baseline
unbound oacb apply --tier strict
unbound oacb apply --tier paranoid
```

---

## Other commands

```bash
unbound oacb audit                    # score your current settings, report gaps
unbound oacb diff --to baseline       # preview what changes at the next tier
unbound oacb doctor --verbose         # run the conformance suite against installed hooks
unbound oacb remove                   # surgically remove OACB from settings.json
```

Every tier's rule set is open JSON — pass `--overrides <path>` to `apply` to layer your own deny rules, allowlist additions, or MCP policies on top of the baseline. This makes OACB adaptable to your organisation's specific tooling and risk posture without forking the project.

---

## Honest limits

OACB is a **host-layer** control. Pattern-match rules can be defeated by obfuscation the agent controls (`\rm`, base64-pipe, MCP indirection, heredocs). The hooks raise the bar considerably, but they do not make Claude Code airtight.

The gap that host-layer controls cannot close is **network egress and LLM traffic**. For that you need enforcement below the agent — inline on the model API call — where every tool invocation, prompt, and response can be inspected and blocked before it reaches the filesystem or network.

[**Unbound Gateway**](https://getunbound.ai) is an Agent Access Security Broker (AASB) built for exactly this: inline policy on LLM traffic, egress DLP, prompt-injection detection, and cross-agent audit — all without changing your Claude Code workflow. OACB + Unbound Gateway is the full-stack answer: OACB handles the host, Gateway handles the network and LLM layer.

Known host-layer residuals are documented in [non-claims.md](non-claims.md).

---

## Contributing

Security reports: **security@unboundsecurity.ai** — 72h ack, 90-day coordinated disclosure. See [SECURITY.md](SECURITY.md).

Code contributions: open a PR. New rules require (a) an OWASP ASI mapping, (b) a passing adversarial test case, (c) false-positive coverage.

---

## Acknowledgements

Rules are grounded in published research by GMO Flatt Security (CVE-2025-66032), Check Point Research (CVE-2025-59536), Cymulate (CVE-2025-54794/5), Embrace The Red (CVE-2025-55284), Invariant Labs, Adversa AI, Pillar Security, Trail of Bits, and others. If you publish a Claude Code bypass, we will cite you and ship the test case.

---

OACB is maintained by [Unbound Security](https://getunbound.ai) and released under Apache 2.0.
