# What OACB Is

**The short version:** OACB is a deployable, CVE-grounded security policy layer for Claude Code running in autonomous mode — the mode where it executes tool calls without stopping to ask a human.

---

## The problem it solves

When Claude Code runs autonomously it can call Bash, read files, push git branches, invoke MCP servers, and run shell commands — all without human approval. That's powerful, and it's also a large attack surface. Documented incidents include:

- An agent running `rm -rf ~/` while cleaning up temp files (GitHub issue #10077)
- Agents being directed by hostile files in a repo (prompt injection) to exfiltrate credentials or wipe production databases
- Malicious MCP servers serving poisoned tool descriptions that redirect the agent's behavior
- Clone-a-repo → auto-execute hooks RCE (CVE-2025-59536)

The market answer ("add a few deny rules to your settings") is easily defeated — the agent controls the command string and can obfuscate, split, base64-encode, or MCP-route around pattern matchers. OACB's honest answer is: **host-layer controls raise the bar; they cannot close every gap.** The `non-claims.md` file documents exactly what they don't close.

---

## What the repo actually ships

### 1. `managed-settings.{tier}.json` — four hardened Claude Code config files

These are drop-in replacements for `~/.claude/settings.json`, designed to be pushed fleet-wide via MDM (Jamf, Intune, Kandji). Four tiers let organizations graduate their enforcement level:

| Tier | What it does |
|---|---|
| `shadow` | Log everything, block nothing. 2-week observation before rollout. |
| `baseline` | Hard-block documented destructive commands (the CVE-mapped ones). Default enterprise rollout. |
| `strict` | Block broadly; require Slack approval on grey-area actions. For regulated environments. |
| `paranoid` | Disable auto mode entirely. Block almost everything. For FedRAMP/high-sensitivity. |

### 2. Four hook scripts — the actual enforcement logic

Claude Code has a hooks system: shell scripts that fire before tool calls and prompt submissions. By default these fail *open* (hook crash = allow). OACB's hooks fail *closed* (hook crash = block):

| Hook | Event | What it covers |
|---|---|---|
| `oacb-enforce.sh` | PreToolUse (Bash) | CVE-mapped destructive commands, all 8 Flatt obfuscation variants (CVE-2025-66032), credential exfil via `env \| grep`, `rm -rf ~`, `terraform destroy`, etc. |
| `oacb-prompt-guard.sh` | UserPromptSubmit | Prompt injection indicators, unicode tag characters (U+E0001), pasted credentials (AWS keys, `sk-ant-*`, PEM headers) |
| `oacb-mcp-guard.sh` | PreToolUse (MCP) | Known-malicious MCP servers (postmark-mcp), destructive MCP tool names, allowlist enforcement at strict/paranoid tiers |
| `oacb-config-audit.sh` | ConfigChange | Non-blocking; writes audit log on every change to `settings.json`, hook scripts, skills, or `CLAUDE.md` |

### 3. An adversarial corpus + conformance test harness

`adversarial-corpus/` contains 12 documented attack cases, each a Markdown file with CVE citation, OWASP/MITRE mapping, and expected hook behavior. `conformance-tests/` has a runner that pipes these cases as JSON into the hooks and verifies exit codes and stderr output. 65 test cases, ~95 tier evaluations. This lets you verify that a hook change doesn't regress coverage, and CI enforces it on every push.

### 4. A false-positive corpus

`false-positive-corpus/` contains 250+ legitimate developer commands that must *not* block at baseline tier — things like `rm -rf node_modules`, `git push --force-with-lease`, `curl https://api.github.com`. Without this, a strict denylist is useless in practice because it blocks normal work.

### 5. A threat model and honest non-claims

`threat-model.md` maps every rule to OWASP ASI 2026, MITRE ATLAS v5.4.0, and specific CVEs. `non-claims.md` lists 12 attack classes OACB explicitly does *not* cover — prompt injection via LLM content, DNS exfiltration, MCP rug-pulls, BYOD endpoints, CI runners, state actors. This is deliberately load-bearing: it's what makes the framework citable without creating false assurance.

---

## How the pieces connect

```
MDM push
  └─► managed-settings.{tier}.json  ←  controls Claude Code's permissions layer
         │
         └─► hooks:                  ←  enforce at the shell/tool boundary
               oacb-enforce.sh          (Bash commands)
               oacb-prompt-guard.sh     (user prompts)
               oacb-mcp-guard.sh        (MCP tool calls)
               oacb-config-audit.sh     (config changes → audit log)

conformance-runner.sh
  └─► pipes adversarial-corpus cases into hooks → verifies exit codes
  └─► CI enforces: every rule ID has a test, every schema validates, etc.
```

The `unbound oacb` CLI subcommand (not in this repo — lives in `unbound-cli`) is the install/audit/apply UX wrapper. This repo is the policy artifact itself: the settings files, hook scripts, test corpus, and documentation that the CLI deploys.

---

## What it is not

It's not a runtime control. Pattern-matching shell scripts at the host layer are defeated by any agent that's been prompt-injected to obfuscate its commands. OACB's own README points to network-layer controls (Unbound Gateway, Wiz, Palo Alto, CrowdStrike) as the correct architectural endpoint. OACB is the **auditable, MDM-deployable baseline** you deploy while those heavier controls are being procured — and the framework you cite in RFPs while you have them.
