# OACB Roadmap

Target order, not calendar. Dates are omitted intentionally (avoiding the reputational time-bomb of missed public commitments).

## v0.1.0 — Claude Code Auto Mode Profile

- [x] Name locked (OACB — Open Autonomous Coding-agent Baseline)
- [x] Blocker decisions (license Apache 2.0; backend schema deferred; shadow default; best-effort OSS + 72h SLA)
- [ ] README, SECURITY.md, MAINTAINERS.md, PROVENANCE.md, COMPATIBILITY.md, non-claims.md
- [ ] Managed-settings tiers: shadow, baseline, strict, paranoid
- [ ] PreToolUse hook with fail-closed semantics (oacb-enforce.sh)
- [ ] UserPromptSubmit hook for prompt-injection flagging (oacb-prompt-guard.sh)
- [ ] ConfigChange hook for managed-settings audit (oacb-config-audit.sh)
- [ ] MCP PreToolUse hook (oacb-mcp-guard.sh)
- [ ] Adversarial corpus: 8 Flatt bypass variants, Cymulate InversePrompt, Adversa compound, Embrace The Red DNS, Invariant MCP, Pillar rules-file-backdoor, compound-command, Replit / DataTalks destructive patterns
- [ ] False-positive corpus: 200+ legitimate dev commands
- [ ] Conformance test harness (conformance-runner.sh + expected.json)
- [ ] `unbound oacb` subcommand merged to unbound-cli
- [ ] cosign-signed releases + SLSA Level 2+ provenance
- [ ] JSON Schema for settings format
- [ ] CLAUDE.md.example showing agent-behavioral rules

## v0.1.1 — Control mapping

- [ ] NIST AI RMF crosswalk (GOVERN / MAP / MEASURE / MANAGE)
- [ ] SOC 2 CC6 + CC7 + CC8 trust services criteria mapping
- [ ] ISO/IEC 42001 (AI management system) mapping
- [ ] CIS Controls v8.1 AI/LLM Companion Guide mapping
- [ ] CSA Agentic NIST AI RMF Profile v1 crosswalk
- [ ] EU AI Act article coverage note (Articles 3, 4, 14, 15, 26, 50)
- [ ] Vanta / Drata automated-evidence integration doc
- [ ] "How to cite OACB in your RFP responses" guide

## v0.2 — Cursor + bypassPermissions profile

- [ ] OACB Cursor Agent Mode Profile (baseline JSON + hooks)
- [ ] OACB Claude Code bypassPermissions Profile (separate threat model — different gating)
- [ ] CI profile (`claude -p` headless + GitHub Actions) — covers the GTG-1002 / Replit class
- [ ] MCP allowlist catalog (known-good community MCP servers with content hashes)
- [ ] Governance: add one non-Unbound maintainer

## v0.3 — Codex + Gemini + third-party review

- [ ] OACB Codex Autonomous Profile
- [ ] OACB Gemini CLI Profile
- [ ] Trail of Bits / NCC Group / IOActive independent review published
- [ ] Governance charter (GOVERNANCE.md) + contribution RFC process
- [ ] Neutral-org migration evaluated

## v0.4 — Devin + multi-agent + expansion

- [ ] OACB Devin Profile
- [ ] ASI07 Inter-Agent Communication coverage
- [ ] ASI08 Cascading Agent Failures coverage
- [ ] Non-coding autonomous agents (SRE bots, customer-support agents) as sibling OACB profiles

## v1.0 — Stability commitment

- [ ] SemVer stability commitment
- [ ] Deprecation policy (N-2 Claude Code versions supported)
- [ ] Foundation transfer decision (CNCF / Linux Foundation / OWASP / independent)

## Topics tracked but not scheduled

- **Windows-native PowerShell** — Claude Code on Windows is a different shell surface; hooks need rewrites
- **Devcontainer / codespaces profile** — different filesystem isolation model
- **SSH-remote Claude Code** — MDM profile does not reach; needs server-side install path
- **Air-gapped deployments** — remote-control mode (local exec + web UI for approvals)
- **Mobile approval flow** — Slack approval via REQUIRE_SLACK_APPROVAL works; iOS / Android approval UX could be first-class
