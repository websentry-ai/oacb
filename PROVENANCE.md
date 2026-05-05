# OACB Provenance

Every rule, adversarial test, threat-model entry, and documented CVE in OACB has a source. This file catalogs them for transparency and to support legal / licensing review.

---

## Release signing and provenance

Every release from v0.1.0 is signed and attested by the CI pipeline:

| Artifact | Mechanism | Verification |
|----------|-----------|--------------|
| `oacb-<version>.tar.gz` | cosign keyless (GitHub OIDC) | `cosign verify-blob` — see SECURITY.md |
| `oacb-<version>.tar.gz.sig` + `.crt` | Sigstore transparency log | Included in release assets |
| SLSA L2 provenance | `actions/attest-build-provenance@v2` | `gh attestation verify` — see SECURITY.md |

The signing identity is:
```
certificate-identity-regexp: https://github.com/websentry-ai/oacb/.github/workflows/release.yml@refs/tags/.*
certificate-oidc-issuer:      https://token.actions.githubusercontent.com
```

No private keys are used. All signatures are verifiable without contacting Unbound Security.

---

## Content licensing

- **All original OACB content** (rules, settings JSON, hook scripts, threat-model table, README, documentation): **Apache 2.0** — authored by Unbound Security, copyright 2026.
- **No vendored content** from Trail of Bits `claude-code-config`, OWASP working group drafts, MITRE ATLAS database dumps, or other CC-BY-SA / copyleft-licensed sources. OACB rules cover similar ground through independent authorship grounded in CVE research.
- **CVE descriptions and incident summaries** in threat-model.md and adversarial-corpus/cases/ are summaries of public research with attribution. Fair-use primary-source citation under US copyright law.

## CVE-grounded rules (public research)

| Rule IDs | Source | Researcher / Org | URL | License |
|---------|--------|------------------|-----|---------|
| OACB-RM-001, 002, 003 | CVE-2025-66032 | GMO Flatt Security (Ryotak) | https://flatt.tech/research/posts/pwning-claude-code-in-8-different-ways/ | Blog post — fair-use citation |
| OACB-OBF-001 (backslash/concatenation) | CVE-2025-66032 | GMO Flatt | Same | Same |
| OACB-OBF-002 (base64-pipe) | General technique | Multiple (Ona, Embrace The Red) | https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox | Same |
| OACB-OBF-003 (process substitution) | Flatt-adjacent | Multiple | — | — |
| OACB-OBF-004 (/proc/self/root) | CVE-2025-66032 | GMO Flatt | Same | Same |
| OACB-HIST-001 | CVE-2025-66032 | GMO Flatt | Same | Same |
| OACB-COMPOUND-001 | Adversa AI disclosure (April 2026) | Adversa AI | https://adversa.ai/blog/claude-code-security-bypass-deny-rules-disabled/ | Blog post — fair-use citation |
| OACB-PROMPT-001, 002 (invisible Unicode) | Pillar Security "Rules File Backdoor" (March 2025) | Pillar Security | https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents | Blog post — fair-use citation |
| OACB-PROMPT-003, 006 (instruction override, jailbreak) | General technique | Multiple (Anthropic public research, HiddenLayer) | https://www.anthropic.com/research/prompt-injection-defenses | Public research |
| OACB-PROMPT-005 (credential patterns) | Original authorship | Unbound Security | — | Apache 2.0 |
| OACB-MCP-001, 003, 004 (MCP allowlisting) | Invariant Labs tool-poisoning research | Invariant Labs | https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks | Blog post — fair-use citation |
| OACB-MCP-002 (postmark-mcp) | Semgrep disclosure (September 2025) | Semgrep | https://semgrep.dev/blog/2025/so-the-first-malicious-mcp-server-has-been-found-on-npm-what-does-this-mean-for-mcp-security/ | Blog post — fair-use citation |
| OACB-TF-001, 002, 003 | Replit incident + DataTalks.Club incident | Public incident reports | https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/ · https://frontierbeat.com/2026/03/07/claude-code-deletes-production-database-terraform-destroy-2026/ | News — fair-use citation |
| OACB-DB-001, 002, 003 | Public incident reports (Drizzle, others) | — | — | — |
| OACB-GIT-001 | General industry practice | — | — | — |
| OACB-NET-001 | General RCE class | Multiple | — | — |
| OACB-EVAL-001 | General practice | — | — | — |
| OACB-EXFIL-001 | Knostic research | Knostic | https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage | Blog post — fair-use citation |

## Threat model sources

- **OWASP Top 10 for Agentic Applications 2026** — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ (Creative Commons licensed; referenced by ASI IDs, not vendored)
- **OWASP LLM Top 10 (2025)** — https://owasp.org/www-project-top-10-for-large-language-model-applications/ (CC BY-SA 4.0; referenced only, not vendored)
- **MITRE ATLAS v5.4.0** — https://atlas.mitre.org/ (public matrix; ATLAS IDs referenced, not vendored)
- **Agents Rule of Two** — Meta / Anthropic / OpenAI / Google DeepMind joint publication, October 31 2025 — https://ai.meta.com/blog/practical-ai-agent-security/ and https://www.anthropic.com/research/prompt-injection-defenses

## Claude Code behavior reference

- Anthropic official Claude Code documentation: https://code.claude.com/docs/en/ (terms of use apply; referenced only)
- Claude Code permission modes, settings schema, hook system: https://code.claude.com/docs/en/permission-modes, https://code.claude.com/docs/en/settings, https://code.claude.com/docs/en/hooks

## Attribution policy

OACB acknowledges every researcher whose work informed a rule. We do not vendor their content. If a researcher believes OACB has failed to credit them appropriately, contact security@unboundsecurity.ai.

We will:
- Add attribution in PROVENANCE.md, README.md acknowledgements, and release notes
- Retroactively credit in CHANGELOG if missed
- Work with researchers on any concerns about derivative-work characterization

## Non-attribution of bypass PoCs

The adversarial corpus includes command payloads that were disclosed in public research. We reproduce the payloads for conformance testing (not weaponization). Working exploits against any system other than a Claude Code instance you own are outside OACB's intent and violate the Anthropic Usage Policy.

## Updating this file

- Every new rule: add a row to the table above
- Every MAJOR release: review and refresh attributions
- Every disputed attribution: investigated and resolved within 14 days of report

OACB is built on the security community's work. Attribution is not optional.
