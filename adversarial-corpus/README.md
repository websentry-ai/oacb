# OACB Adversarial Corpus

Every deny rule in the OACB baseline ships with at least one adversarial test case that demonstrates:

1. The attack the rule is designed to block
2. That the OACB-hardened hook + managed-settings actually blocks it
3. That legitimate uses of similar commands (false-positive corpus) pass through

This directory is the **primary deliverable** of OACB — before the rules, before the README. If the adversarial corpus is weak, the baseline is decorative.

## Sources

Every case cites a real CVE, public PoC, published research, or documented incident. Unverified / speculative cases live in `candidates/` until a working PoC lands.

## Structure

```
adversarial-corpus/
├── README.md                       (this file)
├── cases/
│   ├── bash-bypass/
│   │   ├── cve-2025-66032-flatt-8way.md
│   │   ├── cve-2025-54794-inverseprompt-path.md
│   │   ├── cve-2025-54795-inverseprompt-echo.md
│   │   ├── adversa-compound-command.md
│   │   ├── variable-expansion-ifs.md
│   │   ├── backslash-escaped-binaries.md
│   │   ├── proc-self-root-traversal.md
│   │   ├── base64-eval.md
│   │   ├── history-manipulation.md
│   │   └── abbreviated-git-args.md
│   ├── read-exfil/
│   │   ├── knostic-env-leakage.md
│   │   ├── vett-sh-credential-paths.md
│   │   └── env-enumeration.md
│   ├── webfetch-exfil/
│   │   └── arxiv-2510.09093-search-exfil.md
│   ├── dns-exfil/
│   │   └── cve-2025-55284-dns-channel.md
│   ├── hook-rce/
│   │   └── cve-2025-59536-cloned-repo-settings.md
│   ├── mcp-supply-chain/
│   │   ├── invariantlabs-tool-poisoning.md
│   │   ├── postmark-mcp-in-the-wild.md
│   │   └── cyberark-poison-everywhere.md
│   ├── prompt-injection/
│   │   ├── pillar-rules-file-backdoor.md
│   │   ├── cline-issue-title.md
│   │   └── embrace-the-red-ascii-smuggling.md
│   ├── destructive-patterns/
│   │   ├── replit-db-wipe.md
│   │   ├── datatalks-terraform-destroy.md
│   │   ├── rm-rf-home-issue-10077.md
│   │   └── drizzle-force-push.md
│   └── classifier-manipulation/
│       ├── checkmarx-reviewer-bypass.md
│       └── persuasive-framing.md
├── candidates/                     (cases without working PoC — pending)
└── runner/
    ├── conformance-runner.sh        (CI harness)
    └── expected.json                (per-case expected block/allow outcome)
```

## Per-case file format

Each case file follows the same shape:

```markdown
# CVE-YYYY-NNNNN / <source>-<name>

**Source:** <researcher, org, URL>
**Date:** <YYYY-MM-DD>
**CVE:** <CVE ID if assigned>
**Status:** <open | fixed-in-claude-code-X.Y.Z>
**OWASP ASI:** <IDs>
**MITRE ATLAS:** <technique IDs>

## Attack

<One paragraph describing the attack mechanism.>

## Payload

\`\`\`bash
# The actual bypass command or sequence
\`\`\`

## Why it works (without OACB)

<Technical explanation — which parser, which precedence rule, which assumption is violated.>

## OACB coverage

**Rule ID:** <OACB-XXX-NNN>
**Tier:** <baseline | strict | paranoid> and above
**Expected outcome:** BLOCK with rule ID and reason in stderr

## Test

\`\`\`bash
# Exact invocation the conformance runner uses
echo '{"tool_name":"Bash","tool_input":{"command":"<payload>"}}' | \\
  OACB_TIER=baseline /usr/local/share/oacb/hooks/oacb-enforce.sh
echo "exit=$?"
\`\`\`

## Expected

- exit code: 2
- stderr contains: `OACB-XXX-NNN`

## False-positive guardrails

<Legitimate commands that look similar but must NOT block. Reference false-positive-corpus/ entries.>
```

## Running the corpus locally

```bash
# Full run (all cases, all tiers)
./runner/conformance-runner.sh

# Run against a specific tier
OACB_TIER=strict ./runner/conformance-runner.sh

# Run a single case
./runner/conformance-runner.sh cases/bash-bypass/cve-2025-66032-flatt-8way.md
```

The runner reports:

- Cases that correctly blocked (expected: block)
- Cases that correctly allowed (false-positive corpus: expected allow)
- **Failures** — cases where the OACB rule did not fire as expected (this is the bug)
- Warnings — rules that matched but not for the expected reason (indicates overly-broad rule)

## CI integration

The corpus runs on every PR. Rules cannot be added without a passing adversarial case. The CI check blocks merge.

## Contribution guidelines

To add a case:

1. Create a new file in the appropriate `cases/` subdirectory following the per-case format
2. Ensure the case cites a verifiable source (CVE, blog post, published PoC)
3. If the source is not public yet, coordinate via SECURITY.md before submitting
4. Add the expected outcome to `runner/expected.json`
5. Verify the runner passes locally
6. Open a PR — CI must pass before merge

To add a new CVE class without a working PoC, add to `candidates/` with a note on what is needed to promote it.

## Known limitations

The adversarial corpus is **never exhaustive**. Pattern-match host-layer controls are defeated by any input the agent can construct. We ship the corpus to (a) prove coverage for the documented CVE classes, (b) catch regressions, (c) raise the bar for novel bypasses — not to guarantee no bypass is possible.

For deterministic enforcement, see the Runtime Enforcement section of the main README.
