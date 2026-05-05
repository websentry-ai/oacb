# Credential File Path Reads (vett.sh Research, 2025)

**Source:** vett.sh — "AI Coding Agent Credential Exfiltration: A Practical Survey" (2025)
**Date:** 2025
**CVE:** None assigned (class-level research)
**Status:** Open — direct file reads of credential paths are a permanent residual at the Bash-hook layer; managed-settings Read denylist is the primary OACB defense
**OWASP ASI:** ASI02 Tool Misuse & Exploitation
**MITRE ATLAS:** AML.T0024 Exfiltration via Cyber Means

## Research findings

vett.sh surveyed AI coding agents and found that agents given file-read capability read credential files when instructed by injected content. Unlike `env | grep` (which enumerates all credentials broadly), these attacks target specific known-sensitive file paths:

```bash
cat ~/.aws/credentials          # AWS long-term credentials
cat ~/.aws/config               # region + profile configuration
cat ~/.ssh/id_rsa               # RSA private key
cat ~/.ssh/id_ed25519           # Ed25519 private key
cat ~/.netrc                    # FTP/HTTP basic-auth credentials
cat ~/.config/gh/hosts.yml      # GitHub CLI OAuth token
cat ~/.config/gcloud/credentials.db  # GCP service account credentials
cat ~/.npmrc                    # npm publish token (//registry.npmjs.org/:_authToken=)
cat ~/.pypirc                   # PyPI upload credentials
cat ~/.docker/config.json       # Docker registry auth (base64-encoded)
```

## OACB coverage

OACB defends this class at the **managed-settings layer**, not the Bash hook layer.

The `managed-settings.*.json` files at all tiers include:

```json
"permissions": {
  "deny": [
    "Read(~/.aws/*)",
    "Read(~/.ssh/*)",
    "Read(~/.netrc)",
    "Read(**/.env)",
    "Read(**/.env.*)",
    "Read(~/.config/gh/*)",
    "Read(~/.gnupg/*)"
  ]
}
```

These deny rules apply to Claude Code's **Read tool** — they do not apply when the agent uses the Bash tool to run `cat`.

| Command | Bash hook (oacb-enforce.sh) | Managed-settings Read deny |
|---------|---------------------------|-----------------------------|
| `cat ~/.aws/credentials` (Bash tool) | exit 0 — hook has no `cat` + path denylist | N/A (Bash tool, not Read tool) |
| Read(~/.aws/credentials) (Read tool) | N/A | exit 2 — managed-settings deny |
| `cat ~/.aws/credentials` at paranoid tier | exit 2, OACB-PARANOID-001 | N/A |

**Test (hook residual, non-paranoid):** `cat ~/.aws/credentials` via Bash exits 0 from `oacb-enforce.sh` at baseline.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cat ~/.aws/credentials"}}' | \
  OACB_TIER=baseline ./baseline/claude-code/hooks/oacb-enforce.sh
# expected: exit 0 (hook does not block cat + path; managed-settings Read deny is the control)
```

## Important: why the hook doesn't block `cat`

Adding a `cat ~/.aws/*` deny rule to the Bash hook would require maintaining a duplicate list of credential paths that is already in managed-settings. More importantly, legitimate developer workflows include:

```bash
cat ~/.aws/credentials | grep -v secret  # viewing structure without exposing values
aws configure list                       # shows active configuration without raw keys
```

Blocking all `cat` against credential-adjacent paths would break these. The managed-settings Read denylist is the correct layer for this defense.

## Residual (see non-claims.md §3)

At baseline/strict tier, an agent instructed to use `cat` (Bash tool) instead of the Read tool bypasses the managed-settings Read denylist. At paranoid tier, OACB-PARANOID-001 blocks all Bash calls that the hook receives — but `cat` via Bash passes through `oacb-enforce.sh` even at paranoid (it's a Bash command, so the paranoid non-Bash check doesn't fire).

Full prevention: restrict shell access to the credential paths via OS-level file permissions, or use an AASB proxy that inspects Bash tool output for credential patterns.
