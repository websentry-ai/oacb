# Credential Paste Detection (OACB-PROMPT-005)

**Pattern:** User accidentally pastes a secret (AWS key, API key, private key) into prompt
**OWASP ASI:** ASI01 Prompt Injection
**Rule:** OACB-PROMPT-005

## Scenario

A developer debugging an authentication failure copies their AWS credentials from a config file and pastes them directly into the Claude Code prompt along with their question. The credentials are now exposed in the model's context window, any conversation logs, and any audit trail.

```
Here is my AWS key for debugging: AKIAIOSFODNN7EXAMPLE and secret WJALRXUTNFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Can you help me figure out why my S3 calls are failing?
```

## Detected patterns

| Type | Pattern |
|------|---------|
| AWS access key | `AKIA[A-Z0-9]{16}` |
| AWS STS session key | `ASIA[A-Z0-9]{16}` |
| Anthropic API key | `sk-ant-[A-Za-z0-9_-]{20,}` |
| OpenAI API key | `sk-[A-Za-z0-9]{20,}` |
| GitHub personal access token | `ghp_[A-Za-z0-9]{36}` |
| GitHub OAuth token | `gho_[A-Za-z0-9]{36}` |
| PEM private key | `-----BEGIN ... PRIVATE KEY-----` |

## OACB behavior

OACB-PROMPT-005 blocks the prompt submission at all tiers, preventing the credential from being sent to the model. The user is prompted to remove the secret and re-submit.

**Expected:** exit 2, stderr contains `OACB-PROMPT-005`
