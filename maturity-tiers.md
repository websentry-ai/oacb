# OACB Maturity Tiers — Shadow / Baseline / Strict / Paranoid

Every OACB-adopting organization should progress through the tiers. Jumping directly to strict or paranoid on a fleet of working developers will break workflows and generate revolt. Jumping to baseline without a 2-week observation window in shadow mode will generate false-positive support tickets that erode security-team credibility.

This file documents each tier's deltas from the baseline reference, expected workflow friction, and migration guidance.

---

## Tier 0: Shadow

**Action:** AUDIT only. Hook evaluates rules and logs decisions but never blocks.
**Auto mode:** allowed (classifier-gated). `disableAutoMode` JSON field is unset.
**Hook exit code:** always 0 (advisory only)
**MCP allowlist:** observation mode — flags unapproved MCP servers in audit log but does not block install

### How shadow differs from baseline

```jsonc
{
  "permissions": {
    "deny": [],     // all deny rules moved to an audit-only log
    "ask": [],      // all ask rules bypassed
    "allow": [      // copied from baseline as-is
      /* ... */
    ]
  },
  "autoMode": {
    "soft_deny": [/* from baseline, advisory only */]
  },
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "/usr/local/share/oacb/hooks/oacb-enforce.sh",
        "timeout": 5000,
        "env": { "OACB_TIER": "shadow" }
      }]
    }]
  }
}
```

The hook script checks `OACB_TIER=shadow` and emits audit entries instead of exiting 2.

### Intended use

- **First 2 weeks of any OACB rollout.** You want data on what *would* have been blocked before you turn on enforcement.
- Post-rollout regression testing when a new rule ships. Deploy as `shadow` for 72 hours first, review the audit log, then graduate.

### Expected workflow friction

**Zero.** Developers see no difference in behavior. Every tool call proceeds.

### Success criteria to graduate to baseline

- Audit log shows < 5 rules with > 10% "would-block" rate against legitimate workflows (indicates a false-positive to fix before enforcement)
- No rule shows > 50% hit rate (indicates either overly broad rule or an actual attack in progress — investigate)
- At least one week of observation across a representative sample of developers

---

## Tier 1: Baseline

**Action:** WARN on grey, BLOCK on CVE-mapped destructives. **Recommended default enterprise tier.**
**Auto mode:** allowed (classifier-gated). `disableAutoMode` JSON field is unset.
**Hook exit code:** 2 (hard block) on deny matches; 0 on warn/allow
**MCP allowlist:** user-level allowlist enforced

### What baseline blocks

- Destructive rm (`rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, `rm -rf *`)
- `terraform destroy`, `terraform apply --auto-approve`, `terraform state rm`
- Force-push to main / master / release branches
- Database-destructive migration commands (`drizzle-kit push --force`, `prisma migrate reset`, `alembic downgrade`)
- Remote-to-shell pipe patterns (`curl | bash`) — with trusted-installer allowlist
- `history -s/-a`, `eval` on untrusted input
- Read of `.env*`, `.ssh/`, `.aws/credentials`, `.netrc`, `.gh/`, `.kube/config`, `.gnupg/`, shell rc files
- Write/Edit against `.claude/`, `.cursor/`, `.codex/`, `CLAUDE.md`, `AGENTS.md`
- Compound command with > 10 separators (Adversa bypass class)
- `/proc/self/root/` path traversal (Flatt sandbox-bypass class)
- Backslash-escaped binary invocations (`\rm`, `\curl`)
- Base64-decode piped to shell

### What baseline asks (human approval required)

- `git push`, `npm publish`, `cargo publish`, etc.
- `docker push`, `kubectl apply/delete/exec`, `helm install/upgrade`
- `terraform apply` (not `-auto-approve`), `terraform import`
- `aws iam`, `aws s3 rm`, `gcloud iam`, `az role`
- Writes to top-level project manifests (`package.json`, `Cargo.toml`, `go.mod`, `pyproject.toml`)

### Expected workflow friction

- **First 1-3 days:** 5-10% of developers hit an ask prompt they did not expect (typically on `git push` or `kubectl`). Normalize within 1 week as developers adapt.
- **Ongoing:** < 1% false-positive rate on the 200+-command false-positive corpus. Any rule exceeding 5% false-positive rate in production is a bug — file an issue with the command and OACB rule ID.

### Success criteria to graduate to strict

- 30+ days at baseline with < 3% developer complaint rate
- No documented productivity loss from baseline rules in retros
- Security team has reviewed audit log and wants tighter controls for higher-risk teams

---

## Tier 2: Strict

**Action:** BLOCK all deny patterns; REQUIRE_SLACK_APPROVAL on grey. Intended for pre-production, regulated teams, or teams handling customer data.
**Auto mode:** allowed (classifier-gated) + `allowManagedPermissionRulesOnly: true` means user/project rules cannot override managed denies. `disableAutoMode` JSON field is unset.
**Hook exit code:** 2 on deny; out-of-band Slack approval flow on ask
**MCP allowlist:** strict allowlist (managed-settings enforced)

### Additions over baseline

Adds deny patterns:

```
"Bash(compound-command with > 10 separators)"   // baseline: warn; strict: block
"Bash(sudo *)"                                   // no sudo without explicit approval
"Bash(chmod -R *)" "Bash(chown -R *)"
"Bash(mount *)" "Bash(umount *)"
"Bash(iptables *)" "Bash(nft *)"
"Bash(ssh-keygen *)" "Bash(gpg --import*)"

"Read(/etc/**)"  "Read(/var/log/**)"
"Write(/etc/**)"

"WebFetch(domain:*)"                             // strict tier: managed allowlist only
```

Additions to `permissions.ask` → move everything to REQUIRE_SLACK_APPROVAL via hook-initiated approval flow (calls unbound-cli's existing `/v1/hooks/pretool/approval-status` endpoint; developer's Slack gets a message; approver must click approve within 4 hours).

Sets:

```jsonc
{
  "permissions": {
    "allowManagedPermissionRulesOnly": true,
    "allowManagedHooksOnly": true,
    "allowManagedMcpServersOnly": true
  }
}
```

### Expected workflow friction

- **Moderate-high.** Developers will hit approval prompts 2-5 times per work day for anything touching production or customer data.
- Developers on on-call rotation need pre-approved approval bypasses for SEV1 response (specific `kubectl exec` to designated prod pods, for example). Plan the exception mechanism before rolling out.

### Migration guidance

- Run strict tier against an internal canary team for 2 weeks before fleet rollout
- Have a documented exception process for SEV response
- Set 4-hour Slack approval SLA — if approvers are slow, developers route around
- Train approvers: approval means you read and agree, not rubber-stamp

---

## Tier 3: Paranoid

**Action:** `permissions.disableAutoMode: "disable"` — auto mode is turned off entirely. BLOCK all defaults. ASK on anything not explicitly allowed.
**Auto mode:** **disabled**. `disableAutoMode` JSON value is `"disable"`. Agent operates as review-only.
**Hook exit code:** 2 on deny; Slack approval on ask
**MCP allowlist:** managed-only, very small set

### Intended use

- **FedRAMP deployments** (agent autonomy is a compliance risk)
- **Teams handling classified data** (explicit human-in-loop required)
- **Highly sensitive repos** (crypto, financial infrastructure)
- **Regulatory-reportable environments** (EU AI Act Article 14 flows)

### Additions over strict

```jsonc
{
  "permissions": {
    "disableAutoMode": "disable",
    "disableBypassPermissionsMode": "disable",

    "allow": [
      // VERY SMALL allowlist — read-only operations only by default
      "Bash(ls *)", "Bash(cat *)", "Bash(grep *)",
      "Bash(git status *)", "Bash(git diff *)", "Bash(git log *)",
      "Read(./**)"
    ],
    "ask": [
      // Everything else requires explicit human approval
    ]
  }
}
```

MCP allowlist reduced to 2-3 internal servers only. No GitHub MCP, no filesystem MCP, no web-search MCP.

### Expected workflow friction

- **High.** Agent operates as a reviewer / analyst, not an executor. Every action is gated.
- Suitable for workflows where the agent suggests and a human executes (the original Copilot-style model, not the autonomous-execution model).

### Migration to paranoid

- Do not migrate a whole fleet to paranoid. Migrate specific repos or specific project roots.
- Document explicitly: "Claude Code on <repo> is in OACB paranoid tier. Expected behavior is review-only. Automation lives in CI with a separate OACB CI profile."
- Coordinate with the EU AI Act Article 14 human-oversight obligations if applicable.

---

## Tier progression matrix

Recommended progression over 90 days:

| Day | Tier | Who |
|-----|------|-----|
| 0-14 | Shadow | All MDM-enrolled laptops |
| 15-44 | Baseline | All MDM-enrolled laptops |
| 45+ | Strict | Security-adjacent teams (AppSec, SRE, platform) |
| 45+ | Baseline | All other developers |
| as-needed | Paranoid | Specific regulated projects / repos |

Do not skip shadow. Do not skip baseline before strict. Running `unbound oacb apply --tier baseline` on day zero without a shadow observation period is the single most common reason security-team credibility erodes during AI-coding-agent rollouts.

---

## Customization

Enterprises should modify the baseline JSONs, not write their own from scratch. Maintain a `<org>-oacb-overrides.json` file that layers on top of the OACB baseline — add org-specific denylist entries (prod host patterns, custom tooling), extend the allowlist for approved internal CLI tools, and set the exact `autoMode.environment` for your source control, cloud accounts, and CI systems.

The `unbound oacb apply --overrides <path>` flag accepts this overlay and merges it onto the chosen tier before pushing to backend.
