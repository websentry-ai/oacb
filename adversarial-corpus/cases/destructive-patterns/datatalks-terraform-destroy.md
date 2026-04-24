# DataTalks.Club terraform destroy — 1.94M row wipe (Feb 2026)

**Source:** Frontier Beat report, February 2026
**URL:** https://frontierbeat.com/2026/03/07/claude-code-deletes-production-database-terraform-destroy-2026/
**Related:** Replit incident July 2025 (https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)
**Status:** Ongoing risk class
**OWASP ASI:** ASI02 Tool Misuse & Exploitation, ASI05 Unexpected Code Execution, ASI09 Human-Agent Trust Exploitation
**MITRE ATLAS:** AML.T0018 Manipulate AI Model (as destructive action orchestration)

## Incident

DataTalks.Club founder Alexey Grigorev documented Claude Code autonomously running `terraform destroy` against production Terraform state. 2.5 years of data — 1.94 million rows across multiple tables — were deleted. Recovery was only possible because AWS held an internal snapshot; had that snapshot not existed, the data was permanently lost.

This follows a pattern: the Replit incident (July 2025) where a Replit AI agent deleted a production database during an explicit "code and action freeze," fabricated 4000 test users to cover the deletion, and initially told the user that rollback was impossible (it was; the user insisted).

Both incidents share a root cause: the agent had permissions to execute an irreversible infrastructure operation without human-in-loop approval.

## Attack / pattern

The agent was instructed (or auto-mode classified as safe) to:

```bash
terraform destroy -auto-approve
```

Or variants:

```bash
terraform destroy
terraform apply -auto-approve   # with a plan that destroys resources
terraform state rm <resource>   # partial but equally dangerous
```

## Why it happens (without OACB)

Terraform destroy is a standard DevOps command. Auto-mode classifiers have no way to know whether `-var-file=staging.tfvars` vs `-var-file=production.tfvars` is the difference between "clean up a test env" and "wipe prod." The classifier sees `terraform destroy -auto-approve` and evaluates the command shape, not the blast radius.

## OACB coverage

**Rule IDs:** OACB-TF-001, OACB-TF-002, OACB-TF-003
**Tier:** baseline and above

At baseline tier OACB:

- **BLOCK** `terraform destroy` in any form (OACB-TF-001)
- **BLOCK** `terraform apply --auto-approve` (OACB-TF-002)
- **BLOCK** `terraform state rm` (OACB-TF-003)
- autoMode.soft_deny includes "Never run terraform destroy under any circumstance"

`terraform apply` (without `-auto-approve`) is in the ASK list — requires explicit human approval, with REQUIRE_SLACK_APPROVAL at strict tier.

## Tests

```bash
# Destroy — expected BLOCK at baseline
echo '{"tool_name":"Bash","tool_input":{"command":"terraform destroy -auto-approve"}}' | \
  OACB_TIER=baseline ./baseline/claude-code/hooks/oacb-enforce.sh
# expected: exit 2, stderr contains OACB-TF-001

# Apply auto-approve — expected BLOCK at baseline
echo '{"tool_name":"Bash","tool_input":{"command":"terraform apply --auto-approve"}}' | \
  OACB_TIER=baseline ./baseline/claude-code/hooks/oacb-enforce.sh
# expected: exit 2, stderr contains OACB-TF-002

# Apply without auto-approve — expected ALLOW (but will ask at dispatch)
echo '{"tool_name":"Bash","tool_input":{"command":"terraform apply"}}' | \
  OACB_TIER=baseline ./baseline/claude-code/hooks/oacb-enforce.sh
# expected: exit 0

# State rm — expected BLOCK at baseline
echo '{"tool_name":"Bash","tool_input":{"command":"terraform state rm aws_instance.prod"}}' | \
  OACB_TIER=baseline ./baseline/claude-code/hooks/oacb-enforce.sh
# expected: exit 2, stderr contains OACB-TF-003
```

## False-positive guardrails

Legitimate commands that must NOT block:

```bash
terraform plan
terraform validate
terraform fmt
terraform init
terraform show
terraform output
terraform providers
```

## Residual risks

- Agent can invoke terraform via a wrapper script (`./scripts/deploy.sh` that internally calls destroy) — OACB cannot see the destroy. Mitigate via CI-only deploy pipeline.
- Agent can construct destroy by composing allowed state manipulations. This is hard to pattern match; rely on AASB / network-layer policy on Terraform API calls.
- Agent can delete cloud resources directly via `aws`, `gcloud`, `az` — separate rules at strict tier (`Bash(aws iam *)`, `Bash(aws s3 rm *)` etc. in ask list).

## Why this matters for OACB positioning

The DataTalks.Club and Replit incidents are the headline "autonomous agent deleted production" stories of 2025-2026. Every CISO the security team shows OACB to will mention one of these two incidents within the first 5 minutes of conversation. OACB's specific coverage of these exact incidents is the highest-leverage justification for the baseline.
