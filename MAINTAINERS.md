# OACB Maintainers

## Primary

- **Vignesh Subbiah** — CTO, Unbound Security
  - GitHub: [@vsubbiah](https://github.com/vsubbiah) (verify handle before publication)
  - Email: oacb@unboundsecurity.ai
  - Areas: framework direction, threat model, release decisions

## Secondary

- **Sumit Badsara** — Engineer, Unbound Security
  - Areas: `unbound oacb` CLI subcommand integration, `unbound-cli` extension
- **Pugazhendhi** — Engineer, Unbound Security
  - Areas: `oacb/setup.py` + `oacb/mdm/setup.py` in `websentry-ai/setup`, backend integration

## Security contact

Security reports: **security@unboundsecurity.ai** (72h ack SLA — see SECURITY.md).

## Escalation path

If a primary or secondary maintainer is unresponsive for > 30 days on a security report:

1. Reply to your initial report with `[ESCALATION]` in subject line
2. Open a private GitHub Security Advisory on this repository
3. Contact Vignesh Subbiah (CTO, Unbound Security) — vis@unboundsecurity.ai

## Governance

OACB v0.1 is a single-vendor-maintained project. Unbound Security is the primary maintainer.

Governance roadmap:
- **v0.1 – v0.3:** Single-vendor maintained. External contributions welcome via PR. No governance charter.
- **v0.4+:** Adopt at least one non-Unbound maintainer. Publish a GOVERNANCE.md with contribution RFCs, steering committee, and deprecation policy.
- **v1.0:** Transfer to a neutral foundation (CNCF, Linux Foundation, OWASP, or similar) if external interest supports it. Governance transition is contingent on community uptake, not preset.

Until v0.4, pull requests that substantively change rule content, threat model, or maturity tier definitions require sign-off from a primary maintainer. Documentation, adversarial corpus additions, and false-positive corpus additions have a lighter review bar.

## Expected response time

| Activity | SLA | Notes |
|----------|-----|-------|
| Security report acknowledgment | 72h | Committed in SECURITY.md |
| Security triage response | 7d | Severity assessment, remediation plan |
| Security fix (high severity) | 30d best-effort | Coordinated disclosure window is 90d |
| PR review for contributions | 14d best-effort | Longer for rule / threat-model changes |
| Issue response | best-effort | No committed SLA |

## Conflict of interest

OACB is maintained by Unbound Security, which ships AASB (Agent Access Security Broker, aka Unbound Gateway). The README's Runtime Enforcement section names the AASB as one of the runtime-enforcement options, alongside competitor products (Wiz AI-APP, Palo Prisma AIRS, CrowdStrike Falcon AIDR, Snyk Agent Security, Microsoft Agent Governance Toolkit). We commit to:

- Naming competitor products honestly in documentation
- Not reviewing threat-model rules in a way that disadvantages non-Unbound runtime options
- Accepting contributions from practitioners at competing vendors on the same terms as any other contributor
- Disclosing Unbound affiliation in any external talks or press referencing OACB

If a conflict-of-interest concern arises, raise it via security@unboundsecurity.ai or escalate to Vignesh Subbiah directly.
