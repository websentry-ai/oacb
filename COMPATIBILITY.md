# OACB Compatibility Matrix

## Supported Claude Code versions

| OACB version | Claude Code range | Status | Notes |
|--------------|-------------------|--------|-------|
| 0.1.x | ≥ 2.1.83, < 3.0.0 | Supported | Auto mode available on Team/Enterprise/API plans |
| 0.1.x | ≥ 2.0.0, < 2.1.83 | Unsupported | Pre-auto-mode schema; use `permissions.deny` only |
| 0.1.x | < 2.0.0 | Incompatible | `managedSettings.json` schema mismatch |

## Managed-settings schema

OACB tracks the `managed-settings.json` schema published by Anthropic. Schema changes upstream will be mirrored in PATCH releases when they are backward-compatible; MINOR releases when they are not.

- v0.1 target: `managedSettings.schema@2.1.83`
- Fields OACB relies on:
  - `permissions.allow` / `permissions.deny` / `permissions.ask`
  - `permissions.defaultMode`
  - `permissions.allowManagedPermissionRulesOnly`
  - `permissions.allowManagedHooksOnly`
  - `permissions.allowManagedMcpServersOnly`
  - `permissions.disableAutoMode`
  - `permissions.disableBypassPermissionsMode`
  - `autoMode.environment`
  - `autoMode.soft_deny`
  - `autoMode.allow`
  - `hooks.PreToolUse`, `hooks.UserPromptSubmit`, `hooks.ConfigChange`

## unbound-cli compatibility

| OACB version | unbound-cli range | Status |
|--------------|-------------------|--------|
| 0.1.x | ≥ 1.N.0 (release containing `oacb` subcommand) | Required for `unbound oacb` commands |

Without `unbound-cli`, OACB can still be applied manually by copying `baseline/claude-code/managed-settings.<tier>.json` to the MDM managed-settings path for your platform:

- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux: `/etc/claude-code/managed-settings.json`
- Windows: HKLM registry + `C:\Program Files\ClaudeCode\managed-settings.json`

## Platform support

| Platform | OACB tier support | Notes |
|----------|-------------------|-------|
| macOS 14+ (Intel / Apple Silicon) | All tiers | Primary target platform |
| Ubuntu 22.04 LTS, 24.04 LTS | All tiers | Primary target platform |
| RHEL 8, 9 | All tiers | Landlock requires kernel ≥ 5.13 (RHEL 9) |
| Debian 12+ | All tiers | |
| Windows 11 (WSL2) | Baseline / Strict | Paranoid requires hook rewrites for PowerShell; v0.2 |
| Windows 11 (native) | Not yet supported | PowerShell hooks planned for v0.2 |

## Shell support for hooks

OACB v0.1 ships bash 3.2-compatible hooks (macOS default). Verified on:

- bash 3.2 (macOS default)
- bash 4.4+ (Linux default)
- bash 5.x
- zsh 5.9

Not supported in v0.1:

- PowerShell (Windows native) — v0.2
- fish, nushell — community-contributed ports welcome

## Jamf / Intune / Kandji

OACB's `managed-settings.<tier>.json` files can be pushed as a Jamf Custom Settings payload (preference domain: `com.anthropic.claude-code`) or an Intune Settings Catalog entry targeting the same preference domain.

Recommended deployment pattern:

1. Canary cohort (5 users) on shadow tier — 72 hours
2. Broader observation cohort (10% of fleet) on shadow tier — 2 weeks
3. Full fleet on shadow — 2 weeks of audit log review
4. Canary cohort on baseline — 72 hours
5. Observation cohort on baseline — 1 week
6. Full fleet on baseline

Each tier change is a separate MDM push. Do not skip tiers.

## Anthropic plan requirements

| Claude Code feature OACB uses | Pro | Max | Team | Enterprise | API |
|------------------------------|-----|-----|------|-----|-----|
| Permission modes (default, acceptEdits, plan) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Auto mode | ✗ | ✗ | ✓ | ✓ | ✓ |
| Managed settings | ✗ | ✗ | ✓ | ✓ | — |
| `disableBypassPermissionsMode` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `disableAutoMode` | ✗ | ✗ | ✓ | ✓ | — |
| Hooks | ✓ | ✓ | ✓ | ✓ | ✓ |
| ConfigChange hook | — | — | ✓ | ✓ | — |
| Compliance API | ✗ | ✗ | ✗ | ✓ | ✓ |
| Zero data retention | ✗ | ✗ | ✗ | ✓ | — |

Enterprise deployment of OACB strict or paranoid requires at minimum Team plan (for managed settings + auto mode control). Pro / Max users can apply baseline-compatible user settings but cannot enforce managed-settings lockdown.

## Anthropic release cadence tracking

OACB's release pipeline includes a weekly CI job that diffs the published `managed-settings.json` schema against the version OACB pins. Schema changes trigger an issue in this repo and a PATCH release within 7 days (or a MINOR release if the change is breaking).

Subscribe to [OACB release notifications](https://github.com/websentry-ai/oacb/releases) to stay current.
