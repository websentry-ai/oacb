#!/usr/bin/env bash
#
# oacb-config-audit.sh — OACB ConfigChange hook
#
# Fires when Claude Code detects a change to its configuration during a session.
# Used to detect:
#   - Injection of new hooks (CVE-2025-59536 class — hostile .claude/settings.json)
#   - Unauthorized skill installation
#   - CLAUDE.md modification (ASI06 memory poisoning)
#   - Managed-settings drift
#
# Does not block (ConfigChange is observational per Claude Code hook spec).
# Emits audit events that should be forwarded to Unbound backend / SIEM.
#
# Environment:
#   OACB_TIER                shadow | baseline | strict | paranoid
#   OACB_AUDIT_LOG           defaults to ~/.claude/hooks/oacb-audit.log
#   OACB_REMOTE_AUDIT_URL    optional; if set, POST audit events to this URL

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.claude/hooks/oacb-audit.log}"
OACB_REMOTE_AUDIT_URL="${OACB_REMOTE_AUDIT_URL:-}"
OACB_VERSION="0.2.0"

mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true

input="$(cat)"

# Parse what changed
event_json="$(echo "$input" | jq -c '. + {oacb_tier:"'"$OACB_TIER"'", oacb_version:"'"$OACB_VERSION"'", ts:"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'", hook:"ConfigChange"}' 2>/dev/null || echo '{"error":"parse-failure"}')"

# Local audit log
echo "$event_json" >> "$OACB_AUDIT_LOG" 2>/dev/null || true

# Detect high-signal config changes
changed_path="$(echo "$input" | jq -r '.path // .file // empty' 2>/dev/null)"
change_type="$(echo "$input" | jq -r '.change_type // .action // empty' 2>/dev/null)"

case "$changed_path" in
  *".claude/settings.json"*|*".claude/settings.local.json"*)
    # Claude Code settings changed mid-session — high signal
    echo "OACB audit: Claude Code settings.json modified during session ($change_type)" >&2
    ;;
  *".claude/hooks/"*)
    # Hook script changed — potential CVE-2025-59536 class attack
    echo "OACB alert: Claude Code hook script modified ($changed_path, $change_type). Investigate immediately." >&2
    ;;
  *".claude/skills/"*|*".claude/commands/"*|*".claude/agents/"*)
    # Skill / slash command / subagent modified
    echo "OACB audit: Claude Code extension point modified ($changed_path, $change_type)" >&2
    ;;
  */CLAUDE.md|*/AGENTS.md)
    # Agent-behavioral config changed — ASI06 memory poisoning
    echo "OACB audit: agent-behavioral config modified ($changed_path, $change_type)" >&2
    ;;
esac

# Optional remote audit forward (non-blocking)
if [[ -n "$OACB_REMOTE_AUDIT_URL" ]]; then
  (
    curl -fsSL --max-time 3 -X POST \
      -H "Content-Type: application/json" \
      -H "User-Agent: oacb-config-audit/$OACB_VERSION" \
      --data "$event_json" \
      "$OACB_REMOTE_AUDIT_URL" >/dev/null 2>&1 || true
  ) &
fi

exit 0
