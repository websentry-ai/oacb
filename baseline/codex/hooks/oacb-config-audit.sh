#!/usr/bin/env bash
#
# oacb-config-audit.sh — OACB ConfigChange hook (Codex CLI agent)
#
# Fires when Codex detects a change to its configuration during a session.
# Does not block (ConfigChange is observational). Emits audit events.
#
# Environment:
#   OACB_TIER                shadow | baseline | strict | paranoid
#   OACB_AUDIT_LOG           defaults to ~/.codex/hooks/oacb-audit.log
#   OACB_REMOTE_AUDIT_URL    optional; if set, POST audit events to this URL

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.codex/hooks/oacb-audit.log}"
OACB_REMOTE_AUDIT_URL="${OACB_REMOTE_AUDIT_URL:-}"
OACB_VERSION="0.2.0"

mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true

input="$(cat)"

event_json="$(echo "$input" | jq -c '. + {oacb_tier:"'"$OACB_TIER"'", oacb_version:"'"$OACB_VERSION"'", ts:"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'", hook:"ConfigChange"}' 2>/dev/null || echo '{"error":"parse-failure"}')"

echo "$event_json" >> "$OACB_AUDIT_LOG" 2>/dev/null || true

changed_path="$(echo "$input" | jq -r '.path // .file // empty' 2>/dev/null)"
change_type="$(echo "$input" | jq -r '.change_type // .action // empty' 2>/dev/null)"

case "$changed_path" in
  *".codex/config.toml"*)
    echo "OACB audit: Codex config.toml modified during session ($change_type)" >&2
    ;;
  *".codex/hooks/"*)
    echo "OACB alert: Codex hook script modified ($changed_path, $change_type). Investigate immediately." >&2
    ;;
  */AGENTS.md|*/CLAUDE.md)
    echo "OACB audit: agent-behavioral config modified ($changed_path, $change_type)" >&2
    ;;
esac

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
