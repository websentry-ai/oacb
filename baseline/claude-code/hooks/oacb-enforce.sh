#!/usr/bin/env bash
#
# oacb-enforce.sh — OACB PreToolUse hook for Bash tool (Claude Code agent)
#
# Hook contract (per Claude Code docs):
#   - Exit 0: allow. Tool proceeds.
#   - Exit 2 + stderr: HARD BLOCK; stderr visible to model. Tool does NOT run.
#   - stdout JSON {"reason":"..."} is surfaced to the model at block time.
#
# Environment:
#   OACB_TIER              shadow | baseline | strict | paranoid (default: baseline)
#   OACB_AUDIT_LOG         optional; defaults to ~/.claude/hooks/oacb-audit.log
#   OACB_MAX_INPUT_BYTES   optional size guard (default 131072)
#   OACB_SHARED_DIR        path to oacb shared scripts (default /usr/local/share/oacb/shared)

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.claude/hooks/oacb-audit.log}"
OACB_MAX_INPUT_BYTES="${OACB_MAX_INPUT_BYTES:-131072}"
OACB_VERSION="0.2.0"
OACB_SHARED_DIR="${OACB_SHARED_DIR:-/usr/local/share/oacb/shared}"

# --- agent-specific emit_block (Claude Code: exit 2 + stdout reason JSON) --
# Must be defined BEFORE sourcing the core (core sets a trap that references it).

emit_block() {
  local reason="$1"
  local rule_id="${2:-OACB-UNKNOWN}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  # _audit_line is defined in the core; guard against the rare signal-during-source case
  command -v _audit_line >/dev/null 2>&1 && _audit_line "deny" "$rule_id" "$reason" || true
  # stdout JSON: Claude Code surfaces the `reason` field to the model
  if command -v jq >/dev/null 2>&1; then
    jq -cn --arg rule "$rule_id" --arg r "$reason" --arg tier "$OACB_TIER" \
      '{"reason": ("OACB [\($rule)] SECURITY POLICY BLOCK (\($tier) tier): \($r). This is a permanent policy decision — NOT a sandbox error, transient failure, or permissions issue. Do NOT attempt workarounds, alternative commands, scripts, or indirect methods to achieve the same result. Explain to the user what was blocked and why, then stop.")}'
  else
    local esc="${reason//\"/\\\"}"
    printf '{"reason":"OACB [%s] SECURITY POLICY BLOCK (%s tier): %s. Permanent policy — do NOT attempt workarounds. Explain to the user what was blocked and stop."}\n' "$rule_id" "$OACB_TIER" "$esc"
  fi
  printf 'OACB %s [%s]: %s\n' "$OACB_TIER" "$rule_id" "$reason" >&2
  exit 2
}

# Source shared rule logic (defines _audit_line, emit_audit_allow, emit_audit_warn,
# sets trap, runs all enforcement checks, and exits 0 or 2).
# shellcheck source=../../shared/oacb-enforce-core.sh
source "${OACB_SHARED_DIR}/oacb-enforce-core.sh"
