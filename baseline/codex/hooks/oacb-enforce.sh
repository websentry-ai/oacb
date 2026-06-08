#!/usr/bin/env bash
#
# oacb-enforce.sh — OACB PreToolUse hook for Bash tool (Codex CLI agent)
#
# Hook contract (Codex CLI, identical to Claude Code):
#   - Exit 0: allow. Tool proceeds.
#   - Exit 2 + stderr: HARD BLOCK; stderr visible to model. Tool does NOT run.
#   - stdout JSON {"reason":"..."} is surfaced to the model at block time.
#
# Environment:
#   OACB_TIER              shadow | baseline | strict | paranoid (default: baseline)
#   OACB_AUDIT_LOG         optional; defaults to ~/.codex/hooks/oacb-audit.log
#   OACB_MAX_INPUT_BYTES   optional size guard (default 131072)
#   OACB_SHARED_DIR        path to oacb shared scripts (default: same dir as this script)

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.codex/hooks/oacb-audit.log}"
OACB_MAX_INPUT_BYTES="${OACB_MAX_INPUT_BYTES:-131072}"
OACB_VERSION="0.2.1"
# Resolve OACB_SHARED_DIR: injected by install (env block in config.toml);
# falls back to the directory containing this script so the hook is self-contained
# after `unbound oacb apply` copies oacb-enforce-core.sh alongside it.
OACB_SHARED_DIR="${OACB_SHARED_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

# --- agent-specific emit_block (Codex: exit 2 + stdout reason JSON) ----------
# Must be defined BEFORE sourcing the core (core sets a trap that references it).

emit_block() {
  local reason="$1"
  local rule_id="${2:-OACB-UNKNOWN}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  command -v _audit_line >/dev/null 2>&1 && _audit_line "deny" "$rule_id" "$reason" || true
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

# shellcheck source=../../shared/oacb-enforce-core.sh
source "${OACB_SHARED_DIR}/oacb-enforce-core.sh"
