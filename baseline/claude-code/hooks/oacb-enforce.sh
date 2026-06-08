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
OACB_VERSION="0.2.1"
OACB_SHARED_DIR="${OACB_SHARED_DIR:-/usr/local/share/oacb/shared}"
# Fall back to the hook's own directory when the MDM-default location is
# unavailable. This lets CLI installs work without having to set
# OACB_SHARED_DIR explicitly; MDM deployments that pre-populate
# /usr/local/share/oacb/shared keep their existing behavior.
if [[ ! -f "${OACB_SHARED_DIR}/oacb-enforce-core.sh" ]]; then
  _oacb_orig_shared_dir="$OACB_SHARED_DIR"
  OACB_SHARED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # Diagnostic: emit a structured audit line + stderr breadcrumb so fleet
  # operators can detect mis-configured MDM paths from the audit log alone.
  # Suppressed when OACB_DISABLE_FALLBACK_WARN=1 (e.g. self-host installs
  # that intentionally don't ship the MDM path).
  if [[ "${OACB_DISABLE_FALLBACK_WARN:-0}" != "1" ]]; then
    mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
    printf '{"ts":"%s","decision":"info","tier":"%s","rule":"OACB-MDM-FALLBACK","reason":"shared-core not found at %s — falling back to %s","oacb_version":"%s"}\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$OACB_TIER" \
      "$_oacb_orig_shared_dir" \
      "$OACB_SHARED_DIR" \
      "$OACB_VERSION" >>"$OACB_AUDIT_LOG" 2>/dev/null
    printf 'OACB: shared-core not found at %s — using fallback %s\n' \
      "$_oacb_orig_shared_dir" "$OACB_SHARED_DIR" >&2
  fi
  unset _oacb_orig_shared_dir
fi

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
