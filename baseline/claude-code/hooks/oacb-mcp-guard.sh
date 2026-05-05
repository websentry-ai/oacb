#!/usr/bin/env bash
#
# oacb-mcp-guard.sh — OACB PreToolUse hook for MCP tool calls
#
# Matcher: mcp__.*
#
# Defends against:
#   - Tool-description rug-pull (Invariant Labs research)
#   - Unapproved MCP server usage
#   - MCP tools with known destructive capabilities
#   - Supply-chain attacks via typo-squatted or compromised MCP packages
#
# Environment:
#   OACB_TIER                shadow | baseline | strict | paranoid
#   OACB_MCP_ALLOWLIST_FILE  path to an allowlist of permitted mcp__server__tool combos
#                            (installed by `unbound oacb apply`; default ~/.claude/oacb-mcp-allowlist.json)

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.claude/hooks/oacb-audit.log}"
OACB_MCP_ALLOWLIST_FILE="${OACB_MCP_ALLOWLIST_FILE:-$HOME/.claude/oacb-mcp-allowlist.json}"
OACB_VERSION="0.1.0"

emit_block() {
  local reason="$1"
  local rule_id="${2:-OACB-MCP-UNKNOWN}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","decision":"deny","tier":"%s","rule":"%s","reason":"%s","hook":"PreToolUse-MCP","oacb_version":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OACB_TIER" "$rule_id" "${reason//\"/\\\"}" "$OACB_VERSION" \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  if command -v jq >/dev/null 2>&1; then
    jq -cn --arg rule "$rule_id" --arg r "$reason" --arg tier "$OACB_TIER" \
      '{"reason": ("OACB [\($rule)]: \($r) — blocked by OACB \($tier) tier. See https://github.com/websentry-ai/oacb for the full rule set.")}'
  else
    local esc="${reason//\"/\\\"}"
    printf '{"reason":"OACB [%s]: %s — blocked by OACB %s tier."}\n' "$rule_id" "$esc" "$OACB_TIER"
  fi
  printf 'OACB %s [%s]: %s\n' "$OACB_TIER" "$rule_id" "$reason" >&2
  exit 2
}

emit_audit() {
  local decision="$1"
  local rule_id="$2"
  local reason="$3"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","decision":"%s","tier":"%s","rule":"%s","reason":"%s","hook":"PreToolUse-MCP","oacb_version":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$decision" "$OACB_TIER" "$rule_id" "${reason//\"/\\\"}" "$OACB_VERSION" \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
}

if ! command -v jq >/dev/null 2>&1; then
  emit_block "jq required for OACB mcp-guard but not found" "OACB-ENV-001"
fi

input="$(cat)"
tool_name="$(echo "$input" | jq -r '.tool_name // empty' 2>/dev/null)"

# Only act on MCP tools
if [[ ! "$tool_name" =~ ^mcp__ ]]; then
  exit 0
fi

# Parse mcp__<server>__<tool>
server="$(echo "$tool_name" | sed -E 's/^mcp__([^_]+(_[^_]+)*)__.*$/\1/')"
tool="$(echo "$tool_name" | sed -E 's/^mcp__[^_]+(_[^_]+)*__(.*)$/\2/')"

# Known destructive MCP tool patterns — blocked at strict and above
case "$OACB_TIER" in
  strict|paranoid)
    if echo "$tool" | grep -qiE '(delete|destroy|drop|truncate|purge|force|wipe)'; then
      emit_block "MCP tool '$tool_name' has destructive-sounding name; requires human approval at tier=$OACB_TIER" "OACB-MCP-001"
    fi
    ;;
esac

# Known-hostile or suspicious MCP servers (based on public research)
# postmark-mcp v1.0.16 was the first in-the-wild malicious MCP (Semgrep, Sep 2025)
if [[ "$server" == "postmark-mcp" ]]; then
  # Check version via npm if possible; version 1.0.16 is backdoored
  emit_block "MCP server 'postmark-mcp' has known malicious version (1.0.16, Sep 2025). Verify installed version before allowing." "OACB-MCP-002"
fi

# Shadow tier: audit everything, block nothing
if [[ "$OACB_TIER" == "shadow" ]]; then
  emit_audit "allow" "OACB-MCP-SHADOW" "shadow tier — audit only"
  exit 0
fi

# Enforce allowlist at strict and paranoid
case "$OACB_TIER" in
  strict|paranoid)
    if [[ ! -f "$OACB_MCP_ALLOWLIST_FILE" ]]; then
      emit_block "OACB MCP allowlist file not found at $OACB_MCP_ALLOWLIST_FILE — paranoid/strict tier requires an allowlist" "OACB-MCP-003"
    fi
    if ! jq -e --arg tn "$tool_name" '.allowed | index($tn)' "$OACB_MCP_ALLOWLIST_FILE" >/dev/null 2>&1; then
      # Also check server-level allow (mcp__server__*)
      if ! jq -e --arg s "mcp__${server}__*" '.allowed | index($s)' "$OACB_MCP_ALLOWLIST_FILE" >/dev/null 2>&1; then
        emit_block "MCP tool '$tool_name' not in OACB allowlist. Add via 'unbound oacb mcp allow $tool_name' if intentional." "OACB-MCP-004"
      fi
    fi
    ;;
esac

# Baseline: warn on unapproved MCP servers, don't block
if [[ "$OACB_TIER" == "baseline" ]]; then
  if [[ -f "$OACB_MCP_ALLOWLIST_FILE" ]]; then
    if ! jq -e --arg tn "$tool_name" '.allowed | index($tn)' "$OACB_MCP_ALLOWLIST_FILE" >/dev/null 2>&1; then
      if ! jq -e --arg s "mcp__${server}__*" '.allowed | index($s)' "$OACB_MCP_ALLOWLIST_FILE" >/dev/null 2>&1; then
        emit_audit "warn" "OACB-MCP-004" "MCP tool '$tool_name' not in allowlist (warn only at baseline tier)"
      fi
    fi
  fi
fi

emit_audit "allow" "OACB-MCP-DEFAULT-ALLOW" "no MCP deny rule matched"
exit 0
