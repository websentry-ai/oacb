#!/usr/bin/env bash
#
# oacb-post-tool.sh — OACB PostToolUse / PostToolUseFailure hook
#
# Logs all tool completions and failures to the audit log.
#
# For "ask" commands:
#   - If the user ACCEPTS: PostToolUse fires → logged as "tool-completed"
#   - If the user DENIES:  Claude Code does not appear to fire any post-hook.
#     Denial is inferrable by the absence of a "tool-completed" entry following
#     the corresponding "allow" entry written by oacb-enforce.sh in PreToolUse.
#
# This hook runs async (non-blocking) — exit code is ignored by Claude Code.
#
# Environment:
#   OACB_TIER      shadow | baseline | strict | paranoid
#   OACB_AUDIT_LOG optional; defaults to ~/.claude/hooks/oacb-audit.log

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.claude/hooks/oacb-audit.log}"
OACB_VERSION="0.2.1"

input="$(cat)"
[[ -z "$input" ]] && exit 0

if ! command -v jq >/dev/null 2>&1; then
  exit 0
fi

hook_event="$(echo "$input" | jq -r '.hook_event_name // "PostToolUse"' 2>/dev/null)"
tool_name="$(echo "$input" | jq -r '.tool_name // ""' 2>/dev/null)"
cmd="$(echo "$input" | jq -r '.tool_input.command // ""' 2>/dev/null)"
error="$(echo "$input" | jq -r '.tool_response.error // ""' 2>/dev/null)"
interrupted="$(echo "$input" | jq -r '.tool_response.interrupted // false' 2>/dev/null)"

mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true

if [[ "$hook_event" == "PostToolUseFailure" ]] || [[ -n "$error" ]]; then
  decision="tool-failed"
  jq -cn \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg decision "$decision" \
    --arg tier "$OACB_TIER" \
    --arg tool "$tool_name" \
    --arg cmd "${cmd:0:500}" \
    --arg error "${error:0:300}" \
    --arg ver "$OACB_VERSION" \
    '{ts:$ts,decision:$decision,tier:$tier,hook:"PostToolUse",tool:$tool,cmd:$cmd,error:$error,oacb_version:$ver}' \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
elif [[ "$interrupted" == "true" ]]; then
  jq -cn \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg tier "$OACB_TIER" \
    --arg tool "$tool_name" \
    --arg cmd "${cmd:0:500}" \
    --arg ver "$OACB_VERSION" \
    '{ts:$ts,decision:"tool-interrupted",tier:$tier,hook:"PostToolUse",tool:$tool,cmd:$cmd,oacb_version:$ver}' \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
else
  jq -cn \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg tier "$OACB_TIER" \
    --arg tool "$tool_name" \
    --arg cmd "${cmd:0:500}" \
    --arg ver "$OACB_VERSION" \
    '{ts:$ts,decision:"tool-completed",tier:$tier,hook:"PostToolUse",tool:$tool,cmd:$cmd,oacb_version:$ver}' \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
fi

exit 0
