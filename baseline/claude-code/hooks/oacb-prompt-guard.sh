#!/usr/bin/env bash
#
# oacb-prompt-guard.sh — OACB UserPromptSubmit hook
#
# Flags and optionally blocks user prompts that contain patterns associated
# with prompt injection attacks: invisible Unicode, bidi markers, instruction
# hijacks from pasted content.
#
# NOTE: UserPromptSubmit hook fires AFTER the user submits but BEFORE the prompt
# is sent to the model. Exit 2 blocks the submission. This is the earliest
# interception point available in Claude Code and is critical for ASI01 Goal
# Hijack defense.
#
# Environment:
#   OACB_TIER              shadow | baseline | strict | paranoid
#   OACB_AUDIT_LOG         optional; defaults to ~/.claude/hooks/oacb-audit.log

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.claude/hooks/oacb-audit.log}"
OACB_VERSION="0.1.0"

emit_block() {
  local reason="$1"
  local rule_id="${2:-OACB-PROMPT-UNKNOWN}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","decision":"deny","tier":"%s","rule":"%s","reason":"%s","hook":"UserPromptSubmit","oacb_version":"%s"}\n' \
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

emit_warn() {
  local reason="$1"
  local rule_id="${2:-OACB-PROMPT-WARN}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","decision":"warn","tier":"%s","rule":"%s","reason":"%s","hook":"UserPromptSubmit","oacb_version":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OACB_TIER" "$rule_id" "${reason//\"/\\\"}" "$OACB_VERSION" \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
}

if ! command -v jq >/dev/null 2>&1; then
  emit_block "jq required for OACB prompt-guard but not found" "OACB-ENV-001"
fi

input="$(cat)"
if [[ -z "$input" ]]; then
  exit 0
fi

prompt="$(echo "$input" | jq -r '.prompt // .user_prompt // empty' 2>/dev/null)"
if [[ -z "$prompt" ]]; then
  exit 0
fi

# --- pattern checks -------------------------------------------------------

# 1. Bidi / invisible Unicode (Pillar Security "Rules File Backdoor" class)
#    U+202A..U+202E (bidi overrides), U+2066..U+2069 (isolates),
#    U+200B..U+200D (zero-width), U+FEFF (BOM), U+E0000..U+E007F (tag chars)
if echo "$prompt" | LC_ALL=C grep -qE $'\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]|\xe2\x80[\x8b-\x8d]|\xef\xbb\xbf'; then
  emit_block "prompt contains invisible Unicode (bidi/zero-width/BOM) — known prompt-injection vector" "OACB-PROMPT-001"
fi

# Tag characters (used in Pillar's demo) U+E0000..U+E007F — UTF-8: F3 A0 80 80..F3 A0 81 BF
# Prefer a pure-bash byte check; only consult python3 if it is verified usable.
if echo "$prompt" | LC_ALL=C grep -qE $'\xf3\xa0\x80[\x80-\xbf]|\xf3\xa0\x81[\x80-\xbf]'; then
  emit_block "prompt contains Unicode tag characters (hidden instruction vector)" "OACB-PROMPT-002"
fi
# Secondary python3 check only when python3 is verified functional; fail-open on any
# python3 problem (missing, errored, slow). This prevents fail-closed-on-missing-python3
# from being a universal prompt blocker.
if command -v python3 >/dev/null 2>&1 && echo "test" | python3 -c 'pass' >/dev/null 2>&1; then
  tag_check_exit=0
  echo "$prompt" | python3 -c 'import sys
s = sys.stdin.read()
sys.exit(1 if any(0xE0000 <= ord(c) <= 0xE007F for c in s) else 0)' 2>/dev/null || tag_check_exit=$?
  if [[ "$tag_check_exit" == "1" ]]; then
    emit_block "prompt contains Unicode tag characters (python3 double-check)" "OACB-PROMPT-002"
  fi
  # Any other non-zero exit = python3 problem; we already did the byte-level check above.
fi

# 2. Classic prompt-injection markers in pasted content
case "$OACB_TIER" in
  strict|paranoid)
    if echo "$prompt" | grep -qiE '(ignore (all )?previous (instructions|context)|disregard (the )?(above|prior)|you are now|new (system )?prompt:|\bsystem:\s|\[system\]|<\|im_start\|>|<\|im_end\|>)'; then
      emit_block "prompt contains known instruction-override injection pattern" "OACB-PROMPT-003"
    fi
    ;;
  baseline)
    if echo "$prompt" | grep -qiE '(ignore (all )?previous (instructions|context)|disregard (the )?(above|prior)|<\|im_start\|>|<\|im_end\|>)'; then
      emit_warn "prompt contains injection-pattern markers — logging only at baseline" "OACB-PROMPT-003"
    fi
    ;;
esac

# 3. Attempts to rewrite OACB / Claude Code config via prompt
if echo "$prompt" | grep -qiE '(disable[[:space:]]+(oacb[[:space:]]+)?(security|hook|policy|enforcement))|((turn[[:space:]]+off|bypass|skip)[[:space:]]+(oacb|security|hook|policy|enforcement))|--dangerously-skip-permissions|disableAutoMode.*false'; then
  emit_block "prompt attempts to disable OACB enforcement" "OACB-PROMPT-004"
fi

# 4. Credential paste detection (developer accidentally pastes a secret)
if echo "$prompt" | grep -qE '(AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)'; then
  emit_block "prompt appears to contain a credential (AWS access key, Anthropic API key, OpenAI key, GitHub token, or private key)" "OACB-PROMPT-005"
fi

# 5. Suspicious "act as X" / persona injections from pasted content
case "$OACB_TIER" in
  strict|paranoid)
    if echo "$prompt" | grep -qiE '(pretend to be|act as if you are|you are DAN|developer mode|jailbreak|unrestricted (AI|assistant))'; then
      emit_block "prompt contains jailbreak / persona-injection pattern" "OACB-PROMPT-006"
    fi
    ;;
esac

# Pass — audit the allow
mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
printf '{"ts":"%s","decision":"allow","tier":"%s","rule":"OACB-PROMPT-DEFAULT-ALLOW","hook":"UserPromptSubmit","oacb_version":"%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OACB_TIER" "$OACB_VERSION" \
  >> "$OACB_AUDIT_LOG" 2>/dev/null || true
exit 0
