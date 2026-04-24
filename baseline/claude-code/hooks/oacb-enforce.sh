#!/usr/bin/env bash
#
# oacb-enforce.sh — OACB PreToolUse hook for Bash tool
#
# Hook contract (per Claude Code docs):
#   - Exit 0 + JSON: advisory decision via stdout JSON
#   - Exit 2 + stderr: HARD BLOCK; stderr visible to model
#   - Any other non-zero: soft error, tool execution CONTINUES (fail-open)
#
# OACB enforces FAIL-CLOSED for deny rules by using exit 2 + stderr.
# The script is engineered so that internal errors (jq missing, parse failure,
# timeout approach) also exit 2, not 1 — preventing fail-open via hook crash.
#
# Environment:
#   OACB_TIER              shadow | baseline | strict | paranoid (from managed-settings reference)
#   OACB_POLICY_CACHE      optional override; defaults to ~/.claude/hooks/.oacb_cache.json
#   OACB_AUDIT_LOG         optional; defaults to ~/.claude/hooks/oacb-audit.log
#
# Input: JSON on stdin from Claude Code
#   { "session_id": "...", "tool_name": "Bash", "tool_input": "...", "cwd": "...", ... }
#
# Exit codes:
#   0       Allow (explicit advisory allow in JSON)
#   2       Block with stderr reason
#   other   NEVER INTENTIONALLY — all error paths funnel to exit 2 with a stderr reason

set -uo pipefail

# Fail-closed on SIGPIPE and similar
trap 'emit_block "hook received signal during execution"' INT TERM

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.claude/hooks/oacb-audit.log}"
OACB_VERSION="0.1.0"

# --- helpers ---------------------------------------------------------------

emit_block() {
  local reason="$1"
  local rule_id="${2:-OACB-UNKNOWN}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","decision":"deny","tier":"%s","rule":"%s","reason":"%s","oacb_version":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$OACB_TIER" \
    "$rule_id" \
    "${reason//\"/\\\"}" \
    "$OACB_VERSION" \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  printf 'OACB %s [%s]: %s\n' "$OACB_TIER" "$rule_id" "$reason" >&2
  exit 2
}

emit_audit_allow() {
  local rule_id="${1:-OACB-ALLOW}"
  local reason="${2:-explicit allow}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","decision":"allow","tier":"%s","rule":"%s","reason":"%s","oacb_version":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$OACB_TIER" \
    "$rule_id" \
    "${reason//\"/\\\"}" \
    "$OACB_VERSION" \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
}

# Verify jq is available — if not, fail CLOSED (not open)
if ! command -v jq >/dev/null 2>&1; then
  emit_block "jq is required for OACB enforcement but not found on PATH" "OACB-ENV-001"
fi

# --- parse input -----------------------------------------------------------

input="$(cat)"
if [[ -z "$input" ]]; then
  emit_block "empty stdin to OACB hook" "OACB-IO-001"
fi

tool_name="$(echo "$input" | jq -r '.tool_name // empty' 2>/dev/null)"
if [[ -z "$tool_name" ]]; then
  emit_block "could not parse tool_name from hook input" "OACB-IO-002"
fi

# Only handle Bash; defer other tools to their own hooks
if [[ "$tool_name" != "Bash" ]]; then
  exit 0
fi

cmd="$(echo "$input" | jq -r '.tool_input.command // .tool_input // empty' 2>/dev/null)"
if [[ -z "$cmd" ]]; then
  emit_block "could not parse tool_input.command from hook input" "OACB-IO-003"
fi

# --- shadow tier: log only ------------------------------------------------

if [[ "$OACB_TIER" == "shadow" ]]; then
  # Evaluate but do not block; log the would-be decision.
  # NOTE: bash does not support combined substring + substitution in one expansion,
  # so we split the escape step.
  cmd_head="${cmd:0:200}"
  cmd_safe="${cmd_head//\"/\\\"}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  printf '{"ts":"%s","decision":"allow","tier":"shadow","rule":"OACB-SHADOW","reason":"shadow tier — all decisions logged, none enforced","cmd":"%s","oacb_version":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$cmd_safe" \
    "$OACB_VERSION" \
    >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  exit 0
fi

# --- rule evaluation ------------------------------------------------------

# Normalize: collapse whitespace, strip leading/trailing space
normalized="$(echo "$cmd" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')"

# Resolve common obfuscation: \x expansion, ${IFS} removal, $(echo ...) patterns
# This is BEST EFFORT. Pattern matching is adversarially defeated by construction.
# We do the obvious normalizations and the threat model (non-claims.md) acknowledges
# the residual gap. Do not add normalization that creates false positives on
# legitimate commands — that fails the false-positive corpus.

# Remove ${IFS} and $'\x20' variants used for word-break evasion
dewhitespaced="$(echo "$normalized" | sed -E 's/\$\{IFS\}/ /g; s/\$'\''\\x20'\''/ /g')"

# Flag backslash-escaped common binaries (\rm, \curl etc) — these are deny-evasion
if echo "$dewhitespaced" | grep -qE '(^|[^a-zA-Z0-9])\\(rm|curl|wget|ssh|nc|ncat|chmod|chown|sudo|doas)'; then
  emit_block "backslash-escaped binary detected (deny-evasion pattern)" "OACB-OBF-001"
fi

# Flag command substitution resolving to dangerous binaries ($(echo rm), `echo rm`)
# Matches $(echo rm), $(echo curl), ${VAR:-rm}, `echo rm`, etc.
if echo "$dewhitespaced" | grep -qE '\$\(\s*echo\s+(rm|curl|wget|dd|mkfs|format|shred)\s*\)|`\s*echo\s+(rm|curl|wget|dd|mkfs)\s*`'; then
  emit_block "command-substitution resolves to dangerous binary (Flatt-class bypass)" "OACB-OBF-005"
fi

# Flag variable-indirection resolving to dangerous binaries
if echo "$dewhitespaced" | grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*:?-?(rm|curl|wget|dd)\}'; then
  emit_block "variable-substitution default resolves to dangerous binary" "OACB-OBF-006"
fi

# Flag base64 piped to shell
if echo "$dewhitespaced" | grep -qE 'base64.*-d.*\|.*sh(ell)?\b'; then
  emit_block "base64-decode piped to shell (known exfil / RCE pattern)" "OACB-OBF-002"
fi
if echo "$dewhitespaced" | grep -qE 'base64.*--decode.*\|.*(bash|sh|zsh)\b'; then
  emit_block "base64 --decode piped to shell" "OACB-OBF-002"
fi

# Flag process-substitution exec of curl/wget
if echo "$dewhitespaced" | grep -qE '(bash|sh|zsh)\s*<\(\s*(curl|wget)'; then
  emit_block "process-substitution exec of remote content" "OACB-OBF-003"
fi

# Flag compound commands with > 10 subcommands (Adversa bypass class)
sep_count=$(echo "$dewhitespaced" | grep -oE '(&&|\|\||;)' | wc -l | tr -d ' ')
if [[ "${sep_count:-0}" -gt 10 ]]; then
  case "$OACB_TIER" in
    strict|paranoid)
      emit_block "compound command has $sep_count separators, exceeds OACB compound limit (10)" "OACB-COMPOUND-001"
      ;;
    baseline)
      # WARN at baseline — log as deny-considered but allow
      mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
      printf '{"ts":"%s","decision":"warn","tier":"baseline","rule":"OACB-COMPOUND-001","reason":"compound command separators=%s","oacb_version":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$sep_count" \
        "$OACB_VERSION" \
        >> "$OACB_AUDIT_LOG" 2>/dev/null || true
      ;;
  esac
fi

# /proc/self/root traversal (Flatt sandbox-bypass class) — CHECK BEFORE rm-rf
# so path-traversal-specific rule ID wins over generic rm rule.
if echo "$dewhitespaced" | grep -q '/proc/self/root/'; then
  emit_block "/proc/self/root path traversal; known sandbox-bypass pattern" "OACB-OBF-004"
fi

# Destructive rm patterns (T-10)
if echo "$dewhitespaced" | grep -qE '\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b.*(/|\$HOME|~|\$\{HOME\})'; then
  emit_block "destructive rm -rf against home/root/system path" "OACB-RM-001"
fi
if echo "$dewhitespaced" | grep -qE '\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*[fF].*\*'; then
  emit_block "destructive rm with glob against wildcard path" "OACB-RM-002"
fi

# find -delete against / or ~
if echo "$dewhitespaced" | grep -qE '\bfind\s+(/|\$HOME|~|\$\{HOME\})\s+.*-delete\b'; then
  emit_block "find -delete against home/root — destructive equivalent of rm -rf" "OACB-RM-003"
fi

# Force-push to main/master/release (T-12)
if echo "$dewhitespaced" | grep -qE '\bgit\s+push\s+(--force|-f|--force-with-lease)\b.*\b(origin|upstream)?\s*(main|master|release/)'; then
  emit_block "force-push to main/master/release branch" "OACB-GIT-001"
fi

# terraform destroy / auto-approve (T-11)
if echo "$dewhitespaced" | grep -qE '\bterraform\s+destroy\b'; then
  emit_block "terraform destroy is an irreversible operation; prohibited at OACB baseline" "OACB-TF-001"
fi
if echo "$dewhitespaced" | grep -qE '\bterraform\s+apply\b.*--auto-approve\b'; then
  emit_block "terraform apply --auto-approve in autonomous mode; prohibited at OACB baseline" "OACB-TF-002"
fi
if echo "$dewhitespaced" | grep -qE '\bterraform\s+state\s+rm\b'; then
  emit_block "terraform state rm can cause silent state divergence; prohibited" "OACB-TF-003"
fi

# Database migration destructive patterns (T-13)
if echo "$dewhitespaced" | grep -qE '\bdrizzle-kit\s+push\b.*--force\b'; then
  emit_block "drizzle-kit push --force against any database; prohibited" "OACB-DB-001"
fi
if echo "$dewhitespaced" | grep -qE '\bprisma\s+migrate\s+reset\b'; then
  emit_block "prisma migrate reset drops all tables; prohibited at OACB baseline" "OACB-DB-002"
fi
if echo "$dewhitespaced" | grep -qE '\balembic\s+downgrade\b'; then
  emit_block "alembic downgrade; prohibited at OACB baseline without human approval" "OACB-DB-003"
fi

# curl | bash / wget | sh and variants (T-20)
if echo "$dewhitespaced" | grep -qE '\b(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b'; then
  # Allow specific trusted installers via allowlist env
  case "$dewhitespaced" in
    *"rustup.rs"*|*"sh.rustup.rs"*|*"bun.sh"*|*"astral.sh/uv"*|*"nodejs.org"*)
      emit_audit_allow "OACB-NET-001-ALLOW" "trusted installer allowlist match"
      ;;
    *)
      emit_block "remote-to-shell pipe pattern (curl|bash / wget|sh); known RCE vector" "OACB-NET-001"
      ;;
  esac
fi

# history manipulation (Flatt CVE-2025-66032 variant)
if echo "$dewhitespaced" | grep -qE '\bhistory\s+-[as]\b'; then
  emit_block "history -s / history -a manipulation; used in known denylist bypass" "OACB-HIST-001"
fi

# eval on untrusted input
if echo "$dewhitespaced" | grep -qE '^\s*eval\s+'; then
  emit_block "eval is prohibited at OACB baseline" "OACB-EVAL-001"
fi

# Sandbox self-disable (Flatt / Ona finding) — benign inspection is fine; disabling sandboxing is not.
# (Detection of sandbox-disable behavior is at the session level, not single-command; out of scope for this hook.)

# Credential exfiltration via env enum — match env|grep with token/key/secret/password/credential
# regardless of grep flag ordering (`grep -iE`, `grep -E`, `grep -i`, etc.)
if echo "$dewhitespaced" | grep -qE '\benv\b[[:space:]]*\|[[:space:]]*grep\b'; then
  if echo "$dewhitespaced" | grep -qiE '(token|key|secret|password|credential|api_key|apikey|bearer)'; then
    emit_block "environment enumeration for credentials" "OACB-EXFIL-001"
  fi
fi

# printenv | grep variant (alternative to env | grep)
if echo "$dewhitespaced" | grep -qE '\bprintenv\b[[:space:]]*\|[[:space:]]*grep\b'; then
  if echo "$dewhitespaced" | grep -qiE '(token|key|secret|password|credential)'; then
    emit_block "printenv enumeration for credentials" "OACB-EXFIL-001"
  fi
fi

# Explicit allow sentinel — log and pass
emit_audit_allow "OACB-DEFAULT-ALLOW" "no deny rule matched"
exit 0
