#!/usr/bin/env bash
#
# oacb-enforce.sh — OACB PreToolUse hook for Bash tool
#
# Hook contract (per Claude Code docs):
#   - Exit 0: advisory decision / allow. Tool proceeds.
#   - Exit 2 + stderr: HARD BLOCK; stderr visible to model. Tool does NOT run.
#   - Any other non-zero: soft error per Claude Code; tool execution CONTINUES.
#
# OACB enforces FAIL-CLOSED for deny rules by using exit 2 + stderr.
# All internal error paths funnel to exit 2 with a stderr reason — jq missing,
# parse failure, signal, input too large, etc. A crash must not become an allow.
#
# Environment:
#   OACB_TIER              shadow | baseline | strict | paranoid (default: baseline)
#   OACB_AUDIT_LOG         optional; defaults to ~/.claude/hooks/oacb-audit.log
#   OACB_MAX_INPUT_BYTES   optional size guard (default 131072; input over this fails closed)
#
# Exit codes:
#   0       Allow (evaluated rules did not match)
#   2       Block with stderr reason
#   other   NEVER INTENTIONALLY — all error paths funnel to exit 2

set -uo pipefail

OACB_TIER="${OACB_TIER:-baseline}"
OACB_AUDIT_LOG="${OACB_AUDIT_LOG:-$HOME/.claude/hooks/oacb-audit.log}"
OACB_MAX_INPUT_BYTES="${OACB_MAX_INPUT_BYTES:-131072}"
OACB_VERSION="0.1.0"

# --- helpers (defined before trap) ----------------------------------------

_audit_line() {
  # $1=decision $2=rule_id $3=reason
  # Use jq to construct safe JSON if available; else best-effort printf.
  if command -v jq >/dev/null 2>&1; then
    jq -cn \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg decision "$1" \
      --arg tier "$OACB_TIER" \
      --arg rule "$2" \
      --arg reason "$3" \
      --arg ver "$OACB_VERSION" \
      '{ts:$ts,decision:$decision,tier:$tier,rule:$rule,reason:$reason,oacb_version:$ver}' \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  else
    # Fallback with minimal escaping
    local esc="${3//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    printf '{"ts":"%s","decision":"%s","tier":"%s","rule":"%s","reason":"%s","oacb_version":"%s"}\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$OACB_TIER" "$2" "$esc" "$OACB_VERSION" \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  fi
}

emit_block() {
  local reason="$1"
  local rule_id="${2:-OACB-UNKNOWN}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  _audit_line "deny" "$rule_id" "$reason"
  printf 'OACB %s [%s]: %s\n' "$OACB_TIER" "$rule_id" "$reason" >&2
  exit 2
}

emit_audit_allow() {
  local rule_id="${1:-OACB-ALLOW}"
  local reason="${2:-explicit allow}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  _audit_line "allow" "$rule_id" "$reason"
}

emit_audit_warn() {
  local rule_id="$1"
  local reason="$2"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  _audit_line "warn" "$rule_id" "$reason"
}

# Fail-closed on signals (INT/TERM from timeout, HUP, QUIT, ABRT, PIPE).
# Trap installed AFTER emit_block is defined so handler can call it safely.
trap 'emit_block "hook received signal during execution" "OACB-SIG-001"' INT TERM HUP QUIT ABRT PIPE

# Verify jq is available — if not, fail CLOSED (not open)
if ! command -v jq >/dev/null 2>&1; then
  emit_block "jq is required for OACB enforcement but not found on PATH" "OACB-ENV-001"
fi

# --- parse input -----------------------------------------------------------

input="$(cat)"
if [[ -z "$input" ]]; then
  emit_block "empty stdin to OACB hook" "OACB-IO-001"
fi

# Size guard — adversarial huge-input DoS
input_bytes=${#input}
if [[ $input_bytes -gt $OACB_MAX_INPUT_BYTES ]]; then
  emit_block "hook input exceeds $OACB_MAX_INPUT_BYTES bytes ($input_bytes); suspect DoS" "OACB-IO-004"
fi

tool_name="$(echo "$input" | jq -r '.tool_name // empty' 2>/dev/null)"
if [[ -z "$tool_name" ]]; then
  emit_block "could not parse tool_name from hook input" "OACB-IO-002"
fi

# Only handle Bash; defer other tools to their own hooks.
# NOTE: paranoid tier uses matcher=".*" — when this hook is invoked for non-Bash
# tools at paranoid, we fail closed rather than pass through. Other tiers defer.
if [[ "$tool_name" != "Bash" ]]; then
  if [[ "$OACB_TIER" == "paranoid" ]]; then
    emit_block "paranoid tier: tool '$tool_name' not explicitly allowed by hook; deferring to mcp-guard / prompt-guard if wired, else blocking" "OACB-PARANOID-001"
  fi
  exit 0
fi

cmd="$(echo "$input" | jq -r '.tool_input.command // .tool_input // empty' 2>/dev/null)"
if [[ -z "$cmd" ]]; then
  emit_block "could not parse tool_input.command from hook input" "OACB-IO-003"
fi

# Strip CR and NUL defensively (via tr to avoid bash-version substitution quirks)
cmd="$(printf '%s' "$cmd" | tr -d '\r\0' 2>/dev/null || echo "$cmd")"

# --- shadow tier: log only ------------------------------------------------

if [[ "$OACB_TIER" == "shadow" ]]; then
  cmd_head="${cmd:0:200}"
  cmd_safe="${cmd_head//\"/\\\"}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  if command -v jq >/dev/null 2>&1; then
    jq -cn \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg tier "shadow" \
      --arg cmd "$cmd_head" \
      --arg ver "$OACB_VERSION" \
      '{ts:$ts,decision:"allow",tier:$tier,rule:"OACB-SHADOW",reason:"shadow tier — logged, not enforced",cmd:$cmd,oacb_version:$ver}' \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  else
    printf '{"ts":"%s","decision":"allow","tier":"shadow","rule":"OACB-SHADOW","reason":"shadow tier — logged, not enforced","cmd":"%s","oacb_version":"%s"}\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$cmd_safe" "$OACB_VERSION" \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  fi
  exit 0
fi

# --- normalization --------------------------------------------------------

# Collapse whitespace, strip leading/trailing space
normalized="$(echo "$cmd" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')"

# Expand ${IFS} and $'\x20' used for word-break evasion
dewhitespaced="$(echo "$normalized" | sed -E 's/\$\{IFS\}/ /g; s/\$'\''\\x20'\''/ /g')"

# Mask quoted content (single and double quotes) so rule-matching doesn't fire
# on text inside quotes. Replace quoted-string interiors with placeholders.
# This prevents:   echo 'rm -rf /tmp/x' > cleanup.sh  from matching OACB-RM-001.
# Best-effort only — nested/escaped quotes are out of scope; for those we defer
# to runtime enforcement (see non-claims.md §1).
unquoted="$(echo "$dewhitespaced" | sed -E "s/'[^']*'/'QUOTED'/g; s/\"[^\"]*\"/\"QUOTED\"/g")"

# --- obfuscation detection ------------------------------------------------

# Backslash-escaped common binaries (\rm, \curl, ...) — deny evasion
if echo "$unquoted" | grep -qE '(^|[^a-zA-Z0-9])\\(rm|curl|wget|ssh|nc|ncat|chmod|chown|sudo|doas)'; then
  emit_block "backslash-escaped binary detected (deny-evasion pattern)" "OACB-OBF-001"
fi

# Command substitution resolving to dangerous binaries
if echo "$unquoted" | grep -qE '\$\(\s*echo\s+(rm|curl|wget|dd|mkfs|format|shred)\s*\)|`\s*echo\s+(rm|curl|wget|dd|mkfs)\s*`'; then
  emit_block "command-substitution resolves to dangerous binary (Flatt-class bypass)" "OACB-OBF-005"
fi

# Variable-indirection resolving to dangerous binaries
if echo "$unquoted" | grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*:?-?(rm|curl|wget|dd)\}'; then
  emit_block "variable-substitution default resolves to dangerous binary" "OACB-OBF-006"
fi

# base64 piped to shell (RCE / exfil class)
if echo "$unquoted" | grep -qE 'base64[[:space:]]+(-d|--decode|-D)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(bash|sh|zsh)\b'; then
  emit_block "base64-decode piped to shell (known exfil / RCE pattern)" "OACB-OBF-002"
fi

# Process-substitution exec of remote content
if echo "$unquoted" | grep -qE '(bash|sh|zsh)\s*<\(\s*(curl|wget)'; then
  emit_block "process-substitution exec of remote content" "OACB-OBF-003"
fi

# /proc/self/root traversal (Flatt sandbox-bypass class) — BEFORE rm-rf check
if echo "$unquoted" | grep -q '/proc/self/root/'; then
  emit_block "/proc/self/root path traversal; known sandbox-bypass pattern" "OACB-OBF-004"
fi

# --- compound command (Adversa CVE class) ---------------------------------

sep_count=$(echo "$unquoted" | grep -oE '(&&|\|\||;)' | wc -l | tr -d ' ')
if [[ "${sep_count:-0}" -gt 10 ]]; then
  case "$OACB_TIER" in
    strict|paranoid)
      emit_block "compound command has $sep_count separators, exceeds OACB limit (10)" "OACB-COMPOUND-001"
      ;;
    baseline)
      emit_audit_warn "OACB-COMPOUND-001" "compound command separators=$sep_count"
      ;;
  esac
fi

# --- destructive rm (T-10) ------------------------------------------------

# Helper: does a command contain destructive rm flags (any order/form)?
#   -rf, -fr, -Rf, -fR, -r -f, -f -r, --recursive --force, --force --recursive,
#   long-option variants.
_has_destructive_rm_flags() {
  local s="$1"
  # Short combined forms: any order, any case of r/R and f/F
  echo "$s" | grep -qE '\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*[fF]|-[a-zA-Z]*[fF][a-zA-Z]*[rR])\b' && return 0
  # Split short flags: rm -r -f, rm -f -r, rm -R -f, etc.
  echo "$s" | grep -qE '\brm\s+(-[rR]\b[[:space:]]+-[fF]\b|-[fF]\b[[:space:]]+-[rR]\b)' && return 0
  # Long-option forms
  echo "$s" | grep -qE '\brm\s+.*(--recursive\b.*--force\b|--force\b.*--recursive\b)' && return 0
  return 1
}

# Helper: does the path target an absolute root, home, or system path?
# Must NOT match relative paths like dist/*, node_modules/*, ./tmp/*.
# A sensitive target is one of:
#   - bare `/`               (e.g. `rm -rf /`)
#   - `/something/...`        but only if the `/` is at start of a rm-argument token
#   - `~`, `~/`, `$HOME`, `${HOME}`
#   - explicit system prefixes `/etc/`, `/var/`, `/usr/`, `/bin/`, `/boot/`, `/sbin/`, `/opt/`
_targets_sensitive_path() {
  local s="$1"
  # Tokenize: find arguments after rm (space-delimited) and check each
  # for absolute-path / home-path markers. We scan the rm-command portion.
  # Pattern: `rm <flags> <arg1> <arg2> ...` — any arg starting with /, ~, or $HOME matches.
  # Using [[:space:]]<trigger> requires a space-delimited boundary before the path.
  echo "$s" | grep -qE '\brm\b[^;|&]*[[:space:]](/|~|\$HOME|\$\{HOME\})([[:space:]]|$|/|\*)' && return 0
  echo "$s" | grep -qE '\brm\b[^;|&]*[[:space:]](/etc/|/var/|/usr/|/bin/|/sbin/|/boot/|/opt/|/root/)' && return 0
  return 1
}

# OACB-RM-001: destructive rm against home/root/system path (any flag form)
if _has_destructive_rm_flags "$unquoted" && _targets_sensitive_path "$unquoted"; then
  emit_block "destructive rm against home/root/system path" "OACB-RM-001"
fi

# OACB-RM-002: destructive rm with glob against home/root wildcard specifically.
# NOT triggered by `rm -rf dist/*`, `rm -rf build/*`, `rm -rf node_modules/*`, etc.
if _has_destructive_rm_flags "$unquoted"; then
  if echo "$unquoted" | grep -qE '\brm\b[^;|&]*[[:space:]](/|~|\$HOME|\$\{HOME\})\*|\brm\b[^;|&]*[[:space:]](/|~|\$HOME|\$\{HOME\})/[^[:space:]]*\*'; then
    emit_block "destructive rm with glob against home/root wildcard" "OACB-RM-002"
  fi
fi

# OACB-RM-003: find -delete against home/root
if echo "$unquoted" | grep -qE '\bfind\s+(/|\$HOME|~|\$\{HOME\})[[:space:]][^|;&]*-delete\b'; then
  emit_block "find -delete against home/root" "OACB-RM-003"
fi

# OACB-RM-004: find -exec rm against home/root
if echo "$unquoted" | grep -qE '\bfind\s+(/|\$HOME|~|\$\{HOME\})[[:space:]][^|;&]*-exec\s+rm\b'; then
  emit_block "find -exec rm against home/root" "OACB-RM-004"
fi

# OACB-RM-005: dd against block devices (disk wipe class)
if echo "$unquoted" | grep -qE '\bdd\s+.*of=/dev/(sda|sdb|sdc|nvme|disk|hda|hdb|mmcblk)'; then
  emit_block "dd to block device; disk-wipe class" "OACB-RM-005"
fi

# OACB-RM-006: mkfs against sensitive devices
if echo "$unquoted" | grep -qE '\bmkfs(\.[a-z0-9]+)?\s+.*/dev/(sda|nvme|disk|hda|mmcblk)'; then
  emit_block "mkfs against block device; disk-format class" "OACB-RM-006"
fi

# --- git force-push to protected branches --------------------------------

if echo "$unquoted" | grep -qE '\bgit\s+push\s+.*(--force|-f|--force-with-lease)\b.*\b(main|master|release/|prod|production)\b'; then
  emit_block "force-push to main/master/release/prod branch" "OACB-GIT-001"
fi

# --- terraform destructive -----------------------------------------------

if echo "$unquoted" | grep -qE '\bterraform\s+destroy\b'; then
  emit_block "terraform destroy is an irreversible operation" "OACB-TF-001"
fi
if echo "$unquoted" | grep -qE '\bterraform\s+apply\b.*--auto-approve\b'; then
  emit_block "terraform apply --auto-approve in autonomous mode" "OACB-TF-002"
fi
if echo "$unquoted" | grep -qE '\bterraform\s+state\s+rm\b'; then
  emit_block "terraform state rm can cause silent state divergence" "OACB-TF-003"
fi

# --- destructive DB migrations --------------------------------------------

if echo "$unquoted" | grep -qE '\bdrizzle-kit\s+push\b.*--force\b'; then
  emit_block "drizzle-kit push --force against any database" "OACB-DB-001"
fi
if echo "$unquoted" | grep -qE '\bprisma\s+migrate\s+reset\b'; then
  emit_block "prisma migrate reset drops all tables" "OACB-DB-002"
fi
if echo "$unquoted" | grep -qE '\balembic\s+downgrade\b'; then
  emit_block "alembic downgrade without human approval" "OACB-DB-003"
fi

# --- remote-to-shell pipe (T-20) ------------------------------------------
# Parse URL host carefully; only allow if host exactly matches an installer allowlist.

_extract_url_host() {
  # Extract first https?://host[/...] from the input and print just the host.
  local s="$1"
  echo "$s" | grep -oE 'https?://[^[:space:]"'\''|;)<>]+' | head -1 \
    | sed -E 's|^https?://||; s|/.*$||; s|:[0-9]+$||'
}

_is_trusted_installer_host() {
  local host="$1"
  case "$host" in
    sh.rustup.rs|rustup.rs|bun.sh|astral.sh|nodejs.org|deb.nodesource.com|get.docker.com|cli.github.com|starship.rs|sh.uv.astral.sh)
      return 0 ;;
    *) return 1 ;;
  esac
}

if echo "$unquoted" | grep -qE '\b(curl|wget|fetch)\s+[^|;&]*\|\s*(sudo\s+)?(bash|sh|zsh|ksh)\b'; then
  host="$(_extract_url_host "$unquoted")"
  if [[ -n "$host" ]] && _is_trusted_installer_host "$host"; then
    emit_audit_allow "OACB-NET-001-ALLOW" "trusted installer host: $host"
  else
    emit_block "remote-to-shell pipe; known RCE vector (host=${host:-unknown})" "OACB-NET-001"
  fi
fi

# --- netcat / socat / bash tcp ---------------------------------------------

if echo "$unquoted" | grep -qE '\b(nc|ncat|socat|telnet)\s+[^-]'; then
  # Plain nc/ncat/socat/telnet invocation. Block at baseline+.
  emit_block "netcat/socat/telnet-family invocation; network egress / reverse-shell class" "OACB-NET-002"
fi
if echo "$unquoted" | grep -qE '\b(bash|sh|zsh|ksh)\b[^;|]*/dev/tcp/'; then
  emit_block "bash /dev/tcp reverse-shell pattern" "OACB-NET-003"
fi

# --- history / eval / sudo -----------------------------------------------

if echo "$unquoted" | grep -qE '\bhistory\s+-[as]\b'; then
  emit_block "history -s/-a manipulation; known denylist-bypass primitive" "OACB-HIST-001"
fi

if echo "$unquoted" | grep -qE '(^|\W)eval\s+'; then
  emit_block "eval is prohibited at OACB baseline" "OACB-EVAL-001"
fi

# --- credential exfil via env enum ----------------------------------------
# NOTE: check against $dewhitespaced (pre-quote-mask) because the credential
# keywords in `grep 'token|key|secret'` are inside a quoted arg.

if echo "$dewhitespaced" | grep -qE '\benv\b[[:space:]]*\|[[:space:]]*grep\b'; then
  if echo "$dewhitespaced" | grep -qiE '(token|key|secret|password|credential|api_key|apikey|bearer)'; then
    emit_block "environment enumeration for credentials" "OACB-EXFIL-001"
  fi
fi
if echo "$dewhitespaced" | grep -qE '\bprintenv\b[[:space:]]*\|[[:space:]]*grep\b'; then
  if echo "$dewhitespaced" | grep -qiE '(token|key|secret|password|credential)'; then
    emit_block "printenv enumeration for credentials" "OACB-EXFIL-001"
  fi
fi

# --- default: allow --------------------------------------------------------

emit_audit_allow "OACB-DEFAULT-ALLOW" "no deny rule matched"
exit 0
