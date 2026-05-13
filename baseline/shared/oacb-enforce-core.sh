# oacb-enforce-core.sh — OACB shared rule-enforcement logic
#
# NOT executable — must be sourced by an agent wrapper script.
# The wrapper MUST define emit_block() before sourcing this file.
#
# Expects these variables to be set by the wrapper before sourcing:
#   OACB_TIER              shadow | receipts | baseline | strict | paranoid
#   OACB_AUDIT_LOG         path to audit log file
#   OACB_MAX_INPUT_BYTES   size guard (default 131072)
#   OACB_VERSION           version string
#
# Provides (defines and uses):
#   _classify_risk         rule_id → low|medium|high|critical
#   _promote_on_path       risk × cmd → promoted risk
#   _effective_risk        rule_id × cmd → effective risk (with context)
#   _tier_action           tier × risk → allow|warn|ask|block
#   _dispatch              central router — classifies + routes to emit_*
#   _audit_line            write one JSON line to OACB_AUDIT_LOG
#   emit_audit_allow       log an allow decision
#   emit_audit_warn        log a warn decision (legacy alias)
#   emit_warn              warn with optional TUI prompt; exit 0
#   _audit_line_aborted    write a second log entry with engineer_aborted:true
#
# Audit log JSON schema (one entry per line):
#   ts, decision, tier, rule, risk, risk_taxonomy_version, reason, cmd, oacb_version
#   Optional: engineer_aborted (boolean, only when decision==warn and engineer pressed A)

# Guard: prevent accidental direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "oacb-enforce-core.sh must be sourced by an agent wrapper, not executed directly." >&2
  exit 2
fi

# --- Sensitive path helper (used by risk promotion and RM rules) ----------

_targets_sensitive_path() {
  local s="$1"
  echo "$s" | grep -qE '\brm\b[^;|&]*[[:space:]](/|~|\$HOME|\$\{HOME\})([[:space:]]|$|/|\*)' && return 0
  echo "$s" | grep -qE '\brm\b[^;|&]*[[:space:]](/etc/|/var/|/usr/|/bin/|/sbin/|/boot/|/opt/|/root/)' && return 0
  return 1
}

# --- Risk classification ---------------------------------------------------

_classify_risk() {
  # $1 = rule_id → prints low|medium|high|critical
  case "$1" in
    OACB-OBF-*)         echo "critical" ;;
    OACB-RM-*)          echo "critical" ;;
    OACB-GIT-001)       echo "critical" ;;
    OACB-TF-001)        echo "critical" ;;
    OACB-TF-002)        echo "high" ;;
    OACB-TF-003)        echo "high" ;;
    OACB-DB-001)        echo "high" ;;
    OACB-DB-002)        echo "critical" ;;
    OACB-DB-003)        echo "high" ;;
    OACB-NET-001)       echo "critical" ;;
    OACB-NET-002)       echo "high" ;;
    OACB-NET-003)       echo "critical" ;;
    OACB-HIST-001)      echo "critical" ;;
    OACB-EVAL-001)      echo "critical" ;;
    OACB-EXFIL-001)     echo "high" ;;
    OACB-COMPOUND-001)  echo "medium" ;;
    OACB-PARANOID-001)  echo "medium" ;;
    OACB-IO-*|OACB-ENV-*|OACB-SIG-*) echo "critical" ;;
    *)                  echo "high" ;;  # conservative default
  esac
}

_promote_on_path() {
  # If base risk is medium and command targets a sensitive path, promote to critical
  local risk="$1" cmd_val="$2"
  if [[ "$risk" == "medium" ]] && _targets_sensitive_path "$cmd_val"; then
    echo "critical"
  else
    echo "$risk"
  fi
}

_effective_risk() {
  # $1 = rule_id, $2 = cmd → prints effective risk level
  local rule_id="$1" cmd_val="${2:-}"
  local base_risk
  base_risk="$(_classify_risk "$rule_id")"
  local risk
  risk="$(_promote_on_path "$base_risk" "$cmd_val")"

  # PROMOTE-ON-CONTEXT: if .oacb-context.json has env:prod, high → critical
  # Reject symlinks (could point to /dev/random) and cap jq with timeout 1.
  local ctx_file="${OACB_CONTEXT_FILE:-.oacb-context.json}"
  if [[ -f "$ctx_file" && ! -L "$ctx_file" ]] && command -v jq >/dev/null 2>&1; then
    local env_val
    env_val="$(timeout 1 jq -r '.env // empty' "$ctx_file" 2>/dev/null)"
    if [[ "$env_val" == "prod" || "$env_val" == "production" ]] && [[ "$risk" == "high" ]]; then
      echo "critical"
      return
    fi
  fi
  echo "$risk"
}

# --- Tier action matrix ---------------------------------------------------

_tier_action() {
  # $1=tier $2=risk → prints allow|warn|ask|block
  local tier="$1" risk="$2"
  case "$tier:$risk" in
    shadow:*)          echo "allow" ;;      # shadow = audit-only, no enforcement
    receipts:low)      echo "allow" ;;
    receipts:medium)   echo "warn" ;;
    receipts:high)     echo "warn" ;;
    receipts:critical) echo "warn" ;;
    baseline:low)      echo "allow" ;;
    baseline:medium)   echo "allow" ;;
    baseline:high)     echo "ask" ;;
    baseline:critical) echo "block" ;;
    strict:low)        echo "allow" ;;
    strict:medium)     echo "warn" ;;
    strict:high)       echo "block" ;;
    strict:critical)   echo "block" ;;
    paranoid:low)      echo "allow" ;;
    paranoid:medium)   echo "block" ;;
    paranoid:high)     echo "block" ;;
    paranoid:critical) echo "block" ;;
    *)                 echo "block" ;;     # conservative fallback
  esac
}

# --- Shared audit helpers --------------------------------------------------
# These are identical for all agents. emit_block is NOT defined here —
# it is the agent-specific function the wrapper must define first.

_audit_line() {
  # $1=decision $2=rule_id $3=reason $4=cmd (optional)
  if command -v jq >/dev/null 2>&1; then
    local cmd_snippet="${4:-}"
    cmd_snippet="${cmd_snippet:0:500}"
    local risk_val
    risk_val="$(_effective_risk "$2" "${4:-}")"
    if [[ -n "$cmd_snippet" ]]; then
      jq -cn \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg decision "$1" \
        --arg tier "$OACB_TIER" \
        --arg rule "$2" \
        --arg risk "$risk_val" \
        --arg taxver "1.0" \
        --arg reason "$3" \
        --arg cmd "$cmd_snippet" \
        --arg ver "$OACB_VERSION" \
        '{ts:$ts,decision:$decision,tier:$tier,rule:$rule,risk:$risk,risk_taxonomy_version:$taxver,reason:$reason,cmd:$cmd,oacb_version:$ver}' \
        >> "$OACB_AUDIT_LOG" 2>/dev/null || true
    else
      jq -cn \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg decision "$1" \
        --arg tier "$OACB_TIER" \
        --arg rule "$2" \
        --arg risk "$risk_val" \
        --arg taxver "1.0" \
        --arg reason "$3" \
        --arg ver "$OACB_VERSION" \
        '{ts:$ts,decision:$decision,tier:$tier,rule:$rule,risk:$risk,risk_taxonomy_version:$taxver,reason:$reason,oacb_version:$ver}' \
        >> "$OACB_AUDIT_LOG" 2>/dev/null || true
    fi
  else
    local esc="${3//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    printf '{"ts":"%s","decision":"%s","tier":"%s","rule":"%s","reason":"%s","oacb_version":"%s"}\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$OACB_TIER" "$2" "$esc" "$OACB_VERSION" \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  fi
}

emit_audit_allow() {
  local rule_id="${1:-OACB-ALLOW}"
  local reason="${2:-explicit allow}"
  local cmd_val="${3:-}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  _audit_line "allow" "$rule_id" "$reason" "$cmd_val"
}

emit_audit_warn() {
  local rule_id="$1"
  local reason="$2"
  local cmd_val="${3:-}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  _audit_line "warn" "$rule_id" "$reason" "$cmd_val"
}

# --- emit_warn: warn with optional TUI abort prompt -----------------------

_audit_line_aborted() {
  local rule_id="$1" reason="$2" cmd_val="$3"
  # Write a second audit entry marking engineer-initiated abort
  if command -v jq >/dev/null 2>&1; then
    jq -cn \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg rule "$rule_id" \
      --arg reason "$reason" \
      --arg tier "$OACB_TIER" \
      '{ts:$ts,decision:"warn",rule:$rule,reason:$reason,tier:$tier,engineer_aborted:true}' \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  fi
}

emit_warn() {
  local rule_id="$1" reason="$2" cmd_val="${3:-}"
  local category="${rule_id%%-[0-9]*}"   # e.g. OACB-NET from OACB-NET-001
  local seen_file="/tmp/oacb-warn-seen-${$}-${category}"
  local counter_file="/tmp/oacb-warn-count-$$"

  # Audit log — always
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  _audit_line "warn" "$rule_id" "$reason" "$cmd_val"

  # Status-line counter (increment)
  local count=1
  if [[ -f "$counter_file" ]]; then
    local prev_count
    prev_count="$(cat "$counter_file" 2>/dev/null || echo 0)"
    count=$(( prev_count + 1 ))
  fi
  echo "$count" > "$counter_file"

  # Dedupe: one banner per category per session
  if [[ ! -f "$seen_file" ]]; then
    touch "$seen_file"

    # Bell (opt-in via OACB_CHANNELS)
    if [[ "${OACB_CHANNELS:-}" == *bell* ]]; then
      printf '\a' >&2
    fi

    local effective_risk
    effective_risk="$(_effective_risk "$rule_id" "$cmd_val")"

    # Inline banner to stderr (visible to engineer, not model)
    printf '\n[OACB WARN] %s (%s tier | risk: %s)\n  Rule: %s\n  Command: %.120s\n  [A]bort  [C]ontinue (30s → Continue): ' \
      "$reason" "$OACB_TIER" "$effective_risk" \
      "$rule_id" "$cmd_val" >&2

    # One-keystroke abort with 30s timeout (default: Continue)
    local key=""
    if read -rsn1 -t 30 key 2>/dev/null; then
      printf '\n' >&2
      if [[ "$key" == "a" || "$key" == "A" ]]; then
        _audit_line_aborted "$rule_id" "$reason" "$cmd_val"
        emit_block "engineer aborted warned command" "$rule_id"
        exit 2  # belt-and-suspenders: emit_block should have already exited
      fi
    else
      printf '\n' >&2  # timeout → continue
    fi
  fi

  # stdout JSON: tool runs (exit 0 path), reason surfaces to model as context
  if command -v jq >/dev/null 2>&1; then
    jq -cn --arg rule "$rule_id" --arg r "$reason" --arg tier "$OACB_TIER" \
      '{"decision":"approve","reason":("OACB [\($rule)] WARNING (\($tier) tier): \($r). Command allowed — engineer notified.")}'
  fi
  exit 0
}

# --- Central dispatch router -----------------------------------------------

_dispatch() {
  local rule_id="$1" reason="$2" cmd_val="${3:-}"
  local risk
  risk="$(_effective_risk "$rule_id" "$cmd_val")"
  local action
  action="$(_tier_action "$OACB_TIER" "$risk")"
  case "$action" in
    block) emit_block "$reason" "$rule_id" ;;
    warn)  emit_warn  "$rule_id" "$reason" "$cmd_val" ;;
    # ask: hook blocks — the managed-settings ask list would surface a
    # permission prompt to the engineer in Claude Code's UI. At hook layer,
    # we must still exit non-zero so the tool does not run silently.
    ask)   emit_block "$reason" "$rule_id" ;;
    allow) emit_audit_allow "$rule_id" "allow: $reason" "$cmd_val" ;;
  esac
}

# --- Expiry check (receipts tier) -----------------------------------------

_check_expiry() {
  local expires="${OACB_EXPIRES:-}"
  if [[ -n "$expires" ]]; then
    local today
    today="$(date -u +%Y-%m-%d)"
    if [[ "$today" > "$expires" ]]; then
      printf '[OACB] receipts tier expired %s — run `unbound oacb apply` to renew or upgrade\n' "$expires" >&2
    fi
  fi
}

# Fail-closed on signals. Trap installed here, after emit_block is defined
# by the wrapper (sourcing happens after wrapper's function definitions).
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

input_bytes=${#input}
if [[ $input_bytes -gt $OACB_MAX_INPUT_BYTES ]]; then
  emit_block "hook input exceeds $OACB_MAX_INPUT_BYTES bytes ($input_bytes); suspect DoS" "OACB-IO-004"
fi

tool_name="$(echo "$input" | jq -r '.tool_name // empty' 2>/dev/null)"
if [[ -z "$tool_name" ]]; then
  emit_block "could not parse tool_name from hook input" "OACB-IO-002"
fi

# Only handle Bash; defer other tools to their own hooks.
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

cmd="$(printf '%s' "$cmd" | tr -d '\r\0' 2>/dev/null || echo "$cmd")"

# Expiry check for receipts tier (after cmd parsing, before rule evaluation)
[[ "$OACB_TIER" == "receipts" ]] && _check_expiry

# --- shadow tier: log only ------------------------------------------------

if [[ "$OACB_TIER" == "shadow" ]]; then
  cmd_head="${cmd:0:200}"
  mkdir -p "$(dirname "$OACB_AUDIT_LOG")" 2>/dev/null || true
  if command -v jq >/dev/null 2>&1; then
    jq -cn \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg tier "shadow" \
      --arg cmd "$cmd_head" \
      --arg ver "$OACB_VERSION" \
      '{ts:$ts,decision:"allow",tier:$tier,rule:"OACB-SHADOW",risk:"low",risk_taxonomy_version:"1.0",reason:"shadow tier — logged, not enforced",cmd:$cmd,oacb_version:$ver}' \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  else
    local cmd_safe="${cmd_head//\"/\\\"}"
    printf '{"ts":"%s","decision":"allow","tier":"shadow","rule":"OACB-SHADOW","risk":"low","risk_taxonomy_version":"1.0","reason":"shadow tier — logged, not enforced","cmd":"%s","oacb_version":"%s"}\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$cmd_safe" "$OACB_VERSION" \
      >> "$OACB_AUDIT_LOG" 2>/dev/null || true
  fi
  exit 0
fi

# --- normalization --------------------------------------------------------

normalized="$(echo "$cmd" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')"
dewhitespaced="$(echo "$normalized" | sed -E 's/\$\{IFS\}/ /g; s/\$'\''\\x20'\''/ /g')"
unquoted="$(echo "$dewhitespaced" | sed -E "s/'[^']*'/'QUOTED'/g; s/\"[^\"]*\"/\"QUOTED\"/g")"

# --- obfuscation detection ------------------------------------------------

if echo "$unquoted" | grep -qE '(^|[^a-zA-Z0-9])\\(rm|curl|wget|ssh|nc|ncat|chmod|chown|sudo|doas)'; then
  _dispatch "OACB-OBF-001" "backslash-escaped binary detected (deny-evasion pattern)" "$cmd"
fi

if echo "$unquoted" | grep -qE '\$\(\s*echo\s+(rm|curl|wget|dd|mkfs|format|shred)\s*\)|`\s*echo\s+(rm|curl|wget|dd|mkfs)\s*`'; then
  _dispatch "OACB-OBF-005" "command-substitution resolves to dangerous binary (Flatt-class bypass)" "$cmd"
fi

if echo "$unquoted" | grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*:?-?(rm|curl|wget|dd)\}'; then
  _dispatch "OACB-OBF-006" "variable-substitution default resolves to dangerous binary" "$cmd"
fi

if echo "$unquoted" | grep -qE 'base64[[:space:]]+(-d|--decode|-D)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(bash|sh|zsh)\b'; then
  _dispatch "OACB-OBF-002" "base64-decode piped to shell (known exfil / RCE pattern)" "$cmd"
fi

if echo "$unquoted" | grep -qE '(bash|sh|zsh)\s*<\(\s*(curl|wget)'; then
  _dispatch "OACB-OBF-003" "process-substitution exec of remote content" "$cmd"
fi

if echo "$unquoted" | grep -q '/proc/self/root/'; then
  _dispatch "OACB-OBF-004" "/proc/self/root path traversal; known sandbox-bypass pattern" "$cmd"
fi

# --- compound command (Adversa CVE class) ---------------------------------

sep_count=$(echo "$unquoted" | grep -oE '(&&|\|\||;)' | wc -l | tr -d ' ')
if [[ "${sep_count:-0}" -gt 10 ]]; then
  _dispatch "OACB-COMPOUND-001" "compound command has $sep_count separators, exceeds OACB limit (10)" "$cmd"
fi

# --- destructive rm (T-10) ------------------------------------------------

_has_destructive_rm_flags() {
  local s="$1"
  echo "$s" | grep -qE '\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*[fF]|-[a-zA-Z]*[fF][a-zA-Z]*[rR])\b' && return 0
  echo "$s" | grep -qE '\brm\s+(-[rR]\b[[:space:]]+-[fF]\b|-[fF]\b[[:space:]]+-[rR]\b)' && return 0
  echo "$s" | grep -qE '\brm\s+.*(--recursive\b.*--force\b|--force\b.*--recursive\b)' && return 0
  return 1
}
# Note: _targets_sensitive_path is defined above (near top of file)

if _has_destructive_rm_flags "$unquoted" && _targets_sensitive_path "$unquoted"; then
  _dispatch "OACB-RM-001" "destructive rm against home/root/system path" "$cmd"
fi

if _has_destructive_rm_flags "$unquoted"; then
  if echo "$unquoted" | grep -qE '\brm\b[^;|&]*[[:space:]](/|~|\$HOME|\$\{HOME\})\*|\brm\b[^;|&]*[[:space:]](/|~|\$HOME|\$\{HOME\})/[^[:space:]]*\*'; then
    _dispatch "OACB-RM-002" "destructive rm with glob against home/root wildcard" "$cmd"
  fi
fi

if echo "$unquoted" | grep -qE '\bfind\s+(/|\$HOME|~|\$\{HOME\})[[:space:]][^|;&]*-delete\b'; then
  _dispatch "OACB-RM-003" "find -delete against home/root" "$cmd"
fi

if echo "$unquoted" | grep -qE '\bfind\s+(/|\$HOME|~|\$\{HOME\})[[:space:]][^|;&]*-exec\s+rm\b'; then
  _dispatch "OACB-RM-004" "find -exec rm against home/root" "$cmd"
fi

if echo "$unquoted" | grep -qE '\bdd\s+.*of=/dev/(sda|sdb|sdc|nvme|disk|hda|hdb|mmcblk)'; then
  _dispatch "OACB-RM-005" "dd to block device; disk-wipe class" "$cmd"
fi

if echo "$unquoted" | grep -qE '\bmkfs(\.[a-z0-9]+)?\s+.*/dev/(sda|nvme|disk|hda|mmcblk)'; then
  _dispatch "OACB-RM-006" "mkfs against block device; disk-format class" "$cmd"
fi

# --- git force-push to protected branches --------------------------------

if echo "$unquoted" | grep -qE '\bgit\s+push\s+.*(--force|-f|--force-with-lease)\b.*\b(main|master|release/|prod|production)\b'; then
  _dispatch "OACB-GIT-001" "force-push to main/master/release/prod branch" "$cmd"
fi

# --- terraform destructive -----------------------------------------------

if echo "$unquoted" | grep -qE '\bterraform\s+destroy\b'; then
  _dispatch "OACB-TF-001" "terraform destroy is an irreversible operation" "$cmd"
fi
if echo "$unquoted" | grep -qE '\bterraform\s+apply\b.*--auto-approve\b'; then
  _dispatch "OACB-TF-002" "terraform apply --auto-approve in autonomous mode" "$cmd"
fi
if echo "$unquoted" | grep -qE '\bterraform\s+state\s+rm\b'; then
  _dispatch "OACB-TF-003" "terraform state rm can cause silent state divergence" "$cmd"
fi

# --- destructive DB migrations --------------------------------------------

if echo "$unquoted" | grep -qE '\bdrizzle-kit\s+push\b.*--force\b'; then
  _dispatch "OACB-DB-001" "drizzle-kit push --force against any database" "$cmd"
fi
if echo "$unquoted" | grep -qE '\bprisma\s+migrate\s+reset\b'; then
  _dispatch "OACB-DB-002" "prisma migrate reset drops all tables" "$cmd"
fi
if echo "$unquoted" | grep -qE '\balembic\s+downgrade\b'; then
  _dispatch "OACB-DB-003" "alembic downgrade without human approval" "$cmd"
fi

# --- remote-to-shell pipe (T-20) ------------------------------------------

_extract_url_host() {
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

_check_curl_pipe_per_clause() {
  local full="$1"
  local OLD_IFS="$IFS"
  IFS=$'\n'
  local clauses
  clauses=$(printf '%s\n' "$full" | sed -E 's/(&&|\|\||;)/\n/g')
  while IFS= read -r clause; do
    [[ -z "$clause" ]] && continue
    if echo "$clause" | grep -qE '\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(bash|sh|zsh|ksh)\b'; then
      local host
      host="$(_extract_url_host "$clause")"
      if [[ -z "$host" ]] || ! _is_trusted_installer_host "$host"; then
        IFS="$OLD_IFS"
        _dispatch "OACB-NET-001" "remote-to-shell pipe; known RCE vector (host=${host:-unknown}) in clause: $(echo "$clause" | head -c 120)" "$cmd"
      fi
    fi
  done <<< "$clauses"
  IFS="$OLD_IFS"
}

if echo "$unquoted" | grep -qE '\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(bash|sh|zsh|ksh)\b'; then
  _check_curl_pipe_per_clause "$unquoted"
  emit_audit_allow "OACB-NET-001-ALLOW" "all curl|sh clauses map to trusted installer hosts" "$cmd"
fi

# --- netcat / socat / bash tcp ---------------------------------------------

if echo "$unquoted" | grep -qE '\b(nc|ncat|socat|telnet)\s+\S'; then
  _dispatch "OACB-NET-002" "netcat/socat/telnet-family invocation; network egress / reverse-shell class" "$cmd"
fi
if echo "$unquoted" | grep -qE '\b(bash|sh|zsh|ksh)\b[^;|]*/dev/tcp/'; then
  _dispatch "OACB-NET-003" "bash /dev/tcp reverse-shell pattern" "$cmd"
fi

# --- history / eval -------------------------------------------------------

if echo "$unquoted" | grep -qE '\bhistory\s+-[as]\b'; then
  _dispatch "OACB-HIST-001" "history -s/-a manipulation; known denylist-bypass primitive" "$cmd"
fi

if echo "$unquoted" | grep -qE '(^|\W)eval\s+'; then
  _dispatch "OACB-EVAL-001" "eval is prohibited at OACB baseline" "$cmd"
fi

# --- credential exfil via env enum ----------------------------------------

if echo "$dewhitespaced" | grep -qE '\benv\b[[:space:]]*\|[[:space:]]*grep\b'; then
  if echo "$dewhitespaced" | grep -qiE '(token|key|secret|password|credential|api_key|apikey|bearer)'; then
    _dispatch "OACB-EXFIL-001" "environment enumeration for credentials" "$cmd"
  fi
fi
if echo "$dewhitespaced" | grep -qE '\bprintenv\b[[:space:]]*\|[[:space:]]*grep\b'; then
  if echo "$dewhitespaced" | grep -qiE '(token|key|secret|password|credential)'; then
    _dispatch "OACB-EXFIL-001" "printenv enumeration for credentials" "$cmd"
  fi
fi

# --- default: allow --------------------------------------------------------

emit_audit_allow "OACB-DEFAULT-ALLOW" "no deny rule matched" "$cmd"
exit 0
