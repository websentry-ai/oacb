#!/usr/bin/env bash
#
# conformance-runner.sh — runs OACB adversarial + false-positive corpus
# against a hook script and reports results.
#
# Usage:
#   ./conformance-runner.sh                     # run all tiers, all cases
#   ./conformance-runner.sh --tier baseline     # specific tier
#   ./conformance-runner.sh --case cve-2025-66032   # specific case
#   ./conformance-runner.sh --expected path/to/expected.json
#
# Output: TAP-like plaintext + JUnit XML when --junit PATH is provided.
# Exit code: 0 if all expected-block cases blocked AND all false-positive cases allowed.
#            1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EXPECTED_FILE="${EXPECTED_FILE:-$SCRIPT_DIR/expected.json}"
export OACB_SHARED_DIR="${OACB_SHARED_DIR:-$REPO_ROOT/baseline/shared}"

AGENT="${AGENT:-claude-code}"
TIERS=("baseline" "strict" "paranoid" "receipts")
SPECIFIC_CASE=""
JUNIT=""
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) AGENT="$2"; shift 2 ;;
    --tier) TIERS=("$2"); shift 2 ;;
    --case) SPECIFIC_CASE="$2"; shift 2 ;;
    --expected) EXPECTED_FILE="$2"; shift 2 ;;
    --junit) JUNIT="$2"; shift 2 ;;
    -v|--verbose) VERBOSE=1; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$AGENT" in
  claude-code|codex|cursor) ;;
  *) echo "Unknown agent: $AGENT (expected: claude-code|codex|cursor)" >&2; exit 2 ;;
esac

_HOOK_BASE="$REPO_ROOT/baseline/$AGENT/hooks"
HOOK_ENFORCE="${HOOK_ENFORCE:-$_HOOK_BASE/oacb-enforce.sh}"
HOOK_PROMPT_GUARD="${HOOK_PROMPT_GUARD:-$_HOOK_BASE/oacb-prompt-guard.sh}"
HOOK_MCP_GUARD="${HOOK_MCP_GUARD:-$_HOOK_BASE/oacb-mcp-guard.sh}"
HOOK_CONFIG_AUDIT="${HOOK_CONFIG_AUDIT:-$_HOOK_BASE/oacb-config-audit.sh}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq required" >&2; exit 2
fi
for _hook in "$HOOK_ENFORCE" "$HOOK_PROMPT_GUARD" "$HOOK_MCP_GUARD" "$HOOK_CONFIG_AUDIT"; do
  if [[ ! -x "$_hook" ]]; then
    echo "ERROR: hook script not executable: $_hook" >&2; exit 2
  fi
done
if [[ ! -f "$EXPECTED_FILE" ]]; then
  echo "ERROR: expected.json not found: $EXPECTED_FILE" >&2; exit 2
fi

# Counters
total=0
passed=0
failed=0
failures=()

run_case() {
  local id="$1"
  local tier="$2"
  local hook="$3"
  local stdin_json="$4"
  local expected_exit="$5"
  local expected_stderr_contains="$6"
  local expected_stdout_permission="$7"
  local description="$8"
  local extra_env_json="${9:-}"           # optional JSON object {"KEY":"VALUE",...}
  local expected_stdout_contains="${10:-}"  # optional substring expected in stdout
  local expected_audit_contains="${11:-}"   # optional substring expected in audit log

  total=$((total+1))

  local actual_stdout actual_stderr actual_exit _stdout_tmp _stderr_tmp
  _stdout_tmp=$(mktemp)
  _stderr_tmp=$(mktemp)

  # Use a per-test temp audit log so we can inspect it afterward
  local _audit_tmp
  _audit_tmp=$(mktemp)

  # Build env: start with OACB_TIER and a temp audit log, then add case-level extras
  local -a env_vars=("OACB_TIER=$tier" "OACB_AUDIT_LOG=$_audit_tmp")
  if [[ -n "$extra_env_json" && "$extra_env_json" != "null" && "$extra_env_json" != "{}" ]]; then
    while IFS= read -r pair; do
      [[ -n "$pair" ]] && env_vars+=("$pair")
    done < <(echo "$extra_env_json" | jq -r 'to_entries[] | "\(.key)=\(.value)"' 2>/dev/null)
  fi

  # Resolve $SCRIPT_DIR in env values (for fixture paths)
  local resolved_env=()
  for v in "${env_vars[@]}"; do
    resolved_env+=("${v//\$SCRIPT_DIR/$SCRIPT_DIR}")
  done

  echo "$stdin_json" | env "${resolved_env[@]}" "$hook" >"$_stdout_tmp" 2>"$_stderr_tmp"
  actual_exit=$?
  actual_stdout=$(cat "$_stdout_tmp")
  actual_stderr=$(cat "$_stderr_tmp")
  local actual_audit
  actual_audit=$(cat "$_audit_tmp" 2>/dev/null || echo "")
  rm -f "$_stdout_tmp" "$_stderr_tmp" "$_audit_tmp"

  local pass=1
  if [[ "$actual_exit" != "$expected_exit" ]]; then
    pass=0
  fi
  if [[ -n "$expected_stderr_contains" && "$pass" == "1" ]]; then
    if ! echo "$actual_stderr" | grep -qF "$expected_stderr_contains"; then
      pass=0
    fi
  fi
  if [[ -n "$expected_stdout_permission" && "$pass" == "1" ]]; then
    local actual_perm
    actual_perm=$(echo "$actual_stdout" | jq -r '.permission // ""' 2>/dev/null || echo "")
    if [[ "$actual_perm" != "$expected_stdout_permission" ]]; then
      pass=0
    fi
  fi
  if [[ -n "$expected_stdout_contains" && "$pass" == "1" ]]; then
    if ! echo "$actual_stdout" | grep -qF "$expected_stdout_contains"; then
      pass=0
    fi
  fi
  if [[ -n "$expected_audit_contains" && "$pass" == "1" ]]; then
    if ! echo "$actual_audit" | grep -qF "$expected_audit_contains"; then
      pass=0
    fi
  fi

  if [[ "$pass" == "1" ]]; then
    passed=$((passed+1))
    [[ "$VERBOSE" == "1" ]] && echo "ok $total - [$AGENT/$tier] $id — $description"
  else
    failed=$((failed+1))
    failures+=("[$AGENT/$tier] $id — $description (expected exit=$expected_exit stderr~$expected_stderr_contains; got exit=$actual_exit stderr=$(echo "$actual_stderr" | head -c 200))")
    echo "not ok $total - [$AGENT/$tier] $id — $description" >&2
  fi
}

# expected.json shape:
#   { "cases": [
#       { "id": "...", "hook": "enforce|prompt-guard|mcp-guard", "stdin": {...},
#         "tiers": { "baseline": { "exit": 2, "stderr_contains": "OACB-..." }, ... },
#         "description": "..." },
#       ...
#   ]}

cases=$(jq -c '.cases[]' "$EXPECTED_FILE")
case_count=0

while IFS= read -r case_json; do
  id="$(echo "$case_json" | jq -r '.id')"
  [[ -n "$SPECIFIC_CASE" && "$id" != *"$SPECIFIC_CASE"* ]] && continue

  # Skip cases scoped to specific agents when running a different agent
  case_agents="$(echo "$case_json" | jq -r 'if .agents then .agents | join(",") else "" end')"
  if [[ -n "$case_agents" ]] && ! echo ",$case_agents," | grep -qF ",$AGENT,"; then
    continue
  fi

  case_count=$((case_count+1))

  hook_name="$(echo "$case_json" | jq -r '.hook // "enforce"')"
  case "$hook_name" in
    enforce)      hook_path="$HOOK_ENFORCE" ;;
    prompt-guard) hook_path="$HOOK_PROMPT_GUARD" ;;
    mcp-guard)    hook_path="$HOOK_MCP_GUARD" ;;
    config-audit) hook_path="$HOOK_CONFIG_AUDIT" ;;
    *) echo "Unknown hook: $hook_name" >&2; continue ;;
  esac

  stdin_json="$(echo "$case_json" | jq -c '.stdin')"
  description="$(echo "$case_json" | jq -r '.description // ""')"

  # Case-level env overrides (applies to all tiers in this case)
  case_env="$(echo "$case_json" | jq -c '.env // {}' 2>/dev/null || echo '{}')"

  for tier in "${TIERS[@]}"; do
    tier_spec=$(echo "$case_json" | jq -c --arg t "$tier" '.tiers[$t]')
    [[ "$tier_spec" == "null" ]] && continue
    expected_exit=$(echo "$tier_spec" | jq -r '.exit')
    expected_stderr_contains=$(echo "$tier_spec" | jq -r '.stderr_contains // ""')
    expected_stdout_permission=$(echo "$tier_spec" | jq -r '.stdout_permission // ""')
    expected_stdout_contains=$(echo "$tier_spec" | jq -r '.stdout_contains // ""')
    expected_audit_contains=$(echo "$tier_spec" | jq -r '.audit_contains // ""')
    run_case "$id" "$tier" "$hook_path" "$stdin_json" "$expected_exit" "$expected_stderr_contains" "$expected_stdout_permission" "$description" "$case_env" "$expected_stdout_contains" "$expected_audit_contains"
  done
done <<< "$cases"

# Summary
echo
echo "1..$total"
echo "# agent: $AGENT | ran $total tests across ${#TIERS[@]} tier(s)"
echo "# passed: $passed"
echo "# failed: $failed"

if [[ $failed -gt 0 ]]; then
  echo
  echo "FAILURES:" >&2
  for f in "${failures[@]}"; do
    echo "  - $f" >&2
  done
fi

# Optional JUnit XML
if [[ -n "$JUNIT" ]]; then
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<testsuites name="oacb-conformance">'
    echo "  <testsuite name=\"oacb\" tests=\"$total\" failures=\"$failed\">"
    for f in "${failures[@]}"; do
      local_name=$(echo "$f" | sed 's/"/&quot;/g; s/</\&lt;/g; s/>/\&gt;/g; s/&/\&amp;/g')
      echo "    <testcase name=\"$local_name\"><failure/></testcase>"
    done
    echo "  </testsuite>"
    echo '</testsuites>'
  } > "$JUNIT"
fi

[[ $failed -eq 0 ]]
