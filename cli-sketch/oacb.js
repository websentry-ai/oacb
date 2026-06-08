// src/commands/oacb.js
//
// SKETCH — not yet merged. This is the proposed shape of the `unbound oacb`
// subcommand to be added to `github.com/websentry-ai/unbound-cli`.
//
// Follows the existing Commander v12 pattern from src/commands/policy.js.
// Reuses: src/auth.js (ensureLoggedIn), src/api.js (get/post),
//         src/config.js, src/output.js, src/commands/setup.js
//
// Dependencies (new): node:fs/promises, node:path, node:https

'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { ensureLoggedIn } = require('../auth');
const api = require('../api');
const { readConfig } = require('../config');
const output = require('../output');
const { runSetupAllBundle, checkRoot } = require('./setup');

// OACB baseline content is pinned per release. Fetched from the OSS repo at
// github.com/websentry-ai/oacb. Pinned commit hash is embedded at CLI build time.
const OACB_BASELINE_SOURCE = 'https://raw.githubusercontent.com/websentry-ai/oacb';
const OACB_PINNED_REF = 'v0.2.0'; // bumped per unbound-cli release

const TIERS = ['shadow', 'baseline', 'strict', 'paranoid'];

function register(program) {
  const cmd = program
    .command('oacb')
    .description('OACB — Open Autonomous Coding-agent Baseline. Apply, audit, and manage the security baseline for Claude Code.')
    .addHelpText('after', `
Quick start:
  unbound oacb check                         # pre-flight validation
  unbound oacb audit                         # score current config vs baseline
  unbound oacb apply                         # apply shadow tier (default)
  unbound oacb apply --tier baseline         # turn on enforcement
  unbound oacb apply --tier strict           # regulated / pre-prod
  unbound oacb apply --tier paranoid         # FedRAMP / high-sensitivity
  unbound oacb doctor                        # adversarial self-test

Read the framework at https://github.com/websentry-ai/oacb before applying baseline or higher.`);

  cmd.command('check')
    .description('Pre-flight validation: Claude Code install, config state, supported version')
    .action(async () => {
      try { await handleCheck(); } catch (e) { output.error(e.message); process.exitCode = 1; }
    });

  cmd.command('audit')
    .description('Score the current Claude Code config against the OACB baseline; report gaps by ASI ID')
    .option('--tier <tier>', `compare against a specific tier (${TIERS.join('|')})`, 'baseline')
    .option('--format <fmt>', 'json | table', 'table')
    .action(async (opts) => {
      try { await handleAudit(opts); } catch (e) { output.error(e.message); process.exitCode = 1; }
    });

  cmd.command('apply')
    .description('Apply the OACB baseline to the current device (or fleet via --mdm)')
    .option('--tier <tier>', `one of ${TIERS.join('|')}`, 'shadow')
    .option('--mdm', 'root-mode: apply to all users on this device (mirrors `unbound setup mdm`)', false)
    .option('--overrides <path>', 'path to a local override JSON layered on top of the baseline tier')
    .option('--dry-run', 'compute the diff but do not apply', false)
    .action(async (opts) => {
      try { await handleApply(opts); } catch (e) { output.error(e.message); process.exitCode = 1; }
    });

  cmd.command('doctor')
    .description('Run a subset of the adversarial corpus against the installed config')
    .option('--tier <tier>', `evaluate assuming tier ${TIERS.join('|')}`, 'baseline')
    .action(async (opts) => {
      try { await handleDoctor(opts); } catch (e) { output.error(e.message); process.exitCode = 1; }
    });

  cmd.command('diff')
    .description('Show the diff between the currently-applied OACB tier and a target tier')
    .option('--from <tier>', 'current tier (auto-detected if omitted)')
    .option('--to <tier>', 'target tier', 'baseline')
    .action(async (opts) => {
      try { await handleDiff(opts); } catch (e) { output.error(e.message); process.exitCode = 1; }
    });
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async function handleCheck() {
  output.info('OACB pre-flight check');
  const cfg = await readConfig();
  const hasUnboundCli = !!cfg.api_key;
  const settingsPath = path.join(require('node:os').homedir(), '.claude', 'settings.json');
  let claudeCodeInstalled = false;
  let claudeCodeVersion = null;
  let currentSettings = null;

  try {
    currentSettings = JSON.parse(await fs.readFile(settingsPath, 'utf8'));
    claudeCodeInstalled = true;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }

  // Detect Claude Code via CLI presence and --version
  try {
    const { execSync } = require('node:child_process');
    claudeCodeVersion = execSync('claude --version', { stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 }).toString().trim();
  } catch (_) { /* not installed or not on PATH */ }

  output.table({
    'unbound-cli authenticated': hasUnboundCli,
    'Claude Code on PATH': !!claudeCodeVersion,
    'Claude Code version': claudeCodeVersion || 'not detected',
    'Claude Code settings.json': claudeCodeInstalled ? settingsPath : 'not found',
    'OACB pinned ref': OACB_PINNED_REF,
  });

  if (!hasUnboundCli) { output.warn('Run `unbound login` first.'); }
  if (!claudeCodeInstalled) { output.warn('No ~/.claude/settings.json found. Is Claude Code installed?'); }
  if (claudeCodeVersion && !isVersionSupported(claudeCodeVersion)) {
    output.warn(`Claude Code ${claudeCodeVersion} is outside OACB's supported range (>=2.1.83 <3.0.0). Proceed with caution.`);
  }

  // Check for existing OACB-applied policies
  if (hasUnboundCli) {
    try {
      const policies = await api.get('/api/v1/command-policies/', {});
      const oacbPolicies = (policies.policies || []).filter(p => (p.name || '').startsWith('oacb/'));
      output.info(`OACB policies currently applied to your org: ${oacbPolicies.length}`);
      if (oacbPolicies.length > 0) {
        const tiers = new Set(oacbPolicies.map(p => p.name.split('/')[1]));
        output.info(`Detected tiers: ${[...tiers].join(', ')}`);
      }
    } catch (_) { /* ignore */ }
  }
  output.success('Pre-flight complete.');
}

async function handleAudit({ tier, format }) {
  validateTier(tier);
  await ensureLoggedIn();
  const baseline = await fetchBaseline(tier);
  const current = await loadCurrentSettings();
  const gaps = computeGaps(current, baseline);

  if (format === 'json') {
    process.stdout.write(JSON.stringify({ tier, gaps, ref: OACB_PINNED_REF }, null, 2) + '\n');
    return;
  }

  output.info(`OACB audit — tier=${tier}`);
  if (gaps.length === 0) {
    output.success('No gaps. Current config satisfies the OACB tier baseline.');
    return;
  }
  output.warn(`${gaps.length} gap(s) found:`);
  for (const gap of gaps) {
    console.log(`  [${gap.asi}] ${gap.ruleId}  ${gap.description}`);
    if (gap.recommendation) console.log(`           → ${gap.recommendation}`);
  }
  output.info(`Run \`unbound oacb apply --tier ${tier}\` to remediate.`);
}

async function handleApply({ tier, mdm, overrides, dryRun }) {
  validateTier(tier);

  if (mdm) { checkRoot(); }

  await ensureLoggedIn();

  const baseline = await fetchBaseline(tier);
  let effective = baseline;
  if (overrides) {
    const overrideJson = JSON.parse(await fs.readFile(overrides, 'utf8'));
    effective = mergeOverrides(baseline, overrideJson);
  }

  if (dryRun) {
    output.info('--dry-run: showing what would be applied');
    console.log(JSON.stringify(effective, null, 2));
    return;
  }

  if (tier !== 'shadow') {
    output.warn(`You are applying tier=${tier}. This WILL block tool calls.`);
    output.warn('If you have not run tier=shadow for 2+ weeks, consider stepping down.');
  }

  // Apply via backend policy API: iterate rules, POST individual policies
  const rulesApplied = await applyRulesToBackend(effective, tier);

  // Write hardened hook + settings overlay locally (delegate to oacb/setup.py in websentry-ai/setup)
  // In --mdm mode, delegate to oacb/mdm/setup.py for all-users install
  await runSetupForOacb({ tier, mdm });

  output.success(`OACB ${tier} applied. ${rulesApplied} policies written to backend. Hook installed.`);
  if (tier === 'shadow') {
    output.info('Next step: review audit log at ~/.claude/hooks/oacb-audit.log for 2 weeks, then graduate to --tier baseline.');
  }
}

async function handleDoctor({ tier }) {
  validateTier(tier);
  const corpus = await fetchAdversarialCorpus();
  const results = [];
  const hookPath = path.join(require('node:os').homedir(), '.claude', 'hooks', 'oacb-enforce.sh');
  try { await fs.access(hookPath); }
  catch { throw new Error(`OACB hook not installed. Run \`unbound oacb apply --tier ${tier}\` first.`); }

  for (const testCase of corpus) {
    const passed = await runAdversarialTest(testCase, hookPath, tier);
    results.push({ ...testCase, passed });
  }

  const passedCount = results.filter(r => r.passed).length;
  output.info(`OACB adversarial self-test — tier=${tier}`);
  output.info(`${passedCount} / ${results.length} cases blocked as expected`);
  const failures = results.filter(r => !r.passed);
  if (failures.length > 0) {
    output.warn('Failures:');
    for (const f of failures) {
      console.log(`  [${f.id}] ${f.description}  →  expected BLOCK (${f.rule}), got ALLOW`);
    }
    process.exitCode = 1;
  } else {
    output.success('All adversarial cases blocked.');
  }
}

async function handleDiff({ from, to }) {
  validateTier(to);
  if (from) validateTier(from);
  // Computed diff between two tiers' JSONs
  const fromTier = from || await detectCurrentTier();
  const a = await fetchBaseline(fromTier);
  const b = await fetchBaseline(to);
  output.info(`Diff: ${fromTier} → ${to}`);
  // Simple deep-diff printer (actual impl uses a small deepDiff helper in utils.js)
  console.log(JSON.stringify(computeDeepDiff(a, b), null, 2));
}

// ---------------------------------------------------------------------------
// Helpers (stubs — implementations delegate to existing patterns in policy.js)
// ---------------------------------------------------------------------------

function validateTier(t) {
  if (!TIERS.includes(t)) throw new Error(`Invalid tier '${t}'. Expected one of: ${TIERS.join(', ')}`);
}

async function fetchBaseline(tier) {
  const url = `${OACB_BASELINE_SOURCE}/${OACB_PINNED_REF}/baseline/claude-code/managed-settings.${tier}.json`;
  // Uses api.js HTTP client with signature verification (cosign-embedded)
  return await api.getRaw(url);
}

async function fetchAdversarialCorpus() {
  const url = `${OACB_BASELINE_SOURCE}/${OACB_PINNED_REF}/adversarial-corpus/runner/expected.json`;
  return await api.getRaw(url);
}

async function loadCurrentSettings() {
  const settingsPath = path.join(require('node:os').homedir(), '.claude', 'settings.json');
  try { return JSON.parse(await fs.readFile(settingsPath, 'utf8')); }
  catch (e) { if (e.code === 'ENOENT') return {}; throw e; }
}

function computeGaps(current, baseline) {
  // Compare current permissions.deny/allow/ask, autoMode, hooks against baseline.
  // Return [] or array of { asi, ruleId, description, recommendation }.
  // Detailed logic omitted in sketch — full impl in policy-compare.js
  return [];
}

async function applyRulesToBackend(settings, tier) {
  // Iterate managed-settings.permissions.deny/ask/allow and hooks,
  // POST each as a /api/v1/command-policies/ with name prefix oacb/<tier>/...
  // Returns count of policies written.
  return 0;
}

async function runSetupForOacb({ tier, mdm }) {
  // Delegate to websentry-ai/setup — oacb/setup.py or oacb/mdm/setup.py
  // Same curl | python3 pattern as existing setup.js
  return true;
}

async function runAdversarialTest(testCase, hookPath, tier) {
  // Invoke hook with testCase.stdinJson, expect exit 2 + stderr containing testCase.ruleId
  return true;
}

async function detectCurrentTier() {
  const policies = await api.get('/api/v1/command-policies/', {});
  const oacbPolicies = (policies.policies || []).filter(p => (p.name || '').startsWith('oacb/'));
  if (oacbPolicies.length === 0) return 'none';
  const tiers = new Set(oacbPolicies.map(p => p.name.split('/')[1]));
  if (tiers.size > 1) return `mixed (${[...tiers].join(',')})`;
  return [...tiers][0];
}

function computeDeepDiff(a, b) { return { _note: 'deep diff implementation in utils.js' }; }
function mergeOverrides(base, overrides) { return { ...base, ...overrides }; }
function isVersionSupported(v) {
  const m = v.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const [maj, min, pat] = [m[1], m[2], m[3]].map(Number);
  if (maj < 2) return false;
  if (maj === 2 && min < 1) return false;
  if (maj === 2 && min === 1 && pat < 83) return false;
  if (maj >= 3) return false;
  return true;
}

module.exports = { register };
