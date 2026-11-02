import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';
import { fileURLToPath } from 'node:url';

const runner = new URL('../index.js', import.meta.url);
const preload = `
import assert from 'node:assert/strict';
import { appendFileSync } from 'node:fs';

const scenario = JSON.parse(process.env.SCENARIO);
const attempts = new Map();
const modules = new Map();
const record = (event) => appendFileSync('requests.jsonl', JSON.stringify(event) + '\\n');
globalThis.fetch = async (input, options = {}) => {
  const url = new URL(input);
  assert.equal(url.origin, 'https://suite.example');
  if (url.pathname === '/api/plan') {
    record({ type: 'plan', variant: JSON.parse(url.searchParams.get('variant')), configuration: JSON.parse(options.body) });
    if (scenario.planError) return new Response('plan creation failed', { status: 500 });
    return Response.json({ id: 'plan-id', modules: scenario.modules }, { status: 201 });
  }
  if (url.pathname === '/api/runner') {
    const name = url.searchParams.get('test');
    const attempt = (attempts.get(name) ?? 0) + 1;
    attempts.set(name, attempt);
    const id = name + '-' + attempt;
    modules.set(id, { name, attempt });
    record({ type: 'module', name, attempt });
    return Response.json({ id }, { status: 201 });
  }
  if (url.pathname.startsWith('/api/info/')) {
    const { name, attempt } = modules.get(url.pathname.split('/').pop());
    const outcomes = scenario.outcomes?.[name] ?? ['PASSED'];
    const result = outcomes[Math.min(attempt - 1, outcomes.length - 1)];
    record({ type: 'result', name, attempt, result });
    return Response.json({ status: 'FINISHED', result });
  }
  if (url.pathname === '/api/plan/exporthtml/plan-id') {
    record({ type: 'artifact' });
    return new Response('diagnostic archive');
  }
  throw new Error('unexpected request: ' + url.href);
};
`;

function run(t, scenario, setup = { plan: 'oidcc-test-plan' }) {
  const cwd = mkdtempSync(join(tmpdir(), 'oidc-provider-certification-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  mkdirSync(join(cwd, 'certification/oidc'), { recursive: true });
  writeFileSync(join(cwd, 'certification/oidc/plan.json'), JSON.stringify({
    client: { scope: 'openid profile' }, client2: { scope: 'openid profile' },
  }));
  writeFileSync(join(cwd, 'preload.mjs'), preload);
  writeFileSync(join(cwd, 'requests.jsonl'), '');
  writeFileSync(join(cwd, 'summary.md'), '');
  writeFileSync(join(cwd, 'github.env'), '');
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [
    '--import', join(cwd, 'preload.mjs'), '--test', '--test-reporter=tap', '--test-concurrency=1', fileURLToPath(runner),
  ], {
    cwd,
    encoding: 'utf8',
    timeout: 15_000,
    env: {
      ...env,
      CI: 'true',
      DEBUG: '',
      SETUP: JSON.stringify(setup),
      SUITE_BASE_URL: 'https://suite.example',
      SCENARIO: JSON.stringify(scenario),
      GITHUB_STEP_SUMMARY: join(cwd, 'summary.md'),
      GITHUB_ENV: join(cwd, 'github.env'),
    },
  });
  assert.ifError(result.error);
  return {
    ...result,
    requests: readFileSync(join(cwd, 'requests.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)),
    summary: readFileSync(join(cwd, 'summary.md'), 'utf8'),
    environment: readFileSync(join(cwd, 'github.env'), 'utf8'),
    cwd,
  };
}

const module = (testModule) => ({ testModule, variant: {} });

it('runs plan modules sequentially and preserves the configured skips', (t) => {
  const result = run(t, { modules: [module('first'), module('oidcc-server-rotate-keys'), module('second')] });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(result.requests.map(({ type, name }) => [type, name]), [
    ['plan', undefined], ['module', 'first'], ['result', 'first'], ['module', 'second'], ['result', 'second'],
  ]);
  assert.equal(result.requests[0].variant.client_registration, 'dynamic_client');
  assert.equal(result.requests[0].variant.response_mode, 'default');
  assert.match(result.stdout, /# skipped 1/);
  assert.equal(result.summary, '');
  assert.equal(result.environment, '');
});

it('retries a failed module with a fresh conformance module', (t) => {
  const result = run(t, { modules: [module('flaky')], outcomes: { flaky: ['FAILED', 'PASSED'] } });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(result.requests.filter(({ type }) => type === 'module'), [
    { type: 'module', name: 'flaky', attempt: 1 },
    { type: 'module', name: 'flaky', attempt: 2 },
  ]);
  assert.equal(result.summary, '');
  assert.equal(result.environment, '');
});

it('reports final failures and warnings and downloads the plan diagnostics once', (t) => {
  const result = run(t, {
    modules: [module('failed'), module('warned'), module('last')],
    outcomes: { failed: ['FAILED'], warned: ['WARNING'] },
  });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.deepEqual(result.requests.filter(({ type }) => type === 'module').map(({ name, attempt }) => [name, attempt]), [
    ['failed', 1], ['failed', 2], ['warned', 1], ['last', 1],
  ]);
  assert.match(result.summary, /Conformance failure/);
  assert.match(result.summary, /failed/);
  assert.match(result.summary, /warned/);
  assert.equal(result.requests.filter(({ type }) => type === 'artifact').length, 1);
  assert.equal(result.environment, 'EXPORT_FILE=export-plan-id.zip\n');
  assert.equal(readFileSync(join(result.cwd, 'export-plan-id.zip'), 'utf8'), 'diagnostic archive');
});

it('reports warnings without failing and preserves the ignored warning', (t) => {
  const result = run(t, {
    modules: [module('warned'), module('oidcc-ensure-post-request-succeeds')],
    outcomes: { warned: ['WARNING'], 'oidcc-ensure-post-request-succeeds': ['WARNING'] },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.summary, /Conformance warning/);
  assert.match(result.summary, /warned/);
  assert.doesNotMatch(result.summary, /oidcc-ensure-post-request-succeeds/);
  assert.equal(result.requests.filter(({ type }) => type === 'artifact').length, 1);
});

it('fails when a plan is empty', (t) => {
  const result = run(t, { modules: [] });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /test plan has no modules/);
});

it('reports plan creation errors as failed tests', (t) => {
  const result = run(t, { planError: true });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /creates test plan/);
  assert.match(result.stdout, /plan creation failed/);
});
