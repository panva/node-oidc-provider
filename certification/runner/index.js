import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { after, describe, it } from 'node:test';

import assertNoFocusedTests from '../../tools/check-test-focus.js';
import API, { assertPlanId } from './api.js';
import debug from './debug.js';
import credentialOfferDriver from './vci.js';

if ('CI' in process.env) assertNoFocusedTests([import.meta.filename]);

const {
  SUITE_ACCESS_TOKEN,
  SUITE_BASE_URL = 'https://www.certification.openid.net',
  SETUP,
} = process.env;

assert(SETUP, 'process.env.SETUP missing');

const {
  plan: PLAN_NAME,
  credential_configuration_id: CREDENTIAL_CONFIGURATION_ID,
  ...VARIANT
} = JSON.parse(process.env.SETUP);

let SKIP;
let CONFIGURATION;
if (PLAN_NAME.startsWith('oid4vci')) {
  CONFIGURATION = './certification/vci/.plan.json';
} else if (PLAN_NAME.startsWith('fapi')) {
  VARIANT[PLAN_NAME.includes('ciba') ? 'fapi_ciba_profile' : 'fapi_profile'] ??= 'plain_fapi';
  CONFIGURATION = './certification/fapi/plan.json';
} else {
  CONFIGURATION = './certification/oidc/plan.json';
}

switch (PLAN_NAME) {
  case 'oidcc-dynamic-certification-test-plan':
    SKIP = 'oidcc-server-rotate-keys,oidcc-request-uri-unsigned,oidcc-request-uri-signed-rs256';
    break;
  case 'oidcc-test-plan':
    SKIP = 'oidcc-server-rotate-keys';
    VARIANT.client_registration = 'dynamic_client';
    VARIANT.response_mode = 'default';
    break;
  case 'fapi-ciba-id1-test-plan':
    VARIANT.client_registration = 'dynamic_client';
    break;
  case 'oidcc-rp-initiated-logout-certification-test-plan':
  case 'oidcc-backchannel-rp-initiated-logout-certification-test-plan':
    VARIANT.client_registration = 'dynamic_client';
    VARIANT.response_type = 'code';
    break;
  case 'oidcc-basic-certification-test-plan':
    VARIANT.server_metadata = 'discovery';
    VARIANT.client_registration = 'dynamic_client';
    break;
  case 'oidcc-hybrid-certification-test-plan':
    VARIANT.server_metadata = 'discovery';
    VARIANT.client_registration = 'dynamic_client';
    break;
  case 'oidcc-implicit-certification-test-plan':
    VARIANT.server_metadata = 'discovery';
    VARIANT.client_registration = 'dynamic_client';
    break;
  case 'fapi2-message-signing-final-test-plan':
    VARIANT.fapi_request_method = 'signed_non_repudiation';
    VARIANT.fapi_response_mode = 'jarm';
    break;
  default:
    break;
}

const configuration = JSON.parse(fs.readFileSync(CONFIGURATION));
const runner = new API({ baseUrl: SUITE_BASE_URL, bearerToken: SUITE_ACCESS_TOKEN });

if ('alias' in configuration) {
  const suffix = [CREDENTIAL_CONFIGURATION_ID, ...Object.values(VARIANT)]
    .filter(Boolean).sort().join('-').replace(/[^A-Za-z0-9_-]/g, '-');
  configuration.alias = `${configuration.alias}-${suffix}`;
}

function removeOpenidScope(config) {
  for (const client of [config.client, config.client2]) {
    const scope = new Set(client.scope.split(' '));
    scope.delete('openid');
    client.scope = [...scope].join(' ');
  }
}

const auth = VARIANT.client_auth_type === 'mtls' ? 'mtls' : 'pkjwt';
let override;
switch (PLAN_NAME) {
  case 'oid4vci-1_0-issuer-haip-test-plan':
  case 'oid4vci-1_0-issuer-test-plan':
    override = 'fapi2-security-profile-final';
    break;
  case 'fapi1-advanced-final-test-plan': {
    const revision = 'final';
    override = 'fapi1-advanced-final';
    configuration.client.client_id = `1.0-${revision}-${auth}-one`;
    configuration.client2.client_id = `1.0-${revision}-${auth}-two`;
    break;
  }
  case 'fapi2-security-profile-final-test-plan':
  case 'fapi2-message-signing-final-test-plan': {
    override = 'fapi2-security-profile-final';
    const spec = PLAN_NAME.split('-').slice(1, 3).join('').replace('-', ''); // securityprofile or messagesigning
    if (VARIANT.openid === 'plain_oauth') {
      removeOpenidScope(configuration);
    }
    configuration.client.client_id = `2.0-${spec}-${auth}-${VARIANT.sender_constrain}-one`;
    configuration.client2.client_id = `2.0-${spec}-${auth}-${VARIANT.sender_constrain}-two`;
    break;
  }
}

if (override) {
  configuration.override = Object.entries(configuration.override).reduce((acc, [key, value]) => {
    acc[key.replace('REPLACEME', override)] = value;
    return acc;
  }, {});
}

if (VARIANT.client_registration === 'dynamic_client') {
  delete configuration.alias;
}

if (PLAN_NAME.startsWith('fapi2') && VARIANT.client_auth_type !== 'mtls' && VARIANT.sender_constrain !== 'mtls') {
  delete configuration.mtls;
  delete configuration.mtls2;
}

function markdownCode(value) {
  const text = String(value).replaceAll('\r', '\\r').replaceAll('\n', '\\n');
  const backticks = text.match(/`+/g) ?? [];
  const fence = '`'.repeat(Math.max(1, ...backticks.map((run) => run.length + 1)));
  return `${fence} ${text} ${fence}`;
}

function summary(status, planId, affectedTests) {
  const backticks = '```';
  const heading = status === 'failure' ? '## ❌ Conformance failure' : '## ⚠️ Conformance warning';

  fs.writeFileSync(process.env.GITHUB_STEP_SUMMARY, `
${heading}

- Plan: ${markdownCode(PLAN_NAME)}
- Plan ID: ${markdownCode(planId)}

<details>
<summary>Variant</summary>

${backticks}json
${JSON.stringify(VARIANT, null, 2)}
${backticks}

</details>

`, { flag: 'a' });

  if (affectedTests.length) {
    fs.writeFileSync(process.env.GITHUB_STEP_SUMMARY, `
### Affected tests

${[...new Set(affectedTests.map((test) => `- ${markdownCode(test.split(',')[0])}`))].join('\n')}
`, { flag: 'a' });
  }
}

try {
  const plan = await runner.createTestPlan({
    configuration,
    planName: PLAN_NAME,
    variant: JSON.stringify(VARIANT),
  });

  const { id: PLAN_ID, modules: MODULES } = plan;
  assertPlanId(PLAN_ID);
  assert(Array.isArray(MODULES) && MODULES.length > 0, 'test plan has no modules');

  debug('Created test plan, new id %s', PLAN_ID);
  debug('%s/plan-detail.html?plan=%s', SUITE_BASE_URL, PLAN_ID);
  debug('modules to test %O', MODULES);

  const failedTests = [];
  const warningTests = [];
  describe(PLAN_NAME, { concurrency: false }, () => {
    after(async () => {
      if (process.env.GITHUB_STEP_SUMMARY) {
        if (failedTests.length) {
          summary('failure', PLAN_ID, [...failedTests, ...warningTests]);
        } else if (warningTests.length) {
          summary('warning', PLAN_ID, warningTests);
        }
      }

      if (failedTests.length || warningTests.length) {
        await runner.downloadArtifact({ planId: PLAN_ID });
      }
    });

    const skips = SKIP ? SKIP.split(',') : [];
    for (const { testModule, variant } of MODULES) {
      const title = `${testModule}, ${JSON.stringify(variant)}`;
      it(title, { skip: skips.includes(testModule) }, async (t) => {
        // A retry creates a fresh conformance module, just as the previous
        // runner did. Keep the plan's modules sequential on every runtime.
        for (let attempt = 0; attempt < 2; attempt += 1) {
          try {
            debug('\n\nRunning test module: %s', testModule);
            const { id: moduleId } = await runner.createTestFromPlan({
              plan: PLAN_ID, test: testModule, variant,
            });
            debug('Created test module, new id: %s', moduleId);
            debug('%s/log-detail.html?log=%s', SUITE_BASE_URL, moduleId);
            const onUpdate = VARIANT.vci_authorization_code_flow_variant === 'issuer_initiated'
              ? credentialOfferDriver(configuration, runner, moduleId) : undefined;
            const [, result] = await runner.waitForState({ moduleId, onUpdate });
            if (result === 'WARNING' && testModule !== 'oidcc-ensure-post-request-succeeds') {
              warningTests.push(testModule);
            }
            return;
          } catch (err) {
            if (attempt === 1) {
              failedTests.push(title);
              throw err;
            }
            t.diagnostic(`Retrying after failure: ${err.message}`);
          }
        }
      });
    }
  });
} catch (err) {
  describe(PLAN_NAME, () => {
    it('creates test plan', () => {
      throw err;
    });
  });
}
