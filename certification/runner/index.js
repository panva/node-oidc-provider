/* eslint-env mocha */
/* eslint-disable no-bitwise, func-names, no-console, no-multi-assign */

import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';

import debug from './debug.js';
import API from './api.js';

const {
  SUITE_ACCESS_TOKEN,
  SUITE_BASE_URL = 'https://www.certification.openid.net',
  SETUP,
} = process.env;

assert(SETUP, 'process.env.SETUP missing');

const {
  plan: PLAN_NAME,
  ...VARIANT
} = JSON.parse(process.env.SETUP);

let SKIP;
let CONFIGURATION;
if (PLAN_NAME.startsWith('fapi')) {
  VARIANT.fapi_profile = 'plain_fapi';
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
  configuration.alias = `${configuration.alias}-${Object.values(VARIANT).sort().join('-')}`;
}

function removeOpenidScope(config) {
  for (const client of [config.client, config.client2]) {
    const scope = new Set(client.scope.split(' '));
    scope.delete('openid');
    // eslint-disable-next-line no-param-reassign
    client.scope = [...scope].join(' ');
  }
}

const auth = VARIANT.client_auth_type === 'mtls' ? 'mtls' : 'pkjwt';
let override;
// eslint-disable-next-line default-case
switch (PLAN_NAME) {
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

function summary(prefix, failedTests) {
  const backticks = '```';

  fs.writeFileSync(process.env.GITHUB_STEP_SUMMARY, `
${prefix} Plan Name: \`${PLAN_NAME}\`

${prefix} Variant:

${backticks}json
${JSON.stringify(VARIANT, null, 4)}
${backticks}

<details>
<summary>Expand Configuration</summary>

${backticks}json
${JSON.stringify(configuration, null, 4)}
${backticks}

</details>

`, { flag: 'a' });

  if (failedTests) {
    fs.writeFileSync(process.env.GITHUB_STEP_SUMMARY, `
${prefix} Tests:
${[...new Set(failedTests.map((test) => `* \`${test.split(',')[0]}\``))].join('\n')}
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

  debug('Created test plan, new id %s', PLAN_ID);
  debug('%s/plan-detail.html?plan=%s', SUITE_BASE_URL, PLAN_ID);
  debug('modules to test %O', MODULES);

  const failedTests = [];
  let warned = false;
  describe(PLAN_NAME, () => {
    after(() => {
      if (process.env.GITHUB_STEP_SUMMARY) {
        if (failedTests.length) {
          summary('Failed', failedTests);
        } else if (warned) {
          summary('Warned');
        }
      }

      if (failedTests.length || warned) {
        runner.downloadArtifact({ planId: PLAN_ID });
      }
    });

    afterEach(function () {
      if (this.currentTest.state === 'failed') {
        failedTests.push(this.currentTest.title);
      }
    });

    const skips = SKIP ? SKIP.split(',') : [];
    for (const { testModule, variant } of MODULES) {
      const test = skips.includes(testModule) ? it.skip : it;
      // eslint-disable-next-line no-loop-func
      test(`${testModule}, ${JSON.stringify(variant)}`, async () => {
        debug('\n\nRunning test module: %s', testModule);
        const { id: moduleId } = await runner.createTestFromPlan({
          plan: PLAN_ID, test: testModule, variant,
        });
        debug('Created test module, new id: %s', moduleId);
        debug('%s/log-detail.html?log=%s', SUITE_BASE_URL, moduleId);
        const [, result] = await runner.waitForState({ moduleId });
        if (result === 'WARNING' && testModule !== 'oidcc-ensure-post-request-succeeds') {
          warned ||= true;
        }
      });
    }
  });
} catch (err) {
  console.error(err);
  process.exitCode = 1;
}
