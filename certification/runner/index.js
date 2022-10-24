/* eslint-env mocha */
/* eslint-disable no-bitwise, func-names, no-console, no-restricted-syntax, no-await-in-loop, no-multi-assign, max-len */

const { strict: assert } = require('assert');
const fs = require('fs');

const debug = require('./debug');
const API = require('./api');

const {
  SUITE_ACCESS_TOKEN,
  SUITE_BASE_URL = 'https://www.certification.openid.net',
  SETUP,
} = process.env;

assert(SETUP, 'process.env.SETUP missing');

const {
  configuration: CONFIGURATION,
  plan: PLAN_NAME,
  skip: SKIP,
  ...VARIANT
} = JSON.parse(process.env.SETUP);

const configuration = JSON.parse(fs.readFileSync(CONFIGURATION));
const runner = new API({ baseUrl: SUITE_BASE_URL, bearerToken: SUITE_ACCESS_TOKEN });

if ('alias' in configuration) {
  configuration.alias = `${configuration.alias}-${Object.values(VARIANT).sort().join('-')}`;
}

let override;
// eslint-disable-next-line default-case
switch (PLAN_NAME) {
  case 'fapi1-advanced-final-test-plan': {
    override = 'fapi1-advanced-final';
    const auth = VARIANT.client_auth_type === 'mtls' ? 'mtls' : 'pkjwt';
    configuration.client.client_id = `1.0-final-${auth}-one`;
    configuration.client2.client_id = `1.0-final-${auth}-two`;
    break;
  }
  case 'fapi-rw-id2-test-plan': {
    override = 'fapi-rw-id2';
    const auth = VARIANT.client_auth_type === 'mtls' ? 'mtls' : 'pkjwt';
    configuration.client.client_id = `1.0-id2-${auth}-one`;
    configuration.client2.client_id = `1.0-id2-${auth}-two`;
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

runner.createTestPlan({
  configuration,
  planName: PLAN_NAME,
  variant: JSON.stringify(VARIANT),
}).then((plan) => {
  const { id: PLAN_ID, modules: MODULES } = plan;

  debug('Created test plan, new id %s', PLAN_ID);
  debug('%s/plan-detail.html?plan=%s', SUITE_BASE_URL, PLAN_ID);
  debug('modules to test %O', MODULES);

  let download = false;
  describe(PLAN_NAME, () => {
    after(() => {
      if (download) {
        runner.downloadArtifact({ planId: PLAN_ID });
      }
    });

    afterEach(function () {
      if (this.currentTest.state === 'failed') {
        download = true;
      }
    });

    const skips = SKIP ? SKIP.split(',') : [];
    for (const { testModule, variant } of MODULES) {
      const test = skips.includes(testModule) ? it.skip : it;
      test(`${testModule}, ${JSON.stringify(variant)}`, async () => {
        debug('\n\nRunning test module: %s', testModule);
        const { id: moduleId } = await runner.createTestFromPlan({
          plan: PLAN_ID, test: testModule, variant,
        });
        debug('Created test module, new id: %s', moduleId);
        debug('%s/log-detail.html?log=%s', SUITE_BASE_URL, moduleId);
        await runner.waitForState({ moduleId });
      });
    }
  });

  run();
}).catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
