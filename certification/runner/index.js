/* eslint-env mocha */
/* eslint-disable no-bitwise, func-names, no-console, no-restricted-syntax, no-await-in-loop */

const { strict: assert } = require('assert');
const fs = require('fs');

const parallel = require('mocha.parallel');

const debug = require('./debug');
const API = require('./api');

const {
  SUITE_ACCESS_TOKEN,
  SUITE_BASE_URL = 'https://www.certification.openid.net',
} = process.env;

let {
  CONFIGURATION = './certification/plan.json',
  PLAN_NAME,
  VARIANT,
  SKIP,
} = process.env;

if ('SETUP' in process.env) {
  let configurationFile;
  ({
    configuration: configurationFile,
    plan: PLAN_NAME,
    skip: SKIP,
    ...VARIANT
  } = JSON.parse(process.env.SETUP));
  CONFIGURATION = configurationFile || CONFIGURATION;
  VARIANT = JSON.stringify(VARIANT);
}

assert(PLAN_NAME, 'process.env.PLAN_NAME missing');
assert(CONFIGURATION, 'process.env.CONFIGURATION missing');

const configuration = JSON.parse(fs.readFileSync(CONFIGURATION));
const runner = new API({ baseUrl: SUITE_BASE_URL, bearerToken: SUITE_ACCESS_TOKEN });

if ('alias' in configuration) {
  configuration.alias = `${configuration.alias}-${Object.values(JSON.parse(VARIANT)).join('-')}`;
}

if (JSON.parse(VARIANT).client_registration === 'dynamic_client') {
  delete configuration.alias;
}

runner.createTestPlan({
  configuration,
  planName: PLAN_NAME,
  variant: VARIANT,
}).then((plan) => {
  let { modules: MODULES } = plan;
  const { id: PLAN_ID } = plan;

  MODULES = MODULES.sort(() => Math.random() - 0.5);

  debug('Created test plan, new id %s', PLAN_ID);
  debug('%s/plan-detail.html?plan=%s', SUITE_BASE_URL, PLAN_ID);
  debug('modules to test %O', MODULES);

  SKIP = SKIP || ('SKIP' in process.env ? process.env.SKIP.split(',') : []);

  if (fs.existsSync('.download')) {
    fs.unlinkSync('.download');
  }

  describe(PLAN_NAME, () => {
    after(() => {
      if (fs.existsSync('.download')) {
        fs.unlinkSync('.download');
        return runner.downloadArtifact({ planId: PLAN_ID });
      }
      return undefined;
    });

    parallel('', () => {
      for (const { testModule, variant } of MODULES) {
        const test = SKIP.includes(testModule) ? it.skip : it;
        test(`${testModule}, ${JSON.stringify(variant)}`, async () => {
          debug('\n\nRunning test module: %s', testModule);
          const { id: moduleId } = await runner.createTestFromPlan({
            plan: PLAN_ID, test: testModule, variant,
          });
          debug('Created test module, new id: %s', moduleId);
          debug('%s/log-detail.html?log=%s', SUITE_BASE_URL, moduleId);
          try {
            await runner.waitForState({ moduleId });
          } catch (err) {
            fs.writeFileSync('.download', 'foo');
            throw err;
          }
        });
      }
    });

    if (configuration.alias) {
      parallel.limit(1);
    } else {
      parallel.limit(10);
    }
  });

  run();
}).catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
