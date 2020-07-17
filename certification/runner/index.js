/* eslint-env mocha */
/* eslint-disable no-await-in-loop */
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

(async () => {
  assert(PLAN_NAME, 'process.env.PLAN_NAME missing');
  assert(CONFIGURATION, 'process.env.CONFIGURATION missing');

  const configuration = JSON.parse(fs.readFileSync(CONFIGURATION));
  const runner = new API({ baseUrl: SUITE_BASE_URL, bearerToken: SUITE_ACCESS_TOKEN });

  if ('alias' in configuration) {
    configuration.alias = `${configuration.alias}-${Object.values(JSON.parse(VARIANT)).join('-')}`;
  }

  const plan = await runner.createTestPlan({
    configuration,
    planName: PLAN_NAME,
    variant: VARIANT,
  });

  const { id: PLAN_ID, modules: MODULES } = plan;

  debug('Created test plan, new id %s', PLAN_ID);
  debug('%s/plan-detail.html?plan=%s', SUITE_BASE_URL, PLAN_ID);
  debug('modules to test %O', MODULES);

  SKIP = SKIP || ('SKIP' in process.env ? process.env.SKIP.split(',') : []);

  const defineTestSuite = (modules) => {
    for (const { testModule, variant } of modules) { // eslint-disable-line no-restricted-syntax
      const test = SKIP.includes(testModule) ? it.skip : it;
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
  };

  after(async () => {
    await runner.downloadArtifact({ planId: PLAN_ID });
  });

  const runParallel = !('alias' in configuration);
  if (runParallel) {
    const chunks = [];
    do {
      chunks.push(MODULES.splice(0, 50));
    } while (MODULES.length);
    chunks.forEach((modules, i) => {
      parallel(`${PLAN_NAME} chunk ${i + 1}`, () => {
        defineTestSuite(modules);
      });
    });
  } else {
    defineTestSuite(MODULES);
  }

  run();
})().catch((err) => {
  process.exitCode = 1;
  debug(err);
});
