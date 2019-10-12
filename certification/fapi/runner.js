/* eslint-env mocha */
/* eslint-disable no-await-in-loop */
const { strict: assert } = require('assert');
const fs = require('fs');

const debug = require('./debug');
const API = require('./api');

const {
  CONFIGURATION,
  SUITE_ACCESS_TOKEN,
  SUITE_BASE_URL = 'https://www.certification.openid.net',
  PLAN_NAME,
  VARIANT,
} = process.env;

(async () => {
  assert(PLAN_NAME, 'process.env.PLAN_NAME missing');
  assert(CONFIGURATION, 'process.env.CONFIGURATION missing');

  const configuration = JSON.parse(fs.readFileSync(CONFIGURATION));
  const runner = new API({ baseUrl: SUITE_BASE_URL, bearerToken: SUITE_ACCESS_TOKEN });

  const plan = await runner.createTestPlan({
    configuration,
    planName: PLAN_NAME,
    variant: VARIANT,
  });

  const { id: PLAN_ID, modules: MODULES } = plan;

  debug('Created test plan, new id %s', PLAN_ID);
  debug('%s/plan-detail.html?plan=%s', SUITE_BASE_URL, PLAN_ID);
  debug('modules to test %O', MODULES);

  for (const moduleName of MODULES) { // eslint-disable-line no-restricted-syntax
    it(moduleName, async () => {
      debug('\n\nRunning test module: %s', moduleName);
      const { id: moduleId } = await runner.createTestFromPlan({ plan: PLAN_ID, test: moduleName });
      debug('Created test module, new id: %s', moduleId);
      debug('%s/log-detail.html?log=%s', SUITE_BASE_URL, moduleId);
      await runner.waitForState({ moduleId });
    });
  }

  run();
})().catch((err) => {
  process.exitCode = 1;
  debug(err);
});
