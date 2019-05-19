const { expect } = require('chai');

const Configuration = require('../../lib/helpers/configuration');

describe('Provider configuration', () => {
  // TODO: remove once https://github.com/pillarjs/cookies/issues/109 lands
  it('removes the none cookie options', () => {
    ['none', 'NONE'].forEach((opt) => {
      const conf = new Configuration({
        cookies: {
          long: {
            sameSite: opt,
          },
          short: {
            sameSite: opt,
          },
        },
      });

      expect(conf.cookies.long).to.have.property('sameSite', undefined);
      expect(conf.cookies.short).to.have.property('sameSite', undefined);
    });
  });
});
