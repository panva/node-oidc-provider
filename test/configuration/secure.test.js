import sinon from 'sinon';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('x-forwarded-proto trust', () => {
  /* eslint-disable no-console */
  beforeEach(() => {
    sinon.stub(console, 'warn').returns();
  });

  afterEach(() => console.warn.restore());

  const acceptUnauthorized = { tls: { rejectUnauthorized: false } };

  context('when trusted', () => {
    before(bootstrap(import.meta.url, { protocol: 'https:' }));
    it('is trusted when proxy=true is set on the koa app', async function () {
      if (this.app) {
        this.app.proxy = true;
      } else {
        this.provider.proxy = true;
      }
      await this.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .set('x-forwarded-proto', 'https')
        .expect(200)
        .expect(/"authorization_endpoint":"https:/);

      await this.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .set('x-forwarded-proto', 'https')
        .expect(200)
        .expect(/"authorization_endpoint":"https:/);

      expect(console.warn.called).to.be.false;
    });
  });
});
