import sinon from 'sinon';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('x-forwarded-proto trust, detection and warnings', () => {
  /* eslint-disable no-console */
  beforeEach(() => {
    sinon.stub(console, 'warn').returns();
  });

  afterEach(() => console.warn.restore());

  const acceptUnauthorized = { tls: { rejectUnauthorized: false } };

  context('when not trusted', () => {
    before(bootstrap(import.meta.url, { protocol: 'https:' }));
    it('is ignored unless proxy=true is set and warns once', async function () {
      await this.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .set('x-forwarded-proto', 'https')
        .expect(200)
        .expect(/"authorization_endpoint":"http:/);
      await this.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .set('x-forwarded-proto', 'https')
        .expect(200)
        .expect(/"authorization_endpoint":"http:/);

      expect(console.warn.calledOnce).to.be.true;
      expect(console.warn.calledWithMatch(/x-forwarded-proto header detected but not trusted/)).to.be.true;
    });
  });

  context('when not even detected', () => {
    before(bootstrap(import.meta.url, { protocol: 'https:' }));
    it('is ignored unless proxy=true is set and warns once', async function () {
      await this.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .expect(200)
        .expect(/"authorization_endpoint":"http:/);
      await this.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .expect(200)
        .expect(/"authorization_endpoint":"http:/);

      expect(console.warn.calledOnce).to.be.true;
      expect(console.warn.calledWithMatch(/x-forwarded-proto header not detected for an https issuer/)).to.be.true;
    });
  });

  context('when trusted', () => {
    before(bootstrap(import.meta.url, { protocol: 'https:' }));
    it('is trusted when proxy=true is set on the koa app', async function () {
      if (this.app) {
        this.app.proxy = true;
      } else {
        this.provider.app.proxy = true;
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
