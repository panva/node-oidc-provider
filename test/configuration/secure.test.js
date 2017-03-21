'use strict';

const sinon = require('sinon');
const { expect } = require('chai');
const bootstrap = require('../test_helper');

describe('x-forwarded-proto trust, detection and warnings', function () {
  /* eslint-disable no-console */
  beforeEach(function () {
    sinon.stub(console, 'warn').callsFake(() => {});
  });

  afterEach(function () {
    console.warn.restore();
  });

  context('when not trusted', function () {
    before(bootstrap(__dirname)); // provider
    it('is ignored unless proxy=true is set and warns once', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .set('x-forwarded-proto', 'http')
        .expect(200)
        .expect(/"authorization_endpoint":"http:/)
        .then(() => {
          return this.agent.get('/.well-known/openid-configuration')
            .set('x-forwarded-proto', 'https')
            .expect(200)
            .expect(/"authorization_endpoint":"http:/);
        })
        .then(() => {
          return this.agent.get('/.well-known/openid-configuration')
            .set('x-forwarded-proto', 'https')
            .expect(200)
            .expect(/"authorization_endpoint":"http:/)
            .expect(function () {
              expect(console.warn.calledOnce).to.be.true;
            });
        });
    });
  });

  context('when trusted', function () {
    before(bootstrap(__dirname)); // provider
    it('is trusted when proxy=true is set on the koa app', function () {
      this.provider.app.proxy = true;
      return this.agent.get('/.well-known/openid-configuration')
        .set('x-forwarded-proto', 'https')
        .expect(200)
        .expect(/"authorization_endpoint":"https:/)
        .then(() => {
          return this.agent.get('/.well-known/openid-configuration')
            .set('x-forwarded-proto', 'https')
            .expect(200)
            .expect(/"authorization_endpoint":"https:/)
            .expect(function () {
              expect(console.warn.called).to.be.false;
            });
        });
    });
  });
});
