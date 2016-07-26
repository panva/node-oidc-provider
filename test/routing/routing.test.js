'use strict';

const bootstrap = require('../test_helper');
const _ = require('lodash');
const { expect } = require('chai');

describe('default routing behavior', function () {
  describe('without mounting', function () {
    const { agent } = bootstrap(__dirname);
    it('handles invalid verbs with 405 invalid request', function () {
      return agent.post('/.well-known/openid-configuration')
      .expect(405)
      .expect({
        error: 'invalid_request',
        error_description: 'method not allowed'
      });
    });

    it('handles invalid verbs with 405 invalid request', function () {
      return agent.trace('/.well-known/openid-configuration')
      .expect(501)
      .expect({
        error: 'invalid_request',
        error_description: 'not implemented'
      });
    });
  });

  describe('when mounted', function () {
    const { agent } = bootstrap(__dirname, undefined, '/oidc');

    it('handles being prefixed', function () {
      return agent.get('/oidc/.well-known/openid-configuration')
      .expect(200)
      .expect(function (res) {
        _.forEach(res.body, function (value) {
          if (value.startsWith && value.startsWith('http')) {
            expect(value).to.match(new RegExp('^http://127.0.0.1:\\d{5}/oidc'));
          }
        });
      });
    });
  });
});
