'use strict';

const bootstrap = require('../test_helper');
const _ = require('lodash');
const { expect } = require('chai');

describe('default routing behavior', () => {
  describe('without mounting', () => {
    const { agent } = bootstrap(__dirname);
    it('handles invalid verbs with 405 invalid request', () => {
      return agent.post('/.well-known/openid-configuration')
      .expect(405)
      .expect({
        error: 'invalid_request',
        error_description: 'method not allowed'
      });
    });

    it('handles invalid verbs with 405 invalid request', () => {
      return agent.trace('/.well-known/openid-configuration')
      .expect(501)
      .expect({
        error: 'invalid_request',
        error_description: 'not implemented'
      });
    });

    it('handles unrecognized routes with 404 json response', () => {
      return agent.get('/foobar')
      .expect(404)
      .expect('content-type', /application\/json/)
      .expect({
        error: 'invalid_request',
        error_description: 'unrecognized route'
      });
    });
  });

  describe('when mounted', () => {
    const { agent } = bootstrap(__dirname, undefined, '/oidc');

    it('handles being prefixed', () => {
      return agent.get('/oidc/.well-known/openid-configuration')
      .expect(200)
      .expect((res) => {
        _.forEach(res.body, (value) => {
          if (value.startsWith && value.startsWith('http')) {
            expect(value).to.match(new RegExp('^http://127.0.0.1:\\d{5}/oidc'));
          }
        });
      });
    });

    it('handles unrecognized routes with 404 json response', () => {
      return agent.get('/oidc/foobar')
      .expect(404)
      .expect('content-type', /application\/json/)
      .expect({
        error: 'invalid_request',
        error_description: 'unrecognized route'
      });
    });

    it('does not interfere with the unmounted namespace', () => {
      return agent.get('/foobar')
      .expect(404)
      .expect('Not Found');
    });
  });
});
