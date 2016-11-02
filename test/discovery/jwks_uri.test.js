'use strict';

const bootstrap = require('../test_helper');

const { expect } = require('chai');

const route = '/certs';

describe(route, function () {
  before(bootstrap(__dirname)); // agent

  describe('when populated with signing keys', function () {
    it('responds with json 200', function () {
      return this.agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(200)
        .expect((res) => {
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'e', 'n']);
        });
    });
  });

  describe('EC keys', function () {
    it('responds with json 200', function () {
      return this.agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(200)
        .expect((res) => {
          expect(res.body.keys[1]).to.have.all.keys(['kty', 'kid', 'crv', 'x', 'y']);
        });
    });
  });
});
