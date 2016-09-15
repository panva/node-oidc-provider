'use strict';

const bootstrap = require('../test_helper');

const { expect } = require('chai');

const route = '/certs';

describe(route, () => {
  const { agent } = bootstrap(__dirname);

  describe('when populated with signing keys', () => {
    it('responds with json 200', () => {
      return agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(200)
        .expect((res) => {
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'e', 'n']);
        });
    });
  });

  describe('EC keys', () => {
    it('responds with json 200', () => {
      return agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(200)
        .expect((res) => {
          expect(res.body.keys[1]).to.have.all.keys(['kty', 'kid', 'crv', 'x', 'y']);
        });
    });
  });
});
