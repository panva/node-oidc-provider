'use strict';

const { request } = require('../test_helper')(__dirname);
const route = '/.well-known/openid-configuration';

describe(route, () => {

  describe('GET', () => {
    it('responds with JSON 200', () => {
      return request.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(200);
    });
  });

});
