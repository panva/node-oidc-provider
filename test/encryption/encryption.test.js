'use strict';

const {
  provider, agent, AuthorizationRequest, wrap
} = require('../test_helper')(__dirname);
const { expect } = require('chai');
const { parse } = require('url');
const url = require('url');
const jose = require('node-jose');
const { privKey } = require('./encryption.config');
const JWT = require('../../lib/helpers/jwt');

provider.setupClient();
provider.setupCerts();

before(function () {
  return jose.JWK.asKeyStore(privKey).then((keystore) => {
    this.keystore = keystore;
  });
});

['get', 'post'].forEach((verb) => {
  const route = '/auth';

  describe(`[encryption] IMPLICIT id_token+token ${verb} ${route}`, function () {
    before(agent.login);

    before(function () {
      const auth = new AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(auth.validateFragment)
      .expect((response) => {
        const { query } = url.parse(response.headers.location, true);
        this.id_token = query.id_token;
        this.access_token = query.access_token;
      });
    });

    it('responds with a nested encrypted and signed id_token JWT', function () {
      expect(this.id_token).to.be.ok;
      expect(this.id_token.split('.')).to.have.lengthOf(5);

      return jose.JWE.createDecrypt(this.keystore).decrypt(this.id_token).then((result) => {
        expect(result.payload).to.be.ok;
        expect(result.payload.toString().split('.')).to.have.lengthOf(3);
        expect(JWT.decode(result.payload)).to.be.ok;
      });
    });

    it('responds with a nested encrypted and signed userinfo JWT', function (done) {
      agent.get('/me')
        .set('Authorization', `Bearer ${this.access_token}`)
        .expect(200)
        .expect('content-type', /application\/jwt/)
        .expect((response) => {
          expect(response.text.split('.')).to.have.lengthOf(5);
        })
        .end((err, response) => {
          if (err) throw err;
          jose.JWE.createDecrypt(this.keystore)
          .decrypt(response.text)
          .then((result) => {
            expect(result.payload).to.be.ok;
            expect(result.payload.toString().split('.')).to.have.lengthOf(3);
            expect(JWT.decode(result.payload)).to.be.ok;
          })
          .then(done, done);
        });
    });

    it('works with signed by none', function () {
      return JWT.sign({
        client_id: 'client',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb'
      }, null, 'none').then((signed) =>
        JWT.encrypt(signed, provider.keystore.get(), 'A128CBC-HS256', 'RSA1_5')
      ).then((encrypted) =>
        wrap({
          agent,
          route,
          verb,
          auth: {
            request: encrypted,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code'
          }
        })
        .expect(302)
        .expect(function (response) {
          const expected = parse('https://client.example.com/cb', true);
          const actual = parse(response.headers.location, true);
          ['protocol', 'host', 'pathname'].forEach((attr) => {
            expect(actual[attr]).to.equal(expected[attr]);
          });
          expect(actual.query).to.have.property('code');
        })
      );
    });
  });
});
