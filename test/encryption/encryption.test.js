'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');
const { parse } = require('url');
const url = require('url');
const base64url = require('base64url');
const jose = require('node-jose');
const { privKey } = require('./encryption.config');
const JWT = require('../../lib/helpers/jwt');

const route = '/auth';

['get', 'post'].forEach((verb) => {
  describe(`[encryption] IMPLICIT id_token+token ${verb} ${route}`, function () {
    before(bootstrap(__dirname)); // provider, this.agent, AuthorizationRequest, wrap

    before(function () {
      return jose.JWK.asKeyStore(privKey).then((keystore) => { this.keystore = keystore; });
    });
    before(function () { return this.login(); });

    describe('encrypted authorization results', function () {
      before(function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid'
        });

        return this.wrap({ route, verb, auth })
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

      it('responds with an encrypted userinfo JWT', function (done) {
        this.agent.get('/me')
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

            expect(JSON.parse(result.payload)).to.have.keys('sub');
          })
          .then(done, done);
        });
      });

      describe('userinfo nested signed and encrypted', function () {
        before(function* () {
          const client = yield this.provider.Client.find('client');
          client.userinfoSignedResponseAlg = 'RS256';
        });

        after(function* () {
          const client = yield this.provider.Client.find('client');
          client.userinfoSignedResponseAlg = undefined;
        });

        it('also handles nested encrypted and signed userinfo JWT', function (done) {
          this.agent.get('/me')
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
              const decode = JWT.decode(result.payload);
              expect(decode).to.be.ok;
              expect(decode.payload).to.have.property('exp').above(Date.now() / 1000);
            })
            .then(done, done);
          });
        });
      });
    });

    describe('authorization request object encryption', function () {
      it('works with signed by none', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb'
        }, null, 'none').then(signed =>
        JWT.encrypt(signed, instance(this.provider).keystore.get(), 'A128CBC-HS256', 'RSA1_5')
      ).then(encrypted =>
        this.wrap({
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
          .expect((response) => {
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

    it('handles when no suitable encryption key is found', function* () {
      const client = yield this.provider.Client.find('client');

      client.idTokenEncryptedResponseAlg = 'ECDH-ES';

      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid'
      });

      return this.wrap({ route, verb, auth })
        .expect(() => {
          client.idTokenEncryptedResponseAlg = 'RSA1_5';
        })
        .expect(auth.validateFragment)
        .expect((response) => {
          const { query } = url.parse(response.headers.location, true);
          expect(query).to.have.property('error', 'invalid_client_metadata');
          expect(query).to.have.property('error_description', 'no suitable encryption key found (ECDH-ES)');
        });
    });

    describe('symmetric encryption', function () {
      before(function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
          client_id: 'clientSymmetric',
        });

        return this.wrap({ route, verb, auth })
          .expect(auth.validateFragment)
          .expect((response) => {
            const { query } = url.parse(response.headers.location, true);
            this.id_token = query.id_token;
          });
      });

      it('symmetric encryption makes client secret mandatory', function () {
        expect(this.provider.Client.needsSecret({
          token_endpoint_auth_method: 'none',
          id_token_encrypted_response_alg: 'A128GCMKW',
        })).to.be.true;
      });

      it('responds encrypted with i.e. PBES2 derived key', function () {
        expect(this.id_token).to.be.ok;
        expect(this.id_token.split('.')).to.have.lengthOf(5);
        expect(JSON.parse(base64url.decode(this.id_token.split('.')[0]))).to.have.property('alg', 'PBES2-HS384+A192KW');
      });
    });
  });
});
