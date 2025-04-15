/* eslint-disable prefer-const */

import { parse as parseUrl } from 'node:url';

import { expect } from 'chai';

import bootstrap, { skipConsent } from '../test_helper.js';
import { decode as decodeJWT } from '../../lib/helpers/jwt.js';

const redirect_uri = 'https://client.example.com/cb';
const scope = 'openid email offline_access';
const client_id = 'client';

describe('configuration conformIdTokenClaims=false', () => {
  before(bootstrap(import.meta.url, { config: 'non_conform' }));
  before(function () {
    return this.login({
      scope,
      rejectedClaims: ['email_verified'],
    });
  });

  skipConsent();

  [
    'code id_token token', 'code id_token', 'code token', 'code', 'id_token token', 'id_token',
  ].forEach((response_type) => {
    describe(`response_type=${response_type}`, () => {
      before(async function () {
        const client = await this.provider.Client.find('client');
        const auth = new this.AuthorizationRequest({ response_type, scope, prompt: 'consent' });

        let id_token;
        let refresh_token;
        let code;
        let access_token;

        const { headers: { location } } = await this.agent
          .get('/auth')
          .query(auth)
          .expect(303)
          .expect((...args) => {
            if (response_type === 'code') return;
            auth.validateFragment(...args);
          })
          .expect(auth.validateClientLocation);

        ({ query: { code, id_token, access_token } } = parseUrl(location, true));

        this.authorization = { id_token };

        if (response_type.includes('code')) {
          ({ body: { id_token, refresh_token, access_token } } = await this.agent.post('/token')
            .send({
              client_id,
              code,
              grant_type: 'authorization_code',
              code_verifier: auth.code_verifier,
              redirect_uri,
            })
            .type('form')
            .expect(200));

          this.token = { id_token };

          ({ body: { id_token } } = await this.agent.post('/token')
            .send({ client_id, grant_type: 'refresh_token', refresh_token })
            .type('form')
            .expect(200));

          this.refresh = { id_token };
        }

        if (access_token) {
          let userinfo;
          delete client.userinfoSignedResponseAlg;
          ({ body: userinfo } = await this.agent.get('/me')
            .auth(access_token, { type: 'bearer' })
            .expect(200));
          this.userinfo = userinfo;

          client.userinfoSignedResponseAlg = 'HS256';
          await this.provider.Client.find('client');
          ({ text: userinfo } = await this.agent.get('/me')
            .auth(access_token, { type: 'bearer' })
            .expect(200));
          this.userinfoSigned = userinfo;
        }
      });

      if (response_type.includes('id_token')) {
        it('authorization endpoint id_token has scope requested claims', function () {
          const { payload } = decodeJWT(this.authorization.id_token);
          expect(payload).to.contain.keys('email');
          expect(payload).not.to.contain.keys('email_verified');
        });
      }

      if (response_type !== 'id_token') {
        it('userinfo has scope requested claims', function () {
          expect(this.userinfo).to.contain.keys('email');
          expect(this.userinfo).not.to.contain.keys('email_verified');
        });

        it('signed userinfo has scope requested claims', function () {
          const { payload } = decodeJWT(this.userinfoSigned);
          expect(payload).to.contain.keys('email');
          expect(payload).not.to.contain.keys('email_verified');
        });
      }

      if (response_type.includes('code')) {
        it('token endpoint id_token has scope requested claims', function () {
          const { payload } = decodeJWT(this.token.id_token);
          expect(payload).to.contain.keys('email');
          expect(payload).not.to.contain.keys('email_verified');
        });

        it('refreshed id_token has scope requested claims', function () {
          const { payload } = decodeJWT(this.refresh.id_token);
          expect(payload).to.contain.keys('email');
          expect(payload).not.to.contain.keys('email_verified');
        });
      }
    });
  });
});
