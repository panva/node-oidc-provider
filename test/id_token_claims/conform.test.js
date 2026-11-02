import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseUrl } from 'node:url';


import bootstrap, { skipConsent } from '../test_helper.js';
import { decode as decodeJWT } from '../../lib/helpers/jwt.js';

const redirect_uri = 'https://client.example.com/cb';
const scope = 'openid email offline_access';
const client_id = 'client';
const prompt = 'consent';

describe('configuration conformIdTokenClaims=true', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'conform' }), { timeout: 3000 });
  before(() => fixture.login({
      scope,
      claims: JSON.stringify({ id_token: { gender: null, email: null } }),
      rejectedClaims: ['email_verified'],
    }), { timeout: 3000 });

  skipConsent(fixture);

  [
    'code id_token token', 'code id_token', 'code token', 'code', 'id_token token', 'id_token',
  ].forEach((response_type) => {
    describe(`response_type=${response_type}`, () => {
      const fixture1 = Object.create(fixture);

      before(async () => {
        const client = await fixture1.provider.Client.find('client');

        const claims = JSON.stringify({
          id_token: { gender: null, email: null, email_verified: null },
          ...(response_type !== 'id_token' ? { userinfo: { gender: null } } : undefined),
        });

        const auth = new fixture1.AuthorizationRequest({
          response_type, scope, claims, prompt,
        });

        let id_token;
        let refresh_token;
        let code;
        let access_token;

        const { headers: { location } } = await fixture1.agent
          .get('/auth')
          .query(auth)
          .expect(303)
          .expect((...args) => {
            if (response_type === 'code') return;
            auth.validateFragment(...args);
          })
          .expect(auth.validateClientLocation);

        ({ query: { code, id_token, access_token } } = parseUrl(location, true));

        fixture1.authorization = { id_token };

        if (response_type.includes('code')) {
          ({ body: { id_token, refresh_token } } = await fixture1.agent.post('/token')
            .send({
              client_id,
              code,
              grant_type: 'authorization_code',
              code_verifier: auth.code_verifier,
              redirect_uri,
            })
            .type('form')
            .expect(200));

          fixture1.token = { id_token };

          ({ body: { id_token, access_token } } = await fixture1.agent.post('/token')
            .send({ client_id, grant_type: 'refresh_token', refresh_token })
            .type('form')
            .expect(200));

          fixture1.refresh = { id_token };
        }

        if (access_token) {
          let userinfo;
          delete client.userinfoSignedResponseAlg;
          ({ body: userinfo } = await fixture1.agent.get('/me')
            .auth(access_token, { type: 'bearer' })
            .expect(200));
          fixture1.userinfo = userinfo;

          client.userinfoSignedResponseAlg = 'HS256';
          await fixture1.provider.Client.find('client');
          ({ text: userinfo } = await fixture1.agent.get('/me')
            .auth(access_token, { type: 'bearer' })
            .expect(200));
          fixture1.userinfoSigned = userinfo;
        }
      }, { timeout: 3000 });

      if (response_type === 'id_token') {
        it('authorization endpoint id_token has scope requested claims', { timeout: 3000 }, () => {
          const { payload } = decodeJWT(fixture1.authorization.id_token);
          assert.ok(['gender', 'email'].every((key) => Object.keys(payload).includes(key)));
          assert.ok(!(['email_verified'].every((key) => Object.keys(payload).includes(key))));
        });
      } else if (response_type.includes('id_token')) {
        it('authorization endpoint id_token does not have scope requested claims', { timeout: 3000 }, () => {
          const { payload } = decodeJWT(fixture1.authorization.id_token);
          assert.ok(['gender', 'email'].every((key) => Object.keys(payload).includes(key)));
          assert.ok(!(['email_verified'].every((key) => Object.keys(payload).includes(key))));
        });
      }

      if (response_type !== 'id_token') {
        it('userinfo has scope requested claims', { timeout: 3000 }, () => {
          assert.ok(['email', 'gender'].every((key) => Object.keys(fixture1.userinfo).includes(key)));
          assert.ok(!(['email_verified'].every((key) => Object.keys(fixture1.userinfo).includes(key))));
        });

        it('signed userinfo has scope requested claims', { timeout: 3000 }, () => {
          const { payload } = decodeJWT(fixture1.userinfoSigned);
          assert.ok(['email', 'gender'].every((key) => Object.keys(payload).includes(key)));
          assert.ok(!(['email_verified'].every((key) => Object.keys(payload).includes(key))));
        });
      }

      if (response_type.includes('code')) {
        it('token endpoint id_token does not have scope requested claims', { timeout: 3000 }, () => {
          const { payload } = decodeJWT(fixture1.token.id_token);
          assert.ok(['gender', 'email'].every((key) => Object.keys(payload).includes(key)));
          assert.ok(!(['email_verified'].every((key) => Object.keys(payload).includes(key))));
        });

        it('refreshed id_token does not have scope requested claims', { timeout: 3000 }, () => {
          const { payload } = decodeJWT(fixture1.refresh.id_token);
          assert.ok(['gender', 'email'].every((key) => Object.keys(payload).includes(key)));
          assert.ok(!(['email_verified'].every((key) => Object.keys(payload).includes(key))));
        });
      }
    });
  });
});
