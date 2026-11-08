import { before, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import bootstrap from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.js';
import addClient from '../../lib/helpers/add_client.js';
import KeyStore from '../../lib/helpers/keystore.js';
import { get } from '../../lib/helpers/hpke_algorithms.js';
import ResourceServer from '../../lib/helpers/resource_server.js';
import instance from '../../lib/helpers/weak_cache.js';

import { cases } from './hpke.config.js';

describe('HPKE Integrated Encryption', { skip: !cases.length }, () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'hpke' }), { timeout: 3000 });
  before(() => fixture.login(), { timeout: 3000 });

  it('advertises supported HPKE algorithms in every enabled encryption context', async () => {
    const { body } = await fixture.agent.get('/.well-known/openid-configuration').expect(200);
    for (const prefix of ['id_token', 'userinfo', 'authorization', 'introspection', 'request_object']) {
      assert.deepEqual(body[`${prefix}_encryption_alg_values_supported`].filter((alg) => alg.startsWith('HPKE-')), cases.map(({ alg }) => alg));
    }
    const { body: jwks } = await fixture.agent.get('/jwks').expect(200);
    for (const { issuer } of cases) {
      const key = jwks.keys.find(({ kid }) => kid === issuer.publicJwk.kid);
      assert.deepEqual(key, issuer.publicJwk);
      assert.equal(Object.hasOwn(key, 'priv'), false);
    }
  });

  for (const { alg, clientId, issuer, recipient } of cases) {
    describe(`${alg} Integrated Encryption`, () => {
      async function decrypt(token, audience = clientId) {
        const parts = token.split('.');
        assert.equal(parts.length, 5);
        assert.equal(Buffer.from(parts[1], 'base64url').length, get(alg).suite.KEM.Nenc);
        assert.equal(parts[2], '');
        assert.equal(parts[4], '');
        const header = JWT.header(token);
        assert.equal(header.alg, alg);
        assert.equal(header.kid, recipient.publicJwk.kid);
        assert.equal(Object.hasOwn(header, 'enc'), false);
        assert.equal(Object.hasOwn(header, 'ek'), false);
        const plaintext = await JWT.decrypt(token, new KeyStore([recipient.privateJwk]));
        const verified = await JWT.verify(plaintext.toString(), i(fixture.provider).keystore, {
          issuer: fixture.provider.issuer,
          audience,
        });
        return verified.payload;
      }

      it('encrypts ID Tokens and UserInfo responses without an enc default', async () => {
        const auth = new fixture.AuthorizationRequest({ client_id: clientId, response_type: 'id_token token', scope: 'openid' });
        const response = await fixture.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'access_token', 'token_type', 'expires_in', 'scope', 'state']));
        const parameters = new URL(response.headers.location).searchParams;
        const idToken = await decrypt(parameters.get('id_token'));
        assert.equal(idToken.sub, fixture.getSub());
        assert.equal(idToken.nonce, auth.nonce);

        const { text } = await fixture.agent.get('/me')
          .auth(parameters.get('access_token'), { type: 'bearer' })
          .expect(200)
          .expect('content-type', /application\/jwt/);
        const userinfo = await decrypt(text);
        assert.equal(userinfo.sub, idToken.sub);
      });

      it('encrypts JARM responses', async () => {
        const auth = new fixture.AuthorizationRequest({
          client_id: clientId, response_type: 'code', response_mode: 'query.jwt', scope: 'openid',
        });
        const { headers: { location } } = await fixture.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validatePresence(['response']));
        const payload = await decrypt(new URL(location).searchParams.get('response'));
        assert.equal(payload.state, auth.state);
        assert.equal(typeof payload.code, 'string');
      });

      it('encrypts JWT introspection responses', async () => {
        const { text } = await fixture.agent.post('/token/introspection')
          .auth(clientId, 'secret')
          .type('form')
          .send({ token: 'unknown' })
          .accept('application/token-introspection+jwt')
          .expect(200)
          .expect('content-type', /application\/token-introspection\+jwt/);
        const payload = await decrypt(text);
        assert.deepEqual(payload.token_introspection, { active: false });
      });

      async function requestObject(auth) {
        const signed = await JWT.sign({
          client_id: auth.client_id,
          redirect_uri: auth.redirect_uri,
          response_type: auth.response_type,
          scope: auth.scope,
          state: auth.state,
          code_challenge: auth.code_challenge,
          code_challenge_method: auth.code_challenge_method,
        }, Buffer.from('secret'), 'HS256', { issuer: clientId, audience: fixture.provider.issuer });
        return JWT.encrypt(signed, issuer.publicJwk, { alg, fields: { kid: issuer.publicJwk.kid } });
      }

      it('decrypts signed Request Objects', async () => {
        const auth = new fixture.AuthorizationRequest({ client_id: clientId, response_type: 'code', scope: 'openid' });
        const request = await requestObject(auth);
        const { headers: { location } } = await fixture.wrap({
          route: '/auth',
          verb: 'post',
          params: { client_id: clientId, request },
        }).expect(303);
        const parameters = new URL(location).searchParams;
        assert.equal(parameters.has('error'), false);
        assert.equal(typeof parameters.get('code'), 'string');
        assert.equal(parameters.get('state'), auth.state);
      });

      for (const [label, header] of [
        ['present enc', { enc: 'A256GCM' }],
        ['unsupported HPKE-1', { alg: 'HPKE-1' }],
        ['unsupported HPKE-9-KE', { alg: 'HPKE-9-KE' }],
      ]) {
        it(`rejects Request Objects carrying ${label}`, async () => {
          const auth = new fixture.AuthorizationRequest({ client_id: clientId, response_type: 'code', scope: 'openid' });
          const parts = (await requestObject(auth)).split('.');
          parts[0] = Buffer.from(JSON.stringify({ ...JWT.header(parts.join('.')), ...header })).toString('base64url');
          const { headers: { location } } = await fixture.wrap({
            route: '/auth',
            verb: 'post',
            params: { client_id: clientId, redirect_uri: auth.redirect_uri, response_type: 'code', request: parts.join('.') },
          }).expect(303);
          assert.equal(new URL(location).searchParams.get('error'), 'invalid_request_object');
        });
      }

      for (const unsupported of ['HPKE-1', 'HPKE-9-KE']) {
        it(`rejects ${unsupported} in client encryption metadata`, async () => {
          await assert.rejects(addClient(fixture.provider, {
            client_id: `unsupported-${unsupported}`,
            client_secret: 'secret',
            redirect_uris: ['https://client.example.com/cb'],
            jwks: { keys: [recipient.publicJwk] },
            id_token_encrypted_response_alg: unsupported,
          }), { error: 'invalid_client_metadata' });
        });
      }

      async function accessToken() {
        const resourceServer = new ResourceServer('urn:hpke-resource', {
          audience: 'urn:hpke-resource',
          accessTokenFormat: 'jwt',
          jwt: {
            sign: { alg: 'RS256' },
            encrypt: { alg, key: recipient.publicKey, kid: recipient.publicJwk.kid },
          },
        });
        const client = await fixture.provider.Client.find(clientId);
        return new fixture.provider.AccessToken({
          client,
          accountId: fixture.getSub(),
          grantId: fixture.getGrantId(clientId),
          scope: 'openid',
          resourceServer,
        });
      }

      it('encrypts JWT access tokens with a native public key', async () => {
        const token = await accessToken();
        const payload = await decrypt(await token.save(), 'urn:hpke-resource');
        assert.equal(payload.client_id, clientId);
        assert.equal(payload.sub, fixture.getSub());
        assert.equal(payload.scope, 'openid');
      });

      it('rejects HPKE resource token encryption when the HPKE feature is disabled', async () => {
        const token = await accessToken();
        const { hpke } = instance(fixture.provider).features;
        const { enabled } = hpke;
        hpke.enabled = false;
        try {
          await assert.rejects(token.save(), /requires features\.hpke to be enabled/);
        } finally {
          hpke.enabled = enabled;
        }
      });
    });
  }
});
