import { describe, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';
import supertest from 'supertest';

import Provider from '../../lib/index.js';
import instance from '../../lib/helpers/weak_cache.js';

describe('token endpoint policy configuration', () => {
  const sinon = createSandbox();

  afterEach(() => {
    sinon.restore();
    globalThis.server.removeAllListeners('request');
  }, { timeout: 3000 });

  for (const feature of ['introspection', 'revocation']) {
    it(`${feature} uses a policy replaced after provider construction`, { timeout: 3000 }, async () => {
      const initialPolicy = sinon.stub().resolves(false);
      const provider = new Provider('http://localhost:3000', {
        clients: [{
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: [],
          grant_types: ['client_credentials'],
          response_types: [],
          token_endpoint_auth_method: 'client_secret_post',
        }],
        features: {
          clientCredentials: { enabled: true },
          [feature]: { enabled: true, allowedPolicy: initialPolicy },
        },
      });
      const client = await provider.Client.find('client');
      const token = new provider.ClientCredentials({ client, scope: 'read', expiresIn: 60 });
      const value = await token.save();
      globalThis.server.on('request', provider.callback());

      function request() {
        return supertest(globalThis.server)
          .post(`/token/${feature}`)
          .type('form')
          .send({ client_id: 'client', client_secret: 'secret', token: value })
          .expect(200);
      }

      const denied = await request();
      if (feature === 'introspection') assert.deepEqual(denied.body, { active: false });
      else assert.equal(denied.text, '');
      assert.ok(await provider.ClientCredentials.find(value) instanceof provider.ClientCredentials);

      const replacement = sinon.stub().resolves(true);
      instance(provider).configuration.features[feature].allowedPolicy = replacement;
      const allowed = await request();
      sinon.assert.calledOnce(initialPolicy);
      sinon.assert.calledOnce(replacement);
      assert.equal(replacement.firstCall.args[0].oidc.provider, provider);
      assert.equal(replacement.firstCall.args[1].clientId, 'client');
      assert.equal(replacement.firstCall.args[2].jti, token.jti);

      if (feature === 'introspection') {
        ((actual) => { assert.ok("active" in Object(actual)); assert.equal(actual.active, true); assert.ok("client_id" in Object(actual)); assert.equal(actual.client_id, 'client'); assert.ok("scope" in Object(actual)); assert.equal(actual.scope, 'read'); })(allowed.body);
        await token.destroy();
      } else {
        assert.equal(allowed.text, '');
        assert.equal(await provider.ClientCredentials.find(value), undefined);
      }
    });
  }
});
