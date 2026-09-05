import { expect } from 'chai';
import { createSandbox } from 'sinon';
import supertest from 'supertest';

import Provider from '../../lib/index.js';
import instance from '../../lib/helpers/weak_cache.js';

describe('token endpoint policy configuration', () => {
  const sinon = createSandbox();

  afterEach(() => {
    sinon.restore();
    globalThis.server.removeAllListeners('request');
  });

  for (const feature of ['introspection', 'revocation']) {
    it(`${feature} uses a policy replaced after provider construction`, async () => {
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
      if (feature === 'introspection') expect(denied.body).to.eql({ active: false });
      else expect(denied.text).to.equal('');
      expect(await provider.ClientCredentials.find(value)).to.be.instanceOf(provider.ClientCredentials);

      const replacement = sinon.stub().resolves(true);
      instance(provider).configuration.features[feature].allowedPolicy = replacement;
      const allowed = await request();
      sinon.assert.calledOnce(initialPolicy);
      sinon.assert.calledOnce(replacement);
      expect(replacement.firstCall.args[0].oidc.provider).to.equal(provider);
      expect(replacement.firstCall.args[1].clientId).to.equal('client');
      expect(replacement.firstCall.args[2].jti).to.equal(token.jti);

      if (feature === 'introspection') {
        expect(allowed.body).to.include({ active: true, client_id: 'client', scope: 'read' });
        await token.destroy();
      } else {
        expect(allowed.text).to.equal('');
        expect(await provider.ClientCredentials.find(value)).to.be.undefined;
      }
    });
  }
});
