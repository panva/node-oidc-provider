import { expect } from 'chai';
import sinon from 'sinon';

import Provider from '../../lib/index.js';
import instance from '../../lib/helpers/weak_cache.js';
import { findToken } from '../../lib/helpers/token_find.js';

const HINTS = [
  undefined,
  'unrecognized_hint',
  'access_token',
  'urn:ietf:params:oauth:token-type:access_token',
  'refresh_token',
  'urn:ietf:params:oauth:token-type:refresh_token',
];

function setup(scopes) {
  const provider = new Provider('https://op.example.com', {
    scopes,
    features: {
      introspection: { enabled: true },
      revocation: { enabled: true },
      clientCredentials: { enabled: true },
    },
  });
  const { grantTypeHandlers } = instance(provider);

  return { provider, grantTypeHandlers };
}

describe('findToken helper', () => {
  afterEach(() => sinon.restore());

  it('keeps access token and client credentials lookups concurrent and prefers access tokens', async () => {
    const { provider } = setup(['openid', 'offline_access']);
    const accessToken = { kind: 'AccessToken' };
    const credentialsToken = { kind: 'ClientCredentials' };
    let resolveAccessToken;
    const access = sinon.stub(provider.AccessToken, 'find').returns(new Promise((resolve) => {
      resolveAccessToken = resolve;
    }));
    const credentials = sinon.stub(provider.ClientCredentials, 'find').resolves(credentialsToken);
    const refresh = sinon.stub(provider.RefreshToken, 'find').resolves({ kind: 'RefreshToken' });

    const pending = findToken(provider, 'token-value', 'access_token');
    sinon.assert.calledOnceWithExactly(access, 'token-value');
    sinon.assert.calledOnceWithExactly(credentials, 'token-value');
    sinon.assert.notCalled(refresh);
    resolveAccessToken(accessToken);
    expect(await pending).to.equal(accessToken);
    sinon.assert.notCalled(refresh);
  });

  it('uses the current grant registrations when selecting models to query', async () => {
    const { provider, grantTypeHandlers } = setup(['openid', 'offline_access']);
    const refreshToken = { kind: 'RefreshToken' };
    const refresh = sinon.stub(provider.RefreshToken, 'find').resolves(refreshToken);
    const credentials = sinon.stub(provider.ClientCredentials, 'find').resolves(undefined);
    const refreshHandler = grantTypeHandlers.get('refresh_token');
    grantTypeHandlers.delete('refresh_token');
    grantTypeHandlers.delete('client_credentials');

    expect(await findToken(provider, 'token-value')).to.be.undefined;
    sinon.assert.notCalled(refresh);
    sinon.assert.notCalled(credentials);
    grantTypeHandlers.set('refresh_token', refreshHandler);
    expect(await findToken(provider, 'token-value')).to.equal(refreshToken);
    sinon.assert.calledOnceWithExactly(refresh, 'token-value');
  });

  describe('with the refresh_token grant disabled', () => {
    // the grant is only registered when offline_access is amongst the scopes or issueRefreshToken
    // was customized, leaving RefreshToken lookups to be skipped entirely
    it('resolves for every token_type_hint rather than throwing', async () => {
      const { provider, grantTypeHandlers } = setup(['openid']);
      expect(grantTypeHandlers.has('refresh_token')).to.be.false;

      for (const hint of HINTS) {
        expect(await findToken(provider, 'token-value', hint), `token_type_hint=${hint}`).to.be.undefined;
      }
    });

    it('still finds the other token types when hinted at a refresh token', async () => {
      const { provider } = setup(['openid']);
      const accessToken = { kind: 'AccessToken' };
      sinon.stub(provider.AccessToken, 'find').resolves(accessToken);

      expect(await findToken(provider, 'token-value', 'refresh_token')).to.equal(accessToken);
      expect(await findToken(provider, 'token-value', 'urn:ietf:params:oauth:token-type:refresh_token')).to.equal(accessToken);
    });
  });

  describe('with the refresh_token grant enabled', () => {
    it('honours the refresh_token hint', async () => {
      const { provider, grantTypeHandlers } = setup(['openid', 'offline_access']);
      expect(grantTypeHandlers.has('refresh_token')).to.be.true;

      const refreshToken = { kind: 'RefreshToken' };
      const accessToken = sinon.stub(provider.AccessToken, 'find').resolves({ kind: 'AccessToken' });
      sinon.stub(provider.RefreshToken, 'find').resolves(refreshToken);

      expect(await findToken(provider, 'token-value', 'refresh_token')).to.equal(refreshToken);
      expect(await findToken(provider, 'token-value', 'urn:ietf:params:oauth:token-type:refresh_token')).to.equal(refreshToken);
      expect(accessToken).not.to.have.property('called', true);
    });

    it('falls back to the other token types when the hint does not match', async () => {
      const { provider } = setup(['openid', 'offline_access']);
      const accessToken = { kind: 'AccessToken' };
      sinon.stub(provider.RefreshToken, 'find').resolves(undefined);
      sinon.stub(provider.AccessToken, 'find').resolves(accessToken);

      expect(await findToken(provider, 'token-value', 'refresh_token')).to.equal(accessToken);
    });
  });
});
