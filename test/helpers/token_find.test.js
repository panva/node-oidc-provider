import { expect } from 'chai';
import sinon from 'sinon';

import Provider from '../../lib/index.js';
import instance from '../../lib/helpers/weak_cache.js';
import { createTokenFinder } from '../../lib/helpers/token_find.js';

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

  return { provider, grantTypeHandlers, find: createTokenFinder(provider, grantTypeHandlers) };
}

describe('createTokenFinder helper', () => {
  afterEach(() => sinon.restore());

  describe('with the refresh_token grant disabled', () => {
    // the grant is only registered when offline_access is amongst the scopes or issueRefreshToken
    // was customized, leaving RefreshToken lookups to be skipped entirely
    it('resolves for every token_type_hint rather than throwing', async () => {
      const { grantTypeHandlers, find } = setup(['openid']);
      expect(grantTypeHandlers.has('refresh_token')).to.be.false;

      for (const hint of HINTS) {
        expect(await find('token-value', hint), `token_type_hint=${hint}`).to.be.undefined;
      }
    });

    it('still finds the other token types when hinted at a refresh token', async () => {
      const { provider, find } = setup(['openid']);
      const accessToken = { kind: 'AccessToken' };
      sinon.stub(provider.AccessToken, 'find').resolves(accessToken);

      expect(await find('token-value', 'refresh_token')).to.equal(accessToken);
      expect(await find('token-value', 'urn:ietf:params:oauth:token-type:refresh_token')).to.equal(accessToken);
    });
  });

  describe('with the refresh_token grant enabled', () => {
    it('honours the refresh_token hint', async () => {
      const { provider, grantTypeHandlers, find } = setup(['openid', 'offline_access']);
      expect(grantTypeHandlers.has('refresh_token')).to.be.true;

      const refreshToken = { kind: 'RefreshToken' };
      const accessToken = sinon.stub(provider.AccessToken, 'find').resolves({ kind: 'AccessToken' });
      sinon.stub(provider.RefreshToken, 'find').resolves(refreshToken);

      expect(await find('token-value', 'refresh_token')).to.equal(refreshToken);
      expect(await find('token-value', 'urn:ietf:params:oauth:token-type:refresh_token')).to.equal(refreshToken);
      expect(accessToken).not.to.have.property('called', true);
    });

    it('falls back to the other token types when the hint does not match', async () => {
      const { provider, find } = setup(['openid', 'offline_access']);
      const accessToken = { kind: 'AccessToken' };
      sinon.stub(provider.RefreshToken, 'find').resolves(undefined);
      sinon.stub(provider.AccessToken, 'find').resolves(accessToken);

      expect(await find('token-value', 'refresh_token')).to.equal(accessToken);
    });
  });
});
