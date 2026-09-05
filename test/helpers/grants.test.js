import { expect } from 'chai';

import Provider, { errors } from '../../lib/index.js';
import {
  applyAuthorizationDetails,
  applyRefreshTokenBindings,
  buildTokenResponse,
  checkDpopReplay,
  checkDpopRequired,
  checkMtlsCert,
  consumeGrantSource,
  findAccount,
  findGrantSource,
  resolveAndApplyResource,
  resolveRequestedResources,
  shouldIssueRefreshToken,
  validateClientScope,
  validateGrant,
  validateDpop,
} from '../../lib/helpers/grants.js';
import instance from '../../lib/helpers/weak_cache.js';

async function getError(operation) {
  try {
    await operation();
  } catch (err) {
    return err;
  }

  throw new Error('expected operation to fail');
}

describe('grant implementation helpers', () => {
  describe('provider context binding', () => {
    const provider = {};
    const otherProvider = {};
    const ctx = { oidc: { provider } };
    const operations = {
      applyAuthorizationDetails: () => applyAuthorizationDetails(otherProvider, ctx),
      applyRefreshTokenBindings: () => applyRefreshTokenBindings(otherProvider, ctx),
      checkDpopReplay: () => checkDpopReplay(otherProvider, ctx),
      checkDpopRequired: () => checkDpopRequired(otherProvider, ctx),
      checkMtlsCert: () => checkMtlsCert(otherProvider, ctx),
      consumeGrantSource: () => consumeGrantSource(otherProvider, ctx),
      findAccount: () => findAccount(otherProvider, ctx),
      findGrantSource: () => findGrantSource(otherProvider, ctx),
      resolveAndApplyResource: () => resolveAndApplyResource(otherProvider, ctx),
      resolveRequestedResources: () => resolveRequestedResources(otherProvider, ctx),
      shouldIssueRefreshToken: () => shouldIssueRefreshToken(otherProvider, ctx),
      validateClientScope: () => validateClientScope(otherProvider, ctx),
      validateGrant: () => validateGrant(otherProvider, ctx),
      validateDpop: () => validateDpop(otherProvider, ctx),
    };

    for (const [name, operation] of Object.entries(operations)) {
      it(`${name} rejects a mismatched provider`, async () => {
        const err = await getError(operation);
        expect(err).to.be.instanceOf(TypeError);
        expect(err.message).to.equal('provider does not match ctx.oidc.provider');
      });
    }
  });

  describe('buildTokenResponse', () => {
    const provider = {};

    it('maps input names, preserves extension parameters, and omits undefined values', () => {
      expect(buildTokenResponse(provider, {
        accessToken: 'access-token',
        authorizationDetails: [{ type: 'payment' }],
        expiresIn: 300,
        idToken: 'id-token',
        issuedTokenType: 'urn:example:token-type',
        parameters: {
          transaction_id: 'transaction-id',
          omitted: undefined,
        },
        refreshToken: 'refresh-token',
        scope: 'openid',
        tokenType: 'Bearer',
      })).to.deep.equal({
        access_token: 'access-token',
        authorization_details: [{ type: 'payment' }],
        expires_in: 300,
        id_token: 'id-token',
        issued_token_type: 'urn:example:token-type',
        refresh_token: 'refresh-token',
        scope: 'openid',
        token_type: 'Bearer',
        transaction_id: 'transaction-id',
      });
    });

    it('supports RFC 8693 non-access-token output', () => {
      expect(buildTokenResponse(provider, {
        accessToken: 'signed-assertion',
        issuedTokenType: 'urn:example:assertion',
        tokenType: 'N_A',
      })).to.deep.equal({
        access_token: 'signed-assertion',
        issued_token_type: 'urn:example:assertion',
        token_type: 'N_A',
      });
    });

    for (const member of [
      'access_token',
      'authorization_details',
      'expires_in',
      'id_token',
      'issued_token_type',
      'refresh_token',
      'scope',
      'token_type',
    ]) {
      it(`rejects the reserved ${member} extension parameter`, () => {
        expect(() => buildTokenResponse(provider, {
          accessToken: 'access-token',
          parameters: { [member]: 'replacement' },
          tokenType: 'Bearer',
        })).to.throw(TypeError, `parameters must not contain reserved member ${member}`);
      });
    }

    it('requires a plain extension parameter object', () => {
      expect(() => buildTokenResponse(provider, {
        accessToken: 'access-token',
        parameters: new Date(),
        tokenType: 'Bearer',
      })).to.throw(TypeError, 'parameters must be a plain object');
    });

    it('requires accessToken and tokenType', () => {
      expect(() => buildTokenResponse(provider, {
        tokenType: 'Bearer',
      })).to.throw(TypeError, 'accessToken must be a non-empty string');
      expect(() => buildTokenResponse(provider, {
        accessToken: 'access-token',
      })).to.throw(TypeError, 'tokenType must be a non-empty string');
    });
  });

  describe('sender-constraint stages', () => {
    let provider;
    let ctx;

    beforeEach(() => {
      provider = new Provider('https://op.example.com', {
        features: { devInteractions: { enabled: false } },
      });
      ctx = {
        oidc: { provider, client: {} },
        get() { return ''; },
        assert(value, error) { if (!value) throw error; },
      };
    });

    it('keeps proof validation separate from the client requirement', async () => {
      ctx.oidc.client.dpopBoundAccessTokens = true;

      expect(await validateDpop(provider, ctx)).to.equal(undefined);
      expect(() => checkDpopRequired(provider, ctx, undefined)).to.throw(errors.InvalidGrant);
      expect(() => checkDpopRequired(provider, ctx, undefined, errors.InvalidRequest))
        .to.throw(errors.InvalidRequest);
      expect(() => checkDpopRequired(provider, ctx, { thumbprint: 'thumbprint' })).not.to.throw();

      ctx.oidc.client.dpopBoundAccessTokens = false;
      expect(() => checkDpopRequired(provider, ctx, undefined)).not.to.throw();
    });

    it('retrieves certificates only when required and supports the grant error class', () => {
      const { mTLS } = instance(provider).features;
      let calls = 0;
      mTLS.getCertificate = (actual) => {
        expect(actual).to.equal(ctx);
        calls += 1;
        return 'certificate';
      };

      expect(checkMtlsCert(provider, ctx)).to.equal(undefined);
      expect(calls).to.equal(0);
      ctx.oidc.client.tlsClientCertificateBoundAccessTokens = true;
      expect(checkMtlsCert(provider, ctx)).to.equal('certificate');
      expect(calls).to.equal(1);

      mTLS.getCertificate = () => undefined;
      expect(() => checkMtlsCert(provider, ctx)).to.throw(errors.InvalidGrant);
      expect(() => checkMtlsCert(provider, ctx, errors.InvalidRequest)).to.throw(errors.InvalidRequest);
    });

    it('checks replay without a token and preserves the supplied client namespace', async () => {
      const proof = { jti: 'proof', thumbprint: 'thumbprint' };

      await checkDpopReplay(provider, ctx, proof, 'first');
      await checkDpopReplay(provider, ctx, proof, 'second');

      expect(await getError(() => checkDpopReplay(provider, ctx, proof, 'first')))
        .to.be.instanceOf(errors.InvalidGrant);
      expect(await getError(() => checkDpopReplay(provider, ctx, proof, 'first', errors.InvalidRequest)))
        .to.be.instanceOf(errors.InvalidRequest);
    });
  });
});
