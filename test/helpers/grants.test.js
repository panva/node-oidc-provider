import { expect } from 'chai';

import { errors } from '../../lib/index.js';
import {
  applyAuthorizationDetails,
  applyRefreshTokenBindings,
  applySenderConstraints,
  buildTokenResponse,
  consumeGrantSource,
  findAccount,
  findGrantSource,
  resolveAndApplyResource,
  resolveRequestedResources,
  shouldIssueRefreshToken,
  validateClientScope,
  validateGrant,
  validateSenderConstraints,
} from '../../lib/helpers/grants.js';

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
      applySenderConstraints: () => applySenderConstraints(otherProvider, ctx, undefined, {}),
      consumeGrantSource: () => consumeGrantSource(otherProvider, ctx),
      findAccount: () => findAccount(otherProvider, ctx),
      findGrantSource: () => findGrantSource(otherProvider, ctx),
      resolveAndApplyResource: () => resolveAndApplyResource(otherProvider, ctx),
      resolveRequestedResources: () => resolveRequestedResources(otherProvider, ctx),
      shouldIssueRefreshToken: () => shouldIssueRefreshToken(otherProvider, ctx),
      validateClientScope: () => validateClientScope(otherProvider, ctx),
      validateGrant: () => validateGrant(otherProvider, ctx),
      validateSenderConstraints: () => validateSenderConstraints(otherProvider, ctx),
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

  describe('applySenderConstraints', () => {
    const provider = {};
    const ctx = { oidc: { provider } };

    it('rejects conflicting bindings before mutating the token', async () => {
      const token = {
        setThumbprint() {
          throw new Error('must not be called');
        },
      };

      const err = await getError(() => applySenderConstraints(provider, ctx, token, {
        certificate: 'certificate',
        dPoP: { thumbprint: 'thumbprint' },
      }, errors.InvalidRequest));

      expect(err).to.be.instanceOf(errors.InvalidRequest);
      expect(err.error_description).to.equal('multiple proof-of-possession mechanisms are not allowed');
    });

    it('rejects a binding that conflicts with one already on the token', async () => {
      const token = {
        'x5t#S256': 'certificate-thumbprint',
        setThumbprint() {
          throw new Error('must not be called');
        },
      };

      const err = await getError(() => applySenderConstraints(provider, ctx, token, {
        dPoP: { thumbprint: 'thumbprint' },
      }));

      expect(err).to.be.instanceOf(errors.InvalidGrant);
      expect(err.error_description).to.equal('grant request is invalid');
      expect(err.error_detail).to.equal('multiple proof-of-possession mechanisms are not allowed');
    });
  });
});
