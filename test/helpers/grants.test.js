import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, hash } from 'node:crypto';

import { SignJWT } from 'jose';

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
      it(`${name} rejects a mismatched provider`, { timeout: 3000 }, async () => {
        const err = await getError(operation);
        assert.ok(err instanceof TypeError);
        assert.equal(err.message, 'provider does not match ctx.oidc.provider');
      });
    }
  });

  describe('buildTokenResponse', () => {
    const provider = {};

    it('maps input names, preserves extension parameters, and omits undefined values', { timeout: 3000 }, () => {
      assert.deepEqual(buildTokenResponse(provider, {
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
      }), {
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

    it('supports RFC 8693 non-access-token output', { timeout: 3000 }, () => {
      assert.deepEqual(buildTokenResponse(provider, {
        accessToken: 'signed-assertion',
        issuedTokenType: 'urn:example:assertion',
        tokenType: 'N_A',
      }), {
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
      it(`rejects the reserved ${member} extension parameter`, { timeout: 3000 }, () => {
        assert.throws(() => buildTokenResponse(provider, {
          accessToken: 'access-token',
          parameters: { [member]: 'replacement' },
          tokenType: 'Bearer',
        }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes(`parameters must not contain reserved member ${member}`)); return true; });
      });
    }

    it('requires a plain extension parameter object', { timeout: 3000 }, () => {
      assert.throws(() => buildTokenResponse(provider, {
        accessToken: 'access-token',
        parameters: new Date(),
        tokenType: 'Bearer',
      }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('parameters must be a plain object')); return true; });
    });

    it('requires accessToken and tokenType', { timeout: 3000 }, () => {
      assert.throws(() => buildTokenResponse(provider, {
        tokenType: 'Bearer',
      }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('accessToken must be a non-empty string')); return true; });
      assert.throws(() => buildTokenResponse(provider, {
        accessToken: 'access-token',
      }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('tokenType must be a non-empty string')); return true; });
    });
  });

  describe('resolveAndApplyResource', () => {
    it('filters an explicit scope override against the current Resource Server scopes', { timeout: 3000 }, async () => {
      const resource = 'urn:example:resource';
      const provider = new Provider('https://op.example.com', {
        features: {
          devInteractions: { enabled: false },
          resourceIndicators: {
            getResourceServerInfo() {
              return { scope: 'api:read api:write api:ungranted' };
            },
          },
        },
      });
      const client = { clientId: 'client' };
      const ctx = { oidc: { provider, client, params: { resource } } };
      const grant = new provider.Grant({ accountId: 'account', clientId: client.clientId });
      grant.addResourceScope(resource, 'api:read api:write api:removed');
      const source = {
        scopes: new Set(['api:read', 'api:write', 'api:removed']),
        resourceIndicators: new Set([resource]),
      };
      const token = {};

      await resolveAndApplyResource(
        provider, ctx, source, token, grant, new Set(['api:read', 'api:removed', 'api:ungranted']),
      );

      assert.equal(token.scope, 'api:read');
      assert.deepEqual([...source.scopes], ['api:read', 'api:write', 'api:removed']);
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
    }, { timeout: 3000 });

    it('keeps proof validation separate from the client requirement', { timeout: 3000 }, async () => {
      ctx.oidc.client.dpopBoundAccessTokens = true;

      assert.equal(await validateDpop(provider, ctx), undefined);
      assert.throws(() => checkDpopRequired(provider, ctx, undefined), (error) => { assert.ok(error instanceof errors.InvalidGrant); return true; });
      assert.throws(() => checkDpopRequired(provider, ctx, undefined, errors.InvalidRequest), (error) => { assert.ok(error instanceof errors.InvalidRequest); return true; });
      assert.doesNotThrow(() => checkDpopRequired(provider, ctx, { thumbprint: 'thumbprint' }));

      ctx.oidc.client.dpopBoundAccessTokens = false;
      assert.doesNotThrow(() => checkDpopRequired(provider, ctx, undefined));
    });

    it('retrieves certificates only when required and supports the grant error class', { timeout: 3000 }, () => {
      const { mTLS } = instance(provider).features;
      let calls = 0;
      mTLS.getCertificate = (actual) => {
        assert.equal(actual, ctx);
        calls += 1;
        return 'certificate';
      };

      assert.equal(checkMtlsCert(provider, ctx), undefined);
      assert.equal(calls, 0);
      ctx.oidc.client.tlsClientCertificateBoundAccessTokens = true;
      assert.equal(checkMtlsCert(provider, ctx), 'certificate');
      assert.equal(calls, 1);

      mTLS.getCertificate = () => undefined;
      assert.throws(() => checkMtlsCert(provider, ctx), (error) => { assert.ok(error instanceof errors.InvalidGrant); return true; });
      assert.throws(() => checkMtlsCert(provider, ctx, errors.InvalidRequest), (error) => { assert.ok(error instanceof errors.InvalidRequest); return true; });
    });

    it('checks replay without a token and preserves the supplied client namespace', { timeout: 3000 }, async () => {
      const proof = { jti: 'proof', thumbprint: 'thumbprint' };

      await checkDpopReplay(provider, ctx, proof, 'first');
      await checkDpopReplay(provider, ctx, proof, 'second');

      assert.ok(await getError(() => checkDpopReplay(provider, ctx, proof, 'first')) instanceof errors.InvalidGrant);
      assert.ok(await getError(() => checkDpopReplay(provider, ctx, proof, 'first', errors.InvalidRequest)) instanceof errors.InvalidRequest);
    });

    for (const [description, ath] of [
      ['missing', undefined],
      ['incorrect', hash('sha256', 'another-token', 'base64url')],
      ['correct', hash('sha256', 'access-token', 'base64url')],
    ]) {
      it(`checks a ${description} access token hash after DPoP validation was cached`, { timeout: 3000 }, async () => {
        const { configuration } = instance(provider);
        configuration.features.dPoP.enabled = true;
        configuration.dPoPSigningAlgValues = ['Ed25519'];
        const { publicKey, privateKey } = generateKeyPairSync('ed25519');
        const proof = await new SignJWT({ htm: 'POST', htu: 'https://op.example.com/token', ath })
          .setProtectedHeader({ typ: 'dpop+jwt', alg: 'Ed25519', jwk: publicKey.export({ format: 'jwk' }) })
          .setJti('cached-proof')
          .setIssuedAt()
          .sign(privateKey);
        ctx.method = 'POST';
        ctx.get = () => proof;
        ctx.set = () => {};
        ctx.oidc.urlFor = () => 'https://op.example.com/token';

        const result = await validateDpop(provider, ctx);
        if (description === 'correct') {
          assert.equal(await validateDpop(provider, ctx, 'access-token'), result);
        } else {
          const err = await getError(() => validateDpop(provider, ctx, 'access-token'));
          assert.ok(err instanceof errors.InvalidDpopProof);
          assert.equal(err.error_description, 'DPoP proof ath mismatch');
        }
      });
    }
  });
});
