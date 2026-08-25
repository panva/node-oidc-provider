import upperFirst from './_/upper_first.js';
import camelCase from './_/camel_case.js';
import * as errors from './errors.js';
import { checkDpopReplay } from './validate_dpop.js';
import filterClaims from './filter_claims.js';
import getCtxAccountClaims from './account_claims.js';
import instance from './weak_cache.js';
import assertProviderContext from './assert_provider_context.js';
import { findAccount } from './grant_source.js';
import {
  applyRefreshTokenBindings,
  shouldIssueRefreshToken,
} from './grant_refresh_token.js';

const { InvalidGrant } = errors;
const errorMap = { ...errors };

export function throwIfAsyncGrantError(entity) {
  if (entity.error) {
    const className = upperFirst(camelCase(entity.error));
    if (errorMap[className]) {
      throw new errorMap[className](entity.errorDescription);
    }
    throw new errors.CustomOIDCProviderError(entity.error, entity.errorDescription);
  }
}

export function checkMtlsCert(provider, ctx) {
  assertProviderContext(provider, ctx);

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    const cert = instance(provider).configuration.features.mTLS.getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
    return cert;
  }
  return undefined;
}

export function checkDpopRequired(provider, ctx, dPoP) {
  assertProviderContext(provider, ctx);

  if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
    throw new InvalidGrant('DPoP proof JWT not provided');
  }
}

export async function validateAccount(provider, ctx, code, entityLabel) {
  const account = await findAccount(provider, ctx, code.accountId, code);

  if (!account) {
    throw new InvalidGrant(`${entityLabel} invalid (referenced account not found)`);
  }

  return account;
}

export function checkAccountMismatch(code, grant) {
  if (code.accountId !== grant.accountId) {
    throw new InvalidGrant('accountId mismatch');
  }
}

export function createAccessToken(provider, ctx, source, gty) {
  assertProviderContext(provider, ctx);

  return new provider.AccessToken({
    accountId: source.accountId,
    client: ctx.oidc.client,
    expiresWithSession: source.expiresWithSession,
    grantId: source.grantId,
    gty,
    rar: source.rar,
    sessionUid: source.sessionUid,
    sid: source.sid,
  });
}

export function applyMtlsBinding(at, cert) {
  if (cert) {
    at.setThumbprint('x5t', cert);
  }
}

export async function applyDpopBinding(provider, ctx, dPoP, at) {
  assertProviderContext(provider, ctx);

  if (dPoP) {
    await checkDpopReplay(provider, ctx, dPoP, ctx.oidc.client.clientId, InvalidGrant);
    at.setThumbprint('jkt', dPoP.thumbprint);
  }
}

export async function createRefreshToken(provider, ctx, source, at, gty) {
  assertProviderContext(provider, ctx);

  if (await shouldIssueRefreshToken(provider, ctx, source)) {
    const rt = new provider.RefreshToken({
      accountId: source.accountId,
      acr: source.acr,
      amr: source.amr,
      authTime: source.authTime,
      claims: source.claims,
      client: ctx.oidc.client,
      expiresWithSession: source.expiresWithSession,
      grantId: source.grantId,
      gty,
      nonce: source.nonce,
      resource: source.resource,
      rotations: 0,
      scope: source.scope,
      sessionUid: source.sessionUid,
      sid: source.sid,
      rar: source.rar,
    });

    await applyRefreshTokenBindings(provider, ctx, at, rt);

    ctx.oidc.entity('RefreshToken', rt);
    return rt.save();
  }

  return undefined;
}

export async function issueIdToken(provider, ctx, source, at, grant, scopeOverride) {
  assertProviderContext(provider, ctx);

  const {
    conformIdTokenClaims,
    features: { userinfo },
  } = instance(provider).configuration;
  const scopes = scopeOverride || source.scopes;
  if (!scopes.has('openid')) {
    return undefined;
  }

  const { IdToken } = provider;
  const claims = filterClaims(source.claims, 'id_token', grant);
  const rejected = grant.getRejectedOIDCClaims();
  const token = new IdToken({
    ...await getCtxAccountClaims(
      ctx,
      'id_token',
      !scopeOverride && typeof source.scope === 'string' ? source.scope : [...scopes].join(' '),
      claims,
      rejected,
    ),
    acr: source.acr,
    amr: source.amr,
    auth_time: source.authTime,
  }, { ctx });

  if (conformIdTokenClaims && userinfo.enabled && !at.aud) {
    token.scope = 'openid';
  } else {
    token.scope = grant.getOIDCScopeFiltered(scopes);
  }

  token.mask = claims;
  token.rejected = rejected;

  token.set('nonce', source.nonce);
  token.set('sid', source.sid);

  return token.issue({ use: 'idtoken' });
}
