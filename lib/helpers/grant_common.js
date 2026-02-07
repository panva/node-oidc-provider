import upperFirst from './_/upper_first.js';
import camelCase from './_/camel_case.js';
import * as errors from './errors.js';
import { CHALLENGE_OK_WINDOW } from './validate_dpop.js';
import epochTime from './epoch_time.js';
import filterClaims from './filter_claims.js';
import resolveResource from './resolve_resource.js';
import getCtxAccountClaims from './account_claims.js';
import { setRefreshTokenBindings } from './set_rt_bindings.js';

const { InvalidGrant } = errors;

export function throwIfAsyncGrantError(entity) {
  if (entity.error) {
    const className = upperFirst(camelCase(entity.error));
    if (errors[className]) {
      throw new errors[className](entity.errorDescription);
    }
    throw new errors.CustomOIDCProviderError(entity.error, entity.errorDescription);
  }
}

export function checkMtlsCert(ctx, getCertificate) {
  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    const cert = getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
    return cert;
  }
  return undefined;
}

export function checkDpopRequired(ctx, dPoP) {
  if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
    throw new InvalidGrant('DPoP proof JWT not provided');
  }
}

export async function validateGrant(ctx, grantId) {
  const grant = await ctx.oidc.provider.Grant.find(grantId, {
    ignoreExpiration: true,
  });

  if (!grant) {
    throw new InvalidGrant('grant not found');
  }

  if (grant.isExpired) {
    throw new InvalidGrant('grant is expired');
  }

  if (grant.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  return grant;
}

export async function validateAccount(ctx, findAccount, code, entityLabel) {
  const account = await findAccount(ctx, code.accountId, code);

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

export function createAccessToken(ctx, AccessToken, source, gty) {
  return new AccessToken({
    accountId: source.accountId,
    client: ctx.oidc.client,
    expiresWithSession: source.expiresWithSession,
    grantId: source.grantId,
    gty,
    sessionUid: source.sessionUid,
    sid: source.sid,
  });
}

export function applyMtlsBinding(at, cert) {
  if (cert) {
    at.setThumbprint('x5t', cert);
  }
}

export async function applyDpopBinding(ctx, dPoP, at, allowReplay) {
  if (dPoP) {
    if (!allowReplay) {
      const { ReplayDetection } = ctx.oidc.provider;
      const unique = await ReplayDetection.unique(
        ctx.oidc.client.clientId,
        dPoP.jti,
        epochTime() + CHALLENGE_OK_WINDOW,
      );

      ctx.assert(unique, new InvalidGrant('DPoP proof JWT Replay detected'));
    }

    at.setThumbprint('jkt', dPoP.thumbprint);
  }
}

export async function resolveAndApplyResource(ctx, source, at, grant, {
  userinfo, resourceIndicators,
}, scope) {
  const resource = await resolveResource(ctx, source, { userinfo, resourceIndicators }, scope);

  /* eslint-disable no-param-reassign */
  if (resource) {
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, ctx.oidc.client);
    at.resourceServer = new ctx.oidc.provider.ResourceServer(resource, resourceServerInfo);
    at.scope = grant.getResourceScopeFiltered(resource, scope || source.scopes);
  } else {
    at.claims = source.claims;
    at.scope = grant.getOIDCScopeFiltered(scope || source.scopes);
  }
  /* eslint-enable no-param-reassign */

  return resource;
}

export async function createRefreshToken(ctx, source, at, gty, {
  issueRefreshToken, RefreshToken,
}) {
  if (await issueRefreshToken(ctx, ctx.oidc.client, source)) {
    const rt = new RefreshToken({
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

    await setRefreshTokenBindings(ctx, at, rt);

    ctx.oidc.entity('RefreshToken', rt);
    return rt.save();
  }

  return undefined;
}

export async function issueIdToken(ctx, source, at, grant, {
  conformIdTokenClaims, userinfo,
}, scopeOverride) {
  const scopes = scopeOverride || source.scopes;
  if (!scopes.has('openid')) {
    return undefined;
  }

  const { IdToken } = ctx.oidc.provider;
  const claims = filterClaims(source.claims, 'id_token', grant);
  const rejected = grant.getRejectedOIDCClaims();
  const token = new IdToken({
    ...await getCtxAccountClaims(
      ctx,
      'id_token',
      typeof source.scope === 'string' ? source.scope : [...scopes].join(' '),
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

export function buildTokenResponse(at, accessToken, {
  idToken, refreshToken, source, rar,
}) {
  return {
    access_token: accessToken,
    expires_in: at.expiration,
    id_token: idToken,
    refresh_token: refreshToken,
    scope: source.scope ? at.scope : (at.scope || undefined),
    token_type: at.tokenType,
    authorization_details: rar,
  };
}
