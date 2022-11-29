import upperFirst from '../../helpers/_/upper_first.js';
import camelCase from '../../helpers/_/camel_case.js';
import * as errors from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import filterClaims from '../../helpers/filter_claims.js';
import revoke from '../../helpers/revoke.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import resolveResource from '../../helpers/resolve_resource.js';
import epochTime from '../../helpers/epoch_time.js';

const {
  AuthorizationPending,
  ExpiredToken,
  InvalidGrant,
} = errors;

const gty = 'ciba';

export const handler = async function cibaHandler(ctx, next) {
  presence(ctx, 'auth_req_id');

  const {
    issueRefreshToken,
    conformIdTokenClaims,
    features: {
      userinfo,
      mTLS: { getCertificate },
      resourceIndicators,
    },
  } = instance(ctx.oidc.provider).configuration();

  const dPoP = await dpopValidate(ctx);

  const request = await ctx.oidc.provider.BackchannelAuthenticationRequest.find(
    ctx.oidc.params.auth_req_id,
    { ignoreExpiration: true },
  );

  if (!request) {
    throw new InvalidGrant('backchannel authentication request not found');
  }

  if (request.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  let cert;
  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    cert = getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
  }

  if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
    throw new InvalidGrant('DPoP proof JWT not provided');
  }

  if (request.isExpired) {
    throw new ExpiredToken('backchannel authentication request is expired');
  }

  if (!request.grantId && !request.error) {
    throw new AuthorizationPending();
  }

  if (request.consumed) {
    await revoke(ctx, request.grantId);
    throw new InvalidGrant('backchannel authentication request already consumed');
  }

  await request.consume();

  if (request.error) {
    const className = upperFirst(camelCase(request.error));
    if (errors[className]) {
      throw new errors[className](request.errorDescription);
    }
    throw new errors.CustomOIDCProviderError(request.error, request.errorDescription);
  }

  const grant = await ctx.oidc.provider.Grant.find(request.grantId, {
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

  ctx.oidc.entity('BackchannelAuthenticationRequest', request);
  ctx.oidc.entity('Grant', grant);

  const account = await ctx.oidc.provider.Account.findAccount(ctx, request.accountId, request);

  if (!account) {
    throw new InvalidGrant('backchannel authentication request invalid (referenced account not found)');
  }

  if (request.accountId !== grant.accountId) {
    throw new InvalidGrant('accountId mismatch');
  }

  ctx.oidc.entity('Account', account);

  const {
    AccessToken, IdToken, RefreshToken, ReplayDetection,
  } = ctx.oidc.provider;

  const at = new AccessToken({
    accountId: account.accountId,
    client: ctx.oidc.client,
    expiresWithSession: request.expiresWithSession,
    grantId: request.grantId,
    gty,
    sessionUid: request.sessionUid,
    sid: request.sid,
  });

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    at.setThumbprint('x5t', cert);
  }

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      ctx.oidc.client.clientId,
      dPoP.jti,
      epochTime() + 300,
    );

    ctx.assert(unique, new InvalidGrant('DPoP proof JWT Replay detected'));

    at.setThumbprint('jkt', dPoP.thumbprint);
  }

  const resource = await resolveResource(ctx, request, { userinfo, resourceIndicators });

  if (resource) {
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, ctx.oidc.client);
    at.resourceServer = new ctx.oidc.provider.ResourceServer(resource, resourceServerInfo);
    at.scope = grant.getResourceScopeFiltered(resource, request.scopes);
  } else {
    at.claims = request.claims;
    at.scope = grant.getOIDCScopeFiltered(request.scopes);
  }

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  let refreshToken;
  if (await issueRefreshToken(ctx, ctx.oidc.client, request)) {
    const rt = new RefreshToken({
      accountId: account.accountId,
      acr: request.acr,
      amr: request.amr,
      authTime: request.authTime,
      claims: request.claims,
      client: ctx.oidc.client,
      expiresWithSession: request.expiresWithSession,
      grantId: request.grantId,
      gty,
      nonce: request.nonce,
      resource: request.resource,
      rotations: 0,
      scope: request.scope,
      sessionUid: request.sessionUid,
      sid: request.sid,
    });

    if (ctx.oidc.client.clientAuthMethod === 'none') {
      if (at.jkt) {
        rt.jkt = at.jkt;
      }

      if (at['x5t#S256']) {
        rt['x5t#S256'] = at['x5t#S256'];
      }
    }

    ctx.oidc.entity('RefreshToken', rt);
    refreshToken = await rt.save();
  }

  let idToken;
  if (request.scopes.has('openid')) {
    const claims = filterClaims(request.claims, 'id_token', grant);
    const rejected = grant.getRejectedOIDCClaims();
    const token = new IdToken({
      ...await account.claims('id_token', request.scope, claims, rejected),
      ...{
        acr: request.acr,
        amr: request.amr,
        auth_time: request.authTime,
      },
    }, { ctx });

    if (conformIdTokenClaims && userinfo.enabled && !at.aud) {
      token.scope = 'openid';
    } else {
      token.scope = grant.getOIDCScopeFiltered(request.scopes);
    }

    token.mask = claims;
    token.rejected = rejected;

    token.set('nonce', request.nonce);
    token.set('at_hash', accessToken);
    token.set('urn:openid:params:jwt:claim:rt_hash', refreshToken);
    token.set('sid', request.sid);
    token.set('urn:openid:params:jwt:claim:auth_req_id', ctx.oidc.params.auth_req_id);

    idToken = await token.issue({ use: 'idtoken' });
  }

  ctx.body = {
    access_token: accessToken,
    expires_in: at.expiration,
    id_token: idToken,
    refresh_token: refreshToken,
    scope: at.scope,
    token_type: at.tokenType,
  };

  return next();
};

export const parameters = new Set(['auth_req_id']);
