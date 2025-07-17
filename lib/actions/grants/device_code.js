import upperFirst from '../../helpers/_/upper_first.js';
import camelCase from '../../helpers/_/camel_case.js';
import * as errors from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import filterClaims from '../../helpers/filter_claims.js';
import revoke from '../../helpers/revoke.js';
import dpopValidate, { CHALLENGE_OK_WINDOW } from '../../helpers/validate_dpop.js';
import resolveResource from '../../helpers/resolve_resource.js';
import epochTime from '../../helpers/epoch_time.js';
import getCtxAccountClaims from '../../helpers/account_claims.js';
import { setRefreshTokenBindings } from '../../helpers/set_rt_bindings.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';

const {
  AuthorizationPending,
  ExpiredToken,
  InvalidGrant,
} = errors;

export const gty = 'device_code';

export const handler = async function deviceCodeHandler(ctx) {
  presence(ctx, 'device_code');

  if (ctx.oidc.params.authorization_details) {
    throw new errors.InvalidRequest('authorization_details is unsupported for this grant_type');
  }

  const {
    findAccount,
    issueRefreshToken,
    conformIdTokenClaims,
    features: {
      userinfo,
      mTLS: { getCertificate },
      dPoP: { allowReplay },
      resourceIndicators,
    },
  } = instance(ctx.oidc.provider).configuration;

  const dPoP = await dpopValidate(ctx);

  const code = await ctx.oidc.provider.DeviceCode.find(ctx.oidc.params.device_code, {
    ignoreExpiration: true,
  });

  if (!code) {
    throw new InvalidGrant('device code not found');
  }

  if (code.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await checkAttestBinding(ctx, code);
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

  if (code.isExpired) {
    throw new ExpiredToken('device code is expired');
  }

  if (!code.accountId && !code.error) {
    throw new AuthorizationPending();
  }

  if (code.consumed) {
    await revoke(ctx, code.grantId);
    throw new InvalidGrant('device code already consumed');
  }

  await code.consume();

  if (code.error) {
    const className = upperFirst(camelCase(code.error));
    if (errors[className]) {
      throw new errors[className](code.errorDescription);
    }
    throw new errors.CustomOIDCProviderError(code.error, code.errorDescription);
  }

  const grant = await ctx.oidc.provider.Grant.find(code.grantId, {
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

  ctx.oidc.entity('DeviceCode', code);
  ctx.oidc.entity('Grant', grant);

  const account = await findAccount(ctx, code.accountId, code);

  if (!account) {
    throw new InvalidGrant('device code invalid (referenced account not found)');
  }

  if (code.accountId !== grant.accountId) {
    throw new InvalidGrant('accountId mismatch');
  }

  ctx.oidc.entity('Account', account);

  const {
    AccessToken, IdToken, RefreshToken, ReplayDetection,
  } = ctx.oidc.provider;

  const at = new AccessToken({
    accountId: account.accountId,
    client: ctx.oidc.client,
    expiresWithSession: code.expiresWithSession,
    grantId: code.grantId,
    gty,
    sessionUid: code.sessionUid,
    sid: code.sid,
  });

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    at.setThumbprint('x5t', cert);
  }

  if (dPoP) {
    if (!allowReplay) {
      const unique = await ReplayDetection.unique(
        ctx.oidc.client.clientId,
        dPoP.jti,
        epochTime() + CHALLENGE_OK_WINDOW,
      );

      ctx.assert(unique, new InvalidGrant('DPoP proof JWT Replay detected'));
    }

    at.setThumbprint('jkt', dPoP.thumbprint);
  }

  const resource = await resolveResource(ctx, code, { userinfo, resourceIndicators });

  if (resource) {
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, ctx.oidc.client);
    at.resourceServer = new ctx.oidc.provider.ResourceServer(resource, resourceServerInfo);
    at.scope = grant.getResourceScopeFiltered(resource, code.scopes);
  } else {
    at.claims = code.claims;
    at.scope = grant.getOIDCScopeFiltered(code.scopes);
  }

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  let refreshToken;
  if (await issueRefreshToken(ctx, ctx.oidc.client, code)) {
    const rt = new RefreshToken({
      accountId: account.accountId,
      acr: code.acr,
      amr: code.amr,
      authTime: code.authTime,
      claims: code.claims,
      client: ctx.oidc.client,
      expiresWithSession: code.expiresWithSession,
      grantId: code.grantId,
      gty,
      nonce: code.nonce,
      resource: code.resource,
      rotations: 0,
      scope: code.scope,
      sessionUid: code.sessionUid,
      sid: code.sid,
    });

    await setRefreshTokenBindings(ctx, at, rt);

    ctx.oidc.entity('RefreshToken', rt);
    refreshToken = await rt.save();
  }

  let idToken;
  if (code.scopes.has('openid')) {
    const claims = filterClaims(code.claims, 'id_token', grant);
    const rejected = grant.getRejectedOIDCClaims();
    const token = new IdToken({
      ...await getCtxAccountClaims(ctx, 'id_token', code.scope, claims, rejected),
      ...{
        acr: code.acr,
        amr: code.amr,
        auth_time: code.authTime,
      },
    }, { ctx });

    if (conformIdTokenClaims && userinfo.enabled && !at.aud) {
      token.scope = 'openid';
    } else {
      token.scope = grant.getOIDCScopeFiltered(code.scopes);
    }

    token.mask = claims;
    token.rejected = rejected;

    token.set('nonce', code.nonce);
    token.set('sid', code.sid);

    idToken = await token.issue({ use: 'idtoken' });
  }

  ctx.body = {
    access_token: accessToken,
    expires_in: at.expiration,
    id_token: idToken,
    refresh_token: refreshToken,
    scope: code.scope ? at.scope : (at.scope || undefined),
    token_type: at.tokenType,
  };
};

export const parameters = new Set(['device_code']);

export const grantType = 'urn:ietf:params:oauth:grant-type:device_code';
