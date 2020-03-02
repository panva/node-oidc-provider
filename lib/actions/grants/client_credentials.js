const instance = require('../../helpers/weak_cache');
const { InvalidGrant } = require('../../helpers/errors');
const { InvalidScope } = require('../../helpers/errors');
const { DYNAMIC_SCOPE_LABEL } = require('../../consts');

module.exports.handler = async function clientCredentialsHandler(ctx, next) {
  const { ClientCredentials, ReplayDetection } = ctx.oidc.provider;
  const {
    audiences,
    scopes: statics,
    dynamicScopes: dynamics,
    features: { dPoP: { iatTolerance }, mTLS: { getCertificate } },
  } = instance(ctx.oidc.provider).configuration();

  let whitelist;
  if (ctx.oidc.client.scope) {
    whitelist = new Set(ctx.oidc.client.scope.split(' '));
  }

  const scopes = ctx.oidc.params.scope ? ctx.oidc.params.scope.split(' ').filter((scope) => {
    if (statics.has(scope)) {
      if (whitelist && !whitelist.has(scope)) {
        throw new InvalidScope('requested scope is not whitelisted', scope);
      }
      return true;
    }

    for (const dynamic of dynamics) { // eslint-disable-line no-restricted-syntax
      if (dynamic.test(scope)) {
        if (whitelist && !whitelist.has(dynamic[DYNAMIC_SCOPE_LABEL])) {
          throw new InvalidScope('requested scope is not whitelisted', scope);
        }
        return true;
      }
    }

    return false;
  }) : [];

  const token = new ClientCredentials({
    client: ctx.oidc.client,
    scope: scopes.join(' ') || undefined,
  });

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    const cert = getCertificate(ctx);

    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
    token.setThumbprint('x5t', cert);
  }

  const { dPoP } = ctx.oidc;

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      ctx.oidc.client.clientId, dPoP.jti, dPoP.iat + iatTolerance,
    );

    ctx.assert(unique, new InvalidGrant('DPoP Token Replay detected'));

    token.setThumbprint('jkt', dPoP.jwk);
  }

  token.setAudiences(await audiences(ctx, undefined, token, 'client_credentials'));

  ctx.oidc.entity('ClientCredentials', token);
  const value = await token.save();

  ctx.body = {
    access_token: value,
    expires_in: token.expiration,
    token_type: token.tokenType,
    scope: token.scope,
  };

  await next();
};

module.exports.parameters = new Set(['scope']);
