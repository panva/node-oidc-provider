const instance = require('../../helpers/weak_cache');
const { InvalidGrant, InvalidTarget, InvalidScope } = require('../../helpers/errors');
const checkResource = require('../../shared/check_resource');

module.exports.handler = async function clientCredentialsHandler(ctx, next) {
  const { client } = ctx.oidc;
  const { ClientCredentials, ReplayDetection } = ctx.oidc.provider;
  const {
    features: {
      dPoP: { iatTolerance },
      mTLS: { getCertificate },
    },
    scopes: statics,
  } = instance(ctx.oidc.provider).configuration();

  await checkResource(ctx, () => {});

  const scopes = ctx.oidc.params.scope ? [...new Set(ctx.oidc.params.scope.split(' '))] : [];

  if (client.scope) {
    const whitelist = new Set(client.scope.split(' '));
    // eslint-disable-next-line no-restricted-syntax
    for (const scope of scopes.filter(Set.prototype.has.bind(statics))) {
      if (!whitelist.has(scope)) {
        throw new InvalidScope('requested scope is not whitelisted', scope);
      }
    }
  }

  const token = new ClientCredentials({
    client,
    scope: scopes.join(' ') || undefined,
  });

  // eslint-disable-next-line no-restricted-syntax
  Object.values(ctx.oidc.resourceServers).forEach((resourceServer, i) => {
    if (i !== 0) {
      throw new InvalidTarget('only a single resource indicator value is supported for this grant type');
    }
    token.resourceServer = resourceServer;
    token.scope = scopes.filter(Set.prototype.has.bind(new Set(resourceServer.scope.split(' ')))).join(' ') || undefined;
  });

  if (client.tlsClientCertificateBoundAccessTokens) {
    const cert = getCertificate(ctx);

    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
    token.setThumbprint('x5t', cert);
  }

  const { dPoP } = ctx.oidc;

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      client.clientId, dPoP.jti, dPoP.iat + iatTolerance,
    );

    ctx.assert(unique, new InvalidGrant('DPoP Token Replay detected'));

    token.setThumbprint('jkt', dPoP.jwk);
  }

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
