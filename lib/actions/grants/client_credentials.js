const instance = require('../../helpers/weak_cache');
const { InvalidRequest } = require('../../helpers/errors');

module.exports.handler = async function clientCredentialsHandler(ctx, next) {
  const { ClientCredentials } = ctx.oidc.provider;
  const {
    audiences, scopes: statics, dynamicScopes: dynamics,
  } = instance(ctx.oidc.provider).configuration();

  const scopes = ctx.oidc.params.scope ? ctx.oidc.params.scope.split(' ').filter((scope) => {
    if (statics.has(scope)) {
      return true;
    }

    for (const dynamic of dynamics) { // eslint-disable-line no-restricted-syntax
      if (dynamic.test(scope)) {
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
    const cert = ctx.get('x-ssl-client-cert');

    if (!cert) {
      throw new InvalidRequest('mutual TLS client certificate not provided');
    }
    token.setS256Thumbprint(cert);
  }

  token.setAudiences(await audiences(ctx, undefined, token, 'client_credentials'));

  ctx.oidc.entity('ClientCredentials', token);
  const value = await token.save();

  ctx.body = {
    access_token: value,
    expires_in: token.expiration,
    token_type: 'Bearer',
    scope: token.scope,
  };

  await next();
};

module.exports.parameters = new Set(['scope']);
