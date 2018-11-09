const instance = require('../../helpers/weak_cache');
const { InvalidGrant } = require('../../helpers/errors');

module.exports.handler = function getClientCredentialsHandler(provider) {
  return async function clientCredentialsResponse(ctx, next) {
    const { ClientCredentials } = provider;
    const {
      audiences, scopes: statics, dynamicScopes: dynamics,
    } = instance(provider).configuration();

    const scopes = ctx.oidc.params.scope ? ctx.oidc.params.scope.split(' ').filter((scope) => {
      if (statics.includes(scope)) {
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
        throw new InvalidGrant('MTLS client certificate missing');
      }
      token.setS256Thumbprint(cert);
    }

    token.setAudiences(await audiences(ctx, undefined, token, 'client_credentials'));

    const value = await token.save();
    ctx.oidc.entity('ClientCredentials', token);

    ctx.body = {
      access_token: value,
      expires_in: token.expiration,
      token_type: 'Bearer',
      scope: token.scope,
    };

    await next();
  };
};

module.exports.parameters = new Set(['scope']);
