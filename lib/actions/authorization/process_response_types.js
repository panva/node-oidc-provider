const { get } = require('lodash');

const instance = require('../../helpers/weak_cache');

module.exports = (provider) => {
  const { IdToken, AccessToken, AuthorizationCode } = provider;

  const {
    features: { pkce, conformIdTokenClaims, resourceIndicators },
    audiences,
  } = instance(provider).configuration();

  async function tokenHandler(ctx) {
    const accountId = ctx.oidc.session.accountId();
    const at = new AccessToken({
      client: ctx.oidc.client,
      accountId,
      claims: ctx.oidc.resolvedClaims(),
      grantId: ctx.oidc.uuid,
      scope: ctx.oidc.acceptedScope(),
      sid: ctx.oidc.session.sidFor(ctx.oidc.client.clientId),
      gty: 'implicit',
    });

    at.setAudiences(await audiences(ctx, accountId, at, 'access_token'));

    ctx.oidc.entity('AccessToken', at);

    return {
      access_token: await at.save(),
      expires_in: at.expiration,
      token_type: 'Bearer',
    };
  }

  async function codeHandler(ctx) {
    const ac = new AuthorizationCode({
      accountId: ctx.oidc.session.accountId(),
      acr: ctx.oidc.acr,
      amr: ctx.oidc.amr,
      authTime: ctx.oidc.session.authTime(),
      claims: ctx.oidc.resolvedClaims(),
      client: ctx.oidc.client,
      grantId: ctx.oidc.uuid,
      nonce: ctx.oidc.params.nonce,
      redirectUri: ctx.oidc.params.redirect_uri,
      scope: ctx.oidc.acceptedScope(),
    });

    if (pkce) {
      ac.codeChallenge = ctx.oidc.params.code_challenge;
      ac.codeChallengeMethod = ctx.oidc.params.code_challenge_method;
    }

    if (ctx.oidc.client.includeSid() || get(ctx.oidc.claims, 'id_token.sid')) {
      ac.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
    }

    ctx.oidc.entity('AuthorizationCode', ac);

    if (resourceIndicators) {
      ac.resource = ctx.oidc.params.resource;
    }

    return { code: await ac.save() };
  }

  async function idTokenHandler(ctx) {
    const tokenClaims = ctx.oidc.resolvedClaims();
    const claims = get(tokenClaims, 'id_token', {});
    const rejected = get(tokenClaims, 'rejected', []);
    const token = new IdToken({
      ...await ctx.oidc.account.claims('id_token', ctx.oidc.acceptedScope(), claims, rejected),
      acr: ctx.oidc.acr,
      amr: ctx.oidc.amr,
      auth_time: ctx.oidc.session.authTime(),
    }, ctx.oidc.client);

    if (conformIdTokenClaims) {
      if (ctx.oidc.params.response_type === 'id_token') {
        token.scope = ctx.oidc.acceptedScope();
      } else {
        token.scope = 'openid';
      }
    } else {
      token.scope = ctx.oidc.acceptedScope();
    }

    token.mask = claims;
    token.rejected = rejected;

    token.set('nonce', ctx.oidc.params.nonce);

    if (ctx.oidc.client.includeSid() || get(ctx.oidc.claims, 'id_token.sid')) {
      token.set('sid', ctx.oidc.session.sidFor(ctx.oidc.client.clientId));
    }

    return { id_token: token };
  }

  /*
   * Resolves each requested response type to a single response object. If one of the hybrid
   * response types is used an appropriate _hash is also pushed on to the id_token.
   */
  return async function processResponseTypes(ctx) {
    const responses = ctx.oidc.params.response_type.split(' ');
    const res = Object.assign({}, ...await Promise.all(responses.map((responseType) => {
      switch (responseType) {
        case 'code':
          return codeHandler(ctx);
        case 'token':
          return tokenHandler(ctx);
        case 'id_token':
          return idTokenHandler(ctx);
        default:
          return {};
      }
    })));

    if (res.access_token && res.id_token) {
      res.id_token.set('at_hash', res.access_token);
    }

    if (res.code && res.id_token) {
      res.id_token.set('c_hash', res.code);
    }

    if (ctx.oidc.params.state && res.id_token) {
      res.id_token.set('s_hash', ctx.oidc.params.state);
    }

    if (res.id_token) {
      res.id_token = await res.id_token.sign({
        audiences: await audiences(ctx, ctx.oidc.session.accountId(), res.id_token, 'id_token'),
      });
    }

    return res;
  };
};
