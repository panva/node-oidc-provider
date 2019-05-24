const { get, has } = require('lodash');

const instance = require('../../helpers/weak_cache');

async function tokenHandler(ctx) {
  const accountId = ctx.oidc.session.accountId();
  const scope = ctx.oidc.acceptedScope();
  const token = new ctx.oidc.provider.AccessToken({
    accountId,
    claims: ctx.oidc.resolvedClaims(),
    client: ctx.oidc.client,
    grantId: ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId),
    gty: 'implicit',
    scope,
    sessionUid: ctx.oidc.session.uid,
    sid: ctx.oidc.session.sidFor(ctx.oidc.client.clientId),
  });

  const { audiences, expiresWithSession } = instance(ctx.oidc.provider).configuration();

  if (await expiresWithSession(ctx, token)) {
    token.expiresWithSession = true;
  } else {
    ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout = true;
  }

  token.setAudiences(await audiences(ctx, accountId, token, 'access_token'));

  ctx.oidc.entity('AccessToken', token);

  const result = {
    access_token: await token.save(),
    expires_in: token.expiration,
    token_type: 'Bearer',
  };

  if (token.scope !== ctx.oidc.params.scope) {
    result.scope = token.scope;
  }

  return result;
}

async function codeHandler(ctx) {
  const scope = ctx.oidc.acceptedScope();
  const code = new ctx.oidc.provider.AuthorizationCode({
    accountId: ctx.oidc.session.accountId(),
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    authTime: ctx.oidc.session.authTime(),
    claims: ctx.oidc.resolvedClaims(),
    client: ctx.oidc.client,
    codeChallenge: ctx.oidc.params.code_challenge,
    codeChallengeMethod: ctx.oidc.params.code_challenge_method,
    grantId: ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId),
    nonce: ctx.oidc.params.nonce,
    redirectUri: ctx.oidc.params.redirect_uri,
    scope,
    sessionUid: ctx.oidc.session.uid,
  });

  const {
    expiresWithSession, features: { resourceIndicators },
  } = instance(ctx.oidc.provider).configuration();

  if (await expiresWithSession(ctx, code)) {
    code.expiresWithSession = true;
  } else {
    ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout = true;
  }

  if (ctx.oidc.client.includeSid() || has(ctx.oidc.claims, 'id_token.sid')) {
    code.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
  }


  if (resourceIndicators.enabled) {
    code.resource = ctx.oidc.params.resource;
  }

  ctx.oidc.entity('AuthorizationCode', code);

  return { code: await code.save() };
}

async function idTokenHandler(ctx) {
  const tokenClaims = ctx.oidc.resolvedClaims();
  const claims = get(tokenClaims, 'id_token', {});
  const rejected = get(tokenClaims, 'rejected', []);
  const idToken = new ctx.oidc.provider.IdToken({
    ...await ctx.oidc.account.claims('id_token', ctx.oidc.acceptedScope(), claims, rejected),
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    auth_time: ctx.oidc.session.authTime(),
  }, { ctx });

  const { conformIdTokenClaims } = instance(ctx.oidc.provider).configuration();
  if (conformIdTokenClaims) {
    if (ctx.oidc.params.response_type === 'id_token') {
      idToken.scope = ctx.oidc.acceptedScope();
    } else {
      idToken.scope = 'openid';
    }
  } else {
    idToken.scope = ctx.oidc.acceptedScope();
  }

  idToken.mask = claims;
  idToken.rejected = rejected;

  idToken.set('nonce', ctx.oidc.params.nonce);

  if (ctx.oidc.client.includeSid() || has(ctx.oidc.claims, 'id_token.sid')) {
    idToken.set('sid', ctx.oidc.session.sidFor(ctx.oidc.client.clientId));
  }

  return { id_token: idToken };
}

/*
 * Resolves each requested response type to a single response object. If one of the hybrid
 * response types is used an appropriate _hash is also pushed on to the id_token.
 */
module.exports = async function processResponseTypes(ctx) {
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
    res.id_token = await res.id_token.issue();
  }

  return res;
};
