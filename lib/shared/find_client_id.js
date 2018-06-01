const base64url = require('base64url');
const { InvalidRequest, InvalidClient } = require('../helpers/errors');

// see https://tools.ietf.org/html/rfc6749#appendix-B
function decodeAuthToken(token) {
  return decodeURIComponent(token.replace(/\+/g, '%20'));
}

module.exports = async function findClientId(ctx, next) {
  ctx.oidc.authorization = {};
  const { params } = ctx.oidc;

  // TODO: refactor and fix issues with token_auth

  if (ctx.headers.authorization) { // client_secret_basic
    const parts = ctx.headers.authorization.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Basic') {
      ctx.throw(new InvalidRequest('invalid authorization header value format'));
    }

    const basic = Buffer.from(parts[1], 'base64').toString('utf8');
    const i = basic.indexOf(':');

    if (i === -1) {
      ctx.throw(new InvalidRequest('invalid authorization header value format'));
    }
    try {
      ctx.oidc.authorization.clientId = decodeAuthToken(basic.slice(0, i));
      ctx.oidc.authorization.clientSecret = decodeAuthToken(basic.slice(i + 1));
    } catch (err) {
      ctx.throw(new InvalidRequest('client_id and client_secret are not properly encoded'));
    }
    ctx.oidc.authorization.method = 'client_secret_basic';
  } else if (params.client_id && !params.client_assertion) { // client_secret_post
    ctx.oidc.authorization.clientId = params.client_id;
    ctx.oidc.authorization.method = 'client_secret_post';
  } else if (params.client_assertion) { // client_secret_jwt and private_key_jwt
    const assertionSub = (() => {
      try {
        return JSON.parse(base64url.decode(params.client_assertion.split('.')[1])).sub;
      } catch (err) {
        return ctx.throw(new InvalidRequest('invalid client_assertion'));
      }
    })();

    if (params.client_id && assertionSub !== params.client_id) {
      ctx.throw(new InvalidRequest('subject of client_assertion must be the same as client_id provided in the body'));
    }

    ctx.oidc.authorization.clientId = assertionSub;
    ctx.oidc.authorization.method = 'client_assertion';
  }

  if (!ctx.oidc.authorization.clientId) {
    ctx.throw(new InvalidClient('no client authentication mechanism provided'));
  }

  await next();
};
