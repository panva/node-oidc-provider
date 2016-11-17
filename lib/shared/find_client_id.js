'use strict';

const base64url = require('base64url').decode;
const errors = require('../helpers/errors');

module.exports = async function findClientId(ctx, next) {
  ctx.oidc.authorization = {};

  if (ctx.headers.authorization) {
    // client_secret_basic
    ctx.assert(!ctx.oidc.params.client_id, new errors.InvalidRequestError(
      'combining multiple client authentication mechanism is no good'));

    const parts = ctx.headers.authorization.split(' ');
    ctx.assert(parts.length === 2 && parts[0] === 'Basic',
      new errors.InvalidRequestError('invalid authorization header value format'));

    const basic = new Buffer(parts[1], 'base64').toString('utf8');
    const i = basic.indexOf(':');

    ctx.assert(i !== -1,
      new errors.InvalidRequestError('invalid authorization header value format'));

    ctx.oidc.authorization.clientId = basic.slice(0, i);
    ctx.oidc.authorization.clientSecret = basic.slice(i + 1);
  } else if (ctx.oidc.params.client_id && !ctx.oidc.params.client_assertion) {
    // client_secret_post
    ctx.oidc.authorization.clientId = ctx.oidc.params.client_id;
  } else if (ctx.oidc.params.client_assertion) {
    // client_secret_jwt and private_key_jwt
    const assertionSub = (() => {
      try {
        return JSON.parse(base64url(ctx.oidc.params.client_assertion.split('.')[1])).sub;
      } catch (err) {
        return ctx.throw(new errors.InvalidRequestError('invalid client_assertion'));
      }
    })();

    ctx.assert(!ctx.oidc.params.client_id || assertionSub === ctx.oidc.params.client_id,
      new errors.InvalidRequestError('subject of client_assertion must be the same as client_id'));

    ctx.oidc.authorization.clientId = assertionSub;
  }

  ctx.assert(ctx.oidc.authorization.clientId,
    new errors.InvalidClientError('no client authentication mechanism provided'));

  await next();
};
