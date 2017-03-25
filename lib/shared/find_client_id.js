const { decode } = require('base64url');
const { InvalidRequestError, InvalidClientError } = require('../helpers/errors');

module.exports = async function findClientId(ctx, next) {
  ctx.oidc.authorization = {};
  const params = ctx.oidc.params;

  if (ctx.headers.authorization) { // client_secret_basic
    const parts = ctx.headers.authorization.split(' ');
    ctx.assert(parts.length === 2 && parts[0] === 'Basic',
      new InvalidRequestError('invalid authorization header value format'));

    const basic = new Buffer(parts[1], 'base64').toString('utf8');
    const i = basic.indexOf(':');

    ctx.assert(i !== -1,
      new InvalidRequestError('invalid authorization header value format'));

    ctx.oidc.authorization.clientId = basic.slice(0, i);
    ctx.oidc.authorization.clientSecret = basic.slice(i + 1);
  } else if (params.client_id && !params.client_assertion) { // client_secret_post
    ctx.oidc.authorization.clientId = params.client_id;
  } else if (params.client_assertion) { // client_secret_jwt and private_key_jwt
    const assertionSub = (() => {
      try {
        return JSON.parse(decode(params.client_assertion.split('.')[1])).sub;
      } catch (err) {
        return ctx.throw(new InvalidRequestError('invalid client_assertion'));
      }
    })();

    ctx.assert(!params.client_id || assertionSub === params.client_id,
      new InvalidRequestError('subject of client_assertion must be the same as client_id'));

    ctx.oidc.authorization.clientId = assertionSub;
  }

  ctx.assert(ctx.oidc.authorization.clientId,
    new InvalidClientError('no client authentication mechanism provided'));

  await next();
};
