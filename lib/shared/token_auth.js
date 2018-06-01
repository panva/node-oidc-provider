const compose = require('koa-compose');

const bodyParser = require('./selective_body');
const getParams = require('./get_params');
const rejectDupes = require('./check_dupes');
const loadClient = require('./load_client');
const { InvalidRequest, InvalidClientAuth } = require('../helpers/errors');
const setWWWAuthenticate = require('../helpers/set_www_authenticate');
const JWT = require('../helpers/jwt');

const tokenCredentialAuth = require('./token_credential_auth');
const getJWTAuthMiddleware = require('./token_jwt_auth');

const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

function throwMultipleAuthz(ctx) {
  ctx.throw(new InvalidRequest('client authentication must only be provided using one mechanism'));
}

// see https://tools.ietf.org/html/rfc6749#appendix-B
function decodeAuthToken(token) {
  return decodeURIComponent(token.replace(/\+/g, '%20'));
}

module.exports = function tokenAuth(provider, whitelist, endpoint) {
  const tokenJwtAuth = getJWTAuthMiddleware(provider, endpoint);
  const parseBody = bodyParser('application/x-www-form-urlencoded');
  ['client_assertion', 'client_assertion_type', 'client_id', 'client_secret']
    .forEach(whitelist.add.bind(whitelist));
  const buildParams = getParams(whitelist);

  return compose([
    parseBody,
    buildParams,
    rejectDupes,
    async function setWWWAuthenticateHeader(ctx, next) {
      try {
        await next();
      } catch (err) {
        if (err.statusCode === 401 && ctx.header.authorization !== undefined) {
          setWWWAuthenticate(ctx, 'Basic', {
            realm: provider.issuer,
            error: err.message,
            error_description: err.error_description,
          });
        }
        throw err;
      }
    },
    async function findClientId(ctx, next) {
      const {
        params: {
          client_id: clientId,
          client_assertion: clientAssertion,
          client_assertion_type: clientAssertionType,
          client_secret: clientSecret,
        },
      } = ctx.oidc;

      if (ctx.headers.authorization !== undefined) {
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
        ctx.oidc.authorization.methods = ['client_secret_basic'];

        if (clientId !== undefined && ctx.oidc.authorization.clientId !== clientId) {
          ctx.throw(new InvalidRequest('mismatch in body and authorization client ids'));
        }
        if (clientSecret !== undefined) throwMultipleAuthz(ctx);
      } else if (clientId !== undefined) {
        ctx.oidc.authorization.clientId = clientId;
        ctx.oidc.authorization.methods = ['client_secret_post', 'none'];
      }

      if (clientAssertion !== undefined) {
        if (clientSecret !== undefined || ctx.headers.authorization !== undefined) {
          throwMultipleAuthz(ctx);
        }

        let sub;
        try {
          ({ payload: { sub } } = JWT.decode(clientAssertion));
        } catch (err) {
          ctx.throw(new InvalidRequest('invalid client_assertion format'));
        }

        if (clientId && sub !== clientId) {
          ctx.throw(new InvalidRequest('subject of client_assertion must be the same as client_id provided in the body'));
        }

        if (clientAssertionType === undefined) {
          ctx.throw(new InvalidRequest('client_assertion_type must be provided'));
        }

        if (clientAssertionType !== assertionType) {
          ctx.throw(new InvalidRequest(`client_assertion_type must have value ${assertionType}`));
        }

        ctx.oidc.authorization.clientId = sub;
        ctx.oidc.authorization.methods = ['client_secret_jwt', 'private_key_jwt'];
      }

      if (!ctx.oidc.authorization.clientId) {
        ctx.throw(new InvalidRequest('no client authentication mechanism provided'));
      }

      return next();
    },
    loadClient(provider),
    async function auth(ctx, next) {
      const {
        params,
        client: {
          [`${endpoint}EndpointAuthMethod`]: clientMethod,
          [`${endpoint}EndpointAuthSigningAlg`]: signingAlg,
        },
        authorization: {
          methods,
          clientSecret,
        },
      } = ctx.oidc;

      if (!methods.includes(clientMethod)) {
        ctx.throw(new InvalidClientAuth(`the registered client ${endpoint}_endpoint_auth_method does not match the provided auth mechanism`));
      }

      switch (clientMethod) { // eslint-disable-line default-case
        case 'none':
          if (params.client_secret) {
            ctx.throw(new InvalidClientAuth(`unexpected client_secret provided for ${endpoint}_endpoint_auth_method=none client request`));
          }
          break;

        case 'client_secret_post':
          if (!params.client_secret) {
            ctx.throw(new InvalidClientAuth('client_secret must be provided in the body'));
          }
          tokenCredentialAuth(ctx, ctx.oidc.client.clientSecret, params.client_secret);

          break;

        case 'client_secret_jwt':
          await tokenJwtAuth(
            ctx, ctx.oidc.client.keystore,
            signingAlg ? [signingAlg] : ['HS256', 'HS384', 'HS512'],
          );

          break;

        case 'private_key_jwt':
          await tokenJwtAuth(
            ctx, ctx.oidc.client.keystore,
            signingAlg ?
              [signingAlg] : ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
          );

          break;

        case 'client_secret_basic':
          if (!clientSecret) {
            ctx.throw(new InvalidClientAuth('client_secret must be provided in the Authorization header'));
          }

          tokenCredentialAuth(ctx, ctx.oidc.client.clientSecret, clientSecret);
      }

      await next();
    },
  ]);
};
