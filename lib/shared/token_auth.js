const { InvalidRequest, InvalidClientAuth } = require('../helpers/errors');
const setWWWAuthenticate = require('../helpers/set_www_authenticate');
const JWT = require('../helpers/jwt');

const rejectDupes = require('./reject_dupes');
const loadClient = require('./load_client');
const tokenCredentialAuth = require('./token_credential_auth');
const getJWTAuthMiddleware = require('./token_jwt_auth');

const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

// see https://tools.ietf.org/html/rfc6749#appendix-B
function decodeAuthToken(token) {
  return decodeURIComponent(token.replace(/\+/g, '%20'));
}

const AUTH_PARAMS = new Set([
  'client_assertion', 'client_assertion_type', 'client_id', 'client_secret',
]);

module.exports = function tokenAuth(provider, endpoint) {
  const tokenJwtAuth = getJWTAuthMiddleware(provider, endpoint);

  return [
    rejectDupes.only(...AUTH_PARAMS),
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
          throw new InvalidRequest('invalid authorization header value format');
        }

        const basic = Buffer.from(parts[1], 'base64').toString('utf8');
        const i = basic.indexOf(':');

        if (i === -1) {
          throw new InvalidRequest('invalid authorization header value format');
        }

        try {
          ctx.oidc.authorization.clientId = decodeAuthToken(basic.slice(0, i));
          ctx.oidc.authorization.clientSecret = decodeAuthToken(basic.slice(i + 1));
        } catch (err) {
          throw new InvalidRequest('client_id and client_secret are not properly encoded');
        }
        ctx.oidc.authorization.methods = ['client_secret_basic'];

        if (clientId !== undefined && ctx.oidc.authorization.clientId !== clientId) {
          throw new InvalidRequest('mismatch in body and authorization client ids');
        }
        if (clientSecret !== undefined) throw new InvalidRequest('client authentication must only be provided using one mechanism');
      } else if (clientId !== undefined) {
        ctx.oidc.authorization.clientId = clientId;
        ctx.oidc.authorization.methods = ['client_secret_post', 'none'];
      }

      if (clientAssertion !== undefined) {
        if (clientSecret !== undefined || ctx.headers.authorization !== undefined) {
          throw new InvalidRequest('client authentication must only be provided using one mechanism');
        }

        let sub;
        try {
          ({ payload: { sub } } = JWT.decode(clientAssertion));
        } catch (err) {
          throw new InvalidRequest('invalid client_assertion format');
        }

        if (clientId && sub !== clientId) {
          throw new InvalidRequest('subject of client_assertion must be the same as client_id provided in the body');
        }

        if (clientAssertionType === undefined) {
          throw new InvalidRequest('client_assertion_type must be provided');
        }

        if (clientAssertionType !== assertionType) {
          throw new InvalidRequest(`client_assertion_type must have value ${assertionType}`);
        }

        ctx.oidc.authorization.clientId = sub;
        ctx.oidc.authorization.methods = ['client_secret_jwt', 'private_key_jwt'];
      }

      if (!ctx.oidc.authorization.clientId) {
        throw new InvalidRequest('no client authentication mechanism provided');
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
        throw new InvalidClientAuth(`the registered client ${endpoint}_endpoint_auth_method does not match the provided auth mechanism`);
      }

      switch (clientMethod) { // eslint-disable-line default-case
        case 'none':
          if (params.client_secret) {
            throw new InvalidClientAuth(`unexpected client_secret provided for ${endpoint}_endpoint_auth_method=none client request`);
          }
          break;

        case 'client_secret_post':
          if (!params.client_secret) {
            throw new InvalidClientAuth('client_secret must be provided in the body');
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
            signingAlg
              ? [signingAlg] : ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
          );

          break;

        case 'client_secret_basic':
          if (!clientSecret) {
            throw new InvalidClientAuth('client_secret must be provided in the Authorization header');
          }

          tokenCredentialAuth(ctx, ctx.oidc.client.clientSecret, clientSecret);
      }

      await next();
    },
  ];
};

module.exports.AUTH_PARAMS = AUTH_PARAMS;
