const { InvalidRequest, InvalidClientAuth } = require('../helpers/errors');
const setWWWAuthenticate = require('../helpers/set_www_authenticate');
const JWT = require('../helpers/jwt');
const instance = require('../helpers/weak_cache');
const { 'x5t#S256': thumbprint } = require('../helpers/calculate_thumbprint');

const rejectDupes = require('./reject_dupes');
const getJWTAuthMiddleware = require('./token_jwt_auth');

const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

// see https://tools.ietf.org/html/rfc6749#appendix-B
function decodeAuthToken(token) {
  return decodeURIComponent(token.replace(/\+/g, '%20'));
}

module.exports = function tokenAuth(provider, endpoint, jwtAuthEndpointIdentifier = endpoint) {
  const tokenJwtAuth = getJWTAuthMiddleware(provider, jwtAuthEndpointIdentifier);
  const authParams = new Set(['client_id']);

  instance(provider).configuration(`${endpoint}EndpointAuthMethods`).forEach((method) => {
    switch (method) {
      case 'client_secret_post':
        authParams.add('client_secret');
        break;
      case 'client_secret_jwt':
      case 'private_key_jwt':
        authParams.add('client_assertion');
        authParams.add('client_assertion_type');
        break;
      default:
    }
  });

  authParams.forEach(Set.prototype.add.bind(instance(provider).grantTypeParams.get(undefined)));

  return {
    params: authParams,
    middleware: [
      rejectDupes.bind(undefined, { only: authParams }),
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
          if (parts.length !== 2 || parts[0].toLowerCase() !== 'basic') {
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
            throw new InvalidRequest('client_id and client_secret in the authorization header are not properly encoded');
          }

          if (clientId !== undefined && ctx.oidc.authorization.clientId !== clientId) {
            throw new InvalidRequest('mismatch in body and authorization client ids');
          }

          if (!ctx.oidc.authorization.clientSecret) {
            throw new InvalidRequest('client_secret must be provided in the Authorization header');
          }

          if (clientSecret !== undefined) {
            throw new InvalidRequest('client authentication must only be provided using one mechanism');
          }

          ctx.oidc.authorization.methods = ['client_secret_basic', 'client_secret_post'];
        } else if (clientId !== undefined) {
          ctx.oidc.authorization.clientId = clientId;
          ctx.oidc.authorization.methods = clientSecret
            ? ['client_secret_basic', 'client_secret_post']
            : ['none', 'tls_client_auth', 'self_signed_tls_client_auth'];
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
      async function loadClient(ctx, next) {
        const client = await provider.Client.find(ctx.oidc.authorization.clientId);

        if (!client) {
          throw new InvalidClientAuth('client not found');
        }

        ctx.oidc.entity('Client', client);

        await next();
      },
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
            break;

          case 'client_secret_basic':
          case 'client_secret_post': {
            ctx.oidc.client.checkClientSecretExpiration('could not authenticate the client - its client secret is expired');
            const actual = params.client_secret || clientSecret;
            const matches = await ctx.oidc.client.compareClientSecret(actual);
            if (!matches) {
              throw new InvalidClientAuth('invalid secret provided');
            }

            break;
          }

          case 'client_secret_jwt':
            ctx.oidc.client.checkClientSecretExpiration('could not authenticate the client - its client secret used for the client_assertion is expired');
            await tokenJwtAuth(
              ctx, ctx.oidc.client.keystore,
              signingAlg ? [signingAlg] : instance(provider).configuration(`${endpoint}EndpointAuthSigningAlgValues`).filter((alg) => alg.startsWith('HS')),
            );

            break;

          case 'private_key_jwt':
            await tokenJwtAuth(
              ctx, ctx.oidc.client.keystore,
              signingAlg ? [signingAlg] : instance(provider).configuration(`${endpoint}EndpointAuthSigningAlgValues`).filter((alg) => !alg.startsWith('HS')),
            );

            break;

          case 'tls_client_auth': {
            const { mTLS: { getCertificate, certificateAuthorized, certificateSubjectMatches } } = instance(provider).configuration('features');

            const cert = getCertificate(ctx);

            if (!cert) {
              throw new InvalidClientAuth('client certificate was not provided');
            }

            if (!certificateAuthorized(ctx)) {
              throw new InvalidClientAuth('client certificate was not verified');
            }

            for (const [prop, key] of Object.entries({ // eslint-disable-line no-restricted-syntax
              tlsClientAuthSubjectDn: 'tls_client_auth_subject_dn',
              tlsClientAuthSanDns: 'tls_client_auth_san_dns',
              tlsClientAuthSanIp: 'tls_client_auth_san_ip',
              tlsClientAuthSanEmail: 'tls_client_auth_san_email',
              tlsClientAuthSanUri: 'tls_client_auth_san_uri',
            })) {
              const value = ctx.oidc.client[prop];
              if (value) {
                if (!certificateSubjectMatches(ctx, key, value)) {
                  throw new InvalidClientAuth('certificate subject value does not match the registered one');
                }
                break;
              }
            }

            break;
          }
          case 'self_signed_tls_client_auth': {
            const { mTLS: { getCertificate } } = instance(provider).configuration('features');
            const cert = getCertificate(ctx);

            if (!cert) {
              throw new InvalidClientAuth('client certificate was not provided');
            }

            await ctx.oidc.client.keystore.refresh();
            const match = ctx.oidc.client.keystore.get({ 'x5t#S256': thumbprint(cert) });

            if (!match) {
              throw new InvalidClientAuth('unregistered client certificate provided');
            }

            break;
          }
        }

        await next();
      },
    ],
  };
};
