const JWT = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');
const { InvalidRequest, InvalidRequestObject, OIDCProviderError } = require('../../helpers/errors');
const isPlainObject = require('../../helpers/_/is_plain_object');

const checkResponseMode = require('./check_response_mode');

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 *
 * @throws: invalid_request_object
 */
module.exports = async function processRequestObject(PARAM_LIST, rejectDupesMiddleware, ctx, next) {
  const { params, client, route } = ctx.oidc;

  const pushedRequestObject = 'PushedAuthorizationRequest' in ctx.oidc.entities;
  if (client.requirePushedAuthorizationRequests && route !== 'pushed_authorization_request' && !pushedRequestObject) {
    throw new InvalidRequest('Pushed Authorization Request must be used');
  }

  const isBackchannelAuthentication = route === 'backchannel_authentication';
  const conf = instance(ctx.oidc.provider).configuration();
  const { features } = conf;

  if (
    params.request === undefined
    && (
      client.requireSignedRequestObject
      || (client.backchannelAuthenticationRequestSigningAlg && isBackchannelAuthentication)
      || (ctx.oidc.fapiProfile !== undefined && isBackchannelAuthentication)
    )
  ) {
    throw new InvalidRequest('Request Object must be used by this client');
  }

  if (params.request === undefined) {
    return next();
  }

  let trusted = false; // signed or encrypted by client confidential material

  if (features.encryption.enabled && params.request.split('.').length === 5) {
    if (isBackchannelAuthentication) {
      throw new InvalidRequest('Encrypted Request Objects are not supported by CIBA');
    }

    try {
      const header = JWT.header(params.request);

      if (!conf.requestObjectEncryptionAlgValues.includes(header.alg)) {
        throw new TypeError('unsupported encrypted request alg');
      }
      if (!conf.requestObjectEncryptionEncValues.includes(header.enc)) {
        throw new TypeError('unsupported encrypted request enc');
      }

      let decrypted;
      if (/^(A|P|dir$)/.test(header.alg)) {
        client.checkClientSecretExpiration('could not decrypt the Request Object - the client secret used for its encryption is expired', 'invalid_request_object');
        decrypted = await JWT.decrypt(params.request, client.symmetricKeyStore);
        trusted = true;
      } else {
        decrypted = await JWT.decrypt(params.request, instance(ctx.oidc.provider).keystore);
      }

      params.request = decrypted.toString('utf8');

      if (ctx.oidc.body) {
        ctx.oidc.body.request = params.request;
      }
    } catch (err) {
      if (err instanceof OIDCProviderError) {
        throw err;
      }

      throw new InvalidRequestObject('could not decrypt request object', err.message);
    }
  }

  let decoded;

  try {
    decoded = JWT.decode(params.request);
  } catch (err) {
    throw new InvalidRequestObject('could not parse Request Object', err.message);
  }

  const { payload, header: { alg } } = decoded;

  const request = Object.entries(payload).reduce((acc, [key, value]) => {
    if (PARAM_LIST.has(key)) {
      if (key === 'claims' && isPlainObject(value)) {
        acc[key] = JSON.stringify(value);
      } else if (Array.isArray(value)) {
        acc[key] = value;
      } else if (typeof value !== 'string') {
        acc[key] = String(value);
      } else {
        acc[key] = value;
      }
    }

    return acc;
  }, {});

  rejectDupesMiddleware({ oidc: { params: request } }, () => {});

  if (request.state !== undefined) {
    params.state = request.state;
  }

  if (request.response_mode !== undefined || ctx.oidc.fapiProfile !== undefined) {
    if (request.response_mode !== undefined) {
      params.response_mode = request.response_mode;
    }
    if (request.response_type !== undefined) {
      params.response_type = request.response_type;
    }
    checkResponseMode(ctx, () => {}, ctx.oidc.fapiProfile !== undefined);
  }

  if (request.request !== undefined || request.request_uri !== undefined) {
    throw new InvalidRequestObject('Request Object must not contain request or request_uri properties');
  }

  if (
    params.response_type
    && request.response_type !== undefined
    && request.response_type !== params.response_type
  ) {
    throw new InvalidRequestObject('request response_type must equal the one in request parameters');
  }

  if (
    params.client_id
    && request.client_id !== undefined
    && request.client_id !== params.client_id
  ) {
    throw new InvalidRequestObject('request client_id must equal the one in request parameters');
  }

  if (route === 'pushed_authorization_request') {
    if (request.client_id !== ctx.oidc.client.clientId) {
      throw new InvalidRequestObject('request client_id must equal the authenticated client\'s client_id');
    }
  }

  if (request.client_id !== undefined && request.client_id !== client.clientId) {
    throw new InvalidRequestObject('request client_id mismatch');
  }

  const prop = isBackchannelAuthentication ? 'backchannelAuthenticationRequestSigningAlg' : 'requestObjectSigningAlg';
  if (client[prop] && alg !== client[prop]) {
    throw new InvalidRequestObject('the preregistered alg must be used in request or request_uri');
  }

  if (!pushedRequestObject && !conf.requestObjectSigningAlgValues.includes(alg)) {
    throw new InvalidRequestObject('unsupported signed request alg');
  }

  const opts = {
    issuer: client.clientId,
    audience: ctx.oidc.issuer,
    clockTolerance: conf.clockTolerance,
    ignoreAzp: true,
  };

  if (ctx.oidc.fapiProfile !== undefined) {
    if (!('exp' in payload)) {
      throw new InvalidRequestObject("Request Object is missing the 'exp' claim");
    }

    if (ctx.oidc.fapiProfile === '1.0 Final') {
      if (!('aud' in payload)) {
        throw new InvalidRequestObject("Request Object is missing the 'aud' claim");
      }
      if (!('nbf' in payload)) {
        throw new InvalidRequestObject("Request Object is missing the 'nbf' claim");
      }
      const diff = payload.exp - payload.nbf;
      if (Math.sign(diff) !== 1 || diff > 3600) {
        throw new InvalidRequestObject("Request Object 'exp' claim too far from 'nbf' claim");
      }
    }
  }

  if (isBackchannelAuthentication) {
    // eslint-disable-next-line no-restricted-syntax
    for (const claim of ['exp', 'iat', 'nbf', 'jti']) {
      if (!(claim in payload)) {
        throw new InvalidRequestObject(`Request Object is missing the '${claim}' claim`);
      }
    }

    if (ctx.oidc.fapiProfile !== undefined) {
      const diff = payload.exp - payload.nbf;
      if (Math.sign(diff) !== 1 || diff > 3600) {
        throw new InvalidRequestObject("Request Object 'exp' claim too far from 'nbf' claim");
      }
    }
  }

  // TODO: in v7.x assert that sub !== clientId (re-use of other JWTs)
  // if ('sub' in payload && payload.sub === client.clientId) {
  //   throw new InvalidRequestObject('Cross-JWT Confusion Request Object');
  // }

  try {
    JWT.assertPayload(payload, opts);
  } catch (err) {
    throw new InvalidRequestObject('Request Object claims are invalid', err.message);
  }

  if (alg !== 'none') {
    try {
      if (alg.startsWith('HS')) {
        client.checkClientSecretExpiration('could not validate the Request Object - the client secret used for its signature is expired', 'invalid_request_object');
        await JWT.verify(params.request, client.symmetricKeyStore, opts);
      } else {
        await JWT.verify(params.request, client.asymmetricKeyStore, opts);
      }
      trusted = true;
    } catch (err) {
      if (err instanceof OIDCProviderError) {
        throw err;
      }

      throw new InvalidRequestObject('could not validate Request Object', err.message);
    }

    if (route !== 'pushed_authorization_request' && payload.jti && payload.exp && payload.iss) {
      const unique = await ctx.oidc.provider.ReplayDetection.unique(
        payload.iss, payload.jti, payload.exp,
      );

      if (!unique) {
        throw new InvalidRequestObject(`request replay detected (jti: ${payload.jti})`);
      }
    }
  } else if (client.requireSignedRequestObject) {
    throw new InvalidRequestObject('Request Object must not be unsigned for this client');
  }

  if (pushedRequestObject) {
    await ctx.oidc.entities.PushedAuthorizationRequest.destroy();
  }

  if (trusted || (pushedRequestObject && client.tokenEndpointAuthMethod !== 'none')) {
    ctx.oidc.trusted = Object.keys(request);
  } else if (ctx.oidc.insecureRequestUri) {
    throw new InvalidRequestObject('Request Object from insecure request_uri must be signed and/or symmetrically encrypted');
  }

  params.request = undefined;

  const mode = isBackchannelAuthentication || ctx.oidc.fapiProfile !== undefined ? 'strict' : features.requestObjects.mode;

  switch (mode) {
    case 'lax':
      // use all values from OAuth 2.0 unless they're in the Request Object
      Object.assign(params, request);
      break;
    case 'strict':
      Object.keys(params).forEach((key) => {
        if (key in request) {
          // use value from Request Object
          params[key] = request[key];
        } else {
          // ignore all OAuth 2.0 parameters outside of Request Object
          params[key] = undefined;
        }
      });
      break;
    default:
  }

  return next();
};
