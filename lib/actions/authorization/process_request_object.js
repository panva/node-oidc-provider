const isPlainObject = require('lodash/isPlainObject');

const JWT = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');
const { InvalidRequest, InvalidRequestObject, OIDCProviderError } = require('../../helpers/errors');

const checkResponseMode = require('./check_response_mode');

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 *
 * @throws: invalid_request_object
 */
module.exports = async function processRequestObject(PARAM_LIST, rejectDupesMiddleware, ctx, next) {
  const { params, client } = ctx.oidc;

  if (
    client.requestObjectSigningAlg
    && params.request === undefined
  ) {
    throw new InvalidRequest('Request Object must be used by this client');
  }

  if (params.request === undefined) {
    return next();
  }

  const { keystore, configuration: conf } = instance(ctx.oidc.provider);
  let trusted = false; // signed or encrypted by client confidential material

  if (conf('features.encryption.enabled') && params.request.split('.').length === 5) {
    try {
      const header = JWT.header(params.request);

      if (!conf('requestObjectEncryptionAlgValues').includes(header.alg)) {
        throw new TypeError('unsupported encrypted request alg');
      }
      if (!conf('requestObjectEncryptionEncValues').includes(header.enc)) {
        throw new TypeError('unsupported encrypted request enc');
      }

      let decrypted;
      if (/^(A|P|dir$)/.test(header.alg)) {
        client.checkClientSecretExpiration('could not decrypt the Request Object - the client secret used for its encryption is expired', 'invalid_request_object');
        decrypted = await JWT.decrypt(params.request, client.keystore);
        trusted = true;
      } else {
        decrypted = await JWT.decrypt(params.request, keystore);
      }

      params.request = decrypted.toString('utf8');
    } catch (err) {
      if (err instanceof OIDCProviderError) {
        throw err;
      }

      throw new InvalidRequestObject(`could not decrypt request object (${err.message})`);
    }
  }

  let decoded;

  try {
    decoded = JWT.decode(params.request);
  } catch (err) {
    throw new InvalidRequestObject(`could not parse Request Object (${err.message})`);
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

  if (request.response_mode !== undefined) {
    params.response_mode = request.response_mode;
    checkResponseMode(ctx, () => {});
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

  if (ctx.oidc.route === 'request_object') {
    if (request.client_id !== ctx.oidc.client.clientId) {
      throw new InvalidRequestObject('request client_id must equal the authenticated client\'s client_id');
    }
  }

  const pushedRequestObject = 'RequestObject' in ctx.oidc.entities;

  if (!(alg === 'none' && (pushedRequestObject || ctx.oidc.route === 'request_object'))) {
    if (client.requestObjectSigningAlg && client.requestObjectSigningAlg !== alg) {
      throw new InvalidRequestObject('the preregistered alg must be used in request or request_uri');
    }

    if (!conf('requestObjectSigningAlgValues').includes(alg)) {
      throw new InvalidRequestObject('unsupported signed request alg');
    }
  }

  const opts = {
    issuer: 'iss' in payload ? client.clientId : undefined,
    audience: 'aud' in payload ? ctx.oidc.issuer : undefined,
    clockTolerance: conf('clockTolerance'),
    ignoreAzp: true,
  };

  if (conf('features.fapiRW.enabled')) {
    if (!('exp' in payload)) {
      throw new InvalidRequestObject('Request Object is missing the "exp" claim');
    }
  }

  try {
    JWT.assertPayload(payload, opts);
  } catch (err) {
    throw new InvalidRequestObject(`Request Object claims are invalid (${err.message})`);
  }

  if (alg !== 'none') {
    try {
      if (alg.startsWith('HS')) {
        client.checkClientSecretExpiration('could not validate the Request Object - the client secret used for its signature is expired', 'invalid_request_object');
      }
      await JWT.verify(params.request, client.keystore, opts);
      trusted = true;
    } catch (err) {
      if (err instanceof OIDCProviderError) {
        throw err;
      }

      throw new InvalidRequestObject(`could not validate Request Object (${err.message})`);
    }

    if (ctx.oidc.route !== 'request_object' && payload.jti && payload.exp && payload.iss) {
      const unique = await ctx.oidc.provider.ReplayDetection.unique(
        payload.iss, payload.jti, payload.exp,
      );

      if (!unique) {
        throw new InvalidRequestObject(`request replay detected (jti: ${payload.jti})`);
      }
    }
  }

  if (pushedRequestObject) {
    await ctx.oidc.entities.RequestObject.destroy();
  }

  if (trusted || (pushedRequestObject && client.tokenEndpointAuthMethod !== 'none')) {
    ctx.oidc.signed = Object.keys(request); // TODO: in v7.x rename to "trusted"
  } else if (ctx.oidc.insecureRequestUri) {
    throw new InvalidRequestObject('Request Object from insecure request_uri must be signed and/or symmetrically encrypted');
  }

  params.request = undefined;

  switch (conf('features.requestObjects.mergingStrategy.name')) {
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
    case 'whitelist': {
      const whitelist = conf('features.requestObjects.mergingStrategy.whitelist');
      Object.keys(params).forEach((key) => {
        if (key in request) {
          // use value from Request Object
          params[key] = request[key];
        } else if (!whitelist.has(key)) {
          // ignore OAuth 2.0 parameters outside of Request Object unless whitelisted
          params[key] = undefined;
        }
      });
      break;
    }
    default:
  }

  return next();
};
