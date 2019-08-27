const isPlainObject = require('lodash/isPlainObject');

const JWT = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');
const { InvalidRequest, InvalidRequestObject } = require('../../helpers/errors');

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
        decrypted = await JWT.decrypt(params.request, client.keystore);
        trusted = true;
      } else {
        decrypted = await JWT.decrypt(params.request, keystore);
      }

      params.request = decrypted.toString('utf8');
    } catch (err) {
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

  if (client.requestObjectSigningAlg && client.requestObjectSigningAlg !== alg) {
    throw new InvalidRequestObject('the preregistered alg must be used in request or request_uri');
  }

  if (!conf('requestObjectSigningAlgValues').includes(alg)) {
    throw new InvalidRequestObject('unsupported signed request alg');
  }

  const opts = {
    issuer: payload.iss ? client.clientId : undefined,
    audience: payload.aud ? ctx.oidc.issuer : undefined,
    clockTolerance: conf('clockTolerance'),
    ignoreAzp: true,
  };

  if (conf('features.fapiRW.enabled')) {
    if (!('exp' in payload)) {
      throw new InvalidRequestObject('Request Object is missing the "exp" claim');
    }

    const missing = Object.entries(ctx.oidc.params)
      .filter(([key, value]) => {
        if (key === 'request' || key === 'request_uri' || value === undefined) {
          return false;
        }

        return true;
      }).map(([key]) => {
        if (!(key in payload)) {
          return key;
        }

        return undefined;
      }).filter(Boolean);

    if (missing.length) {
      throw new InvalidRequestObject(`all parameters shall be present inside the signed Request Object (missing: ${missing.join(', ')})`);
    }
  }

  try {
    JWT.assertPayload(payload, opts);
  } catch (err) {
    throw new InvalidRequestObject(`Request Object claims are invalid (${err.message})`);
  }

  if (alg !== 'none') {
    try {
      await JWT.verify(params.request, client.keystore, opts);
      trusted = true;
    } catch (err) {
      throw new InvalidRequestObject(`could not validate Request Object (${err.message})`);
    }

    if (payload.jti && payload.exp && payload.iss) {
      const unique = await ctx.oidc.provider.ReplayDetection.unique(
        payload.iss, payload.jti, payload.exp,
      );

      if (!unique) {
        throw new InvalidRequestObject(`request replay detected (jti: ${payload.jti})`);
      }
    }
  }

  if (trusted) {
    ctx.oidc.signed = Object.keys(request);
  } else if (ctx.oidc.insecureRequestUri) {
    throw new InvalidRequestObject('Request Object from unsecure request_uri must be signed and/or symmetrically encrypted');
  }

  Object.assign(params, request);

  params.request = undefined;

  return next();
};
