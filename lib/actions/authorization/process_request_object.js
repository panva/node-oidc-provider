import * as JWT from '../../helpers/jwt.js';
import instance from '../../helpers/weak_cache.js';
import { InvalidRequest, InvalidRequestObject, OIDCProviderError } from '../../helpers/errors.js';
import isPlainObject from '../../helpers/_/is_plain_object.js';

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 */
export default async function processRequestObject(PARAM_LIST, rejectDupesMiddleware, ctx, next) {
  const { params, client, route } = ctx.oidc;

  const pushedRequestObject = 'PushedAuthorizationRequest' in ctx.oidc.entities;
  if (client.requirePushedAuthorizationRequests && route !== 'pushed_authorization_request' && !pushedRequestObject) {
    throw new InvalidRequest('Pushed Authorization Request must be used');
  }

  const isBackchannelAuthentication = route === 'backchannel_authentication';
  const { configuration, features } = instance(ctx.oidc.provider);

  if (
    params.request === undefined
    && (
      client.requireSignedRequestObject
      || (client.backchannelAuthenticationRequestSigningAlg && isBackchannelAuthentication)
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

      if (!configuration.requestObjectEncryptionAlgValues.includes(header.alg)) {
        throw new TypeError('unsupported encrypted request alg');
      }
      if (!configuration.requestObjectEncryptionEncValues.includes(header.enc)) {
        throw new TypeError('unsupported encrypted request enc');
      }

      let decrypted;
      if (/^(A|dir$)/.test(header.alg)) {
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
      } else if (key === 'authorization_details' && Array.isArray(value)) {
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

  const original = {};
  for (const param of ['state', 'response_mode', 'response_type']) {
    original[param] = params[param];
    if (request[param] !== undefined) {
      params[param] = request[param];
    }
  }

  if (request.request !== undefined || request.request_uri !== undefined) {
    throw new InvalidRequestObject('Request Object must not contain request or request_uri properties');
  }

  if (
    original.response_type
    && request.response_type !== undefined
    && request.response_type !== original.response_type
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

  if (!pushedRequestObject && !configuration.requestObjectSigningAlgValues.includes(alg)) {
    throw new InvalidRequestObject('unsupported signed request alg');
  }

  const prop = isBackchannelAuthentication ? 'backchannelAuthenticationRequestSigningAlg' : 'requestObjectSigningAlg';
  if (!pushedRequestObject && client[prop] && alg !== client[prop]) {
    throw new InvalidRequestObject('the preregistered alg must be used in request or request_uri');
  }

  const opts = {
    issuer: client.clientId,
    audience: ctx.oidc.issuer,
    clockTolerance: configuration.clockTolerance,
    ignoreAzp: true,
  };

  try {
    JWT.assertPayload(payload, opts);
  } catch (err) {
    throw new InvalidRequestObject('Request Object claims are invalid', err.message);
  }

  await features.requestObjects.assertJwtClaimsAndHeader(
    ctx,
    structuredClone(decoded.payload),
    structuredClone(decoded.header),
    client,
  );

  if (pushedRequestObject) {
    ({ trusted } = pushedRequestObject);
  } else {
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
  }

  if (trusted) {
    ctx.oidc.trusted = Object.keys(request);
  }

  params.request = undefined;

  Object.keys(params).forEach((key) => {
    if (key in request) {
      // use value from Request Object
      params[key] = request[key];
    } else {
      // ignore all OAuth 2.0 parameters outside of Request Object
      params[key] = undefined;
    }
  });

  if (pushedRequestObject && ctx.oidc.entities.PushedAuthorizationRequest.dpopJkt) {
    params.dpop_jkt = ctx.oidc.entities.PushedAuthorizationRequest.dpopJkt;
    ctx.oidc.trusted?.push('dpop_jkt');
  }

  return next();
}
