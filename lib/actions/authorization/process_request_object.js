import * as JWT from '../../helpers/jwt.js';
import instance from '../../helpers/weak_cache.js';
import { InvalidRequest, InvalidRequestObject, OIDCProviderError } from '../../helpers/errors.js';
import isPlainObject from '../../helpers/_/is_plain_object.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import epochTime from '../../helpers/epoch_time.js';

import checkResponseMode from './check_response_mode.js';

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 *
 * @throws: invalid_request_object
 */
export default async function processRequestObject(PARAM_LIST, rejectDupesMiddleware, ctx, next) {
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

  const isFapi1 = ctx.oidc.isFapi('1.0 Final', '1.0 ID2');
  if (request.response_mode !== undefined || isFapi1) {
    if (request.response_mode !== undefined) {
      params.response_mode = request.response_mode;
    }
    if (request.response_type !== undefined) {
      params.response_type = request.response_type;
    }
    checkResponseMode(ctx, () => {}, isFapi1);
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

  if (!pushedRequestObject && !conf.requestObjectSigningAlgValues.includes(alg)) {
    throw new InvalidRequestObject('unsupported signed request alg');
  }

  const prop = isBackchannelAuthentication ? 'backchannelAuthenticationRequestSigningAlg' : 'requestObjectSigningAlg';
  if (!pushedRequestObject && client[prop] && alg !== client[prop]) {
    throw new InvalidRequestObject('the preregistered alg must be used in request or request_uri');
  }

  const opts = {
    issuer: client.clientId,
    audience: ctx.oidc.issuer,
    clockTolerance: conf.clockTolerance,
    ignoreAzp: true,
  };

  const fapiProfile = ctx.oidc.isFapi('1.0 Final', '1.0 ID2');
  if (fapiProfile) {
    if (!('exp' in payload)) {
      throw new InvalidRequestObject("Request Object is missing the 'exp' claim");
    }

    if (fapiProfile === '1.0 Final') {
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
    for (const claim of ['exp', 'iat', 'nbf', 'jti']) {
      if (!(claim in payload)) {
        throw new InvalidRequestObject(`Request Object is missing the '${claim}' claim`);
      }
    }

    if (fapiProfile) {
      const diff = payload.exp - payload.nbf;
      if (Math.sign(diff) !== 1 || diff > 3600) {
        throw new InvalidRequestObject("Request Object 'exp' claim too far from 'nbf' claim");
      }
    }
  }

  try {
    JWT.assertPayload(payload, opts);
  } catch (err) {
    throw new InvalidRequestObject('Request Object claims are invalid', err.message);
  }

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

  if (!pushedRequestObject && payload.jti && payload.exp && payload.iss) {
    if (route === 'pushed_authorization_request') {
      const dPoP = await dpopValidate(ctx);
      if (dPoP) {
        const { ReplayDetection } = ctx.oidc.provider;
        const unique = await ReplayDetection.unique(
          ctx.oidc.client.clientId,
          dPoP.jti,
          epochTime() + 300,
        );

        ctx.assert(unique, new InvalidRequest('DPoP proof JWT Replay detected'));
      }
    }
    const unique = await ctx.oidc.provider.ReplayDetection.unique(
      payload.iss,
      payload.jti,
      payload.exp + conf.clockTolerance,
    );

    if (!unique) {
      throw new InvalidRequestObject('request object replay detected');
    }
  }

  if (trusted) {
    ctx.oidc.trusted = Object.keys(request);
  } else if (ctx.oidc.insecureRequestUri) {
    throw new InvalidRequestObject('Request Object from insecure request_uri must be signed and/or symmetrically encrypted');
  }

  params.request = undefined;

  const mode = isBackchannelAuthentication || fapiProfile ? 'strict' : features.requestObjects.mode;

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

  if (pushedRequestObject && ctx.oidc.entities.PushedAuthorizationRequest.dpopJkt) {
    params.dpop_jkt = ctx.oidc.entities.PushedAuthorizationRequest.dpopJkt;
    ctx.oidc.trusted?.push('dpop_jkt');
  }

  return next();
}
