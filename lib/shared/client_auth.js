import { noVSCHAR } from '../consts/client_attributes.js';
import appendWWWAuthenticate from '../helpers/append_www_authenticate.js';
import certificateThumbprint from '../helpers/certificate_thumbprint.js';
import { boolean } from '../helpers/configuration_result.js';
import { InvalidClientAuth, InvalidRequest } from '../helpers/errors.js';
import * as JWT from '../helpers/jwt.js';
import instance from '../helpers/weak_cache.js';
import attestClientAuth, { validateClientAttestationJwtAndPop } from './attest_client_auth.js';
import jwtClientAuth from './jwt_client_auth.js';
import rejectDupes from './reject_dupes.js';

const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

function isValidBase64(input) {
  const match = /^([A-Za-z0-9+/]*)(={0,2})$/u.exec(input);
  if (!match?.[1]) {
    return false;
  }

  const remainder = match[1].length % 4;
  if (!match[2]) {
    return remainder !== 1;
  }

  return (match[1].length + match[2].length) % 4 === 0
    && match[2].length === 4 - remainder;
}

// see https://www.rfc-editor.org/info/rfc6749/#appendix-B
function decodeAuthToken(token) {
  const authToken = decodeURIComponent(token.replace(/\+/g, '%20'));
  if (noVSCHAR.test(authToken)) {
    throw new Error('invalid character found');
  }
  return authToken;
}

export function getClientAuthParams(ctx) {
  const authParams = new Set(['client_id']);
  const { clientAuthMethods } = instance(ctx.oidc.provider).configuration;

  clientAuthMethods.forEach((method) => {
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

  return authParams;
}

function rejectClientAuthDupes(ctx, next) {
  return rejectDupes({ only: getClientAuthParams(ctx) }, ctx, next);
}

async function setWWWAuthenticateHeader(ctx, next) {
  try {
    await next();
  } catch (err) {
    if (err.statusCode === 401 && ctx.headers.authorization !== undefined) {
      appendWWWAuthenticate(ctx, 'Basic', {
        realm: ctx.oidc.provider.issuer,
        error: err.message,
        error_description: err.error_description,
      });
    }
    throw err;
  }
}

async function authenticateClient(ctx, next) {
  const { provider } = ctx.oidc;
  const { features } = instance(provider);
  let methods;
  let clientId;
  let clientSecret;

  const setClientId = (value) => {
    if (clientId !== undefined && value !== clientId) {
      throw new InvalidRequest('client_id mismatch');
    }
    clientId = value;
  };

  const hasAttestation = ctx.headers['oauth-client-attestation'] !== undefined;
  const hasAttestationPop = ctx.headers['oauth-client-attestation-pop'] !== undefined;
  const { additionalSecuritySignal } = features.attestClientAuth;
  const { length } = [
    ctx.headers.authorization,
    ctx.oidc.params.client_assertion,
    ctx.oidc.params.client_secret,
  ].filter(Boolean);

  if (length > 1) {
    throw new InvalidRequest('client authentication must only be provided using one mechanism');
  }

  if (length && (hasAttestation || hasAttestationPop) && !additionalSecuritySignal) {
    throw new InvalidRequest('client authentication must only be provided using one mechanism');
  }

  if (ctx.oidc.params.client_id !== undefined) {
    setClientId(ctx.oidc.params.client_id);
  }

  if (ctx.oidc.params.client_secret) {
    clientSecret = ctx.oidc.params.client_secret;
    methods = ['client_secret_basic', 'client_secret_post'];
  } else if (ctx.headers.authorization !== undefined) {
    const parts = ctx.headers.authorization.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'basic') {
      throw new InvalidRequest('invalid authorization header value format');
    }

    if (!isValidBase64(parts[1])) {
      throw new InvalidRequest('invalid authorization header value format');
    }

    const basic = Buffer.from(parts[1], 'base64').toString('utf8');
    const i = basic.indexOf(':');

    if (i === -1) {
      throw new InvalidRequest('invalid authorization header value format');
    }

    let basicClientId;
    try {
      basicClientId = decodeAuthToken(basic.slice(0, i));
      clientSecret = decodeAuthToken(basic.slice(i + 1));
    } catch (cause) {
      throw new InvalidRequest(
        'client_id and client_secret in the authorization header are not properly encoded',
        undefined,
        { cause },
      );
    }

    setClientId(basicClientId);

    if (!clientSecret) {
      throw new InvalidRequest('client_secret must be provided in the Authorization header');
    }

    methods = ['client_secret_basic', 'client_secret_post'];
  } else if (hasAttestation && (!clientId || !additionalSecuritySignal)) {
    let sub;
    try {
      ({ sub } = JWT.payload(ctx.headers['oauth-client-attestation']));
    } catch (cause) {
      throw new InvalidRequest(
        'invalid OAuth-Client-Attestation format',
        undefined,
        { cause },
      );
    }

    if (!sub) {
      throw new InvalidClientAuth('sub (JWT subject) must be provided in the OAuth-Client-Attestation JWT');
    }

    setClientId(sub);
    methods = ['attest_jwt_client_auth'];
  } else if (ctx.oidc.params.client_assertion !== undefined) {
    let sub;
    try {
      ({ sub } = JWT.payload(ctx.oidc.params.client_assertion));
    } catch (cause) {
      throw new InvalidRequest('invalid client_assertion format', undefined, { cause });
    }

    if (!sub) {
      throw new InvalidClientAuth('sub (JWT subject) must be provided in the client_assertion JWT');
    }

    if (ctx.oidc.params.client_assertion_type === undefined) {
      throw new InvalidRequest('client_assertion_type must be provided');
    }

    if (ctx.oidc.params.client_assertion_type !== assertionType) {
      throw new InvalidRequest(`client_assertion_type must have value ${assertionType}`);
    }

    setClientId(sub);
    methods = ['client_secret_jwt', 'private_key_jwt'];
  } else {
    methods = ['none', 'tls_client_auth', 'self_signed_tls_client_auth'];
    if (hasAttestation && additionalSecuritySignal) {
      methods.push('attest_jwt_client_auth');
    }
  }

  if (!clientId) {
    throw new InvalidRequest('no client authentication mechanism provided');
  }

  const client = await provider.Client.find(clientId);

  if (!client) {
    throw new InvalidClientAuth('client not found');
  }

  ctx.oidc.entity('Client', client);

  if (
    (hasAttestation || hasAttestationPop)
    && !additionalSecuritySignal
    && ctx.oidc.params.client_id !== undefined
    && ctx.oidc.client.clientAuthMethod !== 'attest_jwt_client_auth'
  ) {
    throw new InvalidRequest('client authentication must only be provided using one mechanism');
  }

  if (methods?.includes(ctx.oidc.client.clientAuthMethod) !== true) {
    throw new InvalidClientAuth('the provided authentication mechanism does not match the registered client authentication method');
  }

  switch (ctx.oidc.client.clientAuthMethod) {
    case 'none':
      break;

    case 'client_secret_basic':
    case 'client_secret_post': {
      ctx.oidc.client.checkClientSecretExpiration('could not authenticate the client - its client secret is expired');
      const matches = await ctx.oidc.client.compareClientSecret(clientSecret);
      if (!matches) {
        throw new InvalidClientAuth('invalid secret provided');
      }

      break;
    }

    case 'client_secret_jwt':
      ctx.oidc.client.checkClientSecretExpiration('could not authenticate the client - its client secret used for the client_assertion is expired');
      await jwtClientAuth(ctx, ctx.oidc.client.symmetricKeyStore, (alg) => alg.startsWith('HS'));

      break;

    case 'private_key_jwt':
      await jwtClientAuth(ctx, ctx.oidc.client.asymmetricKeyStore, (alg) => !alg.startsWith('HS'));

      break;

    case 'tls_client_auth': {
      const {
        getCertificate, certificateAuthorized, certificateSubjectMatches,
      } = features.mTLS;

      const cert = getCertificate(ctx);

      if (!cert) {
        throw new InvalidClientAuth('client certificate was not provided');
      }

      if (!boolean(
        certificateAuthorized(ctx),
        'features.mTLS.certificateAuthorized',
      )) {
        throw new InvalidClientAuth('client certificate was not verified');
      }

      for (const [prop, key] of Object.entries({
        tlsClientAuthSubjectDn: 'tls_client_auth_subject_dn',
        tlsClientAuthSanDns: 'tls_client_auth_san_dns',
        tlsClientAuthSanIp: 'tls_client_auth_san_ip',
        tlsClientAuthSanEmail: 'tls_client_auth_san_email',
        tlsClientAuthSanUri: 'tls_client_auth_san_uri',
      })) {
        const value = ctx.oidc.client[prop];
        if (value) {
          if (!boolean(
            certificateSubjectMatches(ctx, key, value),
            'features.mTLS.certificateSubjectMatches',
          )) {
            throw new InvalidClientAuth('certificate subject value does not match the registered one');
          }
          break;
        }
      }

      break;
    }
    case 'self_signed_tls_client_auth': {
      const { getCertificate } = features.mTLS;
      const cert = getCertificate(ctx);

      if (!cert) {
        throw new InvalidClientAuth('client certificate was not provided');
      }

      await ctx.oidc.client.asymmetricKeyStore.refresh();
      const expected = certificateThumbprint(cert);
      const match = [...ctx.oidc.client.asymmetricKeyStore].find(({ 'x5t#S256': actual }) => actual === expected);

      if (!match) {
        throw new InvalidClientAuth('unregistered client certificate provided');
      }

      break;
    }
    case 'attest_jwt_client_auth': {
      await attestClientAuth(ctx);

      break;
    }
  }

  if (
    ctx.oidc.client.clientAuthMethod !== 'attest_jwt_client_auth'
    && (
      additionalSecuritySignal === 'required'
      || (additionalSecuritySignal === 'optional' && (hasAttestation || hasAttestationPop))
    )
  ) {
    await validateClientAttestationJwtAndPop(ctx, { signal: true });
  }

  await next();
}

export default [rejectClientAuthDupes, setWWWAuthenticateHeader, authenticateClient];
