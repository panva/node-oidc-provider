/* eslint-disable no-console */

const { readFileSync } = require('fs');
const path = require('path');
const { randomBytes, randomUUID } = require('crypto');
const https = require('https');
const { promisify } = require('util');
const { URL } = require('url');

const jose = require('jose2');
const helmet = require('helmet');
const selfsigned = require('selfsigned').generate();

const { Provider, errors } = require('../../lib'); // require('oidc-provider');
const MemoryAdapter = require('../../lib/adapters/memory_adapter');

const OFFICIAL_CERTIFICATION = 'https://www.certification.openid.net';
const { PORT = 3000, ISSUER = `http://localhost:${PORT}`, SUITE_BASE_URL = OFFICIAL_CERTIFICATION } = process.env;

const ALGS = ['PS256'];
const tokenEndpointAuthMethods = ['private_key_jwt', 'self_signed_tls_client_auth'];

const normalize = (cert) => cert.toString().replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, '');

const JWK_ONE = jose.JWK.asKey(readFileSync(path.join(__dirname, 'one.key')), { x5c: [normalize(readFileSync(path.join(__dirname, 'one.crt')))], alg: 'PS256', use: 'sig' }).toJWK();
const JWK_TWO = jose.JWK.asKey(readFileSync(path.join(__dirname, 'two.key')), { x5c: [normalize(readFileSync(path.join(__dirname, 'two.crt')))], alg: 'PS256', use: 'sig' }).toJWK();

function jwk(metadata, key) {
  return {
    ...metadata,
    jwks: { keys: [key] },
  };
}

function pkjwt(metadata, key) {
  return jwk({
    ...metadata,
    token_endpoint_auth_method: 'private_key_jwt',
  }, key);
}

function mtlsAuth(metadata, key) {
  return jwk({
    ...metadata,
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
  }, key);
}

function mtlsPoP(metadata) {
  return {
    ...metadata,
    tls_client_certificate_bound_access_tokens: true,
  };
}

function jar(metadata) {
  return {
    ...metadata,
    require_signed_request_object: true,
  };
}

function fapi1(metadata) {
  return mtlsPoP(jar({
    ...metadata,
    default_acr_values: ['urn:mace:incommon:iap:silver'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    response_types: ['code', 'code id_token'],
    redirect_uris: ['https://rp.example.com/cb'],
  }));
}

const adapter = (name) => {
  if (name === 'Client') {
    const memory = new MemoryAdapter(name);
    const orig = MemoryAdapter.prototype.find;
    memory.find = async function find(id) {
      const [version, ...rest] = id.split('-');

      let metadata = {
        cacheBuster: randomUUID(),
      };

      if (version === '1.0') {
        const [tag, clientAuth, num, ...empty] = rest;
        if (empty.length !== 0) {
          return orig.call(this, id);
        }
        metadata = fapi1(metadata);

        switch (tag) {
          case 'final':
            metadata.profile = '1.0 Final';
            break;
          case 'id2':
            metadata.profile = '1.0 ID2';
            break;
          default:
            return orig.call(this, id);
        }

        let key;
        switch (num) {
          case 'one':
            key = JWK_ONE;
            break;
          case 'two':
            key = JWK_TWO;
            break;
          default:
            return orig.call(this, id);
        }

        switch (clientAuth) {
          case 'mtls':
            metadata = mtlsAuth(metadata, key);
            break;
          case 'pkjwt':
            metadata = pkjwt(metadata, key);
            break;
          default:
            return orig.call(this, id);
        }

        metadata.client_id = id;
        return metadata;
      }

      return orig.call(this, id);
    };

    return memory;
  }

  return new MemoryAdapter(name);
};

const fapi = new Provider(ISSUER, {
  acrValues: ['urn:mace:incommon:iap:silver'],
  routes: {
    userinfo: '/accounts',
  },
  adapter,
  jwks: {
    keys: [
      {
        alg: 'PS256',
        d: 'dxzWeLBYGwOgNb-S-4RCDxz7U6lUPPZaIkrbmkpLsdDdZOkMXGg_jk2LIJ3tYgAvZkWm87ZQqKjN2ADzJmpHvu-vCLuh8ccpwaiTXfWTOjjii0-Cfq0-fT6aQpIglbwubVKi1Tqxz-AglrMnCkNICm-e0GsotXFskxhwybp8IAZP__Up1pg-G9Dg_Timtepw55HjO4xDhzY70zV2NqSDEIvKOleyIZj4JP5kCkwP4_FJw_KynXwlxKvCshtFC3U2IEWWUaUQmM8Yy1Hz2x3TqImLQTWs3EMm6oRuhS0Y4tg9VlzJqnetdd6Ulh-DFzSB37KnBZS1qvnGGG4Cri9IkQ',
        dp: 'tc9sHeUoX1V1cedHpn0VUNiFwCSRTIn6IMzaSRS4f3IUMbLUHv6Ybt9MRco3hBRV1PrJv8K2YPWzZnNIoFF6gILIIsmz1EJX36lcHtIme0GLAt3BFNm_ofmxA6pLPawtDvo_uFpTBm-Z2frq-BSGeDGh5_Tr1cdlS1RT70RJzbk',
        dq: 'FXlVWUgfSZ3HDqkuqcTGrFq4DPsPFOHEmnkUpT9TRFTXddWqSQe4IZvoWpidxORHD7a0-8x_DhXA40zLVZ42dOa8O7QUEweC9JQEY7DnD6ORZvbALc55CKBDrE52C9y5sk2FM2mWU2YudqDwt2SMZn3vGFTjygQ_P0EBFI08e80',
        e: 'AQAB',
        kty: 'RSA',
        n: 'sUQ6a7yX-qCAIgqYl_pzn2yK5RsPb5zjxMG1v2bvlvf6l6LyvJkxEr4dWLAbn9WAV72GuyMkvWfVi13fu4cYl2vdkIFBt0JGT40QxkMUp0izHs4RiLK1GTrwJ2qX7H67EaNNWFeE9Yqh3sIRyQgHqQf6L9rZFWBSED-M3OaiwH-zdwrMzjQH6wCEjmuyTFiNLO2QI6Yr7dDl1rPjWvN9d8pHHWxkRMAnQrL5_mfvOD_j1Tr5blXYTMHHpThOHVM2Ibe4_5YDmPaRXFMgQrPjz6mlUa9d1EL7CuxLd19S3A_6XEMB2juo0RRCfaHK7ZORPJKa36qrVZVhXK3Geuqorw',
        p: '5SLM2g4Uv3Q1-PGqwKPQ8h8Onp674FTxxYAHCh8mivgCGx7uIjVaOxCKvCimi8NCgtON0a1QdGY-BT3NsewJUvaniWyb5BZo-kpdkSzXCvQpWuWT_iSorgEgl4anJ59JZH_QW7wtjRnF8jWnw-_nkNv4HIIVd7fdKKCkpGi1Drk',
        q: 'xgyjgfZdlfpne27vdlxi5VGmNnBnLRAe_a7Wgo6JdmKPMPa1qugxVM5tUhoYjUuUpHxi8gDSxb0-N_kIqTu7zp2Ly9iB8wQIyyYmdxN7J_B5bSn5rfTcu_Uz-EuYVEGfj0hk5_aNQc0y02Di1L4QrnMNRGBo3jWCCRZrjqyHfqc',
        qi: 'nmJaonUO_d62824V6YmWuEX7imXdgHKRi-tY4IUDJbrm7lKEfcn_xazqilECh1xm7O8b4bj0th3JrRcs1Al0sWP1FwVHjzzmg5oqq26PvHjmtVIHn3cXGT6AmY8-eUPkYgPBc61Ej58Usazm1iuRIe-wNIBeL244kFTQK7zJfnE',
        use: 'sig',
      },
    ],
  },
  scopes: ['openid', 'offline_access'],
  clientDefaults: {
    authorization_signed_response_alg: 'PS256',
    id_token_signed_response_alg: 'PS256',
    request_object_signing_alg: 'PS256',
  },
  clockTolerance: 5,
  features: {
    ciba: {
      enabled: true,
      processLoginHint(ctx, loginHint) {
        return loginHint;
      },
      verifyUserCode() {},
      validateRequestContext() {},
      triggerAuthenticationDevice() {},
      deliveryModes: ['poll', 'ping'],
    },
    registration: { enabled: true },
    registrationManagement: { enabled: true },
    fapi: {
      enabled: true,
      profile(ctx, client) {
        if (!client?.profile) {
          if (client.grantTypes.includes('urn:openid:params:grant-type:ciba')) {
            return '1.0 Final';
          }
          throw new Error('could not determine FAPI profile');
        }

        return client.profile;
      },
    },
    mTLS: {
      enabled: true,
      certificateBoundAccessTokens: true,
      selfSignedTlsClientAuth: true,
      getCertificate(ctx) {
        if (SUITE_BASE_URL === OFFICIAL_CERTIFICATION) {
          return ctx.get('client-certificate');
        }

        const peerCertificate = ctx.socket.getPeerCertificate();
        if (peerCertificate.raw) {
          return `-----BEGIN CERTIFICATE-----\n${peerCertificate.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
        }
        return undefined;
      },
    },
    jwtResponseModes: { enabled: true },
    pushedAuthorizationRequests: { enabled: true },
    requestObjects: {
      request: true,
      requestUri: false,
      requireSignedRequestObject: false,
      mode: 'strict',
    },
  },
  responseTypes: ['code id_token', 'code'],
  tokenEndpointAuthMethods,
  enabledJWA: {
    authorizationSigningAlgValues: ALGS,
    idTokenSigningAlgValues: ALGS,
    requestObjectSigningAlgValues: ALGS,
    tokenEndpointAuthSigningAlgValues: ALGS,
    userinfoSigningAlgValues: ALGS,
  },
  extraClientMetadata: {
    properties: ['profile'],
  },
  pkce: {
    required: () => false,
  },
});

const clientJwtAuthExpectedAudience = Object.getOwnPropertyDescriptor(fapi.OIDCContext.prototype, 'clientJwtAuthExpectedAudience').value;
Object.defineProperty(fapi.OIDCContext.prototype, 'clientJwtAuthExpectedAudience', {
  value() {
    const acceptedAudiences = clientJwtAuthExpectedAudience.call(this);
    acceptedAudiences.add(this.ctx.href);
    return acceptedAudiences;
  },
});

Object.defineProperty(fapi.Client.prototype, 'redirectUriAllowed', {
  value(url) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (err) {
      return false;
    }

    return parsed.origin === SUITE_BASE_URL && parsed.pathname.endsWith('/callback') && (parsed.search === '' || parsed.search === '?dummy1=lorem&dummy2=ipsum');
  },
});

const orig = fapi.interactionResult;
fapi.interactionResult = function patchedInteractionResult(...args) {
  if (args[2] && args[2].login) {
    args[2].login.acr = 'urn:mace:incommon:iap:silver'; // eslint-disable-line no-param-reassign
  }

  return orig.call(this, ...args);
};

function uuid(e){return e?(e^randomBytes(1)[0]%16>>e/4).toString(16):([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,uuid)} // eslint-disable-line

const directives = helmet.contentSecurityPolicy.getDefaultDirectives();
delete directives['form-action'];
const pHelmet = promisify(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives,
  },
}));

fapi.use(async (ctx, next) => {
  if (ctx.path === '/ciba-sim') {
    const { authReqId, action } = ctx.query;

    const request = await fapi.BackchannelAuthenticationRequest.find(authReqId);

    if (action === 'allow') {
      const client = await fapi.Client.find(request.clientId);
      const grant = new fapi.Grant({
        client,
        accountId: request.accountId,
      });
      grant.addOIDCScope(request.scope);
      let claims = [];
      if (request.claims.id_token) {
        claims = claims.concat(Object.keys(request.claims.id_token));
      }
      if (request.claims.userinfo) {
        claims = claims.concat(Object.keys(request.claims.userinfo));
      }
      grant.addOIDCClaims(claims);
      await grant.save();
      await fapi.backchannelResult(request, grant, { acr: 'urn:mace:incommon:iap:silver' }).catch(() => {});
    } else {
      await fapi.backchannelResult(request, new errors.AccessDenied('end-user cancelled request')).catch(() => {});
    }

    ctx.body = { done: true };
    return undefined;
  }

  return next();
});

fapi.use(async (ctx, next) => {
  const origSecure = ctx.req.secure;
  ctx.req.secure = ctx.request.secure;
  await pHelmet(ctx.req, ctx.res);
  ctx.req.secure = origSecure;
  return next();
});
fapi.use((ctx, next) => {
  if (!('x-fapi-interaction-id' in ctx.headers)) {
    ctx.headers['x-fapi-interaction-id'] = uuid();
  }
  return next();
});

if (process.env.NODE_ENV === 'production') {
  fapi.proxy = true;

  fapi.use(async (ctx, next) => {
    if (ctx.secure) {
      await next();

      switch (ctx.oidc && ctx.oidc.route) {
        case 'discovery': {
          ['token', 'userinfo', 'pushed_authorization_request', 'backchannel_authentication'].forEach((endpoint) => {
            if (ctx.body[`${endpoint}_endpoint`].startsWith(ISSUER)) {
              ctx.body[`${endpoint}_endpoint`] = ctx.body[`${endpoint}_endpoint`].replace('https://', 'https://mtls.');
            }
          });
          break;
        }
        default:
      }
    } else if (ctx.method === 'GET' || ctx.method === 'HEAD') {
      ctx.status = 303;
      ctx.redirect(ctx.href.replace(/^http:\/\//i, 'https://'));
    } else {
      ctx.body = {
        error: 'invalid_request',
        error_description: 'do yourself a favor and only use https',
      };
      ctx.status = 400;
    }
  });
}

if (SUITE_BASE_URL === OFFICIAL_CERTIFICATION) {
  fapi.listen(PORT);
} else {
  const server = https.createServer({
    requestCert: true,
    rejectUnauthorized: false,
    key: selfsigned.private,
    cert: selfsigned.cert,
  }, fapi.callback());

  server.listen(PORT, () => {
    console.log(`application is listening on port ${PORT}, check its /.well-known/openid-configuration`);
    process.on('SIGINT', () => {
      process.exit(0);
    });
  });
}
