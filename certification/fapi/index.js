/* eslint-disable no-console */

import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as https from 'node:https';
import { promisify } from 'node:util';

import { dirname } from 'desm';
import * as jose from 'jose';
import helmet from 'helmet';
import { generate } from 'selfsigned';

import Provider, { errors } from '../../lib/index.js'; // from 'oidc-provider';
import MemoryAdapter from '../../lib/adapters/memory_adapter.js';
import { stripPrivateJWKFields } from '../../test/keys.js';
import Account from '../../example/support/account.js';

const pkg = JSON.parse(
  readFileSync(path.resolve(dirname(import.meta.url), '../../package.json'), {
    encoding: 'utf-8',
  }),
);

const __dirname = dirname(import.meta.url);
const selfsigned = generate();
const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;

const ALGS = ['PS256'];
const clientAuthMethods = ['private_key_jwt', 'self_signed_tls_client_auth'];

const {
  client: { jwks: { keys: [JWK_ONE] } },
  client2: { jwks: { keys: [JWK_TWO] } },
} = JSON.parse(readFileSync(path.join(__dirname, 'plan.json')));

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

function dPoP(metadata) {
  return {
    ...metadata,
    dpop_bound_access_tokens: true,
  };
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

function jarm(metadata) {
  return {
    ...metadata,
    response_modes: ['jwt'],
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

function fapi2(metadata) {
  return {
    ...metadata,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    require_pushed_authorization_requests: true,
    redirect_uris: ['https://rp.example.com/cb'],
  };
}

const eKey = crypto.randomBytes(32);
const resource = 'urn:example:resource-endpoint';

const adapter = (name) => {
  if (name === 'Client') {
    const memory = new MemoryAdapter(name);
    const orig = MemoryAdapter.prototype.find;
    memory.find = async function find(id) {
      const { 0: version, length, ...rest } = id.split('-');

      if (version === '1.0') {
        const { 1: revision, 2: clientAuth, 3: num } = rest;
        if (length !== 4) {
          return orig.call(this, id);
        }
        let metadata = fapi1({ client_id: id });

        switch (revision) {
          case 'final':
            metadata.profile = '1.0 Final';
            break;
          default:
            return orig.call(this, id);
        }

        let key;
        switch (num) {
          case 'one':
            key = stripPrivateJWKFields(JWK_ONE);
            break;
          case 'two':
            key = stripPrivateJWKFields(JWK_TWO);
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

        return metadata;
      }

      if (version === '2.0') {
        const {
          1: spec, 2: clientAuth, 3: constrain, 4: num,
        } = rest;
        if (length !== 5) {
          return orig.call(this, id);
        }
        let metadata = fapi2({ client_id: id });
        metadata.profile = '2.0';

        switch (spec) {
          case 'securityprofile':
            break;
          case 'messagesigning':
            metadata = jar(metadata);
            metadata = jarm(metadata);
            break;
          default:
            return orig.call(this, id);
        }

        let key;
        switch (num) {
          case 'one':
            key = stripPrivateJWKFields(JWK_ONE);
            break;
          case 'two':
            key = stripPrivateJWKFields(JWK_TWO);
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

        switch (constrain) {
          case 'mtls':
            metadata = mtlsPoP(metadata);
            break;
          case 'dpop':
            metadata = dPoP(metadata);
            break;
          default:
            return orig.call(this, id);
        }

        return metadata;
      }

      return orig.call(this, id);
    };

    return memory;
  }

  if (name === 'AccessToken') {
    const accessTokensAdapter = new MemoryAdapter(name);
    const orig = MemoryAdapter.prototype.find;
    accessTokensAdapter.find = async function find(id) {
      try {
        const verified = await jose.jwtDecrypt(id, eKey, {
          audience: resource,
          issuer: ISSUER,
          typ: 'at+jwt',
        });

        const {
          payload: {
            client_id: clientId,
            sub: accountId,
            aud,
            iss,
            cnf,
            ...payload
          },
        } = verified;

        return {
          ...payload,
          scope: `openid ${payload.scope}`,
          ...cnf,
          clientId,
          accountId,
        };
      } catch {
        return orig.call(this, id);
      }
    };
    return accessTokensAdapter;
  }

  return new MemoryAdapter(name);
};

const fapi = new Provider(ISSUER, {
  acrValues: ['urn:mace:incommon:iap:silver'],
  discovery: {
    service_documentation: pkg.homepage,
    version: [
      pkg.version,
      process.env.HEROKU_SLUG_COMMIT ? process.env.HEROKU_SLUG_COMMIT.slice(0, 7) : undefined,
    ].filter(Boolean).join('-'),
  },
  routes: {
    userinfo: '/accounts',
  },
  findAccount: Account.findAccount,
  async extraTokenClaims(ctx, token) {
    if (token.kind === 'AccessToken' && token.resourceServer?.identifier() === resource) {
      return { grantId: token.grantId };
    }

    return undefined;
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
  claims: {
    address: ['address'],
    email: ['email', 'email_verified'],
    phone: ['phone_number', 'phone_number_verified'],
    profile: ['birthdate', 'family_name', 'gender', 'given_name', 'locale', 'middle_name', 'name',
      'nickname', 'picture', 'preferred_username', 'profile', 'updated_at', 'website', 'zoneinfo'],
  },
  clientDefaults: {
    authorization_signed_response_alg: 'PS256',
    id_token_signed_response_alg: 'PS256',
    request_object_signing_alg: 'PS256',
  },
  features: {
    claimsParameter: {
      enabled: true,
    },
    resourceIndicators: {
      defaultResource(ctx, client, oneOf) {
        if (oneOf) return oneOf;
        return resource;
      },
      useGrantedResource() {
        return true;
      },
      getResourceServerInfo(ctx, resourceIndicator) {
        if (resourceIndicator === resource) {
          return {
            scope: 'openid address email phone profile',
            accessTokenTTL: 2 * 60 * 60, // 2 hours
            accessTokenFormat: 'jwt',
            jwt: {
              sign: false,
              encrypt: {
                alg: 'dir',
                enc: 'A128CBC-HS256',
                key: eKey,
              },
            },
          };
        }
        throw new errors.InvalidTarget();
      },
    },
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
    dPoP: {
      enabled: true,
      nonceSecret: crypto.randomBytes(32),
    },
    mTLS: {
      enabled: true,
      certificateBoundAccessTokens: true,
      selfSignedTlsClientAuth: true,
      getCertificate(ctx) {
        if (process.env.NODE_ENV === 'production') {
          try {
            return new crypto.X509Certificate(Buffer.from(ctx.get('client-certificate'), 'base64'));
          } catch {
            return undefined;
          }
        }

        return ctx.socket.getPeerX509Certificate();
      },
    },
    jwtResponseModes: { enabled: true },
    pushedAuthorizationRequests: { enabled: true },
    requestObjects: {
      enabled: true,
      requireSignedRequestObject: false,
    },
  },
  responseTypes: ['code id_token', 'code'],
  clientAuthMethods,
  enabledJWA: {
    authorizationSigningAlgValues: ALGS,
    idTokenSigningAlgValues: ALGS,
    requestObjectSigningAlgValues: ALGS,
    clientAuthSigningAlgValues: ALGS,
    dPoPSigningAlgValues: ALGS,
    userinfoSigningAlgValues: ALGS,
  },
  extraClientMetadata: {
    properties: ['profile'],
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

const SUITE_ORIGINS = /^https:\/\/.+\.certification\.openid\.net$/;
const LOCAL_SUITE_ORIGINS = new Set([
  'https://localhost:8443',
  'https://localhost.emobix.co.uk:8443',
  'https://localhost.emobix.co.uk',
]);

Object.defineProperty(fapi.Client.prototype, 'redirectUriAllowed', {
  value(url) {
    const parsed = URL.parse(url);
    if (!parsed) return false;
    const { origin, pathname, search } = parsed;

    return (LOCAL_SUITE_ORIGINS.has(origin) || SUITE_ORIGINS.test(origin)) && pathname.endsWith('/callback') && (search === '' || search === '?dummy1=lorem&dummy2=ipsum');
  },
});

const orig = fapi.interactionResult;
fapi.interactionResult = function patchedInteractionResult(...args) {
  if (args[2]?.login) {
    args[2].login.acr = 'urn:mace:incommon:iap:silver'; // eslint-disable-line no-param-reassign
  }

  return orig.call(this, ...args);
};

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
      // eslint-disable-next-line no-restricted-syntax
      for (const indicator of request.params.resource) {
        grant.addResourceScope(indicator, request.params.scope);
      }
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
  ctx.set('x-fapi-interaction-id', ctx.get('x-fapi-interaction-id') || crypto.randomUUID());
  return next();
});

if (process.env.NODE_ENV === 'production') {
  fapi.proxy = true;

  fapi.use(async (ctx, next) => {
    if (ctx.secure) {
      await next();

      switch (ctx.oidc?.route) {
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
