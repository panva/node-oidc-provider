import { Provider, interactionPolicy, AsymmetricSigningAlgorithm } from './index.d';

new Provider('https://op.example.com');

new Provider('https://op.example.com', {
  rotateRefreshToken: true,
  formats: {
    jwtAccessTokenSigningAlg() {
      return 'ES384';
    },
    customizers: {
      async jwt(ctx, token, parts) {
        ctx.oidc.issuer.substring(0);
        token.iat.toFixed();
        parts.header = { foo: 'bar' };
        parts.payload.foo = 'bar';
        return parts;
      },
      async 'jwt-ietf'(ctx, token, parts) {
        ctx.oidc.issuer.substring(0);
        token.iat.toFixed();
        parts.header = { foo: 'bar' };
        parts.payload.foo = 'bar';
        return parts;
      },
      async paseto(ctx, token, parts) {
        ctx.oidc.issuer.substring(0);
        token.iat.toFixed();
        parts.footer = { foo: 'bar' };
        parts.footer = Buffer.from('foo');
        parts.footer = undefined;
        parts.footer = 'foo';
        parts.payload.foo = 'bar';
        return parts;
      },
    },
  },
});

new Provider('https://op.example.com', {
  adapter: class Adapter {
    name: string;
    constructor(name: string) {
      this.name = name;
    }

    async upsert(id: string, payload: object, expiresIn: number) {}
    async consume(id: string) {}
    async destroy(id: string) {}
    async revokeByGrantId(grantId: string) {}

    async find(id: string) {
      return {
        client_id: '...',
      };
    }

    async findByUserCode(userCode: string) {}
    async findByUid(uid: string) {}
  }
});

new Provider('https://op.example.com', {
  adapter: (name: string) => ({
    name,
    async upsert(id: string, payload: object, expiresIn: number) {},
    async consume(id: string) {},
    async destroy(id: string) {},
    async revokeByGrantId(grantId: string) {},

    async find(id: string) {
      return {
        client_id: '...',
      };
    },
    async findByUserCode(userCode: string) {},
    async findByUid(uid: string) {},
  })
});

const provider = new Provider('https://op.example.com', {
  acrValues: ['urn:example:bronze'],
  adapter: class Adapter {
    name: string;
    constructor(name: string) {
      this.name = name;
    }

    async upsert(id: string, payload: object, expiresIn: number) {}
    async consume(id: string) {}
    async destroy(id: string) {}
    async revokeByGrantId(grantId: string) {}

    async find(id: string) {
      return {
        consumed: false
      };
    }
    async findByUserCode(userCode: string) {
      return {
        consumed: false
      };
    }
    async findByUid(uid: string) {
      return {
        consumed: false
      };
    }
  },
  claims: {
    acr: null, foo: null, bar: ['bar'],
  },
  clientBasedCORS(ctx, origin, client) {
    ctx.oidc.issuer.substring(0);
    client.clientId.substring(0);
    origin.substring(0);
    return true;
  },
  clients: [
    {
      client_id: 'foo',
      token_endpoint_auth_method: 'none',
      redirect_uris: ['https://rp.example.com/cb'],
    }
  ],
  clientDefaults: {
    foo: 'bar',
    id_token_signed_response_alg: 'EdDSA',
    token_endpoint_auth_signing_alg: 'ES384',
  },
  clockTolerance: 60,
  conformIdTokenClaims: true,
  cookies: {
    names: {
      session: '_foo',
    },
    long: {
      sameSite: 'none',
      secure: true,
    },
    short: {
      httpOnly: true,
      sameSite: 'lax',
    },
    keys: [
      'foo',
      Buffer.from('bar'),
    ],
  },
  discovery: {
    foo: 'bar',
    bar: [123],
    baz: {
      foo: 'bar',
    },
  },
  extraParams: ['foo', 'bar', 'baz'],
  async extraAccessTokenClaims(ctx, token) {
    ctx.oidc.issuer.substring(0);
    token.jti.substring(0);

    return { foo: 'bar' };
  },
  formats: {
    AccessToken: 'paseto',
    ClientCredentials(ctx, clientCredentials) {
      ctx.oidc.issuer.substring(0);
      clientCredentials.iat.toFixed();
      return 'opaque';
    },
    async jwtAccessTokenSigningAlg(ctx, token, client): Promise<AsymmetricSigningAlgorithm> {
      ctx.oidc.issuer.substring(0);
      token.iat.toFixed();
      client.clientId.substring(0);
      return 'ES384';
    },
    customizers: {
      jwt(ctx, token, parts) {
        ctx.oidc.issuer.substring(0);
        token.iat.toFixed();
        parts.header = { foo: 'bar' };
        parts.payload.foo = 'bar';
        return parts;
      },
      'jwt-ietf'(ctx, token, parts) {
        ctx.oidc.issuer.substring(0);
        token.iat.toFixed();
        parts.header = { foo: 'bar' };
        parts.payload.foo = 'bar';
        return parts;
      },
      paseto(ctx, token, parts) {
        ctx.oidc.issuer.substring(0);
        token.iat.toFixed();
        parts.footer = { foo: 'bar' };
        parts.footer = Buffer.from('foo');
        parts.footer = undefined;
        parts.footer = 'foo';
        parts.payload.foo = 'bar';
        return parts;
      }
    },
  },
  httpOptions(options) {
    if (options.headers) {
      options.headers.foo = 'bar';
    }
    options.json = false;
    options.timeout = 5000;
    options.retry = 1;
    return options;
  },
  async expiresWithSession(ctx, token) {
    ctx.oidc.issuer.substring(0);
    token.iat.toFixed();
    return false;
  },
  async issueRefreshToken(ctx, client, token) {
    ctx.oidc.issuer.substring(0);
    client.clientId.substring(0);
    token.iat.toFixed();
    return false;
  },
  jwks: {
    keys: [
      {
        kty: 'RSA',
        d: 'foo',
        n: 'foo',
        e: 'AQAB',
      },
      {
        kty: 'OKP',
        x: 'foo',
        d: 'foo',
        crv: 'Ed25519',
      }
    ],
  },
  responseTypes: ['code', 'code id_token', 'none'],
  pkceMethods: ['plain', 'S256'],
  pkce: {
    methods: ['plain', 'S256'],
    required(ctx, client) {
      ctx.oidc.issuer.substring(0);
      client.clientId.substring(0);
      return true;
    }
  },
  routes: {
    authorization: '/auth',
    check_session: '/session/check',
    code_verification: '/device',
    device_authorization: '/device/auth',
    end_session: '/session/end',
    introspection: '/token/introspection',
    jwks: '/jwks',
    registration: '/reg',
    revocation: '/token/revocation',
    token: '/token',
    userinfo: '/me',
    pushed_authorization_request: '/request',
  },
  scopes: ['foo', 'bar'],
  dynamicScopes: [
    /foo/,
    /bar/
  ],
  subjectTypes: ['public', 'pairwise'],
  tokenEndpointAuthMethods: ['self_signed_tls_client_auth'],
  introspectionEndpointAuthMethods: ['none'],
  revocationEndpointAuthMethods: ['client_secret_basic'],
  ttl: {
    CustomToken: 23,
    AccessToken(ctx, accessToken) {
      ctx.oidc.issuer.substring(0);
      accessToken.iat.toFixed();
      return 2;
    },
    AuthorizationCode: 3,
    ClientCredentials: 3,
    DeviceCode: 3,
    IdToken: 3,
    RefreshToken: 3,
  },
  extraClientMetadata: {
    properties: ['foo', 'bar'],
    validator(key, value, metadata, ctx) {
      ctx.oidc.issuer.substring(0);
      metadata.client_id.substring(0);
      key.substring(0);
      metadata.foo = 'bar';
    }
  },
  async postLogoutSuccessSource(ctx) {
    ctx.oidc.issuer.substring(0);
  },
  interactions: {
    async url(ctx, interaction) {
      ctx.oidc.issuer.substring(0);
      interaction.iat.toFixed();
      interaction.returnTo.substring(0);
      JSON.stringify(interaction.params.foo);
      JSON.stringify(interaction.prompt.name);
      return 'foo';
    },
    policy: [
      new interactionPolicy.Prompt(
        { name: 'foo', requestable: true },
        new interactionPolicy.Check('foo', 'bar', 'baz', (ctx) => false),
        new interactionPolicy.Check('foo', 'bar', 'baz', async (ctx) => true, async (ctx) => ({ foo: 'bar' })),
      ),
      new interactionPolicy.Prompt(
        { name: 'foo', requestable: true },
        (ctx) => ({ foo: 'bar' }),
        new interactionPolicy.Check('foo', 'bar', 'baz', (ctx) => false),
        new interactionPolicy.Check('foo', 'bar', 'baz', async (ctx) => true, async (ctx) => ({ foo: 'bar' })),
      )
    ],
  },
  async findAccount(ctx, sub, token) {
    ctx.oidc.issuer.substring(0);
    sub.substring(0);
    if (token !== undefined) {
      token.iat.toFixed();
    }

    if (Math.random() > 0.5) {
      return {
        accountId: sub,
        async claims() {
          return {
            sub,
            foo: 'bar',
          };
        },
      };
    }
  },
  async rotateRefreshToken(ctx) {
    ctx.oidc.issuer.substring(0);
    return true;
  },
  async audiences(ctx, sub, token, use) {
    ctx.oidc.issuer.substring(0);
    if (sub !== undefined) {
      sub.substring(0);
    }
    token.iat.toFixed();
    use.substring(0);
    return 'foo';
  },
  async logoutSource(ctx, form) {
    ctx.oidc.issuer.substring(0);
    form.substring(0);
  },
  async renderError(ctx, out, err) {
    ctx.oidc.issuer.substring(0);
    out.error.substring(0);
    err.message.substring(0);
  },
  async pairwiseIdentifier(ctx, accountId, client) {
    ctx.oidc.issuer.substring(0);
    accountId.substring(0);
    client.clientId.substring(0);
    return 'foo';
  },
  features: {
    devInteractions: { enabled: false },
    claimsParameter: { enabled: false },
    introspection: {
      enabled: false,
      async allowedPolicy(ctx, client, token) {
        ctx.oidc.issuer.substring(0);
        client.clientId.substring(0);
        token.iat.toFixed();
        return false;
      },
    },
    userinfo: { enabled: false },
    jwtUserinfo: { enabled: false },
    webMessageResponseMode: { enabled: false, ack: 'id-00', scriptNonce() { return "foo"; } },
    revocation: { enabled: false },
    sessionManagement: { enabled: false, ack: 28, keepHeaders: false, scriptNonce() { return "foo"; } },
    jwtIntrospection: { enabled: false, ack: 'draft-09' },
    jwtResponseModes: { enabled: false, ack: 2 },
    pushedAuthorizationRequests: { enabled: false, ack: 'draft-02' },
    registration: {
      enabled: true,
      initialAccessToken: true,
      policies: {
        async foo(ctx, metadata) {
          ctx.oidc.issuer.substring(0);
          metadata.client_id.substring(0);
        }
      },
      idFactory() {
        return 'foo';
      },
      secretFactory() {
        return 'foo';
      }
    },
    registrationManagement: {
      enabled: false,
      async rotateRegistrationAccessToken(ctx) {
        ctx.oidc.issuer.substring(0);
        return true;
      },
    },
    resourceIndicators: {
      enabled: true,
      ack: 7,
      async allowedPolicy(ctx, resources, client) {
        ctx.oidc.issuer.substring(0);
        if (Array.isArray(resources)) {
          resources[0].substring(0);
        } else {
          resources.substring(0);
        }
        return true;
      },
    },
    requestObjects: {
      request: false,
      requestUri: false,
      requireUriRegistration: false,
      mergingStrategy: {
        name: 'lax',
        whitelist: ['nonce'],
      },
    },
    encryption: { enabled: false },
    fapiRW: { enabled: false, ack: 'id02-rev.3' },
    clientCredentials: { enabled: false },
    backchannelLogout: { enabled: false, ack: 4 },
    ietfJWTAccessTokenProfile: { enabled: false, ack: 2 },
    dPoP: { enabled: false, ack: 'draft-01', iatTolerance: 120 },
    frontchannelLogout: {
      ack: 2,
      enabled: false,
      async logoutPendingSource(ctx, frames, postLogoutRedirectUri) {
        ctx.oidc.issuer.substring(0);
        frames[0].substring(0);
        if (postLogoutRedirectUri) {
          postLogoutRedirectUri.substring(0);
        }
      }
    },
    deviceFlow: {
      enabled: false,
      charset: 'digits',
      mask: '*** *** ***',
      deviceInfo(ctx) {
        ctx.oidc.issuer.substring(0);
        return {};
      },
      async userCodeInputSource(ctx, form, out, err) {
        ctx.oidc.issuer.substring(0);
        form.substring(0);
        if (out !== undefined) {
          out.error;
        }
        if (err !== undefined) {
          err.message.substring(0);
        }
      },
      async userCodeConfirmSource(ctx, form, client, deviceInfo, userCode) {
        ctx.oidc.issuer.substring(0);
        form.substring(0);
        client.clientId.substring(0);
        JSON.stringify(deviceInfo.foo);
        userCode.substring(0);
      },
      async successSource(ctx) {
        ctx.oidc.issuer.substring(0);
      }
    },
    mTLS: {
      enabled: false,
      certificateBoundAccessTokens: true,
      selfSignedTlsClientAuth: true,
      tlsClientAuth: true,
      getCertificate(ctx) {
        ctx.oidc.issuer.substring(0);
        return 'foo';
      },
      certificateAuthorized(ctx) {
        ctx.oidc.issuer.substring(0);
        return false;
      },
      certificateSubjectMatches(ctx, property, expected) {
        ctx.oidc.issuer.substring(0);
        property.substring(0);
        expected.substring(0);
        return false;
      },
    }
  },
  whitelistedJWA: {
    tokenEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
    ],
    introspectionEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
    ],
    revocationEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
    ],
    idTokenSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA', 'none',
    ],
    requestObjectSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA', 'none',
    ],
    userinfoSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA', 'none'
    ],
    introspectionSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA', 'none',
    ],
    authorizationSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
    ],
    idTokenEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],
    requestObjectEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],
    userinfoEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],
    introspectionEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],
    authorizationEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],
    idTokenEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],
    requestObjectEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],
    userinfoEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],
    introspectionEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],
    authorizationEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],
    dPoPSigningAlgValues: [
      'RS256', 'PS256', 'ES256', 'EdDSA',
    ],
  },
});

provider.on('access_token.saved', (accessToken) => {
  accessToken.jti.substring(0);
});

provider.registerGrantType('urn:example', async (ctx, next) => {
  ctx.oidc.route.substring(0);
  return next();
}, ['foo', 'bar'], ['foo']);

provider.on('authorization.accepted', (ctx) => {
  const value = ctx.oidc.cookies.get('key');
  if (value !== undefined) {
    value.substring(0);
  }

  ctx.oidc.cookies.set('key', 'value', { signed: true, sameSite: 'strict' });
});

provider.on('interaction.started', (ctx, prompt) => {
  ctx.oidc.route.substring(0);
  prompt.name.substring(0);
  prompt.reasons.pop();
});

provider.use((ctx, next) => {
  ctx.href.substring(0);
  return next();
});

provider.use(async (ctx, next) => {
  ctx.href.substring(0);
  await next();
  //
});

(async () => {
  const client = await provider.Client.find('foo');
  if (client !== undefined) {
    client.clientId.substring(0);
  }
  const accessToken = await provider.AccessToken.find('foo');
  if (accessToken !== undefined) {
    accessToken.jti.substring(0);
  }

  try {
      await Promise.all([
        provider.AccessToken.revokeByGrantId('grantId'),
        provider.AuthorizationCode.revokeByGrantId('grantId'),
        provider.DeviceCode.revokeByGrantId('grantId'),
        provider.RefreshToken.revokeByGrantId('grantId'),
      ]);
  } catch(e) {}
})();
