import * as crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import * as https from 'node:https';

import * as jose from 'jose';
import getRawBody from 'raw-body';
import { generate } from 'selfsigned';

import Provider, { errors } from '../../lib/index.js';
import Account from '../../example/support/account.js';

const { PORT = 3000, ISSUER = `https://localhost:${PORT}` } = process.env;
const setup = JSON.parse(process.env.SETUP || '{}');
const configuration = JSON.parse(readFileSync(new URL('./plan.json', import.meta.url)));
const { browser, override } = JSON.parse(readFileSync(new URL('../fapi/plan.json', import.meta.url)));
const credentialScope = 'eudi.pid.1';
const credentialConfigurationId = setup.credential_configuration_id || configuration.vci.credential_configuration_id;
configuration.vci.credential_configuration_id = credentialConfigurationId;
const rar = setup.authorization_request_type === 'rar';
const preAuthorized = setup.vci_grant_type === 'pre_authorization_code';
const proofType = credentialConfigurationId.endsWith('.attestation') ? 'attestation' : 'jwt';
const keyAttestation = proofType === 'attestation' || credentialConfigurationId.endsWith('.jwt-key-attestation');
const preAuthorizedGrant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const issuerStates = new Map();
const vct = 'urn:example:oidc-provider:pid';

const ca = await generate([{ name: 'commonName', value: 'oidc-provider conformance CA' }], {
  algorithm: 'sha256',
  keyType: 'ec',
  extensions: [
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
  ],
});

async function signingKey(name) {
  const pems = await generate([{ name: 'commonName', value: name }], {
    algorithm: 'sha256',
    keyType: 'ec',
    ca: { key: ca.private, cert: ca.cert },
    extensions: [
      { name: 'basicConstraints', cA: false, critical: true },
      { name: 'keyUsage', digitalSignature: true, critical: true },
    ],
  });
  const privateKey = crypto.createPrivateKey(pems.private);
  const publicKey = crypto.createPublicKey(privateKey);
  const x5c = [new crypto.X509Certificate(pems.cert).raw.toString('base64')];
  const jwk = { ...privateKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig', x5c };
  jwk.kid = await jose.calculateJwkThumbprint(jwk);
  return { pems, privateKey, publicKey, jwk, x5c };
}

const [issuer, attester] = await Promise.all([
  signingKey('oidc-provider credential issuer'),
  signingKey('oidc-provider client attester'),
]);

configuration.server = { discoveryUrl: `${ISSUER}/.well-known/openid-configuration` };
configuration.vci.credential_issuer_url = ISSUER;
configuration.client_attestation.attester_jwks = { keys: [attester.jwk] };
configuration.client_attestation.key_attestation_jwks = { keys: [attester.jwk] };
if (preAuthorized) {
  configuration.vci.static_tx_code = '493536';
}
configuration.credential = {
  trust_anchor_pem: ca.cert,
  status_list_trust_anchor_pem: ca.cert,
};
configuration.resource = { resourceUrl: `${ISSUER}/credential` };
Object.assign(configuration, JSON.parse(JSON.stringify({ browser, override }).replaceAll('https://fapi.panva.cz', ISSUER)));
for (const client of [configuration.client, configuration.client2]) {
  const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const jwk = { ...await jose.exportJWK(privateKey), alg: 'ES256', use: 'sig' };
  jwk.kid = await jose.calculateJwkThumbprint(jwk);
  client.jwks = { keys: [jwk] };
}

const provider = new Provider(ISSUER, {
  clients: [configuration.client, configuration.client2].map(({ client_id }) => ({
    client_id,
    client_name: client_id,
    token_endpoint_auth_method: 'attest_jwt_client_auth',
    grant_types: ['authorization_code', 'refresh_token', ...(preAuthorized ? [preAuthorizedGrant] : [])],
    response_types: ['code'],
    require_pushed_authorization_requests: true,
    dpop_bound_access_tokens: true,
    redirect_uris: ['https://rp.example.com/cb'],
    authorization_details_types: ['openid_credential'],
  })),
  jwks: { keys: [issuer.jwk] },
  scopes: ['openid', 'offline_access', 'eudi.pid.1'],
  clientAuthMethods: ['attest_jwt_client_auth'],
  clientDefaults: {
    id_token_signed_response_alg: 'ES256',
  },
  responseTypes: ['code'],
  extraParams: {
    issuer_state(ctx, value) {
      if (value !== undefined && issuerStates.get(value) !== ctx.oidc.params.client_id) {
        throw new errors.InvalidRequest('unknown issuer_state for this client');
      }
    },
  },
  findAccount: Account.findAccount,
  issueRefreshToken(_ctx, client) {
    // The HAIP plan requests the credential's scope without offline_access.
    return client.grantTypeAllowed('refresh_token');
  },
  features: {
    fapi: { enabled: true, profile: '2.0' },
    dPoP: { enabled: true, nonceSecret: crypto.randomBytes(32) },
    pushedAuthorizationRequests: { enabled: true },
    richAuthorizationRequests: {
      enabled: rar,
      authorizationDetailsForGrantSource(ctx) {
        return ctx.oidc.grant.rar;
      },
      authorizationDetailsForAccessToken(ctx, _token, source) {
        const requested = ctx.oidc.params.authorization_details
          ? JSON.parse(ctx.oidc.params.authorization_details)
          : source?.rar;
        if (!requested) return undefined;
        const granted = new Set(ctx.oidc.grant.rar?.map((detail) => detail.credential_configuration_id));
        if (requested.some((detail) => detail.type !== 'openid_credential' || !granted.has(detail.credential_configuration_id))) {
          throw new errors.InvalidAuthorizationDetails('credential configuration was not granted');
        }
        return requested.map((detail) => ({
          ...detail,
          credential_identifiers: [`${source.grantId}:${detail.credential_configuration_id}`],
        }));
      },
      authorizationDetailsForIntrospection(_ctx, token) {
        return token.rar;
      },
    },
    attestClientAuth: {
      enabled: true,
      ack: 'draft-12',
      challengeSecret: crypto.randomBytes(32),
      getAttestationSignaturePublicKey(_ctx, header, payload) {
        if (payload.iss !== configuration.client_attestation.issuer) {
          throw new Error('unknown client attestation issuer');
        }
        if (header.x5c?.[0] !== attester.x5c[0]) {
          throw new Error('unexpected client attestation certificate');
        }
        return attester.publicKey;
      },
    },
    resourceIndicators: {
      enabled: true,
      defaultResource(ctx) {
        return ctx.oidc.urlFor('credential');
      },
      useGrantedResource() {
        return true;
      },
      getResourceServerInfo(ctx, resource) {
        if (resource === ctx.oidc.urlFor('credential')) {
          return { scope: 'eudi.pid.1' };
        }
        throw new errors.InvalidTarget();
      },
    },
    openid4vci: {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: crypto.randomBytes(32),
      preAuthorizedCodeGrant: preAuthorized,
      metadata: {
        batch_credential_issuance: { batch_size: 5 },
      },
      credentialConfigurationsSupported: {
        [credentialConfigurationId]: {
          format: 'dc+sd-jwt',
          vct,
          ...(!rar && { scope: credentialScope }),
          cryptographic_binding_methods_supported: ['jwk'],
          credential_signing_alg_values_supported: ['ES256'],
          proof_types_supported: {
            [proofType]: {
              proof_signing_alg_values_supported: ['ES256'],
              ...(keyAttestation && {
                key_attestations_required: {
                  key_storage: ['iso_18045_moderate'],
                  user_authentication: ['iso_18045_moderate'],
                },
              }),
            },
          },
        },
      },
      getKeyAttestationSignaturePublicKey(_ctx, _iss, header) {
        if (header.x5c?.[0] !== attester.x5c[0]) {
          throw new Error('unexpected key attestation certificate');
        }
        return attester.publicKey;
      },
      async issueCredential(_ctx, { proofs }) {
        const keys = proofs.attestation?.attestedKeys
          || proofs.jwt.map((proof) => jose.decodeProtectedHeader(proof).jwk);
        const credentials = await Promise.all(keys.map(async (jwk) => {
          const disclosures = Object.entries({ given_name: 'John', family_name: 'Doe' }).map(([name, value]) => (
            Buffer.from(JSON.stringify([crypto.randomBytes(16).toString('base64url'), name, value])).toString('base64url')
          ));
          // Round all validity information so separate credentials do not reveal issuance time.
          const day = Math.floor(Date.now() / 86400000) * 86400;
          const jwt = await new jose.SignJWT({
            iss: ISSUER,
            vct,
            iat: day,
            nbf: day,
            exp: day + 30 * 86400,
            cnf: { jwk },
            _sd_alg: 'sha-256',
            _sd: disclosures.map((disclosure) => crypto.hash('sha256', disclosure, 'base64url')),
          })
            .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: issuer.x5c })
            .sign(issuer.privateKey);
          return { credential: `${jwt}~${disclosures.join('~')}~` };
        }));
        return { credentials };
      },
    },
  },
  enabledJWA: {
    idTokenSigningAlgValues: ['ES256'],
    dPoPSigningAlgValues: ['ES256'],
    attestSigningAlgValues: ['ES256'],
  },
});

const suiteOrigins = /^https:\/\/.+\.certification\.openid\.net$/;
const localSuiteOrigins = new Set([
  'https://localhost:8443',
  'https://localhost.emobix.co.uk:8443',
  'https://localhost.emobix.co.uk',
]);
Object.defineProperty(provider.Client.prototype, 'redirectUriAllowed', {
  value(url) {
    const parsed = URL.parse(url);
    if (!parsed) return false;
    return (localSuiteOrigins.has(parsed.origin) || suiteOrigins.test(parsed.origin))
      && parsed.pathname.endsWith('/callback')
      && (parsed.search === '' || parsed.search === '?dummy1=lorem&dummy2=ipsum');
  },
});

provider.use(async (ctx, next) => {
  if (ctx.method !== 'POST' || ctx.path !== '/credential-offer') {
    return next();
  }
  const { credential_offer_endpoint: endpoint, client_id: clientId } = JSON.parse(await getRawBody(ctx.req, { encoding: 'utf8', limit: '8kb' }));
  const target = new URL(endpoint);
  ctx.assert((localSuiteOrigins.has(target.origin) || suiteOrigins.test(target.origin)) && target.pathname.endsWith('/credential_offer'), 400, 'invalid credential offer endpoint');
  ctx.assert([configuration.client.client_id, configuration.client2.client_id].includes(clientId), 400, 'unknown client');

  let grants;
  if (preAuthorized) {
    const accountId = 'foo';
    const resource = `${ISSUER}/credential`;
    const grant = new provider.Grant({ accountId, clientId });
    grant.addResourceScope(resource, credentialScope);
    const grantId = await grant.save();
    const code = new provider.PreAuthorizedCode({
      accountId,
      clientId,
      grantId,
      resource,
      scope: credentialScope,
      txCode: configuration.vci.static_tx_code,
    });
    grants = {
      [preAuthorizedGrant]: {
        'pre-authorized_code': await code.save(),
        tx_code: { input_mode: 'numeric', length: 6 },
      },
    };
  } else {
    const issuerState = crypto.randomUUID();
    issuerStates.set(issuerState, clientId);
    grants = { authorization_code: { issuer_state: issuerState } };
  }
  const offer = {
    credential_issuer: ISSUER,
    credential_configuration_ids: [credentialConfigurationId],
    grants,
  };
  target.searchParams.set('credential_offer', JSON.stringify(offer));
  const response = await fetch(target);
  await response.arrayBuffer();
  ctx.assert(response.ok, 502, 'credential offer delivery failed');
  ctx.status = 204;
  return undefined;
});

const tls = await generate();
const server = https.createServer({ key: tls.private, cert: tls.cert }, provider.callback());
server.listen(PORT, () => {
  writeFileSync(new URL('./.plan.json', import.meta.url), `${JSON.stringify(configuration, null, 2)}\n`);
  console.log(`application is listening on port ${PORT}, check its /.well-known/openid-credential-issuer`);
});
process.on('SIGINT', () => server.close(() => process.exit(0)));
