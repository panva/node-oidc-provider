const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));
const {
  e, n, kid, kty, use,
} = require('../client.sig.key');
const mtlsKeys = require('../jwks/jwks.json');
const runtimeSupport = require('../../lib/helpers/runtime_support');

const clientKey = {
  e, n, kid, kty, use,
};
const rsaKeys = cloneDeep(mtlsKeys);
rsaKeys.keys.splice(0, 1);

config.tokenEndpointAuthMethods = [
  'none',
  'client_secret_basic',
  'client_secret_post',
  'private_key_jwt',
  'client_secret_jwt',
  ...(runtimeSupport.KeyObject ? [
    'tls_client_auth',
    'self_signed_tls_client_auth',
  ] : []),
];
merge(config.features, {
  introspection: { enabled: true },
  mTLS: {
    enabled: runtimeSupport.KeyObject,
    selfSignedTlsClientAuth: true,
    tlsClientAuth: true,
    getCertificate(ctx) {
      return ctx.get('x-ssl-client-cert');
    },
    certificateAuthorized(ctx) {
      return ctx.get('x-ssl-client-verify') === 'SUCCESS';
    },
    certificateSubjectMatches(ctx, key, expected) {
      return key === 'tls_client_auth_san_dns' && ctx.get('x-ssl-client-san-dns') === expected;
    },
  },
});

module.exports = {
  config,
  clients: [{
    token_endpoint_auth_method: 'none',
    client_id: 'client-none',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    token_endpoint_auth_method: 'client_secret_basic',
    client_id: 'client-basic',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    token_endpoint_auth_method: 'client_secret_basic',
    client_id: 'an:identifier',
    client_secret: 'some secure & non-standard secret',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    token_endpoint_auth_method: 'client_secret_basic',
    client_id: ' %&+£€',
    client_secret: ' %&+£€',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    token_endpoint_auth_method: 'client_secret_post',
    client_id: 'client-post',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    token_endpoint_auth_method: 'client_secret_jwt',
    client_id: 'client-jwt-secret',
    client_secret: 'its64bytes_____________________________________________________!',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-jwt-key',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks: {
      keys: [clientKey],
    },
  }, {
    client_id: 'client-pki-mtls',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'tls_client_auth',
    tls_client_auth_san_dns: 'rp.example.com',
  }, {
    client_id: 'client-self-signed-mtls',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    jwks: mtlsKeys,
  }, {
    client_id: 'client-self-signed-mtls-rsa',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    jwks: rsaKeys,
  }, {
    client_id: 'client-self-signed-mtls-jwks_uri',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    jwks_uri: 'https://client.example.com/jwks',
  }, {
    client_id: 'secret-expired-basic',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
    client_secret_expires_at: 1,
  }, {
    client_id: 'secret-expired-jwt',
    client_secret: 'secret',
    token_endpoint_auth_method: 'client_secret_jwt',
    redirect_uris: ['https://client.example.com/cb'],
    client_secret_expires_at: 1,
  }],
};
