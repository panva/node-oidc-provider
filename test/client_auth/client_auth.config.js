const { cloneDeep } = require('lodash');

const config = cloneDeep(require('../default.config'));
const {
  e, n, kid, kty, use,
} = require('../client.sig.key');
const mtlsKeys = require('../jwks/jwks.json');

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
  'tls_client_auth',
  'self_signed_tls_client_auth',
];
config.features = { introspection: { enabled: true } };

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
    tls_client_auth_subject_dn: 'foobar',
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
  }],
};
