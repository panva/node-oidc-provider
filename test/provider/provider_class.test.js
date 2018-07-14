const { expect } = require('chai');
const { JWK } = require('node-jose');

const Provider = require('../../lib');

describe('Provider', () => {
  it('also exports errors and key related helpers from node-jose', () => {
    expect(Provider).to.have.keys('createKeyStore', 'asKeyStore', 'asKey', 'AdapterTest', 'errors');
    ['createKeyStore', 'asKeyStore', 'asKey'].forEach((method) => {
      expect(Provider[method]).to.equal(JWK[method]);
    });
    expect(Provider.errors).to.have.keys([
      'AccessDenied',
      'AuthorizationPending',
      'ExpiredToken',
      'InvalidClient',
      'InvalidClientAuth',
      'InvalidClientMetadata',
      'InvalidGrant',
      'InvalidRequest',
      'InvalidRequestObject',
      'InvalidRequestUri',
      'InvalidScope',
      'InvalidToken',
      'SessionNotFound',
      'RedirectUriMismatch',
      'RegistrationNotSupported',
      'RequestNotSupported',
      'RequestUriNotSupported',
      'RestrictedGrantType',
      'RestrictedResponseType',
      'SlowDown',
      'TemporarilyUnavailable',
      'UnauthorizedClient',
      'UnsupportedGrantType',
      'UnsupportedResponseMode',
      'UnsupportedResponseType',
      'WebMessageUriMismatch',
    ]);
  });
});
