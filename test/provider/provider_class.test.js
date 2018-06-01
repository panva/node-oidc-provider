const Provider = require('../../lib');
const { expect } = require('chai');
const { JWK } = require('node-jose');

describe('Provider', () => {
  it('also exports errors and key related helpers from node-jose', () => {
    expect(Provider).to.have.keys('createKeyStore', 'asKeyStore', 'asKey', 'AdapterTest', 'errors');
    ['createKeyStore', 'asKeyStore', 'asKey'].forEach((method) => {
      expect(Provider[method]).to.equal(JWK[method]);
    });
    expect(Provider.errors).to.have.keys([
      'InvalidClient',
      'InvalidClientAuth',
      'InvalidClientMetadata',
      'InvalidGrant',
      'InvalidRequest',
      'InvalidRequestObject',
      'InvalidRequestUri',
      'InvalidScope',
      'InvalidToken',
      'RedirectUriMismatch',
      'RegistrationNotSupported',
      'RequestNotSupported',
      'RequestUriNotSupported',
      'RestrictedGrantType',
      'RestrictedResponseType',
      'UnsupportedGrantType',
      'UnsupportedResponseMode',
      'UnsupportedResponseType',
    ]);
  });
});
