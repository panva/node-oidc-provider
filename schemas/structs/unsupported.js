const { struct } = require('superstruct');
const { unsupported: defaults } = require('../../lib/helpers/defaults');

module.exports = struct({
  idTokenEncryptionAlgValues: ['string'],
  idTokenEncryptionEncValues: ['string'],
  idTokenSigningAlgValues: ['string'],
  requestObjectEncryptionAlgValues: ['string'],
  requestObjectEncryptionEncValues: ['string'],
  requestObjectSigningAlgValues: ['string'],
  tokenEndpointAuthSigningAlgValues: ['string'],
  introspectionEndpointAuthSigningAlgValues: ['string'],
  revocationEndpointAuthSigningAlgValues: ['string'],
  userinfoEncryptionAlgValues: ['string'],
  userinfoEncryptionEncValues: ['string'],
  userinfoSigningAlgValues: ['string'],
}, {
  idTokenEncryptionAlgValues: defaults.idTokenEncryptionAlgValues,
  idTokenEncryptionEncValues: defaults.idTokenEncryptionEncValues,
  idTokenSigningAlgValues: defaults.idTokenSigningAlgValues,
  requestObjectEncryptionAlgValues: defaults.requestObjectEncryptionAlgValues,
  requestObjectEncryptionEncValues: defaults.requestObjectEncryptionEncValues,
  requestObjectSigningAlgValues: defaults.requestObjectSigningAlgValues,
  tokenEndpointAuthSigningAlgValues: defaults.tokenEndpointAuthSigningAlgValues,
  introspectionEndpointAuthSigningAlgValues: defaults.introspectionEndpointAuthSigningAlgValues,
  revocationEndpointAuthSigningAlgValues: defaults.revocationEndpointAuthSigningAlgValues,
  userinfoEncryptionAlgValues: defaults.userinfoEncryptionAlgValues,
  userinfoEncryptionEncValues: defaults.userinfoEncryptionEncValues,
  userinfoSigningAlgValues: defaults.userinfoSigningAlgValues,
});
